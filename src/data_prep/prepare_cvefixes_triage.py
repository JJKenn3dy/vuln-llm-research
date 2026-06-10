"""Build v8.2 SAST triage training data from real CVEFixes with MIXED FP sourcing.

Solves Lesson 0 from docs/HISTORY.md (v8.1 collapsed because "safe" examples were
unrelated independent code) AND the structural shortcut found in v8.2 v1 (FP
post-fix code was 1.4-1.8x longer and structurally richer than TP pre-fix,
shortcut MLP F1=0.69).

Methodology:
- TP: vulnerable_code from a CVEFixes row, with claimed_cwe = real_cwe.
- FP: 50% post-fix (fixed_code of the SAME row), 50% other-safe (fixed_code of
  another CVE with the SAME claimed CWE from the same project-split). This
  breaks the inherent post-fix-is-longer structural shortcut while preserving
  the differential-pair signal for half the FPs.
- Project-stratified split by `repo_url`: rows are split BEFORE FP sourcing
  so other-safe FP source is always in the same split as its TP (zero leakage).
- Two test sets: balanced 50/50 + realistic ~1:8 (SastBench-aligned).

Usage:
    # Full prep with Haiku 4.5 teacher (mixed FP, ~$1.16, ~50 min)
    python -m src.data_prep.prepare_cvefixes_triage \\
        --output-dir /workspace/data/train/triage_v8_2 \\
        --teacher openrouter --teacher-model anthropic/claude-haiku-4.5

    # Smoke test: 50 rows, no teacher
    python -m src.data_prep.prepare_cvefixes_triage \\
        --output-dir data/train/triage_v8_2_smoke \\
        --max-pairs 50 --teacher none --dry-run

    # Tune FP mix fraction (default 0.5 = half post-fix, half other-safe)
    python -m src.data_prep.prepare_cvefixes_triage ... --fp-post-fix-frac 0.7
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import re
import time
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

from src.utils.prompts import TRIAGE_SYSTEM, TRIAGE_USER_TEMPLATE


WEB_CWES = {
    "CWE-79", "CWE-89", "CWE-22", "CWE-78", "CWE-94", "CWE-352",
    "CWE-434", "CWE-502", "CWE-611", "CWE-798", "CWE-918", "CWE-787",
}
WEB_LANGS = {"PHP", "Python", "JavaScript", "TypeScript", "Java", "Ruby", "Go"}
SAST_TOOLS = ["semgrep", "codeql", "sonarqube", "snyk-code", "bandit"]

MIN_CODE_CHARS = 50
MAX_CODE_CHARS = 8000

FP_SRC_POSTFIX = "post_fix"
FP_SRC_MISCLASS = "misclassified_cwe"


# Two FP types with semantic difference that the model has to learn:
# - post_fix: code where the bug used to be but is now patched
# - misclassified_cwe: code that has SOME real bug, but it is NOT the claimed CWE
#   (this breaks the length shortcut because both TP and misclass FP come from
#   `vulnerable_code`, so they share the structural distribution).
FP_POSTFIX_PROMPT = """A static analysis tool flagged the code below as a potential {cwe} ({cwe_name}) vulnerability.
This code is the POST-FIX version of a real CVE: the vulnerability used to be here but has been patched in this commit.

Repository: {repo}
File: {file_path}
Commit message: {commit_msg}

Your task: explain in 2-3 sentences why this is a FALSE POSITIVE for this scan.

Requirements:
- Reference at least one specific identifier from the code (function, variable, API call).
- Mention the concrete defensive pattern the fix introduced (sanitisation, validation, parameterised query, etc.).
- Do NOT use the phrase "either ... or ..." or any other generic enumeration.
- Output only the explanation paragraph. No headers, no JSON, no markdown.

Code:
{code}
"""

FP_MISCLASS_PROMPT = """A static analysis tool flagged the code below as a potential {cwe} ({cwe_name}) vulnerability.
The code does have a real bug, but it is a {real_cwe} ({real_cwe_name}) issue, NOT a {cwe} one.
The SAST tool misclassified the CWE category of the actual problem.

Repository: {repo}
File: {file_path}

Your task: explain in 2-3 sentences why the {cwe} claim is a FALSE POSITIVE (even though the code has a different problem).

Requirements:
- Reference at least one specific identifier from the code (function, variable, API call).
- Explain why this code does NOT match the {cwe} pattern (missing source/sink, wrong sanitisation path, etc.).
- Do NOT mention {real_cwe} as the answer — focus only on why {cwe} is wrong.
- Do NOT use the phrase "either ... or ..." or any other generic enumeration.
- Output only the explanation paragraph. No headers, no JSON, no markdown.

Code:
{code}
"""


def log(msg: str) -> None:
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)


def code_hash(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", errors="replace")).hexdigest()[:12]


def project_id_from_repo_url(url: str) -> str:
    if not url:
        return ""
    try:
        p = urlparse(url)
        path = p.path.strip("/")
        parts = path.split("/")
        if len(parts) >= 2:
            return f"{parts[0]}/{parts[1]}"
        return path
    except Exception:
        return url


def shorten_text(s: str, n: int = 500) -> str:
    if not s:
        return ""
    s = s.strip()
    return s[:n] + ("..." if len(s) > n else "")


def parse_cve_description(raw_desc) -> str:
    if not raw_desc:
        return ""
    if isinstance(raw_desc, list):
        for d in raw_desc:
            if isinstance(d, dict) and d.get("lang") == "en":
                return d.get("value", "")
    s = str(raw_desc)
    m = re.search(r"['\"]value['\"]\s*:\s*['\"](.*?)['\"]\s*[,}]", s, re.DOTALL)
    if m:
        return m.group(1).replace("\\n", " ").replace("\\xa0", " ").strip()
    return s[:500]


def collect_exclusion_hashes(*paths: Path) -> set[str]:
    hashes: set[str] = set()
    for path in paths:
        if not path.exists():
            log(f"  WARN: exclusion file {path} not found, skipping")
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception as e:
            log(f"  WARN: could not read {path}: {e}")
            continue
        for entry in data:
            md = entry.get("metadata", {}) or {}
            for k in ("vuln_code_hash", "fixed_code_hash"):
                if md.get(k):
                    hashes.add(md[k])
    log(f"  anti-leakage: {len(hashes)} excluded hashes loaded from {len(paths)} files")
    return hashes


def filter_rows(rows, exclude_hashes: set[str], cap_per_cwe: int | None) -> list[dict]:
    kept = []
    per_cwe = Counter()
    skipped = Counter()
    for r in rows:
        cwe = r.get("cwe_id")
        lang = r.get("language")
        vuln = (r.get("vulnerable_code") or "").strip()
        fix = (r.get("fixed_code") or "").strip()
        if cwe not in WEB_CWES:
            skipped["non_web_cwe"] += 1; continue
        if lang not in WEB_LANGS:
            skipped["non_web_lang"] += 1; continue
        if not vuln or not fix:
            skipped["empty_code"] += 1; continue
        if not (MIN_CODE_CHARS <= len(vuln) <= MAX_CODE_CHARS):
            skipped["bad_vuln_length"] += 1; continue
        if not (MIN_CODE_CHARS <= len(fix) <= MAX_CODE_CHARS):
            skipped["bad_fix_length"] += 1; continue
        if vuln.strip() == fix.strip():
            skipped["identical_pre_post"] += 1; continue
        h_v = code_hash(vuln)
        h_f = code_hash(fix)
        if h_v in exclude_hashes or h_f in exclude_hashes:
            skipped["eval_leakage"] += 1; continue
        if cap_per_cwe is not None and per_cwe[cwe] >= cap_per_cwe:
            skipped["over_cwe_cap"] += 1; continue
        per_cwe[cwe] += 1
        kept.append({
            "cve_id": r.get("cve_id", ""),
            "cwe_id": cwe,
            "cwe_name": r.get("cwe_name", "") or "",
            "repo_url": r.get("repo_url", "") or "",
            "language": lang,
            "severity": str(r.get("severity") or "MEDIUM"),
            "file_paths": r.get("file_paths") or [],
            "commit_message": r.get("commit_message") or "",
            "cve_description": parse_cve_description(r.get("cve_description")),
            "vulnerable_code": vuln,
            "fixed_code": fix,
            "vuln_code_hash": h_v,
            "fixed_code_hash": h_f,
        })
    log(f"  filtered to {len(kept)} pairs; skipped: {dict(skipped)}")
    log(f"  per CWE: {dict(per_cwe.most_common())}")
    return kept


# ---------------------------- Teacher LLM ----------------------------

def call_teacher(backend: str, model: str, prompt: str, retries: int = 3) -> str:
    last_err = None
    for attempt in range(retries):
        try:
            if backend == "openai":
                from openai import OpenAI
                client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])
                resp = client.chat.completions.create(
                    model=model,
                    messages=[{"role": "user", "content": prompt}],
                    temperature=0.7, max_tokens=300,
                )
                return (resp.choices[0].message.content or "").strip()
            if backend == "openrouter":
                from openai import OpenAI
                client = OpenAI(
                    api_key=os.environ["OPENROUTER_API_KEY"],
                    base_url="https://openrouter.ai/api/v1",
                )
                resp = client.chat.completions.create(
                    model=model,
                    messages=[{"role": "user", "content": prompt}],
                    temperature=0.7, max_tokens=300,
                )
                return (resp.choices[0].message.content or "").strip()
            if backend == "none":
                return ""
            raise ValueError(f"unknown backend: {backend}")
        except Exception as e:
            last_err = e
            time.sleep(2 + attempt * 2)
    log(f"  teacher call failed after {retries}: {last_err}")
    return ""


def build_tp_reasoning(row: dict) -> str:
    desc = shorten_text(row["cve_description"], 350)
    msg = shorten_text(row["commit_message"].split("\n")[0], 200)
    parts = [f"The flagged code does contain a {row['cwe_id']} vulnerability"]
    if desc:
        parts.append(desc)
    if msg:
        parts.append(f"The upstream fix commit notes: \"{msg}\".")
    return " ".join(parts).strip()


def build_fp_reasoning(
    claimed_cwe: str,
    claimed_cwe_name: str,
    fp_row: dict,
    fp_source: str,
    fp_code: str,
    backend: str,
    model: str,
) -> str:
    """Generate per-sample FP reasoning via teacher. Prompt depends on fp_source.

    fp_code is passed explicitly because for misclass it comes from
    fp_row.vulnerable_code, not fp_row.fixed_code.
    """
    if backend == "none":
        if fp_source == FP_SRC_POSTFIX:
            return (f"This {fp_row['language']} snippet is the post-fix counterpart "
                    f"of the same function; the {claimed_cwe} pattern has been remediated.")
        return (f"This {fp_row['language']} snippet has a different category of bug "
                f"({fp_row['cwe_id']}), not a {claimed_cwe} issue.")

    if fp_source == FP_SRC_POSTFIX:
        prompt = FP_POSTFIX_PROMPT.format(
            cwe=claimed_cwe,
            cwe_name=claimed_cwe_name[:80],
            repo=project_id_from_repo_url(fp_row["repo_url"]),
            file_path=(fp_row["file_paths"][0] if fp_row["file_paths"] else "<unknown>"),
            commit_msg=shorten_text(fp_row["commit_message"].split("\n")[0], 200),
            code=fp_code[:3500],
        )
    else:
        prompt = FP_MISCLASS_PROMPT.format(
            cwe=claimed_cwe,
            cwe_name=claimed_cwe_name[:80],
            real_cwe=fp_row["cwe_id"],
            real_cwe_name=(fp_row["cwe_name"][:80] if fp_row["cwe_name"] else fp_row["cwe_id"]),
            repo=project_id_from_repo_url(fp_row["repo_url"]),
            file_path=(fp_row["file_paths"][0] if fp_row["file_paths"] else "<unknown>"),
            code=fp_code[:3500],
        )
    out = call_teacher(backend, model, prompt)
    if not out:
        if fp_source == FP_SRC_POSTFIX:
            return (f"This {fp_row['language']} snippet is the post-fix counterpart "
                    f"of the same function; the {claimed_cwe} pattern has been remediated.")
        return (f"This {fp_row['language']} snippet has a different category of bug "
                f"({fp_row['cwe_id']}), not a {claimed_cwe} issue.")
    return out


def make_example(
    code: str,
    verdict: str,
    reasoning: str,
    real_cwe_value: str,
    sugg_fix: str,
    tp_row: dict,
    tool: str,
    fp_source: str | None = None,
) -> dict:
    """All triage examples share TP's project_id, claimed_cwe and file_path so the
    split logic stays consistent. fp_source goes into metadata for downstream
    per-type analysis (and to verify the mix balance after build)."""
    project_id = project_id_from_repo_url(tp_row["repo_url"]) or tp_row["cve_id"]
    file_path = tp_row["file_paths"][0] if tp_row["file_paths"] else "<unknown>"
    user = TRIAGE_USER_TEMPLATE.format(
        tool=tool,
        cwe=tp_row["cwe_id"],
        severity=tp_row["severity"][:30] if tp_row["severity"] else "MEDIUM",
        file_path=file_path,
        line_range="see snippet",
        code=code,
    )
    assistant = (
        f"Verdict: {verdict}\n"
        f"Confidence: HIGH\n"
        f"Reasoning: {reasoning}\n"
        f"RealCWE: {real_cwe_value}\n"
        f"SuggestedFix: {sugg_fix}\n"
    )
    md = {
        "case_id": tp_row["cve_id"],
        "project_id": project_id,
        "claimed_cwe": tp_row["cwe_id"],
        "real_cwe": tp_row["cwe_id"] if verdict == "TRUE_POSITIVE" else "N/A",
        "verdict": verdict,
        "language": tp_row["language"].lower() if tp_row["language"] else "unknown",
        "tool": tool,
        "file_path": file_path,
        "code_hash": code_hash(code),
        "source": "cvefixes_v8_2",
        "severity": tp_row["severity"][:30] if tp_row["severity"] else "MEDIUM",
    }
    if fp_source:
        md["fp_source"] = fp_source
    return {
        "messages": [
            {"role": "system", "content": TRIAGE_SYSTEM},
            {"role": "user", "content": user},
            {"role": "assistant", "content": assistant},
        ],
        "metadata": md,
    }


def build_pair(
    tp_row: dict,
    fp_row: dict,
    fp_source: str,
    backend: str,
    model: str,
    rng: random.Random,
) -> list[dict]:
    """Build (TP, FP) pair. Both keep TP's claimed_cwe (= scanner's claim).

    For misclass FP we take fp_row.vulnerable_code (so length distribution
    matches TP and the structural shortcut is gone). For post-fix FP we take
    fp_row.fixed_code (longer because the fix added validation).
    """
    tool = rng.choice(SAST_TOOLS)
    fp_code = fp_row["fixed_code"] if fp_source == FP_SRC_POSTFIX else fp_row["vulnerable_code"]
    tp = make_example(
        code=tp_row["vulnerable_code"],
        verdict="TRUE_POSITIVE",
        reasoning=build_tp_reasoning(tp_row),
        real_cwe_value=tp_row["cwe_id"],
        sugg_fix=shorten_text(tp_row["commit_message"], 350) or "Apply the upstream patch.",
        tp_row=tp_row,
        tool=tool,
    )
    fp = make_example(
        code=fp_code,
        verdict="FALSE_POSITIVE",
        reasoning=build_fp_reasoning(
            tp_row["cwe_id"], tp_row["cwe_name"], fp_row, fp_source, fp_code, backend, model
        ),
        real_cwe_value="N/A",
        sugg_fix="N/A",
        tp_row=tp_row,
        tool=tool,
        fp_source=fp_source,
    )
    return [tp, fp]


# ---------------------------- Splits ----------------------------

def split_rows_by_project(
    rows: list[dict],
    train_frac: float, val_frac: float,
    test_balanced_frac: float, test_imbalanced_frac: float,
    seed: int,
) -> dict[str, list[dict]]:
    assert abs(train_frac + val_frac + test_balanced_frac + test_imbalanced_frac - 1.0) < 1e-6
    rng = random.Random(seed)
    projects = sorted({project_id_from_repo_url(r["repo_url"]) or r["cve_id"] for r in rows})
    rng.shuffle(projects)
    n = len(projects)
    n_train = int(n * train_frac)
    n_val = int(n * val_frac)
    n_test_b = int(n * test_balanced_frac)
    sets = {
        "train": set(projects[:n_train]),
        "val": set(projects[n_train:n_train + n_val]),
        "test_balanced": set(projects[n_train + n_val:n_train + n_val + n_test_b]),
        "test_imbalanced": set(projects[n_train + n_val + n_test_b:]),
    }
    bucket = defaultdict(list)
    for r in rows:
        pid = project_id_from_repo_url(r["repo_url"]) or r["cve_id"]
        for name, projset in sets.items():
            if pid in projset:
                bucket[name].append(r)
                break
    return dict(bucket)


def downsample_to_imbalanced(examples: list[dict], target_ratio: float, rng: random.Random) -> list[dict]:
    tps = [e for e in examples if e["metadata"]["verdict"] == "TRUE_POSITIVE"]
    fps = [e for e in examples if e["metadata"]["verdict"] == "FALSE_POSITIVE"]
    target_tps = max(1, int(len(fps) / target_ratio))
    if target_tps >= len(tps):
        return examples
    rng.shuffle(tps)
    return tps[:target_tps] + fps


# ---------------------------- I/O & main ----------------------------

def write_json(path: Path, data: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def summarise(name: str, data: list[dict]) -> None:
    if not data:
        log(f"  {name}: 0 examples (empty)")
        return
    verdicts = Counter(e["metadata"]["verdict"] for e in data)
    cwes = Counter(e["metadata"]["claimed_cwe"] for e in data)
    langs = Counter(e["metadata"]["language"] for e in data)
    fp_src = Counter(e["metadata"].get("fp_source", "n/a") for e in data
                     if e["metadata"]["verdict"] == "FALSE_POSITIVE")
    projects = len({e["metadata"]["project_id"] for e in data})
    log(f"  {name}: {len(data)} ex | {projects} projects | "
        f"TP={verdicts.get('TRUE_POSITIVE', 0)} FP={verdicts.get('FALSE_POSITIVE', 0)} "
        f"(FP src: {dict(fp_src)}) | "
        f"top CWE={list(cwes.most_common(5))} | langs={dict(langs.most_common(5))}")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Build v8.2 triage dataset with mixed FP sourcing")
    p.add_argument("--output-dir", required=True)
    p.add_argument("--hf-dataset", default="hitoshura25/cvefixes")
    p.add_argument("--hf-split", default="train")
    p.add_argument("--exclude-from", nargs="*", default=[
        "data/eval/eval_cvefixes_100.json",
        "data/eval/eval_crossvul_100.json",
        "data/eval/fresh_cves_60_detection.json",
        "data/train/train_v5b_train.json",
        "data/train/train_v5b_val.json",
    ])
    p.add_argument("--max-pairs", type=int, default=None)
    p.add_argument("--cap-per-cwe", type=int, default=400)
    p.add_argument("--teacher", choices=["none", "openai", "openrouter"], default="none")
    p.add_argument("--teacher-model", default="gpt-4o-2024-11-20")
    p.add_argument("--fp-post-fix-frac", type=float, default=0.2,
                   help="Fraction of FP examples sourced from post-fix code (rest = misclassified-CWE)")
    p.add_argument("--train-frac", type=float, default=0.70)
    p.add_argument("--val-frac", type=float, default=0.15)
    p.add_argument("--test-balanced-frac", type=float, default=0.075)
    p.add_argument("--test-imbalanced-frac", type=float, default=0.075)
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--dry-run", action="store_true")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    rng = random.Random(args.seed)

    log(f"Loading {args.hf_dataset}:{args.hf_split} ...")
    from datasets import load_dataset
    ds = load_dataset(args.hf_dataset, split=args.hf_split)
    log(f"  loaded {len(ds)} rows")

    log("Building exclusion hash set from prior eval/train files ...")
    excl_paths = [Path(p) for p in args.exclude_from]
    exclude = collect_exclusion_hashes(*excl_paths)

    cap = args.cap_per_cwe
    if args.dry_run:
        log("DRY RUN: using only first 200 rows for sanity check")
        ds = ds.select(range(min(200, len(ds))))
        cap = 5

    log("Filtering to web CWEs + web languages + valid code length ...")
    kept = filter_rows(ds, exclude, cap)
    if args.max_pairs is not None and len(kept) > args.max_pairs:
        rng.shuffle(kept)
        kept = kept[:args.max_pairs]
        log(f"  capped at {len(kept)} after --max-pairs")
    if not kept:
        log("ERROR: filter produced 0 pairs.")
        return

    log("Project-stratified split of ROWS (not examples) ...")
    split_rows = split_rows_by_project(
        kept, args.train_frac, args.val_frac,
        args.test_balanced_frac, args.test_imbalanced_frac, args.seed,
    )
    for name, rows in split_rows.items():
        log(f"  {name}: {len(rows)} rows, {len({project_id_from_repo_url(r['repo_url']) or r['cve_id'] for r in rows})} projects")

    log(f"Producing 2 triage examples per row | fp_post_fix_frac={args.fp_post_fix_frac} | "
        f"teacher={args.teacher}/{args.teacher_model}")

    t0 = time.time()
    out_by_split: dict[str, list[dict]] = {}
    fp_src_stats: dict[str, Counter] = {}
    total_rows_done = 0
    total_rows = sum(len(r) for r in split_rows.values())

    for split_name, rows in split_rows.items():
        # Build per-split pool keyed by CWE so misclass sampling stays in-split
        # (no leakage of FP source code into another split).
        pool_by_cwe: dict[str, list[int]] = defaultdict(list)
        for idx, r in enumerate(rows):
            pool_by_cwe[r["cwe_id"]].append(idx)
        all_cwes_in_split = list(pool_by_cwe.keys())

        ex_list: list[dict] = []
        src_counter: Counter = Counter()
        for i, row in enumerate(rows):
            use_postfix = rng.random() < args.fp_post_fix_frac
            if use_postfix:
                fp_row = row
                fp_source = FP_SRC_POSTFIX
            else:
                # misclass: random row with a DIFFERENT CWE, from the same split.
                other_cwes = [c for c in all_cwes_in_split if c != row["cwe_id"]]
                if other_cwes:
                    other_cwe = rng.choice(other_cwes)
                    fp_idx = rng.choice(pool_by_cwe[other_cwe])
                    fp_row = rows[fp_idx]
                    fp_source = FP_SRC_MISCLASS
                else:
                    fp_row = row
                    fp_source = FP_SRC_POSTFIX
            ex_list.extend(build_pair(row, fp_row, fp_source, args.teacher, args.teacher_model, rng))
            src_counter[fp_source] += 1

            total_rows_done += 1
            if total_rows_done % 100 == 0:
                elapsed = time.time() - t0
                rate = total_rows_done / elapsed
                eta = (total_rows - total_rows_done) / rate
                log(f"  [{total_rows_done}/{total_rows}] elapsed {elapsed:.0f}s, ETA {eta:.0f}s")

        out_by_split[split_name] = ex_list
        fp_src_stats[split_name] = src_counter

    log(f"  built {sum(len(v) for v in out_by_split.values())} examples in {time.time() - t0:.0f}s")
    log(f"  FP source mix per split: {dict({k: dict(v) for k, v in fp_src_stats.items()})}")

    # Downsample test_imbalanced to ~1:8 TP:FP
    imb = downsample_to_imbalanced(out_by_split.get("test_imbalanced", []),
                                   target_ratio=8.0, rng=rng)
    out_by_split["test_imbalanced"] = imb

    out_dir = Path(args.output_dir)
    for name in ("train", "val", "test_balanced", "test_imbalanced"):
        data = out_by_split.get(name, [])
        write_json(out_dir / f"triage_{name}.json", data)
        summarise(name, data)

    cfg = {
        "hf_dataset": args.hf_dataset, "hf_split": args.hf_split,
        "n_input_rows": len(ds), "n_kept_pairs": len(kept),
        "teacher": args.teacher, "teacher_model": args.teacher_model,
        "fp_post_fix_frac": args.fp_post_fix_frac,
        "split_fractions": {
            "train": args.train_frac, "val": args.val_frac,
            "test_balanced": args.test_balanced_frac, "test_imbalanced": args.test_imbalanced_frac,
        },
        "cap_per_cwe": args.cap_per_cwe,
        "exclude_from": [str(p) for p in excl_paths],
        "seed": args.seed, "dry_run": args.dry_run,
        "rows_per_split": {k: len(v) for k, v in split_rows.items()},
        "fp_source_mix_per_split": {k: dict(v) for k, v in fp_src_stats.items()},
    }
    write_json(out_dir / "build_config.json", [cfg])
    log(f"Wrote artefacts to {out_dir}")


if __name__ == "__main__":
    main()

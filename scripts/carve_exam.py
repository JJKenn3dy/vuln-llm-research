"""Carve SastBench into locked exam sets + hand-labeling scaffold.

Output structure (under --out-dir, default data/exam/):

  hand_label_scaffold.json   50 cases — scaffold with empty 'solvable_from_snippet'
                             and 'evidence_packet' columns for manual fill
  hand_label_cases.json      same 50 cases in full triage chat format
                             (used by scripts/sufficiency_probe.py)
  exam_a_in_scope_300.json   LOCKED in-scope final exam — sampled from val-558,
                             contaminated by ONE threshold-sweep aggregate
                             (the 2026-06-11 calibration MCC sweep producing
                             threshold 0.77). No per-case access by researcher.
  val_working_remainder.json the rest of val-558 — free use for diagnostics
  exam_b_finding_ids.json    Out-of-scope adjacent-zone exam (web-lang × non-12-CWE
                             plus 12-CWE × non-web-lang) — finding IDs from raw
                             SastBench, fetched separately. Skipped if no
                             --raw-sastbench provided.
  manifest.json              Per-file lock policy + contamination notes
  README.md                  Human-readable summary + researcher discipline

The split is stratified by ground-truth verdict so the imbalance of val-558
(~13% TP) is preserved in every output bucket.

Usage on pod (where val + raw sastbench live):
    python scripts/carve_exam.py \\
        --val /workspace/vuln-llm-research/data/eval/sastbench_v01_val558.json \\
        --test /workspace/vuln-llm-research/data/eval/sastbench_v01_subset250.json \\
        --raw-sastbench /workspace/data/sastbench/sastbench-v0.1.json \\
        --out-dir data/exam

Locally without raw sastbench (Exam-B selection deferred):
    python scripts/carve_exam.py \\
        --val data/eval/sastbench_v01_val558.json \\
        --out-dir data/exam
"""
from __future__ import annotations

import argparse
import json
import random
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


WEB_CWES = {
    "CWE-79", "CWE-89", "CWE-22", "CWE-78", "CWE-94", "CWE-352",
    "CWE-434", "CWE-502", "CWE-611", "CWE-798", "CWE-918", "CWE-787",
}
WEB_LANGS = {"PHP", "Python", "JavaScript", "TypeScript", "Java", "Ruby", "Go"}


def stratified_sample(cases: list[dict], n: int, seed: int,
                       key=lambda c: c["metadata"]["verdict"]
                       ) -> tuple[list[dict], list[dict]]:
    """Take n cases stratified by `key`. Returns (sampled, remaining).
    Quotas allocated proportionally and rounded to sum to n exactly.
    """
    rng = random.Random(seed)
    groups: dict[str, list[dict]] = {}
    for c in cases:
        groups.setdefault(key(c), []).append(c)
    for g in groups.values():
        rng.shuffle(g)

    total = sum(len(g) for g in groups.values())
    quotas = {k: round(n * len(g) / total) for k, g in groups.items()}
    # Adjust rounding drift
    while sum(quotas.values()) > n:
        donor = max(quotas, key=quotas.get)
        quotas[donor] -= 1
    while sum(quotas.values()) < n:
        recipient = min(quotas, key=lambda k: quotas[k] / max(1, len(groups[k])))
        quotas[recipient] += 1

    sampled = []
    sampled_ids: set[str] = set()
    for k, q in quotas.items():
        for c in groups[k][:q]:
            sampled.append(c)
            sampled_ids.add(str(c["metadata"]["case_id"]))
    remaining = [c for c in cases if str(c["metadata"]["case_id"]) not in sampled_ids]
    return sampled, remaining


def hand_label_scaffold_for(cases: list[dict]) -> list[dict]:
    out = []
    for c in cases:
        md = c["metadata"]
        user_msg = c["messages"][1]["content"]
        preview = user_msg if len(user_msg) <= 400 else user_msg[:400] + "..."
        out.append({
            "case_id": str(md["case_id"]),
            "project_id": md.get("project_id"),
            "claimed_cwe": md.get("claimed_cwe"),
            "language": md.get("language"),
            "file_path": md.get("file_path"),
            "line_range": md.get("line_range"),
            "ground_truth_verdict": md["verdict"],
            "user_message_preview": preview,
            # === FILL THESE MANUALLY ===
            "solvable_from_snippet": None,          # "yes" | "no" | "disputed"
            "your_verdict_with_full_context": None, # "TRUE_POSITIVE" | "FALSE_POSITIVE"
            "evidence_packet": "",                  # paste relevant imports/callers/sanitizer presence/etc.
            "evidence_packet_notes": "",            # free-text notes about your construction choices
            "comments": "",                         # any sanity comment about the case
        })
    return out


def exam_b_select(raw_path: Path | None,
                  already_used_ids: set[str]) -> dict | None:
    """Filter raw SastBench for adjacent-zone finding IDs."""
    if not raw_path or not raw_path.exists():
        return None
    data = json.loads(raw_path.read_text(encoding="utf-8"))
    web_lang_other_cwe: list[str] = []
    other_lang_web_cwe: list[str] = []
    for f in data:
        fid = str(f.get("finding_id"))
        if fid in already_used_ids:
            continue
        md = f.get("metadata", {}) or {}
        cwe = md.get("cwe_id")
        langs = md.get("languages") or []
        is_web_cwe = cwe in WEB_CWES
        is_web_lang = any(l in WEB_LANGS for l in langs)
        if is_web_lang and not is_web_cwe:
            web_lang_other_cwe.append(fid)
        elif not is_web_lang and is_web_cwe:
            other_lang_web_cwe.append(fid)
    return {
        "web_lang_nonweb_cwe": sorted(web_lang_other_cwe),
        "nonweb_lang_web_cwe": sorted(other_lang_web_cwe),
    }


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser()
    p.add_argument("--val", required=True, help="sastbench_v01_val558.json (in-scope working val)")
    p.add_argument("--test", default=None, help="sastbench_v01_subset250.json (excluded from Exam-B)")
    p.add_argument("--raw-sastbench", default=None, help="raw SastBench JSON for Exam-B selection")
    p.add_argument("--out-dir", required=True)
    p.add_argument("--hand-label-n", type=int, default=50)
    p.add_argument("--exam-a-n", type=int, default=300)
    p.add_argument("--seed", type=int, default=42)
    return p.parse_args()


def main() -> None:
    args = parse_args()
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    val = json.loads(Path(args.val).read_text(encoding="utf-8"))
    print(f"val: {len(val)} cases")

    if args.hand_label_n + args.exam_a_n >= len(val):
        raise SystemExit(f"hand_label_n+exam_a_n ({args.hand_label_n+args.exam_a_n}) "
                          f">= val size ({len(val)}); refusing to leave 0 working remainder")

    # Hand-label set first (researcher will inspect deeply -> NOT pristine for eval)
    hand_set, remaining = stratified_sample(val, args.hand_label_n, args.seed)
    # Exam-A from remaining (locked)
    exam_a, working = stratified_sample(remaining, args.exam_a_n, args.seed + 1)

    scaffold = hand_label_scaffold_for(hand_set)
    (out_dir / "hand_label_scaffold.json").write_text(
        json.dumps(scaffold, ensure_ascii=False, indent=2), encoding="utf-8")
    (out_dir / "hand_label_cases.json").write_text(
        json.dumps(hand_set, ensure_ascii=False, indent=2), encoding="utf-8")
    (out_dir / "exam_a_in_scope_300.json").write_text(
        json.dumps(exam_a, ensure_ascii=False, indent=2), encoding="utf-8")
    (out_dir / "val_working_remainder.json").write_text(
        json.dumps(working, ensure_ascii=False, indent=2), encoding="utf-8")

    # Exam-B
    used_ids: set[str] = {str(c["metadata"]["case_id"]) for c in val}
    if args.test and Path(args.test).exists():
        for c in json.loads(Path(args.test).read_text(encoding="utf-8")):
            used_ids.add(str(c["metadata"]["case_id"]))
    raw_path = Path(args.raw_sastbench) if args.raw_sastbench else None
    exam_b = exam_b_select(raw_path, used_ids)
    if exam_b is not None:
        (out_dir / "exam_b_finding_ids.json").write_text(
            json.dumps(exam_b, ensure_ascii=False, indent=2), encoding="utf-8")
        exam_b_summary = {k: len(v) for k, v in exam_b.items()}
        exam_b_status = "selected"
    else:
        (out_dir / "EXAM_B_TODO.md").write_text(
            "# Exam-B selection pending\n\n"
            "Re-run with `--raw-sastbench <path>` to materialise.\n"
            "The script writes IDs only, not code — fetch separately with "
            "src/data_prep/convert_sastbench_to_triage.py filtered to those IDs.\n",
            encoding="utf-8")
        exam_b_summary = None
        exam_b_status = "deferred"

    manifest = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "input": {
            "val": str(args.val),
            "val_n": len(val),
            "test": str(args.test) if args.test else None,
            "raw_sastbench": str(args.raw_sastbench) if args.raw_sastbench else None,
            "seed": args.seed,
        },
        "outputs": {
            "hand_label_scaffold.json": {
                "n": len(hand_set),
                "verdict_dist": dict(Counter(s["ground_truth_verdict"] for s in scaffold)),
                "purpose": "manual researcher inspection + sufficiency probe inputs",
                "contamination": "FULL — researcher reads every case, NOT pristine for any future eval",
                "allowed_readers": [
                    "scripts/sufficiency_probe.py",
                    "scripts/calibrate_judges.py (future)",
                    "human researcher (manual)",
                ],
            },
            "hand_label_cases.json": {
                "n": len(hand_set),
                "purpose": "full triage chat-format cases for probe arms (a)/(a')/(b)",
                "contamination": "same as scaffold",
            },
            "exam_a_in_scope_300.json": {
                "n": len(exam_a),
                "verdict_dist": dict(Counter(c["metadata"]["verdict"] for c in exam_a)),
                "purpose": "LOCKED in-scope final eval for v8.3",
                "contamination": "ONE threshold-sweep aggregate decision (val MCC=0.151 at thr=0.77, "
                                  "made 2026-06-11 in /workspace/runs/v8_2_calib/calibrated.json). "
                                  "No per-case inspection by researcher.",
                "lock_policy": (
                    "Never load from any diagnostic/sweep/analysis script before v8.3 final. "
                    "Allowed only in src/eval/v8_3_final_exam.py (to be written) for a SINGLE eval pass."
                ),
                "after_first_load": "becomes 'dirty', treat as val for v8.4 onward",
            },
            "val_working_remainder.json": {
                "n": len(working),
                "verdict_dist": dict(Counter(c["metadata"]["verdict"] for c in working)),
                "purpose": "free-use diagnostics, judge calibration, slice-and-dice",
                "contamination": "treat as 'dirty' for any final eval purpose",
            },
            "exam_b_finding_ids.json": {
                "status": exam_b_status,
                "counts": exam_b_summary,
                "purpose": "OUT-OF-SCOPE adjacent-zone exam (two axes of generalisation)",
                "filter_rules": (
                    "(language in WEB_LANGS AND cwe NOT in WEB_CWES) "
                    "OR (language NOT in WEB_LANGS AND cwe in WEB_CWES)"
                ),
                "lock_policy": "same as exam_a; never load until v8.3 final",
            },
        },
        "researcher_discipline": {
            "before_v8_3_final": [
                "hand_label_*.json: read freely",
                "val_working_remainder.json: read freely",
                "exam_a_in_scope_300.json: DO NOT LOAD",
                "exam_b_*.json: DO NOT LOAD",
            ],
            "at_v8_3_final": [
                "ONE eval pass on exam_a + exam_b through v8_3_final_exam.py",
                "Report numbers verbatim, no per-case re-inspection",
                "Both files become 'dirty' afterwards",
            ],
        },
    }
    (out_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")

    readme = f"""# Exam carve {manifest['created_at'][:10]}

Source: `{args.val}` (n={len(val)})
Seed: {args.seed}

## Splits

| File | n | Verdict dist | Lock |
|---|---|---|---|
| hand_label_scaffold.json | {len(hand_set)} | {dict(Counter(s['ground_truth_verdict'] for s in scaffold))} | NO (researcher reads) |
| exam_a_in_scope_300.json | {len(exam_a)} | {dict(Counter(c['metadata']['verdict'] for c in exam_a))} | YES until v8.3 final |
| val_working_remainder.json | {len(working)} | {dict(Counter(c['metadata']['verdict'] for c in working))} | NO |
| exam_b_finding_ids.json | {exam_b_summary} | n/a | YES until v8.3 final |

## Researcher discipline

**Before opening `exam_a_*.json` or `exam_b_*.json` in code, ask:
is this final v8.3 evaluation? Default = no. Only open for final pass.**

Full lock policy: `manifest.json`.
"""
    (out_dir / "README.md").write_text(readme, encoding="utf-8")

    print(f"hand_label: {len(hand_set)}  exam_a: {len(exam_a)}  working: {len(working)}  exam_b: {exam_b_status}")
    print(f"manifest: {out_dir / 'manifest.json'}")


if __name__ == "__main__":
    main()

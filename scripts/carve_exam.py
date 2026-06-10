"""Carve SastBench into locked exam sets + hand-labeling scaffold (gate-prep for v8.3).

Carve order matters: exam-A FIRST (most precious, locked), THEN hand-label
from remaining val pool, THEN working remainder. Don't reverse.

Sampling rules:
  - exam_a: PROPORTIONAL stratification on verdict (mirrors real ~13% TP rate
    in val-558 for honest evaluation distribution).
  - hand_label: BALANCED (default 25 TP + 25 FP). Real-world imbalance would
    leave probe with ~6 minority cases, BA/MCC unreliable. Hand-label is a
    diagnostic instrument, not a representative sample, so we trade balance
    for statistical power.

Output structure (under --out-dir, default data/exam/):

  exam_a_in_scope_300.json   LOCKED in-scope final exam — sampled from val-558,
                             contaminated by ONE threshold-sweep aggregate
                             (the 2026-06-11 calibration MCC sweep producing
                             threshold 0.77). No per-case access by researcher.
  hand_label_scaffold.json   N cases — TWO-PASS labeling scaffold (see Protocol)
  hand_label_cases.json      same N cases in full triage chat format
                             (used by scripts/sufficiency_probe.py)
  val_working_remainder.json the rest of val-558 — free use for diagnostics
  exam_b_finding_ids.json    Out-of-scope adjacent-zone exam IDs (skipped if no
                             --raw-sastbench).
  EVIDENCE_PACKET_PROTOCOL.md (co-located with data) — mechanical extraction
                             protocol researcher follows to avoid oracle bias
  manifest.json              Per-file lock policy + contamination notes
  README.md                  Human-readable summary + researcher discipline

## TWO-PASS hand labeling (avoid hindsight)

Pass 1 (snippet only, do NOT open repo):
  fill `solvable_from_snippet` ∈ {yes,no,disputed}
  fill `your_verdict_snippet_only` ∈ {TRUE_POSITIVE,FALSE_POSITIVE}
Pass 1 must be done for ALL N cases before any case enters Pass 2. Otherwise
hindsight from one case's repo bleeds into the next case's snippet impression.

Pass 2 (full repo, per case):
  fill `your_verdict_with_full_context`
  fill `evidence_packet` PER PROTOCOL (see EVIDENCE_PACKET_PROTOCOL.md)
  fill `evidence_packet_protocol_compliance` = true (or false + comments)
  if FP: fill `fp_cause_taxonomy`

## Evidence packet protocol (avoid oracle curation)

Hand-curated evidence biased toward the chosen verdict makes (b) arm measure
"context selected by an answer-knowing human", not "context an automatic
extractor could supply". Follow the deterministic protocol below; do not
add extras even if you "know" they prove the case.

Include in evidence_packet exactly:
  1. The entire enclosing function body of the snippet's line range.
  2. All imports / use / include / require statements from the top of the file.
  3. Up to 2 callers of the enclosing function found by repo-wide grep on the
     function name. Paste their snippets (function context, not whole files).
  4. All lines in this file that contain any of: sanitize, escape, validate,
     clean, encode, prepare, parametr, htmlspecial, strip, filter.

Nothing else. If a case truly cannot be packaged this way (e.g., vuln is in a
config file), set protocol_compliance=false and note the deviation in comments.

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

FP_CAUSE_TAXONOMY = [
    "sanitization_upstream",   # input sanitised before reaching this code
    "test_code",               # path is under tests/ or has test markers
    "dead_code",               # path is unreachable from any entry point
    "framework_protection",    # framework auto-escapes / validates (e.g. ORM)
    "pattern_mismatch",        # Semgrep rule too eager, code does not match
    "modernized_code",         # defensive code via newer API replacing old vuln pattern
    "mislabel",                # SastBench ground truth appears wrong
    "other",                   # specify in comments
]

EVIDENCE_PACKET_PROTOCOL_MD = """# Evidence packet protocol

Hand-curated evidence biased toward the chosen verdict turns the probe (b) arm
into "context selected by an answer-knowing human" rather than "context an
automatic extractor could supply". This invalidates the gate decision because
tree-sitter MVP later cannot reproduce the result.

## Mechanical protocol — follow strictly

Include in the `evidence_packet` field exactly these elements, in this order:

1. **Enclosing function body** — the entire function containing the snippet
   line range, not just the snippet lines.
2. **File-level imports** — all import / use / include / require statements
   from the top of the file.
3. **Up to 2 callers** — find with repo-wide grep on the function name (or
   language equivalent). Paste the enclosing function context of each caller,
   not whole files.
4. **Sanitizer-keyword lines** — all lines in this same file that contain any
   of: `sanitize`, `escape`, `validate`, `clean`, `encode`, `prepare`,
   `parametr` (matches `parametrize`, `parameterized`, etc.), `htmlspecial`,
   `strip`, `filter`.

That's the entire menu. Do **not** include:
- Other files (except for the 2 callers' function context)
- Tests
- Documentation
- README sections
- Lines that you "know" prove the verdict but do not match the keyword set
- Anything else, however helpful it seems

## Exceptions

If the case genuinely cannot be packaged this way (e.g., the vulnerability is in
a configuration file, the snippet is not inside a function, the language has no
imports concept), set `evidence_packet_protocol_compliance = false` and note
the deviation in `comments`. These cases are excluded from the strict (b) arm
metric and tallied separately.

## Why so strict

The (b) arm answers the question: "does evidence packet, as an automatic
extractor would deliver it, change frontier's behaviour?" If a human curates,
the answer is yes by construction. The strict protocol simulates the extractor.
"""


def proportional_stratified_sample(cases: list[dict], n: int, seed: int,
                                     key=lambda c: c["metadata"]["verdict"]
                                     ) -> tuple[list[dict], list[dict]]:
    """Sample n cases stratified by `key` with quotas proportional to class sizes.
    Used for exam_a (preserves real ~13% TP rate for honest evaluation distribution).
    """
    rng = random.Random(seed)
    groups: dict[str, list[dict]] = {}
    for c in cases:
        groups.setdefault(key(c), []).append(c)
    for g in groups.values():
        rng.shuffle(g)

    total = sum(len(g) for g in groups.values())
    quotas = {k: round(n * len(g) / total) for k, g in groups.items()}
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


def balanced_sample(cases: list[dict], n_per_class: int, seed: int,
                     key=lambda c: c["metadata"]["verdict"]
                     ) -> tuple[list[dict], list[dict]]:
    """Take exactly n_per_class cases from each class. Used for hand-label set
    where statistical power on minority class matters more than distribution
    faithfulness. Raises ValueError if any class has fewer than n_per_class.
    """
    rng = random.Random(seed)
    groups: dict[str, list[dict]] = {}
    for c in cases:
        groups.setdefault(key(c), []).append(c)
    for g in groups.values():
        rng.shuffle(g)

    for k, g in groups.items():
        if len(g) < n_per_class:
            raise ValueError(
                f"class {k} has {len(g)} cases, need {n_per_class}. "
                f"Either lower --hand-label-per-class or expand input pool."
            )

    sampled = []
    sampled_ids: set[str] = set()
    for k, g in groups.items():
        for c in g[:n_per_class]:
            sampled.append(c)
            sampled_ids.add(str(c["metadata"]["case_id"]))
    remaining = [c for c in cases if str(c["metadata"]["case_id"]) not in sampled_ids]
    return sampled, remaining


def hand_label_scaffold_for(cases: list[dict]) -> list[dict]:
    out = []
    for c in cases:
        md = c["metadata"]
        user_msg = c["messages"][1]["content"]
        preview = user_msg if len(user_msg) <= 600 else user_msg[:600] + "..."
        out.append({
            "case_id": str(md["case_id"]),
            "project_id": md.get("project_id"),
            "claimed_cwe": md.get("claimed_cwe"),
            "language": md.get("language"),
            "file_path": md.get("file_path"),
            "line_range": md.get("line_range"),
            "ground_truth_verdict": md["verdict"],
            "user_message_preview": preview,

            # === PASS 1: fill these looking ONLY at user_message_preview above ===
            # Do NOT open the repository yet. Complete pass 1 for ALL cases before
            # moving to pass 2 — otherwise hindsight from earlier repo lookups
            # bleeds into your impression of later snippets.
            "solvable_from_snippet": None,        # "yes" | "no" | "disputed"
            "your_verdict_snippet_only": None,    # "TRUE_POSITIVE" | "FALSE_POSITIVE"

            # === PASS 2: fill these AFTER opening the repository for this case ===
            "your_verdict_with_full_context": None,  # "TRUE_POSITIVE" | "FALSE_POSITIVE"
            "evidence_packet": "",                   # follow EVIDENCE_PACKET_PROTOCOL.md
            "evidence_packet_protocol_compliance": None,  # true | false
            # Fill only if your_verdict_with_full_context == "FALSE_POSITIVE":
            "fp_cause_taxonomy": None,            # one of: sanitization_upstream, test_code,
                                                  #         dead_code, framework_protection,
                                                  #         pattern_mismatch, modernized_code,
                                                  #         mislabel, other
            "comments": "",                       # any sanity note, protocol deviation, etc.
        })
    return out


def exam_b_select(raw_path: Path | None,
                  already_used_ids: set[str]) -> dict | None:
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
    p.add_argument("--val", required=True, help="sastbench_v01_val558.json")
    p.add_argument("--test", default=None, help="sastbench_v01_subset250.json (excluded from Exam-B)")
    p.add_argument("--raw-sastbench", default=None, help="raw SastBench JSON for Exam-B selection")
    p.add_argument("--out-dir", required=True)
    p.add_argument("--exam-a-n", type=int, default=300, help="proportional, mirrors real distribution")
    p.add_argument("--hand-label-per-class", type=int, default=25,
                   help="balanced; total hand-label = 2 * this")
    p.add_argument("--seed", type=int, default=42)
    return p.parse_args()


def main() -> None:
    args = parse_args()
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    val = json.loads(Path(args.val).read_text(encoding="utf-8"))
    print(f"val: {len(val)} cases")
    val_dist = Counter(c["metadata"]["verdict"] for c in val)
    print(f"val verdict dist: {dict(val_dist)}")

    hand_label_total = 2 * args.hand_label_per_class
    if args.exam_a_n + hand_label_total >= len(val):
        raise SystemExit(
            f"exam_a_n + hand_label_total ({args.exam_a_n}+{hand_label_total}) "
            f">= val size ({len(val)}); refusing — would leave zero working remainder"
        )

    # Carve order: exam-A FIRST (most precious), THEN hand-label from remainder.
    exam_a, post_exam_pool = proportional_stratified_sample(
        val, args.exam_a_n, args.seed)
    print(f"exam_a: {len(exam_a)} (proportional) → "
          f"{dict(Counter(c['metadata']['verdict'] for c in exam_a))}")

    hand_set, working = balanced_sample(
        post_exam_pool, args.hand_label_per_class, args.seed + 1)
    print(f"hand_label: {len(hand_set)} (balanced) → "
          f"{dict(Counter(c['metadata']['verdict'] for c in hand_set))}")
    print(f"working_remainder: {len(working)}")

    # Emit protocol document co-located with data
    (out_dir / "EVIDENCE_PACKET_PROTOCOL.md").write_text(
        EVIDENCE_PACKET_PROTOCOL_MD, encoding="utf-8")

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
            "Re-run with `--raw-sastbench <path>` to materialise.\n",
            encoding="utf-8")
        exam_b_summary = None
        exam_b_status = "deferred"

    manifest = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "input": {
            "val": str(args.val),
            "val_n": len(val),
            "val_verdict_dist": dict(val_dist),
            "test": str(args.test) if args.test else None,
            "raw_sastbench": str(args.raw_sastbench) if args.raw_sastbench else None,
            "seed": args.seed,
        },
        "carve_order": [
            "1. exam_a (proportional stratification, locks first)",
            "2. hand_label (balanced; from post-exam pool, NOT from full val)",
            "3. working_remainder (the rest)",
            "4. exam_b (independent of val; from raw SastBench if available)",
        ],
        "outputs": {
            "exam_a_in_scope_300.json": {
                "n": len(exam_a),
                "sampling": "proportional stratification on verdict (mirrors val ~13% TP rate)",
                "verdict_dist": dict(Counter(c["metadata"]["verdict"] for c in exam_a)),
                "purpose": "LOCKED in-scope final eval for v8.3",
                "contamination": "ONE threshold-sweep aggregate decision (val MCC=0.151 at thr=0.77, "
                                  "made 2026-06-11 in /workspace/runs/v8_2_calib/calibrated.json). "
                                  "No per-case inspection by researcher.",
                "lock_policy": "Never load from any diagnostic / sweep / analysis script before v8.3 final.",
                "after_first_load": "becomes 'dirty', treat as val for v8.4 onward",
            },
            "hand_label_scaffold.json": {
                "n": len(hand_set),
                "sampling": f"balanced ({args.hand_label_per_class} per verdict class)",
                "verdict_dist": dict(Counter(s["ground_truth_verdict"] for s in scaffold)),
                "purpose": "two-pass manual labeling + sufficiency probe input + judge calibration",
                "contamination": "FULL — researcher reads every case, NOT pristine for any future eval",
                "labeling_protocol": "see EVIDENCE_PACKET_PROTOCOL.md and the per-case scaffold fields",
            },
            "hand_label_cases.json": {
                "n": len(hand_set),
                "purpose": "full triage chat-format cases for probe arms (a)/(a')/(b)",
            },
            "val_working_remainder.json": {
                "n": len(working),
                "verdict_dist": dict(Counter(c["metadata"]["verdict"] for c in working)),
                "purpose": "free-use diagnostics, judge calibration, slicing",
            },
            "exam_b_finding_ids.json": {
                "status": exam_b_status,
                "counts": exam_b_summary,
                "purpose": "OUT-OF-SCOPE adjacent-zone exam (two axes of generalisation)",
                "lock_policy": "same as exam_a; never load until v8.3 final",
            },
            "EVIDENCE_PACKET_PROTOCOL.md": {
                "purpose": "mechanical extraction protocol for the (b) arm of sufficiency probe; "
                           "avoid oracle bias from researcher seeing the answer first"
            },
        },
        "fp_cause_taxonomy_choices": FP_CAUSE_TAXONOMY,
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

| File | n | Sampling | Verdict dist | Lock |
|---|---|---|---|---|
| exam_a_in_scope_300.json | {len(exam_a)} | proportional | {dict(Counter(c['metadata']['verdict'] for c in exam_a))} | YES until v8.3 final |
| hand_label_scaffold.json | {len(hand_set)} | balanced {args.hand_label_per_class}+{args.hand_label_per_class} | {dict(Counter(s['ground_truth_verdict'] for s in scaffold))} | NO (researcher reads) |
| val_working_remainder.json | {len(working)} | the rest | {dict(Counter(c['metadata']['verdict'] for c in working))} | NO |
| exam_b_finding_ids.json | {exam_b_summary} | filter rule | n/a | YES until v8.3 final |

## Two-pass labeling

1. **Pass 1** (snippet only, do NOT open repo): fill `solvable_from_snippet`
   and `your_verdict_snippet_only` for ALL {len(hand_set)} cases.
2. **Pass 2** (full repo, per case): fill `your_verdict_with_full_context`,
   `evidence_packet` per `EVIDENCE_PACKET_PROTOCOL.md`,
   `evidence_packet_protocol_compliance`, and if FP also `fp_cause_taxonomy`.

`your_verdict_snippet_only` is the **human-on-snippet baseline** for the
sufficiency probe — a sixth arm that costs zero API calls.

## Researcher discipline

Before opening `exam_a_*.json` or `exam_b_*.json` in code, ask:
"is this final v8.3 evaluation, or am I about to leak the exam?"
Default = leak; only open for final pass.

Full lock policy: `manifest.json`.
"""
    (out_dir / "README.md").write_text(readme, encoding="utf-8")

    print(f"\nexam_a: {len(exam_a)}  hand_label: {len(hand_set)}  "
          f"working: {len(working)}  exam_b: {exam_b_status}")
    print(f"manifest: {out_dir / 'manifest.json'}")
    print(f"protocol: {out_dir / 'EVIDENCE_PACKET_PROTOCOL.md'}")


if __name__ == "__main__":
    main()

"""Compare AI Pass 1 labels to SastBench ground truth.

Outputs:
  - Overall agreement (Pass 1 verdict matches SastBench)
  - Agreement by self-stated confidence (HIGH/MEDIUM/LOW)
  - Agreement by self-stated solvability (yes/no/partial)
  - Sufficiency probe: AI on snippet alone, conditioned on solvability claim
  - Contested cases (high-confidence Pass 1 disagrees with SastBench)
  - Cases marked solvable_from_snippet=yes that AI got wrong (SastBench-trust check)

This is the "Pass 1 only" report. Pass 2 (full-repo WebFetch) layered on top
in a follow-up script for contested cases.
"""
from __future__ import annotations

import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")


def main() -> None:
    repo = Path(__file__).resolve().parent.parent
    labels = [json.loads(l) for l in (repo / "data/exam/ai_pass1_labels.jsonl").read_text(encoding="utf-8").splitlines()]
    gt_map = json.loads((repo / "data/exam/hand_label_case_id_map.json").read_text(encoding="utf-8"))

    print(f"Pass 1 labels loaded: {len(labels)}")
    print(f"Ground-truth map entries: {len(gt_map)}")

    # Join
    merged = []
    for lab in labels:
        bid = lab["blind_id"]
        gt = gt_map.get(bid)
        if gt is None:
            print(f"WARN: no ground-truth for {bid}")
            continue
        merged.append({
            **lab,
            "ground_truth": gt["ground_truth_verdict"],
            "original_case_id": gt["original_case_id"],
        })

    # Overall agreement
    agree = sum(1 for m in merged if m["verdict_pass1"] == m["ground_truth"])
    print(f"\nOverall Pass 1 agreement with SastBench: {agree}/{len(merged)} = {agree/len(merged):.3f}")

    # Confusion
    cm = Counter()
    for m in merged:
        cm[(m["ground_truth"], m["verdict_pass1"])] += 1
    print("\nConfusion (ground_truth -> predicted):")
    print(f"  TP correctly TP: {cm.get(('TRUE_POSITIVE','TRUE_POSITIVE'),0)}")
    print(f"  TP called FP (false neg): {cm.get(('TRUE_POSITIVE','FALSE_POSITIVE'),0)}")
    print(f"  FP correctly FP: {cm.get(('FALSE_POSITIVE','FALSE_POSITIVE'),0)}")
    print(f"  FP called TP (false alarm): {cm.get(('FALSE_POSITIVE','TRUE_POSITIVE'),0)}")

    # By confidence
    print("\nAgreement by self-stated confidence:")
    by_conf = defaultdict(lambda: [0, 0])
    for m in merged:
        c = m["confidence_pass1"]
        by_conf[c][1] += 1
        if m["verdict_pass1"] == m["ground_truth"]:
            by_conf[c][0] += 1
    for c in ("HIGH", "MEDIUM", "LOW"):
        a, n = by_conf[c]
        if n:
            print(f"  {c}: {a}/{n} = {a/n:.3f}")

    # By solvability
    print("\nAgreement by self-stated solvable_from_snippet:")
    by_solv = defaultdict(lambda: [0, 0])
    for m in merged:
        s = m["solvable_from_snippet"]
        by_solv[s][1] += 1
        if m["verdict_pass1"] == m["ground_truth"]:
            by_solv[s][0] += 1
    for s in ("yes", "partial", "no"):
        a, n = by_solv[s]
        if n:
            print(f"  {s}: {a}/{n} = {a/n:.3f}")

    # Contested HIGH-confidence cases
    print("\nContested (Pass 1 HIGH confidence disagrees with SastBench):")
    contested_high = [m for m in merged if m["confidence_pass1"] == "HIGH" and m["verdict_pass1"] != m["ground_truth"]]
    for m in contested_high:
        print(f"  {m['blind_id']} ({m['original_case_id']})")
        print(f"    SastBench: {m['ground_truth']}  AI: {m['verdict_pass1']}")
        print(f"    {m['reasoning_pass1'][:200]}")

    print(f"\n  Total HIGH-confidence contested: {len(contested_high)}")

    # All disagreements
    print(f"\nAll disagreements ({sum(1 for m in merged if m['verdict_pass1'] != m['ground_truth'])}):")
    for m in merged:
        if m["verdict_pass1"] != m["ground_truth"]:
            print(f"  {m['blind_id']} ({m['original_case_id']}) [conf {m['confidence_pass1']}, solvable {m['solvable_from_snippet']}]: SB={m['ground_truth']} AI={m['verdict_pass1']}")

    # Dump merged for downstream
    out = repo / "data/exam/ai_pass1_vs_groundtruth.json"
    out.write_text(json.dumps(merged, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\nWrote {out}")


if __name__ == "__main__":
    main()

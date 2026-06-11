"""Build a 10-case eval file (TRIAGE chat format) for the contested HIGH-confidence
hand-label cases. Output is consumable by `src.eval.run_triage_eval`.

Input:
  data/exam/ai_pass1_vs_groundtruth.json (merged Pass 1 + ground truth)
  data/exam/hand_label_cases.json (full triage chat-format cases)

Output:
  data/exam/adjudication_10.json
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")


def main() -> None:
    repo = Path(__file__).resolve().parent.parent
    merged = json.loads((repo / "data/exam/ai_pass1_vs_groundtruth.json").read_text(encoding="utf-8"))
    cases = json.loads((repo / "data/exam/hand_label_cases.json").read_text(encoding="utf-8"))

    cases_by_id = {c["metadata"]["case_id"]: c for c in cases}

    contested_high = [
        m for m in merged
        if m["confidence_pass1"] == "HIGH" and m["verdict_pass1"] != m["ground_truth"]
    ]
    print(f"Found {len(contested_high)} HIGH-confidence disagreements")

    out = []
    for m in contested_high:
        orig = m["original_case_id"]
        case = cases_by_id.get(orig)
        if case is None:
            print(f"WARN: no case for {orig}")
            continue
        # Strip assistant message (ground truth) so eval is clean
        new_case = {
            "messages": case["messages"][:2],
            "metadata": case["metadata"],
        }
        out.append(new_case)

    out_path = repo / "data/exam/adjudication_10.json"
    out_path.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"wrote {out_path}  ({len(out)} cases)")

    # Save the AI verdicts mapping for the adjudication compute step
    ai_map = {
        m["original_case_id"]: {
            "blind_id": m["blind_id"],
            "ai_verdict": m["verdict_pass1"],
            "ai_confidence": m["confidence_pass1"],
            "sastbench_verdict": m["ground_truth"],
            "ai_reasoning_preview": m["reasoning_pass1"][:200],
        }
        for m in contested_high
    }
    map_path = repo / "data/exam/adjudication_10_ai_map.json"
    map_path.write_text(json.dumps(ai_map, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"wrote {map_path}")


if __name__ == "__main__":
    main()

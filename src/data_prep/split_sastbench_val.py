"""Split SastBench joint subset into honest val + test by excluding test case_ids.

Used for honest threshold calibration on v8.2 SastBench eval:
  - test  = sastbench_v01_subset250.json (250 cases, what v8.2 was evaluated on)
  - val   = sastbench_v01_joint.json minus those 250 (~558 cases)
  - both sets share the same FP distribution (real Semgrep findings, web CWEs)
    but have no case overlap, so a threshold tuned on val is honest for test.

Usage:
    python -m src.data_prep.split_sastbench_val \\
        --joint /workspace/data/eval/sastbench_v01_joint.json \\
        --exclude data/eval/sastbench_v01_subset250.json \\
        --output /workspace/data/eval/sastbench_v01_val558.json
"""
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Build held-out SastBench val by excluding test case_ids")
    p.add_argument("--joint", required=True, help="Full SastBench joint subset (e.g. 808 cases)")
    p.add_argument("--exclude", required=True, help="Test subset to exclude (e.g. 250 cases)")
    p.add_argument("--output", required=True, help="Where to write val cases")
    return p.parse_args()


def case_ids(cases: list[dict]) -> set[str]:
    return {str(c.get("metadata", {}).get("case_id")) for c in cases}


def main() -> None:
    args = parse_args()
    joint = json.loads(Path(args.joint).read_text(encoding="utf-8"))
    exclude = json.loads(Path(args.exclude).read_text(encoding="utf-8"))

    excl_ids = case_ids(exclude)
    val = [c for c in joint if str(c.get("metadata", {}).get("case_id")) not in excl_ids]

    print(f"joint={len(joint)} exclude={len(exclude)} val={len(val)}")
    if len(val) + len(exclude) != len(joint):
        overlap = len(joint) - len(val) - len(exclude) + len(set(case_ids(joint)) & excl_ids)
        print(f"  note: {overlap} cases in joint not present in exclude (expected if exclude is a strict subset)")

    verdicts = Counter(c["metadata"]["verdict"] for c in val)
    print(f"val verdicts: TP={verdicts.get('TRUE_POSITIVE', 0)} FP={verdicts.get('FALSE_POSITIVE', 0)}")

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text(json.dumps(val, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"wrote {len(val)} -> {args.output}")


if __name__ == "__main__":
    main()

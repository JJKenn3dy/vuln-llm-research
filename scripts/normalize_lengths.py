"""Normalise code lengths in a triage dataset to neutralise the FP-longer-than-TP
shortcut.

After running prepare_cvefixes_triage.py we see FP code is systematically
1.4-1.8x longer than TP code because post-fix versions add validation /
sanitisation / escape calls. A shallow shortcut MLP scores F1=0.69 on this,
which means a real model is likely to learn "longer code => FP" instead of
the pre/post semantic difference.

This script post-processes the prepared JSON files in place:
  - Pull the code out of the user message
  - Truncate to first N characters (head-only — defensive patterns are
    almost always near the start of the function)
  - Re-insert into the user message

Pairs (TP from vuln_code, FP from fix_code) keep their original linkage; we
just clip both to the same budget.

Usage:
    python scripts/normalize_lengths.py \\
        --dir /workspace/data/train/triage_v8_2 \\
        --max-chars 1200
"""
from __future__ import annotations

import argparse
import json
import re
import statistics
from collections import Counter
from pathlib import Path


CODE_BLOCK_RE = re.compile(r"(Code:\s*\n)(.*?)$", re.DOTALL)


def truncate_code_in_user_msg(user_msg: str, max_chars: int) -> tuple[str, int, int]:
    m = CODE_BLOCK_RE.search(user_msg)
    if not m:
        return user_msg, 0, 0
    code = m.group(2).rstrip()
    if len(code) <= max_chars:
        return user_msg, len(code), len(code)
    truncated = code[:max_chars].rstrip() + "\n// ... truncated for length normalisation"
    new_msg = user_msg[:m.start(2)] + truncated
    return new_msg, len(code), len(truncated)


def normalise_file(path: Path, max_chars: int) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    before, after, verdicts = [], [], []
    for entry in data:
        msgs = entry["messages"]
        new_user, orig_len, new_len = truncate_code_in_user_msg(msgs[1]["content"], max_chars)
        msgs[1]["content"] = new_user
        before.append(orig_len)
        after.append(new_len)
        verdicts.append(entry.get("metadata", {}).get("verdict", "?"))
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

    def stats(lens, mask):
        sub = [l for l, m in zip(lens, mask) if m]
        if not sub:
            return {"n": 0}
        return {
            "n": len(sub),
            "mean": round(statistics.mean(sub), 1),
            "median": round(statistics.median(sub), 1),
            "max": max(sub),
        }

    tp_mask = [v == "TRUE_POSITIVE" for v in verdicts]
    fp_mask = [v == "FALSE_POSITIVE" for v in verdicts]
    return {
        "file": str(path),
        "n_total": len(data),
        "before_TP": stats(before, tp_mask),
        "before_FP": stats(before, fp_mask),
        "after_TP": stats(after, tp_mask),
        "after_FP": stats(after, fp_mask),
        "n_truncated_TP": sum(1 for l, m in zip(before, tp_mask) if m and l > max_chars),
        "n_truncated_FP": sum(1 for l, m in zip(before, fp_mask) if m and l > max_chars),
    }


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Truncate code in triage JSONs to neutralise length shortcut")
    p.add_argument("--dir", required=True, help="Directory containing triage_{train,val,test_balanced,test_imbalanced}.json")
    p.add_argument("--max-chars", type=int, default=1200)
    return p.parse_args()


def main() -> None:
    args = parse_args()
    d = Path(args.dir)
    files = ["triage_train.json", "triage_val.json", "triage_test_balanced.json", "triage_test_imbalanced.json"]
    for fname in files:
        path = d / fname
        if not path.exists():
            print(f"skip {fname}: not found")
            continue
        rep = normalise_file(path, args.max_chars)
        print(f"\n=== {fname} ===")
        print(f"  total={rep['n_total']} | "
              f"truncated TP={rep['n_truncated_TP']} FP={rep['n_truncated_FP']}")
        print(f"  BEFORE: TP {rep['before_TP']}, FP {rep['before_FP']}")
        print(f"  AFTER:  TP {rep['after_TP']}, FP {rep['after_FP']}")


if __name__ == "__main__":
    main()

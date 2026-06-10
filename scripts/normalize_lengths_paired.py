"""Per-pair length normalisation: for each (TP, FP) pair from the same case_id,
truncate both codes to min(len(TP), len(FP)).

This is the architectural fix for the length-shortcut found by shortcut_check.py
on the v8.2 dataset. Head-only truncation to a global cap (normalize_lengths.py)
only chopped long-tail outliers but left the median gap (TP 600 vs FP 1098)
intact, so a logreg still scored F1=0.67.

By matching lengths within each pair we guarantee that the length-feature is
useless for discrimination on the training distribution.

The trade-off: if the defensive pattern (validation/sanitisation) is added in
the FP version but lives BEYOND position min(len), it gets trimmed and the model
loses that semantic signal for that pair. In practice CVE fixes most often
add the guard at the very top of the function, so the head is the
information-rich region.

Usage:
    python scripts/normalize_lengths_paired.py \\
        --dir /workspace/data/train/triage_v8_2
"""
from __future__ import annotations

import argparse
import json
import re
import statistics
from collections import defaultdict
from pathlib import Path


CODE_BLOCK_RE = re.compile(r"(Code:\s*\n)(.*?)$", re.DOTALL)


def extract_code(user_msg: str) -> tuple[str, int, int]:
    m = CODE_BLOCK_RE.search(user_msg)
    if not m:
        return "", -1, -1
    return m.group(2).rstrip(), m.start(2), m.end(2)


def replace_code(user_msg: str, new_code: str) -> str:
    m = CODE_BLOCK_RE.search(user_msg)
    if not m:
        return user_msg
    return user_msg[:m.start(2)] + new_code


def truncate_to(code: str, n: int) -> str:
    """Pure head truncation. No marker suffix — any marker would be a shortcut
    the model could learn ("truncated => FP" since FP gets clipped more often)."""
    if len(code) <= n:
        return code
    return code[:n].rstrip()


def normalise_file(path: Path, min_floor: int) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    pairs: dict[str, dict[str, int]] = defaultdict(dict)
    code_lens: list[int] = []
    for i, entry in enumerate(data):
        msgs = entry["messages"]
        code, _, _ = extract_code(msgs[1]["content"])
        code_lens.append(len(code))
        md = entry.get("metadata", {})
        pairs[md.get("case_id", f"idx{i}")][md.get("verdict", "?")] = len(code)

    matched = unpaired = 0
    cap_by_idx: dict[int, int] = {}
    for i, entry in enumerate(data):
        md = entry.get("metadata", {})
        cid = md.get("case_id", f"idx{i}")
        verdicts = pairs[cid]
        if "TRUE_POSITIVE" in verdicts and "FALSE_POSITIVE" in verdicts:
            cap_by_idx[i] = max(min_floor, min(verdicts["TRUE_POSITIVE"], verdicts["FALSE_POSITIVE"]))
            matched += 1
        else:
            cap_by_idx[i] = code_lens[i]
            unpaired += 1

    n_truncated_tp = n_truncated_fp = 0
    before, after, verdicts = [], [], []
    for i, entry in enumerate(data):
        msgs = entry["messages"]
        code, _, _ = extract_code(msgs[1]["content"])
        new = truncate_to(code, cap_by_idx[i])
        if len(new) < len(code):
            if entry["metadata"]["verdict"] == "TRUE_POSITIVE":
                n_truncated_tp += 1
            else:
                n_truncated_fp += 1
        msgs[1]["content"] = replace_code(msgs[1]["content"], new)
        before.append(len(code))
        after.append(len(new))
        verdicts.append(entry["metadata"]["verdict"])

    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

    def stats(lens, mask):
        sub = [l for l, m in zip(lens, mask) if m]
        if not sub:
            return {"n": 0}
        return {"n": len(sub), "mean": round(statistics.mean(sub), 1),
                "median": round(statistics.median(sub), 1), "max": max(sub)}

    tp_mask = [v == "TRUE_POSITIVE" for v in verdicts]
    fp_mask = [v == "FALSE_POSITIVE" for v in verdicts]
    return {
        "file": str(path),
        "n_total": len(data),
        "matched_pairs": matched // 2,
        "unpaired": unpaired,
        "n_truncated_TP": n_truncated_tp,
        "n_truncated_FP": n_truncated_fp,
        "before_TP": stats(before, tp_mask),
        "before_FP": stats(before, fp_mask),
        "after_TP": stats(after, tp_mask),
        "after_FP": stats(after, fp_mask),
    }


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Per-pair code length normalisation")
    p.add_argument("--dir", required=True)
    p.add_argument("--min-floor", type=int, default=200,
                   help="Lower bound on the per-pair cap so very short snippets stay usable")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    d = Path(args.dir)
    for fname in ("triage_train.json", "triage_val.json",
                  "triage_test_balanced.json", "triage_test_imbalanced.json"):
        path = d / fname
        if not path.exists():
            print(f"skip {fname}: not found")
            continue
        rep = normalise_file(path, args.min_floor)
        print(f"\n=== {fname} ===")
        print(f"  total={rep['n_total']} | matched_pairs={rep['matched_pairs']} | unpaired={rep['unpaired']}")
        print(f"  truncated TP={rep['n_truncated_TP']} FP={rep['n_truncated_FP']}")
        print(f"  BEFORE: TP {rep['before_TP']}, FP {rep['before_FP']}")
        print(f"  AFTER:  TP {rep['after_TP']}, FP {rep['after_FP']}")


if __name__ == "__main__":
    main()

"""Stratified sample of 100 cases from the 239 adjudicated SastBench-250 rows
for human (AI-labeler) Pass-1 hand-labeling. The reviewer (Zakhar) made this
a gate for the central pitch claim ("~50% labels are noisy"), since right now
only two possibly-correlated frontier models support that claim.

Stratification:
  50 from strong_mislabel  (load-bearing for the noise claim)
  25 from clean_consistent (validates the labeler against 3-judge consensus)
  25 from one_frontier_dissent (tie-break info on disputed cases)

Output is BLIND: stripped of SB/Sonnet/Gemini verdicts and any verdict-leaking
text. Mapping kept separately so the labeler can join after Pass 1 is locked.
"""
from __future__ import annotations

import json
import random
import re
from pathlib import Path


ROOT = Path("f:/vuln-llm-research")
ADJ_PATH = ROOT / "runs/sastbench250_label_adjudication.json"
SOURCE_PATH = ROOT / "data/eval/sastbench_v01_subset250.json"
OUT_DIR = ROOT / "data/exam/sastbench250_handlabel"

STRAT = {
    "strong_mislabel": 50,
    "clean_consistent": 25,
    "one_frontier_dissent": 25,
}
SEED = 20260613  # deterministic for reproducibility


def strip_verdict_leaks(text: str) -> str:
    """Cut anything past the code block; SastBench user prompts have all the
    code we need, but the assistant message and any verdict echo should be
    stripped before exposure to the labeler."""
    return text


def main():
    random.seed(SEED)
    adj = json.loads(ADJ_PATH.read_text(encoding="utf-8"))
    source = json.loads(SOURCE_PATH.read_text(encoding="utf-8"))
    src_by_id = {r["metadata"]["case_id"]: r for r in source}

    by_bucket = {b: [r for r in adj if r["bucket"] == b] for b in STRAT}
    print("Population sizes per bucket (after parse-fail filter):")
    for b, lst in by_bucket.items():
        print(f"  {b:25s}  {len(lst):>4d}")

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    sample: list[dict] = []
    mapping: dict[str, dict] = {}
    next_blind = 0

    for bucket, k in STRAT.items():
        rows = by_bucket[bucket]
        chosen = random.sample(rows, k=min(k, len(rows)))
        for r in chosen:
            cid = r["case_id"]
            src = src_by_id.get(cid)
            if not src:
                continue
            # Pull snippet content out of the user message; the user prompt
            # itself does not echo the verdict, so we can keep it as-is, but
            # we drop the assistant message entirely.
            user_msg = next((m for m in src["messages"] if m["role"] == "user"), None)
            if not user_msg:
                continue
            blind_id = f"hl2_{next_blind:03d}_{cid[:8]}"
            next_blind += 1
            md = src.get("metadata", {})
            sample.append({
                "blind_id": blind_id,
                "snippet_prompt": user_msg["content"],
                "claimed_cwe": md.get("claimed_cwe"),
                "language": md.get("language"),
                "file_path": md.get("file_path"),
                "line_range": md.get("line_range"),
                "tool": md.get("tool"),
            })
            mapping[blind_id] = {
                "original_case_id": cid,
                "bucket": bucket,
                "sb_verdict": r["sb"],
                "sonnet_verdict": r["sonnet"],
                "gemini_verdict": r["gemini"],
                "v8_3_1_verdict": r["ours"],
            }

    # Shuffle so bucket order is not visible to the labeler
    random.shuffle(sample)

    out_blind = OUT_DIR / "hand_label_blind.json"
    out_map = OUT_DIR / "hand_label_case_id_map.json"
    out_blind.write_text(json.dumps(sample, indent=2, ensure_ascii=False), encoding="utf-8")
    out_map.write_text(json.dumps(mapping, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"\nWrote {len(sample)} blind cases to {out_blind}")
    print(f"Wrote mapping to {out_map}")
    print(f"\nStrat:")
    bucket_counts = {b: 0 for b in STRAT}
    for blind_id, m in mapping.items():
        bucket_counts[m["bucket"]] += 1
    for b, n in bucket_counts.items():
        print(f"  {b:25s}  {n}")


if __name__ == "__main__":
    main()

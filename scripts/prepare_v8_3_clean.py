"""Produce a deduplicated, balanced v8.3 training set from an existing
triage_v8_X train JSON.

Reproduces the 11.06.2026 audit finding: v8.2 train had 64.6% duplicate code
rows, 35% of unique codes had conflicting verdicts. This pipeline:

  1. Hash each row's `code:` block (SHA-256[:16]).
  2. Group rows by hash; if a code has conflicting verdicts (TP and FP), pick
     ONE row with the majority verdict. On a tie, prefer FP (anti-paranoia).
  3. If a code has only one verdict across N rows, keep one row.
  4. Balance to 50/50 by downsampling the majority class with a deterministic
     seed.

Output:
  - <out-dir>/train_dedup_balanced.json
  - <out-dir>/dedup_meta.json with provenance + statistics

Usage:
    python scripts/prepare_v8_3_clean.py \\
        --input data/train/triage_v8_2_train.json \\
        --out-dir data/train/triage_v8_3_clean \\
        --seed 42
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path


def extract_code(case: dict) -> str:
    user = case["messages"][1]["content"]
    m = re.search(r"Code:\s*\n(.*)\Z", user, re.DOTALL)
    return (m.group(1) if m else "").strip()


def code_sha(case: dict) -> str:
    return hashlib.sha256(extract_code(case).encode("utf-8", "replace")).hexdigest()[:16]


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser()
    p.add_argument("--input", required=True, help="raw v8.X triage_train.json")
    p.add_argument("--out-dir", required=True)
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--no-balance", action="store_true",
                   help="skip 50/50 downsampling step (keep dedup raw)")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    train = json.loads(Path(args.input).read_text(encoding="utf-8"))
    print(f"input: {len(train)} rows from {args.input}")

    # Group by code SHA
    by_code: dict[str, list[dict]] = defaultdict(list)
    for c in train:
        by_code[code_sha(c)].append(c)

    n_unique_codes = len(by_code)
    n_conflict = sum(1 for cs in by_code.values()
                      if len({c["metadata"].get("verdict") for c in cs}) > 1)
    print(f"  unique codes: {n_unique_codes}  conflicting-verdict codes: {n_conflict}")

    # Pick one row per code with majority verdict (FP on tie)
    cleaned: list[dict] = []
    n_picked_fp_on_tie = 0
    for cases in by_code.values():
        verdicts = Counter(c["metadata"].get("verdict") for c in cases)
        if len(verdicts) > 1:
            tp_n = verdicts.get("TRUE_POSITIVE", 0)
            fp_n = verdicts.get("FALSE_POSITIVE", 0)
            if fp_n >= tp_n:
                pick = next(c for c in cases if c["metadata"].get("verdict") == "FALSE_POSITIVE")
                if fp_n == tp_n:
                    n_picked_fp_on_tie += 1
            else:
                pick = next(c for c in cases if c["metadata"].get("verdict") == "TRUE_POSITIVE")
        else:
            pick = cases[0]
        cleaned.append(pick)
    print(f"  after dedup (1 row per code, majority verdict): {len(cleaned)}")
    print(f"    FP picked on tied codes: {n_picked_fp_on_tie}")
    pre_balance_dist = dict(Counter(c["metadata"]["verdict"] for c in cleaned))
    print(f"    pre-balance dist: {pre_balance_dist}")

    # 50/50 balance
    if args.no_balance:
        final = cleaned
    else:
        rng = random.Random(args.seed)
        tps = [c for c in cleaned if c["metadata"]["verdict"] == "TRUE_POSITIVE"]
        fps = [c for c in cleaned if c["metadata"]["verdict"] == "FALSE_POSITIVE"]
        target = min(len(tps), len(fps))
        rng.shuffle(tps)
        rng.shuffle(fps)
        final = tps[:target] + fps[:target]
        rng.shuffle(final)
    print(f"  final: {len(final)} rows ({dict(Counter(c['metadata']['verdict'] for c in final))})")

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    train_path = out_dir / "train_dedup_balanced.json"
    train_path.write_text(json.dumps(final, ensure_ascii=False, indent=2), encoding="utf-8")

    meta = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "source": str(args.input),
        "n_input": len(train),
        "n_unique_codes": n_unique_codes,
        "n_conflicting_codes": n_conflict,
        "n_picked_fp_on_tie": n_picked_fp_on_tie,
        "n_after_dedup": len(cleaned),
        "pre_balance_dist": pre_balance_dist,
        "n_after_balance": len(final),
        "final_dist": dict(Counter(c["metadata"]["verdict"] for c in final)),
        "seed": args.seed,
        "tie_breaker": "FP",
        "balance": "downsample to min(TP, FP)" if not args.no_balance else "skipped",
    }
    (out_dir / "dedup_meta.json").write_text(
        json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\nwrote: {train_path}")
    print(f"       {out_dir / 'dedup_meta.json'}")


if __name__ == "__main__":
    main()

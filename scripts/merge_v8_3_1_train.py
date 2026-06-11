"""Merge clean CVEFixes (v8.3.0 base) + CrossVul TRIAGE into v8.3.1 train.

Combine sources, apply (code_sha, verdict) strict uniqueness across the
combined pool, keep source_tag in metadata for LOSO eval. Balance 50/50.

Usage:
    python scripts/merge_v8_3_1_train.py \\
        --cvefixes data/train/triage_v8_3_clean/train_dedup_balanced.json \\
        --crossvul /tmp/cv_smoke4/triage_train.json \\
        --out-dir data/train/triage_v8_3_1 \\
        --seed 42
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
import re
from collections import Counter
from pathlib import Path


def extract_code(case: dict) -> str:
    user = case["messages"][1]["content"]
    m = re.search(r"Code:\s*\n(.*?)\n\nOutput exactly", user, re.DOTALL)
    return (m.group(1) if m else "").strip()


def code_sha(case: dict) -> str:
    return hashlib.sha256(extract_code(case).encode("utf-8", "replace")).hexdigest()[:16]


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser()
    p.add_argument("--cvefixes", required=True)
    p.add_argument("--crossvul", required=True)
    p.add_argument("--out-dir", required=True)
    p.add_argument("--seed", type=int, default=42)
    return p.parse_args()


def tag_source(case: dict, source: str) -> dict:
    md = dict(case.get("metadata", {}))
    md["source"] = source
    case = dict(case)
    case["metadata"] = md
    return case


def main() -> None:
    args = parse_args()
    rng = random.Random(args.seed)
    cv = json.loads(Path(args.cvefixes).read_text(encoding="utf-8"))
    xv = json.loads(Path(args.crossvul).read_text(encoding="utf-8"))
    cv = [tag_source(c, c.get("metadata", {}).get("source") or "cvefixes") for c in cv]
    xv = [tag_source(c, c.get("metadata", {}).get("source") or "crossvul") for c in xv]
    print(f"cvefixes: {len(cv)}  crossvul: {len(xv)}")

    # Cross-source code SHA dedup with verdict awareness.
    # If a code appears in both sources with different verdicts, drop it
    # entirely (we don't want the same conflict the dedup fix removed earlier).
    by_sha: dict[str, list[dict]] = {}
    for c in cv + xv:
        by_sha.setdefault(code_sha(c), []).append(c)

    cleaned: list[dict] = []
    cross_source_conflict = 0
    intra_source_dup = 0
    for sha, cases in by_sha.items():
        verdicts = {c["metadata"]["verdict"] for c in cases}
        if len(verdicts) > 1:
            cross_source_conflict += 1
            continue
        if len(cases) > 1:
            intra_source_dup += len(cases) - 1
        cleaned.append(cases[0])
    print(f"  unique codes: {len(by_sha)}  cross-source verdict conflicts dropped: {cross_source_conflict}")
    print(f"  intra-source duplicates collapsed: {intra_source_dup}")
    print(f"  after merge dedup: {len(cleaned)}")

    # Balance 50/50
    tps = [c for c in cleaned if c["metadata"]["verdict"] == "TRUE_POSITIVE"]
    fps = [c for c in cleaned if c["metadata"]["verdict"] == "FALSE_POSITIVE"]
    target = min(len(tps), len(fps))
    rng.shuffle(tps)
    rng.shuffle(fps)
    balanced = tps[:target] + fps[:target]
    rng.shuffle(balanced)

    src_counts = Counter(c["metadata"]["source"] for c in balanced)
    verdict_counts = Counter(c["metadata"]["verdict"] for c in balanced)
    cwe_counts = Counter(c["metadata"]["claimed_cwe"] for c in balanced)
    print(f"  balanced final: {len(balanced)} ({dict(verdict_counts)})")
    print(f"  source mix: {dict(src_counts)}")
    print(f"  CWE: {dict(cwe_counts.most_common())}")

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    train_path = out_dir / "train_merged.json"
    train_path.write_text(json.dumps(balanced, ensure_ascii=False, indent=2), encoding="utf-8")

    meta = {
        "created_at": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
        "inputs": {"cvefixes": args.cvefixes, "crossvul": args.crossvul},
        "cvefixes_n": len(cv), "crossvul_n": len(xv),
        "cross_source_verdict_conflicts": cross_source_conflict,
        "intra_source_dups_collapsed": intra_source_dup,
        "unique_after_dedup": len(cleaned),
        "balanced_n": len(balanced),
        "source_mix": dict(src_counts),
        "verdict_dist": dict(verdict_counts),
        "cwe_dist": dict(cwe_counts.most_common()),
    }
    (out_dir / "merge_meta.json").write_text(
        json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\nwrote {train_path}")


if __name__ == "__main__":
    main()

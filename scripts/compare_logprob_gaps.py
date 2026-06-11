"""Compare median p_tp gaps between v8.2 and v8.3.0 (or any two adapters).

Mechanistic test for the dedup hypothesis:
  v8.2 has gap = 0.058 on SastBench-250 (collapsed → calibration trick dead)
  Hypothesis: contradictory train labels destroyed first-token signal.
  Prediction: v8.3.0 (clean dedup train) should show gap > 0.10 on in-domain
              test_balanced. SastBench gap may stay collapsed (distribution
              mismatch) or recover (full cure) — informative either way.

Inputs are logprobs JSON produced by src/eval/extract_triage_logprobs.py.

Usage:
    python scripts/compare_logprob_gaps.py \\
        --baseline runs/v8_2_sb_test_logprobs.json \\
        --baseline-label v8.2-sastbench \\
        --new runs/v8_3_0_logprobs_sastbench250.json \\
        --new-label v8.3.0-sastbench
"""
from __future__ import annotations

import argparse
import json
import statistics
from pathlib import Path


def summarise(records: list[dict], label: str) -> dict:
    tps = [r["p_vuln"] for r in records if r["true_verdict"] == "TRUE_POSITIVE"]
    fps = [r["p_vuln"] for r in records if r["true_verdict"] == "FALSE_POSITIVE"]
    out = {
        "label": label,
        "n_total": len(records),
        "n_tp": len(tps),
        "n_fp": len(fps),
    }
    if tps:
        out["tp_median"] = statistics.median(tps)
        out["tp_mean"] = statistics.mean(tps)
        out["tp_min"] = min(tps)
        out["tp_max"] = max(tps)
    if fps:
        out["fp_median"] = statistics.median(fps)
        out["fp_mean"] = statistics.mean(fps)
        out["fp_min"] = min(fps)
        out["fp_max"] = max(fps)
    if tps and fps:
        out["gap_median"] = out["tp_median"] - out["fp_median"]
        out["gap_mean"] = out["tp_mean"] - out["fp_mean"]
    return out


def verdict_for_gap(gap_baseline: float, gap_new: float) -> str:
    """Decision tree from train_v8_3_0.sh, in plain terms."""
    if gap_new > 0.15:
        return "STRONG signal restoration — calibration trick alive"
    if gap_new > 0.10:
        return "moderate signal — calibration plausible, validate via threshold sweep"
    if gap_new > 0.05 and gap_new > gap_baseline + 0.03:
        return "marginal improvement — signal partially restored, distribution may still confound"
    if gap_new <= gap_baseline + 0.02:
        return "NO improvement — dedup hypothesis falsified on this distribution"
    return "ambiguous — interpret with care"


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--baseline", required=True, help="baseline logprobs JSON (e.g. v8.2)")
    p.add_argument("--baseline-label", default="baseline")
    p.add_argument("--new", required=True, help="new model logprobs JSON (e.g. v8.3.0)")
    p.add_argument("--new-label", default="new")
    args = p.parse_args()

    base = json.loads(Path(args.baseline).read_text(encoding="utf-8"))
    new = json.loads(Path(args.new).read_text(encoding="utf-8"))

    base_sum = summarise(base, args.baseline_label)
    new_sum = summarise(new, args.new_label)

    print("=" * 80)
    print("Logprob gap comparison")
    print("=" * 80)
    print(f"\n{'metric':<22} {args.baseline_label:<26} {args.new_label:<26}")
    print("-" * 80)
    for key in ("n_total", "n_tp", "n_fp",
                "tp_median", "fp_median",
                "tp_mean", "fp_mean",
                "gap_median", "gap_mean"):
        b = base_sum.get(key, "-")
        n = new_sum.get(key, "-")
        b_str = f"{b:.3f}" if isinstance(b, float) else str(b)
        n_str = f"{n:.3f}" if isinstance(n, float) else str(n)
        print(f"{key:<22} {b_str:<26} {n_str:<26}")

    g_b = base_sum.get("gap_median", 0)
    g_n = new_sum.get("gap_median", 0)
    delta = g_n - g_b
    print(f"\n=> Δ gap_median: {delta:+.3f}")
    print(f"=> Verdict: {verdict_for_gap(g_b, g_n)}")


if __name__ == "__main__":
    main()

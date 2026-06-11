"""Master analyzer for v8.3.0 results. Run after train_v8_3_0.sh completes.

Reads:
  - v8.3.0 SastBench-250 predictions + metrics
  - v8.3.0 SastBench-250 logprobs
  - v8.3.0 test_balanced predictions + metrics
  - v8.3.0 test_balanced logprobs
  - v8.2 baseline (in repo): predictions, logprobs, gap baselines

Produces:
  - One-page text report with all comparisons + decision branch (A/B/C)
  - Optional JSON dump for downstream consumers

Usage:
    python scripts/v8_3_0_full_report.py \\
        --v83-sb-outputs runs/v8_3_0_sastbench250_outputs.json \\
        --v83-sb-metrics runs/v8_3_0_sastbench250_metrics.json \\
        --v83-sb-logprobs runs/v8_3_0_logprobs_sastbench250.json \\
        --v83-tb-outputs runs/v8_3_0_testbalanced_outputs.json \\
        --v83-tb-metrics runs/v8_3_0_testbalanced_metrics.json \\
        --v83-tb-logprobs runs/v8_3_0_logprobs_testbalanced.json \\
        --sb-cases data/eval/sastbench_v01_subset250.json \\
        --output runs/v8_3_0_report.json
"""
from __future__ import annotations

import argparse
import json
import math
import statistics
from pathlib import Path


def load(path: str) -> object:
    if not path or not Path(path).exists():
        return None
    return json.loads(Path(path).read_text(encoding="utf-8"))


def confusion(rows: list[dict]) -> tuple[int, int, int, int]:
    tp = fn = tn = fp = 0
    for r in rows:
        t, p = r.get("true_verdict"), r.get("predicted_verdict")
        if t == "TRUE_POSITIVE" and p == "TRUE_POSITIVE":
            tp += 1
        elif t == "TRUE_POSITIVE" and p == "FALSE_POSITIVE":
            fn += 1
        elif t == "FALSE_POSITIVE" and p == "FALSE_POSITIVE":
            tn += 1
        elif t == "FALSE_POSITIVE" and p == "TRUE_POSITIVE":
            fp += 1
    return tp, fn, tn, fp


def metrics(rows: list[dict]) -> dict:
    tp, fn, tn, fp = confusion(rows)
    n = tp + fn + tn + fp
    dr = tp / (tp + fn) if (tp + fn) else 0
    far = fp / (tn + fp) if (tn + fp) else 0
    ba = 0.5 * (dr + (1 - far))
    d = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    mcc = ((tp * tn) - (fp * fn)) / d if d else 0
    return {"n": n, "TP": tp, "FN": fn, "TN": tn, "FP": fp,
            "DR": dr, "FAR": far, "BA": ba, "MCC": mcc}


def gap(logprobs: list[dict] | None) -> dict:
    if not logprobs:
        return {"available": False}
    tps = [r["p_vuln"] for r in logprobs if r.get("true_verdict") == "TRUE_POSITIVE"]
    fps = [r["p_vuln"] for r in logprobs if r.get("true_verdict") == "FALSE_POSITIVE"]
    if not tps or not fps:
        return {"available": False, "n_tp": len(tps), "n_fp": len(fps)}
    return {
        "available": True,
        "n_tp": len(tps), "n_fp": len(fps),
        "tp_median": statistics.median(tps),
        "fp_median": statistics.median(fps),
        "tp_mean": statistics.mean(tps),
        "fp_mean": statistics.mean(fps),
        "gap_median": statistics.median(tps) - statistics.median(fps),
        "gap_mean": statistics.mean(tps) - statistics.mean(fps),
    }


def per_cwe_breakdown(outputs: list[dict]) -> dict:
    by_cwe: dict[str, list[dict]] = {}
    for o in outputs:
        by_cwe.setdefault(o.get("claimed_cwe", "?"), []).append(o)
    return {c: metrics(rs) for c, rs in by_cwe.items()}


def verdict_branch(v82_sb: dict, v83_sb: dict, v82_tb: dict, v83_tb: dict,
                    v82_sb_gap: dict, v83_sb_gap: dict,
                    v82_tb_gap: dict, v83_tb_gap: dict) -> str:
    """A/B/C decision tree from train_v8_3_0.sh."""
    sb_mcc_delta = (v83_sb["MCC"] - v82_sb["MCC"]) if v83_sb and v82_sb else 0
    sb_far_delta = (v83_sb["FAR"] - v82_sb["FAR"]) if v83_sb and v82_sb else 0
    sb_gap_v83 = v83_sb_gap.get("gap_median", 0) if v83_sb_gap.get("available") else 0
    tb_gap_v83 = v83_tb_gap.get("gap_median", 0) if v83_tb_gap.get("available") else 0
    tb_gap_v82 = v82_tb_gap.get("gap_median", 0) if v82_tb_gap.get("available") else 0

    if (v83_sb and v83_sb["FAR"] < 0.50 and v83_sb["MCC"] > 0.15
            and sb_gap_v83 > 0.10 and tb_gap_v83 > 0.10):
        return ("CASE A — dedup cures broadly. SastBench MCC > 0.15, FAR < 50%, "
                "gaps restored both in-domain and on SastBench. "
                "Calibration trick alive. v8.3.1 multi-source becomes next "
                "accelerant, not prerequisite.")
    if tb_gap_v83 > 0.10 and sb_gap_v83 <= 0.07:
        return ("CASE B — contradictory train was the issue, distribution mismatch wasn't. "
                "Gap restored on in-domain but stays collapsed on SastBench. "
                "Multi-source mix IS needed for v8.3.1. Don't claim dedup as full fix.")
    if v82_tb_gap.get("available") and tb_gap_v83 < 0.08:
        return ("CASE C — gap stays collapsed on in-domain too. "
                "Dedup hypothesis falsified. Problem is deeper than label noise: "
                "review loss formulation, prompt format, base model.")
    return "MIXED — see per-slice breakdown; manual interpretation required."


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser()
    p.add_argument("--v83-sb-outputs", required=True)
    p.add_argument("--v83-sb-metrics", required=True)
    p.add_argument("--v83-sb-logprobs", default=None)
    p.add_argument("--v83-tb-outputs", default=None)
    p.add_argument("--v83-tb-metrics", default=None)
    p.add_argument("--v83-tb-logprobs", default=None)
    p.add_argument("--v82-sb-outputs", default="runs/v8_2_sastbench250_outputs.json")
    p.add_argument("--v82-sb-logprobs", default="runs/v8_2_sb_test_logprobs.json")
    p.add_argument("--v82-tb-logprobs", default=None,
                   help="v8.2 test_balanced logprobs (may not exist locally)")
    p.add_argument("--sb-cases", required=True)
    p.add_argument("--output", required=True)
    return p.parse_args()


def main() -> None:
    args = parse_args()

    v83_sb_out = load(args.v83_sb_outputs) or []
    v83_sb_met = load(args.v83_sb_metrics) or {}
    v83_sb_lp = load(args.v83_sb_logprobs)
    v83_tb_out = load(args.v83_tb_outputs) or []
    v83_tb_met = load(args.v83_tb_metrics) or {}
    v83_tb_lp = load(args.v83_tb_logprobs)
    v82_sb_out = load(args.v82_sb_outputs) or []
    v82_sb_lp = load(args.v82_sb_logprobs)
    v82_tb_lp = load(args.v82_tb_logprobs)

    v82_sb_m = metrics(v82_sb_out) if v82_sb_out else None
    v83_sb_m = metrics(v83_sb_out)
    v83_tb_m = metrics(v83_tb_out) if v83_tb_out else None

    v82_sb_gap = gap(v82_sb_lp)
    v83_sb_gap = gap(v83_sb_lp)
    v82_tb_gap = gap(v82_tb_lp)
    v83_tb_gap = gap(v83_tb_lp)

    v82_sb_per_cwe = per_cwe_breakdown(v82_sb_out) if v82_sb_out else {}
    v83_sb_per_cwe = per_cwe_breakdown(v83_sb_out)

    branch = verdict_branch(v82_sb_m, v83_sb_m, None, v83_tb_m,
                              v82_sb_gap, v83_sb_gap,
                              v82_tb_gap, v83_tb_gap)

    report = {
        "headline": {
            "v82_sastbench_mcc": v82_sb_m["MCC"] if v82_sb_m else None,
            "v82_sastbench_far": v82_sb_m["FAR"] if v82_sb_m else None,
            "v83_sastbench_mcc": v83_sb_m["MCC"],
            "v83_sastbench_far": v83_sb_m["FAR"],
            "v83_testbalanced_mcc": v83_tb_m["MCC"] if v83_tb_m else None,
            "v83_testbalanced_ba": v83_tb_m["BA"] if v83_tb_m else None,
            "delta_mcc_sastbench": (v83_sb_m["MCC"] - v82_sb_m["MCC"]) if (v82_sb_m and v83_sb_m) else None,
            "delta_far_sastbench": (v83_sb_m["FAR"] - v82_sb_m["FAR"]) if (v82_sb_m and v83_sb_m) else None,
        },
        "gaps": {
            "v82_sastbench": v82_sb_gap,
            "v83_sastbench": v83_sb_gap,
            "v82_testbalanced": v82_tb_gap,
            "v83_testbalanced": v83_tb_gap,
        },
        "v82_sb_metrics": v82_sb_m,
        "v83_sb_metrics": v83_sb_m,
        "v83_tb_metrics": v83_tb_m,
        "v82_sb_per_cwe": v82_sb_per_cwe,
        "v83_sb_per_cwe": v83_sb_per_cwe,
        "branch_verdict": branch,
    }
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    # Pretty-print
    print("=" * 80)
    print("v8.3.0 results — full report")
    print("=" * 80)
    if v82_sb_m and v83_sb_m:
        print(f"\nSastBench-250 (external):")
        print(f"  v8.2   MCC={v82_sb_m['MCC']:+.3f}  BA={v82_sb_m['BA']:.3f}  FAR={v82_sb_m['FAR']:.1%}  DR={v82_sb_m['DR']:.1%}")
        print(f"  v8.3.0 MCC={v83_sb_m['MCC']:+.3f}  BA={v83_sb_m['BA']:.3f}  FAR={v83_sb_m['FAR']:.1%}  DR={v83_sb_m['DR']:.1%}")
        print(f"  Δ      MCC={v83_sb_m['MCC']-v82_sb_m['MCC']:+.3f}  FAR={v83_sb_m['FAR']-v82_sb_m['FAR']:+.1%}")
    if v83_tb_m:
        print(f"\ntest_balanced (v8.2 in-domain control):")
        print(f"  v8.3.0 MCC={v83_tb_m['MCC']:+.3f}  BA={v83_tb_m['BA']:.3f}  FAR={v83_tb_m['FAR']:.1%}")
    if v82_sb_gap.get("available") and v83_sb_gap.get("available"):
        print(f"\nLogprob gap (TP median - FP median):")
        print(f"  v8.2 SastBench:    {v82_sb_gap['gap_median']:+.3f}  (TP={v82_sb_gap['tp_median']:.3f}, FP={v82_sb_gap['fp_median']:.3f}, n_tp={v82_sb_gap['n_tp']}/{v82_sb_gap['n_fp']})")
        print(f"  v8.3.0 SastBench:  {v83_sb_gap['gap_median']:+.3f}  (TP={v83_sb_gap['tp_median']:.3f}, FP={v83_sb_gap['fp_median']:.3f}, n_tp={v83_sb_gap['n_tp']}/{v83_sb_gap['n_fp']})")
    if v83_tb_gap.get("available"):
        print(f"  v8.3.0 testbalanced: {v83_tb_gap['gap_median']:+.3f}  (TP={v83_tb_gap['tp_median']:.3f}, FP={v83_tb_gap['fp_median']:.3f})")
    print(f"\nBranch verdict:")
    print(f"  {branch}")
    print(f"\nwrote {args.output}")


if __name__ == "__main__":
    main()

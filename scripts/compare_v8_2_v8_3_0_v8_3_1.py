"""Three-way comparison: v8.2 (baseline) vs v8.3.0 (dedup) vs v8.3.1 (multi-source).

Reads metrics + logprobs for all three; prints side-by-side table and
identifies which version wins on which axis. Decision support for whether
multi-source actually moved the needle vs dedup alone.

Usage:
    python scripts/compare_v8_2_v8_3_0_v8_3_1.py \\
        --v82-outputs runs/v8_2_sastbench250_outputs.json \\
        --v82-logprobs runs/v8_2_sb_test_logprobs.json \\
        --v83-0-outputs runs/v8_3_0_sastbench250_outputs.json \\
        --v83-0-metrics runs/v8_3_0_sastbench250_metrics.json \\
        --v83-0-logprobs runs/v8_3_0_logprobs_sastbench250.json \\
        --v83-1-outputs runs/v8_3_1_sastbench250_outputs.json \\
        --v83-1-metrics runs/v8_3_1_sastbench250_metrics.json \\
        --v83-1-logprobs runs/v8_3_1_logprobs_sastbench250.json \\
        --output runs/comparison_v8_2_v8_3_0_v8_3_1.json
"""
from __future__ import annotations

import argparse
import json
import math
import statistics
from pathlib import Path


def load(path: str) -> object:
    return json.loads(Path(path).read_text(encoding="utf-8")) if path and Path(path).exists() else None


def confusion(rows: list[dict]) -> tuple[int, int, int, int]:
    tp = fn = tn = fp = 0
    for r in rows or []:
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


def metrics(rows: list[dict] | None) -> dict | None:
    if not rows:
        return None
    tp, fn, tn, fp = confusion(rows)
    dr = tp / (tp + fn) if (tp + fn) else 0
    far = fp / (tn + fp) if (tn + fp) else 0
    ba = 0.5 * (dr + (1 - far))
    d = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    mcc = ((tp * tn) - (fp * fn)) / d if d else 0
    return {"n": tp + fn + tn + fp, "TP": tp, "FN": fn, "TN": tn, "FP": fp,
            "DR": dr, "FAR": far, "BA": ba, "MCC": mcc}


def gap(logprobs: list[dict] | None) -> float | None:
    if not logprobs:
        return None
    tps = [r["p_vuln"] for r in logprobs if r.get("true_verdict") == "TRUE_POSITIVE"]
    fps = [r["p_vuln"] for r in logprobs if r.get("true_verdict") == "FALSE_POSITIVE"]
    if not tps or not fps:
        return None
    return statistics.median(tps) - statistics.median(fps)


def winner(values: list[float | None], names: list[str], higher_is_better: bool = True) -> str:
    valid = [(v, n) for v, n in zip(values, names) if v is not None]
    if not valid:
        return "-"
    return max(valid, key=lambda x: x[0] if higher_is_better else -x[0])[1]


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser()
    p.add_argument("--v82-outputs", default="runs/v8_2_sastbench250_outputs.json")
    p.add_argument("--v82-logprobs", default="runs/v8_2_sb_test_logprobs.json")
    p.add_argument("--v83-0-outputs", default="runs/v8_3_0_sastbench250_outputs.json")
    p.add_argument("--v83-0-metrics", default="runs/v8_3_0_sastbench250_metrics.json")
    p.add_argument("--v83-0-logprobs", default="runs/v8_3_0_logprobs_sastbench250.json")
    p.add_argument("--v83-1-outputs", required=True)
    p.add_argument("--v83-1-metrics", required=True)
    p.add_argument("--v83-1-logprobs", required=True)
    p.add_argument("--output", required=True)
    return p.parse_args()


def main() -> None:
    args = parse_args()

    v82_out = load(args.v82_outputs)
    v82_lp = load(args.v82_logprobs)
    v83_0_out = load(args.v83_0_outputs)
    v83_0_lp = load(args.v83_0_logprobs)
    v83_1_out = load(args.v83_1_outputs)
    v83_1_lp = load(args.v83_1_logprobs)

    m82 = metrics(v82_out)
    m83_0 = metrics(v83_0_out)
    m83_1 = metrics(v83_1_out)
    g82 = gap(v82_lp)
    g83_0 = gap(v83_0_lp)
    g83_1 = gap(v83_1_lp)

    print("=" * 90)
    print("v8.2 vs v8.3.0 vs v8.3.1 — SastBench-250")
    print("=" * 90)
    print(f"  {'metric':<10} {'v8.2':<14} {'v8.3.0':<14} {'v8.3.1':<14}  winner")
    for key, hib in [("MCC", True), ("BA", True), ("DR", True), ("FAR", False)]:
        vals = [m82[key] if m82 else None, m83_0[key] if m83_0 else None, m83_1[key] if m83_1 else None]
        sign = "+" if hib else ""
        sv = [(f"{sign}{v:.3f}" if (key in ("MCC",) and v is not None and v >= 0) else f"{v:+.3f}" if (key == "MCC" and v is not None) else f"{v:.3f}" if v is not None else "-") for v in vals]
        w = winner(vals, ["v8.2", "v8.3.0", "v8.3.1"], higher_is_better=hib)
        print(f"  {key:<10} {sv[0]:<14} {sv[1]:<14} {sv[2]:<14}  {w}")

    print(f"\n  {'gap_p_tp':<10} {g82:.3f}" if g82 is not None else f"\n  {'gap_p_tp':<10} -", end="")
    print(f"        {g83_0:.3f}" if g83_0 is not None else "        -", end="")
    print(f"        {g83_1:.3f}" if g83_1 is not None else "        -", end="")
    print(f"        {winner([g82, g83_0, g83_1], ['v8.2','v8.3.0','v8.3.1'])}")

    print(f"\nDeltas from v8.3.0:")
    if m83_1 and m83_0:
        print(f"  Δ MCC:  v8.3.0 → v8.3.1: {m83_1['MCC']-m83_0['MCC']:+.3f}")
        print(f"  Δ FAR:  v8.3.0 → v8.3.1: {(m83_1['FAR']-m83_0['FAR'])*100:+.1f} pp")
        print(f"  Δ DR:   v8.3.0 → v8.3.1: {(m83_1['DR']-m83_0['DR'])*100:+.1f} pp")
        if g83_1 is not None and g83_0 is not None:
            print(f"  Δ gap:  v8.3.0 → v8.3.1: {g83_1-g83_0:+.3f}")

    out = {
        "v8_2": {"metrics_sastbench": m82, "gap_sastbench": g82},
        "v8_3_0": {"metrics_sastbench": m83_0, "gap_sastbench": g83_0},
        "v8_3_1": {"metrics_sastbench": m83_1, "gap_sastbench": g83_1},
        "deltas_v8_3_1_minus_v8_3_0": {
            "MCC": (m83_1["MCC"] - m83_0["MCC"]) if (m83_1 and m83_0) else None,
            "FAR_pp": ((m83_1["FAR"] - m83_0["FAR"]) * 100) if (m83_1 and m83_0) else None,
            "DR_pp": ((m83_1["DR"] - m83_0["DR"]) * 100) if (m83_1 and m83_0) else None,
            "gap": (g83_1 - g83_0) if (g83_1 is not None and g83_0 is not None) else None,
        },
    }
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\nwrote {args.output}")


if __name__ == "__main__":
    main()

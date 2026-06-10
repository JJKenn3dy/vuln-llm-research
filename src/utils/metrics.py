"""Classification metrics for vulnerability detection and triage.

Includes:
- Standard counts (TP/FN/TN/FP) and derived rates (DR, FAR, P, R, F1)
- Balanced accuracy (the honest metric on balanced eval sets)
- Per-CWE breakdown
- Threshold sweep helper for calibration over logprobs
"""
from __future__ import annotations

import math
from typing import Iterable


def confusion(predictions: Iterable[tuple[str, str]]) -> dict:
    """Compute confusion counts from (true_label, predicted_label) pairs.

    Labels expected: 'vulnerable' or 'safe'.
    """
    tp = fn = tn = fp = 0
    for true, pred in predictions:
        if true == "vulnerable" and pred == "vulnerable":
            tp += 1
        elif true == "vulnerable" and pred == "safe":
            fn += 1
        elif true == "safe" and pred == "safe":
            tn += 1
        elif true == "safe" and pred == "vulnerable":
            fp += 1
    return {"TP": tp, "FN": fn, "TN": tn, "FP": fp}


def derived_metrics(c: dict) -> dict:
    tp, fn, tn, fp = c["TP"], c["FN"], c["TN"], c["FP"]
    n_vuln = tp + fn
    n_safe = tn + fp
    dr = tp / n_vuln if n_vuln else 0.0
    far = fp / n_safe if n_safe else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = dr
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) else 0.0
    bal_acc = 0.5 * (dr + (1.0 - far))
    mcc_denom = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    mcc = ((tp * tn) - (fp * fn)) / mcc_denom if mcc_denom > 0 else 0.0
    return {
        "detection_rate": dr,
        "false_alarm_rate": far,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "balanced_accuracy": bal_acc,
        "mcc": mcc,
    }


def wilson_interval(p: float, n: int, z: float = 1.96) -> tuple[float, float]:
    """95% Wilson score interval for a proportion."""
    if n == 0:
        return 0.0, 1.0
    denom = 1 + z**2 / n
    center = (p + z**2 / (2 * n)) / denom
    half = z * math.sqrt((p * (1 - p) + z**2 / (4 * n)) / n) / denom
    return max(0.0, center - half), min(1.0, center + half)


def per_cwe_detection(results: list[dict]) -> dict[str, float]:
    by_cwe: dict[str, dict] = {}
    for r in results:
        if r["true_label"] != "vulnerable":
            continue
        c = r["true_cwe"]
        by_cwe.setdefault(c, {"tp": 0, "fn": 0})
        if r["predicted_label"] == "vulnerable":
            by_cwe[c]["tp"] += 1
        else:
            by_cwe[c]["fn"] += 1
    return {
        c: (v["tp"] / (v["tp"] + v["fn"]) if (v["tp"] + v["fn"]) else 0.0)
        for c, v in by_cwe.items()
    }


def sweep_threshold(
    logprobs: list[dict],
    metric: str = "balanced_accuracy",
    thresholds: Iterable[float] | None = None,
) -> dict:
    """Find the threshold on p_vuln that maximises the chosen metric.

    Each logprob entry must have:
      - true_label: 'vulnerable' or 'safe'
      - p_vuln: float in [0, 1]
    """
    if thresholds is None:
        thresholds = [i / 100 for i in range(5, 96)]

    best = {"threshold": 0.5, "score": -math.inf, "metrics": {}}
    for t in thresholds:
        pairs = []
        for r in logprobs:
            pred = "vulnerable" if r["p_vuln"] >= t else "safe"
            pairs.append((r["true_label"], pred))
        m = derived_metrics(confusion(pairs))
        if m[metric] > best["score"]:
            best = {"threshold": t, "score": m[metric], "metrics": m}
    return best

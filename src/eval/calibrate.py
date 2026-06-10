"""Threshold calibration over logprobs.

Replaces calibrate_v5b.py and calibrate_honest.py. Supports two modes:
  - 'standard': pick threshold on a VAL set, apply to TEST
  - 'honest':   project-stratified calibration (NOV-only VAL -> NOV-only TEST)

Logprob entries are expected to be dicts with at least:
  - true_label: 'vulnerable' or 'safe'
  - p_vuln: float in [0, 1]  (model's calibrated probability of vulnerable)
  - project_id: str  (optional, required for 'honest' mode)
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from src.utils.metrics import sweep_threshold


def load_logprobs(path: str) -> list[dict]:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def standard_calibration(val: list[dict], test: list[dict], metric: str) -> dict:
    best = sweep_threshold(val, metric=metric)
    threshold = best["threshold"]
    test_metrics = sweep_threshold(test, metric=metric, thresholds=[threshold])
    return {
        "mode": "standard",
        "metric": metric,
        "threshold": threshold,
        "val_metrics": best["metrics"],
        "test_metrics": test_metrics["metrics"],
        "n_val": len(val),
        "n_test": len(test),
    }


def honest_calibration(
    val: list[dict], test: list[dict], train_projects: set[str], metric: str
) -> dict:
    """Project-stratified honest calibration.

    Splits val and test into OVERLAP (project seen in train) and NON-OVERLAP buckets.
    Calibrates threshold on NON-OVERLAP val, then applies to NON-OVERLAP test.
    """
    def split(records: list[dict]) -> tuple[list[dict], list[dict]]:
        ov, nov = [], []
        for r in records:
            (ov if r.get("project_id") in train_projects else nov).append(r)
        return ov, nov

    val_ov, val_nov = split(val)
    test_ov, test_nov = split(test)

    if not val_nov:
        raise ValueError("No non-overlap records in val set — cannot calibrate honestly")

    best = sweep_threshold(val_nov, metric=metric)
    threshold = best["threshold"]
    test_nov_metrics = sweep_threshold(test_nov, metric=metric, thresholds=[threshold])
    test_ov_metrics = sweep_threshold(test_ov, metric=metric, thresholds=[threshold]) if test_ov else None

    return {
        "mode": "honest",
        "metric": metric,
        "threshold": threshold,
        "val_nov_metrics": best["metrics"],
        "test_nov_metrics": test_nov_metrics["metrics"],
        "test_ov_metrics": test_ov_metrics["metrics"] if test_ov_metrics else None,
        "n_val_nov": len(val_nov), "n_val_ov": len(val_ov),
        "n_test_nov": len(test_nov), "n_test_ov": len(test_ov),
    }


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Calibrate threshold on logprobs")
    p.add_argument("--val-file", required=True, help="VAL logprobs JSON")
    p.add_argument("--test-file", required=True, help="TEST logprobs JSON")
    p.add_argument("--mode", choices=["standard", "honest"], default="standard")
    p.add_argument("--metric", default="balanced_accuracy",
                   choices=["balanced_accuracy", "f1", "precision", "recall"])
    p.add_argument("--train-projects-file", default=None,
                   help="JSON list of train project_ids (required for honest mode)")
    p.add_argument("--output", required=True, help="Where to write the calibration result JSON")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    val = load_logprobs(args.val_file)
    test = load_logprobs(args.test_file)

    if args.mode == "standard":
        result = standard_calibration(val, test, args.metric)
    else:
        if not args.train_projects_file:
            raise SystemExit("--train-projects-file is required for honest mode")
        with open(args.train_projects_file, encoding="utf-8") as f:
            train_projects = set(json.load(f))
        result = honest_calibration(val, test, train_projects, args.metric)

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)

    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()

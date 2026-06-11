"""Per-slice threshold calibration on logprobs with cluster-CV honesty.

For each slice (by CWE / language / project): find a per-slice threshold that
maximises MCC on held-out folds (cluster CV by project), apply it to test.
Slices with negative cluster-CV gain → flip predicted verdict (the
Ruby-systematically-inverted case).

This is the honest post-train calibration step. Output is the per-slice
calibrated MCC and an overall calibrated MCC.

Inputs are logprobs JSON (with case_id, project_id, claimed_cwe, language,
true_verdict, p_vuln).

Usage:
    python scripts/per_slice_calibration.py \\
        --logprobs runs/v8_3_0_logprobs_sastbench250.json \\
        --cases data/eval/sastbench_v01_subset250.json \\
        --by language \\
        --output runs/v8_3_0_perslice_calib.json
"""
from __future__ import annotations

import argparse
import json
import math
import random
import statistics
from collections import defaultdict
from pathlib import Path


def confusion(rows: list[dict], threshold: float, flip: bool) -> tuple[int, int, int, int]:
    tp = fn = tn = fp = 0
    for r in rows:
        true_label = "vulnerable" if r["true_verdict"] == "TRUE_POSITIVE" else "safe"
        raw_pred = "vulnerable" if r["p_vuln"] >= threshold else "safe"
        pred = ("safe" if raw_pred == "vulnerable" else "vulnerable") if flip else raw_pred
        if true_label == "vulnerable" and pred == "vulnerable":
            tp += 1
        elif true_label == "vulnerable":
            fn += 1
        elif true_label == "safe" and pred == "safe":
            tn += 1
        else:
            fp += 1
    return tp, fn, tn, fp


def mcc(tp: int, fn: int, tn: int, fp: int) -> float:
    d = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    return ((tp * tn) - (fp * fn)) / d if d else 0.0


def find_best(rows: list[dict], thresholds: list[float]) -> tuple[float, bool, float]:
    """Return (threshold, flip, mcc) maximising MCC."""
    best = (0.5, False, -2.0)
    for t in thresholds:
        for flip in (False, True):
            tp, fn, tn, fp = confusion(rows, t, flip)
            m = mcc(tp, fn, tn, fp)
            if m > best[2]:
                best = (t, flip, m)
    return best


def k_fold_cluster_cv(rows: list[dict], cluster_key: str = "project_id",
                       k: int = 5, seed: int = 42,
                       thresholds: list[float] | None = None
                       ) -> dict:
    """Pick threshold+flip on (k-1) folds, apply on the held-out fold.
    Returns: avg MCC across folds, list of picks per fold."""
    if thresholds is None:
        thresholds = [i / 100 for i in range(5, 96, 5)]
    rng = random.Random(seed)
    by_cluster: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        by_cluster[r.get(cluster_key, "?")].append(r)
    clusters = list(by_cluster.keys())
    rng.shuffle(clusters)
    fold_assignment = {c: i % k for i, c in enumerate(clusters)}

    picks_per_fold = []
    test_mccs = []
    for held in range(k):
        train_clusters = [c for c in clusters if fold_assignment[c] != held]
        test_clusters = [c for c in clusters if fold_assignment[c] == held]
        train_rows = [r for c in train_clusters for r in by_cluster[c]]
        test_rows = [r for c in test_clusters for r in by_cluster[c]]
        if not train_rows or not test_rows:
            continue
        # Need both classes in train to pick threshold
        if (sum(1 for r in train_rows if r["true_verdict"] == "TRUE_POSITIVE") == 0
                or sum(1 for r in train_rows if r["true_verdict"] == "FALSE_POSITIVE") == 0):
            continue
        t, flip, _ = find_best(train_rows, thresholds)
        tp, fn, tn, fp = confusion(test_rows, t, flip)
        m = mcc(tp, fn, tn, fp)
        picks_per_fold.append({"fold": held, "threshold": t, "flip": flip, "test_mcc": m,
                                "n_train": len(train_rows), "n_test": len(test_rows)})
        test_mccs.append(m)
    return {
        "fold_picks": picks_per_fold,
        "mean_mcc": statistics.mean(test_mccs) if test_mccs else 0.0,
        "median_mcc": statistics.median(test_mccs) if test_mccs else 0.0,
        "n_valid_folds": len(test_mccs),
    }


def join_metadata(logprobs: list[dict], cases: list[dict]) -> None:
    """In-place: add file_path, project_id, language to each logprob record."""
    md = {str(c["metadata"]["case_id"]): c["metadata"] for c in cases}

    def detect_lang(fp: str) -> str:
        fp = (fp or "").lower()
        for ext, lang in [(".php", "php"), (".py", "python"),
                           (".js", "javascript"), (".mjs", "javascript"),
                           (".cjs", "javascript"), (".jsx", "javascript"),
                           (".ts", "typescript"), (".tsx", "typescript"),
                           (".go", "go"), (".rb", "ruby"), (".java", "java")]:
            if fp.endswith(ext):
                return lang
        return "other"

    for r in logprobs:
        m = md.get(str(r["case_id"]), {})
        r["project_id"] = r.get("project_id") or m.get("project_id", "?")
        r["language"] = detect_lang(m.get("file_path", ""))


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser()
    p.add_argument("--logprobs", required=True)
    p.add_argument("--cases", required=True)
    p.add_argument("--by", choices=["overall", "language", "cwe", "project"],
                   default="language")
    p.add_argument("--k", type=int, default=5)
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--output", required=True)
    return p.parse_args()


def main() -> None:
    args = parse_args()
    logprobs = json.loads(Path(args.logprobs).read_text(encoding="utf-8"))
    cases = json.loads(Path(args.cases).read_text(encoding="utf-8"))
    join_metadata(logprobs, cases)

    # Baseline default threshold 0.5 no flip
    base_tp, base_fn, base_tn, base_fp = confusion(logprobs, 0.5, False)
    base_mcc = mcc(base_tp, base_fn, base_tn, base_fp)

    # Single-threshold global sweep with cluster CV
    overall_cv = k_fold_cluster_cv(logprobs, "project_id", k=args.k, seed=args.seed)

    # Per-slice sweep with cluster CV per slice
    key_map = {"language": "language", "cwe": "claimed_cwe", "project": "project_id"}
    per_slice = {}
    if args.by != "overall":
        slice_key = key_map[args.by]
        slices: dict[str, list[dict]] = defaultdict(list)
        for r in logprobs:
            slices[r.get(slice_key, "?")].append(r)
        for slice_name, rows in slices.items():
            if len(rows) < 5:
                continue
            # If only one class in slice — degenerate
            n_tp = sum(1 for r in rows if r["true_verdict"] == "TRUE_POSITIVE")
            n_fp = sum(1 for r in rows if r["true_verdict"] == "FALSE_POSITIVE")
            if n_tp == 0 or n_fp == 0:
                per_slice[slice_name] = {"n": len(rows), "degenerate": True,
                                          "n_tp": n_tp, "n_fp": n_fp}
                continue
            cv = k_fold_cluster_cv(rows, "project_id", k=args.k, seed=args.seed)
            per_slice[slice_name] = {"n": len(rows), "n_tp": n_tp, "n_fp": n_fp, **cv}

    out = {
        "input": args.logprobs,
        "by": args.by,
        "baseline_default_thr_0.5_mcc": base_mcc,
        "overall_cluster_cv_mcc_mean": overall_cv["mean_mcc"],
        "overall_cluster_cv_mcc_median": overall_cv["median_mcc"],
        "overall_picks_per_fold": overall_cv["fold_picks"],
        "per_slice": per_slice,
    }
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text(
        json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")

    print("=" * 70)
    print(f"Per-slice calibration on {Path(args.logprobs).name}")
    print("=" * 70)
    print(f"Baseline (default thr=0.5, no flip): MCC = {base_mcc:+.3f}")
    print(f"Overall cluster-CV (single thr+flip): MCC = {overall_cv['mean_mcc']:+.3f} (mean)")
    if per_slice:
        print(f"\nPer-slice (by {args.by}) cluster-CV:")
        print(f"  {'slice':<28} {'n':>3} {'n_tp':>4} {'n_fp':>4} {'cv_mean_MCC':>11}")
        for s, v in sorted(per_slice.items(), key=lambda kv: -kv[1].get("n", 0)):
            if v.get("degenerate"):
                print(f"  {s:<28} {v['n']:>3} {v['n_tp']:>4} {v['n_fp']:>4}  (degenerate)")
                continue
            m = v.get("mean_mcc", 0)
            sign = "+" if m >= 0 else "-"
            print(f"  {s:<28} {v['n']:>3} {v['n_tp']:>4} {v['n_fp']:>4}  {sign}{abs(m):.3f}")
    print(f"\nwrote {args.output}")


if __name__ == "__main__":
    main()

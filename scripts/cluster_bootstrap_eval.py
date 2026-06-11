"""Cluster bootstrap MCC/BA CIs for clustered eval data (SastBench by repo_url).

WeGIA = 30% of SastBench-250 cases. Naive case-level bootstrap underestimates
variance because cases inside one project are correlated. Cluster bootstrap
by repo_url gives honest CIs.

Recomputes per-arm or per-slice MCC with both:
  - case bootstrap (the old way — likely too tight)
  - cluster bootstrap by repo_url (the honest way)

Reports the gap. If cluster CI is materially wider than case CI on the same
slice, the slice was clustering-confounded.

Usage:
    python scripts/cluster_bootstrap_eval.py \\
        --outputs runs/v8_2_sastbench250_outputs.json \\
        --cases data/eval/sastbench_v01_subset250.json \\
        --by-slice cwe       # or 'language', 'project', 'overall'
"""
from __future__ import annotations

import argparse
import json
import math
import random
from collections import defaultdict
from pathlib import Path


def mcc(tp: int, fn: int, tn: int, fp: int) -> float:
    d = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    return ((tp * tn) - (fp * fn)) / d if d else 0.0


def ba(tp: int, fn: int, tn: int, fp: int) -> float:
    n_pos = tp + fn
    n_neg = tn + fp
    dr = tp / n_pos if n_pos else 0.0
    far = fp / n_neg if n_neg else 0.0
    return 0.5 * (dr + (1 - far))


def confusion(rows: list[dict]) -> tuple[int, int, int, int]:
    tp = fn = tn = fp = 0
    for r in rows:
        t, p = r["true_verdict"], r["predicted_verdict"]
        if t == "TRUE_POSITIVE" and p == "TRUE_POSITIVE":
            tp += 1
        elif t == "TRUE_POSITIVE" and p == "FALSE_POSITIVE":
            fn += 1
        elif t == "FALSE_POSITIVE" and p == "FALSE_POSITIVE":
            tn += 1
        elif t == "FALSE_POSITIVE" and p == "TRUE_POSITIVE":
            fp += 1
    return tp, fn, tn, fp


def case_bootstrap(rows: list[dict], n_boot: int = 2000, seed: int = 42
                    ) -> tuple[list[float], list[float]]:
    rng = random.Random(seed)
    n = len(rows)
    bas: list[float] = []
    mccs: list[float] = []
    for _ in range(n_boot):
        sample = [rows[rng.randrange(n)] for _ in range(n)]
        tp, fn, tn, fp = confusion(sample)
        bas.append(ba(tp, fn, tn, fp))
        mccs.append(mcc(tp, fn, tn, fp))
    bas.sort()
    mccs.sort()
    return bas, mccs


def cluster_bootstrap(rows: list[dict], cluster_key: str,
                       n_boot: int = 2000, seed: int = 42
                       ) -> tuple[list[float], list[float]]:
    rng = random.Random(seed)
    by_cluster: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        by_cluster[r.get(cluster_key, "?")].append(r)
    clusters = list(by_cluster.keys())
    n_clusters = len(clusters)
    bas: list[float] = []
    mccs: list[float] = []
    for _ in range(n_boot):
        sample_clusters = [clusters[rng.randrange(n_clusters)] for _ in range(n_clusters)]
        sample = [r for cl in sample_clusters for r in by_cluster[cl]]
        tp, fn, tn, fp = confusion(sample)
        bas.append(ba(tp, fn, tn, fp))
        mccs.append(mcc(tp, fn, tn, fp))
    bas.sort()
    mccs.sort()
    return bas, mccs


def ci95(values: list[float]) -> tuple[float, float]:
    n = len(values)
    return values[int(0.025 * n)], values[int(0.975 * n)]


def detect_language(file_path: str) -> str:
    fp = file_path.lower() if file_path else ""
    for ext, lang in [(".php", "php"), (".py", "python"),
                       (".js", "javascript"), (".mjs", "javascript"),
                       (".cjs", "javascript"), (".jsx", "javascript"),
                       (".ts", "typescript"), (".tsx", "typescript"),
                       (".go", "go"), (".rb", "ruby"), (".java", "java")]:
        if fp.endswith(ext):
            return lang
    return "other"


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser()
    p.add_argument("--outputs", required=True,
                   help="per-case predictions JSON (with case_id, true_verdict, predicted_verdict)")
    p.add_argument("--cases", required=True,
                   help="SastBench cases JSON for joining project_id/file_path/lang")
    p.add_argument("--by-slice", choices=["overall", "cwe", "language", "project"],
                   default="overall")
    p.add_argument("--n-boot", type=int, default=2000)
    p.add_argument("--seed", type=int, default=42)
    return p.parse_args()


def main() -> None:
    args = parse_args()
    out = json.loads(Path(args.outputs).read_text(encoding="utf-8"))
    cases = json.loads(Path(args.cases).read_text(encoding="utf-8"))
    md_by_id = {str(c["metadata"]["case_id"]): c["metadata"] for c in cases}

    for o in out:
        md = md_by_id.get(str(o["case_id"]), {})
        o["project_id"] = md.get("project_id", "?")
        o["claimed_cwe"] = md.get("claimed_cwe", "?")
        o["language"] = detect_language(md.get("file_path", ""))

    # Build slice rows
    slices: dict[str, list[dict]] = {}
    if args.by_slice == "overall":
        slices["overall"] = out
    else:
        key = {"cwe": "claimed_cwe", "language": "language", "project": "project_id"}[args.by_slice]
        for o in out:
            slices.setdefault(o[key], []).append(o)

    print(f"{'slice':<35} {'n':>4} {'n_clust':>7} {'BA':>6} {'BA case CI':<16} {'BA cluster CI':<16} {'MCC':>7} {'MCC case CI':<18} {'MCC clust CI':<18}")
    for slice_name in sorted(slices, key=lambda k: -len(slices[k])):
        rows = slices[slice_name]
        if len(rows) < 4:
            continue
        tp, fn, tn, fp = confusion(rows)
        m = mcc(tp, fn, tn, fp)
        b = ba(tp, fn, tn, fp)
        # Case bootstrap
        case_bas, case_mccs = case_bootstrap(rows, args.n_boot, args.seed)
        # Cluster bootstrap by project_id
        clust_bas, clust_mccs = cluster_bootstrap(rows, "project_id", args.n_boot, args.seed)
        n_clusters = len(set(r["project_id"] for r in rows))
        ba_case_ci = ci95(case_bas)
        ba_clust_ci = ci95(clust_bas)
        mcc_case_ci = ci95(case_mccs)
        mcc_clust_ci = ci95(clust_mccs)
        ba_case_str = f"[{ba_case_ci[0]:.2f},{ba_case_ci[1]:.2f}]"
        ba_clust_str = f"[{ba_clust_ci[0]:.2f},{ba_clust_ci[1]:.2f}]"
        mcc_case_str = f"[{mcc_case_ci[0]:+.2f},{mcc_case_ci[1]:+.2f}]"
        mcc_clust_str = f"[{mcc_clust_ci[0]:+.2f},{mcc_clust_ci[1]:+.2f}]"
        print(f"{slice_name:<35} {len(rows):>4} {n_clusters:>7} {b:.3f}  {ba_case_str:<16} {ba_clust_str:<16} {m:+.3f}   {mcc_case_str:<18} {mcc_clust_str:<18}")


if __name__ == "__main__":
    main()

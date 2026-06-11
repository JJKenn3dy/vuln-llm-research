"""Paired cluster bootstrap for v8.3.1 vs frontier on the same 250 cases.

Resamples whole repo_url clusters with replacement, computes MCC for each
arm on the SAME resampled cases, takes the difference. CI on the
differences is what tells us if "v8.3.1 > frontier" is statistically
defensible. This is strictly stronger than comparing two independent CIs
and noting they don't overlap — it accounts for the fact that all three
models scored the same 250 cases.

Usage:
    python scripts/paired_cluster_bootstrap.py
"""
from __future__ import annotations

import json
import math
import random
from collections import defaultdict
from pathlib import Path


def confusion(rows):
    tp = fn = tn = fp = pf = 0
    for r in rows:
        t, p = r["true_verdict"], r["predicted_verdict"]
        if p == "PARSE_FAIL":
            pf += 1
            continue
        if t == "TRUE_POSITIVE" and p == "TRUE_POSITIVE":
            tp += 1
        elif t == "TRUE_POSITIVE" and p == "FALSE_POSITIVE":
            fn += 1
        elif t == "FALSE_POSITIVE" and p == "FALSE_POSITIVE":
            tn += 1
        elif t == "FALSE_POSITIVE" and p == "TRUE_POSITIVE":
            fp += 1
    return tp, fn, tn, fp, pf


def mcc(tp, fn, tn, fp):
    d = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    return ((tp * tn) - (fp * fn)) / d if d else 0.0


def index(outputs, cases_by_id):
    """Return list of {case_id, repo_url, true_verdict, predicted_verdict}."""
    out = []
    for r in outputs:
        cid = r["case_id"]
        meta = cases_by_id.get(cid)
        repo = meta.get("project_id") if meta else "?"
        out.append({
            "case_id": cid,
            "repo_url": repo,
            "true_verdict": r["true_verdict"],
            "predicted_verdict": r["predicted_verdict"],
        })
    return out


def paired_bootstrap(our, sonnet, gemini, n_boot=2000, seed=42):
    """Resample clusters, compute MCC for each arm on the SAME resample, take diff."""
    rng = random.Random(seed)
    # build cluster -> list of (our_record, sonnet_record, gemini_record)
    by_cluster = defaultdict(list)
    sonnet_by_cid = {r["case_id"]: r for r in sonnet}
    gemini_by_cid = {r["case_id"]: r for r in gemini}
    for r in our:
        cid = r["case_id"]
        s = sonnet_by_cid.get(cid)
        g = gemini_by_cid.get(cid)
        if s is None or g is None:
            continue
        by_cluster[r["repo_url"]].append((r, s, g))

    clusters = list(by_cluster.keys())
    n_clusters = len(clusters)

    mcc_ours = []
    mcc_sonnet = []
    mcc_gemini = []
    diff_ours_minus_sonnet = []
    diff_ours_minus_gemini = []
    win_ours_over_sonnet = 0
    win_ours_over_gemini = 0

    for _ in range(n_boot):
        chosen = [rng.choice(clusters) for _ in range(n_clusters)]
        triples = []
        for c in chosen:
            triples.extend(by_cluster[c])
        ours_rows = [t[0] for t in triples]
        sonnet_rows = [t[1] for t in triples]
        gemini_rows = [t[2] for t in triples]
        m_o = mcc(*confusion(ours_rows)[:4])
        m_s = mcc(*confusion(sonnet_rows)[:4])
        m_g = mcc(*confusion(gemini_rows)[:4])
        mcc_ours.append(m_o)
        mcc_sonnet.append(m_s)
        mcc_gemini.append(m_g)
        diff_ours_minus_sonnet.append(m_o - m_s)
        diff_ours_minus_gemini.append(m_o - m_g)
        if m_o > m_s:
            win_ours_over_sonnet += 1
        if m_o > m_g:
            win_ours_over_gemini += 1

    def ci(vals):
        vals = sorted(vals)
        return vals[int(0.025 * len(vals))], vals[int(0.975 * len(vals))]

    return {
        "n_clusters": n_clusters,
        "n_cases_per_resample_approx": sum(len(by_cluster[c]) for c in by_cluster) // n_clusters * n_clusters,
        "mcc_ours_ci": ci(mcc_ours),
        "mcc_sonnet_ci": ci(mcc_sonnet),
        "mcc_gemini_ci": ci(mcc_gemini),
        "diff_ours_minus_sonnet_ci": ci(diff_ours_minus_sonnet),
        "diff_ours_minus_gemini_ci": ci(diff_ours_minus_gemini),
        "prob_ours_beats_sonnet": win_ours_over_sonnet / n_boot,
        "prob_ours_beats_gemini": win_ours_over_gemini / n_boot,
    }


def main():
    repo_root = Path(__file__).resolve().parent.parent
    cases = json.loads((repo_root / "data/eval/sastbench_v01_subset250.json").read_text(encoding="utf-8"))
    cases_by_id = {c["metadata"]["case_id"]: c["metadata"] for c in cases}

    our = json.loads((repo_root / "runs/v8_3_1_sastbench250_outputs.json").read_text(encoding="utf-8"))
    sonnet = json.loads((repo_root / "runs/frontier_v8_3_1/sonnet_triage_outputs.json").read_text(encoding="utf-8"))
    gemini = json.loads((repo_root / "runs/frontier_v8_3_1/gemini_triage_outputs.json").read_text(encoding="utf-8"))

    our_idx = index(our, cases_by_id)
    sonnet_idx = index(sonnet, cases_by_id)
    gemini_idx = index(gemini, cases_by_id)

    print(f"v8.3.1 records: {len(our_idx)}")
    print(f"Sonnet records: {len(sonnet_idx)}")
    print(f"Gemini records: {len(gemini_idx)}")

    result = paired_bootstrap(our_idx, sonnet_idx, gemini_idx, n_boot=2000)

    def fmt_ci(name, ci):
        return f"  {name}: [{ci[0]:+.3f}, {ci[1]:+.3f}]"

    print(f"\nClusters: {result['n_clusters']}")
    print(f"\nMCC 95% cluster bootstrap CIs (on same resampled clusters):")
    print(fmt_ci("v8.3.1", result["mcc_ours_ci"]))
    print(fmt_ci("Sonnet 4.5", result["mcc_sonnet_ci"]))
    print(fmt_ci("Gemini 2.5 Pro", result["mcc_gemini_ci"]))

    print(f"\nPaired MCC differences (this is the strong test):")
    print(fmt_ci("v8.3.1 - Sonnet 4.5", result["diff_ours_minus_sonnet_ci"]))
    print(f"  ==> lower bound > 0 means v8.3.1 strictly better than Sonnet on every resample")
    print(fmt_ci("v8.3.1 - Gemini 2.5 Pro", result["diff_ours_minus_gemini_ci"]))
    print(f"  ==> lower bound > 0 means v8.3.1 strictly better than Gemini")

    print(f"\nBootstrap win probabilities:")
    print(f"  P(v8.3.1 MCC > Sonnet MCC) = {result['prob_ours_beats_sonnet']:.3f}")
    print(f"  P(v8.3.1 MCC > Gemini MCC) = {result['prob_ours_beats_gemini']:.3f}")

    out_path = repo_root / "runs/frontier_v8_3_1/paired_bootstrap.json"
    out_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(f"\nWrote {out_path}")


if __name__ == "__main__":
    main()

"""Stand v2 analysis: exp5 vs exp4 vs v8.3.1 on the fresh trusted set.

Inputs: runs/standv2_{tag}_outputs.json (from src.eval.run_triage_eval on pod)
joined with data/eval/stand_v2_eval.json (truth = blind dual-judge consensus,
project_id for clustering).

Per model: MCC/DR/FAR two ways — PARSE_FAIL excluded (legacy convention) and
PARSE_FAIL counted as wrong (audit 2026-07-02 p.2.6: silent exclusion inflates
metrics). Cluster bootstrap CI by project_id (N=2000). Pairwise: paired cluster
bootstrap of dMCC + McNemar-style sign test on case correctness.
"""
from __future__ import annotations

import json
import math
import random
import sys
from collections import defaultdict
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")
ROOT = Path("f:/vuln-llm-research")
TAGS = ["exp5", "exp4", "v8_3_1"]
N_BOOT = 2000
SEED = 42


def mcc_from(rows, pf_as_wrong):
    tp = fn = tn = fp = 0
    for r in rows:
        t, p = r["truth"], r["pred"]
        if p == "PARSE_FAIL":
            if not pf_as_wrong:
                continue
            p = "FALSE_POSITIVE" if t == "TRUE_POSITIVE" else "TRUE_POSITIVE"
        if t == "TRUE_POSITIVE":
            tp += p == "TRUE_POSITIVE"; fn += p == "FALSE_POSITIVE"
        else:
            tn += p == "FALSE_POSITIVE"; fp += p == "TRUE_POSITIVE"
    den = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    mcc = (tp * tn - fp * fn) / den if den else 0.0
    dr = tp / (tp + fn) if tp + fn else 0.0
    far = fp / (fp + tn) if fp + tn else 0.0
    return {"mcc": round(mcc, 4), "dr": round(dr, 4), "far": round(far, 4),
            "tp": tp, "fn": fn, "tn": tn, "fp": fp}


def cluster_boot(rows, stat_fn, n_boot=N_BOOT, seed=SEED):
    by_proj = defaultdict(list)
    for r in rows:
        by_proj[r["project"]].append(r)
    projs = sorted(by_proj)
    rng = random.Random(seed)
    stats = []
    for _ in range(n_boot):
        sample = []
        for _ in projs:
            sample.extend(by_proj[rng.choice(projs)])
        stats.append(stat_fn(sample))
    stats.sort()
    return round(stats[int(0.025 * n_boot)], 4), round(stats[int(0.975 * n_boot)], 4)


def main():
    ev = json.loads((ROOT / "data/eval/stand_v2_eval.json").read_text(encoding="utf-8"))
    meta = {c["metadata"]["case_id"]: c["metadata"] for c in ev}

    per_model = {}
    for tag in TAGS:
        out = json.loads((ROOT / f"runs/standv2_{tag}_outputs.json").read_text(encoding="utf-8"))
        rows = []
        for r in out:
            m = meta.get(r["case_id"])
            if not m:
                continue
            rows.append({"case_id": r["case_id"], "truth": m["verdict"],
                         "pred": r["predicted_verdict"], "project": m["project_id"]})
        per_model[tag] = rows

    report = {"n_eval": len(ev), "models": {}, "pairwise": {}}
    for tag, rows in per_model.items():
        pf = sum(1 for r in rows if r["pred"] == "PARSE_FAIL")
        strict = mcc_from(rows, pf_as_wrong=True)
        legacy = mcc_from(rows, pf_as_wrong=False)
        lo, hi = cluster_boot(rows, lambda s: mcc_from(s, True)["mcc"])
        report["models"][tag] = {
            "n": len(rows), "parse_fail": pf,
            "strict(pf_as_wrong)": strict, "legacy(pf_excluded)": legacy,
            "mcc_strict_ci95_cluster": [lo, hi],
        }

    base = per_model["exp5"]
    for other in ["exp4", "v8_3_1"]:
        o_by = {r["case_id"]: r for r in per_model[other]}
        paired = [(r, o_by[r["case_id"]]) for r in base if r["case_id"] in o_by]
        joint = [{"case_id": a["case_id"], "project": a["project"], "truth": a["truth"],
                  "pred_a": a["pred"], "pred_b": b["pred"]} for a, b in paired]

        def dmcc(sample):
            ra = [{"truth": r["truth"], "pred": r["pred_a"], "project": r["project"]} for r in sample]
            rb = [{"truth": r["truth"], "pred": r["pred_b"], "project": r["project"]} for r in sample]
            return mcc_from(ra, True)["mcc"] - mcc_from(rb, True)["mcc"]

        lo, hi = cluster_boot(joint, dmcc)
        a_only = sum(1 for r in joint
                     if (r["pred_a"] == r["truth"]) and (r["pred_b"] != r["truth"]))
        b_only = sum(1 for r in joint
                     if (r["pred_b"] == r["truth"]) and (r["pred_a"] != r["truth"]))
        n_disc = a_only + b_only
        # two-sided binomial sign test on discordant pairs
        if n_disc:
            from math import comb
            k = min(a_only, b_only)
            p = sum(comb(n_disc, i) for i in range(k + 1)) / 2 ** n_disc * 2
            p = min(1.0, p)
        else:
            p = 1.0
        report["pairwise"][f"exp5_vs_{other}"] = {
            "n_paired": len(joint), "dmcc_point": round(dmcc(joint), 4),
            "dmcc_ci95_cluster": [lo, hi],
            "exp5_only_correct": a_only, f"{other}_only_correct": b_only,
            "sign_test_p": round(p, 4),
        }

    (ROOT / "runs/standv2_analysis.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=1), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()

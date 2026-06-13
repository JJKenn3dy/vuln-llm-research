"""Gold-core metrics: trusted-subset compass for v8.4 work.

Gold core = hand-label-100 cases where the two lowest-noise judges from
DIFFERENT origin (human pass-1 anchor and GPT-5.3-codex, pairwise 71.7%)
agree on the verdict. Their consensus verdict becomes the gold label.

Caveats (encoded in the output, repeated in docs):
- The core inherits Human<->GPT-5.3 correlation and skews toward
  unambiguous cases. INTERNAL COMPASS ONLY, not for external claims.
- Human and GPT-5.3 agreement with gold is 100% by construction and is
  not reported as a metric.

Inputs (all already on disk, $0):
- data/exam/sastbench250_handlabel/four_judge_merged.json
- data/exam/sastbench250_handlabel/hand_label_case_id_map.json
- runs/v8_3_2/v8_3_2_sastbench250_outputs.json   (v8.3.2 join)
- data/eval/sastbench_v01_subset250.json          (project_id for cluster bootstrap)

Output: runs/gold_core_metrics.json + table on stdout.
"""

import json
import math
import random
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SEED = 20260613
N_BOOT = 2000

JUDGES = ["sb", "sonnet", "gemini", "ours", "v832"]
JUDGE_LABELS = {
    "sb": "SastBench label",
    "sonnet": "Sonnet 4.5",
    "gemini": "Gemini 2.5 Pro",
    "ours": "v8.3.1",
    "v832": "v8.3.2",
}


def norm(v):
    if v is None:
        return None
    v = str(v).strip().upper()
    if v in ("TP", "TRUE_POSITIVE"):
        return "TP"
    if v in ("FP", "FALSE_POSITIVE"):
        return "FP"
    return None  # parse fail


def mcc_ba(pairs):
    """pairs: list of (gold, pred) with pred possibly None (parse fail = error)."""
    tp = fn = tn = fp = 0
    for gold, pred in pairs:
        err = pred is None or pred != gold
        if gold == "TP":
            tp += 0 if err else 1
            fn += 1 if err else 0
        else:
            tn += 0 if err else 1
            fp += 1 if err else 0
    den = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    mcc = ((tp * tn - fp * fn) / den) if den else 0.0
    dr = tp / (tp + fn) if (tp + fn) else float("nan")
    far = fp / (fp + tn) if (fp + tn) else float("nan")
    ba = ((dr if not math.isnan(dr) else 0) + (1 - far if not math.isnan(far) else 0)) / 2
    agree = (tp + tn) / len(pairs) if pairs else float("nan")
    return {"n": len(pairs), "tp": tp, "fn": fn, "tn": tn, "fp": fp,
            "mcc": mcc, "ba": ba, "dr": dr, "far": far, "agreement": agree}


def cluster_bootstrap_mcc(rows, judge, rng):
    by_proj = {}
    for r in rows:
        by_proj.setdefault(r["project_id"], []).append((r["gold"], r[judge]))
    projects = sorted(by_proj)
    stats = []
    for _ in range(N_BOOT):
        sample = []
        for p in rng.choices(projects, k=len(projects)):
            sample.extend(by_proj[p])
        stats.append(mcc_ba(sample)["mcc"])
    stats.sort()
    return stats[int(0.025 * N_BOOT)], stats[int(0.975 * N_BOOT)]


def score_slice(rows, label, rng):
    out = {"slice": label, "n": len(rows),
           "bucket_mix": dict(Counter(r["bucket"] for r in rows)),
           "gold_mix": dict(Counter(r["gold"] for r in rows)),
           "judges": {}}
    for j in JUDGES:
        m = mcc_ba([(r["gold"], r[j]) for r in rows])
        lo, hi = cluster_bootstrap_mcc(rows, j, rng)
        m["mcc_ci_cluster"] = [lo, hi]
        out["judges"][j] = m
    return out


def main():
    hl_dir = ROOT / "data/exam/sastbench250_handlabel"
    merged = json.loads((hl_dir / "four_judge_merged.json").read_text(encoding="utf-8"))
    cid_map = dict(json.loads((hl_dir / "hand_label_case_id_map.json").read_text(encoding="utf-8")))
    v832 = {r["case_id"]: norm(r["predicted_verdict"])
            for r in json.loads((ROOT / "runs/v8_3_2/v8_3_2_sastbench250_outputs.json").read_text(encoding="utf-8"))}
    proj = {c["metadata"]["case_id"]: c["metadata"]["project_id"]
            for c in json.loads((ROOT / "data/eval/sastbench_v01_subset250.json").read_text(encoding="utf-8"))}

    rows = []
    dropped = 0
    for r in merged:
        case_id = cid_map[r["blind_id"]]["original_case_id"]
        row = {
            "blind_id": r["blind_id"],
            "case_id": case_id,
            "bucket": r["bucket"],
            "project_id": proj[case_id],
            "sb": norm(r["sb"]),
            "sonnet": norm(r["sonnet"]),
            "gemini": norm(r["gemini"]),
            "ours": norm(r["ours"]),
            "v832": v832.get(case_id),
            "human": norm(r["human"]),
            "gpt53": norm(r["gpt53"]),
            "human_conf": r.get("human_conf"),
            "gpt53_conf": r.get("gpt53_conf"),
        }
        if row["human"] is None or row["gpt53"] is None:
            dropped += 1
            continue
        rows.append(row)

    core = [dict(r, gold=r["human"]) for r in rows if r["human"] == r["gpt53"]]
    hi_core = [r for r in core
               if r["human_conf"] == "HIGH" and r["gpt53_conf"] == "HIGH"]

    rng = random.Random(SEED)
    result = {
        "seed": SEED,
        "n_boot": N_BOOT,
        "n_handlabel": len(merged),
        "n_with_anchor_verdicts": len(rows),
        "n_dropped_missing_anchor": dropped,
        "definition": "gold = verdict where human pass-1 anchor == GPT-5.3-codex (blind)",
        "caveat": ("Core inherits Human<->GPT-5.3 correlation (71.7% pairwise) and "
                   "skews to unambiguous cases. Internal compass only. "
                   "Human/GPT-5.3 are 100% by construction, not reported."),
        "slices": [
            score_slice(core, "gold_core (human==gpt53)", rng),
            score_slice(hi_core, "gold_core_high_conf (both HIGH)", rng),
        ],
    }

    out_path = ROOT / "runs/gold_core_metrics.json"
    out_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"saved -> {out_path}\n")

    for sl in result["slices"]:
        print(f"== {sl['slice']}  n={sl['n']}  gold_mix={sl['gold_mix']}  "
              f"bucket_mix={sl['bucket_mix']}")
        print(f"{'judge':<18}{'agree':>7}{'MCC':>8}{'cluster CI':>20}{'BA':>7}{'DR':>7}{'FAR':>7}")
        for j in JUDGES:
            m = sl["judges"][j]
            ci = m["mcc_ci_cluster"]
            print(f"{JUDGE_LABELS[j]:<18}{m['agreement']:>7.1%}{m['mcc']:>8.3f}"
                  f"{'[' + format(ci[0], '+.3f') + ', ' + format(ci[1], '+.3f') + ']':>20}"
                  f"{m['ba']:>7.3f}{m['dr']:>7.1%}{m['far']:>7.1%}")
        print()


if __name__ == "__main__":
    main()

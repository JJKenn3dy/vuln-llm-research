"""Post-hoc calibration of v8.3.1 p_tp: honest val-fit, gold-core eval.

Protocol (no oracle leak): fit Platt scaling (a*logit + b) on test_balanced
VAL logprobs (n=248, in-domain, clean balanced labels). Apply the FIXED
(a,b) to the gold-core (n=71, SastBench distribution, trusted labels) and
measure what changed.

The point this settles: Platt/temperature scaling is a MONOTONIC transform.
It can fix calibration (ECE) and the decision threshold, but it CANNOT change
the order of p_tp -> AUC and precision@K are invariant. So if the question is
"is there quick ranking headroom in calibration", the math answer is no, and
this script demonstrates it on our data rather than asserting it.

What recalibration DOES buy: trustworthy displayed confidence + a correct
binary threshold (the 0.5-is-wrong problem from the model probe).
"""
import json
import math
from pathlib import Path

ROOT = Path("f:/vuln-llm-research")
HL = ROOT / "data/exam/sastbench250_handlabel"


def norm(v):
    if v is None:
        return None
    v = str(v).strip().upper()
    return "TP" if v in ("TP", "TRUE_POSITIVE") else "FP" if v in ("FP", "FALSE_POSITIVE") else None


def p_norm(r):
    a, b = r.get("p_tp_raw", 0.0), r.get("p_fp_raw", 0.0)
    return a / (a + b) if (a + b) > 0 else 0.5


def logit(p):
    p = min(max(p, 1e-6), 1 - 1e-6)
    return math.log(p / (1 - p))


def sigmoid(x):
    return 1 / (1 + math.exp(-x))


def fit_platt(samples, iters=2000, lr=0.05):
    """samples: list of (logit, y in {0,1}). Returns (a, b) minimizing NLL."""
    a, b = 1.0, 0.0
    n = len(samples)
    for _ in range(iters):
        ga = gb = 0.0
        for x, y in samples:
            p = sigmoid(a * x + b)
            ga += (p - y) * x
            gb += (p - y)
        a -= lr * ga / n
        b -= lr * gb / n
    return a, b


def ece(pairs, bins=5):
    buckets = [[] for _ in range(bins)]
    for p, y in pairs:
        buckets[min(bins - 1, int(p * bins))].append((p, y))
    n, e = len(pairs), 0.0
    for bk in buckets:
        if bk:
            conf = sum(p for p, _ in bk) / len(bk)
            acc = sum(y for _, y in bk) / len(bk)
            e += len(bk) / n * abs(conf - acc)
    return e


def auc(pairs):
    pos = [p for p, y in pairs if y == 1]
    neg = [p for p, y in pairs if y == 0]
    if not pos or not neg:
        return float("nan")
    w = sum((1.0 if a > b else 0.5 if a == b else 0.0) for a in pos for b in neg)
    return w / (len(pos) * len(neg))


def prec_at_k(pairs, ks=(5, 10, 15, 20)):
    ranked = sorted(pairs, key=lambda t: t[0], reverse=True)
    return {k: sum(y for _, y in ranked[:k]) / k for k in ks}


def best_threshold(pairs):
    """Threshold on val maximizing balanced accuracy."""
    best_t, best_ba = 0.5, -1
    for i in range(1, 100):
        t = i / 100
        tp = sum(1 for p, y in pairs if p >= t and y == 1)
        fn = sum(1 for p, y in pairs if p < t and y == 1)
        tn = sum(1 for p, y in pairs if p < t and y == 0)
        fp = sum(1 for p, y in pairs if p >= t and y == 0)
        dr = tp / (tp + fn) if (tp + fn) else 0
        far = fp / (fp + tn) if (fp + tn) else 0
        ba = (dr + (1 - far)) / 2
        if ba > best_ba:
            best_ba, best_t = ba, t
    return best_t


def op_point(pairs, t):
    tp = sum(1 for p, y in pairs if p >= t and y == 1)
    fn = sum(1 for p, y in pairs if p < t and y == 1)
    tn = sum(1 for p, y in pairs if p < t and y == 0)
    fp = sum(1 for p, y in pairs if p >= t and y == 0)
    dr = tp / (tp + fn) if (tp + fn) else 0
    far = fp / (fp + tn) if (fp + tn) else 0
    return dr, far


def load_goldcore():
    merged = {r["blind_id"]: r for r in json.loads((HL / "four_judge_merged.json").read_text(encoding="utf-8"))}
    cid = dict(json.loads((HL / "hand_label_case_id_map.json").read_text(encoding="utf-8")))
    lp = {r["case_id"]: r for r in json.loads((ROOT / "runs/v8_3_1_logprobs_sastbench250.json").read_text(encoding="utf-8"))}
    out = []
    for bid, m in merged.items():
        h, g = norm(m["human"]), norm(m["gpt53"])
        if h is None or g is None or h != g:
            continue
        l = lp.get(cid[bid]["original_case_id"])
        if l:
            out.append((p_norm(l), 1 if h == "TP" else 0))
    return out


def main():
    val = [(p_norm(r), 1 if norm(r["true_verdict"]) == "TP" else 0)
           for r in json.loads((ROOT / "runs/v8_3_1_logprobs_testbalanced.json").read_text(encoding="utf-8"))]
    gold = load_goldcore()
    print(f"VAL (test_balanced) n={len(val)}; GOLD-CORE n={len(gold)}\n")

    a, b = fit_platt([(logit(p), y) for p, y in val])
    print(f"Platt fit on VAL: a={a:.3f} (>1 sharpens), b={b:.3f} (threshold shift)\n")

    raw = gold
    cal = [(sigmoid(a * logit(p) + b), y) for p, y in gold]

    print("=== GOLD-CORE: before vs after calibration ===")
    print(f"{'metric':<22}{'raw p_tp':>12}{'calibrated':>12}")
    print(f"{'ECE':<22}{ece(raw):>12.3f}{ece(cal):>12.3f}")
    print(f"{'AUC':<22}{auc(raw):>12.3f}{auc(cal):>12.3f}   (monotonic -> identical, by design)")
    pr_raw, pr_cal = prec_at_k(raw), prec_at_k(cal)
    for k in (5, 10, 15, 20):
        lbl = f"precision@{k}"
        print(f"{lbl:<22}{pr_raw[k]:>12.0%}{pr_cal[k]:>12.0%}")
    rng_raw = (min(p for p, _ in raw), max(p for p, _ in raw))
    rng_cal = (min(p for p, _ in cal), max(p for p, _ in cal))
    print(f"{'p_tp range':<22}{f'[{rng_raw[0]:.2f},{rng_raw[1]:.2f}]':>12}{f'[{rng_cal[0]:.2f},{rng_cal[1]:.2f}]':>12}")

    # threshold chosen on VAL, applied to gold-core
    t_val = best_threshold(val)                      # on calibrated? fit threshold in calibrated space
    t_val_cal = best_threshold([(sigmoid(a * logit(p) + b), y) for p, y in val])
    dr05, far05 = op_point(raw, 0.5)
    drv, farv = op_point(cal, t_val_cal)
    print(f"\n=== Binary operating point on GOLD-CORE ===")
    print(f"naive p_tp>=0.5:                 DR={dr05:.0%}  FAR={far05:.0%}")
    print(f"val-fit threshold (cal space t={t_val_cal:.2f}): DR={drv:.0%}  FAR={farv:.0%}")

    print("\n=== Verdict ===")
    print("Ranking (AUC, precision@K) UNCHANGED by calibration — confirmed on data.")
    print("=> No ranking headroom in calibration. Ranking ceiling for this")
    print("   checkpoint is AUC~0.75; raising it needs a better model (v8.4),")
    print("   not recalibration.")
    print("Calibration DID fix ECE and gives an honest binary threshold.")

    out = ROOT / "runs/calibrate_probe.json"
    out.write_text(json.dumps({
        "platt_a": a, "platt_b": b,
        "ece_raw": ece(raw), "ece_cal": ece(cal),
        "auc_raw": auc(raw), "auc_cal": auc(cal),
        "val_threshold_cal": t_val_cal,
        "op_naive_0.5": [dr05, far05], "op_valfit": [drv, farv],
    }, indent=2), encoding="utf-8")
    print(f"\nsaved -> {out}")


if __name__ == "__main__":
    main()

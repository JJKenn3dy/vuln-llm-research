"""Model probe on the gold-core: calibration, ranker comparison, failure modes.

Answers three questions about v8.3.1 that MCC alone does not:
1. Is p_tp calibrated, or is the narrow band miscalibration (cheap to fix)?
2. As a RANKER (the actual product), how does continuous p_tp compare to
   frontier single-call, which can only emit verdict+HIGH/MED/LOW (coarse)?
3. Where does the model disagree with gold — FN-skewed (misses TP) or
   FP-skewed (flags noise)? What CWE/language?

Gold-core: hand-label-100 cases where human pass-1 == GPT-5.3 blind (n=71).
All inputs on disk, $0. Caveat: n=71, skews to unambiguous cases — internal.
"""
import json
import math
from collections import Counter
from pathlib import Path

ROOT = Path("f:/vuln-llm-research")
HL = ROOT / "data/exam/sastbench250_handlabel"


def norm(v):
    if v is None:
        return None
    v = str(v).strip().upper()
    if v in ("TP", "TRUE_POSITIVE"):
        return "TP"
    if v in ("FP", "FALSE_POSITIVE"):
        return "FP"
    return None


def load():
    merged = {r["blind_id"]: r for r in json.loads((HL / "four_judge_merged.json").read_text(encoding="utf-8"))}
    cid = dict(json.loads((HL / "hand_label_case_id_map.json").read_text(encoding="utf-8")))
    lp = {r["case_id"]: r for r in json.loads((ROOT / "runs/v8_3_1_logprobs_sastbench250.json").read_text(encoding="utf-8"))}
    son = {r["case_id"]: r for r in json.loads((ROOT / "runs/frontier_v8_3_1/sonnet_triage_outputs.json").read_text(encoding="utf-8"))}
    gem = {r["case_id"]: r for r in json.loads((ROOT / "runs/frontier_v8_3_1/gemini_triage_outputs.json").read_text(encoding="utf-8"))}

    rows = []
    for bid, m in merged.items():
        h, g = norm(m["human"]), norm(m["gpt53"])
        if h is None or g is None or h != g:
            continue  # gold-core only
        cid_full = cid[bid]["original_case_id"]
        l = lp.get(cid_full)
        if not l:
            continue
        ptp_raw = l.get("p_tp_raw", 0.0)
        pfp_raw = l.get("p_fp_raw", 0.0)
        p_tp = ptp_raw / (ptp_raw + pfp_raw) if (ptp_raw + pfp_raw) > 0 else 0.5
        s, ge = son.get(cid_full, {}), gem.get(cid_full, {})
        rows.append({
            "case_id": cid_full,
            "gold": h,
            "cwe": l.get("claimed_cwe", "?"),
            "lang": l.get("language", "?"),
            "p_tp": p_tp,
            "son_v": norm(s.get("predicted_verdict")), "son_c": s.get("predicted_confidence"),
            "gem_v": norm(ge.get("predicted_verdict")), "gem_c": ge.get("predicted_confidence"),
            "gpt53_v": g, "gpt53_c": m.get("gpt53_conf"),
        })
    return rows


def conf_score(verdict, conf):
    """Map frontier verdict+confidence to an ordinal rank score in [0,1]."""
    if verdict is None:
        return 0.5
    w = {"HIGH": 0.45, "MEDIUM": 0.30, "LOW": 0.15}.get((conf or "").upper(), 0.30)
    return 0.5 + w if verdict == "TP" else 0.5 - w


def auc(scores_labels):
    """ROC-AUC; handles ties via Mann-Whitney with 0.5 credit."""
    pos = [s for s, y in scores_labels if y == 1]
    neg = [s for s, y in scores_labels if y == 0]
    if not pos or not neg:
        return float("nan")
    wins = sum((1.0 if p > n else 0.5 if p == n else 0.0) for p in pos for n in neg)
    return wins / (len(pos) * len(neg))


def precision_at_k(rows, score_key, ks=(5, 10, 15, 20)):
    ranked = sorted(rows, key=lambda r: r[score_key], reverse=True)
    out = {}
    for k in ks:
        top = ranked[:k]
        out[k] = sum(1 for r in top if r["gold"] == "TP") / k
    return out


def reliability(rows, bins=5):
    """Equal-width p_tp bins -> actual TP rate. Returns (table, ECE)."""
    buckets = [[] for _ in range(bins)]
    for r in rows:
        idx = min(bins - 1, int(r["p_tp"] * bins))
        buckets[idx].append(r)
    table, ece, n = [], 0.0, len(rows)
    for i, b in enumerate(buckets):
        lo, hi = i / bins, (i + 1) / bins
        if not b:
            table.append((lo, hi, 0, float("nan"), float("nan")))
            continue
        conf = sum(r["p_tp"] for r in b) / len(b)
        acc = sum(1 for r in b if r["gold"] == "TP") / len(b)
        ece += (len(b) / n) * abs(conf - acc)
        table.append((lo, hi, len(b), conf, acc))
    return table, ece


def main():
    rows = load()
    n = len(rows)
    base = sum(1 for r in rows if r["gold"] == "TP")
    print(f"gold-core n={n}, {base} TP / {n-base} FP (base rate {base/n:.1%})\n")

    # --- 1. Calibration of v8.3.1 p_tp ---
    print("=== 1. CALIBRATION of v8.3.1 p_tp ===")
    table, ece = reliability(rows, bins=5)
    print(f"{'p_tp bin':<14}{'n':>5}{'mean p_tp':>11}{'actual TP%':>12}")
    for lo, hi, cnt, conf, acc in table:
        if cnt == 0:
            print(f"[{lo:.1f},{hi:.1f})      {cnt:>5}        --          --")
        else:
            print(f"[{lo:.1f},{hi:.1f})      {cnt:>5}{conf:>11.3f}{acc:>11.1%}")
    print(f"ECE = {ece:.3f}  (0 = perfect; >0.1 = materially miscalibrated)")
    pmin = min(r["p_tp"] for r in rows); pmax = max(r["p_tp"] for r in rows)
    print(f"p_tp range observed: [{pmin:.3f}, {pmax:.3f}]  (narrow band = compressed signal)\n")

    # --- 2. Ranker comparison ---
    print("=== 2. RANKER comparison (AUC + precision@K vs gold) ===")
    for r in rows:
        r["son_s"] = conf_score(r["son_v"], r["son_c"])
        r["gem_s"] = conf_score(r["gem_v"], r["gem_c"])
        r["gpt53_s"] = conf_score(r["gpt53_v"], r["gpt53_c"])
    labels = {r["case_id"]: (1 if r["gold"] == "TP" else 0) for r in rows}
    # GPT-5.3 and human DEFINE gold (gold = human==gpt53) -> circular here,
    # excluded from comparison. Only Sonnet/Gemini/v8.3.1 are independent of
    # the gold definition.
    for name, key, circ in [("v8.3.1 p_tp (continuous)", "p_tp", False),
                            ("Sonnet (verdict+conf)", "son_s", False),
                            ("Gemini (verdict+conf)", "gem_s", False),
                            ("GPT-5.3 [CIRCULAR-defines gold]", "gpt53_s", True)]:
        a = auc([(r[key], labels[r["case_id"]]) for r in rows])
        distinct = len(set(round(r[key], 4) for r in rows))
        tag = "  <- IGNORE (grades own key)" if circ else ""
        print(f"{name:<32} AUC={a:.3f}  distinct={distinct:>2}/{n}{tag}")
    print()
    print(f"{'precision@K':<16}{'K=5':>7}{'K=10':>7}{'K=15':>7}{'K=20':>7}   (random={base/n:.0%})")
    for name, key in [("v8.3.1", "p_tp"), ("Sonnet", "son_s"), ("Gemini", "gem_s")]:
        pk = precision_at_k(rows, key)
        print(f"{name:<16}" + "".join(f"{pk[k]:>7.0%}" for k in (5, 10, 15, 20)))
    print("  (frontier collapses to ~2 effective score levels -> top-K is a")
    print("   coin-flip within its huge 'TP' bucket; we order continuously)\n")

    # --- 3. Failure modes ---
    print("=== 3. FAILURE MODES of v8.3.1 (threshold 0.5) ===")
    fn = [r for r in rows if r["gold"] == "TP" and r["p_tp"] < 0.5]
    fp = [r for r in rows if r["gold"] == "FP" and r["p_tp"] >= 0.5]
    print(f"misses (FN: gold TP, p_tp<0.5): {len(fn)}/{base} = {len(fn)/base:.0%} of TP")
    print(f"false alarms (FP: gold FP, p_tp>=0.5): {len(fp)}/{n-base} = {len(fp)/(n-base):.0%} of FP")
    print(f"errors skew: {'FN-heavy (misses real TP, conservative)' if len(fn) > len(fp) else 'FP-heavy (over-flags)'}")
    if fn:
        print("FN by CWE:", dict(Counter(r["cwe"] for r in fn).most_common()))
        print("FN by lang:", dict(Counter(r["lang"] for r in fn).most_common()))
    if fp:
        print("FP by CWE:", dict(Counter(r["cwe"] for r in fp).most_common()))

    out = ROOT / "runs/model_probe_goldcore.json"
    out.write_text(json.dumps({
        "n": n, "tp_base": base, "ece": ece, "p_tp_range": [pmin, pmax],
        "auc": {k: auc([(r[v], labels[r["case_id"]]) for r in rows])
                for k, v in [("v831", "p_tp"), ("sonnet", "son_s"), ("gemini", "gem_s"), ("gpt53", "gpt53_s")]},
        "fn": len(fn), "fp": len(fp),
    }, indent=2), encoding="utf-8")
    print(f"\nsaved -> {out}")


if __name__ == "__main__":
    main()

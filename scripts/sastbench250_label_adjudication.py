"""Apply the same pre-commit adjudication rule used on the 10 hand-label
contested cases (11.06 night) to all 250 SastBench cases.

For each case we have:
  - SastBench-shipped label  (the "ground truth" everyone benchmarks against)
  - Sonnet 4.5 single-call verdict   (frontier judge A)
  - Gemini 2.5 Pro single-call verdict (frontier judge B)
  - v8.3.1 verdict (our model — recorded for the signal-test step below)

Pre-commit rule:
  * SB == Sonnet == Gemini  -> clean_consistent  (label trustworthy)
  * Sonnet == Gemini != SB   -> strong_mislabel  (two frontiers contradict SB)
  * SB == Sonnet != Gemini OR
    SB == Gemini != Sonnet  -> one_frontier_dissent (uncertain)

Then:
  * Recompute v8.3.1 MCC on the clean_consistent subset only.
  * Compare with the headline number on the full 250.
  * If clean MCC > full MCC: SB label noise actually hurts our reported number;
    v8.3.1 does have a non-trivial signal under cleaner labels.
  * If clean MCC <= full MCC: v8.3.1's apparent signal on the full set was
    correlated with the noisy labels themselves (Zakhar's "accidental
    correlation" hypothesis).
"""
from __future__ import annotations

import json
import math
from collections import Counter
from pathlib import Path


def parse_v(s: str) -> str:
    if not s: return "?"
    s = s.upper()
    if "TRUE_POSITIVE" in s or s.strip() == "TP": return "TP"
    if "FALSE_POSITIVE" in s or s.strip() == "FP": return "FP"
    return "?"


def mcc(tp, fp, tn, fn):
    denom = math.sqrt((tp+fp)*(tp+fn)*(tn+fp)*(tn+fn))
    if denom == 0: return 0.0
    return (tp*tn - fp*fn)/denom


def main():
    root = Path("f:/vuln-llm-research")
    v83 = {r["case_id"]: r for r in json.loads((root/"runs/v8_3_1_sastbench250_outputs.json").read_text(encoding="utf-8"))}
    sonnet = {r["case_id"]: r for r in json.loads((root/"runs/frontier_v8_3_1/sonnet_triage_outputs.json").read_text(encoding="utf-8"))}
    gemini = {r["case_id"]: r for r in json.loads((root/"runs/frontier_v8_3_1/gemini_triage_outputs.json").read_text(encoding="utf-8"))}

    case_ids = set(v83) & set(sonnet) & set(gemini)
    print(f"cases with all 4 sources (v8.3.1 + Sonnet + Gemini + SB-truth): {len(case_ids)}")

    rows = []
    for cid in case_ids:
        sb = parse_v(v83[cid].get("true_verdict", ""))
        son = parse_v(sonnet[cid].get("predicted_verdict", ""))
        gem = parse_v(gemini[cid].get("predicted_verdict", ""))
        ours = parse_v(v83[cid].get("predicted_verdict", ""))
        if "?" in (sb, son, gem, ours):
            continue
        if sb == son == gem: bucket = "clean_consistent"
        elif son == gem != sb: bucket = "strong_mislabel"
        else: bucket = "one_frontier_dissent"
        rows.append({"case_id": cid, "sb": sb, "sonnet": son, "gemini": gem, "ours": ours, "bucket": bucket})

    print(f"clean rows (no parse-fail anywhere): {len(rows)}")
    bucket_counts = Counter(r["bucket"] for r in rows)
    print(f"\nbucket distribution:")
    for b, n in bucket_counts.most_common():
        print(f"  {b:25s}  {n:>3d}  ({n/len(rows):.1%})")

    print("\n=== v8.3.1 verdict accuracy by bucket ===")
    print(f"{'bucket':25s}  {'N':>4s}  {'TP':>4s}  {'FN':>4s}  {'TN':>4s}  {'FP':>4s}  {'DR':>6s}  {'FAR':>6s}  {'MCC':>7s}")
    for bucket in ["clean_consistent", "strong_mislabel", "one_frontier_dissent", "ALL"]:
        sub = rows if bucket == "ALL" else [r for r in rows if r["bucket"] == bucket]
        if not sub: continue
        tp = sum(1 for r in sub if r["sb"]=="TP" and r["ours"]=="TP")
        fn = sum(1 for r in sub if r["sb"]=="TP" and r["ours"]=="FP")
        tn = sum(1 for r in sub if r["sb"]=="FP" and r["ours"]=="FP")
        fp = sum(1 for r in sub if r["sb"]=="FP" and r["ours"]=="TP")
        dr = tp/max(tp+fn,1)
        far = fp/max(fp+tn,1)
        m = mcc(tp, fp, tn, fn)
        print(f"  {bucket:23s}  {len(sub):4d}  {tp:4d}  {fn:4d}  {tn:4d}  {fp:4d}  {dr:6.1%}  {far:6.1%}  {m:+7.3f}")

    print("\n=== Strong-mislabel candidates (where v8.3.1 sided with frontier vs SB) ===")
    sm = [r for r in rows if r["bucket"] == "strong_mislabel"]
    sm_agree_frontier = [r for r in sm if r["ours"] == r["sonnet"]]
    print(f"  total strong_mislabel: {len(sm)}")
    print(f"  v8.3.1 agrees with frontier (against SB): {len(sm_agree_frontier)}")
    print(f"  v8.3.1 sides with SB: {len(sm) - len(sm_agree_frontier)}")

    print("\n=== Alternative: 'effective' label as majority of {SB, Sonnet, Gemini} ===")
    eff_tp = eff_fn = eff_tn = eff_fp = 0
    for r in rows:
        votes = [r["sb"], r["sonnet"], r["gemini"]]
        majority = "TP" if votes.count("TP") >= 2 else "FP"
        if majority == "TP" and r["ours"] == "TP": eff_tp += 1
        elif majority == "TP" and r["ours"] == "FP": eff_fn += 1
        elif majority == "FP" and r["ours"] == "FP": eff_tn += 1
        else: eff_fp += 1
    eff_mcc = mcc(eff_tp, eff_fp, eff_tn, eff_fn)
    print(f"  N={len(rows)}  TP={eff_tp} FN={eff_fn} TN={eff_tn} FP={eff_fp}  MCC={eff_mcc:+.3f}")
    print(f"  (compare to SB-label MCC on ALL: {mcc(*[sum(1 for r in rows if (r['sb'],r['ours'])==('TP','TP')), sum(1 for r in rows if (r['sb'],r['ours'])==('FP','TP')), sum(1 for r in rows if (r['sb'],r['ours'])==('FP','FP')), sum(1 for r in rows if (r['sb'],r['ours'])==('TP','FP'))]):+.3f})")

    out_path = root/"runs/sastbench250_label_adjudication.json"
    out_path.write_text(json.dumps(rows, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\nwrote per-case adjudication to {out_path}")


if __name__ == "__main__":
    main()

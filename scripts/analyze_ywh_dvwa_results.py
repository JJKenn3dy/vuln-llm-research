"""Analyze v8.3.1 outputs on the yeswehack + DVWA eval set.

Inputs:
  data/eval/ywh_dvwa_eval.json     (raw cases with truth)
  runs/v8_3_1_outputs.json          (from src.eval.run_triage_eval)

Produces:
  - per-CWE detection matrix (yeswehack: TP rate)
  - DVWA mitigation matrix (per module: low/medium/high TP rate + impossible FP rate)
  - confusion overall
  - source split: yeswehack vs DVWA
"""
import json
import re
import sys
from collections import defaultdict
from pathlib import Path


VERDICT_RE = re.compile(
    r"^\s*Verdict:\s*(TRUE_POSITIVE|FALSE_POSITIVE|TP|FP)\b",
    re.IGNORECASE | re.MULTILINE,
)


def parse_verdict(text: str) -> str:
    m = VERDICT_RE.search(text or "")
    if not m:
        return "PARSE_FAIL"
    v = m.group(1).upper()
    return "TRUE_POSITIVE" if v in ("TP", "TRUE_POSITIVE") else "FALSE_POSITIVE"


def mcc(tp, fp, tn, fn):
    import math
    denom = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    if denom == 0:
        return 0.0
    return (tp * tn - fp * fn) / denom


def main(eval_path: str, outputs_path: str, out_md: str | None = None):
    cases_by_id = {c["case_id"]: c for c in json.loads(Path(eval_path).read_text(encoding="utf-8"))}
    outs = json.loads(Path(outputs_path).read_text(encoding="utf-8"))

    rows = []
    for o in outs:
        cid = o.get("case_id")
        c = cases_by_id.get(cid)
        if c is None:
            continue
        text = o.get("response") or o.get("output") or ""
        pred = parse_verdict(text)
        rows.append({
            "case_id": cid,
            "source": c["source"],
            "category": c["category"],
            "claimed_cwe": c["claimed_cwe"],
            "defense_level": c.get("defense_level", "vulnerable"),
            "truth": c["truth"],
            "pred": pred,
            "response": text,
        })

    lines = []
    def emit(line=""):
        print(line)
        lines.append(line)

    emit("=" * 90)
    emit(f"Total cases evaluated: {len(rows)}")
    n_parse_fail = sum(1 for r in rows if r["pred"] == "PARSE_FAIL")
    emit(f"Parse failures: {n_parse_fail} ({n_parse_fail/len(rows):.1%})")
    emit()

    # ============= Overall =============
    tp = sum(1 for r in rows if r["truth"] == "TRUE_POSITIVE" and r["pred"] == "TRUE_POSITIVE")
    fn = sum(1 for r in rows if r["truth"] == "TRUE_POSITIVE" and r["pred"] != "TRUE_POSITIVE")
    tn = sum(1 for r in rows if r["truth"] == "FALSE_POSITIVE" and r["pred"] == "FALSE_POSITIVE")
    fp = sum(1 for r in rows if r["truth"] == "FALSE_POSITIVE" and r["pred"] == "TRUE_POSITIVE")
    dr = tp / max(tp + fn, 1)
    far = fp / max(fp + tn, 1)
    prec = tp / max(tp + fp, 1)
    emit(f"OVERALL: TP={tp} FN={fn} TN={tn} FP={fp}")
    emit(f"  DR (TP detection rate) = {dr:.1%}")
    emit(f"  FAR (FP-as-TP rate)    = {far:.1%}")
    emit(f"  Precision               = {prec:.1%}")
    emit(f"  MCC                     = {mcc(tp, fp, tn, fn):.3f}")
    emit()

    # ============= yeswehack per CWE =============
    emit("=== yeswehack per-CWE detection rate (TP only) ===")
    by_cwe = defaultdict(list)
    for r in rows:
        if r["source"] != "yeswehack/vulnerable-code-snippets":
            continue
        by_cwe[(r["claimed_cwe"], r["category"])].append(r)
    emit(f"{'CWE':10s}  {'Category':20s}  {'N':>3s}  {'TP detected':>11s}  rate")
    for (cwe, cat), rs in sorted(by_cwe.items(), key=lambda x: -len(x[1])):
        n = len(rs)
        n_tp = sum(1 for r in rs if r["pred"] == "TRUE_POSITIVE")
        rate = n_tp / n if n else 0
        emit(f"  {cwe:8s}  {cat:20s}  {n:3d}  {n_tp:11d}  {rate:.0%}")
    emit()

    # ============= DVWA per module by defense_level =============
    emit("=== DVWA per-module mitigation matrix ===")
    emit(f"{'Module':14s}  {'CWE':8s}  {'low':>5s}  {'medium':>6s}  {'high':>5s}  {'impossible':>10s}")
    dvwa_by_mod = defaultdict(dict)
    for r in rows:
        if r["source"] != "OWASP/DVWA":
            continue
        dvwa_by_mod[r["category"]][r["defense_level"]] = r["pred"]
    for mod in sorted(dvwa_by_mod.keys()):
        levels = dvwa_by_mod[mod]
        cwe = next(r["claimed_cwe"] for r in rows if r["source"] == "OWASP/DVWA" and r["category"] == mod)
        def cell(lvl):
            v = levels.get(lvl, "-")
            if v == "TRUE_POSITIVE": return "TP"
            if v == "FALSE_POSITIVE": return "FP"
            if v == "PARSE_FAIL": return "?"
            return "-"
        emit(f"  {mod:12s}  {cwe:8s}  {cell('low'):>5s}  {cell('medium'):>6s}  {cell('high'):>5s}  {cell('impossible'):>10s}")
    emit()

    # ============= DVWA mitigation-awareness: TP/FP rate by defense level =============
    emit("=== DVWA mitigation awareness (aggregated across modules) ===")
    dvwa_by_lvl = defaultdict(lambda: {"tp": 0, "fp": 0, "n": 0, "truth_tp": 0, "truth_fp": 0})
    for r in rows:
        if r["source"] != "OWASP/DVWA":
            continue
        lvl = r["defense_level"]
        dvwa_by_lvl[lvl]["n"] += 1
        if r["pred"] == "TRUE_POSITIVE":
            dvwa_by_lvl[lvl]["tp"] += 1
        elif r["pred"] == "FALSE_POSITIVE":
            dvwa_by_lvl[lvl]["fp"] += 1
        if r["truth"] == "TRUE_POSITIVE":
            dvwa_by_lvl[lvl]["truth_tp"] += 1
        else:
            dvwa_by_lvl[lvl]["truth_fp"] += 1
    for lvl in ("low", "medium", "high", "impossible"):
        d = dvwa_by_lvl.get(lvl, {})
        if not d:
            continue
        truth_label = "vulnerable" if d["truth_tp"] > 0 else "mitigated"
        emit(f"  {lvl:11s} (truth: {truth_label:10s})  N={d['n']}  predicted_TP={d['tp']}  predicted_FP={d['fp']}")
    emit()

    # ============= source split =============
    emit("=== Source split confusion ===")
    for src in sorted({r["source"] for r in rows}):
        rs = [r for r in rows if r["source"] == src]
        tp = sum(1 for r in rs if r["truth"] == "TRUE_POSITIVE" and r["pred"] == "TRUE_POSITIVE")
        fn = sum(1 for r in rs if r["truth"] == "TRUE_POSITIVE" and r["pred"] != "TRUE_POSITIVE")
        tn = sum(1 for r in rs if r["truth"] == "FALSE_POSITIVE" and r["pred"] == "FALSE_POSITIVE")
        fp = sum(1 for r in rs if r["truth"] == "FALSE_POSITIVE" and r["pred"] == "TRUE_POSITIVE")
        emit(f"  {src}")
        emit(f"    N={len(rs)} TP={tp} FN={fn} TN={tn} FP={fp}  DR={tp/max(tp+fn,1):.1%}  FAR={fp/max(fp+tn,1):.1%}")
    emit()

    if out_md:
        Path(out_md).write_text("\n".join(lines), encoding="utf-8")
        print(f"\nwrote summary to {out_md}")


if __name__ == "__main__":
    eval_path = sys.argv[1] if len(sys.argv) > 1 else "data/eval/ywh_dvwa_eval.json"
    outputs_path = sys.argv[2] if len(sys.argv) > 2 else "runs/v8_3_1_ywh_dvwa_outputs.json"
    out_md = sys.argv[3] if len(sys.argv) > 3 else "runs/v8_3_1_ywh_dvwa_summary.txt"
    main(eval_path, outputs_path, out_md)

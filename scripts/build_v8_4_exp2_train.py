"""Assemble v8.4-exp2 (mixed-anchor) train + held-out test.

exp1 lesson: synthetic-only collapses real-code recall (FP-everything). The fix
needs REAL vulnerable examples that are snippet-sufficient. Those are scarce in
the old pile (69% of real TPs have the sink out of window), so the clean-anchor
from old data is FP-heavy (49 FP / 9 TP). Real TP signal comes from the mined
crossvul vuln halves (real, snippet-sufficient by windowing).

Design:
  - split mined 71 pairs -> 40 train (real anchor) / 31 held-out test (transfer)
  - TRAIN = synthetic XSS (135 pairs) + mined-train (40 pairs) + clean old anchor (58)
  - TEST  = mined held-out (31) + controlled-20 + gold-core (via sastbench)
Mined train pairs get assistant targets (verdict + code-grounded reasoning).

Outputs:
  data/train/v8_4_exp2/train.json, val.json
  data/eval/cwe79_mined_heldout.json   (31 pairs, NOT in train)
"""
import json
import sys
from collections import Counter
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")
ROOT = Path("f:/vuln-llm-research")
OUTDIR = ROOT / "data/train/v8_4_exp2"
SYN = ROOT / "data/train/cwe_web_cybernative/train.json"
SYN_VAL = ROOT / "data/train/cwe_web_cybernative/val.json"
MINED = ROOT / "data/eval/cwe79_mined_pairs.json"
ANCHOR = ROOT / "data/train/clean_anchor/anchor.json"
HELDOUT = ROOT / "data/eval/cwe79_mined_heldout.json"

ASSIST = "Verdict: {v}\nConfidence: HIGH\nReasoning: {r}\nRealCWE: {cwe}\nSuggestedFix: {f}"


def add_target(case):
    """Add assistant target to an eval-format mined case (system+user only)."""
    m = case["metadata"]
    v = m["verdict"]
    if v == "TRUE_POSITIVE":
        r = ("User-controlled data reaches an output sink without context-appropriate "
             "escaping in the shown code, so the finding is a real XSS.")
        f = "Apply context-aware output encoding (e.g. HTML-escape) before the sink."
    else:
        r = ("The flagged output is escaped/encoded before reaching the sink in the shown "
             "code, so the finding is noise.")
        f = "N/A"
    return {"messages": case["messages"] + [
        {"role": "assistant", "content": ASSIST.format(v=v, r=r, cwe=m.get("claimed_cwe", "CWE-79"), f=f)}],
        "metadata": dict(m, source="mined_train")}


def main():
    OUTDIR.mkdir(parents=True, exist_ok=True)
    syn = json.loads(SYN.read_text(encoding="utf-8"))
    syn_val = json.loads(SYN_VAL.read_text(encoding="utf-8"))
    anchor = json.loads(ANCHOR.read_text(encoding="utf-8"))
    mined = json.loads(MINED.read_text(encoding="utf-8"))

    # split mined by pair_id (sorted, deterministic): 40 train / rest test
    pids = sorted({c["metadata"]["pair_id"] for c in mined})
    train_pids = set(pids[:40])
    mined_train_cases, heldout = [], []
    for c in mined:
        if c["metadata"]["pair_id"] in train_pids:
            mined_train_cases.append(add_target(c))
        else:
            heldout.append(c)  # eval format unchanged

    train = syn + mined_train_cases + anchor
    (OUTDIR / "train.json").write_text(json.dumps(train, ensure_ascii=False, indent=1), encoding="utf-8")
    (OUTDIR / "val.json").write_text(json.dumps(syn_val, ensure_ascii=False, indent=1), encoding="utf-8")
    HELDOUT.write_text(json.dumps(heldout, ensure_ascii=False, indent=1), encoding="utf-8")

    def verdicts(cases):
        return dict(Counter(c["metadata"]["verdict"] for c in cases))
    print(f"TRAIN total: {len(train)} cases")
    print(f"  synthetic XSS:  {len(syn)}  {verdicts(syn)}")
    print(f"  mined-train:    {len(mined_train_cases)}  {verdicts(mined_train_cases)}  ({len(train_pids)} pairs)")
    print(f"  clean anchor:   {len(anchor)}  {verdicts(anchor)}")
    print(f"  COMBINED verdict mix: {verdicts(train)}")
    print(f"val: {len(syn_val)} | held-out test: {len(heldout)} cases ({len(pids)-len(train_pids)} pairs)")


if __name__ == "__main__":
    main()

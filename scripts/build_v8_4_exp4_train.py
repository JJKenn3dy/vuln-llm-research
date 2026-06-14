"""Assemble v8.4-exp4: scale the CLEAN real anchor (the right way to multiply exp2).

exp3 lesson: scaling with a relaxed regex filter added noise and hurt recall.
exp4 instead keeps only the real pairs GPT-5.3 discriminates correctly
(vuln->TP AND safe->FP) from the 151-pair scaled pool. That yields MORE clean
real signal than exp2's 40 pairs, without exp3's noise.

TRAIN = synthetic XSS (135 pairs) + GPT-5.3-clean real anchor + clean old anchor.
TEST  = held-out 31 mined pairs (unchanged), controlled-20, gold-core.

Requires runs/scaled_anchor_gpt53.json (GPT-5.3 validation output).
"""
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")
ROOT = Path("f:/vuln-llm-research")
OUTDIR = ROOT / "data/train/v8_4_exp4"


def norm(v):
    v = (v or "").strip().upper()
    return "TP" if v in ("TP", "TRUE_POSITIVE") else "FP" if v in ("FP", "FALSE_POSITIVE") else None


def main():
    OUTDIR.mkdir(parents=True, exist_ok=True)
    syn = json.loads((ROOT / "data/train/cwe_web_cybernative/train.json").read_text(encoding="utf-8"))
    syn_val = json.loads((ROOT / "data/train/cwe_web_cybernative/val.json").read_text(encoding="utf-8"))
    old = json.loads((ROOT / "data/train/clean_anchor/anchor.json").read_text(encoding="utf-8"))
    anchor_full = json.loads((ROOT / "data/train/real_anchor_scaled/anchor.json").read_text(encoding="utf-8"))
    val = json.loads((ROOT / "runs/scaled_anchor_gpt53.json").read_text(encoding="utf-8"))

    # pairs GPT-5.3 discriminates correctly: vuln->TP AND safe->FP
    preds = defaultdict(dict)
    for r in val["rows"]:
        preds[r["pair_id"]][r["variant"]] = r["pred"]
    clean_pairs = {pid for pid, p in preds.items()
                   if p.get("vuln") == "TP" and p.get("safe") == "FP"}

    clean_anchor = [c for c in anchor_full if c["metadata"]["pair_id"] in clean_pairs]
    train = syn + clean_anchor + old
    (OUTDIR / "train.json").write_text(json.dumps(train, ensure_ascii=False, indent=1), encoding="utf-8")
    (OUTDIR / "val.json").write_text(json.dumps(syn_val, ensure_ascii=False, indent=1), encoding="utf-8")

    def vc(c):
        return dict(Counter(x["metadata"]["verdict"] for x in c))
    n_full_pairs = len({c["metadata"]["pair_id"] for c in anchor_full})
    print(f"GPT-5.3 clean pairs: {len(clean_pairs)}/{n_full_pairs} = {len(clean_pairs)/n_full_pairs:.0%}")
    print(f"exp4 train: {len(train)} cases")
    print(f"  synthetic:          {len(syn)} {vc(syn)}")
    print(f"  clean real anchor:  {len(clean_anchor)} {vc(clean_anchor)}  ({len(clean_pairs)} pairs, GPT-5.3-validated)")
    print(f"  clean old anchor:   {len(old)} {vc(old)}")
    print(f"  COMBINED: {vc(train)}")
    print(f"  (exp2 had 40 clean real pairs; exp4 has {len(clean_pairs)})")


if __name__ == "__main__":
    main()

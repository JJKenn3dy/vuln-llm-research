"""exp9: exp5's WINNING principle (clean consensus labels, BALANCED ~1:1 via
oversampling) + escaping pairs.

Lessons locked from exp5-8:
- exp5 (consensus + TP x3 -> balanced 144/160): best (0.695), but escaping-blind.
- exp8 (consensus + escaping, NO oversample -> 176/300 FP-heavy): recall DIED (DR 12%).
  => oversampling to BALANCE is necessary on this FP-heavy data, not optional.
exp9 = consensus + escaping pairs, oversample TP up to ~= FP count (clean labels this
time, unlike exp7's noisy GLM-solo). Target: exp5's DR/FAR balance AND escaping.
"""
import json
import random
from collections import Counter
from pathlib import Path

ROOT = Path("f:/vuln-llm-research")
OUT = ROOT / "data/train/v8_4_exp9"
OUT.mkdir(parents=True, exist_ok=True)
rng = random.Random(42)

cons = json.loads((ROOT / "runs/exp5_dual_train.json").read_text(encoding="utf-8"))
esc = json.loads((ROOT / "data/train/cwe_web_cybernative/train.json").read_text(encoding="utf-8"))


def v(x):
    m = x["metadata"]
    return m.get("consensus_verdict") or m.get("verdict")


allrows = cons + esc
tp = [x for x in allrows if v(x) == "TRUE_POSITIVE"]
fp = [x for x in allrows if v(x) == "FALSE_POSITIVE"]
rng.shuffle(tp); rng.shuffle(fp)

val = tp[:15] + fp[:15]
tp_tr, fp_tr = tp[15:], fp[15:]
# oversample TP up to ~= FP count (balance ~1:1), clean labels
factor = max(1, round(len(fp_tr) / len(tp_tr)))
tp_os = (tp_tr * (factor + 1))[:len(fp_tr)]     # fill up to FP count
train = tp_os + fp_tr
rng.shuffle(train); rng.shuffle(val)

(OUT / "train.json").write_text(json.dumps(train, ensure_ascii=False, indent=2), encoding="utf-8")
(OUT / "val.json").write_text(json.dumps(val, ensure_ascii=False, indent=2), encoding="utf-8")
meta = {
    "recipe": "consensus (236) + escaping pairs (270), TP oversampled to balance ~1:1",
    "unique_tp": len(tp_tr), "unique_fp": len(fp_tr), "balance_target": "~1:1",
    "train_n": len(train), "train_dist": dict(Counter(v(x) for x in train)),
    "val_n": len(val), "val_dist": dict(Counter(v(x) for x in val)),
}
(OUT / "build_meta.json").write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
print(json.dumps(meta, ensure_ascii=False, indent=2))

"""exp7 train: balance the exp5/exp6 tradeoff.

exp5 (TP x3, no escaping pairs): gold-core 0.695 (DR 68%) but escaping-blind (0.229).
exp6 (no oversample, +escaping pairs): escaping fixed (0.655) but recall crashed (0.555, DR 45%).
Lesson: TP weight drives recall; escaping pairs drive escaping. Balance both.

exp7 = exp6 components (GLM-solo relabel + CyberNative escaping pairs) with a
MODERATE TP oversample x2 (not x3 paranoia, not x1 conservative) -> restore recall
while keeping the escaping signal.
"""
import json
import random
from collections import Counter
from pathlib import Path

ROOT = Path("f:/vuln-llm-research")
OUT = ROOT / "data/train/v8_4_exp7"
OUT.mkdir(parents=True, exist_ok=True)
rng = random.Random(42)

glm = json.loads((ROOT / "runs/exp6_glm_train.json").read_text(encoding="utf-8"))
esc = json.loads((ROOT / "data/train/cwe_web_cybernative/train.json").read_text(encoding="utf-8"))


def gv(x):
    return x["metadata"].get("glm_verdict") or x["metadata"].get("verdict")


# pool: GLM relabel + escaping pairs
allrows = glm + esc
tp = [x for x in allrows if gv(x) == "TRUE_POSITIVE"]
fp = [x for x in allrows if gv(x) == "FALSE_POSITIVE"]
rng.shuffle(tp); rng.shuffle(fp)

# balanced val held out before oversampling
val = tp[:15] + fp[:15]
tp_tr, fp_tr = tp[15:], fp[15:]
OVERSAMPLE = 2
train = (tp_tr * OVERSAMPLE) + fp_tr          # moderate TP x2
rng.shuffle(train); rng.shuffle(val)

(OUT / "train.json").write_text(json.dumps(train, ensure_ascii=False, indent=2), encoding="utf-8")
(OUT / "val.json").write_text(json.dumps(val, ensure_ascii=False, indent=2), encoding="utf-8")
meta = {
    "recipe": "GLM-solo relabel + CyberNative escaping pairs, TP oversample x2",
    "unique_tp": len(tp_tr), "unique_fp": len(fp_tr),
    "train_n": len(train), "train_dist": dict(Counter(gv(x) for x in train)),
    "val_n": len(val), "val_dist": dict(Counter(gv(x) for x in val)),
    "oversample": OVERSAMPLE,
}
(OUT / "build_meta.json").write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
print(json.dumps(meta, ensure_ascii=False, indent=2))

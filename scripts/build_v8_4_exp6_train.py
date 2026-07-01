"""Build exp6 train/val: GLM-solo relabeled pool + escaping pairs, NO oversample.

Fixes exp5's two problems:
  1. XSS-escaping blindness -> add CyberNative matched escaping pairs (135 TP / 135 FP,
     the vuln/safe-differ-only-by-escaping signal exp5 lacked; exp4 proved it works).
  2. TP scarcity / oversample-induced paranoia -> GLM-solo relabel gave 268 real TP
     (vs exp5's 56), so NO oversampling needed.
"""
import json
import random
from collections import Counter
from pathlib import Path

ROOT = Path("f:/vuln-llm-research")
OUT = ROOT / "data/train/v8_4_exp6"
OUT.mkdir(parents=True, exist_ok=True)
rng = random.Random(42)

glm = json.loads((ROOT / "runs/exp6_glm_train.json").read_text(encoding="utf-8"))
esc = json.loads((ROOT / "data/train/cwe_web_cybernative/train.json").read_text(encoding="utf-8"))


def gv(x):
    return x["metadata"].get("glm_verdict") or x["metadata"].get("verdict")


tp = [x for x in glm if gv(x) == "TRUE_POSITIVE"]
fp = [x for x in glm if gv(x) == "FALSE_POSITIVE"]
rng.shuffle(tp); rng.shuffle(fp)

# balanced val held out from the GLM set (checkpoint selection only; real eval = stand)
val = tp[:15] + fp[:15]
train = tp[15:] + fp[15:] + esc          # all escaping pairs into train, NO oversample
rng.shuffle(train); rng.shuffle(val)

(OUT / "train.json").write_text(json.dumps(train, ensure_ascii=False, indent=2), encoding="utf-8")
(OUT / "val.json").write_text(json.dumps(val, ensure_ascii=False, indent=2), encoding="utf-8")

meta = {
    "sources": {"glm_relabel": len(glm), "cybernative_escaping_pairs": len(esc)},
    "train_n": len(train),
    "train_dist": dict(Counter(gv(x) for x in train)),
    "val_n": len(val), "val_dist": dict(Counter(gv(x) for x in val)),
    "oversample": "NONE (268 real TP from GLM + 135 escaping TP)",
    "train_cwe": dict(Counter(x["metadata"].get("claimed_cwe") for x in train).most_common()),
}
(OUT / "build_meta.json").write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
print(json.dumps(meta, ensure_ascii=False, indent=2))

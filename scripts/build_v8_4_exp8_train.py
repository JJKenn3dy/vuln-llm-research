"""exp8: exp5's clean dual-consensus labels + escaping pairs, NO oversample.

The exp5-7 lesson: label QUALITY beats quantity/oversample. exp5's 236 dual-consensus
rows (GPT-5.5+GLM agreed) gave the best DR/FAR balance (68%/4%) but were escaping-blind
(no escaping pairs). exp8 adds the CyberNative escaping pairs to that clean set, no
oversample -> test whether clean labels + escaping signal give BOTH.
"""
import json
import random
from collections import Counter
from pathlib import Path

ROOT = Path("f:/vuln-llm-research")
OUT = ROOT / "data/train/v8_4_exp8"
OUT.mkdir(parents=True, exist_ok=True)
rng = random.Random(42)

cons = json.loads((ROOT / "runs/exp5_dual_train.json").read_text(encoding="utf-8"))  # 236 consensus
esc = json.loads((ROOT / "data/train/cwe_web_cybernative/train.json").read_text(encoding="utf-8"))  # 270


def v(x):
    m = x["metadata"]
    return m.get("consensus_verdict") or m.get("verdict")


allrows = cons + esc
tp = [x for x in allrows if v(x) == "TRUE_POSITIVE"]
fp = [x for x in allrows if v(x) == "FALSE_POSITIVE"]
rng.shuffle(tp); rng.shuffle(fp)

val = tp[:15] + fp[:15]
train = tp[15:] + fp[15:]          # NO oversample
rng.shuffle(train); rng.shuffle(val)

(OUT / "train.json").write_text(json.dumps(train, ensure_ascii=False, indent=2), encoding="utf-8")
(OUT / "val.json").write_text(json.dumps(val, ensure_ascii=False, indent=2), encoding="utf-8")
meta = {
    "recipe": "exp5 dual-consensus (236) + CyberNative escaping pairs (270), NO oversample",
    "sources": {"exp5_consensus": len(cons), "escaping_pairs": len(esc)},
    "train_n": len(train), "train_dist": dict(Counter(v(x) for x in train)),
    "val_n": len(val), "val_dist": dict(Counter(v(x) for x in val)),
}
(OUT / "build_meta.json").write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
print(json.dumps(meta, ensure_ascii=False, indent=2))

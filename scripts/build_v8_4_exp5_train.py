"""Build the exp5 pilot train/val from the dual-teacher consensus set.

Source: runs/exp5_dual_train.json (236 AGREE-only, GPT-5.5+GLM-5.2 consensus,
reasoning = GLM-5.2). Consensus is heavily FP (180 FP / 56 TP) because most pool
findings are genuinely noise once read at the snippet level. We:
  - hold out a small balanced val (for checkpoint selection only; real eval = stand),
  - oversample the scarce TP in TRAIN to ~balance (LoRA on top of v8_3_1).
The independent stand (gold-core/controlled/mined-heldout) stays the verdict.
"""
import json
import random
from collections import Counter
from pathlib import Path

ROOT = Path("f:/vuln-llm-research")
SRC = ROOT / "runs/exp5_dual_train.json"
OUT = ROOT / "data/train/v8_4_exp5"
OUT.mkdir(parents=True, exist_ok=True)

rng = random.Random(42)
rows = json.loads(SRC.read_text(encoding="utf-8"))


def verdict(r):
    return r["metadata"]["consensus_verdict"]


tp = [r for r in rows if verdict(r) == "TRUE_POSITIVE"]
fp = [r for r in rows if verdict(r) == "FALSE_POSITIVE"]
rng.shuffle(tp); rng.shuffle(fp)

# val: balanced, held out BEFORE oversampling
val = tp[:8] + fp[:20]
tp_tr, fp_tr = tp[8:], fp[20:]            # 48 TP, 160 FP
# oversample TP x3 to roughly balance against FP
tp_os = (tp_tr * 3)[:len(fp_tr)]          # ~144 TP
train = tp_os + fp_tr
rng.shuffle(train); rng.shuffle(val)

(OUT / "train.json").write_text(json.dumps(train, ensure_ascii=False, indent=2), encoding="utf-8")
(OUT / "val.json").write_text(json.dumps(val, ensure_ascii=False, indent=2), encoding="utf-8")
meta = {
    "source": str(SRC.name), "teachers": "gpt-5.5+glm-5.2 (AGREE-only)",
    "unique_tp": len(tp_tr), "unique_fp": len(fp_tr),
    "train_n": len(train), "train_dist": dict(Counter(verdict(r) for r in train)),
    "val_n": len(val), "val_dist": dict(Counter(verdict(r) for r in val)),
    "tp_oversample": 3,
    "train_cwe": dict(Counter(r["metadata"].get("claimed_cwe") for r in train).most_common()),
}
(OUT / "build_meta.json").write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
print(json.dumps(meta, ensure_ascii=False, indent=2))

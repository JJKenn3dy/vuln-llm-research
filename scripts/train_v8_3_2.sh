#!/bin/bash
# v8.3.2 training on v8.3.1 data with regenerated TP reasoning.
#
# The only difference from v8.3.1:
#   * TP assistant text was regenerated via Llama 3.3 70B (OpenRouter)
#   * FP rows kept verbatim (--skip-fp in scripts/regenerate_tp_reasoning.py)
#
# Why: 100% of v8.3.1 TP rows had hallucinated NVD-style boilerplate
# ("vulnerability was found in [PROJECT] up to [VERSION]", "upstream fix
# commit", "VDB-NNNN", "git-svn-id"). The model learned this stylistic
# shortcut and reproduced fake CVE references at inference time on real
# repos (observed on NodeGoat / devonz_bolt / DVWA top-K filter pass).
#
# Hypothesis: cleaning reasoning labels removes the shortcut without
# changing verdict-prediction signal (verdict tokens are unchanged).
# Expected: similar MCC on SastBench-250, but reasoning is snippet-grounded
# and safe to attach to outreach.
#
# Same hyperparameters as v8.3.0 / v8.3.1: r=16, alpha=32, lr=1e-4, 3 epochs.
#
# Usage:
#   bash scripts/train_v8_3_2.sh [adapter_name] [train_file]
set -euo pipefail

ADAPTER_NAME="${1:-v8_3_2}"
TRAIN_FILE="${2:-/workspace/regen_full/train_merged_clean_tp.json}"
WORKSPACE=/workspace
REPO=$WORKSPACE/vuln-llm-research

cd "$REPO"

if [[ ! -f $TRAIN_FILE ]]; then
    echo "missing $TRAIN_FILE"
    echo "run scripts/regenerate_tp_reasoning.py --skip-fp first"
    exit 1
fi

# Sanity: confirm shortcut markers are gone in TP rows
python - <<'PYEOF'
import json
import re
import sys
import os
path = os.environ.get("TRAIN_FILE", "/workspace/regen_full/train_merged_clean_tp.json")
rows = json.load(open(path, encoding="utf-8"))
pat = re.compile(r"vulnerability was found in|upstream fix commit|VDB-\d+|git-svn-id", re.I)
tp_total = 0
tp_dirty = 0
fp_total = 0
fp_dirty = 0
for r in rows:
    asst = next((m["content"] for m in r["messages"] if m["role"] == "assistant"), "")
    is_tp = "TRUE_POSITIVE" in asst
    if is_tp:
        tp_total += 1
        if pat.search(asst):
            tp_dirty += 1
    else:
        fp_total += 1
        if pat.search(asst):
            fp_dirty += 1
print(f"TP rows: {tp_total}, TP with shortcut markers: {tp_dirty} ({tp_dirty/max(tp_total,1):.1%})")
print(f"FP rows: {fp_total}, FP with shortcut markers: {fp_dirty} ({fp_dirty/max(fp_total,1):.1%})")
if tp_dirty / max(tp_total, 1) > 0.05:
    print("WARNING: more than 5% of TP rows still have shortcut boilerplate", file=sys.stderr)
PYEOF

python -m src.train.train_qlora \
    --train-file "$TRAIN_FILE" \
    --val-file data/train/triage_v8_2_val.json \
    --output-dir "$WORKSPACE/adapters/$ADAPTER_NAME" \
    --epochs 3 \
    --lora-r 16 \
    --lora-alpha 32 \
    --lora-dropout 0.05 \
    --lr 1e-4 \
    --max-seq-length 2048 \
    --batch-size 1 \
    --grad-accum 8 \
    --save-steps 100 \
    --save-total-limit 8 \
    --base-model "$WORKSPACE/models/qwen2.5-coder-7b-instruct"

# SastBench-250 eval (verdict regression check)
python -m src.eval.run_triage_eval \
    --backend local \
    --base-model "$WORKSPACE/models/qwen2.5-coder-7b-instruct" \
    --adapter-dir "$WORKSPACE/adapters/$ADAPTER_NAME" \
    --input data/eval/sastbench_v01_subset250.json \
    --output "$WORKSPACE/runs/${ADAPTER_NAME}_sastbench250_outputs.json" \
    --metrics "$WORKSPACE/runs/${ADAPTER_NAME}_sastbench250_metrics.json"

# test_balanced eval (in-domain control)
python -m src.eval.run_triage_eval \
    --backend local \
    --base-model "$WORKSPACE/models/qwen2.5-coder-7b-instruct" \
    --adapter-dir "$WORKSPACE/adapters/$ADAPTER_NAME" \
    --input /workspace/data/train/triage_v8_2/triage_test_balanced.json \
    --output "$WORKSPACE/runs/${ADAPTER_NAME}_testbalanced_outputs.json" \
    --metrics "$WORKSPACE/runs/${ADAPTER_NAME}_testbalanced_metrics.json"

# ywh+DVWA eval (reasoning quality + verdict on 111 controlled cases)
if [[ -f data/eval/ywh_dvwa_messages.json ]]; then
    python -m src.eval.run_triage_eval \
        --backend local \
        --base-model "$WORKSPACE/models/qwen2.5-coder-7b-instruct" \
        --adapter-dir "$WORKSPACE/adapters/$ADAPTER_NAME" \
        --input data/eval/ywh_dvwa_messages.json \
        --output "$WORKSPACE/runs/${ADAPTER_NAME}_ywh_dvwa_outputs.json" \
        --metrics "$WORKSPACE/runs/${ADAPTER_NAME}_ywh_dvwa_metrics.json"
fi

# Logprobs (mechanistic gap)
python -m src.eval.extract_triage_logprobs \
    --base-model "$WORKSPACE/models/qwen2.5-coder-7b-instruct" \
    --adapter-dir "$WORKSPACE/adapters/$ADAPTER_NAME" \
    --input /workspace/data/train/triage_v8_2/triage_test_balanced.json \
    --output "$WORKSPACE/runs/${ADAPTER_NAME}_logprobs_testbalanced.json"

python -m src.eval.extract_triage_logprobs \
    --base-model "$WORKSPACE/models/qwen2.5-coder-7b-instruct" \
    --adapter-dir "$WORKSPACE/adapters/$ADAPTER_NAME" \
    --input data/eval/sastbench_v01_subset250.json \
    --output "$WORKSPACE/runs/${ADAPTER_NAME}_logprobs_sastbench250.json"

echo ""
echo "=== ${ADAPTER_NAME} done ==="
echo "Expected (vs v8.3.1):"
echo "  SastBench MCC: similar (target keep >0.15, v8.3.1 was +0.177)"
echo "  ywh+DVWA MCC: similar (v8.3.1 was 0.42)"
echo "  Reasoning on top-K filter pass: NO 'vulnerability was found in', 'upstream fix commit', 'VDB-', 'git-svn-id'"
echo "  Reasoning quality: snippet-grounded, mentions actual variable names from the code"
echo ""
echo "Next: run filter pass on NodeGoat / DVWA / devonz_bolt / rpg_life Bandit top-K"
echo "      compare reasoning vs v8.3.1 (see scripts/sarif_topk_to_eval_messages.py)"

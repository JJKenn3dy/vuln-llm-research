#!/bin/bash
# Canonical v8.3.0 training: isolated dedup-only fix, otherwise same as v8.2.
#
# Tests the hypothesis from project_v8_3_train_data_dedup.md:
#   The single biggest lever for v8.3 is removing the 64% duplicate code rows
#   with conflicting verdicts from train. If true, v8.3.0 should show
#   FAR < 50% on SastBench-250 (down from v8.2's 77%) and MCC > 0.15 (up
#   from v8.2's 0.10), WITHOUT changing any hyperparameter.
#
# All hyperparameters are EXACTLY the same as v8.2 (r=16, alpha=32, lr=1e-4,
# 3 epochs, bs=1, grad_accum=8, max_seq=2048). Only the train data differs.
#
# Usage:
#   bash scripts/train_v8_3_0.sh [adapter_name]
# Default adapter_name=v8_3_0
set -euo pipefail

ADAPTER_NAME="${1:-v8_3_0}"
WORKSPACE=/workspace
REPO=$WORKSPACE/vuln-llm-research

cd "$REPO"

# Sanity: clean train must exist (run prepare_v8_3_clean.py first)
TRAIN_FILE=data/train/triage_v8_3_clean/train_dedup_balanced.json
if [[ ! -f $TRAIN_FILE ]]; then
    echo "missing $TRAIN_FILE"
    echo "run: python scripts/prepare_v8_3_clean.py --input data/train/triage_v8_2_train.json --out-dir data/train/triage_v8_3_clean"
    exit 1
fi

# Same hyperparameters as v8.2 — isolate dedup effect
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
    --save-steps 50 \
    --save-total-limit 8 \
    --base-model "$WORKSPACE/models/qwen2.5-coder-7b-instruct" \
    --upload-to-hf "JJKennedy/vuln-llm-adapters/$ADAPTER_NAME"

# Immediate eval on SastBench-250 for quick read on the dedup effect
python -m src.eval.run_triage_eval \
    --backend local \
    --base-model "$WORKSPACE/models/qwen2.5-coder-7b-instruct" \
    --adapter-dir "$WORKSPACE/adapters/$ADAPTER_NAME" \
    --input data/eval/sastbench_v01_subset250.json \
    --output "$WORKSPACE/runs/${ADAPTER_NAME}_sastbench250_outputs.json" \
    --metrics "$WORKSPACE/runs/${ADAPTER_NAME}_sastbench250_metrics.json"

# Also eval on test_balanced (in-domain control)
python -m src.eval.run_triage_eval \
    --backend local \
    --base-model "$WORKSPACE/models/qwen2.5-coder-7b-instruct" \
    --adapter-dir "$WORKSPACE/adapters/$ADAPTER_NAME" \
    --input /workspace/data/train/triage_v8_2/triage_test_balanced.json \
    --output "$WORKSPACE/runs/${ADAPTER_NAME}_testbalanced_outputs.json" \
    --metrics "$WORKSPACE/runs/${ADAPTER_NAME}_testbalanced_metrics.json"

echo ""
echo "=== ${ADAPTER_NAME} done ==="
echo "Expected outcomes if dedup hypothesis correct:"
echo "  SastBench-250: FAR < 50% (v8.2 was 77%), MCC > 0.15 (v8.2 was 0.10)"
echo "  test_balanced: BA may drop slightly (v8.2 was 0.82) as model is less"
echo "                 overfit to v8.2 distribution; that's OK and expected"

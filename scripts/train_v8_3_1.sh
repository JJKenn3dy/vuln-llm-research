#!/bin/bash
# Canonical v8.3.1 multi-source training.
#
# Tests whether adding CrossVul to v8.3 clean train closes the distribution
# mismatch gap that v8.3.0 left open (Case B from train_v8_3_0.sh decision tree).
#
# Same hyperparameters as v8.3.0: r=16, alpha=32, lr=1e-4, 3 epochs.
# Only train data differs (v8.3.1 = 2180 rows from CVEFixes-clean + CrossVul).
#
# Known risk: CrossVul has placeholder reasoning (no teacher call). This means
# ~55% of train has templated FP reasoning. Stylistic shortcut risk; v8.2 Lesson
# 0 territory. Will be visible in (a) train loss curve and (b) FAR on SastBench.
# If stylistic-shortcut paranoia returns, v8.3.2 needs teacher call for CrossVul.
#
# Usage:
#   bash scripts/train_v8_3_1.sh [adapter_name]
set -euo pipefail

ADAPTER_NAME="${1:-v8_3_1}"
WORKSPACE=/workspace
REPO=$WORKSPACE/vuln-llm-research

cd "$REPO"

TRAIN_FILE=data/train/triage_v8_3_1/train_merged.json
if [[ ! -f $TRAIN_FILE ]]; then
    echo "missing $TRAIN_FILE"
    echo "run prepare_crossvul_triage + merge_v8_3_1_train first"
    exit 1
fi

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

# SastBench-250 eval
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

# Logprobs (mechanistic gap test)
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
echo "Expected:"
echo "  SastBench MCC > v8.3.0's 0.14 (target: 0.18+)"
echo "  SastBench FAR < v8.3.0's 32% (target: <30%)"
echo "  test_balanced gap should stay healthy (>0.10)"
echo "  Cluster CI ceiling moves up further (v8.3.0 was [-0.07, +0.31])"

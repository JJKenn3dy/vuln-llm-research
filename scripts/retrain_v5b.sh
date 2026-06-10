#!/bin/bash
# Reproduce v5b baseline on a fresh GPU.
# Use this as the very first sanity check after deploying a new RunPod pod.
#
# Expected outcome:
#   - 3 epochs on Qwen2.5-Coder-7B with LoRA r=16
#   - ~6 hours on L40S 48GB
#   - Saves adapter to /workspace/adapters/v5b_repro
#   - Optionally pushes to HuggingFace if --upload is the first arg

set -e

REPO_DIR="${REPO_DIR:-/workspace/vuln-llm-research}"
ADAPTER_OUT="${ADAPTER_OUT:-/workspace/adapters/v5b_repro}"
HF_REPO="${HF_ADAPTERS_REPO:-zyakuba/vuln-llm-adapters}"

cd "$REPO_DIR"

HF_FLAGS=""
if [ "$1" = "--upload" ]; then
    HF_FLAGS="--hf-repo $HF_REPO --hf-subfolder v5b_repro --hf-private"
fi

python -m src.train.train_qlora \
    --train-file data/train/train_v5b_train.json \
    --val-file data/train/train_v5b_val.json \
    --output-dir "$ADAPTER_OUT" \
    --base-model Qwen/Qwen2.5-Coder-7B-Instruct \
    --epochs 3 --lora-r 16 --lora-alpha 32 --lr 1.5e-4 \
    --batch-size 1 --grad-accum 8 --max-seq-length 1280 \
    --report-to wandb --wandb-project vuln-llm --wandb-run-name v5b_repro \
    $HF_FLAGS

echo "==> Eval baseline on CVEFixes-100"
python -m src.eval.run_eval \
    --adapter-dir "$ADAPTER_OUT" \
    --input-file data/eval/eval_cvefixes_100.json \
    --output-file /workspace/runs/v5b_repro_eval_outputs.json \
    --metrics-file /workspace/runs/v5b_repro_eval_metrics.json

echo "==> Done. Compare metrics to expected F1=0.86 in-domain."

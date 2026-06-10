#!/bin/bash
# Kick off v8 triage fine-tune with defaults from src/train/train_v8_triage.py.
#
# Expected on RunPod A6000:
#   - 2 epochs on 2879 triage pairs from triage_v8_from_v7lite
#   - ~60 min wall-clock, ~$0.50
#   - Adapter saved to /workspace/adapters/v8_first
#   - Auto-pushed to HuggingFace as JJKennedy/vuln-llm-adapters/v8_first
#
# Override any defaults by passing flags through:
#   bash scripts/train_v8.sh --lora-r 8 --epochs 3

set -e

cd "${REPO_DIR:-/workspace/vuln-llm-research}"

python -m src.train.train_v8_triage "$@"

echo "==> v8 training done"
echo "==> Next: python -m src.eval.run_triage_eval --backend local \\"
echo "        --adapter-dir /workspace/adapters/v8_first \\"
echo "        --base-model /workspace/models/qwen2.5-coder-7b-instruct \\"
echo "        --input /workspace/runs/triage_100_sample.json \\"
echo "        --output /workspace/runs/v8_triage100_outputs.json \\"
echo "        --metrics /workspace/runs/v8_triage100_metrics.json"

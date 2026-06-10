#!/bin/bash
# Train v8.2 triage adapter on the CVEFixes pre/post-fix pairs prepared by
# src/data_prep/prepare_cvefixes_triage.py with the Haiku 4.5 teacher.
#
# Defaults derived from BSc-thesis sweep analysis (see f:/diplom/INDEX.md):
#   - v5b (1377 pairs, 3 ep, r=16, lr=1.5e-4) -> F1=0.86 in-domain ✓
#   - v7lite (4079 pairs, 3 ep, r=16, lr=1.5e-4) -> F1=0.78 (memorization at 4k)
#   - v7lite_r8 (4079 pairs, r=8) -> BalAcc=0.526 best OOD; smaller LoRA helps generalisation
#   - v8.1 (2879 pairs, 2 ep, r=16, lr=1e-4) -> BA=0.51 random; failed on data, not on hyperparams
#
# v8.2 picks a middle ground (2588 pairs, 3 ep, r=16, lr=1e-4, lower than v5b's 1.5e-4
# to encourage generalisation on triage). save_steps=50 + save_total_limit=8 keeps
# intermediate checkpoints (Lesson 8 from HISTORY.md: v7lite lost early checkpoints
# and we couldn't post-hoc analyse).
#
# Expected on RunPod A6000 48GB:
#   - ~25-40 min wall-clock for ~970 training steps
#   - ~$0.20-0.33 GPU cost
#   - Adapter saved to /workspace/adapters/v8_2
#   - Auto-pushed to JJKennedy/vuln-llm-adapters/v8_2 on HF
#
# Usage:
#   bash scripts/train_v8_2.sh                 # default settings
#   bash scripts/train_v8_2.sh --lora-r 8      # override for r=8 diagnostic run
#   bash scripts/train_v8_2.sh --no-upload     # skip HF push (smoke test)

set -e

REPO_DIR="${REPO_DIR:-/workspace/vuln-llm-research}"
DATA_DIR="${DATA_DIR:-/workspace/data/train/triage_v8_2}"
ADAPTER_OUT="${ADAPTER_OUT:-/workspace/adapters/v8_2}"
BASE_MODEL="${BASE_MODEL:-/workspace/models/qwen2.5-coder-7b-instruct}"
HF_REPO="${HF_ADAPTERS_REPO:-JJKennedy/vuln-llm-adapters}"
HF_SUBFOLDER="${HF_SUBFOLDER:-v8_2}"

cd "$REPO_DIR"

# Build CLI args, allowing user overrides via $@.
EXTRA_FLAGS=""
UPLOAD_FLAGS="--hf-repo $HF_REPO --hf-subfolder $HF_SUBFOLDER"
for arg in "$@"; do
    if [ "$arg" = "--no-upload" ]; then
        UPLOAD_FLAGS=""
    else
        EXTRA_FLAGS="$EXTRA_FLAGS $arg"
    fi
done

python -m src.train.train_qlora \
    --train-file "$DATA_DIR/triage_train.json" \
    --val-file "$DATA_DIR/triage_val.json" \
    --output-dir "$ADAPTER_OUT" \
    --base-model "$BASE_MODEL" \
    --epochs 3 \
    --lora-r 16 --lora-alpha 32 --lora-dropout 0.05 \
    --lr 1e-4 \
    --batch-size 1 --grad-accum 8 \
    --max-seq-length 2048 \
    --warmup-ratio 0.05 \
    --save-steps 50 --save-total-limit 8 \
    --report-to none \
    $UPLOAD_FLAGS \
    $EXTRA_FLAGS

echo "==> v8.2 training done."
echo "==> Next: eval against triage_test_balanced + triage_test_imbalanced + fresh_cves_60_triage:"
cat <<EOF

  python -m src.eval.run_triage_eval --backend local \\
      --base-model $BASE_MODEL \\
      --adapter-dir $ADAPTER_OUT \\
      --input $DATA_DIR/triage_test_balanced.json \\
      --output /workspace/runs/v8_2_test_balanced_outputs.json \\
      --metrics /workspace/runs/v8_2_test_balanced_metrics.json

  python -m src.eval.run_triage_eval --backend local \\
      --base-model $BASE_MODEL \\
      --adapter-dir $ADAPTER_OUT \\
      --input $DATA_DIR/triage_test_imbalanced.json \\
      --output /workspace/runs/v8_2_test_imbalanced_outputs.json \\
      --metrics /workspace/runs/v8_2_test_imbalanced_metrics.json

  python -m src.eval.run_triage_eval --backend local \\
      --base-model $BASE_MODEL \\
      --adapter-dir $ADAPTER_OUT \\
      --input data/eval/fresh_cves_60_triage.json \\
      --output /workspace/runs/v8_2_fresh_cves_outputs.json \\
      --metrics /workspace/runs/v8_2_fresh_cves_metrics.json

EOF

#!/bin/bash
# v8.4-exp6 (distillation pilot): continue-train v8_3_1 on dual-teacher consensus.
#
# Train data = GPT-5.5 + GLM-5.2 AGREE-only relabel of the v8.3 clean pool
# (236 consensus rows; 36% flipped the pool's noisy label). reasoning = GLM-5.2
# (code-grounded, not the NVD boilerplate that crippled earlier versions).
# TP oversampled x3 (only 48 unique TP -> recall is the known weak spot).
#
# Go/no-go: does clean teacher data beat exp4 on the SAME stand?
#   exp4 baseline: gold-core MCC 0.511, controlled disc 10/20, mined ~0.127.
# Frontier teachers on this stand: GPT-5.5 0.909, GLM-5.2 0.868.
#
# Usage: bash scripts/train_v8_4_exp6.sh [adapter_name]
set -euo pipefail

NAME="${1:-v8_4_exp6}"
WS=/workspace
REPO=$WS/vuln-llm-research
BASE=$WS/models/qwen2.5-coder-7b-instruct
INIT=$WS/adapters/v8_3_1
OUT=$WS/adapters/$NAME
TRAIN=$REPO/data/train/v8_4_exp6/train.json

cd "$REPO"
[[ -f $TRAIN ]] || { echo "missing $TRAIN (run build_v8_4_exp6_train.py + git pull)"; exit 1; }
[[ -d $INIT ]] || { echo "missing init adapter $INIT"; exit 1; }

python -m src.train.train_qlora \
    --train-file "$TRAIN" \
    --val-file data/train/v8_4_exp6/val.json \
    --output-dir "$OUT" \
    --init-adapter "$INIT" \
    --epochs 3 \
    --lr 5e-5 \
    --max-seq-length 2048 \
    --batch-size 1 \
    --grad-accum 8 \
    --save-steps 50 \
    --save-total-limit 4 \
    --base-model "$BASE"

run_eval () {  # $1=input $2=tag
    python -m src.eval.run_triage_eval \
        --backend local --base-model "$BASE" --adapter-dir "$OUT" \
        --input "$1" \
        --output "$WS/runs/${NAME}_$2_outputs.json" \
        --metrics "$WS/runs/${NAME}_$2_metrics.json" \
        --max-new-tokens 256
}

echo "=== EVAL gold-core (n=71, trusted; vs exp4 0.511, GPT-5.5 0.909) ==="
run_eval data/eval/goldcore_71.json goldcore
echo "=== EVAL controlled-20 (escaping killer; vs exp4 10/20) ==="
run_eval data/eval/cwe79_controlled_pairs.json controlled
echo "=== EVAL mined-heldout (real-code transfer/recall; vs exp4 ~0.127) ==="
run_eval data/eval/cwe79_mined_heldout.json mined
echo "=== EVAL sastbench-250 (external/forgetting) ==="
run_eval data/eval/sastbench_v01_subset250.json sastbench250

echo "=== DONE: adapter $OUT, outputs in $WS/runs/${NAME}_* ==="
echo "Next (local): pair-discrimination via scripts/eval_cwe79_controlled.py --analyze"

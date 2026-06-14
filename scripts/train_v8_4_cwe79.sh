#!/bin/bash
# v8.4-CWE79-exp1: teach escaping-discrimination on top of v8.3.1.
#
# The killer test (2026-06-13) showed v8.3.1 is blind to escaping: it called
# all 20 matched vuln/safe pairs TRUE_POSITIVE (discrimination 0/20 vs frontier
# 20/20). Root cause: 69% of its training TP rows had the sink out of snippet.
#
# Fix: continue-train FROM the v8.3.1 adapter on filtered CyberNative XSS pairs
# (self-contained, escaping is the discriminator). Gentle LR + few epochs to add
# the missing signal without catastrophic forgetting. Old pile is NOT re-fed.
#
# Eval (3 angles): controlled-20 (synthetic generalization), mined-real
# (real-code transfer = the verdict), sastbench-250 (-> gold-core, forgetting).
#
# Usage: bash scripts/train_v8_4_cwe79.sh [adapter_name]
set -euo pipefail

NAME="${1:-v8_4_cwe79}"
WS=/workspace
REPO=$WS/vuln-llm-research
BASE=$WS/models/qwen2.5-coder-7b-instruct
INIT=$WS/adapters/v8_3_1
OUT=$WS/adapters/$NAME
TRAIN=$REPO/data/train/cwe_web_cybernative/train.json

cd "$REPO"
[[ -f $TRAIN ]] || { echo "missing $TRAIN (run build_cybernative_train.py)"; exit 1; }
[[ -d $INIT ]] || { echo "missing init adapter $INIT"; exit 1; }

python -m src.train.train_qlora \
    --train-file "$TRAIN" \
    --val-file data/eval/cwe79_controlled_pairs.json \
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

# --- evals ---
run_eval () {  # $1=input $2=tag
    python -m src.eval.run_triage_eval \
        --backend local --base-model "$BASE" --adapter-dir "$OUT" \
        --input "$1" \
        --output "$WS/runs/${NAME}_$2_outputs.json" \
        --metrics "$WS/runs/${NAME}_$2_metrics.json" \
        --max-new-tokens 256
}

echo "=== EVAL controlled-20 (synthetic generalization) ==="
run_eval data/eval/cwe79_controlled_pairs.json controlled
echo "=== EVAL mined-real (real-code TRANSFER = the verdict) ==="
run_eval data/eval/cwe79_mined_pairs.json mined
echo "=== EVAL sastbench-250 (-> gold-core forgetting check) ==="
run_eval data/eval/sastbench_v01_subset250.json sastbench250

echo "=== DONE: adapter $OUT, outputs in $WS/runs/${NAME}_* ==="
echo "Next (local): pair-discrimination via scripts/eval_cwe79_controlled.py --analyze"

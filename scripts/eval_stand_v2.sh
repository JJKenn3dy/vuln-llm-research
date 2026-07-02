#!/bin/bash
# Stand v2 confirmation: exp5 vs exp4 vs v8.3.1 on the fresh trusted set.
# Run on pod from /workspace/vuln-llm-research. Auto-stop pod when done.
set -e
WS=/workspace
BASE=$WS/models/qwen2.5-coder-7b-instruct
cd $WS/vuln-llm-research

run_eval () {  # $1=adapter dir  $2=tag
    python -m src.eval.run_triage_eval \
        --backend local --base-model "$BASE" --adapter-dir "$1" \
        --input data/eval/stand_v2_eval.json \
        --output "$WS/runs/standv2_$2_outputs.json" \
        --metrics "$WS/runs/standv2_$2_metrics.json" \
        --max-new-tokens 256
}

echo "=== stand_v2 EVAL: exp5 (claimed 0.695 on gold-core) ==="
run_eval $WS/adapters/v8_4_exp5 exp5
echo "=== stand_v2 EVAL: exp4 (claimed 0.511) ==="
run_eval $WS/adapters/v8_4_exp4 exp4
echo "=== stand_v2 EVAL: v8_3_1 (claimed 0.447) ==="
run_eval $WS/adapters/v8_3_1 v8_3_1

echo "=== DONE stand_v2 evals ==="

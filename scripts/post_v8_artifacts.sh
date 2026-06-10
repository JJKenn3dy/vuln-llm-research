#!/bin/bash
# Run after v8 triage eval finishes. Produces every comparison artefact in one shot:
#   - comparison_final.md   markdown table of all 8 models
#   - failure_analysis_final.md  per-CWE + per-language breakdown
#   - summary_for_readme.md      compact version for README

set -e

cd "${REPO_DIR:-/workspace/vuln-llm-research}"
RUNS="/workspace/runs"

if [ ! -f "$RUNS/v8_triage100_metrics.json" ]; then
    echo "ERR: v8 metrics not found at $RUNS/v8_triage100_metrics.json"
    exit 1
fi

echo "==> Building full comparison table"
python -m src.eval.build_comparison_table \
    --metrics \
        "GPT-4o (2024-11):$RUNS/gpt4o_triage100_metrics.json" \
        "GPT-4.1:$RUNS/gpt41_triage100_metrics.json" \
        "GPT-5-chat-latest:$RUNS/gpt5chat_triage100_metrics.json" \
        "o3-mini (reasoning):$RUNS/o3mini_triage100_metrics.json" \
        "Claude Sonnet 4.5:$RUNS/sonnet45_triage100_metrics.json" \
        "Llama 3.3 70B:$RUNS/llama33_triage100_metrics.json" \
        "DeepSeek-Chat:$RUNS/deepseek_triage100_metrics.json" \
        "v5b zero-shot (ours, detector):$RUNS/v5b_zeroshot_triage100_metrics.json" \
        "v8-triage (ours, specialist):$RUNS/v8_triage100_metrics.json" \
    --output "$RUNS/comparison_final.md" \
    --title "SAST triage benchmark on triage_100 (50 TP + 50 FP, project-stratified)"

echo "==> Building failure-mode analysis with per-language breakdown"
python -m src.eval.analyze_failure_modes \
    --outputs \
        "GPT-4o:$RUNS/gpt4o_triage100_outputs.json" \
        "GPT-4.1:$RUNS/gpt41_triage100_outputs.json" \
        "GPT-5-chat:$RUNS/gpt5chat_triage100_outputs.json" \
        "o3-mini:$RUNS/o3mini_triage100_outputs.json" \
        "Claude Sonnet 4.5:$RUNS/sonnet45_triage100_outputs.json" \
        "Llama 3.3 70B:$RUNS/llama33_triage100_outputs.json" \
        "DeepSeek-Chat:$RUNS/deepseek_triage100_outputs.json" \
        "v5b zero-shot:$RUNS/v5b_zeroshot_triage100_outputs.json" \
        "v8-triage:$RUNS/v8_triage100_outputs.json" \
    --sample-meta "$RUNS/triage_100_sample.json" \
    --output "$RUNS/failure_analysis_final.md"

echo
echo "==> Top of comparison_final.md:"
echo
head -20 "$RUNS/comparison_final.md"
echo
echo "==> v8 metrics:"
cat "$RUNS/v8_triage100_metrics.json" | python3 -m json.tool | head -20
echo
echo "==> Done. Artefacts in $RUNS/"
echo "    - comparison_final.md"
echo "    - failure_analysis_final.md"

#!/bin/bash
# Frontier baseline on the same SastBench-250 v8.3.1 was evaluated on.
#
# Closes the methodology hole reviewer flagged 2026-06-11 evening: prior
# claims of "outperform Gemini ReAct" or "decisive margin over single-call
# frontier" were apples-to-oranges (different subsets, n=10 smoke). This
# run uses the identical 250 cases, identical parse regex, identical
# parse_fail accounting, identical cluster bootstrap by repo_url.
#
# Sonnet 4.5 runs TWICE: with our TRIAGE_USER_TEMPLATE and with a neutral
# prompt. The report picks the better Sonnet result. Closes "you gave
# frontier an unfriendly format" attack.
#
# Gemini 2.5 Pro runs ONCE (TRIAGE prompt) to stay in budget.
#
# Pre-commit interpretation (per NEXT_STEPS P1, set BEFORE running so
# numbers do not bend interpretation):
#   - "we beat frontier" = our cluster CI lower bound >= their point estimate
#   - "we match frontier" = mutual containment
#   - "we lose to frontier" = their point estimate above our CI upper bound
#
# Budget envelope: ~$1.5-2 OpenRouter, ~45 min wall-clock.
#
# Prereqs:
#   - OPENROUTER_API_KEY env var (uses OpenRouter for both providers)
#   - ANTHROPIC_API_KEY env var if --use-anthropic-direct is passed
#
# Usage:
#   bash scripts/run_frontier_v8_3_1_baseline.sh [out_dir]
set -euo pipefail

OUT_DIR="${1:-runs/frontier_v8_3_1}"
INPUT_TRIAGE=data/eval/sastbench_v01_subset250.json
INPUT_NEUTRAL=data/eval/sastbench_v01_subset250_neutral.json

mkdir -p "$OUT_DIR"

if [[ ! -f "$INPUT_NEUTRAL" ]]; then
    echo "Building neutral-prompt sibling eval ..."
    python scripts/build_neutral_prompt_eval.py \
        --input "$INPUT_TRIAGE" \
        --output "$INPUT_NEUTRAL"
fi

SONNET_MODEL=anthropic/claude-sonnet-4-5
GEMINI_MODEL=google/gemini-2.5-pro

echo "[1/3] Sonnet 4.5 TRIAGE prompt ..."
python -m src.eval.run_triage_eval \
    --backend api --api openrouter --model "$SONNET_MODEL" \
    --input "$INPUT_TRIAGE" \
    --output "$OUT_DIR/sonnet_triage_outputs.json" \
    --metrics "$OUT_DIR/sonnet_triage_metrics.json" \
    --max-new-tokens 400

echo "[2/3] Sonnet 4.5 NEUTRAL prompt ..."
python -m src.eval.run_triage_eval \
    --backend api --api openrouter --model "$SONNET_MODEL" \
    --input "$INPUT_NEUTRAL" \
    --output "$OUT_DIR/sonnet_neutral_outputs.json" \
    --metrics "$OUT_DIR/sonnet_neutral_metrics.json" \
    --max-new-tokens 400

echo "[3/3] Gemini 2.5 Pro TRIAGE prompt ..."
python -m src.eval.run_triage_eval \
    --backend api --api openrouter --model "$GEMINI_MODEL" \
    --input "$INPUT_TRIAGE" \
    --output "$OUT_DIR/gemini_triage_outputs.json" \
    --metrics "$OUT_DIR/gemini_triage_metrics.json" \
    --max-new-tokens 400

echo ""
echo "=== Computing cluster bootstrap CIs and comparison report ==="
python scripts/frontier_v8_3_1_report.py \
    --frontier-dir "$OUT_DIR" \
    --v8-3-1-outputs runs/v8_3_1_sastbench250_outputs.json \
    --cases "$INPUT_TRIAGE" \
    --output "$OUT_DIR/comparison_report.json" \
    --md "$OUT_DIR/comparison_report.md"

echo ""
echo "Report at $OUT_DIR/comparison_report.md"

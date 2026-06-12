#!/bin/bash
# After v8.3.2 train, run filter pass on the same 4 SARIF top-K cases
# we tested v8.3.1 on (NodeGoat, DVWA, devonz_bolt, rpg_life Bandit) so we
# can compare reasoning quality side-by-side.
#
# Uses the original anti-hallu prompt is NOT applied here — we want pure
# v8.3.2 output to see whether the training-time fix removed hallucination
# without prompt engineering.
set -euo pipefail
ADAPTER=/workspace/adapters/v8_3_2
BASE=/workspace/models/qwen2.5-coder-7b-instruct
REPO=/workspace/vuln-llm-research
ROOT=/workspace/v8_3_2_reasoning_eval
mkdir -p "$ROOT/runs"

cd "$REPO"
for tag in nodegoat_top15 rpg_life_bandit_top10 DVWA_top20 devonz_bolt_top10; do
    inp="/workspace/topk_reasoning/${tag}.json"
    out="$ROOT/runs/${tag}_v8_3_2.json"
    [ ! -f "$inp" ] && { echo "skip $inp"; continue; }
    echo "=== $tag ==="
    python -m src.eval.run_triage_eval \
        --backend local --base-model "$BASE" --adapter-dir "$ADAPTER" \
        --input "$inp" --output "$out" \
        --metrics "$ROOT/runs/${tag}_metrics.json" \
        --max-new-tokens 400 2>&1 | tail -4
done
echo "=== FILTER PASS DONE ==="
ls -lh "$ROOT/runs/"

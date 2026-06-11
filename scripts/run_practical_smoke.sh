#!/bin/bash
# Practical smoke: ranker v8.3.1 on real-world AI-coded web apps.
# Designed for one-shot SSH execution on yodelling_maroon_primate pod.
#
# Expects:
#   /workspace/practical_smoke/apps.tar.gz    repos tarball
#   /workspace/practical_smoke/sarif/         SARIF inputs
#   /workspace/adapters/v8_3_1/               adapter
#   /workspace/models/qwen2.5-coder-7b-instruct/   base model
set -euo pipefail

ROOT=/workspace/practical_smoke
APPS=$ROOT/apps
SARIF_IN=$ROOT/sarif
OUT=$ROOT/out
LOGS=$ROOT/logs
ADAPTER=/workspace/adapters/v8_3_1
BASE=/workspace/models/qwen2.5-coder-7b-instruct
REPO=/workspace/vuln-llm-research

mkdir -p "$APPS" "$OUT" "$LOGS"

if [ ! -d "$APPS/NodeGoat" ]; then
    tar --no-same-owner -xzf "$ROOT/apps.tar.gz" -C "$APPS" || true
fi

cd "$REPO"
git pull origin main 2>&1 | tail -3

if [ ! -d "$ADAPTER" ]; then
    echo "ERROR: adapter not found at $ADAPTER"
    echo "Available adapters:"
    ls /workspace/adapters/ 2>/dev/null || echo "  (none)"
    exit 1
fi

pip install --break-system-packages -q peft transformers torch accelerate 2>&1 | tail -3

declare -A REPO_ROOT
REPO_ROOT[nodegoat]="$APPS/NodeGoat"
REPO_ROOT[rpg_life]="$APPS/rpg_life"
REPO_ROOT[survivemedia]="$APPS/survivemedia"
REPO_ROOT[v0_chatbot]="$APPS/openai-agents-sdk-chatbot-UI"

for tag in nodegoat rpg_life survivemedia v0_chatbot; do
    sarif="$SARIF_IN/${tag}.sarif"
    if [ ! -f "$sarif" ]; then
        echo "skip $tag: $sarif missing"
        continue
    fi
    n=$(python -c "import json; d=json.load(open('$sarif')); print(sum(len(r.get('results',[])) for r in d.get('runs',[])))")
    echo "=== $tag: $n findings ==="
    if [ "$n" -eq 0 ]; then
        echo "  skip ranker, no findings"
        continue
    fi
    rroot="${REPO_ROOT[$tag]}"
    out="$OUT/${tag}_ranker.sarif"
    log="$LOGS/${tag}_ranker.log"
    python -m src.product \
        --input "$sarif" \
        --output "$out" \
        --backend local \
        --adapter-dir "$ADAPTER" \
        --base-model "$BASE" \
        --mode ranker \
        --repo-root "$rroot" \
        --context-lines 8 \
        --max-chars 6000 \
        --progress-log "$log" 2>&1 | tail -20
done

echo "=== DONE ==="
ls -lh "$OUT/"

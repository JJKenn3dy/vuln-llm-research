#!/bin/bash
# OSS demo reports: Semgrep -> v8.3.1 ranker on recognizable open-source repos.
# Output feeds src/product/report.py HTML -> PDF outreach attachments (P4).
#
# One-shot SSH execution on yodelling_maroon_primate pod.
# Repo pick rationale: JS/PHP-heavy (our strongest languages per
# RESULTS_v8_2_diagnostics), recognizable names for cold outreach.
set -euo pipefail

ROOT=/workspace/oss_reports
APPS=$ROOT/apps
SARIF_IN=$ROOT/sarif
OUT=$ROOT/out
LOGS=$ROOT/logs
ADAPTER=/workspace/adapters/v8_3_1
BASE=/workspace/models/qwen2.5-coder-7b-instruct
REPO=/workspace/vuln-llm-research

mkdir -p "$APPS" "$SARIF_IN" "$OUT" "$LOGS"

cd "$REPO"
git pull origin main 2>&1 | tail -3

pip install --break-system-packages -q semgrep peft transformers torch accelerate 2>&1 | tail -2

# tag -> github slug (shallow clone, default branch)
declare -A REPOS
REPOS[ghost]="TryGhost/Ghost"
REPOS[strapi]="strapi/strapi"
REPOS[nextcloud]="nextcloud/server"
REPOS[flask_appbuilder]="dpgaspar/Flask-AppBuilder"

for tag in ghost strapi nextcloud flask_appbuilder; do
    slug="${REPOS[$tag]}"
    app="$APPS/$tag"
    if [ ! -d "$app" ]; then
        git clone --depth 1 "https://github.com/$slug" "$app" 2>&1 | tail -1
    fi

    sarif="$SARIF_IN/${tag}.sarif"
    if [ ! -f "$sarif" ]; then
        echo "=== semgrep $tag ==="
        # p/default + security-audit; cap time per rule to keep total sane
        (cd "$app" && semgrep scan --config p/default --config p/security-audit \
            --sarif --output "$sarif" --timeout 30 --max-target-bytes 1000000 \
            --metrics off --quiet) || echo "semgrep $tag exited nonzero (partial sarif ok)"
    fi

    n=$(python -c "import json; d=json.load(open('$sarif')); print(sum(len(r.get('results',[])) for r in d.get('runs',[])))")
    echo "=== $tag: $n findings ==="
    [ "$n" -eq 0 ] && continue

    # Cap at 400 findings (seeded random sample) — ranker is ~3s/finding.
    # The report states the cap explicitly; no silent truncation.
    if [ "$n" -gt 400 ]; then
        python - "$sarif" <<'PYEOF'
import json, random, sys
path = sys.argv[1]
d = json.load(open(path))
rng = random.Random(20260613)
total = sum(len(r.get("results", [])) for r in d.get("runs", []))
keep_frac = 400 / total
kept = 0
for run in d.get("runs", []):
    res = run.get("results", [])
    sampled = [r for r in res if rng.random() < keep_frac]
    run["results"] = sampled
    kept += len(sampled)
json.dump(d, open(path.replace(".sarif", "_capped.sarif"), "w"))
print(f"capped {total} -> {kept} findings (seed 20260613)")
PYEOF
        sarif="${sarif%.sarif}_capped.sarif"
    fi

    out="$OUT/${tag}_ranker.sarif"
    [ -f "$out" ] && { echo "  skip, $out exists"; continue; }
    python -m src.product \
        --input "$sarif" \
        --output "$out" \
        --backend local \
        --adapter-dir "$ADAPTER" \
        --base-model "$BASE" \
        --mode ranker \
        --repo-root "$app" \
        --context-lines 8 \
        --max-chars 6000 \
        --progress-log "$LOGS/${tag}_ranker.log" 2>&1 | tail -10
done

echo "=== DONE ==="
ls -lh "$OUT/" "$SARIF_IN/"

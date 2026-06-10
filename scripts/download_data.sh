#!/bin/bash
# Sync large datasets from HuggingFace dataset repo into /workspace.
# Datasets that live on HF (too big for git):
#   - train_data_v7lite_train.json (19 MB)
#   - eval_crossvul_inputs.json (full, ~3 MB)
#   - sastbench/ (TBD once we mirror it)
#
# Small fixtures (eval_cvefixes_100, train_v5b_*, logprobs) are committed in git.

set -e

HF_REPO="${HF_DATA_REPO:-zyakuba/vuln-llm-datasets}"
DATA_DIR="${DATA_DIR:-/workspace/data/hf}"

mkdir -p "$DATA_DIR"

echo "==> Downloading $HF_REPO -> $DATA_DIR"
huggingface-cli download "$HF_REPO" \
    --repo-type dataset \
    --local-dir "$DATA_DIR" \
    --local-dir-use-symlinks False

echo "==> Done. Files:"
ls -lh "$DATA_DIR"

#!/bin/bash
# RunPod pod startup script.
# Idempotent: safe to run on every container start, sets up persistent /workspace.

set -e

WORKSPACE="/workspace"
REPO_DIR="${WORKSPACE}/vuln-llm-research"
ADAPTERS_DIR="${WORKSPACE}/adapters"
MODELS_DIR="${WORKSPACE}/models"
DATA_DIR="${WORKSPACE}/data"

echo "==> init.sh starting at $(date)"

# 1. Authenticate to HuggingFace if token provided as env var
if [ -n "${HF_TOKEN}" ]; then
    echo "==> Logging into HuggingFace"
    huggingface-cli login --token "${HF_TOKEN}" --add-to-git-credential
else
    echo "WARN: HF_TOKEN not set, hub operations may fail"
fi

# 2. Clone or update repo
if [ ! -d "${REPO_DIR}/.git" ]; then
    if [ -n "${GIT_REPO_URL}" ]; then
        echo "==> Cloning ${GIT_REPO_URL}"
        git clone "${GIT_REPO_URL}" "${REPO_DIR}"
    else
        echo "WARN: GIT_REPO_URL not set, skipping clone"
    fi
else
    echo "==> Repo exists, pulling latest"
    cd "${REPO_DIR}" && git pull --ff-only || echo "WARN: git pull failed (uncommitted changes?)"
fi

# 3. Download base model (Qwen2.5-Coder-7B-Instruct) if missing
QWEN_DIR="${MODELS_DIR}/qwen2.5-coder-7b-instruct"
if [ ! -d "${QWEN_DIR}" ]; then
    echo "==> Downloading base model Qwen2.5-Coder-7B-Instruct (~15 GB)"
    mkdir -p "${MODELS_DIR}"
    huggingface-cli download Qwen/Qwen2.5-Coder-7B-Instruct \
        --local-dir "${QWEN_DIR}" \
        --local-dir-use-symlinks False
else
    echo "==> Base model already cached at ${QWEN_DIR}"
fi

# 4. Download our private adapters if HF repo configured
if [ -n "${HF_ADAPTERS_REPO}" ]; then
    if [ ! -d "${ADAPTERS_DIR}" ] || [ -z "$(ls -A ${ADAPTERS_DIR} 2>/dev/null)" ]; then
        echo "==> Downloading adapters from ${HF_ADAPTERS_REPO}"
        mkdir -p "${ADAPTERS_DIR}"
        huggingface-cli download "${HF_ADAPTERS_REPO}" \
            --local-dir "${ADAPTERS_DIR}" \
            --local-dir-use-symlinks False || echo "WARN: adapter download failed (repo empty or no access)"
    else
        echo "==> Adapters already present at ${ADAPTERS_DIR}"
    fi
fi

# 5. Download datasets if HF repo configured
if [ -n "${HF_DATA_REPO}" ]; then
    if [ ! -d "${DATA_DIR}/hf" ]; then
        echo "==> Downloading datasets from ${HF_DATA_REPO}"
        mkdir -p "${DATA_DIR}/hf"
        huggingface-cli download "${HF_DATA_REPO}" \
            --repo-type dataset \
            --local-dir "${DATA_DIR}/hf" \
            --local-dir-use-symlinks False || echo "WARN: dataset download failed"
    fi
fi

# 6. Print environment summary
echo "==> Environment ready"
nvidia-smi --query-gpu=name,memory.total,driver_version --format=csv,noheader
echo "Python: $(python --version)"
echo "Repo: ${REPO_DIR}"
echo "Adapters: ${ADAPTERS_DIR}"
echo "Models: ${MODELS_DIR}"
echo "Datasets: ${DATA_DIR}"
echo "==> init.sh done at $(date)"

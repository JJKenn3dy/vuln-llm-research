#!/bin/bash
# Push a trained LoRA adapter to HuggingFace.
# Usage: ./scripts/upload_adapter.sh /workspace/adapters/v8_first v8_first

set -e

ADAPTER_DIR="$1"
SUBFOLDER="${2:-$(basename $ADAPTER_DIR)}"
HF_REPO="${HF_ADAPTERS_REPO:-JJKennedy/vuln-llm-adapters}"

if [ -z "$ADAPTER_DIR" ]; then
    echo "Usage: $0 <adapter_dir> [subfolder_name]"
    exit 1
fi

echo "==> Uploading $ADAPTER_DIR -> hf://$HF_REPO/$SUBFOLDER"

python -c "
from huggingface_hub import HfApi
api = HfApi()
api.create_repo('$HF_REPO', repo_type='model', private=True, exist_ok=True)
api.upload_folder(
    folder_path='$ADAPTER_DIR',
    repo_id='$HF_REPO',
    path_in_repo='$SUBFOLDER',
    repo_type='model',
)
print('Upload complete')
"

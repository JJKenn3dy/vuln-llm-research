# Base: official RunPod PyTorch image with CUDA 12.4 and Python 3.11
FROM runpod/pytorch:2.4.0-py3.11-cuda12.4.1-devel-ubuntu22.04

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    HF_HOME=/workspace/hf_cache \
    TRANSFORMERS_CACHE=/workspace/hf_cache \
    HF_HUB_ENABLE_HF_TRANSFER=1

WORKDIR /workspace

# System tools we want available on every pod
RUN apt-get update && apt-get install -y --no-install-recommends \
    git git-lfs \
    htop nvtop \
    curl wget \
    tmux \
    jq \
    && rm -rf /var/lib/apt/lists/* \
    && git lfs install

# Faster HF downloads
RUN pip install hf_transfer

# Pin the Python stack
COPY requirements.txt /tmp/requirements.txt
RUN pip install --upgrade pip && \
    pip install -r /tmp/requirements.txt

# Copy init script
COPY infra/init.sh /usr/local/bin/init.sh
RUN chmod +x /usr/local/bin/init.sh

# Default command: run init then drop into bash
CMD ["/bin/bash", "-c", "/usr/local/bin/init.sh && tail -f /dev/null"]

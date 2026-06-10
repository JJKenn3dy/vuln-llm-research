# RunPod template configuration

Use this as a checklist when creating the saved RunPod template.

## Container image

Build locally and push to a registry, or build inside RunPod with the Dockerfile in this folder.

```bash
docker build -t zyakuba/vuln-llm:latest -f infra/Dockerfile .
docker push zyakuba/vuln-llm:latest
```

(Optional. You can also point RunPod at the official `runpod/pytorch:2.4.0-py3.11-cuda12.4.1-devel-ubuntu22.04` image and run `init.sh` manually after first deploy.)

## RunPod template fields

| Field | Value |
|---|---|
| Container Image | `zyakuba/vuln-llm:latest` (or `runpod/pytorch:2.4.0-py3.11-cuda12.4.1-devel-ubuntu22.04`) |
| Container Disk | 25 GB (ephemeral) |
| Volume Disk | 100 GB persistent at `/workspace` |
| Expose HTTP Ports | 8888 (Jupyter), 6006 (TensorBoard) |
| Expose TCP Ports | 22 (SSH for VSCode Remote) |
| Volume Mount Path | `/workspace` |
| Docker Command | `bash -c "/usr/local/bin/init.sh && tail -f /dev/null"` |

## Environment variables (set as Pod secrets)

| Name | Value | Notes |
|---|---|---|
| `HF_TOKEN` | hf_xxx | HuggingFace write-access token |
| `GIT_REPO_URL` | git@github.com:JJKenn3dy/vuln-llm-research.git | SSH (add deploy key on first pod) or use HTTPS with PAT |
| `HF_ADAPTERS_REPO` | JJKennedy/vuln-llm-adapters | Private HF repo with LoRA weights |
| `HF_DATA_REPO` | JJKennedy/vuln-llm-datasets | Private HF dataset repo |
| `WANDB_API_KEY` | xxx | Optional, for training logs |
| `OPENAI_API_KEY` | sk-xxx | For GPT-4o distillation / baselines |
| `ANTHROPIC_API_KEY` | sk-xxx | For Claude baselines |

## Recommended GPU choices

| Task | Pod type | Cost/hr |
|---|---|---|
| Inference / eval / smoke | L4 (24 GB) | $0.39 |
| QLoRA 7B fine-tune | L40S (48 GB) | $0.86 |
| QLoRA 14B fine-tune | A100 80GB | $1.39 |
| Multi-GPU experiments | 2x A100 80GB | $2.78 |

## First-time setup checklist

1. Create persistent volume (100 GB) in your preferred region.
2. Build or point to container image.
3. Save template with all env vars filled in.
4. Deploy a small L4 pod once to verify `init.sh` runs end-to-end.
5. Check that `/workspace/models/qwen2.5-coder-7b-instruct/` populated correctly (~15 GB).
6. Verify SSH access via VSCode Remote.

## Reconnect via VSCode Remote-SSH

Add to your local `~/.ssh/config`:

```
Host runpod-vuln
    HostName <pod-public-ip>
    Port <runpod-ssh-port>
    User root
    IdentityFile ~/.ssh/id_ed25519
```

Then `code --remote ssh-remote+runpod-vuln /workspace/vuln-llm-research`.

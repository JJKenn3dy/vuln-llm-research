# vuln-llm-research

Fine-tuned 7B LLM for software vulnerability detection and SAST triage. Built on top of Qwen2.5-Coder-7B-Instruct with LoRA adapters.

## Current state (10.06.2026)

Building a commercial SAST triage product. Pivot from academic detection (v5b
defended in BSc thesis) to triage filtering of existing SAST tool findings.

**Latest benchmark on triage_100 (50 TP + 50 FP, stratified from v7lite test set):**

| Model | F1 | BalAcc | MCC | Notes |
|---|---|---|---|---|
| GPT-4o (2024-11-20) | 0.479 | 0.500 | 0.00 | random |
| Llama 3.3 70B Instruct | 0.469 | 0.570 | 0.15 | slight signal |
| DeepSeek-Chat | 0.265 | 0.500 | 0.00 | conservative, random |
| **v8 (target)** | **>0.65** | **>0.65** | **>0.30** | specialist 7B + LoRA |

Headline finding: **frontier LLMs perform at random on our SAST triage task.**
This is the open window for a specialist.

## Historical context

- **v5b** (defended May 2026): F1 = 0.859 on CVEFixes-100 in-domain detection,
  beats GPT-4o, Claude Sonnet 4.5, DeepSeek R1, Qwen-Coder-32B on the same set.
  Now reproduced on RunPod and pushed to HF as `JJKennedy/vuln-llm-adapters/v5b_repro`.
- **v6b / v7lite_r8**: out-of-domain experiments, capped at BalAcc ≈ 0.526 on
  honest project-stratified split. The lessons from those failures shape v8's
  design (see HISTORY.md).
- **v8** (in progress): SAST triage, training on 2879 TP/FP pairs from
  CVEFixes + CrossVul, project-stratified split.

## Why this is commercial

Industry data: average enterprise sees 865k SAST alerts/year, **91% false positive**,
15-30 min triage time per false alert. Existing AI-SAST startups (Corgea, ZeroPath,
Cycode, Black Duck Signal) all use frontier LLMs as the reasoner — which we just
showed are at random on this task. Specialist 7B at $0.0001/finding vs $0.05 API
is a 500x cost edge, plus on-prem option for regulated industries.

For the why and where-we-go, see [docs/PRODUCT.md](docs/PRODUCT.md),
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), [docs/ROADMAP.md](docs/ROADMAP.md),
[docs/HISTORY.md](docs/HISTORY.md), and the per-session log at
[docs/SESSION_2026-06-10.md](docs/SESSION_2026-06-10.md).

## Repo layout

```
vuln-llm-research/
├── docs/                     PRODUCT / ARCHITECTURE / ROADMAP / HISTORY
├── infra/                    Dockerfile + init.sh for RunPod template
├── src/
│   ├── data_prep/            prepare_train_*, prepare_eval_*, prepare_sastbench
│   ├── train/                train_qlora (canonical), train_v8_triage (next track)
│   ├── eval/                 run_eval, calibrate
│   ├── utils/                prompts, metrics
│   └── legacy/               original cHARISMa scripts for reference
├── data/
│   ├── eval/                 small eval fixtures committed in git
│   ├── train/                v5b train+val (the reproducible baseline)
│   └── logprobs/             stored logprobs for re-calibration experiments
├── scripts/                  retrain_v5b.sh, download_data.sh, upload_adapter.sh
└── notebooks/                exploratory work
```

Large datasets (v7lite train, full CrossVul, future SastBench) live on a private HuggingFace dataset repo, fetched via `scripts/download_data.sh`. LoRA adapters live on a private HuggingFace model repo.

## Quickstart on RunPod

Prereqs: HuggingFace account + write token, GitHub access to this repo, RunPod account with persistent volume.

1. **Build the template** following [infra/runpod_template.md](infra/runpod_template.md).
2. **Deploy a pod** with L40S 48GB (or A100 80GB for 14B experiments).
3. **Pod startup** runs `infra/init.sh` automatically. After ~3 minutes you have:
   - This repo at `/workspace/vuln-llm-research`
   - Base Qwen2.5-Coder-7B at `/workspace/models/qwen2.5-coder-7b-instruct`
   - Adapters (if any) at `/workspace/adapters`
4. **Reproduce v5b** as a sanity check:
   ```bash
   bash scripts/retrain_v5b.sh --upload
   ```
   Expected: F1 ≈ 0.86 on CVEFixes-100 (within ±0.005 of original). ~6 hours on L40S, costs ~$5.
5. **Move to v8 triage**: see [docs/ROADMAP.md](docs/ROADMAP.md).

## Quickstart locally (development only)

You can edit and run lint/tests locally on Windows or WSL. Actual training and eval need a GPU.

```bash
python -m venv .venv
.venv\Scripts\activate    # Windows
pip install -r requirements.txt

# Quick smoke: render a prompt and check formatting
python -c "from src.utils.prompts import DETECTION_SYSTEM, DETECTION_USER_TEMPLATE; print(DETECTION_USER_TEMPLATE.format(language='Python', code='x=1'))"
```

## Reproducing v5b from scratch

We have all the train data committed, so v5b is fully reproducible without access to the original cHARISMa cluster:

```bash
python -m src.train.train_qlora \
    --train-file data/train/train_v5b_train.json \
    --val-file data/train/train_v5b_val.json \
    --output-dir /workspace/adapters/v5b_repro \
    --epochs 3 --lora-r 16 --lora-alpha 32 --lr 1.5e-4

python -m src.eval.run_eval \
    --adapter-dir /workspace/adapters/v5b_repro \
    --input-file data/eval/eval_cvefixes_100.json \
    --output-file /workspace/runs/v5b_repro_outputs.json \
    --metrics-file /workspace/runs/v5b_repro_metrics.json
```

Expected: F1 ≈ 0.86, FAR ≈ 13%, CWE accuracy on TP ≈ 70%.

## License

Private repo. All rights reserved. License decision deferred until product launch.

## Author

Zakhar Yakuba ([@zyakuba](https://github.com/zyakuba)). BSc in Information Security, HSE MIEM (2026).

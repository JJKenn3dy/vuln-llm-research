# Data layout

What lives in git vs HuggingFace.

## Committed in git (small fixtures, reproducible reference)

| Path | Size | Purpose |
|---|---|---|
| `eval/eval_cvefixes_100.json` | 184 KB | v5b in-domain eval set (70 vuln + 30 safe) |
| `eval/eval_crossvul_100.json` | 745 KB | OOD eval set (50 vuln + 50 safe) |
| `train/train_v5b_train.json` | 3.8 MB | v5b train set (800 vuln + 800 safe) |
| `train/train_v5b_val.json` | 414 KB | v5b val set |
| `logprobs/v5b_logprobs_eval.json` | 21 KB | calibration data for v5b on CVEFixes |
| `logprobs/v5b_logprobs_val.json` | 32 KB | calibration data for v5b val set |
| `logprobs/v6b_logprobs_*.json` | ~70 KB | v6b runs (OOD experiment) |
| `logprobs/v7lite_r8_logprobs_*.json` | 20 KB | v7lite_r8 (best honest OOD) |

These are enough to reproduce the v5b baseline end-to-end without any external data downloads.

## Lives on HuggingFace (private dataset repo)

Large or generated files. Pull via `scripts/download_data.sh` into `/workspace/data/hf/`:

| Path | Size | Purpose |
|---|---|---|
| `train_v7lite_train.json` | 19 MB | extended train with CrossVul augmentation |
| `train_v7lite_val.json` | ~3 MB | matching val |
| `eval_crossvul_full.json` | ~3 MB | full CrossVul-400 |
| `eval_crossvul_300.json` | ~3 MB | CrossVul-300 OOD val |
| `sastbench/` | TBD | once we mirror the SastBench corpus |

## Not committed (never in git)

- LoRA adapter weights (`qlora_output_*/`) — lived on cHARISMa, now gone. Reproduce via `scripts/retrain_v5b.sh`.
- Base model (`Qwen/Qwen2.5-Coder-7B-Instruct`) — pulled from HF Hub on first pod boot.
- ВКР DOCX/PDF, charts, drafts — those live in the original `f:/diplom/` workspace, not this repo.

## Reading the JSON formats

### Train and eval entries

Each entry is a chat-format example:

```json
{
  "messages": [
    {"role": "system", "content": "<system prompt>"},
    {"role": "user", "content": "<user prompt with code>"},
    {"role": "assistant", "content": "<expected structured output>"}
  ],
  "metadata": {
    "cve_id": "CVE-2023-XXXX",
    "cwe_id": "CWE-89",
    "label": "vulnerable",
    "project_id": "<project hash>",
    "language": "Python"
  }
}
```

Eval entries omit the assistant message (model generates it). See `src/utils/prompts.py` for canonical templates.

### Logprobs entries

```json
{
  "case_id": "CVE-2023-XXXX",
  "true_label": "vulnerable",
  "p_vuln": 0.78,
  "p_type_token": 0.85,
  "p_verdict_token": 0.12,
  "project_id": "<for honest split>"
}
```

Used by `src/eval/calibrate.py` to sweep threshold and pick the optimal one without re-running inference.

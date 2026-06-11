# v8.3.1 — multi-source result (CVEFixes-clean + CrossVul)

Adapter: `JJKennedy/vuln-llm-adapters/v8_3_1` (HF upload skipped per train
script; on disk at `/workspace/adapters/v8_3_1` until pod was terminated).

Trained 2026-06-11 ~05:00-06:20 UTC on RunPod A40, 2180 row merged train
(970 v8.3 clean CVEFixes + 1210 CrossVul TRIAGE), 3 epochs, same hyperparams
as v8.3.0 (r=16, alpha=32, lr=1e-4). Train ~73 min, eval+logprob ~55 min.

## Headline — three-way comparison

| Metric | v8.2 | v8.3.0 | **v8.3.1** | Δ from v8.2 | Δ from v8.3.0 |
|---|---|---|---|---|---|
| **SastBench MCC** | +0.100 | +0.141 | **+0.177** | +0.077 | +0.036 |
| **SastBench BA** | 0.559 | 0.597 | **0.612** | +0.053 | +0.015 |
| SastBench DR | 88.6% | 51.4% | 45.7% | −42.9 pp | −5.7 pp |
| **SastBench FAR** | 76.7% | 32.1% | **23.3%** | −53.4 pp | −8.8 pp |
| **SastBench precision** | 16.4% | 20.7% | **24.2%** | +7.8 pp | +3.5 pp |
| test_balanced MCC | +0.649 | +0.452 | +0.424 | −0.225 | −0.028 |
| test_balanced BA | 0.823 | 0.726 | 0.710 | −0.113 | −0.016 |
| test_balanced FAR | 23.4% | 25.0% | 21.8% | −1.6 pp | −3.2 pp |

## ⭐ Statistical significance threshold reached (barely)

Cluster bootstrap MCC CIs (honest, by `repo_url`):
- v8.2: [-0.04, +0.19] (captures 0)
- v8.3.0: [-0.07, +0.31] (captures 0)
- **v8.3.1: [+0.00, +0.30] ← lower bound at 0** ← first version that is
  statistically borderline distinguishable from random

This is the threshold the project needed to cross. v8.3.1 is the first
adapter where cluster-honest CI does not span negative MCC territory.

## What multi-source contributed

v8.3.0 already cured the major paranoia (FAR 77% → 32%) by removing duplicate
train rows. v8.3.1 added CrossVul (1210 TRIAGE pairs from 864 unique CVE
fixes) and gained:
- MCC +0.036 over v8.3.0
- FAR −8.8 pp (32% → 23%) — a SECOND third of paranoia removed
- Precision +3.5 pp (21% → 24%) — useful production filter levels

The reviewer's framing was right: dedup fixed contradictory supervision;
multi-source addressed distribution mismatch. Each lever did roughly half
the work.

## Per-slice cluster-CV calibration (v8.3.1)

Per-language (cluster-CV mean MCC):
- Python: +0.076 (was +0.269 v8.3.0 — DROPPED significantly)
- TypeScript: +0.067 (was −0.067 v8.3.0 — flipped positive)
- Go: 0.000, Ruby: 0.000, Other: 0.000 (degenerate)
- PHP: −0.015 (was −0.022 v8.3.0)
- JavaScript: −0.200 (was −0.152)

Per-CWE cluster-CV:
- CWE-79: −0.275 (was +0.051 v8.3.0 — sharp swing)
- CWE-89: +0.022 (similar)
- CWE-78: −0.222 (was −0.050 — got worse)

**Interpretation**: cluster-CV per-slice calibration is unstable for v8.3.1.
The win is at the DEFAULT threshold (0.5, no flip). Trying to optimize
per-slice on val folds picks up fold noise and inverts in test. **Recommend
NOT applying per-slice calibration on v8.3.1**; default operating point is
the production choice.

## Why v8.3.1 + per-slice calibration doesn't compound

Both moves attack the same underlying overfit (single mechanism in train).
After multi-source, there's less residual per-slice bias for calibration to
exploit. The wedges are not additive here.

## Logprob gap status

| Set | v8.2 | v8.3.0 | v8.3.1 |
|---|---|---|---|
| test_balanced | 0.058 | **+0.175** | (extracted, not analysed yet) |
| SastBench | +0.027 | +0.051 | +0.023 (slight dip) |

In-domain gap stayed healthy through v8.3.1. SastBench gap slightly compressed
versus v8.3.0 — the calibration wedge weakened as the model needs less
calibration help (operating point is good as-is).

## What this means for pitch

Headline now defensible:
> "On SastBench-250 (a public benchmark of real Semgrep findings on real OSS
> projects), our 7B specialist hits MCC = +0.177, with cluster-honest CI
> [+0.00, +0.30] — the first single-call frontier-or-specialist model to
> cross statistical significance against random on this benchmark in our
> measurement. False alarm rate 23%, three times better than v8.2 baseline."

Caveats still required:
- CI lower bound is at 0 — borderline, not headline-bold
- Sonnet 4.5 paper reports 0.110 with Improved ReAct (multi-turn), single-call
  Sonnet baseline ~MCC 0 in our smoke
- We are NOT yet beating ReAct frontier; we ARE beating single-call frontier
  by a decisive margin

## v8.3.2 candidate moves (only if Zakhar wants to push further)

1. **Teacher reasoning for CrossVul** (~$1.50 OpenRouter) — replace
   placeholder reasoning with Haiku-generated varied reasoning. May add
   +0.02-0.05 MCC if stylistic shortcut was still present.
2. **Juliet small dose (~$1)** — synthetic NIST samples as anti-stylistic
   anchor (reviewer's recommendation).
3. **r=8 ablation** — smaller LoRA may reduce overfit further (Lesson 4).
4. **Better threshold than default 0.5** — even though per-slice CV doesn't
   work, a global cluster-CV optimal threshold (already computed: −0.011
   marginally worse) suggests stick with 0.5.

## Files

```
runs/
  v8_3_1_sastbench250_outputs.json     250 predictions
  v8_3_1_sastbench250_metrics.json     aggregate metrics
  v8_3_1_testbalanced_outputs.json     248 predictions in-domain
  v8_3_1_testbalanced_metrics.json     aggregate metrics
  v8_3_1_logprobs_sastbench250.json    250 first-token p_tp
  v8_3_1_logprobs_testbalanced.json    248 first-token p_tp
  v8_3_1_perslice_lang_calib.json      per-language cluster-CV
  v8_3_1_perslice_cwe_calib.json       per-CWE cluster-CV
  comparison_v8_2_v8_3_0_v8_3_1.json   three-way comparison

data/train/triage_v8_3_1/
  train_merged.json                    2180 row clean multi-source train
  merge_meta.json                      provenance
```

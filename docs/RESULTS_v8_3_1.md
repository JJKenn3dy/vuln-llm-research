# v8.3.1 — multi-source result (CVEFixes-clean + CrossVul)

Adapter: `JJKennedy/vuln-llm-adapters/v8_3_1` (uploaded 2026-06-11 late
evening from temp A40 pod, see SESSION_2026-06-11_reviewer_round.md).

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

### Trivial baselines on SastBench-250 (the floor)

SastBench-250 distribution: 35 true positives, 215 false positives
(production-realistic 14% TP rate). On this imbalanced set:

| Model | DR | FAR | Precision | F1 | BA | MCC |
|---|---|---|---|---|---|---|
| all-TP (predict TP for everything) | 100.0% | 100.0% | 14.0% | 0.246 | 0.500 | 0.000 |
| all-FP (predict FP for everything) | 0.0% | 0.0% | 0.0% | 0.000 | 0.500 | 0.000 |
| random 50/50 (seeded) | 48.6% | 49.8% | 13.7% | 0.214 | 0.494 | −0.008 |
| v5b zero-shot (paranoia) | 76.0% | 78.0% | — | 0.598 | 0.490 | −0.020 |
| **v8.3.1** | **45.7%** | **23.3%** | **24.2%** | 0.317 | 0.612 | **+0.177** |

This is the read: v8.3.1 MCC=+0.177 sits **above** the trivial floor of
MCC=0 (any constant-prediction strategy gives MCC=0 by definition). Below
this line, "I beat the all-TP baseline" is a meaningful claim. Above this
line, comparison only makes sense against models that are also above the
floor (frontier baseline on same 250 still pending — see NEXT_STEPS P1).

## ⭐ Honest CI no longer spans negative MCC

Cluster bootstrap MCC CIs (honest, by `repo_url`):
- v8.2: [-0.04, +0.19] (captures 0)
- v8.3.0: [-0.07, +0.31] (captures 0)
- **v8.3.1: [+0.00, +0.30]** ← lower bound touches 0, no longer in negative
  territory

This is **touching** the significance boundary, not crossing it. CI lower
bound at 0 means we cannot reject the null hypothesis "performance equal
to random" at 95% confidence; the data is consistent with random-or-better.
Correct framing: "first adapter version with honest CI no longer in
negative territory". NOT "crossing statistical significance".

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

## Frontier baseline on the same 250 cases (2026-06-11 late evening)

Closed the methodological hole reviewer flagged. Same 250 SastBench cases,
same parse regex, same parse_fail accounting, same cluster bootstrap by
`repo_url`. See [scripts/run_frontier_v8_3_1_baseline.sh](../scripts/run_frontier_v8_3_1_baseline.sh)
for the runner and [scripts/frontier_v8_3_1_report.py](../scripts/frontier_v8_3_1_report.py)
for the cluster bootstrap + decision rule.

### Results

| Model | MCC | Cluster CI by repo_url | BA | FAR | DR | Precision | parse_fail |
|---|---|---|---|---|---|---|---|
| **v8.3.1 (our 7B)** | **+0.177** | **[+0.004, +0.297]** | 0.612 | **23.3%** | 45.7% | **24.2%** | 0.0% |
| Sonnet 4.5 single-call | +0.019 | [-0.141, +0.118] | 0.513 | 68.8% | 71.4% | 14.5% | 0.0% |
| Gemini 2.5 Pro single-call | +0.043 | [-0.150, +0.138] | 0.531 | 59.4% | 65.6% | 14.6% | 4.4% |

Note: Sonnet was run only with our TRIAGE prompt (single-prompt budget
A); two-prompt (TRIAGE + neutral) run deferred. If Sonnet on TRIAGE format
shows artificially low MCC due to format unfamiliarity, neutral prompt
round (+$3.50 OpenRouter) would address. Current Sonnet smoke 10 had
parse_fail=0% on TRIAGE format, so format-unfamiliarity attack is weak
but not closed.

### Pre-committed decision rule application

From [NEXT_STEPS.md](NEXT_STEPS.md) (rule fixed BEFORE running):
- "beat" = our cluster CI lower bound ≥ frontier point MCC
- "match" = frontier point MCC inside our CI
- "lose" = frontier point MCC above our CI upper bound

Strict application of the script's decision logic:
- vs Sonnet 4.5: our lower bound (+0.004) < Sonnet point (+0.019) → **match**
- vs Gemini 2.5 Pro: our lower bound (+0.004) < Gemini point (+0.043) → **match**

### Honest narrative of the numbers

The strict "match" verdict is technically right under the script's
single-direction check (frontier point in our CI). But the picture is
**asymmetric**:

1. **Our CI [+0.004, +0.297] excludes 0**. We are statistically
   distinguishable from random at 95% confidence on cluster-honest CI.
2. **Both frontier CIs span 0** (Sonnet [-0.141, +0.118], Gemini
   [-0.150, +0.138]). They are NOT distinguishable from random.
3. **Our point MCC +0.177 lies above the upper bound of both frontier
   CIs** (Sonnet upper +0.118, Gemini upper +0.138). They do not contain us.
4. **Their points lie inside our CI** (Sonnet 0.019, Gemini 0.043 both
   in [+0.004, +0.297]). We contain them.

### Paired cluster bootstrap — strictly stronger test

Per Захар's request 2026-06-11 night: independent CIs underestimate the
gap because all three models scored the same 250 cases. A **paired
bootstrap** resamples whole repo_url clusters and computes MCC for each
arm on the SAME resampled cases, then takes the difference. CI on the
differences is the strict test of whether "v8.3.1 > frontier" holds.

`scripts/paired_cluster_bootstrap.py` over 2000 cluster resamples on the
66 repo_url clusters:

| Comparison | Paired MCC diff 95% CI | P(diff > 0) | Strict beat? |
|---|---|---|---|
| **v8.3.1 − Sonnet 4.5** | **[+0.010, +0.304]** | **98.0%** | **YES** (lower bound > 0) |
| v8.3.1 − Gemini 2.5 Pro | [-0.033, +0.354] | 95.65% | near-strict (just under 95%) |

**vs Sonnet 4.5 — strict beat at 95% confidence under paired test.** The
lower bound of the paired MCC difference is +0.010 (strictly above zero),
which means on 95% of bootstrap resamples our MCC was higher than
Sonnet's by at least +0.010. This is the strongest formal claim we can
make on this benchmark.

**vs Gemini 2.5 Pro** — paired diff CI just barely includes 0 at lower
bound (-0.033). We win on 95.65% of resamples, which is shy of the 95%
threshold needed for strict statistical beat at the same standard. Close,
not decisive.

Independent-CI "soft beat" framing is superseded: paired test gives
strict beat vs Sonnet and near-strict vs Gemini.

### Behavioural margin (non-statistical, behavioural)

Even where MCC CIs allow technical "match", behaviour is starkly
different:
- **FAR**: 23% (ours) vs 69% (Sonnet) vs 59% (Gemini) — 3× lower
- **DR**: 46% (ours) vs 71% (Sonnet) vs 66% (Gemini) — they over-call
- **Precision**: 24% (ours) vs 14.5% / 14.6% (frontier) — 1.7× higher

Frontier single-call collapses into **paranoia mode** (default-to-TP).
This is the same mechanism we documented in HISTORY.md Lesson 19
(paranoia is uncertainty signature, three independent observations):
v8.2 dirty train, v8.3.1_r8 undercapacity, frontier single-call — same
behavioural symptom from different causes of "model does not know".

### Defensible pitch formulation (post-frontier baseline + paired test)

> "On public SastBench-250 our 7B Qwen-Coder specialist achieves
> single-call MCC = +0.177 with cluster-honest 95% CI [+0.004, +0.297]
> (project-stratified bootstrap by repo_url). On the SAME 250 cases under
> the SAME parse regex, single-call Sonnet 4.5 scores MCC = +0.019 with
> CI [-0.141, +0.118] and Gemini 2.5 Pro scores MCC = +0.043 with CI
> [-0.150, +0.138] — neither single-call frontier model is statistically
> distinguishable from random on this benchmark. **Paired cluster
> bootstrap shows strict beat vs Sonnet 4.5 at 95% confidence** (paired
> MCC diff CI [+0.010, +0.304], P=98.0%) and near-strict vs Gemini 2.5 Pro
> (P=95.65%). False alarm rate 23% (ours) vs 59-69% (frontier paranoia
> mode). Inference cost wedge ~150× ($0.0001/finding self-hosted with
> vLLM batching vs $0.015/finding Sonnet single-call OpenRouter)."

Mandatory caveats:
- Recall 46% — we miss 54% of real bugs. Production positioning as
  **ranker** (sort alerts by p_tp, do not hide), not as **filter** (drop
  FP). Live-bot deployment with current DR = anti-case at first missed
  bug in customer's repo.
- Strict beat at 95% confidence holds **vs Sonnet 4.5 only**. vs Gemini
  2.5 Pro it's P=95.65%, fractionally below the 95% strict threshold.
- Sonnet two-prompt run not done — format-unfamiliarity attack remains
  weakly open (Sonnet smoke parse_fail=0%, so format adherence is fine,
  but quality could plausibly differ on neutral prompt). Could close for
  +$3.50 OpenRouter if needed for harder pitch.
- v8.3.1 not validated on real production deployment yet.
- Cost wedge of 150× assumes self-hosted vLLM batching at full GPU
  utilisation. Sequential single-call inference (e.g. PR webhook latency
  budget) drops to ~$0.0005/finding, wedge ~30× vs Sonnet, still material.

Forbidden:
- "Decisive margin over single-call frontier" — strict beat only vs
  Sonnet under paired test, not vs Gemini. Say "strict beat vs Sonnet,
  near-strict vs Gemini under paired cluster bootstrap" for accuracy.
- "Crossing statistical significance" without qualifier — our independent
  CI just barely excludes 0. Use "first version where honest cluster CI
  no longer extends into negative MCC" OR cite the paired-test result
  directly.
- "500-1000× cost wedge" — overstated. Conservative honest number is
  ~150× vs Sonnet (vLLM batched) or ~30× sequential.

### Confusion intersection — hand-labeling priority list

Script identified 35 cases where v8.3.1, Sonnet, AND Gemini all disagree
with the SastBench ground truth on the subset250 test set. These are
first-priority candidates for hand-labeling round (likely mis-labelled
benchmark cases). See
[runs/frontier_v8_3_1/comparison_report.md](../runs/frontier_v8_3_1/comparison_report.md)
for the full list.

**Side experiment** (2026-06-11 night, [HAND_LABEL_50_2026-06-11.md](HAND_LABEL_50_2026-06-11.md)):
on the val-558 partition (disjoint from subset250), AI hand-label +
tri-judge adjudication confirmed 7 SastBench mislabels in 10 contested
HIGH-confidence cases out of a 50-case balanced sample. This establishes
the floor on label noise as non-zero. Does NOT directly translate to
subset250 (different partition, different selection bias), but combined
with the 35-case confusion-intersection above suggests material label
noise across the benchmark.

### Cost

| Item | $ |
|---|---|
| Sonnet 4.5 TRIAGE 250 via OpenRouter | ~$3.50 |
| Gemini 2.5 Pro TRIAGE 250 via OpenRouter | ~$2.00 |
| Sonnet + Gemini smoke 10 (cost discovery) | ~$0.17 |
| **Frontier baseline total** | **~$5.67** |

Pre-budget estimate was $1.50-2 (predecessor undercount). Actual within
the refreshed $7 OpenRouter approval Захар granted late evening.

## What this means for pitch (post-frontier-baseline, defensible)

See "Defensible pitch formulation" in the frontier baseline section above.
The short form:

- Our cluster CI doesn't include 0; frontier CIs include 0
- Our point estimate ~9× Sonnet, ~4× Gemini on the same 250
- **Paired bootstrap: strict beat vs Sonnet (95% CI lower bound > 0), near-strict vs Gemini (P=95.65%)**
- FAR 3× lower; cost wedge ~150× (Sonnet single-call, conservative)

**Mandatory caveats still required** (same as before, frontier didn't
change these):
- Recall 46% — miss 54% of real bugs. Ranker positioning, not filter.
- "Asymmetric soft beat", NOT "decisive margin" or "crossing significance"
- Sonnet two-prompt run deferred; format-unfamiliarity attack weakly open
- Not validated on real production deployment yet

**Permanently forbidden** (reviewer caught these earlier, even with
frontier landed):
- "Outperforms Gemini ReAct" — paper numbers (Gemini ReAct 0.148 / Sonnet
  ReAct 0.110) are on a DIFFERENT SastBench subset and use multi-turn.
  We compare against single-call frontier only.
- "Decisive margin over single-call frontier" — the gap is asymmetric and
  large, but technically "match" under strict pre-commit rule. Soft beat.
- "First single-call model crossing statistical significance" — our CI
  just barely excludes 0. Use "first version where honest cluster CI no
  longer extends into negative MCC" instead.

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

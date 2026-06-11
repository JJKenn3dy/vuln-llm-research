# Overnight session summary — 2026-06-11 (Zakhar slept)

Захар ушёл спать с разрешением выжать максимум на ~$8 бюджета.

## What happened

**v8.3.0 train+eval (DONE)**:
- Trained 970-row clean-dedup CVEFixes (from 1794 v8.2 train via
  `scripts/prepare_v8_3_clean.py`)
- Eval on SastBench-250 + test_balanced
- Logprob extract on both
- Result: **Case B from decision tree confirmed**
- See `docs/RESULTS_v8_3_0.md` and `project_v8_3_0_done_case_b.md` memory

**v8.3.1 train+eval (IN PROGRESS at overnight session end)**:
- Multi-source: 970 clean CVEFixes + 1210 CrossVul TRIAGE = 2180 rows
- Same hyperparams as v8.3.0 (r=16) — isolates multi-source effect
- CrossVul prep + merge scripts committed
- Will complete around 07:30 UTC

**Reviewer poked at v8.3.0 result (paste from chat)**:
- Confirmed cluster bootstrap caveat (v8.3.0 cluster CI still captures 0)
- Sufficiency gate still "not closed" honestly (no human hand-labeling)
- v8.3.1 multi-source is the right next move per Case B

## Headline v8.3.0 numbers (cluster-honest where available)

| Metric | v8.2 | v8.3.0 | Δ |
|---|---|---|---|
| SastBench MCC | +0.100 | **+0.141** | +0.041 |
| SastBench BA | 0.559 | 0.597 | +0.038 |
| **SastBench FAR** | 76.7% | **32.1%** | **−44.7 pp (biggest win)** |
| SastBench DR | 88.6% | 51.4% | −37.2 pp (trade-off) |
| test_balanced MCC | +0.649 | +0.452 | −0.197 (expected) |
| **gap_p_tp test_balanced** | +0.058 | **+0.175** | **+0.117 (calibration restored!)** |
| gap_p_tp SastBench | +0.027 | +0.051 | +0.024 (marginal) |

Cluster bootstrap MCC CIs (honest, by repo_url):
- v8.2: [-0.04, +0.19] captures 0
- v8.3.0: [-0.07, +0.31] still captures 0 (ceiling moved up though)

## Budget burn this overnight session

| Item | Cost |
|---|---|
| v8.3.0 RunPod A40 train+eval (1.5h) | ~$0.66 |
| v8.3.1 RunPod A40 train+eval (~2.5h projected) | ~$1.10 |
| OpenRouter (probe + labeling earlier today) | $0 (untouched overnight) |
| OpenAI | $0 (untouched) |
| **Total overnight** | **~$1.76** |

Within $4.80 RunPod budget; OpenRouter $2.70 and OpenAI $1.46 untouched
overnight.

## Memory adds this session

- `project_v8_3_0_done_case_b.md` ⭐ — v8.3.0 result + Case B narrative
- `feedback_no_oracle_leak_in_calibration.md` 🚨 — Захар's flip-set catch
- `feedback_cluster_bootstrap_for_clustered_data.md` 🚨 — reviewer's CI fix
- `feedback_intermediate_results_always.md` 🚨 — partial dumps rule
- `feedback_meta_check_between_experiments.md` 🚨 — don't auto-pilot pipeline

## Decision queue for Zakhar (in priority order)

1. **Look at v8.3.1 result** when it completes (~07:30 UTC). Run
   `python scripts/compare_v8_2_v8_3_0_v8_3_1.py` to get side-by-side.

2. **If v8.3.1 MCC > 0.18**: multi-source is the lever, continue this
   direction. Plan v8.3.2 with more sources (Juliet, D2A if registration done).

3. **If v8.3.1 MCC ≈ v8.3.0** (no improvement): CrossVul placeholder
   reasoning was a stylistic shortcut leak. v8.3.2 should add teacher call
   for CrossVul reasoning. Budget for teacher: ~$1.50 OpenRouter.

4. **If v8.3.1 MCC < v8.3.0** (regression): CrossVul mechanism actively
   hurts. Stop multi-source path, investigate Juliet or curated FP-style
   variations within CVEFixes instead.

5. **Hand-labeling 50 cases for sufficiency probe** still pending. Reviewer
   called it out as gate that dedup cannot answer in principle. Захар has
   to do this himself; not automatable.

6. **Mailbox** with Codex — `coordination/POLICY.md` готово на нашей
   стороне. Когда настроишь Codex'а — будет работать.

## Files for Zakhar to scan first thing

In priority order:
1. `docs/OVERNIGHT_SUMMARY.md` (this file)
2. `docs/RESULTS_v8_3_0.md` (Case B confirmation)
3. `docs/NEXT_STEPS.md` (top of file has overnight update)
4. `runs/v8_3_1_*` when train completes (~07:30 UTC)
5. Memory ⭐/🚨 entries via `MEMORY.md`

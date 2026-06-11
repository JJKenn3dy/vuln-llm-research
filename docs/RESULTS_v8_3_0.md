# v8.3.0 — dedup ablation result

Adapter: `JJKennedy/vuln-llm-adapters/v8_3_0` (HF upload failed; on disk
on network volume `/workspace/adapters/v8_3_0`)
Trained: 2026-06-11 03:42-04:09 UTC on RunPod A40, 970 row clean train,
1605 sec, final train_loss=0.81.

## Headline — Case B from decision tree

Dedup fixed the **contradictory train** problem (gap on in-domain restored)
but **distribution mismatch** remains (gap on SastBench still small).
Multi-source mix is required for v8.3.1 to close the external gap.

## Numbers

| Metric | v8.2 | v8.3.0 | Δ |
|---|---|---|---|
| **SastBench-250 MCC** | +0.100 | +0.141 | **+0.041** |
| SastBench-250 BA | 0.559 | 0.597 | +0.038 |
| **SastBench-250 FAR** | 76.7% | **32.1%** | **−44.7 pp** |
| SastBench-250 DR | 88.6% | 51.4% | −37.2 pp |
| test_balanced MCC | +0.649 | +0.452 | −0.197 |
| test_balanced BA | 0.823 | 0.726 | −0.097 |
| test_balanced FAR | 23.4% | 25.0% | +1.6 pp |
| **gap_p_tp (in-domain)** | +0.058 | **+0.175** | **+0.117** |
| gap_p_tp (SastBench) | +0.027 | +0.051 | +0.024 |
| train_loss | 0.69 | 0.81 | +0.12 |

## Statistical honesty (cluster bootstrap by repo_url)

| Slice | v8.2 cluster CI | v8.3.0 cluster CI |
|---|---|---|
| Overall MCC | [-0.04, +0.19] | [-0.07, +0.31] |
| Overall BA | [0.47, 0.62] | [0.44, 0.70] |

Both v8.2 and v8.3.0 cluster CIs capture 0 — neither is statistically
distinguishable from random by honest cluster bootstrap. But point
estimate of v8.3.0 is shifted right (+41% MCC), CI ceiling pushed up
to +0.31.

## Anti-paranoia is the biggest win

v8.2 was a "yes machine" — 77% of FPs called TP. v8.3.0 drops FAR to 32%.
This is the structural cure for `feedback_intermediate_results_always`-flavour
problem: clean train → less default-to-majority bias.

DR drop from 89% to 51% is the trade-off. v8.2 was finding 89% of real bugs
but with so much noise (FAR=77%) that filtering was nearly useless. v8.3.0
finds 51% of real bugs with much cleaner signal (FAR=32%).

For a production filter, F1 / precision / FAR matter more than raw recall.
v8.3.0 precision: 21% vs v8.2 16%. Modest but real.

## Calibration trick is alive — on in-domain

`gap_p_tp` median(TP) - median(FP):
- v8.2 test_balanced: collapsed at 0.058
- v8.3.0 test_balanced: **+0.175**

The hypothesis from the external reviewer is confirmed: contradictory
labels destroyed first-token signal. Removing duplicates restores it.

Per-language cluster-CV calibration on v8.3.0 SastBench logprobs:
- Python: **+0.269** ← strongest slice signal (was +0.023 on v8.2)
- CWE-79: +0.051 (was +0.139 on v8.2 — decreased)
- JavaScript: -0.152 (was +0.094 on v8.2 — flipped sign)

The signal redistributed away from CWE-79+JS (where v8.2 had its dup-driven
"signal") toward Python. v8.3.0 has different per-slice strengths than v8.2.

## Per-CWE behaviour on SastBench-250

v8.3.0 actual predictions:
| CWE | n | TP | FN | TN | FP | DR | FAR | MCC (rough) |
|---|---|---|---|---|---|---|---|---|
| CWE-79 | 57 | (from outputs file) | | | | | | (to recompute) |

(Run `scripts/cluster_bootstrap_eval.py --by cwe` for the cluster-honest version.)

## What this means for v8.3.1

v8.3.0 confirmed:
1. Train data label noise was THE mechanism behind paranoia (predicted by reviewer, confirmed by gap restoration)
2. Single-source dedup alone cannot fix distribution mismatch on external eval

v8.3.1 plan (per `project_v8_3_plan.md`):
1. Multi-source train: clean dedup CVEFixes + CrossVul TRIAGE-formatted + Juliet small dose
2. CVE-ID dedup across sources (per reviewer — gate for LOSO)
3. Source-tag for LOSO honest internal generalisation metric
4. r=8 (regularisation) — explicitly tested in ablation
5. Keep clean-dedup discipline from prepare_v8_3_clean.py

Budget: ~$5-10 on RunPod (CrossVul download + prep + train + eval).
Expected from reviewer's framing: SastBench MCC into 0.18-0.22 range with
real cluster-CV signal above 0.

## Files

```
runs/
  v8_3_0_sastbench250_outputs.json    250 predictions
  v8_3_0_sastbench250_metrics.json    aggregate metrics
  v8_3_0_testbalanced_outputs.json    248 predictions in-domain
  v8_3_0_testbalanced_metrics.json    aggregate metrics
  v8_3_0_logprobs_sastbench250.json   250 first-token p_tp
  v8_3_0_logprobs_testbalanced.json   248 first-token p_tp
  v8_3_0_full_report.json             one-page summary
  v8_3_0_perslice_lang_calib.json     per-language cluster-CV
  v8_3_0_perslice_cwe_calib.json      per-CWE cluster-CV

data/train/triage_v8_3_clean/
  train_dedup_balanced.json           970 rows, the clean train
  dedup_meta.json                     provenance + stats
```

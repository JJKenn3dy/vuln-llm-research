# v8.3.1_r8 — LoRA rank ablation result

Adapter: trained 2026-06-11 ~14:35-16:35 UTC on temp RunPod A40 (network
volume `ory6yz6p35`). Same train data and hyperparameters as v8.3.1, only
`--lora-r 8 --lora-alpha 16` (instead of r=16/alpha=32). Mechanically a
single isolated factor: half the trainable parameters.

Run script: `scripts/train_v8_3_1_r8.sh` (lives only on temp pod, not
committed to repo since v8.3.1_r8 is a research artefact, not a production
candidate).

## Epistemic status (reviewer correction)

**N=1 run, single seed.** Δ=−0.120 SastBench MCC is **not a point estimate
to cite as precise**. Cluster bootstrap CIs by `repo_url`:
- v8.3.1 (r=16): [+0.00, +0.30] (from docs/RESULTS_v8_3_1.md)
- v8.3.1_r8: estimated [−0.08, +0.20] (overlaps heavily with r=16)

What is robust:
- **Direction of effect**: r=8 < r=16 on this distribution
- **FAR shift of +17 pp**: large behavioural change, very unlikely noise
- **Paranoia returns** at r=8: FAR pattern strongly consistent with
  uncertainty-driven default-to-TP

What is NOT robust:
- The exact magnitude −0.120 on MCC
- Generalisation to other train sizes or other clean datasets
- The mechanism ("undercapacity") — until pre-registered decomposition
  (see [PREREGISTERED_PREDICTION_v8_3_1_r8.md](PREREGISTERED_PREDICTION_v8_3_1_r8.md))
  confirms or refutes it

Status of this doc in FINDINGS / pitch: cite as **"hypothesis with one
confirming run, direction-only"**, not "established mechanism". Full
closure of the 2×2 (clean/dirty × r8/r16) would cost ~$1 more but adds
~$0 product value, so deferred to potential methodology paper section.

## Hypothesis going in

History Lesson 4 (HISTORY.md, from v7lite cycle May 2026):
> Smaller LoRA rank generalized better. r=8 beat r=16 on OOD CrossVul-100
> (BA 0.526 vs 0.46). Classic regularization: less capacity forces the
> model to learn semantics rather than stylistic features.

Reviewer suggestion (NEXT_STEPS P3, this session): on the **clean** v8.3.1
train (2180 dedup'd rows), retry r=8 to see if the regularization
hypothesis still holds.

## Result — Lesson 4 flips on clean data

SastBench-250 (cluster-honest external):

| Metric | v8.3.1 (r=16) | **v8.3.1_r8** | Δ |
|---|---|---|---|
| **MCC** | +0.177 | **+0.057** | **-0.120** |
| BA | 0.612 | 0.541 | -0.071 |
| **FAR** | 23.3% | **40.5%** | **+17.2 pp (paranoia returns)** |
| DR | 45.7% | 48.6% | +2.9 pp |
| Precision | 24.2% | 16.3% | -7.9 pp |
| TP / FN / TN / FP | 16/19/165/50 | 17/18/128/87 | |

test_balanced (in-domain, **final 248/248**):

| Metric | v8.3.1 (r=16) | **v8.3.1_r8** | Δ |
|---|---|---|---|
| MCC | +0.424 | **+0.363** | -0.061 |
| BA | 0.710 | 0.681 | -0.029 |
| **FAR** | 21.8% | **29.8%** | **+8.0 pp** |
| DR | 67.0% | 66.1% | -0.9 pp |
| TP / FN / TN / FP | (not recorded) | 82/42/87/37 | |

Note: in-domain MCC dropped modestly (−0.06) while OOD dropped sharply
(−0.12). Pre-registered R decomposition value R = 0.51 confirms **mixed
mechanism** (both capacity bottleneck and transfer-DoF loss contribute).
See [PREREGISTERED_PREDICTION_v8_3_1_r8.md](PREREGISTERED_PREDICTION_v8_3_1_r8.md)
for the full hypothesis test.

Logprob gap on SastBench (paranoia signature):
- v8.3.1 (r=16): gap = 0.023 (collapsed to begin with)
- v8.3.1_r8: gap = **0.011** (collapsed further)

In-domain logprob gap not extracted in this run (script omission, fix
for future ablations: extract logprobs on both eval sets, not just
SastBench).

## Mechanism — why Lesson 4 has a scope (mixed mechanism per pre-registered R test)

Pre-registered hypothesis test:
- H1 (pure capacity bottleneck) predicted R ≥ 0.7 (in-domain ≈ OOD drop)
- H2 (pure transfer-DoF loss) predicted R ≤ 0.2 (in-domain almost no drop)
- Observed: **R = 0.51** → mixed mechanism

In v7lite (Lesson 4 origin), train data had:
- 4079 pairs with 35% project leakage between train and OOD test
- Documented stylistic shortcut: paranoia (98/100 cases TP)
- Discriminating feature was stylistic (template length, formatting) not
  semantic

Smaller r=8 acted as regularization that prevented memorization of those
stylistic patterns, forcing fallback on whatever semantic signal existed.
Less capacity = less memorization = slightly better OOD (BA 0.46 → 0.53).

In v8.3.1, train data is now:
- 2180 dedup'd rows, no project leakage, no contradictory labels
- Two source mechanisms (CVEFixes + CrossVul) for diversity
- Calibration signal restored (in-domain logprob gap 0.058 → 0.175)

Here r=8 hurts both in-domain AND cross-distribution, but cross-distribution
roughly 2× more. The interpretation that survived the pre-registered test:

- **Both** capacity bottleneck (modest, in-domain MCC −0.06) **and**
  transfer-DoF loss (larger, OOD MCC −0.12) contribute
- It's NOT the case that in-domain task is "easy enough at r=8" (H2 pure
  fail) — there's real in-domain degradation
- It's NOT the case that capacity per se is sole bottleneck (H1 pure fail)
  — the OOD penalty is 2× the in-domain penalty, meaning some of the lost
  degrees of freedom were specifically used for distribution-shift adaptation

The polarity flip of Lesson 4 is a **scope discovery**, not a refutation:
- v7lite era: dirty train + overcapacity at any r → smaller r regularizes
  → win
- v8.3.x era: clean train + multi-source → smaller r starves both
  in-domain capacity (modestly) AND transfer-DoF (more) → loss

The unifying principle (HISTORY.md Lesson 18): regularization heals noisy
supervision and starves clean supervision. The same lever does opposite
things depending on supervision quality.

## Production decision

Keep **r=16** as the production hyperparameter for v8.3.x. The Lesson 4
heuristic ("smaller LoRA generalizes better") is now scoped to dirty-train
regimes only, not general guidance.

NOT recommended to extend the sweep down to r=4 or up to r=32 right now:
- r=4: predicted to be worse on the same logic
- r=32: doubles trainable params to 80M on 2180 rows (ratio 4600:1) — likely
  to over-memorize the clean signal again, risk of returning to v8.2-style
  in-domain overfit

If we get a meaningful train-size bump (5000+ rows) in v8.3.2 via Juliet
or D2A integration, then r=32 sweep makes sense to revisit. Until then r=16
is the production choice.

## Cost

| Item | $ |
|---|---|
| Temp A40 pod (train ~73 min + eval ~50 min + logprob ~25 min ≈ 2.5h) | ~$1.10 |
| Sonnet smoke 10 via OpenRouter (separate budget check, see SESSION_2026-06-11_reviewer_round.md) | ~$0.15 |
| **Total this experiment** | **~$1.25** |

Within Захар's approved budget for r=8 ($0.60 train estimate + $0.50 eval
margin).

## Logprob gap (after final extraction completes)

To be appended once `extract_triage_logprobs` finishes. Predicting:
- If gap collapses on SastBench (< 0.05) → confirms paranoia is back
- If gap stays similar to v8.3.1 (~0.023 SastBench) → r=8 still has signal,
  the calibration wedge is dead for a different reason

## Files

```
/workspace/runs/  (on temp pod, scp'd back after eval completes)
  v8_3_1_r8_sastbench250_outputs.json   250 predictions, ranker-ready
  v8_3_1_r8_sastbench250_metrics.json   aggregate metrics (this doc)
  v8_3_1_r8_testbalanced_outputs.json   248 predictions in-domain
  v8_3_1_r8_testbalanced_metrics.json   aggregate (final pending)
  v8_3_1_r8_logprobs_sastbench250.json  first-token probs for calibration
                                        analysis (final pending)
  v8_3_1_r8_run.log                     train + eval combined log
```

Adapter at `/workspace/adapters/v8_3_1_r8/` (kept for one session for
re-eval if needed; NOT pushed to HF — not a production candidate).

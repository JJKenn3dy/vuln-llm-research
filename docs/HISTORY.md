# Lessons from v5 through v8

Negative results and methodology corrections from the BSc thesis cycle and the
first commercial iteration. Each lesson is load-bearing for the next design.

## Lesson 0: v8 failed because there were no real pre-fix / post-fix pairs in the source data

The single most important lesson from the first session. The v8 training set
was built from v7lite which itself was built from v5b detection data. The "safe"
samples were never the **post-fix versions of the vulnerable samples** — they
were unrelated independent safe code from different CVEs. Only 20 of 707 CVEs
in v5b actually had both vuln and safe representations, and even those were
not paired by file path.

Consequences:
- The triage task collapsed to detection: claimed_cwe always equalled real_cwe,
  the only thing that varied was the code itself.
- Training data presented two visually different distributions (vuln-style code,
  safe-style code) and a clean stylistic difference in the assistant reasoning
  (templated single sentence for FP, rich varied text for TP). The model
  learned the **surface stylistic discriminator**, not the semantic
  pre-fix / post-fix comparison.
- v8 zero-shot eval on triage_100 produced BA=0.510 with a logprob gap of
  0.007 between real TPs and real FPs. No internal signal at all.

**Implication for v8.2**: switch the training data to a source that gives real
differential before/after fix pairs. IBM **D2A** (arxiv 2102.07995) is built
exactly for this. We do not need to manually rebuild from CVEFixes raw.

## Lesson 1: Train loss low does not mean good model

## Lesson 1: Train loss low does not mean good model

In v7lite we ran 3 epochs on 4079 pairs and saw the lowest train loss of the whole project (0.46 vs v5b's 0.56). I read that as "better learned." It was catastrophic memorization. F1 dropped from 0.86 to 0.78 on in-domain, BalAcc collapsed to 0.52 (random) on OOD.

**Implication for v8**: always track val loss during training. Use early stopping. Save intermediate checkpoints (not just last 3) so we can post-hoc analyze.

## Lesson 2: Random split inflates apparent OOD performance by 2x

The biggest finding of the v7lite cycle. CrossVul has `file_pair_id = <project_id>_<file_idx>`. Random split puts different commits of the **same project** into train and test. After diagnosis:

- 30 of 85 test projects (35%) had overlap with train projects in v7lite
- Models that "worked" on CrossVul-100 mostly worked on the overlap subset
- Honest non-overlap (NOV) evaluation showed BalAcc 0.50 (random) for v6b and v5b
- Only v7lite_r8 (lower-rank LoRA) reached BalAcc 0.526 on NOV (the first real OOD signal in the project)

**Implication for v8**: SastBench split must be by `project_id`, not by `commit` or `random`. Any reported metric without that disclosure is misleading.

## Lesson 3: More data did not help

v7lite had 4x more train pairs than v5b (4079 vs 1377), balanced 50/50 vs the original 28/72, with explicit CrossVul augmentation for domain coverage. In-domain F1 went from 0.86 (v5b) **down** to 0.78 (v7lite). On OOD, BalAcc was at the noise floor (0.52).

What this tells us:

1. The 1377-pair v5b dataset was not data-starved on its in-domain task.
2. Adding domain-extension pairs from CrossVul taught the model project-style artifacts, not transferable vulnerability semantics.
3. The bottleneck was **methodology** (split, prompt, single teacher), not **dataset size**.

**Implication for v8**: scale data with discipline. Stratify by project. Use multiple teachers for reasoning. Run scaling experiments only after the methodology baseline is solid.

## Lesson 4: Smaller LoRA rank generalized better

The 7-config sweep over epochs (1-3) and LR showed no effect. The two configs that varied LoRA rank told a different story:

- r=16 (40M trainable): F1 0.78 in-domain, BalAcc 0.46 NOV OOD
- r=8 (20M trainable): F1 0.79 in-domain, BalAcc 0.53 NOV OOD

The smaller adapter won on both axes. This is classic regularization: less capacity forces the model to learn semantics rather than stylistic features.

**Implication for v8**: do not assume "bigger LoRA = better." Sweep r in {4, 8, 16, 24, 32} as part of v8 hyperparameter search. Be skeptical of "scale up" instinct.

## Lesson 5: DeepSeek R1 as teacher did not work

Hypothesized that reasoning-model teachers would give better labels than DeepSeek-Chat-v3. Tested R1 directly as a classifier on CrossVul-100: F1 0.53, BalAcc 0.49 (paranoia, FAR 60%). Tried six prompt-engineering variants. None gave consistent improvement. Cost: $0.77, value: negative.

**Implication for v8**: use **multi-teacher** distillation (GPT-4o + Claude + maybe Qwen-Coder-32B as cross-validation), not a single "smart" reasoner. The benefit of distillation is signal from agreement across teachers, not from any single one being magic.

## Lesson 6: F1 on balanced eval is misleading without BalAcc

Several v7lite configurations hit F1 ≈ 0.67 but with `predicted_label = "vulnerable"` for 98 out of 100 cases. The "balanced 50/50 paranoia mode" gives an automatic F1 ≈ 0.667 (P=0.5, R=1).

**Implication for v8**: always report BalAcc and DR/FAR alongside F1. Reject any config where the model's distribution of predictions does not match the eval distribution within 20%.

## Lesson 7: 100-example eval has ±6% confidence interval

A 95% Wilson interval on 100 binary decisions is roughly ±6 percentage points. Any single F1 number from CVEFixes-100 or CrossVul-100 lives inside that band. We were chasing 0.01 improvements that were statistical noise.

**Implication for v8**: target eval sets of 500-1000 examples for real claims. For sanity checks and iteration speed, 100 is fine — but do not over-interpret single decimals.

## Lesson 8: Save policy matters

`save_total_limit=3` deleted intermediate checkpoints. When v7lite turned out to overfit at 3 epochs, we wanted to evaluate 1.5 and 2 epoch checkpoints — they were gone. Had to re-run a 6-config sweep from scratch, costing extra GPU hours.

**Implication for v8**: keep checkpoints every 0.5 epoch minimum during training. Storage is cheap. Delete after the post-hoc analysis is done, not before.

## Lesson 9: Smoke (no API cost) BEFORE pay (with teacher)

The v8.2 cycle wasted ~$2.30 on two preps where the FP-source logic was wrong:
post-fix and "mixed" both used `fixed_code`, both produced TP/FP length ratio
1.78. Each prep was $1.16, 45 minutes wall-clock, and the shortcut was visible
in 30 seconds of statistical analysis without a single API call.

We later wrote `simulate_misclass.py` — a 50-line script that loads CVEFixes
and computes TP/FP length distributions for various FP-source strategies. It
showed misclass=0.93 ratio vs post-fix=1.78 with zero API spend.

**Implication**: before any prep that uses a teacher LLM, run a zero-cost
sanity check on the structure of the proposed data. If the structure is
broken (length distribution, source overlap, label imbalance) you find it
in seconds, not in 45 minutes.

## Lesson 10: 14B does not solve overfit on small data

User raised mid-session: "shouldn't we upgrade to 14B to fit more examples?"
Wrong intuition. LoRA fine-tuning freezes the base model and trains an
adapter (~40M params for r=16). Going to 14B doesn't change the LoRA capacity.
It does increase the cost and the base-model knowledge, but the bottleneck on
v8.2 is the **ratio** of trainable params to training pairs (22000:1), not
the size of the frozen base.

**Implication**: when overfitting is the failure mode, **smaller LoRA r**
(8 or 4) and **more training data** beat bigger base models. 14B is only
worth it when 7B has clearly plateaued on in-domain quality at scale, which
v5b (F1=0.86) and v8.2 (test_balanced BA=0.82) haven't shown.

## Lesson 11: One shortcut killed → next shortcut appears

After per-pair length matching (TP/FP ratio = 1.03), shortcut MLP F1 went
from 0.69 to 0.85 because the truncation added "// ... truncated for length
normalisation" as a marker that 75% of FP examples got and only 11% of TP
got. We had unwittingly invented a new feature.

**Implication**: shortcut elimination is iterative. After every distribution
fix, re-run shortcut_check. Any marker, header, EOF token, or padding added
to one class becomes a learnable feature.

## Lesson 12: Distribution of FP types matters more than total FP count

v8.2 on test_balanced (mixed 80% misclass + 20% post-fix): BA 0.82.
v8.2 on fresh_cves_60 (100% post-fix): BA 0.47.
v8.2 on SastBench-250 (mostly Semgrep pattern-mismatches): MCC 0.10.

The model learned the dominant FP type and failed when given a different one.
A model that scores 0.82 on one FP distribution and 0.47 on another isn't a
0.65-average model — it is two separate classifiers with the same name.

**Implication for v8.3**: train on a deliberately mixed FP distribution that
matches the *operational* mix the model will see. 50% post-fix + 50% misclass
is a safer prior. Better: source FPs from multiple SAST tools (Semgrep,
CodeQL, Bandit) to capture different "scanner mistakes".

## Lesson 13: Internal benchmarks have home advantage — external is the real test

v8.2 looked great on test_balanced (BA 0.82 vs frontier 0.50-0.61) but matched
Sonnet 4.5 on SastBench (MCC 0.10 vs 0.11). The first number is too optimistic
for pitch decks — it measures how well we fit our own data. The second number
is the real product-market signal.

**Implication for v8.X going forward**: any time we report headline numbers,
attach the external SastBench MCC alongside. If the gap between in-domain
and SastBench is more than ~0.15 BA, we're overfitting and the pitch is
fragile.

## Lesson 14: Calibration trick requires logprob signal — gap < 0.10 means it's dead

v8.2 SastBench median(p_tp|TP) - median(p_tp|FP) = 0.058 (val) and 0.027 (test).
Threshold sweep on val gave MCC=0.151, but transfer to test produced MCC=-0.010
(catastrophic). The wedge-of-three-policies claim from v5b ($threshold 0.40
lifts F1 0.78→0.86) had hidden prerequisite: p_tp distribution actually
separable.

**Implication**: ALWAYS print median TP gap before running any threshold
sweep. Below 0.10, sweep is fitting val noise — don't waste compute on it.

## Lesson 15: 64% of v8.2 train was duplicate code with conflicting verdicts

Audit 2026-06-11: 1794 train rows mapped to 1007 unique code SHAs. 35% of
unique codes appeared with BOTH TP and FP labels (across different claimed
CWEs). Top duplicate code appeared 20 times in train: 17 FP + 3 TP across
8 CWEs.

Root cause: `prepare_cvefixes_triage.py` misclassification FP strategy reused
`fixed_code` from other CVE rows as FP source. Same code could be:
- TP from its own CVE row
- FP-misclass for CWE-89 from another row
- FP-misclass for CWE-22 from a third row
...

**Mechanistic prediction (per reviewer 2026-06-11)**: Contradictory supervision
on identical input means gradient cancels. Model collapses to majority class
frequency — paranoia AND logprob gap collapse follow from the same cause.
v8.2's calibration "didn't work externally" because it didn't exist anywhere.

**Fix**: `scripts/prepare_v8_3_clean.py` produces 970 unique-code 50/50 balanced
rows. v8.3.0 isolates the effect.

## Lesson 16: Honest CI must use cluster bootstrap on clustered eval data

SastBench-250 has WeGIA = 30% of cases. Case-level bootstrap treats cases as
IID and underestimates variance because within-project cases are correlated
(same coder, same patterns, same Semgrep ruleset hits). Cluster bootstrap by
repo_url on v8.2 overall: case CI [-0.01, +0.19], cluster CI [-0.04, +0.19].
Per-language differences larger: PHP +0.10 case → cluster CI [-0.10, +0.33].

Per-slice k-fold cluster-CV on v8.2 SastBench logprobs: overall calibrated
MCC drops from default-thr +0.079 to **cluster-CV mean -0.011**. v8.2 had
no real signal after honest calibration — the +0.10 headline was project-
clustering artifact.

**Implication**: All future eval reports use cluster bootstrap CI by repo_url.
Threshold sweeps via cluster-CV honest (`scripts/per_slice_calibration.py`).
Headline pitch numbers from cluster-CV calibrated MCC, not naive defaults.

## Lesson 17: Per-language inversion is a real wedge, but smaller than oracle

Per-language MCC on v8.2 SastBench-250 has slices with MCC<0 (Python -0.07,
TypeScript -0.12, Ruby -1.0). Oracle ceiling: flip those slices, MCC jumps
overall from +0.10 to +0.20.

5-fold honest CV (pick flip set on 4 folds, apply on 5th) gives Δ MCC = +0.014.
~7× smaller than oracle. Ruby flipped in 4/5 folds (consistent), Python in
3/5, TS in 2/5.

**Implication**: Per-slice calibration is a real free win but modest. Cannot
be the headline pitch driver. Apply as final eval step.

## Lesson 18: LoRA capacity is regime-dependent — Lesson 4 has a scope

Lesson 4 from v7lite (May 2026) said: r=8 generalizes better than r=16
because less capacity = less stylistic overfit. That conclusion was correct
**for v7lite's regime**: 4079 pairs with 35% project leak, paranoia mode,
visible surface-stylistic shortcut. Regularization (smaller r) reduced
memorization of those shortcuts and the model fell back on weaker but
real semantic signal. Honest OOD BA 0.46 → 0.53.

v8.3.1_r8 ablation (this session, 2026-06-11) measured the same lever on
a different regime — clean dedup'd train (2180 rows, no contradictory
labels, two source mechanisms):
- SastBench MCC: +0.177 (r=16) → +0.057 (r=8) — direction-only, N=1
- SastBench FAR: 23.3% → **40.5%** (paranoia returns)
- test_balanced MCC: +0.424 → +0.363 (in-domain hit too, modest)
- test_balanced FAR: 21.8% → 29.8% (paranoia in-domain too)
- SastBench logprob gap collapsed: 0.023 → 0.011

Pre-registered R decomposition (PREREGISTERED_PREDICTION_v8_3_1_r8.md):
R = ΔMCC_ID / ΔMCC_OOD = −0.061 / −0.120 = **0.51** → mixed mechanism.

**Unified principle**: regularization heals noisy supervision and starves
clean supervision. With clean train, smaller r hurts both in-domain AND
cross-distribution, but cross-distribution roughly 2× harder. The
mechanism is NOT pure capacity-bottleneck-on-task (in-domain MCC drop
is modest, −0.06). Dominant effect is loss of the specific degrees of
freedom the model used for distribution-shift adaptation. Both
contribute; not mutually exclusive.

This is **scope/conditions discovery**, not Lesson 4 refutation. Lesson 4
remains valid in its regime; Lesson 18 names the regime boundary. See
`docs/PREREGISTERED_PREDICTION_v8_3_1_r8.md` for the pre-committed
decomposition test that distinguishes (a) "r=8 starves capacity for the
task itself" from (b) "r=8 starves capacity specifically for distribution-
shift adaptation, in-domain task is fine".

**Operational rule**: capacity choice is **re-opened every time train
size doubles**. We carried r=16 forward from v8.2 by inertia and were
lucky it stayed correct on v8.3.x; future train bumps (v8.3.2 Juliet, D2A,
Semgrep-pipeline → 5-8k rows) make r=32 a legitimate candidate. One cheap
ablation per train-doubling event = sufficient discipline.

Don't sweep r=4 or r=32 right now — current ratio (2180 rows / 40M trainable
= 18000:1) is in known-working territory for r=16. Sweep when train doubles.

See `docs/RESULTS_v8_3_1_r8.md` for the ablation numbers and epistemic
caveats (N=1, CIs overlap, direction-only).

## Lesson 19: Paranoia is an uncertainty signature, not a task property

Three independent experiments now point at the same mechanism: when the
model does not know, it defaults to TRUE_POSITIVE.

| Setup | Cause of "not knowing" | FAR symptom |
|---|---|---|
| v8.2 (dirty train, 64% dup rows with conflicting labels) | gradient cancels on identical inputs → model learns the marginal frequency | **77%** |
| v8.3.1_r8 (clean train, undercapacity for cross-source signal) | capacity bottleneck | **41%** |
| Frontier single-call Sonnet 4.5 / Gemini 2.5 (no fine-tune, no in-context examples) | task-format unfamiliarity | **80%+** in smoke |

This is **not "the triage task makes models paranoid"**. It is "model
sees code, has no internal handle for FP, picks the more salient class".
Different causes of low signal, same surface behaviour.

**Operational implication**: anti-paranoia interventions are uncertainty
interventions. Four levers we now know about:

1. **Calibration sweep** (explicit threshold over confidence) — works only
   when median(p_tp|TP) − median(p_tp|FP) ≥ ~0.10 (Lesson 14)
2. **Multi-source train diversity** (cover distribution shift) — Lesson 18,
   diversity-as-structural-cure memory
3. **Capacity matched to train size** (under-fit AND over-fit both create
   paranoia) — this lesson
4. **ReAct / multi-turn for frontier** (explicitly gather signal before
   verdict) — paper finding

For the methodology paper section: one principle, four actionable levers.

## Lesson 20: Self-judging is hopeless; tri-judge adjudication with pre-commit rule converts a soft claim into a defensible one

When AI annotated 50 hand-label cases on snippet only (2026-06-11 night),
56% raw agreement with SastBench. HIGH-confidence band agreement was 37.5%,
**lower than MEDIUM (72%)** — inverted calibration. Two compatible
explanations:

1. Where I'm confident, SastBench is wrong (flattering)
2. Where I'm confident, I'm systematically wrong (unflattering)

Cannot distinguish by self-assessment. Захар's correction was the lever:
adjudicate the 10 HIGH-confidence contested cases via independent
frontier judges (Sonnet 4.5 + Gemini 2.5 Pro) on the SAME cases, with
**pre-committed decision rule** locked before frontier outputs landed:
- all 3 judges disagree with SB → strong_mislabel
- only AI disagrees, both frontier agree with SB → likely_ai_error
- mixed → ambiguous

Result on the 10 cases:
- 7 strong_mislabel (defensible benchmark errors)
- 2 likely_ai_error (AI was wrong; mechanism: missed `echo $e->getMessage()`
  reflection in PHP error paths)
- 1 ambiguous

**Lesson**: a single annotator (human or AI) cannot defensibly claim
"benchmark is wrong" against their own disagreement count — that's the
oracle-leak structural error applied to label trust. Adjudication via
independent judges with **pre-committed interpretation rule** converts the
self-judging confound into a reproducible result.

**Operational rule**: any time you find yourself disagreeing with a
benchmark label, route the case through ≥2 independent judges with a
pre-committed rule. Cheap ($0.25 for 10 cases via OpenRouter on Sonnet +
Gemini at 2026 prices). Cuts confirmation bias to nearly zero.

Related: `feedback_no_oracle_leak_in_calibration.md`,
`feedback_no_apples_to_oranges_frontier_compare.md` — same family of
anti-patterns ("the judge is also the defendant").

## Lessons format note (going forward)

Every lesson lives with two implicit fields whether we write them or not:
- **Scope/conditions**: the regime in which the claim holds
- **Operational rule**: what to do because of the claim

When the regime changes, the lesson does not become wrong — it becomes
scoped. Add a sibling lesson naming the new regime instead of retracting.
Lesson 4 + Lesson 18 is the worked example.

## Summary table

| # | Lesson | v8 design impact |
|---|---|---|
| 1 | Low train loss ≠ good model | Track val loss, early stopping |
| 2 | Random split inflates OOD 2x | Project-stratified split mandatory |
| 3 | More data did not help | Methodology > data scaling |
| 4 | Smaller LoRA generalized — **scope**: dirty/noisy supervision regime (v7lite era) | Apply when train has known label noise or shortcuts; otherwise see Lesson 18 |
| 5 | Reasoner teacher did not work | Multi-teacher distillation |
| 6 | F1 alone is misleading on balanced eval | Always report BalAcc and prediction distribution |
| 7 | 100-example eval has wide CI | Aim for 500-1000 for real claims |
| 8 | Aggressive checkpoint pruning hurts later analysis | Keep intermediate checkpoints |
| 9 | Free sanity-check beats paid teacher run | Statistical simulation before any API spend |
| 10 | 14B does not solve overfit on 1.8k pairs | Lower LoRA r + more data, not bigger base |
| 11 | Shortcut elimination is iterative | Re-run shortcut_check after any fix |
| 12 | FP distribution mix matters more than total FP count | 50/50 post-fix + misclass baseline |
| 13 | Internal benchmark has home advantage | Always attach SastBench MCC to headline |
| 14 | Calibration requires gap ≥ 0.10 in p_tp | Print gap before sweeping |
| 15 | Misclass FP strategy creates duplicates | Strict (code, verdict) uniqueness in prep |
| 16 | Cluster bootstrap mandatory for clustered eval | Per-repo CI for all SastBench claims |
| 17 | Per-language flip is real but small | Apply via CV, not oracle, as final eval step |
| 18 | LoRA capacity is regime-dependent — Lesson 4 has a scope; smaller r heals noisy train, starves clean train | Re-open r choice every time train doubles; one cheap ablation per event; keep r=16 for v8.3.x |
| 19 | Paranoia (default-to-TP) is an uncertainty signature, not a task property | Anti-paranoia = uncertainty intervention: calibration, multi-source, capacity match, ReAct for frontier |
| 20 | Self-judging label disagreements is structurally hopeless | Adjudicate via ≥2 independent judges with pre-committed rule; converts soft claim into defensible result |

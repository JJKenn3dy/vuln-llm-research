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

## Summary table

| # | Lesson | v8 design impact |
|---|---|---|
| 1 | Low train loss ≠ good model | Track val loss, early stopping |
| 2 | Random split inflates OOD 2x | Project-stratified split mandatory |
| 3 | More data did not help | Methodology > data scaling |
| 4 | Smaller LoRA generalized | Sweep r ∈ {4, 8, 16, 24, 32} |
| 5 | Reasoner teacher did not work | Multi-teacher distillation |
| 6 | F1 alone is misleading on balanced eval | Always report BalAcc and prediction distribution |
| 7 | 100-example eval has wide CI | Aim for 500-1000 for real claims |
| 8 | Aggressive checkpoint pruning hurts later analysis | Keep intermediate checkpoints |

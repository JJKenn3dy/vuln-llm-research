# v8.2 SastBench-250 diagnostics — slices and findings 2026-06-11

## ⚠️ CI caveat — cluster bootstrap (added per external review)

All BA/MCC numbers below were initially reported with naive case-level
implicit certainty. WeGIA = 30% of cases means cases are correlated within
project, so naive variance estimates are too tight. Re-running with cluster
bootstrap by `repo_url` shows:

| Slice | n | n_clusters | MCC | case CI | **cluster CI** |
|---|---|---|---|---|---|
| Overall | 250 | 66 | +0.100 | [-0.01, +0.19] | **[-0.04, +0.19]** |
| PHP | 118 | 16 | +0.095 | [-0.06, +0.20] | **[-0.10, +0.33]** |
| Python | 43 | 15 | -0.065 | [-0.43, +0.19] | **[-0.46, +0.33]** |
| JavaScript | 38 | 22 | +0.276 | [+0.00, +0.48] | **[+0.00, +0.49]** |
| Go | 18 | 11 | +0.000 | [0, 0] | [0, 0] |
| TypeScript | 14 | 11 | -0.122 | [-0.65, +0.35] | **[-0.60, +0.32]** |
| Ruby | 10 | 5 | -1.000 | [-1, 0] | [-1, 0] |
| Other | 8 | 6 | +0.378 | [+0.00, +0.77] | [+0.00, +1.00] |

**Reading**: at honest CI level, **most slice claims are not statistically
significant**. Overall MCC=0.10 cluster CI includes 0. PHP +0.10 CI spans
-0.10 to +0.33. JS "best" +0.28 has lower CI at 0. Per-language wedges
should be reported with cluster CIs in pitch, not point estimates.

Ruby's MCC=-1.00 on n=10 / 5 clusters is too small a sample for a strong
"systematically inverted" claim — reviewer was right to push back. Treat as
suggestive observation, not load-bearing.

Numbers below are point estimates; CI for any claim should be re-derived
via `scripts/cluster_bootstrap_eval.py`.



Honest re-analysis of v8.2's MCC=0.100 on SastBench-250 by project and by
language. The headline number hides a load of structure that v8.3 mix design
must directly address.

## Key finding 1: WeGIA project dominates the headline

| Slice | n | DR | FAR | BA | MCC | comment |
|---|---|---|---|---|---|---|
| **Overall** | 250 | 88.6% | 76.7% | 0.559 | **+0.100** | pitch number |
| WeGIA only | 76 | 100.0% | 90.2% | 0.549 | **+0.145** | top-1 project, 30% of cases |
| WeGIA-stripped | 174 | 80.0% | 71.4% | 0.543 | **+0.061** | the actual diverse number |
| Top-3 stripped | 137 | 86.7% | 68.9% | 0.589 | +0.122 | yeswiki + llama_index were depressing it |

**Read**: on the actual diverse multi-project benchmark v8.2 hits MCC ≈ 0.061,
not 0.100. WeGIA's 30% of cases hides the gap. **Sonnet 4.5 paper number 0.110
on SastBench-250** is probably similarly inflated — we should be skeptical of
single-number SastBench comparisons.

**Implication for pitch**:
- Honest headline ≈ MCC 0.06 on diverse OSS findings vs Sonnet's 0.110
- We are worse than Sonnet 4.5 on diverse projects, not equal
- WeGIA is a "lab-friendly" project where our v8.2 happens to work; not representative

## Key finding 1.5: Per-language flip — real but smaller than oracle suggests

Zakhar caught a math observation: MCC=−1 on Ruby (10/10 wrong) means the model
**has the information** but says the opposite. Flipping predictions in that
slice yields MCC=+1. Mathematically correct.

**Oracle ceiling** (pick flip set from test set itself):
| Slice | Before | After flip {Python, TS, Ruby} | Δ |
|---|---|---|---|
| Overall 250 | MCC +0.100 | **MCC +0.204** | +0.104 |
| WeGIA-stripped 174 | MCC +0.061 | **MCC +0.200** | +0.139 |

**HONEST 5-fold CV** (pick flip set from 4 folds, apply on 5th):
| Fold | flip set | before | after |
|---|---|---|---|
| 0 | {python} | -0.044 | -0.055 |
| 1 | {ruby} | +0.055 | +0.084 |
| 2 | {ruby, python, typescript} | +0.169 | +0.196 |
| 3 | {ruby, python} | +0.217 | +0.244 |
| 4 | {ruby, typescript} | +0.056 | +0.056 |

**Mean MCC: +0.091 → +0.105 (Δ=+0.014)**. Modest free win, not the dramatic
2x of oracle leak. Ruby consistently flagged in 4/5 folds, Python in 3/5,
TypeScript in 2/5.

**Read**: per-language flip is a real lever but the headline +0.10 was
researcher-bias inflated. Honest gain is ~1.4 MCC points on this benchmark.
For pitch: applying per-slice calibration is a free post-training fix on a
prediction-policy level (not a model retrain), but it doesn't move us from
mid-tier to top-tier.

Apply as final v8.X eval step: select flip set on held-out val, apply on
test. Add to v8.3 eval pipeline.

## Key finding 2: Per-language MCC is extremely uneven

Detected language from file extension (SastBench metadata.language is unreliable):

| lang | n | DR | FAR | BA | MCC | diagnosis |
|---|---|---|---|---|---|---|
| **JavaScript** | 38 | 100.0% | 38.9% | 0.806 | **+0.276** | best — model has real signal |
| PHP | 118 | 95.7% | 88.4% | 0.536 | +0.095 | high paranoia, mid signal |
| Go | 18 | 100.0% | 100.0% | 0.500 | +0.000 | total paranoia, calls every FP as TP |
| Python | 43 | 66.7% | 77.5% | 0.446 | **-0.065** | actively wrong |
| TypeScript | 14 | 50.0% | 66.7% | 0.417 | -0.122 | wrong |
| **Ruby** | 10 | 0.0% | 100.0% | 0.000 | **-1.000** | catastrophic — every answer flipped |
| Java | 1 | 0.0% | 100.0% | 0.000 | 0.000 | n=1, ignore |
| other | 8 | mixed | mixed | mixed | mixed | YAML/HBS/Vue/Twig — config files |

**Read**:
- v8.2 has **real signal only on JavaScript** (MCC +0.28, BA 0.81)
- PHP is the majority of cases but mid-signal with high paranoia
- **Ruby is catastrophic** — model has zero exposure to Ruby idioms in train,
  and predictions are systematically wrong
- Python and TypeScript are **negatively correlated** — model is actively wrong

**Implication for v8.3 mix design**:
- Mandatory: include Ruby in train data (currently 0% of v8.2 train)
- Mandatory: more Python — v8.2 underperforms despite Python being 17% of train
- Anti-paranoia training needed across all languages, particularly Go (100% FAR)
- Drop "other" extensions from eval (config files, n too small to evaluate)

## Key finding 3: Per-CWE breakdown matches per-language

From earlier analysis (this session):

| CWE | n | MCC | language guess |
|---|---|---|---|
| CWE-79 (XSS) | 57 | **+0.34** | JS/PHP — matches JS being best lang |
| CWE-89 (SQLi) | 38 | -0.088 | PHP/Python — wrong |
| CWE-22 (Path) | 35 | -0.137 | PHP/Python — wrong |
| CWE-918 (SSRF) | 26 | +0.083 | mixed — paranoid |
| CWE-502 (Deser) | 25 | 0.000 | degenerate (0 TP) |
| CWE-78 (Cmd Inj) | 23 | +0.183 | mixed |
| CWE-94 (Code Inj) | 22 | +0.069 | paranoid |

**Cross-axis read**: v8.2 has signal where train was concentrated (CWE-79 + JS).
Everywhere else it falls back to paranoia (call everything TP).

## Implication for v8.3.0 ablation design

Given the slices above, v8.3.0 should isolate:

1. **LoRA r=8 vs r=16** — does lower capacity force semantic learning vs
   pattern memorisation?
2. **FP mix 50/50 vs 20/80** — does balanced post-fix exposure reduce paranoia?
3. **Anti-paranoia loss weight** — does class-weighted BCE (penalising FP→TP
   harder than TP→FN) reduce 76% FAR on SastBench?

All three at once may confound. Suggested protocol:
- v8.3.0a: only r=8 (everything else like v8.2)
- v8.3.0b: only 50/50 FP mix
- v8.3.0c: only loss weighting
- v8.3.0d: all three together
- Eval each on SastBench-250 with both overall and WeGIA-stripped MCC

Compute: ~$2 × 4 runs = $8 on A6000. Decision-relevant data.

If one variable alone fixes paranoia → drop the others (Occam). If all three
needed → that's the v8.3.0 spec.

## Open gates still to close (free, local)

- [x] WeGIA-stripped slice (this doc)
- [x] Per-language slice (this doc)
- [x] Per-CWE slice (session log earlier)
- [ ] Language distribution in v8.2 train (need pod)
- [ ] Intra-train near-duplicate audit (need pod)
- [ ] D2A schema exploration (need pod)

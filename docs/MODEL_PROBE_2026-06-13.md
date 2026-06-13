# Model probe on gold-core — calibration, ranker comparison, failure modes (2026-06-13)

n=71 gold-core (human==GPT-5.3 blind), 22 TP / 49 FP (base rate 31%).
Script: [scripts/model_probe.py](../scripts/model_probe.py),
data: [runs/model_probe_goldcore.json](../runs/model_probe_goldcore.json).
All $0, on-disk. Caveat: n=71, skews to unambiguous cases, internal compass.

## Circularity flag (important)

GPT-5.3 and human **define** the gold label (gold = where they agree). On
this set they grade their own answer key → GPT-5.3 AUC=1.000 is an artifact,
NOT a result. Excluded from the ranker comparison. Only Sonnet, Gemini, and
v8.3.1 are independent of the gold definition and comparable here.

## 1. Calibration: signal is real but compressed and shifted

| p_tp bin | n | mean p_tp | actual TP% |
|---|---:|---:|---:|
| [0.2,0.4) | 5 | 0.353 | 0% |
| [0.4,0.6) | 49 | 0.510 | 22% |
| [0.6,0.8) | 17 | 0.655 | 65% |

- Ordering is **monotonic** (0% → 22% → 65%): the signal is genuine, not noise.
- But **ECE = 0.224** (materially miscalibrated) and the band is narrow
  [0.294, 0.736]. The model crushes 49/71 cases into [0.4,0.6] and calls
  them ~0.51 when only 22% are TP. Model's "0.5" really means "~base rate".
- **This is fixable miscalibration, not absent signal.** A post-hoc
  recalibration (temperature / Platt) fit on a held-out val (NOT this set,
  NOT this n) could spread the band and move the operating point. This is
  the cheap improvement lead, separate from data cleaning.

## 2. Ranker comparison — the real product argument

| Ranker | AUC | distinct scores |
|---|---:|---:|
| v8.3.1 p_tp (continuous) | **0.749** | 54 / 71 |
| Gemini (verdict+conf) | 0.743 | 2 / 71 |
| Sonnet (verdict+conf) | 0.722 | 2 / 71 |

| precision@K | K=5 | K=10 | K=15 | K=20 |
|---|---:|---:|---:|---:|
| v8.3.1 | 60% | **80%** | 73% | 60% |
| Sonnet | 40% | 30% | 40% | 50% |
| Gemini | 40% | 30% | 40% | 50% |
| (random) | 31% | 31% | 31% | 31% |

**On AUC we roughly tie frontier (~0.74).** But AUC gives ties 0.5 credit,
which flatters frontier. The decisive number is precision@K: frontier
single-call collapses to **2 effective score levels** (verdict TP/FP, with
confidence near-constant), so "show me the top 15" is a coin-flip inside its
huge TP bucket. We produce 54 distinct levels → precision@10 of 80% vs 30%.

**This is the structural product argument and it does not depend on a fragile
metric:** a single-call frontier reasoner cannot rank. It emits a verdict.
Our specialist emits a calibrated-enough continuous score. For a "triage
the top-K of 800 alerts" product, that is the whole game.

## 3. Failure modes — and a threshold reconciliation

At p_tp >= 0.5: misses 4/22 TP (18%), false-alarms 29/49 FP (**59%**).
Looks FP-heavy. But the verdict-based FAR on the same model is 18.4%
(GOLD_CORE doc). **The two disagree because 0.5 is the wrong threshold for
p_tp** — the model's text verdict applies an implicitly higher bar. This
also explains the OSS reports' narrow high band (median p_tp ~0.6, 90% > 0.5):
the mass sits above 0.5 but the real discrimination point is ~0.6.

Operational consequence: **do not threshold p_tp at 0.5.** Either use the
verdict, or calibrate the threshold (~0.6) on val. Reinforces finding 1.

FP concentration by CWE: CWE-79 (9), CWE-94 (7), CWE-89 (5), CWE-22 (4).
Broad over-flagging, not one bad CWE. FN tiny and spread (PHP 3, Python 1).

## 4. Calibration headroom — tested, and it is a NEGATIVE result

Ran honest val-fit calibration ([scripts/calibrate_probe.py](../scripts/calibrate_probe.py),
[runs/calibrate_probe.json](../runs/calibrate_probe.json)): Platt scaling fit
on test_balanced VAL (n=248, clean balanced), applied fixed to gold-core.

| metric | raw p_tp | calibrated |
|---|---:|---:|
| ECE | 0.224 | 0.206 |
| AUC | 0.749 | 0.749 |
| precision@10 | 80% | 80% |
| p_tp range | [0.29,0.74] | [0.13,0.86] |

Two things settled:

1. **Ranking is invariant under recalibration — confirmed on data, not
   asserted.** Platt/temperature are monotonic, so AUC and precision@K do
   not move. My earlier claim that recalibration could "improve precision@K"
   was wrong. **There is no quick ranking headroom in calibration.** The
   ranking ceiling for this checkpoint is AUC ~0.75; raising it needs a
   better model (v8.4), not post-hoc tricks.

2. **The calibration that does exist does not transfer.** ECE barely moved
   (0.224 → 0.206) and the val-fit threshold made the gold-core operating
   point *worse* (FAR 59% → 67%), because test_balanced (in-domain, 50/50)
   has a different base rate and threshold than SastBench (31% TP). The
   miscalibration is distribution-shift, not a global scale we can fix from
   in-domain data.

### The actually-useful synthesis: two heads, two jobs

The model probe found verdict-FAR 18% but p_tp@0.5 FAR 59% on the same cases.
Reconciled: the **first-token p_tp** and the **generated verdict** are
different signals.
- **Ranking** → use first-token p_tp (AUC 0.75, continuous, good order).
- **Binary keep/drop** → use the generated verdict (FAR 18%, conservative).
- **Do NOT** threshold p_tp at a fixed value — worse than the verdict and
  does not transfer across distributions.

## Bottom line

- We do NOT beat frontier on accuracy (AUC tie ~0.74). The "win" is
  operating-point + cost + **ranking ability** (frontier can't rank
  single-call) + a conservative verdict head for binary decisions.
- Quick calibration win is **closed (negative)**. The only real model-quality
  lever left is the blind data-clean → v8.4. Effort should go there, not to
  more calibration tricks (consistent with the long-standing "calibration
  trick dead when gap small" lesson).
- Discipline notes that fired this session: the GPT-5.3 circularity trap was
  inside this very probe (any judge that defined the eval set cannot be
  scored on it); and a math claim ("recalibration improves ranking") was
  caught and corrected by running it instead of trusting it.

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

## Bottom line

- We do NOT beat frontier on accuracy (AUC tie ~0.74). The earlier "win"
  is operating-point + cost, now joined by **ranking ability** (frontier
  structurally can't rank single-call).
- Two cheap, independent improvement leads for v8.x: (a) post-hoc p_tp
  recalibration on val (band is compressed, signal monotonic), (b) the
  blind data-clean → v8.4. They stack; neither needs the other.
- Discipline note: the GPT-5.3 circularity trap was inside this very probe.
  Any "judge" that helped define the eval set cannot be scored on it.

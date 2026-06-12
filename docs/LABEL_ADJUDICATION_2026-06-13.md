# SastBench-250 label adjudication + signal decomposition (2026-06-13)

## Context

After v8.3.2 reasoning-fix experiment regressed verdict accuracy on SastBench,
Zakhar identified the v8.3.x training data as the upstream problem ("на хуйне
учился"): 100% of TP rows had hallucinated NVD-style boilerplate, and the
ground-truth verdicts themselves are noisy (CVEFixes labels copied verbatim).

Before deciding teacher choice / Path B vs C vs D / what numbers go into
outreach, the prerequisite is **"is there signal in clean labels at all?"**.

Cost: $0. All inputs already on disk.

## Inputs (already on disk, no new compute)

- `runs/v8_3_1_sastbench250_outputs.json` — 250 v8.3.1 verdicts
- `runs/v8_3_2/v8_3_2_sastbench250_outputs.json` — 250 v8.3.2 verdicts
- `runs/frontier_v8_3_1/sonnet_triage_outputs.json` — 250 Sonnet 4.5 single-call
- `runs/frontier_v8_3_1/gemini_triage_outputs.json` — 250 Gemini 2.5 Pro single-call
- SastBench-shipped labels (in `true_verdict` field on each row)

## Methodology

Apply the same pre-commit rule used on 10 hand-label contested cases (11.06):

* `SB == Sonnet == Gemini` → **clean_consistent** (3-judge consensus)
* `Sonnet == Gemini != SB` → **strong_mislabel** (both frontiers contradict SB)
* mixed → **one_frontier_dissent**

Then compute v8.3.1, v8.3.2, Sonnet, Gemini MCC per bucket against two truth
definitions:
1. SastBench labels (current benchmark)
2. Majority of {SB, Sonnet, Gemini}

Reasoning, methodology cost: 0. Script:
[scripts/sastbench250_label_adjudication.py](../scripts/sastbench250_label_adjudication.py).

## Raw numbers

239 / 250 cases with no parse-fail on any of {v8.3.1, v8.3.2, Sonnet, Gemini}.

| Bucket | N | share |
|---|---:|---:|
| strong_mislabel | 121 | 50.6% |
| clean_consistent | 75 | 31.4% |
| one_frontier_dissent | 43 | 18.0% |

### MCC by bucket vs SastBench label

| Bucket | N | v8.3.1 | v8.3.2 | Sonnet | Gemini |
|---|---:|---:|---:|---:|---:|
| clean_consistent | 75 | +0.475 | +0.251 | +1.000 | +1.000 |
| strong_mislabel | 121 | +0.067 | −0.308 | −1.000 | −1.000 |
| one_frontier_dissent | 43 | +0.003 | −0.133 | −0.098 | +0.098 |
| **ALL** | 239 | **+0.178** | −0.123 | +0.005 | +0.043 |

### MCC by bucket vs majority-of-three

| Bucket | N | v8.3.1 | v8.3.2 | Sonnet | Gemini |
|---|---:|---:|---:|---:|---:|
| clean_consistent | 75 | +0.475 | +0.251 | +1.000 | +1.000 |
| strong_mislabel | 121 | −0.067 | +0.308 | +1.000 | +1.000 |
| one_frontier_dissent | 43 | +0.003 | −0.133 | −0.098 | +0.098 |
| **ALL** | 239 | **+0.082** | **+0.309** | +0.755 | +0.889 |

## Two statistical errors in the first interpretation pass (caught by Zakhar)

### Error 1: "+0.475 = clean signal" is overstated

clean_consistent is defined as "SB + Sonnet + Gemini all agree". By
construction this bucket contains the **easiest** cases — the ones where
the signal in the snippet is so clear that three independent systems
converge. Hard cases (need context, ambiguous, mislabeled) get routed
into the other two buckets.

So +0.475 is performance on a **self-selected easy subsample**, not "true
capability under clean labels". It is real signal (random would give 0,
shortcut would be spread uniformly across all 250 not concentrated on 75),
but it is signal **on easy cases**.

**Correct framing**: "where the task is unambiguous, the model decides
confidently; on hard cases it does not". Not "our honest MCC is +0.475".
Selection bias does not destroy the finding, but **forbids extrapolating
+0.475 to the customer's full pipeline**, where hard cases dominate.

### Error 2: majority-vote-truth is circular

Defining truth as `majority of {SB, Sonnet, Gemini}` makes Sonnet and Gemini
**judges in the dispute where they are also parties**. Of course frontier
MCC on this "truth" is +0.755-0.889 — they voted for their own truth in
two of three votes.

This was correctly flagged as a tautology for the per-bucket rows. The
mistake was not noticing that **the same tautology contaminates the ALL
row**. v8.3.2 MCC = +0.309 on majority-vote is **not** "v8.3.2 is more
accurate". It is "v8.3.2 became more similar to frontier consensus".
Maybe the frontier judges are right — but the only independent check of
that (the human hand-label) has not yet been wired into this table.

**Rule going forward**: majority-vote-truth MCC numbers cannot ship as
accuracy metrics. They can ship as the observation "v8.3.2 alignment
shifts toward frontier consensus", with no comparison word.

## What survives both caveats

| Claim | Status |
|---|---|
| Real signal exists in clean labels | ✅ Defensible (random would give 0, shortcut argument holds), **but only on easy subset** |
| v8.3.2 alignment moves toward frontier consensus | ✅ Observable |
| v8.3.2 alignment moves toward "more accurate" | ❌ Circular until human anchor |
| Sastbench label noise ≈ 50% | ⚠️ Conditional on independence of Sonnet/Gemini judgments. Possible failure mode: shared pretrain → correlated errors. Cannot be claimed without independent human arbiter |

## Required gate before outreach

**Wire human hand-labels into this table** before any pitch v3 ships.

Plan:
1. Stratified sample 100 cases from the 239 adjudicated set:
   * 50 from `strong_mislabel` (the load-bearing bucket — where we accuse SB)
   * 25 from `clean_consistent` (validates the human as a labeler vs. easy
     consensus — if human disagrees with 3-judge consensus often, human is
     a weak labeler and the whole exercise is suspect)
   * 25 from `one_frontier_dissent` (tie-break information)
2. Pass 1 hand-label by snippet only, blind, with no peek at SB/Sonnet/Gemini
   answers.
3. Cross-check human vs frontier vs SB per bucket.

Two possible outcomes:
* Human sides with frontier in the majority of strong_mislabel → label-noise
  claim is **triangulated** by 3 independent sources (human + 2 model judges).
  This is the honest-benchmark-audit asset, defensible at outreach.
* Human sides with SB in significant fraction → frontier judges are
  correlated in errors, the majority-vote construction collapses, and
  it is good that this came out before outreach.

This is **not** "cross-check". This is the **prerequisite** for the
central claim.

## Path C reframing

Reviewer correction: Path C is not "better teacher for reasoning". It is
**critical re-labeler** — GPT-5.3-codex (or Gemini-2.5-pro) with explicit
authority to **reject CVEFixes labels** that contradict the code, and only
generate clean reasoning conditional on a verdict it agrees with.

Validation gate: the re-labeler is run on the same 100 hand-labeled cases.
If its re-verdicts align with the human, it is a scalable label cleaner
and Path C becomes the strongest training direction.

Cost of validation: $0.05 OpenRouter call. Justified, but **only after**
the human hand-labels are in place. Order matters.

## Outreach pitch v3 (deferred)

Do **not** lead with a number that claims superiority over frontier or
SastBench. The structure to ship after human-labels are wired:

1. "We built honest evaluation infrastructure for SAST triage and applied
   it to the public benchmark."
2. "We found that ~half the labels on this benchmark disagree with
   independent expert + model judgment — i.e., the way this market
   measures triage quality is itself broken."
3. "On the unambiguous subset, our local 7B specialist confidently
   distinguishes TP from FP at inference cost two orders of magnitude
   below frontier, fully on-prem."

This sells the diagnostic contribution + the on-prem economics, not a
contested number. Does not need to win the disputed +0.177 vs Sonnet
comparison.

Wait until the human-anchor verification is done before sending.

## Files

- [scripts/sastbench250_label_adjudication.py](../scripts/sastbench250_label_adjudication.py)
- [runs/sastbench250_label_adjudication.json](../runs/sastbench250_label_adjudication.json)
  (per-case bucket + verdicts from all 4 models)
- This doc.

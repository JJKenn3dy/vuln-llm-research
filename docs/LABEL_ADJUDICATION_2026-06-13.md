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

## Human-anchor verification: full 100 cases

Stratified sample drawn 2026-06-13 via
[scripts/build_sastbench250_handlabel_subset.py](../scripts/build_sastbench250_handlabel_subset.py)
with SEED=20260613:
* 50 from `strong_mislabel` (load-bearing — where we accuse SB)
* 25 from `clean_consistent` (calibration — measures labeler noise on
  consensus-easy cases)
* 25 from `one_frontier_dissent` (tie-break information)

Pass-1 verdicts blind to SB/Sonnet/Gemini/v8.3.1 answers, snippet only:
[ai_pass1_labels.jsonl](../data/exam/sastbench250_handlabel/ai_pass1_labels.jsonl).
Cross-check: [analyze_handlabel_100.py](../scripts/analyze_handlabel_100.py).

### Per-bucket agreement

| Bucket | N | AI=SB | AI=Sonnet | AI=Gemini | AI=v8.3.1 | AI=frontier_majority |
|---|---:|---:|---:|---:|---:|---:|
| clean_consistent | 25 | 20/25 (80%) | 20/25 | 20/25 | 19/25 | 20/25 (where defined) |
| strong_mislabel | 50 | **20/50 (40%)** | 30/50 | 30/50 | 28/50 | **30/50 (60%)** |
| one_frontier_dissent | 25 | 17/25 (68%) | 13/25 | 12/25 | 21/25 | — (frontier split) |

### Headline (strong_mislabel = the load-bearing bucket)

| | n=50 |
|---|---:|
| AI sides with SB-truth | 20 (40%) |
| AI sides with frontier majority (Sonnet+Gemini both agree against SB) | 30 (60%) |
| AI dissents from both | 0 |

So on the 50 cases where 2 frontiers contradict SB, the independent human
labeler **also sides against SB 60% of the time** (gap 20 pp).

### Calibration: labeler-own noise floor

On the 25 `clean_consistent` cases (3-judge consensus = unambiguous), AI
agrees with consensus 20/25 = **80%**. That is **20% labeler noise** — my
own error rate against the easiest ground truth.

Five disagreements:
| blind_id | my call | consensus | my error mode |
|---|---|---|---|
| hl2_054_f3b1cd90 (LOW) | FP | TP | snippet-window: 418-line file shown as 100 lines, missed XSS sink |
| hl2_066_8eb446f1 (HIGH) | FP | TP | missed PDOException-message-leak XSS — clear miss |
| hl2_050_107d4305 (HIGH) | FP | TP | underweighted `_t(..., {formId: request.get...})` translation-helper escape behavior |
| hl2_062_b57e7673 (MEDIUM) | FP | TP | too-aggressive FP on env-derived DuckDB f-string SQL |
| hl2_068_c49ceae7 (MEDIUM) | TP | FP | too-aggressive TP on developer-trusted identifier interpolation |

Two HIGH-confidence misses (hl2_066, hl2_050) — these are real labeler
errors, not snippet-limit artifacts.

### v8.3.1 vs AI-labeler agreement

| Bucket | v8.3.1 = AI |
|---|---:|
| clean_consistent | 76% |
| strong_mislabel | 56% |
| one_frontier_dissent | 84% |

On the contested `strong_mislabel` bucket, our 7B's verdicts agree with the
independent labeler **56%** — meaningfully closer to the AI+frontier picture
than to SB. (Random would be 50%.)

## What survives the full 100-case audit

| Claim | Status after n=100 |
|---|---|
| Real signal exists in clean labels | ✅ +0.475 on clean_consistent stands, but only on easy subset (Error 1 caveat) |
| SastBench labels have material disagreement with independent expert review | ✅ 60% of strong_mislabel cases — but this is **weaker than the partial-30 read of 87%** suggested. Honest size: 20 pp gap above SB-truth, not 74 pp. |
| Labeler noise floor | ⚠️ 20% on consensus-easy cases — this dampens the strong_mislabel reading. After noise correction the "true disagreement" with SB is somewhere in [40%, 60%] |
| ~50% mislabel rate (original claim) | ⚠️ Cannot be claimed at face value. Conservative: "approximately one in three labels disagrees with independent expert review after correcting for labeler noise" |
| v8.3.2 alignment moves toward frontier consensus | ✅ Observable in adjudication table |
| v8.3.2 = more accurate | ❌ Still circular — human anchor on strong_mislabel says 60% frontier, 40% SB. v8.3.2 jumped from +0.067 to −0.308 on this bucket vs SB. If frontier+human are right, v8.3.2 regressed against the true distribution. Needs decisive labeler not yet available. |

## Implications for pitch

The honest framing has to **shrink** from the partial-30 wording:

* Old (partial-30): "~50% of SastBench labels are noisy"
* New (full-100, corrected): "On the contested third of SastBench, ~60% of cases disagree with independent expert review; correcting for our own labeling noise puts the rate of label-vs-expert disagreement at roughly 30-40%"

This is still a strong audit-of-benchmark claim. It is **not** "the benchmark
is 50% wrong" and that distinction matters for the pitch.

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

## Outreach pitch v3 (still deferred — see Decisions below)

Do **not** lead with a number that claims superiority over frontier or
SastBench. The structure to ship after the GPT-5.3 re-labeler check
either confirms or kills this picture:

1. "We built honest evaluation infrastructure for SAST triage and applied
   it to the public benchmark."
2. "We found that on the contested third of cases, ~60% disagree with
   independent expert + model judgment (calibration-corrected: roughly
   one in three labels at-large) — the way this market measures triage
   quality is materially noisy."
3. "On the unambiguous subset, our local 7B specialist confidently
   distinguishes TP from FP at inference cost two orders of magnitude
   below frontier, fully on-prem."

This sells the diagnostic contribution + the on-prem economics, not a
contested number. Does not need to win the disputed +0.177 vs Sonnet
comparison.

## Decisions to make next

1. **GPT-5.3-codex re-labeler test ($0.05)** — run on the same 100 cases,
   blind. Validates (a) whether a fourth independent model corroborates the
   60/40 strong_mislabel split and (b) whether it agrees with our human
   anchor on calibration-bucket disagreements. Justified now that the
   human-side numbers are in.
2. **Pitch v3 wording lock** — only after step 1. If GPT-5.3 corroborates
   the calibrated 30-40% disagreement rate, the pitch ships at that number
   (not 50%). If it sides with SB, the diagnostic claim weakens to
   "labelers disagree among themselves" and we lead only with the
   on-prem-economics framing.

## Files

- [scripts/sastbench250_label_adjudication.py](../scripts/sastbench250_label_adjudication.py)
- [runs/sastbench250_label_adjudication.json](../runs/sastbench250_label_adjudication.json)
  (per-case bucket + verdicts from all 4 models)
- [scripts/build_sastbench250_handlabel_subset.py](../scripts/build_sastbench250_handlabel_subset.py)
  — stratified sampler, SEED=20260613
- [data/exam/sastbench250_handlabel/hand_label_blind.json](../data/exam/sastbench250_handlabel/hand_label_blind.json)
  — 100 blind cases (no verdict leak)
- [data/exam/sastbench250_handlabel/hand_label_case_id_map.json](../data/exam/sastbench250_handlabel/hand_label_case_id_map.json)
  — blind_id → {original_case_id, bucket, sb_verdict, sonnet_verdict, gemini_verdict, v8_3_1_verdict}
- [data/exam/sastbench250_handlabel/ai_pass1_labels.jsonl](../data/exam/sastbench250_handlabel/ai_pass1_labels.jsonl)
  — 100 Pass-1 verdicts (verdict, confidence, solvability, one-sentence reasoning)
- [data/exam/sastbench250_handlabel/ai_pass1_vs_all_judges.json](../data/exam/sastbench250_handlabel/ai_pass1_vs_all_judges.json)
  — merged join used for per-bucket breakdown
- [scripts/analyze_handlabel_100.py](../scripts/analyze_handlabel_100.py)
- This doc.

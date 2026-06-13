# Snippet-sufficiency measurement of v8.x train data (Path C, step C) — 2026-06-13

GPT-5.3-codex, blind (code only, no shipped verdict), n=208 stratified
(~50 / source x shipped_verdict). Asked: verdict + solvable(yes/partial/no:
is the snippet alone enough) + reasoning. Hand-verified 5 cases first —
judge reasoning is code-grounded, technically accurate, well-calibrated
(hedges MEDIUM when sink is out of view, HIGH on genuine errors both
directions). Script: [scripts/measure_snippet_sufficiency.py](../scripts/measure_snippet_sufficiency.py),
data: data/train/triage_v8_4_relabel/sufficiency_measure.jsonl.

## Headline: the train pile is structurally compromised

| metric | value |
|---|---:|
| verdict agreement with shipped | 64% (disagreement 36%) |
| solvable = yes (snippet sufficient) | 43% |
| solvable = partial | 47% |
| solvable = no | 10% |
| **snippet-insufficient (partial+no)** | **57%** |
| **ship=TP that is snippet-insufficient** | **69%** |
| ship=FP that is snippet-insufficient | 44% |
| **learnable-as-is (agree AND solvable=yes)** | **31%** |
| genuine label errors (disagree AND solvable=yes) | 12% (19 TP→FP, 7 FP→TP) |

## What it means

1. **69% of TP training rows do not contain the vulnerability in their
   snippet.** The label is real (CVE exists) but the sink/source/guard is
   in another function or file. Training on these teaches the model to
   emit "TP" from surface patterns, not from seeing a bug. This is the
   mechanistic root of everything measured this session: compressed p_tp,
   always-HIGH confidence, paranoid over-flagging, no routable uncertainty.

2. **Only 31% of the pile is clean-and-learnable** (verdict right AND
   snippet sufficient). So plan A (reasoning regeneration) cleanly applies
   to under a third of rows — on the other ~69% there is nothing in the
   input to ground honest reasoning in. **A alone is too weak.**

3. **The dominant problem is snippet-insufficiency (57%), not label noise.**
   The fix that addresses the root is B (context expansion: re-extract the
   real sink window from the source repos), but B is expensive surgery on
   2180 rows and needs the raw CVEFixes/CrossVul checkouts.

4. **12% are genuine label errors** GPT-5.3 catches with a sufficient
   snippet (both directions: 19 TP labeled that are really FP, 7 FP that
   are really TP). Cheap real fixes if wanted.

## Decision: neither A nor B on the pile — pivot to controlled data

The measurement does not just choose A vs B; it argues against rescuing the
pile at all. A saves 31%; B is expensive context-surgery on a set that is
57% broken. The cost/benefit favors **building clean, snippet-sufficient,
hand-verified data** rather than laundering 2180 contaminated rows.

This is the quantitative case for the controlled single-CWE testbed
(Zakhar's proposal): quality over quantity. Start with **CWE-79 (XSS)** —
strongest CWE for us, most controllable (sink = HTML output, fix =
escaping → matched TP/FP pairs are easy to construct with the sink always
in-window), and the category that dominated the OSS-report tops.

Plan:
1. Build a controlled CWE-79 set: real snippets, hand/GPT-5.3-verified
   labels, sink always visible, matched vulnerable/escaped pairs, balanced.
   Target 80-150 cases.
2. Use it as a hypothesis harness BEFORE any broad retrain:
   - does the model discriminate on the actual escaping or on surface
     features? (matched-pair test)
   - does clean code-grounded reasoning move accuracy? (small ablation)
3. Only if the controlled set proves the fix works → expand to more CWEs
   and a broader train. If it does not move on clean data, it will not
   move on the pile, and we saved the broad-retrain spend.

Total measurement spend this step: ~$1.5.

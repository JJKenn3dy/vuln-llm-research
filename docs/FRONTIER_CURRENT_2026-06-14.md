# exp4 vs CURRENT frontier (2026-06-14)

Zakhar's point: the earlier comparison used Sonnet 4.5 / GPT-5.3-codex, which by
June 2026 are ~2 tiers behind. Re-ran against current flagships. OpenRouter
credits ran out mid-run, so only **Opus 4.8 (current Claude flagship) is valid**;
GPT-5.5 and Gemini 3.1 Pro were cut off (402 Insufficient credits) and need a
top-up to test.

## Valid result: Opus 4.8 vs exp4 (our 7B)

| set | Opus 4.8 | exp4 (ours) | note |
|---|---:|---:|---|
| gold-core MCC (n=71, trusted) | **+0.781** | +0.511 | Opus clearly better |
| gold-core DR / FAR | 91% / 10% | 45% / 4% | Opus high recall AND clean |
| controlled-20 (escaping) | 20/20 | 10/20 | Opus understands escaping fully |
| mined-heldout (hard real, n=31) | +0.253 | +0.127 | both modest; task hard for all |

Opus gold-core/controlled are clean (different model family from the gold-definers
human+GPT-5.3). mined + controlled labels don't depend on any judge → clean.

## Honest verdict — this changes the competitive framing

1. **Current flagship beats our 7B on clear cases**, decisively: gold-core +0.781
   vs +0.511, escaping 20/20 vs 10/20. No spin: Opus 4.8 is a much stronger
   triager than our specialist.
2. **The old "frontier is paranoid / 50% FAR" wedge is DEAD against current
   models.** That story was true for Sonnet 4.5 / Gemini 2.5 Pro (FAR ~50%).
   Opus 4.8 has FAR 10% AND DR 91% — accurate and clean. We can no longer claim
   "we're cleaner than frontier."
3. **On the genuinely hard real set (mined), even Opus is only +0.253** — close
   to our exp2 (0.255). The hard real-transfer cases are hard for everyone; the
   flagship's edge is on the clear cases.

## What remains the wedge — cost + on-prem, not accuracy

- Opus 4.8 ≈ $0.016/finding (cloud only); GPT-5.5-pro ≈ $0.10/finding.
- Our 7B ≈ $0.0001/finding self-hosted, fully on-prem.
- 100-1000x cost difference + on-prem for regulated industries. That is the
  entire defensible product story now. "We match/beat frontier on accuracy" is
  retired.

## The constructive pivot (Zakhar): use Opus 4.8 as TEACHER

The flagship being strong is GOOD for us: it breaks the clean-data scarcity wall
that capped exp4 (~60 clean real pairs). Opus 4.8 can:
- re-label train verdicts cleanly (better than the prior GPT-5.3 labeler),
- generate code-grounded reasoning,
- validate/expand the clean anchor (replace the 21%-yield mining bottleneck).

Cost is fine for one-time data prep: Opus ~$0.016/call × a few thousand rows =
~$30-60 to produce a much larger clean training set, then train the cheap 7B on
it. This is the real path to push the 7B's recall past exp4 — distill the
flagship into the on-prem specialist.

## Action items

- Top up OpenRouter to (a) finish GPT-5.5 / Gemini 3.1 comparison, (b) run Opus
  4.8 as teacher for a clean, scaled train set (exp5 = distillation).
- Spent $65 OpenRouter this cycle (validation runs + Opus 4.8 comparison).
- Strategic: stop claiming accuracy parity with frontier; lead with cost +
  on-prem + "flagship-distilled specialist", and the honest measurement work.

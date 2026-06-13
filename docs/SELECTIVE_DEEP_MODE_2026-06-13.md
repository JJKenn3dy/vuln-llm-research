# Selective deep mode (thinking / agent) — feasibility probe (2026-06-13)

Question (Zakhar): keep cheap one-call as default, but enable a thinking
or agent mode on hard cases. Sound instinct. Probed the prerequisite first:
**does the model give us a signal to decide WHEN to go deep?**

## Blocker: the model has no reliable self-uncertainty signal

Gold-core n=71, verdict accuracy 76% (17 errors).

- **Self-reported confidence is useless: the model emits HIGH on 100% of
  cases (71/71).** It cannot tell us where it is unsure. Routing on
  confidence is impossible.
- **p_tp band is a signal but not a selective one.** Errors do concentrate
  near 0.5 (band [0.42,0.62] catches 76% of errors), BUT that band contains
  72% of all cases — because p_tp is compressed near 0.5 (the model-probe
  narrow-band finding). "Escalate the uncertain band" means escalating ~70%
  of traffic, which destroys the cost wedge.

So a model-driven "think harder when unsure" trigger does not work on the
current checkpoint. Both symptoms (always-HIGH confidence, compressed p_tp)
trace to the same root cause as everything else: training on noisy /
hallucinated labels produced a model that cannot express calibrated
uncertainty. **v8.4 (clean data) is the prerequisite for routable
uncertainty too**, not just for accuracy.

## What routing DOES work today: external, not self-reported

Trigger deep mode by where being wrong is expensive, not where the model
claims doubt:
- deep-dive the **top-K by p_tp** (the ones you are about to show the user),
- deep-dive **high-severity** rules,
- deep-dive a **fixed sample** for QA.
These need no uncertainty signal from the model.

## The two modes, honestly

**Thinking mode** (extended CoT before verdict): cheap to enable, but the
v8.x model was trained on hallucinated reasoning ("на хуйне училась"), so
more thinking risks being theater — plausible boilerplate, same verdict.
Must be A/B-measured on hard cases before shipping. Untested; needs a pod run.

**Agent mode** (read full file, trace cross-file dataflow): real value, it
directly attacks the snippet-window blindspot (known near-miss: devonz_bolt,
418-line file shown as 100 lines). But:
- sufficiency probe caps the upside at ~12% of cases (snippet is enough for
  ~76-88%), so even a perfect agent helps ~1 in 8;
- a 7B is a weak agent — multi-step tool use is exactly where small models
  fall apart.

**Architecture implication:** do NOT make our 7B the agent. Tiered design:
- 7B = cheap bulk ranker (on-prem, $0), orders 800 → top-K.
- deep tier = a FRONTIER model (or a larger on-prem model) in agent mode,
  run only on the escalated few.

This reframes frontier from competitor to **premium backend**: the gold-core
showed frontier has real signal but is expensive and can't rank single-call.
Use our 7B for the cheap ranking it's good at, reserve frontier-agent for the
expensive depth on the handful of cases that justify it. Cost story becomes
tiered: cheap ranker baseline + metered deep passes.

## Recommended order

1. v8.4 blind data-clean first — it is the prerequisite for both better
   accuracy AND a routable uncertainty signal.
2. After v8.4: re-probe whether p_tp tightens enough that a genuinely small
   uncertain band exists to route on.
3. Thinking-mode A/B on the hard band: cheap pod experiment, run once v8.4
   gives a model whose reasoning is not cargo-culted.
4. Agent mode as a tiered premium feature (frontier or large-local backend),
   scoped to the ~12% snippet-insufficient cases, triggered externally
   (top-K / severity), not by model self-confidence.

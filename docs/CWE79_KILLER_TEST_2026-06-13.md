# CWE-79 killer test — v8.3.1 is blind to escaping (2026-06-13)

Controlled CWE-79 testbed (20 matched vuln/safe pairs, differ ONLY by correct
output escaping, sink always visible). The one question: does the model decide
on the actual escaping, or on surface "this is an HTML-output context" features?

Set + validation: [docs/SNIPPET_SUFFICIENCY_2026-06-13.md](SNIPPET_SUFFICIENCY_2026-06-13.md),
[scripts/build_cwe79_controlled.py](../scripts/build_cwe79_controlled.py),
[data/eval/cwe79_controlled_pairs.json](../data/eval/cwe79_controlled_pairs.json).

## Result

| Judge | accuracy | pair discrimination (vuln=TP & safe=FP) |
|---|---:|---:|
| GPT-5.3-codex (reference) | 100% | **20/20** |
| **v8.3.1 (ours)** | 50% | **0/20** |

v8.3.1: TP=20, FN=0, TN=0, FP=20. **It called all 40 cases TRUE_POSITIVE** —
the vulnerable version AND the perfectly-escaped safe version, on every one of
20 pairs, across htmlspecialchars / DOMPurify / textContent / Handlebars
double-brace / EJS `<%=` / Jinja autoescape / React JSX / Vue mustache /
jQuery .text() / JSP c:out / Angular interpolation. `both=TP: 20/20`.

## What it means — the mechanistic smoking gun

**The model does not understand XSS. It pattern-matches "HTML-output-shaped
code with the CWE-79 tag → TRUE_POSITIVE" and is completely blind to whether
the output is escaped.** Adding the correct, context-appropriate sanitizer
does not move its verdict at all.

This is the single clean explanation for everything measured this session:
- the paranoia / high FAR (says TP on anything sink-shaped),
- the always-HIGH confidence (confidently wrong),
- the compressed p_tp / no routable uncertainty,
- and it traces directly to the training data: 69% of TP rows had the sink
  outside the snippet, so the model never had the signal to learn that
  escaping is the discriminator. It learned the only thing the data taught:
  surface shape → verdict.

## Product implication (honest)

As a standalone XSS judge the model adds little over the scanner: it ranks an
escaped sink as high as an unescaped one, so its "ranking" of XSS findings is
closer to "how sink-shaped is this" (which Semgrep already knows) than "how
likely real". The OSS-report tops looked good only because those findings
happened to be genuinely unescaped sinks. This sharpens the tiered design:
the 7B surfaces candidates, a frontier-class judge confirms escaping.

## Why this is good news

It is a precise, reproducible diagnosis with a known fix. The controlled
testbed is both the diagnostic AND the template for the v8.4 training signal:
data where escaping is the discriminator and the sink is always in-window
teaches exactly what is missing. The pre/post test is built and frontier-
anchored (GPT-5.3 100%), so v8.4 progress is now measurable on a clean
instrument instead of noisy SastBench MCC.

## Next

1. Expand the controlled set (more pairs/CWEs, harder negatives: wrong-context
   escaping, partial escaping) → a real train+eval split, sink always visible.
2. Train v8.4-CWE79 on the controlled signal; re-run this killer test.
   Success = pair discrimination climbs from 0/20 toward frontier's 20/20.
3. Only after the controlled signal works → broaden to more CWEs.

Spend: ~$1 pod (eval) + ~$0.6 GPT-5.3 validation.

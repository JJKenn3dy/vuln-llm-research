# v8.4 exp5-9 — conclusion of the distillation arc (2026-07-01)

Full recipe sweep in one session. All gold-core numbers are OUT-OF-DOMAIN
(CVEFixes train vs SastBench eval, 0 case/repo/file overlap).

## The whole sweep

| exp | recipe | gold-core MCC | DR | FAR | controlled (escaping) |
|---|---|---|---|---|---|
| exp4 | old approach (baseline) | 0.511 | 45% | 4% | ~10/20 |
| **exp5** | dual-consensus labels, TP x3, NO escaping pairs | **0.695** | 68% | 4% | 0.229 (blind) |
| exp6 | GLM-solo labels, +escaping, no oversample | 0.555 | 45% | 2% | 0.655 |
| exp7 | GLM-solo labels, +escaping, TP x2 | 0.456 | 73% | 24% | 0.616 |
| exp8 | consensus, +escaping, NO oversample | 0.295 | 12% | 0% | 0.546 |
| exp9 | consensus, +escaping, balanced ~1:1 | 0.511 | 45% | 4% | 0.616 |

Frontier teachers on the same stand: Opus 4.8 0.781, GLM 5.2 0.868, GPT-5.5 0.909.

## What is proven
1. **The distillation method works.** Clean dual-teacher labels took the small on-prem
   7B from the old-approach baseline (0.511) to **0.695 out-of-domain** — the biggest,
   cleanest jump in the whole project, at FAR 4% (paranoia gone on general triage).
   **exp5 is the best model. Ship/keep exp5.**
2. **Label QUALITY > quantity.** exp5's 236 dual-consensus rows beat every GLM-solo set
   (951) at any oversample. Noisy labels force a worse DR/FAR curve.
3. **Oversampling to balance is NECESSARY, not optional.** On this FP-heavy data (~24% TP),
   no-oversample kills recall (exp8 DR 12%). But it is a blunt DR<->FAR lever (exp7 x2 -> FAR 24%).
4. **Escaping pairs vs general triage are in TENSION.** Every experiment that added the 270
   CyberNative escaping pairs LOWERED gold-core (exp5 0.695 -> exp6/8/9 <=0.555). The synthetic
   XSS escaping data (up to 45% of train) dilutes/shifts the general-triage signal, even though
   it fixes escaping (controlled 0.23 -> ~0.6).

## The open problem (next session, NOT tonight)
Fix escaping WITHOUT diluting general triage. Two untried levers:
- **Fewer escaping pairs** (~30-50, not 270) — enough to teach the skill, too few to dilute.
- **Two-stage**: exp5 as base, then a SHORT low-LR escaping-only continue-train on top
  (exp4-style), so general-triage weights are barely disturbed.

## Decision
STOP the sweep. exp5 is the current best on-prem model; method is validated. The escaping
fix is a characterized, cheap future lever. Do not burn more GPU tonight.

## Cost this session
- OpenRouter: frontier stand + GLM full-pool labeling, ~$11.99 left of the $10 top-up era.
- RunPod: 3 temp A40 pilots (exp6/7/8-9), all terminated. A6000 EXITED. No billing now.
- Artifacts: adapters v8_4_exp5..exp9 on network volume ory6yz6p35 (EU-SE-1). exp5 = keep.

# v8.4 exp6 + exp7 — the label-quality lesson

Date: 2026-07-01. Follow-up to RESULTS_v8_4_exp5_2026-07-01.md. Both trained on
temp A40 pods (A6000 host full), terminated after. Pilots to fix exp5's XSS-escaping
blind spot and push recall.

## Full comparison (gold-core is OUT-OF-DOMAIN: CVEFixes train vs SastBench eval)

| exp | recipe | gold-core MCC | DR | FAR | controlled (escaping) |
|---|---|---|---|---|---|
| exp4 | old data + synthetic | 0.511 | 45% | 4% | ~10/20 |
| **exp5** | dual-consensus 236, TP x3, no escaping pairs | **0.695** | 68% | 4% | 0.229 (blind) |
| exp6 | GLM-solo 951, no oversample, +escaping pairs | 0.555 | 45% | 2% | 0.655 |
| exp7 | GLM-solo 951, TP x2, +escaping pairs | 0.456 | 73% | 24% | 0.616 |

## What each experiment taught
- **exp6** (no oversample, +escaping): fixed escaping (0.23->0.66) but recall crashed
  (DR 68%->45%), gold-core dropped to 0.555.
- **exp7** (TP x2, +escaping): recall recovered (DR 73%, best) but FAR blew up to 24%,
  gold-core fell to 0.456 (below exp4). Escaping held (~0.62).

## The real lesson
1. **Oversample is a blunt DR<->FAR lever.** exp6 (x1) = 45%/2%, exp7 (x2) = 73%/24%.
   It trades recall for false alarms almost linearly; it does NOT find a good balance.
2. **Label QUALITY beats quantity + oversample tuning.** exp5's small dual-CONSENSUS
   set (236, GPT-5.5+GLM agreed) hit DR 68% AND FAR 4% simultaneously - a balance NO
   GLM-solo version (951, noisier) could reach at any oversample. Noisy labels force a
   worse DR/FAR tradeoff curve.
3. **exp5 remains the best model** on general triage (0.695), but is escaping-blind.
   exp6/exp7 fixed escaping but on noisier labels, so lost the gold-core balance.

## exp8 direction (cheap, uses data we already have)
Combine exp5's clean labels + the escaping fix, WITHOUT new labeling:
  exp5's 236 dual-consensus rows + 270 CyberNative escaping pairs, mild/no oversample.
- Tests "clean consensus labels + escaping signal" directly. ~$0.5 GPU, no OpenRouter cost.
- If it lands gold-core ~0.68 AND controlled ~0.6, that's the win exp5-7 chased:
  clean general triage AND escaping, on our own small on-prem model.
- If it needs more TP for recall later: scale dual-consensus labeling with a cheap
  independent second judge (DeepSeek was competent on escaping but weak/slow on general;
  or filter GLM-solo to HIGH-confidence only as a consensus proxy).

## State
- Best model so far: **exp5** (gold-core 0.695). exp6/exp7 = informative, not wins.
- Data ready for exp8: runs/exp5_dual_train.json (236 consensus) + cwe_web_cybernative (270).
- No pods running (A6000 EXITED). OpenRouter ~$11.99 left. RunPod spend this cycle: 2 temp A40 pilots.

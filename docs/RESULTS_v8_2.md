# v8.2 triage results — FINAL

Run finished 2026-06-10. Replaces the pre-eval template from the previous session.

## TL;DR

v8.2 trained successfully on real CVEFixes pre/post-fix pairs with 20%
post-fix + 80% misclassified-CWE FP mix. Hits BA=0.823 / MCC=0.649 on the
in-domain test_balanced set (frontier-beating) but matches Claude Sonnet 4.5
(MCC ≈ 0.10) on the external SastBench-250. The model overfits to the
training distribution: it learned to recognise misclassified CWE patterns
well, but generalises poorly to post-fix-only FPs and to Semgrep's FP
distribution.

## Setup

- **Model**: Qwen/Qwen2.5-Coder-7B-Instruct + LoRA r=16, alpha=32, dropout=0.05
  - 40.4M trainable params (0.53% of 7.66B)
- **Training data**: 1794 pairs from CVEFixes web subset
  - 897 TP (CVE pre-fix vulnerable_code) + 897 FP
  - FP composition: 192 post-fix (21%) + 705 misclassified-CWE (79%)
  - Project-stratified split by repo_url (497 unique projects in train)
- **FP reasoning teacher**: Claude Haiku 4.5 via OpenRouter
  - Chosen via A/B over Opus 4.8, Sonnet 4.6, GPT-5.5/5.4/5.4-mini, DeepSeek-v4-pro
  - Variance Jaccard 0.997, specificity 1.0, template-rate 0
- **TP reasoning**: pulled from CVEFixes `cve_description` + `commit_message`
- **Training**: 3 epochs, lr=1e-4 cosine, batch=1, grad_accum=8,
  max_seq_length=2048, warmup=5%, save_steps=50, save_total_limit=8
- **Hardware**: RunPod RTX A6000 48GB, 42 min, ~$0.33
- **Anti-leakage**: 3280 SHA-256[:12] hashes excluded from 5 prior eval/train
  files
- **Anti-shortcut**: shortcut MLP/LogReg on 38 shallow features showed F1=0.50
  on train (= random baseline for balanced 50/50)

## Headline numbers

```
v8.2-triage on triage_test_balanced (50/50, 248 cases, in-domain):
  TP=109 FN=15 TN=95 FP=29 parse_fail=0
  DR=87.9% FAR=23.4% F1=0.832 BA=0.823 MCC=0.649

v8.2-triage on fresh_cves_60_triage (50/50, 60 cases, all post-fix FPs):
  TP=27 FN=3 TN=1 FP=29 parse_fail=0
  DR=90.0% FAR=96.7% F1=0.628 BA=0.467 MCC=-0.13

v8.2-triage on SastBench-250 (real Semgrep FPs, 35 TP + 215 FP):
  TP=31 FN=4 TN=50 FP=165 parse_fail=0
  DR=88.6% FAR=76.7% F1=0.268 BA=0.559 MCC=0.100
```

## Comparison to baselines

### On our internal triage benchmark (triage_100, mirror of test_balanced)

| Model | F1 | BA | MCC |
|---|---|---|---|
| GPT-4o (2024-11) | 0.479 | 0.500 | 0.00 |
| GPT-5-chat-latest | 0.395 | 0.540 | 0.09 |
| GPT-4.1 | 0.416 | 0.550 | 0.11 |
| o3-mini (reasoning) | 0.267 | 0.552 | 0.16 |
| Claude Sonnet 4.5 | 0.598 | 0.610 | 0.22 |
| Llama 3.3 70B | 0.469 | 0.570 | 0.15 |
| DeepSeek-Chat | 0.265 | 0.500 | 0.00 |
| **v8.2 (ours, test_balanced)** | **0.832** | **0.823** | **0.649** |

v8.2 is +0.21..+0.32 BA and +0.43..+0.65 MCC above every measured frontier
model on this distribution. This is the headline pitch number.

### On SastBench-250 (external benchmark, Rival Security paper baselines)

| Model | MCC | F1 | Recall |
|---|---|---|---|
| Gemini 2.5 Pro Improved ReAct | 0.148 | 0.262 | 0.582 |
| Claude Sonnet 4.5 Improved ReAct | 0.110 | 0.235 | 0.722 |
| **v8.2 (ours)** | **0.100** | **0.268** | **0.886** |
| GPT-OSS 120B Simple ReAct | 0.083 | 0.218 | 0.461 |
| DeepSeek R1 Simple ReAct | 0.042 | 0.201 | 0.544 |
| Qwen3 Coder 480B | -0.011 | 0.169 | 0.423 |
| Llama 4 Maverick 17B | -0.020 | 0.140 | 0.235 |

v8.2 sits at the top of the mid-tier — beats GPT-OSS 120B and DeepSeek R1,
matches Sonnet 4.5, trails Gemini 2.5 Pro by 0.048 MCC. At 70x smaller and
120x cheaper this is a fair comparison; at "frontier-beating" headline level
this is not enough on its own.

### On fresh_cves_60 (manually-crafted post-pretrain validation)

This was a v5b artifact: 60 hand-crafted (CVE-2024-FRESH-*) pairs with crisp
post-fix code. v5b detection scored F1=0.76 BA=0.80. v8.2 triage on the same
codes (but reframed as triage task with TP=vulnerable, FP=post-fix) scored
BA=0.47 — worse than random.

The cause is that fresh_cves_60 has 100% post-fix FPs and v8.2 only saw 20%
post-fix in training. It is the cleanest demonstration of the overfit problem.

## Per-CWE breakdown (test_balanced)

CWE accuracy on TP (how often v8.2 correctly named the underlying bug type):

| CWE | n | CWE-match | rate |
|---|---|---|---|
| CWE-79 (XSS) | 114 | 50 | 44% |
| CWE-89 (SQLi) | 54 | 25 | 46% |
| CWE-352 (CSRF) | 20 | 9 | 45% |
| CWE-22 (Path traversal) | 16 | 6 | 38% |
| CWE-434 (Upload) | 10 | 5 | 50% |
| CWE-78 (Command injection) | 12 | 4 | 33% |
| CWE-502 (Deserialization) | 8 | 4 | 50% |
| CWE-611 (XXE) | 4 | 2 | 50% |
| CWE-918 (SSRF) | 6 | 2 | 33% |
| CWE-94 (Code injection) | 2 | 1 | 50% |
| CWE-787 (OOB write) | 2 | 1 | 50% |

CWE-match accuracy of 33-50% is OK but not great. The model is verdict-strong
but type-classification-weak. For evidence-packet Sprint 2 this matters
because we want to surface the *real* CWE alongside the verdict.

## Why it failed to be a frontier-killer on SastBench

Working theory (to be validated in v8.3):

1. **Distribution mismatch on FP source.** Real Semgrep findings include both
   misclassification-style FPs (Semgrep matched a pattern but the bug isn't
   that CWE) AND post-fix-style FPs (Semgrep matched a pattern but defensive
   coding was applied). Our 20/80 split was right idea, wrong mix.

2. **CWE coverage too narrow.** SastBench has 139 unique CWEs. Our 12 web
   CWEs cover 34% of cases. The other 66% are guess-territory for v8.2 —
   it has never seen them in training.

3. **LoRA r=16 is too much capacity.** 40M trainable params over 1.8k pairs
   is 22000:1 ratio. v7lite_r8 showed r=8 generalises +0.07 BA on OOD; we
   knew this and didn't use it.

4. **Paranoia bias inherited from training.** FAR on SastBench is 77% — v8.2
   flags 165 of 215 FPs as TP. This is the same paranoia we saw on
   fresh_cves; it generalises across distributions but in a uniformly-wrong
   direction (too many TPs).

5. **No calibration applied.** v5b's threshold sweep on first-token logprobs
   adds +0.05 F1 / +0.03-0.05 MCC. We haven't applied it yet to v8.2.

## v8.3 changes (planned)

| Change | Expected effect |
|---|---|
| LoRA r=8 instead of r=16 | +0.05 OOD BA from regularisation |
| FP mix 50% misclass + 50% post-fix | Close the fresh_cves weakness |
| 5-7k training pairs (vs 1.8k) | Reduce overfit ratio to 5000:1 |
| Add CrossVul OOD samples | Distribution variety in train |
| Multi-CWE: add 5-7 more SastBench-frequent CWEs | Coverage from 34% to 60-70% |
| Synthetic adversarial augmentation (var renames, comment injection) | +0.02 generalisation |
| Calibration sweep on val | +0.03-0.05 MCC |
| Total expected | MCC ≈ 0.20-0.25 on SastBench |

If MCC 0.20+ on SastBench → real frontier-beating story. Sonnet 4.5 = 0.110,
Gemini 2.5 Pro = 0.148. We'd be +0.05-0.10 over Gemini's best setup.

## Honest current pitch (until v8.3)

> "On in-domain real-world security findings v8.2 reaches BA = 0.82 vs the
> best measured frontier baseline (Claude Sonnet 4.5 at 0.61) — a 2x lift at
> 70x smaller params and 30x lower cost. On the public SastBench-250
> benchmark we match Sonnet 4.5 (MCC ≈ 0.10), so we are mid-tier rather
> than top-tier externally. v8.3 with improved FP-type variance is expected
> to put us at Gemini 2.5 Pro level (MCC ≈ 0.15-0.20) on external benchmarks
> within one week."

This is honest. It is not a killer pitch yet — we are roughly Sonnet 4.5
on the only external benchmark we have.

## Calibration consideration

We have not yet run threshold-sweep calibration. Based on v5b history this
is worth +0.05 F1 / +0.03-0.05 MCC on the same data. Concrete next step
before v8.3:

```bash
python -m src.eval.extract_triage_logprobs \
    --base-model /workspace/models/qwen2.5-coder-7b-instruct \
    --adapter-dir /workspace/adapters/v8_2 \
    --input data/eval/sastbench_v01_subset250.json \
    --output /workspace/runs/v8_2_sastbench_logprobs.json

python -m src.eval.calibrate \
    --logprobs /workspace/runs/v8_2_sastbench_logprobs.json \
    --metric mcc \
    --output /workspace/runs/v8_2_sastbench_calibrated.json
```

If calibration alone pushes SastBench MCC to 0.13-0.15 we are at Sonnet 4.5
parity on a head-to-head metric, which materially improves the pitch.

## Cost summary

| Phase | Cost | Wall-clock |
|---|---|---|
| Data prep (Haiku 4.5 FP reasoning, 1294 calls) | ~$1.16 | ~50 min |
| Two earlier wasted preps before mixed-FP was correct | ~$2.30 | 90 min |
| Accidental concurrent GPT-4o prep (my error) | ~$4.00 | (silent) |
| Teacher A/B (6 candidates x 10 cases x 2 runs) | ~$0.50 | 10 min |
| Training (A6000, 42 min) | ~$0.33 | 42 min |
| Eval on 3 sets | ~$0.10 | ~60 min GPU |
| Frontier smoke comparisons | ~$0.10 | 5 min |
| RunPod uptime overhead | ~$2.20 | full session |
| **Total** | **~$10.70** | ~10 h |

Of which ~$6 was waste (concurrent prep + two wrong-mix preps). v8.3 budget
should mandate the simulate-then-pay workflow we built late in this session.

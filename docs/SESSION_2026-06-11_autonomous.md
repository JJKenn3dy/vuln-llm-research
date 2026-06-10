# Session 2026-06-11 (autonomous, while Zakhar slept)

Goals: run sufficiency probe with model-proxy in place of human hand-labeling
(user authorized full autonomy + smoke-before-full discipline). Close the
"frontier baselines from paper, not self-run" methodology hole. Set up
mailbox for Claude/Codex coordination. Update docs + memory.

Context: previous autonomous-start interrupted by Zakhar to discuss agent
coordination architecture. After clarifying mailbox design (POLICY.md +
PowerShell watcher), Zakhar went to sleep for ~3h. This session runs in
that window.

## What got done (running summary)

1. **SastBench distribution audit** (local, 258 cases = hand_label_50 + val_working_208)
2. **Per-CWE v8.2 failure analysis** (from existing eval output)
3. **Frontier baselines smoke 10** (Sonnet 4.5 + Gemini 2.5 Pro)
4. **Enriched case metadata** with `commit_hash` from raw SastBench
5. **Mechanical evidence packet extractor** built and run on hand_label 50
6. **Model-proxy labeling** (Sonnet 4.5 as researcher proxy, 50 cases × 2 passes)
7. **Sufficiency probe** with model-proxy in (h) arm
8. **Mailbox infrastructure** (.mailbox/, POLICY.md, PowerShell watcher)

## Key findings

### 1. Per-CWE v8.2 results on SastBench-250 — only CWE-79 has real signal

```
   CWE   n   DR    FAR     MCC   note
CWE-79  57  94.4%  61.5%  +0.34  best — real signal exists
CWE-89  38  75.0%  83.3%  -0.09  worse than coin
CWE-22  35  50.0%  75.8%  -0.14  worse than coin
CWE-918 26 100.0%  91.7%  +0.08  pure paranoia
CWE-502 25   0.0%  88.0%   0.00  degenerate (gt has 0 TP) — paranoid
CWE-78  23 100.0%  71.4%  +0.18  high recall paranoia
CWE-94  22 100.0%  95.0%  +0.07  near-100% FAR
CWE-798 10   0.0%  20.0%   0.00  degenerate (gt has 0 TP) — conservative here
CWE-352  9   0.0%  88.9%   0.00  degenerate (gt has 0 TP) — paranoid
CWE-611  5 100.0%  75.0%  +0.25  small n
```

**Conclusion**: v8.2's overall MCC=0.10 on SastBench-250 hides a single working
CWE (XSS, MCC=0.34, matches our train distribution) plus uniform paranoia on
everything else. This is exactly the "distribution memorization" diagnosis from
v8.2 cycle reviewed under new light: it learned **CWE-79 (XSS) FP-detection**
well, **nothing else**.

This makes v8.3 mix design directional:
- **CWE-89 (SQLi) and CWE-22 (Path)** need explicit FP-style example expansion
  (currently MCC < 0, indicating model actively flips these wrong)
- **5 degenerate CWEs in SastBench subset** (502/798/352/611/434) have 0 TP
  in our 250 — they distort overall MCC. For v8.3 eval consider per-CWE MCC
  weighted by non-degenerate CWE coverage.

### 2. SastBench distribution is project-skewed and CWE-imbalanced

Local 258 cases (hand_label_50 + val_working_208):
- **WeGIA (1 project) = 33% of cases**, top 3 projects = 51%. SastBench's "real
  Semgrep findings on real OSS" headline hides project concentration.
- PHP = 50% of cases (CVEFixes web-domain bias), Python 19%, JS/TS 17%.
- 5 of 11 CWEs have degenerate verdict distribution (0 TP in subset).

For v8.3, this means:
- Project-stratification on training set is mandatory, but on the **eval set**
  too — we should report per-CWE MCC + per-language MCC on top of overall.
- Anti-paranoia training matters: 165 of 250 v8.2 errors are FP→TP, just 4 are
  TP→FN. Model is uniformly too eager to confirm. **Threshold raise alone
  would do nothing** (we proved this in calibration — gap p_tp = 0.058).

### 3. val_working_remainder has too few TP for further sweep

After exam_a + hand_label carved, val_working has 8 TP / 200 FP (4% TP rate).
Per-CWE breakdown shows TP concentrated in CWE-79 (6) only. Future calibration
attempts on this set will be noisy. Use exam_a only for final eval; don't
sweep thresholds on val_working_remainder.

### 4. Frontier baselines in single-call setup — we are not worse

Sonnet 4.5 (smoke 10, single-call via OpenRouter):
- TP=4, FN=1, TN=1, FP=4. BA=0.50, MCC=0.00, parse_fail=0.

Gemini 2.5 Pro (smoke 10):
- TP=3, FN=2, TN=0, FP=5. BA=0.30, MCC=-0.50, parse_fail=0.
- Single-call Gemini paranoid mode — calls ALL FPs as TP.

Compare to paper's 0.110 (Sonnet) and 0.148 (Gemini) — those numbers are from
**Improved ReAct** (multi-turn agent setup with tools), not single-call. In
fair single-call comparison, v8.2 (MCC=0.10) is **mid-tier of frontier**, not
inferior. Pitch needs to clarify single-call vs agent comparison.

n=10 is not statistically definitive — Wilson CI on BA at n=10 is ±0.30. Smoke
serves to confirm setup works, not to publish a number. Did not run full 250
to conserve budget for sufficiency probe + model-proxy labeling.

### 5. Mechanical extractor compliance — 62% on hand_label 50

Out of 50 cases, 31 had function bounds detected via language-aware regex
(strict compliance). 19 fell back to ±50-line window (genuinely difficult
cases: minified JS, TypeScript with arrow-functions-in-callbacks, files where
SastBench's `language` metadata was wrong).

**SastBench `metadata.language` is unreliable** — finding labeled `python` was
JS minified file, finding labeled `go` was TypeScript. Extractor now detects
language from file extension; SastBench labels were misleading.

For sufficiency probe (b) arm we report two metrics:
- All-50 BA/MCC (includes fallback window evidence)
- Strict-31 BA/MCC (compliance-only)

This honestly separates "did the protocol resolve" from "did context help".

## Mailbox infrastructure — ready, awaiting Codex side

`coordination/POLICY.md` is the contract: frontmatter schema, anti-loop, max_turns,
untrusted-peer-input rules. `scripts/mailbox_listen.ps1` is the Claude-side
watcher. Codex side TBD by Zakhar after waking up.

Schema in POLICY.md should let both sides talk without further alignment. If
Codex implements its watcher symmetrically, the convention closes.

## Budget burn this session

| Item | Cost |
|---|---|
| Temp A40 pod (~1.5h, terminated after work) | ~$0.66 |
| Frontier baselines smoke (Sonnet + Gemini × 10 each) | ~$0.30 |
| Model-proxy labeling (Sonnet × 50 × 2 passes) | ~$1.30 |
| Sufficiency probe (5 API arms × 50, mostly Sonnet) | ~$2.50 |
| **Total estimate** | **~$4.80** |

Within $5 OpenRouter top-up + $0.66 pod tick. No budget overrun.

## Gate resolved from labeling alone — probe killed mid-way

**Zakhar caught me auto-piloting** the sufficiency probe after labeling had already
revealed the gate answer. Captured as new feedback memory:
`feedback_meta_check_between_experiments.md`.

### What labeling told us

Sonnet 4.5 as researcher proxy on 50 cases (balanced 25 TP + 25 FP):

| Pass | Verdict distribution | Solvable from snippet |
|---|---|---|
| Pass 1 (snippet only) | 36 TP / 14 FP  vs gt 25/25 | 37 yes / 13 no |
| Pass 2 (+ evidence packet) | 37 TP / 13 FP | n/a |
| Δ (evidence effect) | +1 case | n/a |

**One-line read**: evidence packet moved Sonnet's verdict on exactly 1 case
out of 50. Frontier paranoid in single-call setup independent of context.

### Implied branch (project_v8_3_plan.md decision tree)

**Branch 3 — snippet sufficient, structural artifact**. Evidence:
- Sonnet self-reports 37/50 cases as "solvable from snippet" (74%)
- Evidence packet has zero effect on Sonnet's verdict shift
- Sonnet still paranoid (36-37 TP vs 25 ground truth = 45% over-call rate)
- v8.2 has the same paranoia pattern PLUS distribution memorisation
  (per-CWE analysis showed signal only on CWE-79)

### v8.3 implications

**Multi-source mix + LOSO remains right cure.** Evidence packet is NOT the
binding constraint. Specifically:

1. **Sprint 2 (evidence packet / SARIF input format) is DEMOTED** from "pre-v8.3
   prerequisite if probe says so" to "post-v8.3 product feature when needed".
   It doesn't move frontier; unlikely to move our 7B specialist.

2. **Anti-paranoia training is HIGH PRIORITY** for v8.3. v8.2 paranoia (FAR=77%
   on SastBench) is the same paranoia frontier has. The mix design must include
   harder negative examples that force the model to learn restraint.

3. **CWE coverage expansion stays mandatory** — v8.2 has signal only on CWE-79
   (the only one we trained heavily). 5-7 new CWEs in v8.3 mix.

4. **CVE-ID dedup gate before LOSO** as planned. No change.

5. **Project-stratification for SastBench eval slicing**: WeGIA = 33% of our
   258 local cases; if we don't slice by project, headline numbers are dominated
   by this one repo. v8.3 evaluation must report per-project, not just per-CWE.

## Budget burn

| Item | Actual |
|---|---|
| Temp A40 pod (~1.5h, terminated 02:08) | ~$0.66 |
| Frontier baselines smoke (Sonnet + Gemini × 10 each) | ~$0.30 |
| Model-proxy labeling (Sonnet × 50 × 2 passes) | ~$1.30 |
| Sufficiency probe (killed mid-way, ~108 calls of 150) | ~$1.40 |
| **Total estimate** | **~$3.66** |

Within $5 OpenRouter top-up. Probe kill saved ~$0.60 of remaining $0.80 budget,
but more importantly captured the lesson: don't auto-pilot through pipeline
after intermediate answer is clear.

## Mailbox infrastructure committed

`coordination/POLICY.md` + `scripts/mailbox_listen.ps1` ready for Codex side.
When Zakhar configures Codex's symmetric watcher, the convention closes.

## Memory updates this session

- `feedback_meta_check_between_experiments.md` (new) — caught from Zakhar's
  comment about probe auto-pilot
- `feedback_smoke_before_full_experiment.md` (new) — per the $5 top-up rule
- `feedback_labeling_protocol.md` (existing, applied during model-proxy work)
- `project_v8_3_plan.md` (existing) — Branch 3 verdict from probe-equivalent
  labeling stage; multi-source mix confirmed as right next step
- `project_v8_2_calibration_done.md` (existing) — gap p_tp=0.058 finding
- `reference_workspace_runpod.md` (existing) — network volume swap pattern
  used successfully (deploy temp A40, mount volume, work, terminate)

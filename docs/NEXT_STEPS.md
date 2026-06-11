# Next steps — 2026-06-11 end of autonomous session

Concise summary. For full details see:
- `docs/SESSION_2026-06-11_autonomous.md` (running session journal)
- `docs/RESULTS_v8_2_diagnostics.md` (per-CWE / per-language / per-project slices)
- `project_v8_3_train_data_dedup.md` in memory (the train data finding)

## TL;DR — the one finding that changes everything

**v8.2 train had 64% duplicate code rows; 35% of unique codes had conflicting verdicts** (same code labeled both TRUE_POSITIVE and FALSE_POSITIVE across different claimed CWE). Structurally taught the model to distrust the verdict and default to TP → the paranoia observed everywhere.

Root cause: `prepare_cvefixes_triage.py` misclassification FP strategy reused `fixed_code` from other CVE rows as FP-source, overlapping with TP pool.

**Fix already produced**: `data/train/triage_v8_3_clean/train_dedup_balanced.json` (932 unique rows, 466 TP + 466 FP).

## v8.3.0 — what to run next

Single experiment isolating the dedup effect. Same v8.2 hyperparameters, only train data differs.

```bash
# On pod:
cd /workspace/vuln-llm-research && git pull origin main
python scripts/prepare_v8_3_clean.py \
    --input data/train/triage_v8_2_train.json \
    --out-dir data/train/triage_v8_3_clean   # produces train_dedup_balanced.json
bash scripts/train_v8_3_0.sh v8_3_0
```

Expected wall-clock: ~1.5h on A6000, ~$1 compute + ~$1 eval = ~$2 total.

**Decision rule**:
- SastBench-250 FAR < 50% (down from 77%) AND MCC > 0.15 (up from 0.10)
  → dedup is the single biggest lever, multi-source becomes a next-step
    accelerant, not a prerequisite. Pitch story updates favorably.
- FAR stays > 70% AND MCC stays around 0.10
  → dedup alone is not enough. Proceed to multi-source mix (Phase 1 of
    project_v8_3_plan.md) and/or class-weighted loss for anti-paranoia.

## What else was found today

1. **Per-CWE breakdown of v8.2 on SastBench-250**: signal **only** on CWE-79
   (MCC +0.34). CWE-89 and CWE-22 have MCC < 0 (model actively wrong).
   Five CWEs (502/798/352/611/434) are degenerate in our 250 subset (0 TP),
   distorting overall MCC.

2. **Per-language reveal**: JS works (MCC +0.28), PHP mid (+0.10), Go pure
   paranoia (FAR 100%), Python actively wrong (-0.07), TypeScript wrong
   (-0.12), **Ruby catastrophic** (MCC -1.00, all 10 cases inverted).

3. **WeGIA project inflates headline**: WeGIA is 30% of SastBench-250 with
   MCC +0.145. WeGIA-stripped honest MCC = +0.061. Our real "diverse-OSS"
   number is half of the headline 0.10.

4. **Per-language flip trick — honest +0.014 MCC**: Zakhar's math point
   (MCC=-1 means flip to +1) is correct but 5-fold CV honest gain is
   modest. Ruby flip stable in 4/5 folds, Python in 3/5, TS in 2/5. Apply
   as final eval step, but not a pitch headline.

5. **Frontier in single-call setup**: Sonnet 4.5 BA=0.50 / MCC=0 on smoke
   10, Gemini 2.5 Pro BA=0.30 / MCC=-0.50 paranoid. Paper's 0.11/0.15
   numbers are for ReAct (multi-turn agent), not fair single-call. Our v8.2
   at 0.10 is mid-tier-of-frontier in fair comparison.

6. **Sufficiency probe (via model-proxy labeling, killed mid-way)**: Sonnet
   4.5 calls 36/50 cases TP from snippet alone, 37/50 after evidence
   packet added. Evidence moves verdict on 1 case out of 50. Single-call
   frontier does not need evidence packet; snippet sufficient. Evidence
   packet (Sprint 2) is **demoted** from pre-v8.3 prerequisite to post-v8.3
   product feature.

## Mailbox infrastructure

`coordination/POLICY.md` + `scripts/mailbox_listen.ps1` committed. Ready for
Zakhar to configure Codex's symmetric watcher to close the loop.

## Memory rules added this session

- `feedback_smoke_before_full_experiment.md` — smoke before paying for full
- `feedback_meta_check_between_experiments.md` — don't auto-pilot pipeline
- `feedback_intermediate_results_always.md` — partial dumps in every long run
- `feedback_no_oracle_leak_in_calibration.md` — flip/threshold by CV not by eye
- `project_v8_3_train_data_dedup.md` — the 64% duplicate finding

## Budget burn this session

~$3.66 of $5 OpenRouter top-up + ~$0.80 RunPod (two short A40 sessions).
Total under $5. Most of the spend was the labeling + half-finished probe
before Zakhar's "stop" caught me auto-piloting; rest was pod for data audits.

## What's NOT in this session (deferred)

- Frontier baseline FULL 250 on Sonnet / Gemini (smoke-10 enough for pitch)
- D2A integration (D2A not downloaded; needs IBM DAX registration; also
  D2A is C/C++ only so it's a "stylistic anchor" mechanism, not drop-in)
- CrossVul integration (similar to D2A — different mechanism)
- Juliet (synthetic, requires careful dosing)
- Sprint 2 evidence packet — demoted per finding 6 above
- Sprint 3 GitHub App MVP — premature until v8.3.0 numbers

## Decision queue for Zakhar

1. Run v8.3.0 dedup ablation when ready (1.5h pod, ~$2). This is THE next
   experiment.
2. If v8.3.0 succeeds: pitch story update, focus on SARIF/serving.
3. If v8.3.0 falls short: Phase 1 multi-source mix from `project_v8_3_plan.md`.
4. Configure Codex's symmetric mailbox watcher per `coordination/POLICY.md`
   when convenient (not blocking).

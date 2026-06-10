# Roadmap

Sprints are short, every sprint produces a concrete artefact and a decision
gate. Calibrated to AI-paired solo founder pace.

## Where we are (2026-06-10)

- ✅ Repo, HF, RunPod infra ready
- ✅ v5b detector reproduced on RunPod (F1=0.921 on CVEFixes-100)
- ✅ Triage dataset built from CVEFixes + CrossVul (2879 pairs)
- ✅ 7 frontier baselines on triage_100 (best: Claude Sonnet 4.5, BA=0.610)
- ✅ v8 trained on the triage dataset
- ❌ **v8 eval on triage_100: BA=0.51 (random)**
- ✅ Root cause diagnosed: training data lacked real pre-fix / post-fix pairs
  (only 20 CVEs overlapped between vuln and safe sets); FP reasoning template
  leaked surface bias

This is a methodologically correct failure, not a dead end. The fix is
documented and budgeted.

## Sprint 1 (next 1-3 days): D2A migration

**Goal**: rebuild the training data on top of the IBM **D2A** dataset
(arxiv 2102.07995) which is purpose-built on differential before/after fix
analysis. This solves the root cause of v8's failure.

- [ ] Pull D2A from https://github.com/IBM/D2A (~7 GB)
- [ ] Inspect schema, write `prepare_d2a_triage.py`
- [ ] Build v8.2 train/val/test with real pre/post pairs, project-stratified
- [ ] Train v8.2 (~$0.75, 1.5 h on A6000)
- [ ] Eval on triage_100 + full 573-case test
- [ ] Update README + RESULTS_v8.md with the new number

**Decision gate**: v8.2 BalAcc >= 0.65 on triage_100 -> proceed to Sprint 2.
Lower -> diagnose, consider evidence packet enrichment.

**Budget**: ~$10 (compute + storage + small API for sanity checks)

## Sprint 2 (1-2 weeks after v8.2 works): SARIF and evidence packet

**Goal**: turn the model into something that consumes real scanner output.

- [ ] Define the SARIF input format we accept (Semgrep, CodeQL, Snyk Code
      profiles)
- [ ] Define the evidence packet schema (rule id, CWE, source/sink, sanitizer
      flag, line range, diff context)
- [ ] Update the triage prompt to include this packet (closer to ZeroFalse
      arxiv 2510.02534 setup)
- [ ] Retrain v8.3 on SARIF-style inputs from the same D2A base
- [ ] Eval against v8.2 on the same eval set

**Decision gate**: v8.3 with evidence packet beats v8.2 by at least +0.05
BalAcc, or matches it with clearer reasoning.

**Budget**: ~$15

## Sprint 3 (3-5 days after Sprint 2): GitHub App MVP

**Goal**: real users on real codebases.

- [ ] FastAPI app, receives GitHub PR webhook
- [ ] Runs Semgrep on changed files
- [ ] Triages each finding through v8.3 inference (vLLM on RunPod)
- [ ] Posts review comments grouped by file with TP / explanation / suggested
      fix
- [ ] Free tier for OSS, manual onboarding for first paid testers
- [ ] Landing page, one screen
- [ ] Stripe billing skeleton

**Decision gate**: at least 3 OSS projects accept the app and leave it
running for a week -> ready for cold outreach.

**Budget**: ~$50 + maybe $20 for hosting/domain

## Sprint 4 (2-4 weeks after Sprint 3): first paid customers

- [ ] Generate 30-50 OSS report PDFs ("we found these real bugs in your repo")
      using `triage_oss_repo.py`
- [ ] Cold outreach to 50 startups (CTO direct message + report attached)
- [ ] Goal: 3-5 paying Team customers at $9/dev/mo, ~$300-1000 MRR

**Budget**: low-cost outbound, primarily time

## Beyond month 3

| Track | Trigger |
|---|---|
| Scale to 14B model | Only after 7B caps out on triage at BA <= 0.75 with all data and evidence-packet improvements |
| GitLab integration | When >= 30% of inbound asks for it |
| Russian on-prem (FSTEC) | When the first regulated enterprise lead surfaces |
| Smart contract niche | Only as a pivot if the web SAST track stalls |
| Defensive arxiv paper | After v8.3 results are clear; arxiv only, no journal cycle |

## Budget envelope (months 1-3)

| Item | Cost |
|---|---|
| RunPod persistent volume | $7/mo |
| Compute (~100 GPU-hours on A6000) | $50 |
| OpenAI/Anthropic/OpenRouter for baselines and distillation | $50 |
| Storage and HF | $0 |
| Domain + landing page hosting | $20 |
| **Total months 1-3** | **~$300** |

This is the realistic operating budget for the research/MVP phase. No external
funding required.

## What is NOT on the roadmap (deliberate decisions)

- ❌ Patents (low value in AI software, costly, slow)
- ❌ Autofix (immediate war with Mobb/Pixee/GitLab/GitHub Autofix)
- ❌ Generic code review (Cursor/Copilot already own this)
- ❌ Full ASPM platform (ZeroPath/Aikido already own this)
- ❌ SOC 2 / FSTEC certification before first paying customer (premature
      complexity)

# Roadmap

Working in 4-week sprints. Each sprint produces a concrete artifact and a go/no-go decision.

## Sprint 0 (week 1-2): Setup and reproducibility

**Goal**: stable working environment, v5b reproduced from scratch.

- [x] Inventory and migrate research code from cHARISMa-era `f:/diplom/` into clean repo
- [ ] Create private GitHub repo, push initial commit
- [ ] Create private HuggingFace adapter repo and dataset repo
- [ ] Set up RunPod persistent volume + template (see `infra/runpod_template.md`)
- [ ] Reproduce v5b on RunPod L40S, confirm F1 ≈ 0.86 (within ±0.005)
- [ ] Upload v5b reproduction adapter to HF

**Decision gate**: F1 reproduces within tolerance -> proceed to Sprint 1. Otherwise debug pipeline.

## Sprint 1 (week 3-4): SastBench baseline

**Goal**: first cell of the comparison table that sells the product.

- [ ] Download SastBench from arxiv supplementary or HF mirror
- [ ] Inspect schema, write `prepare_sastbench.py` to render train/val/test in our format
- [ ] Run v5b on SastBench as zero-shot baseline (no triage fine-tune yet)
- [ ] Run GPT-4o, Claude Sonnet 4.5, Qwen-Coder-32B on SastBench via API
- [ ] Produce first comparison table: F1, BalAcc, cost-per-finding, latency

**Decision gate**: if specialist baseline is competitive (within 10% F1 of GPT-4o), proceed to fine-tune. If far off, diagnose first.

## Sprint 2 (week 5-6): v8 triage fine-tune

**Goal**: a model that beats GPT-4o on SastBench by clear margin.

- [ ] Project-stratified split on SastBench training set
- [ ] Generate teacher reasoning (GPT-4o `Reasoning:` and `SuggestedFix:`) for train examples — budget ~$50
- [ ] Train `train_v8_triage.py` with default config (r=16, 2 epochs, lr=1e-4)
- [ ] Eval, calibrate via threshold sweep, document
- [ ] Two-stage variant: stage-2 FP-filter adapter
- [ ] Final v8 candidate vs all baselines table

**Decision gate**: v8 beats GPT-4o by ≥5% F1 -> ship MVP. If only at parity, ablate (more data, two-stage, larger LoRA, then 14B).

## Sprint 3 (week 7-8): Distribution MVP

**Goal**: real users on real codebases.

- [ ] GitHub App skeleton (Node or Python): receive PR webhook, run v8 on changed code, post comments
- [ ] Self-hosted inference server (vLLM on RunPod)
- [ ] Landing page (one page, "review your PRs for security bugs")
- [ ] Free tier with rate limits
- [ ] Onboard first 5 friendly testers from network

**Decision gate**: at least 3 testers say "this is useful" -> launch on GitHub Marketplace. Otherwise iterate on UX/quality.

## Sprint 4 (week 9-12): First revenue

**Goal**: first paying customer, validation of pricing.

- [ ] GitHub Marketplace listing
- [ ] Pricing: Free / Team $9 / Pro $19 (see PRODUCT.md)
- [ ] Cold outreach to 50 startups (CTO direct message with finding-report on their public repo)
- [ ] Implement Stripe billing
- [ ] Aim: 5 paying Team customers ($45-225 MRR per customer)

**Decision gate**: ≥3 paying customers -> double down on outbound. <3 -> investigate value-prop messaging.

## Beyond month 3

| Track | Trigger |
|---|---|
| Scale model to 14B | When 7B caps on triage F1 at ≤0.85 after distillation + two-stage |
| GitLab integration | When 30% of inbound asks for it |
| Russian on-prem deal | When first enterprise lead requests FSTEC certification |
| Smart contract niche | If web SAST track stalls, pivot to Solidity using Detect Llama precedent |
| Publication (Cyber-AI / CSNet) | After v8 results are clear, parallel to GTM (does not delay revenue) |

## Budget envelope (months 1-3)

| Item | Cost |
|---|---|
| RunPod persistent volume | $7/mo |
| Compute for experiments (~100 GPU-hours on L40S) | $86 |
| OpenAI/Anthropic API for distillation + baselines | $100-200 |
| HuggingFace Pro (if needed for private datasets) | $0 (free is fine for now) |
| Domain + landing page hosting | $20 |
| **Total months 1-3** | **~$300-500** |

This is the realistic operating budget for the research/MVP phase. No external funding required.

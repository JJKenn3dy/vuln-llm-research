# Product strategy

## Elevator pitch

> A GitHub App that reviews every Pull Request and flags real security vulnerabilities with CWE attribution and clear reasoning. Built on a fine-tuned 7B specialist model that beats GPT-4o on SAST triage and runs on a single GPU for $0.0001 per finding. No 91% false-positive noise, no data leaving your perimeter, $9 per developer per month.

## Why now

Every modern SAST tool (Snyk, Checkmarx, Veracode, Semgrep, GitHub CodeQL) produces enormous alert volumes. Industry benchmarks for 2025-2026:

- OX Security 2026 Application Security Benchmark: 865,398 alerts per enterprise per year, **0.092% critical**.
- Ghost Security: scanned public GitHub with traditional SAST tools, **91% false positives**.
- Average triage time per false positive: 15-30 minutes of developer time.

This pain is driving a new wave of AI-SAST startups, all of which use general-purpose LLMs (GPT-4o, Claude) as the reasoning engine:

- ZeroPath ($1,000/mo + $60/dev), Corgea, Cycode, Pixee, Black Duck Signal (Dec 2025)
- GitLab 18.10 AI-native triage, GitHub Security Lab Taskflow Agent, Datadog Bits AI

**No one has shipped a specialist fine-tuned vulnerability detection model.** Academic precedents (Detect Llama on smart contracts, Wang et al. 2026 SAST replacement) show specialist 7B can beat GPT-4 at 100x lower cost. We have the technology and the data to be that specialist.

## Differentiation

| Dimension | General LLM SAST | Traditional SAST | Our v8 |
|---|---|---|---|
| Cost per finding | $0.01-0.05 (API) | sunk cost | $0.0001 (our GPU) |
| Latency | 5-10 sec | seconds | 200 ms |
| Data exposure | sent to OpenAI/Anthropic | none | none (on-prem) |
| False-positive rate | 30-50% (better than rules) | 60-91% | target < 10% |
| CWE explanations | yes | usually no | yes |
| Setup complexity | API key | days | one click GitHub App |

## Monetization

| Plan | Price | Target |
|---|---|---|
| **Free** | $0 | OSS projects, individual devs. Virality through GitHub Marketplace badges. |
| **Team** | $9/dev/mo | Startups 5-50 people. Main recurring revenue. |
| **Pro** | $19/dev/mo | Mid-market 50-300. Extended CWE coverage, priority support. |
| **Enterprise on-prem** | from $30k/year | Banks, government, fintech. Our model on their infra. |
| **One-shot audit** | $500-2,000 per repo | Pentest firms. Second-opinion tool. |

Unit economics: one L40S pod ($0.86/hour, ~$620/month) handles inference for ~50 mid-sized repos. Four to five Team customers per pod break even. At 100 customers we are at ~$18,000 MRR with one pod.

## Go-to-market wedge

Cold outreach with a finished report on the prospect's own public repo.

> "We ran your `companyname/api-gateway` through our model and found 3 real RCE vulnerabilities your current Snyk missed. Here are the findings, the explanations, and the fix PRs ready to merge. Want them?"

This converts much higher than pitch decks. Mobb and Corgea do this and it works. CISOs see a real bug in their own code and they respond.

## Path to first revenue

```
Months 1-2: v8 triage model trained, beats GPT-4o on SastBench, public leaderboard entry.
Month 3:    GitHub App MVP, free for everyone, 50-100 installs via Marketplace.
Months 3-4: 5-10 paying customers via outbound "we looked at your repo" pitch.
Month 6:    $5-10k MRR. Product-market fit validation.
Month 12:   $30-50k MRR + first enterprise on-prem deal.
```

Realistic for a solo founder or duo. Not a unicorn track. A path to $200-500k ARR in 12-18 months with disciplined execution.

## Open questions to resolve before launch

1. **Distribution**: GitHub App + GitLab integration first? Bitbucket?
2. **Self-serve vs sales-led**: free tier for OSS only, or for individuals up to N repos?
3. **Russian market specifically**: do we go FSTEC-certified for the on-prem deal, or stay international?
4. **Brand and trust**: open-source the lite model on day one, sell hosted/enterprise on top?
5. **Naming**: TBD. Working names: `Vrai`, `Sentry7`, `LintLLM`, `RealVuln`.

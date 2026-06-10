# Product strategy

## Elevator pitch

> A lightweight SAST triage engine that plugs into Semgrep, Snyk, CodeQL and
> GitLab Security, then filters false positives using a fine-tuned 7B specialist
> model. Built for teams that want AI triage without sending code to frontier
> APIs.

We do **not** replace your scanner. We cut the noise that comes after it.

## Positioning

### What v8 is

- A **triage-only layer** on top of any existing SAST scanner
- Input: SARIF / JSON findings from the scanner the customer already runs
- Output: same findings re-labelled as TRUE_POSITIVE or FALSE_POSITIVE with
  evidence (real CWE, reasoning, suggested fix), filtered down to the ones
  worth a human's attention
- Deployment: GitHub App (cloud) or on-prem specialist model for regulated /
  air-gapped environments

### What v8 is NOT

- ❌ "Another AI-SAST" or full AppSec platform (that zone is owned by ZeroPath,
  Aikido, Cycode, Black Duck Signal)
- ❌ A replacement for Snyk or Semgrep
- ❌ An autofix / remediation tool (Mobb, Pixee, GitLab Duo, GitHub Autofix
  already do that, and we should not pick a war with them)
- ❌ A generic code review bot (GitHub Copilot Code Review and Cursor own that
  surface)

See [COMPETITIVE_LANDSCAPE.md](COMPETITIVE_LANDSCAPE.md) for full battle-cards.

## Why now

Industry data for 2025-2026:

- OX Security 2026 Application Security Benchmark: 865 398 alerts per
  enterprise per year. After exploitability/reachability analysis only 0.092%
  were critical.
- Ghost Security scan of public GitHub: 91% false positives across traditional
  SAST tools.
- Triaging a single false positive takes 15-30 min of developer time.

This pain is driving the AI-SAST stack to grow:

- ZeroPath, Pixee, Cycode, Aikido, Black Duck Signal (Dec 2025) on the suite
  side
- GitLab Duo, GitHub Copilot Autofix, Mobb on the remediation side
- All of them use frontier LLMs (GPT-4o, Claude Sonnet) as the reasoner

We measured frontier on our own SAST triage benchmark (100 stratified
TP/FP cases from CVEFixes + CrossVul, project-stratified split):

| Frontier model | F1 | BalAcc | Behaviour |
|---|---|---|---|
| GPT-4o (2024-11) | 0.479 | 0.500 | random |
| GPT-5-chat-latest | 0.395 | 0.540 | barely above random |
| GPT-4.1 | 0.416 | 0.550 | barely above random |
| o3-mini (reasoning) | 0.267 | 0.552 | conservative, misses 84% of bugs |
| Claude Sonnet 4.5 | 0.598 | 0.610 | best frontier, marginal signal |
| Llama 3.3 70B | 0.469 | 0.570 | conservative |
| DeepSeek-Chat | 0.265 | 0.500 | random |

**Nobody at frontier scale solves this task well.** That is the window we
target.

## Differentiation

| Dimension | Frontier-LLM AI-SAST | Traditional SAST | Our v8 |
|---|---|---|---|
| Cost per finding | $0.012-0.05 (API) | sunk cost | $0.0001 (own GPU) |
| Latency | 5-10 sec | seconds | 200 ms |
| Data exposure | sent to OpenAI/Anthropic | none | none (on-prem) |
| Scanner agnostic | varies | n/a | yes (SARIF-first) |
| Replaces existing tools | sometimes claimed | n/a | no, sits on top |

## Monetization

| Plan | Price | Target |
|---|---|---|
| Free | $0 | OSS projects, individual developers. Virality through GitHub Marketplace. |
| Team | $9/dev/mo | Startups 5-50 people. Main recurring revenue. |
| Pro | $19/dev/mo | Mid-market 50-300. Extended CWE coverage, priority support. |
| Enterprise on-prem | from $30k/year | Banks, government, fintech. Our model on their infrastructure. |
| One-shot audit | $500-2000 per repo | Pentest firms. Second-opinion tool. |

Unit economics: one L40S pod ($0.86/h, ~$620/mo) handles inference for ~50
mid-sized repos. Four to five Team customers per pod break even. At 100
customers we are at roughly $18k MRR with one pod.

## Go-to-market wedge

Cold outreach with a finished report on the prospect's own public repo.

> "We ran your `companyname/api-gateway` through our triage model. Your
> existing Snyk found 200 issues; we say 5 are real and the other 195 are
> noise. Here are the 5, including 2 that look exploitable from the network."

This converts much higher than pitch decks. Mobb and Corgea do exactly this.

## Open questions and risks

1. **Final v8 number must be honest.** A weak BalAcc on a full project-stratified
   test breaks the entire thesis. Pitch waits for the number.
2. **Distribution**: GitHub App + GitLab integration first. Bitbucket later if
   demand.
3. **Self-serve vs sales-led**: free tier for OSS only, or for individuals up
   to N repos?
4. **Russian market specifically**: FSTEC-certified for on-prem deals or stay
   international?
5. **Naming**: TBD. Working names: Vrai, Sentry7, LintLLM, RealVuln.

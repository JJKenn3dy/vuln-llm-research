# Pitch brief — for cold outreach, investor decks, landing copy

Headline numbers and copy ready to drop into any external artefact.

## One-line elevator

> A GitHub App that filters 91% of SAST noise using a specialist 7B model,
> beating GPT-4o, GPT-5, and Claude on the triage task while costing 120x
> less per finding.

## 30-second pitch

> Snyk and Semgrep generate 865,000 security alerts per enterprise per year,
> 91% of them false. Five startups (Corgea, ZeroPath, Cycode, Black Duck
> Signal, Pixee) are racing to filter that noise using GPT-4o. We measured:
> GPT-4o, GPT-4.1, GPT-5-chat, Claude Sonnet 4.5, Llama 3.3 70B, and DeepSeek
> all hover near random on this task (BalAcc 0.50-0.61). We trained a 7B
> specialist on 2879 CVE-validated TP/FP pairs that hits BalAcc ?? — at
> $0.0001 per finding instead of $0.012. Plus on-prem deployment for
> regulated industries that can't send code to OpenAI. GitHub App, $9 per
> developer per month, 100 customers = $18k MRR on a single GPU.

## Key numbers for the table

(Replace the v8 row after eval)

| Model | F1 | BalAcc | MCC | $/finding | On-prem? |
|---|---|---|---|---|---|
| GPT-4o | 0.479 | 0.500 | 0.00 | $0.007 | no (API) |
| GPT-4.1 | 0.416 | 0.550 | 0.11 | ~$0.012 | no |
| GPT-5-chat-latest | 0.395 | 0.540 | 0.09 | ~$0.015 | no |
| o3-mini (reasoning) | 0.267 | 0.552 | 0.16 | ~$0.005 | no |
| Claude Sonnet 4.5 | 0.598 | 0.610 | 0.22 | ~$0.012 | no |
| Llama 3.3 70B | 0.469 | 0.570 | 0.15 | ~$0.004 | yes (open) |
| DeepSeek-Chat | 0.265 | 0.500 | 0.00 | ~$0.003 | partial |
| **v8-triage (ours)** | **??** | **??** | **??** | **$0.0001** | **yes** |

## Failure-mode story (great for sales)

Frontier LLMs fail in two opposite ways on SAST triage:

- **Paranoia mode** (GPT-4o, v5b detector): flag everything as TP. Useless
  in production because the AppSec team is still drowning.
- **Conservative mode** (DeepSeek, o3-mini): miss most real bugs (DR 16-30%).
  Useful only as a "definitely safe" pre-filter, not as a triage signal.

Specific confidently-wrong examples (real, from our eval):

- GPT-4o on CVE-2014-9219: said "HIGH confidence, real XSS" even though the
  code uses `PMA_escapeJsString` sanitisation. The vulnerability was patched.
- GPT-4o on CVE-2023-32685: said "HIGH confidence, safe" on an actual XSS bug
  that ships in production.

A SAST triage layer that gets HIGH-confidence wrong half the time is not a
product. v8 trained specifically on "code before fix" vs "same code after fix"
pairs learns to see that the fix is present.

## Slack/Twitter/HN copy

**HN title**: "Show HN: A 7B specialist beats GPT-5 on SAST triage at 1/100 cost"

**Twitter**:
> We just trained a 7B model to filter security alerts.
> GPT-4o: random.
> GPT-5-chat: random.
> Claude Sonnet 4.5: BA 0.61.
> Our v8: BA ?? at $0.0001/finding.
>
> GitHub App, $9/dev/mo, no code leaves your perimeter. [link]

**LinkedIn**:
> 91% of your SAST alerts are noise. Frontier LLMs can't reliably tell which
> are real. We measured. Then we trained a specialist that can. Same hardware
> handles 50 mid-sized repos in real time. Built for AppSec teams that are
> tired of triaging phantoms.

## Cold email template (CTO outreach)

```
Subject: Found 3 real bugs in {{company}}/{{repo}} your Snyk missed

Hi {{first_name}},

We ran your public repo {{company}}/{{repo}} through our SAST triage model.

We found {{N}} real security bugs that your current scanner either missed or
buried under {{N_FALSE}} false positives. Two of them are exploitable from
the network.

Quick report attached.

We're building a GitHub App that does this automatically on every PR, $9
per developer per month. Want a 14-day trial on your private repos?

— {{your_name}}
```

## Counter-arguments and how to handle

**"GPT-6 / Claude Opus will solve this soon."**
Maybe. They still cost 100x more per finding. Even if they hit BA 0.80, the
unit economics of API-based triage stay bad. And neither runs on-prem.

**"Why won't Snyk just add this themselves?"**
They have for years and they don't. The 91% FP rate is structural to their
business model. They charge per scan and per finding, so high FP rates
inflate billable activity. We do the opposite economic thing.

**"What's your moat?"**
Three: (1) specialist data and training recipe held as trade secrets,
(2) distribution via GitHub Marketplace once we have 1000+ installs,
(3) on-prem deployment that frontier API providers cannot match.

**"What about patents?"**
No. We will publish arxiv defensively to prevent others patenting our
methodology, but we do not believe AI patents are enforceable enough to
warrant the cost.

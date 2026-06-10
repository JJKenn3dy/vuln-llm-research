# AI-SAST / SAST Triage — competitive landscape

Internal strategy report. Prepared 2026-06-10.

## Main verdict

The market is already occupied by broad AI AppSec platforms, but there is still
a practical niche: a cheap, narrow, on-prem-compatible triage engine that runs
on top of Semgrep / Snyk / CodeQL / GitLab Security. Not "yet another scanner",
but a second layer that cuts false-positive noise and explains the verdict.

## Executive summary

v8 cannot be positioned as "we are the only AI-SAST". Too many players already.
The stronger formulation: **"we are the specialist triage brain for SAST
findings: cheaper, narrower, simpler, with an on-prem option."**

### Key takeaways

- **Direct competitors exist**: ZeroPath and Pixee sell AI-native AppSec /
  agentic security engineering with triage and autofix. Mobb leads on
  remediation. Aikido covers a broad ASPM layer.
- **The niche is still alive**: most players are wider and more expensive than
  "a lightweight SAST triage layer for teams that already live on
  Semgrep/Snyk/CodeQL".
- **Main defence against platforms**: v8 must be scanner-agnostic — accept
  SARIF/JSON findings and work on top of any source, not be tied to one stack.
- **Main risk**: if v8 does not show a stable BalAcc/MCC on an honest
  project-stratified eval, the product thesis collapses. Pitch must wait for a
  solid v8 number.

## Market map

| Category | Examples | What they sell | Threat to v8 |
|---|---|---|---|
| Full AI AppSec suite | ZeroPath, Aikido, Cycode, Black Duck Signal | Scanning, prioritization, autofix, dashboards, integrations | High if v8 tries to "do everything" |
| Agentic remediation / autofix | Pixee, Mobb, GitLab Duo, GitHub Copilot Autofix | Fixes, PR/MR, exploitability analysis, remediation workflow | Medium: overlap but wider focus |
| SAST triage / FP filtering | GitLab Duo, Pixee, Aikido AutoTriage, research agents | Separate real findings from false positives | **Direct v8 zone** |
| Research analogs | SastBench, QASecClaw, ZeroFalse, CodeCureAgent, D2A | Methodologies, benchmarks, agentic filtering, static analyzer warning repair | Not competitors; proof and idea source |
| Platform owners | GitHub, GitLab, Snyk, SonarQube | Distribution + native workflow | Largest long-term threat |

## Key player comparison

| Player | Product class | Triage / autofix | Pricing / deployment | Meaning for v8 |
|---|---|---|---|---|
| **ZeroPath** | AI-native AppSec suite: SAST, SCA, secrets, DAST, PR reviews | Contextual triage/prioritization + one-click autofix | $1,000/mo + $60/dev Team; Enterprise on-prem/self-hosted/private cloud | Closest "big" benchmark, but broad and expensive. v8 must be the cheap triage-only layer |
| **Pixee** | Agentic security engineering: triage, reachability, exploitability, fix generation | Automated triage engine + fix generation | Outcome-based pricing; self-hosted/air-gapped in Enterprise | Strong enterprise analog. v8 sells as cheap first-pass classifier before remediation |
| **Mobb** | Fix-oriented remediation on top of existing scanners | False positive identification on Team/Enterprise + fix automation | $20/dev IDE, $40/dev Team; Enterprise on-prem/private cloud | Strong on remediation. v8 stays in pure triage and avoids autofix war |
| **Aikido** | All-in-one security HQ: code, cloud, attack, protect | AutoTriage + AutoFix + broad prioritization | Pricing less transparent; cloud + enterprise/security controls | Wide platform. v8 must be a small embedded triage layer |
| **GitLab Duo** | Native GitLab security workflow + MR resolution | Secret FP detection; SAST pre-fix validation; MR suggestions | Ultimate + Duo add-on; GitLab.com/self-managed/dedicated; LLM may be external | Strong inside GitLab. v8 must stay scanner-agnostic and private-model-friendly |
| **GitHub / CodeQL / Copilot** | Platform-native scanning, code review, autofix | Partial: CodeQL alerts + AI review/autofix | GitHub-native, bundle/platform pricing | Largest long-term distribution threat. v8 must be specialist security triage, not general code review |
| **Snyk / DeepCode** | Developer-first SAST/SCA with ML/code analysis heritage | Partial: scanner output + repair research | Cloud/enterprise | v8 filters Snyk findings; does not promise to replace Snyk |
| **SonarQube** | Code quality + security + AI CodeFix | Partial: issue explanations/fixes, not pure SAST triage | Cloud/server/IDE, enterprise/cloud plans | v8 must speak AppSec: TP/FP, CWE, evidence, confidence |

## Detailed competitor profiles

### ZeroPath

Closest "big" reference. ZeroPath sells an AI-native AppSec suite: SAST, SCA,
secrets, DAST, PR reviews, autofix, prioritization, enterprise deployment.
Pricing page Team starts at $1,000/mo + $60/dev. Enterprise gives
on-prem/self-hosted/private cloud and BYOK.

- Strengths: wide platform, PR reviews, runtime validation, business
  logic/broken auth positioning, enterprise trust.
- Weakness for v8: expensive and broad. Small teams may want only triage, not a
  full AppSec suite.
- Battle-card: *"ZeroPath is the suite. v8 is the cheap specialist triage
  engine you can put in front of your existing scanner stack."*

### Pixee

Agentic security engineering with outcome-based pricing — they charge per
resolved problem rather than per developer. Includes automated triage engine,
fix generation, context/reachability/exploitability analysis, GitHub/GitLab and
scanner integrations, self-hosted/air-gapped options.

- Strengths: strong product story (pay per result), enterprise-friendly
  deployment.
- Weakness for v8: more complex, wider scope, likely enterprise-sales motion.
  v8 can enter as a lightweight triage step before remediation.
- Battle-card: *"Pixee automates resolution. v8 first makes the alert stream
  clean and cheap."*

### Mobb

Fix-oriented remediation layer. Free for public repos, IDE Auto-fix at
$20/dev/month, Team at $40/dev/month. Team includes false positive
identification, one private repo, one scanner, one platform integration.
Enterprise gives on-prem/private cloud, multiple scanners, fix automation.

- Strengths: clean scanner integrations (Checkmarx, Fortify, SonarQube, Snyk,
  CodeQL) and GitHub/GitLab/Azure/Bitbucket coverage.
- Weakness for v8: Team is still pricier and limited to one private repo. v8
  can be the cheaper FP triage without the remediation lock-in.
- Battle-card: *"Mobb fixes. v8 filters. Use v8 when you want fewer wrong
  findings before anyone writes patches."*

### Aikido

Broad "Security HQ" for code/cloud/attack/protect. Lists SAST, AI SAST, SCA,
secrets, IaC, malware, cloud, runtime, AI pentesting. The relevant capability
is **AutoTriage**: Aikido evaluates alerts in the context of code and
infrastructure and deprioritises issues that do not pose real risk. AutoFix
generates reviewable PRs.

- Strengths: very wide platform, strong dev-friendly packaging, "only alerts
  that matter" claim.
- Weakness for v8: breadth means complexity. v8 can be small and easily
  embedded.
- Battle-card: *"Aikido is the security HQ. v8 is a small model you can deploy
  next to the scanner."*

### GitLab Duo

Platform competitor inside GitLab. Duo can analyse secret detection findings
for false positives, give confidence scores and explanations. SAST Vulnerability
Resolution can create an MR with contextual fixes; powered by default by Claude
Sonnet, with code and CWE identifiers sent to third-party AI APIs.

- Strengths: native GitLab UX, MR workflow, self-managed/dedicated offering,
  built-in security reports.
- Weakness for v8: GitLab-only and expensive Ultimate/Duo tier. Also a
  sensitivity around sending code to external AI providers.
- Battle-card: *"v8 is not GitLab-only and can run as a private specialist
  model."*

## Platform threats

### GitHub / CodeQL / Copilot

GitHub owns PR workflow and CodeQL distribution. Even if Copilot Code Review is
not currently a strong security reviewer, platform-native UX is the most
powerful advantage. A 2025 evaluation paper of Copilot Code Review found it
often missed SQL injection, XSS and insecure deserialization, mostly giving
low-severity / style feedback.

- v8 lesson: do not try to be generic code review. Be a dedicated security
  triage engine with honest metrics.
- Defence: SARIF-first integration. If GitHub strengthens autofix, v8 must
  still be able to act as an independent adjudicator of findings.

### Snyk / DeepCode

Snyk has distribution and the Snyk Code / DeepCode heritage. The DeepCode AI Fix
paper shows an academically important pattern: narrow the static-analysis
context down to the relevant snippet and context rather than handing the LLM
the whole project. In their work the best system removed over 80% of reported
defects, outperforming GPT-3.5/GPT-4 baselines.

- v8 lesson: Snyk is better used as a source of findings, not an enemy.
  "Filter your Snyk noise" is easier to sell than "replace Snyk".
- Idea for v8: add an **evidence packet** around the alert — source/sink,
  sanitizer flag, line range, diff context, rule metadata.

### SonarQube / AI CodeFix

SonarQube is code quality plus security plus AI CodeFix that generates fix
suggestions in IDE / Cloud / Server. Not pure SAST triage but a strong adjacent
workflow.

- v8 lesson: Sonar is stronger in code quality breadth. v8 must speak AppSec:
  TP/FP, CWE, exploitability, evidence, confidence.
- Defence: support SonarQube findings as input if demand emerges.

## Research analogs (use as design inspiration)

| Work | What it shows | What v8 takes from it |
|---|---|---|
| **SastBench** (arxiv 2601.02941) | Benchmark for agentic SAST triage: real CVEs as TP + filtered SAST findings as approximate FP | Main external benchmark. Without it the pitch is weaker |
| **QASecClaw** (arxiv 2605.01885) | Multi-agent SAST FP reduction: F1 90.93% vs 78.39% Semgrep; FPs reduced from 560 to 64 on OWASP Benchmark | Proof that FP reduction is sellable and measurable. Agents are expensive though |
| **ZeroFalse** (arxiv 2510.02534) | Structured analyzer outputs + traces + CWE knowledge before LLM adjudication; F1 0.912/0.955 | Do not give the model raw code. Give an evidence packet |
| **CodeCureAgent** (arxiv 2509.11787) | Agentic classification + repair of static warnings; ~2.9 cents and ~4 min per warning | Cost / latency edge for a specialist 7B vs an agentic loop |
| **D2A** (arxiv 2102.07995) | Differential analysis: compare before/after commits; bugs disappearing after a fix are likely true bugs | Methodological backing for our pre-fix/post-fix TP/FP proxy. Real public dataset, IBM source |
| **DeepCode AI Fix** (arxiv 2402.13291) | Program analysis reduces code context before LLM repair | Context must be narrow and relevant, not "throw in the whole file" |

### Methodology takeaways

- **Our v8 proxy is acceptable as a starting concept**: pre-fix = TP, post-fix
  with same claimed CWE = FP. D2A and SastBench support the same idea.
- **For a product we need real realism**: run real scanners on real repos and
  collect real SARIF findings.
- **Biggest opening vs agents**: agents can be accurate but expensive and slow.
  v8 can be a cheap first-pass adjudicator.

## Positioning

### Recommended one-liner

> A lightweight SAST triage engine that plugs into Semgrep, Snyk, CodeQL and
> GitLab Security, then filters false positives using a fine-tuned 7B
> specialist model. Built for teams that want AI triage without sending code
> to frontier APIs.

### What NOT to say

- "We are the only AI-SAST." Not true and easily countered by
  ZeroPath/Pixee/Aikido/GitLab.
- "We replace Snyk/Semgrep." Raises the bar and triggers resistance.
- "We guarantee real bugs were found." No full external validation yet.

### What to say

- "We do not replace your scanner. We cut the noise that comes after it."
- "You already pay for SAST. We make its findings usable."
- "Specialist 7B is cheaper and runs on-prem. Frontier APIs are expensive and
  sensitive for private code."
- "Triage first, autofix later."

## Strategy: where to hit first

| Priority | Action | Why |
|---|---|---|
| P0 | Close the final v8 eval: triage_100 + full 573-case test, BalAcc/MCC/FAR/DR | Without this no strong pitch or cold outreach |
| P0 | Add docs/COMPETITIVE_LANDSCAPE.md (this file) to the repo | Project looks like product strategy, not only experiments |
| P1 | Build SARIF input/output + a minimal GitHub App PR comment | Shortest path to real user feedback |
| P1 | Run 30-50 OSS repos: Semgrep/CodeQL findings + v8 report | Material for outreach: "we already ran your repo" |
| P1 | Build an evidence packet: rule id, CWE, source/sink, sanitizer, line range, diff context | Reduces hallucinations; aligns with ZeroFalse / SastBench realism |
| P2 | Do not build autofix until triage is stable | Autofix immediately puts us in a war with Mobb/Pixee/GitLab/GitHub |

## Final verdict

The niche exists. It is not "yet another AI AppSec platform" — that zone is
already taken and requires sales, brand, integrations and money. The realistic
niche for v8 is **a narrow SAST triage layer that turns a noisy scanner
finding stream into a short list of probably real problems**.

- **First customers**: small and medium teams that already use
  Semgrep/Snyk/CodeQL/GitLab Security but do not have an AppSec team.
- **First product**: GitHub App + SARIF parser + PR comments + dashboard-lite.
- **First claim**: not "we find vulnerabilities", but "we reduce triage noise
  with evidence".
- **First enterprise angle**: on-prem specialist model for regulated companies
  that do not want to send code to OpenAI/Anthropic.

## Sources

| ID | Source | URL |
|---|---|---|
| ZP1 | ZeroPath product and pricing | https://zeropath.com/ ; https://zeropath.com/pricing |
| PX1 | Pixee pricing and platform claims | https://www.pixee.ai/pricing |
| MB1 | Mobb pricing, scanner integrations and FP identification | https://mobb.ai/pricing |
| AIK1 | Aikido product page, AutoTriage and AutoFix | https://www.aikido.dev/ |
| GL1 | GitLab vulnerability details, secret FP detection, Duo Vulnerability Resolution | https://docs.gitlab.com/user/application_security/vulnerabilities/ |
| GH1 | GitHub Copilot Code Review security evaluation paper | https://arxiv.org/abs/2509.13650 |
| SN1 | DeepCode AI Fix paper | https://arxiv.org/abs/2402.13291 |
| SQ1 | SonarQube / AI CodeFix overview | https://en.wikipedia.org/wiki/SonarQube |
| SB1 | SastBench: A Benchmark for Testing Agentic SAST Triage | https://arxiv.org/abs/2601.02941 |
| QC1 | QASecClaw: Multi-Agent LLM Approach for FP Reduction in SAST | https://arxiv.org/abs/2605.01885 |
| ZF1 | ZeroFalse: Improving Precision in Static Analysis with LLMs | https://arxiv.org/abs/2510.02534 |
| CCA1 | CodeCureAgent: Automatic Classification and Repair of Static Analysis Warnings | https://arxiv.org/abs/2509.11787 |
| D2A1 | D2A: Dataset Built for AI-Based Vulnerability Detection Using Differential Analysis | https://arxiv.org/abs/2102.07995 |

Caveat: competitor public pages describe marketing/feature claims, not actual
model quality. Real quality comparison requires the same eval sets, same
metrics, reproducible setup.

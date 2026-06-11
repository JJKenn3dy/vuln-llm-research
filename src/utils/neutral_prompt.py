"""Neutral triage prompt for fair frontier comparison.

Per reviewer 2026-06-11 evening: when comparing a fine-tuned specialist
to frontier API models, our TRIAGE_USER_TEMPLATE may be unfamiliar to
the frontier prompt — biasing the comparison. Running frontier with a
second neutral prompt and reporting the better of the two closes the
"you gave frontier an unfamiliar format" attack.

The neutral prompt asks for the same Verdict: TRUE_POSITIVE/FALSE_POSITIVE
first line so the same parse regex still applies. Reasoning is freeform.
"""
from __future__ import annotations

NEUTRAL_SYSTEM = (
    "You are an expert security engineer triaging static analysis output. "
    "Your job is to decide whether a flagged finding is a true positive "
    "(real vulnerability) or a false positive (noise). Be concise."
)

NEUTRAL_USER_TEMPLATE = """A Semgrep static analysis run flagged the following code as potentially vulnerable.

Finding details:
- Tool: {tool}
- Claimed CWE: {cwe}
- Severity: {severity}
- File: {file_path}
- Lines: {line_range}

Code:
{code}

Decide whether this is a real vulnerability or noise. Respond on the first line with exactly:
Verdict: TRUE_POSITIVE
or:
Verdict: FALSE_POSITIVE

Then add one short paragraph explaining the decision.
"""


def render_neutral_messages(
    *,
    tool: str,
    cwe: str,
    severity: str,
    file_path: str,
    line_range: str,
    code: str,
) -> list[dict[str, str]]:
    user = NEUTRAL_USER_TEMPLATE.format(
        tool=tool,
        cwe=cwe,
        severity=severity,
        file_path=file_path,
        line_range=line_range,
        code=code,
    )
    return [
        {"role": "system", "content": NEUTRAL_SYSTEM},
        {"role": "user", "content": user},
    ]

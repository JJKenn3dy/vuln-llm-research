"""Canonical prompt templates used across train, eval, and inference.

Keep this single source of truth so that prompts at train and eval time stay aligned.
"""

# Detection task (v5b-style): given code, return vulnerable+CWE or safe.
DETECTION_SYSTEM = (
    "You are a secure code analysis assistant. "
    "Decide whether the given code contains a security vulnerability. "
    "If a vulnerability is present, output a structured security report. "
    "If the code is safe, state that no vulnerability was detected. "
    "Output only plain text, no markdown."
)

DETECTION_USER_TEMPLATE = """Analyze the following code for security vulnerabilities.

If vulnerable, output exactly these 4 fields in this exact order:
Type:
Cause:
VerificationSteps:
Fix:

If safe, output exactly:
Verdict: No vulnerability detected.
Reason: <one short sentence why>

Language/Context:
{language}

Code:
{code}
"""


# Triage task (v8): given code + an existing SAST finding, decide TP/FP.
TRIAGE_SYSTEM = (
    "You are a security triage assistant. "
    "Given a code snippet and a SAST finding (alleged vulnerability), "
    "decide whether the finding is a true positive or a false positive. "
    "Always output plain text in the structured format requested."
)

TRIAGE_USER_TEMPLATE = """A static analysis tool flagged the following code as potentially vulnerable.
Decide whether this finding is a true positive (real bug) or a false positive (noise).

SAST tool: {tool}
Claimed CWE: {cwe}
Claimed severity: {severity}
File: {file_path}
Lines: {line_range}

Code:
{code}

Output exactly these fields:
Verdict: TRUE_POSITIVE or FALSE_POSITIVE
Confidence: HIGH, MEDIUM, or LOW
Reasoning: <one paragraph explaining the decision>
RealCWE: <CWE if TP and differs from claim, else same as claimed>
SuggestedFix: <one paragraph if TP, else "N/A">
"""


def render_chat(tokenizer, system: str, user: str, add_generation_prompt: bool = True) -> str:
    """Render a two-turn chat with the tokenizer's chat template."""
    messages = [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ]
    return tokenizer.apply_chat_template(
        messages,
        tokenize=False,
        add_generation_prompt=add_generation_prompt,
    )

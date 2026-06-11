"""Triage verdict types and SARIF output parser.

Mirrors the Verdict/Confidence/Reasoning/RealCWE/SuggestedFix format that
TRIAGE_USER_TEMPLATE asks the model to emit. Same regex as
src.eval.run_triage_eval to guarantee identical parsing semantics.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

VERDICT_RE = re.compile(
    r"^\s*Verdict:\s*(TRUE_POSITIVE|FALSE_POSITIVE|TP|FP)\b",
    re.IGNORECASE | re.MULTILINE,
)
CONF_RE = re.compile(
    r"^\s*Confidence:\s*(HIGH|MEDIUM|LOW)\b",
    re.IGNORECASE | re.MULTILINE,
)
REASONING_RE = re.compile(
    r"^\s*Reasoning:\s*(.+?)(?=\n\s*(?:RealCWE|SuggestedFix):|$)",
    re.IGNORECASE | re.MULTILINE | re.DOTALL,
)
REAL_CWE_RE = re.compile(
    r"^\s*RealCWE:\s*(CWE-\d+|N/A)\b",
    re.IGNORECASE | re.MULTILINE,
)
SUGGESTED_FIX_RE = re.compile(
    r"^\s*SuggestedFix:\s*(.+?)$",
    re.IGNORECASE | re.MULTILINE | re.DOTALL,
)

TRUE_POSITIVE = "TRUE_POSITIVE"
FALSE_POSITIVE = "FALSE_POSITIVE"
PARSE_FAIL = "PARSE_FAIL"


@dataclass
class Verdict:
    verdict: str
    confidence: str
    reasoning: str
    real_cwe: str
    suggested_fix: str
    raw_response: str


def parse(response: str) -> Verdict:
    return Verdict(
        verdict=_verdict(response),
        confidence=_confidence(response),
        reasoning=_reasoning(response),
        real_cwe=_real_cwe(response),
        suggested_fix=_suggested_fix(response),
        raw_response=response,
    )


def _verdict(text: str) -> str:
    m = VERDICT_RE.search(text)
    if not m:
        return PARSE_FAIL
    v = m.group(1).upper()
    if v in ("TP", "TRUE_POSITIVE"):
        return TRUE_POSITIVE
    if v in ("FP", "FALSE_POSITIVE"):
        return FALSE_POSITIVE
    return PARSE_FAIL


def _confidence(text: str) -> str:
    m = CONF_RE.search(text)
    return m.group(1).upper() if m else ""


def _reasoning(text: str) -> str:
    m = REASONING_RE.search(text)
    return m.group(1).strip() if m else ""


def _real_cwe(text: str) -> str:
    m = REAL_CWE_RE.search(text)
    return m.group(1).upper() if m else ""


def _suggested_fix(text: str) -> str:
    m = SUGGESTED_FIX_RE.search(text)
    return m.group(1).strip() if m else ""

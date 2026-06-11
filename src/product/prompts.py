"""Triage prompt rendering for the product surface.

Wraps src.utils.prompts.TRIAGE_SYSTEM / TRIAGE_USER_TEMPLATE so the
product code does not duplicate the canonical template. Same wording as
training and eval to keep distribution consistent.
"""
from __future__ import annotations

from src.utils.prompts import TRIAGE_SYSTEM, TRIAGE_USER_TEMPLATE


def build_triage_messages(
    *,
    tool: str,
    cwe: str,
    severity: str,
    file_path: str,
    line_range: str,
    code: str,
) -> list[dict[str, str]]:
    user = TRIAGE_USER_TEMPLATE.format(
        tool=tool,
        cwe=cwe,
        severity=severity,
        file_path=file_path,
        line_range=line_range,
        code=code,
    )
    return [
        {"role": "system", "content": TRIAGE_SYSTEM},
        {"role": "user", "content": user},
    ]

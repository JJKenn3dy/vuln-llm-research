"""Deterministic mock backend.

Verdict policy: if the finding's claimed_cwe is in the configured
true_cwes set, mark TRUE_POSITIVE; otherwise FALSE_POSITIVE. Used in
tests and dry-run CLI mode where loading a 7B model is overkill.

Score policy: returns a deterministic p_tp in [0,1] that orders findings
sensibly by CWE membership + a small jitter from the snippet hash so
ranking output is not constant across findings of the same CWE.
"""
from __future__ import annotations

import hashlib
from typing import Optional

from . import TriageRequest


class MockBackend:
    def __init__(self, true_cwes: Optional[set[str]] = None) -> None:
        self.true_cwes = true_cwes or set()

    def infer(self, req: TriageRequest) -> str:
        verdict = "TRUE_POSITIVE" if req.claimed_cwe in self.true_cwes else "FALSE_POSITIVE"
        confidence = "HIGH"
        reasoning = (
            f"Mock verdict based on claimed_cwe={req.claimed_cwe}. "
            f"Snippet length={len(req.code)} chars."
        )
        real_cwe = req.claimed_cwe if verdict == "TRUE_POSITIVE" else "N/A"
        fix = "Validate and sanitize input at the sink." if verdict == "TRUE_POSITIVE" else "N/A"
        return (
            f"Verdict: {verdict}\n"
            f"Confidence: {confidence}\n"
            f"Reasoning: {reasoning}\n"
            f"RealCWE: {real_cwe}\n"
            f"SuggestedFix: {fix}\n"
        )

    def score_p_tp(self, req: TriageRequest) -> Optional[float]:
        base = 0.70 if req.claimed_cwe in self.true_cwes else 0.30
        jitter = int(hashlib.sha1(req.code.encode("utf-8", errors="replace")).hexdigest()[:4], 16)
        delta = (jitter / 0xFFFF) * 0.20 - 0.10
        return max(0.0, min(1.0, base + delta))

    def close(self) -> None:
        return None

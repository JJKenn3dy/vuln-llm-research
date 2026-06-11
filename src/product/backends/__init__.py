"""Inference backends for the triage product.

Backend = a callable that takes a TriageRequest and returns either:
  - raw model response string (filter mode), or
  - first-token p_tp probability (ranker mode)

Parsing into Verdict happens upstream in the orchestrator so backends
stay narrow.

  - local: HF transformers + LoRA, same loading path as run_triage_eval
  - vllm:  OpenAI-compatible HTTP endpoint pointed at a vLLM server
  - mock:  deterministic stub for tests (no model needed)
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Protocol


@dataclass
class TriageRequest:
    finding_id: str
    tool: str
    claimed_cwe: str
    severity: str
    file_path: str
    line_range: str
    code: str


class TriageBackend(Protocol):
    def infer(self, req: TriageRequest) -> str: ...
    def score_p_tp(self, req: TriageRequest) -> Optional[float]: ...
    def close(self) -> None: ...

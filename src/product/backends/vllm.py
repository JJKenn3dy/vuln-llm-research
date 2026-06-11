"""vLLM (OpenAI-compatible HTTP) backend.

Targets `vllm serve` with `--enable-lora`. Same chat template, but the
chat completion endpoint owns rendering. base_url should include the
`/v1` suffix (e.g. http://pod:8000/v1).

score_p_tp uses `logprobs=True, top_logprobs=20` on the first generated
token (max_tokens=1) and sums probabilities over TP/FP token prefixes
returned by the server. This is approximate compared to a forced-prefix
forward pass: the model has to be willing to emit "Verdict:" or
equivalent as its actual first token under greedy sampling. Smoke test
on real vLLM before claiming latency/quality numbers.
"""
from __future__ import annotations

import math
from typing import Optional

from . import TriageRequest

TP_PREFIXES = {"TRUE", " TRUE", "TP", " TP", "true", " true"}
FP_PREFIXES = {"FALSE", " FALSE", "FP", " FP", "false", " false"}


class VLLMBackend:
    def __init__(
        self,
        base_url: str,
        model: str,
        api_key: str = "EMPTY",
        max_new_tokens: int = 400,
        timeout: float = 60.0,
    ) -> None:
        from openai import OpenAI

        self.client = OpenAI(api_key=api_key, base_url=base_url, timeout=timeout)
        self.model = model
        self.max_new_tokens = max_new_tokens

    def infer(self, req: TriageRequest) -> str:
        from ..prompts import build_triage_messages

        messages = build_triage_messages(
            tool=req.tool,
            cwe=req.claimed_cwe,
            severity=req.severity,
            file_path=req.file_path,
            line_range=req.line_range,
            code=req.code,
        )
        resp = self.client.chat.completions.create(
            model=self.model,
            messages=messages,
            temperature=0.0,
            max_tokens=self.max_new_tokens,
        )
        return resp.choices[0].message.content or ""

    def score_p_tp(self, req: TriageRequest) -> Optional[float]:
        from ..prompts import build_triage_messages

        messages = build_triage_messages(
            tool=req.tool,
            cwe=req.claimed_cwe,
            severity=req.severity,
            file_path=req.file_path,
            line_range=req.line_range,
            code=req.code,
        )
        ext = list(messages)
        ext.append({"role": "assistant", "content": "Verdict: "})
        try:
            resp = self.client.chat.completions.create(
                model=self.model,
                messages=ext,
                temperature=0.0,
                max_tokens=1,
                logprobs=True,
                top_logprobs=20,
            )
        except Exception:
            return None

        choice = resp.choices[0]
        if not getattr(choice, "logprobs", None) or not choice.logprobs.content:
            return None
        first = choice.logprobs.content[0]
        top = getattr(first, "top_logprobs", None) or []
        p_tp = 0.0
        p_fp = 0.0
        for entry in top:
            token = entry.token
            prob = math.exp(entry.logprob)
            if token in TP_PREFIXES:
                p_tp += prob
            elif token in FP_PREFIXES:
                p_fp += prob
        denom = p_tp + p_fp
        return p_tp / denom if denom > 0 else None

    def close(self) -> None:
        return None

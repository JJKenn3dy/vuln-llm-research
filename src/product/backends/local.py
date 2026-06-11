"""HF Transformers + LoRA backend.

Mirrors src.eval.run_triage_eval.run_local: load base model + adapter once,
render the chat template, generate greedy, return raw text. Heavy import
of torch/transformers/peft is lazy so the rest of src.product imports on
machines without a GPU stack.

score_p_tp reuses the extract_triage_logprobs approach: append the literal
"Verdict: " to the chat template, single forward pass, normalize the
TRUE/FALSE token probabilities. Reviewer rule (NEXT_STEPS P4): ranker
output MUST come from real logprobs, not text-verdict-to-1/0 mapping.
"""
from __future__ import annotations

from typing import Optional

from . import TriageRequest

VERDICT_PREFIX = "Verdict: "
TP_PREFIXES = ["TRUE", " TRUE", "TP", " TP"]
FP_PREFIXES = ["FALSE", " FALSE", "FP", " FP"]


class LocalBackend:
    def __init__(
        self,
        base_model: str,
        adapter_dir: Optional[str],
        max_new_tokens: int = 400,
    ) -> None:
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer

        self._torch = torch
        self.max_new_tokens = max_new_tokens
        self.tokenizer = AutoTokenizer.from_pretrained(base_model, trust_remote_code=True)
        model = AutoModelForCausalLM.from_pretrained(
            base_model,
            torch_dtype=torch.float16,
            device_map="auto",
            trust_remote_code=True,
        )
        if adapter_dir and adapter_dir.lower() != "none":
            from peft import PeftModel

            model = PeftModel.from_pretrained(model, adapter_dir)
        model.eval()
        self.model = model

        self._tp_ids = self._resolve_token_ids(TP_PREFIXES)
        self._fp_ids = self._resolve_token_ids(FP_PREFIXES)

    def _resolve_token_ids(self, prefixes: list[str]) -> list[int]:
        ids = set()
        for s in prefixes:
            toks = self.tokenizer(s, add_special_tokens=False).input_ids
            if toks:
                ids.add(toks[0])
        return sorted(ids)

    def _render(self, req: TriageRequest, force_verdict_prefix: bool) -> str:
        from ..prompts import build_triage_messages

        messages = build_triage_messages(
            tool=req.tool,
            cwe=req.claimed_cwe,
            severity=req.severity,
            file_path=req.file_path,
            line_range=req.line_range,
            code=req.code,
        )
        rendered = self.tokenizer.apply_chat_template(
            messages, tokenize=False, add_generation_prompt=True
        )
        if force_verdict_prefix:
            rendered = rendered + VERDICT_PREFIX
        return rendered

    def infer(self, req: TriageRequest) -> str:
        rendered = self._render(req, force_verdict_prefix=False)
        inputs = self.tokenizer(rendered, return_tensors="pt").to(self.model.device)
        with self._torch.no_grad():
            output = self.model.generate(
                **inputs,
                max_new_tokens=self.max_new_tokens,
                do_sample=False,
                pad_token_id=self.tokenizer.eos_token_id,
            )
        generated = output[0][inputs["input_ids"].shape[1]:]
        return self.tokenizer.decode(generated, skip_special_tokens=True).strip()

    def score_p_tp(self, req: TriageRequest) -> Optional[float]:
        rendered = self._render(req, force_verdict_prefix=True)
        inputs = self.tokenizer(rendered, return_tensors="pt").to(self.model.device)
        with self._torch.no_grad():
            out = self.model(**inputs)
        logits = out.logits[0, -1]
        probs = self._torch.softmax(logits.float(), dim=-1)
        p_tp = float(probs[self._tp_ids].sum().item()) if self._tp_ids else 0.0
        p_fp = float(probs[self._fp_ids].sum().item()) if self._fp_ids else 0.0
        denom = p_tp + p_fp
        return p_tp / denom if denom > 0 else 0.5

    def close(self) -> None:
        del self.model
        del self.tokenizer
        try:
            self._torch.cuda.empty_cache()
        except Exception:
            pass

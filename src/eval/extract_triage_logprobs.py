"""Extract first-token TRUE_POSITIVE vs FALSE_POSITIVE probabilities for triage.

The triage prompt asks the model to emit a structured response starting with:

    Verdict: TRUE_POSITIVE or FALSE_POSITIVE

The model's first decision token after "Verdict: " is either "TRUE" or "FALSE"
(after BPE tokenisation). Reading the logits at that position gives us the
calibration signal:

    p_tp = P("TRUE" | context) / (P("TRUE") + P("FALSE"))

Sweeping a threshold over p_tp recovers the model's confidence even when the
surface decoding (greedy) is biased. This is the same trick we used for v5b
detection where threshold 0.40 lifted F1 from 0.78 to 0.86.

Output JSON: list of records with case_id, true_verdict, p_tp, project_id.
Feed into src/eval/calibrate.py to sweep threshold.

Example:

    python -m src.eval.extract_triage_logprobs \\
        --base-model /workspace/models/qwen2.5-coder-7b-instruct \\
        --adapter-dir /workspace/adapters/v8_first \\
        --input /workspace/runs/triage_100_sample.json \\
        --output /workspace/runs/v8_triage100_logprobs.json
"""
from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path

import torch
from peft import PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer


VERDICT_PREFIX = "Verdict: "
# The decision token strings we'll check at the first position after "Verdict: "
# Different tokenisers may use different leading whitespace handling, so we try
# several candidates and accumulate probability mass.
TP_PREFIXES = ["TRUE", " TRUE", "TP", " TP"]
FP_PREFIXES = ["FALSE", " FALSE", "FP", " FP"]


def log(msg: str) -> None:
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)


def first_token_id_of(tokenizer, s: str) -> int | None:
    """Return the first BPE token id of `s`, or None if not representable."""
    ids = tokenizer(s, add_special_tokens=False).input_ids
    return ids[0] if ids else None


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Extract TP/FP first-token logprobs for triage calibration")
    p.add_argument("--base-model", default="Qwen/Qwen2.5-Coder-7B-Instruct")
    p.add_argument("--adapter-dir", required=True)
    p.add_argument("--input", required=True)
    p.add_argument("--output", required=True)
    return p.parse_args()


def main() -> None:
    args = parse_args()

    log(f"Loading tokenizer: {args.base_model}")
    tokenizer = AutoTokenizer.from_pretrained(args.base_model, trust_remote_code=True)

    log(f"Loading base model: {args.base_model}")
    model = AutoModelForCausalLM.from_pretrained(
        args.base_model,
        torch_dtype=torch.float16,
        device_map="auto",
        trust_remote_code=True,
    )
    log(f"Loading LoRA adapter: {args.adapter_dir}")
    model = PeftModel.from_pretrained(model, args.adapter_dir)
    model.eval()

    # Pre-resolve candidate token ids
    tp_ids = {first_token_id_of(tokenizer, s) for s in TP_PREFIXES}
    fp_ids = {first_token_id_of(tokenizer, s) for s in FP_PREFIXES}
    tp_ids.discard(None)
    fp_ids.discard(None)
    log(f"TP candidate token ids: {sorted(tp_ids)}")
    log(f"FP candidate token ids: {sorted(fp_ids)}")

    with open(args.input, encoding="utf-8") as f:
        cases = json.load(f)
    log(f"Eval cases: {len(cases)}")

    results = []
    for i, ex in enumerate(cases):
        md = ex.get("metadata", {})
        true_verdict = md.get("verdict", "UNKNOWN")
        case_id = str(md.get("case_id") or md.get("cve_id") or md.get("project_id") or f"case_{i}")

        # Render prompt with chat template + add "Verdict: " as forced prefix so
        # the next token logits directly correspond to the TRUE/FALSE decision.
        messages = ex["messages"][:2]
        prompt = tokenizer.apply_chat_template(
            messages, tokenize=False, add_generation_prompt=True
        ) + VERDICT_PREFIX

        inputs = tokenizer(prompt, return_tensors="pt").to(model.device)
        with torch.no_grad():
            out = model(**inputs)
        logits = out.logits[0, -1]  # last position logits
        probs = torch.softmax(logits.float(), dim=-1)

        p_tp = float(probs[list(tp_ids)].sum().item()) if tp_ids else 0.0
        p_fp = float(probs[list(fp_ids)].sum().item()) if fp_ids else 0.0
        denom = p_tp + p_fp
        p_tp_norm = p_tp / denom if denom > 0 else 0.5

        results.append({
            "case_id": case_id,
            "project_id": md.get("project_id"),
            "claimed_cwe": md.get("claimed_cwe"),
            "language": md.get("language"),
            "true_verdict": true_verdict,
            # cast to triage convention used by calibrate.py:
            "true_label": "vulnerable" if true_verdict == "TRUE_POSITIVE" else "safe",
            "p_tp_raw": p_tp,
            "p_fp_raw": p_fp,
            "p_vuln": p_tp_norm,  # name kept for compatibility with calibrate.py
        })

        if (i + 1) % 20 == 0:
            log(f"  [{i+1}/{len(cases)}]")

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)

    # Quick distribution summary
    tp_vals = sorted(r["p_vuln"] for r in results if r["true_verdict"] == "TRUE_POSITIVE")
    fp_vals = sorted(r["p_vuln"] for r in results if r["true_verdict"] == "FALSE_POSITIVE")
    def median(xs): return xs[len(xs) // 2] if xs else 0.0
    log(f"p_tp median on real TPs : {median(tp_vals):.3f}  (n={len(tp_vals)})")
    log(f"p_tp median on real FPs : {median(fp_vals):.3f}  (n={len(fp_vals)})")
    log(f"gap (TP - FP medians)   : {median(tp_vals) - median(fp_vals):.3f}")
    log(f"Wrote {args.output}")


if __name__ == "__main__":
    main()

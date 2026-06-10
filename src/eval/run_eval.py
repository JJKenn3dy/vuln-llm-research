"""Cloud-agnostic eval entrypoint.

Replaces run_eval_v5b.py and similar. Loads a LoRA adapter on top of the base model
and runs greedy generation over an eval JSON, then computes detection metrics.

Example:

    python -m src.eval.run_eval \\
        --adapter-dir /workspace/adapters/v5b \\
        --input-file data/eval/eval_v5_inputs.json \\
        --output-file /workspace/runs/v5b_eval_outputs.json \\
        --metrics-file /workspace/runs/v5b_eval_metrics.json
"""
from __future__ import annotations

import argparse
import json
import re
from datetime import datetime
from pathlib import Path

import torch
from peft import PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer

from src.utils.metrics import confusion, derived_metrics, per_cwe_detection


SAFE_VERDICT_RE = re.compile(
    r"^\s*Verdict:\s*No vulnerability detected\.", re.IGNORECASE | re.MULTILINE
)
TYPE_CWE_RE = re.compile(r"^\s*Type:\s*(CWE-\d+)", re.IGNORECASE | re.MULTILINE)
STRUCT_FIELDS = ("Type:", "Cause:", "VerificationSteps:", "Fix:")


def log(msg: str) -> None:
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)


def classify_response(response: str) -> str:
    return "safe" if SAFE_VERDICT_RE.search(response) else "vulnerable"


def predicted_cwe(response: str) -> str:
    m = TYPE_CWE_RE.search(response)
    return m.group(1).upper() if m else ""


def is_structured(response: str) -> bool:
    return all(f in response for f in STRUCT_FIELDS)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Eval LoRA adapter on a vulnerability detection set")
    p.add_argument("--base-model", default="Qwen/Qwen2.5-Coder-7B-Instruct")
    p.add_argument("--adapter-dir", required=True, help="Path to LoRA adapter, or 'none' for base model only")
    p.add_argument("--input-file", required=True)
    p.add_argument("--output-file", required=True)
    p.add_argument("--metrics-file", required=True)
    p.add_argument("--max-new-tokens", type=int, default=600)
    p.add_argument("--save-every", type=int, default=10)
    return p.parse_args()


def load_model(base_model: str, adapter_dir: str):
    log(f"Loading tokenizer: {base_model}")
    tokenizer = AutoTokenizer.from_pretrained(base_model, trust_remote_code=True)

    log(f"Loading base model: {base_model}")
    model = AutoModelForCausalLM.from_pretrained(
        base_model,
        torch_dtype=torch.float16,
        device_map="auto",
        trust_remote_code=True,
    )

    if adapter_dir and adapter_dir.lower() != "none":
        log(f"Loading LoRA adapter: {adapter_dir}")
        model = PeftModel.from_pretrained(model, adapter_dir)

    model.eval()
    return tokenizer, model


def run_eval(args: argparse.Namespace) -> None:
    tokenizer, model = load_model(args.base_model, args.adapter_dir)

    with open(args.input_file, encoding="utf-8") as f:
        cases = json.load(f)
    log(f"Eval cases: {len(cases)}")

    Path(args.output_file).parent.mkdir(parents=True, exist_ok=True)
    Path(args.metrics_file).parent.mkdir(parents=True, exist_ok=True)

    results = []
    for i, ex in enumerate(cases):
        md = ex.get("metadata", {})
        true_label = md.get("label", "unknown")
        true_cwe = md.get("cwe_id", "")
        case_id = md.get("cve_id") or md.get("id") or f"case_{i}"
        log(f"[{i+1}/{len(cases)}] {case_id} | true={true_label}/{true_cwe}")

        messages = ex["messages"][:2]
        rendered = tokenizer.apply_chat_template(
            messages, tokenize=False, add_generation_prompt=True
        )
        inputs = tokenizer(rendered, return_tensors="pt").to(model.device)

        with torch.no_grad():
            output = model.generate(
                **inputs,
                max_new_tokens=args.max_new_tokens,
                do_sample=False,
                pad_token_id=tokenizer.eos_token_id,
            )

        generated = output[0][inputs["input_ids"].shape[1]:]
        response = tokenizer.decode(generated, skip_special_tokens=True).strip()

        pred_label = classify_response(response)
        pred_cwe = predicted_cwe(response)
        structured = is_structured(response)

        results.append({
            "case_id": case_id,
            "true_label": true_label,
            "true_cwe": true_cwe,
            "predicted_label": pred_label,
            "predicted_cwe": pred_cwe,
            "structured": structured,
            "model_response": response,
        })
        log(f"  pred={pred_label}/{pred_cwe} | structured={structured}")

        if (i + 1) % args.save_every == 0:
            with open(args.output_file, "w", encoding="utf-8") as f:
                json.dump(results, f, ensure_ascii=False, indent=2)

    with open(args.output_file, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)

    pairs = [(r["true_label"], r["predicted_label"]) for r in results]
    c = confusion(pairs)
    d = derived_metrics(c)

    tp_results = [r for r in results if r["true_label"] == "vulnerable" and r["predicted_label"] == "vulnerable"]
    cwe_correct = sum(1 for r in tp_results if r["predicted_cwe"] == r["true_cwe"])
    cwe_acc = cwe_correct / len(tp_results) if tp_results else 0.0
    struct_rate = sum(1 for r in tp_results if r["structured"]) / len(tp_results) if tp_results else 0.0

    metrics = {
        "n_total": len(results),
        "n_vuln": c["TP"] + c["FN"],
        "n_safe": c["TN"] + c["FP"],
        **c,
        **d,
        "cwe_accuracy_on_tp": cwe_acc,
        "structural_rate_on_tp": struct_rate,
        "per_cwe_detection": per_cwe_detection(results),
    }
    with open(args.metrics_file, "w", encoding="utf-8") as f:
        json.dump(metrics, f, ensure_ascii=False, indent=2)

    log("=" * 60)
    log(f"DONE: {args.output_file}, {args.metrics_file}")
    log(f"TP={c['TP']} FN={c['FN']} TN={c['TN']} FP={c['FP']}")
    log(f"DR={d['detection_rate']:.3f}  FAR={d['false_alarm_rate']:.3f}  F1={d['f1']:.3f}  BA={d['balanced_accuracy']:.3f}")
    log(f"CWE accuracy on TP: {cwe_acc:.3f}  Structural: {struct_rate:.3f}")


def main() -> None:
    run_eval(parse_args())


if __name__ == "__main__":
    main()

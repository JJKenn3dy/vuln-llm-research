"""Eval a model on the triage TP/FP task.

Supports two backends:
  - local: load base + LoRA adapter and run greedy generation
  - api:   call OpenAI / Anthropic chat completion endpoint

Computes:
  - TP/FN/TN/FP counts (TRUE_POSITIVE = positive class)
  - DR, FAR, Precision, F1, BalAcc, MCC
  - Per-CWE breakdown
  - Verdict-parsing failure rate (model didn't emit a valid Verdict line)

Example:

    # Local LoRA
    python -m src.eval.run_triage_eval \\
        --backend local \\
        --base-model /workspace/models/qwen2.5-coder-7b-instruct \\
        --adapter-dir /workspace/adapters/v8_first \\
        --input data/train/triage_v8_from_v7lite/triage_test.json \\
        --output /workspace/runs/v8_triage_test_outputs.json \\
        --metrics /workspace/runs/v8_triage_test_metrics.json

    # GPT-4o baseline
    python -m src.eval.run_triage_eval \\
        --backend api --api openai --model gpt-4o-2024-11-20 \\
        --input data/train/triage_v8_from_v7lite/triage_test.json \\
        --output /workspace/runs/gpt4o_triage_test_outputs.json \\
        --metrics /workspace/runs/gpt4o_triage_test_metrics.json
"""
from __future__ import annotations

import argparse
import json
import math
import os
import re
import time
from collections import Counter
from datetime import datetime
from pathlib import Path


VERDICT_RE = re.compile(r"^\s*Verdict:\s*(TRUE_POSITIVE|FALSE_POSITIVE|TP|FP)\b",
                        re.IGNORECASE | re.MULTILINE)
CONF_RE = re.compile(r"^\s*Confidence:\s*(HIGH|MEDIUM|LOW)\b", re.IGNORECASE | re.MULTILINE)
REALCWE_RE = re.compile(r"^\s*RealCWE:\s*(CWE-\d+|N/A)\b", re.IGNORECASE | re.MULTILINE)


def log(msg: str) -> None:
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)


def parse_verdict(response: str) -> str:
    m = VERDICT_RE.search(response)
    if not m:
        return "PARSE_FAIL"
    v = m.group(1).upper()
    if v in ("TP", "TRUE_POSITIVE"):
        return "TRUE_POSITIVE"
    if v in ("FP", "FALSE_POSITIVE"):
        return "FALSE_POSITIVE"
    return "PARSE_FAIL"


def parse_real_cwe(response: str) -> str:
    m = REALCWE_RE.search(response)
    return m.group(1).upper() if m else ""


def parse_confidence(response: str) -> str:
    m = CONF_RE.search(response)
    return m.group(1).upper() if m else ""


def confusion(predictions: list[tuple[str, str]]) -> dict:
    tp = fn = tn = fp = parse_fail = 0
    for true, pred in predictions:
        if pred == "PARSE_FAIL":
            parse_fail += 1
            continue
        if true == "TRUE_POSITIVE" and pred == "TRUE_POSITIVE":
            tp += 1
        elif true == "TRUE_POSITIVE" and pred == "FALSE_POSITIVE":
            fn += 1
        elif true == "FALSE_POSITIVE" and pred == "FALSE_POSITIVE":
            tn += 1
        elif true == "FALSE_POSITIVE" and pred == "TRUE_POSITIVE":
            fp += 1
    return {"TP": tp, "FN": fn, "TN": tn, "FP": fp, "PARSE_FAIL": parse_fail}


def derived(c: dict) -> dict:
    tp, fn, tn, fp = c["TP"], c["FN"], c["TN"], c["FP"]
    n_pos = tp + fn
    n_neg = tn + fp
    dr = tp / n_pos if n_pos else 0.0
    far = fp / n_neg if n_neg else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = dr
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) else 0.0
    bal_acc = 0.5 * (dr + (1.0 - far))
    denom = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    mcc = ((tp * tn) - (fp * fn)) / denom if denom else 0.0
    return {
        "detection_rate": dr,
        "false_alarm_rate": far,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "balanced_accuracy": bal_acc,
        "mcc": mcc,
    }


# ---------------------------- Backends ----------------------------

def run_local(args: argparse.Namespace, cases: list[dict]) -> list[dict]:
    import torch
    from peft import PeftModel
    from transformers import AutoModelForCausalLM, AutoTokenizer

    log(f"Loading tokenizer: {args.base_model}")
    tokenizer = AutoTokenizer.from_pretrained(args.base_model, trust_remote_code=True)

    log(f"Loading base model: {args.base_model}")
    model = AutoModelForCausalLM.from_pretrained(
        args.base_model,
        torch_dtype=torch.float16,
        device_map="auto",
        trust_remote_code=True,
    )

    if args.adapter_dir and args.adapter_dir.lower() != "none":
        log(f"Loading LoRA adapter: {args.adapter_dir}")
        model = PeftModel.from_pretrained(model, args.adapter_dir)
    model.eval()

    results = []
    for i, ex in enumerate(cases):
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
        results.append(_make_record(ex, response, i, len(cases)))
        if (i + 1) % 20 == 0:
            log(f"  [{i+1}/{len(cases)}]")
    return results


def run_api(args: argparse.Namespace, cases: list[dict]) -> list[dict]:
    if args.api == "openai":
        from openai import OpenAI
        client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])
    elif args.api == "openrouter":
        from openai import OpenAI
        client = OpenAI(
            api_key=os.environ["OPENROUTER_API_KEY"],
            base_url="https://openrouter.ai/api/v1",
        )
    elif args.api == "anthropic":
        from anthropic import Anthropic
        client = Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
    else:
        raise ValueError(f"unknown api: {args.api}")

    results = []
    for i, ex in enumerate(cases):
        messages = ex["messages"][:2]
        try:
            if args.api in ("openai", "openrouter"):
                is_reasoning = args.model.startswith(("o1", "o3", "o4"))
                kwargs = {
                    "model": args.model,
                    "messages": messages,
                }
                if is_reasoning:
                    # o-series: no temperature, use max_completion_tokens
                    # and budget more tokens for hidden reasoning
                    kwargs["max_completion_tokens"] = max(args.max_new_tokens, 1500)
                else:
                    kwargs["temperature"] = 0.0
                    kwargs["max_tokens"] = args.max_new_tokens
                resp = client.chat.completions.create(**kwargs)
                response = resp.choices[0].message.content or ""
            else:
                resp = client.messages.create(
                    model=args.model,
                    system=messages[0]["content"],
                    messages=[{"role": "user", "content": messages[1]["content"]}],
                    max_tokens=args.max_new_tokens,
                )
                response = resp.content[0].text
        except Exception as e:
            log(f"  [{i+1}/{len(cases)}] API error: {e}")
            response = f"API_ERROR: {e}"
            time.sleep(2)

        results.append(_make_record(ex, response, i, len(cases)))
        if (i + 1) % 20 == 0:
            log(f"  [{i+1}/{len(cases)}]")
    return results


def _make_record(ex: dict, response: str, i: int, total: int) -> dict:
    md = ex.get("metadata", {})
    true_verdict = md.get("verdict", "UNKNOWN")
    pred_verdict = parse_verdict(response)
    return {
        "i": i,
        "case_id": md.get("case_id") or md.get("cve_id") or md.get("project_id") or f"case_{i}",
        "claimed_cwe": md.get("claimed_cwe"),
        "real_cwe": md.get("real_cwe"),
        "true_verdict": true_verdict,
        "predicted_verdict": pred_verdict,
        "predicted_confidence": parse_confidence(response),
        "predicted_real_cwe": parse_real_cwe(response),
        "model_response": response,
    }


# ---------------------------- Entry ----------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Eval a model on triage TP/FP examples")
    p.add_argument("--backend", choices=["local", "api"], required=True)
    p.add_argument("--input", required=True)
    p.add_argument("--output", required=True)
    p.add_argument("--metrics", required=True)
    p.add_argument("--max-new-tokens", type=int, default=400)
    # local
    p.add_argument("--base-model", default="Qwen/Qwen2.5-Coder-7B-Instruct")
    p.add_argument("--adapter-dir", default=None)
    # api
    p.add_argument("--api", choices=["openai", "openrouter", "anthropic"], default="openai")
    p.add_argument("--model", default="gpt-4o-2024-11-20")
    return p.parse_args()


def main() -> None:
    args = parse_args()

    with open(args.input, encoding="utf-8") as f:
        cases = json.load(f)
    log(f"Eval cases: {len(cases)}")

    if args.backend == "local":
        results = run_local(args, cases)
    else:
        results = run_api(args, cases)

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)

    pairs = [(r["true_verdict"], r["predicted_verdict"]) for r in results]
    c = confusion(pairs)
    d = derived(c)

    by_cwe_count = Counter(r["claimed_cwe"] for r in results)
    cwe_match = Counter()
    for r in results:
        if (r["predicted_verdict"] == "TRUE_POSITIVE" and
            r["true_verdict"] == "TRUE_POSITIVE"):
            if r["predicted_real_cwe"] and r["predicted_real_cwe"] == r["real_cwe"]:
                cwe_match[r["claimed_cwe"]] += 1

    metrics = {
        "n_total": len(results),
        **c,
        **d,
        "parse_fail_rate": c["PARSE_FAIL"] / len(results) if results else 0.0,
        "per_claimed_cwe_count": dict(by_cwe_count.most_common()),
        "per_claimed_cwe_cwe_match": dict(cwe_match.most_common()),
    }
    Path(args.metrics).parent.mkdir(parents=True, exist_ok=True)
    with open(args.metrics, "w", encoding="utf-8") as f:
        json.dump(metrics, f, ensure_ascii=False, indent=2)

    log("=" * 60)
    log(f"DONE: {args.output}, {args.metrics}")
    log(f"TP={c['TP']} FN={c['FN']} TN={c['TN']} FP={c['FP']} parse_fail={c['PARSE_FAIL']}")
    log(f"DR={d['detection_rate']:.3f}  FAR={d['false_alarm_rate']:.3f}  "
        f"F1={d['f1']:.3f}  BA={d['balanced_accuracy']:.3f}  MCC={d['mcc']:.3f}")


if __name__ == "__main__":
    main()

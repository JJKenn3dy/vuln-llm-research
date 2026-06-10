"""
Eval для v5b: тот же eval-100 hold-out, но загружает qlora_output_v5b.
Различия с run_eval_v5.py — только пути ADAPTER_DIR / OUTPUT_FILE / METRICS_FILE.
"""
import json
import re
import torch
from datetime import datetime
from collections import Counter
from transformers import AutoTokenizer, AutoModelForCausalLM
from peft import PeftModel

BASE_MODEL  = "Qwen/Qwen2.5-Coder-7B-Instruct"
ADAPTER_DIR = "qlora_output_v5b"
INPUT_FILE  = "eval_v5_inputs.json"
OUTPUT_FILE = "eval_v5b_outputs.json"
METRICS_FILE = "metrics_v5b.json"

SAFE_VERDICT_RE = re.compile(r"^\s*Verdict:\s*No vulnerability detected\.", re.IGNORECASE | re.MULTILINE)
TYPE_CWE_RE = re.compile(r"^\s*Type:\s*(CWE-\d+)", re.IGNORECASE | re.MULTILINE)
STRUCT_FIELDS = ("Type:", "Cause:", "VerificationSteps:", "Fix:")


def log(msg):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)


def classify_response(response: str) -> str:
    return "safe" if SAFE_VERDICT_RE.search(response) else "vulnerable"


def predicted_cwe(response: str) -> str:
    m = TYPE_CWE_RE.search(response)
    return m.group(1).upper() if m else ""


def is_structured(response: str) -> bool:
    return all(f in response for f in STRUCT_FIELDS)


def main():
    log("Loading tokenizer...")
    tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL, trust_remote_code=True)

    log("Loading base model...")
    model = AutoModelForCausalLM.from_pretrained(
        BASE_MODEL,
        torch_dtype=torch.float16,
        device_map="auto",
        trust_remote_code=True,
    )

    log(f"Loading LoRA adapter: {ADAPTER_DIR}...")
    model = PeftModel.from_pretrained(model, ADAPTER_DIR)
    model.eval()
    log("Model ready.")

    with open(INPUT_FILE, encoding="utf-8") as f:
        cases = json.load(f)
    log(f"Eval cases: {len(cases)}")

    results = []
    for i, ex in enumerate(cases):
        md = ex["metadata"]
        true_label = md["label"]
        true_cwe = md["cwe_id"]
        cve_id = md["cve_id"]
        log(f"[{i+1}/{len(cases)}] {cve_id} | true={true_label}/{true_cwe}")

        messages = [
            ex["messages"][0],
            ex["messages"][1],
        ]
        rendered = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
        inputs = tokenizer(rendered, return_tensors="pt").to(model.device)

        with torch.no_grad():
            output = model.generate(
                **inputs,
                max_new_tokens=600,
                do_sample=False,
                pad_token_id=tokenizer.eos_token_id,
            )

        generated = output[0][inputs["input_ids"].shape[1]:]
        response = tokenizer.decode(generated, skip_special_tokens=True).strip()

        pred_label = classify_response(response)
        pred_cwe = predicted_cwe(response)
        structured = is_structured(response)

        results.append({
            "cve_id": cve_id,
            "true_label": true_label,
            "true_cwe": true_cwe,
            "predicted_label": pred_label,
            "predicted_cwe": pred_cwe,
            "structured": structured,
            "model_response": response,
        })
        log(f"  pred={pred_label}/{pred_cwe} | structured={structured}")

        if (i + 1) % 10 == 0:
            with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
                json.dump(results, f, ensure_ascii=False, indent=2)
            log(f"  saved: {i+1}/{len(cases)}")

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)

    tp = sum(1 for r in results if r["true_label"] == "vulnerable" and r["predicted_label"] == "vulnerable")
    fn = sum(1 for r in results if r["true_label"] == "vulnerable" and r["predicted_label"] == "safe")
    tn = sum(1 for r in results if r["true_label"] == "safe" and r["predicted_label"] == "safe")
    fp = sum(1 for r in results if r["true_label"] == "safe" and r["predicted_label"] == "vulnerable")

    total_vuln = tp + fn
    total_safe = tn + fp
    detection_rate = tp / total_vuln if total_vuln else 0.0
    false_alarm_rate = fp / total_safe if total_safe else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = detection_rate
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) else 0.0

    tp_results = [r for r in results if r["true_label"] == "vulnerable" and r["predicted_label"] == "vulnerable"]
    cwe_correct = sum(1 for r in tp_results if r["predicted_cwe"] == r["true_cwe"])
    cwe_accuracy = cwe_correct / len(tp_results) if tp_results else 0.0

    structured_tp = sum(1 for r in tp_results if r["structured"])
    structural_rate = structured_tp / len(tp_results) if tp_results else 0.0

    by_cwe = {}
    for r in results:
        if r["true_label"] != "vulnerable":
            continue
        c = r["true_cwe"]
        by_cwe.setdefault(c, {"tp": 0, "fn": 0})
        if r["predicted_label"] == "vulnerable":
            by_cwe[c]["tp"] += 1
        else:
            by_cwe[c]["fn"] += 1
    per_cwe_detection = {c: v["tp"] / (v["tp"] + v["fn"]) if (v["tp"]+v["fn"]) else 0.0 for c, v in by_cwe.items()}

    metrics = {
        "n_total": len(results),
        "n_vuln": total_vuln,
        "n_safe": total_safe,
        "TP": tp, "FN": fn, "TN": tn, "FP": fp,
        "detection_rate": detection_rate,
        "false_alarm_rate": false_alarm_rate,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "cwe_accuracy_on_tp": cwe_accuracy,
        "structural_rate_on_tp": structural_rate,
        "per_cwe_detection": per_cwe_detection,
    }
    with open(METRICS_FILE, "w", encoding="utf-8") as f:
        json.dump(metrics, f, ensure_ascii=False, indent=2)

    log("=" * 60)
    log(f"DONE: {OUTPUT_FILE}, {METRICS_FILE}")
    log(f"TP={tp} FN={fn} TN={tn} FP={fp}")
    log(f"Detection Rate: {detection_rate:.3f}")
    log(f"False Alarm Rate: {false_alarm_rate:.3f}")
    log(f"Precision: {precision:.3f} | Recall: {recall:.3f} | F1: {f1:.3f}")
    log(f"CWE accuracy (on TP): {cwe_accuracy:.3f}")
    log(f"Structural rate (on TP): {structural_rate:.3f}")


if __name__ == "__main__":
    main()

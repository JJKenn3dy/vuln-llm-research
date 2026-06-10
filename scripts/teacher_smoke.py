"""A/B/C/... compare candidate teacher models for FP-reasoning generation.

Lesson 0 from docs/HISTORY.md: v8.1 collapsed because all FP training examples
used the same 279-char template. The model learned the surface stylistic
discriminator instead of pre/post semantics. For v8.2 we need per-sample
varied FP reasoning - this script picks the teacher empirically.

Default candidate set covers current (June 2026) frontier non-reasoning models.
Discovered from /v1/models on both OpenAI and OpenRouter on 2026-06-10:
  - openai_gpt55           gpt-5.5                  (released 2026-04-23, flagship)
  - openai_gpt54           gpt-5.4                  (released 2026-03-05, solid mid)
  - openai_gpt54_mini      gpt-5.4-mini             (cheap, test if it suffices)
  - openrouter_opus48      anthropic/claude-opus-4.8 (released 2026-05-28, top Anthropic)
  - openrouter_sonnet_lat  anthropic/claude-sonnet-latest (= Sonnet 4.7 mid)
  - openrouter_fable5      anthropic/claude-fable-5  (released 2026-06-09, "most capable GA")
  - openrouter_deepseek4   deepseek/deepseek-v4-pro  (wild card: ultra-cheap)

Metrics (HIGH variance, HIGH specificity, LOW template-fraction wins;
cost is the tiebreaker):
  - Lexical variance: mean pairwise Jaccard distance over 4-grams
  - Specificity: % of answers naming a concrete identifier from the code
  - Template-y-ness: % of answers with the "either ... or ..." pattern (v8.1 trap)
  - Avg length (words)
  - $ cost (input+output tokens, list prices)

Usage:
    python scripts/teacher_smoke.py \\
        --input data/eval/fresh_cves_60_detection.json \\
        --n 10 \\
        --output runs/teacher_ab.json

    # Custom subset:
    python scripts/teacher_smoke.py --candidates openai_gpt41,openrouter_opus47 ...
"""
from __future__ import annotations

import argparse
import json
import os
import re
import statistics
import time
from collections import Counter
from datetime import datetime
from pathlib import Path


FP_PROMPT_TEMPLATE = """A static analysis tool flagged the code below as a potential {cwe} vulnerability.
The code is actually safe - the vulnerability has been patched.

Your task: explain in 2-3 sentences why this is a FALSE POSITIVE.

Requirements:
- Reference at least one specific identifier from the code (function name, variable, API call).
- Mention the concrete defensive pattern that makes this safe (sanitisation, validation, parameterised query, etc.).
- Do NOT use the phrase "either ... or ..." or any other generic enumeration.
- Output only the explanation paragraph. No headers, no JSON, no markdown.

Code:
{code}
"""


# Prices per 1M tokens (input, output) verified via /v1/models on 2026-06-10.
# Rough estimate per call: prompt ~ 400 tokens, answer ~ 100 tokens.
TEACHER_REGISTRY: dict[str, dict] = {
    "openai_gpt55": {
        "backend": "openai",
        "model": "gpt-5.5",
        "input_per_m": 5.00,
        "output_per_m": 30.00,
        "label": "GPT-5.5 (2026-04-23, flagship)",
    },
    "openai_gpt54": {
        "backend": "openai",
        "model": "gpt-5.4",
        "input_per_m": 2.50,
        "output_per_m": 15.00,
        "label": "GPT-5.4 (2026-03-05)",
    },
    "openai_gpt54_mini": {
        "backend": "openai",
        "model": "gpt-5.4-mini",
        "input_per_m": 0.75,
        "output_per_m": 4.50,
        "label": "GPT-5.4-mini (cheap)",
    },
    "openrouter_opus48": {
        "backend": "openrouter",
        "model": "anthropic/claude-opus-4.8",
        "input_per_m": 5.00,
        "output_per_m": 25.00,
        "label": "Opus 4.8 (2026-05-28)",
    },
    "openrouter_sonnet46": {
        "backend": "openrouter",
        "model": "anthropic/claude-sonnet-4.6",
        "input_per_m": 3.00,
        "output_per_m": 15.00,
        "label": "Sonnet 4.6 (current Anthropic mid)",
    },
    "openrouter_haiku45": {
        "backend": "openrouter",
        "model": "anthropic/claude-haiku-4.5",
        "input_per_m": 1.00,
        "output_per_m": 5.00,
        "label": "Haiku 4.5 (cheap Anthropic)",
    },
    "openrouter_deepseek4": {
        "backend": "openrouter",
        "model": "deepseek/deepseek-v4-pro",
        "input_per_m": 0.435,
        "output_per_m": 0.87,
        "label": "DeepSeek-v4-pro (ultra cheap wild card)",
    },
}

DEFAULT_CANDIDATES = [
    "openai_gpt55",
    "openai_gpt54",
    "openai_gpt54_mini",
    "openrouter_opus48",
    "openrouter_sonnet46",
    "openrouter_haiku45",
    "openrouter_deepseek4",
]


def log(msg: str) -> None:
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)


def extract_code(user_message: str) -> str:
    m = re.search(r"Code:\s*\n(.*?)(?:\n\nAnswer:|\Z)", user_message, re.DOTALL)
    return m.group(1).strip() if m else user_message


def n_grams(text: str, n: int = 4) -> set[str]:
    tokens = re.findall(r"\w+", text.lower())
    return {" ".join(tokens[i:i + n]) for i in range(max(0, len(tokens) - n + 1))}


def jaccard_distance(a: set, b: set) -> float:
    if not a and not b:
        return 0.0
    return 1.0 - len(a & b) / len(a | b)


def lexical_variance(answers: list[str]) -> float:
    grams = [n_grams(a) for a in answers]
    pairs = [(i, j) for i in range(len(grams)) for j in range(i + 1, len(grams))]
    if not pairs:
        return 0.0
    return statistics.mean(jaccard_distance(grams[i], grams[j]) for i, j in pairs)


def specificity_rate(answers: list[str], codes: list[str]) -> float:
    hits = 0
    stop = {"true", "false", "none", "null", "self", "this", "return", "import",
            "from", "function", "const", "class", "public", "private", "static",
            "void", "string", "char", "echo", "print", "require", "include",
            "code", "vulnerability", "positive"}
    for ans, code in zip(answers, codes):
        idents = set(re.findall(r"[a-zA-Z_][a-zA-Z0-9_]{3,}", code)) - stop
        ans_tokens = set(re.findall(r"[a-zA-Z_][a-zA-Z0-9_]{3,}", ans))
        if idents & ans_tokens:
            hits += 1
    return hits / max(1, len(answers))


def template_rate(answers: list[str]) -> float:
    pattern = re.compile(r"\beither\b.*?\bor\b", re.IGNORECASE)
    hits = sum(1 for a in answers if pattern.search(a))
    return hits / max(1, len(answers))


def avg_word_count(answers: list[str]) -> float:
    return statistics.mean(len(a.split()) for a in answers) if answers else 0.0


def cost_per_call(meta: dict, prompt_tokens: int = 400, output_tokens: int = 100) -> float:
    return (prompt_tokens * meta["input_per_m"] + output_tokens * meta["output_per_m"]) / 1_000_000


def call_one(backend: str, model: str, prompt: str) -> tuple[str, float]:
    """Single-shot call. Raises on persistent failure.

    GPT-5+ on OpenAI direct API requires max_completion_tokens instead of
    max_tokens, and rejects custom temperature. We detect those and adjust.
    """
    from openai import OpenAI
    if backend == "openai":
        client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])
    elif backend == "openrouter":
        client = OpenAI(
            api_key=os.environ["OPENROUTER_API_KEY"],
            base_url="https://openrouter.ai/api/v1",
        )
    else:
        raise ValueError(f"unknown backend {backend}")

    is_new_openai = backend == "openai" and (
        model.startswith(("gpt-5", "o1", "o3", "o4", "o5"))
    )
    kwargs: dict = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
    }
    if is_new_openai:
        kwargs["max_completion_tokens"] = 300
        # temperature is not customisable on GPT-5+ (only default 1.0 allowed)
    else:
        kwargs["temperature"] = 0.7
        kwargs["max_tokens"] = 300

    t0 = time.time()
    resp = client.chat.completions.create(**kwargs)
    return (resp.choices[0].message.content or "").strip(), time.time() - t0


def analyse(key: str, meta: dict, answers: list[str], codes: list[str], elapsed: list[float]) -> dict:
    cpc = cost_per_call(meta)
    valid_elapsed = [t for t in elapsed if t > 0]
    metrics = {
        "key": key,
        "label": meta["label"],
        "model": meta["model"],
        "backend": meta["backend"],
        "n": len(answers),
        "n_error": sum(1 for a in answers if a.startswith("ERROR:")),
        "lexical_variance_jaccard4": round(lexical_variance([a for a in answers if not a.startswith("ERROR:")]), 4),
        "specificity_rate": round(specificity_rate(answers, codes), 4),
        "template_pattern_rate": round(template_rate(answers), 4),
        "avg_word_count": round(avg_word_count(answers), 1),
        "avg_latency_sec": round(statistics.mean(valid_elapsed), 2) if valid_elapsed else 0.0,
        "cost_per_call_usd": round(cpc, 6),
        "total_cost_usd": round(len(answers) * cpc, 4),
    }
    log(f"{key}: {json.dumps({k: v for k, v in metrics.items() if k not in ('key', 'label', 'model', 'backend')})}")
    return metrics


def pick_winner(metrics_list: list[dict]) -> str:
    """Score = variance + specificity - template_rate. Tiebreak: lower cost."""
    valid = [m for m in metrics_list if m["n_error"] < m["n"]]
    if not valid:
        return ""
    valid.sort(key=lambda m: (
        -(m["lexical_variance_jaccard4"] + m["specificity_rate"] - m["template_pattern_rate"]),
        m["cost_per_call_usd"],
    ))
    return valid[0]["key"]


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="A/B candidate teacher models for FP reasoning")
    p.add_argument("--input", default="data/eval/fresh_cves_60_detection.json")
    p.add_argument("--n", type=int, default=10)
    p.add_argument("--output", default="runs/teacher_ab.json")
    p.add_argument("--candidates", default=",".join(DEFAULT_CANDIDATES),
                   help="Comma-separated TEACHER_REGISTRY keys to test")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    candidates = [c.strip() for c in args.candidates.split(",") if c.strip()]
    for c in candidates:
        if c not in TEACHER_REGISTRY:
            raise SystemExit(f"unknown candidate {c}; choose from {list(TEACHER_REGISTRY)}")

    with open(args.input, encoding="utf-8") as f:
        data = json.load(f)
    safe_cases = [d for d in data if d.get("metadata", {}).get("label") == "safe"]
    sample = safe_cases[:args.n] if len(safe_cases) >= args.n else safe_cases
    log(f"Testing {len(candidates)} teachers on {len(sample)} safe (post-fix) cases")

    codes: list[str] = []
    cwes: list[str] = []
    per_teacher_answers: dict[str, list[str]] = {c: [] for c in candidates}
    per_teacher_elapsed: dict[str, list[float]] = {c: [] for c in candidates}

    for i, case in enumerate(sample, 1):
        user_msg = case["messages"][1]["content"]
        code = extract_code(user_msg)
        md = case["metadata"]
        cwe = md.get("cwe_id", "CWE-?")
        cve = md.get("cve_id", "")
        codes.append(code)
        cwes.append(cwe)

        prompt = FP_PROMPT_TEMPLATE.format(cwe=cwe, code=code)
        summary_parts = []
        for c in candidates:
            meta = TEACHER_REGISTRY[c]
            try:
                a, t = call_one(meta["backend"], meta["model"], prompt)
                per_teacher_answers[c].append(a)
                per_teacher_elapsed[c].append(t)
                summary_parts.append(f"{c}={len(a)}ch/{t:.1f}s")
            except Exception as e:
                per_teacher_answers[c].append(f"ERROR: {e}")
                per_teacher_elapsed[c].append(0.0)
                summary_parts.append(f"{c}=ERR({type(e).__name__})")
        log(f"  [{i}/{len(sample)}] {cve} {cwe}: " + " | ".join(summary_parts))

    metrics_list = []
    for c in candidates:
        m = analyse(c, TEACHER_REGISTRY[c], per_teacher_answers[c], codes, per_teacher_elapsed[c])
        metrics_list.append(m)

    winner = pick_winner(metrics_list)
    log(f"==> WINNER: {winner} ({TEACHER_REGISTRY[winner]['label'] if winner else 'NONE'})")

    report = {
        "n_samples": len(sample),
        "candidates": candidates,
        "metrics": metrics_list,
        "winner": winner,
        "samples": [
            {
                "cve_id": sample[i]["metadata"].get("cve_id", ""),
                "cwe": cwes[i],
                "code_excerpt": codes[i][:300],
                "answers": {c: per_teacher_answers[c][i] for c in candidates},
            }
            for i in range(len(sample))
        ],
    }
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    log(f"==> Wrote {args.output}")


if __name__ == "__main__":
    main()

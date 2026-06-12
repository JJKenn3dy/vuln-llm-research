"""Regenerate the assistant reasoning for TP rows in v8.3.1 training data
using Claude Haiku 4.5 via OpenRouter. Replaces hallucinated CVE-style
boilerplate ("vulnerability was found in [PROJECT] up to [VERSION]...")
with concrete, snippet-grounded reasoning + actionable suggested fix.

Why: see docs and project_practical_smoke_2026_06_11.md — 100% of TP rows
across all v8.3.x training data contain copy-pasted NVD descriptions.
The model learned to hallucinate fake CVE references at inference time
(observed on NodeGoat / devonz / DVWA top-K filter pass).

Strategy:
  - Verdict, code, claimed_cwe are kept verbatim from the original row
    (truth labels do not change)
  - Only Reasoning + SuggestedFix are regenerated
  - Haiku is told to describe ONLY the code shown, no fictional CVEs

Usage:
  # Smoke 10 rows to inspect output before full batch
  python scripts/regenerate_tp_reasoning.py \\
      --in data/train/triage_v8_3_1/train_merged.json \\
      --out data/train/triage_v8_3_2/train_merged_clean.json \\
      --limit 10 --smoke

  # Full TP-only regeneration
  python scripts/regenerate_tp_reasoning.py \\
      --in data/train/triage_v8_3_1/train_merged.json \\
      --out data/train/triage_v8_3_2/train_merged_clean.json \\
      --skip-fp
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Any

try:
    import urllib.request
    import urllib.error
except Exception:
    print("urllib unavailable", file=sys.stderr)
    raise


MODEL = "meta-llama/llama-3.3-70b-instruct"
OR_ENDPOINT = "https://openrouter.ai/api/v1/chat/completions"
TOKEN_PATHS = [
    Path("C:/Users/zahar/.openrouter_token"),
    Path.home() / ".openrouter_token",
    Path("/workspace/.openrouter_token"),
]


SYSTEM = (
    "You rewrite security-triage explanations. You are given a code snippet, "
    "a claimed CWE, and the ground-truth verdict (TRUE_POSITIVE or FALSE_POSITIVE). "
    "Your job: write a short concrete explanation grounded only in the code shown.\n\n"
    "STRICT RULES:\n"
    "1. Describe ONLY the snippet you are given. Do NOT invent CVE entries, "
    "project names, versions, patch SHAs, or commit messages.\n"
    "2. Do NOT use phrases like 'A vulnerability was found in <project>', "
    "'upstream fix commit', 'Upgrading to version X', 'see CVE notes', 'patch identifier', "
    "'VDB-NNNN', 'git-svn-id', 'It has been declared/classified as critical'.\n"
    "3. For TP: identify the specific dangerous operation in this code "
    "(e.g. 'eval(req.body.preTax) executes attacker-controlled input as code') "
    "and the concrete fix (e.g. 'replace eval with parseFloat and validate the range').\n"
    "4. For FP: name the concrete reason the snippet is NOT exploitable "
    "(e.g. 'the input is wrapped in parameterized query placeholders').\n"
    "5. Output exactly these fields in this order, no markdown, no extra text:\n"
    "Verdict: <copy the ground truth>\n"
    "Confidence: HIGH\n"
    "Reasoning: <2-4 sentences about this specific code>\n"
    "RealCWE: <CWE-NNN if TP, N/A if FP>\n"
    "SuggestedFix: <one concrete refactor if TP, N/A if FP>\n"
)


USER_TEMPLATE = """Code (the only thing you should describe):
```
{code}
```

Claimed CWE: {cwe}
Ground-truth verdict: {verdict}

Rewrite the explanation now. Follow the rules in the system message.
"""


def find_token() -> str:
    for p in TOKEN_PATHS:
        try:
            if p.is_file():
                return p.read_text(encoding="utf-8").strip()
        except Exception:
            continue
    env = os.environ.get("OPENROUTER_API_KEY")
    if env:
        return env.strip()
    raise SystemExit(
        "OpenRouter token not found. Put it in C:/Users/zahar/.openrouter_token "
        "or set OPENROUTER_API_KEY."
    )


def call_haiku(token: str, system: str, user: str, max_tokens: int = 600,
               retry: int = 3, base_delay: float = 2.0) -> dict[str, Any]:
    body = json.dumps({
        "model": MODEL,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "max_tokens": max_tokens,
        "temperature": 0.0,
    }).encode("utf-8")
    req = urllib.request.Request(
        OR_ENDPOINT,
        data=body,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://github.com/JJKenn3dy/vuln-llm-research",
            "X-Title": "vuln-llm-research reasoning regeneration",
        },
        method="POST",
    )
    last_err = None
    for attempt in range(retry):
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            body_bytes = e.read() if hasattr(e, "read") else b""
            last_err = f"HTTP {e.code}: {body_bytes[:200].decode('utf-8', 'replace')}"
            if e.code in (429, 500, 502, 503, 504):
                time.sleep(base_delay * (2 ** attempt))
                continue
            raise RuntimeError(last_err)
        except Exception as e:
            last_err = str(e)
            time.sleep(base_delay * (2 ** attempt))
    raise RuntimeError(f"OpenRouter call failed after {retry} retries: {last_err}")


def extract_code(user_msg: str) -> str:
    """The training user prompt has 'Code:\n<...>' format from TRIAGE_USER_TEMPLATE.
    Capture everything after the literal 'Code:' marker up to optional next field."""
    m = re.search(r"Code:\s*\n(.+)$", user_msg, re.DOTALL)
    if not m:
        return ""
    return m.group(1).strip()


def extract_claimed_cwe(user_msg: str) -> str:
    m = re.search(r"Claimed CWE:\s*(\S+)", user_msg)
    return m.group(1).strip() if m else "unknown"


def get_verdict(assistant: str) -> str:
    if "TRUE_POSITIVE" in assistant:
        return "TRUE_POSITIVE"
    if "FALSE_POSITIVE" in assistant:
        return "FALSE_POSITIVE"
    return "?"


def regenerate(row: dict, token: str) -> tuple[str, dict[str, Any]]:
    msgs = row.get("messages", [])
    user_msg = next((m["content"] for m in msgs if m["role"] == "user"), "")
    asst_msg = next((m["content"] for m in msgs if m["role"] == "assistant"), "")
    code = extract_code(user_msg)
    cwe = extract_claimed_cwe(user_msg)
    verdict = get_verdict(asst_msg)
    user = USER_TEMPLATE.format(code=code[:6000], cwe=cwe, verdict=verdict)
    resp = call_haiku(token, SYSTEM, user)
    text = resp["choices"][0]["message"]["content"].strip()
    usage = resp.get("usage", {})
    return text, usage


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--in", dest="input_path", required=True)
    p.add_argument("--out", dest="output_path", required=True)
    p.add_argument("--limit", type=int, default=0, help="0 = all")
    p.add_argument("--skip-fp", action="store_true")
    p.add_argument("--smoke", action="store_true", help="print first 5 outputs for review")
    args = p.parse_args()

    token = find_token()
    rows = json.loads(Path(args.input_path).read_text(encoding="utf-8"))
    print(f"Input rows: {len(rows)}")

    out_rows = []
    total_prompt_tokens = 0
    total_completion_tokens = 0
    n_regen = 0
    n_kept = 0

    targets = rows[: args.limit] if args.limit else rows
    Path(args.output_path).parent.mkdir(parents=True, exist_ok=True)
    partial_path = Path(str(args.output_path) + ".partial.jsonl")
    partial_fp = open(partial_path, "w", encoding="utf-8")

    for i, row in enumerate(targets):
        msgs = row.get("messages", [])
        asst_msg = next((m["content"] for m in msgs if m["role"] == "assistant"), "")
        verdict = get_verdict(asst_msg)
        if verdict == "FALSE_POSITIVE" and args.skip_fp:
            out_rows.append(row)
            n_kept += 1
            partial_fp.write(json.dumps({"i": i, "skip": "FP"}, ensure_ascii=False) + "\n")
            continue
        try:
            new_asst, usage = regenerate(row, token)
        except Exception as e:
            print(f"[{i+1}/{len(targets)}] FAIL: {e}", flush=True)
            out_rows.append(row)
            n_kept += 1
            partial_fp.write(json.dumps({"i": i, "skip": str(e)}, ensure_ascii=False) + "\n")
            continue
        new_row = dict(row)
        new_row["messages"] = [
            m if m["role"] != "assistant" else {"role": "assistant", "content": new_asst}
            for m in msgs
        ]
        meta = dict(new_row.get("metadata", {}) or {})
        meta["reasoning_regenerated_by"] = "anthropic/claude-haiku-4.5"
        meta["original_assistant"] = asst_msg
        new_row["metadata"] = meta
        out_rows.append(new_row)
        n_regen += 1
        total_prompt_tokens += usage.get("prompt_tokens", 0)
        total_completion_tokens += usage.get("completion_tokens", 0)
        partial_fp.write(json.dumps({"i": i, "verdict": verdict, "new": new_asst[:160]}, ensure_ascii=False) + "\n")
        if (i + 1) % 5 == 0:
            partial_fp.flush()
            print(f"[{i+1}/{len(targets)}] regen={n_regen} kept={n_kept} "
                  f"in={total_prompt_tokens} out={total_completion_tokens}", flush=True)
        if args.smoke and i < 5:
            print(f"\n--- smoke row {i} ({verdict}) ---\n{new_asst}\n", flush=True)

    partial_fp.close()
    Path(args.output_path).write_text(
        json.dumps(out_rows, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    # Llama 3.3 70B via OpenRouter: $0.10/Min, $0.32/Mout
    cost = total_prompt_tokens / 1_000_000 * 0.10 + total_completion_tokens / 1_000_000 * 0.32
    print(f"\nDone. regenerated={n_regen} kept={n_kept} "
          f"prompt_toks={total_prompt_tokens} completion_toks={total_completion_tokens} "
          f"est_cost=${cost:.4f}")
    print(f"wrote {args.output_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

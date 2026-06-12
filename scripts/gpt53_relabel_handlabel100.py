"""Run GPT-5.3-codex as a blind re-labeler on the 100 hand-label cases,
matching the prompt format used for the human AI-labeler pass.

Goal: 4th independent voice (alongside SB, Sonnet, Gemini, human Pass-1)
on the SastBench-250 audit question. Cost estimate: ~$0.60 at $1.75/M in,
$14/M out for 100 cases.

Output: data/exam/sastbench250_handlabel/gpt53_codex_labels.jsonl
        with the same schema as ai_pass1_labels.jsonl so the same
        analysis script can join them.

Schema per line:
  {"blind_id": "...", "verdict": "TRUE_POSITIVE|FALSE_POSITIVE",
   "confidence": "HIGH|MEDIUM|LOW", "solvable": "yes|partial|no",
   "reasoning": "one paragraph", "raw": "<full model output>"}

Writes .partial.jsonl every 10 cases (intermediate-results discipline).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

sys.stdout.reconfigure(encoding="utf-8")

ROOT = Path("f:/vuln-llm-research")
BLIND = ROOT / "data/exam/sastbench250_handlabel/hand_label_blind.json"
OUT = ROOT / "data/exam/sastbench250_handlabel/gpt53_codex_labels.jsonl"
PARTIAL = ROOT / "data/exam/sastbench250_handlabel/gpt53_codex_labels.partial.jsonl"

MODEL = "openai/gpt-5.3-codex"
OR_ENDPOINT = "https://openrouter.ai/api/v1/chat/completions"
TOKEN_PATHS = [
    Path("C:/Users/zahar/.openrouter_token"),
    Path.home() / ".openrouter_token",
    Path("/workspace/.openrouter_token"),
]


SYSTEM = (
    "You are an experienced application-security engineer reviewing static-analysis "
    "findings. For each finding you receive a code snippet, the claimed CWE, and the "
    "SAST tool that produced it. Decide whether the finding is a TRUE_POSITIVE (real "
    "exploitable bug in the shown code) or a FALSE_POSITIVE (noise: code is safe, "
    "wrong CWE, sink not reachable, defense in place, etc.).\n\n"
    "Be calibrated. Use HIGH only when the code in the snippet is sufficient to "
    "decide unambiguously. Use MEDIUM when the decision is well-supported but you "
    "could imagine a context flip. Use LOW when you are guessing.\n\n"
    "Output EXACTLY these four fields, one per line, no extra commentary, no markdown:\n"
    "Verdict: TRUE_POSITIVE or FALSE_POSITIVE\n"
    "Confidence: HIGH or MEDIUM or LOW\n"
    "Solvable: yes (snippet alone is enough), partial (snippet is suggestive but caller/context matters), or no\n"
    "Reasoning: one or two sentences naming the specific code element that drives your verdict\n"
)


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
    raise SystemExit("OpenRouter token not found")


def call_model(token: str, user_content: str, max_tokens: int = 4000,
               retry: int = 3, base_delay: float = 2.0) -> dict[str, Any]:
    body = json.dumps({
        "model": MODEL,
        "messages": [
            {"role": "system", "content": SYSTEM},
            {"role": "user", "content": user_content},
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
            "X-Title": "vuln-llm-research SastBench-250 relabel",
        },
        method="POST",
    )
    last_err = None
    for attempt in range(retry):
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            body_bytes = e.read() if hasattr(e, "read") else b""
            msg = body_bytes[:400].decode("utf-8", "replace")
            last_err = f"HTTP {e.code}: {msg}"
            if e.code in (429, 500, 502, 503, 504):
                time.sleep(base_delay * (2 ** attempt))
                continue
            raise RuntimeError(last_err)
        except Exception as e:
            last_err = str(e)
            time.sleep(base_delay * (2 ** attempt))
    raise RuntimeError(f"OpenRouter call failed after {retry} retries: {last_err}")


VERDICT_RE = re.compile(r"Verdict:\s*(TRUE_POSITIVE|FALSE_POSITIVE|TP|FP)", re.I)
CONF_RE = re.compile(r"Confidence:\s*(HIGH|MEDIUM|LOW)", re.I)
SOLV_RE = re.compile(r"Solvable:\s*(yes|partial|no)", re.I)
REASON_RE = re.compile(r"Reasoning:\s*(.+?)(?:\n[A-Z][a-z]+:|\Z)", re.I | re.S)


def parse(raw: str) -> dict[str, str]:
    v = VERDICT_RE.search(raw)
    c = CONF_RE.search(raw)
    s = SOLV_RE.search(raw)
    r = REASON_RE.search(raw)
    verdict = v.group(1).upper() if v else "?"
    if verdict == "TP":
        verdict = "TRUE_POSITIVE"
    elif verdict == "FP":
        verdict = "FALSE_POSITIVE"
    return {
        "verdict": verdict,
        "confidence": (c.group(1).upper() if c else "?"),
        "solvable": (s.group(1).lower() if s else "?"),
        "reasoning": (r.group(1).strip() if r else raw.strip()[:400]),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--start", type=int, default=0)
    ap.add_argument("--end", type=int, default=100)
    ap.add_argument("--smoke", action="store_true", help="run 3 cases and stop")
    ap.add_argument("--dry-run", action="store_true", help="print prompts, no API call")
    args = ap.parse_args()

    token = find_token()
    cases = json.loads(BLIND.read_text(encoding="utf-8"))
    end = min(args.end, len(cases))
    if args.smoke:
        end = min(args.start + 3, end)

    print(f"Model: {MODEL}")
    print(f"Cases: {args.start}..{end} (n={end-args.start})")
    print()

    # Resume support: if PARTIAL exists, skip already-labeled blind_ids
    done = set()
    if PARTIAL.exists():
        for line in PARTIAL.read_text(encoding="utf-8").splitlines():
            if line.strip():
                try:
                    done.add(json.loads(line)["blind_id"])
                except Exception:
                    pass
        print(f"Resume: {len(done)} blind_ids already in partial file")

    results: list[dict] = []
    total_in = 0
    total_out = 0
    t0 = time.time()
    for i in range(args.start, end):
        case = cases[i]
        bid = case["blind_id"]
        if bid in done:
            continue
        prompt = case["snippet_prompt"]
        if args.dry_run:
            print(f"--- {i} {bid} ({len(prompt)} chars) ---")
            print(prompt[:400])
            continue
        try:
            resp = call_model(token, prompt)
        except Exception as e:
            print(f"  {i:>3d} {bid}: ERROR {e}")
            continue
        msg = resp["choices"][0]["message"]
        # Reasoning models may return content=None and put text in "reasoning"
        raw = msg.get("content") or msg.get("reasoning") or ""
        raw = (raw or "").strip()
        if not raw:
            finish = resp["choices"][0].get("finish_reason", "?")
            print(f"  {i:>3d} {bid}: EMPTY (finish={finish}) — skipping")
            continue
        usage = resp.get("usage", {})
        total_in += usage.get("prompt_tokens", 0)
        total_out += usage.get("completion_tokens", 0)
        parsed = parse(raw)
        rec = {"blind_id": bid, **parsed, "raw": raw}
        results.append(rec)
        with PARTIAL.open("a", encoding="utf-8", newline="\n") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        elapsed = time.time() - t0
        n_so_far = len(results)
        print(f"  {i:>3d} {bid}: {parsed['verdict']:<15s} {parsed['confidence']:<6s} {parsed['solvable']:<8s} ({elapsed/max(n_so_far,1):.1f}s/case)")

    # Move partial to final on completion (only if we hit args.end)
    if not args.dry_run and not args.smoke:
        if PARTIAL.exists():
            # merge all partials into final
            all_recs = []
            for line in PARTIAL.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    all_recs.append(json.loads(line))
            with OUT.open("w", encoding="utf-8", newline="\n") as f:
                for r in all_recs:
                    f.write(json.dumps(r, ensure_ascii=False) + "\n")
            print(f"\nWrote {len(all_recs)} records to {OUT}")

    cost = total_in * 1.75e-6 + total_out * 14e-6
    print(f"\nTokens: in={total_in} out={total_out}")
    print(f"Estimated cost: ${cost:.3f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

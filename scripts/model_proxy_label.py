"""Model-proxy hand-labeling replacement.

When human is unavailable (e.g. user is asleep), use a strong frontier model
to fill the scaffold's Pass 1 and Pass 2 fields. Result is NOT a human
baseline — it's a model-on-snippet baseline. Document this in probe output.

Two passes preserved structurally (model is asked separately in each pass):
  Pass 1 — model sees ONLY snippet + claimed CWE, answers:
            solvable_from_snippet, your_verdict_snippet_only
  Pass 2 — model sees snippet + mechanically-extracted evidence packet, answers:
            your_verdict_with_full_context, fp_cause_taxonomy (if FP)

Pass 2 evidence packet comes from extract_evidence_packets.py (mechanical, not
human-curated). protocol_compliance carried over verbatim from that step.

Usage:
    OPENROUTER_API_KEY=... python scripts/model_proxy_label.py \\
        --scaffold data/exam/hand_label_scaffold.json \\
        --cases data/exam/hand_label_cases.json \\
        --evidence runs/hand_label_evidence_extracted.json \\
        --model anthropic/claude-sonnet-4.5 \\
        --output data/exam/hand_label_scaffold_model_proxy.json \\
        --limit 5    # smoke first
"""
from __future__ import annotations

import argparse
import json
import os
import re
import time
from datetime import datetime
from pathlib import Path


PASS1_SYSTEM = (
    "You are a careful security code reviewer. You will see only a code snippet "
    "and a SAST tool's claim. You must answer two questions and emit them in the "
    "exact format requested. No extra text."
)
PASS1_USER_TEMPLATE = """A static analysis tool flagged the following code snippet.

SAST tool: {tool}
Claimed CWE: {cwe}  ({cwe_name})
File: {file_path}
Lines: {line_range}

Code snippet:
{code}

Two questions:
1) Looking ONLY at this snippet (no repository, no caller, no imports outside what is shown), can a careful reviewer decide whether the SAST finding is a true positive or false positive?
   Choose: yes / no / disputed
   - yes  = the snippet alone is sufficient to decide.
   - no   = the snippet alone is insufficient; you'd need wider context.
   - disputed = could go either way; some readers might say yes, others no.

2) Based solely on this snippet, what is your best guess for the SAST claim's verdict?
   Choose: TRUE_POSITIVE / FALSE_POSITIVE

Emit EXACTLY this format, nothing else:
SolvableFromSnippet: yes|no|disputed
VerdictSnippetOnly: TRUE_POSITIVE|FALSE_POSITIVE
Reasoning: <2-3 short sentences, no markdown>
"""

PASS2_SYSTEM = (
    "You are a careful security code reviewer. You will see a code snippet, a SAST "
    "tool's claim, and an additional context packet extracted mechanically from the "
    "repository. Answer the questions in the exact format requested."
)
PASS2_USER_TEMPLATE = """A static analysis tool flagged the following code.

SAST tool: {tool}
Claimed CWE: {cwe}  ({cwe_name})
File: {file_path}
Lines: {line_range}

Code snippet:
{code}

Additional context (mechanically extracted from the repository — enclosing function, imports, sanitizer-keyword lines):
{evidence_packet}

Based on the snippet PLUS the additional context, answer:

1) Final verdict on the SAST claim:
   Choose: TRUE_POSITIVE / FALSE_POSITIVE

2) If FALSE_POSITIVE, what is the cause? Choose one of:
   sanitization_upstream  — input sanitised before reaching this code
   test_code              — path is under tests/ or has test markers
   dead_code              — path appears unreachable from any entry point
   framework_protection   — framework auto-escapes / validates (e.g. ORM)
   pattern_mismatch       — SAST rule too eager, code does not match the CWE pattern
   modernized_code        — defensive code via newer API replacing old vuln pattern
   mislabel               — SastBench ground truth appears wrong to you
   other                  — explain in reasoning

   If TRUE_POSITIVE, this field is N/A.

Emit EXACTLY this format, nothing else:
VerdictWithFullContext: TRUE_POSITIVE|FALSE_POSITIVE
FpCauseTaxonomy: <one of the values above, or N/A if TP>
Reasoning: <2-3 short sentences, no markdown>
"""


PASS1_SOLVABLE_RE = re.compile(r"^\s*SolvableFromSnippet:\s*(yes|no|disputed)\b", re.I | re.M)
PASS1_VERDICT_RE = re.compile(r"^\s*VerdictSnippetOnly:\s*(TRUE_POSITIVE|FALSE_POSITIVE|TP|FP)\b", re.I | re.M)
PASS2_VERDICT_RE = re.compile(r"^\s*VerdictWithFullContext:\s*(TRUE_POSITIVE|FALSE_POSITIVE|TP|FP)\b", re.I | re.M)
PASS2_TAXONOMY_RE = re.compile(
    r"^\s*FpCauseTaxonomy:\s*(sanitization_upstream|test_code|dead_code|framework_protection|"
    r"pattern_mismatch|modernized_code|mislabel|other|N/A)\b", re.I | re.M)
REASONING_RE = re.compile(r"^\s*Reasoning:\s*(.+?)$", re.I | re.M | re.S)


def log(msg: str) -> None:
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)


def dump_partial(results: list, output_path: str) -> None:
    """Atomic partial dump — writes <output>.partial.json next to final path.
    Safe to call inside loops; overwritable; safe to read while writer is alive.
    """
    p = Path(output_path)
    partial = p.with_suffix(".partial" + p.suffix)
    tmp = partial.with_suffix(partial.suffix + ".tmp")
    tmp.write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(partial)


def call_openrouter(model: str, system: str, user: str, max_tokens: int = 600) -> str:
    from openai import OpenAI
    client = OpenAI(
        api_key=os.environ["OPENROUTER_API_KEY"],
        base_url="https://openrouter.ai/api/v1",
    )
    r = client.chat.completions.create(
        model=model,
        messages=[{"role": "system", "content": system}, {"role": "user", "content": user}],
        temperature=0.0,
        max_tokens=max_tokens,
    )
    return r.choices[0].message.content or ""


def with_retry(fn, retries: int = 3, label: str = ""):
    for attempt in range(retries):
        try:
            return fn()
        except Exception as e:
            wait = 2 ** attempt
            log(f"  {label} retry {attempt+1}/{retries} after {wait}s: {type(e).__name__}: {str(e)[:120]}")
            time.sleep(wait)
    raise RuntimeError(f"{label}: all retries failed")


def extract_code_from_user(user_msg: str) -> str:
    m = re.search(r"Code:\s*\n(.*)$", user_msg, re.DOTALL)
    return m.group(1).strip() if m else user_msg


def parse_pass1(text: str) -> tuple[str | None, str | None]:
    s = PASS1_SOLVABLE_RE.search(text)
    v = PASS1_VERDICT_RE.search(text)
    solvable = s.group(1).lower() if s else None
    verdict = None
    if v:
        x = v.group(1).upper()
        verdict = "TRUE_POSITIVE" if x in ("TP", "TRUE_POSITIVE") else "FALSE_POSITIVE"
    return solvable, verdict


def parse_pass2(text: str) -> tuple[str | None, str | None]:
    v = PASS2_VERDICT_RE.search(text)
    t = PASS2_TAXONOMY_RE.search(text)
    verdict = None
    if v:
        x = v.group(1).upper()
        verdict = "TRUE_POSITIVE" if x in ("TP", "TRUE_POSITIVE") else "FALSE_POSITIVE"
    taxonomy = None
    if t:
        x = t.group(1).lower()
        taxonomy = x if x.lower() != "n/a" else None
    return verdict, taxonomy


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser()
    p.add_argument("--scaffold", required=True)
    p.add_argument("--cases", required=True)
    p.add_argument("--evidence", required=True)
    p.add_argument("--model", default="anthropic/claude-sonnet-4.5")
    p.add_argument("--output", required=True)
    p.add_argument("--limit", type=int, default=None, help="smoke testing")
    p.add_argument("--retries", type=int, default=3)
    return p.parse_args()


def main() -> None:
    args = parse_args()
    scaffold = json.loads(Path(args.scaffold).read_text(encoding="utf-8"))
    cases = json.loads(Path(args.cases).read_text(encoding="utf-8"))
    evidence = json.loads(Path(args.evidence).read_text(encoding="utf-8"))
    if args.limit:
        scaffold = scaffold[:args.limit]
        cases = cases[:args.limit]

    case_by_id = {str(c["metadata"]["case_id"]): c for c in cases}
    evidence_by_id = {str(e["case_id"]): e for e in evidence}

    log(f"scaffold n={len(scaffold)}  model={args.model}  total API calls = {2 * len(scaffold)}")

    pass1_n_parsed = pass2_n_parsed = 0
    for i, s in enumerate(scaffold):
        cid = str(s["case_id"])
        case = case_by_id[cid]
        md = case["metadata"]
        code = extract_code_from_user(case["messages"][1]["content"])

        # ===== PASS 1 (snippet only) =====
        pass1_user = PASS1_USER_TEMPLATE.format(
            tool=md.get("tool", "semgrep"),
            cwe=md.get("claimed_cwe", "CWE-?"),
            cwe_name=md.get("vulnerability_name", ""),
            file_path=md.get("file_path", "?"),
            line_range=md.get("line_range", "?"),
            code=code[:4000],
        )
        try:
            resp1 = with_retry(
                lambda: call_openrouter(args.model, PASS1_SYSTEM, pass1_user),
                retries=args.retries, label=f"pass1/{cid}"
            )
        except Exception as e:
            log(f"  PASS1 {cid} FAILED: {e}")
            resp1 = ""
        solvable, verdict_snippet = parse_pass1(resp1)
        if solvable and verdict_snippet:
            pass1_n_parsed += 1
        s["solvable_from_snippet"] = solvable
        s["your_verdict_snippet_only"] = verdict_snippet
        s["_pass1_raw_response"] = resp1[:1500]

        # ===== PASS 2 (with evidence packet) =====
        ev = evidence_by_id.get(cid, {})
        evidence_packet = ev.get("evidence_packet", "(no packet)")
        protocol_compliance = ev.get("evidence_packet_protocol_compliance", False)

        pass2_user = PASS2_USER_TEMPLATE.format(
            tool=md.get("tool", "semgrep"),
            cwe=md.get("claimed_cwe", "CWE-?"),
            cwe_name=md.get("vulnerability_name", ""),
            file_path=md.get("file_path", "?"),
            line_range=md.get("line_range", "?"),
            code=code[:3000],
            evidence_packet=evidence_packet[:6000],
        )
        try:
            resp2 = with_retry(
                lambda: call_openrouter(args.model, PASS2_SYSTEM, pass2_user, max_tokens=600),
                retries=args.retries, label=f"pass2/{cid}"
            )
        except Exception as e:
            log(f"  PASS2 {cid} FAILED: {e}")
            resp2 = ""
        verdict_full, taxonomy = parse_pass2(resp2)
        if verdict_full:
            pass2_n_parsed += 1
        s["your_verdict_with_full_context"] = verdict_full
        s["evidence_packet"] = evidence_packet
        s["evidence_packet_protocol_compliance"] = protocol_compliance
        s["fp_cause_taxonomy"] = taxonomy if verdict_full == "FALSE_POSITIVE" else None
        s["_pass2_raw_response"] = resp2[:1500]
        s["comments"] = f"model_proxy=true; model={args.model}; compliance={protocol_compliance}"

        log(f"  [{i+1}/{len(scaffold)}] {cid}  pass1={solvable}/{verdict_snippet}  pass2={verdict_full}/{taxonomy}")

        # Partial dump after EVERY case — if killed mid-way, work survives
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        dump_partial(scaffold[:i + 1], args.output)

    Path(args.output).write_text(
        json.dumps(scaffold, ensure_ascii=False, indent=2), encoding="utf-8")

    log(f"\nDONE. parse rate: pass1={pass1_n_parsed}/{len(scaffold)}  pass2={pass2_n_parsed}/{len(scaffold)}")
    log(f"wrote {args.output}")


if __name__ == "__main__":
    main()

"""Sufficiency probe: does the v8.2 input (50-4000 char snippet + claimed CWE)
contain enough information for the triage task? Or does evidence packet move
the needle?

Five arms × N hand-labeled cases, against two frontier models. Each arm sees
the same cases.

  (a) snippet-only,  TRIAGE prompt (v8.2 input format),         Sonnet 4.5
  (a) snippet-only,  TRIAGE prompt (v8.2 input format),         Gemini 2.5 Pro
  (a') snippet-only, neutral prompt (no SAST framing prior),    Sonnet 4.5
  (b) snippet + evidence_packet, TRIAGE prompt,                 Sonnet 4.5
  (b) snippet + evidence_packet, TRIAGE prompt,                 Gemini 2.5 Pro

Inputs:
  - hand_label_scaffold.json (with researcher-filled solvable_from_snippet and
    evidence_packet columns). Produced by scripts/carve_exam.py and edited.
  - hand_label_cases.json (the same 50 cases in full triage chat format).

Outputs to --output:
  - per-arm overall BA/MCC + bootstrap 95% CI
  - per-arm DISAGGREGATION by solvable_from_snippet={yes,no,disputed}
    (the column that separates "data missing" from "frontier limit")
  - per-case predictions (for later failure-mode review)

The (a) vs (a') comparison on Sonnet separates "TRIAGE prompt biases the answer"
from "snippet lacks information". The (a) vs (b) comparison separates
"snippet sufficient" from "evidence packet required". The disaggregation by
solvable_from_snippet validates against human-on-snippet baseline.

Usage (locally, after scaffold is hand-filled):
    OPENROUTER_API_KEY=... python scripts/sufficiency_probe.py \\
        --scaffold data/exam/hand_label_scaffold.json \\
        --cases data/exam/hand_label_cases.json \\
        --output runs/sufficiency_probe.json
"""
from __future__ import annotations

import argparse
import json
import math
import os
import random
import re
import time
from collections import Counter
from datetime import datetime
from pathlib import Path


VERDICT_RE = re.compile(
    r"^\s*Verdict:\s*(TRUE_POSITIVE|FALSE_POSITIVE|TP|FP)\b",
    re.IGNORECASE | re.MULTILINE,
)

NEUTRAL_SYSTEM = "You are a security code reviewer."
NEUTRAL_USER_TEMPLATE = """Code under review.

File: {file_path}
Lines: {line_range}

```
{code}
```

Question: does this code contain a {cwe} vulnerability that an attacker could exploit?

Respond exactly:
Verdict: TRUE_POSITIVE if vulnerable, FALSE_POSITIVE otherwise.
Reasoning: <one short paragraph>
"""

# Each arm: (arm_name, prompt_kind, model_id, client_kind).
# prompt_kind: 'triage_snippet' | 'neutral_snippet' | 'triage_evidence'
# All models go through OpenRouter to keep one client + one key.
ARMS = [
    ("a_triage_snippet_sonnet", "triage_snippet", "anthropic/claude-sonnet-4.5", "openrouter"),
    ("a_triage_snippet_gemini", "triage_snippet", "google/gemini-2.5-pro", "openrouter"),
    ("aprime_neutral_snippet_sonnet", "neutral_snippet", "anthropic/claude-sonnet-4.5", "openrouter"),
    ("b_triage_evidence_sonnet", "triage_evidence", "anthropic/claude-sonnet-4.5", "openrouter"),
    ("b_triage_evidence_gemini", "triage_evidence", "google/gemini-2.5-pro", "openrouter"),
]


def log(msg: str) -> None:
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)


def parse_verdict(response: str) -> str:
    m = VERDICT_RE.search(response or "")
    if not m:
        return "PARSE_FAIL"
    v = m.group(1).upper()
    if v in ("TP", "TRUE_POSITIVE"):
        return "TRUE_POSITIVE"
    if v in ("FP", "FALSE_POSITIVE"):
        return "FALSE_POSITIVE"
    return "PARSE_FAIL"


def extract_code_from_user(user_msg: str) -> str:
    m = re.search(r"Code:\s*\n(.*)$", user_msg, re.DOTALL)
    return m.group(1).strip() if m else user_msg


def build_messages(arm_kind: str, case: dict, evidence_packet: str) -> list[dict]:
    if arm_kind == "triage_snippet":
        return case["messages"][:2]  # exact v8.2 input

    if arm_kind == "neutral_snippet":
        md = case["metadata"]
        code = extract_code_from_user(case["messages"][1]["content"])
        user = NEUTRAL_USER_TEMPLATE.format(
            file_path=md.get("file_path", "unknown"),
            line_range=md.get("line_range", "?"),
            code=code,
            cwe=md.get("claimed_cwe", "CWE-?"),
        )
        return [
            {"role": "system", "content": NEUTRAL_SYSTEM},
            {"role": "user", "content": user},
        ]

    if arm_kind == "triage_evidence":
        sys_msg, user_msg = case["messages"][0], case["messages"][1]
        appended = (
            user_msg["content"]
            + "\n\nAdditional context (researcher-constructed evidence packet — "
            "function imports, callers/callees, sanitizer presence, source/sink trace):\n"
            + evidence_packet.strip()
            + "\n"
        )
        return [sys_msg, {"role": "user", "content": appended}]

    raise ValueError(f"unknown arm_kind: {arm_kind}")


def call_openrouter(model: str, messages: list[dict], max_tokens: int = 600) -> str:
    from openai import OpenAI
    client = OpenAI(
        api_key=os.environ["OPENROUTER_API_KEY"],
        base_url="https://openrouter.ai/api/v1",
    )
    r = client.chat.completions.create(
        model=model,
        messages=messages,
        temperature=0.0,
        max_tokens=max_tokens,
    )
    return r.choices[0].message.content or ""


def call_with_retry(client_kind: str, model: str, messages: list[dict],
                     retries: int = 3) -> str:
    last_err = None
    for attempt in range(retries):
        try:
            if client_kind == "openrouter":
                return call_openrouter(model, messages)
            raise ValueError(f"unsupported client_kind: {client_kind}")
        except Exception as e:
            last_err = e
            wait = 2 ** attempt
            log(f"  retry {attempt+1}/{retries} after {wait}s: {type(e).__name__}: {str(e)[:120]}")
            time.sleep(wait)
    raise RuntimeError(f"all retries failed: {last_err}")


def metrics(predictions: list[tuple[str, str]]) -> dict:
    tp = fn = tn = fp = pf = 0
    for true, pred in predictions:
        if pred == "PARSE_FAIL":
            pf += 1
            continue
        if true == "TRUE_POSITIVE":
            if pred == "TRUE_POSITIVE":
                tp += 1
            else:
                fn += 1
        else:
            if pred == "FALSE_POSITIVE":
                tn += 1
            else:
                fp += 1
    n_pos = tp + fn
    n_neg = tn + fp
    dr = tp / n_pos if n_pos else 0.0
    far = fp / n_neg if n_neg else 0.0
    ba = 0.5 * (dr + (1 - far))
    denom = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    mcc = ((tp * tn) - (fp * fn)) / denom if denom else 0.0
    return {
        "n": len(predictions), "TP": tp, "FN": fn, "TN": tn, "FP": fp,
        "parse_fail": pf, "dr": dr, "far": far, "ba": ba, "mcc": mcc,
    }


def bootstrap_ci(predictions: list[tuple[str, str]],
                  n_boot: int = 1000, seed: int = 42) -> dict:
    if len(predictions) < 10:
        return {"ba_ci95": None, "mcc_ci95": None, "n_boot": 0}
    rng = random.Random(seed)
    n = len(predictions)
    bas, mccs = [], []
    for _ in range(n_boot):
        sample = [predictions[rng.randrange(n)] for _ in range(n)]
        m = metrics(sample)
        bas.append(m["ba"])
        mccs.append(m["mcc"])
    bas.sort()
    mccs.sort()
    lo, hi = int(0.025 * n_boot), int(0.975 * n_boot)
    return {
        "ba_ci95": [bas[lo], bas[hi]],
        "mcc_ci95": [mccs[lo], mccs[hi]],
        "n_boot": n_boot,
    }


def validate_scaffold(scaffold: list[dict]) -> None:
    missing = []
    for s in scaffold:
        if s.get("solvable_from_snippet") not in ("yes", "no", "disputed"):
            missing.append(("solvable_from_snippet", s["case_id"]))
        if not (s.get("evidence_packet") or "").strip():
            missing.append(("evidence_packet", s["case_id"]))
    if missing:
        examples = ", ".join(f"{kind}:{cid}" for kind, cid in missing[:5])
        raise SystemExit(
            f"scaffold has {len(missing)} missing fields. "
            f"Fill 'solvable_from_snippet' (yes/no/disputed) and 'evidence_packet'. "
            f"Examples: {examples}"
        )


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser()
    p.add_argument("--scaffold", required=True)
    p.add_argument("--cases", required=True)
    p.add_argument("--output", required=True)
    p.add_argument("--retries", type=int, default=3)
    p.add_argument("--limit", type=int, default=None, help="for smoke testing")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    scaffold = json.loads(Path(args.scaffold).read_text(encoding="utf-8"))
    cases = json.loads(Path(args.cases).read_text(encoding="utf-8"))
    if args.limit:
        scaffold = scaffold[:args.limit]

    validate_scaffold(scaffold)
    case_by_id = {str(c["metadata"]["case_id"]): c for c in cases}

    log(f"scaffold n={len(scaffold)}  arms={len(ARMS)}  "
        f"total API calls = {len(scaffold) * len(ARMS)}")
    log(f"solvable_from_snippet dist: {Counter(s['solvable_from_snippet'] for s in scaffold)}")

    per_arm: dict[str, list[dict]] = {arm[0]: [] for arm in ARMS}
    for i, s in enumerate(scaffold):
        cid = str(s["case_id"])
        case = case_by_id.get(cid)
        if case is None:
            log(f"skip {cid}: not in cases file")
            continue
        for arm_name, arm_kind, model, client_kind in ARMS:
            try:
                messages = build_messages(arm_kind, case, s.get("evidence_packet") or "")
                response = call_with_retry(client_kind, model, messages, retries=args.retries)
            except Exception as e:
                log(f"  {arm_name}/{cid} FAILED: {e}")
                response = ""
            per_arm[arm_name].append({
                "case_id": cid,
                "true_verdict": s["ground_truth_verdict"],
                "predicted_verdict": parse_verdict(response),
                "solvable_from_snippet": s["solvable_from_snippet"],
                "raw_response": response[:1000],
            })
        log(f"  [{i+1}/{len(scaffold)}] {cid} done")

    # Aggregate
    results: dict = {
        "meta": {
            "created_at": datetime.now().isoformat(),
            "n_scaffold": len(scaffold),
            "n_arms": len(ARMS),
            "scaffold_dist": dict(Counter(s["solvable_from_snippet"] for s in scaffold)),
            "verdict_dist": dict(Counter(s["ground_truth_verdict"] for s in scaffold)),
            "arms": [{"name": a[0], "kind": a[1], "model": a[2]} for a in ARMS],
        },
        "arms": {},
    }
    for arm_name, rows in per_arm.items():
        overall_preds = [(r["true_verdict"], r["predicted_verdict"]) for r in rows]
        overall_m = metrics(overall_preds)
        overall_ci = bootstrap_ci(overall_preds)

        slices = {}
        for slice_key in ("yes", "no", "disputed"):
            slice_preds = [(r["true_verdict"], r["predicted_verdict"])
                            for r in rows if r["solvable_from_snippet"] == slice_key]
            if not slice_preds:
                continue
            sm = metrics(slice_preds)
            slices[slice_key] = {**sm, **bootstrap_ci(slice_preds)}

        results["arms"][arm_name] = {
            **overall_m, **overall_ci,
            "by_solvable_from_snippet": slices,
            "per_case": rows,
        }

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text(
        json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")

    # Headline table to stdout
    print("\n=== SUFFICIENCY PROBE ===")
    print(f"{'arm':<38} {'n':>3} {'BA':>6} {'BA 95% CI':<14} {'MCC':>+7} {'MCC 95% CI':<16} pf")
    for arm_name, res in results["arms"].items():
        ba_ci = res.get("ba_ci95") or [0, 0]
        mcc_ci = res.get("mcc_ci95") or [0, 0]
        print(f"{arm_name:<38} {res['n']:>3} {res['ba']:.3f} "
              f"[{ba_ci[0]:.2f},{ba_ci[1]:.2f}] {res['mcc']:>+.3f} "
              f"[{mcc_ci[0]:+.2f},{mcc_ci[1]:+.2f}] {res['parse_fail']}")

    print("\nDisaggregation by solvable_from_snippet:")
    for arm_name, res in results["arms"].items():
        sl = res.get("by_solvable_from_snippet") or {}
        if not sl:
            continue
        print(f"  {arm_name}:")
        for key in ("yes", "no", "disputed"):
            if key in sl:
                d = sl[key]
                print(f"    {key:<8} n={d['n']:<3} BA={d['ba']:.3f} MCC={d['mcc']:+.3f}")

    print(f"\nfull results: {args.output}")


if __name__ == "__main__":
    main()

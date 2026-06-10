"""Sufficiency probe: does the v8.2 input (50-4000 char snippet + claimed CWE)
contain enough information for the triage task? Or does evidence packet move
the needle? Plus: how does human-on-snippet (blind) compare?

Six arms × N hand-labeled cases:

  (a)   TRIAGE prompt, snippet only           — Sonnet 4.5 + Gemini 2.5 Pro
  (a')  neutral prompt, snippet only          — Sonnet 4.5
  (b)   TRIAGE prompt + evidence_packet       — Sonnet 4.5 + Gemini 2.5 Pro
  (h)   HUMAN snippet-only verdict (no API)   — from scaffold pass 1

Arm (h) is the *baseline truth* against which frontier (a)/(a') are measured:
if human snippet-blind = 50% and frontier (a) = 50%, snippet is genuinely
insufficient. If human snippet-blind = 80% and frontier (a) = 50%, snippet
contains info but frontier doesn't pull it out.

(a) vs (a'): separates TRIAGE prompt biasing the answer from data sufficiency.
(a) vs (b): separates snippet sufficiency from evidence-packet requirement.
(h) vs (a): is the human-on-snippet baseline above or below frontier?

## Disaggregation caveat

Disaggregation by `solvable_from_snippet` slice at n_total=50 gives 15-25
cases per cell. CI bands wide. Treat slice patterns as HINTS, not proof.
Make the gate decision on (a) vs (b) overall, then look at slices for
direction of v8.3 levers (e.g., "the NO-slice is where evidence packet
matters most — so packet content design should target what's missing in NO").

## Strict scaffold validation

Scaffold must be fully two-pass labeled before probe runs. Refuses to start
otherwise. Excluded from strict (b) metric: cases with
`evidence_packet_protocol_compliance == false` (tallied separately, since
mechanical extractor cannot reproduce them).

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

API_ARMS = [
    ("a_triage_snippet_sonnet", "triage_snippet", "anthropic/claude-sonnet-4.5", "openrouter"),
    ("aprime_neutral_snippet_sonnet", "neutral_snippet", "anthropic/claude-sonnet-4.5", "openrouter"),
    ("b_triage_evidence_sonnet", "triage_evidence", "anthropic/claude-sonnet-4.5", "openrouter"),
    # Gemini arms skipped to stay within OpenRouter $5 budget; smoke-10 already
    # showed single-call Gemini 2.5 Pro is paranoid (BA=0.30) — adding more
    # would not change conclusions and would overrun budget. Re-add later.
]
HUMAN_ARM_NAME = "h_human_snippet_blind"


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
        return case["messages"][:2]
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
            + "\n\nAdditional context (mechanically-extracted evidence packet — "
            "enclosing function, imports, callers, sanitizer-keyword lines):\n"
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
    """Reject if two-pass labeling not complete."""
    missing: list[tuple[str, str]] = []
    for s in scaffold:
        cid = s["case_id"]
        # Pass 1 (snippet-blind) fields
        if s.get("solvable_from_snippet") not in ("yes", "no", "disputed"):
            missing.append(("pass1.solvable_from_snippet", cid))
        if s.get("your_verdict_snippet_only") not in ("TRUE_POSITIVE", "FALSE_POSITIVE"):
            missing.append(("pass1.your_verdict_snippet_only", cid))
        # Pass 2 (full-context) fields
        if s.get("your_verdict_with_full_context") not in ("TRUE_POSITIVE", "FALSE_POSITIVE"):
            missing.append(("pass2.your_verdict_with_full_context", cid))
        if not (s.get("evidence_packet") or "").strip():
            missing.append(("pass2.evidence_packet", cid))
        if s.get("evidence_packet_protocol_compliance") not in (True, False):
            missing.append(("pass2.evidence_packet_protocol_compliance", cid))
        # Taxonomy required only if your_verdict_with_full_context is FP
        if s.get("your_verdict_with_full_context") == "FALSE_POSITIVE":
            if not s.get("fp_cause_taxonomy"):
                missing.append(("pass2.fp_cause_taxonomy(FP only)", cid))
    if missing:
        examples = ", ".join(f"{kind}:{cid}" for kind, cid in missing[:8])
        raise SystemExit(
            f"scaffold has {len(missing)} unfilled fields. "
            f"Complete two-pass labeling first. Examples: {examples}"
        )


def per_arm_disaggregation(rows: list[dict]) -> dict:
    """Slice by solvable_from_snippet ∈ {yes,no,disputed}."""
    slices = {}
    for key in ("yes", "no", "disputed"):
        slice_preds = [
            (r["true_verdict"], r["predicted_verdict"])
            for r in rows if r["solvable_from_snippet"] == key
        ]
        if not slice_preds:
            continue
        sm = metrics(slice_preds)
        slices[key] = {**sm, **bootstrap_ci(slice_preds)}
    return slices


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser()
    p.add_argument("--scaffold", required=True)
    p.add_argument("--cases", required=True)
    p.add_argument("--output", required=True)
    p.add_argument("--retries", type=int, default=3)
    p.add_argument("--limit", type=int, default=None, help="for smoke testing")
    p.add_argument("--strict-b-only-compliant", action="store_true", default=True,
                   help="Exclude protocol_compliance=false cases from (b) arm metric "
                        "(reported separately)")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    scaffold = json.loads(Path(args.scaffold).read_text(encoding="utf-8"))
    cases = json.loads(Path(args.cases).read_text(encoding="utf-8"))
    if args.limit:
        scaffold = scaffold[:args.limit]

    validate_scaffold(scaffold)
    case_by_id = {str(c["metadata"]["case_id"]): c for c in cases}

    n = len(scaffold)
    log(f"scaffold n={n}  API arms={len(API_ARMS)}  total API calls = {n * len(API_ARMS)}")
    log(f"solvable_from_snippet dist: {Counter(s['solvable_from_snippet'] for s in scaffold)}")
    log(f"protocol_compliance dist: {Counter(s['evidence_packet_protocol_compliance'] for s in scaffold)}")
    log(f"fp_cause_taxonomy dist (FP only): "
        f"{Counter(s.get('fp_cause_taxonomy') for s in scaffold if s['your_verdict_with_full_context']=='FALSE_POSITIVE')}")

    per_arm: dict[str, list[dict]] = {arm[0]: [] for arm in API_ARMS}
    for i, s in enumerate(scaffold):
        cid = str(s["case_id"])
        case = case_by_id.get(cid)
        if case is None:
            log(f"skip {cid}: not in cases file")
            continue
        for arm_name, arm_kind, model, client_kind in API_ARMS:
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
                "evidence_packet_protocol_compliance": s["evidence_packet_protocol_compliance"],
                "fp_cause_taxonomy": s.get("fp_cause_taxonomy"),
                "raw_response": response[:1000],
            })
        log(f"  [{i+1}/{n}] {cid} done")

    # === 6th arm: human snippet-blind (no API call) ===
    human_rows = [
        {
            "case_id": s["case_id"],
            "true_verdict": s["ground_truth_verdict"],
            "predicted_verdict": s["your_verdict_snippet_only"],
            "solvable_from_snippet": s["solvable_from_snippet"],
            "evidence_packet_protocol_compliance": s["evidence_packet_protocol_compliance"],
            "fp_cause_taxonomy": s.get("fp_cause_taxonomy"),
            "raw_response": "(human, blind)",
        }
        for s in scaffold
    ]

    # Aggregate results
    results: dict = {
        "meta": {
            "created_at": datetime.now().isoformat(),
            "n_scaffold": n,
            "n_api_arms": len(API_ARMS),
            "scaffold_solvable_dist": dict(Counter(s["solvable_from_snippet"] for s in scaffold)),
            "scaffold_verdict_dist": dict(Counter(s["ground_truth_verdict"] for s in scaffold)),
            "scaffold_compliance_dist": dict(Counter(s["evidence_packet_protocol_compliance"] for s in scaffold)),
            "human_snippet_only_vs_full_context": dict(Counter(
                f"snippet={s['your_verdict_snippet_only']} full={s['your_verdict_with_full_context']}"
                for s in scaffold
            )),
            "fp_taxonomy_dist": dict(Counter(
                s.get("fp_cause_taxonomy")
                for s in scaffold if s["your_verdict_with_full_context"] == "FALSE_POSITIVE"
            )),
            "arms": [{"name": a[0], "kind": a[1], "model": a[2]} for a in API_ARMS] + [
                {"name": HUMAN_ARM_NAME, "kind": "human_blind", "model": "researcher"}
            ],
            "decision_caveat": "Gate decision: (a) vs (b) OVERALL with CI. "
                                "Slice patterns are HINTS, not proof, at n_per_slice=15-25.",
        },
        "arms": {},
    }

    for arm_name, rows in list(per_arm.items()) + [(HUMAN_ARM_NAME, human_rows)]:
        overall_preds = [(r["true_verdict"], r["predicted_verdict"]) for r in rows]
        overall_m = metrics(overall_preds)
        overall_ci = bootstrap_ci(overall_preds)

        # Strict (b): only compliant cases
        strict_b = None
        if arm_name.startswith("b_") and args.strict_b_only_compliant:
            strict_rows = [r for r in rows if r["evidence_packet_protocol_compliance"] is True]
            if strict_rows:
                strict_preds = [(r["true_verdict"], r["predicted_verdict"]) for r in strict_rows]
                strict_b = {**metrics(strict_preds), **bootstrap_ci(strict_preds)}

        results["arms"][arm_name] = {
            **overall_m, **overall_ci,
            "strict_compliant_only": strict_b,
            "by_solvable_from_snippet": per_arm_disaggregation(rows),
            "per_case": rows,
        }

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text(
        json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")

    # Headline table
    print("\n=== SUFFICIENCY PROBE ===")
    print(f"{'arm':<38} {'n':>3} {'BA':>6} {'BA 95% CI':<14} {'MCC':>7} {'MCC 95% CI':<16} pf")
    for arm_name, res in results["arms"].items():
        ba_ci = res.get("ba_ci95") or [0, 0]
        mcc_ci = res.get("mcc_ci95") or [0, 0]
        print(f"{arm_name:<38} {res['n']:>3} {res['ba']:.3f} "
              f"[{ba_ci[0]:.2f},{ba_ci[1]:.2f}] {res['mcc']:>+.3f} "
              f"[{mcc_ci[0]:+.2f},{mcc_ci[1]:+.2f}] {res['parse_fail']}")

    print("\nStrict (b) compliant-only (where applicable):")
    for arm_name, res in results["arms"].items():
        sb = res.get("strict_compliant_only")
        if sb:
            ba_ci = sb.get("ba_ci95") or [0, 0]
            print(f"  {arm_name:<38} n={sb['n']:<3} BA={sb['ba']:.3f} "
                  f"[{ba_ci[0]:.2f},{ba_ci[1]:.2f}] MCC={sb['mcc']:+.3f}")

    print("\nDisaggregation by solvable_from_snippet (HINTS at n_per_slice=15-25):")
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

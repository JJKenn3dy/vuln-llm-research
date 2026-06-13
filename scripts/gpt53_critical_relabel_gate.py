"""Path C gate: GPT-5.3-codex as CRITICAL RE-LABELER on the hand-label-100.

Difference from gpt53_relabel_handlabel100.py (blind 4th voice): here the
model SEES the shipped label and is explicitly authorized to reject it.
This mirrors the Path C application (cleaning CVEFixes train labels) and
measures the one thing the blind run cannot: anchoring robustness.

PRE-COMMITTED PASS CRITERIA (fixed before the run, 2026-06-13):
  Blind baseline: GPT-5.3 blind <-> human anchor = 71.7% (n=99).
  Cave rate = share of cases where blind GPT-5.3 contradicted the shipped
  label but the re-labeler flips TO the shipped label.

  GATE PASSES if BOTH:
    (a) relabeler <-> human agreement >= 68.7%  (blind - 3 pp)
    (b) cave rate <= 25% on the blind-disagreed-with-label subset

  PASS  -> GPT-5.3 critical re-labeler is a scalable label cleaner:
           use it on CVEFixes train rows (Path C -> v8.4) and to extend
           the gold-core eval to 300-500 cases.
  FAIL (a) -> showing the label degrades judgment; re-labeling must stay blind
           (two-pass: blind verdict first, then compare to shipped label).
  FAIL (b) -> the model echoes shipped labels; it cannot clean training
           data regardless of its blind quality.

Cost: ~$0.70 full 100 (same as blind run). Smoke 5 cases first.
Output: data/exam/sastbench250_handlabel/gpt53_relabeler_labels.jsonl
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")

ROOT = Path("f:/vuln-llm-research")
HL = ROOT / "data/exam/sastbench250_handlabel"
BLIND = HL / "hand_label_blind.json"
CID_MAP = HL / "hand_label_case_id_map.json"
OUT = HL / "gpt53_relabeler_labels.jsonl"
PARTIAL = HL / "gpt53_relabeler_labels.partial.jsonl"

sys.path.insert(0, str(ROOT / "scripts"))
from gpt53_relabel_handlabel100 import (  # noqa: E402
    MODEL, call_model, find_token, parse,
)

SYSTEM = (
    "You are an experienced application-security engineer auditing the LABELS of a "
    "static-analysis benchmark. For each finding you receive a code snippet, the "
    "claimed CWE, the SAST tool, and the verdict the dataset currently ships for "
    "this finding.\n\n"
    "Your job is to KEEP or REJECT the shipped verdict based on the code alone. "
    "The shipped label is frequently wrong: it was produced by a heuristic pipeline, "
    "not by expert review. Treat it as a claim under audit, NOT as evidence. If the "
    "code contradicts the shipped verdict, reject it without hesitation.\n\n"
    "TRUE_POSITIVE means a real exploitable bug in the shown code. FALSE_POSITIVE "
    "means noise: code is safe, wrong CWE, sink not reachable, defense in place, etc.\n\n"
    "Be calibrated. Use HIGH only when the snippet is sufficient to decide "
    "unambiguously. Use MEDIUM when well-supported but a context flip is imaginable. "
    "Use LOW when guessing.\n\n"
    "Output EXACTLY these four fields, one per line, no extra commentary, no markdown:\n"
    "Verdict: TRUE_POSITIVE or FALSE_POSITIVE   (your own verdict, regardless of the shipped one)\n"
    "Confidence: HIGH or MEDIUM or LOW\n"
    "Solvable: yes (snippet alone is enough), partial (caller/context matters), or no\n"
    "Reasoning: one or two sentences naming the specific code element that drives your verdict\n"
)

LABEL_LINE = (
    "\n\nShipped dataset verdict for this finding: {label}\n"
    "Audit this label against the code and output your own verdict."
)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--start", type=int, default=0)
    ap.add_argument("--end", type=int, default=100)
    ap.add_argument("--smoke", type=int, default=0, help="run N cases and stop")
    args = ap.parse_args()

    token = find_token()
    cases = json.loads(BLIND.read_text(encoding="utf-8"))
    cid = dict(json.loads(CID_MAP.read_text(encoding="utf-8")))
    end = min(args.end, len(cases))
    if args.smoke:
        end = min(args.start + args.smoke, end)

    done = set()
    if PARTIAL.exists():
        for line in PARTIAL.read_text(encoding="utf-8").splitlines():
            if line.strip():
                try:
                    done.add(json.loads(line)["blind_id"])
                except Exception:
                    pass
        print(f"Resume: {len(done)} blind_ids already in partial file")

    print(f"Model: {MODEL} (critical re-labeler mode)")
    print(f"Cases: {args.start}..{end}")

    results = []
    total_in = total_out = 0
    t0 = time.time()
    for i in range(args.start, end):
        case = cases[i]
        bid = case["blind_id"]
        if bid in done:
            continue
        sb = cid[bid]["sb_verdict"]
        shipped = "TRUE_POSITIVE" if sb == "TP" else "FALSE_POSITIVE"
        prompt = case["snippet_prompt"] + LABEL_LINE.format(label=shipped)
        try:
            resp = call_model(token, prompt)
        except Exception as e:
            print(f"  {i:>3d} {bid}: ERROR {e}")
            continue
        msg = resp["choices"][0]["message"]
        raw = (msg.get("content") or msg.get("reasoning") or "").strip()
        if not raw:
            print(f"  {i:>3d} {bid}: EMPTY (finish={resp['choices'][0].get('finish_reason')}) — skipping")
            continue
        usage = resp.get("usage", {})
        total_in += usage.get("prompt_tokens", 0)
        total_out += usage.get("completion_tokens", 0)
        parsed = parse(raw)
        rec = {"blind_id": bid, "shipped_label": shipped, **parsed, "raw": raw}
        results.append(rec)
        with PARTIAL.open("a", encoding="utf-8", newline="\n") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        kept = "KEEP" if parsed["verdict"] == shipped else "REJECT"
        print(f"  {i:>3d} {bid}: {parsed['verdict']:<15s} {parsed['confidence']:<6s} "
              f"[{kept} shipped] ({(time.time()-t0)/max(len(results),1):.1f}s/case)")

    if not args.smoke and PARTIAL.exists():
        all_recs = [json.loads(l) for l in PARTIAL.read_text(encoding="utf-8").splitlines() if l.strip()]
        with OUT.open("w", encoding="utf-8", newline="\n") as f:
            for r in all_recs:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
        print(f"\nWrote {len(all_recs)} records to {OUT}")

    cost = total_in * 1.75e-6 + total_out * 14e-6
    print(f"\nTokens: in={total_in} out={total_out}  est cost: ${cost:.3f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

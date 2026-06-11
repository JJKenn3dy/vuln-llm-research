"""Tri-judge adjudication of contested HIGH cases.

Joins AI Pass 1 verdicts + Sonnet verdicts + Gemini verdicts on the same 10
cases, applies the pre-committed decision rule, and produces the final
"likely mislabel" subset.

Pre-committed rule (from chat with Zakhar 2026-06-11 night):
  - all three judges (AI, Sonnet, Gemini) disagree with SastBench → strong
    mislabel evidence
  - only AI disagrees with SastBench, both frontier agree with SB → likely
    AI error, drop from list
  - mixed (one of two frontier on AI's side) → ambiguous, defer to human

Usage:
    python scripts/compute_adjudication.py \\
        --sonnet runs/adjudication_10/sonnet_outputs.json \\
        --gemini runs/adjudication_10/gemini_outputs.json
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")


def index_outputs(path: Path) -> dict[str, str]:
    out = json.loads(path.read_text(encoding="utf-8"))
    return {r["case_id"]: r["predicted_verdict"] for r in out}


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--sonnet", required=True)
    p.add_argument("--gemini", required=True)
    p.add_argument("--ai-map", default="data/exam/adjudication_10_ai_map.json")
    p.add_argument("--output", default="runs/adjudication_10/adjudication_report.json")
    p.add_argument("--md", default="runs/adjudication_10/adjudication_report.md")
    args = p.parse_args()

    ai_map = json.loads(Path(args.ai_map).read_text(encoding="utf-8"))
    sonnet = index_outputs(Path(args.sonnet))
    gemini = index_outputs(Path(args.gemini))

    rows = []
    counts = {"strong_mislabel": 0, "likely_ai_error": 0, "ambiguous": 0}

    for orig_id, info in ai_map.items():
        sb = info["sastbench_verdict"]
        ai = info["ai_verdict"]
        son = sonnet.get(orig_id, "MISSING")
        gem = gemini.get(orig_id, "MISSING")

        ai_disagrees = ai != sb
        son_disagrees = son != sb and son != "PARSE_FAIL" and son != "MISSING"
        gem_disagrees = gem != sb and gem != "PARSE_FAIL" and gem != "MISSING"

        n_disagree = sum([ai_disagrees, son_disagrees, gem_disagrees])

        if n_disagree == 3:
            verdict = "strong_mislabel"
        elif ai_disagrees and not son_disagrees and not gem_disagrees:
            verdict = "likely_ai_error"
        else:
            verdict = "ambiguous"

        counts[verdict] += 1
        rows.append({
            "original_case_id": orig_id,
            "blind_id": info["blind_id"],
            "sastbench": sb,
            "ai": ai,
            "sonnet": son,
            "gemini": gem,
            "n_disagree": n_disagree,
            "adjudication": verdict,
            "ai_reasoning_preview": info["ai_reasoning_preview"],
        })

    out = {
        "counts": counts,
        "rule": "strong_mislabel = all 3 judges disagree with SB; likely_ai_error = only AI disagrees; ambiguous = mixed",
        "rows": rows,
    }
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"counts: {counts}")
    print(f"wrote {args.output}")

    md = _render_md(out)
    Path(args.md).write_text(md, encoding="utf-8")
    print(f"wrote {args.md}")
    print()
    print(md)


def _render_md(report: dict) -> str:
    lines = [
        "# Adjudication of 10 contested HIGH-confidence hand-label cases",
        "",
        "## Pre-committed decision rule",
        "",
        "- **strong_mislabel**: AI + Sonnet + Gemini all disagree with SastBench",
        "- **likely_ai_error**: only AI disagrees, both frontier agree with SB",
        "- **ambiguous**: mixed pattern (one of two frontier on AI's side)",
        "",
        f"## Counts: {report['counts']}",
        "",
        "## Per-case verdict",
        "",
        "| original_case_id | SB | AI | Sonnet | Gemini | n_disagree | adjudication |",
        "|---|---|---|---|---|---|---|",
    ]
    short = {"TRUE_POSITIVE": "TP", "FALSE_POSITIVE": "FP", "PARSE_FAIL": "PF", "MISSING": "?"}
    for r in report["rows"]:
        lines.append(
            f"| {r['original_case_id']} | {short.get(r['sastbench'], '?')} | "
            f"{short.get(r['ai'], '?')} | {short.get(r['sonnet'], '?')} | "
            f"{short.get(r['gemini'], '?')} | {r['n_disagree']} | **{r['adjudication']}** |"
        )
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    main()

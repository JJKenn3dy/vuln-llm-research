"""Look at where each baseline gets things wrong on the triage_100 set.

For each model output file, surface:
  - Per-CWE accuracy (where does the model fail?)
  - Confidence vs correctness (does the model know when it's wrong?)
  - Examples of confident-but-wrong answers (great for sales decks)
  - Verdict-format quality (parse failures, schema violations)

This script reads the *_outputs.json files written by run_triage_eval.py
and produces a human-readable markdown report.

Example:

    python -m src.eval.analyze_failure_modes \\
        --outputs \\
            "GPT-4o:/workspace/runs/gpt4o_triage100_outputs.json" \\
            "Llama 3.3 70B:/workspace/runs/llama33_triage100_outputs.json" \\
            "DeepSeek-Chat:/workspace/runs/deepseek_triage100_outputs.json" \\
        --output /workspace/runs/failure_analysis.md
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path


def load_outputs(path: str) -> list[dict]:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def analyze(name: str, outputs: list[dict]) -> dict:
    correct_by_cwe = defaultdict(lambda: [0, 0])  # [correct, total]
    confidence_correctness = Counter()  # (confidence, is_correct) -> n
    parse_fails = 0
    confidently_wrong = []  # (case_id, true, pred, claimed_cwe, response_excerpt)

    for r in outputs:
        true = r.get("true_verdict")
        pred = r.get("predicted_verdict")
        cwe = r.get("claimed_cwe", "UNKNOWN")
        conf = r.get("predicted_confidence", "")
        is_correct = (true == pred and pred != "PARSE_FAIL")

        if pred == "PARSE_FAIL":
            parse_fails += 1

        correct_by_cwe[cwe][1] += 1
        if is_correct:
            correct_by_cwe[cwe][0] += 1

        confidence_correctness[(conf or "NONE", is_correct)] += 1

        if conf == "HIGH" and not is_correct and pred != "PARSE_FAIL":
            confidently_wrong.append({
                "case_id": r.get("case_id"),
                "true_verdict": true,
                "predicted_verdict": pred,
                "claimed_cwe": cwe,
                "response_excerpt": (r.get("model_response", "") or "")[:300],
            })

    return {
        "name": name,
        "n": len(outputs),
        "parse_fails": parse_fails,
        "per_cwe_accuracy": {
            cwe: (c / t, t) for cwe, (c, t) in correct_by_cwe.items()
        },
        "confidence_breakdown": dict(confidence_correctness),
        "confidently_wrong": confidently_wrong[:5],  # top 5 examples
    }


def format_report(reports: list[dict]) -> str:
    lines = ["# Failure mode analysis on triage_100", ""]

    for r in reports:
        lines.append(f"## {r['name']}")
        lines.append("")
        lines.append(f"- N = {r['n']}, parse_fails = {r['parse_fails']}")
        lines.append("")

        lines.append("### Per-CWE accuracy (sorted by sample size)")
        lines.append("")
        lines.append("| CWE | correct/total | accuracy |")
        lines.append("|---|---|---|")
        sorted_cwes = sorted(
            r["per_cwe_accuracy"].items(),
            key=lambda kv: -kv[1][1],
        )
        for cwe, (acc, n) in sorted_cwes[:10]:
            correct = round(acc * n)
            lines.append(f"| {cwe} | {correct}/{n} | {acc*100:.1f}% |")
        lines.append("")

        lines.append("### Confidence vs correctness")
        lines.append("")
        lines.append("| Confidence | Correct | Wrong |")
        lines.append("|---|---|---|")
        confs = {c for (c, _) in r["confidence_breakdown"].keys()}
        for c in sorted(confs):
            correct = r["confidence_breakdown"].get((c, True), 0)
            wrong = r["confidence_breakdown"].get((c, False), 0)
            lines.append(f"| {c} | {correct} | {wrong} |")
        lines.append("")

        if r["confidently_wrong"]:
            lines.append("### Top 5 confidently-wrong examples (great for sales deck)")
            lines.append("")
            for i, w in enumerate(r["confidently_wrong"], 1):
                lines.append(
                    f"**{i}.** case={w['case_id']}, claimed={w['claimed_cwe']}, "
                    f"true={w['true_verdict']}, model said={w['predicted_verdict']} (HIGH confidence)"
                )
                lines.append("")
                lines.append(f"> {w['response_excerpt']}")
                lines.append("")

    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Analyse triage failure modes per model")
    p.add_argument("--outputs", nargs="+", required=True,
                   help="Entries 'name:path' pointing to *_outputs.json files")
    p.add_argument("--output", default=None,
                   help="Write report here; if omitted, print to stdout")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    reports = []
    for entry in args.outputs:
        if ":" not in entry:
            sys.exit(f"Bad --outputs entry (need 'name:path'): {entry}")
        name, path = entry.split(":", 1)
        if not Path(path).exists():
            print(f"WARN: {path} missing, skipping {name}", file=sys.stderr)
            continue
        reports.append(analyze(name.strip(), load_outputs(path)))

    if not reports:
        sys.exit("No outputs files found")

    text = format_report(reports)
    if args.output:
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(text)
        print(f"Wrote {args.output}")
    else:
        print(text)


if __name__ == "__main__":
    main()

"""Aggregate triage eval metrics into a single comparison markdown table.

Reads metrics JSONs (output of run_triage_eval.py) and produces a sales-ready
table. Designed so the README "Current state" section can be regenerated from
ground truth after every experiment.

Example:

    python -m src.eval.build_comparison_table \\
        --metrics \\
            "GPT-4o:/workspace/runs/gpt4o_triage100_metrics.json" \\
            "Llama 3.3 70B:/workspace/runs/llama33_triage100_metrics.json" \\
            "DeepSeek-Chat:/workspace/runs/deepseek_triage100_metrics.json" \\
            "v5b (zero-shot):/workspace/runs/v5b_zeroshot_triage100_metrics.json" \\
            "v8-triage (ours):/workspace/runs/v8_triage100_metrics.json" \\
        --output /workspace/runs/comparison_table.md
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def load_metrics(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def format_row(name: str, m: dict) -> str:
    """Format one row in the comparison table."""
    tp = m.get("TP", "")
    fn = m.get("FN", "")
    tn = m.get("TN", "")
    fp = m.get("FP", "")
    pf = m.get("PARSE_FAIL", 0)
    n = m.get("n_total", tp + fn + tn + fp + pf)
    f1 = m.get("f1", 0.0)
    ba = m.get("balanced_accuracy", 0.0)
    mcc = m.get("mcc", 0.0)
    dr = m.get("detection_rate", 0.0)
    far = m.get("false_alarm_rate", 0.0)

    return (
        f"| {name} | {n} | {tp} | {fn} | {tn} | {fp} | {pf} | "
        f"{dr*100:.1f}% | {far*100:.1f}% | {f1:.3f} | {ba:.3f} | {mcc:.3f} |"
    )


def render_table(entries: list[tuple[str, dict]]) -> str:
    header = (
        "| Model | N | TP | FN | TN | FP | parse_fail | DR | FAR | F1 | BalAcc | MCC |"
    )
    sep = "|" + "|".join(["---"] * 12) + "|"
    rows = [format_row(name, m) for name, m in entries]
    return "\n".join([header, sep] + rows)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Build a triage eval comparison table")
    p.add_argument(
        "--metrics", nargs="+", required=True,
        help="Entries of the form 'display name:path/to/metrics.json'",
    )
    p.add_argument("--output", default=None,
                   help="Write the table to this path; if omitted, print to stdout")
    p.add_argument("--title", default="Triage eval: model comparison")
    return p.parse_args()


def main() -> None:
    args = parse_args()

    entries: list[tuple[str, dict]] = []
    for entry in args.metrics:
        if ":" not in entry:
            sys.exit(f"Bad --metrics entry (need 'name:path'): {entry}")
        name, path = entry.split(":", 1)
        if not Path(path).exists():
            print(f"WARN: {path} missing, skipping {name}", file=sys.stderr)
            continue
        entries.append((name.strip(), load_metrics(path)))

    if not entries:
        sys.exit("No metrics files found")

    table = render_table(entries)
    output = f"# {args.title}\n\n{table}\n"

    if args.output:
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output)
        print(f"Wrote {args.output}")
    else:
        print(output)


if __name__ == "__main__":
    main()

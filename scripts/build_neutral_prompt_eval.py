"""Produce a sibling eval JSON with the neutral prompt swapped in.

Reads `data/eval/sastbench_v01_subset250.json`, extracts the original
code/metadata, re-renders messages with `src.utils.neutral_prompt`, and
writes `data/eval/sastbench_v01_subset250_neutral.json`. The metadata
block is preserved unchanged so downstream eval scripts (cluster
bootstrap, per-CWE breakdown) still work.

Usage:
    python scripts/build_neutral_prompt_eval.py \\
        --input data/eval/sastbench_v01_subset250.json \\
        --output data/eval/sastbench_v01_subset250_neutral.json
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.utils.neutral_prompt import render_neutral_messages

CODE_BLOCK_RE = re.compile(
    r"Code:\n(.*?)(?=\n\nOutput exactly these fields:|\Z)",
    re.DOTALL,
)


def extract_code(user_content: str) -> str:
    """Pull the code section out of the TRIAGE_USER_TEMPLATE rendering."""
    m = CODE_BLOCK_RE.search(user_content)
    if not m:
        return ""
    return m.group(1).strip("\n")


def build_neutral_case(case: dict) -> dict:
    md = case["metadata"]
    code = extract_code(case["messages"][1]["content"])
    if not code:
        raise ValueError(
            f"could not extract code from case {md.get('case_id', '?')}; "
            "TRIAGE prompt format may have changed"
        )
    messages = render_neutral_messages(
        tool=md.get("tool", "semgrep"),
        cwe=md.get("claimed_cwe", "unknown"),
        severity="MEDIUM",
        file_path=md.get("file_path", "<unknown>"),
        line_range=md.get("line_range", "?"),
        code=code,
    )
    if len(case["messages"]) >= 3:
        messages.append(case["messages"][2])
    return {"messages": messages, "metadata": md}


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--input", required=True)
    p.add_argument("--output", required=True)
    args = p.parse_args()

    with open(args.input, encoding="utf-8") as f:
        cases = json.load(f)
    print(f"loaded {len(cases)} cases from {args.input}")

    rebuilt = [build_neutral_case(c) for c in cases]
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(rebuilt, f, ensure_ascii=False, indent=2)
    print(f"wrote {args.output}")


if __name__ == "__main__":
    main()

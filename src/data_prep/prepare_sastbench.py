"""Skeleton: prepare SastBench-style triage training data.

SastBench (arXiv 2601.02941, Jan 2026) frames SAST triage as: given a code commit
and SAST findings grouped by CWE, decide which are true positives.

This script will:
  1. Download SastBench from arxiv/HF (TODO: pin source)
  2. For each (code_snippet, sast_finding, ground_truth_label) tuple, render our
     TRIAGE_USER_TEMPLATE from src.utils.prompts
  3. Split by project_id (not commit) for honest OOD evaluation
  4. Write train/val/test JSONs in our standard chat-format

Status: SKELETON. Fill in once SastBench source format is confirmed.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from src.utils.prompts import TRIAGE_SYSTEM, TRIAGE_USER_TEMPLATE


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Build SastBench triage training set")
    p.add_argument("--source-dir", required=True,
                   help="Local path to SastBench data after download")
    p.add_argument("--output-dir", required=True)
    p.add_argument("--split-by", choices=["project", "commit", "random"], default="project",
                   help="Use 'project' for honest OOD evaluation (lesson from v7lite)")
    p.add_argument("--train-frac", type=float, default=0.7)
    p.add_argument("--val-frac", type=float, default=0.15)
    p.add_argument("--seed", type=int, default=42)
    return p.parse_args()


def render_triage_example(finding: dict, label: str) -> dict:
    """Convert one SastBench finding into our chat-format training example.

    Expected finding fields (TODO: confirm against actual SastBench schema):
      - tool: str
      - cwe: str (e.g., "CWE-89")
      - severity: str
      - file_path: str
      - line_range: str (e.g., "47-52")
      - code: str
      - project_id: str (used for stratified split)

    label: "TRUE_POSITIVE" or "FALSE_POSITIVE"
    """
    user = TRIAGE_USER_TEMPLATE.format(
        tool=finding.get("tool", "unknown"),
        cwe=finding.get("cwe", "unknown"),
        severity=finding.get("severity", "unknown"),
        file_path=finding.get("file_path", "unknown"),
        line_range=finding.get("line_range", "unknown"),
        code=finding["code"],
    )

    # TODO: generate Reasoning via teacher model (GPT-4o or Claude) during data prep
    # For now leave as placeholder so the example still trains.
    assistant = (
        f"Verdict: {label}\n"
        f"Confidence: HIGH\n"
        f"Reasoning: <FILL_VIA_TEACHER_DISTILLATION>\n"
        f"RealCWE: {finding.get('cwe', 'unknown')}\n"
        f"SuggestedFix: <FILL_VIA_TEACHER_DISTILLATION>\n"
    )

    return {
        "messages": [
            {"role": "system", "content": TRIAGE_SYSTEM},
            {"role": "user", "content": user},
            {"role": "assistant", "content": assistant},
        ],
        "metadata": {
            "project_id": finding.get("project_id"),
            "cwe": finding.get("cwe"),
            "label": label,
            "tool": finding.get("tool"),
        },
    }


def stratified_split_by_project(
    examples: list[dict], train_frac: float, val_frac: float, seed: int
) -> tuple[list[dict], list[dict], list[dict]]:
    import random
    rng = random.Random(seed)
    projects = sorted({e["metadata"]["project_id"] for e in examples if e["metadata"].get("project_id")})
    rng.shuffle(projects)

    n_train = int(len(projects) * train_frac)
    n_val = int(len(projects) * val_frac)
    train_p = set(projects[:n_train])
    val_p = set(projects[n_train:n_train + n_val])
    test_p = set(projects[n_train + n_val:])

    train, val, test = [], [], []
    for e in examples:
        pid = e["metadata"].get("project_id")
        if pid in train_p:
            train.append(e)
        elif pid in val_p:
            val.append(e)
        elif pid in test_p:
            test.append(e)
    return train, val, test


def main() -> None:
    args = parse_args()
    source = Path(args.source_dir)
    output = Path(args.output_dir)
    output.mkdir(parents=True, exist_ok=True)

    # TODO: replace with real loader once SastBench schema is confirmed
    raise NotImplementedError(
        "SastBench loader not yet implemented. "
        "First step: download SastBench from arxiv/HF, inspect schema, then fill in this function."
    )


if __name__ == "__main__":
    main()

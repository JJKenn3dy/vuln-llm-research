"""Skeleton: v8 triage fine-tune.

The triage task differs from v5-v7lite detection task:
  - Input: code + existing SAST finding (with claimed CWE)
  - Output: TP/FP verdict + reasoning + real CWE + suggested fix

Architecture choices to validate empirically:
  1. Single-stage: directly predict TP/FP from code + finding
  2. Two-stage: stage1 detects vuln, stage2 with different prompt re-checks
     (motivated by Datadog's LLM-as-FP-filter: 92% -> 6.3% FP on OWASP)

Differences from train_qlora.py:
  - Larger LoRA r (24-32) since we predict more structured output
  - Smaller LR to avoid memorization (lesson from v7lite)
  - Strict project-level split (no random split — see HISTORY.md)
  - Multi-task loss: TP/FP + CWE + severity (configurable)

Status: SKELETON. Use train_qlora.py as canonical baseline first, swap in
triage data + triage prompt once prepare_sastbench.py is implemented.
"""
from __future__ import annotations

import argparse

# Re-use the train_qlora entry point with sensible defaults for triage.
# Once we have data, this becomes a thin wrapper that calls train_qlora.main
# with triage-tuned hyperparameters.


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="v8 triage fine-tune (SastBench)")
    p.add_argument("--train-file", required=True,
                   help="Output of prepare_sastbench.py with triage examples")
    p.add_argument("--val-file", required=True)
    p.add_argument("--output-dir", required=True)
    p.add_argument("--base-model", default="Qwen/Qwen2.5-Coder-7B-Instruct")
    p.add_argument("--epochs", type=float, default=2.0,
                   help="2 epochs default, lesson from v7lite (3 caused memorization)")
    p.add_argument("--lora-r", type=int, default=16,
                   help="r=8 if memorization, r=24 if structured output needs more capacity")
    p.add_argument("--lora-alpha", type=int, default=32)
    p.add_argument("--lr", type=float, default=1.0e-4,
                   help="Lower than v5b (1.5e-4) to encourage generalization")
    p.add_argument("--max-seq-length", type=int, default=2048,
                   help="Longer than detection because triage output is larger")
    p.add_argument("--two-stage", action="store_true",
                   help="If set, train second-stage FP-filter as separate adapter")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    raise NotImplementedError(
        "v8-triage training pipeline not yet implemented. "
        "Next steps: (1) implement prepare_sastbench.py, (2) run train_qlora.py "
        "with --train-file <triage train> to validate end-to-end, "
        "(3) optimize hyperparameters from there."
    )


if __name__ == "__main__":
    main()

"""v8 triage fine-tune launcher.

Thin wrapper around train_qlora.py with v8-appropriate defaults baked in:
  - 2 epochs (lesson from v7lite: 3 epochs caused memorization on 4k pairs)
  - lr 1e-4 (lower than v5b's 1.5e-4 to encourage generalization)
  - max_seq_length 2048 (triage prompts are longer than detection)

If you just want to run with defaults:

    bash scripts/train_v8.sh

To override anything, pass through to train_qlora directly:

    python -m src.train.train_qlora --train-file ... --lora-r 8 ...

See [docs/ARCHITECTURE.md](../../docs/ARCHITECTURE.md) for the rationale.
"""
from __future__ import annotations

import argparse
import sys


V8_DEFAULTS = {
    "epochs": 2.0,
    "lora_r": 16,
    "lora_alpha": 32,
    "lr": 1.0e-4,
    "max_seq_length": 2048,
    "batch_size": 1,
    "grad_accum": 8,
    "save_steps": 50,
    "save_total_limit": 5,
    "warmup_ratio": 0.05,
    "report_to": "none",
}


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="v8 triage fine-tune (delegates to train_qlora)")
    p.add_argument("--train-file", default="data/train/triage_v8_from_v7lite/triage_train.json")
    p.add_argument("--val-file", default="data/train/triage_v8_from_v7lite/triage_val.json")
    p.add_argument("--output-dir", default="/workspace/adapters/v8_first")
    p.add_argument("--base-model", default="/workspace/models/qwen2.5-coder-7b-instruct")
    p.add_argument("--epochs", type=float, default=V8_DEFAULTS["epochs"])
    p.add_argument("--lora-r", type=int, default=V8_DEFAULTS["lora_r"])
    p.add_argument("--lora-alpha", type=int, default=V8_DEFAULTS["lora_alpha"])
    p.add_argument("--lr", type=float, default=V8_DEFAULTS["lr"])
    p.add_argument("--max-seq-length", type=int, default=V8_DEFAULTS["max_seq_length"])
    p.add_argument("--hf-repo", default="JJKennedy/vuln-llm-adapters")
    p.add_argument("--hf-subfolder", default="v8_first")
    p.add_argument("--no-upload", action="store_true",
                   help="Skip pushing the trained adapter to HuggingFace")
    return p.parse_args()


def main() -> None:
    args = parse_args()

    forwarded = [
        "train_qlora",
        "--train-file", args.train_file,
        "--val-file", args.val_file,
        "--output-dir", args.output_dir,
        "--base-model", args.base_model,
        "--epochs", str(args.epochs),
        "--lora-r", str(args.lora_r),
        "--lora-alpha", str(args.lora_alpha),
        "--lr", str(args.lr),
        "--max-seq-length", str(args.max_seq_length),
        "--batch-size", str(V8_DEFAULTS["batch_size"]),
        "--grad-accum", str(V8_DEFAULTS["grad_accum"]),
        "--save-steps", str(V8_DEFAULTS["save_steps"]),
        "--save-total-limit", str(V8_DEFAULTS["save_total_limit"]),
        "--warmup-ratio", str(V8_DEFAULTS["warmup_ratio"]),
        "--report-to", V8_DEFAULTS["report_to"],
    ]
    if not args.no_upload and args.hf_repo:
        forwarded += [
            "--hf-repo", args.hf_repo,
            "--hf-subfolder", args.hf_subfolder,
        ]

    sys.argv = forwarded

    from src.train.train_qlora import main as train_qlora_main
    train_qlora_main()


if __name__ == "__main__":
    main()

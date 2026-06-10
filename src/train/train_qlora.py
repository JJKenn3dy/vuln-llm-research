"""Cloud-agnostic LoRA fine-tuning entrypoint.

Replaces the cHARISMa-specific train_qlora_v5b.py with an argparse-driven version
suitable for RunPod, Vast.ai, or local GPU. Optionally pushes the trained adapter
to HuggingFace Hub when --hf-repo is provided.

Example (reproduce v5b baseline):

    python -m src.train.train_qlora \\
        --train-file data/train/train_data_v5b_train.json \\
        --val-file data/train/train_data_v5b_val.json \\
        --output-dir /workspace/adapters/v5b_repro \\
        --base-model Qwen/Qwen2.5-Coder-7B-Instruct \\
        --epochs 3 --lora-r 16 --lora-alpha 32 --lr 1.5e-4 \\
        --hf-repo JJKennedy/vuln-llm-adapters --hf-subfolder v5b_repro
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

import torch
from datasets import Dataset
from peft import LoraConfig, get_peft_model
from transformers import AutoModelForCausalLM, AutoTokenizer, TrainingArguments
from trl import SFTTrainer


def load_data(path: str) -> Dataset:
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    texts = []
    for entry in data:
        msgs = entry["messages"]
        text = (
            f"<|im_start|>system\n{msgs[0]['content']}<|im_end|>\n"
            f"<|im_start|>user\n{msgs[1]['content']}<|im_end|>\n"
            f"<|im_start|>assistant\n{msgs[2]['content']}<|im_end|>"
        )
        texts.append({"text": text})
    return Dataset.from_list(texts)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="QLoRA fine-tune for vulnerability detection / triage")
    p.add_argument("--train-file", required=True)
    p.add_argument("--val-file", required=True)
    p.add_argument("--output-dir", required=True)
    p.add_argument("--base-model", default="Qwen/Qwen2.5-Coder-7B-Instruct")
    p.add_argument("--epochs", type=float, default=3.0)
    p.add_argument("--lora-r", type=int, default=16)
    p.add_argument("--lora-alpha", type=int, default=32)
    p.add_argument("--lora-dropout", type=float, default=0.05)
    p.add_argument("--lr", type=float, default=1.5e-4)
    p.add_argument("--batch-size", type=int, default=1)
    p.add_argument("--grad-accum", type=int, default=8)
    p.add_argument("--max-seq-length", type=int, default=1280)
    p.add_argument("--warmup-ratio", type=float, default=0.05)
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--save-steps", type=int, default=50)
    p.add_argument("--save-total-limit", type=int, default=3)
    p.add_argument("--target-modules", nargs="+", default=[
        "q_proj", "k_proj", "v_proj", "o_proj",
        "gate_proj", "up_proj", "down_proj",
    ])
    p.add_argument("--report-to", default="none", choices=["none", "wandb", "tensorboard"])
    p.add_argument("--wandb-project", default="vuln-llm")
    p.add_argument("--wandb-run-name", default=None)
    p.add_argument("--hf-repo", default=None, help="If set, push adapter here on finish")
    p.add_argument("--hf-subfolder", default=None)
    p.add_argument("--hf-private", action="store_true", default=True)
    return p.parse_args()


def main() -> None:
    args = parse_args()

    if args.report_to == "wandb":
        os.environ.setdefault("WANDB_PROJECT", args.wandb_project)

    print(f"==> Loading tokenizer: {args.base_model}")
    tokenizer = AutoTokenizer.from_pretrained(args.base_model, trust_remote_code=True)
    tokenizer.pad_token = tokenizer.eos_token

    print(f"==> Loading model in float16: {args.base_model}")
    model = AutoModelForCausalLM.from_pretrained(
        args.base_model,
        torch_dtype=torch.float16,
        device_map="auto",
        trust_remote_code=True,
    )
    model.config.use_cache = False

    lora_config = LoraConfig(
        r=args.lora_r,
        lora_alpha=args.lora_alpha,
        target_modules=args.target_modules,
        lora_dropout=args.lora_dropout,
        bias="none",
        task_type="CAUSAL_LM",
    )
    model = get_peft_model(model, lora_config)
    model.print_trainable_parameters()
    model.enable_input_require_grads()

    print(f"==> Loading data: train={args.train_file}, val={args.val_file}")
    train_ds = load_data(args.train_file)
    val_ds = load_data(args.val_file)
    print(f"   Train: {len(train_ds)} | Val: {len(val_ds)}")

    targs = TrainingArguments(
        output_dir=args.output_dir,
        num_train_epochs=args.epochs,
        per_device_train_batch_size=args.batch_size,
        gradient_accumulation_steps=args.grad_accum,
        learning_rate=args.lr,
        fp16=True,
        logging_steps=10,
        eval_strategy="no",
        save_strategy="steps",
        save_steps=args.save_steps,
        save_total_limit=args.save_total_limit,
        warmup_ratio=args.warmup_ratio,
        lr_scheduler_type="cosine",
        report_to=args.report_to,
        run_name=args.wandb_run_name,
        gradient_checkpointing=True,
        dataloader_pin_memory=False,
        seed=args.seed,
    )

    trainer = SFTTrainer(
        model=model,
        args=targs,
        train_dataset=train_ds,
        eval_dataset=val_ds,
        dataset_text_field="text",
        max_seq_length=args.max_seq_length,
        tokenizer=tokenizer,
    )

    print("==> Starting training")
    trainer.train()

    print(f"==> Saving adapter -> {args.output_dir}")
    trainer.save_model(args.output_dir)
    tokenizer.save_pretrained(args.output_dir)

    if args.hf_repo:
        print(f"==> Uploading to HuggingFace: {args.hf_repo}/{args.hf_subfolder or ''}")
        from huggingface_hub import HfApi
        api = HfApi()
        api.create_repo(args.hf_repo, repo_type="model", private=args.hf_private, exist_ok=True)
        api.upload_folder(
            folder_path=args.output_dir,
            repo_id=args.hf_repo,
            path_in_repo=args.hf_subfolder or Path(args.output_dir).name,
            repo_type="model",
        )
        print("==> Upload done")

    print("==> Done")


if __name__ == "__main__":
    main()

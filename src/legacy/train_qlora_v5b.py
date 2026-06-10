"""
LoRA fine-tuning для v5b (balanced detector).

Идентично train_qlora_v5.py, отличается только TRAIN_FILE / VAL_FILE / OUTPUT_DIR
для работы с balanced датасетом (50/50 vuln/safe из полного HF CVEfixes).

Запуск: sbatch train_v5b_a100.sbatch
"""
import json
import torch
from transformers import AutoTokenizer, AutoModelForCausalLM, TrainingArguments
from peft import LoraConfig, get_peft_model
from trl import SFTTrainer
from datasets import Dataset

MODEL_NAME = "Qwen/Qwen2.5-Coder-7B-Instruct"
TRAIN_FILE = "train_data_v5b_train.json"
VAL_FILE   = "train_data_v5b_val.json"
OUTPUT_DIR = "qlora_output_v5b"


def load_data(path):
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


def main():
    print("Загружаем токенизатор...")
    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME, trust_remote_code=True)
    tokenizer.pad_token = tokenizer.eos_token

    print("Загружаем модель в float16...")
    model = AutoModelForCausalLM.from_pretrained(
        MODEL_NAME,
        torch_dtype=torch.float16,
        device_map="auto",
        trust_remote_code=True,
    )
    model.config.use_cache = False

    lora_config = LoraConfig(
        r=16,
        lora_alpha=32,
        target_modules=[
            "q_proj", "k_proj", "v_proj", "o_proj",
            "gate_proj", "up_proj", "down_proj",
        ],
        lora_dropout=0.05,
        bias="none",
        task_type="CAUSAL_LM",
    )
    model = get_peft_model(model, lora_config)
    model.print_trainable_parameters()

    print("Загружаем данные...")
    train_ds = load_data(TRAIN_FILE)
    val_ds   = load_data(VAL_FILE)
    print(f"Train: {len(train_ds)} | Val: {len(val_ds)}")

    model.enable_input_require_grads()

    args = TrainingArguments(
        output_dir=OUTPUT_DIR,
        num_train_epochs=3,
        per_device_train_batch_size=1,
        gradient_accumulation_steps=8,
        learning_rate=1.5e-4,
        fp16=True,
        logging_steps=10,
        eval_strategy="no",
        save_strategy="steps",
        save_steps=50,
        save_total_limit=3,
        warmup_ratio=0.05,
        lr_scheduler_type="cosine",
        report_to="none",
        gradient_checkpointing=True,
        dataloader_pin_memory=False,
        seed=42,
    )

    trainer = SFTTrainer(
        model=model,
        args=args,
        train_dataset=train_ds,
        eval_dataset=val_ds,
        dataset_text_field="text",
        max_seq_length=1280,
        tokenizer=tokenizer,
    )

    print("Старт обучения...")
    trainer.train()
    trainer.save_model(OUTPUT_DIR)
    tokenizer.save_pretrained(OUTPUT_DIR)
    print(f"Готово -> {OUTPUT_DIR}")


if __name__ == "__main__":
    main()

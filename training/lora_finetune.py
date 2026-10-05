"""LoRA fine-tune a small code model to emit review findings as JSON.

    pip install -e ".[train]"
    python training/lora_finetune.py --dry-run                      # validate + preview, no GPU/torch needed
    python training/lora_finetune.py --epochs 5 --out training/out  # train; adapter saved to training/out/adapter

Then run the reviewer with the adapter:
    CRA_ADAPTER_DIR=training/out/adapter crassist review --backend local src/
The sample dataset only demonstrates the pipeline; use hundreds+ of real, reviewed examples for quality.
"""
from __future__ import annotations

import argparse
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from crassist.dataset import format_example, load_jsonl, validate_dataset  # noqa: E402


def parse_args(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--data", default=str(Path(__file__).with_name("sample_dataset.jsonl")))
    p.add_argument("--base-model", default="Qwen/Qwen2.5-Coder-0.5B-Instruct")
    p.add_argument("--out", default="training/out")
    p.add_argument("--epochs", type=float, default=4)
    p.add_argument("--lr", type=float, default=2e-4)
    p.add_argument("--batch-size", type=int, default=2)
    p.add_argument("--grad-accum", type=int, default=4)
    p.add_argument("--max-len", type=int, default=1024)
    p.add_argument("--lora-r", type=int, default=16)
    p.add_argument("--lora-alpha", type=int, default=32)
    p.add_argument("--lora-dropout", type=float, default=0.05)
    p.add_argument("--val-split", type=float, default=0.15)
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--load-4bit", action="store_true", help="QLoRA: 4-bit base weights (needs bitsandbytes + CUDA)")
    p.add_argument("--dry-run", action="store_true")
    return p.parse_args(argv)


def tokenize_example(tok, ex: dict, max_len: int) -> dict:
    """Prompt tokens are masked (-100) so loss is computed on the JSON completion only."""
    prompt, completion = format_example(ex)
    p_ids = tok(prompt, add_special_tokens=False)["input_ids"]
    c_ids = tok(completion + tok.eos_token, add_special_tokens=False)["input_ids"]
    if len(c_ids) >= max_len:
        raise ValueError("completion longer than --max-len")
    p_ids = p_ids[-(max_len - len(c_ids)):]  # keep the end of the prompt if truncating
    return {"input_ids": p_ids + c_ids, "labels": [-100] * len(p_ids) + c_ids}


def main(argv=None) -> int:
    args = parse_args(argv)
    rows = load_jsonl(args.data)
    errors = validate_dataset(rows)
    if errors:
        print("Dataset errors:\n  " + "\n  ".join(errors), file=sys.stderr)
        return 2
    random.Random(args.seed).shuffle(rows)
    n_val = int(len(rows) * args.val_split)
    train_rows, val_rows = rows[n_val:], rows[:n_val]
    print(f"{len(rows)} examples -> {len(train_rows)} train / {len(val_rows)} validation")
    if args.dry_run:
        prompt, completion = format_example(train_rows[0])
        print("--- sample prompt (tail) ---\n" + prompt[-400:] + "\n--- sample completion ---\n" + completion)
        return 0

    import torch
    from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
    from transformers import (AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig, Trainer, TrainingArguments)

    torch.manual_seed(args.seed)
    tok = AutoTokenizer.from_pretrained(args.base_model)
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token

    kwargs = {}
    if args.load_4bit:
        kwargs["quantization_config"] = BitsAndBytesConfig(
            load_in_4bit=True, bnb_4bit_quant_type="nf4", bnb_4bit_compute_dtype=torch.bfloat16)
    else:
        kwargs["torch_dtype"] = torch.bfloat16 if torch.cuda.is_available() else torch.float32
    model = AutoModelForCausalLM.from_pretrained(args.base_model, **kwargs)
    if args.load_4bit:
        model = prepare_model_for_kbit_training(model)
    model = get_peft_model(model, LoraConfig(
        r=args.lora_r, lora_alpha=args.lora_alpha, lora_dropout=args.lora_dropout, task_type="CAUSAL_LM",
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"]))
    model.print_trainable_parameters()

    class DS(torch.utils.data.Dataset):
        def __init__(self, items):
            self.items = [tokenize_example(tok, ex, args.max_len) for ex in items]
        def __len__(self):
            return len(self.items)
        def __getitem__(self, i):
            return self.items[i]

    def collate(batch):
        n = max(len(b["input_ids"]) for b in batch)
        pad = lambda seq, v: seq + [v] * (n - len(seq))  # noqa: E731
        return {
            "input_ids": torch.tensor([pad(b["input_ids"], tok.pad_token_id) for b in batch]),
            "attention_mask": torch.tensor([pad([1] * len(b["input_ids"]), 0) for b in batch]),
            "labels": torch.tensor([pad(b["labels"], -100) for b in batch]),
        }

    targs = TrainingArguments(
        output_dir=str(Path(args.out) / "checkpoints"), num_train_epochs=args.epochs,
        per_device_train_batch_size=args.batch_size, per_device_eval_batch_size=args.batch_size,
        gradient_accumulation_steps=args.grad_accum, learning_rate=args.lr, lr_scheduler_type="cosine",
        warmup_ratio=0.05, logging_steps=1, save_strategy="no", report_to="none", seed=args.seed,
        eval_strategy="epoch" if val_rows else "no", bf16=torch.cuda.is_available() and torch.cuda.is_bf16_supported(),
        remove_unused_columns=False)
    trainer = Trainer(model=model, args=targs, train_dataset=DS(train_rows),
                      eval_dataset=DS(val_rows) if val_rows else None, data_collator=collate)
    trainer.train()
    adapter_dir = Path(args.out) / "adapter"
    model.save_pretrained(adapter_dir)
    tok.save_pretrained(adapter_dir)
    print(f"Saved LoRA adapter to {adapter_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

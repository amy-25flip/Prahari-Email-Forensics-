"""Fine-tune bert-base-uncased from scratch on the team's own labeled phishing dataset.

Not a continuation of the current pretrained ealvaradob/bert-finetuned-phishing checkpoint —
starts from a general base model so the result is genuinely "trained by us," matching the
input format the app actually uses at inference time (subject + "\n" + body, see
backend/local_model.py::classify).
"""
import argparse
import json
import os
import time
from pathlib import Path

import numpy as np
import torch
from datasets import load_dataset
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, roc_auc_score, confusion_matrix
from transformers import (
    AutoModelForSequenceClassification,
    AutoTokenizer,
    Trainer,
    TrainingArguments,
    EarlyStoppingCallback,
)

DATA_DIR = Path(r"C:\Users\Admin\OneDrive\Documents\ChatGPT\SIH\datasets\processed")
BASE_MODEL = "bert-base-uncased"
MAX_LENGTH = 256
ID2LABEL = {0: "LEGITIMATE", 1: "PHISHING"}
LABEL2ID = {v: k for k, v in ID2LABEL.items()}


def build_text(example):
    subject = (example.get("subject") or "").strip()
    body = (example.get("body") or "").strip()
    example["text_input"] = f"{subject}\n{body}"
    return example


def tokenize_factory(tokenizer):
    def _tokenize(batch):
        return tokenizer(batch["text_input"], truncation=True, max_length=MAX_LENGTH, padding="max_length")
    return _tokenize


def compute_metrics(eval_pred):
    logits, labels = eval_pred
    probs = torch.softmax(torch.tensor(logits), dim=-1).numpy()
    preds = np.argmax(logits, axis=-1)
    precision, recall, f1, _ = precision_recall_fscore_support(labels, preds, average="binary", zero_division=0)
    try:
        auc = roc_auc_score(labels, probs[:, 1])
    except ValueError:
        auc = float("nan")
    return {
        "accuracy": accuracy_score(labels, preds),
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "roc_auc": auc,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--max-train-samples", type=int, default=None, help="Subsample train set for a quick smoke test")
    parser.add_argument("--max-eval-samples", type=int, default=None)
    parser.add_argument("--epochs", type=float, default=2.0)
    parser.add_argument("--batch-size", type=int, default=32)
    parser.add_argument("--output-dir", default=str(Path(__file__).parent / "output" / "phishing-bert-v1"))
    parser.add_argument("--smoke-test", action="store_true", help="Tiny run to validate the pipeline end-to-end")
    args = parser.parse_args()

    if args.smoke_test:
        args.max_train_samples = args.max_train_samples or 500
        args.max_eval_samples = args.max_eval_samples or 200
        args.epochs = 1.0

    print(f"CUDA available: {torch.cuda.is_available()}")
    if torch.cuda.is_available():
        print(f"GPU: {torch.cuda.get_device_name(0)}")

    print("Loading dataset...")
    data_files = {
        "train": str(DATA_DIR / "train.csv"),
        "validation": str(DATA_DIR / "validation.csv"),
        "test": str(DATA_DIR / "test.csv"),
    }
    dataset = load_dataset("csv", data_files=data_files)

    keep_cols = ["subject", "body", "label"]
    for split in dataset:
        drop_cols = [c for c in dataset[split].column_names if c not in keep_cols]
        dataset[split] = dataset[split].remove_columns(drop_cols)

    dataset = dataset.filter(lambda ex: ex["label"] in (0, 1))

    if args.max_train_samples:
        dataset["train"] = dataset["train"].shuffle(seed=42).select(range(min(args.max_train_samples, len(dataset["train"]))))
    if args.max_eval_samples:
        dataset["validation"] = dataset["validation"].shuffle(seed=42).select(range(min(args.max_eval_samples, len(dataset["validation"]))))
        dataset["test"] = dataset["test"].shuffle(seed=42).select(range(min(args.max_eval_samples, len(dataset["test"]))))

    print(f"train={len(dataset['train'])} validation={len(dataset['validation'])} test={len(dataset['test'])}")

    dataset = dataset.map(build_text)

    print(f"Loading base model: {BASE_MODEL}")
    tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL)
    model = AutoModelForSequenceClassification.from_pretrained(
        BASE_MODEL, num_labels=2, id2label=ID2LABEL, label2id=LABEL2ID
    )

    tokenized = dataset.map(tokenize_factory(tokenizer), batched=True, remove_columns=["subject", "body", "text_input"])
    tokenized = tokenized.rename_column("label", "labels")
    tokenized.set_format("torch")

    steps_per_epoch = max(1, len(tokenized["train"]) // args.batch_size)
    total_steps = int(steps_per_epoch * args.epochs)
    warmup_steps = max(1, int(total_steps * 0.1))

    training_args = TrainingArguments(
        output_dir=str(Path(args.output_dir) / "checkpoints"),
        num_train_epochs=args.epochs,
        per_device_train_batch_size=args.batch_size,
        per_device_eval_batch_size=args.batch_size,
        learning_rate=2e-5,
        weight_decay=0.01,
        warmup_steps=warmup_steps,
        fp16=torch.cuda.is_available(),
        eval_strategy="steps",
        eval_steps=2000,
        save_strategy="steps",
        save_steps=2000,
        save_total_limit=2,
        load_best_model_at_end=True,
        metric_for_best_model="f1",
        greater_is_better=True,
        logging_steps=100,
        report_to=[],
        dataloader_num_workers=2,
    )

    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=tokenized["train"],
        eval_dataset=tokenized["validation"],
        compute_metrics=compute_metrics,
        callbacks=[EarlyStoppingCallback(early_stopping_patience=2)],
    )

    print("Starting training...")
    started = time.time()
    trainer.train()
    elapsed = time.time() - started
    print(f"Training took {elapsed / 60:.1f} minutes")

    print("Evaluating on held-out TEST set (never used for training or model selection)...")
    test_metrics = trainer.evaluate(eval_dataset=tokenized["test"], metric_key_prefix="test")
    print(json.dumps(test_metrics, indent=2))

    preds = trainer.predict(tokenized["test"])
    pred_labels = np.argmax(preds.predictions, axis=-1)
    cm = confusion_matrix(preds.label_ids, pred_labels).tolist()

    final_dir = Path(args.output_dir) / "final"
    final_dir.mkdir(parents=True, exist_ok=True)
    trainer.save_model(str(final_dir))
    tokenizer.save_pretrained(str(final_dir))

    report = {
        "base_model": BASE_MODEL,
        "max_length": MAX_LENGTH,
        "train_rows": len(dataset["train"]),
        "validation_rows": len(dataset["validation"]),
        "test_rows": len(dataset["test"]),
        "training_minutes": round(elapsed / 60, 1),
        "test_metrics": {k: v for k, v in test_metrics.items() if isinstance(v, (int, float))},
        "confusion_matrix": {"labels": ["LEGITIMATE", "PHISHING"], "matrix": cm},
        "smoke_test": args.smoke_test,
    }
    with open(final_dir / "training_report.json", "w") as f:
        json.dump(report, f, indent=2)
    print(f"Saved model + report to {final_dir}")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()

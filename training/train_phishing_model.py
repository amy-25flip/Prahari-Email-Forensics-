"""Fine-tune bert-base-uncased on the team's own labeled phishing dataset.

Fine-tuned from the public bert-base-uncased checkpoint (not a randomly-initialized
"from scratch" pretraining run, and not a continuation of the current pretrained
ealvaradob/bert-finetuned-phishing checkpoint) -- matching the input format the app
actually uses at inference time (subject + "\n" + body, see backend/local_model.py::classify).

Dedup note: the source dataset's own train/validation/test split assignment was found
(via independent review) to leak near-duplicate content across splits -- several source
CSVs came pre-split upstream (e.g. one corpus's own train/eval/test), and near-duplicates
that existed across THAT boundary carried into the merged splits. bert-base-uncased's
tokenizer lowercases and effectively collapses whitespace internally, so content that
differs only by case/whitespace reaches the model as identical or near-identical token
sequences -- a real leakage risk for the held-out test number, not just a cosmetic one.
This script ignores the dataset's own split column, deduplicates on normalized
(lowercased, whitespace-collapsed) subject+body across the *entire* pool, then performs
a fresh stratified random split -- so no evaluation split can share content with train.

Caveat (confirmed via independent review): this only removes *exact* normalized duplicates.
It does not catch fuzzy/template-level near-duplicates -- the same phishing kit with one URL
or recipient name changed, HTML/text extraction differences, or the same campaign repeated
with minor variation. So the reported test accuracy should be read as "deduped random-split
test accuracy," not as evidence of generalization to unseen campaigns/sources/domains.
"""
import argparse
import json
import os
import re
import time
from pathlib import Path

import numpy as np
import pandas as pd
import torch
from datasets import Dataset, DatasetDict, load_dataset
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, roc_auc_score, confusion_matrix
from sklearn.model_selection import train_test_split
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
SPLIT_SEED = 42
SPLIT_RATIOS = {"train": 0.8, "validation": 0.1, "test": 0.1}


def build_text(example):
    subject = (example.get("subject") or "").strip()
    body = (example.get("body") or "").strip()
    example["text_input"] = f"{subject}\n{body}"
    return example


def _dedup_key(subject, body):
    # NaN is truthy in Python (`bool(float('nan')) is True`), so `subject or ""` does NOT
    # catch missing values -- it silently embeds the literal string "nan" instead, which
    # breaks matching against the same row's content when it was NOT NaN in another split
    # (e.g. loaded as Python None elsewhere). Must use pd.isna() to be correct here.
    subject = "" if pd.isna(subject) else str(subject)
    body = "" if pd.isna(body) else str(body)
    text = (subject + "\n" + body).lower()
    return re.sub(r"\s+", " ", text).strip()


def load_deduplicated_and_resplit():
    """Pool all three source files, drop cross-source near-duplicates (by normalized
    subject+body, since that's what the uncased tokenizer effectively sees), then produce
    a fresh stratified train/validation/test split so no eval row can leak into train."""
    frames = []
    for name in ("train", "validation", "test"):
        df = pd.read_csv(DATA_DIR / f"{name}.csv", usecols=["subject", "body", "label"])
        frames.append(df)
    pool = pd.concat(frames, ignore_index=True)
    pool = pool[pool["label"].isin([0, 1])].reset_index(drop=True)
    before = len(pool)

    pool["_dedup_key"] = [_dedup_key(s, b) for s, b in zip(pool["subject"], pool["body"])]
    label_conflicts = pool.groupby("_dedup_key")["label"].nunique()
    conflicting_keys = set(label_conflicts[label_conflicts > 1].index)
    if conflicting_keys:
        pool = pool[~pool["_dedup_key"].isin(conflicting_keys)]
    pool = pool.drop_duplicates(subset="_dedup_key", keep="first").reset_index(drop=True)
    removed = before - len(pool)

    train_df, rest_df = train_test_split(
        pool, test_size=(1 - SPLIT_RATIOS["train"]), stratify=pool["label"], random_state=SPLIT_SEED
    )
    val_fraction_of_rest = SPLIT_RATIOS["validation"] / (SPLIT_RATIOS["validation"] + SPLIT_RATIOS["test"])
    val_df, test_df = train_test_split(
        rest_df, test_size=(1 - val_fraction_of_rest), stratify=rest_df["label"], random_state=SPLIT_SEED
    )

    splits = {"train": train_df, "validation": val_df, "test": test_df}
    keys_by_split = {name: set(df["_dedup_key"]) for name, df in splits.items()}
    for a, b in (("train", "validation"), ("train", "test"), ("validation", "test")):
        overlap = keys_by_split[a] & keys_by_split[b]
        if overlap:
            # Explicit exception, not assert: asserts are stripped under `python -O`, and a
            # leakage check this load-bearing must not be silently skippable.
            raise RuntimeError(f"Cross-split leakage between {a} and {b}: {len(overlap)} shared normalized rows")

    dedup_stats = {
        "rows_before_dedup": before,
        "rows_removed_as_near_duplicate_or_label_conflict": removed,
        "label_conflicting_groups_removed": len(conflicting_keys),
    }
    dataset = DatasetDict({
        name: Dataset.from_pandas(df.drop(columns="_dedup_key").reset_index(drop=True))
        for name, df in splits.items()
    })
    return dataset, dedup_stats


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

    print("Loading dataset (deduplicating cross-split near-duplicates, fresh stratified split)...")
    dataset, dedup_stats = load_deduplicated_and_resplit()
    print(f"Dedup: {dedup_stats}")

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
        "fine_tuned_from": "public bert-base-uncased checkpoint, not a from-scratch/randomly-initialized run and not a continuation of ealvaradob/bert-finetuned-phishing",
        "test_metric_caveat": "Deduped random-split test accuracy: exact normalized duplicates were removed across a fresh stratified split, but fuzzy/template-level near-duplicates (same kit/campaign with minor edits) were not detected or excluded. Not evidence of generalization to unseen campaigns, sources, or domains.",
        "max_length": MAX_LENGTH,
        "dedup_stats": dedup_stats,
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

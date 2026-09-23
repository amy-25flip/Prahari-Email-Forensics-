# -*- coding: utf-8 -*-
"""Post-hoc probability calibration for the already-trained phishing classifier.

Motivation (this project's own existing caveat, in backend/local_model.py):
classify() reports the model's raw softmax probability and says so honestly
("Uncalibrated model probability ... independent evaluation pending"). A raw
softmax score from a fine-tuned transformer is well known to be systematically
overconfident (Guo et al., "On Calibration of Modern Neural Networks", ICML
2017) -- it is NOT the same thing as "this many times out of 100, a score
like this one is actually right." This script makes that caveat a measured
number instead of a guess:

1. Fits a single-parameter temperature T on the VALIDATION split (never test
   -- fitting on the same data you evaluate calibration on would be a
   leakage of a different kind than the near-duplicate one this project's
   other evaluation script already covers) by grid-searching the T that
   minimizes negative log-likelihood.
2. Reports the Brier score (lower is better; a proper scoring rule for
   probabilistic binary predictions) and a 10-bin reliability diagram (mean
   predicted probability vs actual positive fraction per bin) on the TEST
   split, for both the raw (T=1) and temperature-scaled probabilities.
3. Writes the fitted temperature to calibration.json next to the model
   weights ONLY if it demonstrably improves test-set Brier score -- never
   silently turn a currently-honest "uncalibrated" state into a dishonestly
   labeled "'calibrated' but not actually better" one.

Honest scope: temperature scaling only rescales confidence uniformly; it
cannot fix a model whose ranking of examples is itself wrong, and it never
changes which class wins (argmax is invariant under a positive temperature --
see backend/test_local_model.py's direct regression test for that invariant).

Usage:
    python training/calibration_analysis.py [--sample-per-subset N]
"""
import argparse
import json
import math
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from train_phishing_model import load_deduplicated_and_resplit, MAX_LENGTH  # noqa: E402

sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))
from local_model import _phishing_label_index, MIN_TEMPERATURE, MAX_TEMPERATURE  # noqa: E402

MODEL_DIR = Path(__file__).parent / "output" / "phishing-bert-v1" / "final"
CALIBRATION_PATH = MODEL_DIR / "calibration.json"
# Codex review: a raw `scaled_brier < raw_brier` gate would write the file for
# a difference like 0.05004 vs 0.05005 -- numerically lower on one sample, not
# a "demonstrable" improvement. Require a minimum absolute margin instead.
MIN_BRIER_IMPROVEMENT = 0.001


def load_model_once():
    from transformers import AutoModelForSequenceClassification, AutoTokenizer
    tokenizer = AutoTokenizer.from_pretrained(MODEL_DIR, local_files_only=True)
    model = AutoModelForSequenceClassification.from_pretrained(MODEL_DIR, local_files_only=True)
    model.eval()
    return tokenizer, model


def run_logits(tokenizer, model, texts, batch_size=32):
    import torch
    chunks = []
    with torch.no_grad():
        for i in range(0, len(texts), batch_size):
            batch = texts[i:i + batch_size]
            enc = tokenizer(batch, truncation=True, max_length=MAX_LENGTH, padding=True, return_tensors="pt")
            chunks.append(model(**enc).logits)
    return torch.cat(chunks, dim=0)


def phishing_probabilities(logits, temperature, phishing_index):
    import torch
    probs = torch.softmax(logits / temperature, dim=-1)
    return probs[:, phishing_index].tolist()


def negative_log_likelihood(probs, labels):
    eps = 1e-12
    total = 0.0
    for p, y in zip(probs, labels):
        p = min(max(p, eps), 1 - eps)
        total += -(y * math.log(p) + (1 - y) * math.log(1 - p))
    return total / len(labels)


def brier_score(probs, labels):
    return sum((p - y) ** 2 for p, y in zip(probs, labels)) / len(labels)


def reliability_bins(probs, labels, n_bins=10):
    bins = [[] for _ in range(n_bins)]
    for p, y in zip(probs, labels):
        bins[min(int(p * n_bins), n_bins - 1)].append((p, y))
    rows = []
    for i, entries in enumerate(bins):
        lo, hi = i / n_bins, (i + 1) / n_bins
        if not entries:
            rows.append({"bin": f"{lo:.1f}-{hi:.1f}", "count": 0, "mean_predicted": None, "actual_positive_fraction": None})
            continue
        mean_pred = sum(p for p, _ in entries) / len(entries)
        actual = sum(y for _, y in entries) / len(entries)
        rows.append({"bin": f"{lo:.1f}-{hi:.1f}", "count": len(entries),
                     "mean_predicted": round(mean_pred, 4), "actual_positive_fraction": round(actual, 4)})
    return rows


def fit_temperature(logits, labels, phishing_index, lo=0.5, hi=5.0, step=0.02):
    best_t, best_nll = 1.0, None
    t = lo
    steps = int(round((hi - lo) / step)) + 1
    for i in range(steps):
        t = round(lo + i * step, 2)
        nll = negative_log_likelihood(phishing_probabilities(logits, t, phishing_index), labels)
        if best_nll is None or nll < best_nll:
            best_nll, best_t = nll, t
    return best_t, best_nll


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--sample-per-subset", type=int, default=4000,
                         help="Max rows for the validation-fit and test-eval passes (full splits are slow on CPU). Must be a positive integer.")
    args = parser.parse_args()
    if args.sample_per_subset <= 0:
        parser.error("--sample-per-subset must be a positive integer")

    print("Loading and re-splitting the full dataset (same code/seed as training)...")
    t0 = time.perf_counter()
    dataset, dedup_stats = load_deduplicated_and_resplit()
    print(f"  done in {time.perf_counter() - t0:.1f}s. {dedup_stats}")

    val_df = dataset["validation"].to_pandas()
    test_df = dataset["test"].to_pandas()

    def sample(df, n):
        return df if len(df) <= n else df.sample(n=n, random_state=42)

    val_sample = sample(val_df, args.sample_per_subset)
    test_sample = sample(test_df, args.sample_per_subset)

    if not MODEL_DIR.exists():
        print(f"\nModel not found at {MODEL_DIR}; cannot run calibration analysis.")
        return

    print("\nLoading the trained model once (reused for validation-fit and test-eval)...")
    t0 = time.perf_counter()
    tokenizer, model = load_model_once()
    if len(model.config.id2label) != 2:
        # negative_log_likelihood()/brier_score() below are binary-only (they
        # treat the phishing-column probability as if 1-p were the entire
        # remaining probability mass) -- silently running them against a
        # >2-class model would produce numbers that look plausible but are
        # simply wrong.
        raise SystemExit(f"This script's NLL/Brier math is binary-only, but the model has "
                          f"{len(model.config.id2label)} labels ({model.config.id2label}). Refusing to produce "
                          "misleading calibration numbers for a non-binary model.")
    phishing_index = _phishing_label_index(model.config.id2label)
    print(f"  done in {time.perf_counter() - t0:.1f}s.")

    print(f"\nRunning model on validation set ({len(val_sample)} of {len(val_df)} rows"
          f"{' -- SAMPLED' if len(val_sample) < len(val_df) else ''}) to fit temperature...")
    t0 = time.perf_counter()
    val_logits = run_logits(tokenizer, model, [f"{s}\n{b}" for s, b in zip(val_sample["subject"], val_sample["body"])])
    val_labels = list(val_sample["label"])
    print(f"  done in {time.perf_counter() - t0:.1f}s.")

    search_lo, search_hi = 0.5, 5.0
    best_t, best_nll = fit_temperature(val_logits, val_labels, phishing_index, lo=search_lo, hi=search_hi)
    raw_val_nll = negative_log_likelihood(phishing_probabilities(val_logits, 1.0, phishing_index), val_labels)
    print(f"  Fitted temperature T={best_t} (validation NLL={best_nll:.4f}; T=1.0 validation NLL={raw_val_nll:.4f})")
    if best_t in (search_lo, search_hi):
        print(f"  WARNING: the fitted temperature landed exactly on the search boundary ({best_t}) -- "
              f"the true optimum may lie outside the searched range [{search_lo}, {search_hi}]. "
              "Widen search_lo/search_hi above and re-run before trusting this fit.")

    print(f"\nRunning model on test set ({len(test_sample)} of {len(test_df)} rows"
          f"{' -- SAMPLED' if len(test_sample) < len(test_df) else ''}) to evaluate calibration...")
    t0 = time.perf_counter()
    test_logits = run_logits(tokenizer, model, [f"{s}\n{b}" for s, b in zip(test_sample["subject"], test_sample["body"])])
    test_labels = list(test_sample["label"])
    print(f"  done in {time.perf_counter() - t0:.1f}s.")

    raw_probs = phishing_probabilities(test_logits, 1.0, phishing_index)
    scaled_probs = phishing_probabilities(test_logits, best_t, phishing_index)
    raw_brier = brier_score(raw_probs, test_labels)
    scaled_brier = brier_score(scaled_probs, test_labels)

    test_sampled = len(test_sample) < len(test_df)
    val_sampled = len(val_sample) < len(val_df)
    print("\n=== Summary (test set, n={}{}) ===".format(len(test_sample), ' -- SAMPLED' if test_sampled else ' -- full split'))
    print(f"  Raw (T=1.0)               Brier score: {raw_brier:.4f}")
    print(f"  Temperature-scaled (T={best_t})  Brier score: {scaled_brier:.4f}")

    print("\n=== Reliability diagram -- raw probabilities ===")
    for row in reliability_bins(raw_probs, test_labels):
        print(f"  {row}")
    print("\n=== Reliability diagram -- temperature-scaled probabilities ===")
    for row in reliability_bins(scaled_probs, test_labels):
        print(f"  {row}")

    improvement = raw_brier - scaled_brier
    temperature_in_bounds = math.isfinite(best_t) and MIN_TEMPERATURE <= best_t <= MAX_TEMPERATURE
    if improvement >= MIN_BRIER_IMPROVEMENT and temperature_in_bounds:
        CALIBRATION_PATH.write_text(json.dumps({
            "temperature": best_t,
            "fitted_on": "validation split (same dedup/split code+seed as training); grid search minimizing NLL",
            "raw_test_brier_score": round(raw_brier, 4),
            "calibrated_test_brier_score": round(scaled_brier, 4),
            "brier_improvement": round(improvement, 4),
            "sample_sizes": {"validation_fit": len(val_sample), "validation_full": len(val_df),
                             "validation_sampled": val_sampled,
                             "test_eval": len(test_sample), "test_full": len(test_df), "test_sampled": test_sampled},
            "note": "Temperature scaling only rescales confidence (argmax is invariant under a positive temperature, "
                    "so it never changes which class wins); it improves confidence calibration, not detection "
                    "quality, and may not generalize to real-world drift. The write decision below used the SAME "
                    "test split as the reported Brier score (selected because it cleared a minimum improvement "
                    "margin), so this test Brier score is a selection criterion, not a purely independent final "
                    "check -- treat it as indicative, not as an unbiased generalization estimate.",
        }, indent=2), encoding="utf-8")
        print(f"\nWrote {CALIBRATION_PATH} -- temperature scaling improved test-set Brier score by {improvement:.4f} "
              f"(>= the {MIN_BRIER_IMPROVEMENT} minimum margin) and the fitted temperature is within the sane bound.")
    elif not temperature_in_bounds:
        print(f"\nFitted temperature {best_t} falls outside the accepted [{MIN_TEMPERATURE}, {MAX_TEMPERATURE}] bound "
              f"local_model.py enforces at load time -- leaving the model uncalibrated (no {CALIBRATION_PATH} written) "
              "rather than writing a file that would just be rejected (or worse, silently reinterpreted) downstream.")
    else:
        print(f"\nTemperature scaling did not clear the minimum {MIN_BRIER_IMPROVEMENT}-point Brier improvement margin "
              f"({improvement:+.4f}, raw {raw_brier:.4f} vs scaled {scaled_brier:.4f}) -- "
              f"leaving the model uncalibrated (no {CALIBRATION_PATH} written); the raw probability, honestly labeled "
              "'uncalibrated', remains the more truthful choice than a 'calibrated' label that isn't demonstrably better.")


if __name__ == "__main__":
    main()

# -*- coding: utf-8 -*-
"""Adversarial-robustness evaluation for the already-trained phishing classifier,
covering evasion techniques NOT already handled by backend/adversarial.py
(homoglyph substitution + zero-width injection). Per the project roadmap:
"Broader adversarial-robustness testing (paraphrase, padding, truncation
attacks - beyond today's homoglyph/zero-width coverage)".

This script does not retrain anything. It takes phishing-labeled rows from
the held-out TEST split that the model ALREADY correctly classifies as
phishing at baseline (perturbing something the model never caught in the
first place tells you nothing about evasion), applies three real, offline,
deterministic perturbations, and measures how often each one flips the
verdict or meaningfully lowers the phishing probability:

1. PADDING attack: append a large block of neutral, benign filler text after
   the real phishing content, diluting the malicious signal with volume -- a
   well-known "good word attack" class against text classifiers.
2. TRUNCATION-SHIFT attack: prepend enough benign filler BEFORE the real
   phishing content that it gets pushed past the model's own MAX_LENGTH
   token-truncation point -- exploiting the SAME truncation boundary
   training/evaluate_near_duplicate_safety.py's model-view signature already
   had to account for elsewhere in this project.
3. KEYWORD-SUBSTITUTION attack (rule-based, fully offline, no LLM call):
   swaps a static list of common phishing trigger words/phrases for close
   synonyms -- a cheap, deterministic stand-in for the roadmap's
   "paraphrase" entry, without incurring an actual LLM call or needing any
   external dataset.

Honest scope: this measures robustness to three SPECIFIC, cheap, offline
perturbation classes on a SAMPLE of already-detected phishing rows. It is
NOT a comprehensive adversarial-robustness certification -- a determined
attacker with white-box model access, or a real LLM-generated paraphrase,
could plausibly do meaningfully worse than these fixed, hand-authored
perturbations.

Usage:
    python training/adversarial_robustness_eval.py [--sample-size N]
"""
import argparse
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from train_phishing_model import load_deduplicated_and_resplit, MAX_LENGTH  # noqa: E402

sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))
from local_model import _phishing_label_index  # noqa: E402

MODEL_DIR = Path(__file__).parent / "output" / "phishing-bert-v1" / "final"

# Neutral, benign filler wording -- deliberately generic business-email
# boilerplate, repeated to reach a target word budget. Not sourced from any
# dataset; its only job is to be long, neutral, and non-phishing-flavored.
_FILLER_SENTENCE = ("Thank you for your continued business with our team. "
                    "We appreciate your patience while we process this routine matter. "
                    "Please let us know if you have any questions about our regular update.")

_SYNONYM_SUBSTITUTIONS = [
    (re.compile(r'\bverify\b', re.I), 'confirm'),
    (re.compile(r'\burgent\b', re.I), 'time-sensitive'),
    (re.compile(r'\bimmediately\b', re.I), 'without delay'),
    (re.compile(r'\bpassword\b', re.I), 'passcode'),
    (re.compile(r'\bclick here\b', re.I), 'follow this link'),
    (re.compile(r'\baccount\b', re.I), 'profile'),
    (re.compile(r'\bsuspended\b', re.I), 'restricted'),
    (re.compile(r'\bupdate your information\b', re.I), 'refresh your details'),
    (re.compile(r'\bconfirm your identity\b', re.I), 'validate who you are'),
    (re.compile(r'\bact now\b', re.I), 'respond promptly'),
]


def _clean(value):
    # A pandas NaN is truthy in Python, so f"{value}" on a missing subject/
    # body would embed the literal string "nan" rather than treating it as
    # missing -- the same class of bug train_phishing_model.py's _dedup_key
    # and training/calibration_analysis.py's _clean() already had to fix.
    import pandas as pd
    return "" if pd.isna(value) else str(value)


def _filler_words(target_extra_words):
    base_words = _FILLER_SENTENCE.split()
    repeats = target_extra_words // len(base_words) + 1
    return (base_words * repeats)[:target_extra_words]


def pad_attack(text, target_extra_words=400):
    """Dilutes the phishing signal with bulk -- position doesn't matter here,
    so a word-count budget is fine; this attack never claims to guarantee
    anything about the model's own token-truncation boundary."""
    return text + '\n' + ' '.join(_filler_words(target_extra_words))


def required_filler_word_count(tokenizer, max_length, safety_margin_tokens=8, max_filler_words=5000):
    """Tokenizer-VERIFIED (not word-count-assumed): how many _FILLER_SENTENCE
    words are needed so that tokenizing them ALONE reaches at least
    max_length + safety_margin_tokens real tokens. Computed ONCE per
    (tokenizer, max_length) -- it depends only on the filler text and the
    tokenizer, not on any individual row being attacked, so callers should
    compute it once and reuse it via truncation_shift_attack() below rather
    than re-deriving it per row. safety_margin_tokens covers BERT's own
    [CLS]/[SEP] special tokens, so the boundary check has real margin, not
    an exact off-by-one-token race.

    Codex review (Medium): an earlier version picked a fixed
    target_extra_words=400 word budget and asserted the truncation claim
    without ever checking real token counts -- a filler/tokenizer change
    could have silently weakened the attack while the output still said
    "truncation-shift"."""
    target_tokens = max_length + safety_margin_tokens
    base_words = _FILLER_SENTENCE.split()
    words = []
    while True:
        words.append(base_words[len(words) % len(base_words)])
        token_count = len(tokenizer(' '.join(words), add_special_tokens=False)['input_ids'])
        if token_count >= target_tokens:
            return len(words)
        if len(words) >= max_filler_words:
            raise RuntimeError(f'Could not reach {target_tokens} filler tokens within {max_filler_words} words -- '
                                'the filler sentence may be tokenizing far shorter than expected per word; '
                                'investigate before trusting any truncation-shift result.')


def truncation_shift_attack(text, filler_word_count):
    """Prepends exactly `filler_word_count` filler words (a count already
    tokenizer-verified by required_filler_word_count() to reach past the
    model's truncation boundary) before `text`."""
    return ' '.join(_filler_words(filler_word_count)) + '\n' + text


def keyword_substitution_attack(text):
    result = text
    for pattern, replacement in _SYNONYM_SUBSTITUTIONS:
        result = pattern.sub(replacement, result)
    return result


def load_model_once():
    from transformers import AutoModelForSequenceClassification, AutoTokenizer
    tokenizer = AutoTokenizer.from_pretrained(MODEL_DIR, local_files_only=True)
    model = AutoModelForSequenceClassification.from_pretrained(MODEL_DIR, local_files_only=True)
    model.eval()
    return tokenizer, model


def run_probs(tokenizer, model, texts, phishing_index, batch_size=32):
    import torch
    probs = []
    with torch.no_grad():
        for i in range(0, len(texts), batch_size):
            batch = texts[i:i + batch_size]
            enc = tokenizer(batch, truncation=True, max_length=MAX_LENGTH, padding=True, return_tensors="pt")
            logits = model(**enc).logits
            assert logits.shape[0] == len(batch), f'model returned {logits.shape[0]} rows for a batch of {len(batch)}'
            assert logits.shape[1] > phishing_index, f'phishing_index {phishing_index} out of range for {logits.shape[1]} classes'
            probs.extend(torch.softmax(logits, dim=-1)[:, phishing_index].tolist())
    assert len(probs) == len(texts), f'expected {len(texts)} probabilities, got {len(probs)}'
    return probs


def find_baseline_detected(tokenizer, model, phishing_df, phishing_index, sample_size, seed=42):
    """Scans phishing-labeled rows in randomized (but seeded/deterministic)
    order, in batches, until `sample_size` baseline-correctly-detected rows
    are found or the entire phishing split is exhausted. Codex review
    (Medium): a fixed-size scan (e.g. 3x sample_size) can silently return
    fewer than sample_size rows without any warning, making a tiny,
    underpowered n look like a normal-looking robustness result -- this
    keeps scanning (bounded by the real split size, never infinite) and
    always reports exactly how many were found versus how many were
    scanned, so a shortfall is visible, never silent.

    Self-caught bug (found via a real run producing a nonsensical "33.3%
    conditional retention" against a model independently verified elsewhere
    in this project at ~99% recall): an earlier version's inner loop broke
    out of appending to detected_texts as soon as sample_size successes were
    collected, but the OUTER scanned counter still added the FULL chunk size
    every time regardless of where the break happened -- so a capped
    numerator (exactly sample_size) got compared against an uncapped
    denominator (the whole chunk, even the part after the target was
    already met and stopped being counted), understating the true retention
    rate. Model inference itself is unaffected either way (run_probs()
    always scores the whole chunk in one batched call; nothing was actually
    skipped) -- this was purely a Python-level bookkeeping bug in what got
    reported, not a difference in what got computed. Fixed by never capping
    the counting loop early: every scanned row's true hit/miss is tallied,
    and only the STORED sample (used for the actual attacks) is capped to
    sample_size.

    Returns (detected_texts, detected_probs, total_scanned, total_detected_among_scanned)."""
    pool = phishing_df.sample(frac=1, random_state=seed).reset_index(drop=True)
    batch_size = max(sample_size * 3, 100)
    detected_texts, detected_probs = [], []
    total_detected = 0
    scanned = 0
    while len(detected_texts) < sample_size and scanned < len(pool):
        chunk = pool.iloc[scanned:min(scanned + batch_size, len(pool))]
        texts = [f"{_clean(s)}\n{_clean(b)}" for s, b in zip(chunk["subject"], chunk["body"])]
        probs = run_probs(tokenizer, model, texts, phishing_index)
        for text, prob in zip(texts, probs):
            if prob >= 0.5:
                total_detected += 1
                if len(detected_texts) < sample_size:
                    detected_texts.append(text)
                    detected_probs.append(prob)
        scanned += len(chunk)
    return detected_texts, detected_probs, scanned, total_detected


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--sample-size", type=int, default=300,
                         help="How many baseline-correctly-detected phishing rows to test each attack against. Must be a positive integer.")
    args = parser.parse_args()
    if args.sample_size <= 0:
        parser.error("--sample-size must be a positive integer")

    print("Loading and re-splitting the full dataset (same code/seed as training)...")
    t0 = time.perf_counter()
    dataset, _ = load_deduplicated_and_resplit()
    print(f"  done in {time.perf_counter() - t0:.1f}s.")

    test_df = dataset["test"].to_pandas()
    phishing_df = test_df[test_df["label"] == 1].reset_index(drop=True)

    if not MODEL_DIR.exists():
        print(f"\nModel not found at {MODEL_DIR}; cannot run adversarial-robustness evaluation.")
        return

    print("\nLoading the trained model once...")
    tokenizer, model = load_model_once()
    phishing_index = _phishing_label_index(model.config.id2label)

    print(f"\nScanning phishing test rows (up to all {len(phishing_df)}) to find {args.sample_size} baseline-correctly-detected ones...")
    t0 = time.perf_counter()
    baseline_texts, baseline_probs, scanned, total_detected = find_baseline_detected(
        tokenizer, model, phishing_df, phishing_index, args.sample_size)
    print(f"  done in {time.perf_counter() - t0:.1f}s.")
    print(f"  {total_detected} of {scanned} scanned phishing rows were correctly detected at baseline "
          f"({100 * total_detected / max(1, scanned):.1f}% conditional retention on this sample); "
          f"using {len(baseline_texts)} of those {total_detected} as the fixed basis for every attack below.")
    if len(baseline_texts) < args.sample_size:
        print(f"  WARNING: requested {args.sample_size} baseline-detected rows but only found {len(baseline_texts)} "
              f"after scanning the entire available phishing test split ({len(phishing_df)} rows). Every result "
              "below is based on this SMALLER n -- treat percentages with correspondingly less confidence.")
    if not baseline_texts:
        print("No baseline-detected rows found; cannot evaluate evasion attacks.")
        return

    baseline_mean = sum(baseline_probs) / len(baseline_probs)
    print(f"\n=== Baseline (n={len(baseline_texts)}, all correctly detected by construction) ===")
    print(f"  Mean phishing probability: {baseline_mean * 100:.1f}%")
    print("  Scope: this is CONDITIONAL retention among phishing rows the model already caught, not overall "
          "test-set robustness -- baseline-detected rows likely skew toward higher starting confidence.")

    print("\nDeriving the tokenizer-verified filler length for the truncation-shift attack...")
    filler_word_count = required_filler_word_count(tokenizer, MAX_LENGTH)
    print(f"  {filler_word_count} filler words reliably exceed the {MAX_LENGTH}-token truncation boundary "
          "(verified with the real tokenizer, not assumed from a word count).")

    attacks = {
        "padding": [pad_attack(t) for t in baseline_texts],
        "truncation_shift": [truncation_shift_attack(t, filler_word_count) for t in baseline_texts],
        "keyword_substitution": [keyword_substitution_attack(t) for t in baseline_texts],
    }

    print("\n=== Attack results ===")
    for name, perturbed_texts in attacks.items():
        t0 = time.perf_counter()
        probs = run_probs(tokenizer, model, perturbed_texts, phishing_index)
        elapsed = time.perf_counter() - t0
        still_detected = sum(1 for p in probs if p >= 0.5)
        evaded = len(probs) - still_detected
        mean_prob = sum(probs) / len(probs)
        print(f"  {name:22s}: {elapsed:.1f}s. Still detected: {still_detected}/{len(probs)} "
              f"({100 * still_detected / len(probs):.1f}%). Evaded: {evaded} ({100 * evaded / len(probs):.1f}%). "
              f"Mean phishing probability: {mean_prob * 100:.1f}% (drop of {(baseline_mean - mean_prob) * 100:.1f} "
              "points from baseline).")

    print("\nScope: measures robustness to 3 specific, cheap, offline perturbation classes on a SAMPLE of "
          "already-detected phishing rows -- not a comprehensive adversarial-robustness certification.")


if __name__ == "__main__":
    main()

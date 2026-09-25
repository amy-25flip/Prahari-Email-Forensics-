# -*- coding: utf-8 -*-
"""Plain-assertion sanity checks for the pure perturbation functions in
adversarial_robustness_eval.py (training/ has no pytest dependency; run
directly: python test_adversarial_robustness_eval.py). Most tests don't load
the trained model -- they test text-perturbation logic in isolation. One
test (test_truncation_shift_attack_actually_crosses_the_real_token_boundary)
loads the real tokenizer only (fast, no model weights) to verify the
tokenizer-backed truncation claim, skipped if the model isn't present."""
import pandas as pd
import adversarial_robustness_eval as are
from adversarial_robustness_eval import (
    pad_attack, truncation_shift_attack, keyword_substitution_attack,
    required_filler_word_count, find_baseline_detected, _filler_words, MODEL_DIR, MAX_LENGTH,
)


def test_filler_words_returns_exactly_the_requested_count():
    assert len(_filler_words(50)) == 50
    assert len(_filler_words(1)) == 1
    assert len(_filler_words(0)) == 0


def test_filler_words_is_deterministic():
    assert _filler_words(200) == _filler_words(200)


def test_pad_attack_appends_filler_after_the_original_text():
    original = "Verify your account now"
    padded = pad_attack(original, target_extra_words=20)
    assert padded.startswith(original)
    assert len(padded) > len(original)


def test_pad_attack_preserves_the_full_original_text_verbatim():
    original = "Verify your account now at http://evil.example/login"
    padded = pad_attack(original, target_extra_words=10)
    assert original in padded


def test_pad_attack_target_zero_adds_no_filler():
    original = "Verify your account now"
    assert pad_attack(original, target_extra_words=0) == original + '\n'


def test_truncation_shift_attack_prepends_filler_before_the_original_text():
    original = "Verify your account now"
    shifted = truncation_shift_attack(original, filler_word_count=20)
    assert shifted.endswith(original)
    assert not shifted.startswith(original)


def test_truncation_shift_attack_preserves_the_full_original_text_verbatim():
    original = "Verify your account now at http://evil.example/login"
    shifted = truncation_shift_attack(original, filler_word_count=10)
    assert original in shifted


def test_truncation_shift_attack_target_zero_adds_no_filler():
    original = "Verify your account now"
    assert truncation_shift_attack(original, filler_word_count=0) == '\n' + original


def test_truncation_shift_pushes_original_text_start_index_further_than_padding_does():
    # The whole point of the two attacks differing: truncation_shift moves
    # the original content's START position much later in the string (so it
    # can fall past a token-truncation boundary), while pad_attack leaves it
    # at position 0.
    original = "Verify your account now"
    padded = pad_attack(original, target_extra_words=50)
    shifted = truncation_shift_attack(original, filler_word_count=50)
    assert padded.index(original) == 0
    assert shifted.index(original) > 0


def test_keyword_substitution_swaps_known_trigger_words():
    original = "Please verify your account immediately, click here to reset your password."
    attacked = keyword_substitution_attack(original)
    assert 'verify' not in attacked.lower()
    assert 'immediately' not in attacked.lower()
    assert 'click here' not in attacked.lower()
    assert 'password' not in attacked.lower()
    assert 'confirm' in attacked.lower()


def test_keyword_substitution_handles_every_listed_multi_word_phrase():
    cases = {
        "click here now": "click here",
        "please update your information today": "update your information",
        "confirm your identity to proceed": "confirm your identity",
        "act now or lose access": "act now",
    }
    for text, phrase in cases.items():
        attacked = keyword_substitution_attack(text)
        assert phrase not in attacked.lower(), f'{phrase!r} was not substituted in {text!r} -> {attacked!r}'


def test_keyword_substitution_respects_word_boundaries():
    # "accounting" must not be mangled just because it contains "account".
    original = "Our accounting department will review this."
    assert keyword_substitution_attack(original) == original


def test_keyword_substitution_is_case_insensitive():
    attacked = keyword_substitution_attack("VERIFY your ACCOUNT")
    assert 'verify' not in attacked.lower() and 'account' not in attacked.lower()


def test_keyword_substitution_leaves_unrelated_text_unchanged():
    original = "Let's meet for lunch tomorrow at noon."
    assert keyword_substitution_attack(original) == original


def test_keyword_substitution_does_not_crash_on_empty_string():
    assert keyword_substitution_attack('') == ''


def test_pad_and_truncation_attacks_do_not_crash_on_empty_string():
    assert pad_attack('', target_extra_words=10) != ''  # filler still gets added
    assert truncation_shift_attack('', filler_word_count=10) != ''


def test_truncation_shift_attack_actually_crosses_the_real_token_boundary():
    # Regression: the whole attack's validity depends on the
    # ORIGINAL content actually starting past MAX_LENGTH tokens once
    # truncated -- this must be verified against the real tokenizer, not
    # assumed from a word count. Loads only the tokenizer (fast, no model
    # weights), skipped if this environment doesn't have the trained model.
    if not MODEL_DIR.exists():
        print("  (skipped: no trained model available in this environment)")
        return
    from transformers import AutoTokenizer
    tokenizer = AutoTokenizer.from_pretrained(MODEL_DIR, local_files_only=True)
    filler_word_count = required_filler_word_count(tokenizer, MAX_LENGTH)
    sentinel = "SENTINELTOKENVALUE12345"
    shifted = truncation_shift_attack(sentinel, filler_word_count)
    truncated_ids = tokenizer(shifted, truncation=True, max_length=MAX_LENGTH, add_special_tokens=True)['input_ids']
    truncated_text = tokenizer.decode(truncated_ids, skip_special_tokens=True)
    assert sentinel.lower() not in truncated_text.lower(), (
        f'sentinel content survived truncation -- the filler ({filler_word_count} words) did not actually '
        f'push it past the model\'s real {MAX_LENGTH}-token boundary')


def test_find_baseline_detected_reports_true_total_not_capped_at_sample_size():
    # Regression: a REAL run of this script reported "200 of 600 (33.3%)"
    # baseline detection against a model independently verified elsewhere in
    # this project at ~99% recall -- a manual reproduction of the exact same
    # 600-row chunk found 597/600 (99.5%) detected. The bug: the counting
    # loop capped the detected-count NUMERATOR at sample_size (200) as soon
    # as it was reached, but the scanned DENOMINATOR still reported the
    # full, uncapped chunk size (600) regardless. This directly tests
    # find_baseline_detected()'s bookkeeping against a controlled,
    # monkeypatched run_probs, so the exact bug is caught without needing
    # the real model.
    phishing_df = pd.DataFrame({
        'subject': [f'subj{i}' for i in range(10)],
        'body': [f'body{i}' for i in range(10)],
        'label': [1] * 10,
    })
    # 6 of 10 "detected" (prob >= 0.5) -- deliberately MORE successes than
    # sample_size=3, so a numerator-capping bug would show up as total_detected==3.
    fake_probs = [0.9, 0.9, 0.2, 0.9, 0.9, 0.1, 0.9, 0.3, 0.4, 0.9]

    original_run_probs = are.run_probs
    are.run_probs = lambda tokenizer, model, texts, phishing_index, batch_size=32: fake_probs
    try:
        detected_texts, detected_probs, scanned, total_detected = find_baseline_detected(
            tokenizer=None, model=None, phishing_df=phishing_df, phishing_index=1, sample_size=3, seed=0)
    finally:
        are.run_probs = original_run_probs

    assert scanned == 10, f'expected all 10 rows scanned in one batch, got {scanned}'
    assert total_detected == 6, f'expected the TRUE total of 6 successes, got {total_detected} (capping bug regressed)'
    assert len(detected_texts) == 3, 'stored sample must still be capped at sample_size for the actual attacks'
    assert len(detected_probs) == 3


def test_find_baseline_detected_stops_scanning_once_enough_batches_collected():
    # A second batch must not be scanned once sample_size is already met by
    # the first one -- verifies the outer while loop's stopping condition,
    # not just the inner counting fix above.
    phishing_df = pd.DataFrame({
        'subject': [f'subj{i}' for i in range(4)],
        'body': [f'body{i}' for i in range(4)],
        'label': [1] * 4,
    })
    call_count = [0]

    def fake_run_probs(tokenizer, model, texts, phishing_index, batch_size=32):
        call_count[0] += 1
        return [0.9] * len(texts)  # every row "detected"

    original_run_probs = are.run_probs
    are.run_probs = fake_run_probs
    try:
        detected_texts, detected_probs, scanned, total_detected = find_baseline_detected(
            tokenizer=None, model=None, phishing_df=phishing_df, phishing_index=1, sample_size=2, seed=0)
    finally:
        are.run_probs = original_run_probs

    assert call_count[0] == 1, 'should stop after the first batch once sample_size is already satisfied'
    assert scanned == 4  # the whole (small) pool fit in one batch
    assert total_detected == 4
    assert len(detected_texts) == 2


if __name__ == "__main__":
    tests = [v for k, v in list(globals().items()) if k.startswith("test_")]
    for fn in tests:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"\n{len(tests)} checks passed.")

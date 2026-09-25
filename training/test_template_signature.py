# -*- coding: utf-8 -*-
"""Plain-assertion sanity checks for template_signature() (training/ has no
pytest dependency; run directly: python test_template_signature.py).

Verifies the two properties the near-duplicate-safety evaluation depends on:
1. The same phishing-kit template with only its URL/recipient-number/email
   changed collapses to the SAME signature (that's the whole point -- it's
   what the exact-normalized dedup upstream misses).
2. Genuinely different wording does NOT collapse to the same signature (a
   signature that matched everything would be useless, not just imprecise)."""
from evaluate_near_duplicate_safety import template_signature, model_view_signature, _wilson_diff_note, MODEL_DIR


def test_same_template_different_url_collapses():
    a = template_signature("Verify your account", "Click http://evil1.example/login to verify now.")
    b = template_signature("Verify your account", "Click http://totally-different-domain.example/x to verify now.")
    assert a == b, "same template, different URL, must collapse to one signature"


def test_same_template_different_amount_collapses():
    # Only digits are masked, not arbitrary named entities (that would need a
    # real NER step, out of scope here) -- keep the name constant and vary
    # only the invoice number/amount/account digits.
    a = template_signature("Invoice #4821 due", "Dear John, please pay $500 to account 12345.")
    b = template_signature("Invoice #9999 due", "Dear John, please pay $999999 to account 67890.")
    assert a == b, "same template, different digits, must collapse to one signature"


def test_different_recipient_name_does_not_collapse():
    # Documents the real, current limitation: two rows differing ONLY by a
    # named recipient (no URL/email/digit difference) are NOT treated as the
    # same template. Honest scope, not a bug -- a future NER-based version
    # could close this gap, but doesn't invent that capability here.
    a = template_signature("Invoice due", "Dear John, please pay the attached invoice.")
    b = template_signature("Invoice due", "Dear Priya, please pay the attached invoice.")
    assert a != b


def test_same_template_different_email_collapses():
    a = template_signature("Password reset", "Contact support@help-desk1.example for assistance.")
    b = template_signature("Password reset", "Contact admin@another-helpdesk.example for assistance.")
    assert a == b


def test_genuinely_different_content_does_not_collapse():
    a = template_signature("Meeting tomorrow", "Are we still on for lunch at noon?")
    b = template_signature("Quarterly report", "Please review the attached financial summary by Friday.")
    assert a != b, "genuinely unrelated content must not share a signature"


def test_case_and_whitespace_insensitive():
    a = template_signature("URGENT: Verify Now", "Click here immediately!")
    b = template_signature("urgent:   verify   now", "click   here   immediately!")
    assert a == b


def test_missing_subject_or_body_does_not_crash():
    template_signature(None, "body only")
    template_signature("subject only", None)
    template_signature(None, None)


def test_nan_subject_or_body_treated_same_as_missing():
    # Regression: a pandas float NaN is truthy in Python, so
    # `value or ""` silently embeds the literal string "nan" instead of
    # treating it as missing -- the exact bug train_phishing_model.py's
    # _dedup_key already had to fix with pd.isna(). A NaN field and a real
    # None/empty field for the same other-field content must collapse to the
    # same signature, not differ because one hashed the string "nan".
    a = template_signature(float("nan"), "Please pay the attached invoice.")
    b = template_signature(None, "Please pay the attached invoice.")
    assert a == b, "NaN subject must be treated as missing, same as None"

    c = template_signature("Invoice due", float("nan"))
    d = template_signature("Invoice due", None)
    assert c == d, "NaN body must be treated as missing, same as None"


def test_wilson_diff_note_reports_a_ci_string():
    note = _wilson_diff_note(0.99, 1000, 0.95, 1000)
    assert "CI" in note and "+" in note


def test_wilson_diff_note_handles_empty_subset_without_crashing():
    assert _wilson_diff_note(0.5, 0, 0.5, 10) == "n/a (empty subset)"


def test_model_view_signature_survives_tokenizer_round_trip():
    # Regression: an earlier version masked URLs/emails/digits AFTER decoding
    # token ids back to text, but BERT's WordPiece decode re-spaces
    # punctuation (a URL comes back as "http : / / evil1. example / login"),
    # which silently broke the URL regex and made two same-template rows
    # NOT collapse. Masking must happen on the raw text before tokenization.
    if not MODEL_DIR.exists():
        print("  (skipped: no trained model available in this environment)")
        return
    from transformers import AutoTokenizer
    tokenizer = AutoTokenizer.from_pretrained(MODEL_DIR, local_files_only=True)
    a = model_view_signature(tokenizer, "Verify your account", "Click http://evil1.example/login now.")
    b = model_view_signature(tokenizer, "Verify your account", "Click http://other-domain.example/x now.")
    assert a == b, "same template, different URL, must still collapse under the model-view signature"
    c = model_view_signature(tokenizer, "Meeting tomorrow", "Are we still on for lunch?")
    assert a != c, "genuinely different content must not share a model-view signature"


if __name__ == "__main__":
    tests = [v for k, v in list(globals().items()) if k.startswith("test_")]
    for fn in tests:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"\n{len(tests)} checks passed.")

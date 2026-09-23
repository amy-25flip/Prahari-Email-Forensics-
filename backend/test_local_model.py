import pytest
import local_model


def test_exact_phishing_label_wins_over_negated_lookalike():
    # A naive `'phish' in name` first-match scan would pick label 0
    # ('not_phishing') here, since it ALSO contains "phishing" as a
    # substring -- silently inverting every verdict for this common
    # negative-class naming convention.
    assert local_model._phishing_label_index({0: 'not_phishing', 1: 'phishing'}) == 1
    assert local_model._phishing_label_index({0: 'non_phishing', 1: 'phishing'}) == 1
    assert local_model._phishing_label_index({0: 'phishing', 1: 'not_phishing'}) == 0


def test_substring_fallback_used_when_no_exact_label():
    assert local_model._phishing_label_index({0: 'legitimate', 1: 'phishing_email'}) == 1


def test_negated_substring_excluded_from_fallback_candidates():
    # No exact 'phishing' label and the only phish-containing label is
    # negated -- must raise rather than silently picking it.
    with pytest.raises(ValueError):
        local_model._phishing_label_index({0: 'not_phishing_email', 1: 'benign'})


def test_ambiguous_mapping_raises_instead_of_guessing():
    with pytest.raises(ValueError):
        local_model._phishing_label_index({0: 'phishing_v1', 1: 'phishing_v2'})


def test_no_phishing_label_at_all_raises():
    with pytest.raises(ValueError):
        local_model._phishing_label_index({0: 'spam', 1: 'ham'})


def test_deployed_team_trained_checkpoint_label_scheme_is_safe():
    # Confirmed via training/output/phishing-bert-v1/final/config.json:
    # {0: 'LEGITIMATE', 1: 'PHISHING'} -- exact match, case-insensitive,
    # no negation ambiguity.
    assert local_model._phishing_label_index({0: 'LEGITIMATE', 1: 'PHISHING'}) == 1


def test_missing_calibration_file_falls_back_to_uncalibrated(tmp_path):
    temperature, note = local_model._load_calibration(tmp_path)
    assert temperature == 1.0 and note == ''


def test_valid_calibration_file_is_applied(tmp_path):
    (tmp_path / 'calibration.json').write_text(
        '{"temperature": 1.8, "raw_test_brier_score": 0.05, "calibrated_test_brier_score": 0.03}', encoding='utf-8')
    temperature, note = local_model._load_calibration(tmp_path)
    assert temperature == 1.8
    assert 'T=1.8' in note and '0.05' in note and '0.03' in note


def test_malformed_calibration_json_falls_back_safely(tmp_path):
    (tmp_path / 'calibration.json').write_text('not valid json{{{', encoding='utf-8')
    assert local_model._load_calibration(tmp_path) == (1.0, '')


def test_non_positive_temperature_is_rejected(tmp_path):
    # A zero or negative temperature would divide-by-zero or flip logit sign
    # in classify() -- must never be trusted from a file, however it got there.
    (tmp_path / 'calibration.json').write_text('{"temperature": 0}', encoding='utf-8')
    assert local_model._load_calibration(tmp_path) == (1.0, '')
    (tmp_path / 'calibration.json').write_text('{"temperature": -2.0}', encoding='utf-8')
    assert local_model._load_calibration(tmp_path) == (1.0, '')


def test_infinite_temperature_is_rejected(tmp_path):
    # Regression (Codex Critical): json.loads() accepts non-standard
    # `Infinity`/`-Infinity`/`NaN` tokens, and 1e309 also overflows to inf in
    # Python. `float('inf') > 0` is True, so a naive positivity check alone
    # lets it through -- dividing logits by inf makes softmax UNIFORM, which
    # CAN flip argmax and change the reported label. That directly violates
    # "temperature scaling never changes which class wins". Must be rejected.
    (tmp_path / 'calibration.json').write_text('{"temperature": Infinity}', encoding='utf-8')
    assert local_model._load_calibration(tmp_path) == (1.0, '')
    (tmp_path / 'calibration.json').write_text('{"temperature": 1e309}', encoding='utf-8')
    assert local_model._load_calibration(tmp_path) == (1.0, '')
    (tmp_path / 'calibration.json').write_text('{"temperature": NaN}', encoding='utf-8')
    assert local_model._load_calibration(tmp_path) == (1.0, '')


def test_absurdly_large_finite_temperature_is_rejected(tmp_path):
    # A finite but absurd value (e.g. a corrupted/malicious file) should also
    # be bounded, not just "not infinite" -- a temperature of 1e6 would still
    # make softmax practically uniform.
    (tmp_path / 'calibration.json').write_text('{"temperature": 1000000.0}', encoding='utf-8')
    assert local_model._load_calibration(tmp_path) == (1.0, '')


def test_oversized_calibration_file_is_rejected(tmp_path):
    # Regression (Codex): an arbitrarily large calibration.json read at model
    # load time is a small memory/time DoS surface for a file that should
    # always be tiny (a handful of numbers).
    huge_padding = '"padding": "' + ('x' * (local_model.MAX_CALIBRATION_FILE_BYTES + 1)) + '"'
    (tmp_path / 'calibration.json').write_text('{"temperature": 1.5, ' + huge_padding + '}', encoding='utf-8')
    assert local_model._load_calibration(tmp_path) == (1.0, '')


def test_missing_temperature_key_falls_back_safely(tmp_path):
    (tmp_path / 'calibration.json').write_text('{"raw_test_brier_score": 0.05}', encoding='utf-8')
    assert local_model._load_calibration(tmp_path) == (1.0, '')


def test_temperature_scaling_never_changes_which_class_wins():
    # The whole point of temperature scaling is to recalibrate confidence,
    # never to relabel. Verify the invariant directly against torch, the
    # same way classify() actually computes it, rather than just asserting
    # it in a docstring.
    import torch
    logits = torch.tensor([[1.2, 3.4, -0.7]])
    raw_index = int(torch.softmax(logits, dim=-1)[0].argmax())
    for temperature in (0.3, 1.0, 2.5, 10.0):
        scaled_index = int(torch.softmax(logits / temperature, dim=-1)[0].argmax())
        assert scaled_index == raw_index

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


class _FakeTokenizer:
    """A minimal stand-in for a real tokenizer: treats the 'text' argument as
    a plain token COUNT (an int) rather than an actual string, so window-math
    can be tested precisely and fast, without loading a real model/tokenizer."""
    def __call__(self, token_count, add_special_tokens=False, truncation=False):
        assert not add_special_tokens and not truncation
        return {'input_ids': list(range(token_count))}


def test_short_text_fits_in_a_single_window():
    windows, covered_all = local_model._window_token_ids(_FakeTokenizer(), 100, max_length=256, stride=32, max_windows=8)
    assert len(windows) == 1 and windows[0] == list(range(100)) and covered_all


def test_text_exactly_at_the_content_length_boundary_fits_in_one_window():
    # content_length = max_length - 2 (room for [CLS]/[SEP])
    windows, covered_all = local_model._window_token_ids(_FakeTokenizer(), 254, max_length=256, stride=32, max_windows=8)
    assert len(windows) == 1 and covered_all


def test_long_text_produces_multiple_overlapping_windows_covering_everything():
    # 500 tokens, content_length=254, stride=32 -> step=222: windows at
    # [0:254), [222:476), [444:500) (partial last window) -- 3 windows, fully covered.
    windows, covered_all = local_model._window_token_ids(_FakeTokenizer(), 500, max_length=256, stride=32, max_windows=8)
    assert len(windows) == 3 and covered_all
    assert windows[0] == list(range(0, 254))
    assert windows[1] == list(range(222, 476))
    assert windows[2] == list(range(444, 500))
    # Consecutive windows must actually overlap (that's the whole point --
    # a payload split across one window's boundary still lands whole in the next).
    assert set(windows[0]) & set(windows[1])
    assert set(windows[1]) & set(windows[2])


def test_max_windows_cap_is_enforced_and_honestly_reported_as_not_covered():
    # Regression target: the SAME 500-token text as above, but capped at 2
    # windows -- must stop there and report covered_all=False, not silently
    # claim full coverage of content it never actually inspected.
    windows, covered_all = local_model._window_token_ids(_FakeTokenizer(), 500, max_length=256, stride=32, max_windows=2)
    assert len(windows) == 2 and not covered_all


def test_this_projects_own_measured_truncation_attack_now_requires_multiple_windows():
    # The exact scenario training/adversarial_robustness_eval.py measured as
    # 100% evasive against single-window classification: ~242 filler words
    # (roughly 256+ tokens) prepended before the real payload. Confirms that
    # content lands in a LATER window now, not silently truncated away by a
    # single first-256-token pass.
    filler_tokens, payload_tokens = 260, 40
    windows, covered_all = local_model._window_token_ids(
        _FakeTokenizer(), filler_tokens + payload_tokens, max_length=256, stride=32, max_windows=8)
    assert len(windows) > 1, 'the attack-sized input must not fit in a single window'
    assert covered_all
    last_real_token_index = filler_tokens + payload_tokens - 1
    assert any(last_real_token_index in w for w in windows), 'the payload past the old truncation boundary must land inside at least one window'


def test_empty_text_produces_one_empty_window_not_a_crash():
    # Regression (Codex Low): _window_token_ids(text=0 tokens) must return a
    # well-defined, intentional result ([[]], fully covered), not an
    # accidental edge case nobody decided about.
    windows, covered_all = local_model._window_token_ids(_FakeTokenizer(), 0, max_length=256, stride=32, max_windows=8)
    assert windows == [[]] and covered_all


def test_module_level_config_asserts_reject_pathological_values():
    # Regression (Codex Low): MAX_LENGTH/WINDOW_STRIDE_TOKENS/MAX_WINDOWS are
    # env-driven -- a pathological value (stride >= content window, MAX_LENGTH
    # too small to hold any content) must fail loudly at load time, not
    # produce silently-empty or nonsensical windows downstream.
    import importlib
    import os
    original = os.environ.get('MODEL_MAX_LENGTH')
    os.environ['MODEL_MAX_LENGTH'] = '2'  # leaves zero room for content tokens
    try:
        with pytest.raises(AssertionError):
            importlib.reload(local_model)
    finally:
        if original is None:
            os.environ.pop('MODEL_MAX_LENGTH', None)
        else:
            os.environ['MODEL_MAX_LENGTH'] = original
        importlib.reload(local_model)  # restore real module state for later tests


def test_tokens_covered_matches_a_hand_computed_known_case():
    # Regression (Codex Medium, twice over): a first version reported
    # MAX_WINDOWS * content_length (double-counts every overlap). A second
    # version fixed that but reported content_length + (N-1)*step, which
    # assumes the LAST window is always a full content_length long -- wrong
    # whenever the message doesn't end exactly on a step boundary. For the
    # documented 500-token/3-window example (windows at [0:254), [222:476),
    # [444:500)), the correct covered span is exactly 500 -- the real
    # message length -- not 698 (what the second, still-wrong version
    # reported).
    windows, covered_all = local_model._window_token_ids(_FakeTokenizer(), 500, max_length=256, stride=32, max_windows=8)
    step = max(1, (256 - 2) - 32)
    assert local_model._tokens_covered(windows, step) == 500


def test_tokens_covered_is_zero_for_empty_windows():
    assert local_model._tokens_covered([], step=222) == 0


def test_tokens_covered_matches_message_length_when_capped_before_the_end():
    # When max_windows is hit before reaching the end (covered_all=False),
    # tokens_covered must equal exactly what was actually inspected -- the
    # sum of the windows genuinely examined, not the full (uninspected)
    # message length.
    windows, covered_all = local_model._window_token_ids(_FakeTokenizer(), 500, max_length=256, stride=32, max_windows=2)
    step = max(1, (256 - 2) - 32)
    assert not covered_all
    assert local_model._tokens_covered(windows, step) == 476  # (2-1)*222 + len(windows[-1]==254) == 222+254

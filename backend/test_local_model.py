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

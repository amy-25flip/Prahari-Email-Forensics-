# -*- coding: utf-8 -*-
"""Plain-assertion sanity checks for calibration_analysis.py's pure math
(training/ has no pytest dependency; run directly: python test_calibration_analysis.py).
Does not load the trained model -- these test the scoring/fitting math in
isolation against known-correct values."""
from calibration_analysis import brier_score, negative_log_likelihood, reliability_bins, fit_temperature, phishing_probabilities
import torch


def test_brier_score_of_perfect_predictions_is_zero():
    assert brier_score([1.0, 0.0, 1.0], [1, 0, 1]) == 0.0


def test_brier_score_of_worst_possible_predictions_is_one():
    assert brier_score([0.0, 1.0], [1, 0]) == 1.0


def test_brier_score_of_always_predicting_half_is_a_quarter():
    assert brier_score([0.5, 0.5, 0.5, 0.5], [1, 0, 1, 0]) == 0.25


def test_negative_log_likelihood_of_confident_correct_predictions_is_near_zero():
    nll = negative_log_likelihood([0.999, 0.001], [1, 0])
    assert nll < 0.01


def test_negative_log_likelihood_penalizes_confident_wrong_predictions_heavily():
    correct_nll = negative_log_likelihood([0.9], [1])
    wrong_nll = negative_log_likelihood([0.1], [1])
    assert wrong_nll > correct_nll


def test_reliability_bins_group_by_predicted_probability_range():
    probs = [0.05, 0.15, 0.95]
    labels = [0, 1, 1]
    bins = reliability_bins(probs, labels, n_bins=10)
    assert bins[0]['count'] == 1 and bins[0]['actual_positive_fraction'] == 0.0
    assert bins[1]['count'] == 1 and bins[1]['actual_positive_fraction'] == 1.0
    assert bins[9]['count'] == 1 and bins[9]['actual_positive_fraction'] == 1.0
    assert bins[5]['count'] == 0 and bins[5]['mean_predicted'] is None


def test_reliability_bins_probability_of_exactly_one_lands_in_last_bin():
    # A predicted probability of exactly 1.0 would compute bin index
    # int(1.0 * 10) == 10, one past the last valid index (0-9) -- must be
    # clamped into the last bin, not raise an IndexError.
    bins = reliability_bins([1.0], [1], n_bins=10)
    assert bins[9]['count'] == 1


def test_fit_temperature_recovers_a_known_overconfident_distribution():
    # Genuinely overconfident data: the model claims 99% confidence (a large
    # logit gap), but only 80% of instances at that confidence level are
    # actually correct -- the raw softmax overstates certainty relative to
    # real frequency. The correct fix is temperature > 1 (softening).
    # (Note: a claimed-confident group that is ALSO 100%-consistently
    # correct is not overconfident in the NLL sense -- NLL-optimal there is
    # to sharpen further (T < 1), not soften. An earlier version of this test
    # used exactly that 100%-consistent construction and only asserted
    # `best_nll <= raw_nll`, which is vacuously true for ANY input because
    # T=1.0 is always itself one of the grid-searched candidates. Fixed by
    # constructing genuine overconfidence and asserting the fitted direction.)
    logit_gap = 9.19  # softmax ~0.99/0.01
    logits = torch.tensor([[0.0, logit_gap]] * 100)
    labels = [1] * 80 + [0] * 20  # only 80% actually positive, not 99%
    phishing_index = 1
    best_t, best_nll = fit_temperature(logits, labels, phishing_index, lo=0.5, hi=10.0, step=0.05)
    raw_nll = negative_log_likelihood(phishing_probabilities(logits, 1.0, phishing_index), labels)
    assert best_t > 2.0, "genuinely overconfident data must fit a temperature well above 1 (softening)"
    assert best_nll < raw_nll, "the fitted temperature must strictly improve on T=1 for genuinely miscalibrated data"


def test_fit_temperature_leaves_a_genuinely_well_calibrated_model_near_one():
    # If raw probabilities already match empirical frequency -- predicted
    # P(class1)=0.7 for a group where exactly 70% really are class1, and
    # predicted 0.3 for a group where exactly 30% are -- no rescaling should
    # be "discovered" as necessary. (An earlier version of this test used
    # predicted-0.7-but-100%-actually-positive data, which is UNDERconfident,
    # not calibrated -- it correctly fit best_t down to the search floor, and
    # a loose 0.5-2.0 bound then passed for the wrong reason. Verified here
    # against genuinely matching frequencies instead.)
    logits = torch.tensor([[0.0, 0.847]] * 10 + [[0.847, 0.0]] * 10)  # softmax ~ (0.30, 0.70) style split
    labels = [1] * 7 + [0] * 3 + [1] * 3 + [0] * 7  # matches the 0.7/0.3 predicted split exactly
    best_t, _ = fit_temperature(logits, labels, phishing_index=1, lo=0.5, hi=5.0, step=0.05)
    assert best_t == 1.0


if __name__ == "__main__":
    tests = [v for k, v in list(globals().items()) if k.startswith("test_")]
    for fn in tests:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"\n{len(tests)} checks passed.")

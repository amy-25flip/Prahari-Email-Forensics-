import pytest

import attribution
from attribution_scenarios import ORDERINGS, SCENARIOS


def score(sid):
    return attribution.assess(SCENARIOS[sid][1])


@pytest.mark.parametrize('sid', sorted(SCENARIOS))
def test_scenario_lands_in_the_expected_band(sid):
    description, _, expected = SCENARIOS[sid]
    result = score(sid)
    assert result['band'] == expected, f'{sid} ({description}): got {result["band"]} at {result["confidence_score"]}'


@pytest.mark.parametrize('stronger,weaker', ORDERINGS)
def test_stronger_evidence_never_scores_lower(stronger, weaker):
    strong, weak = score(stronger)['confidence_score'], score(weaker)['confidence_score']
    assert strong > weak, f'{stronger}={strong} should exceed {weaker}={weak}'


def test_scores_are_bounded_and_the_matrix_covers_all_three_bands():
    results = [score(sid) for sid in SCENARIOS]
    assert all(0 <= r['confidence_score'] <= 100 for r in results)
    assert {r['band'] for r in results} == {'low', 'moderate', 'high'}


def test_tor_and_hosting_penalties_never_raise_a_score():
    assert score('S05')['confidence_score'] <= score('S04')['confidence_score']
    assert score('S13')['confidence_score'] <= score('S03')['confidence_score']

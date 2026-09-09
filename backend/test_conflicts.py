import pytest
from conflicts import detect

PAYMENT = [{'title': 'Payment diversion', 'detail': 'updated bank details'}, {'title': 'Verification avoidance', 'detail': 'do not call'}]
MODEL = {'status': 'ready', 'label': 'benign', 'confidence': 92}


def test_disagreement_has_evidence_and_action():
    result = detect(PAYMENT, {'dmarc': {'status': 'pass'}}, MODEL, [])
    assert {r['id'] for r in result} == {'authenticated-payment', 'model-payment'}
    assert all(r['evidence_refs'] and r['action'] for r in result)
    assert all('score' not in r for r in result)


@pytest.mark.parametrize('findings', [[], PAYMENT[:1], PAYMENT[1:]])
def test_ordinary_invoice_or_isolated_phrase_is_insufficient(findings):
    assert not detect(findings, {'dmarc': {'status': 'pass'}}, MODEL, [])


@pytest.mark.parametrize('state', ['unknown', 'missing', 'fail'])
def test_unverified_auth_never_becomes_pass(state):
    result = detect(PAYMENT, {'dmarc': {'status': state}}, {'status': 'unavailable', 'label': 'benign'}, [])
    assert not result


def test_link_conflict_points_to_specific_url():
    result = detect([], {}, {}, [{'reasons': []}, {'reasons': ['Displayed URL differs from destination']}])
    assert result[0]['evidence_refs'] == ['urls/1']
    assert 'Tracking' in result[0]['explanation']


def test_unknown_model_label_is_not_benign():
    assert not detect(PAYMENT, {}, {'status': 'ready', 'label': 'LABEL_0'}, [])

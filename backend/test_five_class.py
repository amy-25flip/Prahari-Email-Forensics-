import pytest
import classification
import run_five_class


def test_precedence_and_undetermined():
    base = {'findings': [], 'score': 0, 'ml': {'status': 'unavailable'}, 'authentication': {'dmarc': {'status': 'none'}}, 'subject': '', 'body': ''}
    assert classification.classify(base)['primary'] == 'undetermined'
    both = dict(base, findings=[{'title': 'Credential pressure', 'points': 10}, {'title': 'Payment diversion', 'points': 10}])
    assert classification.classify(both)['primary'] == 'phishing' and classification.classify(both)['secondary'] == ['fraud_related']
    model_only = dict(base, findings=[{'title': 'High model phishing probability', 'points': 30}], score=30)
    assert classification.classify(model_only)['primary'] == 'suspicious'
    dmarc_only = dict(base, findings=[], authentication={'dmarc': {'status': 'fail'}})
    assert classification.classify(dmarc_only)['primary'] != 'impersonated'
    ok = dict(base, ml={'status': 'ready', 'label': 'Benign'})
    assert classification.classify(ok)['primary'] == 'legitimate'


def test_synthetic_fixture_evaluation():
    import local_model
    local_model.load()
    if local_model.classify('Your order has shipped.').get('status') != 'ready':
        pytest.skip('BERT model not available in this test process')
    conf, _ = run_five_class.run()
    stats = run_five_class.per_class(conf)
    assert stats['accuracy'] >= 0.8
    for cls in ('phishing', 'fraud_related', 'impersonated'):
        assert stats[cls]['recall'] >= 0.8, cls
    assert stats['legitimate']['recall'] >= 0.6

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


def test_synthetic_fixture_evaluation(monkeypatch):
    monkeypatch.delenv('DISABLE_ML', raising=False)   # other test modules disable the model process-wide
    import importlib
    import local_model
    importlib.reload(local_model)          # other tests patch the model state; start from a clean load
    local_model.load()
    if local_model.classify('Your order has shipped.').get('status') != 'ready':
        pytest.skip('BERT model not available in this test process: ' + str(local_model.classify('x').get('detail')))
    try:
        conf, _ = run_five_class.run()
    finally:
        monkeypatch.setenv('DISABLE_ML', '1')
        local_model.load()
    stats = run_five_class.per_class(conf)
    assert stats['accuracy'] >= 0.8
    for cls in ('phishing', 'fraud_related', 'impersonated'):
        assert stats[cls]['recall'] >= 0.8, cls
    assert stats['legitimate']['recall'] >= 0.6


def test_expiry_lure_needs_link_and_unauthenticated_sender():
    base = {'findings': [{'title': 'Account-expiry pressure', 'points': 10}], 'score': 10, 'ml': {'status': 'unavailable'}, 'subject': '', 'body': 'Your password expired today.'}
    lure = dict(base, urls=[{'url': 'http://x.example'}], authentication={'dmarc': {'status': 'none'}})
    assert classification.classify(lure)['primary'] == 'phishing'
    assert classification.classify(dict(lure, authentication={'dmarc': {'status': 'pass'}}))['primary'] == 'suspicious'
    assert classification.classify(dict(lure, urls=[]))['primary'] == 'suspicious'


def test_qr_link_and_bare_expiry_notice_do_not_decide_phishing():
    base = {'score': 15, 'ml': {'status': 'unavailable'}, 'subject': '', 'body': 'Register here.', 'urls': [{'url': 'http://x.example'}], 'authentication': {'dmarc': {'status': 'none'}}}
    qr = dict(base, findings=[{'title': 'QR code in attachment decodes to a link', 'points': 15}])
    assert classification.classify(qr)['primary'] == 'suspicious'
    qr_cred = dict(qr, findings=qr['findings'] + [{'title': 'Credential pressure', 'points': 10}])
    assert classification.classify(qr_cred)['primary'] == 'phishing'
    notice = dict(base, findings=[{'title': 'Account-expiry pressure', 'points': 10}], body='Your account password will expire in 5 days. Renew at the portal.')
    assert classification.classify(notice)['primary'] == 'suspicious'
    urgent = dict(notice, body='Your password has expired today. Sign in immediately.')
    assert classification.classify(urgent)['primary'] == 'phishing'


def test_authenticated_credential_notice_is_not_phishing_without_corroboration():
    notice = {'findings': [{'title': 'Credential pressure', 'points': 10}], 'score': 10, 'ml': {'status': 'unavailable'}, 'subject': '', 'body': 'Please verify your KYC.',
              'urls': [], 'authentication': {'dmarc': {'status': 'pass'}}}
    assert classification.classify(notice)['primary'] == 'suspicious'
    assert classification.classify(dict(notice, authentication={'dmarc': {'status': 'none'}}))['primary'] == 'phishing'
    lookalike = dict(notice, findings=notice['findings'] + [{'title': 'Look-alike domain', 'points': 15}])
    assert classification.classify(lookalike)['primary'] == 'phishing'



def test_lure_rules_require_link_and_unauthenticated_sender():
    base = {'findings': [], 'score': 5, 'ml': {'status': 'unavailable'}, 'subject': '', 'body': '', 'urls': [{'url': 'https://x.example'}], 'authentication': {'dmarc': {'status': 'none'}}}
    shared = dict(base, subject='Document shared', body='A secure document was shared with you. View the document.')
    assert classification.classify(shared)['primary'] == 'phishing'
    assert classification.classify(dict(shared, authentication={'dmarc': {'status': 'pass'}}))['primary'] not in ('phishing', 'fraud_related', 'impersonated')
    assert classification.classify(dict(shared, urls=[]))['primary'] not in ('phishing', 'fraud_related', 'impersonated')
    voicemail = dict(base, subject='New voicemail', body='You have a new voicemail message. Open it here.')
    assert classification.classify(voicemail)['primary'] == 'phishing'
    invoice = dict(base, subject='Invoice notification', body='Invoice 8821 is available. View invoice online.')
    assert classification.classify(invoice)['primary'] == 'fraud_related'
    assert classification.classify(dict(invoice, authentication={'dmarc': {'status': 'pass'}}))['primary'] not in ('phishing', 'fraud_related', 'impersonated')


def test_identity_mismatch_plus_lure_can_mark_impersonation_but_newsletter_cannot():
    report = {'findings': [{'title': 'Reply-To domain differs', 'points': 20}], 'score': 20, 'ml': {'status': 'unavailable'},
              'subject': 'Invoice available', 'body': 'A billing notice is ready. View it online.', 'urls': [{'url': 'https://x.example'}],
              'authentication': {'dmarc': {'status': 'fail'}}}
    result = classification.classify(report)
    assert result['primary'] == 'fraud_related' and 'impersonated' in result['secondary']
    newsletter = dict(report, findings=[], score=5, subject='Weekly product update', body='Read our newsletter and register for the webinar.', authentication={'dmarc': {'status': 'pass'}})
    assert classification.classify(newsletter)['primary'] not in ('phishing', 'fraud_related', 'impersonated')

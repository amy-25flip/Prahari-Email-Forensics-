from engine import interpret_model


def auth(**kw):
    base = {k: {'status': 'unknown'} for k in ('spf', 'dkim', 'dmarc', 'arc')}
    for k, v in kw.items():
        base[k] = {'status': v}
    return base


def pred(pp, status='ready'):
    return {'status': status, 'phishing_probability': pp,
            'label': 'PHISHING' if pp >= 50 else 'LEGITIMATE', 'confidence': pp}


def test_unavailable_when_model_not_ready():
    assert interpret_model(pred(80, 'unavailable'), auth())['band'] == 'unavailable'


def test_non_numeric_probability_is_unavailable():
    assert interpret_model({'status': 'ready', 'phishing_probability': None}, auth())['band'] == 'unavailable'


def test_low_probability_is_legitimate():
    v = interpret_model(pred(5), auth())
    assert v['band'] == 'legitimate' and v['note'] is None


def test_high_probability_unauthenticated_is_phishing():
    v = interpret_model(pred(100), auth())
    assert v['band'] == 'phishing' and v['summary'] == 'Likely phishing'


def test_mid_band_unauthenticated_is_uncertain():
    assert interpret_model(pred(80), auth())['band'] == 'uncertain'


def test_mid_band_authenticated_downgrades_to_legitimate():
    # The real Google/Render false positive: ~80% phishing-like content, DMARC pass.
    v = interpret_model(pred(80), auth(dmarc='pass'))
    assert v['band'] == 'legitimate'
    assert v['authenticated_sender'] is True
    assert v['note']


def test_dkim_and_spf_pass_counts_as_authenticated():
    v = interpret_model(pred(80), auth(dkim='pass', spf='pass'))
    assert v['authenticated_sender'] is True and v['band'] == 'legitimate'


def test_dkim_alone_is_not_treated_as_authenticated():
    # DKIM without SPF (and without DMARC) is not enough to override a mid-band signal.
    v = interpret_model(pred(80), auth(dkim='pass'))
    assert v['authenticated_sender'] is False and v['band'] == 'uncertain'


def test_high_probability_authenticated_is_caution_not_clean():
    # Strong phishing content from an authenticated sender -> flag for review
    # (possible compromised account), not a clean pass.
    v = interpret_model(pred(100), auth(dmarc='pass'))
    assert v['band'] == 'caution' and v['authenticated_sender'] is True and v['note']


def test_raw_probability_preserved():
    assert interpret_model(pred(80), auth(dmarc='pass'))['phishing_probability'] == 80

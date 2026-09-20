import adversarial
import engine


def test_contains_suspect():
    assert adversarial.contains_suspect('pаypal')       # Cyrillic a
    assert adversarial.contains_suspect('verify​now')   # zero-width space
    assert not adversarial.contains_suspect('paypal verify now')


def test_skeleton_folds_homoglyphs_and_strips_zero_width():
    assert adversarial.skeleton('pаypаl') == 'paypal'
    assert adversarial.skeleton('verify​now') == 'verifynow'
    assert adversarial.skeleton('normal text') == 'normal text'


def test_engine_flags_adversarial_evasion(monkeypatch):
    # Model scores the homoglyph text low and the normalized text high -> evasion.
    def fake_classify(text):
        pp = 8 if 'а' in text else 96
        return {'status': 'ready', 'label': 'PHISHING' if pp >= 50 else 'LEGITIMATE',
                'confidence': pp, 'phishing_probability': pp, 'detail': 'test'}
    monkeypatch.setattr(engine.ml, 'classify', fake_classify)
    raw = ('From: a@b.com\r\nTo: c@d.com\r\nSubject: pаypal security\r\n\r\n'
           'verify your pаypal account now').encode('utf-8')
    result = engine.analyze(raw)
    assert result['adversarial'] is not None
    assert result['adversarial']['flagged'] is True
    assert result['adversarial']['delta'] >= 40
    assert any('evasion' in f['title'].lower() for f in result['findings'])


def test_engine_no_adversarial_field_on_clean_text(monkeypatch):
    monkeypatch.setattr(engine.ml, 'classify', lambda t: {
        'status': 'ready', 'label': 'LEGITIMATE', 'confidence': 2,
        'phishing_probability': 2, 'detail': 'test'})
    raw = b'From: a@b.com\r\nTo: c@d.com\r\nSubject: lunch\r\n\r\nsee you at 1pm'
    result = engine.analyze(raw)
    assert result['adversarial'] is None


def test_clean_text_does_not_run_second_classify(monkeypatch):
    calls = {'n': 0}
    def c(t):
        calls['n'] += 1
        return {'status': 'ready', 'label': 'LEGITIMATE', 'confidence': 3, 'phishing_probability': 3, 'detail': 'x'}
    monkeypatch.setattr(engine.ml, 'classify', c)
    raw = b'From: a@b.com\r\nTo: c@d.com\r\nSubject: lunch plans\r\n\r\nsee you at 1pm today'
    r = engine.analyze(raw)
    assert calls['n'] == 1            # no second (normalized) classify on clean text
    assert r['adversarial'] is None


def test_below_threshold_delta_not_flagged(monkeypatch):
    def c(text):
        pp = 55 if '\u0430' in text else 70   # raw(cyrillic)=55, normalized=70 -> delta 15
        return {'status': 'ready', 'label': 'PHISHING' if pp >= 50 else 'LEGITIMATE',
                'confidence': pp, 'phishing_probability': pp, 'detail': 'x'}
    monkeypatch.setattr(engine.ml, 'classify', c)
    raw = 'From: a@b.com\r\nTo: c@d.com\r\nSubject: p\u0430y now\r\n\r\np\u0430y your invoice'.encode()
    r = engine.analyze(raw)
    assert r['adversarial'] is not None
    assert r['adversarial']['flagged'] is False
    assert r['adversarial']['delta'] == 15
    assert not any('evasion' in f['title'].lower() for f in r['findings'])


def test_model_unavailable_no_adversarial(monkeypatch):
    monkeypatch.setattr(engine.ml, 'classify',
                        lambda t: {'status': 'unavailable', 'label': 'Unavailable', 'confidence': None, 'detail': 'x'})
    raw = 'From: a@b.com\r\nTo: c@d.com\r\nSubject: p\u0430y\r\n\r\np\u0430y now'.encode()
    r = engine.analyze(raw)
    assert r['adversarial'] is None

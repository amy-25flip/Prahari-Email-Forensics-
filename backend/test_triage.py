import pytest
import engine
from triage import assess, high_model_signal
from test_selection import client, HEADERS

def prediction(value=99, status='ready'):
    return {'status': status, 'phishing_probability': value, 'label': 'phishing', 'confidence': value, 'detail': 'Controlled test prediction'}

@pytest.mark.parametrize('value', [None, float('nan'), float('inf'), -1, 101, True, '100'])
def test_invalid_probability_does_not_count(value):
    assert not high_model_signal(prediction(value))

def test_unavailable_prediction_does_not_count():
    assert not high_model_signal(prediction(100, 'unavailable'))

def test_model_alone_requires_review_not_confirmed_phishing():
    r = assess(30, [], prediction(), [])
    assert r['priority'] == 'review'
    assert not r['model_corroborated']

def test_moderate_score_with_deceptive_link_gets_urgent_review():
    r = assess(45, [], prediction(), [{'reasons':['Displayed URL differs from destination']}])
    assert r['priority'] == 'urgent'
    assert r['model_corroborated']

def test_payment_avoidance_does_not_depend_on_model():
    r = assess(20, [{'title':'Payment diversion'},{'title':'Verification avoidance'}], prediction(1), [])
    assert r['priority'] == 'urgent'

def test_tracking_link_alone_not_urgent():
    r = assess(10, [{'title':'Suspicious URL structure'}], prediction(1), [{'reasons':['Displayed URL differs from destination']}])
    assert r['priority'] == 'review'

def test_fresh_reputation_escalates():
    assert assess(60, [{'title':'PhishTank URL match'}], prediction(1), [])['priority'] == 'urgent'

def test_missing_model_is_incomplete():
    assert assess(0, [], prediction(None,'unavailable'), [])['priority'] == 'incomplete'

def test_benign_has_no_safety_guarantee():
    r = assess(0, [], prediction(1), [])
    assert r['priority'] == 'routine'
    assert 'does not establish safety' in r['reasons'][0]

def test_engine_keeps_score_and_surfaces_corroboration(monkeypatch):
    monkeypatch.setattr(engine.ml, 'classify', lambda text: prediction())
    raw = b'From: person@example.org\r\nSubject: Notice\r\nContent-Type: text/html\r\n\r\n<a href="http://other.example/login">https://example.org</a>'
    r = engine.analyze(raw)
    assert r['score'] == 40
    assert r['triage']['priority'] == 'urgent'

def test_unavailable_model_cannot_boost_engine_score(monkeypatch):
    monkeypatch.setattr(engine.ml, 'classify', lambda text: prediction(100,'unavailable'))
    r = engine.analyze(b'From: person@example.org\r\nSubject: Meeting\r\n\r\nSee you tomorrow.')
    assert r['score'] == 0
    assert r['triage']['priority'] == 'incomplete'

def test_stored_and_exported_review_decision(client):
    r = client.post('/api/samples/invoice', headers=HEADERS).json()
    assert r['triage']['priority'] == 'urgent'
    exported = client.get(f"/api/cases/{r['id']}/export/json").json()
    assert exported['triage'] == r['triage']
    assert client.get(f"/api/cases/{r['id']}/export/pdf").content.startswith(b'%PDF')


def test_pdf_export_preserves_hindi_text_not_replaced_with_question_marks(client):
    # Regression (Antigravity-flagged, real): the core 'Helvetica' PDF font
    # only supports Latin-1, so every non-Latin-1 character (Hindi/
    # Devanagari script especially, real for an India-focused platform) was
    # forced through .encode('latin-1','replace') and silently became a
    # literal '?' -- indistinguishable from real content in a forensic
    # report. Fixed by bundling Noto Sans + Noto Sans Devanagari with
    # fallback + real text shaping (see main.py's export() for fmt=='pdf').
    pypdf = pytest.importorskip('pypdf')
    subject = 'सुरक्षा चेतावनी: अपना खाता सत्यापित करें'  # "Security warning: verify your account"
    raw = ('From: a@b.com\r\nTo: c@d.com\r\nSubject: ' + subject + '\r\n\r\nHello.').encode('utf-8')
    analyzed = client.post('/api/analyze', content=raw, headers=HEADERS).json()
    export = client.get(f"/api/cases/{analyzed['id']}/export/pdf")
    assert export.status_code == 200 and export.content.startswith(b'%PDF')

    import io
    reader = pypdf.PdfReader(io.BytesIO(export.content))
    extracted = ''.join(page.extract_text() for page in reader.pages)
    assert extracted.strip(), 'sanity: PDF text extraction produced nothing at all'
    # The real assertion: the Devanagari text must survive, not collapse to '?'.
    assert 'सुरक्षा' in extracted or 'चेतावनी' in extracted, \
        f'Hindi subject text did not survive PDF export/extraction: {extracted[:300]!r}'
    assert '???' not in extracted


def test_high_model_signal_suppressed_for_authenticated_sender():
    # A high content-model score from a cryptographically authenticated sender is
    # not strong phishing evidence (no domain spoofing) -- must not count.
    p = prediction(100)
    p['verdict'] = {'authenticated_sender': True}
    assert not high_model_signal(p)


def test_high_model_signal_fires_for_unauthenticated_high_probability():
    p = prediction(100)
    p['verdict'] = {'authenticated_sender': False}
    assert high_model_signal(p)


def test_high_model_signal_without_verdict_key_is_unaffected():
    # Legacy path (no verdict on the prediction) keeps the original behavior.
    assert high_model_signal(prediction(95))


def test_authenticated_sender_high_model_does_not_force_review():
    # With no concrete findings, an authenticated high-content email stays routine
    # instead of being pushed to "Review required" by the model alone.
    p = prediction(100)
    p['verdict'] = {'authenticated_sender': True}
    assert assess(0, [], p, [])['priority'] == 'routine'

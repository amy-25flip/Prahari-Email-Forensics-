import bz2
import io
import json
import time
from email import policy
from email.parser import BytesParser
import pytest
import requests
import dkim
import dns.resolver
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import base64
import engine
import reputation
import store
from test_selection import client, HEADERS


@pytest.fixture
def snapshot(monkeypatch):
    data = {'source': 'PhishTank', 'fetched_at': time.time(), 'entries': {
        reputation.key('https://test-phish.example/confirm?token=abc'): {'id': '123', 'verified_at': '2026-09-08T00:00:00Z'}}}
    monkeypatch.setattr(reputation, '_snapshot', data)
    monkeypatch.setattr(reputation, '_last_error', None)
    return data


def test_normalization_preserves_security_semantics(snapshot):
    assert reputation.lookup('HTTPS://TEST-PHISH.EXAMPLE:443/confirm?token=abc')['status'] == 'listed'
    for url in ('https://test-phish.example/Confirm?token=abc', 'https://test-phish.example/confirm?token=other',
                'https://test-phish.example/confirm?token=abc#different', 'https://test-phish.example/safe'):
        assert reputation.lookup(url)['status'] == 'not_listed'
    assert reputation.key('https://example.org:bad') is None


def test_stale_snapshot_is_never_current_intelligence(snapshot):
    snapshot['source_modified'] = time.time() - 90000
    assert reputation.lookup('https://test-phish.example/confirm?token=abc')['status'] == 'listed_stale'
    assert reputation.lookup('https://unknown.example')['status'] == 'stale'


def test_unavailable_feed_does_not_claim_safe(monkeypatch):
    monkeypatch.setattr(reputation, '_snapshot', None)
    assert reputation.lookup('https://example.org')['status'] == 'unavailable'


def test_refresh_failure_preserves_snapshot(snapshot, monkeypatch):
    def offline(*a, **k): raise requests.Timeout()
    monkeypatch.setattr(reputation.requests, 'get', offline)
    reputation.refresh(force=True)
    assert reputation.lookup('https://test-phish.example/confirm?token=abc')['match']
    assert 'retained' in reputation.status()['detail']


def test_feed_ingestion_ignores_unverified_rows(tmp_path, monkeypatch):
    content = b'phish_id,url,verified,online,verification_time\n1,https://test-phish.example/,yes,yes,2026-09-08\n2,https://unverified.example/,no,yes,2026-09-08\n'
    class Response:
        headers = {}
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def raise_for_status(self): pass
        def iter_content(self, size): yield bz2.compress(content)
    monkeypatch.setattr(reputation, 'CACHE_PATH', tmp_path / 'feed.json')
    monkeypatch.setattr(reputation.requests, 'get', lambda *a, **k: Response())
    monkeypatch.setattr(reputation, '_snapshot', None)
    assert reputation.refresh(force=True)['count'] == 1
    assert reputation.lookup('https://test-phish.example')['match']
    assert not reputation.lookup('https://unverified.example')['match']
    assert 'https://test-phish.example' not in reputation.CACHE_PATH.read_text()


@pytest.fixture
def signed_mail(monkeypatch):
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption())
    public = private.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    raw = b'From: person@example.org\r\nSubject: Meeting\r\n\r\nSee you at noon.\r\n'
    signature = dkim.sign(raw, b'test', b'example.org', pem, include_headers=[b'from', b'subject'])
    class TXT:
        def __init__(self, content): self.strings = [content]
    def resolve(name, *args, **kwargs):
        return [TXT(b'v=DKIM1; p=' + base64.b64encode(public))] if '_domainkey' in str(name) else [TXT(b'v=DMARC1; p=reject; adkim=s')]
    monkeypatch.setattr(dns.resolver, 'resolve', resolve)
    return signature + raw


def auth(raw, source='upload', live=True):
    return engine.authenticate(BytesParser(policy=policy.default).parsebytes(raw), raw, live, source)


def test_real_signed_email_passes(signed_mail):
    result = auth(signed_mail)
    assert result['dkim']['status'] == 'pass'
    assert result['dmarc']['status'] == 'pass'


def test_real_signature_detects_modified_body(signed_mail):
    assert auth(signed_mail.replace(b'noon', b'midnight'))['dkim']['status'] == 'fail'


def test_paste_attempts_verification_without_claiming_original(signed_mail):
    result = auth(signed_mail, source='paste')
    assert result['dkim']['status'] == 'pass'
    assert result['dmarc']['status'] == 'pass'
    assert 'original file provenance is not established' in result['dkim']['signatures'][0]['detail']


def test_modified_paste_is_inconclusive(signed_mail):
    result = auth(signed_mail.replace(b'noon', b'midnight'), source='paste')
    assert result['dkim']['status'] == 'unknown'
    assert result['dmarc']['status'] == 'unknown'
    assert result['dmarc']['dkim_aligned'] is None
    assert result['dmarc']['spf_aligned'] is None


def test_missing_spf_context_is_not_false_alignment(signed_mail):
    result = auth(signed_mail)
    assert result['dmarc']['spf_aligned'] is None
    assert result['dmarc']['dkim_aligned'] is True


def test_dns_timeout_is_unknown(signed_mail, monkeypatch):
    def timeout(*a, **k): raise dns.resolver.LifetimeTimeout()
    monkeypatch.setattr(dns.resolver, 'resolve', timeout)
    assert auth(signed_mail)['dkim']['status'] == 'unknown'


def test_invalid_dmarc_does_not_pass(signed_mail, monkeypatch):
    original = dns.resolver.resolve
    class BadTXT:
        strings = [b'v=DMARC1; p=reject; adkim=invalid']
    monkeypatch.setattr(dns.resolver, 'resolve', lambda name, *a, **k: [BadTXT()] if str(name).startswith('_dmarc') else original(name, *a, **k))
    result = auth(signed_mail)
    assert result['dkim']['status'] == 'pass'
    assert result['dmarc']['status'] == 'unknown'


def test_dmarc_timeout_does_not_erase_dkim_pass(signed_mail, monkeypatch):
    original = dns.resolver.resolve
    def resolver(name, *a, **k):
        if str(name).startswith('_dmarc'): raise dns.resolver.LifetimeTimeout()
        return original(name, *a, **k)
    monkeypatch.setattr(dns.resolver, 'resolve', resolver)
    assert auth(signed_mail)['dkim']['status'] == 'pass'


def test_feed_match_affects_risk_and_exports(client, snapshot):
    raw = 'From: person@example.org\nSubject: A link\n\nhttps://test-phish.example/confirm?token=abc'
    r = client.post('/api/analyze', json={'email': raw}, headers=HEADERS).json()
    assert r['score'] >= 60
    assert r['urls'][0]['reputation']['record_id'] == '123'
    assert client.get(f"/api/cases/{r['id']}/export/json").json()['reputation_feed']['source'] == 'PhishTank'


def test_cleanup_expired_sessions_and_capacity(client, monkeypatch):
    client.post('/api/samples/account', headers=HEADERS)
    with store.connect() as db: db.execute('UPDATE sessions SET expires=0')
    store.cleanup()
    with store.connect() as db:
        assert db.execute('SELECT COUNT(*) FROM cases').fetchone()[0] == 0
        assert db.execute('SELECT COUNT(*) FROM events').fetchone()[0] == 0
    monkeypatch.setattr(store, 'MAX_SESSIONS', 0)
    with pytest.raises(ValueError): store.session(None)


def test_storage_quota_and_stateless_health(client, monkeypatch):
    monkeypatch.setattr(store, 'MAX_STORAGE', 1)
    # A full store is a TRANSIENT capacity condition, not a bad request: the email
    # is valid, there's just no room right now. It surfaces as 503 so the Gmail
    # push pipeline dead-letters and retries it instead of dropping a good email
    # as permanently unprocessable.
    assert client.post('/api/samples/account', headers=HEADERS).status_code == 503
    assert client.get('/api/health').headers.get('set-cookie') is None
    assert client.get('/api/ready').status_code == 503

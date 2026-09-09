import hashlib
import os
os.environ['DISABLE_ML'] = '1'
os.environ['DISABLE_FEED_REFRESH'] = '1'
import pytest
from fastapi.testclient import TestClient
import engine
import main
import store
import reputation
from samples import SAMPLES

HEADERS = {'X-Requested-With': 'Email-Threat-Detection'}


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(store, 'DATA', tmp_path)
    monkeypatch.setattr(reputation, 'CACHE_PATH', tmp_path / 'feed.json')
    monkeypatch.setattr(reputation, '_snapshot', None)
    main.limits.clear()
    with TestClient(main.app) as c:
        c.get('/api/health')
        yield c


def test_fixture_pipeline_and_exports(client):
    response = client.post('/api/samples/account', headers=HEADERS)
    assert response.status_code == 200, response.text
    r = response.json()
    assert r['score'] >= 25
    assert r['authentication']['dkim']['status'] == 'missing'
    assert r['authentication']['spf']['status'] == 'unknown'
    assert any('Displayed URL' in reason for u in r['urls'] for reason in u['reasons'])
    assert client.get('/api/verify').json()['valid']
    for fmt in ('json', 'csv', 'pdf'):
        export = client.get(f"/api/cases/{r['id']}/export/{fmt}")
        assert export.status_code == 200, export.text
        if fmt == 'pdf': assert export.content.startswith(b'%PDF')


def test_sessions_are_isolated(client):
    cid = client.post('/api/samples/account', headers=HEADERS).json()['id']
    with TestClient(main.app) as outsider:
        assert outsider.get('/api/cases').json() == []
        assert outsider.get('/api/cases/' + cid).status_code == 404
        assert outsider.delete('/api/cases/' + cid, headers=HEADERS).status_code == 404


def test_related_messages_and_delete(client):
    a = client.post('/api/samples/account', headers=HEADERS).json()
    client.post('/api/samples/invoice', headers=HEADERS)
    edges = client.get('/api/connections').json()['edges']
    assert len(edges) == 1
    assert edges[0]['evidence'][0]['value'] == 'recovery@secure-desk.example'
    assert client.delete('/api/cases/' + a['id'], headers=HEADERS).status_code == 200
    assert client.get('/api/verify').json()['valid']
    assert not client.get('/api/connections').json()['edges']


def test_integrity_detects_original_modification(client):
    client.post('/api/samples/account', headers=HEADERS)
    with store.connect() as db: db.execute("UPDATE cases SET raw=?", (b'changed',))
    assert not client.get('/api/verify').json()['valid']


def test_integrity_detects_unlogged_deletion(client):
    client.post('/api/samples/account', headers=HEADERS)
    with store.connect() as db: db.execute('DELETE FROM cases')
    assert not client.get('/api/verify').json()['valid']


def test_missing_headers_not_automatic_failure(client):
    r = client.post('/api/analyze', json={'email': 'From: person@example.org\nSubject: Meeting\n\nSee you at noon.'}, headers=HEADERS)
    assert r.status_code == 200
    assert r.json()['score'] == 0
    assert r.json()['origin'] == 'Unverified'


def test_upload_preserves_bytes_and_paste_is_labeled(client):
    raw = b'From: user@example.org\r\nSubject: Original\r\n\r\nHello\r\n'
    r = client.post('/api/analyze', content=raw, headers={**HEADERS, 'Content-Type': 'message/rfc822'}).json()
    assert r['sha256'] == hashlib.sha256(raw).hexdigest()
    assert r['source'] == 'upload'


def test_limits_and_request_header(client):
    assert client.post('/api/samples/account').status_code == 403
    assert client.post('/api/analyze', content=b'x' * 1500001, headers=HEADERS).status_code == 413
    assert client.post('/api/analyze', content=b'invalid', headers=HEADERS).status_code == 400


def test_address_domains_and_url_structures():
    assert engine.domain('Person <x@Sub.Example.org>') == 'sub.example.org'
    assert engine.base('x.example.co.uk') == 'example.co.uk'
    assert engine.scan_url('https://example.org/news')['score'] == 0
    assert engine.scan_url('http://127.0.0.1/login?next=x')['score'] >= 40
    assert engine.scan_url('javascript:alert(1)') is None


def test_forged_authentication_is_not_trusted(client):
    raw = 'From: x@example.org\nSubject: test\nAuthentication-Results: trusted.example; spf=pass; dkim=pass; dmarc=pass\n\nHello'
    r = client.post('/api/analyze', json={'email': raw}, headers=HEADERS).json()
    assert r['authentication']['spf']['status'] == 'unknown'
    assert r['authentication']['dmarc']['status'] == 'unknown'

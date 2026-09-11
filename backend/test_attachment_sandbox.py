import hashlib
import pytest
from test_selection import client, HEADERS
import attachment_reputation as ar
import engine


@pytest.fixture(autouse=True)
def reset_rate_limiter(monkeypatch):
    ar._cache.clear()
    ar._requests.clear()
    ar._inflight.clear()
    monkeypatch.setattr(ar, '_blocked_until', 0.0)


def upload_with_attachment():
    payload = b'MZ fake executable content'
    digest = hashlib.sha256(payload).hexdigest()
    import base64
    raw = (
        'From: a@b.com\r\nTo: c@d.com\r\nSubject: has attachment\r\n'
        'Content-Type: multipart/mixed; boundary="X"\r\n\r\n'
        '--X\r\nContent-Type: text/plain\r\n\r\nbody\r\n'
        '--X\r\nContent-Type: application/octet-stream\r\n'
        'Content-Disposition: attachment; filename="a.exe"\r\n'
        'Content-Transfer-Encoding: base64\r\n\r\n'
        + base64.b64encode(payload).decode() + '\r\n--X--\r\n'
    ).encode()
    return raw, digest


def test_extract_attachment_finds_matching_hash():
    raw, digest = upload_with_attachment()
    assert engine.extract_attachment(raw, digest) == b'MZ fake executable content'


def test_extract_attachment_returns_none_for_unknown_hash():
    raw, _ = upload_with_attachment()
    assert engine.extract_attachment(raw, 'f' * 64) is None


def test_sandbox_endpoint_rejects_invalid_hash(client):
    response = client.post('/api/samples/account', headers=HEADERS)
    cid = response.json()['id']
    assert client.post(f'/api/cases/{cid}/attachments/not-hex/sandbox', headers=HEADERS).status_code == 400


def test_sandbox_endpoint_rejects_unknown_hash(client):
    response = client.post('/api/samples/account', headers=HEADERS)
    cid = response.json()['id']
    assert client.post(f'/api/cases/{cid}/attachments/{"f"*64}/sandbox', headers=HEADERS).status_code == 404


def test_sandbox_status_endpoint_validates_id(client, monkeypatch):
    monkeypatch.setenv('VIRUSTOTAL_API_KEY', 'test-key')
    response = client.post('/api/attachments/sandbox/not valid id!!', headers=HEADERS)
    assert response.status_code == 200
    assert response.json()['status'] == 'error'


def test_submit_for_sandbox_disabled_without_key(monkeypatch):
    monkeypatch.delenv('VIRUSTOTAL_API_KEY', raising=False)
    assert ar.submit_for_sandbox(b'content')['status'] == 'disabled'


def test_submit_for_sandbox_rejects_empty_content(monkeypatch):
    monkeypatch.setenv('VIRUSTOTAL_API_KEY', 'test-key')
    assert ar.submit_for_sandbox(b'')['status'] == 'error'


def test_submit_for_sandbox_rejects_oversized_content(monkeypatch):
    monkeypatch.setenv('VIRUSTOTAL_API_KEY', 'test-key')
    result = ar.submit_for_sandbox(b'x' * (ar.MAX_UPLOAD_BYTES + 1))
    assert result['status'] == 'error'


def test_analysis_status_rejects_malformed_id(monkeypatch):
    monkeypatch.setenv('VIRUSTOTAL_API_KEY', 'test-key')
    assert ar.analysis_status('../../etc/passwd')['status'] == 'error'


class FakeResponse:
    def __init__(self, status_code, payload=None, headers=None):
        self.status_code = status_code
        self._payload = payload or {}
        self.headers = headers or {}
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def raise_for_status(self): pass
    def json(self): return self._payload
    def iter_content(self, n):
        import json
        yield json.dumps(self._payload).encode()


def test_submit_for_sandbox_parses_analysis_id(monkeypatch):
    monkeypatch.setenv('VIRUSTOTAL_API_KEY', 'test-key')
    monkeypatch.setattr(ar, '_requests', __import__('collections').deque())
    monkeypatch.setattr(ar, '_blocked_until', 0.0)
    monkeypatch.setattr(ar.requests, 'post', lambda *a, **k: FakeResponse(200, {'data': {'id': 'abc123=='}}))
    result = ar.submit_for_sandbox(b'some file bytes')
    assert result['status'] == 'submitted'
    assert result['analysis_id'] == 'abc123=='


def test_analysis_status_reports_pending_then_completed(monkeypatch):
    monkeypatch.setenv('VIRUSTOTAL_API_KEY', 'test-key')
    monkeypatch.setattr(ar.requests, 'get', lambda *a, **k: FakeResponse(200, {'data': {'attributes': {'status': 'queued'}}}))
    assert ar.analysis_status('abc123==')['status'] == 'pending'
    monkeypatch.setattr(ar.requests, 'get', lambda *a, **k: FakeResponse(200, {'data': {'attributes': {
        'status': 'completed', 'stats': {'malicious': 2, 'suspicious': 1, 'undetected': 60, 'harmless': 5}}}}))
    result = ar.analysis_status('abc123==')
    assert result['status'] == 'completed'
    assert result['malicious_count'] == 2


def test_analysis_status_shares_the_rate_limit_budget(monkeypatch):
    # Regression: analysis_status() used to make unlimited provider calls without
    # reserving a slot in the shared deque, letting repeated polling act as an
    # unthrottled VirusTotal proxy using the server's own key.
    monkeypatch.setenv('VIRUSTOTAL_API_KEY', 'test-key')
    monkeypatch.setenv('VIRUSTOTAL_REQUESTS_PER_MINUTE', '4')
    calls = {'n': 0}
    def fake_get(*a, **k):
        calls['n'] += 1
        return FakeResponse(200, {'data': {'attributes': {'status': 'queued'}}})
    monkeypatch.setattr(ar.requests, 'get', fake_get)
    results = [ar.analysis_status('abc123==') for _ in range(6)]
    assert calls['n'] == 4
    assert [r['status'] for r in results] == ['pending', 'pending', 'pending', 'pending', 'rate_limited', 'rate_limited']


def test_sandbox_status_endpoint_requires_post_and_app_header(client):
    # GET must no longer work (bypassed the peer-limiter/app-header middleware, which
    # only guards POST/DELETE) -- this endpoint now goes through those checks too.
    assert client.get('/api/attachments/sandbox/abc123').status_code in (404, 405)
    response_no_header = client.post('/api/attachments/sandbox/abc123')
    assert response_no_header.status_code == 403

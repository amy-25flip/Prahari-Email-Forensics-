import pytest
import attachment_reputation as ar

HASH_A = 'a' * 64
HASH_B = 'b' * 64
HASH_C = 'c' * 64
HASH_D = 'd' * 64
HASH_E = 'e' * 64


@pytest.fixture(autouse=True)
def reset(monkeypatch):
    ar._cache.clear()
    monkeypatch.setenv('VIRUSTOTAL_API_KEY', 'test-key')


def test_disabled_never_network(monkeypatch):
    monkeypatch.setattr(ar.requests, 'get', lambda *a, **k: pytest.fail('Unexpected network'))
    attachments = [{'sha256': HASH_A, 'size': 10}]
    result = ar.enrich(attachments, False)
    assert result == [{'sha256': HASH_A, 'status': 'disabled', 'detail': 'Attachment reputation lookup not enabled.'}]


def test_missing_key_is_disabled(monkeypatch):
    monkeypatch.delenv('VIRUSTOTAL_API_KEY', raising=False)
    monkeypatch.setattr(ar.requests, 'get', lambda *a, **k: pytest.fail('Unexpected network'))
    result = ar.enrich([{'sha256': HASH_A, 'size': 10}], True)
    assert result[0]['status'] == 'disabled'


def test_zero_size_attachments_skipped():
    assert ar.enrich([{'sha256': HASH_A, 'size': 0}], True) == []


class FakeResponse:
    def __init__(self, status_code, payload=None):
        self.status_code = status_code
        self._payload = payload or {}
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def raise_for_status(self): pass
    def iter_content(self, n):
        import json
        yield json.dumps(self._payload).encode()


def test_404_is_no_prior_reports(monkeypatch):
    monkeypatch.setattr(ar.requests, 'get', lambda *a, **k: FakeResponse(404))
    assert ar.lookup_hash(HASH_A)['status'] == 'no_prior_reports'


def test_rate_limited(monkeypatch):
    monkeypatch.setattr(ar.requests, 'get', lambda *a, **k: FakeResponse(429))
    assert ar.lookup_hash(HASH_A)['status'] == 'rate_limited'


def test_malicious_stats_parsed(monkeypatch):
    payload = {'data': {'attributes': {'last_analysis_stats': {'malicious': 5, 'suspicious': 1, 'undetected': 60, 'harmless': 4}}}}
    monkeypatch.setattr(ar.requests, 'get', lambda *a, **k: FakeResponse(200, payload))
    result = ar.lookup_hash(HASH_A)
    assert result['status'] == 'available'
    assert result['malicious_count'] == 5
    assert result['total_engines'] == 70


def test_caps_lookups_per_analysis(monkeypatch):
    payload = {'data': {'attributes': {'last_analysis_stats': {'malicious': 0, 'suspicious': 0, 'undetected': 1, 'harmless': 1}}}}
    calls = {'n': 0}
    def fake_get(*a, **k):
        calls['n'] += 1
        return FakeResponse(200, payload)
    monkeypatch.setattr(ar.requests, 'get', fake_get)
    attachments = [{'sha256': h, 'size': 10} for h in (HASH_A, HASH_B, HASH_C, HASH_D, HASH_E)]
    result = ar.enrich(attachments, True)
    assert calls['n'] == 4
    assert [r['status'] for r in result] == ['available', 'available', 'available', 'available', 'not_checked']
    assert result[-1]['sha256'] == HASH_E


def test_cache_hit_skips_network(monkeypatch):
    payload = {'data': {'attributes': {'last_analysis_stats': {'malicious': 0, 'undetected': 1}}}}
    calls = {'n': 0}
    def fake_get(*a, **k):
        calls['n'] += 1
        return FakeResponse(200, payload)
    monkeypatch.setattr(ar.requests, 'get', fake_get)
    ar.lookup_hash(HASH_A)
    second = ar.lookup_hash(HASH_A)
    assert calls['n'] == 1
    assert second['cached']

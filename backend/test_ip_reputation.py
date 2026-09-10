import pytest
import ip_reputation as ir


@pytest.fixture(autouse=True)
def reset(monkeypatch):
    ir._cache.clear()
    monkeypatch.setenv('ABUSEIPDB_API_KEY', 'test-key')


def test_no_key_never_network(monkeypatch):
    monkeypatch.delenv('ABUSEIPDB_API_KEY', raising=False)
    monkeypatch.setattr(ir.requests, 'get', lambda *a, **k: pytest.fail('Unexpected network'))
    assert ir.lookup('8.8.8.8')['status'] == 'disabled'


def test_enrich_disabled_no_network(monkeypatch):
    monkeypatch.setattr(ir.requests, 'get', lambda *a, **k: pytest.fail('Unexpected network'))
    hops = [{'ips': ['8.8.8.8']}]
    result = ir.enrich(hops, False)
    assert result == [{'ip': '8.8.8.8', 'status': 'disabled', 'detail': 'External IP reputation lookup not enabled.'}]


def test_missing_key_is_disabled(monkeypatch):
    monkeypatch.delenv('ABUSEIPDB_API_KEY', raising=False)
    monkeypatch.setattr(ir.requests, 'get', lambda *a, **k: pytest.fail('Unexpected network'))
    result = ir.enrich([{'ips': ['8.8.8.8']}], True)
    assert result[0]['status'] == 'disabled'


def test_private_ip_not_submitted(monkeypatch):
    monkeypatch.setattr(ir.requests, 'get', lambda *a, **k: pytest.fail('Unexpected network'))
    assert ir.lookup('10.0.0.1')['status'] == 'not_public'


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


def test_rate_limited(monkeypatch):
    monkeypatch.setattr(ir.requests, 'get', lambda *a, **k: FakeResponse(429))
    assert ir.lookup('8.8.8.8')['status'] == 'rate_limited'


def test_available_flags_hosting_as_anonymization_signal(monkeypatch):
    payload = {'data': {'usageType': 'Data Center/Web Hosting/Transit', 'abuseConfidenceScore': 10, 'isTor': False,
                        'isp': 'Example Host', 'domain': 'example.com', 'totalReports': 3}}
    monkeypatch.setattr(ir.requests, 'get', lambda *a, **k: FakeResponse(200, payload))
    result = ir.lookup('8.8.8.8')
    assert result['status'] == 'available'
    assert result['anonymization_signal'] is True


def test_cache_hit_skips_network(monkeypatch):
    payload = {'data': {'usageType': 'Fixed Line ISP', 'abuseConfidenceScore': 0, 'isTor': False, 'isp': 'ISP', 'domain': '', 'totalReports': 0}}
    calls = {'n': 0}
    def fake_get(*a, **k):
        calls['n'] += 1
        return FakeResponse(200, payload)
    monkeypatch.setattr(ir.requests, 'get', fake_get)
    first = ir.lookup('8.8.8.8')
    second = ir.lookup('8.8.8.8')
    assert calls['n'] == 1
    assert first['status'] == 'available' and not first['cached']
    assert second['cached']

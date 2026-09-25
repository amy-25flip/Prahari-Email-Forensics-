import leads

DOMAIN = {'events': [{'eventAction': 'registration', 'eventDate': '2024-01-02T00:00:00Z'}, {'eventAction': 'expiration', 'eventDate': '2026-01-02T00:00:00Z'}],
          'entities': [{'roles': ['registrar'], 'vcardArray': ['vcard', [['fn', {}, 'text', 'Example Registrar Inc']]],
                        'entities': [{'roles': ['abuse'], 'vcardArray': ['vcard', [['email', {}, 'text', 'abuse@registrar.example']]]}]}]}
IP = {'name': 'EXAMPLE-NET', 'handle': 'NET-1', 'country': 'US', 'startAddress': '203.0.113.0', 'endAddress': '203.0.113.255',
      'entities': [{'roles': ['abuse'], 'vcardArray': ['vcard', [['email', {}, 'text', 'abuse@host.example']]]}]}


def test_parsers():
    d = leads.parse_domain(DOMAIN)
    assert d == {'registrar': 'Example Registrar Inc', 'abuse_contact': 'abuse@registrar.example', 'registered_at': '2024-01-02T00:00:00Z', 'expires_at': '2026-01-02T00:00:00Z'}
    n = leads.parse_ip(IP)
    assert n['network'] == 'EXAMPLE-NET' and n['abuse_contact'] == 'abuse@host.example' and n['range'].startswith('203.0.113.0')
    assert leads.parse_domain({})['registrar'] is None


def test_disabled_and_assembly(monkeypatch):
    assert leads.assess({}, False)['status'] == 'disabled'
    leads._cache.clear()
    monkeypatch.setattr(leads, '_domain_lookup', lambda d: leads.parse_domain(DOMAIN))
    monkeypatch.setattr(leads, '_ip_lookup', lambda ip: leads.parse_ip(IP))
    report = {'domain_intelligence': {'registered_domain': 'evil.net'}, 'hops': [{'ips': ['93.184.216.34', '10.0.0.1']}]}
    out = leads.assess(report, True)
    kinds = {i['kind']: i for i in out['items']}
    assert kinds['registrar']['abuse_contact'] == 'abuse@registrar.example' and kinds['network_owner']['subject'] == '93.184.216.34'
    assert 'none of this identifies' in out['caveat']


def test_lookup_failure_is_unavailable_not_an_error(monkeypatch):
    leads._cache.clear()
    def boom(_): raise ValueError('x')
    monkeypatch.setattr(leads, '_domain_lookup', boom)
    out = leads.assess({'domain_intelligence': {'registered_domain': 'evil.net'}, 'hops': []}, True)
    assert out['status'] == 'unavailable' and out['items'] == []



def test_real_trimmed_rdap_fixtures_parse():
    import json
    from pathlib import Path
    root = Path(__file__).parent / 'data' / 'rdap_fixtures'
    fastly = json.loads((root / 'arin_fastly_151_101_0_223.json').read_text(encoding='utf-8'))
    google = json.loads((root / 'google_com_domain.json').read_text(encoding='utf-8'))
    ip = leads.parse_ip(fastly)
    assert ip['network'] and ip['range'].startswith('151.101.')
    assert ip['abuse_contact']
    domain = leads.parse_domain(google)
    assert domain['registrar'] or domain['registered_at']


def test_mailto_vcard_email_is_supported():
    data = {'entities': [{'roles': ['abuse'], 'vcardArray': ['vcard', [['email', {}, 'uri', 'mailto:abuse@example.net']]]}]}
    assert leads.parse_ip(data)['abuse_contact'] == 'abuse@example.net'


class _Resp:
    def __init__(self, status, body=b'', headers=None):
        self.status_code = status
        self._body = body
        self.headers = headers or {}
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def iter_content(self, _):
        yield self._body


def test_rdap_one_safe_rir_redirect(monkeypatch):
    calls = []
    payload = b'{"name":"FASTLY","startAddress":"151.101.0.0","endAddress":"151.101.255.255","entities":[]}'
    def fake_get(url, **kwargs):
        calls.append(url)
        if len(calls) == 1:
            return _Resp(301, headers={'Location': 'https://rdap.arin.net/registry/ip/151.101.0.223'})
        return _Resp(200, payload)
    monkeypatch.setattr(leads.requests, 'get', fake_get)
    out = leads.fetch_rdap_json('https://rdap.db.ripe.net/ip/151.101.0.223')
    assert out['name'] == 'FASTLY'
    assert calls == ['https://rdap.db.ripe.net/ip/151.101.0.223', 'https://rdap.arin.net/registry/ip/151.101.0.223']


def test_rdap_redirect_rejects_unsafe_targets(monkeypatch):
    bad_locations = [
        'http://rdap.arin.net/registry/ip/151.101.0.223',
        'https://evil.example/rdap/ip/151.101.0.223',
        'https://user@rdap.arin.net/registry/ip/151.101.0.223',
        'https://rdap.arin.net:443/registry/ip/151.101.0.223',
        'https://rdap.arin.net/not-rdap/151.101.0.223',
    ]
    for loc in bad_locations:
        monkeypatch.setattr(leads.requests, 'get', lambda *a, loc=loc, **k: _Resp(301, headers={'Location': loc}))
        try:
            leads.fetch_rdap_json('https://rdap.db.ripe.net/ip/151.101.0.223')
        except ValueError as exc:
            assert 'redirect' in str(exc).lower()
        else:
            raise AssertionError(loc)


def test_ip_bootstrap_tolerates_malformed_entries(monkeypatch):
    leads._ip_bootstrap.clear()
    def fake_fetch(url):
        return {'services': [None, [['bad-cidr'], ['https://rdap.example/']], [['151.101.0.0/16'], ['https://rdap.arin.net/registry']]]}
    monkeypatch.setattr(leads.di, 'fetch_json', fake_fetch)
    assert leads._ip_endpoint(__import__('ipaddress').ip_address('151.101.0.223')) == 'https://rdap.arin.net/registry'

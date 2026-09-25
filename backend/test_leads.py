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

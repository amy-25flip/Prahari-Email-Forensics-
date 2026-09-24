from request_limits import PeerLimiter
from test_selection import client, HEADERS


class _FakeClient:
    def __init__(self, host):
        self.host = host


class _FakeRequest:
    def __init__(self, client_host, headers=None):
        self.client = _FakeClient(client_host) if client_host else None
        self.headers = headers or {}

def test_limit_expiry_and_capacity():
    limiter=PeerLimiter(limit=2,window=60,capacity=1)
    assert limiter.allow('a',0)
    assert limiter.allow('a',1)
    assert not limiter.allow('a',2)
    assert not limiter.allow('b',2)
    assert limiter.allow('b',62)

def test_peer_limit_cannot_be_reset_with_cookie_or_forwarded_header(client):
    import main
    main.peer_limiter.reset()
    for i in range(30):
        response=client.post('/api/analyze',json={},headers={**HEADERS,'X-Forwarded-For':str(i),'Cookie':'efp_session=forged'})
        assert response.status_code==400
    response=client.post('/api/analyze',json={},headers=HEADERS)
    assert response.status_code==429
    assert response.headers['retry-after']=='60'
    main.peer_limiter.reset()

def test_get_requests_are_peer_rate_limited_too(client):
    # Previously only POST/DELETE were peer-rate-limited here, but every GET
    # to an /api/* route still reaches store.session() and creates a brand
    # new session (consuming a MAX_SESSIONS slot) whenever no cookie is sent
    # -- an unauthenticated GET flood could exhaust session capacity with
    # zero POSTs involved, since GETs were entirely exempt from this limiter.
    import main
    main.peer_limiter.reset()
    for i in range(30):
        response = client.get('/api/cases', headers={'X-Forwarded-For': str(i)})
        assert response.status_code == 200
    response = client.get('/api/cases')
    assert response.status_code == 429
    assert response.headers['retry-after'] == '60'
    main.peer_limiter.reset()


def test_health_and_ready_remain_exempt_from_peer_limit(client):
    import main
    main.peer_limiter.reset()
    for _ in range(40):
        assert client.get('/api/health').status_code == 200
    main.peer_limiter.reset()


def test_peer_identity_ignores_forwarded_header_by_default(monkeypatch):
    # Regression (Antigravity-flagged, real): behind a reverse proxy,
    # request.client.host is always the PROXY's own address, so every real
    # user shared one rate-limit bucket. But blindly trusting
    # X-Forwarded-For instead would be a WORSE, trivially exploitable
    # rate-limit bypass (a client can set it to anything) -- this is why
    # trusting it is opt-in (TRUSTED_PROXY_HOPS), not automatic.
    import main
    monkeypatch.setattr(main, 'TRUSTED_PROXY_HOPS', 0)
    request = _FakeRequest('10.0.0.5', {'x-forwarded-for': '1.2.3.4'})
    assert main.peer_identity(request) == '10.0.0.5'


def test_peer_identity_uses_last_entry_with_one_trusted_hop(monkeypatch):
    import main
    monkeypatch.setattr(main, 'TRUSTED_PROXY_HOPS', 1)
    monkeypatch.setattr(main, 'TRUSTED_PROXY_IPS', {'proxy-internal-ip'})
    request = _FakeRequest('proxy-internal-ip', {'x-forwarded-for': '203.0.113.9'})
    assert main.peer_identity(request) == '203.0.113.9'


def test_peer_identity_ignores_client_prepended_fake_entries_with_one_trusted_hop(monkeypatch):
    # A malicious client sends its OWN X-Forwarded-For with fake entries; the
    # ONE real trusted proxy in front of this app still only ever APPENDS
    # the peer it directly observed, as the LAST entry -- that's the only
    # position ever trusted, regardless of what the client prepended.
    import main
    monkeypatch.setattr(main, 'TRUSTED_PROXY_HOPS', 1)
    monkeypatch.setattr(main, 'TRUSTED_PROXY_IPS', {'proxy-internal-ip'})
    request = _FakeRequest('proxy-internal-ip', {'x-forwarded-for': 'totally-fake-ip, 203.0.113.9'})
    assert main.peer_identity(request) == '203.0.113.9'


def test_peer_identity_falls_back_to_direct_when_header_has_too_few_entries(monkeypatch):
    # A misconfigured/missing proxy must not silently trust attacker input
    # just because SOME header happens to be present.
    import main
    monkeypatch.setattr(main, 'TRUSTED_PROXY_HOPS', 2)
    monkeypatch.setattr(main, 'TRUSTED_PROXY_IPS', {'direct-ip'})
    request = _FakeRequest('direct-ip', {'x-forwarded-for': 'only-one-entry'})
    assert main.peer_identity(request) == 'direct-ip'


def test_peer_identity_falls_back_to_direct_when_header_absent(monkeypatch):
    import main
    monkeypatch.setattr(main, 'TRUSTED_PROXY_HOPS', 1)
    monkeypatch.setattr(main, 'TRUSTED_PROXY_IPS', {'direct-ip'})
    request = _FakeRequest('direct-ip', {})
    assert main.peer_identity(request) == 'direct-ip'


def test_peer_identity_ignores_xff_from_an_untrusted_direct_peer_even_with_hops_set(monkeypatch):
    # Regression (Codex Medium): TRUSTED_PROXY_HOPS alone previously trusted
    # XFF from ANY direct connection once set, with no check on who actually
    # made it -- an attacker reaching this app directly (bypassing the real
    # proxy, e.g. a network misconfiguration) could set an arbitrary XFF and
    # freely rotate their own rate-limit identity. Now XFF is only consulted
    # when the direct peer is itself a known, explicitly trusted proxy.
    import main
    monkeypatch.setattr(main, 'TRUSTED_PROXY_HOPS', 1)
    monkeypatch.setattr(main, 'TRUSTED_PROXY_IPS', {'the.real.proxy.ip'})
    request = _FakeRequest('attacker-direct-connection', {'x-forwarded-for': 'attacker-forged-identity'})
    assert main.peer_identity(request) == 'attacker-direct-connection'


def test_peer_identity_never_trusts_xff_when_trusted_proxy_ips_is_left_empty(monkeypatch):
    # The default (fail-closed): even with TRUSTED_PROXY_HOPS set, an empty
    # TRUSTED_PROXY_IPS means XFF is NEVER trusted, matching this codebase's
    # existing convention of failing safe on incomplete configuration.
    import main
    monkeypatch.setattr(main, 'TRUSTED_PROXY_HOPS', 1)
    monkeypatch.setattr(main, 'TRUSTED_PROXY_IPS', set())
    request = _FakeRequest('any-direct-peer', {'x-forwarded-for': '203.0.113.9'})
    assert main.peer_identity(request) == 'any-direct-peer'


def test_security_headers_on_html_and_errors(client):
    for path in ('/','/api/health','/api/missing'):
        response=client.get(path)
        assert response.headers['x-content-type-options']=='nosniff'
        assert response.headers['x-frame-options']=='DENY'
        if path.startswith('/api/'): assert response.headers['cache-control']=='no-store'


def test_csp_header_present_on_every_response(client):
    # Regression (Antigravity-flagged, real): no Content-Security-Policy at
    # all was previously sent. img-src explicitly allows tile.openstreetmap.org
    # -- the ONE external resource the built frontend actually loads
    # (RelayMap.jsx's Leaflet tile layer) -- verified against the real,
    # running app that a genuine map tile still loads under this exact
    # policy, not guessed.
    for path in ('/', '/api/health', '/api/missing'):
        csp = client.get(path).headers['content-security-policy']
        assert "default-src 'self'" in csp
        assert 'tile.openstreetmap.org' in csp
        assert "frame-ancestors 'none'" in csp


def test_hsts_only_sent_when_cookie_secure_is_explicitly_enabled(client, monkeypatch):
    import main
    # Default (no COOKIE_SECURE set) -- must NOT send HSTS. Sending it when
    # HTTPS isn't guaranteed risks the browser refusing to connect at all
    # until the policy's max-age expires, a far worse failure than omitting it.
    monkeypatch.delenv('COOKIE_SECURE', raising=False)
    assert 'strict-transport-security' not in client.get('/api/health').headers

    monkeypatch.setenv('COOKIE_SECURE', '1')
    response = client.get('/api/health')
    assert response.headers['strict-transport-security'] == 'max-age=31536000; includeSubDomains'


def test_multi_hop_stops_at_the_first_untrusted_entry_from_the_right(monkeypatch):
    # Chain: client -> proxyA -> proxyB(direct) -> app, HOPS=2. XFF = "client, proxyA".
    import main
    monkeypatch.setattr(main, 'TRUSTED_PROXY_HOPS', 2)
    monkeypatch.setattr(main, 'TRUSTED_PROXY_IPS', {'proxyB', 'proxyA'})
    request = _FakeRequest('proxyB', {'x-forwarded-for': '203.0.113.9, proxyA'})
    assert main.peer_identity(request) == '203.0.113.9'


def test_multi_hop_forged_prefix_cannot_masquerade_when_a_middle_hop_is_untrusted(monkeypatch):
    # Attacker reaches the last proxy directly with a forged XFF. The "middle" entry
    # is not a trusted proxy, so it is treated as the real client identity - the
    # forged prefix ("victim-ip") is never reached.
    import main
    monkeypatch.setattr(main, 'TRUSTED_PROXY_HOPS', 2)
    monkeypatch.setattr(main, 'TRUSTED_PROXY_IPS', {'proxyB'})
    request = _FakeRequest('proxyB', {'x-forwarded-for': 'victim-ip, attacker-ip'})
    assert main.peer_identity(request) == 'attacker-ip'


def test_multi_hop_three_proxies_all_trusted_returns_the_client(monkeypatch):
    import main
    monkeypatch.setattr(main, 'TRUSTED_PROXY_HOPS', 3)
    monkeypatch.setattr(main, 'TRUSTED_PROXY_IPS', {'p1', 'p2', 'p3'})
    request = _FakeRequest('p3', {'x-forwarded-for': 'fake, 198.51.100.4, p1, p2'})
    assert main.peer_identity(request) == '198.51.100.4'


def test_trusted_proxy_cidr_ranges_are_honoured_and_bad_entries_ignored(monkeypatch):
    import main
    monkeypatch.setattr(main, 'TRUSTED_PROXY_HOPS', 2)
    monkeypatch.setattr(main, 'TRUSTED_PROXY_IPS', set())
    monkeypatch.setattr(main, 'TRUSTED_PROXY_CIDRS', main._parse_networks('10.0.0.0/8, not-a-cidr, 192.168.1.0/24'))
    assert len(main.TRUSTED_PROXY_CIDRS) == 2
    request = _FakeRequest('10.4.5.6', {'x-forwarded-for': '203.0.113.7, 192.168.1.20'})
    assert main.peer_identity(request) == '203.0.113.7'
    outside = _FakeRequest('172.16.0.1', {'x-forwarded-for': '203.0.113.7, 192.168.1.20'})
    assert main.peer_identity(outside) == '172.16.0.1'

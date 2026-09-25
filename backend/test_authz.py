import json

import pytest

import authz
import main
import store
from test_selection import client

H = {'X-Requested-With': 'Email-Threat-Detection'}
TOKENS = 'asha:analyst:analyst-token-0123456789,ravi:admin:admin-token-0123456789abc,meera:viewer:viewer-token-0123456789ab,dev:analyst:second-analyst-token-0123'


def bearer(token):
    return {**H, 'Authorization': f'Bearer {token}'}


ANALYST, ADMIN, VIEWER, ANALYST2 = (bearer('analyst-token-0123456789'), bearer('admin-token-0123456789abc'),
                                    bearer('viewer-token-0123456789ab'), bearer('second-analyst-token-0123'))
EMAIL = ('From: a@b.example\r\nTo: c@d.example\r\nSubject: Verify\r\nContent-Type: text/plain\r\n\r\n'
         'Please verify your account at http://college-login.example/verify now to avoid suspension of services today.\r\n')


@pytest.fixture
def secured(monkeypatch):
    monkeypatch.setenv('ROLE_TOKENS', TOKENS)


# ---------- pure functions ----------
def test_disabled_by_default_and_malformed_entries_are_ignored(monkeypatch):
    monkeypatch.delenv('ROLE_TOKENS', raising=False)
    assert authz.enabled() is False
    monkeypatch.setenv('ROLE_TOKENS', 'bad,also:bad,x:superuser:0123456789abcdef01,y:analyst:short,:analyst:0123456789abcdef01,ok:viewer:0123456789abcdef01')
    assert [e[0] for e in authz._entries()] == ['ok']
    assert authz.enabled() is True


def test_fails_closed_when_configured_but_no_valid_entry(monkeypatch, client):
    monkeypatch.setenv('ROLE_TOKENS', 'x:analyst:short')
    assert authz.enabled() and authz.authenticate('Bearer short') is None
    assert client.get('/api/cases').status_code == 401          # never falls back to open access
    assert client.get('/api/health').status_code == 200


def test_authenticate_uses_exact_bearer_tokens(secured):
    assert authz.authenticate('Bearer analyst-token-0123456789') == authz.Actor('asha', 'analyst')
    assert authz.authenticate('bearer   admin-token-0123456789abc ') == authz.Actor('ravi', 'admin')
    for bad in (None, '', 'Bearer', 'Bearer nope', 'Basic analyst-token-0123456789', 'analyst-token-0123456789', 'Bearer analyst-token-012345678'):
        assert authz.authenticate(bad) is None


@pytest.mark.parametrize('method,path,query,role', [
    ('GET', '/api/cases', {}, 'viewer'), ('GET', '/api/cases/abc', {}, 'viewer'), ('GET', '/api/cases/abc/export/json', {'privacy': 'redacted'}, 'viewer'),
    ('GET', '/api/cases/abc/export/json', {}, 'analyst'), ('GET', '/api/cases/abc/export/evidence', {'privacy': 'redacted'}, 'analyst'),
    ('GET', '/api/cases/abc/export/stix', {}, 'analyst'), ('GET', '/api/quarantine', {}, 'analyst'), ('GET', '/api/gateway/inbox', {}, 'analyst'),
    ('POST', '/api/analyze', {}, 'analyst'), ('POST', '/api/samples/account', {}, 'analyst'), ('POST', '/api/cases/abc/notes', {}, 'analyst'),
    ('POST', '/api/cases/abc/assign', {}, 'analyst'), ('POST', '/api/cases/abc/review', {}, 'analyst'), ('POST', '/api/cases/abc/urls/inspect', {}, 'analyst'),
    ('POST', '/api/quarantine/q1/release', {}, 'analyst'), ('POST', '/api/quarantine/q1/discard', {}, 'admin'),
    ('DELETE', '/api/cases/abc', {}, 'admin'), ('POST', '/api/checkpoint/blockchain-stamp', {}, 'admin'), ('POST', '/api/something/new', {}, 'admin'),
])
def test_permission_map(method, path, query, role):
    assert authz.required_role(method, path, query) == role


def test_exempt_paths_are_the_exact_self_authenticated_gmail_routes_and_static():
    for path in ('/api/health', '/api/ready', '/api/gmail/push', '/api/gmail/cases', '/api/gmail/cases/abc123', '/api/gmail/watch/start', '/', '/assets/x.js'):
        assert authz.is_exempt(path)
    for path in ('/api/cases', '/api/gmail/debug', '/api/gmail/actions', '/api/gmail/cases/a/b', '/api/gmail/', '/api/gmail/push/x', '/api/gmailx/cases'):
        assert not authz.is_exempt(path), path


# ---------- through the app ----------
def test_no_token_is_401_and_wrong_role_is_403(client, secured):
    assert client.get('/api/cases', headers=H).status_code == 401
    assert client.get('/api/cases', headers=bearer('wrong-token-0123456789')).status_code == 401
    assert client.get('/api/cases', headers=VIEWER).status_code == 200
    assert client.post('/api/analyze', json={'email': EMAIL}, headers=VIEWER).status_code == 403
    made = client.post('/api/analyze', json={'email': EMAIL}, headers=ANALYST)
    assert made.status_code == 200
    cid = made.json()['id']
    assert client.delete(f'/api/cases/{cid}', headers=ANALYST).status_code == 403
    assert client.delete(f'/api/cases/{cid}', headers=ADMIN).status_code == 200


def test_viewer_gets_redacted_exports_only(client, secured):
    cid = client.post('/api/analyze', json={'email': EMAIL}, headers=ANALYST).json()['id']
    assert client.get(f'/api/cases/{cid}/export/json?privacy=redacted', headers=VIEWER).status_code == 200
    assert client.get(f'/api/cases/{cid}/export/json', headers=VIEWER).status_code == 403
    assert client.get(f'/api/cases/{cid}/export/evidence', headers=VIEWER).status_code == 403
    assert client.get(f'/api/cases/{cid}/export/evidence', headers=ANALYST).status_code == 200


def test_authenticated_people_share_one_workspace_without_cookies(client, secured):
    cid = client.post('/api/analyze', json={'email': EMAIL}, headers=ANALYST).json()['id']
    client.cookies.clear()
    assert [c['id'] for c in client.get('/api/cases', headers=ANALYST2).json()] == [cid]     # another person sees it
    assert client.get('/api/whoami', headers=ANALYST2).json() == {'auth_required': True, 'actor': 'dev', 'role': 'analyst'}
    assert 'set-cookie' not in client.get('/api/cases', headers=VIEWER).headers


def test_every_audit_event_is_stamped_with_the_real_actor(client, secured):
    cid = client.post('/api/analyze', json={'email': EMAIL}, headers=ANALYST).json()['id']
    client.post(f'/api/cases/{cid}/notes', json={'text': 'called the vendor on the number on file'}, headers=ANALYST2)
    client.post(f'/api/cases/{cid}/assign', json={'owner': 'dev'}, headers=ANALYST)
    events = store.case_events(store.WORKSPACE_SID, cid)
    stamped = {(e['event']['action'], e['event'].get('actor'), e['event'].get('role')) for e in events}
    assert ('analyze', 'asha', 'analyst') in stamped and ('note', 'dev', 'analyst') in stamped and ('assign', 'asha', 'analyst') in stamped
    assert store.verify(store.WORKSPACE_SID)['valid'] is True                     # stamped events keep the chain valid
    pack = client.get(f'/api/cases/{cid}/export/evidence', headers=ANALYST).text
    assert 'by asha, analyst' in pack and 'by dev, analyst' in pack


def test_four_eyes_the_analyzer_cannot_approve_but_another_reviewer_can(client, secured, monkeypatch):
    cid = client.post('/api/analyze', json={'email': EMAIL}, headers=ANALYST).json()['id']
    note = 'Reviewed sender and links; confirmed with the vendor separately.'
    body = {'decision': 'approved', 'note': note, 'acknowledged': True}
    blocked = client.post(f'/api/cases/{cid}/review', json=body, headers=ANALYST)
    assert blocked.status_code == 403 and 'Four-eyes' in blocked.json()['detail']
    assert client.post(f'/api/cases/{cid}/review', json={**body, 'decision': 'hold'}, headers=ANALYST).status_code == 200     # holding is always allowed
    ok = client.post(f'/api/cases/{cid}/review', json=body, headers=ANALYST2)
    assert ok.status_code == 200
    events = store.case_events(store.WORKSPACE_SID, cid)
    review = [e['event'] for e in events if e['event']['action'] == 'review' and e['event']['decision'] == 'approved'][0]
    assert review['actor'] == 'dev'
    # explicit opt-out for single-person demos
    other = client.post('/api/analyze', json={'email': EMAIL.replace('Verify', 'Verify 2')}, headers=ANALYST).json()['id']
    monkeypatch.setenv('FOUR_EYES', '0')
    assert client.post(f'/api/cases/{other}/review', json=body, headers=ANALYST).status_code == 200


def test_per_person_analysis_rate_limit_not_shared(client, secured):
    main.limits.clear()
    for i in range(10):
        assert client.post('/api/analyze', json={'email': EMAIL.replace('Verify', f'V{i}')}, headers=ANALYST).status_code == 200
        client.delete(f"/api/cases/{client.get('/api/cases', headers=ANALYST).json()[0]['id']}", headers=ADMIN)
    main.peer_limiter.reset()                       # isolate the per-person analysis limit from the per-peer request limit
    over = client.post('/api/analyze', json={'email': EMAIL}, headers=ANALYST)
    assert over.status_code == 429 and 'analyses per minute' in over.json()['detail']
    assert client.post('/api/analyze', json={'email': EMAIL}, headers=ANALYST2).status_code == 200     # a different person is unaffected
    main.limits.clear()
    main.peer_limiter.reset()


def test_open_mode_is_unchanged_and_events_are_unstamped(client, monkeypatch):
    monkeypatch.delenv('ROLE_TOKENS', raising=False)
    cid = client.post('/api/analyze', json={'email': EMAIL}, headers=H).json()['id']
    assert client.get('/api/health').json()['auth_required'] is False
    assert client.get('/api/whoami').json() == {'auth_required': False, 'actor': None, 'role': None}
    for item in store.case_events(store.session(client.cookies.get('efp_session'))[0], cid):
        assert 'actor' not in item['event']


def test_fixed_session_refresh_is_throttled_but_recreated_when_the_data_dir_changes(tmp_path, monkeypatch):
    writes = []
    real = store.connect
    def counting_connect():
        writes.append(1)
        return real()
    monkeypatch.setattr(store, 'DATA', tmp_path / 'a')
    monkeypatch.setattr(store, 'connect', counting_connect)
    store.init()
    writes.clear()
    assert store.workspace_session() == store.WORKSPACE_SID and len(writes) == 1
    for _ in range(50):
        store.workspace_session()
    assert len(writes) == 1                                  # 50 more calls, zero more write transactions
    monkeypatch.setattr(store, 'DATA', tmp_path / 'b')       # a different database must get its own row
    store.init()
    writes.clear()
    store.workspace_session()
    assert len(writes) == 1
    with real() as db:
        assert db.execute('SELECT COUNT(*) FROM sessions WHERE id=?', (store.WORKSPACE_SID,)).fetchone()[0] == 1
    monkeypatch.setattr(store, '_fixed_refreshed', {})       # after the window (simulated) the expiry is extended again
    writes.clear()
    store.workspace_session()
    assert len(writes) == 1

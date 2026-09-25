import sqlite3
import time

import ledger
import store
from test_selection import client

H = {'X-Requested-With': 'Email-Threat-Detection'}


def _mail(n, reply='recovery@shared-desk.example'):
    return (f'From: Notice <alerts@bank-secure.example>\r\nReply-To: {reply}\r\nTo: analyst@college.example\r\nSubject: Notice {n}\r\n'
            f'Date: Thu, 24 Sep 2026 10:0{n}:00 +0530\r\nMessage-ID: <n{n}@bank-secure.example>\r\nContent-Type: text/plain\r\n\r\n'
            f'Your account needs verification today. Reply to {reply} to confirm your identity and avoid suspension of services (ref {n}).\r\n')


def test_record_then_lookup_counts_and_sessions(tmp_path, monkeypatch):
    monkeypatch.setattr(store, 'DATA', tmp_path)
    pairs = [('url', 'http://bad.example/x'), ('sender_domain', 'bad.example')]
    assert ledger.lookup(pairs, 's1') == {}
    base = time.time() - 5000
    ledger.record(pairs, 's1', now=base + 1000)
    ledger.record(pairs, 's1', now=base + 2000)
    ledger.record(pairs, 's2', now=base + 3000)
    hit = ledger.lookup(pairs, 's1')[('url', 'http://bad.example/x')]
    assert hit['seen_count'] == 3 and hit['distinct_sessions'] == 2 and hit['other_sessions'] == 1
    assert hit['first_seen'] == base + 1000 and hit['last_seen'] == base + 3000
    assert ledger.lookup([('url', 'http://never-seen.example')], 's1') == {}


def test_database_holds_no_raw_indicator_values_or_session_ids(tmp_path, monkeypatch):
    monkeypatch.setattr(store, 'DATA', tmp_path)
    ledger.record([('url', 'http://very-secret-phish.example/login?u=alice@corp.example')], 'session-abc-123', now=time.time())
    blob = b''.join(p.read_bytes() for p in tmp_path.iterdir() if p.name == 'ledger.sqlite')
    for needle in (b'very-secret-phish', b'alice@corp', b'session-abc-123', b'login'):
        assert needle not in blob
    db = sqlite3.connect(tmp_path / 'ledger.sqlite')
    row = db.execute('SELECT h, kind FROM indicators').fetchone()
    assert len(row[0]) == 64 and row[1] == 'url'
    db.close()


def test_hash_is_keyed_so_a_different_key_cannot_match(tmp_path, monkeypatch):
    monkeypatch.setattr(store, 'DATA', tmp_path)
    monkeypatch.setenv('LEDGER_KEY', 'key-one')
    ledger.record([('url', 'http://x.example')], 's', now=time.time())
    assert ledger.lookup([('url', 'http://x.example')], 's')
    monkeypatch.setenv('LEDGER_KEY', 'key-two')
    assert ledger.lookup([('url', 'http://x.example')], 's') == {}


def test_generated_key_persists_across_calls(tmp_path, monkeypatch):
    monkeypatch.setattr(store, 'DATA', tmp_path)
    ledger.record([('sender_domain', 'a.example')], 's', now=time.time())
    key = (tmp_path / 'ledger.key').read_bytes()
    ledger._key_cache.clear()
    assert (tmp_path / 'ledger.key').read_bytes() == key and len(key) == 32
    assert ledger.lookup([('sender_domain', 'a.example')], 's')


def test_retention_expires_and_cleanup_removes(tmp_path, monkeypatch):
    monkeypatch.setattr(store, 'DATA', tmp_path)
    monkeypatch.setenv('LEDGER_RETENTION_DAYS', '1')
    old = time.time() - 3 * 86400
    ledger.record([('url', 'http://old.example')], 's', now=old)
    ledger.record([('url', 'http://new.example')], 's', now=time.time())
    assert ledger.lookup([('url', 'http://old.example')], 's') == {}        # expired entries are ignored...
    assert ledger.cleanup() == 1                                            # ...and physically removed
    assert ledger.lookup([('url', 'http://new.example')], 's')
    db = sqlite3.connect(tmp_path / 'ledger.sqlite')
    assert db.execute('SELECT COUNT(*) FROM sessions').fetchone()[0] == 1
    db.close()


def test_disabled_and_bounded(tmp_path, monkeypatch):
    monkeypatch.setattr(store, 'DATA', tmp_path)
    monkeypatch.setenv('LEDGER_ENABLED', '0')
    assert ledger.record([('url', 'http://x.example')], 's') == 0 and ledger.lookup([('url', 'http://x.example')], 's') == {}
    assert not (tmp_path / 'ledger.sqlite').exists()
    monkeypatch.setenv('LEDGER_ENABLED', '1')
    report = {'indicators': [{'type': 'url', 'value': f'http://u{i}.example'} for i in range(200)], 'sender': 'a@b.example'}
    assert len(ledger.pairs_for(report)) == ledger.MAX_INDICATORS_PER_CASE


def test_cross_session_history_through_the_api_and_samples_excluded(client, tmp_path):
    # session 1 analyzes a suspicious email; a DIFFERENT session then sees the shared indicators, without case content
    first = client.post('/api/analyze', json={'email': _mail(1)}, headers=H).json()
    assert first['assessment']['network_history']['cross_session'] == []
    client.cookies.clear()                                            # new browser session
    second = client.post('/api/analyze', json={'email': _mail(2)}, headers=H).json()
    cross = second['assessment']['network_history']
    assert second['assessment']['network_history']['recurring'] == []  # per-session history is still isolated
    hits = {(c['type'], c['value']): c for c in cross['cross_session']}
    reply = hits[('reply_address', 'recovery@shared-desk.example')]
    assert reply['seen_count'] == 1 and reply['other_sessions'] == 1 and 'case' not in ' '.join(reply)
    assert 'hashed indicator ledger' in cross['scope']
    # samples never enter the ledger
    client.cookies.clear()
    client.post('/api/samples/account', headers=H)
    client.cookies.clear()
    third = client.post('/api/analyze', json={'email': _mail(3, reply='other@unrelated.example')}, headers=H).json()
    assert ('reply_address', 'recovery@secure-desk.example') not in {(c['type'], c['value']) for c in third['assessment']['network_history']['cross_session']}

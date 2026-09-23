import network_history


def report(indicators=None, sender='vendor@ok.example', hops=None, headers=None, created=1000.0, id='r1'):
    return {'indicators': indicators or [], 'sender': sender, 'hops': hops or [], 'headers': headers or [],
            'created': created, 'id': id}


def test_no_prior_reports_is_a_clean_no_op():
    current = report(indicators=[{'type': 'url', 'value': 'http://evil.example/a'}])
    result = network_history.assess(current, [])
    assert result['recurring'] == []


def test_no_shared_indicators_is_a_clean_no_op():
    current = report(sender='new@nobody.example')
    prior = report(sender='someone-else@other.example', id='r0')
    result = network_history.assess(current, [prior])
    assert result['recurring'] == []


def test_repeated_sender_domain_is_reported_with_occurrence_count():
    prior1 = report(sender='billing@shared-domain.example', id='r0', created=100.0)
    prior2 = report(sender='ops@shared-domain.example', id='r1', created=200.0)
    current = report(sender='alerts@shared-domain.example', id='r2', created=300.0)
    result = network_history.assess(current, [prior1, prior2])
    entry = next(e for e in result['recurring'] if e['type'] == 'sender_domain')
    assert entry['value'] == 'shared-domain.example'
    assert entry['occurrence_count'] == 2
    assert entry['first_seen'] == 100.0
    assert entry['last_seen'] == 200.0
    assert set(entry['case_ids']) == {'r0', 'r1'}


def test_repeated_url_across_cases_is_tracked():
    prior = report(indicators=[{'type': 'url', 'value': 'http://evil.example/login'}], id='r0', created=50.0)
    current = report(indicators=[{'type': 'url', 'value': 'http://evil.example/login'}], id='r1', created=150.0)
    result = network_history.assess(current, [prior])
    entry = next(e for e in result['recurring'] if e['type'] == 'url')
    assert entry['value'] == 'http://evil.example/login'
    assert entry['occurrence_count'] == 1
    assert entry['first_seen'] == 50.0


def test_repeated_attachment_hash_is_tracked():
    digest = 'a' * 64
    prior = report(indicators=[{'type': 'attachment_hash', 'value': digest}], id='r0')
    current = report(indicators=[{'type': 'attachment_hash', 'value': digest}], id='r1')
    result = network_history.assess(current, [prior])
    assert any(e['type'] == 'attachment_hash' and e['value'] == digest for e in result['recurring'])


def test_repeated_reported_ip_is_tracked():
    prior = report(hops=[{'ips': ['8.8.8.8']}], id='r0')
    current = report(hops=[{'ips': ['8.8.8.8']}], id='r1')
    result = network_history.assess(current, [prior])
    assert any(e['type'] == 'reported_ip' and e['value'] == '8.8.8.8' for e in result['recurring'])


def test_repeated_reply_address_is_tracked():
    prior = report(indicators=[{'type': 'reply_address', 'value': 'attacker@redirect.example'}], id='r0')
    current = report(indicators=[{'type': 'reply_address', 'value': 'attacker@redirect.example'}], id='r1')
    result = network_history.assess(current, [prior])
    assert any(e['type'] == 'reply_address' and e['value'] == 'attacker@redirect.example' for e in result['recurring'])


def test_private_ip_is_never_tracked_as_reported_ip():
    prior = report(sender='a@x.example', hops=[{'ips': ['10.0.0.5']}], id='r0')
    current = report(sender='b@y.example', hops=[{'ips': ['10.0.0.5']}], id='r1')
    result = network_history.assess(current, [prior])
    assert result['recurring'] == []


def test_thread_id_is_not_tracked_here_conversation_py_already_covers_it():
    msgid_header = [{'name': 'Message-ID', 'value': '<same@thread.example>'}]
    prior = report(sender='a@x.example', headers=msgid_header, id='r0')
    current = report(sender='b@y.example', headers=msgid_header, id='r1')
    result = network_history.assess(current, [prior])
    assert result['recurring'] == []


def test_current_report_never_counts_itself():
    # Guard against a report object appearing in its own "prior_reports" list
    # (e.g. store.all_cases() called after the current result was already
    # saved) inflating its own occurrence count.
    current = report(sender='alerts@shared-domain.example', id='r2', created=300.0)
    result = network_history.assess(current, [current])
    assert result['recurring'] == []


def test_same_id_different_object_never_counts_itself():
    # Regression (Codex Medium): a future/different caller could pass a
    # saved-and-reloaded copy of the current report (same id, different
    # Python object identity) inside prior_reports. It must still be excluded,
    # not just the exact same object.
    current = report(sender='alerts@shared-domain.example', id='r2', created=300.0)
    reloaded_copy = dict(current)
    result = network_history.assess(current, [reloaded_copy])
    assert result['recurring'] == []


def test_mismatched_timestamp_types_do_not_crash_sorting():
    # Regression (Codex Medium-low): mixed float/string/None 'created' values
    # across cases (e.g. an imported/legacy report) must not raise a
    # cross-type comparison error during sort.
    prior_a = report(sender='x@shared.example', id='r0', created='not-a-number')
    prior_b = report(sender='y@shared.example', id='r1', created=None)
    prior_c = report(sender='z@shared.example', id='r2', created=50.0)
    current = report(sender='w@shared.example', id='r3', created=100.0)
    result = network_history.assess(current, [prior_a, prior_b, prior_c])
    entry = next(e for e in result['recurring'] if e['type'] == 'sender_domain')
    assert entry['occurrence_count'] == 3
    assert entry['first_seen'] == 50.0  # the one real, comparable timestamp sorts first


def test_multiple_recurring_indicators_all_reported():
    prior = report(sender='vendor@shared.example',
                    indicators=[{'type': 'url', 'value': 'http://evil.example/a'}], id='r0')
    current = report(sender='vendor@shared.example',
                      indicators=[{'type': 'url', 'value': 'http://evil.example/a'}], id='r1')
    result = network_history.assess(current, [prior])
    types_seen = {e['type'] for e in result['recurring']}
    assert 'sender_domain' in types_seen and 'sender_address' in types_seen and 'url' in types_seen


# --- Integration: the full wiring through a real /api/analyze call ---
from test_selection import client, HEADERS  # noqa: E402


def test_network_history_present_and_empty_for_a_first_time_sender(client):
    raw = b'From: brandnew@nobody.example\r\nTo: v@d.com\r\nSubject: Hi\r\n\r\nJust checking in.'
    r = client.post('/api/analyze', content=raw, headers=HEADERS)
    assert r.status_code == 200
    history = r.json()['assessment']['network_history']
    assert history['recurring'] == []


def test_network_history_flags_a_repeated_sender_domain_across_cases(client):
    first = b'From: alice@repeat-domain.example\r\nTo: v@d.com\r\nSubject: One\r\n\r\nHello.'
    r1 = client.post('/api/analyze', content=first, headers=HEADERS)
    assert r1.status_code == 200

    second = b'From: bob@repeat-domain.example\r\nTo: v@d.com\r\nSubject: Two\r\n\r\nHello again.'
    r2 = client.post('/api/analyze', content=second, headers=HEADERS)
    assert r2.status_code == 200
    history = r2.json()['assessment']['network_history']
    entry = next(e for e in history['recurring'] if e['type'] == 'sender_domain')
    assert entry['value'] == 'repeat-domain.example'
    assert entry['occurrence_count'] == 1


def test_network_history_does_not_escalate_triage_by_itself(client):
    # Recurrence alone must stay purely informational -- a repeated sender
    # domain must not, on its own, change an otherwise-clean email's verdict
    # at all (not just "not review" -- must be the SAME routine verdict a
    # first-time sender from the same content would get).
    first = b'From: alice@calm-domain.example\r\nTo: v@d.com\r\nSubject: One\r\n\r\nHello.'
    r1 = client.post('/api/analyze', content=first, headers=HEADERS)
    second = b'From: bob@calm-domain.example\r\nTo: v@d.com\r\nSubject: Two\r\n\r\nHello again.'
    r2 = client.post('/api/analyze', content=second, headers=HEADERS)
    body = r2.json()
    assert body['assessment']['network_history']['recurring']  # sanity: it did fire
    # Same baseline verdict as the first (unrelated, non-recurring) email got --
    # recurrence must not change it either direction.
    assert body['triage']['priority'] == r1.json()['triage']['priority']


def test_network_history_is_isolated_per_session(client, monkeypatch):
    # The highest-stakes property of this feature: it must never let one
    # analyst's session see indicator history belonging to a different
    # session's cases. Force two separate sessions by clearing cookies
    # between requests (same pattern the app's own session-scoping relies on).
    shared_domain_first = b'From: alice@repeat-domain.example\r\nTo: v@d.com\r\nSubject: One\r\n\r\nHi.'
    r1 = client.post('/api/analyze', content=shared_domain_first, headers=HEADERS)
    assert r1.status_code == 200
    client.cookies.clear()  # start a brand new session, as a different analyst would

    shared_domain_second = b'From: bob@repeat-domain.example\r\nTo: v@d.com\r\nSubject: Two\r\n\r\nHi again.'
    r2 = client.post('/api/analyze', content=shared_domain_second, headers=HEADERS)
    assert r2.status_code == 200
    assert r2.json()['assessment']['network_history']['recurring'] == []

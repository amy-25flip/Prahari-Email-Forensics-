import base64
import json
from pathlib import Path

import pytest
from googleapiclient.errors import HttpError

import gmail_integration as gi
import store
from test_selection import client, HEADERS

PUSH_SUBJECT = 'push-invoker@email-threat-detection-508403.iam.gserviceaccount.com'


@pytest.fixture(autouse=True)
def isolate_state(tmp_path, monkeypatch):
    monkeypatch.setattr(gi, 'TOKEN_FILE', tmp_path / 'gmail_token.json')
    monkeypatch.setattr(gi, 'STATE_FILE', tmp_path / 'gmail_watch_state.json')


def _configure_push_env(monkeypatch):
    monkeypatch.setenv('GMAIL_PUSH_AUDIENCE', 'https://example.onrender.com/api/gmail/push')
    monkeypatch.setenv('GMAIL_PUSH_SERVICE_ACCOUNT_EMAIL', PUSH_SUBJECT)
    monkeypatch.setattr(gi, 'configured', lambda: True)


def _mock_valid_token(monkeypatch):
    from google.oauth2 import id_token as google_id_token
    monkeypatch.setattr(google_id_token, 'verify_oauth2_token',
                         lambda *a, **k: {'email': PUSH_SUBJECT, 'email_verified': True})


def test_not_configured_without_token_file():
    assert gi.configured() is False


def test_credentials_refresh_tolerates_unwritable_token_file(tmp_path, monkeypatch):
    # Regression: found live on Render, where TOKEN_FILE points at a Secret File
    # mount that likely isn't writable. Writing back a refreshed access token is
    # a caching optimization, not a correctness requirement -- a failed write
    # must not crash every call that needed fresh credentials.
    token_path = tmp_path / 'gmail_token.json'
    token_path.write_text(json.dumps({
        'token': 'old', 'refresh_token': 'r', 'token_uri': 'https://oauth2.googleapis.com/token',
        'client_id': 'cid', 'client_secret': 'secret', 'scopes': gi.SCOPES,
    }))
    monkeypatch.setattr(gi, 'TOKEN_FILE', token_path)

    class FakeCreds:
        expired = True
        refresh_token = 'r'
        def refresh(self, request): pass
        def to_json(self): return '{}'

    monkeypatch.setattr(gi.Credentials, 'from_authorized_user_file', staticmethod(lambda *a, **k: FakeCreds()))
    def raise_oserror(self, *a, **k):
        raise OSError('read-only filesystem')
    monkeypatch.setattr(Path, 'write_text', raise_oserror)
    creds = gi._credentials()
    assert isinstance(creds, FakeCreds)


def test_read_state_tolerates_corrupt_file(monkeypatch):
    # Regression: a state file corrupted by an interrupted write (deploy restart,
    # OOM) must not permanently break every subsequent Gmail push -- treat it as
    # "no state yet" rather than raising out of json.loads.
    gi.STATE_FILE.write_text('not valid json{{{')
    assert gi._read_state() == {}


def test_write_state_is_atomic_and_creates_parent_dir(tmp_path, monkeypatch):
    nested = tmp_path / 'nested' / 'dir' / 'gmail_watch_state.json'
    monkeypatch.setattr(gi, 'STATE_FILE', nested)
    gi._write_state({'last_history_id': '5'})
    assert json.loads(nested.read_text()) == {'last_history_id': '5'}
    assert not nested.with_suffix('.json.tmp').exists()


def test_session_sid_persists_across_calls(tmp_path, monkeypatch):
    monkeypatch.setattr(store, 'DATA', tmp_path)
    store.init()
    first = gi.session_sid()
    second = gi.session_sid()
    assert first == second


def test_b64decode_accepts_both_standard_and_urlsafe_alphabets():
    payload = b'{"historyId": "42"}'
    standard = base64.b64encode(payload).decode()
    urlsafe = base64.urlsafe_b64encode(payload).decode().rstrip('=')
    assert gi.b64decode(standard) == payload
    assert gi.b64decode(urlsafe) == payload


class FakeHistoryList:
    def __init__(self, records):
        self.records = records
    def execute(self):
        return {'history': self.records}


class FakeMessagesGet:
    def __init__(self, raw_b64url):
        self.raw_b64url = raw_b64url
    def execute(self):
        return {'raw': self.raw_b64url}


class FakeUsers:
    def __init__(self, history_records, message_bodies):
        self.history_records = history_records
        self.message_bodies = message_bodies
    def history(self):
        return self
    def list(self, **kwargs):
        return FakeHistoryList(self.history_records)
    def messages(self):
        return self
    def get(self, userId, id, format):
        return FakeMessagesGet(self.message_bodies[id])


class FakeService:
    def __init__(self, history_records, message_bodies):
        self._users = FakeUsers(history_records, message_bodies)
    def users(self):
        return self._users


def test_diff_new_message_ids_does_not_advance_watermark(monkeypatch):
    # Regression: diffing must be a pure read -- advancing the watermark is a
    # separate, explicit step the caller takes only after actually attempting to
    # process what was found, so a fetch-succeeded-but-processing-never-happened
    # case can't silently mark mail as "seen".
    records = [{'messagesAdded': [{'message': {'id': 'msg1'}}]}]
    monkeypatch.setattr(gi, '_service', lambda: FakeService(records, {}))
    ids = gi.diff_new_message_ids('999')
    assert ids == ['msg1']
    assert not gi.STATE_FILE.exists()


def test_fetch_raw_decodes_message_body(monkeypatch):
    raw_bytes = b'From: a@b.com\r\nSubject: hi\r\n\r\nbody'
    raw_b64url = base64.urlsafe_b64encode(raw_bytes).decode().rstrip('=')
    monkeypatch.setattr(gi, '_service', lambda: FakeService([], {'msg1': raw_b64url}))
    assert gi.fetch_raw('msg1') == raw_bytes


def test_advance_watermark_persists_history_id():
    gi.advance_watermark('999')
    assert json.loads(gi.STATE_FILE.read_text())['last_history_id'] == '999'


def test_advance_watermark_is_monotonic(monkeypatch):
    # Regression (caught in review): if a newer notification (larger historyId)
    # happens to finish processing before an older, slower one, the older one's
    # later advance_watermark() call must not regress the watermark backward --
    # that would make already-handled mail look new again on the next notification.
    gi.advance_watermark('100')
    gi.advance_watermark('50')  # arrives "late" from an earlier, slower notification
    assert json.loads(gi.STATE_FILE.read_text())['last_history_id'] == '100'
    gi.advance_watermark('150')
    assert json.loads(gi.STATE_FILE.read_text())['last_history_id'] == '150'


def test_diff_handles_expired_history_gracefully(monkeypatch):
    class FailingUsers(FakeUsers):
        def list(self, **kwargs):
            resp = type('R', (), {'status': 404, 'reason': 'Not Found'})()
            raise HttpError(resp, b'not found')
    class FailingService:
        def users(self):
            return FailingUsers([], {})
    monkeypatch.setattr(gi, '_service', lambda: FailingService())
    assert gi.diff_new_message_ids('999') == []


def test_diff_reraises_non_404_errors(monkeypatch):
    class FailingUsers(FakeUsers):
        def list(self, **kwargs):
            resp = type('R', (), {'status': 500, 'reason': 'Server Error'})()
            raise HttpError(resp, b'server error')
    class FailingService:
        def users(self):
            return FailingUsers([], {})
    monkeypatch.setattr(gi, '_service', lambda: FailingService())
    with pytest.raises(HttpError):
        gi.diff_new_message_ids('999')


def test_push_endpoint_disabled_without_audience(client, monkeypatch):
    monkeypatch.delenv('GMAIL_PUSH_AUDIENCE', raising=False)
    assert client.post('/api/gmail/push', json={}).status_code == 503


def test_push_endpoint_disabled_without_service_account_email(client, monkeypatch):
    monkeypatch.setenv('GMAIL_PUSH_AUDIENCE', 'https://example.onrender.com/api/gmail/push')
    monkeypatch.delenv('GMAIL_PUSH_SERVICE_ACCOUNT_EMAIL', raising=False)
    monkeypatch.setattr(gi, 'configured', lambda: True)
    assert client.post('/api/gmail/push', json={}).status_code == 503


def test_push_endpoint_disabled_without_token_file(client, monkeypatch):
    _configure_push_env(monkeypatch)
    monkeypatch.setattr(gi, 'configured', lambda: False)
    assert client.post('/api/gmail/push', json={}).status_code == 503


def test_push_endpoint_rejects_missing_bearer_token(client, monkeypatch):
    _configure_push_env(monkeypatch)
    assert client.post('/api/gmail/push', json={}).status_code == 401


def test_push_endpoint_rejects_wrong_subject_token(client, monkeypatch):
    # This is exactly the bug that was caught in review: checking the Gmail-publish
    # identity (gmail-api-push@system.gserviceaccount.com) instead of the push
    # subscription's own configured auth identity. A token from the WRONG identity
    # -- including that publish-side one -- must still be rejected.
    _configure_push_env(monkeypatch)
    from google.oauth2 import id_token as google_id_token
    monkeypatch.setattr(google_id_token, 'verify_oauth2_token',
                         lambda *a, **k: {'email': 'gmail-api-push@system.gserviceaccount.com', 'email_verified': True})
    response = client.post('/api/gmail/push', json={}, headers={'Authorization': 'Bearer fake'})
    assert response.status_code == 401


def test_push_endpoint_does_not_require_app_header_or_hit_peer_limit(client, monkeypatch):
    # Regression: Pub/Sub push requests can't send X-Requested-With, and shouldn't
    # be gated by the browser-peer rate limiter either -- confirmed by calling
    # without HEADERS at all and getting past the app-header/peer-limit checks
    # (a 503/401 here means those checks were bypassed; a 403 would mean they weren't).
    monkeypatch.delenv('GMAIL_PUSH_AUDIENCE', raising=False)
    response = client.post('/api/gmail/push', json={})
    assert response.status_code == 503
    assert response.status_code != 403


def test_push_endpoint_processes_valid_notification_end_to_end(client, monkeypatch, tmp_path):
    monkeypatch.setattr(store, 'DATA', tmp_path)
    _configure_push_env(monkeypatch)
    _mock_valid_token(monkeypatch)
    raw = b'From: a@b.com\r\nTo: c@d.com\r\nSubject: watched mail\r\n\r\nbody text'
    monkeypatch.setattr(gi, 'diff_new_message_ids', lambda history_id: ['msg1'])
    monkeypatch.setattr(gi, 'fetch_raw', lambda message_id: raw)
    advanced = []
    monkeypatch.setattr(gi, 'advance_watermark', lambda history_id: advanced.append(history_id))
    payload = base64.b64encode(json.dumps({'emailAddress': 'a@b.com', 'historyId': '42'}).encode()).decode()
    response = client.post('/api/gmail/push', json={'message': {'data': payload}}, headers={'Authorization': 'Bearer fake'})
    assert response.status_code == 200
    body = response.json()
    assert body['processed'] == 1
    assert advanced == ['42']  # watermark only advanced after processing was attempted
    sid = gi.session_sid()
    cases = store.all_cases(sid)
    assert len(cases) == 1 and cases[0]['subject'] == 'watched mail'


def test_push_endpoint_advances_watermark_even_when_a_message_fails_to_store(client, monkeypatch, tmp_path):
    # A per-message processing failure (e.g. session case-cap, rate limit) must not
    # crash the whole notification or leave the watermark stuck -- but this does mean
    # that specific message won't be retried, a known, documented tradeoff (see
    # diff_new_message_ids's docstring) rather than building a full dead-letter queue.
    monkeypatch.setattr(store, 'DATA', tmp_path)
    _configure_push_env(monkeypatch)
    _mock_valid_token(monkeypatch)
    monkeypatch.setattr(gi, 'diff_new_message_ids', lambda history_id: ['msg1'])
    def boom(message_id):
        from fastapi import HTTPException
        raise HTTPException(400, 'simulated failure')
    monkeypatch.setattr(gi, 'fetch_raw', boom)
    advanced = []
    monkeypatch.setattr(gi, 'advance_watermark', lambda history_id: advanced.append(history_id))
    payload = base64.b64encode(json.dumps({'emailAddress': 'a@b.com', 'historyId': '43'}).encode()).decode()
    response = client.post('/api/gmail/push', json={'message': {'data': payload}}, headers={'Authorization': 'Bearer fake'})
    assert response.status_code == 200
    assert response.json()['processed'] == 0
    assert advanced == ['43']


def test_push_endpoint_rejects_malformed_envelope(client, monkeypatch):
    _configure_push_env(monkeypatch)
    _mock_valid_token(monkeypatch)
    response = client.post('/api/gmail/push', json={'not': 'a real envelope'}, headers={'Authorization': 'Bearer fake'})
    assert response.status_code == 400


def test_gmail_cases_endpoints_disabled_without_read_token(client, monkeypatch):
    # Fail closed: unlike every other case-viewing endpoint, these have no
    # per-caller session to isolate against, so an unset read token must deny
    # access entirely, not default to open.
    monkeypatch.delenv('GMAIL_CASES_READ_TOKEN', raising=False)
    assert client.get('/api/gmail/cases').status_code == 503
    assert client.get('/api/gmail/cases/anything').status_code == 503


def test_gmail_cases_endpoints_reject_missing_or_wrong_read_token(client, monkeypatch):
    monkeypatch.setenv('GMAIL_CASES_READ_TOKEN', 'the-real-token')
    assert client.get('/api/gmail/cases').status_code == 401
    assert client.get('/api/gmail/cases', headers={'Authorization': 'Bearer wrong'}).status_code == 401


def test_gmail_cases_lists_push_triggered_cases_regardless_of_caller_session(client, monkeypatch, tmp_path):
    # Regression: gmail-push cases live under a dedicated session, not whatever
    # session cookie a browser happens to send -- /api/cases (session-scoped)
    # would never show them, so this dedicated read path is the only way to
    # actually see what the automated pipeline found.
    monkeypatch.setattr(store, 'DATA', tmp_path)
    _configure_push_env(monkeypatch)
    _mock_valid_token(monkeypatch)
    monkeypatch.setenv('GMAIL_CASES_READ_TOKEN', 'the-real-token')
    read_headers = {'Authorization': 'Bearer the-real-token'}
    monkeypatch.setattr(gi, 'diff_new_message_ids', lambda history_id: ['msg1'])
    monkeypatch.setattr(gi, 'fetch_raw', lambda message_id: b'From: a@b.com\r\nTo: c@d.com\r\nSubject: watched mail\r\n\r\nbody')
    monkeypatch.setattr(gi, 'advance_watermark', lambda history_id: None)
    payload = base64.b64encode(json.dumps({'emailAddress': 'a@b.com', 'historyId': '42'}).encode()).decode()
    client.post('/api/gmail/push', json={'message': {'data': payload}}, headers={'Authorization': 'Bearer fake'})
    listed = client.get('/api/gmail/cases', headers=read_headers).json()
    assert len(listed) == 1 and listed[0]['subject'] == 'watched mail'
    detail = client.get(f"/api/gmail/cases/{listed[0]['id']}", headers=read_headers)
    assert detail.status_code == 200 and detail.json()['subject'] == 'watched mail'
    assert client.get('/api/gmail/cases/does-not-exist', headers=read_headers).status_code == 404


def test_diff_new_message_ids_catches_label_added_records_too(monkeypatch):
    # Regression: watching only 'messageAdded' silently missed real messages --
    # Gmail can report a message reaching INBOX via a separate 'labelAdded'
    # history record instead (e.g. if the label is applied after a filter runs),
    # which the previous version never checked.
    records = [{'labelsAdded': [{'message': {'id': 'msg1'}, 'labelIds': ['INBOX', 'UNREAD']}]}]
    monkeypatch.setattr(gi, '_service', lambda: FakeService(records, {}))
    assert gi.diff_new_message_ids('999') == ['msg1']


def test_diff_new_message_ids_ignores_label_added_for_other_labels(monkeypatch):
    records = [{'labelsAdded': [{'message': {'id': 'msg1'}, 'labelIds': ['IMPORTANT']}]}]
    monkeypatch.setattr(gi, '_service', lambda: FakeService(records, {}))
    assert gi.diff_new_message_ids('999') == []


def test_diff_new_message_ids_dedupes_message_reported_both_ways(monkeypatch):
    records = [{
        'messagesAdded': [{'message': {'id': 'msg1'}}],
        'labelsAdded': [{'message': {'id': 'msg1'}, 'labelIds': ['INBOX']}],
    }]
    monkeypatch.setattr(gi, '_service', lambda: FakeService(records, {}))
    assert gi.diff_new_message_ids('999') == ['msg1']


def test_gmail_watch_start_endpoint_disabled_without_topic(client, monkeypatch):
    monkeypatch.setenv('GMAIL_WATCH_ADMIN_TOKEN', 'the-admin-token')
    monkeypatch.delenv('GMAIL_PUBSUB_TOPIC', raising=False)
    response = client.post('/api/gmail/watch/start', headers={**HEADERS, 'Authorization': 'Bearer the-admin-token'})
    assert response.status_code == 503


def test_gmail_watch_start_endpoint_requires_admin_token(client, monkeypatch):
    monkeypatch.setenv('GMAIL_PUBSUB_TOPIC', 'projects/p/topics/t')
    monkeypatch.setenv('GMAIL_WATCH_ADMIN_TOKEN', 'the-admin-token')
    assert client.post('/api/gmail/watch/start', headers=HEADERS).status_code == 401


def test_gmail_watch_start_endpoint_rejects_the_read_only_cases_token(client, monkeypatch):
    # Regression: the watch/start endpoint mutates state (resets last_history_id
    # to "now"), so the separate read-only GMAIL_CASES_READ_TOKEN must not also
    # work here -- confirmed in review that reusing one token for both would let
    # a read-only credential holder cause unprocessed mail to be silently skipped.
    monkeypatch.setenv('GMAIL_PUBSUB_TOPIC', 'projects/p/topics/t')
    monkeypatch.setenv('GMAIL_WATCH_ADMIN_TOKEN', 'the-admin-token')
    monkeypatch.setenv('GMAIL_CASES_READ_TOKEN', 'the-read-token')
    response = client.post('/api/gmail/watch/start', headers={**HEADERS, 'Authorization': 'Bearer the-read-token'})
    assert response.status_code == 401


def test_gmail_watch_start_endpoint_registers_watch_on_this_instance(client, monkeypatch):
    # This is the actual fix: gmail_watch_start.py (the CLI script) only ever
    # writes to whoever's own local machine's state file. Running it against a
    # deployed instance's Gmail account does nothing for THAT instance's own
    # watermark -- this endpoint is what actually seeds it correctly, by running
    # start_watch() in the same process/filesystem the push handler itself reads.
    monkeypatch.setenv('GMAIL_PUBSUB_TOPIC', 'projects/p/topics/t')
    monkeypatch.setenv('GMAIL_WATCH_ADMIN_TOKEN', 'the-admin-token')
    monkeypatch.setattr(gi, 'configured', lambda: True)
    monkeypatch.setattr(gi, 'start_watch', lambda topic: {'historyId': '123', 'expiration': '999'})
    response = client.post('/api/gmail/watch/start', headers={**HEADERS, 'Authorization': 'Bearer the-admin-token'})
    assert response.status_code == 200
    assert response.json() == {'historyId': '123', 'expiration': '999'}

import base64
import json
import logging
from pathlib import Path

import pytest
from fastapi import HTTPException
from googleapiclient.errors import HttpError

import gmail_integration as gi
import main
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


def test_start_watch_uses_explicit_inbox_include_filter(monkeypatch):
    calls = []
    class FakeWatch:
        def execute(self):
            return {'historyId': '123', 'expiration': '999'}
    class WatchUsers:
        def watch(self, **kwargs):
            calls.append(kwargs)
            return FakeWatch()
    class WatchService:
        def users(self):
            return WatchUsers()
    monkeypatch.setattr(gi, '_service', lambda: WatchService())

    assert gi.start_watch('projects/p/topics/t') == {'historyId': '123', 'expiration': '999'}
    assert calls == [{
        'userId': 'me',
        'body': {
            'topicName': 'projects/p/topics/t',
            'labelIds': ['INBOX'],
            'labelFilterBehavior': 'INCLUDE',
        },
    }]


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


def test_diff_retries_empty_result_and_succeeds_once_gmail_catches_up(monkeypatch):
    # Real, documented race condition: Gmail's Pub/Sub push can arrive before
    # the triggering message is actually queryable via history.list() --
    # confirmed live (a real test email was silently lost this exact way).
    # Simulates Gmail's indexing lag resolving on the second call.
    calls = []
    class FlakyUsers(FakeUsers):
        def list(self, **kwargs):
            calls.append(1)
            records = [] if len(calls) == 1 else [{'messagesAdded': [{'message': {'id': 'msg1'}}]}]
            return FakeHistoryList(records)
    class FlakyService:
        def users(self):
            return FlakyUsers([], {})
    monkeypatch.setattr(gi, '_service', lambda: FlakyService())
    slept = []
    ids = gi.diff_new_message_ids('999', sleep=slept.append)
    assert ids == ['msg1']
    assert len(calls) == 2  # first attempt empty, second attempt found it
    assert slept == [gi._DIFF_RETRY_DELAY_SECONDS]  # slept exactly once, between the two attempts


def test_diff_gives_up_after_max_retries_on_persistent_empty_result(monkeypatch):
    calls = []
    class AlwaysEmptyUsers(FakeUsers):
        def list(self, **kwargs):
            calls.append(1)
            return FakeHistoryList([])
    class AlwaysEmptyService:
        def users(self):
            return AlwaysEmptyUsers([], {})
    monkeypatch.setattr(gi, '_service', lambda: AlwaysEmptyService())
    slept = []
    ids = gi.diff_new_message_ids('999', sleep=slept.append)
    assert ids == []
    assert len(calls) == gi._DIFF_RETRY_ATTEMPTS + 1  # final call is the unfiltered probe
    assert len(slept) == gi._DIFF_RETRY_ATTEMPTS - 1  # sleeps only BETWEEN attempts, not after the last one


def test_diff_defers_when_newer_history_window_is_not_queryable_after_retries(monkeypatch):
    # Stronger regression for the Gmail indexing-lag race: if our stored
    # watermark is older than the notification but Gmail still returns no
    # filtered OR unfiltered history after retries, advancing would make a real
    # message permanently disappear. Let Pub/Sub retry the notification later.
    gi.advance_watermark('900')
    calls = []
    class EmptyUsers(FakeUsers):
        def list(self, **kwargs):
            calls.append(kwargs)
            return FakeHistoryList([])
    class EmptyService:
        def users(self):
            return EmptyUsers([], {})
    monkeypatch.setattr(gi, '_service', lambda: EmptyService())
    slept = []

    with pytest.raises(gi.EmptyHistoryDiff):
        gi.diff_new_message_ids('999', sleep=slept.append)

    assert len([c for c in calls if c.get('historyTypes') == ['messageAdded', 'labelAdded']]) == gi._DIFF_RETRY_ATTEMPTS
    assert len([c for c in calls if 'historyTypes' not in c]) == 1  # final unfiltered probe
    assert slept == [gi._DIFF_RETRY_DELAY_SECONDS, gi._DIFF_RETRY_DELAY_SECONDS]


def test_diff_accepts_empty_new_message_diff_when_unfiltered_history_exists(monkeypatch):
    # Not every INBOX-related push is a new message. If an unfiltered history
    # probe sees some other history record, the empty add-message diff is not
    # the "Gmail notified before indexing anything" race and can be acked.
    gi.advance_watermark('900')
    calls = []
    class NonAddUsers(FakeUsers):
        def list(self, **kwargs):
            calls.append(kwargs)
            if 'historyTypes' in kwargs:
                return FakeHistoryList([])
            return FakeHistoryList([{'labelsRemoved': [{'message': {'id': 'msg1'}, 'labelIds': ['UNREAD']}]}])
    class NonAddService:
        def users(self):
            return NonAddUsers([], {})
    monkeypatch.setattr(gi, '_service', lambda: NonAddService())

    assert gi.diff_new_message_ids('999', sleep=lambda seconds: None) == []
    assert len([c for c in calls if 'historyTypes' not in c]) == 1


def test_diff_never_retries_a_404_since_it_can_never_recover(monkeypatch):
    # Retrying a too-old startHistoryId is pointless -- the same input always
    # 404s again -- and was a real bug in an early version of this retry
    # logic: it wasted ~4 real seconds retrying an unrecoverable 404 both in
    # production and in test_diff_handles_expired_history_gracefully above.
    calls = []
    class FailingUsers(FakeUsers):
        def list(self, **kwargs):
            calls.append(1)
            resp = type('R', (), {'status': 404, 'reason': 'Not Found'})()
            raise HttpError(resp, b'not found')
    class FailingService:
        def users(self):
            return FailingUsers([], {})
    monkeypatch.setattr(gi, '_service', lambda: FailingService())
    slept = []
    assert gi.diff_new_message_ids('999', sleep=slept.append) == []
    assert len(calls) == 1  # no retry attempted
    assert slept == []


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


def test_claim_processed_only_the_first_caller_succeeds():
    assert gi.claim_processed('msg1') is True
    assert gi.claim_processed('msg1') is False  # already claimed
    assert gi.claim_processed('msg2') is True  # a different id is unaffected


def test_unclaim_processed_allows_a_fresh_claim():
    assert gi.claim_processed('msg1') is True
    gi.unclaim_processed('msg1')
    assert gi.claim_processed('msg1') is True  # not permanently "done" anymore


def test_unclaim_processed_is_a_noop_for_an_unclaimed_id():
    gi.unclaim_processed('never-claimed')  # must not raise
    assert gi.claim_processed('never-claimed') is True


def test_unclaim_processed_does_not_affect_other_claimed_ids():
    gi.claim_processed('keep-me')
    gi.claim_processed('drop-me')
    gi.unclaim_processed('drop-me')
    assert gi.claim_processed('keep-me') is False  # still claimed
    assert gi.claim_processed('drop-me') is True  # claimable again


def test_claim_processed_is_bounded_fifo(monkeypatch):
    monkeypatch.setattr(gi, '_MAX_PROCESSED_IDS', 3)
    for mid in ['a', 'b', 'c', 'd']:
        gi.claim_processed(mid)
    # oldest ('a') evicted once the bound is exceeded -- claimable again
    assert gi.claim_processed('a') is True
    assert gi.claim_processed('d') is False


def test_claim_processed_is_race_safe_under_true_concurrency():
    # Regression: check-then-act (a separate already_processed() check followed
    # later by mark_processed()) left a race window where two concurrent
    # Pub/Sub deliveries for the same message could both pass the check before
    # either marked it. claim_processed() must be a single atomic operation --
    # verified here with real concurrent threads, not just sequential calls.
    import threading
    results = []
    barrier = threading.Barrier(8)
    def attempt():
        barrier.wait()  # maximize actual overlap, not just interleaving
        results.append(gi.claim_processed('contested-id'))
    threads = [threading.Thread(target=attempt) for _ in range(8)]
    for t in threads: t.start()
    for t in threads: t.join()
    assert results.count(True) == 1  # exactly one winner, no matter the race


def test_push_endpoint_skips_a_message_id_seen_in_an_earlier_notification(client, monkeypatch, tmp_path):
    # Regression: confirmed live -- the same email was stored as two separate
    # cases (identical SHA-256) because Gmail reported it via a messageAdded
    # event in one notification and a labelAdded event in a later, separate
    # notification. diff_new_message_ids()'s own per-call dedup can't catch
    # this since each call only sees its own history window.
    monkeypatch.setattr(store, 'DATA', tmp_path)
    _configure_push_env(monkeypatch)
    _mock_valid_token(monkeypatch)
    raw = b'From: a@b.com\r\nTo: c@d.com\r\nSubject: watched mail\r\n\r\nbody'
    fetch_calls = []
    def fetch_raw(message_id):
        fetch_calls.append(message_id)
        return raw
    monkeypatch.setattr(gi, 'fetch_raw', fetch_raw)
    monkeypatch.setattr(gi, 'advance_watermark', lambda history_id: None)

    monkeypatch.setattr(gi, 'diff_new_message_ids', lambda history_id: ['msg1'])
    payload1 = base64.b64encode(json.dumps({'emailAddress': 'a@b.com', 'historyId': '10'}).encode()).decode()
    first = client.post('/api/gmail/push', json={'message': {'data': payload1}}, headers={'Authorization': 'Bearer fake'})
    assert first.status_code == 200 and first.json()['processed'] == 1

    # A later, separate notification reports the SAME message id again.
    monkeypatch.setattr(gi, 'diff_new_message_ids', lambda history_id: ['msg1'])
    payload2 = base64.b64encode(json.dumps({'emailAddress': 'a@b.com', 'historyId': '20'}).encode()).decode()
    second = client.post('/api/gmail/push', json={'message': {'data': payload2}}, headers={'Authorization': 'Bearer fake'})
    assert second.status_code == 200
    assert second.json()['processed'] == 0  # skipped, not reprocessed
    assert fetch_calls == ['msg1']  # only fetched once, across both notifications

    sid = gi.session_sid()
    assert len(store.all_cases(sid)) == 1  # exactly one case, not a duplicate


def test_push_endpoint_survives_a_gmail_api_error_on_one_message(client, monkeypatch, tmp_path):
    # Regression: fetch_raw() can raise googleapiclient's HttpError (a real
    # Gmail API failure, distinct from this app's own HTTPException) -- the
    # loop previously only caught HTTPException, so an HttpError would crash
    # the entire batch AND skip advance_watermark() entirely, potentially
    # reprocessing already-stored messages on the next notification.
    # 'bad-msg' fails with a persistent 500 on every attempt, so it still
    # exhausts all retries (see test_push_endpoint_retries_transient_gmail_api_error_then_succeeds
    # for the transient-then-recovers case) and ends up unclaimed with the
    # watermark still advancing -- the known, documented best-effort tradeoff.
    monkeypatch.setattr(store, 'DATA', tmp_path)
    _configure_push_env(monkeypatch)
    _mock_valid_token(monkeypatch)
    monkeypatch.setattr(gi, 'diff_new_message_ids', lambda history_id: ['bad-msg', 'good-msg'])
    monkeypatch.setattr(main, '_PUSH_RETRY_DELAY_SECONDS', 0)
    def fetch_raw(message_id):
        if message_id == 'bad-msg':
            resp = type('R', (), {'status': 500, 'reason': 'Server Error'})()
            raise HttpError(resp, b'boom')
        return b'From: a@b.com\r\nTo: c@d.com\r\nSubject: good one\r\n\r\nbody'
    monkeypatch.setattr(gi, 'fetch_raw', fetch_raw)
    advanced = []
    monkeypatch.setattr(gi, 'advance_watermark', lambda history_id: advanced.append(history_id))
    payload = base64.b64encode(json.dumps({'emailAddress': 'a@b.com', 'historyId': '77'}).encode()).decode()
    response = client.post('/api/gmail/push', json={'message': {'data': payload}}, headers={'Authorization': 'Bearer fake'})
    assert response.status_code == 200
    assert response.json()['processed'] == 1  # good-msg still made it through
    assert advanced == ['77']  # watermark still advances despite the mid-batch error


def test_push_endpoint_retries_transient_gmail_api_error_then_succeeds(client, monkeypatch, tmp_path):
    # Regression: a transient Gmail-side error (5xx/quota) on fetch_raw() previously
    # got zero retries at the notification level -- unlike our own 429s -- so a
    # one-off Gmail API blip could permanently drop a perfectly good message. Now
    # retried the same way, up to _PUSH_MAX_ATTEMPTS.
    monkeypatch.setattr(store, 'DATA', tmp_path)
    _configure_push_env(monkeypatch)
    _mock_valid_token(monkeypatch)
    monkeypatch.setattr(gi, 'diff_new_message_ids', lambda history_id: ['flaky-msg'])
    monkeypatch.setattr(main, '_PUSH_RETRY_DELAY_SECONDS', 0)
    attempts = {'n': 0}
    def flaky_fetch_raw(message_id):
        attempts['n'] += 1
        if attempts['n'] < 2:
            resp = type('R', (), {'status': 503, 'reason': 'Service Unavailable'})()
            raise HttpError(resp, b'temporarily unavailable')
        return b'From: a@b.com\r\nTo: c@d.com\r\nSubject: recovered\r\n\r\nbody'
    monkeypatch.setattr(gi, 'fetch_raw', flaky_fetch_raw)
    payload = base64.b64encode(json.dumps({'emailAddress': 'a@b.com', 'historyId': '78'}).encode()).decode()
    response = client.post('/api/gmail/push', json={'message': {'data': payload}}, headers={'Authorization': 'Bearer fake'})
    assert response.status_code == 200
    assert response.json()['processed'] == 1
    assert attempts['n'] == 2


def test_push_endpoint_never_retries_a_permanent_gmail_api_error(client, monkeypatch, tmp_path):
    # A 404 (message deleted before fetch) or other non-5xx/429 Gmail error will
    # never succeed on retry -- must not waste attempts (or real wall-clock time)
    # on it, matching the same "don't retry the unrecoverable" principle already
    # applied to a 404 in diff_new_message_ids/_list_new_message_ids.
    monkeypatch.setattr(store, 'DATA', tmp_path)
    _configure_push_env(monkeypatch)
    _mock_valid_token(monkeypatch)
    monkeypatch.setattr(gi, 'diff_new_message_ids', lambda history_id: ['gone-msg'])
    monkeypatch.setattr(main, '_PUSH_RETRY_DELAY_SECONDS', 0)
    calls = {'n': 0}
    def fetch_raw(message_id):
        calls['n'] += 1
        resp = type('R', (), {'status': 404, 'reason': 'Not Found'})()
        raise HttpError(resp, b'message not found')
    monkeypatch.setattr(gi, 'fetch_raw', fetch_raw)
    payload = base64.b64encode(json.dumps({'emailAddress': 'a@b.com', 'historyId': '79'}).encode()).decode()
    response = client.post('/api/gmail/push', json={'message': {'data': payload}}, headers={'Authorization': 'Bearer fake'})
    assert response.status_code == 200
    assert response.json()['processed'] == 0
    assert calls['n'] == 1  # no retry attempted


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


def test_push_endpoint_logs_successful_notification_steps(client, monkeypatch, tmp_path, caplog):
    monkeypatch.setattr(store, 'DATA', tmp_path)
    _configure_push_env(monkeypatch)
    _mock_valid_token(monkeypatch)
    raw = b'From: a@b.com\r\nTo: c@d.com\r\nSubject: logged mail\r\n\r\nbody text'
    monkeypatch.setattr(gi, 'diff_new_message_ids', lambda history_id: ['msg-log'])
    monkeypatch.setattr(gi, 'fetch_raw', lambda message_id: raw)
    monkeypatch.setattr(gi, 'advance_watermark', lambda history_id: None)
    caplog.set_level(logging.INFO, logger='gmail_push')

    payload = base64.b64encode(json.dumps({'emailAddress': 'a@b.com', 'historyId': '4242'}).encode()).decode()
    response = client.post(
        '/api/gmail/push',
        json={'message': {'data': payload, 'messageId': 'pubsub-1'}},
        headers={'Authorization': 'Bearer fake'},
    )

    assert response.status_code == 200
    logs = caplog.text
    assert 'Gmail push OIDC verified' in logs
    assert 'Gmail push envelope parsed: historyId=4242 emailAddress=a@b.com pubsubMessageId=pubsub-1' in logs
    assert "Gmail push diff complete: historyId=4242 message_count=1 message_ids=['msg-log']" in logs
    assert 'Gmail push message claimed: historyId=4242 messageId=msg-log' in logs
    assert 'Gmail push message fetched: historyId=4242 messageId=msg-log bytes=' in logs
    assert 'Gmail push message analyzed: historyId=4242 messageId=msg-log caseId=' in logs
    assert 'Gmail push watermark advanced: historyId=4242 processed=1 skipped=0 failed=0 total=1' in logs
    assert 'Gmail push notification complete: historyId=4242 processed=1 skipped=0 failed=0' in logs


def test_push_endpoint_advances_watermark_even_when_a_message_fails_to_store(client, monkeypatch, tmp_path):
    # A per-message processing failure (e.g. a malformed/oversized email --
    # a non-429 HTTPException, so not retried) must not crash the whole
    # notification or leave the watermark stuck. The watermark still moving
    # past this notification's historyId means a message that fails for a
    # genuinely non-retryable reason still won't be picked up by a LATER,
    # separate notification -- a known, documented tradeoff (see
    # unclaim_processed()'s docstring) rather than a full dead-letter queue.
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
    assert gi.claim_processed('msg1')  # unclaimed on failure -- a fresh claim succeeds


def test_push_endpoint_retries_busy_analysis_slot_then_succeeds(client, monkeypatch, tmp_path):
    # Regression for the confirmed "permanently lost message" bug: claim_processed()
    # marks a message done BEFORE fetch/execute, so a transient 429 (this instance's
    # own analysis-slot semaphore or per-session rate limit momentarily saturated --
    # nothing wrong with the email itself) used to permanently drop it with no retry.
    monkeypatch.setattr(store, 'DATA', tmp_path)
    _configure_push_env(monkeypatch)
    _mock_valid_token(monkeypatch)
    raw = b'From: a@b.com\r\nTo: c@d.com\r\nSubject: retried mail\r\n\r\nbody text'
    monkeypatch.setattr(gi, 'diff_new_message_ids', lambda history_id: ['msg-retry'])
    monkeypatch.setattr(gi, 'fetch_raw', lambda message_id: raw)
    monkeypatch.setattr(main, '_PUSH_RETRY_DELAY_SECONDS', 0)
    attempts = {'n': 0}
    real_execute = main.execute
    def flaky_execute(*args, **kwargs):
        attempts['n'] += 1
        if attempts['n'] < 3:
            raise HTTPException(429, 'Analysis workers busy. Please retry shortly.')
        return real_execute(*args, **kwargs)
    monkeypatch.setattr(main, 'execute', flaky_execute)
    payload = base64.b64encode(json.dumps({'emailAddress': 'a@b.com', 'historyId': '99'}).encode()).decode()
    response = client.post('/api/gmail/push', json={'message': {'data': payload}}, headers={'Authorization': 'Bearer fake'})
    assert response.status_code == 200
    assert response.json()['processed'] == 1
    assert attempts['n'] == 3


def test_push_endpoint_defers_empty_history_diff_without_advancing_watermark(client, monkeypatch, tmp_path):
    monkeypatch.setattr(store, 'DATA', tmp_path)
    _configure_push_env(monkeypatch)
    _mock_valid_token(monkeypatch)
    advanced = []
    def not_queryable(history_id):
        raise gi.EmptyHistoryDiff('Gmail history not queryable yet')
    monkeypatch.setattr(gi, 'diff_new_message_ids', not_queryable)
    monkeypatch.setattr(gi, 'advance_watermark', lambda history_id: advanced.append(history_id))

    payload = base64.b64encode(json.dumps({'emailAddress': 'a@b.com', 'historyId': '999'}).encode()).decode()
    response = client.post('/api/gmail/push', json={'message': {'data': payload}}, headers={'Authorization': 'Bearer fake'})

    assert response.status_code == 503
    assert advanced == []


def test_push_endpoint_unclaims_after_exhausting_retries_on_persistent_429(client, monkeypatch, tmp_path):
    monkeypatch.setattr(store, 'DATA', tmp_path)
    _configure_push_env(monkeypatch)
    _mock_valid_token(monkeypatch)
    monkeypatch.setattr(gi, 'diff_new_message_ids', lambda history_id: ['msg-stuck'])
    monkeypatch.setattr(gi, 'fetch_raw', lambda message_id: b'From: a@b.com\r\nTo: c@d.com\r\nSubject: s\r\n\r\nb')
    monkeypatch.setattr(main, '_PUSH_RETRY_DELAY_SECONDS', 0)
    def always_busy(*args, **kwargs):
        raise HTTPException(429, 'Analysis workers busy. Please retry shortly.')
    monkeypatch.setattr(main, 'execute', always_busy)
    payload = base64.b64encode(json.dumps({'emailAddress': 'a@b.com', 'historyId': '100'}).encode()).decode()
    response = client.post('/api/gmail/push', json={'message': {'data': payload}}, headers={'Authorization': 'Bearer fake'})
    assert response.status_code == 200
    assert response.json()['processed'] == 0
    assert gi.claim_processed('msg-stuck')  # unclaimed -- a fresh claim succeeds, not "already claimed"


def test_push_endpoint_rejects_malformed_envelope(client, monkeypatch):
    _configure_push_env(monkeypatch)
    _mock_valid_token(monkeypatch)
    response = client.post('/api/gmail/push', json={'not': 'a real envelope'}, headers={'Authorization': 'Bearer fake'})
    assert response.status_code == 400


def test_push_endpoint_rejects_malformed_base64_envelope(client, monkeypatch, caplog):
    _configure_push_env(monkeypatch)
    _mock_valid_token(monkeypatch)
    caplog.set_level(logging.WARNING, logger='gmail_push')
    response = client.post(
        '/api/gmail/push',
        json={'message': {'data': 'not valid base64!!!'}},
        headers={'Authorization': 'Bearer fake'},
    )
    assert response.status_code == 400
    assert 'Gmail push rejected: malformed Pub/Sub envelope' in caplog.text


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
    # Genuinely, permanently empty for this input (not a transient indexing
    # race) -- a real sleep would just make this test slow for no reason.
    assert gi.diff_new_message_ids('999', sleep=lambda seconds: None) == []


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


# --- Dead-letter retry queue (closes the transient-failure loss window) ---

def test_dead_letter_record_pending_and_clear():
    assert gi.pending_retry_message_ids() == []
    gi.record_failed_message('m1')
    gi.record_failed_message('m2')
    assert set(gi.pending_retry_message_ids()) == {'m1', 'm2'}
    gi.clear_failed_message('m1')
    assert gi.pending_retry_message_ids() == ['m2']
    gi.clear_failed_message('never-there')  # must not raise
    assert gi.pending_retry_message_ids() == ['m2']


def test_dead_letter_queue_is_bounded(monkeypatch):
    monkeypatch.setattr(gi, '_MAX_PENDING_RETRY_IDS', 3)
    for mid in ['a', 'b', 'c', 'd']:
        gi.record_failed_message(mid)
    ids = gi.pending_retry_message_ids()
    assert len(ids) == 3 and 'a' not in ids  # oldest evicted once the bound is exceeded


def test_dead_letter_queue_gives_up_after_attempt_cap(monkeypatch):
    monkeypatch.setattr(gi, '_MAX_RETRY_ATTEMPTS', 3)
    for _ in range(3):
        gi.record_failed_message('stuck')  # attempts -> 1, 2, 3
    assert gi.pending_retry_message_ids() == []  # attempts (3) >= cap: no longer eligible
    assert gi.drain_exhausted_retries() == ['stuck']
    assert gi.drain_exhausted_retries() == []  # already drained


def test_push_dead_letters_transient_failure_and_recovers_on_next_notification(client, monkeypatch, tmp_path):
    # The core fix: a message whose in-request retries are all exhausted for a
    # TRANSIENT reason must not be lost when the watermark advances past it -- it
    # is dead-lettered and retried on a later notification.
    monkeypatch.setattr(store, 'DATA', tmp_path)
    _configure_push_env(monkeypatch)
    _mock_valid_token(monkeypatch)
    monkeypatch.setattr(main, '_PUSH_RETRY_DELAY_SECONDS', 0)
    monkeypatch.setattr(gi, 'advance_watermark', lambda history_id: None)
    fail = {'on': True}
    def fetch_raw(message_id):
        if fail['on']:
            resp = type('R', (), {'status': 503, 'reason': 'Service Unavailable'})()
            raise HttpError(resp, b'temporarily down')
        return b'From: a@b.com\r\nTo: c@d.com\r\nSubject: recovered later\r\n\r\nbody'
    monkeypatch.setattr(gi, 'fetch_raw', fetch_raw)

    monkeypatch.setattr(gi, 'diff_new_message_ids', lambda history_id: ['flaky'])
    payload1 = base64.b64encode(json.dumps({'emailAddress': 'a@b.com', 'historyId': '10'}).encode()).decode()
    first = client.post('/api/gmail/push', json={'message': {'data': payload1}}, headers={'Authorization': 'Bearer fake'})
    assert first.status_code == 200 and first.json()['processed'] == 0
    assert gi.pending_retry_message_ids() == ['flaky']  # durably queued, not lost

    fail['on'] = False
    monkeypatch.setattr(gi, 'diff_new_message_ids', lambda history_id: [])  # nothing new this time
    payload2 = base64.b64encode(json.dumps({'emailAddress': 'a@b.com', 'historyId': '20'}).encode()).decode()
    second = client.post('/api/gmail/push', json={'message': {'data': payload2}}, headers={'Authorization': 'Bearer fake'})
    assert second.status_code == 200 and second.json()['processed'] == 1  # recovered from the dead-letter queue
    assert gi.pending_retry_message_ids() == []  # cleared after success
    assert len(store.all_cases(gi.session_sid())) == 1


def test_push_does_not_dead_letter_a_permanent_failure(client, monkeypatch, tmp_path):
    # A permanent Gmail error (404 deleted) can never succeed on retry, so it must
    # NOT be queued -- otherwise the queue would churn on it until the attempt cap.
    monkeypatch.setattr(store, 'DATA', tmp_path)
    _configure_push_env(monkeypatch)
    _mock_valid_token(monkeypatch)
    monkeypatch.setattr(main, '_PUSH_RETRY_DELAY_SECONDS', 0)
    monkeypatch.setattr(gi, 'advance_watermark', lambda history_id: None)
    monkeypatch.setattr(gi, 'diff_new_message_ids', lambda history_id: ['gone'])
    def fetch_raw(message_id):
        resp = type('R', (), {'status': 404, 'reason': 'Not Found'})()
        raise HttpError(resp, b'deleted')
    monkeypatch.setattr(gi, 'fetch_raw', fetch_raw)
    payload = base64.b64encode(json.dumps({'emailAddress': 'a@b.com', 'historyId': '30'}).encode()).decode()
    resp = client.post('/api/gmail/push', json={'message': {'data': payload}}, headers={'Authorization': 'Bearer fake'})
    assert resp.status_code == 200 and resp.json()['processed'] == 0
    assert gi.pending_retry_message_ids() == []  # permanent failure is not retried


def test_push_dead_letter_retry_does_not_double_process_same_push_ids(client, monkeypatch, tmp_path):
    # A message failing transiently in this notification's own diff must not also
    # be re-attempted by the dead-letter pass in the SAME request.
    monkeypatch.setattr(store, 'DATA', tmp_path)
    _configure_push_env(monkeypatch)
    _mock_valid_token(monkeypatch)
    monkeypatch.setattr(main, '_PUSH_RETRY_DELAY_SECONDS', 0)
    monkeypatch.setattr(gi, 'advance_watermark', lambda history_id: None)
    monkeypatch.setattr(gi, 'diff_new_message_ids', lambda history_id: ['msg-x'])
    calls = {'n': 0}
    def fetch_raw(message_id):
        calls['n'] += 1
        resp = type('R', (), {'status': 503, 'reason': 'Service Unavailable'})()
        raise HttpError(resp, b'down')
    monkeypatch.setattr(gi, 'fetch_raw', fetch_raw)
    payload = base64.b64encode(json.dumps({'emailAddress': 'a@b.com', 'historyId': '40'}).encode()).decode()
    resp = client.post('/api/gmail/push', json={'message': {'data': payload}}, headers={'Authorization': 'Bearer fake'})
    assert resp.status_code == 200 and resp.json()['processed'] == 0
    assert calls['n'] == main._PUSH_MAX_ATTEMPTS  # exactly the in-request retries, no extra same-request dead-letter attempt
    assert gi.pending_retry_message_ids() == ['msg-x']  # queued for a FUTURE notification


def test_gmail_403_rate_limit_is_transient_but_other_403_is_permanent():
    # Regression (review): Gmail returns quota/rate-limit errors as HTTP 403 with
    # reason rateLimitExceeded/userRateLimitExceeded and documents them as
    # retryable -- classifying every 403 as permanent would silently drop a merely
    # rate-limited message. A genuinely permanent 403 (domainPolicy) and a 404
    # must still be permanent.
    def err(status, body):
        resp = type('R', (), {'status': status, 'reason': 'x'})()
        return HttpError(resp, body)
    assert main._gmail_httperror_is_transient(429, err(429, b'')) is True
    assert main._gmail_httperror_is_transient(503, err(503, b'')) is True
    assert main._gmail_httperror_is_transient(403, err(403, b'{"error":{"errors":[{"reason":"rateLimitExceeded"}]}}')) is True
    assert main._gmail_httperror_is_transient(403, err(403, b'{"error":{"errors":[{"reason":"userRateLimitExceeded"}]}}')) is True
    assert main._gmail_httperror_is_transient(403, err(403, b'{"error":{"errors":[{"reason":"domainPolicy"}]}}')) is False
    assert main._gmail_httperror_is_transient(404, err(404, b'')) is False
    assert main._gmail_httperror_is_transient(None, err(0, b'')) is False

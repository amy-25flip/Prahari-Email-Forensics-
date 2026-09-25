import base64
import json

import pytest
from googleapiclient.errors import HttpError

import gmail_actions as ga
import gmail_integration as gi
import store
from test_gmail_integration import _configure_push_env, _mock_valid_token, isolate_state  # noqa: F401  (autouse fixture)
from test_selection import client

URGENT = {'triage': {'priority': 'urgent'}, 'score': 80, 'id': 'c1'}
REVIEW = {'triage': {'priority': 'review'}, 'score': 30, 'id': 'c2'}
ROUTINE = {'triage': {'priority': 'routine'}, 'score': 5, 'id': 'c3'}


class FakeGmail:
    """Records calls like the real discovery client: service.users().labels()/messages().<verb>(...).execute()."""
    def __init__(self, existing=(), fail_modify=None):
        self.label_store, self.calls, self.fail_modify, self.next = [{'id': f'L{i}', 'name': n} for i, n in enumerate(existing)], [], fail_modify, 100

    def users(self): return self
    def labels(self): return _Labels(self)
    def messages(self): return _Messages(self)


class _Exec:
    def __init__(self, fn): self.fn = fn
    def execute(self): return self.fn()


class _Labels:
    def __init__(self, g): self.g = g
    def list(self, userId): return _Exec(lambda: {'labels': list(self.g.label_store)})
    def create(self, userId, body):
        def go():
            self.g.next += 1
            label = {'id': f'L{self.g.next}', 'name': body['name']}
            self.g.label_store.append(label); self.g.calls.append(('create_label', body['name'])); return label
        return _Exec(go)


class _Messages:
    def __init__(self, g): self.g = g
    def modify(self, userId, id, body):
        def go():
            if self.g.fail_modify: raise self.g.fail_modify
            self.g.calls.append(('modify', id, body)); return {'id': id}
        return _Exec(go)


@pytest.fixture(autouse=True)
def clean(monkeypatch):
    ga._label_cache.clear()
    monkeypatch.delenv('GMAIL_ACTION_MODE', raising=False)
    monkeypatch.delenv('GMAIL_ACTION_MIN_SCORE', raising=False)


def test_default_and_invalid_modes_do_nothing(monkeypatch):
    assert ga.mode() == 'off' and ga.apply('m1', URGENT, FakeGmail()) is None
    monkeypatch.setenv('GMAIL_ACTION_MODE', 'DELETE-EVERYTHING')
    assert ga.mode() == 'off' and ga.apply('m1', URGENT, FakeGmail()) is None
    monkeypatch.setenv('GMAIL_ACTION_MODE', ' Quarantine ')
    assert ga.mode() == 'quarantine'


def test_plan_by_triage_and_score(monkeypatch):
    assert ga.plan(URGENT, 'label') == {'labels': [ga.LABEL_HIGH], 'remove_from_inbox': False}
    assert ga.plan(URGENT, 'quarantine') == {'labels': [ga.LABEL_HIGH], 'remove_from_inbox': True}
    assert ga.plan(REVIEW, 'quarantine') == {'labels': [ga.LABEL_REVIEW], 'remove_from_inbox': False}     # review is never removed from the inbox
    assert ga.plan(ROUTINE, 'quarantine') is None
    assert ga.plan({'triage': {'priority': 'incomplete'}, 'score': 61}, 'label')['labels'] == [ga.LABEL_HIGH]
    monkeypatch.setenv('GMAIL_ACTION_MIN_SCORE', '90')
    assert ga.plan({'triage': {'priority': 'incomplete'}, 'score': 61}, 'label') is None


def test_dry_run_records_a_plan_and_never_touches_gmail(monkeypatch):
    monkeypatch.setenv('GMAIL_ACTION_MODE', 'dry-run')
    monkeypatch.setattr(ga, '_modify_service', lambda: pytest.fail('dry-run must not build a Gmail client'))
    out = ga.apply('m1', URGENT)
    assert out['status'] == 'planned' and out['labels'] == [ga.LABEL_HIGH] and 'no Gmail API call' in out['detail']


def test_label_mode_creates_the_label_once_and_keeps_the_message_in_the_inbox(monkeypatch):
    monkeypatch.setenv('GMAIL_ACTION_MODE', 'label')
    gmail = FakeGmail(existing=['INBOX'])
    out = ga.apply('m1', URGENT, gmail)
    assert out['status'] == 'applied'
    modify = [c for c in gmail.calls if c[0] == 'modify'][0]
    assert modify[1] == 'm1' and modify[2]['removeLabelIds'] == [] and len(modify[2]['addLabelIds']) == 1
    ga.apply('m2', URGENT, gmail)
    assert [c for c in gmail.calls if c[0] == 'create_label'] == [('create_label', ga.LABEL_HIGH)]      # label created once, then cached


def test_quarantine_removes_only_the_inbox_label_and_never_trashes(monkeypatch):
    monkeypatch.setenv('GMAIL_ACTION_MODE', 'quarantine')
    gmail = FakeGmail(existing=[ga.LABEL_HIGH])
    out = ga.apply('m9', URGENT, gmail)
    body = [c for c in gmail.calls if c[0] == 'modify'][0][2]
    assert out['status'] == 'applied' and body['removeLabelIds'] == ['INBOX'] and 'TRASH' not in json.dumps(body) and 'SPAM' not in json.dumps(body)
    assert not [c for c in gmail.calls if c[0] == 'create_label']                                     # existing label reused
    assert ga.apply('m10', ROUTINE, gmail) is None


def _http_error(status):
    class Resp:
        pass
    r = Resp(); r.status = status; r.reason = 'x'
    return HttpError(r, b'{}')


def test_failures_are_reported_never_raised(monkeypatch):
    monkeypatch.setenv('GMAIL_ACTION_MODE', 'label')
    forbidden = ga.apply('m1', URGENT, FakeGmail(fail_modify=_http_error(403)))
    assert forbidden['status'] == 'failed' and 'gmail.modify' in forbidden['detail']
    boom = ga.apply('m1', URGENT, FakeGmail(fail_modify=RuntimeError('network down')))
    assert boom['status'] == 'failed' and 'left untouched' in boom['detail'] and 'network down' not in boom['detail']
    monkeypatch.setattr(ga, '_modify_service', lambda: (_ for _ in ()).throw(RuntimeError('Gmail not connected.')))
    assert ga.apply('m1', URGENT)['status'] == 'failed'


def _push(client, monkeypatch, raw, mid='msg-act'):
    _configure_push_env(monkeypatch); _mock_valid_token(monkeypatch)
    monkeypatch.setattr(gi, 'diff_new_message_ids', lambda history_id: [mid])
    monkeypatch.setattr(gi, 'fetch_raw', lambda message_id: raw)
    monkeypatch.setattr(gi, 'advance_watermark', lambda history_id: None)
    payload = base64.b64encode(json.dumps({'emailAddress': 'a@b.com', 'historyId': '7'}).encode()).decode()
    return client.post('/api/gmail/push', json={'message': {'data': payload}}, headers={'Authorization': 'Bearer fake'})


PHISH = (b'From: Bank <alerts@bank-secure.example>\r\nReply-To: r@other-desk.example\r\nTo: c@d.com\r\nSubject: Urgent\r\n\r\n'
         b'Please verify your account now or your account will be suspended. Do not call anyone about this, keep this confidential.')


def test_push_pipeline_records_the_action_in_the_chain_and_survives_action_failure(client, monkeypatch):
    monkeypatch.setenv('GMAIL_ACTION_MODE', 'dry-run')
    assert _push(client, monkeypatch, PHISH).json()['processed'] == 1
    sid = gi.session_sid()
    actions = [e['event'] for e in store.case_events(sid, store.all_cases(sid)[0]['id']) if e['event']['action'] == 'gmail_action']
    assert len(actions) == 1 and actions[0]['status'] == 'planned' and actions[0]['actor'] == 'system:gmail-push'
    assert store.verify(sid)['valid'] is True
    # a Gmail failure must not lose the message or fail the push
    monkeypatch.setenv('GMAIL_ACTION_MODE', 'label')
    monkeypatch.setattr(ga, '_modify_service', lambda: (_ for _ in ()).throw(RuntimeError('token lacks scope')))
    response = _push(client, monkeypatch, PHISH + b' (2)', mid='msg-act2')
    assert response.status_code == 200 and response.json()['processed'] == 1
    failed = [e['event'] for c in store.all_cases(sid) for e in store.case_events(sid, c['id']) if e['event']['action'] == 'gmail_action' and e['event']['status'] == 'failed']
    assert failed


def test_push_pipeline_with_mode_off_adds_no_action_events(client, monkeypatch):
    assert _push(client, monkeypatch, PHISH, mid='msg-off').json()['processed'] == 1
    sid = gi.session_sid()
    assert not [e for c in store.all_cases(sid) for e in store.case_events(sid, c['id']) if e['event']['action'] == 'gmail_action']

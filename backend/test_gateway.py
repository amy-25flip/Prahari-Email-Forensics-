import smtplib
import socket

import pytest

import authz
import gateway
import main
import samples
import store
from test_selection import client

H = {'X-Requested-With': 'Email-Threat-Detection'}
PHISH = samples.SAMPLES[1]['raw']            # credential-phishing fixture: urgent triage
NEWSLETTER = samples.SAMPLES[0]['raw']       # legitimate-style fixture: routine


def _free_port():
    s = socket.socket(); s.bind(('127.0.0.1', 0)); port = s.getsockname()[1]; s.close()
    return port


@pytest.fixture
def gw(client):
    port = main.start_gateway(_free_port())
    yield port
    main.stop_gateway()


def send(port, raw, sender='sender@remote.example', to='user@college.example'):
    with smtplib.SMTP('127.0.0.1', port, timeout=20) as smtp:
        return smtp.sendmail(sender, [to], raw.replace('\n', '\r\n').encode('utf-8'))


def drop():
    return main._maildrop()


# ---------- policy + maildrop units ----------
def test_decide_holds_urgent_or_high_score_only(monkeypatch):
    assert gateway.decide({'triage': {'priority': 'urgent', 'reasons': ['x']}, 'score': 10})[0] == 'hold'
    assert gateway.decide({'triage': {'priority': 'review'}, 'score': 59})[0] == 'deliver'
    assert gateway.decide({'triage': {'priority': 'review'}, 'score': 60})[0] == 'hold'
    monkeypatch.setenv('GATEWAY_HOLD_SCORE', '90')
    assert gateway.decide({'triage': {'priority': 'review'}, 'score': 80})[0] == 'deliver'
    monkeypatch.setenv('GATEWAY_HOLD_SCORE', 'garbage')
    assert gateway.hold_score() == 60


def test_maildrop_rejects_ids_that_could_escape_the_directory(tmp_path):
    md = gateway.Maildrop(tmp_path)
    for bad in ('../../etc/passwd', '..', 'x', '1234567890-zzzzzzzzzzzzzzzz', '1234567890-0123456789abcdef/../x', '', None, 123):
        with pytest.raises(ValueError):
            md._path(md.quarantine, bad, '.eml')
    md.hold('1234567890-0123456789abcdef', b'raw', {'id': '1234567890-0123456789abcdef', 'status': 'held'})
    with pytest.raises(ValueError):
        md.release('../../evil', 'x')
    assert md.release('1234567890-0123456789abcdef', 'tester\r\nBcc: evil@x.example')['status'] == 'released'
    delivered = (md.inbox / '1234567890-0123456789abcdef.eml').read_bytes()
    assert b'\r\nBcc:' not in delivered.split(b'\r\n\r\n')[0][:200].replace(b'X-PRAHARI-Released-By: tester Bcc: evil@x.example', b'')   # CR/LF stripped from the header value


# ---------- end to end over real SMTP ----------
def test_phishing_is_held_before_delivery_and_a_clean_email_is_delivered_with_headers(gw):
    send(gw, PHISH)
    send(gw, NEWSLETTER)
    md = drop()
    held = md.list_held()
    assert len(held) == 1 and held[0]['triage'] == 'urgent' and held[0]['status'] == 'held'
    assert held[0]['case_id'] and 'Credential pressure' in held[0]['findings']
    assert len(list(md.quarantine.glob('*.eml'))) == 1                     # held bytes exist...
    inbox = md.list_inbox()
    assert len(inbox) == 1 and inbox[0]['triage'] in ('routine', 'incomplete') and inbox[0]['score'].isdigit()
    assert not any('Verify' in m['subject'] and 'college' in m['subject'].lower() for m in inbox)   # ...and the phish never reached the inbox
    held_raw = (md.quarantine / f"{held[0]['id']}.eml").read_bytes()
    assert b'Subject:' in held_raw and b'X-PRAHARI' not in held_raw         # quarantined copy is the original, unmodified


def test_held_case_is_in_the_evidence_store_and_the_custody_chain_is_valid(gw):
    send(gw, PHISH)
    held = drop().list_held()[0]
    case = store.get(store.gateway_session(), held['case_id'])
    assert case['source'] == 'gateway' and case['triage']['priority'] == 'urgent'
    actions = [e['event']['action'] for e in store.case_events(store.gateway_session(), held['case_id'])]
    assert 'analyze' in actions and 'gateway_hold' in actions
    assert store.verify(store.gateway_session())['valid'] is True


def test_release_and_discard_are_logged_one_shot_decisions(gw, client):
    send(gw, PHISH); send(gw, PHISH.replace('Account verification', 'Account verification 2') if 'Account verification' in PHISH else PHISH + '\r\nx')
    ids = [m['id'] for m in client.get('/api/quarantine').json()['held']]
    assert len(ids) == 2
    released = client.post(f'/api/quarantine/{ids[0]}/release', headers=H)
    assert released.status_code == 200 and released.json()['status'] == 'released' and released.json()['closed_by'] == 'analyst (open mode)'
    assert client.post(f'/api/quarantine/{ids[0]}/release', headers=H).status_code == 404      # cannot be released twice
    assert client.post(f'/api/quarantine/{ids[1]}/discard', headers=H).json()['status'] == 'discarded'
    assert not list(drop().quarantine.glob('*.eml'))
    assert any(m['released_by'] for m in drop().list_inbox())
    assert client.get('/api/quarantine').json()['held'] == []
    events = [e['event'] for e in store.case_events(store.gateway_session(), released.json()['case_id'])]
    assert any(e['action'] == 'quarantine_release' and e['by'] == 'analyst (open mode)' for e in events)


def test_api_rejects_bad_ids_and_reports_gateway_status(gw, client):
    assert client.post('/api/quarantine/not-an-id/release', headers=H).status_code == 400
    assert client.post('/api/quarantine/1234567890-0123456789abcdef/release', headers=H).status_code == 404
    assert client.get('/api/quarantine/..').status_code in (400, 404)
    q = client.get('/api/quarantine').json()
    assert q['gateway']['listening'] is True and q['gateway']['port'] == gw and q['gateway']['hold_score'] == 60
    assert client.get('/api/health').json()['gateway'] == {'listening': True, 'port': gw}
    send(gw, PHISH)
    detail = client.get(f"/api/quarantine/{client.get('/api/quarantine').json()['held'][0]['id']}").json()
    assert detail['case']['triage']['priority'] == 'urgent' and detail['meta']['status'] == 'held'


def test_analysis_failure_fails_closed_and_capacity_gets_a_retryable_451(client, monkeypatch):
    def boom(raw, envelope): raise RuntimeError('model exploded')
    monkeypatch.setattr(main, '_gateway_analyze', boom)
    port = main.start_gateway(_free_port())
    try:
        send(port, NEWSLETTER)
        held = drop().list_held()
        assert len(held) == 1 and 'Analysis failed (RuntimeError)' in held[0]['reasons'][0] and drop().list_inbox() == []   # never delivered unscanned
    finally:
        main.stop_gateway()

    def busy(raw, envelope): raise gateway.GatewayTransient()
    monkeypatch.setattr(main, '_gateway_analyze', busy)
    port = main.start_gateway(_free_port())
    try:
        with pytest.raises(smtplib.SMTPDataError) as info:
            send(port, NEWSLETTER)
        assert info.value.smtp_code == 451
        assert len(drop().list_held()) == 1          # nothing new was filed; the sender MTA will retry
    finally:
        main.stop_gateway()


def test_oversized_messages_are_refused_by_smtp(gw):
    big = 'From: a@b.example\nTo: c@d.example\nSubject: big\n\n' + ('A' * 80 + '\n') * 15000
    with pytest.raises(smtplib.SMTPException):
        send(gw, big)
    assert drop().list_held() == [] and drop().list_inbox() == []


def test_gateway_is_off_by_default_and_start_is_idempotent(client):
    assert client.get('/api/health').json()['gateway'] == {'listening': False, 'port': None}
    port = main.start_gateway(_free_port())
    try:
        assert main.start_gateway(_free_port()) == port
    finally:
        main.stop_gateway()
    assert client.get('/api/quarantine').json()['gateway']['listening'] is False


# ---------- roles ----------
def test_roles_govern_the_quarantine(gw, client, monkeypatch):
    monkeypatch.setenv('ROLE_TOKENS', 'asha:analyst:analyst-token-0123456789,ravi:admin:admin-token-0123456789abc,meera:viewer:viewer-token-0123456789ab')
    viewer, analyst, admin = ({**H, 'Authorization': f'Bearer {t}'} for t in ('viewer-token-0123456789ab', 'analyst-token-0123456789', 'admin-token-0123456789abc'))
    send(gw, PHISH)
    assert client.get('/api/quarantine', headers=viewer).status_code == 403
    listed = client.get('/api/quarantine', headers=analyst)
    assert listed.status_code == 200
    qid = listed.json()['held'][0]['id']
    assert client.post(f'/api/quarantine/{qid}/discard', headers=analyst).status_code == 403     # discard is admin-only
    released = client.post(f'/api/quarantine/{qid}/release', headers=analyst)
    assert released.status_code == 200 and released.json()['closed_by'] == 'asha'
    # with roles on, gateway cases live in the shared workspace, so people can open them normally
    assert client.get(f"/api/cases/{released.json()['case_id']}", headers=viewer).status_code == 200


def test_simultaneous_release_and_discard_resolve_to_exactly_one_outcome(gw, client):
    import threading
    send(gw, PHISH)
    qid = drop().list_held()[0]['id']
    outcomes = []
    def act(kind):
        try:
            outcomes.append((kind, getattr(drop(), kind)(qid, 'tester') is not None))
        except Exception as exc:                                       # the old code could 500 here (missing .eml)
            outcomes.append((kind, type(exc).__name__))
    threads = [threading.Thread(target=act, args=(k,)) for k in ('release', 'discard', 'release', 'discard')]
    [t.start() for t in threads]; [t.join() for t in threads]
    assert [ok for _, ok in outcomes].count(True) == 1 and all(ok in (True, False) for _, ok in outcomes), outcomes
    meta = drop().load_meta(qid)
    inbox_has = any(m['id'] == qid for m in drop().list_inbox())
    assert (meta['status'] == 'released') == inbox_has                # inbox copy exists iff the final status is 'released'


def test_storage_failure_gets_a_retryable_451_and_nothing_is_delivered(client, monkeypatch):
    real = gateway.Maildrop.hold
    monkeypatch.setattr(gateway.Maildrop, 'hold', lambda self, *a, **k: (_ for _ in ()).throw(OSError('disk full')))
    port = main.start_gateway(_free_port())
    try:
        with pytest.raises(smtplib.SMTPDataError) as info:
            send(port, PHISH)
        assert info.value.smtp_code == 451 and drop().list_inbox() == []
    finally:
        main.stop_gateway()
        monkeypatch.setattr(gateway.Maildrop, 'hold', real)


def test_gateway_receipt_gives_an_attested_earliest_node_only_when_a_key_is_configured(gw, monkeypatch):
    send(gw, PHISH)
    case = store.get(store.gateway_session(), drop().list_held()[0]['case_id'])
    assert case['assessment']['origin_evidence']['confidence'] != 'authenticated_observation'
    monkeypatch.setenv('GATEWAY_RECEIPT_KEY', 'k' * 40)
    send(gw, 'X-Run: second\n' + PHISH)
    newest = max(drop().list_held(), key=lambda m: m['held_at'])
    origin = store.get(store.gateway_session(), newest['case_id'])['assessment']['origin_evidence']
    assert origin['confidence'] == 'authenticated_observation'
    assert origin['earliest_reliable_node'] == {'ip': '127.0.0.1', 'provenance': 'receiver_attestation', 'receiver': 'prahari-gateway'}
    assert origin['approximate_location'] is None                      # private/loopback demo address is never geolocated


def test_receipt_is_bound_to_the_bytes_and_rejects_a_short_key(monkeypatch):
    import receiver_evidence
    signed = receiver_evidence.sign(b'abc', {'client_ip': '203.0.113.5', 'mail_from': 'a@b.example', 'helo': 'mx.example'}, 'r', 'k' * 40)
    assert receiver_evidence.verify(signed, b'abc', {'r': 'k' * 40})['smtp']['client_ip'] == '203.0.113.5'
    with pytest.raises(ValueError): receiver_evidence.verify(signed, b'abcd', {'r': 'k' * 40})
    monkeypatch.setenv('GATEWAY_RECEIPT_KEY', 'short')
    assert main._gateway_receipt(b'abc', {'peer': '203.0.113.5', 'mail_from': 'a@b.example', 'helo': 'mx.example'}) == (None, None)

import hashlib
import pytest
import blockchain_timestamp as bt
from opentimestamps.core.notary import BitcoinBlockHeaderAttestation, PendingAttestation
from opentimestamps.core.timestamp import Timestamp

DIGEST = hashlib.sha256(b'test evidence').hexdigest()


def test_stamp_rejects_invalid_hex():
    result = bt.stamp('not-hex')
    assert result['status'] == 'error'


def test_stamp_rejects_wrong_length():
    result = bt.stamp('ab' * 10)
    assert result['status'] == 'error'


def test_stamp_unavailable_when_all_calendars_fail(monkeypatch):
    class FailingCalendar:
        def __init__(self, *a, **k): pass
        def submit(self, *a, **k): raise ConnectionError('unreachable')
    monkeypatch.setattr(bt, 'RemoteCalendar', FailingCalendar)
    result = bt.stamp(DIGEST)
    assert result['status'] == 'unavailable'
    assert len(result['errors']) == len(bt.CALENDAR_URLS)


def test_stamp_reports_pending_from_partial_success(monkeypatch):
    calls = []
    class FakeCalendar:
        def __init__(self, url, **k): self.url = url
        def submit(self, digest, timeout=None):
            calls.append(self.url)
            if self.url == bt.CALENDAR_URLS[0]: raise ConnectionError('down')
            ts = Timestamp(digest)
            ts.attestations.add(PendingAttestation(self.url))
            return ts
    monkeypatch.setattr(bt, 'RemoteCalendar', FakeCalendar)
    result = bt.stamp(DIGEST)
    assert result['status'] == 'pending'
    assert bt.CALENDAR_URLS[0] not in result['calendars_used']
    assert 'proof' in result and len(result['proof']) > 0


def test_check_reports_confirmed_without_network_when_already_attested(monkeypatch):
    digest = bytes.fromhex(DIGEST)
    ts = Timestamp(digest)
    ts.attestations.add(BitcoinBlockHeaderAttestation(123456))
    from opentimestamps.core.timestamp import DetachedTimestampFile
    from opentimestamps.core.op import OpSHA256
    file_ts = DetachedTimestampFile(OpSHA256(), ts)
    proof = bt._encode(file_ts)

    def fail(*a, **k): pytest.fail('Should not contact the network for an already-confirmed proof')
    monkeypatch.setattr(bt, 'RemoteCalendar', fail)
    result = bt.check(DIGEST, proof)
    assert result['status'] == 'confirmed'
    assert result['bitcoin_block_height'] == 123456


def test_check_rejects_mismatched_digest():
    from opentimestamps.core.timestamp import DetachedTimestampFile
    from opentimestamps.core.op import OpSHA256
    ts = Timestamp(bytes.fromhex(DIGEST))
    ts.attestations.add(PendingAttestation('https://example.test/calendar'))
    stamped = bt._encode(DetachedTimestampFile(OpSHA256(), ts))
    other_digest = hashlib.sha256(b'unrelated content').hexdigest()
    result = bt.check(other_digest, stamped)
    assert result['status'] == 'error'
    assert 'mismatch' in result['detail'].lower() or 'different evidence' in result['detail'].lower()


def test_check_rejects_malformed_proof():
    result = bt.check(DIGEST, 'not-valid-base64!!!')
    assert result['status'] == 'error'

import hashlib
import pytest
import blockchain_timestamp as bt
from opentimestamps.core.notary import BitcoinBlockHeaderAttestation, PendingAttestation
from opentimestamps.core.op import OpAppend, OpSHA256
from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp

DIGEST = hashlib.sha256(b'test evidence').hexdigest()


def _realistic_attested_proof(height):
    """Build a proof the way a real OpenTimestamps calendar actually would:
    the attestation sits on a merkle root reached by applying real ops
    (append + hash) to the original digest, NOT on the original digest
    itself. Returns (proof_b64, merkle_root_bytes) -- exercises the same
    all_attestations() op-chain traversal the real code path relies on,
    not just the terminal comparison in isolation."""
    digest = bytes.fromhex(DIGEST)
    ts = Timestamp(digest)
    appended = ts.ops.add(OpAppend(b'padding-from-a-real-merkle-path'))
    merkle_root_stamp = appended.ops.add(OpSHA256())
    merkle_root_stamp.attestations.add(BitcoinBlockHeaderAttestation(height))
    proof = bt._encode(DetachedTimestampFile(OpSHA256(), ts))
    return proof, merkle_root_stamp.msg


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


def test_check_reports_confirmed_when_explorer_merkle_root_matches(monkeypatch):
    # 'confirmed' must come from an independent check against a real block's
    # merkle root, not merely from the proof's own self-declared attestation
    # -- otherwise anyone could hand-craft a proof claiming an attestation
    # that was never actually mined, and this code would call it "confirmed"
    # (the exact bug this test used to encode as expected behavior).
    digest = bytes.fromhex(DIGEST)
    ts = Timestamp(digest)
    ts.attestations.add(BitcoinBlockHeaderAttestation(123456))
    from opentimestamps.core.timestamp import DetachedTimestampFile
    from opentimestamps.core.op import OpSHA256
    file_ts = DetachedTimestampFile(OpSHA256(), ts)
    proof = bt._encode(file_ts)

    def fail(*a, **k): pytest.fail('Should not contact a calendar server for an already-attested proof')
    monkeypatch.setattr(bt, 'RemoteCalendar', fail)
    monkeypatch.setattr(bt, '_fetch_block_merkle_root', lambda height: digest if height == 123456 else None)
    result = bt.check(DIGEST, proof)
    assert result['status'] == 'confirmed'
    assert result['bitcoin_block_height'] == 123456


def test_check_confirms_through_a_realistic_op_chain_not_the_original_digest(monkeypatch):
    # The test above attaches the attestation directly to the original
    # digest, which proves the comparison logic but not that the op-chain
    # traversal (append/hash ops transforming the original digest into a
    # different terminal merkle-root value) is actually followed correctly
    # -- a real OpenTimestamps calendar's proof always looks like this, not
    # like an attestation sitting on the bare original digest.
    proof, merkle_root = _realistic_attested_proof(123456)

    def fail(*a, **k): pytest.fail('Should not contact a calendar server for an already-attested proof')
    monkeypatch.setattr(bt, 'RemoteCalendar', fail)
    seen_heights = []
    def fake_fetch(height):
        seen_heights.append(height)
        return merkle_root
    monkeypatch.setattr(bt, '_fetch_block_merkle_root', fake_fetch)
    result = bt.check(DIGEST, proof)
    assert result['status'] == 'confirmed'
    assert seen_heights == [123456]


def test_check_rejects_realistic_proof_when_explorer_returns_the_original_digest(monkeypatch):
    # If the comparison were accidentally checking file_ts.timestamp.msg (the
    # original digest) instead of the attestation node's own msg (the real
    # merkle root reached via the op chain), this would wrongly pass.
    proof, merkle_root = _realistic_attested_proof(123456)
    assert merkle_root != bytes.fromhex(DIGEST)  # sanity: the fixture actually transforms the digest
    monkeypatch.setattr(bt, '_fetch_block_merkle_root', lambda height: bytes.fromhex(DIGEST))
    result = bt.check(DIGEST, proof)
    assert result['status'] == 'invalid'


def test_check_reports_invalid_when_explorer_merkle_root_does_not_match(monkeypatch):
    digest = bytes.fromhex(DIGEST)
    ts = Timestamp(digest)
    ts.attestations.add(BitcoinBlockHeaderAttestation(123456))
    from opentimestamps.core.timestamp import DetachedTimestampFile
    from opentimestamps.core.op import OpSHA256
    proof = bt._encode(DetachedTimestampFile(OpSHA256(), ts))

    monkeypatch.setattr(bt, '_fetch_block_merkle_root', lambda height: b'\x00' * 32)
    result = bt.check(DIGEST, proof)
    assert result['status'] == 'invalid'
    assert result['bitcoin_block_height'] == 123456


def test_check_reports_unverified_when_no_explorer_reachable(monkeypatch):
    digest = bytes.fromhex(DIGEST)
    ts = Timestamp(digest)
    ts.attestations.add(BitcoinBlockHeaderAttestation(123456))
    from opentimestamps.core.timestamp import DetachedTimestampFile
    from opentimestamps.core.op import OpSHA256
    proof = bt._encode(DetachedTimestampFile(OpSHA256(), ts))

    monkeypatch.setattr(bt, '_fetch_block_merkle_root', lambda height: None)
    result = bt.check(DIGEST, proof)
    assert result['status'] == 'unverified'
    assert result['bitcoin_block_height'] == 123456


def test_fetch_block_merkle_root_reverses_display_order_hex(monkeypatch):
    # Block explorers report merkle roots in display (big-endian) hex;
    # OpenTimestamps digests use the reverse (internal) byte order. Verified
    # against the well-known, publicly documented Bitcoin genesis block.
    genesis_display_hex = '4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b'
    expected = bytes.fromhex(genesis_display_hex)[::-1]

    class FakeResponse:
        def __init__(self, text=None, json_body=None):
            self._text, self._json = text, json_body
        @property
        def text(self): return self._text
        def json(self): return self._json
        def raise_for_status(self): pass

    def fake_get(url, timeout=None):
        if '/block-height/' in url:
            return FakeResponse(text='0' * 63 + '1')
        return FakeResponse(json_body={'merkle_root': genesis_display_hex})
    monkeypatch.setattr(bt.requests, 'get', fake_get)
    assert bt._fetch_block_merkle_root(0) == expected


def test_fetch_block_merkle_root_returns_none_when_every_explorer_fails(monkeypatch):
    import requests as real_requests
    def fake_get(url, timeout=None): raise real_requests.RequestException('unreachable')
    monkeypatch.setattr(bt.requests, 'get', fake_get)
    assert bt._fetch_block_merkle_root(123456) is None


def test_check_rejects_proof_with_bad_magic_bytes():
    # base64-valid but not a real OpenTimestamps proof -- must degrade to
    # the module's usual {'status': 'error'} shape, not an unhandled 500.
    result = bt.check(DIGEST, 'AAAA')
    assert result['status'] == 'error'


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


# ---------- upgrade path (regression: check() used to ask calendars for the FILE digest) ----------
def _realistic_pending_proof(uri='https://cal.example'):
    """Proof shaped like a real calendar submission: the pending attestation sits on a COMMITMENT
    (file digest -> append nonce -> sha256), which is not the original digest."""
    digest = bytes.fromhex(DIGEST)
    ts = Timestamp(digest)
    commitment = ts.ops.add(OpAppend(b'calendar-nonce')).ops.add(OpSHA256())
    commitment.attestations.add(PendingAttestation(uri))
    return bt._encode(DetachedTimestampFile(OpSHA256(), ts)), commitment.msg


class _UpgradeCalendar:
    """Answers only for the exact commitment, like a real calendar; anything else is 'not found'."""
    asked = []

    def __init__(self, commitment, height=777777, ready=True):
        self.commitment, self.height, self.ready = commitment, height, ready

    def factory(self):
        outer = self

        class Cal:
            def __init__(self, url, **k): pass
            def get_timestamp(self, msg, timeout=None):
                from opentimestamps.calendar import CommitmentNotFoundError
                outer.asked.append(msg)
                if msg != outer.commitment or not outer.ready:
                    raise CommitmentNotFoundError('not found')
                stamp = Timestamp(msg)
                merkle = stamp.ops.add(OpAppend(b'merkle-path')).ops.add(OpSHA256())
                merkle.attestations.add(BitcoinBlockHeaderAttestation(outer.height))
                outer.merkle_root = merkle.msg
                return stamp
        return Cal


def test_check_upgrades_a_pending_proof_by_asking_the_calendar_for_the_commitment(monkeypatch):
    proof, commitment = _realistic_pending_proof()
    assert commitment != bytes.fromhex(DIGEST)
    cal = _UpgradeCalendar(commitment)
    cal.asked.clear()
    monkeypatch.setattr(bt, 'RemoteCalendar', cal.factory())
    monkeypatch.setattr(bt, '_fetch_block_merkle_root', lambda height: cal.merkle_root if height == 777777 else None)
    result = bt.check(DIGEST, proof)
    assert result['status'] == 'confirmed' and result['bitcoin_block_height'] == 777777
    assert cal.asked == [commitment]                      # asked with the commitment, never the file digest
    # the upgraded proof is returned and now verifies on its own without contacting any calendar
    def fail(*a, **k): pytest.fail('confirmed proof must not re-contact calendars')
    monkeypatch.setattr(bt, 'RemoteCalendar', fail)
    again = bt.check(DIGEST, result['proof'])
    assert again['status'] == 'confirmed'


def test_check_stays_pending_when_the_calendar_has_not_confirmed_yet(monkeypatch):
    proof, commitment = _realistic_pending_proof()
    cal = _UpgradeCalendar(commitment, ready=False)
    monkeypatch.setattr(bt, 'RemoteCalendar', cal.factory())
    result = bt.check(DIGEST, proof)
    assert result['status'] == 'pending'
    assert result['proof'] == proof                        # nothing upgraded, original proof preserved
    assert result['calendar_errors'] and 'CommitmentNotFoundError' in result['calendar_errors'][0]


def test_upgraded_but_unverifiable_proof_is_not_reported_confirmed(monkeypatch):
    proof, commitment = _realistic_pending_proof()
    cal = _UpgradeCalendar(commitment)
    monkeypatch.setattr(bt, 'RemoteCalendar', cal.factory())
    monkeypatch.setattr(bt, '_fetch_block_merkle_root', lambda height: b'\x00' * 32)   # explorer disagrees
    assert bt.check(DIGEST, proof)['status'] == 'invalid'
    monkeypatch.setattr(bt, '_fetch_block_merkle_root', lambda height: None)           # explorer unreachable
    assert bt.check(DIGEST, proof)['status'] == 'unverified'

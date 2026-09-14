"""Independent evidence timestamping via OpenTimestamps, anchored to the Bitcoin blockchain.

Only a SHA-256 digest is ever submitted (e.g. a checkpoint's chain head) -- never email
content, case data, or any other evidence itself. This gives investigators a proof-of-existence
that does not depend on trusting this server or the OpenTimestamps calendar operators: once a
proof upgrades to a Bitcoin attestation, this module cross-checks it against a public block
explorer's real merkle root before ever reporting 'confirmed' -- and the exported proof itself
remains independently re-checkable by anyone, using any OpenTimestamps-compatible verifier.

Confirmation is not immediate: a submission is "pending" until a Bitcoin block includes it,
which is typically hours, not seconds. This module never blocks waiting for that -- it submits
(or checks) and returns whatever state is available right now.
"""
import base64
import re
import threading

import requests
from opentimestamps.calendar import RemoteCalendar
from opentimestamps.core.notary import BitcoinBlockHeaderAttestation, PendingAttestation
from opentimestamps.core.op import OpSHA256
from opentimestamps.core.serialize import BytesDeserializationContext, BytesSerializationContext, DeserializationError
from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp

CALENDAR_URLS = [
    'https://a.pool.opentimestamps.org',
    'https://b.pool.opentimestamps.org',
    'https://a.pool.eternitywall.com',
    'https://ots.btc.catallaxy.com',
]
# Public block explorers, used only to independently cross-check a claimed
# Bitcoin attestation's merkle root -- never to submit or fetch evidence
# content, only a block height (public knowledge) and a block's own public
# merkle root. Two independent operators, tried in order, so one being down
# doesn't turn a genuinely valid proof into a false "unverified".
BLOCK_EXPLORER_URLS = ['https://mempool.space/api', 'https://blockstream.info/api']
EXPLORER_TIMEOUT = (3, 7)
USER_AGENT = 'AIEmailThreatDetection/0.1 (evidence-integrity-checkpoint)'
TIMEOUT = 10
_lock = threading.Lock()


def _fetch_block_merkle_root(height):
    """Fetch a mined block's merkle root, in the raw internal byte order
    OpenTimestamps attestations commit to (block explorers report it in
    display/big-endian hex -- Bitcoin's own wire format, and this digest
    comparison, use the reverse order; this is a universal, protocol-level
    convention, not something specific to one explorer).

    Returns None (never raises) if no explorer could be reached, so a
    verification attempt degrades to an honest 'unverified' status rather
    than crashing or silently trusting the proof's own claim."""
    for base in BLOCK_EXPLORER_URLS:
        try:
            hash_resp = requests.get(f'{base}/block-height/{height}', timeout=EXPLORER_TIMEOUT)
            hash_resp.raise_for_status()
            block_hash = hash_resp.text.strip()
            if not re.fullmatch(r'[0-9a-fA-F]{64}', block_hash):
                continue
            block_resp = requests.get(f'{base}/block/{block_hash}', timeout=EXPLORER_TIMEOUT)
            block_resp.raise_for_status()
            merkle_root_hex = block_resp.json()['merkle_root']
            return bytes.fromhex(merkle_root_hex)[::-1]
        except (requests.RequestException, ValueError, KeyError, TypeError):
            continue
    return None


def _parse_digest(sha256_hex):
    if not isinstance(sha256_hex, str):
        raise ValueError('Digest must be a hex string.')
    digest = bytes.fromhex(sha256_hex.strip().lower())
    if len(digest) != 32:
        raise ValueError('Expected a 32-byte SHA-256 digest (64 hex characters).')
    return digest


def _encode(file_ts):
    ctx = BytesSerializationContext()
    file_ts.serialize(ctx)
    return base64.b64encode(ctx.getbytes()).decode('ascii')


def _decode(proof_b64, expected_digest):
    try:
        raw = base64.b64decode(proof_b64, validate=True)
    except (ValueError, TypeError) as exc:
        raise ValueError(f'Invalid proof encoding: {type(exc).__name__}') from exc
    ctx = BytesDeserializationContext(raw)
    try:
        file_ts = DetachedTimestampFile.deserialize(ctx)
    except DeserializationError as exc:
        # base64-valid but not a real OpenTimestamps proof (bad magic bytes,
        # truncated, trailing garbage, ...) -- must degrade to the same
        # ValueError->{'status':'error'} shape as every other malformed-input
        # path here, not crash the endpoint with an unhandled 500.
        raise ValueError(f'Invalid proof format: {type(exc).__name__}') from exc
    if file_ts.timestamp.msg != expected_digest:
        raise ValueError('Proof does not match the supplied digest; it was issued for different evidence.')
    return file_ts


def _attestation_status(file_ts):
    """Summarize the best-known attestation state.

    A BitcoinBlockHeaderAttestation is only ever the PROOF's own claim of
    where it was committed -- deserializing it proves nothing by itself.
    Reporting 'confirmed' from that claim alone (as this function used to)
    meant anyone could hand-craft a proof with a fabricated attestation and
    have it reported as independently verified evidence, which it never was.
    'confirmed' now requires actually fetching that block's real merkle root
    from a public explorer and checking it matches this proof's own
    commitment digest -- the same check https://opentimestamps.org's own
    verifier performs against a Bitcoin node.
    """
    confirmed_heights, mismatched_heights, unverifiable_heights = [], [], []
    pending_calendars = []
    for msg, attestation in file_ts.timestamp.all_attestations():
        if isinstance(attestation, BitcoinBlockHeaderAttestation):
            merkle_root = _fetch_block_merkle_root(attestation.height)
            if merkle_root is None:
                unverifiable_heights.append(attestation.height)
            elif msg == merkle_root:
                confirmed_heights.append(attestation.height)
            else:
                mismatched_heights.append(attestation.height)
        elif isinstance(attestation, PendingAttestation):
            pending_calendars.append(attestation.uri)
    if confirmed_heights:
        return {'status': 'confirmed', 'bitcoin_block_height': min(confirmed_heights),
                'detail': 'Independently verified against a public block explorer: the digest matches the actual mined Bitcoin block at this height.'}
    if mismatched_heights:
        return {'status': 'invalid', 'bitcoin_block_height': min(mismatched_heights),
                'detail': f'Proof claims Bitcoin attestation at block height {min(mismatched_heights)}, but the real block does not match this digest -- this proof does not verify.'}
    if unverifiable_heights:
        return {'status': 'unverified', 'bitcoin_block_height': min(unverifiable_heights),
                'detail': f'Proof claims Bitcoin attestation at block height {min(unverifiable_heights)}, but no block explorer could be reached to independently check it. Treat as unconfirmed, not as invalid.'}
    if pending_calendars:
        return {'status': 'pending', 'pending_calendars': pending_calendars,
                'detail': 'Submitted; awaiting Bitcoin block confirmation (typically hours, not immediate).'}
    return {'status': 'unknown', 'detail': 'Proof carries no recognized attestation.'}


def stamp(sha256_hex):
    """Submit a digest to public OpenTimestamps calendar servers. Returns a status dict with a base64 proof."""
    try:
        digest = _parse_digest(sha256_hex)
    except ValueError as exc:
        return {'status': 'error', 'detail': str(exc)}
    file_ts = DetachedTimestampFile(OpSHA256(), Timestamp(digest))
    accepted, errors = [], []
    for url in CALENDAR_URLS:
        try:
            calendar_ts = RemoteCalendar(url, user_agent=USER_AGENT).submit(digest, timeout=TIMEOUT)
            file_ts.timestamp.merge(calendar_ts)
            accepted.append(url)
        except Exception as exc:
            errors.append(f'{url}: {type(exc).__name__}')
    if not accepted:
        return {'status': 'unavailable', 'detail': 'No calendar server accepted the submission.', 'errors': errors}
    result = _attestation_status(file_ts)
    result.update(proof=_encode(file_ts), calendars_used=accepted, sha256=sha256_hex.strip().lower())
    if errors: result['calendar_errors'] = errors
    return result


def check(sha256_hex, proof_b64):
    """Check (and attempt to upgrade) an existing proof's confirmation status."""
    try:
        digest = _parse_digest(sha256_hex)
        file_ts = _decode(proof_b64, digest)
    except ValueError as exc:
        return {'status': 'error', 'detail': str(exc)}
    current = _attestation_status(file_ts)
    if current['status'] == 'confirmed':
        current.update(proof=proof_b64, sha256=sha256_hex.strip().lower())
        return current
    upgraded, errors = False, []
    for _, attestation in list(file_ts.timestamp.all_attestations()):
        if not isinstance(attestation, PendingAttestation):
            continue
        try:
            calendar_ts = RemoteCalendar(attestation.uri, user_agent=USER_AGENT).get_timestamp(digest, timeout=TIMEOUT)
            file_ts.timestamp.merge(calendar_ts)
            upgraded = True
        except Exception as exc:
            errors.append(f'{attestation.uri}: {type(exc).__name__}')
    result = _attestation_status(file_ts)
    result.update(proof=_encode(file_ts) if upgraded else proof_b64, sha256=sha256_hex.strip().lower())
    if errors: result['calendar_errors'] = errors
    return result

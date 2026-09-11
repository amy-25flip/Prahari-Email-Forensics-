"""Independent evidence timestamping via OpenTimestamps, anchored to the Bitcoin blockchain.

Only a SHA-256 digest is ever submitted (e.g. a checkpoint's chain head) -- never email
content, case data, or any other evidence itself. This gives investigators a proof-of-existence
that does not depend on trusting this server or Anthropic/OpenTimestamps' calendar operators:
once a proof upgrades to a Bitcoin attestation, anyone can independently verify it against the
Bitcoin blockchain using the OpenTimestamps proof format (RFC-independent, publicly documented).

Confirmation is not immediate: a submission is "pending" until a Bitcoin block includes it,
which is typically hours, not seconds. This module never blocks waiting for that -- it submits
(or checks) and returns whatever state is available right now.
"""
import base64
import threading

from opentimestamps.calendar import RemoteCalendar
from opentimestamps.core.notary import BitcoinBlockHeaderAttestation, PendingAttestation
from opentimestamps.core.op import OpSHA256
from opentimestamps.core.serialize import BytesDeserializationContext, BytesSerializationContext
from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp

CALENDAR_URLS = [
    'https://a.pool.opentimestamps.org',
    'https://b.pool.opentimestamps.org',
    'https://a.pool.eternitywall.com',
    'https://ots.btc.catallaxy.com',
]
USER_AGENT = 'AIEmailThreatDetection/0.1 (evidence-integrity-checkpoint)'
TIMEOUT = 10
_lock = threading.Lock()


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
    file_ts = DetachedTimestampFile.deserialize(ctx)
    if file_ts.timestamp.msg != expected_digest:
        raise ValueError('Proof does not match the supplied digest; it was issued for different evidence.')
    return file_ts


def _attestation_status(file_ts):
    """Summarize the best-known attestation state without contacting any server."""
    confirmed_heights = []
    pending_calendars = []
    for _, attestation in file_ts.timestamp.all_attestations():
        if isinstance(attestation, BitcoinBlockHeaderAttestation):
            confirmed_heights.append(attestation.height)
        elif isinstance(attestation, PendingAttestation):
            pending_calendars.append(attestation.uri)
    if confirmed_heights:
        return {'status': 'confirmed', 'bitcoin_block_height': min(confirmed_heights),
                'detail': 'Independently verifiable: this digest is committed in a mined Bitcoin block.'}
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

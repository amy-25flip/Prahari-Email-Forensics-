"""Optional role-based access control with actor-stamped audit events.

Off by default (open demo mode, exactly the previous behaviour). Turned on by setting ROLE_TOKENS to a comma-separated
list of `name:role:token` entries, e.g.  ROLE_TOKENS="asha:analyst:<random>,ravi:admin:<random>,meera:viewer:<random>".
Roles: viewer (read + redacted exports) < analyst (analyze, notes, assignment, review, full exports, landing inspection,
quarantine release) < admin (deletes, blockchain stamping, quarantine discard, anything unlisted).

Deliberate scope: this is application-role access control with per-person bearer tokens, not an identity provider. It gives
a real actor on every audit-chain event ("authenticated app role", not legal identity) and enforces separation of duties.
If ROLE_TOKENS is set but holds no valid entry, EVERY protected request is refused - it never falls back to open."""
import contextvars
import hmac
import logging
import os
import re
from dataclasses import dataclass

RANK = {'viewer': 1, 'analyst': 2, 'admin': 3}
MIN_TOKEN_LENGTH = 16
# These exact routes carry their own dedicated authentication (Pub/Sub OIDC, Gmail read/admin bearer tokens). Deliberately an
# exact list, not a prefix: a future /api/gmail/... route must opt in here or it falls under role auth like everything else.
SELF_AUTHENTICATED = re.compile(r'^/api/gmail/(push|watch/start|cases(/[^/]+)?)/?$')
EXEMPT_PATHS = {'/api/health', '/api/ready'}


@dataclass(frozen=True)
class Actor:
    name: str
    role: str


current_actor = contextvars.ContextVar('current_actor', default=None)
SYSTEM_GMAIL = Actor('system:gmail-push', 'system')
SYSTEM_GATEWAY = Actor('system:gateway', 'system')


def enabled():
    return bool(os.getenv('ROLE_TOKENS', '').strip())


def _entries():
    entries = []
    for item in os.getenv('ROLE_TOKENS', '').split(','):
        item = item.strip()
        if not item:
            continue
        parts = item.split(':', 2)
        if len(parts) != 3:
            logging.warning('Ignoring malformed ROLE_TOKENS entry (expected name:role:token)')
            continue
        name, role, token = (p.strip() for p in parts)
        if role not in RANK or not name or len(token) < MIN_TOKEN_LENGTH:
            logging.warning('Ignoring invalid ROLE_TOKENS entry for %r (bad role, empty name or token shorter than %d)', name, MIN_TOKEN_LENGTH)
            continue
        entries.append((name, role, token))
    return entries


def authenticate(authorization):
    """Actor for an `Authorization: Bearer <token>` header, or None. Compares against every token in constant time."""
    if not authorization or not authorization.lower().startswith('bearer '):
        return None
    supplied = authorization[7:].strip().encode()
    match = None
    for name, role, token in _entries():
        if hmac.compare_digest(supplied, token.encode()) and match is None:
            match = Actor(name, role)
    return match


def is_exempt(path):
    return path in EXEMPT_PATHS or not path.startswith('/api/') or bool(SELF_AUTHENTICATED.match(path))


_ANALYST_WRITES = re.compile(r'^/api/(analyze|samples/[^/]+|checkpoint/verify|checkpoint/blockchain-verify|'
                             r'cases/[^/]+/(notes|assign|review|urls/inspect|siem)|cases/[^/]+/attachments/[a-f0-9]+/sandbox|'
                             r'attachments/sandbox/[^/]+|quarantine/[^/]+/release)$')
_EXPORT = re.compile(r'^/api/cases/[^/]+/export/(\w+)$')


def required_role(method, path, query=None):
    """Minimum role for a request. Unknown writes fail safe to admin."""
    p = path.rstrip('/') or '/'
    query = query or {}
    if method in ('GET', 'HEAD', 'OPTIONS'):
        m = _EXPORT.match(p)
        if m:
            return 'viewer' if (query.get('privacy') == 'redacted' and m.group(1) in ('json', 'csv', 'pdf', 'cef')) else 'analyst'
        if p.startswith(('/api/quarantine', '/api/gateway')):       # held/delivered mail metadata: not for viewers
            return 'analyst'
        return 'viewer'
    if p == '/api/checkpoint/blockchain-stamp' or re.fullmatch(r'/api/quarantine/[^/]+/discard', p):
        return 'admin'
    if method == 'DELETE':
        return 'admin'
    if _ANALYST_WRITES.match(p):
        return 'analyst'
    return 'admin'


def allows(actor_role, needed):
    return RANK.get(actor_role, 0) >= RANK[needed]


def stamp(payload):
    """Add actor/role to an audit-event payload when an actor is known (authenticated user or named system component)."""
    actor = current_actor.get()
    if actor is None or 'actor' in payload:
        return payload
    return {**payload, 'actor': actor.name, 'role': actor.role}

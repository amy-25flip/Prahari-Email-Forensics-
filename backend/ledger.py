"""Cross-session indicator ledger: "have we seen this indicator before, anywhere in this deployment?"

Privacy design (DPDP-conscious):
- Only keyed HMAC-SHA256 hashes of indicators are stored - never raw URLs, addresses, domains or IPs - plus the
  indicator kind, first/last-seen times, an analysis count and hashed session markers. Without the secret key the
  table cannot be reversed or dictionary-guessed; with it, a value can only be *checked*, not listed.
- No case content, subjects, bodies or case IDs are stored, so the ledger cannot reconstruct any email.
- Demo/sample cases never enter it; entries expire after LEDGER_RETENTION_DAYS (default 90).
- Session isolation is unchanged: a lookup reveals only aggregate counts, never which case or analyst.
Key handling: LEDGER_KEY (env, ideally from a secret manager) wins; otherwise a random 32-byte key is generated once in DATA_DIR/ledger.key
(owner-only permissions on POSIX; on Windows the file relies on the folder's ACLs, so set LEDGER_KEY there). Anyone holding the key can CHECK a
guessed indicator against the table (a dictionary attack on common domains), so protect it like any other secret.
Recurrence is informational - it never raises triage by itself."""
import hashlib
import hmac
import os
import secrets
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path

import store
from network_history import TRACKED_TYPES
from campaigns import indicators as extract_indicators

MAX_INDICATORS_PER_CASE = 50
_lock = threading.Lock()
_key_cache = {}


def enabled():
    return os.getenv('LEDGER_ENABLED', '1') != '0'


def retention_seconds():
    try:
        days = max(1, min(3650, int(os.getenv('LEDGER_RETENTION_DAYS', '90'))))
    except ValueError:
        days = 90
    return days * 86400


def _db_path():
    return Path(store.DATA) / 'ledger.sqlite'


def _key():
    env = os.getenv('LEDGER_KEY')
    if env:
        return env.encode()
    path = Path(store.DATA) / 'ledger.key'
    cached = _key_cache.get(str(path))
    if cached:
        return cached
    Path(store.DATA).mkdir(parents=True, exist_ok=True)
    if path.exists():
        key = path.read_bytes()
    else:
        key = secrets.token_bytes(32)
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'wb') as handle:
                handle.write(key)
        except FileExistsError:
            key = path.read_bytes()
    _key_cache[str(path)] = key
    return key


def _connect():
    Path(store.DATA).mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(_db_path(), timeout=10)
    db.execute('CREATE TABLE IF NOT EXISTS indicators (h TEXT PRIMARY KEY, kind TEXT NOT NULL, first_seen REAL NOT NULL, '
               'last_seen REAL NOT NULL, seen_count INTEGER NOT NULL)')
    db.execute('CREATE TABLE IF NOT EXISTS sessions (h TEXT NOT NULL, s TEXT NOT NULL, PRIMARY KEY (h, s))')
    return db


@contextmanager
def _open():
    db = _connect()
    try:
        with db:
            yield db
    finally:
        db.close()


def _hash(kind, value):
    return hmac.new(_key(), f'{kind}\x00{value}'.encode('utf-8', errors='replace'), hashlib.sha256).hexdigest()


def _session_marker(sid):
    return hmac.new(_key(), f'session\x00{sid}'.encode(), hashlib.sha256).hexdigest()[:32]


def pairs_for(report):
    """Tracked (kind, value) indicators of a report, bounded and sorted for determinism."""
    return sorted(pair for pair in extract_indicators(report) if pair[0] in TRACKED_TYPES)[:MAX_INDICATORS_PER_CASE]


def lookup(pairs, sid=None):
    """{(kind, value): {seen_count, distinct_sessions, other_sessions, first_seen, last_seen}} for indicators seen before."""
    if not enabled() or not pairs:
        return {}
    cutoff = time.time() - retention_seconds()
    marker = _session_marker(sid) if sid else None
    hits = {}
    with _lock, _open() as db:
        for kind, value in pairs:
            h = _hash(kind, value)
            row = db.execute('SELECT seen_count, first_seen, last_seen FROM indicators WHERE h=? AND last_seen>=?', (h, cutoff)).fetchone()
            if not row:
                continue
            sessions = [r[0] for r in db.execute('SELECT s FROM sessions WHERE h=?', (h,))]
            hits[(kind, value)] = {'seen_count': row[0], 'distinct_sessions': len(sessions),
                                   'other_sessions': len([s for s in sessions if s != marker]),
                                   'first_seen': row[1], 'last_seen': row[2]}
    return hits


def record(pairs, sid, now=None):
    """Count one analysis of these indicators. No-op when disabled."""
    if not enabled() or not pairs:
        return 0
    now = now or time.time()
    marker = _session_marker(sid or '')
    with _lock, _open() as db:
        db.execute('BEGIN IMMEDIATE')
        for kind, value in pairs:
            h = _hash(kind, value)
            db.execute('INSERT INTO indicators (h, kind, first_seen, last_seen, seen_count) VALUES (?,?,?,?,1) '
                       'ON CONFLICT(h) DO UPDATE SET last_seen=excluded.last_seen, seen_count=seen_count+1', (h, kind, now, now))
            db.execute('INSERT OR IGNORE INTO sessions (h, s) VALUES (?,?)', (h, marker))
    return len(pairs)


def cleanup(now=None):
    """Drop indicators (and their session markers) not seen within the retention window."""
    if not _db_path().exists():
        return 0
    cutoff = (now or time.time()) - retention_seconds()
    with _lock, _open() as db:
        db.execute('BEGIN IMMEDIATE')
        stale = [r[0] for r in db.execute('SELECT h FROM indicators WHERE last_seen<?', (cutoff,))]
        for h in stale:
            db.execute('DELETE FROM sessions WHERE h=?', (h,))
            db.execute('DELETE FROM indicators WHERE h=?', (h,))
    return len(stale)

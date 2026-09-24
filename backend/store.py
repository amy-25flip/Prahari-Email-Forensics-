"""Session-scoped evidence with transactional hash-chained events."""
import hashlib
import json
import os
import secrets
import sqlite3
import time
from pathlib import Path
import db_encryption

DATA = Path(os.getenv('DATA_DIR', str(Path(__file__).parent / 'data')))
RETENTION_SECONDS = max(1, min(168, int(os.getenv('RETENTION_HOURS', '24')))) * 3600
MAX_SESSIONS = int(os.getenv('MAX_SESSIONS', '1000'))
MAX_STORAGE = int(os.getenv('MAX_STORAGE_MB', '256')) * 1024 * 1024


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True)


def connect():
    DATA.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(DATA / 'cases.sqlite', timeout=10)
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA foreign_keys=ON')
    db.execute('PRAGMA secure_delete=ON')
    return db


def init():
    with connect() as db:
        db.executescript('''
        CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, expires REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS cases (id TEXT PRIMARY KEY, session TEXT REFERENCES sessions(id) ON DELETE CASCADE,
          created REAL, report TEXT, raw BLOB, report_hash TEXT);
        CREATE TABLE IF NOT EXISTS events (seq INTEGER PRIMARY KEY AUTOINCREMENT, session TEXT REFERENCES sessions(id) ON DELETE CASCADE,
          payload TEXT, previous TEXT, hash TEXT);
        ''')


def session(cookie):
    hashed = hashlib.sha256((cookie or '').encode()).hexdigest()
    with connect() as db:
        db.execute('BEGIN IMMEDIATE')
        db.execute('DELETE FROM sessions WHERE expires < ?', (time.time(),))
        if cookie and db.execute('SELECT id FROM sessions WHERE id=?', (hashed,)).fetchone(): return hashed, None
        if db.execute('SELECT COUNT(*) FROM sessions').fetchone()[0] >= MAX_SESSIONS:
            raise ValueError('Session capacity reached')
        cookie = secrets.token_urlsafe(32)
        hashed = hashlib.sha256(cookie.encode()).hexdigest()
        db.execute('INSERT INTO sessions VALUES (?,?)', (hashed, time.time() + RETENTION_SECONDS))
    return hashed, cookie


def cleanup():
    with connect() as db:
        db.execute('DELETE FROM sessions WHERE expires < ?', (time.time(),))


def append(db, sid, payload):
    row = db.execute('SELECT hash FROM events WHERE session=? ORDER BY seq DESC LIMIT 1', (sid,)).fetchone()
    previous = row['hash'] if row else '0' * 64
    encoded = canonical(payload)
    digest = hashlib.sha256((previous + encoded).encode()).hexdigest()
    db.execute('INSERT INTO events(session,payload,previous,hash) VALUES (?,?,?,?)', (sid, encoded, previous, digest))


def save(sid, report, raw):
    with connect() as db:
        db.execute('BEGIN IMMEDIATE')
        if db.execute('SELECT COUNT(*) FROM cases WHERE session=?', (sid,)).fetchone()[0] >= 30:
            raise ValueError('Session limit reached (30 emails). Delete cases first.')
        cid = secrets.token_hex(8)
        report.update(id=cid, created=time.time())
        encoded = canonical(report)
        used = db.execute('SELECT COALESCE(SUM(length(raw) + length(CAST(report AS BLOB))), 0) FROM cases').fetchone()[0]
        if used + len(raw) + len(encoded.encode()) > MAX_STORAGE:
            raise ValueError('Evidence storage capacity reached. Retry after case expiration or deletion.')
        rh = hashlib.sha256(encoded.encode()).hexdigest()
        stored_report, stored_raw = db_encryption.encrypt_text(encoded), db_encryption.encrypt_bytes(raw)
        db.execute('INSERT INTO cases VALUES (?,?,?,?,?,?)', (cid, sid, time.time(), stored_report, stored_raw, rh))
        append(db, sid, {'action': 'analyze', 'id': cid, 'raw_hash': report['sha256'], 'report_hash': rh, 'at': time.time()})
    return report


def get(sid, cid):
    with connect() as db: row = db.execute('SELECT report FROM cases WHERE session=? AND id=?', (sid, cid)).fetchone()
    return json.loads(db_encryption.decrypt_text(row['report'])) if row else None


def get_raw(sid, cid):
    with connect() as db: row = db.execute('SELECT raw FROM cases WHERE session=? AND id=?', (sid, cid)).fetchone()
    return db_encryption.decrypt_bytes(row['raw']) if row else None


def all_cases(sid):
    with connect() as db: rows = db.execute('SELECT report FROM cases WHERE session=? ORDER BY created DESC', (sid,)).fetchall()
    return [json.loads(db_encryption.decrypt_text(row['report'])) for row in rows]


def search_cases(sid, query):
    """Case-insensitive substring search across every case's subject, sender,
    recipient, findings, and indicator values -- not just the lightweight
    summary fields the plain case list exposes. Bounded by the same
    per-session case cap save() already enforces, so a linear scan over every
    decrypted report is cheap; no separate search index is needed at this scale.
    Defensive against a malformed/legacy stored report (None or non-list
    findings/indicators, or a non-dict entry inside either list) -- one bad
    row must degrade that row's search text, never 500 the whole listing."""
    needle = query.strip().casefold()
    if not needle: return all_cases(sid)
    matches = []
    for report in all_cases(sid):
        findings = report.get('findings') or []
        indicators = report.get('indicators') or []
        parts = [report.get('subject'), report.get('sender'), report.get('recipient')]
        parts += [f.get('title') for f in findings if isinstance(f, dict)]
        parts += [f.get('detail') for f in findings if isinstance(f, dict)]
        parts += [i.get('value') for i in indicators if isinstance(i, dict)]
        haystack = ' '.join(str(v) for v in parts if v).casefold()
        if needle in haystack: matches.append(report)
    return matches


# Analyst notes and case ownership/assignment are modelled the same way as
# review decisions (see main.py's /api/cases/{cid}/review): append-only audit
# events, never a separately-mutable row, so every analyst action stays inside
# the same tamper-evident hash chain as the rest of the evidence trail. Notes
# accumulate (every 'note' event is kept); assignment is single-current-state
# (only the latest 'assign' event for a case matters).

MAX_NOTES_PER_CASE = 50  # bounds events-table growth from repeated note-taking on one case


def list_notes(sid, cid, db=None):
    def _query(conn):
        rows = conn.execute("SELECT payload FROM events WHERE session=? ORDER BY seq", (sid,)).fetchall()
        notes = []
        for row in rows:
            event = json.loads(row['payload'])
            if event.get('action') == 'note' and event.get('id') == cid: notes.append(event)
        return notes

    if db is not None:
        return _query(db)
    with connect() as conn:
        return _query(conn)


def add_note(db, sid, cid, text):
    if len(list_notes(sid, cid, db=db)) >= MAX_NOTES_PER_CASE:
        raise ValueError(f'Note limit reached ({MAX_NOTES_PER_CASE} per case). Delete unneeded notes first.')
    event = {'action': 'note', 'id': cid, 'at': time.time(), 'text': text}
    append(db, sid, event)
    return event


def set_owner(db, sid, cid, owner):
    event = {'action': 'assign', 'id': cid, 'at': time.time(), 'owner': owner}
    append(db, sid, event)
    return event


def get_owner(sid, cid, db=None):
    def _query(conn):
        rows = conn.execute("SELECT payload FROM events WHERE session=? ORDER BY seq DESC", (sid,)).fetchall()
        for row in rows:
            event = json.loads(row['payload'])
            if event.get('action') == 'assign' and event.get('id') == cid: return event
        return None

    if db is not None:
        return _query(db)
    with connect() as conn:
        return _query(conn)


def case_events(sid, cid):
    """Hash-chained custody events that concern one case (analyze, notes, assignment, review, delete)."""
    events = []
    with connect() as db:
        for row in db.execute('SELECT seq, payload, previous, hash FROM events WHERE session=? ORDER BY seq', (sid,)):
            event = json.loads(row['payload'])
            if event.get('id') == cid:
                events.append({'seq': row['seq'], 'previous': row['previous'], 'hash': row['hash'], 'event': event})
    return events


def delete(sid, cid):
    with connect() as db:
        db.execute('BEGIN IMMEDIATE')
        removed = db.execute('DELETE FROM cases WHERE session=? AND id=?', (sid, cid)).rowcount
        if removed: append(db, sid, {'action': 'delete', 'id': cid, 'at': time.time()})
    return bool(removed)


def verify(sid):
    previous, count, created, deleted = '0' * 64, 0, {}, set()
    with connect() as db:
        # Without an explicit transaction, these two SELECTs each get their
        # own implicit read snapshot -- a case+event written by a concurrent
        # request for this same session (e.g. a second browser tab) between
        # them could make `found` and `created` legitimately diverge with
        # nothing actually corrupted, producing a false "tamper detected".
        # BEGIN (deferred; no write follows) pins one consistent snapshot for
        # the whole function, the same way save/delete/append use BEGIN
        # IMMEDIATE to make their own writes atomic.
        db.execute('BEGIN')
        for row in db.execute('SELECT * FROM events WHERE session=? ORDER BY seq', (sid,)):
            expected = hashlib.sha256((previous + row['payload']).encode()).hexdigest()
            if row['previous'] != previous or row['hash'] != expected: return {'valid': False, 'detail': 'Audit chain mismatch', 'checked': count}
            event = json.loads(row['payload'])
            if event['action'] == 'analyze': created[event['id']] = event
            if event['action'] == 'delete': deleted.add(event['id'])
            previous, count = row['hash'], count + 1
        found = set()
        for row in db.execute('SELECT * FROM cases WHERE session=?', (sid,)):
            found.add(row['id'])
            event = created.get(row['id'], {})
            report_plain = db_encryption.decrypt_text(row['report'])
            raw_plain = db_encryption.decrypt_bytes(row['raw'])
            if hashlib.sha256(report_plain.encode()).hexdigest() != event.get('report_hash') or hashlib.sha256(raw_plain).hexdigest() != event.get('raw_hash'):
                return {'valid': False, 'detail': 'Stored evidence differs from audit event', 'checked': count}
        if found != set(created) - deleted: return {'valid': False, 'detail': 'Case inventory differs from audit events', 'checked': count}
    return {'valid': True, 'checked': count, 'head': previous,
            'detail': 'Local chain and retained artifacts match. No independent checkpoint; full-chain rewriting or tail truncation may evade detection.'}


def connections(sid):
    reports, edges = all_cases(sid), []
    for i, left in enumerate(reports):
        for right in reports[i + 1:]:
            if left['sha256'] == right['sha256']: continue
            shared = [x for x in left['indicators'] if x in right['indicators']]
            if shared: edges.append({'source': left['id'], 'target': right['id'], 'evidence': shared,
                                     'assessment': 'Shared indicators; analyst confirmation required'})
    return {'nodes': [{'id': r['id'], 'subject': r['subject'], 'score': r['score'], 'sample': r.get('sample', False)} for r in reports], 'edges': edges}

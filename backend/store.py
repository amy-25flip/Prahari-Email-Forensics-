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


def delete(sid, cid):
    with connect() as db:
        db.execute('BEGIN IMMEDIATE')
        removed = db.execute('DELETE FROM cases WHERE session=? AND id=?', (sid, cid)).rowcount
        if removed: append(db, sid, {'action': 'delete', 'id': cid, 'at': time.time()})
    return bool(removed)


def verify(sid):
    previous, count, created, deleted = '0' * 64, 0, {}, set()
    with connect() as db:
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

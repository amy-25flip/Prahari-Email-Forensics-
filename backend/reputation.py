"""Local matching against the official PhishTank verified-online feed.

No submitted email URLs leave the process. Only the fixed feed URL is fetched.
"""
import bz2
import csv
import hashlib
import io
import json
import os
import threading
import time
from email.utils import parsedate_to_datetime
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit
import requests

SOURCE = 'PhishTank'
MAX_AGE = 24 * 3600
REFRESH_SECONDS = 3600 if os.getenv('PHISHTANK_APP_KEY') else 12 * 3600
CACHE_PATH = Path(os.getenv('REPUTATION_CACHE', str(Path(os.getenv('DATA_DIR', str(Path(__file__).parent / 'data'))) / 'phishtank.json')))
_snapshot = None
_last_error = None
_lock = threading.Lock()


def normalize(url):
    try:
        p = urlsplit(url.strip())
        if p.scheme.lower() not in ('http', 'https') or not p.hostname: return None
        host = p.hostname.encode('idna').decode('ascii').lower()
        if ':' in host: host = '[' + host + ']'
        port = p.port
        if port and (p.scheme.lower(), port) not in (('http', 80), ('https', 443)): host += ':' + str(port)
        if '@' in p.netloc: host = p.netloc.rsplit('@', 1)[0] + '@' + host
        return urlunsplit((p.scheme.lower(), host, p.path or '/', p.query, p.fragment))
    except (ValueError, UnicodeError): return None


def key(url):
    normalized = normalize(url)
    return hashlib.sha256(normalized.encode()).hexdigest() if normalized else None


def load():
    global _snapshot, _last_error
    if not CACHE_PATH.exists(): return
    try:
        if CACHE_PATH.stat().st_size > 80 * 1024 * 1024: raise ValueError('Cache too large')
        data = json.loads(CACHE_PATH.read_text(encoding='utf-8'))
        if data.get('source') != SOURCE or not isinstance(data.get('entries'), dict) or not data['entries']: raise ValueError('Invalid cache')
        fetched = data['fetched_at']
        if not isinstance(fetched, (int, float)) or not 0 < fetched <= time.time() + 300: raise ValueError('Invalid timestamp')
        if data.get('source_modified') is not None and (not isinstance(data['source_modified'], (int, float)) or data['source_modified'] <= 0): raise ValueError('Invalid source timestamp')
        for digest, entry in data['entries'].items():
            if len(digest) != 64 or not isinstance(entry, dict) or not str(entry.get('id', '')).isdigit(): raise ValueError('Invalid entry')
        _snapshot, _last_error = data, None
    except (ValueError, OSError, TypeError, KeyError): _last_error = 'Stored feed could not be validated'


def status(snapshot=None):
    data = _snapshot if snapshot is None else snapshot
    if not data: return {'source': SOURCE, 'status': 'unavailable', 'count': 0, 'fetched_at': None, 'detail': _last_error or 'Feed has not been downloaded'}
    timestamp = min(data['fetched_at'], data.get('source_modified') or data['fetched_at'])
    age = max(0, time.time() - timestamp)
    return {'source': SOURCE, 'status': 'fresh' if age <= MAX_AGE else 'stale', 'count': len(data['entries']),
            'fetched_at': data['fetched_at'], 'source_modified': data.get('source_modified'),
            'age_hours': round(age / 3600, 1), 'detail': _last_error or 'Local normalized-exact URL matching; absence is not a safety verdict'}


def lookup(url, snapshot=None):
    data = _snapshot if snapshot is None else snapshot
    info = status(data)
    entry = data['entries'].get(key(url)) if data else None
    return {**info, 'match': bool(entry), 'status': ('listed' if info['status'] == 'fresh' else 'listed_stale') if entry else ('not_listed' if info['status'] == 'fresh' else info['status']),
            'feed_status': info['status'], 'record_id': entry['id'] if entry else None,
            'verified_at': entry.get('verified_at') if entry else None,
            'detail': ('URL matched a verified-online feed entry at the recorded observation time.' if entry else 'No match in the available feed; this does not establish safety.') if data else info['detail']}


def annotate(urls):
    snapshot = _snapshot
    for url in urls: url['reputation'] = lookup(url['url'], snapshot)
    return status(snapshot)


def refresh(force=False):
    global _snapshot, _last_error
    if not _lock.acquire(blocking=False): return status()
    try:
        if not force and _snapshot and time.time() - _snapshot['fetched_at'] < REFRESH_SECONDS: return status()
        token = os.getenv('PHISHTANK_APP_KEY', '')
        if token and not token.isalnum(): raise ValueError('Invalid key format')
        url = 'https://data.phishtank.com/data/' + (token + '/' if token else '') + 'online-valid.csv.bz2'
        compressed = bytearray()
        with requests.get(url, headers={'User-Agent': 'AIEmailThreatDetection/0.2 academic research'}, stream=True, timeout=(5, 20)) as response:
            response.raise_for_status()
            started = time.monotonic()
            for chunk in response.iter_content(65536):
                compressed.extend(chunk)
                if len(compressed) > 25 * 1024 * 1024 or time.monotonic() - started > 60: raise ValueError('Feed size/time limit exceeded')
            modified = response.headers.get('Last-Modified')
        decoder = bz2.BZ2Decompressor()
        payload = decoder.decompress(bytes(compressed), max_length=100 * 1024 * 1024)
        if not decoder.eof: raise ValueError('Feed exceeds decompression limit or is incomplete')
        reader = csv.DictReader(io.StringIO(payload.decode('utf-8-sig')))
        if not {'phish_id', 'url', 'verified', 'online', 'verification_time'}.issubset(reader.fieldnames or []): raise ValueError('Unexpected feed schema')
        entries = {}
        for row in reader:
            if row['verified'] != 'yes' or row['online'] != 'yes': continue
            digest = key(row['url'])
            if digest and row['phish_id'].isdigit(): entries[digest] = {'id': row['phish_id'], 'verified_at': row['verification_time']}
            if len(entries) > 500000: raise ValueError('Feed entry limit exceeded')
        if not entries: raise ValueError('Empty feed rejected; previous snapshot preserved')
        source_modified = None
        if modified:
            try: source_modified = parsedate_to_datetime(modified).timestamp()
            except (TypeError, ValueError, OverflowError): pass
        candidate = {'source': SOURCE, 'fetched_at': time.time(), 'source_modified': source_modified,
                     'payload_sha256': hashlib.sha256(payload).hexdigest(), 'entries': entries}
        CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        temp = CACHE_PATH.with_suffix('.tmp')
        temp.write_text(json.dumps(candidate, separators=(',', ':')), encoding='utf-8')
        os.replace(temp, CACHE_PATH)
        _snapshot, _last_error = candidate, None
    except (requests.RequestException, OSError, ValueError, KeyError, csv.Error) as exc:
        _last_error = 'Refresh unavailable (' + type(exc).__name__ + '); last valid snapshot retained'
    finally: _lock.release()
    return status()


if __name__ == '__main__':
    load()
    print(json.dumps(refresh(), indent=2))

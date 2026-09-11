"""Opt-in VirusTotal hash reputation for attachment SHA-256 digests.

Only the hash is sent, never the file content. Absence of a report is not a clean verdict.
"""
import json
import re
import math
import os
import threading
import time
import requests
from collections import deque
from email.utils import parsedate_to_datetime

SOURCE = 'https://www.virustotal.com/api/v3/files/'
MAX_PER_ANALYSIS = 4  # Per-email work budget; the shared rolling-window limit is separate.
_cache = {}
_lock = threading.Lock()
_requests = deque()
_blocked_until = 0.0
_inflight = set()


def request_limit():
    try: return max(1, min(1000, int(os.getenv('VIRUSTOTAL_REQUESTS_PER_MINUTE', '4'))))
    except ValueError: return 4


def retry_delay(value):
    try:
        seconds=float(value)
        if not math.isfinite(seconds):raise ValueError()
        return max(60,seconds)
    except (ValueError,TypeError):
        try: return max(60,parsedate_to_datetime(value).timestamp()-time.time())
        except (ValueError,TypeError,OverflowError): return 60


def config():
    return os.getenv('VIRUSTOTAL_API_KEY', '') or None


def lookup_hash(sha256):
    global _blocked_until
    if not isinstance(sha256,str) or not re.fullmatch(r'[0-9a-fA-F]{64}',sha256):
        return {'sha256':sha256,'status':'not_checked','detail':'Invalid SHA-256 digest.'}
    sha256=sha256.lower()
    token = config()
    if not token:
        return {'sha256': sha256, 'status': 'disabled', 'detail': 'VIRUSTOTAL_API_KEY not configured.'}
    now = time.time()
    with _lock:
        cached = _cache.get(sha256)
        if cached and cached[0] > now: return {**cached[1], 'cached': True}
        tick=time.monotonic()
        while _requests and tick-_requests[0]>=60: _requests.popleft()
        delay=max(0,_blocked_until-tick)
        if len(_requests)>=request_limit():delay=max(delay,60-(tick-_requests[0]))
        if delay>0:
            return {'sha256':sha256,'status':'rate_limited','retry_after_seconds':math.ceil(delay),
                    'detail':'Shared VirusTotal request budget or provider backoff active; hash not queried.'}
        if sha256 in _inflight:
            return {'sha256':sha256,'status':'not_checked','detail':'This hash already has a lookup in progress; retry later.'}
        _requests.append(tick)
        _inflight.add(sha256)
    result = {'sha256': sha256, 'source': 'VirusTotal', 'observed_at': now, 'cached': False, 'status': 'unavailable'}
    try:
        with requests.get(SOURCE + sha256, headers={'x-apikey': token, 'Accept': 'application/json'},
                          timeout=(3, 10), stream=True, allow_redirects=False) as response:
            if response.status_code == 404:
                result.update(status='no_prior_reports', detail='No VirusTotal report for this hash; this is not a clean/benign verdict, only an absence of prior submissions.')
            elif response.status_code == 429:
                result.update(status='rate_limited', detail='VirusTotal quota exceeded; retry later.')
                delay=retry_delay(getattr(response,'headers',{}).get('Retry-After'))
                with _lock: _blocked_until=max(_blocked_until,time.monotonic()+delay)
                result['retry_after_seconds']=math.ceil(delay)
            elif response.status_code == 401:
                result.update(status='unavailable', detail='VirusTotal rejected the configured API key.')
            else:
                response.raise_for_status()
                chunks, total = [], 0
                for chunk in response.iter_content(8192):
                    total += len(chunk)
                    if total > 262144: raise ValueError('Oversized response')
                    chunks.append(chunk)
                payload = json.loads(b''.join(chunks))
                attributes = (payload.get('data') or {}).get('attributes')
                if not isinstance(attributes, dict): raise ValueError('Invalid provider response')
                stats = attributes.get('last_analysis_stats') or {}
                if not isinstance(stats,dict) or any(type(v) is not int or v<0 for v in stats.values()):
                    raise ValueError('Invalid engine statistics')
                malicious, suspicious = stats.get('malicious', 0) or 0, stats.get('suspicious', 0) or 0
                total_engines = sum(v for v in stats.values() if isinstance(v, int))
                result.update(status='available', malicious_count=malicious, suspicious_count=suspicious,
                              total_engines=total_engines, permalink=f'https://www.virustotal.com/gui/file/{sha256}',
                              detail=(f'{malicious} of {total_engines} engines flagged this file hash as malicious.' if total_engines
                                      else 'Report present but no engine statistics available.'))
    except (requests.RequestException, ValueError, TypeError, KeyError, AttributeError) as exc:
        result['detail'] = f'VirusTotal lookup unavailable ({type(exc).__name__}).'
    finally:
        with _lock:
            if len(_cache) >= 256: _cache.pop(next(iter(_cache)))
            _cache[sha256] = (now + (86400 if result['status'] in ('available', 'no_prior_reports') else 60), result)
            _inflight.discard(sha256)
    return result


def enrich(attachments, enabled):
    hashes = list(dict.fromkeys(a['sha256'] for a in attachments if a.get('size')))
    if not enabled or not config():
        detail = 'Attachment reputation lookup not enabled.' if not enabled else 'VIRUSTOTAL_API_KEY not configured.'
        return [{'sha256': h, 'status': 'disabled', 'detail': detail} for h in hashes]
    checked,uncached=[],0
    for h in hashes:
        with _lock: cached=h in _cache and _cache[h][0]>time.time()
        if cached or uncached<MAX_PER_ANALYSIS:
            checked.append(lookup_hash(h))
            if not cached:uncached+=1
        else:
            checked.append({'sha256':h,'status':'not_checked','detail':'Per-analysis uncached lookup budget exceeded; attachment not checked.'})
    return checked

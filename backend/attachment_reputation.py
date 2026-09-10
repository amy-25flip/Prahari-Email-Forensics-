"""Opt-in VirusTotal hash reputation for attachment SHA-256 digests.

Only the hash is sent, never the file content. Absence of a report is not a clean verdict.
"""
import json
import os
import threading
import time
import requests

SOURCE = 'https://www.virustotal.com/api/v3/files/'
MAX_PER_ANALYSIS = 4  # VirusTotal free-tier rate limit is 4 requests/minute.
_cache = {}
_lock = threading.Lock()


def config():
    return os.getenv('VIRUSTOTAL_API_KEY', '') or None


def lookup_hash(sha256):
    token = config()
    if not token:
        return {'sha256': sha256, 'status': 'disabled', 'detail': 'VIRUSTOTAL_API_KEY not configured.'}
    now = time.time()
    with _lock:
        cached = _cache.get(sha256)
        if cached and cached[0] > now: return {**cached[1], 'cached': True}
    result = {'sha256': sha256, 'source': 'VirusTotal', 'observed_at': now, 'cached': False, 'status': 'unavailable'}
    try:
        with requests.get(SOURCE + sha256, headers={'x-apikey': token, 'Accept': 'application/json'},
                          timeout=(3, 10), stream=True) as response:
            if response.status_code == 404:
                result.update(status='no_prior_reports', detail='No VirusTotal report for this hash; this is not a clean/benign verdict, only an absence of prior submissions.')
            elif response.status_code == 429:
                result.update(status='rate_limited', detail='VirusTotal quota exceeded; retry later.')
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
                malicious, suspicious = stats.get('malicious', 0) or 0, stats.get('suspicious', 0) or 0
                total_engines = sum(v for v in stats.values() if isinstance(v, int))
                result.update(status='available', malicious_count=malicious, suspicious_count=suspicious,
                              total_engines=total_engines, permalink=f'https://www.virustotal.com/gui/file/{sha256}',
                              detail=(f'{malicious} of {total_engines} engines flagged this file hash as malicious.' if total_engines
                                      else 'Report present but no engine statistics available.'))
    except (requests.RequestException, ValueError, TypeError, KeyError) as exc:
        result['detail'] = f'VirusTotal lookup unavailable ({type(exc).__name__}).'
    with _lock:
        if len(_cache) >= 256: _cache.pop(next(iter(_cache)))
        _cache[sha256] = (now + (86400 if result['status'] in ('available', 'no_prior_reports') else 60), result)
    return result


def enrich(attachments, enabled):
    hashes = list(dict.fromkeys(a['sha256'] for a in attachments if a.get('size')))
    if not enabled or not config():
        detail = 'Attachment reputation lookup not enabled.' if not enabled else 'VIRUSTOTAL_API_KEY not configured.'
        return [{'sha256': h, 'status': 'disabled', 'detail': detail} for h in hashes]
    checked = [lookup_hash(h) for h in hashes[:MAX_PER_ANALYSIS]]
    skipped = [{'sha256': h, 'status': 'not_checked',
                'detail': 'Per-analysis lookup budget exceeded (VirusTotal free-tier limit of 4 requests/minute); this attachment was not checked in this analysis.'}
               for h in hashes[MAX_PER_ANALYSIS:]]
    return checked + skipped

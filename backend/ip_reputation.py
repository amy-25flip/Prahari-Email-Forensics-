"""Opt-in AbuseIPDB reputation lookup: hosting/proxy/VPN classification and abuse history for reported IPs.

No email content is sent to the provider, only public IP addresses already extracted from headers.
"""
import ipaddress
import json
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
import requests

SOURCE = 'https://api.abuseipdb.com/api/v2/check'
_cache = {}
_lock = threading.Lock()


def config():
    return os.getenv('ABUSEIPDB_API_KEY', '') or None


def lookup(ip):
    ip = str(ipaddress.ip_address(ip))
    if not ipaddress.ip_address(ip).is_global:
        return {'ip': ip, 'status': 'not_public', 'detail': 'Private or reserved IP; not submitted to the provider.'}
    token = config()
    if not token:
        return {'ip': ip, 'status': 'disabled', 'detail': 'ABUSEIPDB_API_KEY not configured.'}
    now = time.time()
    with _lock:
        cached = _cache.get(ip)
        if cached and cached[0] > now: return {**cached[1], 'cached': True}
    result = {'ip': ip, 'source': 'AbuseIPDB', 'observed_at': now, 'cached': False, 'status': 'unavailable'}
    try:
        with requests.get(SOURCE, headers={'Key': token, 'Accept': 'application/json'},
                          params={'ipAddress': ip, 'maxAgeInDays': 90}, timeout=(3, 7), stream=True) as response:
            if response.status_code == 429:
                result.update(status='rate_limited', detail='AbuseIPDB quota exceeded; retry later.')
            elif response.status_code == 401:
                result.update(status='unavailable', detail='AbuseIPDB rejected the configured API key.')
            else:
                response.raise_for_status()
                chunks, total = [], 0
                for chunk in response.iter_content(8192):
                    total += len(chunk)
                    if total > 65536: raise ValueError('Oversized response')
                    chunks.append(chunk)
                payload = json.loads(b''.join(chunks))
                data = payload.get('data')
                if not isinstance(data, dict): raise ValueError('Invalid provider response')
                usage = str(data.get('usageType') or 'Unknown')
                usage_l = usage.lower()
                is_tor = bool(data.get('isTor'))
                anonymization_signal = is_tor or any(k in usage_l for k in ('hosting', 'data center', 'transit', 'vpn', 'proxy'))
                score = data.get('abuseConfidenceScore')
                if isinstance(score, (int, float)) and score > 50: anonymization_signal = True
                result.update(status='available', abuse_confidence_score=score, usage_type=usage,
                              isp=str(data.get('isp') or 'Unknown'), domain=str(data.get('domain') or ''),
                              is_tor=is_tor, total_reports=data.get('totalReports'),
                              anonymization_signal=anonymization_signal,
                              detail='Community-reported abuse history and usage classification; not proof of this message’s sender.')
    except (requests.RequestException, ValueError, TypeError, KeyError) as exc:
        result['detail'] = f'AbuseIPDB lookup unavailable ({type(exc).__name__}).'
    with _lock:
        if len(_cache) >= 256: _cache.pop(next(iter(_cache)))
        _cache[ip] = (now + (3600 if result['status'] == 'available' else 60), result)
    return result


def enrich(hops, enabled):
    ips = list(dict.fromkeys(ip for hop in hops for ip in hop.get('ips', [])))[:8]
    if not enabled or not config():
        detail = 'External IP reputation lookup not enabled.' if not enabled else 'ABUSEIPDB_API_KEY not configured.'
        return [{'ip': ip, 'status': 'disabled', 'detail': detail} for ip in ips]
    with ThreadPoolExecutor(max_workers=4) as pool:
        return list(pool.map(lookup, ips))

"""Bounded, cached public-IP enrichment; never invent coordinates."""
import ipaddress
import math
import time
import threading
from concurrent.futures import ThreadPoolExecutor
import requests

_cache = {}
_lock = threading.Lock()


def locate(ip):
    ip = str(ipaddress.ip_address(ip))
    if not ipaddress.ip_address(ip).is_global:
        return {'ip': ip, 'status': 'not_public', 'error': 'Private or reserved IP; not submitted to the provider.'}
    now = time.time()
    with _lock:
        cached = _cache.get(ip)
        if cached and cached[0] > now: return {**cached[1], 'cached': True}
    result = {'ip': ip, 'source': 'ipwho.is', 'observed_at': now, 'cached': False, 'status': 'unavailable'}
    try:
        with requests.get('https://ipwho.is/' + ip, timeout=(2, 4), stream=True) as response:
            if response.status_code == 429:
                result.update(status='rate_limited', error='IP provider quota exceeded; retry later.')
            else:
                response.raise_for_status()
                chunks, total = [], 0
                for chunk in response.iter_content(8192):
                    total += len(chunk)
                    if total > 65536: raise ValueError('Oversized response')
                    chunks.append(chunk)
                import json
                data = json.loads(b''.join(chunks))
                if not isinstance(data, dict): raise ValueError('Invalid provider response')
                if data.get('success') is not True: raise ValueError('Provider could not locate this IP')
                lat, lon = data.get('latitude'), data.get('longitude')
                if not all(isinstance(n, (int, float)) and not isinstance(n, bool) and math.isfinite(n) for n in (lat, lon)) or not (-90 <= lat <= 90 and -180 <= lon <= 180): raise ValueError('Invalid coordinates')
                connection = data.get('connection') or {}
                if not isinstance(connection, dict): raise ValueError('Invalid connection metadata')
                result.update(status='available', lat=lat, lon=lon, city=str(data.get('city') or 'Unknown'),
                              country=str(data.get('country') or 'Unknown'), region=str(data.get('region') or ''),
                              isp=str(connection.get('isp') or 'Unknown'), org=str(connection.get('org') or ''), asn=connection.get('asn'),
                              detail='Approximate infrastructure location. Header provenance and human location are unverified.')
    except (requests.RequestException, ValueError, TypeError) as exc:
        result['error'] = f'Geolocation unavailable ({type(exc).__name__}).'
    with _lock:
        if len(_cache) >= 512: _cache.pop(next(iter(_cache)))
        _cache[ip] = (now + (86400 if result['status'] == 'available' else 60), result)
    return result


def enrich(hops, enabled):
    ips = list(dict.fromkeys(ip for hop in hops for ip in hop['ips']))[:8]
    if not enabled: return [{'ip': ip, 'status': 'disabled', 'error': 'External IP lookup not enabled.'} for ip in ips]
    with ThreadPoolExecutor(max_workers=4) as pool: return list(pool.map(locate, ips))

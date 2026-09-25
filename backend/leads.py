"""Investigator leads: WHO TO CONTACT for a takedown or legal request, from public RDAP data (opt-in enrichment only).

Registrar/hosting abuse contacts and network owners for the sender domain and public relay IPs. Registrant data is usually
redacted and this never identifies the person behind a message: it says who can be asked, not who the actor is."""
import ipaddress
import json
import threading
from concurrent.futures import ThreadPoolExecutor
import time
from urllib.parse import urlsplit, urljoin
import requests
import domain_intelligence as di

CAVEAT = ('Leads identify organisations that can act on an abuse report or answer a legal request (registrar, hosting provider, network owner). '
          'Registrant details are usually redacted, and none of this identifies the person who sent the message.')
_cache, _ip_bootstrap, _lock = {}, {}, threading.Lock()
MAX_IPS = 3
RIR_RDAP_HOSTS = {'rdap.arin.net', 'rdap.db.ripe.net', 'rdap.apnic.net', 'rdap.lacnic.net', 'rdap.afrinic.net'}


def _vcard(entity):
    card = entity.get('vcardArray') or []
    rows = card[1] if len(card) == 2 and isinstance(card[1], list) else []
    def value(row):
        data = row[3] if len(row) > 3 else None
        if isinstance(data, str) and data.lower().startswith('mailto:'):
            data = data[7:]
        return str(data)[:256] if data else None
    def pick(field): return next((value(r) for r in rows if len(r) > 3 and r[0] == field and value(r)), None)
    return pick('fn'), pick('email')


def _walk(entities, depth=0):
    for entity in entities or []:
        if not isinstance(entity, dict) or depth > 4: continue
        yield entity
        yield from _walk(entity.get('entities'), depth + 1)




def _valid_rdap_redirect(location, base_url):
    target = urlsplit(urljoin(base_url, location or ''))
    if (target.scheme != 'https' or not target.hostname or target.username or target.password or target.port
            or target.query or target.fragment):
        return None
    host = target.hostname.lower()
    path = target.path or ''
    if host not in RIR_RDAP_HOSTS:
        return None
    if not (path == '/rdap' or path.startswith('/rdap/') or path.startswith('/ip/') or path.startswith('/domain/') or path.startswith('/registry/ip/') or path.startswith('/registry/domain/')):
        return None
    return target.geturl()


def fetch_rdap_json(url):
    """Fetch RDAP JSON with one tightly validated RIR redirect.

    domain_intelligence.fetch_json intentionally rejects all redirects for its broader callers. Network RDAP sometimes delegates
    between RIRs (for example RIPE -> ARIN). Leads can follow exactly one such handoff, but only to known HTTPS RIR RDAP hosts and
    only on RDAP-looking paths; this keeps the SSRF surface narrow and local to investigator leads.
    """
    current = url
    redirected = False
    for _ in range(2):
        with requests.get(current, headers={'Accept': 'application/rdap+json, application/json'}, timeout=(2, 3),
                          allow_redirects=False, stream=True) as response:
            if response.status_code in (301, 302, 303, 307, 308):
                if redirected:
                    raise ValueError('Second RDAP redirect rejected')
                nxt = _valid_rdap_redirect(response.headers.get('Location'), current)
                if not nxt:
                    raise ValueError('Unsafe RDAP redirect rejected')
                current, redirected = nxt, True
                continue
            if response.status_code != 200:
                raise ValueError('Registry lookup unavailable')
            chunks, size = [], 0
            for chunk in response.iter_content(8192):
                size += len(chunk)
                if size > 524288:
                    raise ValueError('Oversized registry response')
                chunks.append(chunk)
            data = json.loads(b''.join(chunks))
            if not isinstance(data, dict):
                raise ValueError('Invalid registry response')
            return data
    raise ValueError('RDAP redirect loop rejected')

def parse_domain(data):
    registered = next((e.get('eventDate') for e in data.get('events', []) if e.get('eventAction') == 'registration'), None)
    expires = next((e.get('eventDate') for e in data.get('events', []) if e.get('eventAction') == 'expiration'), None)
    registrar = abuse = None
    for entity in _walk(data.get('entities')):
        roles = entity.get('roles', [])
        name, email = _vcard(entity)
        if 'registrar' in roles and not registrar: registrar = name
        if 'abuse' in roles and email and not abuse: abuse = email
    return {'registrar': registrar, 'abuse_contact': abuse, 'registered_at': registered, 'expires_at': expires}


def parse_ip(data):
    abuse = None
    for entity in _walk(data.get('entities')):
        if 'abuse' in entity.get('roles', []):
            _, email = _vcard(entity)
            if email:
                abuse = email
                break
    return {'network': str(data.get('name') or '')[:128] or None, 'handle': str(data.get('handle') or '')[:64] or None,
            'country': data.get('country'), 'range': f"{data.get('startAddress')}-{data.get('endAddress')}" if data.get('startAddress') else None,
            'abuse_contact': abuse}


def _ip_endpoint(ip):
    kind = 'ipv6' if ip.version == 6 else 'ipv4'
    with _lock:
        saved = _ip_bootstrap.get(kind, (0, []))
    if saved[0] < time.time():                        # fetch outside the lock so concurrent lookups are not serialised
        data = di.fetch_json(f'https://data.iana.org/rdap/{kind}.json')
        services = [s for s in data.get('services', []) if (isinstance(s, list) and len(s) == 2 and isinstance(s[0], list) and isinstance(s[1], list))]
        saved = (time.time() + 86400, services)
        with _lock:
            _ip_bootstrap[kind] = saved
    services = saved[1]
    for cidrs, urls in services:
        try:
            matched = any(ip in ipaddress.ip_network(c, strict=False) for c in cidrs)
        except ValueError:
            continue
        if matched:
            return next((u for u in urls if isinstance(u, str) and u.startswith('https://')), None)
    return None


def _domain_lookup(domain):
    with di.lock:
        expired, services = di.bootstrap['expires'] < time.time(), di.bootstrap['services']
    if expired:                                       # fetch outside the shared lock so other domain lookups are not blocked
        data = di.fetch_json('https://data.iana.org/rdap/dns.json')
        with di.lock:
            di.bootstrap.update(expires=time.time() + 86400, services=data['services'])
        services = data['services']
    tld = domain.rsplit('.', 1)[-1]
    endpoint = next((u for suffixes, urls in services if tld in suffixes for u in urls if u.startswith('https://')), None)
    if not endpoint: return None
    return parse_domain(di.fetch_json(endpoint.rstrip('/') + '/domain/' + domain))


def _ip_lookup(ip):
    endpoint = _ip_endpoint(ip)
    return parse_ip(fetch_rdap_json(endpoint.rstrip('/') + '/ip/' + str(ip))) if endpoint else None


def _cached(key, fn):
    with _lock:
        saved = _cache.get(key)
        if saved and saved[0] > time.time(): return saved[1]
    try: value = fn()
    except Exception: value = None
    with _lock:
        if len(_cache) > 256: _cache.pop(next(iter(_cache)))
        _cache[key] = (time.time() + 3600, value)
    return value


def assess(report, enabled):
    if not enabled:
        return {'status': 'disabled', 'items': [], 'caveat': CAVEAT}
    now = time.time()
    jobs = []
    base = (report.get('domain_intelligence') or {}).get('registered_domain')
    if base and not base.endswith(('.example', '.invalid', '.test', '.localhost')):
        jobs.append(('registrar', base, lambda: _domain_lookup(base)))
    seen = []
    for hop in report.get('hops', []):
        for ip in hop.get('ips', []):
            try: addr = ipaddress.ip_address(ip)
            except ValueError: continue
            if addr.is_global and ip not in seen and len(seen) < MAX_IPS: seen.append(ip)
    for ip in seen:
        jobs.append(('network_owner', ip, lambda ip=ip: _ip_lookup(ipaddress.ip_address(ip))))
    items = []
    if jobs:
        with ThreadPoolExecutor(max_workers=len(jobs)) as pool:      # lookups are independent; run them together to bound added latency
            futures = [(kind, subject, pool.submit(_cached, (kind, subject), fn)) for kind, subject, fn in jobs]
            for kind, subject, future in futures:
                found = future.result()
                if found and any(found.values()):
                    items.append({'kind': kind, 'subject': subject, **found, 'source': 'RDAP (IANA bootstrap)', 'observed_at': now})
    return {'status': 'available' if items else 'unavailable', 'items': items, 'caveat': CAVEAT}

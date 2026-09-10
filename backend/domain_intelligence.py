"""Opt-in DNS and registry RDAP metadata; no visits to sender websites."""
import copy
import json
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlsplit
import dns.resolver
import requests
from publicsuffixlist import PublicSuffixList

psl = PublicSuffixList()
cache, bootstrap = {}, {'expires': 0, 'services': []}
lock = threading.Lock()


def dns_record(domain, kind):
    try:
        answer = dns.resolver.resolve(domain, kind, lifetime=2)
        values = [str(r)[:512] for r in answer][:10]
        return {'status': 'available', 'values': values}
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return {'status': 'none', 'values': []}
    except Exception:
        return {'status': 'unavailable', 'values': []}


def fetch_json(url):
    with requests.get(url, headers={'Accept':'application/rdap+json, application/json'},
                      timeout=(2, 3), allow_redirects=False, stream=True) as response:
        if response.status_code != 200: raise ValueError('Registry lookup unavailable')
        chunks, size = [], 0
        for chunk in response.iter_content(8192):
            size += len(chunk)
            if size > 524288: raise ValueError('Oversized registry response')
            chunks.append(chunk)
        data = json.loads(b''.join(chunks))
        if not isinstance(data, dict): raise ValueError('Invalid registry response')
        return data


def registration(domain):
    try:
        with lock:
            if bootstrap['expires'] < time.time():
                data = fetch_json('https://data.iana.org/rdap/dns.json')
                bootstrap.update(expires=time.time()+86400, services=data['services'])
            services = bootstrap['services']
        tld = domain.rsplit('.',1)[-1]
        endpoints = [url for suffixes, urls in services if tld in suffixes for url in urls]
        endpoint = next((url for url in endpoints if urlsplit(url).scheme == 'https'), None)
        if not endpoint: return {'status':'unavailable','detail':'No HTTPS registry endpoint in the IANA bootstrap.'}
        parsed = urlsplit(endpoint)
        if not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment: raise ValueError('Invalid registry endpoint')
        data = fetch_json(endpoint.rstrip('/')+'/domain/'+domain)
        registered = next((e.get('eventDate') for e in data.get('events',[]) if e.get('eventAction')=='registration'), None)
        registrar = None
        for entity in data.get('entities',[]):
            if 'registrar' not in entity.get('roles',[]): continue
            cards = entity.get('vcardArray',[])
            if len(cards)==2 and isinstance(cards[1],list):
                registrar = next((str(row[3])[:256] for row in cards[1] if len(row)>3 and row[0]=='fn'), None)
        return {'status':'available','source':parsed.hostname,'registered_at':registered,'registrar':registrar,
                'detail':'Registry metadata only; registrant personal details are not collected. Domain age is not proof of fraud.'}
    except (requests.RequestException, ValueError, KeyError, TypeError, AttributeError, IndexError):
        return {'status':'unavailable','detail':'Registry metadata unavailable; no risk penalty applied.'}


def lookup(domain, enabled):
    domain = domain.lower().strip('.')
    base = psl.privatesuffix(domain)
    result = {'domain':domain, 'registered_domain':base, 'status':'disabled', 'observed_at':time.time()}
    if not enabled: return result
    if (not base or domain.endswith(('.example','.invalid','.test','.localhost'))
            or len(domain)>253 or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',p) for p in domain.split('.'))):
        return {**result,'status':'not_public','detail':'No public registrable sender domain available.'}
    with lock:
        saved=cache.get(domain)
        if saved and saved[0]>time.time(): return {**copy.deepcopy(saved[1]),'cached':True}
    with ThreadPoolExecutor(max_workers=5) as pool:
        jobs={kind:pool.submit(dns_record,domain,kind) for kind in ('MX','NS','A','AAAA')}
        rdap=pool.submit(registration,base)
        result.update(status='completed',cached=False,dns={kind:job.result() for kind,job in jobs.items()},registration=rdap.result())
    with lock:
        if len(cache)>=256: cache.pop(next(iter(cache)))
        cache[domain]=(time.time()+600,copy.deepcopy(result))
    return result

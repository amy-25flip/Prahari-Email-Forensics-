"""Local exact-IP correlation against the Tor Project exit snapshot."""
import ipaddress
import threading
import time
import requests

SOURCE='https://check.torproject.org/torbulkexitlist'
_lock=threading.Lock()
_ips=frozenset()
_fetched=0
_attempt=0


def refresh():
    global _ips, _fetched, _attempt
    with _lock:
        now=time.time()
        if now-_attempt<300 or (_fetched and now-_fetched<21600): return
        _attempt=now
        try:
            with requests.get(SOURCE,timeout=(2,3),stream=True,allow_redirects=False) as response:
                if response.status_code!=200: return
                chunks=[]
                size=0
                for chunk in response.iter_content(8192):
                    size+=len(chunk)
                    if size>512000: return
                    chunks.append(chunk)
                values=b''.join(chunks).decode('ascii').splitlines()
                parsed=frozenset(str(ipaddress.ip_address(value.strip())) for value in values if value.strip())
                if parsed: _ips,_fetched=parsed,time.time()
        except (requests.RequestException,ValueError,UnicodeError): pass


def assess(hops, enabled):
    if not enabled: return {'status':'disabled','source':SOURCE,'matches':[], 'detail':'External intelligence disabled.'}
    refresh()
    with _lock: ips,fetched=_ips,_fetched
    state='unavailable' if not fetched else 'fresh' if 0<=time.time()-fetched<86400 else 'stale'
    observed={ip for hop in hops for ip in hop.get('ips',[])}
    return {'status':state,'source':SOURCE,'fetched_at':fetched or None,
            'matches':sorted(observed&ips),
            'detail':'Exact reported-IP matches to a Tor exit snapshot, not proof of Tor use at email delivery or malicious intent. No match is not a clean verdict. VPN coverage and open-relay detection are unavailable (open relay would need active probing, which is out of scope); botnet/netblock matches are under known_bad.'}

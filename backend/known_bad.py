"""Known-bad infrastructure feeds for relay IPs: abuse.ch Feodo Tracker (botnet C2 IPs) and Spamhaus DROP (hijacked/criminal netblocks).

Checked 2026-09-25: both are plain downloads that need no API key. Terms: feodotracker.abuse.ch/blocklist and spamhaus.org/drop
(free to download and use; we cache locally and do not redistribute). A match means the reported relay IP is listed as botnet
command-and-control or inside a listed netblock; it does NOT prove the sender machine is a bot. No match is not a clean verdict.
Open-relay detection is NOT provided: it would require actively probing mail servers, which is out of scope."""
import ipaddress
import re
import threading
import time
import requests

FEEDS = {
    'feodo_botnet_c2': {'url': 'https://feodotracker.abuse.ch/downloads/ipblocklist.txt', 'label': 'abuse.ch Feodo Tracker (botnet C2 IPs)'},
    'spamhaus_drop': {'url': 'https://www.spamhaus.org/drop/drop.txt', 'label': 'Spamhaus DROP (hijacked/criminal netblocks)'},
}
_lock = threading.Lock()
_state = {name: {'nets': (), 'fetched': 0, 'attempt': 0} for name in FEEDS}


def parse(text):
    nets = []
    for line in text.splitlines():
        value = re.split(r'[;#]', line, maxsplit=1)[0].strip()
        if not value: continue
        try: nets.append(ipaddress.ip_network(value, strict=False))
        except ValueError: continue
    return tuple(nets)


def refresh(name):
    entry = _state[name]
    now = time.time()
    if now - entry['attempt'] < 300 or (entry['fetched'] and now - entry['fetched'] < 21600): return
    entry['attempt'] = now
    try:
        with requests.get(FEEDS[name]['url'], timeout=(2, 4), stream=True, allow_redirects=False, headers={'User-Agent': 'prahari-forensics/1.0'}) as response:
            if response.status_code != 200: return
            data, size = [], 0
            for chunk in response.iter_content(8192):
                size += len(chunk)
                if size > 2_000_000: return
                data.append(chunk)
        nets = parse(b''.join(data).decode('utf-8', errors='ignore'))
        if nets: entry['nets'], entry['fetched'] = nets, time.time()
    except (requests.RequestException, ValueError): pass


def assess(hops, enabled):
    observed = []
    for hop in hops:
        for ip in hop.get('ips', []):
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError: continue
            if addr.is_global and str(addr) not in observed: observed.append(str(addr))
    out = {}
    for name, meta in FEEDS.items():
        if not enabled:
            out[name] = {'status': 'disabled', 'label': meta['label'], 'matches': []}
            continue
        with _lock:
            refresh(name)
            nets, fetched = _state[name]['nets'], _state[name]['fetched']
        status = 'unavailable' if not fetched else 'fresh' if 0 <= time.time() - fetched < 86400 else 'stale'
        matches = [ip for ip in observed if any(ipaddress.ip_address(ip) in net for net in nets if net.version == ipaddress.ip_address(ip).version)]
        out[name] = {'status': status, 'label': meta['label'], 'source': meta['url'], 'fetched_at': fetched or None, 'matches': matches}
    return out


def checks(result):
    found = []
    for name, entry in result.items():
        for ip in entry['matches']:
            what = 'known botnet command-and-control infrastructure' if name == 'feodo_botnet_c2' else 'a listed hijacked/criminal netblock'
            found.append({'kind': 'infrastructure', 'title': 'Relay IP on known-bad list', 'detail':
                          f"{ip} is listed by {entry['label']} ({what}; feed {entry['status']}). This does not prove the sender is a bot; review the hop context."})
    return found

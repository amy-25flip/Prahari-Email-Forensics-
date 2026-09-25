"""Times the full live-enrichment path (/api/analyze?enrich=true: DNS, RDAP, geolocation, Tor/Feodo/Spamhaus feeds, investigator leads)
against real services. One email per real public domain, each carrying that domain's real IPv4 in a Received header.
Each round is a FRESH process (empty feed/RDAP/DNS/geo caches). Per round it records: the very first request, the rest of the domains
(feed caches warm, domain caches cold) and a repeat pass (everything warm). Run from repo root:
    .venv/Scripts/python.exe benchmarks/live_enrichment_timing.py [rounds]
Writes benchmarks/live_enrichment_timing.json. Not reproducible offline; no third-party API keys are configured, so AbuseIPDB and
VirusTotal are NOT part of these timings."""
import json, os, socket, statistics, subprocess, sys, datetime, platform
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOMAINS = ['microsoft.com', 'python.org', 'mozilla.org', 'wikipedia.org', 'kernel.org', 'debian.org']

if len(sys.argv) > 1 and sys.argv[1] == '--child':
    import tempfile, time
    sys.path.insert(0, str(ROOT / 'backend'))
    os.environ.setdefault('MODEL_ID', str(ROOT / 'training' / 'output' / 'phishing-bert-v1' / 'final'))
    for key in ('ABUSEIPDB_API_KEY', 'VIRUSTOTAL_API_KEY'): os.environ.pop(key, None)
    import store
    store.DATA = Path(tempfile.mkdtemp(prefix='efp_live_'))
    import main
    from fastapi.testclient import TestClient
    H = {'X-Requested-With': 'Email-Threat-Detection'}

    def email(domain, ip):
        return (f'From: "Support" <alerts@{domain}>\nTo: user@example.org\nSubject: Account notice {domain}\nDate: Mon, 01 Sep 2025 10:00:00 +0000\n'
                f'Message-ID: <t-{domain}@fixture.example>\nReceived: from mail.{domain} ([{ip}]) by mx.example.org with ESMTP; Mon, 01 Sep 2025 10:00:01 +0000\n'
                f'Content-Type: text/plain\n\nYour account statement is ready. Sign in to review it.\n')

    ips = {}
    for d in DOMAINS:
        try: ips[d] = socket.gethostbyname(d)
        except OSError: pass
    out = {'first': None, 'cold_domains': {}, 'repeat': {}}
    with TestClient(main.app) as client:
        for _ in range(120):
            if main.local_model.status == 'ready': break
            time.sleep(1)
        for pass_name in ('cold', 'repeat'):
            for i, (d, ip) in enumerate(ips.items()):
                main.peer_limiter.reset(); main.limits.clear()
                r = client.post('/api/analyze?enrich=true', json={'email': email(d, ip)}, headers=H)
                if r.status_code != 200: sys.exit(f'{d}: {r.status_code} {r.text[:200]}')
                ms = r.json()['elapsed_ms']
                if pass_name == 'cold':
                    if i == 0: out['first'] = ms
                    else: out['cold_domains'][d] = ms
                else: out['repeat'][d] = ms
    print(json.dumps(out))
    sys.exit(0)

rounds = int(sys.argv[1]) if len(sys.argv) > 1 else 3
results = []
for _ in range(rounds):
    proc = subprocess.run([sys.executable, __file__, '--child'], capture_output=True, text=True, timeout=600)
    line = [l for l in proc.stdout.splitlines() if l.startswith('{')]
    if not line: sys.exit('child failed: ' + proc.stderr[-500:])
    results.append(json.loads(line[-1]))
firsts = [r['first'] for r in results]
cold = [v for r in results for v in r['cold_domains'].values()]
rep = [v for r in results for v in r['repeat'].values()]
summary = {
    'what': 'Server-measured elapsed_ms for /api/analyze?enrich=true against LIVE external services (DNS, RDAP, ipwho.is geolocation, Tor exit list, abuse.ch Feodo, Spamhaus DROP, investigator leads). '
            'No AbuseIPDB/VirusTotal keys configured, so those are not included. One email per real public domain with that domain\'s real IPv4 in a Received header. '
            'Each round is a fresh process with empty caches.',
    'measured_at': datetime.datetime.now().isoformat(timespec='seconds'), 'python': platform.python_version(), 'platform': platform.platform(),
    'rounds': rounds, 'domains': DOMAINS,
    'first_request_in_fresh_process_ms': {'values': firsts, 'median': statistics.median(firsts), 'max': max(firsts)},
    'later_domains_feeds_warm_domain_caches_cold_ms': {'median': statistics.median(cold), 'max': max(cold), 'min': min(cold), 'n': len(cold)},
    'repeat_all_warm_ms': {'median': statistics.median(rep), 'max': max(rep), 'n': len(rep)},
    'raw_rounds': results,
    'caveat': 'Depends on external service latency and this machine\'s network; treat as an order of magnitude, not a guarantee.'}
(ROOT / 'benchmarks' / 'live_enrichment_timing.json').write_text(json.dumps(summary, indent=2), encoding='utf-8')
print(json.dumps({k: v for k, v in summary.items() if k not in ('raw_rounds',)}, indent=2))

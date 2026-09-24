"""Times the local-only analysis path (no live enrichment) using the server's own
elapsed_ms field over the built-in sample emails. Full API path (incl. storing the case). Run from repo root:
    .venv/Scripts/python.exe benchmarks/api_timing.py
Writes benchmarks/local_analysis_api_timing.json."""
import json, os, statistics, sys, tempfile, platform, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'backend'))
os.environ.setdefault('EFP_DATA_DIR', tempfile.mkdtemp(prefix='efp_bench_'))

os.environ.setdefault('MODEL_ID', str(ROOT / 'training' / 'output' / 'phishing-bert-v1' / 'final'))
os.environ['DISABLE_FEED_REFRESH'] = '1'
import time
import store
store.DATA = Path(tempfile.mkdtemp(prefix='efp_bench_'))
import main
from fastapi.testclient import TestClient

RUNS = 100
HEADERS = {'X-Requested-With': 'Email-Threat-Detection'}

with TestClient(main.app) as client:
    for _ in range(120):
        if main.local_model.status == 'ready': break
        time.sleep(1)
    if main.local_model.status != 'ready': sys.exit(f'model not ready: {main.local_model.status} {main.local_model.detail}')
    samples = client.get('/api/samples').json()
    timings = []
    for i in range(RUNS):
        main.peer_limiter.reset(); main.limits.clear()
        raw = samples[i % len(samples)]['raw']
        r = client.post('/api/analyze', json={'email': raw}, headers=HEADERS)
        if r.status_code != 200: sys.exit(f"run {i}: {r.status_code} {r.text}")
        body = r.json()
        timings.append(body['elapsed_ms'])
        client.delete(f"/api/cases/{body['id']}", headers=HEADERS)

warm = timings[3:]
def pct(data, p):
    s = sorted(data); return s[min(len(s) - 1, int(len(s) * p / 100))]

out = {
    'what': 'server-measured elapsed_ms, local-only path (no live enrichment), BERT model loaded, built-in sample emails, in-process TestClient',
    'model': main.local_model.status,
    'runs': RUNS, 'warmup_discarded': 3, 'samples_used': len(samples),
    'median_ms': statistics.median(warm), 'mean_ms': round(statistics.mean(warm), 1),
    'p95_ms': pct(warm, 95), 'max_ms': max(warm), 'min_ms': min(warm),
    'raw_ms': timings,
    'python': platform.python_version(), 'platform': platform.platform(),
    'measured_at': datetime.datetime.now().isoformat(timespec='seconds'),
}
(ROOT / 'benchmarks' / 'local_analysis_api_timing.json').write_text(json.dumps(out, indent=2))
print({k: v for k, v in out.items() if k != 'raw_ms'})

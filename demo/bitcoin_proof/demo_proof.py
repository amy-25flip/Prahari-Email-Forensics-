"""Pre-confirmed Bitcoin-anchoring demo proof.

  stamp : analyze a built-in sample, take the real hash-chain checkpoint head, submit ONLY its
          SHA-256 to the public OpenTimestamps calendars, save digest + proof here.
  check : re-check / upgrade the saved proof; once a Bitcoin block includes it, the status becomes
          'confirmed' and the upgraded proof is written back.

Run from repo root: .venv/Scripts/python.exe demo/bitcoin_proof/demo_proof.py stamp|check
Confirmation takes hours - run `stamp` early, `check` later, and show the confirmed result live."""
import datetime, json, os, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
OUT = Path(__file__).resolve().parent / 'demo_proof.json'
sys.path.insert(0, str(ROOT / 'backend'))
import blockchain_timestamp as bt


def stamp():
    os.environ['DISABLE_ML'] = '1'; os.environ['DISABLE_FEED_REFRESH'] = '1'
    import store; store.DATA = Path(tempfile.mkdtemp(prefix='efp_proof_'))
    import main
    from fastapi.testclient import TestClient
    with TestClient(main.app) as c:
        h = {'X-Requested-With': 'Email-Threat-Detection'}
        c.post('/api/samples/account', headers=h)
        snap = c.get('/api/checkpoint').json()
    result = bt.stamp(snap['head'])
    if 'proof' not in result: sys.exit(f'stamp failed: {result}')
    OUT.write_text(json.dumps({
        'purpose': 'Demo: SHA-256 head of a real hash-chained case log, anchored via OpenTimestamps.',
        'submitted_at': datetime.datetime.now().astimezone().isoformat(timespec='seconds'),
        'checkpoint': snap, 'sha256': result['sha256'], 'proof': result['proof'],
        'status': result['status'], 'calendars_used': result['calendars_used']}, indent=2))
    print('stamped:', result['status'], result['sha256'])


def check():
    d = json.loads(OUT.read_text())
    r = bt.check(d['sha256'], d['proof'])
    d.update(status=r['status'], proof=r.get('proof', d['proof']),
             last_checked=datetime.datetime.now().astimezone().isoformat(timespec='seconds'))
    if r['status'] == 'confirmed':
        d['confirmation'] = {k: v for k, v in r.items() if k not in ('proof', 'sha256')}
    OUT.write_text(json.dumps(d, indent=2))
    print({k: v for k, v in r.items() if k != 'proof'})


if __name__ == '__main__':
    {'stamp': stamp, 'check': check}[sys.argv[1] if len(sys.argv) > 1 else 'check']()

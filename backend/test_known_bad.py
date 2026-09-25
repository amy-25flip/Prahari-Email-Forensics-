import known_bad

FEODO = '# header\n#\n# DstIP\n162.243.103.246\n34.204.119.63\n'
DROP = '; comment\n1.10.16.0/20 ; SBL256894\n2.57.232.0/23 ; SBL538946\n'


def test_parse():
    assert len(known_bad.parse(FEODO)) == 2 and len(known_bad.parse(DROP)) == 2
    assert known_bad.parse('garbage\n; only comments') == ()


def load(monkeypatch):
    import time
    monkeypatch.setitem(known_bad._state, 'feodo_botnet_c2', {'nets': known_bad.parse(FEODO), 'fetched': time.time(), 'attempt': time.time()})
    monkeypatch.setitem(known_bad._state, 'spamhaus_drop', {'nets': known_bad.parse(DROP), 'fetched': time.time(), 'attempt': time.time()})


def test_matches_exact_and_cidr_and_ignores_private(monkeypatch):
    load(monkeypatch)
    hops = [{'ips': ['162.243.103.246', '10.0.0.5']}, {'ips': ['1.10.20.9', '8.8.8.8']}]
    out = known_bad.assess(hops, True)
    assert out['feodo_botnet_c2']['matches'] == ['162.243.103.246']
    assert out['spamhaus_drop']['matches'] == ['1.10.20.9']
    assert out['feodo_botnet_c2']['status'] == 'fresh'
    found = known_bad.checks(out)
    assert found and 'does not prove' in found[0]['detail']


def test_disabled_and_unavailable(monkeypatch):
    assert known_bad.assess([{'ips': ['8.8.8.8']}], False)['feodo_botnet_c2']['status'] == 'disabled'
    monkeypatch.setitem(known_bad._state, 'feodo_botnet_c2', {'nets': (), 'fetched': 0, 'attempt': 10**12})
    monkeypatch.setitem(known_bad._state, 'spamhaus_drop', {'nets': (), 'fetched': 0, 'attempt': 10**12})
    out = known_bad.assess([{'ips': ['8.8.8.8']}], True)
    assert out['feodo_botnet_c2']['status'] == 'unavailable' and not known_bad.checks(out)



def reset_state(monkeypatch):
    for name in known_bad.FEEDS:
        monkeypatch.setitem(known_bad._state, name, {'nets': (), 'fetched': 0, 'attempt': 0})


class Resp:
    def __init__(self, status, body):
        self.status_code = status
        self.body = body.encode()
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def iter_content(self, _):
        yield self.body


def test_refreshes_feeds_concurrently(monkeypatch):
    import time
    reset_state(monkeypatch)
    starts = []
    def fake_get(url, **kwargs):
        starts.append((url, time.perf_counter()))
        time.sleep(0.2)
        body = FEODO if 'feodo' in url else DROP
        return Resp(200, body)
    monkeypatch.setattr(known_bad.requests, 'get', fake_get)
    started = time.perf_counter()
    out = known_bad.assess([{'ips': ['162.243.103.246', '1.10.20.9']}], True)
    elapsed = time.perf_counter() - started
    assert elapsed < 0.35
    assert len(starts) == 2 and abs(starts[0][1] - starts[1][1]) < 0.12
    assert out['feodo_botnet_c2']['matches'] == ['162.243.103.246']
    assert out['spamhaus_drop']['matches'] == ['1.10.20.9']


def test_one_feed_failure_does_not_block_other_and_throttle_prevents_refetch(monkeypatch):
    reset_state(monkeypatch)
    calls = []
    def fake_get(url, **kwargs):
        calls.append(url)
        if 'feodo' in url:
            raise known_bad.requests.Timeout('slow')
        return Resp(200, DROP)
    monkeypatch.setattr(known_bad.requests, 'get', fake_get)
    out = known_bad.assess([{'ips': ['1.10.20.9']}], True)
    assert out['feodo_botnet_c2']['status'] == 'unavailable'
    assert out['spamhaus_drop']['matches'] == ['1.10.20.9']
    out2 = known_bad.assess([{'ips': ['1.10.20.9']}], True)
    assert len(calls) == 2
    assert out2['spamhaus_drop']['matches'] == ['1.10.20.9']

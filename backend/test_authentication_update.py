import json
from email import policy
from email.parser import BytesParser
import pytest
import authentication as auth
import geolocation as geo
import spf
from test_day_one import signed_mail
from test_selection import client, HEADERS

RAW = b'From: Analyst <person@example.org>\r\nSubject: Test\r\n\r\nHello\r\n'
CONTEXT = {'client_ip': '8.8.8.8', 'mail_from': 'person@example.org', 'helo': 'mail.example.org'}

def check(raw=RAW, context=None, live=True):
    return auth.authenticate(BytesParser(policy=policy.default).parsebytes(raw), raw, live, 'upload', context)

@pytest.fixture
def dns_policy(monkeypatch):
    class TXT:
        strings = [b'v=DMARC1; p=reject; aspf=s; adkim=s']
    monkeypatch.setattr(auth.dns.resolver, 'resolve', lambda *a, **k: [TXT()])

@pytest.mark.parametrize('status,expected', [('pass','pass'),('fail','fail'),('softfail','fail'),('neutral','fail'),('none','fail'),('temperror','unknown'),('permerror','fail')])
def test_spf_without_dkim(monkeypatch, dns_policy, status, expected):
    def evaluate(**kwargs):
        assert kwargs['i'] == CONTEXT['client_ip']
        assert kwargs['s'] == CONTEXT['mail_from']
        return status, 'Test result'
    monkeypatch.setattr(auth.spf, 'check2', evaluate)
    result = check(context=CONTEXT)
    assert result['spf']['status'] == status
    assert result['dkim']['status'] == 'missing'
    assert result['dmarc']['status'] == expected
    assert 'analyst-supplied' in result['spf']['context_source']

def test_missing_context_not_inferred_from_headers(dns_policy):
    result = check(b'Authentication-Results: forged; spf=pass; dmarc=pass\r\n' + RAW)
    assert result['spf']['status'] == result['dmarc']['status'] == 'unknown'

def test_offline_no_dns(monkeypatch):
    def forbidden(*a, **k): pytest.fail('Network used offline')
    monkeypatch.setattr(auth.dns.resolver, 'resolve', forbidden)
    assert check(live=False)['spf']['status'] == 'unknown'

def test_real_spf_mechanism():
    assert spf.query(i='8.8.8.8', s='a@example.org', h='example.org').check(spf='v=spf1 ip4:8.8.8.8 -all')[0] == 'pass'
    assert spf.query(i='1.1.1.1', s='a@example.org', h='example.org').check(spf='v=spf1 ip4:8.8.8.8 -all')[0] == 'fail'

def test_multiple_signatures_any_valid(signed_mail):
    bad = b'DKIM-Signature: v=1; a=rsa-sha256; d=example.org; s=bad; b=bad\r\n'
    result = check(bad + signed_mail)
    assert result['dkim']['status'] == result['dmarc']['status'] == 'pass'
    assert len(result['dkim']['signatures']) == 2

def test_tree_boundaries_and_limit():
    calls = []
    def txt(name):
        calls.append(name)
        return ['v=DMARC1; p=reject; psd=y'] if name == '_dmarc.co.test' else []
    lookup = auth.PolicyLookup(txt)
    assert lookup.organization('mail.company.co.test') == 'company.co.test'
    assert not lookup.aligned('attacker.co.test', 'company.co.test', 'r')
    calls.clear()
    auth.PolicyLookup(lambda name: calls.append(name) or []).walk('a.b.c.d.e.f.g.h.i.j.test')
    assert len(calls) == 8

@pytest.mark.parametrize('context', [dict(CONTEXT, client_ip='invalid'),dict(CONTEXT, trusted=True),dict(CONTEXT, helo='bad host')])
def test_api_rejects_invalid_context(client, context):
    response = client.post('/api/analyze?enrich=true', json={'email':RAW.decode()}, headers={**HEADERS, 'X-SMTP-Context':json.dumps(context)})
    assert response.status_code == 400

def test_context_requires_enrichment(client):
    assert client.post('/api/analyze', json={'email':RAW.decode()}, headers={**HEADERS,'X-SMTP-Context':json.dumps(CONTEXT)}).status_code == 400

@pytest.mark.parametrize('ip', ['127.0.0.1','192.0.2.1','::1','10.0.0.1'])
def test_private_ips_never_submitted(monkeypatch, ip):
    monkeypatch.setattr(geo.requests, 'get', lambda *a, **k: pytest.fail('Reserved IP submitted'))
    assert geo.locate(ip)['status'] == 'not_public'

@pytest.mark.parametrize('payload,status', [({'success':True,'latitude':0,'longitude':0},'available'),({'success':True,'latitude':999,'longitude':0},'unavailable'),([], 'unavailable'),({'success':True,'latitude':1,'longitude':1,'connection':[]},'available')])
def test_geo_validation_and_cache(monkeypatch, payload, status):
    geo._cache.clear()
    calls = []
    class Response:
        status_code = 200
        def __enter__(self): return self
        def __exit__(self,*a): pass
        def raise_for_status(self): pass
        def iter_content(self,size): yield json.dumps(payload).encode()
    monkeypatch.setattr(geo.requests,'get',lambda *a,**k: calls.append(a) or Response())
    assert geo.locate('8.8.8.8')['status'] == status
    assert geo.locate('8.8.8.8')['cached']
    assert len(calls) == 1

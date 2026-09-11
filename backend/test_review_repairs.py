import copy
from email.message import EmailMessage
from concurrent.futures import ThreadPoolExecutor
import threading
import pytest
from test_selection import client, HEADERS
from test_attachment_reputation import FakeResponse
import engine
import attribution
import ps_assessment
import attachment_reputation as ar
import infrastructure
import ip_reputation


@pytest.fixture(autouse=True)
def quota_reset(monkeypatch):
    ar._cache.clear()
    ar._requests.clear()
    ar._inflight.clear()
    monkeypatch.setattr(ar,'_blocked_until',0.0)
    monkeypatch.setenv('VIRUSTOTAL_API_KEY','controlled-test-only')
    monkeypatch.setenv('VIRUSTOTAL_REQUESTS_PER_MINUTE','4')


@pytest.mark.parametrize('malicious,expected',[(50,'urgent'),(1,'review'),(0,'routine')])
def test_vt_result_reaches_stored_triage(client,monkeypatch,malicious,expected):
    msg=EmailMessage()
    msg['From']='sender@example.com'
    msg['Subject']='Meeting notes'
    msg.set_content('Minutes from our meeting.')
    msg.add_attachment(b'%PDF-1.4 normal content',maintype='application',subtype='pdf',filename='notes.pdf')
    raw=msg.as_bytes()
    monkeypatch.setattr(engine.ml,'classify',lambda text:{'status':'ready','label':'benign','phishing_probability':1,'confidence':99,'detail':'test'})
    baseline=engine.analyze(raw)
    monkeypatch.setattr(engine,'analyze',lambda *args:copy.deepcopy(baseline))
    monkeypatch.setattr(infrastructure,'assess',lambda *args:{'matches':[]})
    monkeypatch.setattr(ip_reputation,'enrich',lambda *args:[])
    monkeypatch.setattr(ar,'enrich',lambda *args:[{'sha256':baseline['attachments'][0]['sha256'],'status':'available','malicious_count':malicious,'suspicious_count':0}])
    result=client.post('/api/analyze?enrich=true',content=raw,headers=HEADERS).json()
    assert result['triage']['priority']==expected
    assert result['fraud_score']==result['score']
    if malicious:
        assert result['score']>0 and result['assessment']['categories']==['suspicious']
        assert any(f['group']=='reputation' for f in result['findings'])
    else:assert result['score']==0
    assert client.get('/api/cases/'+result['id']).json()==result
    assert client.get('/api/verify').json()['valid']


@pytest.mark.parametrize('status',['no_prior_reports','unavailable','rate_limited','disabled'])
def test_missing_reports_do_not_escalate(status):
    from reputation_triage import apply
    report={'attachments':[{'sha256':'a'*64}],'assessment':{'attachment_reputation':[{'sha256':'a'*64,'status':status,'malicious_count':99}]},'score':0}
    original=copy.deepcopy(report)
    apply(report)
    assert report==original


def test_google_redirect_context_not_risk():
    result=engine.scan_url('https://accounts.google.com/AccountChooser?continue=https://myaccount.google.com/notifications')
    assert result['score']==0
    assert 'Redirect remains within registrable domain' in result['reasons']


@pytest.mark.parametrize('source,target',[
    ('accounts.google.com','google.com.attacker.example'),
    ('a.github.io','b.github.io'),
    ('accounts.google.com','evil.example'),
])
def test_cross_domain_and_tenant_redirects_preserved(source,target):
    result=engine.scan_url(f'https://{source}/?continue=https://{target}/')
    assert 'Redirect parameter points to another host' in result['reasons']
    assert result['score']>=20


def test_same_domain_not_blanket_exemption():
    result=engine.scan_url('http://user:password@accounts.google.com/login?continue=https://myaccount.google.com/')
    assert result['score']>=40


@pytest.mark.parametrize('label',['benign','legitimate',' BENIGN '])
def test_legitimate_labels_normalized(label):
    report={'findings':[],'score':0,'ml':{'label':label,'status':'ready'},'authentication':{'dmarc':{'status':'unknown'}}}
    assert ps_assessment.inspect(b'From: a@example.com\r\n\r\n',report)['categories']==['legitimate']
    report['ml']['status']='unavailable'
    assert ps_assessment.inspect(b'From: a@example.com\r\n\r\n',report)['categories']==['undetermined']


def test_routing_warning_removes_bonus_and_duplicates_not_double_counted():
    warning={'kind':'routing','title':'Possible relay loop'}
    report={'hops':[{}],'assessment':{'checks':[warning,warning],'origin_evidence':{'confidence':'low'}}}
    factors={f['factor']:f for f in attribution.assess(report)['factors']}
    assert not factors['no_header_conflicts']['applied']
    assert factors['header_conflicts']['weight']==10
    report['assessment']['checks']=[]
    report['conflicts']=[{'id':'model-payment'}]
    assert next(f for f in attribution.assess(report)['factors'] if f['factor']=='no_header_conflicts')['applied']


def test_unknown_registration_age_not_positive():
    result=attribution.assess({'domain_intelligence':{'registration':{'status':'available'}}})
    assert not next(f for f in result['factors'] if f['factor']=='domain_registration')['applied']


def test_shared_quota_window_cache_and_new_email(monkeypatch):
    clock=[100.0]
    monkeypatch.setattr(ar.time,'monotonic',lambda:clock[0])
    calls=[]
    monkeypatch.setattr(ar.requests,'get',lambda url,**kw:(calls.append(url) or FakeResponse(404)))
    for i in range(4): assert ar.lookup_hash(f'{i:064x}')['status']=='no_prior_reports'
    assert ar.lookup_hash(f'{4:064x}')['status']=='rate_limited'
    assert ar.lookup_hash(f'{0:064x}')['cached']
    assert len(calls)==4
    clock[0]+=60
    assert ar.lookup_hash(f'{4:064x}')['status']=='no_prior_reports'
    assert len(calls)==5


def test_retry_after_blocks_other_hashes(monkeypatch):
    clock=[100.0]
    monkeypatch.setattr(ar.time,'monotonic',lambda:clock[0])
    response=FakeResponse(429)
    response.headers={'Retry-After':'120'}
    calls=[]
    monkeypatch.setattr(ar.requests,'get',lambda *a,**kw:(calls.append(1) or response))
    ar.lookup_hash('a'*64)
    assert ar.lookup_hash('b'*64)['status']=='rate_limited'
    clock[0]+=61
    assert ar.lookup_hash('c'*64)['status']=='rate_limited'
    assert len(calls)==1
    clock[0]+=60
    ar.lookup_hash('d'*64)
    assert len(calls)==2


def test_same_hash_concurrent_requests_coalesced(monkeypatch):
    started=threading.Event()
    release=threading.Event()
    calls=[]
    def get(*args,**kwargs):
        calls.append(1)
        started.set()
        assert release.wait(3)
        return FakeResponse(404)
    monkeypatch.setattr(ar.requests,'get',get)
    with ThreadPoolExecutor(max_workers=2) as pool:
        first=pool.submit(ar.lookup_hash,'a'*64)
        try:
            assert started.wait(3)
            assert ar.lookup_hash('a'*64)['status']=='not_checked'
        finally:release.set()
        assert first.result()['status']=='no_prior_reports'
    assert ar.lookup_hash('a'*64)['cached'] and len(calls)==1

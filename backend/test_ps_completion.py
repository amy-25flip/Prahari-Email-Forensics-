import copy
from test_selection import client, HEADERS
import campaigns
import ps_assessment
import infrastructure
import time
from email.message import EmailMessage


def test_redacted_exports_preserve_original(client):
    report=client.post('/api/samples/account',headers=HEADERS).json()
    for fmt in ('json','pdf','csv','cef'):
        response=client.get(f"/api/cases/{report['id']}/export/{fmt}?privacy=redacted")
        assert response.status_code==200
        if fmt!='pdf':
            assert report['sender'] not in response.text
            assert report['subject'] not in response.text
    masked=client.get(f"/api/cases/{report['id']}/export/json?privacy=redacted").json()
    assert masked['body']=='[REDACTED]' and not masked['headers']
    assert masked['sha256']==report['sha256']
    assert client.get('/api/cases/'+report['id']).json()==report
    assert client.get('/api/verify').json()['valid']
    assert client.get(f"/api/cases/{report['id']}/export/json?privacy=bad").status_code==400


def test_campaign_api(client):
    client.post('/api/samples/account',headers=HEADERS)
    client.post('/api/samples/invoice',headers=HEADERS)
    data=client.get('/api/campaigns').json()
    assert len(data['campaigns'])==1
    assert data['campaigns'][0]['count']==2


def test_static_attachment_and_identity(client):
    msg=EmailMessage()
    msg['From']='"boss@trusted.example" <outsider@other.example>'
    msg['Subject']='Document'
    msg['Message-ID']='not-an-id'
    msg.set_content('Please review')
    msg.add_attachment(b'MZ'+b'0'*100,maintype='application',subtype='octet-stream',filename='invoice.pdf')
    response=client.post('/api/analyze',content=msg.as_bytes(),headers=HEADERS)
    assert response.status_code==200
    assessment=response.json()['assessment']
    assert 'impersonated' in assessment['categories']
    assert {'Malformed Message-ID','Executable attachment content','Display-name address differs'} <= {x['title'] for x in assessment['checks']}
    redacted=client.get('/api/cases/'+response.json()['id']+'/export/json?privacy=redacted').json()
    assert 'assessment' not in redacted


def test_header_clock_skew_is_qualified():
    report={'findings':[],'ml':{'label':'unavailable'},'score':0,'authentication':{'dmarc':{'status':'unknown'}}}
    raw=b'Received: by b; Thu, 10 Sep 2026 01:00:00 +0000\r\nReceived: by a; Thu, 10 Sep 2026 02:00:00 +0000\r\n\r\n'
    assessment=ps_assessment.inspect(raw,report)
    assert assessment['checks'][0]['title']=='Relay timestamp reversal'
    assert assessment['categories']==['suspicious']


def test_tor_match_and_stale(monkeypatch):
    monkeypatch.setattr(infrastructure,'refresh',lambda:None)
    monkeypatch.setattr(infrastructure,'_ips',frozenset({'1.1.1.1'}))
    monkeypatch.setattr(infrastructure,'_fetched',time.time())
    assert infrastructure.assess([{'ips':['1.1.1.1']}],True)['matches']==['1.1.1.1']
    monkeypatch.setattr(infrastructure,'_fetched',time.time()-90000)
    assert infrastructure.assess([],True)['status']=='stale'
    assert infrastructure.assess([],False)['status']=='disabled'


def test_review_requires_acknowledgement_and_logs(client):
    report=client.post('/api/samples/account',headers=HEADERS).json()
    path='/api/cases/'+report['id']+'/review'
    assert client.get(path).json()['decision']=='pending'
    payload={'decision':'approved','note':'Verified through a separate known contact.','acknowledged':False}
    assert client.post(path,json=payload,headers=HEADERS).status_code==409
    payload['acknowledged']=True
    assert client.post(path,json=payload,headers=HEADERS).status_code==200
    assert client.get(path).json()['decision']=='approved'
    assert client.get('/api/verify').json()['valid']
    assert client.get('/api/cases/'+report['id']).json()==report


def test_shared_domain_does_not_make_campaign():
    a={'id':'a','sha256':'1','sender':'a@example.com','created':1}
    b={**a,'id':'b','sha256':'2'}
    result=campaigns.build([a,b])
    assert result['edges'] and not result['campaigns']


def test_campaign_thread_and_demo_isolation():
    a={'id':'a','sha256':'1','created':1,'headers':[{'name':'Message-ID','value':'<a@example.com>'}]}
    b={'id':'b','sha256':'2','created':2,'headers':[{'name':'In-Reply-To','value':'<a@example.com>'}]}
    assert campaigns.build([a,b])['campaigns']
    b['sample']=True
    assert not campaigns.build([a,b])['edges']
    b=copy.deepcopy(a)
    b['id']='b'
    assert not campaigns.build([a,b])['edges']

import json
import pytest
import requests
import siem
from test_selection import client, HEADERS

@pytest.fixture(autouse=True)
def disabled(monkeypatch):
    monkeypatch.setenv('SIEM_MODE','disabled')

@pytest.fixture
def report(client):
    return client.post('/api/samples/account', headers=HEADERS).json()

def test_disabled_and_cef_export(client, report):
    assert not client.get('/api/siem').json()['enabled']
    assert client.post(f"/api/cases/{report['id']}/siem",headers=HEADERS).status_code == 503
    output = client.get(f"/api/cases/{report['id']}/export/cef").text
    assert output.startswith('CEF:0|')
    assert report['sha256'] in output
    assert report['sender'] not in output

def test_minimal_payload(report):
    payload = siem.event(report)
    assert not {'body','sender','subject','urls','headers','recipient'} & payload.keys()
    assert siem.event(report)['event_id'] == payload['event_id']

def test_wazuh_log_and_integrity(client, report, monkeypatch, tmp_path):
    path = tmp_path/'siem.jsonl'
    monkeypatch.setenv('SIEM_MODE','wazuh')
    monkeypatch.setenv('WAZUH_LOG_PATH',str(path))
    response = client.post(f"/api/cases/{report['id']}/siem",headers=HEADERS)
    assert response.json()['status'] == 'written'
    assert json.loads(path.read_text())['case_id'] == report['id']
    assert client.get('/api/verify').json()['valid']
    assert client.get(f"/api/cases/{report['id']}").json() == report

@pytest.mark.parametrize('url',['http://collector.example/services/collector/event','https://user:pass@collector.example/services/collector/event','https://collector.example/other','https://collector.example/services/collector/event?token=secret'])
def test_reject_bad_configuration(monkeypatch,url):
    monkeypatch.setenv('SIEM_MODE','splunk')
    monkeypatch.setenv('SPLUNK_HEC_URL',url)
    monkeypatch.setenv('SPLUNK_HEC_TOKEN','example-token')
    assert not siem.status()['enabled']

@pytest.mark.parametrize('http,body,expected',[(200,{'code':0},'accepted'),(200,{'code':False},'failed'),(200,{'code':4},'failed'),(302,{},'failed'),(401,{},'failed')])
def test_splunk_response(monkeypatch,report,http,body,expected):
    monkeypatch.setenv('SIEM_MODE','splunk')
    monkeypatch.setenv('SPLUNK_HEC_URL','https://collector.example/services/collector/event')
    monkeypatch.setenv('SPLUNK_HEC_TOKEN','example-token')
    class Response:
        status_code=http
        def __enter__(self): return self
        def __exit__(self,*a): pass
        def iter_content(self,size): yield json.dumps(body).encode()
    def post(url,**kwargs):
        assert kwargs['allow_redirects'] is False
        assert kwargs['headers']['Authorization']=='Splunk example-token'
        assert 'body' not in kwargs['json']['event']
        return Response()
    monkeypatch.setattr(siem.requests,'post',post)
    assert siem.deliver(report)['status']==expected

def test_timeout_unknown(monkeypatch,report):
    monkeypatch.setenv('SIEM_MODE','splunk')
    monkeypatch.setenv('SPLUNK_HEC_URL','https://collector.example/services/collector/event')
    monkeypatch.setenv('SPLUNK_HEC_TOKEN','example-token')
    def timeout(*a,**k): raise requests.Timeout('secret endpoint info')
    monkeypatch.setattr(siem.requests,'post',timeout)
    receipt=siem.deliver(report)
    assert receipt['status']=='unknown'
    assert 'secret endpoint' not in receipt['detail']

def test_other_session_cannot_send(client, report):
    from fastapi.testclient import TestClient
    import main
    with TestClient(main.app) as other:
        assert other.post(f"/api/cases/{report['id']}/siem",headers=HEADERS).status_code==404

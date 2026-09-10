import hashlib
import hmac
import json
import time
import pytest
import receiver_evidence
from test_selection import client, HEADERS

RAW=b'From: sender@example.com\r\nSubject: Receiver test\r\n\r\nHello'
KEY='controlled-test-key-only-not-for-production'


def proof(raw=RAW):
    data={'receiver':'mx.example','issued_at':int(time.time()),'sha256':hashlib.sha256(raw).hexdigest(),
          'smtp':{'client_ip':'8.8.8.8','mail_from':'sender@example.com','helo':'sender.example.com'}}
    return sign(data)


def sign(data):
    data={k:v for k,v in data.items() if k!='signature'}
    return {**data,'signature':hmac.new(KEY.encode(),receiver_evidence.canonical(data),hashlib.sha256).hexdigest()}


def test_authenticated_receiver_pipeline(client,monkeypatch):
    monkeypatch.setenv('RECEIVER_KEYS_JSON',json.dumps({'mx.example':KEY}))
    response=client.post('/api/analyze',content=RAW,headers={**HEADERS,'X-Receiver-Evidence':json.dumps(proof())})
    assert response.status_code==200,response.text
    data=response.json()
    assert data['assessment']['origin_evidence']['earliest_reliable_node']['ip']=='8.8.8.8'
    assert data['origin']=='Receiver-attested ingress'
    assert data['authentication']['spf']['status']=='unknown'
    assert client.get('/api/verify').json()['valid']


@pytest.mark.parametrize('change',['raw','signature','context','old','future','unknown'])
def test_bad_receiver_evidence_rejected(monkeypatch,change):
    monkeypatch.setenv('RECEIVER_KEYS_JSON',json.dumps({'mx.example':KEY}))
    data=proof()
    raw=RAW
    if change=='raw': raw+=b'changed'
    if change=='signature':data['signature']='0'*64
    if change=='context':data['smtp']['client_ip']='1.1.1.1'
    if change=='old': data=sign({**data,'issued_at':int(time.time())-400})
    if change=='future': data=sign({**data,'issued_at':int(time.time())+400})
    if change=='unknown':data=sign({**data,'receiver':'other.example'})
    with pytest.raises(ValueError):receiver_evidence.verify(json.dumps(data),raw)


def test_pasted_message_cannot_claim_receiver_trust(client,monkeypatch):
    monkeypatch.setenv('RECEIVER_KEYS_JSON',json.dumps({'mx.example':KEY}))
    response=client.post('/api/analyze',json={'email':RAW.decode()},headers={**HEADERS,'X-Receiver-Evidence':json.dumps(proof())})
    assert response.status_code==400

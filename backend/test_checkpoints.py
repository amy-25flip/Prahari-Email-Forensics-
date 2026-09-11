from test_selection import client,HEADERS
import store
import blockchain_timestamp

def test_checkpoint_survives_legitimate_append(client):
    client.post('/api/samples/account',headers=HEADERS)
    checkpoint=client.get('/api/checkpoint').json()
    client.post('/api/samples/invoice',headers=HEADERS)
    assert client.post('/api/checkpoint/verify',json=checkpoint,headers=HEADERS).json()['valid']

def test_checkpoint_detects_tail_truncation(client):
    client.post('/api/samples/account',headers=HEADERS)
    latest=client.post('/api/samples/invoice',headers=HEADERS).json()
    checkpoint=client.get('/api/checkpoint').json()
    with store.connect() as db:
        db.execute('DELETE FROM cases WHERE id=?',(latest['id'],))
        db.execute('DELETE FROM events WHERE seq=(SELECT MAX(seq) FROM events)')
    assert client.get('/api/verify').json()['valid']
    assert not client.post('/api/checkpoint/verify',json=checkpoint,headers=HEADERS).json()['valid']

def test_checkpoint_rejects_other_session(client):
    checkpoint=client.get('/api/checkpoint').json()
    checkpoint['session_fingerprint']='f'*64
    assert not client.post('/api/checkpoint/verify',json=checkpoint,headers=HEADERS).json()['valid']

def test_checkpoint_validates_input(client):
    checkpoint=client.get('/api/checkpoint').json()
    checkpoint['event_count']=-1
    assert client.post('/api/checkpoint/verify',json=checkpoint,headers=HEADERS).status_code==422

def test_blockchain_stamp_submits_current_head(client,monkeypatch):
    client.post('/api/samples/account',headers=HEADERS)
    checkpoint=client.get('/api/checkpoint').json()
    captured={}
    def fake_stamp(head):
        captured['head']=head
        return {'status':'pending','proof':'ZmFrZQ==','sha256':head,'pending_calendars':['https://example.test']}
    monkeypatch.setattr(blockchain_timestamp,'stamp',fake_stamp)
    response=client.post('/api/checkpoint/blockchain-stamp',headers=HEADERS)
    assert response.status_code==200
    assert response.json()['status']=='pending'
    assert captured['head']==checkpoint['head']

def test_blockchain_verify_rejects_malformed_input(client):
    assert client.post('/api/checkpoint/blockchain-verify',json={'sha256':'not-hex','proof':'x'},headers=HEADERS).status_code==422

def test_blockchain_verify_checks_supplied_proof(client,monkeypatch):
    def fake_check(sha256,proof):
        return {'status':'confirmed','bitcoin_block_height':900000,'sha256':sha256,'proof':proof}
    monkeypatch.setattr(blockchain_timestamp,'check',fake_check)
    payload={'sha256':'a'*64,'proof':'ZmFrZQ=='}
    response=client.post('/api/checkpoint/blockchain-verify',json=payload,headers=HEADERS)
    assert response.status_code==200
    assert response.json()['status']=='confirmed'

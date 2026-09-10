from test_selection import client,HEADERS
import store

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

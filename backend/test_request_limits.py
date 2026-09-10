from request_limits import PeerLimiter
from test_selection import client, HEADERS

def test_limit_expiry_and_capacity():
    limiter=PeerLimiter(limit=2,window=60,capacity=1)
    assert limiter.allow('a',0)
    assert limiter.allow('a',1)
    assert not limiter.allow('a',2)
    assert not limiter.allow('b',2)
    assert limiter.allow('b',62)

def test_peer_limit_cannot_be_reset_with_cookie_or_forwarded_header(client):
    import main
    main.peer_limiter.reset()
    for i in range(30):
        response=client.post('/api/analyze',json={},headers={**HEADERS,'X-Forwarded-For':str(i),'Cookie':'efp_session=forged'})
        assert response.status_code==400
    response=client.post('/api/analyze',json={},headers=HEADERS)
    assert response.status_code==429
    assert response.headers['retry-after']=='60'
    main.peer_limiter.reset()

def test_security_headers_on_html_and_errors(client):
    for path in ('/','/api/health','/api/missing'):
        response=client.get(path)
        assert response.headers['x-content-type-options']=='nosniff'
        assert response.headers['x-frame-options']=='DENY'
        if path.startswith('/api/'): assert response.headers['cache-control']=='no-store'

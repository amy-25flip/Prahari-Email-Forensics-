import routing
import origin_assessment


def test_sender_ip_not_receiver_ip():
    value='from source.example (source.example [8.8.8.8]) by receiver.example [1.1.1.1]; Thu, 10 Sep 2026 00:00:00 +0000'
    parsed=routing.parse(value)
    assert parsed['sender_ips']==['8.8.8.8']
    assert parsed['by_host']=='receiver.example'
    result=origin_assessment.assess({'hops':[{'index':1,'ips':['1.1.1.1','8.8.8.8'],**parsed}]})
    assert result['earliest_reported_public_node']['ip']=='8.8.8.8'


def test_by_inside_comment_not_clause():
    parsed=routing.parse('from source.example (by misleading.example [8.8.8.8]) by receiver.example; today')
    assert parsed['by_host']=='receiver.example'
    assert parsed['sender_ips']==['8.8.8.8']


def test_continuous_route_not_flagged():
    assert not routing.inspect(['from relay.example by inbox.example; today','from origin.example by relay.example; today'])


def test_discontinuous_and_loop():
    assert routing.inspect(['from other.example by inbox.example; today','from origin.example by relay.example; today'])[0]['title']=='Relay naming discontinuity'
    assert any(c['title']=='Possible relay loop' for c in routing.inspect(['from b.example by a.example','from a.example by b.example']))


def test_repeated_header_and_no_sender():
    assert routing.inspect(['by a.example','by a.example'])[0]['title']=='Repeated relay record'
    assert routing.parse('by a.example [8.8.8.8]')['sender_ips']==[]

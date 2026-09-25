import campaigns


def report(id, sender='vendor@ok.example', indicators=None, hops=None, headers=None, sample=False, created=100.0, sha256='a' * 64):
    return {'id': id, 'sender': sender, 'indicators': indicators or [], 'hops': hops or [], 'headers': headers or [],
            'sample': sample, 'created': created, 'sha256': sha256}


def test_no_reports_produces_an_empty_graph():
    graph = campaigns.evidence_graph([])
    assert graph['nodes'] == [] and graph['edges'] == []


def test_single_report_produces_a_case_node_and_its_indicator_nodes():
    r = report('r1', sender='alerts@example.com', indicators=[{'type': 'url', 'value': 'http://evil.example/a'}])
    graph = campaigns.evidence_graph([r])
    node_types = {n['type'] for n in graph['nodes']}
    assert 'case' in node_types and 'sender_domain' in node_types and 'sender_address' in node_types and 'url' in node_types
    case_node = next(n for n in graph['nodes'] if n['type'] == 'case')
    assert case_node['id'] == 'case:r1' and case_node['value'] == 'r1'


def test_shared_indicator_across_cases_produces_one_shared_node_with_two_edges():
    a = report('r1', indicators=[{'type': 'url', 'value': 'http://evil.example/a'}])
    b = report('r2', indicators=[{'type': 'url', 'value': 'http://evil.example/a'}])
    graph = campaigns.evidence_graph([a, b])
    url_nodes = [n for n in graph['nodes'] if n['type'] == 'url']
    assert len(url_nodes) == 1, 'the same URL across two cases must collapse to ONE node, not two'
    shared_id = url_nodes[0]['id']
    edges_to_shared = [e for e in graph['edges'] if e['target'] == shared_id]
    assert len(edges_to_shared) == 2
    assert {e['source'] for e in edges_to_shared} == {'case:r1', 'case:r2'}


def test_strong_indicator_types_get_strong_confidence_edges():
    r = report('r1', indicators=[{'type': 'url', 'value': 'http://evil.example/a'}])
    graph = campaigns.evidence_graph([r])
    url_node = next(n for n in graph['nodes'] if n['type'] == 'url')
    edge = next(e for e in graph['edges'] if e['target'] == url_node['id'])
    assert edge['confidence'] == 'strong'
    assert 'url' in campaigns.STRONG  # sanity: this is what the assertion above actually depends on


def test_weak_indicator_types_get_context_only_confidence_edges():
    r = report('r1', sender='alerts@example.com')
    graph = campaigns.evidence_graph([r])
    domain_node = next(n for n in graph['nodes'] if n['type'] == 'sender_domain')
    edge = next(e for e in graph['edges'] if e['target'] == domain_node['id'])
    assert edge['confidence'] == 'context_only'
    assert 'sender_domain' not in campaigns.STRONG


def test_private_reported_ip_never_becomes_a_graph_node():
    r = report('r1', hops=[{'ips': ['10.0.0.5']}])
    graph = campaigns.evidence_graph([r])
    assert not any(n['type'] == 'reported_ip' for n in graph['nodes'])


def test_public_reported_ip_becomes_a_shared_node_across_cases():
    a = report('r1', hops=[{'ips': ['8.8.8.8']}])
    b = report('r2', hops=[{'ips': ['8.8.8.8']}])
    graph = campaigns.evidence_graph([a, b])
    ip_nodes = [n for n in graph['nodes'] if n['type'] == 'reported_ip']
    assert len(ip_nodes) == 1 and ip_nodes[0]['value'] == '8.8.8.8'


def test_unknown_indicator_type_is_silently_skipped_not_fabricated_into_a_node():
    # Regression: indicators() pulls arbitrary (type, value) pairs
    # straight from report['indicators'] without validating the type name --
    # a malformed/legacy report entry with an unrecognized type must not
    # silently become a surprise node type, contradicting the "exactly these
    # types" policy claim.
    r = report('r1', indicators=[{'type': 'totally_unknown_type', 'value': 'x'}])
    graph = campaigns.evidence_graph([r])
    assert not any(n['type'] == 'totally_unknown_type' for n in graph['nodes'])
    assert not any(e['target'] not in {n['id'] for n in graph['nodes']} for e in graph['edges'])


def test_report_with_no_id_raises_instead_of_silently_merging_case_nodes():
    # Self-caught during final review: the indicator-node collision guard
    # existed, but the case node used setdefault() unconditionally with no
    # equivalent check -- two reports both missing an id would silently
    # collapse onto the same 'case:' node. Every stored case always has a
    # real id in this app; a report without one signals a bug elsewhere and
    # must raise, not silently merge.
    import pytest
    a = {'id': None, 'sender': 'a@x.example', 'indicators': [], 'hops': [], 'headers': []}
    with pytest.raises(RuntimeError, match='no id'):
        campaigns.evidence_graph([a])


def test_node_id_collision_between_different_indicators_raises_not_silently_merges(monkeypatch):
    # Regression: setdefault() previously kept the FIRST node's
    # recorded type/value on a hash collision and silently pointed later
    # edges at it. A truncated-hash collision must raise, never silently
    # merge two genuinely different indicators onto one graph node.
    import pytest
    monkeypatch.setattr(campaigns, '_indicator_node_id', lambda kind, value: 'forced-collision')
    a = report('r1', indicators=[{'type': 'url', 'value': 'http://one.example'}])
    b = report('r2', indicators=[{'type': 'url', 'value': 'http://two.example'}])
    with pytest.raises(RuntimeError, match='collision'):
        campaigns.evidence_graph([a, b])


def test_all_strong_indicator_types_get_strong_confidence_not_just_url():
    r = report('r1', indicators=[
        {'type': 'reply_address', 'value': 'attacker@evil.example'},
        {'type': 'attachment_hash', 'value': 'b' * 64},
    ], headers=[{'name': 'Message-ID', 'value': '<abc@thread.example>'}])
    graph = campaigns.evidence_graph([r])
    for kind in ('reply_address', 'attachment_hash', 'thread_id'):
        assert kind in campaigns.STRONG, f'test assumption broken: {kind} is no longer in STRONG'
        node = next(n for n in graph['nodes'] if n['type'] == kind)
        edge = next(e for e in graph['edges'] if e['target'] == node['id'])
        assert edge['confidence'] == 'strong', f'{kind} should be a strong-confidence edge'


def test_various_non_global_ips_never_become_graph_nodes():
    for ip in ('127.0.0.1', '169.254.1.1', '::1', 'fe80::1', '192.0.2.1'):  # loopback, link-local, IPv6, TEST-NET
        r = report('r1', hops=[{'ips': [ip]}])
        graph = campaigns.evidence_graph([r])
        assert not any(n['type'] == 'reported_ip' for n in graph['nodes']), f'{ip} leaked into the graph'


def test_no_certificate_node_type_exists_since_this_app_does_not_collect_tls_data():
    # Explicit, honest scope check: the roadmap mentions a certificate node
    # type, but this app has no TLS certificate collection anywhere -- the
    # graph must never fabricate one.
    r = report('r1', indicators=[{'type': 'url', 'value': 'https://evil.example/a'}])
    graph = campaigns.evidence_graph([r])
    assert not any(n['type'] == 'certificate' for n in graph['nodes'])


def test_two_reports_with_nothing_in_common_produce_no_shared_nodes():
    a = report('r1', sender='a@one.example')
    b = report('r2', sender='b@two.example')
    graph = campaigns.evidence_graph([a, b])
    case_nodes = {n['id'] for n in graph['nodes'] if n['type'] == 'case'}
    assert case_nodes == {'case:r1', 'case:r2'}
    indicator_nodes = [n for n in graph['nodes'] if n['type'] != 'case']
    values = {n['value'] for n in indicator_nodes}
    assert 'one.example' in values and 'two.example' in values
    assert len(indicator_nodes) == len({n['id'] for n in indicator_nodes})  # no accidental collisions


# --- Integration: the full wiring through the real API ---
from test_selection import client, HEADERS  # noqa: E402


def test_real_api_endpoint_returns_a_graph_shape(client):
    client.post('/api/samples/account', headers=HEADERS)
    r = client.get('/api/campaigns/graph', headers=HEADERS)
    assert r.status_code == 200
    body = r.json()
    assert 'nodes' in body and 'edges' in body and 'policy' in body
    assert any(n['type'] == 'case' for n in body['nodes'])


def test_real_api_endpoint_is_session_scoped(client):
    client.post('/api/samples/account', headers=HEADERS)
    with_history = client.get('/api/campaigns/graph', headers=HEADERS).json()
    client.cookies.clear()
    fresh_session = client.get('/api/campaigns/graph', headers=HEADERS).json()
    assert fresh_session['nodes'] == [] and fresh_session['edges'] == []
    assert with_history['nodes']  # sanity: the original session actually had data

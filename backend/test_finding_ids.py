import finding_ids


def test_assign_adds_a_stable_id_field():
    entries = [{'group': 'links', 'title': 'Suspicious URL', 'detail': 'http://evil.example/a', 'points': 10}]
    finding_ids.assign(entries, 'group')
    assert 'id' in entries[0] and isinstance(entries[0]['id'], str) and len(entries[0]['id']) == finding_ids.ID_LENGTH


def test_same_content_produces_the_same_id():
    # The whole point: re-analyzing byte-identical content must reproduce the
    # same id, so it can be cited across independent re-analysis/exports.
    a = [{'group': 'links', 'title': 'Suspicious URL', 'detail': 'http://evil.example/a', 'points': 10}]
    b = [{'group': 'links', 'title': 'Suspicious URL', 'detail': 'http://evil.example/a', 'points': 10}]
    finding_ids.assign(a, 'group')
    finding_ids.assign(b, 'group')
    assert a[0]['id'] == b[0]['id']


def test_different_detail_produces_a_different_id():
    a = [{'group': 'links', 'title': 'Suspicious URL', 'detail': 'http://evil.example/a', 'points': 10}]
    b = [{'group': 'links', 'title': 'Suspicious URL', 'detail': 'http://evil.example/b', 'points': 10}]
    finding_ids.assign(a, 'group')
    finding_ids.assign(b, 'group')
    assert a[0]['id'] != b[0]['id']


def test_different_category_key_produces_a_different_id():
    # Same title/detail text but a different category (e.g. 'links' vs
    # 'identity') must not collide -- the category is part of the basis.
    a = [{'group': 'links', 'title': 'Same text', 'detail': 'same detail'}]
    b = [{'group': 'identity', 'title': 'Same text', 'detail': 'same detail'}]
    finding_ids.assign(a, 'group')
    finding_ids.assign(b, 'group')
    assert a[0]['id'] != b[0]['id']


def test_category_key_can_be_kind_for_check_style_entries():
    # engine.py findings use 'group'; ps_assessment/conversation/etc checks
    # use 'kind' -- assign() must work with either key name.
    entries = [{'kind': 'identity', 'title': 'Protected identity address mismatch', 'detail': 'x versus y'}]
    finding_ids.assign(entries, 'kind')
    assert 'id' in entries[0]


def test_missing_fields_do_not_crash():
    entries = [{}, {'title': 'only a title'}, {'detail': 'only a detail'}]
    finding_ids.assign(entries, 'group')
    assert all('id' in e for e in entries)


def test_id_is_lowercase_hex_of_the_expected_length():
    entries = [{'group': 'links', 'title': 'X', 'detail': 'Y'}]
    finding_ids.assign(entries, 'group')
    identifier = entries[0]['id']
    assert len(identifier) == finding_ids.ID_LENGTH
    assert identifier == identifier.lower()
    assert all(c in '0123456789abcdef' for c in identifier)


def test_duplicate_generic_findings_get_distinct_ids_not_a_collision():
    # Regression: several real producers emit intentionally
    # generic title+detail text shared by genuinely different findings (e.g.
    # two different suspicious URLs both explained by the same structural
    # reason string). Without disambiguation these would collide onto the
    # SAME id within one report, defeating the whole point of citing a
    # specific finding.
    entries = [
        {'group': 'links', 'title': 'Suspicious URL', 'detail': 'Structural risk factors present'},
        {'group': 'links', 'title': 'Suspicious URL', 'detail': 'Structural risk factors present'},
        {'group': 'links', 'title': 'Suspicious URL', 'detail': 'Structural risk factors present'},
    ]
    finding_ids.assign(entries, 'group')
    ids = [e['id'] for e in entries]
    assert len(set(ids)) == 3, f'expected 3 distinct ids for 3 duplicate-content findings, got {ids}'


def test_first_occurrence_id_unaffected_by_having_duplicates_at_all():
    # The first of several duplicates should get the SAME id it would have
    # gotten if it were the only entry in the list -- duplicate handling
    # must not perturb the "normal", non-duplicate case's id.
    solo = [{'group': 'links', 'title': 'Suspicious URL', 'detail': 'same text'}]
    finding_ids.assign(solo, 'group')
    with_duplicates = [
        {'group': 'links', 'title': 'Suspicious URL', 'detail': 'same text'},
        {'group': 'links', 'title': 'Suspicious URL', 'detail': 'same text'},
    ]
    finding_ids.assign(with_duplicates, 'group')
    assert solo[0]['id'] == with_duplicates[0]['id']


def test_rerunning_assign_after_detail_changes_recomputes_the_id():
    entries = [{'group': 'links', 'title': 'X', 'detail': 'original'}]
    finding_ids.assign(entries, 'group')
    first_id = entries[0]['id']
    entries[0]['detail'] = 'changed'
    finding_ids.assign(entries, 'group')
    assert entries[0]['id'] != first_id


def test_assign_mutates_in_place_and_returns_the_same_list():
    entries = [{'group': 'links', 'title': 'X', 'detail': 'Y'}]
    result = finding_ids.assign(entries, 'group')
    assert result is entries


# --- Integration: ids actually reach real /api/analyze findings and checks ---
from test_selection import client, HEADERS  # noqa: E402


def test_real_analyze_response_findings_and_checks_carry_stable_ids(client):
    raw = (b'From: vendor@ok.example\r\nReply-To: attacker@evil.example\r\nTo: v@d.com\r\n'
           b'Subject: Verify your account\r\n\r\nClick http://evil.example/login to verify your password now.')
    r = client.post('/api/analyze', content=raw, headers=HEADERS)
    assert r.status_code == 200
    body = r.json()
    assert body['findings'], 'sanity: this email should produce at least one finding'
    for f in body['findings']:
        assert 'id' in f and len(f['id']) == finding_ids.ID_LENGTH
    for c in body['assessment']['checks']:
        assert 'id' in c and len(c['id']) == finding_ids.ID_LENGTH


def test_reanalyzing_identical_content_reproduces_the_same_finding_ids(client):
    raw = (b'From: vendor@ok.example\r\nReply-To: attacker@evil.example\r\nTo: v@d.com\r\n'
           b'Subject: Verify your account\r\n\r\nClick http://evil.example/login to verify your password now.')
    r1 = client.post('/api/analyze', content=raw, headers=HEADERS).json()
    r2 = client.post('/api/analyze', content=raw, headers=HEADERS).json()
    ids1 = sorted(f['id'] for f in r1['findings'])
    ids2 = sorted(f['id'] for f in r2['findings'])
    assert ids1 == ids2 and ids1, 'the same input re-analyzed independently must cite the same finding ids'


def test_no_duplicate_finding_ids_within_one_real_multi_url_report(client):
    # Real-world version of the duplicate-collision regression: several
    # distinct suspicious URLs in one email can share the same generic
    # structural finding text -- their ids must still all be distinct.
    raw = (b'From: vendor@ok.example\r\nTo: v@d.com\r\nSubject: Urgent payment\r\n\r\n'
           b'Click http://192.168.1.1.evil-one.example/login and also '
           b'http://192.168.1.1.evil-two.example/login and also '
           b'http://192.168.1.1.evil-three.example/login to verify your password now.')
    r = client.post('/api/analyze', content=raw, headers=HEADERS)
    assert r.status_code == 200
    ids = [f['id'] for f in r.json()['findings']]
    assert len(ids) == len(set(ids)), f'duplicate finding ids in one report: {ids}'


def test_pdf_export_still_succeeds_with_the_id_prefix_wired_in(client):
    # PDF content streams can be compressed, so this doesn't assert the
    # literal "[id]" text is recoverable from the raw bytes -- it's a smoke
    # test that check.get('id', '?') and finding.get('id', '?') don't raise
    # or otherwise break PDF generation now that every entry carries an id.
    r = client.post('/api/samples/account', headers=HEADERS)
    assert r.status_code == 200
    case_id = r.json()['id']
    export = client.get(f'/api/cases/{case_id}/export/pdf')
    assert export.status_code == 200 and export.content.startswith(b'%PDF')

import campaigns


def report(id, subject, body, sha256=None, sample=False, created=0, indicators=None, sender='a@b.com', headers=None, hops=None):
    return {'id': id, 'sha256': sha256 or id, 'sample': sample, 'created': created,
            'subject': subject, 'body': body, 'sender': sender,
            'indicators': indicators or [], 'headers': headers or [], 'hops': hops or []}


def test_shingles_short_text_is_single_shingle():
    assert campaigns._shingles('hi') == frozenset({'hi'})
    assert campaigns._shingles('') == frozenset()


def test_body_similarity_identical_text_is_one():
    text = 'verify your account immediately or it will be suspended today'
    assert campaigns.body_similarity(text, text) == 1.0


def test_body_similarity_unrelated_text_is_low():
    a = 'quarterly engineering newsletter with release notes and roadmap updates'
    b = 'urgent payment invoice attached please wire funds to the new account'
    assert campaigns.body_similarity(a, b) < 0.3


def test_near_duplicate_bodies_merge_into_a_campaign_even_with_no_shared_indicators():
    left = report('c1', 'Verify your account', 'Dear Customer, your account will be suspended unless you verify now. Click here to confirm your identity and avoid suspension.', created=1)
    right = report('c2', 'Verify your account now', 'Dear Client, your account will be suspended unless you verify now. Click here to confirm your identity and avoid suspension.', created=2)
    result = campaigns.build([left, right])
    assert len(result['campaigns']) == 1
    assert result['campaigns'][0]['case_ids'] == ['c1', 'c2']
    edge = result['edges'][0]
    assert edge['strength'] == 'candidate'
    assert any(e['type'] == 'body_similarity' for e in edge['evidence'])


def test_dissimilar_bodies_with_no_shared_indicators_produce_no_edge():
    left = report('c1', 'Team lunch', 'Lets grab lunch on Friday at noon near the office.', sender='alice@example.org', created=1)
    right = report('c2', 'Server outage', 'The production database had a brief outage at 3am, root cause is being investigated.', sender='bob@other.test', created=2)
    result = campaigns.build([left, right])
    assert result['campaigns'] == []
    assert result['edges'] == []


def test_exact_duplicate_raw_email_is_excluded():
    left = report('c1', 'X', 'same body content used twice', sha256='dup', created=1)
    right = report('c2', 'X', 'same body content used twice', sha256='dup', created=2)
    result = campaigns.build([left, right])
    assert result['campaigns'] == []


def test_sample_and_live_cases_never_merge_even_if_near_identical():
    text = 'urgent verify your password immediately to avoid account suspension today'
    left = report('c1', 'Alert', text, sample=True, created=1)
    right = report('c2', 'Alert', text, sample=False, created=2)
    result = campaigns.build([left, right])
    assert result['campaigns'] == []

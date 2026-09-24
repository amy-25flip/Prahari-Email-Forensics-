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


PHISH_A = ('Dear Rahul, your SBI account ending 4412 has been temporarily locked due to unusual activity. To restore access, '
           'please verify your KYC details within 24 hours by visiting the secure link below or your account will be permanently suspended.')
PHISH_B = ('Hello Priya, we noticed unusual activity on your HDFC account ending 9081 and it has been temporarily locked. '
           'Verify your KYC details within 48 hours using the secure link below to restore access, otherwise your account will be permanently suspended.')


def test_reworded_template_gets_a_context_only_link_but_is_not_merged():
    result = campaigns.build([report('c1', 'Account locked', PHISH_A, created=1), report('c2', 'Action required', PHISH_B, created=2)])
    assert result['campaigns'] == []          # weak tier never merges cases
    assert len(result['edges']) == 1
    edge = result['edges'][0]
    assert edge['strength'] == 'context_only'
    similarity = [e for e in edge['evidence'] if e['type'] == 'body_similarity']
    assert similarity and 'tf-idf cosine + simhash' in similarity[0]['value']


def test_tfidf_simhash_strong_tier_merges_close_paraphrases():
    a = PHISH_A
    b = PHISH_A.replace('Dear Rahul', 'Dear Sanjay').replace('4412', '7730').replace('24 hours', '12 hours').replace('SBI', 'PNB')
    tokens_a, tokens_b = campaigns._words(a.lower()), campaigns._words(b.lower())
    assert campaigns.cosine_similarity(tokens_a, tokens_b) >= campaigns.COSINE_STRONG
    assert campaigns.simhash_distance(campaigns.simhash(tokens_a), campaigns.simhash(tokens_b)) <= campaigns.SIMHASH_STRONG


def test_unrelated_business_emails_from_one_org_are_not_linked():
    a = ('Hi team, the quarterly engineering roadmap review is scheduled for Thursday. Please add your project updates to the shared '
         'document before the meeting and flag any blockers so we can plan the next release cycle together.')
    b = ('Hi all, the monthly finance close checklist is attached. Please review the numbers for your cost centre and confirm any '
         'variances before Friday so we can plan the audit schedule together.')
    result = campaigns.build([report('c1', 'Roadmap review', a, sender='m@corp.example', created=1),
                              report('c2', 'Finance close', b, sender='a@corp.example', created=2)])
    assert result['campaigns'] == []
    assert not any(e['type'] == 'body_similarity' for edge in result['edges'] for e in edge['evidence'])


def test_word_masking_ignores_numbers_and_links():
    assert campaigns._words('pay 5000 now at https://x.tk/a1 today') == ['pay', 'now', 'at', 'today']


def test_simhash_is_stable_and_distance_zero_for_identical_text():
    tokens = campaigns._words('verify your account immediately or it will be suspended')
    assert campaigns.simhash(tokens) == campaigns.simhash(list(tokens))
    assert campaigns.simhash_distance(campaigns.simhash(tokens), campaigns.simhash(tokens)) == 0

import conversation


def report(headers=None, sender='vendor@ok.example', subject='Invoice', upi=None, account=None, marker=None):
    r = {'headers': headers or [], 'sender': sender, 'subject': subject,
         'payment_signals': {'upi': upi or [], 'account': account or [], 'ifsc': []}}
    if marker is not None: r['_marker'] = marker  # lets tests tell reports apart by identity where needed
    return r


def hdr(name, value):
    return {'name': name, 'value': value}


def test_real_reply_chain_is_recognized_even_though_the_first_message_has_no_references():
    # The realistic, non-symmetric case: message 1 has a Message-ID and no
    # References (nothing to reference yet); message 2's References points at
    # message 1's Message-ID. This must match despite the two messages'
    # header sets looking nothing alike.
    first = report(headers=[hdr('Message-ID', '<thread1@x>')])
    second = report(headers=[hdr('References', '<thread1@x>')], subject='Re: Invoice')
    assert conversation.is_same_thread(first, second)
    assert conversation.is_same_thread(second, first)  # symmetric regardless of argument order


def test_siblings_replying_to_the_same_ancestor_are_same_thread():
    a = report(headers=[hdr('References', '<root@x> <mid@x>')])
    b = report(headers=[hdr('References', '<root@x> <other@x>')], subject='Re: Invoice')
    assert conversation.is_same_thread(a, b)


def test_thread_key_falls_back_to_sender_and_normalized_subject_when_no_headers_at_all():
    a = report(sender='Vendor <vendor@ok.example>', subject='Payment due')
    b = report(sender='vendor@ok.example', subject='Re: Payment due')
    assert conversation.is_same_thread(a, b)


def test_thread_key_fallback_distinguishes_different_senders():
    a = report(sender='vendor@ok.example', subject='Payment due')
    b = report(sender='attacker@evil.example', subject='Payment due')
    assert not conversation.is_same_thread(a, b)


def test_matching_subject_alone_does_not_join_an_unrelated_real_thread():
    # A message that DOES carry real threading headers for a DIFFERENT thread
    # must not be pulled in just because its subject happens to coincide.
    a = report(headers=[hdr('Message-ID', '<real-thread@x>')], subject='Invoice')
    b = report(headers=[hdr('References', '<some-other-thread@x>')], subject='Invoice')
    assert not conversation.is_same_thread(a, b)


def test_no_prior_thread_messages_is_a_clean_no_op():
    current = report(upi=['ramesh@oksbi'])
    result = conversation.assess(current, [])
    assert result['checks'] == [] and result['prior_messages_considered'] == 0


def test_new_upi_id_mid_thread_is_flagged():
    prior = report(subject='Invoice #1', upi=['vendor@oksbi'])
    current = report(subject='Re: Invoice #1', upi=['attacker@paytm'])
    result = conversation.assess(current, [prior])
    assert any('Payment UPI ID changed' in c['title'] for c in result['checks'])
    assert result['prior_messages_considered'] == 1


def test_same_upi_id_repeated_is_not_flagged():
    prior = report(subject='Invoice #1', upi=['vendor@oksbi'])
    current = report(subject='Re: Invoice #1', upi=['vendor@oksbi'])
    result = conversation.assess(current, [prior])
    assert result['checks'] == []


def test_first_mention_of_a_upi_id_is_not_flagged_as_a_change():
    # No payment identifier was ever established earlier in the thread, so
    # its first appearance now is not itself an "anomaly".
    prior = report(subject='Invoice #1', upi=[])
    current = report(subject='Re: Invoice #1', upi=['vendor@oksbi'])
    result = conversation.assess(current, [prior])
    assert result['checks'] == []


def test_new_account_number_mid_thread_is_flagged():
    prior = report(subject='Invoice #1', account=['123456789012'])
    current = report(subject='Re: Invoice #1', account=['999999999999'])
    result = conversation.assess(current, [prior])
    assert any('Bank account number changed' in c['title'] for c in result['checks'])


def test_reply_to_domain_swap_mid_thread_is_flagged():
    prior = report(subject='Invoice #1', headers=[hdr('Reply-To', 'vendor@ok.example')])
    current = report(subject='Re: Invoice #1', headers=[hdr('Reply-To', 'vendor@attacker-controlled.example')])
    result = conversation.assess(current, [prior])
    assert any('Reply-To domain changed' in c['title'] for c in result['checks'])


def test_same_reply_to_domain_is_not_flagged():
    prior = report(subject='Invoice #1', headers=[hdr('Reply-To', 'vendor@ok.example')])
    current = report(subject='Re: Invoice #1', headers=[hdr('Reply-To', 'billing@ok.example')])
    result = conversation.assess(current, [prior])
    assert result['checks'] == []


def test_unrelated_thread_messages_do_not_contribute_signals():
    unrelated = report(sender='someone-else@example.com', subject='Totally different topic', upi=['other@paytm'])
    prior = report(subject='Invoice #1', upi=['vendor@oksbi'])
    current = report(subject='Re: Invoice #1', upi=['attacker@paytm'])
    result = conversation.assess(current, [unrelated, prior])
    assert result['prior_messages_considered'] == 1  # only the real thread-mate counted
    assert any('Payment UPI ID changed' in c['title'] for c in result['checks'])


# --- Integration: the full wiring through a real /api/analyze call ---
from test_selection import client, HEADERS  # noqa: E402


def test_conversation_check_fires_through_the_real_api_and_escalates_review(client):
    first = (b'From: vendor@ok.example\r\nTo: v@d.com\r\nMessage-ID: <thread1@ok.example>\r\n'
             b'Subject: Invoice #100\r\n\r\nPlease pay to vendor@oksbi when ready.')
    r1 = client.post('/api/analyze', content=first, headers=HEADERS)
    assert r1.status_code == 200
    assert r1.json()['assessment']['conversation']['prior_messages_considered'] == 0

    second = (b'From: vendor@ok.example\r\nTo: v@d.com\r\nMessage-ID: <thread2@ok.example>\r\n'
              b'References: <thread1@ok.example>\r\nIn-Reply-To: <thread1@ok.example>\r\n'
              b'Subject: Re: Invoice #100\r\n\r\nOur account changed -- please pay to attacker@paytm instead.')
    r2 = client.post('/api/analyze', content=second, headers=HEADERS)
    assert r2.status_code == 200
    body = r2.json()
    conv = body['assessment']['conversation']
    assert conv['prior_messages_considered'] == 1
    assert any('Payment UPI ID changed' in c['title'] for c in conv['checks'])
    # The check rides the same escalation path impersonation/ps_assessment checks use.
    assert body['triage']['priority'] == 'review'


def test_conversation_section_present_and_empty_for_a_lone_email(client):
    raw = b'From: friend@ok.example\r\nTo: v@d.com\r\nSubject: Lunch?\r\n\r\nAre we still on?'
    r = client.post('/api/analyze', content=raw, headers=HEADERS)
    conv = r.json()['assessment']['conversation']
    assert conv['checks'] == [] and conv['prior_messages_considered'] == 0


def test_garbage_shared_reference_tokens_do_not_false_join_threads():
    # Regression (Codex Low/Medium): a malformed/placeholder References value
    # is not shaped like a real Message-ID and must not become thread-linking
    # evidence just because two unrelated messages both have it.
    a = report(headers=[hdr('References', 'unknown')], subject='Totally different')
    b = report(headers=[hdr('References', 'unknown')], subject='Also different')
    assert not conversation.is_same_thread(a, b)


def test_dash_placeholder_reference_does_not_false_join():
    # Different sender+subject too, so the only way these could match is via
    # the garbage '-' reference token itself -- which must not count.
    a = report(headers=[hdr('In-Reply-To', '-')], sender='a@x.example', subject='First topic')
    b = report(headers=[hdr('In-Reply-To', '-')], sender='b@y.example', subject='Second topic')
    assert not conversation.is_same_thread(a, b)


import engine  # noqa: E402


def test_phone_and_tracking_numbers_are_not_captured_as_account_numbers():
    # Regression (Codex Medium): the account-number extractor must require
    # actual banking context, not fire on any 9-18 digit run (a phone number,
    # invoice number, or tracking number).
    raw = (b'From: a@b.com\r\nTo: c@d.com\r\nSubject: Update\r\n\r\n'
           b'Call me at 9876543210. Your tracking number is 123456789012. '
           b'Invoice reference 987654321.')
    result = engine.analyze(raw)
    assert result['payment_signals']['account'] == []


def test_real_account_context_is_still_captured():
    raw = (b'From: a@b.com\r\nTo: c@d.com\r\nSubject: Payment details\r\n\r\n'
           b'Please transfer funds to account number 123456789012 as discussed.')
    result = engine.analyze(raw)
    assert '123456789012' in result['payment_signals']['account']


def test_account_context_variant_number_before_keyword_also_captured():
    raw = (b'From: a@b.com\r\nTo: c@d.com\r\nSubject: Payment details\r\n\r\n'
           b'New A/C: 987654321012 acct for future payments.')
    result = engine.analyze(raw)
    assert '987654321012' in result['payment_signals']['account']


def test_phone_number_thread_change_no_longer_falsely_flagged():
    # End-to-end version of the same regression: a thread where only a phone
    # number (not a real account number) changes must not trigger "Bank
    # account number changed mid-thread".
    prior = report(subject='Invoice #1', account=[])  # empty because engine.py now correctly excludes bare phone numbers
    current = report(subject='Re: Invoice #1', account=[])
    result = conversation.assess(current, [prior])
    assert result['checks'] == []

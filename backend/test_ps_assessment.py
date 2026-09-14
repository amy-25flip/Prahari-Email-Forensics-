import engine
import ps_assessment


def _titles(raw):
    # ps_assessment.inspect() is only ever called downstream of engine.analyze()
    # in the real pipeline (main.py's execute()) with the fully-populated report
    # it produces -- build one the same way rather than hand-crafting a partial
    # dict that's missing fields (findings, etc.) other checks in this module
    # also read.
    report = engine.analyze(raw, source='upload', live=False)
    return [c['title'] for c in ps_assessment.inspect(raw, report)['checks']]


def test_relay_timestamp_reversal_detected_across_one_unparseable_hop():
    # Hop order (top = most recent, matching how Received headers are
    # prepended): C (11:00) is newer-in-sequence than A (12:00) but reports
    # an EARLIER time -- over an hour of reversal. B in between has no
    # parseable date at all. The bug: zip(dates, dates[1:]) only compared
    # ADJACENT hops, so the (A,B) and (B,C) pairs were both skipped for
    # having a None, and A was never compared directly against C -- the
    # genuine reversal went completely undetected.
    raw = (
        b'Received: from relay-c.example by final.example; Mon, 1 Jan 2024 11:00:00 +0000\r\n'
        b'Received: from relay-b.example by mid.example; not-a-real-date\r\n'
        b'Received: from relay-a.example by origin.example; Mon, 1 Jan 2024 12:00:00 +0000\r\n'
        b'From: sender@example.com\r\n'
        b'To: recipient@example.com\r\n'
        b'Subject: Test\r\n'
        b'Message-ID: <abc@example.com>\r\n'
        b'\r\n'
        b'Body text.\r\n'
    )
    assert 'Relay timestamp reversal' in _titles(raw)


def test_no_reversal_flagged_for_consistent_hop_order():
    raw = (
        b'Received: from relay-c.example by final.example; Mon, 1 Jan 2024 12:10:00 +0000\r\n'
        b'Received: from relay-b.example by mid.example; not-a-real-date\r\n'
        b'Received: from relay-a.example by origin.example; Mon, 1 Jan 2024 12:00:00 +0000\r\n'
        b'From: sender@example.com\r\n'
        b'To: recipient@example.com\r\n'
        b'Subject: Test\r\n'
        b'Message-ID: <abc@example.com>\r\n'
        b'\r\n'
        b'Body text.\r\n'
    )
    assert 'Relay timestamp reversal' not in _titles(raw)

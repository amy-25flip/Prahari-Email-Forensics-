import dkim
import dns.resolver
import arc_verification as arc


def test_disabled_when_not_live():
    result = arc.verify(b'From: a@b.com\r\nSubject: x\r\n\r\nbody', False)
    assert result['status'] == 'unknown'


def test_not_present_for_ordinary_email(monkeypatch):
    monkeypatch.setattr(dkim, 'arc_verify', lambda *a, **k: (dkim.CV_None, [], 'Message is not ARC signed'))
    result = arc.verify(b'From: a@b.com\r\nSubject: x\r\n\r\nbody', True)
    assert result['status'] == 'not_present'


def test_pass_reports_chain_length(monkeypatch):
    # Shaped like dkimpy's real ARC.verify_instance() output (confirmed via
    # inspect.getsource): keys are 'instance'/'as-domain'/'cv', not 'd'/'i'.
    monkeypatch.setattr(dkim, 'arc_verify', lambda *a, **k: (
        dkim.CV_Pass, [{'instance': 1, 'as-domain': 'example.com', 'cv': 'pass'}], None))
    result = arc.verify(b'raw', True)
    assert result['status'] == 'pass'
    assert result['chain_length'] == 1
    assert result['chain'][0]['domain'] == 'example.com'
    assert result['chain'][0]['instance'] == 1


def test_fail_is_reported_with_reason(monkeypatch):
    monkeypatch.setattr(dkim, 'arc_verify', lambda *a, **k: (
        dkim.CV_Fail, [{'instance': 1, 'as-domain': 'example.com', 'cv': 'fail'}], 'seal mismatch'))
    result = arc.verify(b'raw', True)
    assert result['status'] == 'fail'
    assert 'seal mismatch' in result['detail']


def test_exception_is_caught_not_raised(monkeypatch):
    def boom(*a, **k): raise RuntimeError('dns exploded')
    monkeypatch.setattr(dkim, 'arc_verify', boom)
    result = arc.verify(b'raw', True)
    assert result['status'] == 'unknown'


def test_fail_is_downgraded_to_unknown_when_a_dns_lookup_failed(monkeypatch):
    # Regression: confirmed live against a real Google email -- a transient DNS timeout
    # looking up the ARC-Seal's signing key flipped the verdict between pass and fail
    # across identical retries of the same message. dkim.ARC.verify() can't distinguish
    # "key genuinely absent/forged" from "DNS query timed out" -- both collapse to the
    # same CV_Fail. Penalizing a legitimate sender's attribution confidence for an
    # environmental DNS hiccup (rather than a real broken seal) is worse than reporting
    # it as inconclusive, matching this codebase's existing "DNS outages do not add
    # failure penalties" principle used for SPF/DKIM/DMARC.
    def fake_arc_verify(raw, dnsfunc, timeout):
        dnsfunc(b'arc-selector._domainkey.example.com')  # simulates the failing lookup
        return dkim.CV_Fail, [{'instance': 1, 'as-domain': b'example.com', 'cv': b'fail'}], 'ARC-Seal did not validate'
    monkeypatch.setattr(dkim, 'arc_verify', fake_arc_verify)
    monkeypatch.setattr('dns.resolver.resolve', lambda *a, **k: (_ for _ in ()).throw(dns.resolver.LifetimeTimeout()))
    result = arc.verify(b'raw', True)
    assert result['status'] == 'unknown'
    assert 'DNS' in result['detail']


def test_fail_stays_fail_when_dns_gives_a_definitive_negative_answer(monkeypatch):
    # Counterpart to the test above: NXDOMAIN/NoAnswer mean the selector genuinely has
    # no published key -- real evidence of an absent/forged seal, not DNS flakiness.
    # This must NOT be downgraded, or a genuinely broken ARC chain could hide behind the
    # same 'unknown' treatment meant for transient DNS trouble.
    def fake_arc_verify(raw, dnsfunc, timeout):
        dnsfunc(b'arc-selector._domainkey.example.com')
        return dkim.CV_Fail, [{'instance': 1, 'as-domain': b'example.com', 'cv': b'fail'}], 'ARC-Seal did not validate'
    monkeypatch.setattr(dkim, 'arc_verify', fake_arc_verify)
    monkeypatch.setattr('dns.resolver.resolve', lambda *a, **k: (_ for _ in ()).throw(dns.resolver.NXDOMAIN()))
    result = arc.verify(b'raw', True)
    assert result['status'] == 'fail'


def test_real_message_with_no_arc_headers_end_to_end():
    # No monkeypatching: exercises the real dkimpy call path against a plain message.
    # live=True but DNS should never actually be reached since there's nothing to verify.
    raw = b'From: a@b.com\r\nTo: c@d.com\r\nSubject: no arc\r\n\r\nplain body text\r\n'
    result = arc.verify(raw, True)
    assert result['status'] == 'not_present'


def test_chain_entries_are_json_serializable_when_dkimpy_returns_bytes(monkeypatch):
    # Regression: dkimpy's real ARC.verify_instance() (confirmed via inspect.getsource,
    # not assumed) returns 'as-domain'/'cv' as bytes and no 'd'/'i' keys at all -- every
    # test above previously monkeypatched str values under the wrong key names, which hid
    # both a JSON-serialization crash (TypeError: Object of type bytes is not JSON
    # serializable) and a silent data-loss bug (the real per-hop domain/instance were
    # never actually being read). Both only surfaced against a real ARC-signed email (a
    # genuine Google account-notification message) analyzed through the live app.
    import json
    monkeypatch.setattr(dkim, 'arc_verify', lambda *a, **k: (
        dkim.CV_Pass, [{'instance': 1, 'as-domain': b'google.com', 'cv': b'none'}], None))
    result = arc.verify(b'raw', True)
    assert result['chain'][0]['domain'] == 'google.com'
    assert result['chain'][0]['instance'] == 1
    assert result['chain'][0]['cv'] == 'none'
    json.dumps(result)

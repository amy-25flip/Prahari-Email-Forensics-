import dkim
import arc_verification as arc


def test_disabled_when_not_live():
    result = arc.verify(b'From: a@b.com\r\nSubject: x\r\n\r\nbody', False)
    assert result['status'] == 'unknown'


def test_not_present_for_ordinary_email(monkeypatch):
    monkeypatch.setattr(dkim, 'arc_verify', lambda *a, **k: (dkim.CV_None, [], 'Message is not ARC signed'))
    result = arc.verify(b'From: a@b.com\r\nSubject: x\r\n\r\nbody', True)
    assert result['status'] == 'not_present'


def test_pass_reports_chain_length(monkeypatch):
    monkeypatch.setattr(dkim, 'arc_verify', lambda *a, **k: (dkim.CV_Pass, [{'d': 'example.com', 'i': '1', 'cv': 'pass'}], None))
    result = arc.verify(b'raw', True)
    assert result['status'] == 'pass'
    assert result['chain_length'] == 1
    assert result['chain'][0]['d'] == 'example.com'


def test_fail_is_reported_with_reason(monkeypatch):
    monkeypatch.setattr(dkim, 'arc_verify', lambda *a, **k: (dkim.CV_Fail, [{'d': 'example.com', 'i': '1', 'cv': 'fail'}], 'seal mismatch'))
    result = arc.verify(b'raw', True)
    assert result['status'] == 'fail'
    assert 'seal mismatch' in result['detail']


def test_exception_is_caught_not_raised(monkeypatch):
    def boom(*a, **k): raise RuntimeError('dns exploded')
    monkeypatch.setattr(dkim, 'arc_verify', boom)
    result = arc.verify(b'raw', True)
    assert result['status'] == 'unknown'


def test_real_message_with_no_arc_headers_end_to_end():
    # No monkeypatching: exercises the real dkimpy call path against a plain message.
    # live=True but DNS should never actually be reached since there's nothing to verify.
    raw = b'From: a@b.com\r\nTo: c@d.com\r\nSubject: no arc\r\n\r\nplain body text\r\n'
    result = arc.verify(raw, True)
    assert result['status'] == 'not_present'

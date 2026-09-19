"""Redacted-export projection edge cases."""
import privacy


def _base_report():
    return {
        'id': 'case-1', 'created': 0, 'sha256': 'a' * 64, 'score': 10, 'risk': 'Low',
        'authentication': {'spf': {'status': 'pass'}, 'dkim': {'status': 'pass'},
                           'dmarc': {'status': 'pass'}, 'arc': {'status': 'none'}},
        'ml': {'label': 'legitimate'}, 'findings': [],
    }


def test_redact_masks_all_auth_statuses_when_present():
    out = privacy.redact(_base_report())
    assert set(out['authentication']) == {'spf', 'dkim', 'dmarc', 'arc'}
    assert out['authentication']['arc'] == {'status': 'none', 'detail': '[REDACTED]'}
    assert out['subject'] == '[REDACTED]' and out['privacy']['mode'] == 'redacted'


def test_redact_tolerates_a_case_missing_the_arc_key():
    # Regression: a retained cases.sqlite row stored before ARC support was added
    # has no authentication.arc key. Redaction hard-subscripted every auth name,
    # so a redacted export of such a row raised KeyError -> 500. It must degrade
    # a missing mechanism to an 'unknown' status instead.
    report = _base_report()
    del report['authentication']['arc']
    out = privacy.redact(report)
    assert out['authentication']['arc'] == {'status': 'unknown', 'detail': '[REDACTED]'}


def test_redact_tolerates_authentication_missing_entirely():
    report = _base_report()
    del report['authentication']
    out = privacy.redact(report)
    assert all(out['authentication'][name]['status'] == 'unknown'
               for name in ('spf', 'dkim', 'dmarc', 'arc'))

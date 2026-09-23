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


def test_redact_preserves_stable_finding_ids():
    # Regression (Codex, whole-session integration review): findings gained
    # a stable 'id' field this session (see finding_ids.py) so a forensic
    # report can cite a specific finding across re-analysis/exports. redact()
    # rebuilt each finding as a fresh dict of only group/title/detail/points
    # and silently dropped 'id' -- so a REDACTED export lost that citation
    # ability entirely, even though a full export keeps it.
    report = _base_report()
    report['findings'] = [{'id': 'abc123', 'group': 'links', 'title': 'Suspicious URL', 'detail': 'http://evil.example', 'points': 10}]
    out = privacy.redact(report)
    assert out['findings'][0]['id'] == 'abc123'
    assert out['findings'][0]['detail'] == '[REDACTED]'  # the actual fix must not weaken masking


def test_redact_tolerates_a_finding_missing_id_entirely():
    # Legacy/pre-existing stored cases were saved before finding_ids.py
    # existed, so their findings have no 'id' key -- must degrade to None,
    # never KeyError into a 500 on redacted export of an old case.
    report = _base_report()
    report['findings'] = [{'group': 'links', 'title': 'Suspicious URL', 'detail': 'http://evil.example', 'points': 10}]
    out = privacy.redact(report)
    assert out['findings'][0]['id'] is None

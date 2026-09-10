import attribution


def base_report(**overrides):
    report = {
        'authentication': {'dmarc': {'status': 'unknown', 'spf_aligned': None, 'dkim_aligned': None}},
        'assessment': {'origin_evidence': {'confidence': 'undetermined'}, 'infrastructure': {'matches': []}, 'ip_reputation': []},
        'domain_intelligence': {'registration': {'status': 'unavailable'}},
        'conflicts': [],
        'geo': [],
    }
    report.update(overrides)
    return report


def test_fully_authenticated_clean_report_is_high_band():
    report = base_report(
        authentication={'dmarc': {'status': 'pass', 'spf_aligned': True, 'dkim_aligned': True}},
        assessment={'origin_evidence': {'confidence': 'authenticated_observation'}, 'infrastructure': {'matches': []},
                    'ip_reputation': [{'status': 'available', 'anonymization_signal': False}]},
        domain_intelligence={'registration': {'status': 'available', 'registered_at': '2010-01-01T00:00:00Z'}},
        geo=[{'status': 'available'}],
    )
    result = attribution.assess(report)
    assert result['band'] == 'high'
    assert result['confidence_score'] >= 70


def test_undetermined_origin_caps_score_regardless_of_other_signals():
    report = base_report(
        authentication={'dmarc': {'status': 'pass', 'spf_aligned': True, 'dkim_aligned': True}},
        domain_intelligence={'registration': {'status': 'available', 'registered_at': '2010-01-01T00:00:00Z'}},
        geo=[{'status': 'available'}],
    )
    result = attribution.assess(report)
    assert result['band'] == 'low'
    assert result['confidence_score'] <= attribution.UNDETERMINED_CAP
    assert any('capped' in c for c in result['caveats'])


def test_tor_match_applies_penalty_and_is_visible_in_factors():
    report = base_report(assessment={'origin_evidence': {'confidence': 'conditional'}, 'infrastructure': {'matches': ['1.2.3.4']}, 'ip_reputation': []})
    result = attribution.assess(report)
    tor_factor = next(f for f in result['factors'] if f['factor'] == 'tor_exit_match')
    assert tor_factor['applied'] is True
    assert tor_factor['weight'] == 25


def test_all_unevaluated_inputs_do_not_crash():
    result = attribution.assess({})
    # An empty report has no conflicts to report (vacuously true), earning that one factor;
    # everything else that requires actual evidence stays unapplied.
    assert result['confidence_score'] == attribution.FACTOR_WEIGHTS['no_header_conflicts']
    assert result['band'] == 'low'
    assert isinstance(result['factors'], list) and len(result['factors']) > 0


def test_every_factor_is_always_listed_even_when_not_applied():
    result = attribution.assess(base_report())
    names = {f['factor'] for f in result['factors']}
    assert set(attribution.FACTOR_WEIGHTS) <= names


def test_score_never_negative_or_above_100():
    report = base_report(
        assessment={'origin_evidence': {'confidence': 'undetermined'}, 'infrastructure': {'matches': ['1.2.3.4']},
                    'ip_reputation': [{'status': 'available', 'anonymization_signal': True}]},
        domain_intelligence={'registration': {'status': 'available', 'registered_at': '2026-09-09T00:00:00Z'}},
        conflicts=[{}, {}, {}, {}],
    )
    result = attribution.assess(report)
    assert 0 <= result['confidence_score'] <= 100

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
    # Missing evidence is not a successful header inspection.
    assert result['confidence_score'] == 0
    assert result['band'] == 'low'
    assert isinstance(result['factors'], list) and len(result['factors']) > 0


def test_every_factor_is_always_listed_even_when_not_applied():
    result = attribution.assess(base_report())
    names = {f['factor'] for f in result['factors']}
    assert set(attribution.FACTOR_WEIGHTS) <= names


def test_all_nine_positive_factors_applied_still_caps_at_exactly_100():
    # Regression: the
    # 9 positive FACTOR_WEIGHTS values (35+10+10+10+10+10+10+5+10) sum to
    # 110, not 100. That is INTENTIONAL headroom, not a bug -- assess()'s own
    # final = min(100, ...) cap (see attribution.py) is what actually governs
    # the displayed/exported/consumed confidence_score everywhere in this
    # app (PDF export, frontend, JSON). This proves that cap actually holds
    # at the true theoretical maximum, with every one of the 9 positive
    # factors genuinely triggered at once, not just asserting a loose <=100.
    report = base_report(
        authentication={'dmarc': {'status': 'pass', 'spf_aligned': True, 'dkim_aligned': True}},
        assessment={'origin_evidence': {'confidence': 'authenticated_observation'},
                    'infrastructure': {'matches': []}, 'ip_reputation': [{'status': 'available', 'anonymization_signal': False}],
                    'checks': []},
        domain_intelligence={'registration': {'status': 'available', 'registered_at': '2010-01-01T00:00:00Z'}},
        geo=[{'status': 'available'}],
        hops=[{'index': 1}],
    )
    report['authentication']['arc'] = {'status': 'pass'}
    result = attribution.assess(report)
    applied_positive = [f for f in result['factors'] if f['direction'] == '+' and f['applied']]
    assert len(applied_positive) == len(attribution.FACTOR_WEIGHTS), \
        f'expected all 9 positive factors applied, got {[f["factor"] for f in applied_positive]}'
    assert sum(f['weight'] for f in applied_positive) == 110, 'sanity: the raw sum really is 110'
    assert result['confidence_score'] == 100, 'the final cap must bring 110 down to exactly 100, never higher'


def test_score_never_negative_or_above_100():
    report = base_report(
        assessment={'origin_evidence': {'confidence': 'undetermined'}, 'infrastructure': {'matches': ['1.2.3.4']},
                    'ip_reputation': [{'status': 'available', 'anonymization_signal': True}]},
        domain_intelligence={'registration': {'status': 'available', 'registered_at': '2026-09-09T00:00:00Z'}},
        conflicts=[{}, {}, {}, {}],
    )
    result = attribution.assess(report)
    assert 0 <= result['confidence_score'] <= 100

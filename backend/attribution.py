"""Calibrated attribution-confidence scoring.

Answers "how much should an investigator trust this email's origin evidence", not
a fraud-probability score (engine.py's evidence score already covers that) and not
a guilt/innocence verdict. Every factor is listed whether it applied or not, so the
score is auditable rather than a black box.
"""
from datetime import datetime, timezone

FACTOR_WEIGHTS = {
    'receiver_attested': 35,
    'spf_aligned': 10,
    'dkim_aligned': 10,
    'dmarc_pass': 10,
    'domain_registration': 10,
    'no_header_conflicts': 10,
    'ip_reputation_available': 10,
    'geolocation_available': 5,
}
UNDETERMINED_CAP = 20


def _domain_age_days(registered_at):
    if not isinstance(registered_at, str) or not registered_at:
        return None
    try:
        value = registered_at.replace('Z', '+00:00')
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None: parsed = parsed.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - parsed).days
    except (ValueError, TypeError):
        return None


def assess(report):
    auth = report.get('authentication') or {}
    assessment = report.get('assessment') or {}
    origin = assessment.get('origin_evidence') or {}
    infra = assessment.get('infrastructure') or {}
    ip_rep = assessment.get('ip_reputation') or []
    if not isinstance(ip_rep, list): ip_rep = []
    domain_reg = (report.get('domain_intelligence') or {}).get('registration') or {}
    conflicts = report.get('conflicts') or []
    dmarc = auth.get('dmarc') or {}

    factors, score = [], 0.0

    def add(name, applied, detail):
        nonlocal score
        weight = FACTOR_WEIGHTS[name]
        if applied: score += weight
        factors.append({'factor': name, 'direction': '+', 'weight': weight, 'applied': bool(applied), 'detail': detail})

    def penalize(name, applied, weight, detail):
        nonlocal score
        if applied: score -= weight
        factors.append({'factor': name, 'direction': '-', 'weight': weight, 'applied': bool(applied), 'detail': detail})

    receiver_attested = origin.get('confidence') == 'authenticated_observation'
    add('receiver_attested', receiver_attested,
        'Earliest reliable node established via cryptographic receiver attestation.' if receiver_attested
        else 'No receiver-attested ingress; earliest node remains an unverified header report.')

    spf_aligned = bool(dmarc.get('spf_aligned'))
    add('spf_aligned', spf_aligned, 'SPF passed and aligned with the author domain.' if spf_aligned else 'SPF not established as aligned.')

    dkim_aligned = bool(dmarc.get('dkim_aligned'))
    add('dkim_aligned', dkim_aligned, 'DKIM passed and aligned with the author domain.' if dkim_aligned else 'DKIM not established as aligned.')

    dmarc_pass = dmarc.get('status') == 'pass'
    add('dmarc_pass', dmarc_pass, 'DMARC alignment passed against current DNS.' if dmarc_pass else 'DMARC did not reach an aligned pass.')

    reg_available = domain_reg.get('status') == 'available'
    age_days = _domain_age_days(domain_reg.get('registered_at'))
    reg_trustworthy = reg_available and (age_days is None or age_days > 30)
    add('domain_registration', reg_trustworthy,
        'Sender domain registration data available and not newly registered.' if reg_trustworthy
        else 'Domain registration data unavailable, or the domain is very recently registered.')

    no_conflicts = len(conflicts) == 0
    add('no_header_conflicts', no_conflicts,
        'No header/relay conflicts detected.' if no_conflicts else f'{len(conflicts)} header/relay conflict(s) detected.')

    ip_available = any(r.get('status') == 'available' for r in ip_rep)
    add('ip_reputation_available', ip_available,
        'IP reputation data available for a reported node.' if ip_available else 'IP reputation lookup unavailable, rate-limited or disabled.')

    geo_available = any(g.get('status') == 'available' for g in (report.get('geo') or []))
    add('geolocation_available', geo_available,
        'Geolocation resolved for a reported node.' if geo_available else 'No geolocation data available for reported nodes.')

    tor_match = bool(infra.get('matches'))
    penalize('tor_exit_match', tor_match, 25,
              'Reported node matches a Tor exit snapshot.' if tor_match else 'No Tor exit-list match.')

    anon_ip = any(r.get('anonymization_signal') for r in ip_rep)
    penalize('hosting_or_proxy_ip', anon_ip, 15,
              'A reported node is classified as hosting/proxy/VPN infrastructure or carries a high abuse score.' if anon_ip
              else 'No hosting/proxy/VPN classification on reported nodes.')

    new_domain = reg_available and age_days is not None and age_days < 30
    penalize('newly_registered_domain', new_domain, 10,
              'Sender domain was registered within the last 30 days.' if new_domain else 'Sender domain is not newly registered, or age is unknown.')

    conflict_penalty = min(30, len(conflicts) * 10)
    penalize('header_conflicts', conflict_penalty > 0, conflict_penalty,
              f'{len(conflicts)} conflict(s) reduce confidence in the reported chain.' if conflicts else 'No conflicts to penalize.')

    undetermined = origin.get('confidence') == 'undetermined'
    final = max(0.0, score)
    if undetermined: final = min(final, UNDETERMINED_CAP)
    final = int(round(max(0, min(100, final))))
    band = 'low' if final < 35 else 'moderate' if final < 70 else 'high'

    caveats = ['Investigative support only, not proof of identity or legal attribution.',
               'The score reflects the trustworthiness of available origin evidence, not a probability of guilt.']
    if undetermined:
        caveats.append('Origin evidence is undetermined (no receiver attestation and no usable header chain); the score is capped regardless of other signals.')
    if not ip_rep or all(r.get('status') in ('disabled', 'unavailable') for r in ip_rep):
        caveats.append('IP reputation intelligence was not available for this analysis; enable enrichment and configure ABUSEIPDB_API_KEY for fuller coverage.')

    return {'confidence_score': final, 'band': band, 'factors': factors, 'caveats': caveats,
            'policy': 'attribution-v1; weighted transparency score over available evidence, not a calibrated statistical probability or proof of actor identity.'}

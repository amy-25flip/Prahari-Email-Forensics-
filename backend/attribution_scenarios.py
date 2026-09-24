"""Labeled validation scenarios for the attribution confidence engine.

Each scenario is a hand-built report plus the band an analyst would EXPECT, decided from the
evidence alone (before looking at the score). The test suite asserts the engine reproduces
these bands and orderings; benchmarks/attribution_matrix.py renders the same data as a
table. This validates that the hand-set weights produce the intended ordering - it does NOT
make the score a calibrated probability (see attribution.py 'policy')."""

AUTH_PASS = {'dmarc': {'status': 'pass', 'spf_aligned': True, 'dkim_aligned': True}}
OLD_DOMAIN = {'registration': {'status': 'available', 'registered_at': '2010-01-01T00:00:00Z'}}
NEW_DOMAIN = {'registration': {'status': 'available', 'registered_at': '2999-01-01T00:00:00Z'}}
CLEAN_IP = [{'status': 'available', 'anonymization_signal': False}]
HOSTING_IP = [{'status': 'available', 'anonymization_signal': True}]
HOPS = [{'ips': ['198.51.100.7']}]


def _report(origin='undetermined', auth=None, domain=None, ip=None, geo=True, tor=False,
            conflicts=0, hops=True, arc=None):
    auth = dict(auth or {'dmarc': {'status': 'unknown', 'spf_aligned': None, 'dkim_aligned': None}})
    if arc: auth['arc'] = {'status': arc}
    checks = [{'kind': 'header', 'title': f'conflict {i}'} for i in range(conflicts)]
    return {
        'authentication': auth,
        'assessment': {'origin_evidence': {'confidence': origin},
                       'infrastructure': {'matches': ['203.0.113.9'] if tor else []},
                       'ip_reputation': ip if ip is not None else [], 'checks': checks},
        'domain_intelligence': domain or {'registration': {'status': 'unavailable'}},
        'geo': [{'status': 'available'}] if geo else [],
        'hops': HOPS if hops else [],
    }


FULL_ATTESTED = dict(origin='authenticated_observation', auth=AUTH_PASS, domain=OLD_DOMAIN, ip=CLEAN_IP, arc='pass')
FULL_CONDITIONAL = dict(origin='conditional', auth=AUTH_PASS, domain=OLD_DOMAIN, ip=CLEAN_IP)

# id -> (description, report, expected band)
SCENARIOS = {
    'S01': ('Receiver-attested, fully authenticated, old domain, clean IP, valid ARC', _report(**FULL_ATTESTED), 'high'),
    'S02': ('Same as S01 plus a Tor exit match', _report(**FULL_ATTESTED, tor=True), 'high'),
    'S03': ('Receiver-attested, nothing else known', _report(origin='authenticated_observation', hops=False, geo=False), 'moderate'),
    'S04': ('Authenticated + old domain + clean IP, but no receiver attestation (headers only)', _report(**FULL_CONDITIONAL), 'moderate'),
    'S05': ('S04 plus a Tor exit match', _report(**FULL_CONDITIONAL, tor=True), 'moderate'),
    'S06': ('S04 but the sender domain is newly registered', _report(**{**FULL_CONDITIONAL, 'domain': NEW_DOMAIN}), 'moderate'),
    'S07': ('S04 plus two header/relay conflicts', _report(**FULL_CONDITIONAL, conflicts=2), 'moderate'),
    'S08': ('Origin undetermined: everything else perfect', _report(**{**FULL_ATTESTED, 'origin': 'undetermined'}), 'low'),
    'S09': ('Origin undetermined, Tor + hosting IP + new domain + failed ARC', _report(origin='undetermined', auth=AUTH_PASS, domain=NEW_DOMAIN, ip=HOSTING_IP, tor=True, arc='fail'), 'low'),
    'S10': ('No evidence at all', {}, 'low'),
    'S11': ('Header chain usable, but unauthenticated and nothing else', _report(origin='conditional'), 'low'),
    'S12': ('Receiver-attested but with two header conflicts', _report(origin='authenticated_observation', conflicts=2, geo=False), 'low'),
    'S13': ('Receiver-attested but reported node is hosting/proxy infrastructure', _report(origin='authenticated_observation', ip=HOSTING_IP, geo=False, hops=False), 'low'),
    'S14': ('Forwarded mail: DKIM aligned + valid ARC + clean chain + geo (BOUNDARY: scores exactly 35, the low/moderate cutoff)', _report(origin='conditional', auth={'dmarc': {'status': 'fail', 'spf_aligned': False, 'dkim_aligned': True}}, arc='pass'), 'moderate'),
    'S17': ('S14 without geolocation (just under the cutoff)', _report(origin='conditional', auth={'dmarc': {'status': 'fail', 'spf_aligned': False, 'dkim_aligned': True}}, arc='pass', geo=False), 'low'),
    'S15': ('S01 with a failed ARC chain instead of a valid one', _report(**{**FULL_ATTESTED, 'arc': 'fail'}), 'high'),
    'S16': ('Receiver-attested, authenticated, new domain, hosting IP, Tor match', _report(origin='authenticated_observation', auth=AUTH_PASS, domain=NEW_DOMAIN, ip=HOSTING_IP, tor=True), 'moderate'),
}

# (stronger scenario, weaker scenario): the stronger one must score strictly higher.
ORDERINGS = [
    ('S01', 'S03'), ('S01', 'S04'), ('S04', 'S05'), ('S04', 'S06'), ('S04', 'S07'),
    ('S03', 'S12'), ('S03', 'S13'), ('S04', 'S11'), ('S01', 'S15'), ('S01', 'S16'),
    ('S16', 'S13'), ('S04', 'S08'), ('S01', 'S02'),
]

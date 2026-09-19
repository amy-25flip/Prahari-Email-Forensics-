"""Allowlisted redacted report projection; never mutate retained evidence."""
def redact(report):
    masked = '[REDACTED]'
    # Tolerate a retained case that predates a given auth mechanism (e.g. an old
    # cases.sqlite row stored before ARC support was added) -- a missing key must
    # degrade to an "unknown" status, never KeyError into a 500 on redacted export.
    stored_auth = report.get('authentication') or {}
    auth = {name: {'status': (stored_auth.get(name) or {}).get('status', 'unknown'), 'detail': masked}
            for name in ('spf', 'dkim', 'dmarc', 'arc')}
    return {
        'id': report['id'], 'created': report['created'], 'sample': report.get('sample', False),
        'subject': masked, 'sender': masked, 'recipient': masked, 'body': masked,
        'sha256': report['sha256'], 'score': report['score'], 'risk': report['risk'],
        'origin': 'Withheld in redacted export', 'authentication': auth,
        'ml': {'label': report['ml']['label'], 'detail': 'Local model output; uncalibrated.'},
        'findings': [{'group': f['group'], 'title': f['title'], 'detail': masked, 'points': f['points']}
                     for f in report['findings']],
        'indicators': [], 'urls': [], 'attachments': [], 'hops': [], 'headers': [],
        'privacy': {'mode': 'redacted', 'original_preserved': True,
                    'scope': 'Content, identities, infrastructure and free-text evidence withheld. Case ID, time and original hash retained; not anonymous.'},
        'limitations': ['REDACTED DERIVATIVE REPORT: not a replacement for the original evidence.',
                        'Case ID, timestamp and original hash remain linkable. Store and share accordingly.']}

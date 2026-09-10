"""Allowlisted redacted report projection; never mutate retained evidence."""
def redact(report):
    masked = '[REDACTED]'
    auth = {name: {'status': report['authentication'][name]['status'], 'detail': masked}
            for name in ('spf', 'dkim', 'dmarc')}
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

"""STIX 2.1 bundle export for sharing case indicators (MISP-importable). Deliberately conservative:
- indicators are emitted only for cases at urgent/review triage, and only for items with adverse
  evidence (risky URLs, reply-to identity mismatches, flagged attachments, flagged infrastructure) -
  never every observed URL or IP;
- no message body, subject or recipient is exported; the caller passes an already PII-masked report;
- everything is marked TLP:AMBER and labelled a candidate needing analyst confirmation."""
import datetime
import re
import uuid

NAMESPACE = uuid.UUID('6ba7b811-9dad-11d1-80b4-00c04fd430c8')  # RFC 4122 URL namespace, used for deterministic ids
TLP_AMBER_ID = 'marking-definition--f88d31f6-486f-44da-b317-01333bde0b82'
TLP_AMBER_CREATED = '2017-01-20T00:00:00.000Z'
IDENTITY_ID = 'identity--' + str(uuid.uuid5(NAMESPACE, 'urn:prahari:tool'))


def _now():
    return datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.000Z')


def _sid(kind, *parts):
    return f'{kind}--{uuid.uuid5(NAMESPACE, "urn:prahari:" + kind + ":" + "|".join(parts))}'


def _quote(value):
    return "'" + str(value).replace('\\', '\\\\').replace("'", "\\'") + "'"


def _domain_of_address(address):
    return address.rsplit('@', 1)[1].lower() if '@' in address else ''


def _pattern_items(result):
    """(label, stix pattern, human note) for each adverse indicator."""
    items = []
    seen = set()

    def add(kind, value, pattern, note):
        if value and (kind, value) not in seen:
            seen.add((kind, value))
            items.append((kind, value, pattern, note))

    for url in result.get('urls', []):
        if url.get('score', 0) >= 40 and url.get('url'):
            add('url', url['url'], f"[url:value = {_quote(url['url'])}]", 'URL scored as risky by structural/reputation checks')
    titles = {f.get('title') for f in result.get('findings', [])}
    mismatch = bool(titles & {'Reply-To domain differs', 'Return-Path domain differs'})
    for ind in result.get('indicators', []):
        if ind.get('type') == 'reply_address' and (mismatch or result.get('triage', {}).get('priority') == 'urgent'):
            add('email', ind['value'], f"[email-addr:value = {_quote(ind['value'])}]", 'Reply address differing from the sender')
    for att in result.get('attachments', []):
        if att.get('warning') and att.get('sha256'):
            add('file', att['sha256'], f"[file:hashes.'SHA-256' = {_quote(att['sha256'])}]", 'Attachment with an active-content extension')
    for ip in ((result.get('assessment') or {}).get('infrastructure') or {}).get('matches', []) or []:
        if re.fullmatch(r'[0-9.]{7,15}', str(ip)):
            add('ip', str(ip), f"[ipv4-addr:value = {_quote(ip)}]", 'Relay address matching a Tor exit-node snapshot')
    return items


def build(result, case_id, created=None):
    created = created or _now()
    triage = (result.get('triage') or {}).get('priority', 'routine')
    score = int(result.get('score', 0) or 0)
    objects = [
        {'type': 'marking-definition', 'spec_version': '2.1', 'id': TLP_AMBER_ID, 'created': TLP_AMBER_CREATED,
         'name': 'TLP:AMBER', 'definition_type': 'tlp', 'definition': {'tlp': 'amber'}},
        {'type': 'identity', 'spec_version': '2.1', 'id': IDENTITY_ID, 'created': created, 'modified': created,
         'name': 'PRAHARI email forensics (automated analysis)', 'identity_class': 'system',
         'object_marking_refs': [TLP_AMBER_ID]},
    ]
    indicator_ids = []
    if triage in ('urgent', 'review'):
        for kind, value, pattern, note in _pattern_items(result):
            ind_id = _sid('indicator', kind, value)
            indicator_ids.append(ind_id)
            objects.append({
                'type': 'indicator', 'spec_version': '2.1', 'id': ind_id, 'created': created, 'modified': created,
                'created_by_ref': IDENTITY_ID, 'name': f'{kind} indicator from case {case_id}',
                'description': f'{note}. Candidate indicator from automated analysis; requires analyst confirmation before blocking or sharing further.',
                'indicator_types': ['malicious-activity'] if triage == 'urgent' else ['anomalous-activity'],
                'pattern': pattern, 'pattern_type': 'stix', 'pattern_version': '2.1', 'valid_from': created,
                'confidence': max(1, min(100, score)), 'labels': ['phishing-candidate'],
                'object_marking_refs': [TLP_AMBER_ID]})
    report_id = _sid('report', case_id)
    objects.append({
        'type': 'report', 'spec_version': '2.1', 'id': report_id, 'created': created, 'modified': created,
        'created_by_ref': IDENTITY_ID, 'name': f'PRAHARI case {case_id}',
        'description': (f'Automated email analysis. Triage: {triage}. Evidence score {score}/100 (heuristic, uncalibrated). '
                        'Locates relay infrastructure, not a human attacker. Message content is not included.'),
        'report_types': ['threat-report'], 'published': created,
        'object_refs': indicator_ids or [IDENTITY_ID], 'object_marking_refs': [TLP_AMBER_ID]})
    return {'type': 'bundle', 'id': _sid('bundle', case_id, created), 'objects': objects}

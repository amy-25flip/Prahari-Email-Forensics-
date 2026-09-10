"""Session-local candidate grouping, not actor attribution."""
import hashlib
import ipaddress
import re
from email.utils import parseaddr
from publicsuffixlist import PublicSuffixList

PSL = PublicSuffixList()
STRONG = {'reply_address', 'attachment_hash', 'url', 'thread_id'}


def indicators(report):
    found = {(x['type'], x['value']) for x in report.get('indicators', [])}
    address = parseaddr(report.get('sender', ''))[1].lower()
    if '@' in address:
        found.add(('sender_address', address))
        domain = address.rsplit('@', 1)[1]
        found.add(('sender_domain', PSL.privatesuffix(domain) or domain))
    for hop in report.get('hops', []):
        for value in hop.get('ips', []):
            try:
                if ipaddress.ip_address(value).is_global: found.add(('reported_ip', value))
            except ValueError: pass
    for header in report.get('headers', []):
        if header['name'].lower() in ('message-id', 'in-reply-to', 'references'):
            for value in re.findall(r'<[^<>\s]{1,250}>', header['value'])[:30]:
                found.add(('thread_id', value))
    return found


def build(reports):
    edges, parent = [], {r['id']: r['id'] for r in reports}
    def root(cid):
        while parent[cid] != cid:
            cid = parent[cid]
        return cid
    entries = [(r, indicators(r)) for r in reports]
    for index, (left, left_i) in enumerate(entries):
        for right, right_i in entries[index + 1:]:
            if left['sha256'] == right['sha256'] or bool(left.get('sample')) != bool(right.get('sample')):
                continue
            shared = sorted(left_i & right_i)
            if not shared: continue
            strong = any(kind in STRONG for kind, _ in shared)
            edges.append({'source': left['id'], 'target': right['id'],
                          'evidence': [{'type': k, 'value': v} for k, v in shared],
                          'strength': 'candidate' if strong else 'context_only',
                          'assessment': 'Shared evidence requires analyst confirmation; reported IPs and headers are untrusted.'})
            if strong: parent[root(right['id'])] = root(left['id'])
    groups = {}
    for report in reports: groups.setdefault(root(report['id']), []).append(report)
    campaigns = []
    for members in groups.values():
        if len(members) < 2: continue
        ids = sorted(r['id'] for r in members)
        campaigns.append({'id': hashlib.sha256('|'.join(ids).encode()).hexdigest()[:12],
                          'case_ids': ids, 'count': len(ids), 'sample': bool(members[0].get('sample')),
                          'first_seen': min(r['created'] for r in members),
                          'last_seen': max(r['created'] for r in members),
                          'assessment': 'Candidate group, not a confirmed fraud campaign. Common links or reply addresses can be legitimate.'})
    return {'campaigns': campaigns, 'edges': edges,
            'policy': 'Shared domains, sender addresses and IPs alone never create campaign groups. Duplicate emails and demo/live mixtures are excluded.'}

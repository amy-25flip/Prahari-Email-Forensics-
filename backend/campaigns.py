"""Session-local candidate grouping, not actor attribution."""
import hashlib
import ipaddress
import re
from email.utils import parseaddr
from publicsuffixlist import PublicSuffixList

PSL = PublicSuffixList()
STRONG = {'reply_address', 'attachment_hash', 'url', 'thread_id'}
SHINGLE_SIZE = 5
SIMILARITY_TEXT_CHARS = 4000
SIMILARITY_THRESHOLD = 0.75


def _normalize_for_similarity(report):
    text = (str(report.get('subject', '')) + '\n' + str(report.get('body', ''))).lower()
    text = re.sub(r'\s+', ' ', text).strip()
    return text[:SIMILARITY_TEXT_CHARS]


def _shingles(text):
    if len(text) < SHINGLE_SIZE: return frozenset({text}) if text else frozenset()
    return frozenset(text[i:i + SHINGLE_SIZE] for i in range(len(text) - SHINGLE_SIZE + 1))


def body_similarity(left_text, right_text):
    """Character-shingle Jaccard similarity: a dependency-free stand-in for ssdeep/TLSH
    fuzzy hashing (neither builds on this project's Windows setup -- both require native
    compilation with no available wheel here). Same underlying idea -- catches near-duplicate
    phishing templates (reworded body, different target name, same kit) that exact
    hash/URL matching misses -- without a native dependency."""
    a, b = _shingles(left_text), _shingles(right_text)
    if not a or not b: return 0.0
    return len(a & b) / len(a | b)


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
    entries = [(r, indicators(r), _normalize_for_similarity(r)) for r in reports]
    for index, (left, left_i, left_text) in enumerate(entries):
        for right, right_i, right_text in entries[index + 1:]:
            if left['sha256'] == right['sha256'] or bool(left.get('sample')) != bool(right.get('sample')):
                continue
            shared = sorted(left_i & right_i)
            similarity = body_similarity(left_text, right_text)
            fuzzy_match = similarity >= SIMILARITY_THRESHOLD
            if not shared and not fuzzy_match: continue
            strong = fuzzy_match or any(kind in STRONG for kind, _ in shared)
            evidence = [{'type': k, 'value': v} for k, v in shared]
            if fuzzy_match: evidence.append({'type': 'body_similarity', 'value': f'{similarity:.2f}'})
            edges.append({'source': left['id'], 'target': right['id'], 'evidence': evidence,
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
            'policy': 'Shared domains, sender addresses and IPs alone never create campaign groups. Near-duplicate subject/body content (character-shingle similarity) is treated as strong evidence, same as exact-matched indicators. Duplicate emails and demo/live mixtures are excluded.'}

"""Session-local candidate grouping, not actor attribution."""
import hashlib
import ipaddress
import re
from email.utils import parseaddr
from publicsuffixlist import PublicSuffixList

GRAPH_NODE_ID_LENGTH = 16

PSL = PublicSuffixList()
STRONG = {'reply_address', 'attachment_hash', 'url', 'thread_id'}
SHINGLE_SIZE = 5
SIMILARITY_TEXT_CHARS = 4000
SIMILARITY_THRESHOLD = 0.75
# Below this, a short-text Jaccard comparison is not a meaningful signal: e.g. two
# unrelated one-word subjects with empty bodies both normalize to a single shingle
# and trivially score 1.0 similarity. Require enough content for the comparison to
# actually discriminate before treating it as strong evidence.
MIN_SIMILARITY_TEXT_CHARS = 60


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


# Two tiers, deliberately conservative and tuned on a small fixture set (heuristic, not
# calibrated on real traffic): both signals must agree in each tier. The strong tier can
# group cases into a campaign; the context tier only draws a 'related' link and never
# merges cases, because two benign emails from one org can share boilerplate.
COSINE_STRONG, SIMHASH_STRONG = 0.80, 8
COSINE_CONTEXT, SIMHASH_CONTEXT = 0.55, 20  # simhash is noisy on short reworded text: loose sanity check only
MIN_SIMILARITY_WORDS = 12


def _words(text):
    """Word tokens with digits/URLs masked, so a template that only swaps names, amounts or
    links between victims still looks like the same template."""
    text = re.sub(r'https?://\S+', ' ', text)
    return re.findall(r'[a-z]{2,}', re.sub(r'\d+', ' ', text))


def _idf(token_lists):
    import math
    df = {}
    for tokens in token_lists:
        for word in set(tokens): df[word] = df.get(word, 0) + 1
    n = len(token_lists)
    return {word: math.log((1 + n) / (1 + count)) + 1 for word, count in df.items()}


def _tfidf(tokens, idf):
    import math
    counts = {}
    for word in tokens: counts[word] = counts.get(word, 0) + 1
    return {word: (1 + math.log(count)) * idf.get(word, 1.0) for word, count in counts.items()}


def cosine_similarity(left_tokens, right_tokens, idf=None):
    """TF-IDF cosine over word tokens (sublinear tf)."""
    import math
    idf = idf or _idf([left_tokens, right_tokens])
    a, b = _tfidf(left_tokens, idf), _tfidf(right_tokens, idf)
    dot = sum(weight * b.get(word, 0.0) for word, weight in a.items())
    norm = math.sqrt(sum(w * w for w in a.values())) * math.sqrt(sum(w * w for w in b.values()))
    return dot / norm if norm else 0.0


def simhash(tokens):
    """64-bit SimHash over word tokens weighted by term frequency."""
    counts = {}
    for word in tokens: counts[word] = counts.get(word, 0) + 1
    bits = [0] * 64
    for word, weight in counts.items():
        h = int.from_bytes(hashlib.blake2b(word.encode(), digest_size=8).digest(), 'big')
        for i in range(64): bits[i] += weight if (h >> i) & 1 else -weight
    return sum(1 << i for i in range(64) if bits[i] > 0)


def simhash_distance(left_hash, right_hash):
    return bin(left_hash ^ right_hash).count('1')


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
    words = [_words(text) for _, _, text in entries]
    idf = _idf(words)
    hashes = [simhash(w) if len(w) >= MIN_SIMILARITY_WORDS else None for w in words]
    for index, (left, left_i, left_text) in enumerate(entries):
        for offset, (right, right_i, right_text) in enumerate(entries[index + 1:], start=index + 1):
            if left['sha256'] == right['sha256'] or bool(left.get('sample')) != bool(right.get('sample')):
                continue
            shared = sorted(left_i & right_i)
            similarity = body_similarity(left_text, right_text)
            enough_text = len(left_text) >= MIN_SIMILARITY_TEXT_CHARS and len(right_text) >= MIN_SIMILARITY_TEXT_CHARS
            jaccard_match = similarity >= SIMILARITY_THRESHOLD and enough_text
            hybrid_note, hybrid_strong = None, False
            if not jaccard_match and enough_text and hashes[index] is not None and hashes[offset] is not None:
                cosine = cosine_similarity(words[index], words[offset], idf)
                distance = simhash_distance(hashes[index], hashes[offset])
                if cosine >= COSINE_STRONG and distance <= SIMHASH_STRONG:
                    hybrid_note, hybrid_strong = f'{cosine:.2f} (tf-idf cosine + simhash distance {distance})', True
                elif cosine >= COSINE_CONTEXT and distance <= SIMHASH_CONTEXT:
                    hybrid_note = f'{cosine:.2f} (tf-idf cosine + simhash distance {distance}, context only)'
            fuzzy_match = jaccard_match or hybrid_note is not None
            if not shared and not fuzzy_match: continue
            strong = jaccard_match or hybrid_strong or any(kind in STRONG for kind, _ in shared)
            evidence = [{'type': k, 'value': v} for k, v in shared]
            if jaccard_match: evidence.append({'type': 'body_similarity', 'value': f'{similarity:.2f}'})
            elif hybrid_note: evidence.append({'type': 'body_similarity', 'value': hybrid_note})
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


# The only node types indicators() is documented to produce. Enforced here,
# not just claimed: indicators() itself pulls arbitrary (type, value) pairs
# straight out of report['indicators'] without validating the type name, so
# without this whitelist a malformed/legacy report could inject an
# unexpected node type and silently make the "exactly these types" policy
# claim below false. this was previously true only by
# convention (every current engine.py call site happens to only ever write
# reply_address/url/attachment_hash there), not by enforcement.
KNOWN_INDICATOR_NODE_TYPES = {'sender_address', 'sender_domain', 'reported_ip', 'url', 'attachment_hash',
                               'reply_address', 'thread_id'}


def _indicator_node_id(kind, value):
    return hashlib.sha256(f'{kind}:{value}'.encode('utf-8', errors='replace')).hexdigest()[:GRAPH_NODE_ID_LENGTH]


def evidence_graph(reports):
    """A typed node/edge graph over the SAME session-scoped case indicators
    build() already extracts (see indicators() above), exposed as a proper
    graph rather than only pairwise case-to-case edges. Where build() answers
    "which two cases are linked", this answers "which cases touch domain X"
    or "how many cases share this reported IP" directly -- a case node
    connects to an indicator node for every indicator it exhibits, with the
    SAME strong/context_only confidence tiering build() already uses.

    Honest scope: node types are exactly KNOWN_INDICATOR_NODE_TYPES above --
    unrecognized indicator types are silently skipped, not fabricated into a
    surprise node type. There is deliberately NO certificate/TLS-fingerprint
    node type: this app does not collect TLS certificate data anywhere, so
    adding that node type would be a fabricated capability, not a documented
    gap. Session-scoped only, bounded by the same per-session case cap
    store.py already enforces -- this is not built to scale past that, and
    doesn't need to for this app's own case history.

    A truncated-hash node id collision (astronomically unlikely at this
    app's session-scoped case counts, but checked rather than assumed) never
    silently merges two different indicators onto one node -- it raises,
    the same "explicit exception over a silently-wrong result" convention
    training/train_phishing_model.py's own cross-split leakage check uses."""
    nodes = {}
    edges = []
    for report in reports:
        case_id = report.get('id')
        if not case_id:
            # Every stored case is assigned a real id by store.py -- a report
            # without one indicates a bug elsewhere, not a graph to build
            # around. Without this check, two such reports would silently
            # collapse onto the same 'case:' node (setdefault keeps the
            # first), same class of silent-merge the indicator-node collision
            # guard below exists to prevent -- so this is checked the same way.
            raise RuntimeError('evidence_graph() received a report with no id; every stored case must have one.')
        case_node_id = 'case:' + str(case_id)
        nodes.setdefault(case_node_id, {'id': case_node_id, 'type': 'case', 'value': case_id})
        for kind, value in sorted(indicators(report)):
            if kind not in KNOWN_INDICATOR_NODE_TYPES:
                continue
            node_id = _indicator_node_id(kind, value)
            existing = nodes.get(node_id)
            if existing is None:
                nodes[node_id] = {'id': node_id, 'type': kind, 'value': value}
            elif existing['type'] != kind or existing['value'] != value:
                raise RuntimeError(f'Evidence-graph node id collision between ({existing["type"]!r}, '
                                    f'{existing["value"]!r}) and ({kind!r}, {value!r}) -- refusing to silently '
                                    'merge two different indicators onto one node.')
            edges.append({'source': case_node_id, 'target': node_id,
                         'confidence': 'strong' if kind in STRONG else 'context_only'})
    return {'nodes': list(nodes.values()), 'edges': edges,
            'policy': 'Case-to-indicator graph, session-scoped only -- a case sharing an indicator with another case '
                      'is not proof of a common actor, same caveat as build(). Node types are limited to what this '
                      'app actually collects (address/domain/IP/URL/hash/thread); there is no certificate/TLS-'
                      'fingerprint node type since this app does not collect that data.'}

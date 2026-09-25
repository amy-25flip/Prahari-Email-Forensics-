"""Curated brand table for lookalike-domain and display-name-spoofing checks.

CURATED, NOT EXHAUSTIVE: Indian banks/payment/government identities (reused from impersonation.INDIA_DEFAULT_IDENTITIES,
whose domains were individually verified) plus a few global brands whose primary domains are well known. A brand that is
not listed is simply not covered. Findings are review hypotheses: similarity is not proof, and legitimate domains and
their subdomains are never flagged."""
import re
from email.utils import parseaddr
from publicsuffixlist import PublicSuffixList
import adversarial
import impersonation

PSL = PublicSuffixList()
GLOBAL = [
    ('Microsoft', ['microsoft.com', 'office.com', 'outlook.com', 'live.com', 'microsoftonline.com', 'windows.net', 'azure.com', 'sharepoint.com', 'msftauth.net'], ['microsoft']),
    ('Google', ['google.com', 'googleusercontent.com', 'googleapis.com', 'googleadservices.com', 'gstatic.com', 'googlesyndication.com', 'doubleclick.net', 'youtube.com'], ['google']),
    ('Apple', ['apple.com', 'icloud.com'], ['apple', 'icloud']),
    ('Amazon', ['amazon.com', 'amazon.in', 'amazonaws.com', 'amazonses.com', 'cloudfront.net', 'media-amazon.com'], ['amazon']),
    ('PayPal', ['paypal.com'], ['paypal']),
    ('Netflix', ['netflix.com'], ['netflix']),
    ('Flipkart', ['flipkart.com'], ['flipkart']),
    ('DHL', ['dhl.com'], ['dhl']),
]
LURE = re.compile(r'login|secure|verify|verif|support|account|bank|pay|update|kyc|billing|alert|refund|helpdesk|service|online|customer|care')
SHORT_TOKENS = {'State Bank of India': ['sbi'], 'HDFC Bank': ['hdfc'], 'ICICI Bank': ['icici'], 'Axis Bank': ['axisbank'],
                'Kotak Mahindra Bank': ['kotak'], 'Paytm': ['paytm'], 'PhonePe': ['phonepe'], 'Income Tax Department': ['incometax'],
                'UIDAI (Aadhaar)': ['uidai', 'aadhaar'], 'IRCTC': ['irctc'], 'EPFO': ['epfo'], 'NPCI / BHIM UPI': ['npci'],
                'Punjab National Bank': ['pnb'], 'Bank of Baroda': ['bankofbaroda'], 'DigiLocker': ['digilocker']}


def table():
    rows = [(e['name'], list(e['domains']), SHORT_TOKENS.get(e['name'], [])) for e in impersonation.INDIA_DEFAULT_IDENTITIES]
    return rows + GLOBAL


def _legit(host, domains):
    return any(host == d or host.endswith('.' + d) for d in domains)


def _label(host):
    return (PSL.privatesuffix(host) or host).split('.')[0]


def _match(host, name, domains, tokens):
    label = _label(host)
    try: shown = label.encode('ascii').decode('idna')
    except UnicodeError: shown = label
    skel = adversarial.skeleton(shown).lower()
    legit_labels = {_label(d) for d in domains}
    if label in legit_labels:
        return 'same brand name under a different domain suffix'
    if skel in legit_labels:
        return 'homoglyph/look-alike characters spell the brand name'
    leet = shown.translate(str.maketrans('01345$', 'oleass'))
    for legit in legit_labels:
        # Generic one-character edits only for long brand labels (short ones collide with ordinary words such as apple/apply);
        # short labels are matched only through digit-for-letter substitution.
        if len(legit) >= 7 and impersonation.one_edit(label, legit):
            return f'one-character edit of {legit}'
        if any(ch.isdigit() for ch in shown) and leet == legit:
            return f'digits substituted for letters spell {legit}'
    parts = [p for p in re.split(r'-', skel) if p]
    for token in tokens:
        if token in parts or (len(token) >= 5 and token in skel and LURE.search(skel)):
            return f'contains the brand name "{token}" inside an unrelated domain'
    return ''


def assess(sender, reply_to, url_hosts):
    display, address = parseaddr(str(sender or ''))
    source = impersonation.hostname(address.rsplit('@', 1)[-1]) if '@' in address else ''
    hosts = {}
    for label, host in [('sender', source), ('reply-to', impersonation.hostname(parseaddr(str(reply_to or ''))[1].rsplit('@', 1)[-1]))]:
        if host: hosts.setdefault(host, label)
    for host in url_hosts:
        host = impersonation.hostname(host or '')
        if host: hosts.setdefault(host, 'link')
    checks = []
    rows = table()
    every = [d for _, ds, _ in rows for d in ds]
    for name, domains, tokens in rows:
        for host, where in hosts.items():
            if _legit(host, every): continue
            why = _match(host, name, domains, tokens)
            if why:
                checks.append({'kind': 'lookalike_domain', 'brand': name, 'host': host, 'where': where,
                               'detail': f'{where.capitalize()} domain {host} may imitate {name}: {why}. Similarity is not proof of impersonation.'})
        shown = adversarial.skeleton(display).lower()
        if display and source and not _legit(source, every):
            words = [name.lower()] + tokens
            if any(re.search(r'(?<![a-z0-9])' + re.escape(w) + r'(?![a-z0-9])', shown) for w in words if len(w) >= 3):
                checks.append({'kind': 'display_name_spoof', 'brand': name, 'host': source, 'where': 'display name',
                               'detail': f'Display name invokes {name} but the sender domain {source} is not one of its known domains.'})
    seen, out = set(), []
    for c in checks:
        key = (c['kind'], c['brand'], c['host'])
        if key not in seen: seen.add(key); out.append(c)
    return out[:20]

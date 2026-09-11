import hashlib
import ipaddress
import re
import time
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from html.parser import HTMLParser
from urllib.parse import urlsplit, parse_qs
from publicsuffixlist import PublicSuffixList
import local_model as ml
import reputation
import domain_intelligence
import general_detection
import routing
from authentication import authenticate
from geolocation import enrich as enrich_locations
from conflicts import detect as detect_conflicts
from triage import assess, high_model_signal

PSL = PublicSuffixList()
MAX_BYTES = 1024 * 1024


def domain(address):
    value = parseaddr(str(address or ''))[1].rsplit('@', 1)
    if len(value) != 2:
        return ''
    try:
        return value[1].lower().strip('.').encode('idna').decode('ascii')
    except UnicodeError:
        return ''


def base(value):
    return PSL.privatesuffix(value) or value


class HTMLText(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.text, self.links, self.current = [], [], None
        self.hidden = 0

    def handle_starttag(self, tag, attrs):
        if tag in ('script', 'style'):
            self.hidden += 1
        if tag == 'a':
            self.current = [dict(attrs).get('href', ''), '']

    def handle_data(self, data):
        if not self.hidden:
            self.text.append(data)
            if self.current:
                self.current[1] += data

    def handle_endtag(self, tag):
        if tag in ('script', 'style'):
            self.hidden = max(0, self.hidden - 1)
        if tag == 'a' and self.current:
            self.links.append(self.current)
            self.current = None


def scan_url(value, displayed=''):
    try:
        parts = urlsplit(value)
        host = (parts.hostname or '').lower().encode('idna').decode('ascii')
        if parts.scheme.lower() not in ('http', 'https') or not host:
            return None
        reasons = general_detection.url_signals(value)
        if parts.scheme.lower() == 'http': reasons.append('Unencrypted HTTP')
        try:
            ipaddress.ip_address(host)
            reasons.append('IP address used as host')
        except ValueError:
            pass
        if parts.username: reasons.append('User information obscures destination')
        if host.startswith('xn--') or '.xn--' in host: reasons.append('Internationalized domain; review visual similarity')
        if len(host.split('.')) - len(base(host).split('.')) >= 3: reasons.append('Excessive subdomains')
        if any(k.lower() in ('redirect', 'url', 'next', 'continue', 'return', 'redirect_uri') for k in parse_qs(parts.query)):
            reasons.append('Redirect parameter')
        if len(value) > 250: reasons.append('Unusually long URL')
        shown = re.search(r'https?://[^\s<>]+', displayed)
        if shown and urlsplit(shown[0]).hostname != parts.hostname: reasons.append('Displayed URL differs from destination')
        if re.search(r'(verify|login|password|secure|account)', host + parts.path, re.I): reasons.append('Account-action wording')
        return {'url': value[:4096], 'domain': host, 'protocol': parts.scheme.upper(), 'displayed': displayed[:200],
                'reasons': reasons, 'score': min(100, sum(r not in general_detection.URL_CONTEXT_ONLY for r in reasons) * 20), 'reputation': 'Not checked', 'length': len(value)}
    except (ValueError, UnicodeError):
        return None


def extract_attachment(raw, sha256_hex):
    """Re-locate one attachment's original bytes by hash, for an explicit, opt-in
    follow-up action (e.g. sandbox submission) -- never retained across the main
    analysis pass itself."""
    if not raw or len(raw) > MAX_BYTES:
        return None
    try:
        msg = BytesParser(policy=policy.default).parsebytes(raw)
    except Exception:
        return None
    for i, part in enumerate(msg.walk()):
        if i > 100: break
        if part.is_multipart(): continue
        if not (part.get_filename() or part.get_content_disposition() == 'attachment'): continue
        payload = part.get_payload(decode=True) or b''
        if payload and hashlib.sha256(payload).hexdigest() == sha256_hex:
            return payload
    return None


def analyze(raw, source='upload', live=False, context=None):
    started = time.perf_counter()
    if not raw or len(raw) > MAX_BYTES:
        raise ValueError('Email must be between 1 byte and 1 MiB.')
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    if not msg.get('From') or not msg.get('Subject'):
        raise ValueError('Include at least From and Subject headers in a raw email.')
    attachments, texts, html_links = [], [], []
    for i, part in enumerate(msg.walk()):
        if i > 100: raise ValueError('Email has too many MIME parts (maximum 100).')
        if part.is_multipart(): continue
        payload = part.get_payload(decode=True) or b''
        if part.get_filename() or part.get_content_disposition() == 'attachment':
            name = str(part.get_filename() or 'unnamed')
            attachments.append({'name': name[:300], 'type': part.get_content_type(), 'size': len(payload),
                                'sha256': hashlib.sha256(payload).hexdigest(),
                                'warning': bool(re.search(r'\.(exe|scr|js|vbs|lnk|iso|html|htm)$', name, re.I))})
        elif part.get_content_type() in ('text/plain', 'text/html'):
            try: decoded = payload.decode(part.get_content_charset() or 'utf-8', errors='replace')
            except LookupError: decoded = payload.decode('utf-8', errors='replace')
            if part.get_content_type() == 'text/html':
                parser = HTMLText()
                parser.feed(decoded)
                texts.append(' '.join(parser.text))
                html_links.extend(parser.links)
            else: texts.append(decoded)
    body = '\n'.join(texts)[:100000]
    candidates = html_links + [(x.rstrip('.,;)'), '') for x in re.findall(r'https?://[^\s<>"\']+', body, re.I)]
    urls = {}
    for candidate, shown in candidates:
        scanned = scan_url(candidate, shown)
        if scanned and candidate not in urls: urls[candidate] = scanned
        if len(urls) >= 50: break
    feed = reputation.annotate(list(urls.values()))
    findings = []
    def flag(group, title, detail, points):
        findings.append({'group': group, 'title': title, 'detail': detail, 'points': points})
    sender = domain(msg.get('From'))
    for header, points in [('Reply-To', 20), ('Return-Path', 15)]:
        other = domain(msg.get(header))
        if sender and other and base(sender) != base(other):
            flag('identity', header + ' domain differs', f'{sender} versus {other}. Legitimate delegation is possible; inspect context.', points)
    if len(msg.get_all('From', [])) > 1: flag('identity', 'Multiple From headers', 'Ambiguous sender identity.', 25)
    if 'xn--' in sender: flag('identity', 'Internationalized sender domain', 'Review the Unicode display for impersonation.', 10)
    auth = authenticate(msg, raw, live, source, context)
    if auth['dkim']['status'] == 'fail': flag('authentication', 'DKIM signature failed', auth['dkim']['detail'], 15)
    if auth['spf']['status'] == 'fail': flag('authentication', 'SPF evaluation failed', auth['spf']['detail'], 15)
    if auth['dmarc']['status'] == 'fail': flag('authentication', 'DMARC alignment failed', auth['dmarc']['detail'], 20)
    for url in urls.values():
        if url['score'] >= 40: flag('links', 'Suspicious URL structure', '; '.join(url['reasons']), 10)
        rep = url['reputation']
        if rep['match']:
            stale = rep['feed_status'] != 'fresh'
            flag('reputation', 'Historical phishing-feed match' if stale else 'PhishTank URL match',
                 f"Record {rep['record_id']}; snapshot {rep['feed_status']}. URL matched locally, not visited.", 25 if stale else 60)
    if any(a['warning'] for a in attachments): flag('attachments', 'Active-content attachment extension', 'File was inventoried, not executed or malware-scanned.', 15)
    for title, pattern in [('Credential pressure', r'(verify.{0,40}(account|password)|account.{0,30}suspend)'),
                           ('Payment diversion', r'(bank account.{0,25}chang|transfer the payment|updated bank details)'),
                           ('Verification avoidance', r'(do not (call|contact)|bypass.{0,25}approval|keep this confidential)')]:
        match = re.search(pattern, body, re.I | re.S)
        if match: flag('language', title, match[0], 10)
    prediction = ml.classify(str(msg.get('Subject')) + '\n' + body)
    if high_model_signal(prediction):
        flag('language', 'High model phishing probability', 'Independent model evidence; uncalibrated and requires analyst review.', 30)
    caps = {'identity': 30, 'authentication': 20, 'links': 25, 'language': 35, 'attachments': 15, 'reputation': 60}
    groups = {group: min(cap, sum(f['points'] for f in findings if f['group'] == group)) for group, cap in caps.items()}
    score = min(100, sum(groups.values()))
    hops = []
    for index, header in enumerate(reversed(msg.get_all('Received', []))):
        value = str(header)
        ips = []
        for token in re.findall(r'[0-9a-fA-F:.]+', re.sub(r'IPv6:', '', value, flags=re.I)):
            try:
                ip = ipaddress.ip_address(token)
                if str(ip) not in ips: ips.append(str(ip))
            except ValueError: pass
        hops.append({'index': index + 1, 'raw': value[:2000], 'ips': ips, **routing.parse(value),
                     'trust': 'Header-reported; receiver trust not established', 'location': None})
    indicators = []
    reply = parseaddr(str(msg.get('Reply-To', '')))[1].lower()
    if reply: indicators.append({'type': 'reply_address', 'value': reply})
    for url in urls.values(): indicators.append({'type': 'url', 'value': url['url']})
    for a in attachments:
        if a['size']: indicators.append({'type': 'attachment_hash', 'value': a['sha256']})
    geo = enrich_locations(hops, live)
    return {'subject': str(msg.get('Subject'))[:500], 'sender': str(msg.get('From'))[:500], 'recipient': str(msg.get('To', ''))[:500],
            'date': str(msg.get('Date', 'Unknown')), 'body': body, 'sha256': hashlib.sha256(raw).hexdigest(),
            'source': source, 'score': score, 'risk': 'High' if score >= 60 else 'Review' if score >= 25 else 'Low',
            'score_policy': 'evidence-v2; grouped heuristic, not fraud probability', 'groups': groups,
            'domain_intelligence': domain_intelligence.lookup(sender, live),
            'reputation_feed': feed,
            'triage': assess(score, findings, prediction, list(urls.values())),
            'conflicts': detect_conflicts(findings, auth, prediction, list(urls.values())),
            'findings': findings, 'ml': prediction, 'authentication': auth, 'urls': list(urls.values()),
            'attachments': attachments, 'hops': hops, 'indicators': indicators, 'geo': geo,
            'headers': [{'name': k, 'value': str(v)[:4000]} for k, v in list(msg.items())[:100]],
            'origin': 'Unverified', 'coverage': {'completed': 4 + int(auth['dkim']['status'] in ('pass', 'fail')), 'total': 8},
            'limitations': ['Header-reported relays do not identify a human sender.',
                            'PhishTank has limited coverage; an unlisted URL is not necessarily safe. No destination URLs are visited.',
                            'IP geolocation requires opt-in enrichment and does not locate the human sender.',
                            'SPF using supplied SMTP context is conditional on those inputs; current DNS may differ from historical DNS.',
                            'Coverage counts completed checks, not confidence or safety.'],
            'elapsed_ms': round((time.perf_counter() - started) * 1000), 'live_dns': live}

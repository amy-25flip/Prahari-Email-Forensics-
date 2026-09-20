import hashlib
import ipaddress
import os
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
import prompt_injection
import adversarial
import pii
import routing
from authentication import authenticate
from geolocation import enrich as enrich_locations
from conflicts import detect as detect_conflicts
from triage import assess, high_model_signal

PSL = PublicSuffixList()
MAX_BYTES = 1024 * 1024
ADVERSARIAL_DELTA = float(os.getenv('ADVERSARIAL_DELTA', '40'))  # heuristic min prob jump to flag NLP evasion; not a calibrated figure


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
        # A stack, not a single slot: html.parser is a permissive tokenizer,
        # not a real HTML5 tree constructor, so it does NOT auto-close an <a>
        # when another <a> starts inside it (real browsers do). A single
        # self.current slot meant a nested <a href="evil"><a href="benign">
        # click</a></a> silently dropped the outer href the moment the inner
        # </a> fired -- a concrete way to hide a malicious link from every
        # downstream check. Each open <a> now gets its own frame; closing one
        # always records it, however deep it was nested.
        self.text, self.links, self.stack = [], [], []
        self.hidden = 0

    def handle_starttag(self, tag, attrs):
        if tag in ('script', 'style'):
            self.hidden += 1
        if tag == 'a':
            self.stack.append([dict(attrs).get('href', ''), ''])

    def handle_data(self, data):
        if not self.hidden:
            self.text.append(data)
            for frame in self.stack:
                frame[1] += data

    def handle_endtag(self, tag):
        if tag in ('script', 'style'):
            self.hidden = max(0, self.hidden - 1)
        if tag == 'a' and self.stack:
            self.links.append(self.stack.pop())


def scan_url(value, displayed=''):
    try:
        parts = urlsplit(value)
        raw_host = (parts.hostname or '').lower()
        # A host that fails IDNA encoding (e.g. an empty label like
        # "example..com") is itself a red flag, not a reason to drop the URL
        # from analysis entirely -- a genuinely missing host (raw_host=='')
        # still short-circuits below via `not host`, but a malformed one now
        # gets scored and flagged instead of silently disappearing.
        try:
            host = raw_host.encode('idna').decode('ascii')
            malformed_host = False
        except UnicodeError:
            host = raw_host
            malformed_host = True
        if parts.scheme.lower() not in ('http', 'https') or not host:
            return None
        reasons = general_detection.url_signals(value)
        if malformed_host: reasons.append('Malformed or invalid host encoding')
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


def interpret_model(prediction, auth):
    """Turn the raw content-classifier output into a banded, authentication-aware
    verdict for display. The evidence engine only treats the model as a strong
    signal at >=90% phishing probability (triage.high_model_signal), but the raw
    argmax label reads "PHISHING" for anything over 50%, which overstates a weak
    signal. A cryptographically authenticated sender (DMARC pass, or DKIM+SPF
    pass) is not spoofing its domain, so content resemblance alone is much weaker
    evidence there -- legitimate security/transactional mail is this model's
    classic false-positive class. The raw label and probability are preserved on
    the prediction; this only affects how the signal is summarised."""
    unavailable = {'band': 'unavailable', 'summary': 'Model unavailable', 'authenticated_sender': False, 'note': None}
    if prediction.get('status') != 'ready':
        return unavailable
    pp = prediction.get('phishing_probability')
    if not isinstance(pp, (int, float)) or isinstance(pp, bool):
        return unavailable
    authenticated = (auth.get('dmarc', {}).get('status') == 'pass'
                     or (auth.get('dkim', {}).get('status') == 'pass' and auth.get('spf', {}).get('status') == 'pass'))
    note = None
    if pp < 60:
        band, summary = 'legitimate', 'Likely legitimate'
    elif pp < 90:
        if authenticated:
            band, summary = 'legitimate', 'Likely legitimate'
            note = ('Content resembles phishing, but the sender is cryptographically authenticated '
                    '(DMARC, or DKIM and SPF, pass), which is inconsistent with domain spoofing. '
                    'Treated as a weak content-similarity signal, not a verdict.')
        else:
            band, summary = 'uncertain', 'Uncertain content signal'
    else:
        if authenticated:
            band, summary = 'caution', 'Authenticated sender — content flagged'
            note = ('The sending domain is cryptographically authenticated (DMARC, or DKIM and SPF, '
                    'pass), so this is not domain spoofing. The content resembles phishing, which is '
                    'common for legitimate security and transactional mail; verify only if the message '
                    'is unexpected or asks you to act. Uncalibrated content signal.')
        else:
            band, summary = 'phishing', 'Likely phishing'
    return {'band': band, 'summary': summary, 'phishing_probability': pp,
            'authenticated_sender': authenticated, 'note': note}


def analyze(raw, source='upload', live=False, context=None):
    started = time.perf_counter()
    if not raw or len(raw) > MAX_BYTES:
        raise ValueError('Email must be between 1 byte and 1 MiB.')
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    # Subject is optional per RFC 5322 and commonly sent blank -- msg.get()
    # returns '' (falsy) for a present-but-empty header and None only when
    # the header is genuinely absent, so `not msg.get('Subject')` wrongly
    # rejected a real, legitimately blank-subject email as malformed.
    # Confirmed live: a real Gmail-push email with Subject: <empty> was
    # permanently dropped by this check. From has no such legitimate empty
    # case (a blank sender is not a real, deliverable email), so it keeps
    # the stricter truthiness check.
    if not msg.get('From') or msg.get('Subject') is None:
        raise ValueError('Include at least From and Subject headers in a raw email.')
    attachments, texts, html_links, html_sources = [], [], [], []
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
                html_sources.append(decoded)
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
    classifier_text = str(msg.get('Subject')) + '\n' + body
    prediction = ml.classify(classifier_text)
    prediction['verdict'] = interpret_model(prediction, auth)
    if high_model_signal(prediction):
        flag('language', 'High model phishing probability', 'Independent model evidence; uncalibrated and requires analyst review.', 30)
    # Adversarial-evasion check: only classify a second (normalized) copy when the
    # raw text actually contains homoglyph/zero-width characters (cheap gate), then
    # flag a large probability jump as a deliberate attempt to blind the classifier.
    adversarial_delta = None
    if adversarial.contains_suspect(classifier_text):
        normalized = adversarial.skeleton(classifier_text)
        if normalized != classifier_text:
            alt = ml.classify(normalized)
            raw_pp, alt_pp = prediction.get('phishing_probability'), alt.get('phishing_probability')
            numeric = (prediction.get('status') == 'ready' and alt.get('status') == 'ready'
                       and isinstance(raw_pp, (int, float)) and not isinstance(raw_pp, bool)
                       and isinstance(alt_pp, (int, float)) and not isinstance(alt_pp, bool))
            if numeric:
                delta = round(alt_pp - raw_pp, 1)
                flagged = delta >= ADVERSARIAL_DELTA
                adversarial_delta = {'raw_probability': raw_pp, 'normalized_probability': alt_pp,
                                     'delta': delta, 'flagged': flagged,
                                     'detail': 'Phishing probability on the raw text versus a homoglyph/zero-width-normalized copy.'}
                if flagged:
                    flag('manipulation', 'Possible adversarial NLP evasion signal',
                         'Homoglyph/zero-width obfuscation lowers the model phishing probability by '
                         f'{delta:.0f} points ({alt_pp:.0f}% on normalized text vs {raw_pp:.0f}% raw), '
                         'consistent with content crafted to evade automated classification.', 25)
    # instruction_pattern is matched directly against classifier_text -- the
    # SAME string just handed to ml.classify() -- so that indicator type is
    # proven to be content the model actually sees. hidden_instruction (an
    # instruction pattern found specifically inside CSS-hidden content) and
    # hidden_comment_raw_html_only (found only in an HTML comment, which
    # HTMLText never extracts) are scored lower/differently below precisely
    # because they don't carry that same guarantee -- see prompt_injection.py.
    manipulation = prompt_injection.scan(classifier_text, html_sources)
    # hidden_content_present is deliberately 0: CSS-hidden text with no
    # instruction pattern in it (preheader text, ESP boilerplate) is normal
    # in legitimate marketing/transactional email and must never move the
    # score on its own -- it stays visible in the dedicated panel via
    # result['prompt_injection'] without being added to scored findings.
    manipulation_points = {'instruction_pattern': 25, 'hidden_instruction': 35,
                            'hidden_comment_raw_html_only': 15, 'hidden_content_present': 0,
                            'zero_width_characters': 15}
    for indicator in manipulation['indicators']:
        points = manipulation_points[indicator['type']]
        if points > 0:
            flag('manipulation', indicator['description'], indicator['excerpt'] or manipulation['detail'], points)
    caps = {'identity': 30, 'authentication': 20, 'links': 25, 'language': 35, 'attachments': 15, 'reputation': 60, 'manipulation': 40}
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
            'prompt_injection': manipulation, 'adversarial': adversarial_delta, 'pii': pii.scan(classifier_text),
            'headers': [{'name': k, 'value': str(v)[:4000]} for k, v in list(msg.items())[:100]],
            'origin': 'Unverified', 'coverage': {'completed': 4 + int(auth['dkim']['status'] in ('pass', 'fail')), 'total': 8},
            'limitations': ['Header-reported relays do not identify a human sender.',
                            'PhishTank has limited coverage; an unlisted URL is not necessarily safe. No destination URLs are visited.',
                            'IP geolocation requires opt-in enrichment and does not locate the human sender.',
                            'SPF using supplied SMTP context is conditional on those inputs; current DNS may differ from historical DNS.',
                            'Coverage counts completed checks, not confidence or safety.'],
            'elapsed_ms': round((time.perf_counter() - started) * 1000), 'live_dns': live}

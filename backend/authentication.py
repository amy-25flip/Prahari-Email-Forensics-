"""Current-DNS authentication, with explicit provenance for SMTP inputs."""
import re
import time
from email.utils import getaddresses
import dkim
import dns.resolver
import spf
import arc_verification


def address_domain(value):
    addresses = getaddresses([str(value or '')])
    if len(addresses) != 1 or '@' not in addresses[0][1]: return ''
    try: return addresses[0][1].rsplit('@', 1)[1].rstrip('.').encode('idna').decode().lower()
    except UnicodeError: return ''


def parse_policy(record):
    pairs = [p.strip().split('=', 1) for p in record.split(';') if p.strip()]
    if not pairs or any(len(p) != 2 for p in pairs): return None
    tags = {k.strip(): v.strip() for k, v in pairs}
    # pairs[0] itself is unstripped around the '=' (only the whole segment
    # was stripped above) -- comparing it directly rejected a record like
    # "v = DMARC1; p=reject" (extra spacing, which real registrar/admin UIs
    # commonly insert) even though record()'s own regex pre-filter already
    # matched it as DMARC1. Strip both sides before comparing.
    first_key, first_value = (x.strip() for x in pairs[0])
    if first_key != 'v' or first_value != 'DMARC1' or len(tags) != len(pairs): return None
    # RFC 7489: 'p' is a mandatory tag. A record missing it entirely is
    # simply invalid -- it must not fall into the same recovery path as a
    # record that HAS a 'p' but the value is malformed/unsupported, or a
    # DMARC record with no policy at all silently becomes an accepted
    # "p=none" monitoring policy as long as rua happens to be present.
    if 'p' not in tags: return None
    for tag in ('adkim', 'aspf'):
        if tags.get(tag, 'r') not in ('r', 's'): return None
    if tags.get('psd', 'u') not in ('y', 'n', 'u'): return None
    if any(tags.get(t, tags['p']) not in ('none', 'quarantine', 'reject') for t in ('p', 'sp', 'np')):
        if not any(re.fullmatch(r'mailto:[^\s@,]+@[^\s@,]+', uri.strip()) for uri in tags.get('rua', '').split(',')): return None
        tags['p'] = 'none'
        tags.pop('sp', None)
        tags.pop('np', None)
    return tags


class PolicyLookup:
    def __init__(self, txt):
        self.txt, self.cache, self.walks = txt, {}, {}
        self.invalid = False

    def record(self, domain):
        if domain not in self.cache:
            values = [r for r in self.txt('_dmarc.' + domain) if re.match(r'^v\s*=\s*DMARC1(?:\s*;|\s*$)', r)]
            self.cache[domain] = (parse_policy(values[0]), values[0]) if len(values) == 1 else (None, None)
            if values and not self.cache[domain][0]: self.invalid = True
        return self.cache[domain]

    def walk(self, domain):
        if domain in self.walks: return self.walks[domain]
        labels, records = domain.split('.'), []
        names = [domain] + ['.'.join(labels[i:]) for i in range(max(1, len(labels) - 7), len(labels))]
        for name in names:
            tags, raw = self.record(name)
            if tags:
                records.append((name, tags, raw))
                if tags.get('psd') in ('y', 'n'): break
        self.walks[domain] = records
        return records

    def organization(self, domain):
        records = self.walk(domain)
        for name, tags, _ in records:
            if tags.get('psd') == 'n': return name
            if tags.get('psd') == 'y' and name != domain:
                return '.'.join(domain.split('.')[-len(name.split('.')) - 1:])
        return records[-1][0] if records else domain

    def policy(self, author):
        tags, raw = self.record(author)
        if tags: return author, tags, raw
        org = self.organization(author)
        records = self.walk(author)
        for name, tags, raw in records:
            if name == org: return name, tags, raw
        for name, tags, raw in reversed(records):
            if tags.get('psd') == 'y': return name, tags, raw
        return None

    def aligned(self, signer, author, mode):
        if signer == author: return True
        return mode == 'r' and self.organization(signer) == self.organization(author)


def authenticate(msg, raw, live, source, context=None):
    observed = time.time()
    result = {name: {'status': 'unknown', 'detail': 'External DNS verification disabled.', 'observed_at': observed} for name in ('spf', 'dkim', 'dmarc', 'arc')}
    signatures = msg.get_all('DKIM-Signature', [])
    if not signatures: result['dkim'].update(status='missing', detail='No DKIM signature present.')
    if not context:
        if source == 'gmail-push':
            # Structural, not an oversight: the Gmail API's messages.get
            # (format=raw) returns only the RFC822 message bytes, never the
            # original SMTP transaction (connecting IP/MAIL FROM/HELO) --
            # there is no side channel to recover real envelope data for a
            # message ingested this way. This is NOT a total authentication
            # blind spot: DKIM verification and DMARC's DKIM-alignment path
            # both run unconditionally below (no context needed), so a
            # gmail-push email can still reach a genuine DMARC 'pass'/'fail'
            # via DKIM alone -- SPF specifically is the only mechanism that
            # structurally cannot be evaluated for this ingestion path.
            result['spf']['detail'] = ('SMTP client IP, MAIL FROM and HELO are not available for Gmail-push-ingested '
                                        "mail -- the Gmail API's raw message fetch does not expose the original SMTP "
                                        'transaction. DKIM and DMARC (via DKIM alignment) are still evaluated below.')
        else:
            result['spf']['detail'] = 'SMTP client IP, MAIL FROM and HELO are not established. Supply receiver context to evaluate SPF.'
    result['spf']['context_source'] = 'analyst-supplied; not independently authenticated' if context else 'unavailable'
    if context: result['spf']['inputs'] = context
    if not live: return result
    result['arc'] = {**arc_verification.verify(raw, live), 'observed_at': observed}
    deadline = time.monotonic() + 18
    def txt(name):
        remaining = deadline - time.monotonic()
        if remaining <= 0: raise dns.resolver.LifetimeTimeout()
        try:
            answer = dns.resolver.resolve(name, 'TXT', lifetime=min(2, remaining))
            return [b''.join(r.strings).decode('ascii', errors='replace') for r in answer]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer): return []

    if context:
        sender = '' if context['mail_from'] == '<>' else context['mail_from']
        try:
            state, explanation = spf.check2(i=context['client_ip'], s=sender, h=context['helo'], timeout=2, querytime=6)
            result['spf'].update(status=state, detail=explanation + ' Evaluated with analyst-supplied inputs against current DNS.',
                                 domain=address_domain(sender) if sender else context['helo'])
        except Exception as exc:
            result['spf'].update(status='temperror', detail=f'SPF evaluation unavailable ({type(exc).__name__}); no failure penalty.')

    checks = []
    for index, signature in enumerate(signatures[:4]):
        tags = dict(re.findall(r'(\w+)\s*=\s*([^;]+)', str(signature)))
        item = {'domain': tags.get('d', '').strip().lower(), 'selector': tags.get('s', '').strip(), 'status': 'unknown'}
        errors = []
        def key_lookup(name, timeout=2):
            try:
                records = txt(name.decode().rstrip('.'))
                if len(records) != 1:
                    errors.append('missing or ambiguous key')
                    return b''
                return records[0].encode('ascii')
            except Exception as exc:
                errors.append(type(exc).__name__)
                return b''
        try:
            passed = dkim.DKIM(raw, timeout=2).verify(idx=index, dnsfunc=key_lookup)
            item.update(status='unknown' if errors else 'pass' if passed else 'fail',
                        detail='DNS key unavailable: ' + ', '.join(errors) if errors else 'Signature verified against current DNS.' if passed else 'Cryptographic verification failed against available key.')
        except Exception as exc:
            item.update(status='unknown' if errors else 'fail', detail='DNS key unavailable.' if errors else f'Signature could not be verified ({type(exc).__name__}).')
        if source == 'paste':
            item['input_source'] = 'pasted text'
            if item['status'] == 'pass':
                item['detail'] += ' Verified on submitted text; original file provenance is not established.'
            else:
                item['status'] = 'unknown'
                item['detail'] += ' Pasting may change signed content; upload the original .eml to investigate.'
        checks.append(item)
    if checks:
        state = 'pass' if any(c['status'] == 'pass' for c in checks) else 'unknown' if len(signatures) > 4 or any(c['status'] == 'unknown' for c in checks) else 'fail'
        result['dkim'].update(status=state, signatures=checks, detail=f'{len(checks)} of {len(signatures)} signatures evaluated. ' + ('At least one signature verified.' if state == 'pass' else 'See per-signature results.'))

    author = address_domain(msg.get('From'))
    if not author or len(msg.get_all('From', [])) != 1:
        result['dmarc'].update(detail='A single unambiguous From mailbox is required.')
        return result
    try:
        lookup = PolicyLookup(txt)
        policy = lookup.policy(author)
        if not policy:
            result['dmarc'].update(status='unknown' if lookup.invalid else 'none', detail='Invalid or ambiguous DMARC configuration encountered.' if lookup.invalid else 'No applicable valid DMARC policy found in current DNS.')
            return result
        policy_domain, tags, record = policy
        # RFC 7489 SS6.6.3: when the returned record belongs to an ANCESTOR
        # domain (policy_domain != author -- author had no DMARC record of
        # its own, so the organizational/PSD record above it was used), the
        # 'sp' tag (if present) is the effective policy for that subdomain,
        # not 'p' -- 'p' only applies directly when the record was found at
        # author's own exact domain. Using tags['p'] unconditionally here
        # misreported e.g. p=reject; sp=quarantine as "reject" for genuine
        # subdomain mail that the publisher explicitly meant to quarantine,
        # not reject -- misleading evidence for an analyst reading this field,
        # even though it never changed the computed pass/fail/unknown verdict
        # above (that only depends on alignment, not the policy tag's value).
        effective_policy = tags.get('sp', tags['p']) if policy_domain != author else tags['p']
        result['dmarc'].update(policy_domain=policy_domain, record=record, published_policy=effective_policy, standard='RFC 9989 DNS tree walk', detail='Alignment evaluated against current DNS, not delivery-time DNS.')
        spf_aligned = result['spf']['status'] == 'pass' and lookup.aligned(result['spf']['domain'], author, tags.get('aspf', 'r'))
        dkim_aligned = any(c['status'] == 'pass' and lookup.aligned(c['domain'], author, tags.get('adkim', 'r')) for c in checks)
        if not spf_aligned and result['spf']['status'] in ('unknown', 'temperror'): spf_aligned = None
        if not dkim_aligned and result['dkim']['status'] == 'unknown': dkim_aligned = None
        result['dmarc'].update(spf_aligned=spf_aligned, dkim_aligned=dkim_aligned)
        if spf_aligned or dkim_aligned:
            result['dmarc'].update(status='pass', detail='Aligned DKIM passed.' if dkim_aligned else 'Aligned SPF passed using analyst-supplied receiver context; conditional on those inputs.')
        elif result['spf']['status'] in ('unknown', 'temperror') or result['dkim']['status'] == 'unknown':
            result['dmarc'].update(status='unknown', detail='No aligned pass established; incomplete verification prevents a definitive failure.')
        else:
            result['dmarc'].update(status='fail', detail='Neither evaluated SPF nor DKIM produced an aligned pass. This is not proof of malicious intent.')
    except Exception as exc:
        result['dmarc'].update(status='unknown', detail=f'DMARC lookup/alignment unavailable ({type(exc).__name__}); existing DKIM/SPF results preserved.')
    return result

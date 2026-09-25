"""Safe, static landing-page inspection for a link found in an email. Analyst-triggered only.

What it does: fetches ONE page with a locked-down HTTP client and reports what the page *is* - title, forms,
password fields, where forms submit, meta-refresh, external scripts, brand cues, a structure hash. It never runs
JavaScript, never renders, never sends cookies or credentials, and never touches anything but public web hosts.

Safety (this is an SSRF/hostile-content boundary, so every rule is enforced in code and tested):
- http/https only; no userinfo in the URL; only ports 80, 443, 8080, 8443.
- The host is resolved ONCE; every resolved address must be globally routable (no private, loopback, link-local,
  CGNAT, multicast, reserved, unspecified, IPv4-mapped/NAT64/6to4/Teredo tricks). The connection is then PINNED to
  that validated address, so DNS rebinding between check and connect is impossible.
- Redirects are followed manually (max 4) and every hop is re-validated the same way.
- Hard caps: 512 KB body, 8 s total time; no compression accepted; TLS certificates are verified (an invalid
  certificate is reported, not bypassed).
- The destination will see this server's IP address - the UI requires an explicit confirmation for that reason."""
import hashlib
import http.client
import ipaddress
import re
import socket
import ssl
import time
from urllib.parse import urljoin, urlsplit

from lxml import html as lxml_html
from publicsuffixlist import PublicSuffixList

MAX_BYTES = 512 * 1024
MAX_REDIRECTS = 4
TOTAL_TIMEOUT = 8.0
CONNECT_TIMEOUT = 4.0
ALLOWED_PORTS = {80, 443, 8080, 8443}
ALLOW_PRIVATE = False        # tests only; never set in production code paths
USER_AGENT = 'PRAHARI-static-inspector/1.0 (+analyst-triggered; no JavaScript, no cookies)'
PSL = PublicSuffixList()
_BLOCKED_V6 = [ipaddress.ip_network(n) for n in ('64:ff9b::/96', '64:ff9b:1::/48', '2002::/16', '2001::/32', '100::/64', 'fec0::/10')]
BRAND_CUES = ('sbi', 'hdfc', 'icici', 'axis bank', 'pnb', 'kotak', 'paytm', 'phonepe', 'google', 'microsoft', 'office 365', 'outlook',
              'amazon', 'netflix', 'paypal', 'income tax', 'aadhaar', 'irctc', 'epfo', 'digilocker', 'whatsapp', 'facebook',
              'instagram', 'apple', 'dhl', 'fedex')
SCOPE = ('Static capture only: one page fetched without JavaScript, cookies or rendering. It shows what the page contains, not what it '
         'does after scripts run, and a clean result is not a safety guarantee. The destination saw this server\'s IP address.')


SCOPE_NOT_CONTACTED = 'No request was sent: the URL was refused before any connection was made, so the destination saw nothing.'


class Blocked(Exception):
    pass


def _is_public(ip):
    if ALLOW_PRIVATE:
        return True
    mapped = getattr(ip, 'ipv4_mapped', None)
    if mapped is not None:
        return _is_public(mapped)
    if ip.version == 6 and any(ip in net for net in _BLOCKED_V6):
        return False
    return bool(ip.is_global) and not (ip.is_multicast or ip.is_reserved or ip.is_unspecified or ip.is_loopback or ip.is_link_local or ip.is_private)


def _resolve(host, port):
    try:
        literal = ipaddress.ip_address(host.strip('[]'))
        infos = [literal]
    except ValueError:
        try:
            infos = [ipaddress.ip_address(info[4][0]) for info in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)]
        except (socket.gaierror, UnicodeError, OSError) as exc:
            raise Blocked(f'Host could not be resolved ({type(exc).__name__}).') from exc
    if not infos:
        raise Blocked('Host resolved to no addresses.')
    for ip in infos:
        if not _is_public(ip):
            raise Blocked(f'Host resolves to a non-public address ({ip}); refused to prevent server-side request forgery.')
    return str(infos[0])


def _validate_url(url):
    if not isinstance(url, str) or len(url) > 2048 or any(c in url for c in '\r\n\t\x00'):
        raise Blocked('URL is missing, too long or contains control characters.')
    parts = urlsplit(url.strip())
    if parts.scheme.lower() not in ('http', 'https'):
        raise Blocked(f'Only http and https URLs can be inspected (got "{parts.scheme or "none"}").')
    if parts.username or parts.password or '@' in parts.netloc:
        raise Blocked('URLs with embedded credentials are refused.')
    host = (parts.hostname or '').lower()
    if not host:
        raise Blocked('URL has no host.')
    try:
        host = host.encode('idna').decode('ascii')       # internationalised names are sent (Host header / SNI) in their ASCII form
    except UnicodeError as exc:
        raise Blocked('URL host is not a valid internationalised name.') from exc
    try:
        port = parts.port or (443 if parts.scheme.lower() == 'https' else 80)
    except ValueError as exc:
        raise Blocked('URL has an invalid port.') from exc
    if port not in ALLOWED_PORTS and not ALLOW_PRIVATE:
        raise Blocked(f'Port {port} is not allowed (only {sorted(ALLOWED_PORTS)}).')
    return parts, host, port


class _PinnedHTTP(http.client.HTTPConnection):
    def __init__(self, host, port, ip, timeout):
        super().__init__(host, port, timeout=timeout)
        self._ip = ip

    def connect(self):
        self.sock = socket.create_connection((self._ip, self.port), self.timeout)


class _PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, host, port, ip, timeout):
        super().__init__(host, port, timeout=timeout, context=ssl.create_default_context())
        self._ip = ip

    def connect(self):
        sock = socket.create_connection((self._ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


def _get(parts, host, port, ip, deadline):
    """One pinned GET. Returns (status, headers dict, body bytes, truncated)."""
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise Blocked('Time budget exhausted.')
    cls = _PinnedHTTPS if parts.scheme.lower() == 'https' else _PinnedHTTP
    conn = cls(host, port, ip, min(CONNECT_TIMEOUT, remaining))
    try:
        target = (parts.path or '/') + (('?' + parts.query) if parts.query else '')
        conn.request('GET', target, headers={'User-Agent': USER_AGENT, 'Accept': 'text/html,application/xhtml+xml;q=0.9,*/*;q=0.1',
                                             'Accept-Encoding': 'identity', 'Connection': 'close'})
        resp = conn.getresponse()
        headers = {k.lower(): v for k, v in resp.getheaders()}
        body = b''
        if resp.status < 300 or resp.status >= 400:
            # read1() returns after ONE socket read, so the deadline is re-checked between reads: a server that drips a byte
            # every few seconds cannot hold this worker past the time budget (a plain read(n) would block until n bytes arrive).
            while len(body) <= MAX_BYTES:
                if time.monotonic() > deadline:
                    raise TimeoutError('Time budget exhausted while reading the response.')
                if conn.sock is not None:
                    conn.sock.settimeout(max(0.2, min(CONNECT_TIMEOUT, deadline - time.monotonic())))
                chunk = resp.read1(min(8192, MAX_BYTES + 1 - len(body)))
                if not chunk:
                    break
                body += chunk
        return resp.status, headers, body[:MAX_BYTES], len(body) > MAX_BYTES
    finally:
        conn.close()


def _registrable(host):
    try:
        return PSL.privatesuffix(host) or host
    except Exception:
        return host


def _analyze(body, final_url):
    parser = lxml_html.HTMLParser(no_network=True, recover=True, remove_comments=True, remove_pis=True)
    doc = lxml_html.fromstring(body, parser=parser)
    page_host = (urlsplit(final_url).hostname or '').lower()
    page_reg = _registrable(page_host)
    title = (doc.findtext('.//title') or '').strip()[:200]
    text = ' '.join(doc.text_content().split())
    forms, findings = [], []
    for form in doc.findall('.//form')[:20]:
        inputs = form.findall('.//input')
        types = [(i.get('type') or 'text').lower() for i in inputs]
        action = urljoin(final_url, form.get('action') or '')
        action_host = (urlsplit(action).hostname or '').lower()
        forms.append({'action': action[:300], 'method': (form.get('method') or 'get').lower(), 'fields': len(inputs),
                      'password_fields': types.count('password'), 'hidden_fields': types.count('hidden'),
                      'cross_domain_action': bool(action_host) and _registrable(action_host) != page_reg})
    scripts = doc.findall('.//script')
    external = [s.get('src') for s in scripts if s.get('src') and (urlsplit(urljoin(final_url, s.get('src'))).hostname or page_host) != page_host]
    refresh = [m.get('content', '')[:200] for m in doc.findall('.//meta') if (m.get('http-equiv') or '').lower() == 'refresh']
    signals = {'forms': len(forms), 'password_fields': sum(f['password_fields'] for f in forms), 'iframes': len(doc.findall('.//iframe')),
               'scripts_inline': len([s for s in scripts if not s.get('src')]), 'scripts_external': len(external),
               'links': len(doc.findall('.//a')), 'text_chars': len(text)}
    if signals['password_fields']:
        findings.append({'title': 'Credential form', 'detail': f"The page contains {signals['password_fields']} password field(s) - it collects credentials."})
        if urlsplit(final_url).scheme.lower() == 'http':
            findings.append({'title': 'Password form over plain HTTP', 'detail': 'Credentials would be sent unencrypted.'})
    for f in forms:
        if f['cross_domain_action'] and f['password_fields']:
            findings.append({'title': 'Credential form submits to another domain', 'detail': f"Form posts to {f['action'][:120]}, a different domain from the page."})
            break
    if refresh:
        findings.append({'title': 'Meta refresh redirect', 'detail': refresh[0]})
    if signals['iframes']:
        findings.append({'title': 'Embedded frames', 'detail': f"{signals['iframes']} iframe(s) present (content not fetched)."})
    if re.fullmatch(r'[\d.]+', page_host) or ':' in page_host:
        findings.append({'title': 'Page served from a bare IP address', 'detail': page_host})
    heading = ' '.join(t for t in [title] + [h.text_content() for h in doc.findall('.//h1')[:2]] if t).lower()
    for brand in BRAND_CUES:
        if brand in heading and brand.replace(' ', '') not in page_reg.replace('-', '').replace('.', '') and (signals['password_fields'] or forms):
            findings.append({'title': 'Brand cue does not match the domain',
                             'detail': f'Title/heading mentions "{brand}" but the page is served from {page_reg}. Possible impersonation - verify independently.'})
            break
    tags = [el.tag for el in doc.iter() if isinstance(el.tag, str)][:2000]
    dom_hash = hashlib.sha256('>'.join(tags).encode()).hexdigest()
    return {'title': title, 'forms': forms, 'signals': signals, 'findings': findings, 'dom_hash': dom_hash, 'meta_refresh': refresh[:2],
            'external_script_hosts': sorted({(urlsplit(urljoin(final_url, s)).hostname or '') for s in external})[:10]}


def inspect(url):
    """Never raises. Returns a result dict with status 'ok' | 'blocked' | 'error'."""
    started = time.monotonic()
    deadline = started + TOTAL_TIMEOUT
    result = {'requested': url if isinstance(url, str) else '', 'status': 'error', 'redirects': [], 'transcript': [], 'scope': SCOPE_NOT_CONTACTED}
    current = url
    try:
        for hop in range(MAX_REDIRECTS + 1):
            parts, host, port = _validate_url(current)
            ip = _resolve(host, port)
            result['transcript'].append(f'GET {parts.scheme}://{host}:{port}{parts.path or "/"} -> pinned {ip}')
            result['scope'] = SCOPE      # a connection is about to be attempted: the destination will see this server's IP
            status, headers, body, truncated = _get(parts, host, port, ip, deadline)
            result['transcript'][-1] += f' = {status}'
            if 300 <= status < 400 and headers.get('location'):
                if hop == MAX_REDIRECTS:
                    raise Blocked(f'More than {MAX_REDIRECTS} redirects.')
                current = urljoin(current, headers['location'])
                result['redirects'].append(current[:300])
                continue
            result.update(final_url=current[:600], http_status=status, content_type=headers.get('content-type', '')[:100], bytes_read=len(body),
                          truncated=truncated, fetched_from_ip=ip, elapsed_ms=round((time.monotonic() - started) * 1000))
            if headers.get('content-encoding', 'identity').lower() not in ('identity', ''):
                result.update(status='ok', findings=[], note='Response used compression that was not requested; body not parsed.')
                return result
            sniff = body[:1024].lower()
            if 'html' in headers.get('content-type', '').lower() or b'<html' in sniff or b'<!doctype html' in sniff:
                result.update(_analyze(body, current))
                result['status'] = 'ok'
            else:
                result.update(status='ok', findings=[], note='Not an HTML page; nothing to analyze.')
            if truncated:
                result.setdefault('findings', []).append({'title': 'Page truncated', 'detail': f'Only the first {MAX_BYTES // 1024} KB was read.'})
            return result
    except Blocked as exc:
        result.update(status='blocked', reason=str(exc))
    except ssl.SSLError as exc:
        result.update(status='error', reason=f'TLS error: {type(exc).__name__} (certificate is verified, not bypassed).')
    except (OSError, http.client.HTTPException, TimeoutError, ValueError) as exc:
        result.update(status='error', reason=f'Fetch failed: {type(exc).__name__}.')
    except Exception as exc:  # a hostile page must never crash the request
        result.update(status='error', reason=f'Analysis failed: {type(exc).__name__}.')
    result['elapsed_ms'] = round((time.monotonic() - started) * 1000)
    return result

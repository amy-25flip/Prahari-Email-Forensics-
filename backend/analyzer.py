import email
import re
import requests
import checkdmarc
import concurrent.futures
import dns.resolver
dns.resolver.default_resolver = dns.resolver.Resolver(configure=False)
dns.resolver.default_resolver.nameservers = ['8.8.8.8', '1.1.1.1']

def _extract_email(s):
    m = re.search(r'[\w.+-]+@[\w.-]+', s or '')
    return m.group(0).lower() if m else ''

def parse_email(raw):
    msg = email.message_from_string(raw)
    from_addr = msg.get('From', '')
    return_path = msg.get('Return-Path', '')
    reply_to = msg.get('Reply-To', '')
    subject = msg.get('Subject', '')
    received = msg.get_all('Received', [])
    return msg, {
        'from': from_addr,
        'return_path': return_path,
        'reply_to': reply_to,
        'subject': subject,
        'received_chain': received
    }

def extract_ips(received_headers):
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    ips = []
    for header in received_headers:
        found = re.findall(ip_pattern, header)
        public = [ip for ip in found
                  if not any(ip.startswith(p) for p in [
                      '10.', '192.168.', '172.16.', '172.17.',
                      '172.18.', '172.19.', '172.2', '127.',
                      '0.', '169.254.', '100.64.'
                  ])]
        ips.extend(public)
    return list(dict.fromkeys(ips))

def geolocate_ip(ip):
    try:
        r = requests.get(
            f'http://ip-api.com/json/{ip}?fields=status,country,city,isp,org,lat,lon,proxy,hosting',
            timeout=5
        ).json()
        if r.get('status') == 'fail':
            return {'ip': ip, 'error': 'private or invalid IP'}
        return {
            'ip': ip,
            'country': r.get('country', 'Unknown'),
            'city': r.get('city', 'Unknown'),
            'isp': r.get('isp', 'Unknown'),
            'org': r.get('org', ''),
            'lat': r.get('lat', 0),
            'lon': r.get('lon', 0),
            'proxy': r.get('proxy', False),
            'hosting': r.get('hosting', False)
        }
    except Exception:
        return {'ip': ip, 'error': 'lookup failed'}

def detect_spoofing(headers):
    signals = []
    score = 0

    from_email = _extract_email(headers.get('from', ''))
    return_email = _extract_email(headers.get('return_path', ''))
    reply_email = _extract_email(headers.get('reply_to', ''))

    # only flag reply-to mismatch if reply-to is actually set
    if headers.get('reply_to') and reply_email and reply_email != from_email:
        signals.append('Reply-To mismatch with From')
        score += 25

    # only flag return-path mismatch if domains differ (not just formatting)
    if headers.get('return_path') and return_email:
        from_domain = from_email.split('@')[-1] if '@' in from_email else ''
        return_domain = return_email.split('@')[-1] if '@' in return_email else ''
        if from_domain and return_domain and from_domain != return_domain:
            signals.append('Return-Path domain mismatch with From')
            score += 20

    if not headers.get('received_chain'):
        signals.append('No Received headers — suspicious')
        score += 30

    return signals, min(score, 100)

def check_authentication(from_header):
    try:
        # handle "Name <email@domain.com>" and plain "email@domain.com"
        email_match = re.search(r'<[^@]+@([\w.-]+)>', from_header)
        if not email_match:
            email_match = re.search(r'[\w.+-]+@([\w.-]+)', from_header)
        if not email_match:
            return {
                'error': 'no domain found',
                'spf_valid': False, 'dmarc_valid': False,
                'spf_record': 'none', 'dmarc_policy': 'none', 'domain': None
            }
        domain = email_match.group(1).strip().strip('>')

        with concurrent.futures.ThreadPoolExecutor() as executor:
            future = executor.submit(checkdmarc.check_domains, [domain])
            try:
                result = future.result(timeout=10)
                spf = result[0].get('spf', {})
                dmarc = result[0].get('dmarc', {})
                return {
                    'domain': domain,
                    'spf_valid': spf.get('valid', False),
                    'dmarc_valid': dmarc.get('valid', False),
                    'spf_record': spf.get('record', 'none'),
                    'dmarc_policy': dmarc.get('tags', {}).get('p', {}).get('value', 'none'),
                    'timed_out': False
                }
            except concurrent.futures.TimeoutError:
                return {
                    'domain': domain,
                    'spf_valid': False,
                    'dmarc_valid': False,
                    'spf_record': 'timeout',
                    'dmarc_policy': 'timeout',
                    'timed_out': True,
                    'error': 'DNS lookup timed out'
                }
    except Exception as e:
        return {
            'error': str(e),
            'spf_valid': False, 'dmarc_valid': False,
            'spf_record': 'none', 'dmarc_policy': 'none',
            'domain': None, 'timed_out': False
        }

def analyze(raw_email):
    msg, headers = parse_email(raw_email)
    ips = extract_ips(headers['received_chain'])
    geo_data = [geolocate_ip(ip) for ip in ips[:5]]
    spoof_signals, base_score = detect_spoofing(headers)
    auth = check_authentication(headers['from'])

    # only penalize SPF/DMARC if they actually failed (not timed out)
    timed_out = auth.get('timed_out', False)
    if not timed_out:
        if not auth.get('spf_valid'):
            base_score += 20
        if not auth.get('dmarc_valid'):
            base_score += 20

    # penalize proxy/hosting IPs
    for g in geo_data:
        if g.get('proxy'):
            base_score += 15
        if g.get('hosting'):
            base_score += 10

    # get body safely
    body = msg.get_payload(decode=True)
    if body is None:
        # multipart email - get first text part
        try:
            for part in msg.walk():
                if part.get_content_type() in ('text/plain', 'text/html'):
                    body = part.get_payload(decode=True)
                    break
        except Exception:
            body = b''

    return {
        'headers': headers,
        'relay_chain': headers['received_chain'],
        'ips': geo_data,
        'spoof_signals': spoof_signals,
        'authentication': auth,
        'fraud_score': min(base_score, 100),
        'body': body
    }

if __name__ == '__main__':
    sample = open('test.eml').read()
    result = analyze(sample)
    print('Fraud Score:', result['fraud_score'])
    print('Spoof Signals:', result['spoof_signals'])
    print('Authentication:', result['authentication'])
    print('IPs found:')
    for g in result['ips']:
        print(f"  {g['ip']} -> {g.get('city')}, {g.get('country')} ({g.get('isp')})")
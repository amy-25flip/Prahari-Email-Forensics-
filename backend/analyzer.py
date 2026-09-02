import email
import re
import requests
import checkdmarc

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
                  if not any(ip.startswith(p) for p in
                  ['10.', '192.168.', '172.16.', '172.17.',
                   '172.18.', '172.19.', '172.2', '127.'])]
        ips.extend(public)
    return list(dict.fromkeys(ips))

def geolocate_ip(ip):
    try:
        r = requests.get(f'http://ip-api.com/json/{ip}', timeout=5).json()
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
    if headers['reply_to'] and headers['reply_to'] != headers['from']:
        signals.append('Reply-To mismatch with From')
        score += 25
    if headers['return_path'] and headers['return_path'] != headers['from']:
        signals.append('Return-Path mismatch with From')
        score += 20
    if not headers['received_chain']:
        signals.append('No Received headers — suspicious')
        score += 30
    return signals, min(score, 100)

def check_authentication(from_header):
    try:
        domain = re.search(r'@([\w.-]+)', from_header)
        if not domain:
            return {'error': 'no domain found'}
        domain = domain.group(1)
        result = checkdmarc.check_domains([domain])
        spf = result[0].get('spf', {})
        dmarc = result[0].get('dmarc', {})
        return {
            'domain': domain,
            'spf_valid': spf.get('valid', False),
            'dmarc_valid': dmarc.get('valid', False),
            'spf_record': spf.get('record', 'none'),
            'dmarc_policy': dmarc.get('tags', {}).get('p', {}).get('value', 'none')
        }
    except Exception as e:
        return {'error': str(e)}

def analyze(raw_email):
    msg, headers = parse_email(raw_email)
    ips = extract_ips(headers['received_chain'])
    geo_data = [geolocate_ip(ip) for ip in ips[:5]]
    spoof_signals, base_score = detect_spoofing(headers)
    auth = check_authentication(headers['from'])

    if not auth.get('spf_valid'):
        base_score += 20
    if not auth.get('dmarc_valid'):
        base_score += 20

    for g in geo_data:
        if g.get('proxy'):
            base_score += 15
        if g.get('hosting'):
            base_score += 10

    return {
        'headers': headers,
        'relay_chain': headers['received_chain'],
        'ips': geo_data,
        'spoof_signals': spoof_signals,
        'authentication': auth,
        'fraud_score': min(base_score, 100),
        'body': msg.get_payload(decode=True)
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
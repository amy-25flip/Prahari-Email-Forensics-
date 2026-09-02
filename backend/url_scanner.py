import re
import requests

SUSPICIOUS_KEYWORDS = [
    'login', 'signin', 'account', 'verify', 'secure', 'update',
    'confirm', 'password', 'bank', 'paypal', 'amazon', 'apple',
    'microsoft', 'google', 'netflix', 'urgent', 'suspended',
    'limited', 'click', 'free', 'winner', 'prize', 'billing',
    'invoice', 'payment', 'credential', 'authenticate', 'validate'
]

def extract_urls(text):
    if not text:
        return []
    if isinstance(text, bytes):
        text = text.decode('utf-8', errors='replace')
    pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    urls = re.findall(pattern, text)
    return list(dict.fromkeys(urls))[:10]

def extract_domain(url):
    match = re.search(r'https?://([^/]+)', url)
    return match.group(1) if match else None

def count_suspicious_keywords(url):
    url_lower = url.lower()
    return sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url_lower)

def check_url(url):
    domain = extract_domain(url)
    keyword_hits = count_suspicious_keywords(url)
    is_long = len(url) > 100
    has_ip = bool(re.search(r'https?://\d+\.\d+\.\d+\.\d+', url))
    has_redirect = any(x in url.lower() for x in ['redirect', 'url=', 'link=', 'goto='])
    subdomain_count = domain.count('.') if domain else 0

    suspicious_flags = []
    if keyword_hits > 0:
        suspicious_flags.append(f'{keyword_hits} suspicious keyword(s)')
    if is_long:
        suspicious_flags.append('unusually long URL')
    if has_ip:
        suspicious_flags.append('IP address used instead of domain')
    if has_redirect:
        suspicious_flags.append('redirect parameter detected')
    if subdomain_count > 3:
        suspicious_flags.append('excessive subdomains')

    is_suspicious = len(suspicious_flags) > 0

    return {
        'url': url,
        'domain': domain,
        'is_suspicious': is_suspicious,
        'flags': suspicious_flags,
        'keyword_hits': keyword_hits
    }

def scan_urls(body_text):
    urls = extract_urls(body_text)
    if not urls:
        return {'count': 0, 'urls': [], 'suspicious_count': 0}

    results = [check_url(u) for u in urls]
    suspicious_count = sum(1 for r in results if r['is_suspicious'])

    return {
        'count': len(urls),
        'urls': results,
        'suspicious_count': suspicious_count
    }
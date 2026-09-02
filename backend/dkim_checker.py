import re

def check_dkim(raw_email):
    try:
        import dkim
        raw_bytes = raw_email.encode() if isinstance(raw_email, str) else raw_email
        result = dkim.verify(raw_bytes)
        return {
            'valid': bool(result),
            'status': 'pass' if result else 'fail',
            'detail': 'DKIM signature verified' if result else 'DKIM signature invalid or missing'
        }
    except Exception as e:
        return {
            'valid': False,
            'status': 'error',
            'detail': str(e)
        }

def extract_dkim_header(raw_email):
    match = re.search(
        r'DKIM-Signature:(.+?)(?=\r?\n\S|\r?\n\r?\n)',
        raw_email, re.DOTALL | re.IGNORECASE
    )
    if not match:
        return {'found': False, 'domain': None, 'selector': None, 'algorithm': None}
    header = match.group(1)
    domain = re.search(r'd=([^;]+)', header)
    selector = re.search(r's=([^;]+)', header)
    algo = re.search(r'a=([^;]+)', header)
    return {
        'found': True,
        'domain': domain.group(1).strip() if domain else 'unknown',
        'selector': selector.group(1).strip() if selector else 'unknown',
        'algorithm': algo.group(1).strip() if algo else 'unknown'
    }
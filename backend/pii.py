"""Indian statutory-identifier (PII) detection and masking for DPDP-conscious
exports. Derivative reports (JSON/CSV/CEF/PDF) get Aadhaar, PAN, UPI and Indian
mobile numbers masked to reduce exposure; the tamper-evident store keeps the
original bytes intact, so custody is preserved. This is best-effort regex
masking, not a certified DLP / compliance guarantee.

Best-effort regex detection, not exhaustive. Aadhaar candidates are additionally
validated with the UIDAI Verhoeff checksum, so a random 12-digit string is not
masked as an Aadhaar number."""
import copy
import re

# Verhoeff checksum tables (UIDAI Aadhaar uses Verhoeff) -- cuts false positives.
_D = [[0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],
      [3,4,0,1,2,8,9,5,6,7],[4,0,1,2,3,9,5,6,7,8],[5,9,8,7,6,0,4,3,2,1],
      [6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],[8,7,6,5,9,3,2,1,0,4],
      [9,8,7,6,5,4,3,2,1,0]]
_P = [[0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,3,7,9,6,1,4,2],
      [8,9,1,6,0,4,3,5,2,7],[9,4,5,3,1,2,6,8,7,0],[4,2,8,6,5,7,3,9,0,1],
      [2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8]]


def _verhoeff_valid(num):
    if not (isinstance(num, str) and num.isdigit() and len(num) == 12):
        return False
    c = 0
    for i, digit in enumerate(reversed(num)):
        c = _D[c][_P[i % 8][int(digit)]]
    return c == 0


_AADHAAR = re.compile(r'\b[2-9]\d{3}[\s-]?\d{4}[\s-]?\d{4}\b')      # 12 digits, first not 0/1, space/hyphen grouped
_PAN = re.compile(r'\b[A-Za-z]{5}[0-9]{4}[A-Za-z]\b')              # e.g. ABCDE1234F (case-insensitive)
# UPI VPA -- the (?![\w.\-]) stops it matching an ordinary email whose domain
# merely starts with a PSP name (e.g. support@sbi.co.in is NOT a VPA).
_UPI = re.compile(r'\b[a-z0-9.\-_]{2,256}@(?:oksbi|okhdfcbank|okaxis|okicici|ybl|'
                  r'paytm|apl|axl|ibl|upi|sbi|hdfcbank|icici|axisbank|barodampay|'
                  r'pnb|kotak|federal|idfcfirst|fbl)(?![\w.\-])', re.I)
_PHONE = re.compile(r'(?<![\d\w])(?:\+?91[\s-]?|0)?[6-9]\d{4}[\s-]?\d{5}(?!\d)')  # Indian mobile, optional grouping

# Opt-in only: sender/recipient addresses are forensic evidence, so email masking
# keeps the first character and the whole domain (j***@example.com) -- enough to
# hide a private individual's identity, not enough to destroy the investigation.
_EMAIL = re.compile(r'\b([A-Za-z0-9._%+\-])[A-Za-z0-9._%+\-]*@([A-Za-z0-9.\-]+\.[A-Za-z]{2,})\b')

_MASKS = {'aadhaar': '[AADHAAR REDACTED]', 'pan': '[PAN REDACTED]',
          'upi': '[UPI REDACTED]', 'phone': '[PHONE REDACTED]'}


def _mask_aadhaar(match):
    return _MASKS['aadhaar'] if _verhoeff_valid(re.sub(r'\D', '', match.group())) else match.group()


def sanitize(text, emails=False):
    """Return text with Indian statutory identifiers masked (and, when
    emails=True, email local-parts partially masked). Non-strings pass through."""
    if not isinstance(text, str) or not text:
        return text
    text = _AADHAAR.sub(_mask_aadhaar, text)
    text = _PAN.sub(_MASKS['pan'], text)
    text = _UPI.sub(_MASKS['upi'], text)
    text = _PHONE.sub(_MASKS['phone'], text)
    if emails:
        text = _EMAIL.sub(lambda m: f'{m.group(1)}***@{m.group(2)}', text)
    return text


def scan(text):
    """Count Indian PII by type without returning any raw value (safe to store/log)."""
    if not isinstance(text, str) or not text:
        return {'aadhaar': 0, 'pan': 0, 'upi': 0, 'phone': 0}
    aadhaar = sum(1 for m in _AADHAAR.finditer(text) if _verhoeff_valid(re.sub(r'\D', '', m.group())))
    return {'aadhaar': aadhaar, 'pan': len(_PAN.findall(text)),
            'upi': len(_UPI.findall(text)), 'phone': len(_PHONE.findall(text))}


_SKIP_EXACT = {'id', 'sha256', 'sha', 'previous', 'permalink', 'created', 'elapsed_ms'}


def _skip(key):
    # Never rewrite identifiers or hashes: exact 'id', any *_id (case_id,
    # message_id, record_id, ...), or anything hash-like.
    if not isinstance(key, str):
        return False
    k = key.lower()
    return k in _SKIP_EXACT or k.endswith('_id') or 'hash' in k or 'sha256' in k


def _walk(obj, key=None, emails=False):
    if isinstance(obj, dict):
        return {k: _walk(v, k, emails) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_walk(v, key, emails) for v in obj]
    if isinstance(obj, str) and not _skip(key):
        return sanitize(obj, emails)
    return obj


def _strings(obj, key=None):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _strings(v, k)
    elif isinstance(obj, list):
        for v in obj:
            yield from _strings(v, key)
    elif isinstance(obj, str) and not _skip(key):
        yield obj


def summarize(report, emails=False):
    """Counts (never values) of what sanitize_report will mask in this report."""
    totals = {'aadhaar': 0, 'pan': 0, 'upi': 0, 'phone': 0}
    email_count = 0
    for text in _strings(report):
        for kind, n in scan(text).items():
            totals[kind] += n
        if emails:
            email_count += len(_EMAIL.findall(text))
    if emails:
        totals['email'] = email_count
    return {'masked_counts': totals, 'email_masking': bool(emails),
            'coverage_note': 'Best-effort pattern masking of Aadhaar (checksum-validated), PAN, UPI IDs and Indian mobile numbers'
                             + ('; email local-parts partially masked' if emails else '; email addresses NOT masked (forensic evidence retained)')
                             + '. Not certified DLP.'}


def sanitize_report(report, emails=False):
    """Deep-copy a report and mask Indian PII in every free-text field, leaving
    hashes/case-ids untouched. The stored original is never mutated."""
    return _walk(copy.deepcopy(report), emails=emails)

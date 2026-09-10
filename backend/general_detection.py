"""General BEC cues and bounded URL interpretation, without visiting links."""
import re
from urllib.parse import urlsplit, unquote, parse_qs


def url_signals(value):
    reasons=[]
    parts=urlsplit(value)
    if '%' in parts.netloc: reasons.append('Percent-encoded authority obscures destination')
    if '\\' in value: reasons.append('Backslash can produce inconsistent URL interpretation')
    if any(ord(c)<32 or ord(c)==127 for c in value): reasons.append('Control characters in URL')
    host=parts.hostname or ''
    if host.isdecimal() or re.fullmatch(r'0x[0-9a-f]+',host,re.I):
        reasons.append('Numeric host representation requires review')
    try: query=parse_qs(parts.query,max_num_fields=100)
    except ValueError: return reasons+['Query inspection limit reached']
    for key,values in query.items():
        if key.lower() not in ('url','redirect','redirect_uri','next','continue','return','target','dest','destination'):continue
        for target in values[:2]:
            for _ in range(2): target=unquote(target)
            destination=urlsplit(target)
            if destination.scheme.lower() in ('http','https') and destination.hostname and destination.hostname.lower()!=host.lower():
                reasons.append('Redirect parameter points to another host')
                return reasons
    return reasons


def language_checks(subject,body):
    text=subject+'\n'+body
    checks=[]
    authority=re.search(r"\b(?:i am|i'm|this is) (?:your |the )?(?:ceo|cfo|director|principal|chairman|president)\b",text,re.I)
    request=re.search(r'\b(?:buy|purchase|send|transfer|pay|wire)\b.{0,60}\b(?:gift cards?|money|funds|payment|invoice)\b',text,re.I|re.S)
    avoidance=re.search(r'\b(?:do not call|don.t call|keep (?:this |it )?(?:confidential|secret)|unavailable (?:by|on) phone)\b',text,re.I)
    if authority and request:
        checks.append({'kind':'language','title':'Executive-authority payment request',
                       'detail':'First-person executive authority is combined with a money or gift-card request. This is a BEC pattern, not proof of who wrote the email.'})
    if request and avoidance:
        checks.append({'kind':'language','title':'Payment request with verification avoidance',
                       'detail':'A financial request is paired with secrecy or avoidance of phone verification. Verify through an independently known channel.'})
    return checks

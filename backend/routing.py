"""Conservative parsing of Received observations; not a trust decision."""
import ipaddress
import re


def parse(value):
    value=str(value)[:4000]
    # Ignore comment tokens when locating clauses, but retain their IP literals.
    plain=[]
    depth=0
    escaped=False
    for char in value:
        if escaped:
            plain.append(' ' if depth else char)
            escaped=False
        elif char=='\\':
            escaped=True
            plain.append(' ')
        elif char=='(':
            depth+=1
            plain.append(' ')
        elif char==')':
            depth=max(0,depth-1)
            plain.append(' ')
        else:plain.append(' ' if depth else char)
    clauses=''.join(plain)
    sender=re.match(r'\s*from\s+([A-Za-z0-9_.:-]+)',clauses,re.I)
    receiver=re.search(r'\bby\s+([A-Za-z0-9_.:-]+)',clauses,re.I)
    sender_segment=value[:receiver.start()] if sender and receiver else value if sender else ''
    ips=[]
    for token in re.findall(r'[0-9a-fA-F:.]+',re.sub(r'IPv6:','',sender_segment,flags=re.I)):
        try:
            ip=str(ipaddress.ip_address(token))
            if ip not in ips:ips.append(ip)
        except ValueError:pass
    return {'from_host':sender[1].lower().rstrip('.') if sender else None,
            'by_host':receiver[1].lower().rstrip('.') if receiver else None,'sender_ips':ips}


def inspect(headers):
    values=[str(h) for h in headers]
    parsed=[parse(h) for h in reversed(values)]
    checks=[]
    if len(values)!=len(set(values)):
        checks.append({'kind':'routing','title':'Repeated relay record','detail':'Identical Received records occur more than once; inspect duplication or manipulation.'})
    discontinuities=[]
    for index,(older,newer) in enumerate(zip(parsed,parsed[1:]),1):
        if older['by_host'] and newer['from_host'] and older['by_host']!=newer['from_host']:
            discontinuities.append(index)
    if discontinuities:
        checks.append({'kind':'routing','title':'Relay naming discontinuity',
                       'detail':'Adjacent reported receiver/sender names differ at transitions '+', '.join(map(str,discontinuities[:20]))+'. Aliases, internal relays or incomplete headers can explain this; it is not proof of forgery.'})
    pairs={(p['from_host'],p['by_host']) for p in parsed if p['from_host'] and p['by_host'] and p['from_host']!=p['by_host']}
    if any((b,a) in pairs for a,b in pairs):
        checks.append({'kind':'routing','title':'Possible relay loop','detail':'The reported path contains transfers in both directions between the same host names. Forwarding can also explain this.'})
    return checks

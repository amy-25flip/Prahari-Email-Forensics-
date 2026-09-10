"""Conservative identity checks against administrator-configured identities."""
import json
import os
import re
import unicodedata
from email.utils import parseaddr
from publicsuffixlist import PublicSuffixList

PSL=PublicSuffixList()


def normalized(value):
    return ' '.join(unicodedata.normalize('NFKC',value).casefold().split())


def hostname(value):
    try:
        result=value.rstrip('.').lower().encode('idna').decode('ascii')
        if len(result)>253 or not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',label) for label in result.split('.')):
            return ''
        return result
    except (UnicodeError,AttributeError): return ''


def directory():
    raw=os.getenv('PROTECTED_IDENTITIES_JSON','[]')
    try:
        if len(raw)>65536: raise ValueError()
        entries=json.loads(raw)
        if not isinstance(entries,list) or len(entries)>100: raise ValueError()
        for entry in entries:
            if not isinstance(entry,dict) or set(entry)!={'name','domains','addresses'}: raise ValueError()
            if not isinstance(entry['name'],str) or not 2<=len(entry['name'])<=100: raise ValueError()
            if not isinstance(entry['domains'],list) or not 1<=len(entry['domains'])<=20: raise ValueError()
            if not all(isinstance(d,str) and hostname(d) for d in entry['domains']): raise ValueError()
            if not isinstance(entry['addresses'],list) or len(entry['addresses'])>20: raise ValueError()
            if not all(isinstance(a,str) and re.fullmatch(r'[^\s@<>]+@[^\s@<>]+',a) for a in entry['addresses']): raise ValueError()
        return entries,'configured' if entries else 'not_configured'
    except (ValueError,TypeError): return [],'invalid_configuration'


def one_edit(left,right):
    if left==right or abs(len(left)-len(right))>1: return False
    if len(left)==len(right):
        diffs=[i for i,(a,b) in enumerate(zip(left,right)) if a!=b]
        return len(diffs)==1 or (len(diffs)==2 and diffs[1]==diffs[0]+1 and left[diffs[0]]==right[diffs[1]] and left[diffs[1]]==right[diffs[0]])
    shorter,longer=sorted((left,right),key=len)
    for i in range(len(longer)):
        if longer[:i]+longer[i+1:]==shorter:return True
    return False


def assess(sender,urls,body):
    entries,status=directory()
    display,address=parseaddr(sender)
    source=hostname(address.rsplit('@',1)[-1]) if '@' in address else ''
    checks=[]
    action=bool(re.search(r'\b(payment|invoice|transfer|password|credential|verify|login|gift cards?)\b',body,re.I))
    hosts={source}|{hostname(u.get('domain','')) for u in urls}
    for entry in entries:
        allowed={hostname(d) for d in entry['domains']}
        exact_addresses={a.casefold() for a in entry['addresses']}
        sender_authorized=address.casefold() in exact_addresses if exact_addresses else any(source==d or source.endswith('.'+d) for d in allowed)
        if normalized(display)==normalized(entry['name']) and not sender_authorized:
            checks.append({'kind':'identity','title':'Protected identity address mismatch',
                           'detail':f"Display name matches configured identity {entry['name']}, but its sender address is outside the configured allowlist. Verify possible delegation."})
        for observed in sorted(hosts-{''}):
            if any(observed==d or observed.endswith('.'+d) for d in allowed):continue
            observed_base=PSL.privatesuffix(observed) or observed
            for target in allowed:
                target_base=PSL.privatesuffix(target) or target
                target_label=target_base.split('.')[0]
                observed_label=observed_base.split('.')[0]
                deceptive=target in observed and not observed.endswith('.'+target)
                similar=len(target_label)>=5 and one_edit(observed_label,target_label)
                if deceptive or (similar and action):
                    checks.append({'kind':'identity','title':'Protected-domain resemblance',
                                   'detail':f'{observed} resembles configured domain {target}; different ownership is possible. Similarity is not proof of impersonation.'})
                    break
    return {'status':status,'protected_identities':len(entries),'checks':checks[:100],
            'scope':'Configured identities only. Exact address/domain allowlists and limited spelling similarity, not comprehensive Unicode brand detection.'}

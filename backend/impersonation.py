"""Conservative identity checks against administrator-configured identities."""
import json
import os
import re
import unicodedata
from email.utils import parseaddr
from publicsuffixlist import PublicSuffixList

PSL=PublicSuffixList()

# Starter set of major Indian institutions commonly impersonated in phishing/BEC
# email (banks, UPI/payment apps, and key government portals). Domains only,
# NOT specific sender addresses, which are left empty on purpose rather than
# guessed; assess() already falls back to a domain-suffix match when an entry
# has no configured addresses (see sender_authorized below).
#
# RBI mandated (Circular RBI/2025-26/28, deadline 31 Oct 2025) that all Indian
# banks migrate to the exclusive '.bank.in' domain -- an already-passed
# deadline. Each bank below lists BOTH its current .bank.in domain and its
# pre-migration legacy domain (still commonly seen in transition-period mail
# and existing customer habit): omitting either one risks exactly the false
# positive this list exists to avoid -- flagging a genuinely legitimate
# current or recent bank email as impersonation.
#
# Re-verified and expanded 2026-09-23 via live web search (each entry's real,
# current official domain independently confirmed, not guessed from pattern --
# see the review that caught this: the FIRST version of this list, built
# without live search, had TWO wrong .bank.in domains for ICICI and Axis that
# would have caused real false positives on genuine bank mail; both fixed
# below). Karnataka Bank was investigated and deliberately excluded -- no
# clean, current official-domain confirmation was found, and shipping a
# guessed domain here is worse than omitting the institution.
#
# This is a STARTER list, not a comprehensive or continuously-verified
# registry -- institutions add/retire domains over time, so treat this as a
# default to extend or replace via PROTECTED_IDENTITIES_JSON, not a final word.
INDIA_DEFAULT_IDENTITIES=[
    {'name':'State Bank of India','domains':['sbi.bank.in','onlinesbi.sbi.bank.in','onlinesbi.sbi'],'addresses':[]},
    {'name':'HDFC Bank','domains':['hdfc.bank.in','hdfcbank.com'],'addresses':[]},
    {'name':'ICICI Bank','domains':['icici.bank.in','icicibank.com'],'addresses':[]},
    {'name':'Axis Bank','domains':['axis.bank.in','axisbank.com'],'addresses':[]},
    {'name':'Bank of Baroda','domains':['bankofbaroda.bank.in','bankofbaroda.in'],'addresses':[]},
    {'name':'Punjab National Bank','domains':['pnb.bank.in','pnbindia.in'],'addresses':[]},
    {'name':'Kotak Mahindra Bank','domains':['kotak.bank.in','kotak.com','kotak811.bank.in'],'addresses':[]},
    {'name':'YES Bank','domains':['yes.bank.in'],'addresses':[]},
    {'name':'Canara Bank','domains':['canarabank.bank.in'],'addresses':[]},
    {'name':'Union Bank of India','domains':['unionbankofindia.bank.in','unionbankonline.bank.in'],'addresses':[]},
    {'name':'Indian Bank','domains':['indianbank.bank.in'],'addresses':[]},
    {'name':'Bank of India','domains':['bankofindia.bank.in','bankofindia.co.in'],'addresses':[]},
    {'name':'IndusInd Bank','domains':['indusind.bank.in','indusind.com'],'addresses':[]},
    {'name':'IDFC FIRST Bank','domains':['idfcfirst.bank.in','idfcfirstbank.com'],'addresses':[]},
    {'name':'Federal Bank','domains':['federal.bank.in','federalbank.co.in'],'addresses':[]},
    {'name':'IDBI Bank','domains':['idbi.bank.in','idbibank.in'],'addresses':[]},
    {'name':'AU Small Finance Bank','domains':['au.bank.in','aubank.in'],'addresses':[]},
    {'name':'Bandhan Bank','domains':['bandhan.bank.in','bandhanbank.com'],'addresses':[]},
    {'name':'Paytm','domains':['paytm.com'],'addresses':[]},
    {'name':'PhonePe','domains':['phonepe.com'],'addresses':[]},
    {'name':'Google Pay India','domains':['pay.google.com','google.com'],'addresses':[]},
    {'name':'Amazon Pay India','domains':['amazonpay.amazon.in','amazon.in'],'addresses':[]},
    {'name':'CRED','domains':['cred.club'],'addresses':[]},
    {'name':'NPCI / BHIM UPI','domains':['npci.org.in','bhimupi.org.in'],'addresses':[]},
    {'name':'Income Tax Department','domains':['incometax.gov.in','incometaxindia.gov.in'],'addresses':[]},
    {'name':'UIDAI (Aadhaar)','domains':['uidai.gov.in'],'addresses':[]},
    {'name':'DigiLocker','domains':['digilocker.gov.in'],'addresses':[]},
    {'name':'GST Portal','domains':['gst.gov.in'],'addresses':[]},
    {'name':'EPFO','domains':['epfindia.gov.in','unifiedportal-emp.epfindia.gov.in','unifiedportal-mem.epfindia.gov.in'],'addresses':[]},
    {'name':'PM-KISAN','domains':['pmkisan.gov.in'],'addresses':[]},
    {'name':'IRCTC','domains':['irctc.co.in'],'addresses':[]},
    {'name':'India Post','domains':['indiapost.gov.in'],'addresses':[]},
    {'name':'Life Insurance Corporation of India','domains':['licindia.in'],'addresses':[]},
]


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
    # No env var set at all -> ship with the curated India starter defaults
    # rather than an empty list, so impersonation checks aren't a no-op out of
    # the box. An admin who explicitly sets PROTECTED_IDENTITIES_JSON --
    # including to the literal '[]' to deliberately disable this -- always
    # overrides the default; a set-but-invalid value still fails closed to
    # 'invalid_configuration' rather than silently falling back, so a real
    # deployment mistake is never masked by the default.
    unset=os.getenv('PROTECTED_IDENTITIES_JSON') is None
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
        if unset: return INDIA_DEFAULT_IDENTITIES,'default'
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

"""Within-email domain resemblance and reproducible infrastructure observations."""
import hashlib
import json
import re
from email.utils import parseaddr
from publicsuffixlist import PublicSuffixList
from impersonation import hostname, one_edit

PSL=PublicSuffixList()


def compare(report):
    address=parseaddr(report.get('sender',''))[1]
    sender=hostname(address.rsplit('@',1)[-1]) if '@' in address else ''
    if not sender:return []
    sender_base=PSL.privatesuffix(sender) or sender
    peers={hostname(u.get('domain','')) for u in report.get('urls',[])}
    for header in report.get('headers',[]):
        if header['name'].lower() in ('reply-to','return-path'):
            other=parseaddr(header['value'])[1]
            if '@' in other:peers.add(hostname(other.rsplit('@',1)[-1]))
    if not re.search(r'\b(?:verify|password|payment|invoice|account|login|bank)\b',report.get('subject','')+' '+report.get('body',''),re.I):return []
    checks=[]
    for peer in sorted(peers-{''}):
        target=PSL.privatesuffix(peer) or peer
        if target==sender_base:continue
        left,right=sender_base.split('.')[0],target.split('.')[0]
        embedding=sender_base in peer
        if embedding or (len(left)>=5 and len(right)>=5 and one_edit(left,right)):
            checks.append({'kind':'identity','title':'Related domains have deceptive resemblance',
                           'detail':f'{sender_base} and {peer} occur in the same sensitive-request email but have different registrable domains. Verify ownership; resemblance is not proof of impersonation.'})
    return checks[:50]


def fingerprint(report):
    info=report.get('domain_intelligence',{})
    records=info.get('dns',{})
    observations={kind:sorted(set(str(v).lower().strip() for v in records.get(kind,{}).get('values',[])))
                  for kind in ('MX','NS','A','AAAA')}
    observations['relay_asns']=sorted(set(str(g['asn']) for g in report.get('geo',[]) if g.get('status')=='available' and g.get('asn')))
    available=any(observations.values())
    digest=hashlib.sha256(json.dumps(observations,sort_keys=True,separators=(',',':')).encode()).hexdigest() if available else None
    return {'status':'observed' if available else 'unavailable','sha256':digest,'observations':observations,
            'scope':'Fingerprint of observed DNS and relay ASN metadata, not proof of common ownership. Shared hosting and mail services can match; absent records do not establish absence of infrastructure.'}

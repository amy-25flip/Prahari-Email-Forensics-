"""Bounded static checks and evidence-derived categories, without executing content."""
import io
import re
import zipfile
import impersonation
import general_detection
import routing
import domain_evidence
from email import policy
from email.parser import BytesParser
from email.utils import parsedate_to_datetime, parseaddr


def inspect(raw, report):
    msg=BytesParser(policy=policy.default).parsebytes(raw)
    checks=[]
    checks.extend(routing.inspect(msg.get_all('Received',[])))
    checks.extend(domain_evidence.compare(report))
    checks.extend(general_detection.language_checks(report.get('subject',''),report.get('body','')))
    identity=impersonation.assess(report.get('sender',''),report.get('urls',[]),report.get('body',''))
    checks.extend(identity['checks'])
    def add(kind, title, detail):
        checks.append({'kind':kind,'title':title,'detail':detail})
    mids=msg.get_all('Message-ID',[])
    if len(mids)>1: add('header','Duplicate Message-ID headers','Ambiguous message identity; inspect the original receiver record.')
    if mids and not re.fullmatch(r'<[^<>\s@]+@[^<>\s@]+>',str(mids[0]).strip()):
        add('header','Malformed Message-ID','Message-ID does not use the expected single identifier form. This does not prove forgery.')
    for header in ('Date','Subject','Reply-To','Return-Path'):
        if len(msg.get_all(header,[]))>1: add('header','Duplicate '+header,'Repeated singleton header requires review.')
    dates=[]
    for value in reversed(msg.get_all('Received',[])):
        try:
            date=parsedate_to_datetime(str(value).rsplit(';',1)[1])
            dates.append(date.timestamp() if date.tzinfo else None)
        except (ValueError,TypeError,IndexError,OverflowError): dates.append(None)
    # Compare adjacent pairs of the KNOWN dates only, not adjacent pairs of the
    # raw hop list -- one unparseable/missing Received date used to create a
    # blind spot: zip(dates, dates[1:]) skipped both pairs touching that None,
    # so a genuine reversal spanning the hop before it to the hop after it was
    # never compared at all. Dropping the Nones first makes the two real
    # timestamps on either side adjacent again.
    known=[d for d in dates if d is not None]
    if any(b<a-300 for a,b in zip(known,known[1:])):
        add('header','Relay timestamp reversal','Reported delivery order reverses by over five minutes. Clock skew or forged headers are possible; neither is established.')
    display,address=parseaddr(str(msg.get('From','')))
    claimed=re.search(r'[\w.+-]+@[A-Za-z0-9.-]+',display)
    if claimed and claimed[0].lower()!=address.lower():
        add('identity','Display-name address differs','The display name contains a different email address from the actual sender address.')
    for part in list(msg.walk())[:101]:
        if part.is_multipart() or not (part.get_filename() or part.get_content_disposition()=='attachment'): continue
        payload=part.get_payload(decode=True) or b''
        name=str(part.get_filename() or 'unnamed')[:300]
        if payload.startswith((b'MZ',b'\x7fELF')):
            add('attachment','Executable attachment content',name+': executable file signature; not executed.')
        if payload.startswith(b'%PDF') and re.search(rb'/(JavaScript|JS|Launch|OpenAction)\b',payload):
            add('attachment','PDF active-action marker',name+': static marker present; no PDF execution or complete parser analysis.')
        if payload.startswith(b'PK\x03\x04'):
            try:
                with zipfile.ZipFile(io.BytesIO(payload)) as archive:
                    entries=archive.infolist()
                    if len(entries)>500: add('attachment','Archive inspection limit',name+': more than 500 entries; content was not decompressed.')
                    for entry in entries[:500]:
                        path=entry.filename.lower()
                        if path.endswith('vbaproject.bin'):
                            add('attachment','Office macro payload',name+': archive contains a VBA project; macro presence is not a malware verdict.')
                        if entry.flag_bits&1:
                            add('attachment','Encrypted archive member',name+': encrypted content cannot be inspected by this check.')
                            break
            except (zipfile.BadZipFile,ValueError,NotImplementedError):
                add('attachment','Unreadable archive',name+': archive structure could not be inspected.')
    titles={f['title'] for f in report['findings']}
    labels=[]
    if 'Payment diversion' in titles or any(c['kind']=='language' for c in checks): labels.append('fraud-related')
    if any(c['kind']=='identity' for c in checks): labels.append('impersonated')
    phishing=report['ml'].get('label','').lower()=='phishing'
    if phishing or any('PhishTank' in title for title in titles): labels.append('phishing')
    if (checks or report['findings'] or report['score']>=25) and not labels: labels.append('suspicious')
    if not labels:
        labels=['legitimate'] if report['ml'].get('status')=='ready' and report['ml'].get('label','').strip().lower() in ('benign','legitimate') else ['undetermined']
    dmarc=report['authentication']['dmarc']['status']
    origin_flags=[]
    if dmarc=='fail': origin_flags.append('Possible spoofed domain: current authentication alignment failed; forwarding or configuration can also cause failures.')
    if dmarc=='pass' and ('fraud-related' in labels or phishing):
        origin_flags.append('Authenticated suspicious content: compromised-account or authorized-sender abuse is a hypothesis, not a confirmed compromise.')
    return {'categories':labels,'hosting_fingerprint':domain_evidence.fingerprint(report),'identity_coverage':{k:v for k,v in identity.items() if k!='checks'},'method':'Hybrid assessment: binary pretrained NLP plus explicit static rules. Not a trained multiclass model.',
            'category_caveat':'Categories are review hypotheses. Legitimate means no configured adverse evidence, not a safety guarantee.',
            'checks':checks,'origin_confidence':'Undetermined: no independently trusted receiver boundary.',
            'origin_flags':origin_flags,
            'attachment_scope':'Bounded static signatures and ZIP directory inspection only. No execution, decompression, antivirus verdict or encrypted-content inspection.'}

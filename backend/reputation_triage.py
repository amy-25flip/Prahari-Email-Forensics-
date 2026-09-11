"""Fold attachment reputation into existing evidence without equating it with certainty."""
from triage import assess


def apply(report):
    known={a['sha256'] for a in report['attachments']}
    seen=set()
    points=0
    urgent=False
    for item in report['assessment'].get('attachment_reputation',[]):
        digest=item.get('sha256')
        if digest not in known or digest in seen or item.get('status')!='available': continue
        seen.add(digest)
        malicious=item.get('malicious_count',0)
        suspicious=item.get('suspicious_count',0)
        if any(type(v) is not int or v<0 for v in (malicious,suspicious)): continue
        if malicious+suspicious==0:continue
        corroborated=malicious>=3
        urgent |= corroborated
        weight=60 if corroborated else 15
        points+=weight
        report['findings'].append({'group':'reputation','title':'Attachment flagged by multiple engines' if corroborated else 'Attachment reputation requires review',
            'detail':f"VirusTotal hash {digest}: {malicious} malicious and {suspicious} suspicious engine verdicts in a prior report. Engines are not independent votes; this is not a confirmed malware verdict.",
            'points':weight})
    if not points:return
    report['groups']['reputation']=min(60,report['groups'].get('reputation',0)+points)
    report['score']=min(100,sum(report['groups'].values()))
    report['risk']='High' if report['score']>=60 else 'Review' if report['score']>=25 else 'Low'
    report['triage']=assess(report['score'],report['findings'],report['ml'],report['urls'])
    report['triage']['action']='Do not open the flagged attachment. Verify independently and refer it for controlled malware analysis.'
    report['triage']['reasons'].append('Attachment hash reputation contains adverse engine verdicts; review the cited historical report.')
    if urgent:report['triage'].update(priority='urgent',label='Urgent review')
    labels=report['assessment']['categories']
    report['assessment']['categories']=[label for label in labels if label not in ('legitimate','undetermined')]
    if not report['assessment']['categories']:report['assessment']['categories']=['suspicious']

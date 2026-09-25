"""Five-way primary classification: legitimate / suspicious / impersonated / phishing / fraud_related (+ 'undetermined').

A deterministic decision table over evidence the pipeline already produced. It is NOT a trained five-class model and the
classes are review hypotheses. Precedence, first match wins for the PRIMARY class (every other class with evidence is
listed as secondary):
  1 phishing       - phishing-feed match, credential-pressure wording (ignored when the sender is DMARC-authenticated and nothing else corroborates), or a QR/suspicious link combined with credential or
                     lookalike-domain evidence. A high model probability alone (no corroborating rule)
                     yields 'suspicious', never 'phishing'
                     (also: password-expiry / undelivered-mail lure with an urgency cue and a link from a sender that is not DMARC-authenticated;
                     a bare 'will expire in 5 days' notice does not count)
  2 fraud_related  - payment diversion, verification avoidance, gift-card/advance-fee/extortion wording, payment-detail change
  3 impersonated   - lookalike domain, brand display-name spoofing, protected-identity mismatch, or DMARC failure together with
                     a Reply-To/display-name mismatch (DMARC failure alone is NOT enough: forwarding breaks alignment)
  4 suspicious     - other adverse evidence or score >= 25 without one of the above
  5 legitimate     - no adverse evidence and the model (authenticated-sender aware) says benign
  - undetermined   - no adverse evidence but the model is unavailable
"""
import re
WEAK_PHISH = 'High model phishing probability'
PHISH_TITLES = {'PhishTank URL match', 'Historical phishing-feed match', 'Credential pressure',
                'QR code in attachment decodes to a link', 'Suspicious URL structure'}
CORROBORATED = {'Suspicious URL structure', 'QR code in attachment decodes to a link'}     # never decide phishing on their own
URGENCY = re.compile(r'expired|expires? today|today|immediately|within \d+ ?(?:hours?|hrs)|24 hours|1 day|suspend|deactivat|is full|not delivered|were held|are held', re.I)
FRAUD_TITLES = {'Payment diversion', 'Verification avoidance'}
FRAUD_KEYWORDS = ('gift card', 'advance fee', 'lottery', 'inheritance', 'blackmail', 'extortion', 'bitcoin ransom')
IMPERSONATION_TITLES = {'Homoglyph display name', 'Look-alike domain', 'Display-name brand spoofing', 'Protected identity address mismatch', 'Protected-domain resemblance'}


def classify(report):
    findings = report.get('findings', [])
    titles = {f['title'] for f in findings}
    text = (report.get('subject', '') + ' ' + report.get('body', '')).lower()
    ml = report.get('ml', {})
    dmarc_fail = report.get('authentication', {}).get('dmarc', {}).get('status') == 'fail'
    evidence = {'phishing': [], 'fraud_related': [], 'impersonated': []}
    authenticated = report.get('authentication', {}).get('dmarc', {}).get('status') == 'pass'
    for f in findings:
        t = f['title']
        if t == 'Credential pressure' and authenticated and not (titles & {'Look-alike domain', 'PhishTank URL match', 'Historical phishing-feed match'}): continue     # authenticated KYC/security notices
        if t in PHISH_TITLES:
            if t in CORROBORATED and not (titles & {'Credential pressure', 'Look-alike domain', 'Account-expiry pressure'}): continue
            evidence['phishing'].append(t)
        elif t in FRAUD_TITLES: evidence['fraud_related'].append(t)
        elif t in IMPERSONATION_TITLES: evidence['impersonated'].append(t)
    if 'Account-expiry pressure' in titles and report.get('urls') and not authenticated and URGENCY.search(text): evidence['phishing'].append('Account-expiry lure with link, sender not authenticated')
    if any(k in text for k in FRAUD_KEYWORDS): evidence['fraud_related'].append('Fraud-scheme wording')
    if dmarc_fail and titles & {'Reply-To domain differs', 'Display-name brand spoofing'}: evidence['impersonated'].append('DMARC failure with identity mismatch')
    for cls in evidence: evidence[cls] = sorted(set(evidence[cls]))
    active = [c for c in ('phishing', 'fraud_related', 'impersonated') if evidence[c]]
    if active:
        primary = active[0]
        strength = sum(len(evidence[c]) for c in active)
        confidence = 'high' if len(evidence[primary]) >= 2 or report.get('score', 0) >= 60 else 'medium'
    elif report.get('score', 0) >= 25 or any(f['points'] > 0 for f in findings):
        primary, confidence = 'suspicious', 'low'
    elif ml.get('status') == 'ready' and str(ml.get('label', '')).strip().lower() in ('benign', 'legitimate'):
        primary, confidence = 'legitimate', 'medium'
    else:
        primary, confidence = 'undetermined', 'low'
    model_only = primary == 'suspicious' and {f['title'] for f in findings if f['points'] > 0} == {WEAK_PHISH}
    return {'primary': primary, 'confidence': confidence, 'basis': 'model_only' if model_only else 'rules_and_model', 'secondary': active[1:], 'evidence': evidence.get(primary, []) if active else
            [f['title'] for f in findings if f['points'] > 0][:6],
            'method': 'Deterministic decision table over model, authentication and rule evidence. Not a trained five-class model; classes are review hypotheses.'}

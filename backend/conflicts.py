"""Explain disagreements between observed evidence without double-counting risk."""
VERSION = 'conflicts-v1'


def detect(findings, authentication, model, urls):
    conflicts = []
    by_title = {item['title']: i for i, item in enumerate(findings)}
    payment = 'Payment diversion' in by_title
    avoidance = 'Verification avoidance' in by_title
    refs = [f'findings/{by_title[t]}' for t in ('Payment diversion', 'Verification avoidance') if t in by_title]
    def add(code, title, explanation, evidence, action):
        conflicts.append({'id': code, 'title': title, 'explanation': explanation,
                          'evidence_refs': evidence, 'action': action,
                          'assessment': 'Manual verification required; not proof of fraud', 'rule_version': VERSION})
    if payment and avoidance:
        if authentication.get('dmarc', {}).get('status') == 'pass':
            add('authenticated-payment', 'Authentication passes, but the request needs verification',
                'Verified sender alignment coexists with payment-diversion and verification-avoidance indicators. Authentication does not establish that the requested action is authorized.',
                ['authentication/dmarc'] + refs,
                'Confirm the payment destination with an independently known contact before changing or approving payment details.')
        label = str(model.get('label', '')).lower()
        if model.get('status') == 'ready' and label in ('benign', 'legitimate'):
            add('model-payment', 'Model prediction conflicts with payment-risk indicators',
                'The model predicts benign language, while separate rules identify payment diversion and avoidance of independent verification.',
                ['ml'] + refs,
                'Review the quoted findings and confirm the request through an established contact channel; do not rely on the model label alone.')
    for index, url in enumerate(urls):
        if 'Displayed URL differs from destination' in url.get('reasons', []):
            add(f'link-identity-{index}', 'Displayed link conflicts with its destination',
                'The visible URL and actual link destination have different hosts. Tracking links can also cause this discrepancy.',
                [f'urls/{index}'], 'Compare the displayed address and destination. Navigate through a known official address instead of opening the email link.')
    return conflicts

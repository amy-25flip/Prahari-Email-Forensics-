"""Evidence-driven next-step suggestions for an analyst. Every step is triggered by something actually
present in the analysed result and states why. These are review suggestions, not legal advice and not
automated actions; nothing here contacts any external service."""

CYBERCRIME_NOTE = ('If money has been or may be sent: report on the National Cyber Crime Reporting Portal '
                   '(cybercrime.gov.in) or call the 1930 financial cyber-fraud helpline as soon as possible - early reports improve the chance of freezing funds.')
CERTIN_NOTE = 'Report the incident to CERT-In (incident@cert-in.org.in) with the exported evidence pack; preserve the original message unaltered.'


def _titles(result):
    checks = (result.get('assessment') or {}).get('checks') or []
    return {f.get('title') for f in result.get('findings', [])} | {c.get('title') for c in checks}


def build(result):
    triage = (result.get('triage') or {}).get('priority', 'routine')
    titles = _titles(result)
    auth = result.get('authentication') or {}
    dmarc = (auth.get('dmarc') or {}).get('status')
    urls = [u for u in result.get('urls', []) if u.get('score', 0) >= 40]
    risky_attachments = [a for a in result.get('attachments', []) if a.get('warning') or a.get('qr_payloads')]
    conversation = (result.get('assessment') or {}).get('conversation') or {}
    money = bool(titles & {'Payment diversion', 'Payment UPI ID changed mid-thread'}) or any(
        (result.get('payment_signals') or {}).get(k) for k in ('upi', 'account', 'ifsc'))
    steps = []

    def add(priority, action, why):
        steps.append({'priority': priority, 'action': action, 'why': why})

    if triage == 'urgent':
        add('now', 'Do not open links or attachments and do not act on any payment or credential request in this message.',
            'Triage is urgent: the combined evidence crosses the high-review threshold.')
    if money:
        add('now', 'Verify any payment or bank-detail change out-of-band using a phone number already on file (never one from this email) before releasing funds.',
            'Payment-diversion or mid-thread payment-detail signals are present.')
    if dmarc == 'fail' or 'Reply-To domain differs' in titles or 'Return-Path domain differs' in titles or 'Display-name address differs' in titles:
        add('next', 'Treat the sender identity as unverified: confirm with the purported sender through a separate channel and check the real sending domain against the visible display name.',
            'Authentication failed or the sender/reply/return-path identities disagree.')
    if urls:
        add('next', f'Block the {len(urls)} flagged link destination(s) at the mail/web gateway and search other mailboxes for the same URLs.',
            'Structural or reputation checks scored these links as risky: ' + '; '.join(u['url'][:60] for u in urls[:3]))
    if risky_attachments:
        add('next', 'Quarantine the flagged attachment(s); do not open them. Submit the hash to a sandbox or reputation service before any further handling.',
            'Attachment rules, active-content extensions or QR codes were detected: ' + ', '.join(a.get('name', 'unnamed') for a in risky_attachments[:3]))
    if (result.get('prompt_injection') or {}).get('status') not in (None, 'clear') or result.get('adversarial'):
        add('next', 'Do not rely on automated AI summaries of this message; review the raw source manually.',
            'The message contains content crafted to manipulate an automated classifier or AI assistant.')
    related = (result.get('assessment') or {}).get('network_history') or {}
    if conversation.get('checks') or related.get('checks'):
        add('next', 'Review earlier messages in the same thread and from the same infrastructure before deciding; a single change mid-thread is a stronger signal than any one email.',
            'Conversation or network-history context found related earlier cases.')
    if triage in ('urgent', 'review'):
        add('record', 'Preserve evidence: export the case (JSON/PDF and the evidence pack), keep the original .eml unaltered, and note who reviewed it and when.',
            'Chain of custody: every export is hashed and the case log is hash-chained.')
    if triage == 'urgent' or money:
        add('record', CYBERCRIME_NOTE, 'Financial-fraud exposure is possible.')
        add('record', CERTIN_NOTE, 'Institutional incident reporting and coordination.')
    if not steps:
        add('record', 'No adverse evidence triggered a specific action. Legitimate means no configured adverse evidence, not a safety guarantee; use normal judgment.',
            'Routine triage with no findings.')
    return {'steps': steps, 'note': 'Suggested review steps derived from this case\'s evidence. Not legal advice; nothing here is executed automatically.'}

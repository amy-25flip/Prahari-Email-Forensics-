"""Conversation-aware BEC detection: compares the current email against prior
messages in the SAME thread within this session's own case history, looking
for payment-instruction changes and reply-to swaps mid-thread -- signals a
single-message analysis structurally cannot see at all.

Scope, stated honestly:
- "Same thread" is inferred from References/In-Reply-To headers when present
  (the strongest signal -- a genuine reply chain); it falls back to a
  normalized sender-address + subject match when they aren't (common for a
  pasted/forwarded .eml with no header chain). The fallback is weaker and can
  both under-match (a real reply with a stripped References header) and
  over-match (a coincidentally identical subject from an unrelated sender
  sharing the same address, if the address itself is reused/spoofed).
- Prior messages come only from THIS session's own stored case history --
  bounded by the same per-session case cap the rest of the app already
  relies on. It has zero visibility into thread messages never uploaded or
  pushed into this app, so "no anomaly found" is never a claim that the
  wider conversation elsewhere is clean.
- Payment-identifier comparison is shape-based (UPI/account/IFSC token
  matching, reusing pii.py's hardened UPI pattern), not a verified real
  payment instruction -- a coincidental token match/mismatch is possible.
"""
import re
import unicodedata
from email.utils import parseaddr


def _header(headers, name):
    for h in headers or []:
        if h.get('name', '').lower() == name.lower():
            return h.get('value', '')
    return ''


def _normalize_subject(subject):
    s = re.sub(r'^\s*(re|fwd?|fw)\s*:\s*', '', (subject or '').strip(), flags=re.I)
    return unicodedata.normalize('NFKC', s).casefold().strip()


_MSGID_SHAPE = re.compile(r'<[^\s<>]+@[^\s<>]+>')  # RFC 5322 msg-id shape: <local@domain>


def message_id(report):
    value = _header(report.get('headers', []), 'Message-ID').strip()[:512]
    return value if _MSGID_SHAPE.fullmatch(value) else ''


def reference_tokens(report):
    """Every id this message's References/In-Reply-To headers point at,
    restricted to tokens actually shaped like a real Message-ID (<local@domain>)
    -- a malformed or placeholder header value (e.g. 'unknown', '-') must not
    become false thread-linking evidence just because two unrelated messages
    happen to share that same garbage string.

    A real reply chain is NOT symmetric -- the first message in a thread has
    Message-ID X and no References; the reply has References containing X,
    not some independently-derived 'key' equal to the first message's own.
    So thread membership has to be checked pairwise (does either message's
    reference set contain the other's Message-ID, or do they share a common
    ancestor reference), not by comparing two messages' own single "key" for
    equality."""
    headers = report.get('headers', [])
    tokens = set()
    for name in ('References', 'In-Reply-To'):
        value = _header(headers, name)
        if value: tokens.update(_MSGID_SHAPE.findall(value))
    return tokens


def _fallback_key(report):
    sender_addr = (parseaddr(report.get('sender', ''))[1] or '').lower()
    return (sender_addr, _normalize_subject(report.get('subject', '')))


def is_same_thread(a, b):
    a_id, b_id = message_id(a), message_id(b)
    a_refs, b_refs = reference_tokens(a), reference_tokens(b)
    if a_id and a_id in b_refs: return True
    if b_id and b_id in a_refs: return True
    if a_refs and b_refs and (a_refs & b_refs): return True
    # Only fall back to the weaker sender+subject heuristic when NEITHER
    # message carries any Message-ID/References/In-Reply-To at all -- a
    # message that DOES have real threading headers but simply isn't part of
    # this particular thread must not be pulled in just because its subject
    # happens to match (e.g. two unrelated "Invoice" emails from one vendor).
    if not (a_id or a_refs or b_id or b_refs):
        return _fallback_key(a) == _fallback_key(b)
    return False


def _reply_to_domain(report):
    value = _header(report.get('headers', []), 'Reply-To')
    addr = parseaddr(value)[1] if value else ''
    return addr.rsplit('@', 1)[-1].lower() if '@' in addr else ''


def assess(report, prior_reports):
    """prior_reports: other reports from this session that share report's
    thread_key(), in any order (chronology isn't required -- a UNION of what
    was seen before is compared against the current message, not a strict
    sequence). Returns a dict with the same {group,title,detail} check shape
    ps_assessment/impersonation already use, so callers can fold it straight
    into result['assessment']['checks']."""
    thread_mates = [p for p in prior_reports if p is not report and is_same_thread(report, p)]
    checks = []
    matched_on = 'header' if (message_id(report) or reference_tokens(report)) else 'fallback'
    if not thread_mates:
        return {'thread_matched_on': matched_on, 'prior_messages_considered': 0, 'checks': checks,
                'scope': 'Session-scoped thread history only; no prior message in this thread was found in this session.'}

    prior_upi, prior_account = set(), set()
    prior_reply_domains = set()
    for prior in thread_mates:
        signals = prior.get('payment_signals') or {}
        prior_upi.update(signals.get('upi', []))
        prior_account.update(signals.get('account', []))
        domain = _reply_to_domain(prior)
        if domain: prior_reply_domains.add(domain)

    current = report.get('payment_signals') or {}
    new_upi = set(current.get('upi', [])) - prior_upi
    new_account = set(current.get('account', [])) - prior_account
    if new_upi and prior_upi:
        checks.append({'kind': 'conversation', 'title': 'Payment UPI ID changed mid-thread',
                       'detail': f"This message introduces a UPI handle not seen earlier in this thread ({', '.join(sorted(new_upi)[:3])}); "
                                 'prior messages in the same thread used a different one. Verify the change out-of-band before paying.'})
    if new_account and prior_account:
        checks.append({'kind': 'conversation', 'title': 'Bank account number changed mid-thread',
                       'detail': 'This message introduces an account-number-shaped token not seen earlier in this thread; '
                                 'prior messages used a different one. Verify the change out-of-band before paying.'})

    current_reply_domain = _reply_to_domain(report)
    if current_reply_domain and prior_reply_domains and current_reply_domain not in prior_reply_domains:
        checks.append({'kind': 'conversation', 'title': 'Reply-To domain changed mid-thread',
                       'detail': f'Reply-To now points to {current_reply_domain}, different from {", ".join(sorted(prior_reply_domains))} '
                                 'used earlier in this thread. Replies may route to an attacker-controlled mailbox.'})

    return {'thread_matched_on': matched_on, 'prior_messages_considered': len(thread_mates), 'checks': checks,
            'scope': 'Session-scoped thread history only; a clean result here is not proof the wider conversation is clean.'}

"""Network-behavior-over-time tracking: for each indicator in the current
report (sender domain/address, reported relay IP, URL, attachment hash, reply
address), reports how many OTHER cases already in this session's own history
carried the same indicator before, and when it was first/last seen.

Distinct from campaigns.py: campaigns.py links CURRENT reports to each other
pairwise to propose a candidate campaign group. This module instead
accumulates a per-indicator timeline across ALL prior reports regardless of
whether they are otherwise similar, answering a different, simpler question:
"have we seen this exact indicator before in this session, and how often."

Honest scope, stated up front:
- Session-scoped only, same bound the rest of this app already relies on for
  case history (search, notes, conversation threading). Zero visibility into
  anything outside this session's own stored cases -- "no prior history
  found" is never a claim that the indicator is new to the wider world, only
  that it is new to this session.
- Purely informational. Recurrence alone does NOT escalate triage/priority --
  a sender domain or URL can legitimately repeat across many genuine emails
  (a company's own portal link, a regular correspondent), so treating "seen
  before" as itself suspicious would create alert fatigue on exactly the
  traffic an analyst deals with every day. The analyst reads the count/dates
  and decides; this module does not decide for them.
"""
from campaigns import indicators as extract_indicators

# thread_id is deliberately excluded: conversation.py already tracks same-thread
# history via Message-ID/References, so tracking it here too would be a
# duplicate, overlapping signal rather than a distinct one.
TRACKED_TYPES = {'sender_domain', 'sender_address', 'reported_ip', 'url', 'attachment_hash', 'reply_address'}


def _is_same_report(report, prior):
    # Identity check covers the normal call site (execute() passes the
    # in-progress, not-yet-saved result object). The id-equality fallback
    # guards a future/different caller that passes a saved-and-reloaded copy
    # of the current report in prior_reports -- without it, that copy would
    # count as its own prior occurrence and inflate its indicators' counts.
    if prior is report:
        return True
    report_id, prior_id = report.get('id'), prior.get('id')
    return bool(report_id) and report_id == prior_id


def _sort_key(created):
    # Never let a missing/malformed timestamp raise a cross-type comparison
    # error during sort: real numbers sort first (oldest first), a non-numeric
    # value sorts after by its string form, and a missing value sorts last.
    if isinstance(created, (int, float)):
        return (0, created)
    if created is not None:
        return (1, str(created))
    return (2, '')


def _cross_session(current, ledger_hits):
    out = []
    for kind, value in sorted(current):
        hit = (ledger_hits or {}).get((kind, value))
        if hit:
            out.append({'type': kind, 'value': value, **hit})
    return out


def assess(report, prior_reports, ledger_hits=None):
    current = {pair for pair in extract_indicators(report) if pair[0] in TRACKED_TYPES}
    if not current:
        return {'recurring': [], 'cross_session': [], 'scope': 'Session-scoped indicator history only.'}

    occurrences_by_pair = {}
    for prior in prior_reports:
        if _is_same_report(report, prior):
            continue
        prior_created, prior_id = prior.get('created'), prior.get('id')
        for pair in extract_indicators(prior):
            if pair in current:
                occurrences_by_pair.setdefault(pair, []).append((prior_created, prior_id))

    recurring = []
    for kind, value in sorted(current):
        occurrences = occurrences_by_pair.get((kind, value))
        if not occurrences:
            continue
        occurrences.sort(key=lambda entry: _sort_key(entry[0]))
        recurring.append({
            'type': kind,
            'value': value,
            'occurrence_count': len(occurrences),
            'first_seen': occurrences[0][0],
            'last_seen': occurrences[-1][0],
            'case_ids': [case_id for _, case_id in occurrences],
        })

    return {'recurring': recurring,
            'cross_session': _cross_session(current, ledger_hits),
            'scope': 'Session history is per browser session. Cross-session counts come from a hashed indicator ledger (no case content stored, expires after a retention window) and only cover analyses this deployment has performed; '
                     'a clean result is not proof an indicator is new to the wider world, and recurrence alone is not itself treated as suspicious.'}

"""Optional, reversible protective actions on Gmail messages that the push pipeline has just analysed.

GMAIL_ACTION_MODE (default `off`):
  off         - do nothing (previous behaviour; no extra Gmail permission needed).
  dry-run     - decide and RECORD what would be done in the audit chain; make no Gmail API call at all.
  label       - add a `PRAHARI/High-risk` (or `PRAHARI/Review`) label; the message stays in the inbox.
  quarantine  - label high-risk mail AND remove it from the inbox (it stays in All Mail; nothing is trashed or deleted).
Hard rules: never delete, never trash, never send, never modify a message we did not just analyse, and never let an action
failure disturb ingestion - failures are recorded, not raised. Label/quarantine need the `gmail.modify` scope; the current
read-only token is enough for `off` and `dry-run`. HONEST STATUS: the API calls are unit-tested against a fake Gmail service
only; they have not been verified against a live Gmail account."""
import logging
import os

from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build

import gmail_integration

_logger = logging.getLogger('gmail_push')
MODIFY_SCOPES = ['https://www.googleapis.com/auth/gmail.modify']
LABEL_HIGH = 'PRAHARI/High-risk'
LABEL_REVIEW = 'PRAHARI/Review'
MODES = ('off', 'dry-run', 'label', 'quarantine')
_label_cache = {}


def mode():
    value = os.getenv('GMAIL_ACTION_MODE', 'off').strip().lower()
    return value if value in MODES else 'off'        # an unknown value must never enable an action


def min_score():
    try:
        return max(0, min(100, int(os.getenv('GMAIL_ACTION_MIN_SCORE', '60'))))
    except ValueError:
        return 60


def plan(result, current_mode=None):
    """What we would do for this analysis: {'labels': [...], 'remove_from_inbox': bool} or None."""
    current_mode = current_mode or mode()
    if current_mode == 'off':
        return None
    priority = (result.get('triage') or {}).get('priority')
    score = int(result.get('score', 0) or 0)
    if priority == 'urgent' or score >= min_score():
        return {'labels': [LABEL_HIGH], 'remove_from_inbox': current_mode == 'quarantine'}
    if priority == 'review':
        return {'labels': [LABEL_REVIEW], 'remove_from_inbox': False}
    return None


def _modify_service():
    if not gmail_integration.TOKEN_FILE.exists():
        raise RuntimeError('Gmail not connected.')
    creds = Credentials.from_authorized_user_file(str(gmail_integration.TOKEN_FILE), MODIFY_SCOPES)
    return build('gmail', 'v1', credentials=creds, cache_discovery=False)


def _label_id(service, name):
    if name in _label_cache:
        return _label_cache[name]
    listed = service.users().labels().list(userId='me').execute().get('labels', [])
    for label in listed:
        if label.get('name') == name:
            _label_cache[name] = label['id']
            return label['id']
    created = service.users().labels().create(userId='me', body={
        'name': name, 'labelListVisibility': 'labelShow', 'messageListVisibility': 'show'}).execute()
    _label_cache[name] = created['id']
    return created['id']


def apply(message_id, result, service=None):
    """Plan and (unless dry-run/off) perform the action. Returns an audit dict, or None when mode is off / nothing to do. Never raises."""
    current_mode = mode()
    try:
        chosen = plan(result, current_mode)
        if chosen is None:
            return None
        event = {'mode': current_mode, 'labels': chosen['labels'], 'remove_from_inbox': chosen['remove_from_inbox']}
        if current_mode == 'dry-run':
            return {**event, 'status': 'planned', 'detail': 'Dry run: no Gmail API call was made.'}
        service = service or _modify_service()
        add_ids = [_label_id(service, name) for name in chosen['labels']]
        body = {'addLabelIds': add_ids, 'removeLabelIds': ['INBOX'] if chosen['remove_from_inbox'] else []}
        service.users().messages().modify(userId='me', id=message_id, body=body).execute()
        return {**event, 'status': 'applied', 'detail': 'Labels added' + ('; removed from inbox (still in All Mail).' if chosen['remove_from_inbox'] else '.')}
    except Exception as exc:
        status = getattr(getattr(exc, 'resp', None), 'status', None)
        detail = ('Gmail refused the change (HTTP 403): the token needs the gmail.modify scope - re-authorize with that scope.'
                  if status == 403 else f'Action failed ({type(exc).__name__}); the message was left untouched.')
        _logger.warning('Gmail action failed for messageId=%s: %s', message_id, detail)
        return {'mode': current_mode, 'status': 'failed', 'detail': detail}

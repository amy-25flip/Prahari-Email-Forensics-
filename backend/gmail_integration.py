"""Gmail API integration: fetches newly-arrived mail for a single watched mailbox,
triggered by a Google Cloud Pub/Sub push notification (see main.py's /api/gmail/push).

Read-only access only (gmail.readonly scope, set up via gmail_oauth_setup.py). This
module never sends, modifies, or deletes anything in the mailbox.
"""
import base64
import json
import os
import threading
from pathlib import Path

from google.auth.transport.requests import Request as GoogleRequest
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
# Render's Secret Files always land at a fixed /etc/secrets/<filename> path (you
# can't choose an arbitrary mount path there), so this must be overridable rather
# than hardcoded next to the source -- GMAIL_TOKEN_FILE=/etc/secrets/gmail_token.json
# on Render; unset locally, where the gitignored file just sits next to this module.
TOKEN_FILE = Path(os.getenv('GMAIL_TOKEN_FILE', str(Path(__file__).parent / 'gmail_token.json')))
# Gitignored, machine-local: {"last_history_id": "...", "session_cookie": "..."}.
# session_cookie lets every push-triggered analysis land in one stable case list
# (store.session() otherwise has no notion of a fixed session without a real
# browser cookie to reuse -- see main.py's boundary middleware).
#
# Defaults under DATA_DIR (same pattern as store.py's own DATA), not next to this
# module's source: the Docker image only grants the app user write access to
# /data (see Dockerfile's chown), not the source directory -- writing there
# crashed every real deployment call that touched state (session_sid,
# advance_watermark) with an unhandled PermissionError/OSError, surfacing as a
# bare 500. GMAIL_STATE_FILE remains available to override entirely if needed.
STATE_FILE = Path(os.getenv('GMAIL_STATE_FILE', str(Path(os.getenv('DATA_DIR', str(Path(__file__).parent))) / 'gmail_watch_state.json')))
_state_lock = threading.Lock()


def b64decode(value):
    # Accept both standard and URL-safe base64 (Google's own docs and real
    # payloads have been inconsistent about which alphabet a given bytes field
    # uses) rather than gambling on one and rejecting the other.
    padded = value + '=' * (-len(value) % 4)
    return base64.urlsafe_b64decode(padded.replace('+', '-').replace('/', '_'))


def configured():
    return TOKEN_FILE.exists()


def _credentials():
    if not TOKEN_FILE.exists():
        raise RuntimeError('Gmail not connected: run gmail_oauth_setup.py first.')
    creds = Credentials.from_authorized_user_file(str(TOKEN_FILE), SCOPES)
    if creds.expired and creds.refresh_token:
        creds.refresh(GoogleRequest())
        try:
            TOKEN_FILE.write_text(creds.to_json())
        except OSError:
            # Persisting the refreshed access token is an optimization, not a
            # correctness requirement -- the refresh_token itself doesn't get
            # consumed/rotated by one use, so a failed write here (e.g. Render's
            # Secret Files mount is read-only) just means the next call refreshes
            # again from Google rather than reusing a cached access token.
            pass
    return creds


def _service():
    return build('gmail', 'v1', credentials=_credentials(), cache_discovery=False)


def _read_state():
    if not STATE_FILE.exists():
        return {}
    try:
        return json.loads(STATE_FILE.read_text())
    except (OSError, ValueError):
        # A corrupt/unreadable state file must not permanently break every
        # subsequent Gmail push (session_sid, diff_new_message_ids all read
        # this) -- treat it the same as "no state yet" rather than crashing.
        return {}


def _write_state(state):
    # Atomic write: a process killed mid-write (deploy restart, OOM, etc.) must
    # never leave a half-written/corrupt STATE_FILE behind, since a corrupt file
    # would otherwise break every subsequent read -- the same class of "one bad
    # write crashes everything after it" bug this module already hit once on Render.
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = STATE_FILE.with_suffix(STATE_FILE.suffix + '.tmp')
    tmp.write_text(json.dumps(state))
    os.replace(tmp, STATE_FILE)


def session_sid():
    """Stable store.py session id for every Gmail-push-triggered case, so they all
    land in one viewable case list instead of a fresh throwaway session each push."""
    import store
    with _state_lock:
        state = _read_state()
        hashed, new_cookie = store.session(state.get('session_cookie'))
        if new_cookie:
            state['session_cookie'] = new_cookie
            _write_state(state)
    return hashed


def start_watch(topic_name):
    """Register (or renew) push notifications for the INBOX label. Must be called
    again before the ~7-day expiration Gmail imposes on watch registrations."""
    service = _service()
    response = service.users().watch(userId='me', body={'topicName': topic_name, 'labelIds': ['INBOX']}).execute()
    with _state_lock:
        state = _read_state()
        state['last_history_id'] = response['historyId']
        _write_state(state)
    return response


def diff_new_message_ids(notified_history_id):
    """Given the historyId from a push notification, return the ids of messages
    added to INBOX since our last known point. Does NOT advance the stored
    watermark -- call advance_watermark() only after the caller has actually
    attempted to fetch and process each id, so a message can't be marked "seen"
    before anything was ever done with it (e.g. if the session's case-count cap
    or the per-session analysis rate limit rejects it downstream).

    Known limitation: if the watermark file is lost/missing entirely (rather than
    just stale), the very next notification's own triggering message can be
    missed, since Gmail's history API returns entries *after* the given start id
    -- run gmail_watch_start.py (which sets an initial watermark) before the
    first real push, not after, to avoid this in normal operation."""
    service = _service()
    with _state_lock:
        start_id = _read_state().get('last_history_id') or notified_history_id
    message_ids = []
    try:
        page_token = None
        while True:
            # Both historyTypes matter: Gmail can report a message reaching INBOX
            # as a 'messageAdded' record, or (if the label is applied in a
            # separate step, e.g. after a filter runs) as a 'labelAdded' record
            # on an already-added message. Watching only 'messageAdded' silently
            # missed real messages -- confirmed against Gmail's own history.list
            # docs, which list these as distinct history types.
            history = service.users().history().list(
                userId='me', startHistoryId=start_id, historyTypes=['messageAdded', 'labelAdded'],
                labelId='INBOX', pageToken=page_token).execute()
            for record in history.get('history', []):
                for added in record.get('messagesAdded', []):
                    message_ids.append(added['message']['id'])
                for added in record.get('labelsAdded', []):
                    if 'INBOX' in added.get('labelIds', []):
                        message_ids.append(added['message']['id'])
            page_token = history.get('nextPageToken')
            if not page_token:
                break
    except HttpError as exc:
        if exc.resp.status != 404:
            raise
        # startHistoryId too old (history entries expire after some time on Gmail's
        # side) -- can't recover the exact diff. Don't guess at old mail; just
        # re-anchor the watermark below so future notifications work correctly.
        message_ids = []
    return list(dict.fromkeys(message_ids))  # dedupe, preserve order (same message
    # could appear in both a messageAdded and a labelAdded record)


def fetch_raw(message_id):
    return b64decode(_service().users().messages().get(userId='me', id=message_id, format='raw').execute()['raw'])


def advance_watermark(notified_history_id):
    """Commit the watermark. Call this once per notification after attempting to
    process every id diff_new_message_ids() returned -- not before, and not per
    message, so a mid-batch crash doesn't leave the watermark ahead of work that
    never actually happened.

    Monotonic by design: if two notifications are in flight at once and the
    newer one (a larger historyId) happens to finish processing first, a later
    write from the older, slower one must not regress the watermark backward --
    that would make already-handled mail look new again on the next notification.
    Gmail's historyId is documented to only increase over time, so a plain
    numeric comparison is a safe, sufficient ordering check here.
    """
    with _state_lock:
        state = _read_state()
        current = state.get('last_history_id')
        if current is None or int(notified_history_id) > int(current):
            state['last_history_id'] = notified_history_id
            _write_state(state)

"""Gmail API integration: fetches newly-arrived mail for a single watched mailbox,
triggered by a Google Cloud Pub/Sub push notification (see main.py's /api/gmail/push).

Read-only access only (gmail.readonly scope, set up via gmail_oauth_setup.py). This
module never sends, modifies, or deletes anything in the mailbox.
"""
import base64
import json
import logging
import os
import threading
import time
from pathlib import Path

from google.auth.transport.requests import Request as GoogleRequest
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# Same logger main.py's push handler already configures (name lookup, not a
# new logger) -- main.py attaches the actual handler/level, since it's
# imported first; this module just adds retry visibility to that same trail.
_logger = logging.getLogger('gmail_push')

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


class EmptyHistoryDiff(RuntimeError):
    """Raised when Gmail says the mailbox advanced but history.list is still empty."""


def start_watch(topic_name):
    """Register (or renew) push notifications for the INBOX label. Must be called
    again before the ~7-day expiration Gmail imposes on watch registrations."""
    service = _service()
    response = service.users().watch(
        userId='me',
        body={'topicName': topic_name, 'labelIds': ['INBOX'], 'labelFilterBehavior': 'INCLUDE'},
    ).execute()
    with _state_lock:
        state = _read_state()
        state['last_history_id'] = response['historyId']
        _write_state(state)
    return response


def _list_new_message_ids(service, start_id):
    """One history.list() pass (with pagination).

    Returns (message_ids, recoverable): recoverable=False on a 404 (start_id
    too old for Gmail to still have history for) -- retrying that can never
    succeed since the same start_id always 404s again, unlike a genuinely
    empty result, which can be a real Gmail indexing-lag race worth retrying
    (see diff_new_message_ids)."""
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
        return [], False
    return list(dict.fromkeys(message_ids)), True  # dedupe, preserve order (same
    # message could appear in both a messageAdded and a labelAdded record)


def _history_has_any_records(service, start_id):
    """Return whether Gmail exposes any history at all after start_id.

    Used only after the add-message diff stays empty: if an unfiltered history
    probe finds records, the notification likely represented a non-new-message
    INBOX change (read/unread/star/etc.) and can be safely acknowledged. If even
    the unfiltered probe is empty while the notified historyId is newer than our
    watermark, Gmail may still be indexing the change, so advancing would make a
    new message permanently disappear from this pipeline.
    """
    try:
        page_token = None
        while True:
            history = service.users().history().list(
                userId='me', startHistoryId=start_id, labelId='INBOX',
                pageToken=page_token).execute()
            if history.get('history'):
                return True, True
            page_token = history.get('nextPageToken')
            if not page_token:
                return False, True
    except HttpError as exc:
        if exc.resp.status != 404:
            raise
        return False, False


_DIFF_RETRY_ATTEMPTS = 3
_DIFF_RETRY_DELAY_SECONDS = 2


def diff_new_message_ids(notified_history_id, sleep=time.sleep):
    """Given the historyId from a push notification, return the ids of messages
    added to INBOX since our last known point. Does NOT advance the stored
    watermark -- call advance_watermark() only after the caller has actually
    attempted to fetch and process each id, so a message can't be marked "seen"
    before anything was ever done with it (e.g. if the session's case-count cap
    or the per-session analysis rate limit rejects it downstream).

    Retries an empty result: Gmail's Pub/Sub push notification can arrive
    before the triggering message is actually queryable via history.list() --
    a well-documented real-world race condition (Gmail's own indexing lags its
    Pub/Sub notification by a few seconds in practice; see e.g. Hiver
    Engineering's writeup and github.com/openclaw/gogcli#379). Since a push
    notification only ever fires because SOMETHING changed, a first-try empty
    result is inherently suspicious -- trusting it immediately risks silently
    treating "not indexed yet" as "nothing new" and permanently missing a real
    email once the watermark advances past it. `sleep` is injectable so tests
    don't actually wait.

    Known limitation: if the watermark file is lost/missing entirely (rather than
    just stale), the very next notification's own triggering message can be
    missed, since Gmail's history API returns entries *after* the given start id
    -- run gmail_watch_start.py (which sets an initial watermark) before the
    first real push, not after, to avoid this in normal operation."""
    service = _service()
    with _state_lock:
        start_id = _read_state().get('last_history_id') or notified_history_id
    last_recoverable = True
    for attempt in range(1, _DIFF_RETRY_ATTEMPTS + 1):
        message_ids, recoverable = _list_new_message_ids(service, start_id)
        last_recoverable = recoverable
        if message_ids:
            if attempt > 1:
                _logger.info('Gmail diff succeeded after retry: attempt=%d startHistoryId=%s notifiedHistoryId=%s',
                              attempt, start_id, notified_history_id)
            return message_ids
        if not recoverable:
            return message_ids
        if attempt == _DIFF_RETRY_ATTEMPTS:
            break
        _logger.info('Gmail diff empty, retrying (Gmail indexing lag): attempt=%d startHistoryId=%s notifiedHistoryId=%s',
                      attempt, start_id, notified_history_id)
        sleep(_DIFF_RETRY_DELAY_SECONDS)
    if last_recoverable:
        has_any_history, recoverable = _history_has_any_records(service, start_id)
        try:
            stale_window = int(start_id) < int(notified_history_id)
        except (TypeError, ValueError):
            stale_window = str(start_id) != str(notified_history_id)
        if not has_any_history and recoverable and stale_window:
            _logger.warning(
                'Gmail diff still empty after retries and unfiltered probe; deferring notification so Pub/Sub can retry: startHistoryId=%s notifiedHistoryId=%s',
                start_id, notified_history_id)
            raise EmptyHistoryDiff(
                f'Gmail history not queryable yet for {start_id}->{notified_history_id}')
        _logger.info(
            'Gmail diff empty after retries: startHistoryId=%s notifiedHistoryId=%s has_any_history=%s recoverable=%s',
            start_id, notified_history_id, has_any_history, recoverable)
    return []


def fetch_raw(message_id):
    return b64decode(_service().users().messages().get(userId='me', id=message_id, format='raw').execute()['raw'])


# Bounded FIFO of recently-processed Gmail message ids, so the same email
# doesn't get analyzed and stored twice. This is a real, observed failure mode:
# diff_new_message_ids() dedupes *within* one call (a message reported by both
# a messageAdded and a labelAdded record in the same history window), but
# Gmail can also emit that message's messageAdded and labelAdded events across
# TWO SEPARATE notifications/historyId windows -- each notification's diff
# then sees the message as "new" independently, since neither the watermark
# nor the per-call dedup has any memory of message ids across calls. Confirmed
# live: the same email (identical SHA-256) was stored as two separate cases,
# ~38 seconds apart, from two distinct push notifications.
_MAX_PROCESSED_IDS = 500


def claim_processed(message_id):
    """Atomically claim this message id before fetching/processing it. Returns
    True if this call is the one that claimed it (proceed), False if another
    call already claimed it first (skip).

    Must be a single atomic check-and-mark, not a separate already_processed()
    check followed later by a mark_processed() call: with those as two calls,
    two concurrent Pub/Sub deliveries for the same message could both pass the
    check before either marks it, both fetch, and both store a duplicate case
    -- a real risk given Pub/Sub's at-least-once delivery semantics and this
    app's own concurrent-request handling (two analysis slots, an async
    endpoint). Combining check-and-mark under one _state_lock acquisition
    closes that race: only one caller can ever see message_id absent and add it.
    """
    with _state_lock:
        state = _read_state()
        ids = state.get('processed_message_ids', [])
        if message_id in ids:
            return False
        ids.append(message_id)
        state['processed_message_ids'] = ids[-_MAX_PROCESSED_IDS:]
        _write_state(state)
        return True


def unclaim_processed(message_id):
    """Undo a claim_processed() claim.

    claim_processed() marks a message done BEFORE it's fetched/analyzed, so a
    transient failure after claiming (this instance's own analysis-slot
    semaphore full, its own per-session rate limit, a momentary Gmail API
    error) used to leave that id permanently in processed_message_ids even
    though nothing was ever actually stored for it -- a real email silently
    and permanently lost, confirmed live. Call this when processing fails so
    a later attempt (within the same push notification's retry loop, or a
    message that gets reported again in a future notification) isn't
    rejected as "already claimed" for work that never happened.

    Known remaining limitation: advance_watermark() still moves the
    watermark past this notification's historyId regardless of per-message
    outcome (so a mid-batch crash can't leave it stuck ahead of unattempted
    work) -- so unclaiming alone does not guarantee a LATER, separate
    notification will ever re-report this exact message once the watermark
    has passed it. This closes the same-request retry window, not every
    possible loss window.
    """
    with _state_lock:
        state = _read_state()
        ids = state.get('processed_message_ids', [])
        if message_id in ids:
            ids.remove(message_id)
            state['processed_message_ids'] = ids
            _write_state(state)


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

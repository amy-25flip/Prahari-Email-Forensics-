import csv
import asyncio
import binascii
import io
import json
import logging
import os
import threading
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import Response, JSONResponse
from fastapi.staticfiles import StaticFiles
import engine
import local_model
import store
import reputation
import siem
from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress, ValidationError, field_validator
from samples import SAMPLES
from request_limits import PeerLimiter

gmail_push_logger = logging.getLogger('gmail_push')
gmail_push_logger.setLevel(logging.INFO)
if not gmail_push_logger.handlers:
    # Configured independently of the root/uvicorn logging setup: uvicorn's
    # default logging config only attaches handlers to its own 'uvicorn'/
    # 'uvicorn.access' loggers, not to root, so with no handler here every
    # .info() call below would be silently dropped in production (root
    # defaults to WARNING with no handler) -- defeating the entire point of
    # this diagnostic trail, which exists so Render logs can show exactly
    # where a push notification succeeded or failed.
    _gmail_push_handler = logging.StreamHandler()
    _gmail_push_handler.setFormatter(logging.Formatter('%(asctime)s %(name)s %(levelname)s %(message)s'))
    gmail_push_logger.addHandler(_gmail_push_handler)
# Own handler is self-contained; don't also emit through root (which may one
# day gain a handler of its own) and print every line twice.
gmail_push_logger.propagate = False
# Bounded retry for a single push message hitting our OWN transient capacity
# (429 from the shared analysis-slot semaphore or the gmail-push session's
# rate limit) -- not a general-purpose retry policy, and not applied to a
# malformed/oversized email, which would just fail identically every time.
_PUSH_MAX_ATTEMPTS = 3
_PUSH_RETRY_DELAY_SECONDS = 2


@asynccontextmanager
async def lifespan(app):
    store.init()
    reputation.load()
    threading.Thread(target=local_model.load, daemon=True).start()
    stop = threading.Event()
    def maintain():
        next_refresh = 0
        while not stop.is_set():
            store.cleanup()
            if os.getenv('DISABLE_FEED_REFRESH') != '1' and time.monotonic() >= next_refresh:
                reputation.refresh()
                next_refresh = time.monotonic() + reputation.REFRESH_SECONDS
            stop.wait(60)
    worker = threading.Thread(target=maintain, daemon=True)
    worker.start()
    yield
    stop.set()
    worker.join(timeout=1)


app = FastAPI(title='AI-Powered Email Threat Detection', lifespan=lifespan)
limits = defaultdict(deque)
slots = threading.BoundedSemaphore(2)
rate_lock = threading.Lock()
peer_limiter = PeerLimiter()


@app.middleware('http')
async def boundary(request: Request, call_next):
    # Pub/Sub push requests can't send our custom app header and aren't a per-analyst
    # browser peer -- they're authenticated by their own signed OIDC bearer token,
    # verified inside the handler itself (see /api/gmail/push).
    push = request.url.path == '/api/gmail/push'
    if request.method in ('POST', 'DELETE') and not push and request.headers.get('x-requested-with') != 'Email-Threat-Detection':
        return JSONResponse({'detail': 'Missing application request header'}, status_code=403)
    # Previously only POST/DELETE were peer-rate-limited here, but every GET
    # to an /api/* route also reaches store.session() below and creates a
    # brand-new session (consuming a MAX_SESSIONS slot) whenever no cookie is
    # sent -- an unauthenticated GET flood could exhaust session capacity and
    # 503 every real user with zero POSTs involved. Gate every real API route
    # (not health/ready, not push, not static asset serving) uniformly.
    if not push and request.url.path.startswith('/api/') and request.url.path not in ('/api/health', '/api/ready'):
        peer = request.client.host if request.client else 'unknown'
        if not peer_limiter.allow(peer):
            return JSONResponse({'detail': 'Peer request limit reached. Retry in one minute.'}, status_code=429, headers={'Retry-After':'60'})
    if request.method == 'POST':
        chunks, size = [], 0
        try:
            async with asyncio.timeout(15):
                async for chunk in request.stream():
                    size += len(chunk)
                    if size > 1500000: return JSONResponse({'detail': 'Upload exceeds email size limit'}, status_code=413)
                    chunks.append(chunk)
        except TimeoutError:
            return JSONResponse({'detail': 'Upload timed out.'}, status_code=408)
        request._body = b''.join(chunks)
    if request.url.path in ('/api/health', '/api/ready', '/api/gmail/push') or not request.url.path.startswith('/api/'):
        return await call_next(request)
    try:
        sid, cookie = store.session(request.cookies.get('efp_session'))
    except ValueError:
        return JSONResponse({'detail': 'Server capacity reached. Please retry later.'}, status_code=503)
    request.state.sid = sid
    response = await call_next(request)
    if cookie: response.set_cookie('efp_session', cookie, httponly=True, samesite='strict', secure=os.getenv('COOKIE_SECURE') == '1', max_age=store.RETENTION_SECONDS)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['X-Frame-Options'] = 'DENY'
    if request.url.path.startswith('/api'): response.headers['Cache-Control'] = 'no-store'
    return response


@app.middleware('http')
async def response_security(request: Request, call_next):
    response = await call_next(request)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'no-referrer'
    if request.url.path.startswith('/api/'): response.headers['Cache-Control'] = 'no-store'
    return response


@app.get('/api/health')
def health():
    import ip_reputation, attachment_reputation, db_encryption, gmail_integration
    return {'status': 'ready', 'model': local_model.status, 'model_detail': local_model.detail, 'retention_hours': store.RETENTION_SECONDS / 3600,
            'reputation': reputation.status(),
            'ip_reputation': {'configured': bool(ip_reputation.config())},
            'attachment_reputation': {'configured': bool(attachment_reputation.config())},
            'db_encryption': db_encryption.status(),
            'gmail_push': {'configured': bool(os.getenv('GMAIL_PUSH_AUDIENCE')) and gmail_integration.configured()}}


@app.get('/api/ready')
def ready():
    return JSONResponse({'ready': local_model.status == 'ready', 'model': local_model.status}, status_code=200 if local_model.status == 'ready' else 503)


@app.get('/api/samples')
def samples(): return SAMPLES


@app.get('/api/siem')
def siem_status(): return siem.status()


@app.post('/api/cases/{cid}/siem')
def send_siem(cid: str, request: Request):
    report = get_case(cid, request)
    if not slots.acquire(blocking=False): raise HTTPException(429, 'Workers busy. Please retry shortly.')
    try:
        receipt = siem.deliver(report)
        with store.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            store.append(db, request.state.sid, {'action': 'siem_delivery', 'id': cid, **receipt})
        return receipt
    except ValueError as exc: raise HTTPException(503, str(exc)) from exc
    finally: slots.release()


class SMTPContext(BaseModel):
    model_config = ConfigDict(extra='forbid')
    client_ip: IPvAnyAddress
    mail_from: str = Field(max_length=320)
    helo: str = Field(min_length=1, max_length=253)

    @field_validator('mail_from')
    @classmethod
    def envelope(cls, value):
        import re
        if value != '<>' and not re.fullmatch(r'[^\s<>@]+@[A-Za-z0-9.-]+', value):
            raise ValueError('Enter the SMTP MAIL FROM address, or <> for an empty envelope.')
        return value

    @field_validator('helo')
    @classmethod
    def hostname(cls, value):
        import re
        if not all(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', label) for label in value.rstrip('.').split('.')):
            raise ValueError('HELO must be a DNS hostname.')
        return value.lower().rstrip('.')


def execute(request, raw, source, live, sample=False, context=None, receiver=None):
    started = time.perf_counter()
    sid, now = request.state.sid, time.time()
    with rate_lock:
        for key in list(limits):
            if not limits[key] or limits[key][-1] < now - 60: del limits[key]
        hits = limits[sid]
        while hits and hits[0] < now - 60: hits.popleft()
        if len(hits) >= 10: raise HTTPException(429, 'Limit: 10 analyses per minute.')
        hits.append(now)
    if not slots.acquire(blocking=False): raise HTTPException(429, 'Analysis workers busy. Please retry shortly.')
    try:
        result = engine.analyze(raw, source, live, context)
        import ps_assessment
        result['assessment'] = ps_assessment.inspect(raw, result)
        import origin_assessment
        if receiver and live and not any(g.get('ip') == context['client_ip'] for g in result['geo']):
            from geolocation import locate
            result['geo'].append(locate(context['client_ip']))
        result['assessment']['origin_evidence'] = origin_assessment.assess(result, context, receiver)
        if receiver:
            result['assessment']['origin_confidence'] = 'Authenticated receiver observation; original sender and human location are not established.'
            result['origin'] = 'Receiver-attested ingress'
        import infrastructure
        result['assessment']['infrastructure'] = infrastructure.assess(result['hops'], live)
        import ip_reputation
        result['assessment']['ip_reputation'] = ip_reputation.enrich(result['hops'], live)
        import attachment_reputation
        result['assessment']['attachment_reputation'] = attachment_reputation.enrich(result['attachments'], live)
        import reputation_triage
        reputation_triage.apply(result)
        import attribution
        result['assessment']['attribution'] = attribution.assess(result)
        if result['assessment']['checks'] and result['triage']['priority'] in ('routine', 'incomplete'):
            result['triage'].update(priority='review', label='Review required',
                                   reasons=['Supplemental header, identity or attachment checks require review.'],
                                   action='Review the static findings before opening attachments or approving sensitive requests.')
        result['elapsed_ms'] = round((time.perf_counter() - started) * 1000)
        result['sample'] = sample
        result['fraud_score'] = result['score']
        return store.save(sid, result, raw)
    except ValueError as exc: raise HTTPException(400, str(exc)) from exc
    finally: slots.release()


@app.post('/api/analyze')
async def analyze_request(request: Request):
    from starlette.concurrency import run_in_threadpool
    content, source = await request.body(), 'upload'
    live = request.query_params.get('enrich') == 'true'
    context = None
    context_data = request.headers.get('x-smtp-context')
    if context_data:
        try:
            if len(context_data) > 2048: raise ValueError('Context too large')
            context = SMTPContext.model_validate_json(context_data).model_dump(mode='json')
        except (ValidationError, ValueError):
            raise HTTPException(400, 'Invalid SMTP context. Provide a client IP, MAIL FROM address (or <>), and HELO hostname.')
        if not live: raise HTTPException(400, 'Enable external DNS verification to evaluate SMTP context.')
    if 'application/json' in request.headers.get('content-type', ''):
        try: content = json.loads(content)['email'].encode('utf-8')
        except (ValueError, KeyError, AttributeError, TypeError): raise HTTPException(400, 'Expected JSON with an email string.')
        source = 'paste'
    receiver = None
    evidence = request.headers.get('x-receiver-evidence')
    if evidence:
        if source != 'upload': raise HTTPException(400, 'Receiver evidence requires original .eml bytes')
        try:
            import receiver_evidence
            receiver = receiver_evidence.verify(evidence, content)
            verified_context = SMTPContext.model_validate(receiver['smtp']).model_dump(mode='json')
            if context is not None and context != verified_context: raise ValueError('Conflicting context')
            context = verified_context
        except (ValueError, ValidationError): raise HTTPException(400, 'Receiver evidence could not be verified against the email and configured receiver')
    return await run_in_threadpool(execute, request, content, source, live, False, context, receiver)


@app.post('/api/gmail/push')
async def gmail_push(request: Request):
    """Google Cloud Pub/Sub push target for real-time Gmail notifications (PS's
    "alerts before user interaction" ask, beyond the analyst-upload workflow).

    Authenticated entirely by Pub/Sub's own signed OIDC bearer token -- not the
    X-Requested-With app header or peer rate limiter (see boundary() above),
    since Google's push infrastructure can't send either and isn't a per-analyst
    browser session. GMAIL_PUSH_AUDIENCE must exactly match the push subscription's
    configured endpoint URL, and the token's verified email claim must match
    GMAIL_PUSH_SERVICE_ACCOUNT_EMAIL -- the service account YOU configure as the
    push subscription's own auth identity (not gmail-api-push@system.gserviceaccount.com,
    which is a different identity entirely: that one is what Gmail's backend uses
    to *publish* to the topic, granted via `gcloud pubsub topics
    add-iam-policy-binding`, unrelated to who signs the *delivery* request that
    actually arrives here).
    """
    from starlette.concurrency import run_in_threadpool
    from googleapiclient.errors import HttpError
    import gmail_integration
    gmail_push_logger.info('Gmail push notification received')
    audience = os.getenv('GMAIL_PUSH_AUDIENCE')
    expected_subject = os.getenv('GMAIL_PUSH_SERVICE_ACCOUNT_EMAIL')
    if not audience or not expected_subject or not gmail_integration.configured():
        gmail_push_logger.warning(
            'Gmail push rejected: not configured audience=%s expected_subject=%s token_file_configured=%s',
            bool(audience), bool(expected_subject), gmail_integration.configured())
        raise HTTPException(503, 'Gmail push is not configured')
    auth = request.headers.get('authorization', '')
    if not auth.startswith('Bearer '):
        gmail_push_logger.warning('Gmail push rejected: missing bearer token')
        raise HTTPException(401, 'Missing bearer token')
    try:
        from google.oauth2 import id_token as google_id_token
        from google.auth.transport import requests as google_requests
        claims = google_id_token.verify_oauth2_token(auth[len('Bearer '):], google_requests.Request(), audience=audience)
        if claims.get('email') != expected_subject or not claims.get('email_verified'):
            raise ValueError('Unexpected token subject')
        gmail_push_logger.info('Gmail push OIDC verified: email=%s audience=%s', claims.get('email'), audience)
    except Exception as exc:
        gmail_push_logger.warning('Gmail push rejected: invalid OIDC token (%s)', type(exc).__name__)
        raise HTTPException(401, 'Invalid push authentication')
    try:
        envelope = await request.json()
        pubsub_message_id = envelope.get('message', {}).get('messageId')
        data = json.loads(gmail_integration.b64decode(envelope['message']['data']))
        history_id = data['historyId']
        email_address = data.get('emailAddress')
        gmail_push_logger.info(
            'Gmail push envelope parsed: historyId=%s emailAddress=%s pubsubMessageId=%s',
            history_id, email_address, pubsub_message_id)
    except (KeyError, ValueError, TypeError, UnicodeDecodeError, binascii.Error) as exc:
        gmail_push_logger.warning('Gmail push rejected: malformed Pub/Sub envelope (%s)', type(exc).__name__)
        raise HTTPException(400, 'Malformed Pub/Sub push envelope')
    try:
        request.state.sid = gmail_integration.session_sid()
        gmail_push_logger.info('Gmail push session resolved: sid=%s historyId=%s', request.state.sid, history_id)
    except Exception as exc:
        gmail_push_logger.exception('Gmail push session resolution failed for historyId=%s: %s', history_id, exc)
        raise
    try:
        message_ids = await run_in_threadpool(gmail_integration.diff_new_message_ids, history_id)
        gmail_push_logger.info(
            'Gmail push diff complete: historyId=%s message_count=%d message_ids=%s',
            history_id, len(message_ids), message_ids)
    except gmail_integration.EmptyHistoryDiff as exc:
        gmail_push_logger.warning('Gmail push diff deferred for historyId=%s: %s', history_id, exc)
        raise HTTPException(503, 'Gmail history is not queryable yet; retry this push') from exc
    except Exception as exc:
        gmail_push_logger.exception('Gmail push diff failed for historyId=%s: %s', history_id, exc)
        raise
    processed = []
    skipped = 0
    failed = 0
    for mid in message_ids:
        # Claim BEFORE fetching, atomically -- not a check then a separate mark
        # after fetch -- so two concurrent notifications for the same message
        # (Gmail can report it via a messageAdded event in one notification and
        # a labelAdded event in a later, separate one) can't both race past a
        # "not yet processed" check and both store a duplicate case. Confirmed
        # live as a real bug before this existed.
        if not await run_in_threadpool(gmail_integration.claim_processed, mid):
            skipped += 1
            gmail_push_logger.info('Gmail push message skipped: historyId=%s messageId=%s reason=already_claimed', history_id, mid)
            continue
        gmail_push_logger.info('Gmail push message claimed: historyId=%s messageId=%s', history_id, mid)
        stored, last_status, last_detail = False, None, None
        for attempt in range(1, _PUSH_MAX_ATTEMPTS + 1):
            try:
                raw = await run_in_threadpool(gmail_integration.fetch_raw, mid)
                gmail_push_logger.info('Gmail push message fetched: historyId=%s messageId=%s bytes=%d', history_id, mid, len(raw))
                result = await run_in_threadpool(execute, request, raw, 'gmail-push', True, False, None, None)
                processed.append(result)
                gmail_push_logger.info(
                    'Gmail push message analyzed: historyId=%s messageId=%s caseId=%s score=%s risk=%s',
                    history_id, mid, result.get('id'), result.get('score'), result.get('risk'))
                stored = True
                break
            except HTTPException as exc:
                last_status, last_detail = exc.status_code, exc.detail
                # 429 here means OUR OWN transient capacity (the shared
                # 2-slot analysis semaphore, or the fixed gmail-push
                # session's own per-minute cap) was momentarily exhausted --
                # nothing wrong with this email. Confirmed live: concurrent
                # web-UI testing or a burst of pushes could saturate these
                # and permanently drop an otherwise-good message. A 4xx that
                # isn't 429 (malformed/oversized email) will never succeed
                # on retry, so don't waste attempts on it.
                if exc.status_code == 429 and attempt < _PUSH_MAX_ATTEMPTS:
                    gmail_push_logger.info(
                        'Gmail push message busy, retrying: historyId=%s messageId=%s attempt=%d status=%s',
                        history_id, mid, attempt, exc.status_code)
                    await asyncio.sleep(_PUSH_RETRY_DELAY_SECONDS)
                    continue
                gmail_push_logger.warning(
                    'Gmail push message failed with HTTPException: historyId=%s messageId=%s status=%s detail=%s',
                    history_id, mid, exc.status_code, exc.detail)
                break
            except HttpError as exc:
                last_status = getattr(getattr(exc, 'resp', None), 'status', None)
                last_detail = str(exc)
                gmail_push_logger.warning(
                    'Gmail push message failed with Gmail HttpError: historyId=%s messageId=%s status=%s reason=%s',
                    history_id, mid, last_status, exc)
                break  # one bad/oversized/over-quota/Gmail-API-error message must not sink the rest of the batch
        if not stored:
            failed += 1
            # Un-claim so this message isn't permanently marked "done" for
            # work that never actually happened -- see unclaim_processed()'s
            # docstring for the retry window this does and doesn't cover.
            await run_in_threadpool(gmail_integration.unclaim_processed, mid)
            gmail_push_logger.warning(
                'Gmail push message failed after all attempts, unclaimed (not guaranteed to be retried once the watermark advances): historyId=%s messageId=%s status=%s detail=%s',
                history_id, mid, last_status, last_detail)
    # Advance only after attempting every id this notification covers -- not before
    # processing, so a message a batch never got to isn't wrongly marked "seen".
    try:
        await run_in_threadpool(gmail_integration.advance_watermark, history_id)
        gmail_push_logger.info(
            'Gmail push watermark advanced: historyId=%s processed=%d skipped=%d failed=%d total=%d',
            history_id, len(processed), skipped, failed, len(message_ids))
    except Exception as exc:
        gmail_push_logger.exception('Gmail push watermark advance failed for historyId=%s: %s', history_id, exc)
        raise
    gmail_push_logger.info(
        'Gmail push notification complete: historyId=%s processed=%d skipped=%d failed=%d case_ids=%s',
        history_id, len(processed), skipped, failed, [r['id'] for r in processed])
    return {'processed': len(processed), 'case_ids': [r['id'] for r in processed]}


def _require_bearer_token(request, env_var, unconfigured_detail):
    # Fail closed: the env var must be explicitly configured, never defaulting
    # to open just because it's unset.
    import secrets
    token = os.getenv(env_var)
    if not token:
        raise HTTPException(503, unconfigured_detail)
    auth = request.headers.get('authorization', '')
    if not auth.startswith('Bearer ') or not secrets.compare_digest(auth[len('Bearer '):], token):
        raise HTTPException(401, 'Invalid or missing token')


def _require_gmail_read_token(request):
    # Unlike every other case-viewing endpoint, these read a single shared
    # session with no per-caller session cookie to isolate against -- on a
    # public URL watching a real mailbox (not a demo/dummy inbox), that means
    # anyone who can reach the deployment could otherwise read real analyzed
    # email content.
    _require_bearer_token(request, 'GMAIL_CASES_READ_TOKEN', 'Gmail case viewing is not configured')


def _require_gmail_watch_admin_token(request):
    # Deliberately a separate, stronger-privilege token from the read token above:
    # this is a mutating action (re-registers the watch and resets last_history_id
    # to "now"), so anyone holding it could effectively cause unprocessed mail to
    # be silently skipped -- a read-only viewing token should not also grant this.
    _require_bearer_token(request, 'GMAIL_WATCH_ADMIN_TOKEN', 'Gmail watch administration is not configured')


@app.get('/api/gmail/cases')
def gmail_cases(request: Request):
    """Every case analyzed from Gmail push notifications. These live under a
    dedicated, stable session (see gmail_integration.session_sid()), not the
    caller's own browser session cookie -- gated by GMAIL_CASES_READ_TOKEN
    instead, since there's no per-analyst session to check against here."""
    import gmail_integration
    _require_gmail_read_token(request)
    if not gmail_integration.configured():
        raise HTTPException(503, 'Gmail push is not configured')
    sid = gmail_integration.session_sid()
    return [{k: r[k] for k in ('id', 'subject', 'sender', 'score', 'risk', 'created', 'sample')} for r in store.all_cases(sid)]


@app.get('/api/gmail/cases/{cid}')
def gmail_case(cid: str, request: Request):
    import gmail_integration
    _require_gmail_read_token(request)
    if not gmail_integration.configured():
        raise HTTPException(503, 'Gmail push is not configured')
    result = store.get(gmail_integration.session_sid(), cid)
    if not result: raise HTTPException(404, 'Case not found')
    return result


@app.post('/api/gmail/watch/start')
def gmail_watch_start(request: Request):
    """(Re-)register the Gmail push watch, run on THIS instance -- not a local
    script. gmail_watch_start.py (the CLI equivalent) only ever runs on whoever's
    own machine, writing the initial watermark to THEIR local state file; running
    it there does nothing for a deployed instance, since state lives wherever
    GMAIL_STATE_FILE/DATA_DIR points on that instance, not on the developer's
    machine. This is the only way to actually seed a deployed instance's own
    watermark so its first real push notification doesn't fall back to the
    documented "missed the triggering message" edge case."""
    import gmail_integration
    _require_gmail_watch_admin_token(request)
    topic = os.getenv('GMAIL_PUBSUB_TOPIC')
    if not topic or not gmail_integration.configured():
        raise HTTPException(503, 'Gmail push is not configured')
    try:
        response = gmail_integration.start_watch(topic)
    except Exception as exc:
        raise HTTPException(502, f'Gmail watch registration failed ({type(exc).__name__})') from exc
    return {'historyId': response['historyId'], 'expiration': response['expiration']}


@app.post('/api/samples/{sample_id}')
def analyze_sample(sample_id: str, request: Request):
    sample = next((s for s in SAMPLES if s['id'] == sample_id), None)
    if not sample: raise HTTPException(404, 'Sample not found')
    return execute(request, sample['raw'].replace('\n', '\r\n').encode(), 'fixture', False, True)


@app.get('/api/cases')
def cases(request: Request):
    return [{k: r[k] for k in ('id', 'subject', 'sender', 'score', 'risk', 'created', 'sample')} for r in store.all_cases(request.state.sid)]


@app.get('/api/cases/{cid}')
def get_case(cid: str, request: Request):
    result = store.get(request.state.sid, cid)
    if not result: raise HTTPException(404, 'Case not found in this session')
    return result


@app.post('/api/cases/{cid}/attachments/{sha256}/sandbox')
def submit_attachment_sandbox(cid: str, sha256: str, request: Request):
    import re, engine, attachment_reputation
    if not re.fullmatch(r'[0-9a-fA-F]{64}', sha256): raise HTTPException(400, 'Invalid SHA-256 digest')
    report = get_case(cid, request)
    if not any(a['sha256'] == sha256.lower() for a in report.get('attachments', [])):
        raise HTTPException(404, 'No attachment with this hash in this case')
    raw = store.get_raw(request.state.sid, cid)
    payload = engine.extract_attachment(raw, sha256.lower())
    if payload is None: raise HTTPException(404, 'Attachment bytes are no longer available for this case')
    if not slots.acquire(blocking=False): raise HTTPException(429, 'Workers busy. Please retry shortly.')
    try:
        result = attachment_reputation.submit_for_sandbox(payload, filename=sha256[:16])
        with store.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            store.append(db, request.state.sid, {'action': 'sandbox_submit', 'id': cid, 'sha256': sha256.lower(), 'status': result['status']})
        return result
    finally: slots.release()


@app.post('/api/attachments/sandbox/{analysis_id}')
def get_attachment_sandbox_status(analysis_id: str):
    import attachment_reputation
    if not slots.acquire(blocking=False): raise HTTPException(429, 'Workers busy. Please retry shortly.')
    try:
        return attachment_reputation.analysis_status(analysis_id)
    finally: slots.release()


@app.delete('/api/cases/{cid}')
def delete_case(cid: str, request: Request):
    if not store.delete(request.state.sid, cid): raise HTTPException(404, 'Case not found')
    return {'deleted': True}


@app.get('/api/connections')
def connections(request: Request): return store.connections(request.state.sid)


@app.get('/api/campaigns')
def campaign_groups(request: Request):
    import campaigns
    return campaigns.build(store.all_cases(request.state.sid))


class Checkpoint(BaseModel):
    model_config = ConfigDict(extra='forbid')
    schema_version: int = Field(alias='schema', ge=1, le=1, strict=True)
    session_fingerprint: str = Field(pattern=r'^[a-f0-9]{64}$')
    event_count: int = Field(ge=0, le=1000000, strict=True)
    head: str = Field(pattern=r'^[a-f0-9]{64}$')
    created_at: float = Field(ge=0, allow_inf_nan=False)
    scope: str = Field(max_length=300)


class ReviewDecision(BaseModel):
    model_config = ConfigDict(extra='forbid')
    decision: str = Field(pattern=r'^(hold|approved)$')
    note: str = Field(min_length=20, max_length=1000)
    acknowledged: bool = Field(strict=True)


class BlockchainProof(BaseModel):
    model_config = ConfigDict(extra='forbid')
    sha256: str = Field(pattern=r'^[a-f0-9]{64}$')
    proof: str = Field(min_length=1, max_length=16384)


@app.get('/api/cases/{cid}/review')
def review_status(cid: str, request: Request):
    get_case(cid, request)
    with store.connect() as db:
        for row in db.execute('SELECT payload FROM events WHERE session=? ORDER BY seq DESC', (request.state.sid,)):
            event = json.loads(row['payload'])
            if event.get('action') == 'review' and event.get('id') == cid: return event
    return {'decision': 'pending'}


@app.post('/api/cases/{cid}/review')
def record_review(cid: str, payload: ReviewDecision, request: Request):
    report = get_case(cid, request)
    elevated = report['triage']['priority'] != 'routine'
    if payload.decision == 'approved' and elevated and not payload.acknowledged:
        raise HTTPException(409, 'Acknowledge the findings before recording approval.')
    if len(payload.note.strip()) < 20: raise HTTPException(400, 'Provide a substantive review note.')
    event = {'action': 'review', 'id': cid, 'at': time.time(), **payload.model_dump(),
             'scope': 'Session analyst decision only; no mail delivery, release or external action performed.'}
    with store.connect() as db:
        db.execute('BEGIN IMMEDIATE')
        if not db.execute('SELECT id FROM cases WHERE id=? AND session=?', (cid, request.state.sid)).fetchone():
            raise HTTPException(404, 'Case no longer exists')
        store.append(db, request.state.sid, event)
    return event


@app.get('/api/checkpoint')
def checkpoint(request: Request):
    import checkpoints
    try:
        return checkpoints.snapshot(request.state.sid)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc


@app.post('/api/checkpoint/verify')
def verify_checkpoint(payload: Checkpoint, request: Request):
    import checkpoints
    return checkpoints.verify(request.state.sid, payload.model_dump(by_alias=True))


@app.get('/api/verify')
def verify(request: Request): return store.verify(request.state.sid)


@app.post('/api/checkpoint/blockchain-stamp')
def blockchain_stamp(request: Request):
    import checkpoints, blockchain_timestamp
    try:
        head = checkpoints.snapshot(request.state.sid)['head']
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
    if not slots.acquire(blocking=False): raise HTTPException(429, 'Workers busy. Please retry shortly.')
    try:
        result = blockchain_timestamp.stamp(head)
        with store.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            store.append(db, request.state.sid, {'action': 'blockchain_stamp', 'head': head, 'status': result['status']})
        return result
    finally: slots.release()


@app.post('/api/checkpoint/blockchain-verify')
def blockchain_verify(payload: BlockchainProof):
    import blockchain_timestamp
    if not slots.acquire(blocking=False): raise HTTPException(429, 'Workers busy. Please retry shortly.')
    try:
        return blockchain_timestamp.check(payload.sha256, payload.proof)
    finally: slots.release()


@app.get('/api/cases/{cid}/export/{fmt}')
def export(cid: str, fmt: str, request: Request):
    result = get_case(cid, request)
    mode = request.query_params.get('privacy', 'full')
    if mode not in ('full', 'redacted'): raise HTTPException(400, 'Choose full or redacted privacy mode')
    if mode == 'redacted':
        from privacy import redact
        result = redact(result)
    if fmt == 'json': body, mime = json.dumps(result, indent=2, ensure_ascii=True).encode(), 'application/json'
    elif fmt == 'cef': body, mime = siem.cef(result).encode(), 'text/plain'
    elif fmt == 'csv':
        stream = io.StringIO(newline='')
        writer = csv.writer(stream)
        writer.writerow(['type', 'indicator'])
        for item in result['indicators']:
            val = item['value']
            if val.lstrip().startswith(('=', '+', '-', '@')): val = "'" + val
            writer.writerow([item['type'], val])
        body, mime = stream.getvalue().encode('utf-8-sig'), 'text/csv'
    elif fmt == 'pdf':
        from fpdf import FPDF
        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=18)
        pdf.add_page()
        def line(text, size=10):
            pdf.set_font('Helvetica', size=size)
            pdf.multi_cell(0, 6, str(text).encode('latin-1', 'replace').decode('latin-1'), new_x='LMARGIN', new_y='NEXT')
        line('AI-Powered Email Threat Detection', 18)
        line('Redacted Email Forensic Report' if mode == 'redacted' else 'Email Forensic Report', 12)
        line('Case: ' + cid)
        line('CONTROLLED DEMONSTRATION FIXTURE' if result.get('sample') else 'User-submitted email')
        line('Subject: ' + result['subject'])
        line('From: ' + result['sender'])
        line(f"Risk: {result['risk']} / {result['score']} of 100 (heuristic)")
        if result.get('triage'):
            line('Review priority: ' + result['triage']['label'])
            for reason in result['triage']['reasons']: line(reason)
            line(result['triage']['action'])
            line(result['triage']['score_explanation'])
        line('Original SHA-256: ' + result['sha256'])
        line('Origin: ' + result['origin'])
        line('NLP: ' + result['ml']['label'] + ' / ' + result['ml']['detail'])
        line('EVIDENCE', 13)
        if result.get('assessment'):
            line('Threat categories: ' + ', '.join(result['assessment']['categories']))
            line(result['assessment']['method'])
            for check in result['assessment']['checks']: line(check['title'] + ': ' + check['detail'])
            origin = result['assessment'].get('origin_evidence', {})
            line('Origin evidence confidence: ' + origin.get('confidence', 'undetermined'))
            line(origin.get('basis', ''))
            fingerprint = result['assessment'].get('hosting_fingerprint', {})
            line('Infrastructure fingerprint: ' + str(fingerprint.get('sha256') or 'Unavailable'))
            if origin.get('earliest_reliable_node'):
                line('Receiver-attested ingress: ' + origin['earliest_reliable_node']['ip'])
            attribution = result['assessment'].get('attribution', {})
            if attribution:
                line(f"Attribution confidence: {attribution['confidence_score']}/100 ({attribution['band']})")
                for factor in attribution['factors']:
                    if factor['applied']: line(f"  {factor['direction']} {factor['factor']} ({factor['weight']}): {factor['detail']}")
                for caveat in attribution['caveats']: line('  Caveat: ' + caveat)
            for entry in result['assessment'].get('ip_reputation', []):
                if entry.get('status') == 'available':
                    line(f"IP reputation {entry['ip']}: {entry['usage_type']} | abuse score {entry.get('abuse_confidence_score')} | Tor={entry.get('is_tor')}")
            for entry in result['assessment'].get('attachment_reputation', []):
                if entry.get('status') in ('available', 'no_prior_reports'):
                    line(f"Attachment reputation {entry['sha256'][:16]}...: {entry['detail']}")
        for finding in result['findings']: line(f"{finding['title']}: {finding['detail']}")
        if result.get('prompt_injection', {}).get('indicators'):
            line('AI MANIPULATION SIGNALS', 13)
            line(result['prompt_injection']['detail'])
            for indicator in result['prompt_injection']['indicators']:
                line(f"{indicator['type']}: {indicator['description']}" + (f" — \"{indicator['excerpt']}\"" if indicator.get('excerpt') else ''))
        if result.get('conflicts'): line('EVIDENCE CONFLICTS', 13)
        for conflict in result.get('conflicts', []):
            line('EVIDENCE CONFLICT: ' + conflict['title'], 12)
            line(conflict['explanation'])
            line('Evidence: ' + ', '.join(conflict['evidence_refs']))
            line('Next verification: ' + conflict['action'])
            line(conflict['assessment'])
        line('AUTHENTICATION RESULTS', 13)
        for key, value in result['authentication'].items(): line(f"{key.upper()}: {value['status']} - {value['detail']}")
        if result.get('domain_intelligence'):
            info = result['domain_intelligence']
            line('DOMAIN INTELLIGENCE', 13)
            line(str(info.get('domain', '')) + ': ' + info['status'])
            for kind, record in info.get('dns', {}).items(): line(kind + ': ' + ', '.join(record['values']) + ' (' + record['status'] + ')')
            registry = info.get('registration', {})
            line('Registrar: ' + str(registry.get('registrar') or 'Unavailable'))
            line('Registered: ' + str(registry.get('registered_at') or 'Unavailable'))
        line('RELAY OBSERVATIONS', 13)
        for hop in result['hops']: line(hop['raw'] + ' | ' + hop['trust'])
        line('INDICATORS', 13)
        for item in result['indicators']: line(item['type'] + ': ' + item['value'])
        line('URL REPUTATION', 13)
        for item in result['urls']:
            rep = item.get('reputation')
            if isinstance(rep, dict): line(f"{item['url']} | {rep['source']}: {rep['status']} | record {rep.get('record_id') or '-'} | {rep['detail']}")
        line('LIMITATIONS', 13)
        for limitation in result['limitations']: line(limitation)
        line('Local hash verification is tamper-evident, not proof of legal admissibility or independent custody.')
        body, mime = bytes(pdf.output()), 'application/pdf'
    else: raise HTTPException(400, 'Choose json, csv, pdf or cef')
    return Response(body, media_type=mime, headers={'Content-Disposition': f'attachment; filename="case-{cid}.{fmt}"'})


DIST = Path(__file__).resolve().parents[1] / 'frontend' / 'dist'
if DIST.exists(): app.mount('/', StaticFiles(directory=DIST, html=True), name='frontend')

import csv
import asyncio
import binascii
import io
import json
import logging
import os
import threading
import time
import datetime
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import Response, JSONResponse
from fastapi.staticfiles import StaticFiles
import authz
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
            try:
                store.cleanup()
                import ledger
                ledger.cleanup()
                if os.getenv('DISABLE_FEED_REFRESH') != '1' and time.monotonic() >= next_refresh:
                    reputation.refresh()
                    next_refresh = time.monotonic() + reputation.REFRESH_SECONDS
            except Exception:
                logging.exception("Maintenance cycle failed; retrying next cycle")
            stop.wait(60)
    worker = threading.Thread(target=maintain, daemon=True)
    worker.start()
    gateway_port = os.getenv('GATEWAY_SMTP_PORT', '').strip()
    if gateway_port:
        try:
            start_gateway(int(gateway_port), os.getenv('GATEWAY_SMTP_HOST', '127.0.0.1'))
        except Exception:
            logging.exception('Pre-delivery gateway failed to start; continuing without it')
    retry_drain = None if os.getenv('DISABLE_GMAIL_RETRY_DRAIN') == '1' else asyncio.create_task(_dead_letter_drain_loop())
    try:
        yield
    finally:
        stop.set()
        stop_gateway()
        worker.join(timeout=1)
        if retry_drain is not None:
            retry_drain.cancel()
            try:
                await retry_drain
            except asyncio.CancelledError:
                pass


app = FastAPI(title='AI-Powered Email Threat Detection', lifespan=lifespan)
limits = defaultdict(deque)
slots = threading.BoundedSemaphore(2)
rate_lock = threading.Lock()
peer_limiter = PeerLimiter()

# X-Forwarded-For is client-controllable and NOT trusted by default -- a
# request.client.host of the real TCP peer is safe from spoofing, but behind
# a real reverse proxy it is always the PROXY's own address, so every real
# user shares one rate-limit bucket. TRUSTED_PROXY_HOPS is an explicit,
# opt-in escape hatch: set it to the exact number of reverse proxies known to
# sit in front of this app (each of which faithfully APPENDS, never
# replaces, the peer address it observed) to recover the real per-client
# identity safely. Left at the default 0, behavior is UNCHANGED from before
# this fix -- see test_peer_limit_cannot_be_reset_with_cookie_or_forwarded_header,
# which deliberately proves the header is ignored by default.
TRUSTED_PROXY_HOPS = int(os.getenv('TRUSTED_PROXY_HOPS', '0'))
# Codex review (Medium): TRUSTED_PROXY_HOPS alone trusted X-Forwarded-For
# from ANY direct connection once set, with no check on who actually made
# that connection -- an attacker reaching this app directly (a network
# misconfiguration, or the app being reachable on a path the real proxy
# doesn't front) could set an arbitrary XFF and freely rotate their own
# rate-limit identity. TRUSTED_PROXY_IPS closes that: XFF is only ever
# consulted when request.client.host (the real, non-spoofable direct TCP
# peer) is itself one of these known, explicitly-configured proxy addresses.
# Left empty (the default), XFF is NEVER trusted, even if TRUSTED_PROXY_HOPS
# is set -- fails closed, matching this codebase's existing convention for
# every other "explicitly configured, else safe default" setting.
TRUSTED_PROXY_IPS = {ip.strip() for ip in os.getenv('TRUSTED_PROXY_IPS', '').split(',') if ip.strip()}


def _parse_networks(value):
    import ipaddress
    networks = []
    for item in value.split(','):
        item = item.strip()
        if not item: continue
        try: networks.append(ipaddress.ip_network(item, strict=False))
        except ValueError: logging.warning('Ignoring invalid TRUSTED_PROXY_CIDRS entry: %r', item)
    return networks


# Optional CIDR ranges (e.g. 10.0.0.0/8) for proxy fleets whose addresses change.
TRUSTED_PROXY_CIDRS = _parse_networks(os.getenv('TRUSTED_PROXY_CIDRS', ''))


def _is_trusted_proxy(address):
    if address in TRUSTED_PROXY_IPS: return True
    if not TRUSTED_PROXY_CIDRS: return False
    import ipaddress
    try: ip = ipaddress.ip_address(address)
    except ValueError: return False
    return any(ip in network for network in TRUSTED_PROXY_CIDRS)


def peer_identity(request):
    """The identity used for peer rate-limiting. With TRUSTED_PROXY_HOPS=0
    (default) or an unrecognized direct peer, this is exactly
    request.client.host, ignoring any client-supplied header entirely. Only
    when BOTH TRUSTED_PROXY_HOPS>=1 AND the direct peer is listed in
    TRUSTED_PROXY_IPS does it take the entry N positions from the RIGHT of
    X-Forwarded-For -- the standard trusted-proxy convention: a client can
    prepend arbitrary fake entries to its own request, but each real trusted
    hop only ever APPENDS what it itself observed, so the last N entries are
    exactly the N real hops regardless of what the client tried to prepend.
    Falls back to request.client.host if the header is absent or has fewer
    entries than expected (a misconfigured/missing proxy must not silently
    trust attacker input)."""
    direct = request.client.host if request.client else 'unknown'
    if TRUSTED_PROXY_HOPS <= 0 or not _is_trusted_proxy(direct):
        return direct
    forwarded = request.headers.get('x-forwarded-for', '')
    parts = [p.strip() for p in forwarded.split(',') if p.strip()]
    if len(parts) < TRUSTED_PROXY_HOPS:
        return direct
    # Multi-hop: the direct peer is proxy #1 and appended parts[-1]; every entry
    # between it and the client (parts[-1] .. parts[-(HOPS-1)]) must itself be a
    # trusted proxy. The first entry from the right that is NOT trusted is the
    # real client -- a forged value prepended by an attacker can never be reached,
    # because trusted proxies only ever append.
    for offset in range(1, TRUSTED_PROXY_HOPS):
        if not _is_trusted_proxy(parts[-offset]):
            return parts[-offset]
    return parts[-TRUSTED_PROXY_HOPS]


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
        peer = peer_identity(request)
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
    actor_token = None
    if authz.enabled() and not authz.is_exempt(request.url.path):
        actor = authz.authenticate(request.headers.get('authorization'))
        if actor is None:
            return JSONResponse({'detail': 'Authentication required: send a valid access token.'}, status_code=401, headers={'WWW-Authenticate': 'Bearer'})
        needed = authz.required_role(request.method, request.url.path, request.query_params)
        if not authz.allows(actor.role, needed):
            return JSONResponse({'detail': f'Your role ({actor.role}) cannot do this; {needed} access is required.'}, status_code=403)
        request.state.actor = actor
        actor_token = authz.current_actor.set(actor)
    try:
        return await _with_session(request, call_next)
    finally:
        if actor_token is not None: authz.current_actor.reset(actor_token)


async def _with_session(request, call_next):
    try:
        if getattr(request.state, 'actor', None) is not None:
            sid, cookie = store.workspace_session(), None      # authenticated people share one workspace (see authz.py)
        else:
            sid, cookie = store.session(request.cookies.get('efp_session'))
    except ValueError:
        return JSONResponse({'detail': 'Server capacity reached. Please retry later.'}, status_code=503)
    request.state.sid = sid
    response = await call_next(request)
    if cookie: response.set_cookie('efp_session', cookie, httponly=True, samesite='strict', secure=os.getenv('COOKIE_SECURE') == '1', max_age=store.RETENTION_SECONDS)
    # Security headers (X-Content-Type-Options, X-Frame-Options, Referrer-Policy,
    # Cache-Control) are set once, for every response including early returns from
    # this middleware, by response_security() below -- it wraps this middleware as
    # the outer layer (registered after it), so it always runs on the way out.
    return response


# img-src's tile.openstreetmap.org: the ONLY external resource the built
# frontend actually loads (RelayMap.jsx's Leaflet tile layer, confirmed by
# grepping the frontend source for every https:// reference, not guessed) --
# exact hostname, not a *.tile.openstreetmap.org wildcard, since the app
# requests that single host directly with no {s} subdomain placeholder.
# style-src allows 'unsafe-inline': Codex review (Medium) -- React's own
# inline style={{...}} props and Leaflet's runtime marker/tile positioning
# rely on inline styling, and 'self'-only style-src risked silently breaking
# the map (verified an img-src tile itself loads fine, but that alone
# doesn't prove Leaflet's own style-attribute manipulation isn't blocked).
# This is a standard, low-risk tradeoff: CSP's real XSS defense value is in
# script-src (kept strict, 'self' only), not style-src -- a CSS-only
# injection is a much lower-severity class of attack than script injection,
# and this app has no inline-style-based user content rendering that
# 'unsafe-inline' here would newly expose.
CONTENT_SECURITY_POLICY = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data: https://tile.openstreetmap.org; "
    "connect-src 'self'; "
    "frame-ancestors 'none'; "
    "base-uri 'self'; "
    "form-action 'self'"
)


@app.middleware('http')
async def response_security(request: Request, call_next):
    response = await call_next(request)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['Content-Security-Policy'] = CONTENT_SECURITY_POLICY
    response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
    # Only ever sent when the deployer has explicitly asserted the app is
    # served over HTTPS (the SAME COOKIE_SECURE flag already gates the
    # session cookie's own Secure attribute above) -- sending HSTS over
    # plain HTTP, or when HTTPS isn't guaranteed, risks the browser
    # REFUSING to connect at all until the policy's max-age expires, a far
    # worse failure mode than simply not having the header.
    if os.getenv('COOKIE_SECURE') == '1':
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    if request.url.path.startswith('/api/'): response.headers['Cache-Control'] = 'no-store'
    return response


@app.get('/api/whoami')
def whoami(request: Request):
    actor = getattr(request.state, 'actor', None)
    return {'auth_required': authz.enabled(), 'actor': actor.name if actor else None, 'role': actor.role if actor else None}


@app.get('/api/health')
def health():
    import ip_reputation, attachment_reputation, db_encryption, gmail_integration
    return {'status': 'ready', 'auth_required': authz.enabled(), 'model': local_model.status, 'model_detail': local_model.detail, 'retention_hours': store.RETENTION_SECONDS / 3600,
            'reputation': reputation.status(),
            'ip_reputation': {'configured': bool(ip_reputation.config())},
            'attachment_reputation': {'configured': bool(attachment_reputation.config())},
            'db_encryption': db_encryption.status(),
            'gmail_push': {'configured': bool(os.getenv('GMAIL_PUSH_AUDIENCE')) and gmail_integration.configured()},
            'gateway': {'listening': gateway_state['controller'] is not None, 'port': gateway_state['port']}}


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
    actor = getattr(request.state, 'actor', None)
    bucket = actor.name if actor else sid          # per person when authenticated (the workspace session is shared)
    with rate_lock:
        for key in list(limits):
            if not limits[key] or limits[key][-1] < now - 60: del limits[key]
        hits = limits[bucket]
        while hits and hits[0] < now - 60: hits.popleft()
        cap = 60 if source == 'gateway' else 10
        if len(hits) >= cap: raise HTTPException(429, f'Limit: {cap} analyses per minute.')
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
        import conversation
        prior_reports = store.all_cases(sid)  # session-scoped; current result isn't saved yet
        result['assessment']['conversation'] = conversation.assess(result, prior_reports)
        result['assessment']['checks'] = result['assessment']['checks'] + result['assessment']['conversation']['checks']
        import finding_ids
        finding_ids.assign(result['assessment']['checks'], 'kind')
        import network_history, ledger
        ledger_pairs = ledger.pairs_for(result)
        try: ledger_hits = ledger.lookup(ledger_pairs, sid)
        except Exception:
            logging.exception('Indicator ledger lookup failed; continuing without cross-session history')
            ledger_hits = {}
        result['assessment']['network_history'] = network_history.assess(result, prior_reports, ledger_hits)
        if result['assessment']['checks'] and result['triage']['priority'] in ('routine', 'incomplete'):
            result['triage'].update(priority='review', label='Review required',
                                   reasons=['Supplemental header, identity or attachment checks require review.'],
                                   action='Review the static findings before opening attachments or approving sensitive requests.')
        import playbook
        result['assessment']['playbook'] = playbook.build(result)
        result['elapsed_ms'] = round((time.perf_counter() - started) * 1000)
        result['sample'] = sample
        result['fraud_score'] = result['score']
        saved = store.save(sid, result, raw)
        if not sample:
            try: ledger.record(ledger_pairs, sid)
            except Exception: logging.exception('Indicator ledger record failed; the analysis result is unaffected')
        return saved
    except ValueError as exc:
        msg = str(exc)
        # A store capacity / session ceiling is a TRANSIENT condition -- the email
        # itself is perfectly valid, the store is just full. Surface it as 503 so
        # the Gmail push pipeline dead-letters and retries it (space frees up as
        # cases expire or are deleted) instead of misreading a good email as
        # permanently unprocessable and dropping it. Genuine payload problems
        # (malformed .eml, conflicting context) stay a 400.
        if 'capacity reached' in msg or 'Session limit reached' in msg:
            raise HTTPException(503, msg) from exc
        raise HTTPException(400, msg) from exc
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


def _gmail_httperror_is_transient(status, exc):
    """Classify a googleapiclient HttpError as transient (worth retrying) or
    permanent. 429 and 5xx are transient. Gmail ALSO returns its quota/rate-limit
    errors as HTTP 403 with reason `rateLimitExceeded`/`userRateLimitExceeded`,
    which Google documents as retryable with backoff -- so those specific 403s are
    transient too, while a genuinely permanent 403 (domainPolicy, access revoked)
    and a 404 (deleted) stay permanent. The retryable 403 reasons include the
    per-user/per-second rate limits AND the project/daily quota limits
    (quotaExceeded/dailyLimitExceeded), which are equally temporary. Matching the
    reason string (from the error body) avoids dropping a rate-limited or
    quota-limited message as if it were unprocessable.
    See https://developers.google.com/workspace/gmail/api/guides/handle-errors."""
    try:
        status = int(status)
    except (TypeError, ValueError):
        return False
    if status == 429 or status == 408 or status >= 500:
        return True
    if status == 403:
        text = ''
        try:
            text = (getattr(exc, 'content', b'') or b'').decode('utf-8', 'replace')
        except (AttributeError, UnicodeDecodeError):
            text = ''
        text += str(exc)
        return any(reason in text for reason in (
            'rateLimitExceeded', 'userRateLimitExceeded', 'quotaExceeded', 'dailyLimitExceeded'))
    return False


def _gmail_action(sid, mid, result):
    """Optional protective label/quarantine (see gmail_actions.py); records what happened in the custody chain."""
    import gmail_actions
    outcome = gmail_actions.apply(mid, result)
    if outcome is None: return
    token = authz.current_actor.set(authz.SYSTEM_GMAIL)
    try:
        with store.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            store.append(db, sid, {'action': 'gmail_action', 'id': result.get('id'), 'at': time.time(), **outcome})
    finally: authz.current_actor.reset(token)


async def _process_gmail_message(request, mid, history_id):
    """Claim, fetch and analyze one Gmail message id, with the same bounded
    in-request retry for transient failures used for both freshly-notified ids
    and dead-lettered retries. Returns one of:
      ('stored', result)            -- analyzed and persisted
      ('skipped', None)             -- another call already claimed/processed it
      ('failed_transient', (status, detail))  -- worth retrying later
      ('failed_permanent', (status, detail))  -- can never succeed; do not retry
    On any failure the claim is released so a later attempt isn't wrongly
    rejected as already-claimed."""
    from starlette.concurrency import run_in_threadpool
    from googleapiclient.errors import HttpError
    import gmail_integration
    if not await run_in_threadpool(gmail_integration.claim_processed, mid):
        gmail_push_logger.info('Gmail push message skipped: historyId=%s messageId=%s reason=already_claimed', history_id, mid)
        return 'skipped', None
    gmail_push_logger.info('Gmail push message claimed: historyId=%s messageId=%s', history_id, mid)
    last_status, last_detail, transient = None, None, False
    stored = False
    try:
        for attempt in range(1, _PUSH_MAX_ATTEMPTS + 1):
            try:
                raw = await run_in_threadpool(gmail_integration.fetch_raw, mid)
                gmail_push_logger.info('Gmail push message fetched: historyId=%s messageId=%s bytes=%d', history_id, mid, len(raw))
                result = await run_in_threadpool(execute, request, raw, 'gmail-push', True, False, None, None)
                gmail_push_logger.info(
                    'Gmail push message analyzed: historyId=%s messageId=%s caseId=%s score=%s risk=%s',
                    history_id, mid, result.get('id'), result.get('score'), result.get('risk'))
                stored = True
                try: await run_in_threadpool(_gmail_action, request.state.sid, mid, result)
                except Exception: gmail_push_logger.exception('Gmail action step failed for messageId=%s; ingestion is unaffected', mid)
                return 'stored', result
            except HTTPException as exc:
                # 429 = OUR OWN transient capacity (the shared 2-slot analysis
                # semaphore, or the fixed gmail-push session's per-minute cap);
                # 503 = the store is momentarily at its case/storage ceiling (see
                # execute()). In both the email is fine, so retry then dead-letter.
                # Any other 4xx (malformed/oversized) will never succeed on retry,
                # so it's permanent.
                last_status, last_detail = exc.status_code, exc.detail
                retryable = exc.status_code in (429, 503)
                if retryable and attempt < _PUSH_MAX_ATTEMPTS:
                    gmail_push_logger.info('Gmail push message busy, retrying: historyId=%s messageId=%s attempt=%d status=%s',
                                           history_id, mid, attempt, exc.status_code)
                    await asyncio.sleep(_PUSH_RETRY_DELAY_SECONDS)
                    continue
                transient = retryable
                gmail_push_logger.warning(
                    'Gmail push message failed with HTTPException: historyId=%s messageId=%s status=%s detail=%s',
                    history_id, mid, exc.status_code, exc.detail)
                break
            except HttpError as exc:
                # A transient Gmail-side error (5xx, 429, or a 403 rate-limit) is
                # retryable; a genuinely permanent one (404 deleted, 403 policy/revoked)
                # is not -- see _gmail_httperror_is_transient().
                last_status = getattr(getattr(exc, 'resp', None), 'status', None)
                last_detail = str(exc)
                retryable = _gmail_httperror_is_transient(last_status, exc)
                if retryable and attempt < _PUSH_MAX_ATTEMPTS:
                    gmail_push_logger.info(
                        'Gmail push message hit a transient Gmail API error, retrying: historyId=%s messageId=%s attempt=%d status=%s',
                        history_id, mid, attempt, last_status)
                    await asyncio.sleep(_PUSH_RETRY_DELAY_SECONDS)
                    continue
                transient = retryable
                gmail_push_logger.warning(
                    'Gmail push message failed with Gmail HttpError: historyId=%s messageId=%s status=%s reason=%s',
                    history_id, mid, last_status, exc)
                break
            except Exception as exc:
                # Any OTHER error -- a raw socket/transport timeout, a dropped
                # connection, a momentary sqlite OperationalError (database
                # locked), an out-of-memory blip -- says nothing about THIS
                # email, so it's transient: retry within budget, then dead-letter.
                # This branch is load-bearing. Without it such an error would
                # escape the loop, skip the unclaim in the finally below, leave
                # the id claimed on disk, and lose the email for good -- the exact
                # failure the HTTP paths were already hardened against.
                # asyncio.CancelledError subclasses BaseException, so a genuine
                # shutdown/cancel is NOT swallowed here.
                last_status, last_detail = 503, '%s: %s' % (type(exc).__name__, exc)
                transient = True
                if attempt < _PUSH_MAX_ATTEMPTS:
                    gmail_push_logger.info(
                        'Gmail push message hit a transient error (%s), retrying: historyId=%s messageId=%s attempt=%d',
                        type(exc).__name__, history_id, mid, attempt)
                    await asyncio.sleep(_PUSH_RETRY_DELAY_SECONDS)
                    continue
                gmail_push_logger.warning(
                    'Gmail push message failed with an unexpected error: historyId=%s messageId=%s exc=%s',
                    history_id, mid, exc)
                break
    finally:
        # Release the claim for anything that did NOT actually get stored, so a
        # later attempt (this push's dead-letter pass, a future notification, or
        # the background drain) isn't rejected as "already claimed" for work that
        # never happened. A stored message keeps its claim to prevent duplicates.
        if not stored:
            await run_in_threadpool(gmail_integration.unclaim_processed, mid)
    return ('failed_transient' if transient else 'failed_permanent'), (last_status, last_detail)


async def _retry_dead_letters(request, history_id, skip_ids=frozenset()):
    """Attempt every message id currently in the dead-letter retry queue that we
    haven't just handled: clear the ones that succeed or are permanently
    unprocessable, bump the attempt count on the ones that fail transiently, and
    log any that have exhausted their retry budget. Shared by the Pub/Sub push
    handler and the background drain so their behaviour can't drift. Returns the
    list of freshly-stored result payloads."""
    from starlette.concurrency import run_in_threadpool
    import gmail_integration
    recovered = []
    for mid in await run_in_threadpool(gmail_integration.pending_retry_message_ids):
        if mid in skip_ids:
            continue
        outcome, payload = await _process_gmail_message(request, mid, history_id)
        if outcome == 'stored':
            recovered.append(payload)
            await run_in_threadpool(gmail_integration.clear_failed_message, mid)
            gmail_push_logger.info('Gmail push dead-letter message recovered: messageId=%s caseId=%s', mid, payload.get('id'))
        elif outcome == 'skipped':
            # Another concurrent worker holds the claim and is actively processing
            # this id right now -- it is NOT necessarily stored yet. Do NOT clear
            # it from the retry queue here: the worker that owns the claim is
            # solely responsible for clearing it on success or re-recording it on
            # a transient failure. Clearing it here races that owner and can drop
            # a message the owner then fails to store.
            pass
        elif outcome == 'failed_transient':
            await run_in_threadpool(gmail_integration.record_failed_message, mid)  # bump attempt count
        else:
            await run_in_threadpool(gmail_integration.clear_failed_message, mid)
            gmail_push_logger.warning('Gmail push dead-letter message permanently failed, dropped: messageId=%s status=%s detail=%s', mid, payload[0], payload[1])
    for mid in await run_in_threadpool(gmail_integration.drain_exhausted_retries):
        gmail_push_logger.warning('Gmail push dead-letter message exhausted its retry budget, giving up: messageId=%s', mid)
    return recovered


def _synthetic_push_request(sid):
    """A minimal stand-in request for background dead-letter processing that isn't
    driven by a real HTTP request. execute() only reads request.state.sid; the
    other attributes are set defensively so nothing downstream trips on them."""
    import types
    req = types.SimpleNamespace()
    req.state = types.SimpleNamespace(sid=sid)
    req.method = 'POST'
    req.headers = {}
    req.query_params = {}
    return req


async def _dead_letter_drain_loop():
    """Actively drain the Gmail dead-letter retry queue on a timer so a message
    that failed transiently right before a quiet period isn't stuck unprocessed
    until the next inbound email happens to arrive. A safety net only -- the push
    handler still drains on every notification."""
    from starlette.concurrency import run_in_threadpool
    import gmail_integration
    try:
        interval = max(30, int(os.getenv('GMAIL_RETRY_DRAIN_SECONDS', '300')))
    except (TypeError, ValueError):
        interval = 300
    while True:
        await asyncio.sleep(interval)
        try:
            if not gmail_integration.configured():
                continue
            pending = await run_in_threadpool(gmail_integration.pending_retry_message_ids)
            if not pending:
                continue
            request = _synthetic_push_request(gmail_integration.session_sid())
            recovered = await _retry_dead_letters(request, None)
            if recovered:
                gmail_push_logger.info('Gmail dead-letter background drain recovered %d message(s)', len(recovered))
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            gmail_push_logger.warning('Gmail dead-letter background drain error: %s', exc)


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
    attempted_this_push = set()
    for mid in message_ids:
        attempted_this_push.add(mid)
        outcome, payload = await _process_gmail_message(request, mid, history_id)
        if outcome == 'stored':
            processed.append(payload)
            # If this id had been dead-lettered by an earlier notification and now
            # succeeds via the normal diff, drop its stale retry-queue entry so a
            # later dead-letter pass doesn't waste an attempt re-checking it.
            await run_in_threadpool(gmail_integration.clear_failed_message, mid)
        elif outcome == 'skipped':
            skipped += 1
        else:
            failed += 1
            if outcome == 'failed_transient':
                # Durably queue it so advance_watermark() below doesn't make it
                # unreachable via Gmail's history API -- it gets retried on
                # subsequent notifications until it succeeds or exhausts its budget.
                await run_in_threadpool(gmail_integration.record_failed_message, mid)
                gmail_push_logger.warning(
                    'Gmail push message queued for retry after transient failure: historyId=%s messageId=%s status=%s detail=%s',
                    history_id, mid, payload[0], payload[1])
            else:
                # Permanent (malformed/oversized/deleted/forbidden): retrying can
                # never succeed, so don't queue it; drop any prior queue entry.
                await run_in_threadpool(gmail_integration.clear_failed_message, mid)
                gmail_push_logger.warning(
                    'Gmail push message permanently failed, not retried: historyId=%s messageId=%s status=%s detail=%s',
                    history_id, mid, payload[0], payload[1])
    # Retry messages dead-lettered by EARLIER notifications (transient failures
    # the watermark has since advanced past). Skip any id already handled in this
    # notification's own diff above so it isn't attempted twice in one request.
    processed.extend(await _retry_dead_letters(request, history_id, skip_ids=attempted_this_push))
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
def cases(request: Request, q: str | None = None):
    # q, when given, searches full case content (subject, sender, recipient,
    # findings, indicators) -- not just the lightweight summary fields
    # returned below. See store.search_cases for scope/limits.
    reports = store.search_cases(request.state.sid, q) if q else store.all_cases(request.state.sid)
    return [{k: r[k] for k in ('id', 'subject', 'sender', 'score', 'risk', 'created', 'sample')} for r in reports]


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


@app.get('/api/campaigns/graph')
def campaign_evidence_graph(request: Request):
    import campaigns
    return campaigns.evidence_graph(store.all_cases(request.state.sid))


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


class NoteEntry(BaseModel):
    model_config = ConfigDict(extra='forbid')
    text: str = Field(min_length=1, max_length=2000)


class CaseAssignment(BaseModel):
    model_config = ConfigDict(extra='forbid')
    owner: str = Field(min_length=1, max_length=200)


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
    actor = getattr(request.state, 'actor', None)
    if payload.decision == 'approved' and actor is not None and os.getenv('FOUR_EYES', '1') != '0':
        creator = next((e['event'].get('actor') for e in store.case_events(request.state.sid, cid) if e['event'].get('action') == 'analyze'), None)
        if creator and creator == actor.name:
            raise HTTPException(403, 'Four-eyes rule: the person who analyzed this case cannot approve it. Ask another reviewer (or record a hold).')
    event = {'action': 'review', 'id': cid, 'at': time.time(), **payload.model_dump(),
             'scope': 'Session analyst decision only; no mail delivery, release or external action performed.'}
    with store.connect() as db:
        db.execute('BEGIN IMMEDIATE')
        if not db.execute('SELECT id FROM cases WHERE id=? AND session=?', (cid, request.state.sid)).fetchone():
            raise HTTPException(404, 'Case no longer exists')
        store.append(db, request.state.sid, event)
    return event


@app.get('/api/cases/{cid}/notes')
def list_notes(cid: str, request: Request):
    get_case(cid, request)
    return store.list_notes(request.state.sid, cid)


@app.post('/api/cases/{cid}/notes')
def add_note(cid: str, payload: NoteEntry, request: Request):
    text = payload.text.strip()
    if len(text) < 1: raise HTTPException(400, 'Provide non-empty note text.')
    get_case(cid, request)
    try:
        with store.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            if not db.execute('SELECT id FROM cases WHERE id=? AND session=?', (cid, request.state.sid)).fetchone():
                raise HTTPException(404, 'Case no longer exists')
            event = store.add_note(db, request.state.sid, cid, text)
    except ValueError as exc:
        # A per-case note-count ceiling is transient (the case is fine, notes
        # can be deleted or the analyst can wait) -- 503, not 400, matching
        # execute()'s own capacity-vs-malformed-input distinction.
        raise HTTPException(503, str(exc)) from exc
    return event


@app.get('/api/cases/{cid}/assign')
def get_assignment(cid: str, request: Request):
    get_case(cid, request)
    return store.get_owner(request.state.sid, cid) or {'owner': None}


@app.post('/api/cases/{cid}/assign')
def assign_case(cid: str, payload: CaseAssignment, request: Request):
    owner = payload.owner.strip()
    if len(owner) < 1: raise HTTPException(400, 'Provide a non-empty owner.')
    get_case(cid, request)
    with store.connect() as db:
        db.execute('BEGIN IMMEDIATE')
        if not db.execute('SELECT id FROM cases WHERE id=? AND session=?', (cid, request.state.sid)).fetchone():
            raise HTTPException(404, 'Case no longer exists')
        event = store.set_owner(db, request.state.sid, cid, owner)
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
    # DPDP-conscious export masking: reduce exposure of Indian statutory identifiers
    # (Aadhaar/PAN/UPI/mobile) in every derivative export. The tamper-evident store
    # keeps the original bytes, so custody is preserved. Best-effort, not certified DLP.
    import pii
    mask_emails = request.query_params.get('mask_emails', '0') == '1'
    summary = pii.summarize(result, emails=mask_emails)
    result = pii.sanitize_report(result, emails=mask_emails)
    result['masking_summary'] = summary
    result['export_schema'] = 1
    if fmt == 'json': body, mime = json.dumps(result, indent=2, ensure_ascii=True).encode(), 'application/json'
    elif fmt == 'stix':
        import stix_export
        created = datetime.datetime.fromtimestamp(float(result.get('created') or time.time()), datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.000Z')
        body, mime = json.dumps(stix_export.build(result, cid, created), indent=2, ensure_ascii=True).encode(), 'application/json'
    elif fmt == 'evidence':
        import evidence_pack
        body = evidence_pack.build(result, cid, store.case_events(request.state.sid, cid), store.verify(request.state.sid), mask_emails).encode('utf-8')
        mime = 'text/markdown; charset=utf-8'
    elif fmt == 'cef': body, mime = siem.cef(result).encode(), 'text/plain'
    elif fmt == 'csv':
        stream = io.StringIO(newline='')
        writer = csv.writer(stream)
        def cell(value):
            value = '' if value is None else str(value)
            # Neutralise spreadsheet formula injection (a leading = + - @ or tab/CR runs as a formula).
            return "'" + value if value.lstrip().startswith(('=', '+', '-', '@', '\t', '\r')) else value
        writer.writerow(['section', 'type', 'value', 'detail'])
        for item in result.get('indicators', []):
            writer.writerow(['indicators', cell(item.get('type')), cell(item.get('value')), ''])
        for item in result.get('findings', []):
            writer.writerow(['findings', cell(item.get('group')), cell(item.get('title')), cell(f"{item.get('detail', '')} (points: {item.get('points', 0)})")])
        for item in result.get('urls', []):
            writer.writerow(['urls', cell(item.get('protocol')), cell(item.get('url')), cell(f"score {item.get('score', 0)}: " + '; '.join(item.get('reasons', [])))])
        for name, value in (result.get('authentication') or {}).items():
            if isinstance(value, dict): writer.writerow(['authentication', cell(name), cell(value.get('status')), cell(value.get('detail') or value.get('published_policy') or '')])
        for item in result.get('attachments', []):
            writer.writerow(['attachments', cell(item.get('type')), cell(item.get('name')), cell(f"sha256 {item.get('sha256', '')}, {item.get('size', 0)} bytes" + (', active-content extension' if item.get('warning') else ''))])
        body, mime = stream.getvalue().encode('utf-8-sig'), 'text/csv'
    elif fmt == 'pdf':
        from fpdf import FPDF
        pdf = FPDF()
        # Regression: the core 'Helvetica' PDF font only supports Latin-1, so
        # every non-Latin-1 character (Hindi/Devanagari script, most emoji,
        # many other scripts) was forced through .encode('latin-1','replace')
        # and silently became a literal '?' -- indistinguishable from real
        # content, in a FORENSIC report. Noto Sans (broad Latin/Cyrillic/
        # Greek coverage) plus Noto Sans Devanagari (Hindi and related
        # scripts) are bundled under backend/fonts/ (SIL Open Font License,
        # OFL.txt alongside them) and used with fallback + real text shaping
        # instead. Honest scope: this closes the Hindi/Devanagari and
        # Latin-extended cases specifically; a script neither font covers
        # (e.g. CJK, Arabic, color emoji) renders as an empty/placeholder
        # glyph, not a crash and not a misleading '?'.
        FONT_DIR = Path(__file__).parent / 'fonts'
        pdf.add_font('NotoSans', '', str(FONT_DIR / 'NotoSans.ttf'))
        pdf.add_font('NotoSansDevanagari', '', str(FONT_DIR / 'NotoSansDevanagari.ttf'))
        pdf.set_fallback_fonts(['NotoSansDevanagari'])
        pdf.set_text_shaping(True)
        pdf.set_auto_page_break(auto=True, margin=18)
        pdf.add_page()
        def line(text, size=10):
            pdf.set_font('NotoSans', size=size)
            pdf.multi_cell(0, 6, str(text), new_x='LMARGIN', new_y='NEXT')
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
            for check in result['assessment']['checks']:
                line(f"[{check.get('id', '?')}] " + check['title'] + ': ' + check['detail'])
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
        for finding in result['findings']: line(f"[{finding.get('id', '?')}] {finding['title']}: {finding['detail']}")
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
    else: raise HTTPException(400, 'Choose json, csv, pdf, cef, stix or evidence')
    extension = {'stix': 'stix.json', 'evidence': 'evidence.md'}.get(fmt, fmt)
    return Response(body, media_type=mime, headers={'Content-Disposition': f'attachment; filename="case-{cid}.{extension}"'})


gateway_state = {'controller': None, 'port': None}


def _maildrop():
    import gateway
    return gateway.Maildrop(Path(store.DATA) / 'maildrop')


def _gateway_analyze(raw, envelope):
    """Bridge from the SMTP gateway to the normal analysis pipeline (fixed gateway session, system actor)."""
    import types, gateway
    request = types.SimpleNamespace(state=types.SimpleNamespace(sid=store.gateway_session(), actor=None))
    token = authz.current_actor.set(authz.SYSTEM_GATEWAY)
    try:
        return execute(request, raw, 'gateway', False)
    except HTTPException as exc:
        if exc.status_code == 429: raise gateway.GatewayTransient() from exc
        raise
    finally: authz.current_actor.reset(token)


def _gateway_event(action, item_id, result):
    token = authz.current_actor.set(authz.SYSTEM_GATEWAY)
    try:
        sid = store.gateway_session()      # resolved BEFORE the write transaction: it takes its own write lock
        with store.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            store.append(db, sid, {'action': 'gateway_' + action, 'id': result.get('id'), 'item': item_id, 'at': time.time()})
    except Exception:
        logging.exception('Gateway audit event failed; the message decision is unaffected')
    finally: authz.current_actor.reset(token)


def start_gateway(port, host='127.0.0.1'):
    import gateway
    if gateway_state['controller'] is not None: return gateway_state['port']
    handler = gateway.GatewayHandler(_gateway_analyze, _maildrop(), _gateway_event)
    gateway_state['controller'] = gateway.start(handler, host, port)
    gateway_state['port'] = gateway_state['controller'].server.sockets[0].getsockname()[1]
    return gateway_state['port']


def stop_gateway():
    controller, gateway_state['controller'], gateway_state['port'] = gateway_state['controller'], None, None
    if controller is not None:
        try: controller.stop()
        except Exception: logging.exception('Gateway did not stop cleanly')


def _quarantine_actor(request):
    actor = getattr(request.state, 'actor', None)
    return actor.name if actor else 'analyst (open mode)'


@app.get('/api/quarantine')
def quarantine_list():
    import gateway
    drop = _maildrop()
    return {'held': drop.list_held(), 'inbox_count': len(list(drop.inbox.glob('*.eml'))),
            'gateway': {'listening': gateway_state['controller'] is not None, 'port': gateway_state['port'], 'hold_score': gateway.hold_score()},
            'note': 'Held messages were stopped before reaching any mailbox. Releasing or discarding is a logged decision.'}


@app.get('/api/quarantine/{qid}')
def quarantine_detail(qid: str):
    drop = _maildrop()
    try: meta = drop.load_meta(qid)
    except ValueError: raise HTTPException(400, 'Invalid message id')
    if not meta: raise HTTPException(404, 'Held message not found')
    case = store.get(store.gateway_session(), meta['case_id']) if meta.get('case_id') else None
    return {'meta': meta, 'case': case}


@app.get('/api/gateway/inbox')
def gateway_inbox():
    return {'messages': _maildrop().list_inbox()}


def _close_quarantine(qid, request, action):
    drop = _maildrop()
    who = _quarantine_actor(request)
    try: meta = drop.release(qid, who) if action == 'release' else drop.discard(qid, who)
    except ValueError: raise HTTPException(400, 'Invalid message id')
    if not meta: raise HTTPException(404, 'No held message with that id (it may already be released or discarded).')
    sid = store.gateway_session()
    with store.connect() as db:
        db.execute('BEGIN IMMEDIATE')
        store.append(db, sid, {'action': 'quarantine_' + action, 'id': meta.get('case_id'), 'item': qid, 'at': time.time(), 'by': who})
    return meta


@app.post('/api/quarantine/{qid}/release')
def quarantine_release(qid: str, request: Request): return _close_quarantine(qid, request, 'release')


@app.post('/api/quarantine/{qid}/discard')
def quarantine_discard(qid: str, request: Request): return _close_quarantine(qid, request, 'discard')


class LandingInspect(BaseModel):
    model_config = ConfigDict(extra='forbid')
    url: str = Field(min_length=8, max_length=2048)
    confirm: bool = Field(strict=True)


landing_hits = defaultdict(deque)


@app.post('/api/cases/{cid}/urls/inspect')
def inspect_landing_page(cid: str, payload: LandingInspect, request: Request):
    """Analyst-triggered static inspection of ONE link that appears in this case (see landing_page.py for the safety model)."""
    if os.getenv('LANDING_INSPECT_ENABLED', '1') == '0': raise HTTPException(403, 'Landing-page inspection is disabled on this server.')
    if not payload.confirm: raise HTTPException(400, "Confirm that the destination will see this server's IP address.")
    case = get_case(cid, request)
    if payload.url not in {u.get('url') for u in case.get('urls', [])}: raise HTTPException(400, "That URL is not one of this case's links.")
    sid, now = request.state.sid, time.time()
    with rate_lock:
        hits = landing_hits[sid]
        while hits and hits[0] < now - 60: hits.popleft()
        if len(hits) >= 6: raise HTTPException(429, 'Limit: 6 landing-page inspections per minute.')
        hits.append(now)
    if not slots.acquire(blocking=False): raise HTTPException(429, 'Analysis workers busy. Please retry shortly.')
    try:
        import landing_page
        result = landing_page.inspect(payload.url)
        with store.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            store.append(db, sid, {'action': 'landing_inspect', 'id': cid, 'url': payload.url[:500], 'status': result.get('status'),
                                   'final_url': str(result.get('final_url') or '')[:500], 'at': time.time()})
        return result
    finally: slots.release()


DIST = Path(__file__).resolve().parents[1] / 'frontend' / 'dist'
if DIST.exists(): app.mount('/', StaticFiles(directory=DIST, html=True), name='frontend')

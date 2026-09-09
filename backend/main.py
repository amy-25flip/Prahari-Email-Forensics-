import csv
import io
import json
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
from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress, ValidationError, field_validator
from samples import SAMPLES


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


@app.middleware('http')
async def boundary(request: Request, call_next):
    if request.method in ('POST', 'DELETE') and request.headers.get('x-requested-with') != 'Email-Threat-Detection':
        return JSONResponse({'detail': 'Missing application request header'}, status_code=403)
    if request.method == 'POST':
        chunks, size = [], 0
        async for chunk in request.stream():
            size += len(chunk)
            if size > 1500000: return JSONResponse({'detail': 'Upload exceeds email size limit'}, status_code=413)
            chunks.append(chunk)
        request._body = b''.join(chunks)
    if request.url.path in ('/api/health', '/api/ready') or not request.url.path.startswith('/api/'):
        return await call_next(request)
    try:
        sid, cookie = store.session(request.cookies.get('efp_session'))
    except ValueError:
        return JSONResponse({'detail': 'Server capacity reached. Please retry later.'}, status_code=503)
    request.state.sid = sid
    response = await call_next(request)
    if cookie: response.set_cookie('efp_session', cookie, httponly=True, samesite='strict', secure=os.getenv('COOKIE_SECURE') == '1', max_age=86400)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['X-Frame-Options'] = 'DENY'
    if request.url.path.startswith('/api'): response.headers['Cache-Control'] = 'no-store'
    return response


@app.get('/api/health')
def health():
    return {'status': 'ready', 'model': local_model.status, 'model_detail': local_model.detail, 'retention_hours': 24, 'reputation': reputation.status()}


@app.get('/api/ready')
def ready():
    return JSONResponse({'ready': local_model.status == 'ready', 'model': local_model.status}, status_code=200 if local_model.status == 'ready' else 503)


@app.get('/api/samples')
def samples(): return SAMPLES


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


def execute(request, raw, source, live, sample=False, context=None):
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
    return await run_in_threadpool(execute, request, content, source, live, False, context)


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


@app.delete('/api/cases/{cid}')
def delete_case(cid: str, request: Request):
    if not store.delete(request.state.sid, cid): raise HTTPException(404, 'Case not found')
    return {'deleted': True}


@app.get('/api/connections')
def connections(request: Request): return store.connections(request.state.sid)


@app.get('/api/verify')
def verify(request: Request): return store.verify(request.state.sid)


@app.get('/api/cases/{cid}/export/{fmt}')
def export(cid: str, fmt: str, request: Request):
    result = get_case(cid, request)
    if fmt == 'json': body, mime = json.dumps(result, indent=2, ensure_ascii=True).encode(), 'application/json'
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
        line('Email Forensic Report', 12)
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
        for finding in result['findings']: line(f"{finding['title']}: {finding['detail']}")
        if result.get('conflicts'): line('EVIDENCE CONFLICTS', 13)
        for conflict in result.get('conflicts', []):
            line('EVIDENCE CONFLICT: ' + conflict['title'], 12)
            line(conflict['explanation'])
            line('Evidence: ' + ', '.join(conflict['evidence_refs']))
            line('Next verification: ' + conflict['action'])
            line(conflict['assessment'])
        line('AUTHENTICATION RESULTS', 13)
        for key, value in result['authentication'].items(): line(f"{key.upper()}: {value['status']} - {value['detail']}")
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
    else: raise HTTPException(400, 'Choose json, csv or pdf')
    return Response(body, media_type=mime, headers={'Content-Disposition': f'attachment; filename="case-{cid}.{fmt}"'})


DIST = Path(__file__).resolve().parents[1] / 'frontend' / 'dist'
if DIST.exists(): app.mount('/', StaticFiles(directory=DIST, html=True), name='frontend')

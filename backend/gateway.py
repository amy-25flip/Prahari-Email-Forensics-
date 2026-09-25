"""Pre-delivery mail gateway: analyse a message BEFORE it reaches a mailbox, then deliver or hold it.

An SMTP endpoint (aiosmtpd) that accepts mail from an upstream MTA (Postfix `content_filter`/`relay` hop, a mail proxy, or any
SMTP client), runs the same analysis pipeline as every other entry point, and files the message in a local maildrop:
  inbox/       delivered messages, with X-PRAHARI-* headers added (the analysed original is retained in the evidence store)
  quarantine/  held messages - byte-identical to what was received - plus a JSON sidecar; released or discarded by an analyst.
Policy: urgent triage, or a score at/above GATEWAY_HOLD_SCORE (default 60), is held. If the analysis raises an exception the message
is HELD rather than delivered unscanned. Transient capacity limits and storage failures (e.g. disk full) are answered with SMTP 451, so
nothing is delivered and the sending MTA retries. A process crash mid-message is not covered: the sender sees a dropped connection.
This is a locally testable gateway model, NOT a Gmail integration: a mail provider's own inbox cannot be intercepted this way."""
import asyncio
import json
import os
import re
import secrets
import threading
import time
from email import policy
from email.parser import BytesParser
from pathlib import Path

from aiosmtpd.controller import Controller

MAX_MESSAGE_BYTES = 1_048_576
ID_PATTERN = re.compile(r'^\d{10,14}-[a-f0-9]{16}$')
HEADER_PREFIX = b'X-PRAHARI'
_decision_lock = threading.Lock()      # release/discard are check-then-act on files: serialise them


def hold_score():
    try:
        return max(0, min(100, int(os.getenv('GATEWAY_HOLD_SCORE', '60'))))
    except ValueError:
        return 60


def decide(result):
    """('hold'|'deliver', [reasons]) from an analysis result."""
    reasons = []
    triage = (result.get('triage') or {}).get('priority')
    score = int(result.get('score', 0) or 0)
    if triage == 'urgent':
        reasons.append('Urgent review priority: ' + '; '.join((result.get('triage') or {}).get('reasons', []))[:300])
    if score >= hold_score():
        reasons.append(f'Evidence score {score} is at or above the hold threshold ({hold_score()}).')
    return ('hold' if reasons else 'deliver'), reasons


def _safe_header_value(text):
    return re.sub(r'[\r\n\x00]+', ' ', str(text))[:200]


class Maildrop:
    def __init__(self, root):
        self.root = Path(root)
        self.inbox, self.quarantine = self.root / 'inbox', self.root / 'quarantine'
        for directory in (self.inbox, self.quarantine):
            directory.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def new_id():
        return f'{int(time.time()):010d}-{secrets.token_hex(8)}'

    def _path(self, directory, item_id, suffix):
        if not isinstance(item_id, str) or not ID_PATTERN.fullmatch(item_id):
            raise ValueError('Invalid message id.')
        return directory / f'{item_id}{suffix}'

    def deliver(self, item_id, raw, result):
        headers = (b'X-PRAHARI-Triage: ' + _safe_header_value((result.get('triage') or {}).get('priority', 'unknown')).encode() + b'\r\n'
                   b'X-PRAHARI-Score: ' + str(int(result.get('score', 0) or 0)).encode() + b'\r\n'
                   b'X-PRAHARI-Case: ' + _safe_header_value(result.get('id', '')).encode() + b'\r\n')
        self._path(self.inbox, item_id, '.eml').write_bytes(headers + raw)

    def hold(self, item_id, raw, meta):
        self._path(self.quarantine, item_id, '.eml').write_bytes(raw)
        self._path(self.quarantine, item_id, '.json').write_text(json.dumps(meta, indent=2), encoding='utf-8')

    def load_meta(self, item_id):
        path = self._path(self.quarantine, item_id, '.json')
        return json.loads(path.read_text(encoding='utf-8')) if path.exists() else None

    def save_meta(self, item_id, meta):
        self._path(self.quarantine, item_id, '.json').write_text(json.dumps(meta, indent=2), encoding='utf-8')

    def list_held(self, include_closed=False):
        out = []
        for path in sorted(self.quarantine.glob('*.json'), reverse=True)[:200]:
            try:
                meta = json.loads(path.read_text(encoding='utf-8'))
            except (OSError, ValueError):
                continue
            if include_closed or meta.get('status') == 'held':
                out.append(meta)
        return out

    def release(self, item_id, released_by):
        with _decision_lock:
            meta = self.load_meta(item_id)
            if not meta or meta.get('status') != 'held':
                return None
            eml = self._path(self.quarantine, item_id, '.eml')
            raw = eml.read_bytes()
            self._path(self.inbox, item_id, '.eml').write_bytes(
                b'X-PRAHARI-Triage: released-from-quarantine\r\nX-PRAHARI-Released-By: ' + _safe_header_value(released_by).encode() + b'\r\n' + raw)
            eml.unlink()
            meta.update(status='released', closed_at=time.time(), closed_by=released_by)
            self.save_meta(item_id, meta)
            return meta

    def discard(self, item_id, discarded_by):
        with _decision_lock:
            meta = self.load_meta(item_id)
            if not meta or meta.get('status') != 'held':
                return None
            self._path(self.quarantine, item_id, '.eml').unlink(missing_ok=True)
            meta.update(status='discarded', closed_at=time.time(), closed_by=discarded_by)
            self.save_meta(item_id, meta)
            return meta

    def list_inbox(self, limit=50):
        rows = []
        for path in sorted(self.inbox.glob('*.eml'), reverse=True)[:limit]:
            try:
                msg = BytesParser(policy=policy.default).parsebytes(path.read_bytes(), headersonly=True)
                rows.append({'id': path.stem, 'subject': str(msg.get('Subject') or '')[:200], 'from': str(msg.get('From') or '')[:200],
                             'triage': str(msg.get('X-PRAHARI-Triage') or ''), 'score': str(msg.get('X-PRAHARI-Score') or ''), 'released_by': str(msg.get('X-PRAHARI-Released-By') or '')})
            except (OSError, ValueError):
                continue
        return rows


class GatewayTransient(Exception):
    """Our own capacity limit - ask the sender to retry (SMTP 451)."""


class GatewayHandler:
    def __init__(self, analyze, maildrop, on_event=None):
        self.analyze, self.maildrop, self.on_event = analyze, maildrop, on_event

    def process(self, raw, mail_from, rcpt_tos, peer, helo=''):
        """Synchronous core (also used directly by tests). Returns ('deliver'|'hold', item_id)."""
        item_id = self.maildrop.new_id()
        try:
            result = self.analyze(raw, {'mail_from': mail_from, 'rcpt_tos': list(rcpt_tos), 'peer': peer, 'helo': helo})
            action, reasons = decide(result)
        except GatewayTransient:
            raise
        except Exception as exc:                       # analysis raised: hold for manual review instead of delivering unscanned mail
            result, action, reasons = {}, 'hold', [f'Analysis failed ({type(exc).__name__}); held for manual review.']
        if action == 'deliver':
            self.maildrop.deliver(item_id, raw, result)
        else:
            subject = ''
            try:
                subject = str(BytesParser(policy=policy.default).parsebytes(raw, headersonly=True).get('Subject') or '')[:200]
            except Exception:
                pass
            self.maildrop.hold(item_id, raw, {
                'id': item_id, 'status': 'held', 'held_at': time.time(), 'mail_from': str(mail_from)[:300], 'rcpt_tos': [str(r)[:300] for r in rcpt_tos][:20],
                'subject': subject, 'score': int(result.get('score', 0) or 0), 'triage': (result.get('triage') or {}).get('priority', 'unknown'),
                'reasons': reasons, 'case_id': result.get('id'), 'findings': [f.get('title') for f in result.get('findings', [])][:8], 'peer': str(peer)[:64]})
        if self.on_event:
            self.on_event(action, item_id, result)
        return action, item_id

    async def handle_DATA(self, server, session, envelope):
        raw = envelope.original_content or envelope.content or b''
        peer = (session.peer or ('unknown',))[0]
        try:
            action, _ = await asyncio.get_running_loop().run_in_executor(None, self.process, raw, envelope.mail_from, envelope.rcpt_tos, peer, str(getattr(session, 'host_name', '') or ''))
        except GatewayTransient:
            return '451 4.7.1 Analysis capacity reached, please retry shortly'
        except Exception:                       # e.g. disk full while filing the message: never deliver, never bounce - ask the sender to retry
            return '451 4.3.0 Temporary storage failure, please retry later'
        return '250 OK message accepted' if action == 'deliver' else '250 OK message accepted and held for review'


def start(handler, host='127.0.0.1', port=2525):
    controller = Controller(handler, hostname=host, port=port, data_size_limit=MAX_MESSAGE_BYTES)
    controller.start()
    return controller

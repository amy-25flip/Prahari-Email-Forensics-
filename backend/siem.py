"""Explicit, minimal-data SIEM delivery to administrator-configured targets."""
import hashlib
import json
import os
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit
import requests

lock = threading.Lock()


def config():
    mode = os.getenv('SIEM_MODE', 'disabled')
    if mode == 'splunk':
        url, token = os.getenv('SPLUNK_HEC_URL', ''), os.getenv('SPLUNK_HEC_TOKEN', '')
        parts = urlsplit(url)
        if (parts.scheme != 'https' or not parts.hostname or parts.username or parts.password
                or parts.query or parts.fragment or parts.path.rstrip('/') != '/services/collector/event'
                or not token or any(c.isspace() for c in token)):
            raise ValueError('Invalid administrator Splunk configuration')
        return mode, url, token
    if mode == 'wazuh':
        path = Path(os.getenv('WAZUH_LOG_PATH', ''))
        if not path.is_absolute(): raise ValueError('Wazuh log requires an absolute administrator-configured path')
        return mode, path, None
    if mode != 'disabled': raise ValueError('Unsupported SIEM mode')
    return mode, None, None


def status():
    try:
        mode, _, _ = config()
        return {'mode': mode, 'enabled': mode != 'disabled', 'detail': 'Only case metadata and finding names are sent; no email body, addresses or URLs.'}
    except ValueError:
        return {'mode': 'misconfigured', 'enabled': False, 'detail': 'Administrator SIEM configuration needs correction.'}


def event(report):
    return {'integration': 'email_threat_detection', 'schema_version': 1,
            'event_id': hashlib.sha256(('efp-siem-v1:' + report['id']).encode()).hexdigest(),
            'case_id': report['id'], 'email_sha256': report['sha256'], 'observed_at': report['created'],
            'score': report['score'], 'risk': report['risk'], 'sample': report.get('sample', False),
            'review_priority': report.get('triage', {}).get('priority', 'unknown'),
            'authentication': {k: v['status'] for k, v in report['authentication'].items()},
            'findings': [f['title'] for f in report['findings']][:100]}


def cef(report):
    value = event(report)
    def escape(text):
        return str(text).replace('\\', '\\\\').replace('=', '\\=').replace('\r', '\\r').replace('\n', '\\n')
    severity = 8 if value['review_priority'] == 'urgent' else 5 if value['score'] >= 25 else 2
    fields = {'externalId': value['event_id'], 'cs1Label': 'CaseId', 'cs1': value['case_id'],
              'cs2Label': 'EmailSHA256', 'cs2': value['email_sha256'], 'cn1Label': 'EvidenceScore', 'cn1': value['score'],
              'cs3Label': 'ReviewPriority', 'cs3': value['review_priority']}
    return f'CEF:0|EFP|Email Threat Detection|1|email-analysis|Email analysis|{severity}|' + ' '.join(f'{k}={escape(v)}' for k, v in fields.items())


def deliver(report):
    mode, target, token = config()
    if mode == 'disabled': raise ValueError('SIEM delivery is not configured')
    payload = event(report)
    receipt = {'event_id': payload['event_id'], 'mode': mode, 'at': time.time()}
    if mode == 'wazuh':
        try:
            with lock:
                if target.exists() and target.stat().st_size >= 10 * 1024 * 1024:
                    return {**receipt, 'status': 'failed', 'detail': 'Local SIEM log capacity reached; administrator rotation required.'}
                with target.open('a', encoding='utf-8', newline='\n') as stream:
                    stream.write(json.dumps(payload, ensure_ascii=True, separators=(',', ':')) + '\n')
                    stream.flush()
                    os.fsync(stream.fileno())
            return {**receipt, 'status': 'written', 'detail': 'Written to the local Wazuh input log. Agent collection and server ingestion are not confirmed.'}
        except OSError:
            return {**receipt, 'status': 'failed', 'detail': 'Could not write the configured Wazuh input log.'}
    # TLS verification is on by default (True) for any real deployment. The one opt-in
    # escape hatch is SPLUNK_HEC_INSECURE_SKIP_VERIFY=1, meant only for local testing
    # against a self-signed dev Splunk instance (e.g. the bundled default cert that
    # ships with a fresh `splunk/splunk` install) -- never set this against a real
    # collector, since it removes protection against a credential-stealing MITM.
    verify = os.getenv('SPLUNK_HEC_INSECURE_SKIP_VERIFY') != '1'
    try:
        # Redirects must never forward the collector credential to another endpoint.
        with requests.post(target, headers={'Authorization': 'Splunk ' + token},
                           json={'time': payload['observed_at'], 'source': 'email-threat-detection',
                                 'sourcetype': '_json', 'event': payload}, timeout=(3, 7),
                           allow_redirects=False, stream=True, verify=verify) as response:
            if response.status_code != 200:
                return {**receipt, 'status': 'failed', 'detail': f'Collector returned HTTP {response.status_code}; no success confirmed.'}
            chunks, size = [], 0
            for chunk in response.iter_content(4096):
                size += len(chunk)
                if size > 16384: raise ValueError('Oversized collector response')
                chunks.append(chunk)
            result = json.loads(b''.join(chunks))
            if isinstance(result, dict) and type(result.get('code')) is int and result['code'] == 0:
                return {**receipt, 'status': 'accepted', 'detail': 'Splunk HEC accepted the event. Indexing is not independently confirmed.'}
            return {**receipt, 'status': 'failed', 'detail': 'Collector did not acknowledge success.'}
    except (requests.RequestException, ValueError):
        return {**receipt, 'status': 'unknown', 'detail': 'No reliable collector acknowledgment. A retry may duplicate the same event ID.'}

import json
import re

import playbook
import stix_export
from test_selection import client

H = {'X-Requested-With': 'Email-Threat-Detection'}
UUID = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'


def _case(client, sample='account'):
    return client.post(f'/api/samples/{sample}', headers=H).json()


# ---------- playbook ----------
def test_playbook_is_evidence_driven_and_never_empty():
    quiet = playbook.build({'triage': {'priority': 'routine'}, 'findings': [], 'urls': [], 'attachments': [], 'authentication': {}})
    assert [s['priority'] for s in quiet['steps']] == ['record'] and 'not a safety guarantee' in quiet['steps'][0]['action']
    urgent = playbook.build({'triage': {'priority': 'urgent'}, 'findings': [{'title': 'Payment diversion'}],
                             'urls': [{'url': 'http://bad.tk/x', 'score': 60}], 'attachments': [{'name': 'a.exe', 'warning': True}],
                             'authentication': {'dmarc': {'status': 'fail'}}})
    text = ' '.join(s['action'] for s in urgent['steps'])
    assert 'out-of-band' in text and 'Block' in text and 'Quarantine' in text and 'unverified' in text
    assert '1930' in text and 'CERT-In' in text
    assert {s['priority'] for s in urgent['steps']} >= {'now', 'next', 'record'}


def test_playbook_omits_steps_without_supporting_evidence():
    steps = playbook.build({'triage': {'priority': 'review'}, 'findings': [], 'urls': [], 'attachments': [], 'authentication': {}})['steps']
    text = ' '.join(s['action'] for s in steps)
    assert 'out-of-band' not in text and 'Block' not in text and '1930' not in text
    assert 'Preserve evidence' in text


def test_analysis_result_carries_a_playbook(client):
    result = _case(client)
    steps = result['assessment']['playbook']['steps']
    assert steps and all({'priority', 'action', 'why'} <= set(s) for s in steps)


# ---------- STIX ----------
def _valid_bundle_shape(bundle):
    assert bundle['type'] == 'bundle' and re.fullmatch('bundle--' + UUID, bundle['id'])
    assert 'spec_version' not in bundle
    ids = {o['id'] for o in bundle['objects']}
    assert len(ids) == len(bundle['objects'])
    for obj in bundle['objects']:
        assert re.fullmatch(obj['type'] + '--' + UUID, obj['id']), obj['id']
        assert obj['spec_version'] == '2.1'
        assert obj['created'].endswith('Z')
        if obj['type'] != 'marking-definition': assert obj['modified'] >= obj['created']
        for ref in obj.get('object_marking_refs', []) + obj.get('object_refs', []) + ([obj['created_by_ref']] if 'created_by_ref' in obj else []):
            assert ref in ids, ref
        if obj['type'] == 'indicator':
            assert obj['pattern_type'] == 'stix' and obj['pattern'].startswith('[') and obj['pattern'].endswith(']') and obj['valid_from']
    assert any(o['type'] == 'report' and o['object_refs'] for o in bundle['objects'])


def test_stix_bundle_for_a_phishing_case_is_well_formed_and_conservative(client):
    cid = _case(client)['id']
    response = client.get(f'/api/cases/{cid}/export/stix')
    assert response.status_code == 200 and 'case-' + cid + '.stix.json' in response.headers['content-disposition']
    bundle = response.json()
    _valid_bundle_shape(bundle)
    indicators = [o for o in bundle['objects'] if o['type'] == 'indicator']
    patterns = ' '.join(o['pattern'] for o in indicators)
    assert 'college-login.example' in patterns            # the flagged link
    assert 'https://college.example' not in patterns      # the benign link is NOT exported as an indicator
    assert all('requires analyst confirmation' in o['description'] for o in indicators)
    assert all(stix_export.TLP_AMBER_ID in o['object_marking_refs'] for o in indicators)
    text = json.dumps(bundle)
    assert 'subject' not in text.lower() or 'PRAHARI case' in text


def test_stix_exports_no_indicators_for_a_routine_case_and_ids_are_deterministic(client):
    cid = _case(client, 'newsletter')['id']
    bundle = client.get(f'/api/cases/{cid}/export/stix').json()
    _valid_bundle_shape(bundle)
    assert not [o for o in bundle['objects'] if o['type'] == 'indicator']
    a = stix_export.build({'triage': {'priority': 'urgent'}, 'score': 80, 'urls': [{'url': 'http://x.tk/a', 'score': 70}]}, 'c1', '2026-01-01T00:00:00.000Z')
    b = stix_export.build({'triage': {'priority': 'urgent'}, 'score': 80, 'urls': [{'url': 'http://x.tk/a', 'score': 70}]}, 'c1', '2026-01-01T00:00:00.000Z')
    assert a == b


def test_stix_pattern_quoting_survives_hostile_values():
    hostile = "http://x.tk/a'b\\c]; [url:value = 'evil"
    bundle = stix_export.build({'triage': {'priority': 'urgent'}, 'score': 90, 'urls': [{'url': hostile, 'score': 90}]}, 'c2', '2026-01-01T00:00:00.000Z')
    pattern = next(o['pattern'] for o in bundle['objects'] if o['type'] == 'indicator')
    assert pattern.count('[') == 2 and "\\'" in pattern     # quote escaped; the hostile ']' stays inside the literal
    assert pattern.startswith("[url:value = '") and pattern.endswith("']")


# ---------- evidence pack ----------
def test_evidence_pack_contains_hashes_custody_trail_and_a_draft_declaration(client):
    cid = _case(client)['id']
    client.post(f'/api/cases/{cid}/notes', json={'text': 'Checked with sender by phone; call 9876543210'}, headers=H)
    response = client.get(f'/api/cases/{cid}/export/evidence')
    assert response.status_code == 200 and response.headers['content-type'].startswith('text/markdown')
    assert f'case-{cid}.evidence.md' in response.headers['content-disposition']
    text = response.text
    case = client.get(f'/api/cases/{cid}').json()
    assert case['sha256'] in text                                   # original-message hash
    assert 'Analyzed (original bytes and report hashed)' in text and 'Analyst note added' in text
    assert 'valid' in text and 'DRAFT' in text and 'Not a certificate' in text
    assert 'does not' in text.lower() or 'not establish' in text.lower()
    assert '9876543210' not in text and '[PHONE REDACTED]' in text  # masking applies to notes
    assert 'infrastructure, **not** the person' in text


def test_evidence_pack_reports_a_broken_chain_honestly(client, monkeypatch):
    import store
    cid = _case(client)['id']
    monkeypatch.setattr(store, 'verify', lambda sid: {'valid': False, 'detail': 'Audit chain mismatch', 'checked': 1})
    assert 'NOT VALID - Audit chain mismatch' in client.get(f'/api/cases/{cid}/export/evidence').text


def test_unknown_export_format_lists_the_new_options(client):
    cid = _case(client)['id']
    response = client.get(f'/api/cases/{cid}/export/nope')
    assert response.status_code == 400 and 'stix' in response.json()['detail'] and 'evidence' in response.json()['detail']

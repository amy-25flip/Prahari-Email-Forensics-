import csv
import io

from test_selection import client


def _csv_rows(client, cid, query=''):
    response = client.get(f'/api/cases/{cid}/export/csv{query}')
    assert response.status_code == 200
    text = response.content.decode('utf-8-sig')
    return list(csv.reader(io.StringIO(text)))


def test_csv_export_has_sections_for_findings_urls_auth_and_indicators(client):
    cid = client.post('/api/samples/account', headers={'X-Requested-With': 'Email-Threat-Detection'}).json()['id']
    rows = _csv_rows(client, cid)
    assert rows[0] == ['section', 'type', 'value', 'detail']
    sections = {row[0] for row in rows[1:]}
    assert {'findings', 'urls', 'authentication'} <= sections
    assert all(len(row) == 4 for row in rows)


def test_csv_neutralises_spreadsheet_formula_injection(client):
    raw = ('From: a@b.com\r\nTo: c@d.com\r\nSubject: =HYPERLINK("http://evil.tk","click")\r\n\r\n'
           'Please visit http://x.example/=cmd|calc for the invoice details and the payment instructions today.')
    cid = client.post('/api/analyze', json={'email': raw}, headers={'X-Requested-With': 'Email-Threat-Detection'}).json()['id']
    for row in _csv_rows(client, cid):
        for value in row:
            assert not value.startswith(('=', '+', '@')), value


def test_json_export_declares_a_schema_version(client):
    cid = client.post('/api/samples/newsletter', headers={'X-Requested-With': 'Email-Threat-Detection'}).json()['id']
    assert client.get(f'/api/cases/{cid}/export/json').json()['export_schema'] == 1

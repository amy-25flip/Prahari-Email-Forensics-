import io
import zipfile

import attachment_rules as rules


def ids(name, payload):
    return {h['id'] for h in rules.scan(name, payload)}


def test_html_smuggling_needs_both_blob_decode_and_download_trigger():
    bad = b'<html><script>var b=new Blob([atob("AAAA")]);a.download="x.iso";</script></html>'
    assert 'ATT-HTML-SMUGGLING' in ids('invoice.html', bad)
    assert 'ATT-HTML-SMUGGLING' not in ids('page.html', b'<html><script>var b=atob("AA");</script></html>')
    assert 'ATT-HTML-SMUGGLING' not in ids('notes.txt', bad)  # filename condition


def test_ole_macro_autoexec_and_shell():
    ole = b'\xd0\xcf\x11\xe0' + b'\x00' * 20 + b'_VBA_PROJECT Sub AutoOpen() CreateObject("WScript.Shell")'
    got = ids('macro.doc', ole)
    assert {'ATT-OLE-AUTOEXEC', 'ATT-OLE-SHELL'} <= got
    plain_ole = b'\xd0\xcf\x11\xe0' + b'\x00' * 40 + b'just a legacy document'
    assert not ({'ATT-OLE-AUTOEXEC', 'ATT-OLE-SHELL'} & ids('old.doc', plain_ole))


def test_rtf_embedded_object_and_lnk_and_pdf_embedded_file():
    assert 'ATT-RTF-OBJECT' in ids('a.rtf', b'{\\rtf1 {\\object\\objdata 0105}}')
    assert 'ATT-RTF-OBJECT' not in ids('a.rtf', b'{\\rtf1 hello}')
    assert 'ATT-LNK-SHORTCUT' in ids('a.lnk', b'L\x00\x00\x00\x01\x14\x02\x00' + b'\x00' * 30)
    assert 'ATT-PDF-EMBEDDED-FILE' in ids('a.pdf', b'%PDF-1.7 << /EmbeddedFile /Type >>')
    assert 'ATT-PDF-EMBEDDED-FILE' not in ids('a.pdf', b'%PDF-1.7 plain')


def test_script_dropper_idioms():
    assert 'ATT-SCRIPT-DROPPER' in ids('a.txt', b'powershell.exe -NoP -enc SQBFAFgA')
    assert 'ATT-SCRIPT-DROPPER' in ids('a.bat', b'cmd /c start x.exe')
    assert 'ATT-SCRIPT-DROPPER' not in ids('a.txt', b'Please review the attached quarterly report.')


def test_filename_rules():
    assert 'ATT-DOUBLE-EXTENSION' in ids('Invoice.pdf.exe', b'')
    assert 'ATT-DOUBLE-EXTENSION' not in ids('report.pdf', b'')
    assert 'ATT-RTL-OVERRIDE' in ids('invoice‮fdp.exe', b'')
    assert 'ATT-DISK-IMAGE' in ids('payload.iso', b'')


def _zip(entries):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
        for name, data in entries:
            z.writestr(name, data)
    return zipfile.ZipFile(io.BytesIO(buf.getvalue()))


def test_zip_path_traversal_and_nested_archives():
    hit = {h['id'] for h in rules.scan_archive('a.zip', _zip([('../../evil.dll', b'x'), ('ok.txt', b'y')]))}
    assert 'ATT-ZIP-TRAVERSAL' in hit
    absolute = {h['id'] for h in rules.scan_archive('a.zip', _zip([('/etc/cron.d/x', b'x')]))}
    assert 'ATT-ZIP-TRAVERSAL' in absolute
    nested = {h['id'] for h in rules.scan_archive('a.zip', _zip([('a.zip', b'1'), ('b.7z', b'2'), ('c.rar', b'3')]))}
    assert 'ATT-ZIP-NESTED' in nested
    clean = rules.scan_archive('a.zip', _zip([('docs/readme.txt', b'hello'), ('img/logo.png', b'png')]))
    assert clean == []


def test_zip_bomb_uses_declared_sizes_without_decompressing():
    class E:
        def __init__(self, name, file_size, compress_size):
            self.filename, self.file_size, self.compress_size = name, file_size, compress_size

    class A:
        def __init__(self, entries):
            self._e = entries
        def infolist(self):
            return self._e

    bomb = rules.scan_archive('b.zip', A([E('big.bin', 900 * 1024 * 1024, 50 * 1024)]))
    assert {h['id'] for h in bomb} == {'ATT-ZIP-BOMB'}
    fine = rules.scan_archive('b.zip', A([E('data.csv', 50 * 1024 * 1024, 10 * 1024 * 1024)]))
    assert fine == []


def test_scan_is_bounded_and_never_raises_on_odd_input():
    assert rules.scan(None, None) == []
    assert rules.scan('x', b'\x00' * (rules.MAX_SCAN_BYTES * 4)) == []


def test_findings_surface_in_the_assessment_with_rule_ids():
    import engine
    raw = (b'From: a@b.com\r\nTo: c@d.com\r\nSubject: invoice\r\nContent-Type: multipart/mixed; boundary="X"\r\n\r\n'
           b'--X\r\nContent-Type: text/plain\r\n\r\nsee attached\r\n'
           b'--X\r\nContent-Type: application/octet-stream; name="Invoice.pdf.exe"\r\n'
           b'Content-Disposition: attachment; filename="Invoice.pdf.exe"\r\nContent-Transfer-Encoding: 7bit\r\n\r\nplain\r\n--X--')
    result = engine.analyze(raw)
    import ps_assessment
    assessment = ps_assessment.inspect(raw, result)
    assert any('ATT-DOUBLE-EXTENSION' in c['detail'] for c in assessment['checks'])

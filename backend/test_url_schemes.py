import engine


def test_handler_schemes_file_and_ms_family_are_flagged_at_review_level():
    for value in ('file:///C:/Windows/System32/calc.exe', 'ms-msdt:/id PCWDiagnostic',
                  'search-ms:query=invoice&crumb=location:\\\\evil\\share',
                  'ms-officecmd:{"id":1}', 'MS-Word:ofe|u|http://x.tk/a.docx'):
        scanned = engine.scan_url(value)
        assert scanned is not None and scanned['score'] == 60, value
        assert 'launches a local application or file handler' in scanned['reasons'][0]


def test_scheme_obfuscation_variants_are_still_caught():
    for value in ('JaVaScRiPt:alert(1)', '  javascript:alert(1)', '\x01javascript:alert(1)', 'java\tscript:alert(1)',
                  'java\nscript:alert(1)', '\tdata:text/html;base64,PHNjcmlwdD4=', 'VBScript:msgbox(1)'):
        scanned = engine.scan_url(value)
        assert scanned is not None and scanned['score'] == 100, repr(value)


def test_mailto_tel_and_lookalike_hosts_are_not_treated_as_handler_schemes():
    assert engine.scan_url('mailto:a@b.com') is None
    assert engine.scan_url('tel:+911234567890') is None
    scanned = engine.scan_url('https://ms-office.example.com/help')
    assert scanned is None or scanned['protocol'] == 'HTTPS'

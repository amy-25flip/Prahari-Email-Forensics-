import pii


def _valid_aadhaar():
    # Verhoeff has exactly one valid check digit for any 11-digit prefix.
    for d in '0123456789':
        n = '23412341234' + d
        if pii._verhoeff_valid(n):
            return n
    raise AssertionError('no valid check digit found')


def test_verhoeff_accepts_valid_and_rejects_invalid():
    good = _valid_aadhaar()
    assert pii._verhoeff_valid(good)
    bad = good[:-1] + str((int(good[-1]) + 1) % 10)
    assert not pii._verhoeff_valid(bad)


def test_aadhaar_masked_only_when_checksum_valid():
    good = _valid_aadhaar()
    spaced = f'{good[:4]} {good[4:8]} {good[8:]}'
    assert pii.sanitize(f'Aadhaar {spaced} on file') == 'Aadhaar [AADHAAR REDACTED] on file'
    bad = good[:-1] + str((int(good[-1]) + 1) % 10)
    assert bad in pii.sanitize(f'ref {bad} end')  # invalid checksum -> not masked as Aadhaar


def test_pan_upi_phone_masked():
    assert pii.sanitize('PAN ABCDE1234F') == 'PAN [PAN REDACTED]'
    assert pii.sanitize('pay ramesh@oksbi now') == 'pay [UPI REDACTED] now'
    assert pii.sanitize('call +91 9876543210') == 'call [PHONE REDACTED]'
    assert pii.sanitize('call 9876543210') == 'call [PHONE REDACTED]'


def test_scan_counts_without_leaking_values():
    good = _valid_aadhaar()
    s = pii.scan(f'{good} ABCDE1234F ramesh@paytm 9123456780')
    assert s == {'aadhaar': 1, 'pan': 1, 'upi': 1, 'phone': 1}


def test_clean_text_unchanged():
    t = 'Meeting at 3pm about the Q4 report, thanks.'
    assert pii.sanitize(t) == t
    assert pii.scan(t) == {'aadhaar': 0, 'pan': 0, 'upi': 0, 'phone': 0}


def test_sanitize_report_masks_body_but_keeps_hashes_and_does_not_mutate():
    good = _valid_aadhaar()
    report = {'id': 'abc123', 'sha256': 'deadbeef' * 8, 'subject': 'PAN ABCDE1234F',
              'body': f'my aadhaar is {good}', 'findings': [{'detail': 'call 9876543210'}]}
    out = pii.sanitize_report(report)
    assert out['id'] == 'abc123' and out['sha256'] == 'deadbeef' * 8
    assert out['subject'] == 'PAN [PAN REDACTED]'
    assert '[AADHAAR REDACTED]' in out['body']
    assert out['findings'][0]['detail'] == 'call [PHONE REDACTED]'
    assert report['subject'] == 'PAN ABCDE1234F'  # original untouched


def test_upi_does_not_mask_ordinary_email():
    # Regression (Codex High): an email whose domain merely starts with a PSP name is NOT a VPA.
    for s in ('mail support@sbi.co.in now', 'care@hdfcbank.com replied', 'x@icici.com'):
        assert '[UPI REDACTED]' not in pii.sanitize(s)
    assert pii.scan('support@sbi.co.in care@hdfcbank.com')['upi'] == 0


def test_upi_masks_real_vpa():
    assert pii.sanitize('pay ramesh@oksbi today') == 'pay [UPI REDACTED] today'
    assert pii.sanitize('to priya@paytm') == 'to [UPI REDACTED]'


def test_pan_case_insensitive():
    assert pii.sanitize('pan abcde1234f') == 'pan [PAN REDACTED]'
    assert pii.scan('abcde1234f')['pan'] == 1


def test_phone_common_groupings():
    assert pii.sanitize('call +91 98765 43210') == 'call [PHONE REDACTED]'
    assert pii.sanitize('num 98765 43210') == 'num [PHONE REDACTED]'
    assert pii.sanitize('m 9876543210') == 'm [PHONE REDACTED]'


def test_verhoeff_known_vectors_and_hyphen_grouping():
    assert pii._verhoeff_valid('234123412346')       # known-good static vector
    assert not pii._verhoeff_valid('234123412340')   # known-bad (wrong check digit)
    assert pii.sanitize('aadhaar 2341-2341-2346 on file') == 'aadhaar [AADHAAR REDACTED] on file'


def test_sanitize_report_skips_id_and_hash_keys():
    report = {'case_id': 'ABCDE1234F', 'message_id': 'ABCDE1234F', 'report_hash': 'ABCDE1234F',
              'sha256': 'ABCDE1234F', 'body': 'PAN ABCDE1234F'}
    out = pii.sanitize_report(report)
    assert out['case_id'] == 'ABCDE1234F' and out['message_id'] == 'ABCDE1234F'
    assert out['report_hash'] == 'ABCDE1234F' and out['sha256'] == 'ABCDE1234F'
    assert out['body'] == 'PAN [PAN REDACTED]'

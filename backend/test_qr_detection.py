import base64
import struct

import cv2
import numpy as np
import pytest

import engine
import qr_detection


def _qr_png_bytes(payload):
    """Build a real QR-code PNG (via OpenCV's own encoder) for use as a test fixture.
    The raw encoder output is a tiny one-pixel-per-module bitmap (e.g. 29x29) --
    too small for the detector's finder-pattern localization, the same way a
    real photographed/screenshotted QR code is never that small. Upscale with
    nearest-neighbor (preserves hard module edges) to a realistic size, matching
    what an actual email attachment looks like."""
    encoder = cv2.QRCodeEncoder.create()
    image = encoder.encode(payload)
    image = cv2.resize(image, (400, 400), interpolation=cv2.INTER_NEAREST)
    image = cv2.cvtColor(image, cv2.COLOR_GRAY2BGR)
    ok, buf = cv2.imencode('.png', image)
    assert ok
    return buf.tobytes()


def _plain_png_bytes():
    """A real, decodable PNG with no QR code in it at all."""
    image = np.zeros((32, 32, 3), dtype=np.uint8)
    ok, buf = cv2.imencode('.png', image)
    assert ok
    return buf.tobytes()


def test_decode_qr_payloads_finds_encoded_url():
    png = _qr_png_bytes('http://phish-example.tk/login')
    assert qr_detection.decode_qr_payloads(png) == ['http://phish-example.tk/login']


def test_decode_qr_payloads_empty_on_plain_image():
    assert qr_detection.decode_qr_payloads(_plain_png_bytes()) == []


def test_decode_qr_payloads_never_raises_on_garbage():
    assert qr_detection.decode_qr_payloads(b'not an image at all') == []
    assert qr_detection.decode_qr_payloads(b'') == []
    assert qr_detection.decode_qr_payloads(None) == []


def test_decode_qr_payloads_rejects_oversized_input():
    huge = b'\x00' * (qr_detection.MAX_IMAGE_BYTES + 1)
    assert qr_detection.decode_qr_payloads(huge) == []


def _email_with_image_attachment(image_bytes, filename='invoice.png', content_type='image/png'):
    b64 = base64.b64encode(image_bytes).decode()
    return (
        f'From: a@b.com\r\nTo: c@d.com\r\nSubject: Your invoice\r\n'
        f'Content-Type: multipart/mixed; boundary="X"\r\n\r\n'
        f'--X\r\nContent-Type: text/plain\r\n\r\nSee attached invoice.\r\n'
        f'--X\r\nContent-Type: {content_type}; name="{filename}"\r\n'
        f'Content-Disposition: attachment; filename="{filename}"\r\n'
        f'Content-Transfer-Encoding: base64\r\n\r\n{b64}\r\n--X--'
    ).encode()


def test_engine_flags_qr_code_decoding_to_a_link():
    raw = _email_with_image_attachment(_qr_png_bytes('http://account-verify.tk/secure'))
    result = engine.analyze(raw)
    assert any('QR code in attachment' in f['title'] for f in result['findings'])
    assert any(u['url'] == 'http://account-verify.tk/secure' for u in result['urls'])
    assert result['attachments'][0]['qr_payloads'] == ['http://account-verify.tk/secure']


def test_engine_no_qr_finding_on_plain_image_attachment():
    raw = _email_with_image_attachment(_plain_png_bytes())
    result = engine.analyze(raw)
    assert not any('QR code' in f['title'] for f in result['findings'])
    assert result['attachments'][0]['qr_payloads'] == []


def test_engine_ignores_non_image_attachments_for_qr():
    # A .pdf attachment isn't scanned for QR content in this implementation
    # (only direct image attachments are) -- confirm it's simply skipped, not
    # mis-decoded or erroring.
    raw = _email_with_image_attachment(b'%PDF-1.4 not a real pdf', filename='doc.pdf', content_type='application/pdf')
    result = engine.analyze(raw)
    assert result['attachments'][0]['qr_payloads'] == []


def test_engine_qr_decoded_url_still_scored_by_normal_url_rules():
    # The QR-decoded URL goes through the exact same scan_url() pipeline as a
    # body link -- a suspicious structure on it still raises its own finding.
    raw = _email_with_image_attachment(_qr_png_bytes('http://1.2.3.4/verify-account-login'))
    result = engine.analyze(raw)
    assert any('Suspicious URL structure' in f['title'] for f in result['findings'])


def test_declared_pixel_count_reads_png_header_without_decoding():
    png = _qr_png_bytes('http://a.tk')
    assert qr_detection._declared_pixel_count(png) == 400 * 400


def test_declared_pixel_count_none_for_unrecognized_header():
    assert qr_detection._declared_pixel_count(b'not a real image header') is None


def test_oversized_declared_png_dimensions_rejected_before_decode(monkeypatch):
    # A PNG header can *declare* an enormous width/height while the actual
    # compressed bytes are tiny (the decompression-bomb-class risk Codex
    # flagged) -- craft a minimal, valid PNG signature+IHDR claiming a huge
    # image, and confirm it's rejected without ever reaching cv2.imdecode.
    huge_ihdr = struct.pack('>II', 50000, 50000)  # 2.5 billion declared pixels
    fake_png = b'\x89PNG\r\n\x1a\n' + b'\x00' * 8 + huge_ihdr + b'\x00' * 8
    called = {'n': 0}
    monkeypatch.setattr(qr_detection.cv2, 'imdecode', lambda *a, **k: called.__setitem__('n', called['n'] + 1))
    assert qr_detection.decode_qr_payloads(fake_png) == []
    assert called['n'] == 0  # imdecode was never even attempted


def test_decode_qr_payloads_dedupes_repeated_codes():
    # Two identical QR codes side by side in one image should collapse to one entry.
    single = cv2.QRCodeEncoder.create().encode('http://dup.tk')
    single = cv2.resize(single, (300, 300), interpolation=cv2.INTER_NEAREST)
    single = cv2.cvtColor(single, cv2.COLOR_GRAY2BGR)
    canvas = np.full((320, 620, 3), 255, dtype=np.uint8)
    canvas[10:310, 10:310] = single
    canvas[10:310, 320:620] = single
    ok, buf = cv2.imencode('.png', canvas)
    assert ok
    result = qr_detection.decode_qr_payloads(buf.tobytes())
    assert result == ['http://dup.tk']


def test_qr_url_not_starved_by_fifty_body_url_cap():
    # Regression (Codex Medium/Low): QR-derived links must be scanned even
    # when an email also contains 50 unrelated body URLs that would otherwise
    # exhaust the per-analysis URL cap first.
    body_links = ' '.join(f'http://harmless-{i}.example.com/page' for i in range(60))
    b64 = base64.b64encode(_qr_png_bytes('http://qr-phish.tk/login')).decode()
    raw = (
        b'From: a@b.com\r\nTo: c@d.com\r\nSubject: many links\r\n'
        b'Content-Type: multipart/mixed; boundary="X"\r\n\r\n'
        b'--X\r\nContent-Type: text/plain\r\n\r\n' + body_links.encode() + b'\r\n'
        b'--X\r\nContent-Type: image/png; name="qr.png"\r\n'
        b'Content-Disposition: attachment; filename="qr.png"\r\n'
        b'Content-Transfer-Encoding: base64\r\n\r\n' + b64.encode() + b'\r\n--X--'
    )
    result = engine.analyze(raw)
    assert any(u['url'] == 'http://qr-phish.tk/login' for u in result['urls'])
    assert any('QR code in attachment' in f['title'] for f in result['findings'])

import base64
import io

import pytest
from PIL import Image, ImageDraw, ImageFont

import engine
import ocr
import qr_detection

pytest.importorskip('rapidocr')


def _png(lines, size=(1000, 60)):
    font = ImageFont.load_default(size=34)
    img = Image.new('RGB', (size[0], 70 * len(lines) + 20), 'white')
    draw = ImageDraw.Draw(img)
    for i, line in enumerate(lines):
        draw.text((30, 15 + i * 70), line, fill='black', font=font)
    out = io.BytesIO(); img.save(out, format='PNG')
    return out.getvalue()


def _mail(parts, body='', subject='Invoice'):
    msg = (f'From: a@b.example\r\nTo: c@d.example\r\nSubject: {subject}\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary="BB"\r\n\r\n'
           f'--BB\r\nContent-Type: text/plain\r\n\r\n{body}\r\n')
    for ctype, name, data in parts:
        msg += (f'--BB\r\nContent-Type: {ctype}; name="{name}"\r\nContent-Disposition: attachment; filename="{name}"\r\n'
                f'Content-Transfer-Encoding: base64\r\n\r\n{base64.b64encode(data).decode()}\r\n')
    return (msg + '--BB--').encode()


PHISH_LINES = ['URGENT: Your bank account will be suspended', 'Verify now at http://sbi-secure-login.example/kyc', 'Do not call anyone. Keep this confidential.']


def test_engine_available_and_reads_english_text_from_an_image():
    status = ocr.status()
    assert status['available'] is True and 'English/Latin-script' in status['detail']
    blocks = ocr.extract_texts([('image', _png(PHISH_LINES))])
    text = ' '.join(blocks).lower()
    assert 'bank account' in text and 'suspended' in text and 'sbi-secure-login.example' in text


def test_image_only_phishing_is_now_read_scanned_and_scored():
    result = engine.analyze(_mail([('image/png', 'notice.png', _png(PHISH_LINES))]))
    titles = {f['title'] for f in result['findings']}
    assert {'Image-only message', 'Text read from image (OCR)', 'Credential pressure', 'Verification avoidance'} <= titles
    assert any('sbi-secure-login.example' in u['url'] for u in result['urls'])          # link inside the image was extracted and scanned
    assert result['ocr']['chars'] > 40 and result['ocr']['engine']['available'] is True
    assert 'read by OCR' in next(f['detail'] for f in result['findings'] if f['title'] == 'Image-only message')
    assert result['body'].strip() == ''                                                  # the stored body is untouched by OCR text
    assert result['score'] > 0


def test_benign_image_text_does_not_create_findings():
    result = engine.analyze(_mail([('image/png', 'menu.png', _png(['Team lunch on Friday at noon', 'Cafeteria second floor']))], body='Menu for Friday is attached to this message, please have a look and see you all there at lunch.'))
    assert {f['title'] for f in result['findings']} <= {'Text read from image (OCR)'}


def test_pdf_pages_are_rendered_and_read():
    from fpdf import FPDF
    pdf = FPDF(); pdf.add_page(); pdf.set_font('Helvetica', size=22)
    pdf.cell(0, 12, 'Verify your account now to avoid account suspension', new_x='LMARGIN', new_y='NEXT')
    pdf_bytes = bytes(pdf.output())
    text = ' '.join(ocr.extract_texts([('pdf', pdf_bytes)])).lower()
    assert 'verify' in text and 'suspension' in text


def test_bounds_at_most_three_images_and_disabled_flag(monkeypatch):
    calls = []
    real = ocr._read
    monkeypatch.setattr(ocr, '_read', lambda engine, image: calls.append(1) or real(engine, image))
    ocr.extract_texts([('image', _png(['One two three']))] * 6)
    assert len(calls) == ocr.MAX_IMAGES_PER_EMAIL
    monkeypatch.setenv('OCR_ENABLED', '0')
    assert ocr.extract_texts([('image', _png(['x']))]) == [] and ocr.status()['available'] is False


def test_time_budget_stops_further_work(monkeypatch):
    monkeypatch.setattr(ocr, '_read', lambda engine, image: pytest.fail('must not run after the deadline'))
    assert ocr.extract_texts([('image', _png(['late']))], deadline=0) == []


def test_hostile_and_oversized_inputs_degrade_to_no_text(monkeypatch):
    assert ocr.extract_texts([('image', b'not an image'), ('image', b''), ('pdf', b'%PDF-broken'), ('image', None)]) == []
    assert ocr.extract_texts([('image', b'\x89PNG' + b'\x00' * (qr_detection.MAX_IMAGE_BYTES + 1))]) == []
    big = io.BytesIO(); Image.new('RGB', (30, 30), 'white').save(big, format='PNG')
    header = bytearray(big.getvalue()); header[16:20] = (30000).to_bytes(4, 'big'); header[20:24] = (30000).to_bytes(4, 'big')   # declares 900 MP
    assert ocr.extract_texts([('image', bytes(header))]) == []


def test_large_images_are_downscaled_before_recognition():
    import numpy as np
    small = ocr._shrink(np.zeros((300, 900, 3), dtype='uint8'))
    assert small.shape[:2] == (300, 900)
    big = ocr._shrink(np.zeros((1200, 4500, 3), dtype='uint8'))
    assert max(big.shape[:2]) == ocr.MAX_SIDE_PX and big.shape[0] < 1200


def test_engine_failure_is_reported_not_raised(monkeypatch):
    monkeypatch.setattr(ocr, '_engine', None)
    monkeypatch.setattr(ocr, '_engine_error', 'ImportError: simulated')
    assert ocr.extract_texts([('image', _png(['x']))]) == []
    status = ocr.status()
    assert status['available'] is False and 'simulated' in status['detail']
    result = engine.analyze(_mail([('image/png', 'a.png', _png(['x']))]))
    assert result['ocr']['engine']['available'] is False and 'unavailable' in next(f['detail'] for f in result['findings'] if f['title'] == 'Image-only message')


def test_budget_expiring_while_waiting_for_the_ocr_lock_stops_work(monkeypatch):
    import threading
    ran = []
    monkeypatch.setattr(ocr, '_read', lambda engine, image: ran.append(1) or ['text'])
    deadline = ocr.time.monotonic() + 0.6
    results = []
    with ocr._lock:                                               # another request is using the engine
        t = threading.Thread(target=lambda: results.append(ocr.extract_texts([('image', _png(['queued']))], deadline=deadline)))
        t.start()
        ocr.time.sleep(1.0)                                       # ...long enough for our budget to expire while we wait
    t.join()
    assert results == [[]] and ran == []

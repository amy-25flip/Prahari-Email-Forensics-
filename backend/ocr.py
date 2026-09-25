"""Bounded OCR of image attachments and rendered PDF pages, so image-only phishing text is read and analysed like any body text.

Engine: RapidOCR (PP-OCR models over ONNX Runtime). The default English/Chinese detection, recognition and angle models ship
inside the rapidocr wheel (checked by listing the 3.9.2 wheel: three .onnx files, ~32 MB) - no download and no system binary for
the default path; if initialisation fails for any reason the feature reports itself unavailable instead of pretending.
HONEST SCOPE: English/Latin-script text. Devanagari and other Indic scripts are NOT recognised by these models (the language
router still flags such messages as outside the classifier's validated coverage). OCR text is an aid, never proof: it can miss
or misread characters, and adversarial images can defeat it.
Safety bounds: at most MAX_IMAGES_PER_EMAIL images/pages per message, the same pixel/byte caps as QR decoding, images
downscaled to MAX_SIDE_PX, a total time budget per message, a lock (one OCR run at a time), and every failure degrades to
"no text" rather than an error. Disabled with OCR_ENABLED=0; when the engine is not installed the feature reports itself
unavailable instead of pretending."""
import os
import threading
import time

import cv2
import numpy as np

import qr_detection

MAX_IMAGES_PER_EMAIL = 3
MAX_SIDE_PX = 2000
MAX_TEXT_CHARS = 5000
TIME_BUDGET_SECONDS = 12.0
_lock = threading.Lock()
_engine = None
_engine_error = None


def enabled():
    return os.getenv('OCR_ENABLED', '1') != '0'


def _get_engine():
    """Lazy singleton. Returns None (and remembers why) if RapidOCR is not installed or fails to initialise."""
    global _engine, _engine_error
    if _engine is not None or _engine_error is not None:
        return _engine
    try:
        import logging
        logging.getLogger('RapidOCR').setLevel(logging.WARNING)
        from rapidocr import RapidOCR
        _engine = RapidOCR()
    except Exception as exc:                               # missing package, missing ONNX runtime, bad models...
        _engine_error = f'{type(exc).__name__}: {str(exc)[:120]}'
    return _engine


def status():
    if not enabled():
        return {'available': False, 'engine': 'rapidocr', 'detail': 'Disabled (OCR_ENABLED=0).'}
    engine = _get_engine()
    if engine is None:
        return {'available': False, 'engine': 'rapidocr', 'detail': 'OCR engine not installed or failed to start (' + str(_engine_error) + ').'}
    return {'available': True, 'engine': 'rapidocr', 'detail': 'English/Latin-script text only; not a general multilingual OCR.'}


def _shrink(image):
    height, width = image.shape[:2]
    longest = max(height, width)
    if longest <= MAX_SIDE_PX:
        return image
    scale = MAX_SIDE_PX / longest
    return cv2.resize(image, (max(1, int(width * scale)), max(1, int(height * scale))), interpolation=cv2.INTER_AREA)


def _decode_image(image_bytes):
    if not image_bytes or len(image_bytes) > qr_detection.MAX_IMAGE_BYTES:
        return None
    declared = qr_detection._declared_pixel_count(image_bytes)
    if declared is not None and declared > qr_detection.MAX_DECLARED_PIXELS:
        return None
    image = cv2.imdecode(np.frombuffer(image_bytes, dtype=np.uint8), cv2.IMREAD_COLOR)
    if image is None or image.shape[0] * image.shape[1] > qr_detection.MAX_DECLARED_PIXELS:
        return None
    return image


def _read(engine, image):
    result = engine(_shrink(image))
    lines = getattr(result, 'txts', None) or ()
    return [str(t).strip() for t in lines if str(t).strip()]


def extract_texts(items, deadline=None):
    """items: iterable of ('image'|'pdf', bytes). Returns a list of text blocks (one per image / PDF page), never raising."""
    if not enabled():
        return []
    engine = _get_engine()
    if engine is None:
        return []
    if deadline is None:
        deadline = time.monotonic() + TIME_BUDGET_SECONDS
    blocks, used = [], 0
    for kind, data in items:
        if used >= MAX_IMAGES_PER_EMAIL:
            break
        try:
            images = [i for i in [_decode_image(data)] if i is not None] if kind == 'image' else qr_detection.render_pdf_pages(data)
        except Exception:
            continue
        for image in images:
            if used >= MAX_IMAGES_PER_EMAIL or time.monotonic() > deadline:
                return blocks
            used += 1
            try:
                with _lock:
                    if time.monotonic() > deadline:        # the budget may have run out while waiting for another request's OCR
                        return blocks
                    lines = _read(engine, image)
            except Exception:
                continue
            if lines:
                blocks.append(' '.join(lines)[:MAX_TEXT_CHARS])
    return blocks

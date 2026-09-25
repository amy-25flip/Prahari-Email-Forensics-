"""QR-code decoding for image and PDF attachments ("quishing" -- phishing links hidden
inside a QR code image, which text-only scanners never see).

Scope, stated honestly: this decodes QR codes embedded in image attachments
(PNG/JPEG/GIF/BMP/WEBP) using OpenCV's built-in detector -- no external
service, no image content leaves the process. PDFs are handled by
rasterizing only the first few pages at a bounded resolution (pypdfium2) and
running the same decoder on each page image. It does NOT run OCR on arbitrary
in-image text -- that needs a Tesseract-class engine and a real quality
benchmark, and is not implemented here. Decoded QR payloads are handed to the same URL analyzer already used
for links found in the email body, so a malicious QR destination gets the
same reputation/structure checks as a normal link -- not a separate, weaker
code path.
"""
import struct
import threading

import cv2
import numpy as np

IMAGE_CONTENT_TYPES = {'image/png', 'image/jpeg', 'image/jpg', 'image/gif', 'image/bmp', 'image/webp'}
MAX_IMAGE_BYTES = 5 * 1024 * 1024  # generous relative to the overall 1 MiB email cap; defensive only
# A compressed image can be small while its DECOMPRESSED pixel buffer is huge
# (a decompression-bomb-class risk -- PNG's DEFLATE in particular can compress
# a large solid-color image to well under 1 MiB). cv2.imdecode() allocates the
# full decompressed buffer before any pixel-count check is possible, so the
# real mitigation is a cheap, decode-free header read of the DECLARED
# width/height for common formats, rejecting oversized images before ever
# calling imdecode. 20 megapixels is generous for any real email attachment
# (a 5000x4000 photo) while still bounding worst-case allocation.
MAX_DECLARED_PIXELS = 20_000_000


def _declared_pixel_count(data):
    """Best-effort, decode-free read of an image's own declared width/height
    from its file header, without inflating/decompressing any pixel data.
    Returns None if the format isn't recognised or the header is too short --
    callers must treat None as "unknown", not "safe"."""
    try:
        if data[:8] == b'\x89PNG\r\n\x1a\n' and len(data) >= 24:
            width, height = struct.unpack('>II', data[16:24])
            return width * height
        if data[:4] == b'RIFF' and data[8:12] == b'WEBP' and len(data) >= 30:
            # Covers the common VP8/VP8L/VP8X WebP header layouts closely enough
            # for a conservative bound; falls through to None on anything unusual.
            if data[12:16] == b'VP8X' and len(data) >= 30:
                width = 1 + int.from_bytes(data[24:27], 'little')
                height = 1 + int.from_bytes(data[27:30], 'little')
                return width * height
            return None
        if data[:6] in (b'GIF87a', b'GIF89a') and len(data) >= 10:
            width, height = struct.unpack('<HH', data[6:10])
            return width * height
        if data[:2] == b'BM' and len(data) >= 26:
            width, height = struct.unpack('<ii', data[18:26])
            return abs(width) * abs(height)
        if data[:2] == b'\xff\xd8':  # JPEG: scan markers for an SOFn frame header
            i = 2
            while i + 9 < len(data):
                if data[i] != 0xFF:
                    i += 1
                    continue
                marker = data[i + 1]
                if marker in (0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7,
                              0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF):
                    height, width = struct.unpack('>HH', data[i + 5:i + 9])
                    return width * height
                if marker in (0xD8, 0xD9) or 0xD0 <= marker <= 0xD7:
                    i += 2
                    continue
                length = struct.unpack('>H', data[i + 2:i + 4])[0]
                i += 2 + length
            return None
    except (struct.error, IndexError):
        return None
    return None


MAX_PDF_BYTES = 5 * 1024 * 1024
PDF_MAX_PAGES = 2
PDF_RENDER_SCALE = 2.0  # ~144 dpi: enough for a printed/embedded QR, cheap enough to bound
_pdfium_lock = threading.Lock()  # PDFium is not thread-safe


def _decode_array(image):
    """Try progressively more tolerant decoders; first one that finds anything
    wins. Rendered PDF pages and resampled images can defeat the plain detector
    on small/blurry codes that a thresholded or ArUco-based pass still reads."""
    gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
    _, otsu = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    attempts = [(cv2.QRCodeDetector, image), (cv2.QRCodeDetector, cv2.cvtColor(otsu, cv2.COLOR_GRAY2BGR))]
    if hasattr(cv2, 'QRCodeDetectorAruco'):
        attempts.append((cv2.QRCodeDetectorAruco, image))
    for factory, candidate in attempts:
        try:
            ok, decoded, _points, _straight = factory().detectAndDecodeMulti(candidate)
        except cv2.error:
            continue
        found = [text for text in decoded if text] if ok else []
        if found:
            return found
    return []


def render_pdf_pages(pdf_bytes):
    """BGR arrays of the first PDF_MAX_PAGES pages, rendered at a bounded scale under the PDFium lock. Returns [] on anything
    unexpected (corrupt, encrypted, oversized, renderer failure). Never raises. Shared by QR decoding and OCR."""
    if not pdf_bytes or len(pdf_bytes) > MAX_PDF_BYTES or not pdf_bytes.lstrip()[:5] == b'%PDF-':
        return []
    try:
        import pypdfium2 as pdfium
        pages = []
        with _pdfium_lock:
            pdf = pdfium.PdfDocument(pdf_bytes)
            try:
                for index in range(min(len(pdf), PDF_MAX_PAGES)):
                    page = pdf[index]
                    width, height = page.get_size()
                    if width * height * PDF_RENDER_SCALE ** 2 > MAX_DECLARED_PIXELS:
                        continue
                    rgb = np.array(page.render(scale=PDF_RENDER_SCALE).to_pil().convert('RGB'))
                    pages.append(cv2.cvtColor(rgb, cv2.COLOR_RGB2BGR))
            finally:
                pdf.close()
        return pages
    except Exception:
        return []


def decode_pdf_qr_payloads(pdf_bytes):
    """Return distinct QR payloads found on the first PDF_MAX_PAGES pages, or [] on anything unexpected. Never raises."""
    found = []
    for page in render_pdf_pages(pdf_bytes):
        try:
            found.extend(_decode_array(page))
        except Exception:
            continue
    return list(dict.fromkeys(found))


def decode_qr_payloads(image_bytes):
    """Return every distinct string decoded from QR codes in an image, or []
    if none are found, the bytes aren't a decodable image, or the image is
    rejected as oversized. Never raises -- a corrupt/adversarial image
    degrades to "no QR found", not a crash."""
    if not image_bytes or len(image_bytes) > MAX_IMAGE_BYTES:
        return []
    declared_pixels = _declared_pixel_count(image_bytes)
    if declared_pixels is not None and declared_pixels > MAX_DECLARED_PIXELS:
        return []
    try:
        array = np.frombuffer(image_bytes, dtype=np.uint8)
        image = cv2.imdecode(array, cv2.IMREAD_COLOR)
        if image is None:
            return []
        # Backstop for formats _declared_pixel_count() couldn't parse (returned
        # None) or a header that understated the true size: bail before doing
        # any further work on an unexpectedly huge decoded buffer.
        if image.shape[0] * image.shape[1] > MAX_DECLARED_PIXELS:
            return []
        return list(dict.fromkeys(_decode_array(image)))
    except Exception:
        # Any OpenCV/decoding failure on hostile or malformed input is a
        # "nothing found" result, never an unhandled exception reaching the
        # caller -- matches this codebase's fallback convention everywhere else.
        return []

"""Declarative static rules for email attachments -- YARA-style (rule id, magic bytes,
required/optional byte patterns, filename conditions), implemented in pure Python so it
adds no dependency and stays auditable. Static only: nothing is executed, and archives are
inspected via their directory, never decompressed. A hit is a review hint, not a malware
verdict; absence of a hit is not a safety guarantee."""
import re

MAX_SCAN_BYTES = 256 * 1024
ZIP_MAX_UNCOMPRESSED = 1024 * 1024 * 1024   # declared total, 1 GiB
ZIP_MAX_RATIO = 200                          # per-entry declared expansion ratio
ZIP_BOMB_MIN_ENTRY = 10 * 1024 * 1024        # ignore tiny entries when judging ratio
ARCHIVE_EXT = re.compile(r'\.(zip|jar|docm|xlsm|pptm|docx|xlsx|pptx|7z|rar|gz|iso|img|vhd)$', re.I)

_I = re.IGNORECASE

RULES = [
    {'id': 'ATT-HTML-SMUGGLING', 'title': 'HTML smuggling pattern',
     'detail': 'Script decodes an embedded blob and triggers a download - a common way to build a payload client-side and bypass gateways.',
     'name': re.compile(r'\.(html?|xhtml|svg)$', _I),
     'all': [re.compile(rb'atob\(|new\s+Blob\(|Uint8Array'),
             re.compile(rb'\.download\s*=|msSaveOrOpenBlob|createObjectURL|saveAs\(')]},
    {'id': 'ATT-OLE-AUTOEXEC', 'title': 'Legacy Office macro auto-execution',
     'detail': 'OLE document with a macro entry point that runs when the file is opened.',
     'magic': b'\xd0\xcf\x11\xe0',
     'all': [re.compile(rb'_VBA_PROJECT|VBA/|Attribut', _I),
             re.compile(rb'Auto_?Open|Document_Open|Workbook_Open|Auto_?Exec', _I)]},
    {'id': 'ATT-OLE-SHELL', 'title': 'Legacy Office document referencing a shell or downloader',
     'detail': 'OLE document contains strings used to launch processes or download content.',
     'magic': b'\xd0\xcf\x11\xe0',
     'any': [re.compile(rb'WScript\.Shell|Shell\s*\(|powershell|CreateObject|URLDownloadToFile', _I)]},
    {'id': 'ATT-RTF-OBJECT', 'title': 'RTF with embedded object',
     'detail': 'RTF contains embedded/linked object data, a frequent exploit and dropper carrier.',
     'magic': b'{\\rtf',
     'any': [re.compile(rb'\\objdata|\\objupdate|\\objautlink')]},
    {'id': 'ATT-LNK-SHORTCUT', 'title': 'Windows shortcut (.lnk) content',
     'detail': 'Shortcut files can run arbitrary commands when opened and are rarely legitimate email attachments.',
     'magic': b'L\x00\x00\x00\x01\x14\x02\x00'},
    {'id': 'ATT-PDF-EMBEDDED-FILE', 'title': 'PDF with embedded file',
     'detail': 'PDF carries an embedded file object; the embedded content was not extracted or scanned.',
     'magic': b'%PDF',
     'any': [re.compile(rb'/EmbeddedFile\b')]},
    {'id': 'ATT-SCRIPT-DROPPER', 'title': 'Encoded or obfuscated script command',
     'detail': 'Contains command-line/script idioms used to run encoded payloads.',
     'any': [re.compile(rb'powershell(\.exe)?\s+.{0,40}-(enc|encodedcommand)\b', _I | re.S),
             re.compile(rb'FromBase64String\(|Invoke-Expression|\bIEX\s*\(|cmd(\.exe)?\s*/c\s', _I)]},
]

_DOUBLE_EXT = re.compile(r'\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|txt|csv)\s*\.(exe|scr|js|vbs|bat|cmd|lnk|com|jar|ps1|hta)$', _I)
_DISK_IMAGE = re.compile(r'\.(iso|img|vhd|vhdx)$', _I)


def _hit(rule):
    return {'id': rule['id'], 'title': rule['title'], 'detail': rule['detail']}


def scan(name, payload):
    """Return rule hits for one attachment (list of {'id','title','detail'})."""
    name = name or ''
    payload = (payload or b'')[:MAX_SCAN_BYTES]
    hits = []
    if _DOUBLE_EXT.search(name):
        hits.append({'id': 'ATT-DOUBLE-EXTENSION', 'title': 'Double file extension',
                     'detail': 'Filename ends in a document-looking extension followed by an executable one.'})
    if '‮' in name:
        hits.append({'id': 'ATT-RTL-OVERRIDE', 'title': 'Right-to-left override in filename',
                     'detail': 'The filename contains a Unicode direction override, used to disguise the real extension.'})
    if _DISK_IMAGE.search(name):
        hits.append({'id': 'ATT-DISK-IMAGE', 'title': 'Disk-image attachment',
                     'detail': 'Disk images can bypass mark-of-the-web protections; content was not mounted or inspected.'})
    for rule in RULES:
        if rule.get('magic') and not payload.startswith(rule['magic']):
            continue
        if rule.get('name') and not rule['name'].search(name):
            continue
        if rule.get('all') and not all(p.search(payload) for p in rule['all']):
            continue
        if rule.get('any') and not any(p.search(payload) for p in rule['any']):
            continue
        hits.append(_hit(rule))
    return hits


def scan_archive(name, archive):
    """Directory-only checks on an open ZipFile: path traversal, absolute paths, declared
    zip-bomb expansion, nested archives. Never decompresses."""
    hits, total, nested = [], 0, 0
    traversal = bomb = False
    for entry in archive.infolist()[:500]:
        path = entry.filename.replace('\\', '/')
        if path.startswith('/') or re.match(r'^[A-Za-z]:', path) or '..' in path.split('/'):
            traversal = True
        total += entry.file_size
        if entry.file_size > ZIP_BOMB_MIN_ENTRY and entry.file_size / max(entry.compress_size, 1) > ZIP_MAX_RATIO:
            bomb = True
        if ARCHIVE_EXT.search(path):
            nested += 1
    if traversal:
        hits.append({'id': 'ATT-ZIP-TRAVERSAL', 'title': 'Archive path traversal entry',
                     'detail': name + ': an entry uses an absolute path or "..", which can write outside the extraction folder (zip-slip).'})
    if bomb or total > ZIP_MAX_UNCOMPRESSED:
        hits.append({'id': 'ATT-ZIP-BOMB', 'title': 'Archive declares extreme expansion',
                     'detail': name + ': declared uncompressed size is far larger than the archive (possible decompression bomb); not decompressed.'})
    if nested >= 3:
        hits.append({'id': 'ATT-ZIP-NESTED', 'title': 'Archive contains multiple nested archives',
                     'detail': name + ': nested archives can hide content from single-pass scanners; not recursed into.'})
    return hits

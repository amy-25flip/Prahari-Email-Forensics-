"""Optional at-rest field encryption for stored case content, via Fernet (AES-128-CBC + HMAC).

Opt-in: set DB_ENCRYPTION_KEY (a Fernet key -- e.g. the output of
`python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`)
to enable. Without it, data is stored in plaintext exactly as before -- an additive
protection, not a required one, matching every other optional control in this codebase.

Encrypts only the two columns that hold actual evidence content (report JSON, original
email bytes) at the store.py read/write boundary -- hash-chain integrity is always computed
over plaintext before encryption / after decryption, so enabling this does not change what
the audit chain or checkpoints mean or verify.
"""
import os


def _fernet():
    key = os.getenv('DB_ENCRYPTION_KEY')
    if not key:
        return None
    from cryptography.fernet import Fernet
    try:
        return Fernet(key.encode('ascii') if isinstance(key, str) else key)
    except (ValueError, TypeError) as exc:
        raise ValueError(f'DB_ENCRYPTION_KEY is not a valid Fernet key: {type(exc).__name__}') from exc


def encrypt_text(value):
    f = _fernet()
    return value if f is None else f.encrypt(value.encode('utf-8')).decode('ascii')


def decrypt_text(value):
    f = _fernet()
    if f is None:
        return value
    from cryptography.fernet import InvalidToken
    try:
        return f.decrypt(value.encode('ascii')).decode('utf-8')
    except (InvalidToken, ValueError):
        return value  # a row written before encryption was enabled; read as plaintext


def encrypt_bytes(value):
    f = _fernet()
    return value if f is None else f.encrypt(value)


def decrypt_bytes(value):
    f = _fernet()
    if f is None:
        return value
    from cryptography.fernet import InvalidToken
    try:
        return f.decrypt(value)
    except (InvalidToken, ValueError):
        return value


def status():
    configured = os.getenv('DB_ENCRYPTION_KEY') is not None
    if not configured:
        return {'status': 'disabled', 'detail': 'DB_ENCRYPTION_KEY not configured; stored evidence relies on OS/disk encryption only.'}
    try:
        _fernet()
    except ValueError as exc:
        return {'status': 'misconfigured', 'detail': str(exc)}
    return {'status': 'enabled', 'detail': 'Report content and original email bytes are encrypted at rest (Fernet/AES-128-CBC+HMAC).'}

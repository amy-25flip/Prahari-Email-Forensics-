import hashlib
import json
import sqlite3
import pytest
from cryptography.fernet import Fernet
import db_encryption as dbe
import store


@pytest.fixture(autouse=True)
def reset_env(monkeypatch):
    monkeypatch.delenv('DB_ENCRYPTION_KEY', raising=False)


def test_disabled_by_default_is_identity():
    assert dbe.encrypt_text('hello') == 'hello'
    assert dbe.decrypt_text('hello') == 'hello'
    assert dbe.encrypt_bytes(b'hello') == b'hello'
    assert dbe.decrypt_bytes(b'hello') == b'hello'
    assert dbe.status()['status'] == 'disabled'


def test_roundtrip_when_enabled(monkeypatch):
    monkeypatch.setenv('DB_ENCRYPTION_KEY', Fernet.generate_key().decode())
    ciphertext = dbe.encrypt_text('sensitive report json')
    assert ciphertext != 'sensitive report json'
    assert dbe.decrypt_text(ciphertext) == 'sensitive report json'

    raw = b'\x00\x01original email bytes\xff'
    encrypted_raw = dbe.encrypt_bytes(raw)
    assert encrypted_raw != raw
    assert dbe.decrypt_bytes(encrypted_raw) == raw
    assert dbe.status()['status'] == 'enabled'


def test_wrong_key_cannot_decrypt(monkeypatch):
    monkeypatch.setenv('DB_ENCRYPTION_KEY', Fernet.generate_key().decode())
    ciphertext = dbe.encrypt_text('secret')
    monkeypatch.setenv('DB_ENCRYPTION_KEY', Fernet.generate_key().decode())
    # Decryption with the wrong key falls back to returning the (still-encrypted) input
    # rather than raising -- matches the "legacy plaintext row" tolerance by design, but
    # the important guarantee is it never crashes and never fabricates plaintext.
    assert dbe.decrypt_text(ciphertext) == ciphertext


def test_legacy_plaintext_row_readable_after_enabling_encryption(monkeypatch):
    monkeypatch.setenv('DB_ENCRYPTION_KEY', Fernet.generate_key().decode())
    assert dbe.decrypt_text('{"already":"plaintext json"}') == '{"already":"plaintext json"}'


def test_invalid_key_format_is_reported_not_crashed(monkeypatch):
    monkeypatch.setenv('DB_ENCRYPTION_KEY', 'not-a-valid-fernet-key')
    assert dbe.status()['status'] == 'misconfigured'


def test_save_get_verify_roundtrip_with_encryption_enabled(tmp_path, monkeypatch):
    monkeypatch.setattr(store, 'DATA', tmp_path)
    monkeypatch.setenv('DB_ENCRYPTION_KEY', Fernet.generate_key().decode())
    store.init()
    sid, _ = store.session(None)
    raw = b'From: a@b.com\r\nSubject: test\r\n\r\nbody'
    report = {'sha256': hashlib.sha256(raw).hexdigest(), 'subject': 'test', 'sender': 'a@b.com', 'score': 10}
    saved = store.save(sid, dict(report), raw)

    # Confirm the stored bytes on disk are not the plaintext JSON/email.
    with sqlite3.connect(tmp_path / 'cases.sqlite') as db:
        row = db.execute('SELECT report, raw FROM cases WHERE id=?', (saved['id'],)).fetchone()
    assert b'"subject":"test"' not in row[0].encode() if isinstance(row[0], str) else row[0]
    assert b'From: a@b.com' not in row[1]

    fetched = store.get(sid, saved['id'])
    assert fetched['subject'] == 'test'
    assert store.all_cases(sid)[0]['id'] == saved['id']

    result = store.verify(sid)
    assert result['valid'], result.get('detail')

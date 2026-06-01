# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Tests for app.core.crypto — Fernet encryption/decryption utilities.

Uses a deterministic Fernet key so tests don't depend on Settings or a .env file.
"""

import base64
import hashlib
from unittest.mock import patch

import pytest
from cryptography.fernet import Fernet

import app.core.crypto as crypto_mod
from app.core.crypto import (
    decrypt_credential,
    decrypt_dict,
    encrypt_credential,
    encrypt_dict,
    is_encrypted,
)

# ── Fixtures ────────────────────────────────────────────────────────────────

_TEST_SECRET = "test-secret-key-for-unit-tests-1234567890"
_TEST_SALT = "test-salt-abcdef"


def _make_fernet(secret: str = _TEST_SECRET, salt: str = _TEST_SALT) -> Fernet:
    """Derive a Fernet instance identical to how crypto.py does it."""
    dk = hashlib.pbkdf2_hmac(
        "sha256",
        secret.encode("utf-8"),
        salt.encode("utf-8"),
        iterations=260_000,
    )
    key = base64.urlsafe_b64encode(dk[:32])
    return Fernet(key)


@pytest.fixture(autouse=True)
def _patch_fernet():
    """Replace the module-level _fernet with a test instance for every test."""
    test_fernet = _make_fernet()
    with patch.object(crypto_mod, "_fernet", test_fernet):
        yield


# ── encrypt / decrypt roundtrip ─────────────────────────────────────────────


class TestEncryptDecryptRoundtrip:
    def test_basic_roundtrip(self):
        plaintext = "my-super-secret-password"
        cipher = encrypt_credential(plaintext)
        assert cipher != plaintext
        assert decrypt_credential(cipher) == plaintext

    def test_unicode_roundtrip(self):
        plaintext = "p@$$w0rd-with-unicode"
        assert decrypt_credential(encrypt_credential(plaintext)) == plaintext

    def test_long_string_roundtrip(self):
        plaintext = "x" * 10_000
        assert decrypt_credential(encrypt_credential(plaintext)) == plaintext

    def test_special_characters(self):
        plaintext = '{"user": "admin", "pass": "a&b=c<d>e"}'
        assert decrypt_credential(encrypt_credential(plaintext)) == plaintext


# ── Decrypt with wrong key ──────────────────────────────────────────────────


class TestDecryptWrongKey:
    def test_wrong_key_raises_value_error(self):
        cipher = encrypt_credential("secret")

        # Create a different Fernet with a different secret
        wrong_fernet = _make_fernet(secret="completely-different-key-XXXXXXXXXX")
        with patch.object(crypto_mod, "_fernet", wrong_fernet):
            with pytest.raises(ValueError, match="Cannot decrypt"):
                decrypt_credential(cipher)

    def test_garbage_input_raises_value_error(self):
        with pytest.raises(ValueError, match="Cannot decrypt"):
            decrypt_credential("not-a-valid-fernet-token-at-all")


# ── Empty / None input handling ─────────────────────────────────────────────


class TestEmptyInput:
    def test_encrypt_empty_string(self):
        assert encrypt_credential("") == ""

    def test_decrypt_empty_string(self):
        assert decrypt_credential("") == ""

    def test_encrypt_none_like_empty(self):
        # The function checks `if not plaintext` so falsy values return ""
        assert encrypt_credential("") == ""

    def test_decrypt_none_like_empty(self):
        assert decrypt_credential("") == ""


# ── is_encrypted detection ──────────────────────────────────────────────────


class TestIsEncrypted:
    def test_real_token_detected(self):
        token = encrypt_credential("something")
        assert is_encrypted(token) is True

    def test_short_string_not_encrypted(self):
        assert is_encrypted("short") is False

    def test_empty_string_not_encrypted(self):
        assert is_encrypted("") is False

    def test_plaintext_not_encrypted(self):
        assert is_encrypted("this-is-plaintext-password-that-is-long-enough-" * 5) is False

    def test_none_not_encrypted(self):
        # is_encrypted checks `if not value` first
        assert is_encrypted(None) is False

    def test_fernet_prefix_but_short(self):
        assert is_encrypted("gAAAAA") is False

    def test_looks_like_fernet(self):
        # Starts with gAAAAA and is 100+ chars
        fake = "gAAAAA" + "A" * 100
        assert is_encrypted(fake) is True


# ── Dict-level encryption ──────────────────────────────────────────────────


class TestDictEncryption:
    def test_roundtrip(self):
        data = {"username": "admin", "password": "s3cret", "port": 443}
        encrypted = encrypt_dict(data)
        assert "_encrypted" in encrypted
        assert "password" not in str(encrypted.get("_encrypted", ""))

        decrypted = decrypt_dict(encrypted)
        assert decrypted == data

    def test_empty_dict_passthrough(self):
        assert encrypt_dict({}) == {}
        assert decrypt_dict({}) == {}

    def test_none_passthrough(self):
        assert encrypt_dict(None) is None
        assert decrypt_dict(None) is None

    def test_already_encrypted_idempotent(self):
        data = {"username": "admin", "password": "pw"}
        encrypted = encrypt_dict(data)
        double_encrypted = encrypt_dict(encrypted)
        # Should not re-encrypt
        assert double_encrypted == encrypted

    def test_unencrypted_dict_passthrough_on_decrypt(self):
        plain = {"username": "admin", "password": "pw"}
        assert decrypt_dict(plain) == plain

    def test_wrong_key_raises(self):
        data = {"key": "value"}
        encrypted = encrypt_dict(data)

        wrong_fernet = _make_fernet(secret="different-key-XXXXXXXXXXXXXXXX")
        with patch.object(crypto_mod, "_fernet", wrong_fernet):
            with pytest.raises(ValueError, match="Cannot decrypt"):
                decrypt_dict(encrypted)

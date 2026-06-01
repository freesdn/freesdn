# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Tests for the ECDSA-P256 release signing helper.

Validates the full sign + verify round-trip, key persistence, and
public-key export. We point the helper at a tmp dir per test so the
global cached keypair doesn't bleed between tests.
"""

from __future__ import annotations

import hashlib
import importlib

import pytest


def _reload_signing(tmp_path, monkeypatch):
    """Force the signing module to re-initialize against a fresh dir.

    The module caches the keypair in module-level globals so we reset
    those + point the dir env var at tmp_path before re-importing.
    """
    monkeypatch.setenv("FREESDN_SIGNING_KEY_DIR", str(tmp_path))
    monkeypatch.setenv("FREESDN_AGENT_RELEASE_DIR", str(tmp_path))
    import app.services.release_signing as signing

    importlib.reload(signing)
    return signing


class TestKeyGeneration:
    def test_lazy_generates_keypair_on_first_call(self, tmp_path, monkeypatch):
        signing = _reload_signing(tmp_path, monkeypatch)
        pem = signing.public_key_pem()
        assert pem.startswith(b"-----BEGIN PUBLIC KEY-----")
        # On-disk persistence
        priv_path = tmp_path / ".signing-key.pem"
        pub_path = tmp_path / ".public-key.pem"
        assert priv_path.exists()
        assert pub_path.exists()

    def test_reuses_existing_keypair_across_reloads(self, tmp_path, monkeypatch):
        signing = _reload_signing(tmp_path, monkeypatch)
        pem_first = signing.public_key_pem()

        # Re-import: should NOT regenerate the key (key file persists)
        signing2 = _reload_signing(tmp_path, monkeypatch)
        pem_second = signing2.public_key_pem()
        assert pem_first == pem_second


class TestSignVerify:
    def test_round_trip_valid_digest(self, tmp_path, monkeypatch):
        signing = _reload_signing(tmp_path, monkeypatch)
        digest = hashlib.sha256(b"fake-binary-bytes").hexdigest()
        sig = signing.sign_digest(digest)
        assert signing.verify_digest(digest, sig) is True

    def test_verify_rejects_tampered_digest(self, tmp_path, monkeypatch):
        """If the binary changed after signing, the digest changes and
        verification must fail."""
        signing = _reload_signing(tmp_path, monkeypatch)
        digest_orig = hashlib.sha256(b"original").hexdigest()
        digest_tampered = hashlib.sha256(b"tampered").hexdigest()
        sig = signing.sign_digest(digest_orig)
        assert signing.verify_digest(digest_tampered, sig) is False

    def test_verify_rejects_garbage_signature(self, tmp_path, monkeypatch):
        signing = _reload_signing(tmp_path, monkeypatch)
        digest = hashlib.sha256(b"x").hexdigest()
        assert signing.verify_digest(digest, "AAAAAAAA") is False
        assert signing.verify_digest(digest, "not-base64-at-all!!!") is False

    def test_sign_rejects_non_hex_digest(self, tmp_path, monkeypatch):
        signing = _reload_signing(tmp_path, monkeypatch)
        with pytest.raises(ValueError):
            signing.sign_digest("not-hex")

    def test_sign_rejects_wrong_length_digest(self, tmp_path, monkeypatch):
        signing = _reload_signing(tmp_path, monkeypatch)
        # Hex but not 32 bytes
        short = "ab" * 16  # 16 bytes
        with pytest.raises(ValueError):
            signing.sign_digest(short)

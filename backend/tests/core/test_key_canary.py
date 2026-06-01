# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Credential key-canary: the startup guard that detects a changed SECRET_KEY
before the app silently re-encrypts new secrets under a key that can't read the
old ones (the exact failure a wrong env-file recreate caused).

``verify_blobs`` tries to decrypt stored credential blobs with the CURRENT key:
- a single corrupt blob does NOT trip a mismatch (if any decrypt → ok),
- only when encrypted creds exist and NONE decrypt is it a 'mismatch',
- plaintext / non-encrypted values are skipped.
"""
from __future__ import annotations

from app.core.crypto import encrypt_credential, encrypt_dict, verify_blobs

# A string that LOOKS like a Fernet token (passes is_encrypted) but is invalid.
_BAD_TOKEN = "gAAAAA" + "A" * 120
_BAD_DICT = {"_encrypted": _BAD_TOKEN}


def test_empty_is_empty() -> None:
    assert verify_blobs([])["status"] == "empty"
    # plaintext-only values are skipped → still nothing key-dependent to check.
    assert verify_blobs(["plain", {"host": "x"}, ""])["status"] == "empty"


def test_valid_token_ok() -> None:
    r = verify_blobs([encrypt_credential("super-secret")])
    assert r["status"] == "ok" and r["ok"] == 1 and r["failed"] == 0


def test_valid_dict_ok() -> None:
    r = verify_blobs([encrypt_dict({"api_key": "k", "api_secret": "s"})])
    assert r["status"] == "ok" and r["ok"] == 1


def test_all_invalid_is_mismatch() -> None:
    r = verify_blobs([_BAD_TOKEN, _BAD_DICT])
    assert r["status"] == "mismatch" and r["ok"] == 0 and r["failed"] == 2


def test_single_corruption_is_not_a_mismatch() -> None:
    # A key change breaks EVERY cred; one bad blob among good ones is isolated
    # corruption, not a key mismatch → must NOT refuse boot.
    r = verify_blobs([encrypt_credential("ok"), _BAD_TOKEN])
    assert r["status"] == "ok" and r["ok"] == 1 and r["failed"] == 1


def test_plaintext_skipped_among_encrypted() -> None:
    r = verify_blobs(["plaintext", encrypt_credential("ok"), {"host": "h"}])
    assert r["status"] == "ok" and r["encrypted"] == 1

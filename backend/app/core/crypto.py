# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Credential Encryption
=====================================

Fernet symmetric encryption for storing sensitive credentials.

Derives a 256-bit key from the application SECRET_KEY via PBKDF2.
All passwords, tokens, and secrets at rest are encrypted with this key.

Usage::

    from app.core.crypto import encrypt_credential, decrypt_credential

    cipher = encrypt_credential("my-password")     # -> base64 token
    plain  = decrypt_credential(cipher)             # -> "my-password"
"""

from __future__ import annotations

import base64
import hashlib
import logging
from typing import Any

from cryptography.fernet import Fernet, InvalidToken

logger = logging.getLogger("freesdn.crypto")

# Module-level Fernet instance — initialized lazily
_fernet: Fernet | None = None


def _get_fernet() -> Fernet:
    """Derive Fernet key from SECRET_KEY (cached)."""
    global _fernet
    if _fernet is None:
        from app.core.config import settings

        # PBKDF2 to produce exactly 32 bytes for Fernet
        dk = hashlib.pbkdf2_hmac(
            "sha256",
            settings.SECRET_KEY.encode("utf-8"),
            settings.ENCRYPTION_SALT.encode("utf-8"),
            iterations=260_000,  # OWASP 2024 recommendation
        )
        key = base64.urlsafe_b64encode(dk[:32])
        _fernet = Fernet(key)
    return _fernet


def encrypt_credential(plaintext: str) -> str:
    """
    Encrypt a credential string and return a base64 Fernet token.

    Returns an opaque string safe for database storage.
    """
    if not plaintext:
        return ""
    return _get_fernet().encrypt(plaintext.encode("utf-8")).decode("ascii")


def decrypt_credential(ciphertext: str) -> str:
    """
    Decrypt a Fernet token back to plaintext.

    Raises ValueError if the token is invalid or corrupted.
    """
    if not ciphertext:
        return ""
    try:
        return _get_fernet().decrypt(ciphertext.encode("ascii")).decode("utf-8")
    except InvalidToken:
        logger.error("Failed to decrypt credential — token invalid or key changed")
        raise ValueError("Cannot decrypt credential — encryption key may have changed")


def verify_blobs(blobs: list[Any]) -> dict[str, Any]:
    """Key-canary: try to decrypt a list of stored credential blobs with the
    CURRENT key, to detect a changed ``SECRET_KEY`` before the app re-encrypts
    new secrets under a key that can't read the old ones.

    Each blob is either a Fernet token ``str`` or an ``{"_encrypted": ...}``
    dict. Plaintext / non-encrypted values are skipped (not key-dependent).

    Returns ``{encrypted, ok, failed, status}`` where ``status`` is:

    * ``"empty"``    — nothing encrypted to check (fresh system / no creds).
    * ``"mismatch"`` — encrypted creds exist but NONE decrypt → key changed.
      (A single corrupt blob does NOT trip this: if *any* decrypt, status is ok.)
    * ``"ok"``       — at least one encrypted cred decrypts with the current key.
    """
    ok = fail = 0
    for blob in blobs:
        try:
            if isinstance(blob, dict):
                if "_encrypted" not in blob:
                    continue  # plaintext dict — not key-dependent
                decrypt_dict(blob)
            elif isinstance(blob, str):
                if not is_encrypted(blob):
                    continue  # plaintext / empty — not key-dependent
                decrypt_credential(blob)
            else:
                continue
            ok += 1
        except Exception:  # noqa: BLE001 — any decrypt failure counts as a miss
            fail += 1
    total = ok + fail
    status = "empty" if total == 0 else ("mismatch" if ok == 0 else "ok")
    return {"encrypted": total, "ok": ok, "failed": fail, "status": status}


def is_encrypted(value: str) -> bool:
    """
    Heuristic: check if a string looks like a Fernet token.

    Fernet tokens are base64-encoded, start with 'gAAAAA', and are 100+ chars.
    """
    if not value or len(value) < 100:
        return False
    return value.startswith("gAAAAA")


# ═══════════════════════════════════════════════════════════════════════════════
# Dict-level encryption (for JSONB credential columns)
# ═══════════════════════════════════════════════════════════════════════════════

import json


def encrypt_dict(data: dict[str, Any]) -> dict[str, Any]:
    """Encrypt a plain dict → ``{"_encrypted": "<fernet token>"}``.

    Returns the input unchanged if it's already encrypted.
    """
    if not data:
        return data
    if "_encrypted" in data:
        return data  # already encrypted
    plaintext = json.dumps(data, separators=(",", ":")).encode("utf-8")
    token = _get_fernet().encrypt(plaintext).decode("ascii")
    return {"_encrypted": token}


def decrypt_dict(data: dict[str, Any]) -> dict[str, Any]:
    """Decrypt ``{"_encrypted": "<fernet token>"}`` → original dict.

    If the dict has no ``_encrypted`` key, return as-is for backwards
    compatibility with existing unencrypted rows.
    """
    if not data or "_encrypted" not in data:
        return data  # plaintext — backwards compatible
    try:
        plaintext = _get_fernet().decrypt(data["_encrypted"].encode("ascii"))
        result: dict[str, Any] = json.loads(plaintext)
        return result
    except (InvalidToken, Exception) as exc:
        logger.error("Failed to decrypt credential dict: %s", type(exc).__name__)
        raise ValueError("Cannot decrypt credential dict — encryption key may have changed")

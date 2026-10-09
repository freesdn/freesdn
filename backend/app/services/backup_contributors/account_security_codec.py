# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Bounded portable account-secret primitives for the proposed core v2 format.

PRIVATE, not integrated or runtime qualified. These helpers do not authorize
export, validate ownership/provider bindings, encrypt data, or restore accounts.
The caller must validate the complete record before using these primitives.
Never authenticate an archive-supplied hash to decide whether it is safe.
"""

from __future__ import annotations

import base64
import binascii
import json
import re


class AccountSecurityFormatError(ValueError):
    """Fixed, secret-free diagnostic for an unsupported security record."""


# FreeSDN's current and documented previous password configuration is Argon2id
# v19, m=65536 KiB, t=3, p=4, with 16-byte salt and 32-byte output. This is an
# explicit supported profile, not acceptance of arbitrary work factors. A
# different historical profile requires review and explicit support.
_ARGON2_PROFILE = re.compile(
    r"\A\$argon2id\$v=19\$m=65536,t=3,p=4\$([A-Za-z0-9+/]{22})\$([A-Za-z0-9+/]{43})\Z"
)
_SEED = re.compile(r"\A[A-Z2-7]{32}\Z")
_MAX_CODES = 10  # Actual /auth/mfa/setup output; consumed lists can be smaller.
_MAX_CODES_JSON_BYTES = 4096


def require_argon2_hash(value: object) -> str:
    """Check one supported PHC encoding without invoking the hash verifier.

    Inputs are length-bounded before regex/base64 decoding. Canonical unpadded
    base64 rules reject invalid trailing bits rather than silently normalizing
    an imported credential. The original valid encoded value is preserved.
    """
    if not isinstance(value, str) or len(value) > 255:
        raise AccountSecurityFormatError("Unsupported account password or recovery-code hash.")
    match = _ARGON2_PROFILE.fullmatch(value)
    if match is None:
        raise AccountSecurityFormatError("Unsupported account password or recovery-code hash.")
    for encoded, size in zip(match.groups(), (16, 32), strict=True):
        try:
            decoded = base64.b64decode(encoded + "=" * (-len(encoded) % 4), validate=True)
        except (ValueError, binascii.Error):
            raise AccountSecurityFormatError("Invalid account hash encoding.") from None
        if len(decoded) != size or base64.b64encode(decoded).decode().rstrip("=") != encoded:
            raise AccountSecurityFormatError("Invalid account hash encoding.")
    return value


def require_password_hash(
    value: object,
    *,
    active: bool,
    external_binding_validated: bool,
) -> str:
    """Accept an explicit unusable marker only with its validated account mode.

    `external_binding_validated` must mean the complete external protocol,
    subject and provider ownership/reference were checked by the caller. It
    must never be obtained by coercing a nonempty archive field to bool.
    """
    if type(active) is not bool or type(external_binding_validated) is not bool:
        raise AccountSecurityFormatError("Invalid account authentication mode.")
    if value == "!SSO_MANAGED":
        if external_binding_validated:
            return value
        raise AccountSecurityFormatError(
            "External account marker requires a valid provider binding."
        )
    if value == "!":
        if not active and not external_binding_validated:
            return value
        raise AccountSecurityFormatError("Disabled profile marker cannot enable an account.")
    return require_argon2_hash(value)


def require_portable_seed(value: object) -> str | None:
    """Validate plaintext seed material only inside a passphrase-sealed payload.

    Encryption/decryption belongs at the source/destination field boundary.
    In particular, source `fernet:` ciphertext is not a portable seed. None
    remains None; consistency with enabled/pending state is a caller duty.
    """
    if value is None:
        return None
    if not isinstance(value, str) or _SEED.fullmatch(value) is None:
        raise AccountSecurityFormatError("Unsupported portable MFA seed.")
    try:
        decoded = base64.b32decode(value, casefold=False)
    except (ValueError, binascii.Error):
        raise AccountSecurityFormatError("Invalid portable MFA seed encoding.") from None
    if len(decoded) != 20 or base64.b32encode(decoded).decode() != value:
        raise AccountSecurityFormatError("Invalid portable MFA seed encoding.")
    return value


def require_backup_code_hashes(value: object) -> list[str] | None:
    """Parse the actual stored JSON hash list with bounded input and work.

    Preserve the distinction between no configured list and an empty consumed
    list. No plaintext code is hashed and no existing hash is authenticated.
    """
    if value is None:
        return None
    if not isinstance(value, str) or len(value) > _MAX_CODES_JSON_BYTES:
        raise AccountSecurityFormatError("Invalid MFA recovery-code list.")
    try:
        encoded_bytes = value.encode("utf-8")
    except UnicodeError:
        raise AccountSecurityFormatError("Invalid MFA recovery-code list.") from None
    if len(encoded_bytes) > _MAX_CODES_JSON_BYTES:
        raise AccountSecurityFormatError("Invalid MFA recovery-code list.")
    try:
        items = json.loads(value)
    except (ValueError, RecursionError):
        raise AccountSecurityFormatError("Invalid MFA recovery-code list.") from None
    if not isinstance(items, list) or len(items) > _MAX_CODES:
        raise AccountSecurityFormatError("Invalid MFA recovery-code list.")
    validated = [require_argon2_hash(item) for item in items]
    if len(set(validated)) != len(validated):
        raise AccountSecurityFormatError("Duplicate MFA recovery-code hashes.")
    return validated

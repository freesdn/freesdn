# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Security Module
=============================

JWT token generation, password hashing, and authentication utilities.
Uses Argon2id for password hashing and RS256/HS256 for JWT signing.
"""

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import (
    InvalidHashError,
    VerificationError,
    VerifyMismatchError,
)
from jwt.exceptions import PyJWTError

from app.core.config import settings

# Password hashing using Argon2id via argon2-cffi (maintained).
#
# Migration note: replaced passlib.context.CryptContext
# with argon2.PasswordHasher direct. passlib hadn't shipped a release
# since 2020. The output hash format is identical
# (``$argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>``) so all existing
# user password hashes verify with both implementations — verified
# bidirectionally with a cross-compat test before this change.
#
# Parameters match the prior passlib config exactly so newly hashed
# passwords are bit-for-bit identical to what the previous code
# produced for the same input + salt.
_PH = PasswordHasher(
    memory_cost=65536,  # 64 MB
    time_cost=3,
    parallelism=4,
)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plain password against an Argon2id hashed password.

    Returns False for any verification failure (mismatch, invalid hash
    format, or unexpected error) — never raises, so callers can use it
    as a boolean gate in auth paths. The previous passlib wrapper had
    the same swallow-everything-to-bool semantics.
    """
    try:
        return bool(_PH.verify(hashed_password, plain_password))
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False
    except Exception:
        # Defensive: any other unexpected error (e.g. malformed hash
        # in DB) → treat as auth failure, don't leak details.
        return False


def get_password_hash(password: str) -> str:
    """Generate Argon2id hash for a password.

    Output format is the standard PHC encoding
    (``$argon2id$v=19$m=65536,t=3,p=4$<salt-b64>$<hash-b64>``) which
    is portable across argon2 implementations.
    """
    return str(_PH.hash(password))


def validate_password(password: str) -> str:
    """
    Canonical password validation function.

    Enforces the password policy defined in application settings:
      - Minimum length (default 12 characters, configurable via PASSWORD_MIN_LENGTH)
      - At least one uppercase letter (when PASSWORD_REQUIRE_UPPERCASE is True)
      - At least one lowercase letter (when PASSWORD_REQUIRE_LOWERCASE is True)
      - At least one digit (when PASSWORD_REQUIRE_DIGIT is True)
      - At least one special character from ``!@#$%^&*()_+-=[]{}|;:,.<>?``
        (when PASSWORD_REQUIRE_SPECIAL is True)

    Args:
        password: The plain-text password to validate.

    Returns:
        The password unchanged if it passes all checks.

    Raises:
        ValueError: With a clear, user-facing message describing every
            requirement that was not met (semicolon-separated).
    """
    errors: list[str] = []

    if len(password) < settings.PASSWORD_MIN_LENGTH:
        errors.append(f"Password must be at least {settings.PASSWORD_MIN_LENGTH} characters")

    if settings.PASSWORD_REQUIRE_UPPERCASE and not any(c.isupper() for c in password):
        errors.append("Password must contain at least one uppercase letter")

    if settings.PASSWORD_REQUIRE_LOWERCASE and not any(c.islower() for c in password):
        errors.append("Password must contain at least one lowercase letter")

    if settings.PASSWORD_REQUIRE_DIGIT and not any(c.isdigit() for c in password):
        errors.append("Password must contain at least one digit")

    if settings.PASSWORD_REQUIRE_SPECIAL:
        special_chars = set("!@#$%^&*()_+-=[]{}|;:,.<>?")
        if not any(c in special_chars for c in password):
            errors.append("Password must contain at least one special character")

    if errors:
        raise ValueError("; ".join(errors))

    return password


def validate_password_strength(password: str) -> tuple[bool, list[str]]:
    """
    Validate password meets security requirements.

    .. deprecated::
        Use :func:`validate_password` instead.  This wrapper exists only for
        backward compatibility with call-sites that expect a
        ``(is_valid, errors)`` tuple.

    Returns:
        Tuple of (is_valid, list of error messages)
    """
    try:
        validate_password(password)
        return True, []
    except ValueError as exc:
        return False, str(exc).split("; ")


def verify_totp_single_use(
    secret: str,
    code: str,
    last_step: int | None,
    valid_window: int = 1,
) -> tuple[bool, int | None]:
    """Verify a TOTP code and enforce single-use per timestep (RFC 6238 §5.2).

    Returns ``(is_valid, matched_step)``. ``matched_step`` is the integer
    timestep the code matched; the caller MUST persist it (e.g. into
    ``user.mfa_last_totp_step``) so the same code cannot be replayed within
    its ~90s acceptance window. A code matching a step ``<= last_step`` is
    rejected as a replay. On no match, returns ``(False, None)``.

    ``secret`` is the already-decrypted base32 TOTP secret. Mirrors the
    previous ``totp.verify(code, valid_window=1)`` acceptance window but adds
    the consumed-step check that the bare verify lacked.
    """
    import pyotp

    totp = pyotp.TOTP(secret)
    now = datetime.now(UTC)
    for offset in range(-valid_window, valid_window + 1):
        t = now + timedelta(seconds=offset * totp.interval)
        if totp.verify(code, for_time=t):  # exact-step check (valid_window=0)
            step = totp.timecode(t)
            if last_step is not None and step <= last_step:
                return False, None  # replay of an already-consumed timestep
            return True, step
    return False, None


def create_access_token(
    subject: str | int,
    expires_delta: timedelta | None = None,
    extra_claims: dict[str, Any] | None = None,
    token_version: int = 0,
) -> str:
    """
    Create a JWT access token.

    Args:
        subject: The token subject (typically user ID)
        expires_delta: Optional custom expiration time
        extra_claims: Additional claims to include in token
        token_version: User's current token version for session invalidation

    Returns:
        Encoded JWT token string
    """
    if expires_delta:
        expire = datetime.now(UTC) + expires_delta
    else:
        expire = datetime.now(UTC) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode = {
        "sub": str(subject),
        "exp": expire,
        "iat": datetime.now(UTC),
        "type": "access",
        "iss": "freesdn",
        "aud": "freesdn-api",
        "jti": str(uuid.uuid4()),
        "tv": token_version,
    }

    if extra_claims:
        to_encode.update(extra_claims)

    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def create_refresh_token(
    subject: str | int,
    expires_delta: timedelta | None = None,
    token_version: int = 0,
    extra_claims: dict[str, Any] | None = None,
) -> str:
    """
    Create a JWT refresh token.

    Args:
        subject: The token subject (typically user ID)
        expires_delta: Optional custom expiration time
        token_version: User's current token version for session invalidation
        extra_claims: Additional claims (e.g. ``{"rmb": True}`` to mark a
            "remember me" session so its long window is preserved on rotation)

    Returns:
        Encoded JWT refresh token string
    """
    if expires_delta:
        expire = datetime.now(UTC) + expires_delta
    else:
        expire = datetime.now(UTC) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)

    to_encode = {
        "sub": str(subject),
        "exp": expire,
        "iat": datetime.now(UTC),
        "type": "refresh",
        "iss": "freesdn",
        "aud": "freesdn-api",
        "jti": str(uuid.uuid4()),
        "tv": token_version,
    }

    if extra_claims:
        to_encode.update(extra_claims)

    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


async def decode_token(token: str) -> dict[str, Any] | None:
    """
    Decode and validate a JWT token, checking the revocation blacklist.

    Args:
        token: The JWT token string

    Returns:
        Decoded token payload or None if invalid / revoked
    """
    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM],
            options={"require": ["exp", "iat", "sub"]},
            audience="freesdn-api",
            issuer="freesdn",
        )

        # Check token revocation
        from app.core.token_blacklist import is_token_blacklisted

        jti = payload.get("jti")
        if jti and await is_token_blacklisted(jti):
            return None

        return payload
    except (PyJWTError, KeyError, ValueError):
        return None


async def verify_token(token: str, token_type: str = "access") -> dict[str, Any] | None:
    """
    Verify a JWT token and check its type.

    Args:
        token: The JWT token string
        token_type: Expected token type ("access" or "refresh")

    Returns:
        Decoded token payload or None if invalid
    """
    payload = await decode_token(token)
    if payload is None:
        return None

    if payload.get("type") != token_type:
        return None

    return payload

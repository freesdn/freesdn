# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Tests for FreeSDN authentication: password hashing, JWT tokens, and password validation.

Covers:
  - Password hashing and verification (Argon2id via passlib)
  - JWT access/refresh token creation and claims
  - JWT token verification (valid, expired, invalid, wrong type)
  - Password policy enforcement (min length, uppercase, lowercase, digit, special)
"""

import uuid
from datetime import timedelta
from unittest.mock import AsyncMock, patch

import jwt
import pytest

from app.core.config import settings
from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    get_password_hash,
    validate_password,
    validate_password_strength,
    verify_password,
    verify_token,
)

# =============================================================================
# Password Hashing
# =============================================================================


class TestPasswordHashing:
    """Tests for Argon2id password hashing and verification."""

    def test_verify_password_correct(self):
        password = "SecureP@ssw0rd!"
        hashed = get_password_hash(password)
        assert verify_password(password, hashed) is True

    def test_verify_password_incorrect(self):
        hashed = get_password_hash("SecureP@ssw0rd!")
        assert verify_password("WrongPassword123!", hashed) is False

    def test_verify_password_empty_input(self):
        hashed = get_password_hash("SecureP@ssw0rd!")
        assert verify_password("", hashed) is False

    def test_hash_produces_unique_outputs(self):
        password = "SamePassword123!"
        hash1 = get_password_hash(password)
        hash2 = get_password_hash(password)
        assert hash1 != hash2, "Each hash should use a unique salt"

    def test_hash_is_argon2_format(self):
        hashed = get_password_hash("TestPassword1!")
        assert hashed.startswith("$argon2"), "Hash should be Argon2 format"

    def test_verify_password_with_unicode(self):
        password = "Pas\u00e9w\u00f6rd123!"
        hashed = get_password_hash(password)
        assert verify_password(password, hashed) is True
        assert verify_password("Pasewrd123!", hashed) is False


# =============================================================================
# JWT Access Token Creation
# =============================================================================


class TestCreateAccessToken:
    """Tests for create_access_token."""

    def test_creates_valid_jwt(self):
        token = create_access_token(subject="user-123")
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM],
            audience="freesdn-api",
            issuer="freesdn",
        )
        assert payload["sub"] == "user-123"

    def test_contains_expected_claims(self):
        token = create_access_token(subject="user-456")
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM],
            audience="freesdn-api",
            issuer="freesdn",
        )
        assert payload["sub"] == "user-456"
        assert payload["type"] == "access"
        assert payload["iss"] == "freesdn"
        assert payload["aud"] == "freesdn-api"
        assert "exp" in payload
        assert "iat" in payload
        assert "jti" in payload

    def test_jti_is_unique_per_token(self):
        t1 = create_access_token(subject="user-1")
        t2 = create_access_token(subject="user-1")
        p1 = jwt.decode(t1, settings.SECRET_KEY, algorithms=[settings.ALGORITHM],
                         audience="freesdn-api", issuer="freesdn")
        p2 = jwt.decode(t2, settings.SECRET_KEY, algorithms=[settings.ALGORITHM],
                         audience="freesdn-api", issuer="freesdn")
        assert p1["jti"] != p2["jti"]

    def test_subject_cast_to_string(self):
        token = create_access_token(subject=42)
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM],
            audience="freesdn-api",
            issuer="freesdn",
        )
        assert payload["sub"] == "42"

    def test_custom_expiration(self):
        token = create_access_token(
            subject="user-1", expires_delta=timedelta(minutes=5)
        )
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM],
            audience="freesdn-api",
            issuer="freesdn",
        )
        # exp - iat should be ~300 seconds
        diff = payload["exp"] - payload["iat"]
        assert 290 <= diff <= 310

    def test_extra_claims_included(self):
        token = create_access_token(
            subject="user-1",
            extra_claims={"role": "admin", "org_id": "org-abc"},
        )
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM],
            audience="freesdn-api",
            issuer="freesdn",
        )
        assert payload["role"] == "admin"
        assert payload["org_id"] == "org-abc"


# =============================================================================
# JWT Refresh Token Creation
# =============================================================================


class TestCreateRefreshToken:
    """Tests for create_refresh_token."""

    def test_refresh_token_type_claim(self):
        token = create_refresh_token(subject="user-1")
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM],
            audience="freesdn-api",
            issuer="freesdn",
        )
        assert payload["type"] == "refresh"

    def test_refresh_token_default_expiry(self):
        token = create_refresh_token(subject="user-1")
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM],
            audience="freesdn-api",
            issuer="freesdn",
        )
        diff_seconds = payload["exp"] - payload["iat"]
        expected = settings.REFRESH_TOKEN_EXPIRE_DAYS * 86400
        # Allow 10s tolerance
        assert abs(diff_seconds - expected) < 10

    def test_refresh_token_custom_expiry(self):
        token = create_refresh_token(
            subject="user-1", expires_delta=timedelta(days=1)
        )
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM],
            audience="freesdn-api",
            issuer="freesdn",
        )
        diff = payload["exp"] - payload["iat"]
        assert 86390 <= diff <= 86410


# =============================================================================
# JWT Token Verification (decode_token / verify_token)
# =============================================================================


class TestTokenVerification:
    """Tests for decode_token and verify_token."""

    @pytest.mark.asyncio
    @patch("app.core.token_blacklist.is_token_blacklisted", new_callable=AsyncMock, return_value=False)
    async def test_decode_valid_access_token(self, mock_blacklist):
        token = create_access_token(subject="user-99")
        payload = await decode_token(token)
        assert payload is not None
        assert payload["sub"] == "user-99"
        assert payload["type"] == "access"

    @pytest.mark.asyncio
    @patch("app.core.token_blacklist.is_token_blacklisted", new_callable=AsyncMock, return_value=False)
    async def test_verify_access_token(self, mock_blacklist):
        token = create_access_token(subject="user-1")
        payload = await verify_token(token, token_type="access")
        assert payload is not None
        assert payload["sub"] == "user-1"

    @pytest.mark.asyncio
    @patch("app.core.token_blacklist.is_token_blacklisted", new_callable=AsyncMock, return_value=False)
    async def test_verify_refresh_token(self, mock_blacklist):
        token = create_refresh_token(subject="user-1")
        payload = await verify_token(token, token_type="refresh")
        assert payload is not None
        assert payload["type"] == "refresh"

    @pytest.mark.asyncio
    @patch("app.core.token_blacklist.is_token_blacklisted", new_callable=AsyncMock, return_value=False)
    async def test_verify_wrong_token_type_returns_none(self, mock_blacklist):
        access_token = create_access_token(subject="user-1")
        result = await verify_token(access_token, token_type="refresh")
        assert result is None

    @pytest.mark.asyncio
    @patch("app.core.token_blacklist.is_token_blacklisted", new_callable=AsyncMock, return_value=False)
    async def test_verify_refresh_as_access_returns_none(self, mock_blacklist):
        refresh_token = create_refresh_token(subject="user-1")
        result = await verify_token(refresh_token, token_type="access")
        assert result is None

    @pytest.mark.asyncio
    async def test_decode_expired_token_returns_none(self):
        token = create_access_token(
            subject="user-1", expires_delta=timedelta(seconds=-1)
        )
        result = await decode_token(token)
        assert result is None

    @pytest.mark.asyncio
    async def test_decode_invalid_token_returns_none(self):
        result = await decode_token("not.a.valid.jwt.token")
        assert result is None

    @pytest.mark.asyncio
    async def test_decode_empty_string_returns_none(self):
        result = await decode_token("")
        assert result is None

    @pytest.mark.asyncio
    async def test_decode_token_wrong_secret_returns_none(self):
        payload = {
            "sub": "user-1",
            "exp": 9999999999,
            "iat": 1700000000,
            "type": "access",
            "iss": "freesdn",
            "aud": "freesdn-api",
            "jti": str(uuid.uuid4()),
        }
        token = jwt.encode(payload, "wrong-secret-key", algorithm="HS256")
        result = await decode_token(token)
        assert result is None

    @pytest.mark.asyncio
    async def test_decode_token_wrong_issuer_returns_none(self):
        payload = {
            "sub": "user-1",
            "exp": 9999999999,
            "iat": 1700000000,
            "type": "access",
            "iss": "not-freesdn",
            "aud": "freesdn-api",
            "jti": str(uuid.uuid4()),
        }
        token = jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
        result = await decode_token(token)
        assert result is None

    @pytest.mark.asyncio
    async def test_decode_token_wrong_audience_returns_none(self):
        payload = {
            "sub": "user-1",
            "exp": 9999999999,
            "iat": 1700000000,
            "type": "access",
            "iss": "freesdn",
            "aud": "wrong-audience",
            "jti": str(uuid.uuid4()),
        }
        token = jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
        result = await decode_token(token)
        assert result is None

    @pytest.mark.asyncio
    async def test_decode_token_missing_sub_returns_none(self):
        payload = {
            "exp": 9999999999,
            "iat": 1700000000,
            "type": "access",
            "iss": "freesdn",
            "aud": "freesdn-api",
            "jti": str(uuid.uuid4()),
        }
        token = jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
        result = await decode_token(token)
        assert result is None

    @pytest.mark.asyncio
    @patch("app.core.token_blacklist.is_token_blacklisted", new_callable=AsyncMock, return_value=True)
    async def test_decode_blacklisted_token_returns_none(self, mock_blacklist):
        token = create_access_token(subject="user-1")
        result = await decode_token(token)
        assert result is None


# =============================================================================
# Password Validation Policy
# =============================================================================


class TestPasswordValidation:
    """Tests for validate_password and validate_password_strength."""

    @patch.object(settings, "PASSWORD_MIN_LENGTH", 12)
    @patch.object(settings, "PASSWORD_REQUIRE_UPPERCASE", True)
    @patch.object(settings, "PASSWORD_REQUIRE_LOWERCASE", True)
    @patch.object(settings, "PASSWORD_REQUIRE_DIGIT", True)
    @patch.object(settings, "PASSWORD_REQUIRE_SPECIAL", True)
    def test_valid_password_passes(self):
        result = validate_password("MySecure1Pass!")
        assert result == "MySecure1Pass!"

    @patch.object(settings, "PASSWORD_MIN_LENGTH", 12)
    def test_too_short_raises_valueerror(self):
        with pytest.raises(ValueError, match="at least 12 characters"):
            validate_password("Ab1!")

    @patch.object(settings, "PASSWORD_MIN_LENGTH", 4)
    @patch.object(settings, "PASSWORD_REQUIRE_UPPERCASE", True)
    @patch.object(settings, "PASSWORD_REQUIRE_LOWERCASE", False)
    @patch.object(settings, "PASSWORD_REQUIRE_DIGIT", False)
    @patch.object(settings, "PASSWORD_REQUIRE_SPECIAL", False)
    def test_missing_uppercase_raises_valueerror(self):
        with pytest.raises(ValueError, match="uppercase"):
            validate_password("nouppercase1!")

    @patch.object(settings, "PASSWORD_MIN_LENGTH", 4)
    @patch.object(settings, "PASSWORD_REQUIRE_UPPERCASE", False)
    @patch.object(settings, "PASSWORD_REQUIRE_LOWERCASE", True)
    @patch.object(settings, "PASSWORD_REQUIRE_DIGIT", False)
    @patch.object(settings, "PASSWORD_REQUIRE_SPECIAL", False)
    def test_missing_lowercase_raises_valueerror(self):
        with pytest.raises(ValueError, match="lowercase"):
            validate_password("NOLOWERCASE1!")

    @patch.object(settings, "PASSWORD_MIN_LENGTH", 4)
    @patch.object(settings, "PASSWORD_REQUIRE_UPPERCASE", False)
    @patch.object(settings, "PASSWORD_REQUIRE_LOWERCASE", False)
    @patch.object(settings, "PASSWORD_REQUIRE_DIGIT", True)
    @patch.object(settings, "PASSWORD_REQUIRE_SPECIAL", False)
    def test_missing_digit_raises_valueerror(self):
        with pytest.raises(ValueError, match="digit"):
            validate_password("NoDigitHere!")

    @patch.object(settings, "PASSWORD_MIN_LENGTH", 4)
    @patch.object(settings, "PASSWORD_REQUIRE_UPPERCASE", False)
    @patch.object(settings, "PASSWORD_REQUIRE_LOWERCASE", False)
    @patch.object(settings, "PASSWORD_REQUIRE_DIGIT", False)
    @patch.object(settings, "PASSWORD_REQUIRE_SPECIAL", True)
    def test_missing_special_char_raises_valueerror(self):
        with pytest.raises(ValueError, match="special character"):
            validate_password("NoSpecialChar1")

    @patch.object(settings, "PASSWORD_MIN_LENGTH", 12)
    @patch.object(settings, "PASSWORD_REQUIRE_UPPERCASE", True)
    @patch.object(settings, "PASSWORD_REQUIRE_LOWERCASE", True)
    @patch.object(settings, "PASSWORD_REQUIRE_DIGIT", True)
    @patch.object(settings, "PASSWORD_REQUIRE_SPECIAL", True)
    def test_multiple_violations_reported_together(self):
        with pytest.raises(ValueError) as exc_info:
            validate_password("short")
        msg = str(exc_info.value)
        assert "at least 12 characters" in msg
        assert "uppercase" in msg
        assert "digit" in msg
        assert "special character" in msg

    @patch.object(settings, "PASSWORD_MIN_LENGTH", 4)
    @patch.object(settings, "PASSWORD_REQUIRE_UPPERCASE", False)
    @patch.object(settings, "PASSWORD_REQUIRE_LOWERCASE", False)
    @patch.object(settings, "PASSWORD_REQUIRE_DIGIT", False)
    @patch.object(settings, "PASSWORD_REQUIRE_SPECIAL", False)
    def test_all_requirements_disabled_accepts_anything(self):
        result = validate_password("abcd")
        assert result == "abcd"

    def test_validate_password_strength_compat_valid(self):
        """validate_password_strength returns (True, []) for a valid password."""
        with patch.object(settings, "PASSWORD_MIN_LENGTH", 4), \
             patch.object(settings, "PASSWORD_REQUIRE_UPPERCASE", False), \
             patch.object(settings, "PASSWORD_REQUIRE_LOWERCASE", False), \
             patch.object(settings, "PASSWORD_REQUIRE_DIGIT", False), \
             patch.object(settings, "PASSWORD_REQUIRE_SPECIAL", False):
            is_valid, errors = validate_password_strength("test")
            assert is_valid is True
            assert errors == []

    def test_validate_password_strength_compat_invalid(self):
        """validate_password_strength returns (False, [messages]) for weak password."""
        with patch.object(settings, "PASSWORD_MIN_LENGTH", 20):
            is_valid, errors = validate_password_strength("short")
            assert is_valid is False
            assert len(errors) > 0
            assert any("20 characters" in e for e in errors)

    @patch.object(settings, "PASSWORD_MIN_LENGTH", 8)
    @patch.object(settings, "PASSWORD_REQUIRE_UPPERCASE", True)
    @patch.object(settings, "PASSWORD_REQUIRE_LOWERCASE", True)
    @patch.object(settings, "PASSWORD_REQUIRE_DIGIT", True)
    @patch.object(settings, "PASSWORD_REQUIRE_SPECIAL", True)
    def test_each_special_char_accepted(self):
        """Every character in the documented special-char set is accepted."""
        special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        for ch in special_chars:
            pw = f"Abcdefg1{ch}"
            result = validate_password(pw)
            assert result == pw, f"Special char '{ch}' should be accepted"

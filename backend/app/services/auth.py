# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Authentication Service
=====================================

Handles user authentication, session management, and security operations.
"""

import logging
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.config import settings
from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    get_password_hash,
    validate_password_strength,
    verify_password,
    verify_totp_single_use,
)
from app.core.security_utils import decrypt_field, encrypt_field
from app.models import User

logger = logging.getLogger(__name__)


# =============================================================================
# Exceptions
# =============================================================================


class AuthError(Exception):
    """Base authentication error."""

    def __init__(self, message: str, code: str = "auth_error"):
        self.message = message
        self.code = code
        super().__init__(message)


class InvalidCredentialsError(AuthError):
    """Invalid email or password."""

    def __init__(self) -> None:
        super().__init__("Invalid email or password", "invalid_credentials")


class AccountLockedError(AuthError):
    """Account is locked due to too many failed attempts."""

    def __init__(self, until: datetime) -> None:
        self.locked_until = until
        super().__init__(f"Account is locked until {until.isoformat()}", "account_locked")


class AccountDisabledError(AuthError):
    """Account is disabled or inactive."""

    def __init__(self) -> None:
        super().__init__("Account is disabled", "account_disabled")


class MFARequiredError(AuthError):
    """MFA verification required to complete login."""

    def __init__(self, mfa_token: str) -> None:
        self.mfa_token = mfa_token
        super().__init__("MFA verification required", "mfa_required")


class MFAInvalidError(AuthError):
    """Invalid MFA code provided."""

    def __init__(self) -> None:
        super().__init__("Invalid MFA code", "mfa_invalid")


class TokenExpiredError(AuthError):
    """Token has expired."""

    def __init__(self) -> None:
        super().__init__("Token has expired", "token_expired")


class TokenInvalidError(AuthError):
    """Token is invalid or malformed."""

    def __init__(self) -> None:
        super().__init__("Invalid token", "token_invalid")


class PasswordTooWeakError(AuthError):
    """Password doesn't meet security requirements."""

    def __init__(self, errors: list[str]):
        self.errors = errors
        super().__init__(f"Password too weak: {', '.join(errors)}", "password_too_weak")


# =============================================================================
# Configuration
# =============================================================================

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION_MINUTES = 30


# NOTE: pre-computed Argon2id hash for timing-safe login failure on
# every "no real verify happens" branch (no user / locked / disabled). The
# value is computed lazily at import time using the configured Argon2
# parameters so the failure timing matches a real password check.
_DUMMY_HASH: str = get_password_hash("this-is-not-a-real-password-its-a-timing-decoy")


def _hash_for_log(value: str) -> str:
    """Return a stable short hash of a sensitive value for log correlation.

    NOTE: we never want to log raw email addresses on failed-login branches —
    the log stream would become an account-enumeration oracle for anyone
    with log-read access. A truncated SHA-256 lets ops correlate repeated
    attempts against the same identifier without exposing the identifier
    itself.
    """
    import hashlib

    return hashlib.sha256(value.lower().encode("utf-8")).hexdigest()[:16]


# =============================================================================
# Data Classes
# =============================================================================


class TokenPair:
    """Access and refresh token pair."""

    def __init__(
        self,
        access_token: str,
        refresh_token: str,
        token_type: str = "bearer",
        expires_in: int = 900,  # 15 minutes
    ):
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.token_type = token_type
        self.expires_in = expires_in


class AuthResult:
    """Authentication result."""

    def __init__(
        self,
        user: User,
        tokens: TokenPair,
        require_mfa: bool = False,
        force_password_change: bool = False,
    ):
        self.user = user
        self.tokens = tokens
        self.require_mfa = require_mfa
        self.force_password_change = force_password_change


# =============================================================================
# Auth Service
# =============================================================================


class AuthService:
    """
    Authentication service for user login/logout and session management.

    Features:
    - Email/password authentication
    - JWT access and refresh tokens
    - Account lockout after failed attempts
    - MFA support (TOTP)
    - Session tracking
    - Password strength validation
    """

    def __init__(self, db: AsyncSession):
        self.db = db

    # =========================================================================
    # Authentication
    # =========================================================================

    async def authenticate(
        self,
        email: str,
        password: str,
        mfa_code: str | None = None,
        remember_me: bool = False,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> AuthResult:
        """
        Authenticate a user with email and password.

        Args:
            email: User email address
            password: Plain text password
            mfa_code: Optional MFA code if enabled
            remember_me: Extend token expiration
            ip_address: Client IP for audit
            user_agent: Client user agent for audit

        Returns:
            AuthResult with user and tokens

        Raises:
            InvalidCredentialsError: Invalid email or password
            AccountLockedError: Account is locked
            AccountDisabledError: Account is disabled
            MFARequiredError: MFA verification needed
            MFAInvalidError: Invalid MFA code
        """
        # Find user by email
        result = await self.db.execute(
            select(User)
            .options(selectinload(User.organization))
            .where(User.email == email.lower())
            .where(User.deleted_at.is_(None))
        )
        user = result.scalar_one_or_none()

        # NOTE: collapse every failure path
        # to a single generic InvalidCredentialsError. Previously this
        # method raised AccountLockedError / AccountDisabledError BEFORE
        # the password was verified, which let an attacker enumerate
        # locked / disabled accounts (timing AND distinct exception
        # classes leaked the account state). Now all "real" reasons are
        # logged server-side via logger.warning, and the caller sees the
        # same error whether the email exists, is wrong, is locked, or
        # is disabled.
        if not user:
            # NOTE: mirror the endpoint's _dummy_verify pattern —
            # run Argon2 verify against a fixed bogus hash so timing on
            # the "no such user" branch matches the "wrong password"
            # branch, defeating account-existence enumeration via timing.
            try:
                verify_password(password, _DUMMY_HASH)
            except Exception:
                pass
            logger.warning(
                "Login attempt for unknown email",
                extra={"email_hash": _hash_for_log(email)},
            )
            raise InvalidCredentialsError()

        # Check if account is locked (log + generic error, do NOT raise
        # AccountLockedError — that leaks account state to the caller).
        if user.locked_until and user.locked_until > datetime.now(UTC):
            logger.warning(
                "Login attempt on locked account",
                extra={"user_id": str(user.id), "locked_until": user.locked_until.isoformat()},
            )
            try:
                verify_password(password, _DUMMY_HASH)
            except Exception:
                pass
            raise InvalidCredentialsError()

        # Check if account is active (same pattern as locked branch).
        if not user.is_active:
            logger.warning(
                "Login attempt on disabled account",
                extra={"user_id": str(user.id)},
            )
            try:
                verify_password(password, _DUMMY_HASH)
            except Exception:
                pass
            raise InvalidCredentialsError()

        # Verify password
        if not verify_password(password, user.hashed_password):
            await self._handle_failed_login(user)
            raise InvalidCredentialsError()

        # Check MFA requirement
        if user.mfa_enabled and user.mfa_secret:
            if not mfa_code:
                # Generate temporary token for MFA flow. Pin aud="freesdn-mfa"
                # (matching the live /login endpoint + /login/mfa verifier) so
                # this challenge token can NEVER be replayed as a full access
                # token even if this service method is wired up later — the
                # default audience is freesdn-api, the same one the central auth
                # dependency accepts (defense-in-depth alongside
                # the type!=access check).
                current_tv = getattr(user, "token_version", 0) or 0
                mfa_token = create_access_token(
                    str(user.id),
                    expires_delta=timedelta(minutes=5),
                    token_version=current_tv,
                    extra_claims={"type": "mfa_pending", "aud": "freesdn-mfa"},
                )
                raise MFARequiredError(mfa_token)

            # Verify MFA code
            if not await self._verify_mfa(user, mfa_code):
                raise MFAInvalidError()

        # Successful login
        return await self._complete_login(
            user=user,
            remember_me=remember_me,
            ip_address=ip_address,
            user_agent=user_agent,
        )

    async def _handle_failed_login(self, user: User) -> None:
        """Handle failed login attempt - increment counter and lock if needed."""
        user.failed_login_attempts = (user.failed_login_attempts or 0) + 1

        if user.failed_login_attempts >= MAX_FAILED_ATTEMPTS:
            user.locked_until = datetime.now(UTC) + timedelta(minutes=LOCKOUT_DURATION_MINUTES)
            # log user_id instead of email so the log stream isn't
            # a free email enumeration oracle for anyone with log read access.
            logger.warning("Account locked", extra={"user_id": str(user.id)})

        await self.db.commit()

    async def _verify_mfa(self, user: User, code: str) -> bool:
        """Verify MFA code (TOTP or backup code)."""
        # single-use per timestep — reject replay of an observed
        # code within its ~90s window.
        totp_ok, matched_step = verify_totp_single_use(
            decrypt_field(user.mfa_secret),  # type: ignore[arg-type]
            code,
            getattr(user, "mfa_last_totp_step", None),
        )
        if totp_ok:
            user.mfa_last_totp_step = matched_step
            await self.db.commit()
            return True

        # NOTE: backup codes are stored as a JSON string of
        # hashed values. Length-prefilter cheap discriminator: TOTP codes
        # are 6 digits, backup codes are 8 hex chars; if the submitted
        # ``code`` length doesn't match the backup-code length, skip
        # straight past the (expensive) Argon2 verify loop.
        if user.mfa_backup_codes and len(code) == 8:
            import json as _json

            try:
                backup_codes_list = _json.loads(user.mfa_backup_codes)
                if not isinstance(backup_codes_list, list):
                    backup_codes_list = []
            except (ValueError, TypeError):
                backup_codes_list = []

            for i, stored_hash in enumerate(backup_codes_list):
                if verify_password(code, stored_hash):
                    # Remove used backup code (one-time use)
                    backup_codes_list.pop(i)
                    user.mfa_backup_codes = _json.dumps(backup_codes_list)  # type: ignore[assignment]
                    await self.db.commit()
                    return True

        return False

    async def _complete_login(
        self,
        user: User,
        remember_me: bool,
        ip_address: str | None,
        user_agent: str | None,
    ) -> AuthResult:
        """Complete login and generate tokens."""
        # Reset failed attempts
        user.failed_login_attempts = 0
        user.locked_until = None
        user.last_login = datetime.now(UTC)

        # Build extra claims
        extra_claims = {
            "org_id": str(user.organization_id) if user.organization_id else None,
            "role": user.role,
        }

        # Token expiration
        access_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        refresh_expires = timedelta(days=7 if remember_me else settings.REFRESH_TOKEN_EXPIRE_DAYS)

        # Create tokens
        token_version = getattr(user, "token_version", 0) or 0
        access_token = create_access_token(
            subject=str(user.id),
            expires_delta=access_expires,
            extra_claims=extra_claims,
            token_version=token_version,
        )
        refresh_token = create_refresh_token(
            subject=str(user.id),
            expires_delta=refresh_expires,
            token_version=token_version,
        )

        await self.db.commit()

        return AuthResult(
            user=user,
            tokens=TokenPair(
                access_token=access_token,
                refresh_token=refresh_token,
                expires_in=int(access_expires.total_seconds()),
            ),
            require_mfa=False,
            force_password_change=False,
        )

    # =========================================================================
    # Token Refresh
    # =========================================================================

    async def refresh_tokens(self, refresh_token: str) -> TokenPair:
        """
        Refresh access token using refresh token.

        Args:
            refresh_token: Valid refresh token

        Returns:
            New TokenPair

        Raises:
            TokenExpiredError: Token has expired
            TokenInvalidError: Token is invalid
        """
        payload = await decode_token(refresh_token)
        if not payload:
            raise TokenInvalidError()

        if payload.get("type") != "refresh":
            raise TokenInvalidError()

        user_id = payload.get("sub")
        if not user_id:
            raise TokenInvalidError()

        # Get user
        result = await self.db.execute(
            select(User)
            .where(User.id == UUID(user_id))
            .where(User.is_active)
            .where(User.deleted_at.is_(None))
        )
        user = result.scalar_one_or_none()

        if not user:
            raise TokenInvalidError()

        current_tv = getattr(user, "token_version", 0) or 0
        if payload.get("tv", 0) != current_tv:
            raise TokenInvalidError()

        old_jti = payload.get("jti")
        old_exp = payload.get("exp")
        if old_jti and old_exp:
            from app.core.token_blacklist import blacklist_token

            await blacklist_token(old_jti, old_exp)

        # Create new tokens
        extra_claims = {
            "org_id": str(user.organization_id) if user.organization_id else None,
            "role": user.role,
        }

        new_access = create_access_token(
            subject=str(user.id),
            extra_claims=extra_claims,
            token_version=current_tv,
        )
        new_refresh = create_refresh_token(subject=str(user.id), token_version=current_tv)

        return TokenPair(
            access_token=new_access,
            refresh_token=new_refresh,
        )

    # =========================================================================
    # Password Management
    # =========================================================================

    async def change_password(
        self,
        user: User,
        current_password: str,
        new_password: str,
    ) -> bool:
        """
        Change user's password.

        Args:
            user: User object
            current_password: Current password for verification
            new_password: New password

        Returns:
            True if successful

        Raises:
            InvalidCredentialsError: Current password is wrong
            PasswordTooWeakError: New password doesn't meet requirements
        """
        # Verify current password
        if not verify_password(current_password, user.hashed_password):
            raise InvalidCredentialsError()

        # Validate new password
        is_valid, errors = validate_password_strength(new_password)
        if not is_valid:
            raise PasswordTooWeakError(errors)

        # Update password
        user.hashed_password = get_password_hash(new_password)
        user.token_version = (getattr(user, "token_version", 0) or 0) + 1
        # SECURITY: revoke API keys so they can't outlive the bump
        from app.models.api_keys import revoke_user_api_keys

        await revoke_user_api_keys(self.db, user.id)

        await self.db.commit()
        return True

    async def reset_password(
        self,
        token: str,
        new_password: str,
    ) -> bool:
        """
        Reset password using reset token.

        Args:
            token: Password reset token
            new_password: New password

        Returns:
            True if successful
        """
        payload = await decode_token(token)
        if not payload or payload.get("type") != "password_reset":
            raise TokenInvalidError()

        reset_jti = payload.get("jti")
        reset_exp = payload.get("exp")
        if reset_jti:
            from app.core.token_blacklist import blacklist_token, is_token_blacklisted

            if await is_token_blacklisted(reset_jti):
                raise TokenInvalidError()
            if reset_exp:
                await blacklist_token(reset_jti, reset_exp)

        user_id = payload.get("sub")
        result = await self.db.execute(
            select(User).where(User.id == UUID(user_id), User.deleted_at.is_(None))
        )
        user = result.scalar_one_or_none()

        if not user:
            raise TokenInvalidError()

        # Validate password
        is_valid, errors = validate_password_strength(new_password)
        if not is_valid:
            raise PasswordTooWeakError(errors)

        user.hashed_password = get_password_hash(new_password)
        user.failed_login_attempts = 0
        user.locked_until = None
        user.token_version = (getattr(user, "token_version", 0) or 0) + 1
        # SECURITY: revoke API keys so they can't outlive the bump
        from app.models.api_keys import revoke_user_api_keys

        await revoke_user_api_keys(self.db, user.id)

        await self.db.commit()
        return True

    # =========================================================================
    # MFA Management
    # =========================================================================

    async def setup_mfa(self, user: User) -> dict[str, Any]:
        """
        Begin MFA enrolment for a user.

        NOTE: this method only PROVISIONS the MFA
        secret + backup codes. It does NOT set ``mfa_enabled = True``.
        The endpoint must call ``confirm_mfa()`` once the user has
        successfully entered a TOTP code from their authenticator app.

        Previously a single ``enable_mfa()`` flipped ``mfa_enabled = True``
        immediately, which meant a user could lock themselves out (e.g.
        scanned the QR into the wrong device) and, more importantly, an
        attacker who hijacked the setup flow could trivially "enable" MFA
        on the victim's account without ever proving possession of the
        TOTP secret.

        Returns:
            Dict with secret, provisioning URI, and one-time backup codes.
        """
        try:
            import pyotp
        except ImportError:
            raise AuthError("MFA not available (pyotp not installed)", "mfa_unavailable")

        # Generate secret
        secret = pyotp.random_base32()

        # Generate backup codes
        backup_codes = [secrets.token_hex(4).upper() for _ in range(10)]
        hashed_codes = [get_password_hash(code) for code in backup_codes]

        user.mfa_secret = encrypt_field(secret)
        # NOTE: the DB column stores a string
        # (json-encoded list). The endpoint at endpoints/auth.py:975 already
        # uses ``json.dumps([...])`` — the service used to assign a raw
        # Python list which the SQLAlchemy column would either reject or
        # silently mangle depending on driver. Mirror the endpoint pattern.
        # TODO: standardize the column type to JSONB in a future migration
        # so this dance is no longer needed.
        import json as _json

        user.mfa_backup_codes = _json.dumps(hashed_codes)  # type: ignore[assignment]
        # NOTE: explicitly DO NOT set mfa_enabled here.

        await self.db.commit()

        # Generate URI for authenticator apps
        totp = pyotp.TOTP(secret)
        uri = totp.provisioning_uri(name=user.email, issuer_name="FreeSDN")

        return {
            "secret": secret,
            "uri": uri,
            "backup_codes": backup_codes,
        }

    async def confirm_mfa(self, user: User, code: str) -> bool:
        """
        Confirm MFA enrolment by verifying a TOTP code from the user's
        authenticator app.

        NOTE: only this method sets ``mfa_enabled = True``, and
        only AFTER the TOTP code verifies. It also bumps ``token_version``
        so any existing access/refresh tokens issued before MFA was
        enabled are invalidated.
        """
        if not user.mfa_secret:
            raise AuthError("MFA setup has not been started", "mfa_not_initialized")

        try:
            import pyotp
        except ImportError:
            raise AuthError("MFA not available (pyotp not installed)", "mfa_unavailable")

        totp = pyotp.TOTP(decrypt_field(user.mfa_secret))  # type: ignore[arg-type]
        if not totp.verify(code, valid_window=1):
            raise MFAInvalidError()

        user.mfa_enabled = True
        # NOTE: bump token_version on MFA confirmation so any
        # access/refresh tokens minted during the pre-MFA window are
        # invalidated. Without this, an attacker who held a pre-MFA
        # access token would still be authenticated AFTER MFA went live.
        user.token_version = (getattr(user, "token_version", 0) or 0) + 1

        await self.db.commit()
        return True

    # NOTE: keep ``enable_mfa`` as a thin alias of ``setup_mfa``
    # for backward compatibility with any caller that still uses the old
    # name. New code must use ``setup_mfa()`` + ``confirm_mfa()``.
    async def enable_mfa(self, user: User) -> dict[str, Any]:
        """Deprecated alias for ``setup_mfa()``.

        Preserved for backward compatibility — new callers should use
        ``setup_mfa()`` (provisioning) + ``confirm_mfa()`` (verification).
        """
        return await self.setup_mfa(user)

    async def disable_mfa(self, user: User, password: str) -> bool:
        """
        Disable MFA for a user (requires password confirmation).
        """
        if not verify_password(password, user.hashed_password):
            raise InvalidCredentialsError()

        user.mfa_enabled = False
        user.mfa_secret = None
        user.mfa_backup_codes = None
        # NOTE: bump token_version on MFA disable so anyone
        # holding a token tied to the MFA-on identity is forced to
        # re-authenticate. Parity with password change.
        user.token_version = (getattr(user, "token_version", 0) or 0) + 1

        await self.db.commit()
        return True

    # =========================================================================
    # User Creation
    # =========================================================================

    async def create_user(
        self,
        email: str,
        password: str,
        username: str | None = None,
        full_name: str | None = None,
        organization_id: UUID | None = None,
        role: str = "viewer",
    ) -> User:
        """
        Create a new user account.
        """
        # Validate password
        is_valid, errors = validate_password_strength(password)
        if not is_valid:
            raise PasswordTooWeakError(errors)

        # Check for existing user
        result = await self.db.execute(select(User).where(User.email == email.lower()))
        if result.scalar_one_or_none():
            raise AuthError("Email already registered", "email_exists")

        user = User(
            email=email.lower(),
            username=username or email.split("@")[0],
            hashed_password=get_password_hash(password),
            full_name=full_name,
            organization_id=organization_id,
            role=role,
            is_active=True,
        )

        self.db.add(user)
        await self.db.commit()
        await self.db.refresh(user)

        return user

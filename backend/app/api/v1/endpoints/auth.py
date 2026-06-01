# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Authentication Endpoints
======================================

JWT-based authentication with access and refresh tokens.
"""

import asyncio
import logging
import time
import uuid as _uuid
from collections import defaultdict
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy import or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.metrics import auth_events_total
from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    get_password_hash,
    validate_password_strength,
    verify_password,
    verify_token,
    verify_totp_single_use,
)
from app.core.security_utils import decrypt_field, encrypt_field
from app.db import get_session
from app.models import User
from app.schemas import (
    BrowserAuthResponse,
    LoginRequest,
    MfaDisableRequest,
    MfaEnableRequest,
    MfaLoginRequest,
    MfaSetupRequest,
    MfaSetupResponse,
    PasswordChangeRequest,
    PasswordResetConfirmSchema,
    PasswordResetRequestSchema,
    ProfileUpdateRequest,
    RefreshTokenRequest,
    RegisterRequest,
    TokenResponse,
    UserResponse,
)

router = APIRouter()

logger = logging.getLogger(__name__)

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl=f"{settings.API_V1_PREFIX}/auth/token",
    auto_error=False,
)


# ═══════════════════════════════════════════════════════════════════════
# Timing-attack mitigation
# ═══════════════════════════════════════════════════════════════════════
# Login-style endpoints must spend the same CPU time whether or not the
# user exists, otherwise an attacker can enumerate valid usernames/emails
# by measuring response latency.  Argon2id with our configured parameters
# takes ~300 ms — plenty of signal if the short-circuit branch returns
# instantly.  We fix this by always running a verify() call against a
# pre-computed dummy hash on the "user is None" / locked / other-failure
# branches.
#
# SECURITY: the dummy hash MUST use the same algorithm and parameters as
# real passwords, so timing is identical.  It is computed lazily on first
# use (not at import time) to avoid a startup-time side channel and to
# dodge circular-import hazards with app.core.security.
_DUMMY_PASSWORD_HASH: str | None = None


def _get_dummy_hash() -> str:
    """Return a pre-computed Argon2id hash for timing-safe login failure.

    The hash is computed once on first call and cached.  Subsequent calls
    reuse the same hash so every timing-safe verify() path does exactly
    the same amount of work as a real password check.
    """
    global _DUMMY_PASSWORD_HASH
    if _DUMMY_PASSWORD_HASH is None:
        # Use the public helper (formerly used the pwd_context global,
        # which the passlib → argon2-cffi migration removed).
        from app.core.security import get_password_hash

        _DUMMY_PASSWORD_HASH = get_password_hash("this-is-a-dummy-password-not-a-real-credential")
    return _DUMMY_PASSWORD_HASH


def _dummy_verify(plain_password: str) -> None:
    """Waste CPU verifying against the dummy hash.

    Called on any login-failure branch where the user does not exist (or
    is locked out, etc.) so attackers cannot distinguish failure modes
    via response-time measurements.  Result is intentionally discarded.
    """
    from app.core.security import verify_password

    # verify_password swallows all exceptions internally and returns a
    # bool; we discard the bool because the GOAL is to spend the time,
    # not to learn the answer.
    verify_password(plain_password, _get_dummy_hash())


# ═══════════════════════════════════════════════════════════════════════
# Auth-specific rate limiting (Redis-backed, per-IP)
# ═══════════════════════════════════════════════════════════════════════
# The global RateLimitMiddleware allows 300 req/min, but login/reset
# endpoints need a much stricter limit to prevent credential stuffing.
# Uses Redis INCR+EXPIRE so the limit works across multiple workers.

_AUTH_RATE_LIMIT = 5  # max attempts per 60-second window per IP
_AUTH_RATE_WINDOW = 60  # seconds

# Per-username sliding window (defence against distributed credential
# stuffing across thousands of IPs). 20 failed attempts per 5 minutes
# keyed on the *username submitted* (NOT a real account) — so it cannot
# be used by an attacker to lock real users out of their accounts; the
# response on lockout is still the generic "invalid credentials" 401 so
# this is not an account-enumeration oracle.
_AUTH_USER_RATE_LIMIT = 20  # max failed attempts per username
_AUTH_USER_RATE_WINDOW = 300  # 5-minute sliding window

_fallback_rate: dict[str, list[float]] = defaultdict(list)
_fallback_user_rate: dict[str, list[float]] = defaultdict(list)
_FALLBACK_MAX = 10000  # max tracked IPs/usernames


def _is_auth_path(path: str | None) -> bool:
    """Return True for the small set of auth-flow paths that must fail
    closed instead of fail-open when Redis is unavailable. Defence against
    a Redis-DoS bypassing credential-stuffing protections."""
    if not path:
        return False
    return path.startswith("/api/v1/auth/") or path == "/api/v1/auth"


async def check_auth_rate_limit(ip: str, path: str | None = None) -> None:
    """Raise 429 if login attempts exceed 5/minute for this IP.

    Uses Redis INCR with TTL so the counter works across all workers.
    When Redis is unavailable on an /auth/* route, fail CLOSED (503)
    rather than silently allowing the request — otherwise an attacker who
    can DoS Redis defeats both the per-IP and per-username credential
    stuffing protections.

    The per-username sliding window is enforced separately by
    ``check_auth_user_rate_limit`` so the failure modes can be reported
    with a generic 401 (preventing user enumeration via 429 oracle).
    """
    try:
        from app.core.redis_client import get_async_redis

        r = get_async_redis(decode_responses=True)
        key = f"auth:ratelimit:{ip}"
        count = await r.incr(key)
        if count == 1:
            # First request in window — set TTL
            await r.expire(key, _AUTH_RATE_WINDOW)
        await r.aclose()

        if count > _AUTH_RATE_LIMIT:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many login attempts. Try again later.",
            )
    except HTTPException:
        raise  # Re-raise 429 as-is
    except Exception:
        # Redis unavailable.
        # SECURITY: credential-stuffing
        # protections must NOT be silently dropped just because Redis is
        # down. For /auth/* routes return 503 so the attacker can't ride
        # past the gate by DoS-ing Redis. For non-auth callers (none in
        # the current codebase, but defence in depth) we still fall back
        # to the in-memory bucket.
        if _is_auth_path(path):
            logger.error(
                "Redis unavailable for auth rate limiting on %s; failing closed",
                path,
            )
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Authentication temporarily unavailable. Please retry shortly.",
            )

        logger.warning("Redis unavailable for auth rate limiting; using in-memory fallback")
        now = time.time()
        timestamps = _fallback_rate[ip]
        # Clean expired entries
        timestamps[:] = [t for t in timestamps if now - t < _AUTH_RATE_WINDOW]
        if len(timestamps) >= _AUTH_RATE_LIMIT:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many login attempts. Try again later.",
            )
        timestamps.append(now)
        # Evict oldest IPs if too many tracked
        if len(_fallback_rate) > _FALLBACK_MAX:
            oldest_ip = min(
                _fallback_rate, key=lambda k: _fallback_rate[k][-1] if _fallback_rate[k] else 0
            )
            del _fallback_rate[oldest_ip]


def _normalize_username(identifier: str) -> str:
    """Lowercased, trimmed username/email used as rate-limit bucket key.

    Bucketing by submitted identifier — NOT by resolved User — so this
    cannot be exploited to lock real accounts out, and so attackers who
    cycle case (Alice / alice / ALICE) all collide into one bucket.
    """
    return (identifier or "").strip().lower()


async def check_auth_user_rate_limit(identifier: str) -> bool:
    """Per-username sliding window for failed-login attempts.

    Returns True if the submitted identifier has exceeded the global
    per-username failure budget (20 fails / 5 min). Callers MUST present
    a generic "invalid credentials" 401 to the user when this returns
    True — never reveal that a rate limit is active, since doing so
    would be an account-existence oracle.

    Counter is decremented (effectively reset) by
    ``reset_auth_user_rate_limit`` on successful authentication.
    Failures are recorded by ``record_auth_user_failure``.
    """
    key = _normalize_username(identifier)
    if not key:
        return False

    try:
        from app.core.redis_client import get_async_redis

        r = get_async_redis(decode_responses=True)
        try:
            now_ts = time.time()
            window_start = now_ts - _AUTH_USER_RATE_WINDOW
            zkey = f"auth:user:{key}:fail_count"
            async with r.pipeline() as pipe:
                pipe.zremrangebyscore(zkey, "-inf", window_start)
                pipe.zcard(zkey)
                results = await pipe.execute()
        finally:
            await r.aclose()
        count = int(results[1] or 0)
        return count >= _AUTH_USER_RATE_LIMIT
    except Exception:
        # Redis down — use in-memory fallback. We intentionally do NOT
        # fail closed here. Failing closed on the per-username bucket
        # would be a remotely-triggerable account lockout (attacker sends
        # 1 request, Redis is down → real user gets 401s for 5 minutes).
        # The per-IP path already fails closed for the /auth/* surface,
        # so total bypass is still prevented.
        now = time.time()
        ts = _fallback_user_rate[key]
        ts[:] = [t for t in ts if now - t < _AUTH_USER_RATE_WINDOW]
        if len(_fallback_user_rate) > _FALLBACK_MAX:
            oldest_user = min(
                _fallback_user_rate,
                key=lambda k: _fallback_user_rate[k][-1] if _fallback_user_rate[k] else 0,
            )
            del _fallback_user_rate[oldest_user]
        return len(ts) >= _AUTH_USER_RATE_LIMIT


async def record_auth_user_failure(identifier: str) -> None:
    """Record a failed-login event in the per-username sliding window."""
    key = _normalize_username(identifier)
    if not key:
        return
    try:
        from app.core.redis_client import get_async_redis

        r = get_async_redis(decode_responses=True)
        try:
            now_ts = time.time()
            zkey = f"auth:user:{key}:fail_count"
            async with r.pipeline() as pipe:
                pipe.zadd(zkey, {f"{now_ts}:{_uuid.uuid4().hex[:8]}": now_ts})
                pipe.expire(zkey, _AUTH_USER_RATE_WINDOW + 60)
                await pipe.execute()
        finally:
            await r.aclose()
    except Exception:
        # Mirror to in-memory bucket so the limit still has some effect
        # while Redis is unreachable.
        now = time.time()
        _fallback_user_rate[key].append(now)


async def reset_auth_user_rate_limit(identifier: str) -> None:
    """Clear the per-username failure window on successful login."""
    key = _normalize_username(identifier)
    if not key:
        return
    try:
        from app.core.redis_client import get_async_redis

        r = get_async_redis(decode_responses=True)
        try:
            await r.delete(f"auth:user:{key}:fail_count")
        finally:
            await r.aclose()
    except Exception:
        pass
    _fallback_user_rate.pop(key, None)


# ═══════════════════════════════════════════════════════════════════════
# Security audit trail (best-effort, decoupled from the auth transaction)
# ═══════════════════════════════════════════════════════════════════════
# The live brute-force / lockout protections (the per-IP and per-username
# Redis windows above, plus the User.locked_until counter) are intentionally
# NOT changed here. These helpers only populate the PERSISTENT forensic trail
# that the Security Audit page reads (FailedLoginRecord / AuditLogRecord) —
# which had no producer at the auth layer, so those views were always empty
# even though protection worked. Each write runs on its OWN short-lived
# session so a forensic-write failure can never break login, and the record
# survives even if the auth transaction itself rolls back.


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


async def _audit_failed_login(
    *, identifier: str, request: Request, reason: str = "invalid_credentials"
) -> None:
    """Persist a FailedLoginRecord for the security audit trail (best-effort)."""
    try:
        from app.db.session import audit_session_factory
        from app.services.security_audit import PersistentSecurityAuditService

        async with audit_session_factory() as s:
            await PersistentSecurityAuditService.record_failed_login(
                s,
                username=(identifier or "")[:255],
                ip_address=_client_ip(request),
                user_agent=request.headers.get("user-agent"),
                reason=reason,
            )
            await s.commit()
    except Exception:
        logger.debug("failed-login forensic write skipped", exc_info=True)


async def _audit_auth_event(
    *,
    action: str,
    request: Request,
    user: User | None = None,
    status_: str = "success",
    method: str = "password",
) -> None:
    """Persist an AuditLogRecord for an auth event (login/logout/password change).

    Best-effort: a write failure is logged at debug and swallowed so it can
    never affect the user-facing auth response.
    """
    try:
        from app.db.session import audit_session_factory
        from app.services.audit import AuditService

        async with audit_session_factory() as s:
            # Route through AuditService.log so auth events join the SAME
            # tamper-evident HMAC hash-chain that every other audit_logs row
            # uses (pg_advisory_xact_lock-serialized); a plain insert here
            # would leave unchained rows in an otherwise-complete chain.
            await AuditService(s).log(
                action=action,
                resource_type="auth_session",
                resource_id=user.id if user else None,
                actor_id=user.id if user else None,
                actor_email=getattr(user, "email", None) if user else None,
                organization_id=getattr(user, "organization_id", None) if user else None,
                ip_address=_client_ip(request),
                user_agent=request.headers.get("user-agent"),
                request_path=request.url.path,
                status=status_,
                tags=["auth", method],
            )
            await s.commit()
    except Exception:
        logger.debug("auth-event audit write skipped", exc_info=True)


# ═══════════════════════════════════════════════════════════════════════
# Per-device session helpers
# ═══════════════════════════════════════════════════════════════════════
# Sessions are tracked in the ``user_sessions`` table keyed on the
# refresh-token JTI. The auth dependency uses ``access_jti`` for the
# common fast-path; refresh rotation updates the row in place.
#
# Design notes:
#   - ``_create_*_with_jti`` mint a token AND return its decoded jti so
#     the caller can persist it without re-decoding (security.py is out
#     of edit scope so we extract from the freshly-encoded token).
#   - ``_upsert_session`` records a new device session (on login) or
#     rotates an existing one (on refresh).
#   - ``_revoke_session_by_access_jti`` flips ``revoked_at``; the auth
#     dep then rejects further requests with 401 (no token_version bump,
#     so the user's OTHER devices stay signed in).


def _decode_jti(token: str) -> str | None:
    """Pull the ``jti`` claim out of a JWT without verifying signature
    (the token was just minted in-process so signature checks are
    redundant — we only need the claim for DB bookkeeping)."""
    try:
        import jwt as _jwt

        claims = _jwt.decode(token, options={"verify_signature": False})
        jti = claims.get("jti")
        return str(jti) if jti else None
    except Exception:
        return None


def _create_access_with_jti(
    *,
    subject: str,
    extra_claims: dict[str, Any] | None,
    token_version: int,
) -> tuple[str, str | None]:
    """Mint an access token and return ``(token, jti)``."""
    tok = create_access_token(
        subject=subject,
        extra_claims=extra_claims,
        token_version=token_version,
    )
    return tok, _decode_jti(tok)


def _refresh_token_ttl(remember_me: bool) -> timedelta:
    """Refresh-token (and refresh/CSRF cookie) lifetime.

    ``remember_me`` opts into the longer window so the session survives longer
    before re-authentication is required. Only the EXPIRY changes — revocation
    (token_version bump on password-change/logout-all; per-device
    ``UserSession.revoked_at``) is unaffected.
    """
    days = (
        settings.REMEMBER_ME_REFRESH_TOKEN_EXPIRE_DAYS
        if remember_me
        else settings.REFRESH_TOKEN_EXPIRE_DAYS
    )
    return timedelta(days=days)


def _create_refresh_with_jti(
    *,
    subject: str,
    token_version: int,
    remember_me: bool = False,
) -> tuple[str, str | None]:
    """Mint a refresh token and return ``(token, jti)``.

    ``remember_me`` extends the refresh window AND stamps an ``rmb`` claim so
    the long session is preserved across rotations — ``/auth/refresh`` reads it
    back and re-applies the extended window (without the claim the session would
    silently shrink to the default window on the first token rotation).
    """
    tok = create_refresh_token(
        subject=subject,
        token_version=token_version,
        expires_delta=_refresh_token_ttl(remember_me),
        extra_claims={"rmb": True} if remember_me else None,
    )
    return tok, _decode_jti(tok)


def _client_user_agent(request: Request) -> str | None:
    ua = request.headers.get("user-agent")
    if not ua:
        return None
    return ua[:512]  # cap so a hostile UA can't bloat the row


def _client_ip(request: Request) -> str | None:
    # Trust X-Forwarded-For only when behind the reverse proxy; otherwise
    # fall back to the direct peer.
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()[:45]
    return request.client.host if request.client else None


async def _upsert_session(
    session: AsyncSession,
    *,
    user_id: UUID,
    refresh_jti: str | None,
    access_jti: str | None,
    request: Request,
    previous_refresh_jti: str | None = None,
) -> None:
    """Create-or-update the session row for this device.

    On a fresh login ``previous_refresh_jti`` is ``None`` and we always
    insert a new row. On a refresh-token rotation pass the OLD jti and
    we update that row in place — preserving the device identity across
    rotations without leaving an orphan row behind.

    Bookkeeping failures are swallowed: if the DB write fails for any
    reason we still let the user in. Revocation is enforced by checking
    ``revoked_at`` on the way back IN, so a missing row simply behaves
    like the legacy "no-session-table" code path.
    """
    if not refresh_jti:
        return

    from app.models import UserSession

    try:
        now = datetime.now(UTC)
        row: UserSession | None = None
        if previous_refresh_jti:
            res = await session.execute(
                select(UserSession).where(UserSession.refresh_jti == previous_refresh_jti)
            )
            row = res.scalar_one_or_none()

        if row is None:
            row = UserSession(
                user_id=user_id,
                refresh_jti=refresh_jti,
                access_jti=access_jti,
                user_agent=_client_user_agent(request),
                ip_address=_client_ip(request),
                created_at=now,
                last_used_at=now,
                is_revoked=False,
            )
            session.add(row)
        else:
            row.refresh_jti = refresh_jti
            row.access_jti = access_jti
            row.last_used_at = now
            # Update fingerprint in case the user moved networks; this
            # is informational, not an auth gate.
            row.user_agent = _client_user_agent(request) or row.user_agent
            row.ip_address = _client_ip(request) or row.ip_address
    except Exception:
        # Bookkeeping must never break login.
        logger.exception("Session upsert failed (continuing without record)")


async def _session_is_revoked_for_access_jti(session: AsyncSession, access_jti: str) -> bool:
    """Return True if the session bound to this access-jti has been revoked.

    Thin delegate to the shared ``app.core.session_revocation`` helper so the
    auth router and the shared REST dependency (AUTH-001) use ONE
    implementation. Missing rows are treated as NOT-revoked (legacy compat)."""
    from app.core.session_revocation import is_session_revoked_for_access_jti

    return await is_session_revoked_for_access_jti(session, access_jti)


async def _revoke_session_by_access_jti(session: AsyncSession, access_jti: str) -> bool:
    """Flip ``revoked_at`` for the session that owns this access-jti.
    Returns True on success."""
    from app.models import UserSession

    res = await session.execute(select(UserSession).where(UserSession.access_jti == access_jti))
    row = res.scalar_one_or_none()
    if row is None:
        return False
    if row.revoked_at is None:
        row.revoked_at = datetime.now(UTC)
        row.is_revoked = True
    return True


async def _revoke_session_by_refresh_jti(session: AsyncSession, refresh_jti: str) -> bool:
    """Flip ``revoked_at`` for the session that owns this refresh-jti."""
    from app.models import UserSession

    res = await session.execute(select(UserSession).where(UserSession.refresh_jti == refresh_jti))
    row = res.scalar_one_or_none()
    if row is None:
        return False
    if row.revoked_at is None:
        row.revoked_at = datetime.now(UTC)
        row.is_revoked = True
    return True


async def _get_authenticated_user(
    request: Request,
    token: Annotated[str | None, Depends(oauth2_scheme)] = None,
    session: AsyncSession = Depends(get_session),
) -> User:
    """
    Internal dependency to get the current authenticated user (raw User model).

    Used only within auth.py endpoints (login, refresh, MFA, etc.) where the
    full RBAC CurrentUser wrapper is not needed.  For all other endpoints, use
    ``get_current_user`` from ``app.core.dependencies`` which returns a
    ``CurrentUser`` wrapper with permission helpers.

    Supports both Bearer header and httpOnly cookie authentication.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    # Fall back to httpOnly cookie if no Bearer token
    if not token:
        from app.core.cookies import ACCESS_COOKIE

        token = request.cookies.get(ACCESS_COOKIE)
    if not token:
        raise credentials_exception

    payload = await verify_token(token, token_type="access")
    if payload is None:
        raise credentials_exception

    user_id = payload.get("sub")
    if user_id is None:
        raise credentials_exception

    try:
        user_uuid = UUID(user_id)
    except ValueError:
        raise credentials_exception

    result = await session.execute(
        select(User).where(User.id == user_uuid, User.deleted_at.is_(None))
    )
    user = result.scalar_one_or_none()

    if user is None:
        raise credentials_exception

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is disabled",
        )

    current_tv = getattr(user, "token_version", 0) or 0
    if payload.get("tv", 0) != current_tv:
        raise credentials_exception

    # SECURITY: the access-token JTI
    # must map to a Session row that is NOT revoked. Rows missing
    # entirely are treated as legacy / pre-migration tokens and allowed;
    # only an explicitly-revoked row blocks the request. This lets
    # /auth/logout invalidate THIS device without touching every other
    # browser the user has open.
    access_jti = payload.get("jti")
    if access_jti and await _session_is_revoked_for_access_jti(session, str(access_jti)):
        raise credentials_exception

    return user


async def _get_active_user(
    current_user: Annotated[User, Depends(_get_authenticated_user)],
) -> User:
    """Internal dependency to get current active user (raw User model).

    Only used within auth.py.  Other endpoints should use
    ``get_current_active_user`` from ``app.core.dependencies``.
    """
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user",
        )
    return current_user


@router.post("/token", response_model=TokenResponse)
async def login_for_access_token(
    request: Request,
    response: Response,
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """
    OAuth2 compatible token endpoint.

    Returns access and refresh tokens for valid credentials.
    """
    # SECURITY: enforce auth-specific rate limit (5/min per IP).
    # Pass the request path so the helper fails CLOSED on /auth/* when
    # Redis is down (instead of silently allowing credential stuffing).
    await check_auth_rate_limit(
        request.client.host if request.client else "unknown",
        path=request.url.path,
    )

    # Accept email or username (industry standard for self-hosted platforms)
    identifier = form_data.username  # OAuth2 spec calls this field "username"

    # SECURITY: per-username
    # sliding window on TOP of the per-IP limit. An attacker behind a
    # botnet of N IPs would otherwise get N × 5 attempts/min against one
    # account. The 401 message is intentionally identical to the "wrong
    # password" branch so this is not an account-existence oracle.
    if await check_auth_user_rate_limit(identifier):
        _dummy_verify(form_data.password)
        auth_events_total.labels(event_type="login", status="failure").inc()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email/username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    result = await session.execute(
        select(User).where(
            or_(User.email == identifier, User.username == identifier),
            User.deleted_at.is_(None),
        )
    )
    user = result.scalar_one_or_none()

    # SECURITY: if the user does not exist, burn the same CPU
    # time as a real Argon2id verify() so attackers cannot enumerate valid
    # accounts via response-timing measurements.  The error message MUST
    # be identical to the "wrong password" branch below.
    if user is None:
        _dummy_verify(form_data.password)
        await _audit_failed_login(identifier=identifier, request=request)
        await record_auth_user_failure(identifier)
        auth_events_total.labels(event_type="login", status="failure").inc()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email/username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # SECURITY: check lockout BEFORE password verification to avoid Argon2 DoS.
    # Also normalize timing with a dummy verify so the locked-out branch is
    # indistinguishable from the non-existent-user branch.
    if user.locked_until and user.locked_until > datetime.now(UTC):
        _dummy_verify(form_data.password)
        await _audit_failed_login(identifier=identifier, request=request)
        await record_auth_user_failure(identifier)
        auth_events_total.labels(event_type="login", status="locked").inc()
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail="Account is temporarily locked due to too many failed attempts. Try again later.",
        )

    if not verify_password(form_data.password, user.hashed_password):
        user.failed_login_attempts = (user.failed_login_attempts or 0) + 1
        if user.failed_login_attempts >= 5:
            user.locked_until = datetime.now(UTC) + timedelta(minutes=30)
        await session.commit()
        await _audit_failed_login(identifier=identifier, request=request)
        await record_auth_user_failure(identifier)
        auth_events_total.labels(event_type="login", status="failure").inc()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email/username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        # SECURITY: do NOT distinguish "inactive account" from
        # "wrong password" in the response — otherwise an attacker with a
        # valid password for a disabled account can enumerate disabled
        # users. Log the real reason server-side for audit, return the
        # identical 401 the wrong-password branch uses. Timing is already
        # normalized because verify_password() has run for the real hash.
        logger.info("Login attempt on inactive account: user_id=%s", user.id)
        await _audit_failed_login(identifier=identifier, request=request)
        await record_auth_user_failure(identifier)
        auth_events_total.labels(event_type="login", status="failure").inc()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email/username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # SECURITY: the OAuth2 password grant spec has no native
    # representation for MFA challenges, and legitimate OAuth2 clients
    # would happily treat any bearer token we returned here as a fully
    # authenticated session.  If the user has MFA enabled, refuse to mint
    # a token via this endpoint entirely — they must use /auth/login and
    # /auth/login/mfa instead.  This runs AFTER password verification so
    # the dummy-hash timing normalization on the failure branches above is
    # still effective for account enumeration resistance.
    if user.mfa_enabled and user.mfa_secret:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "MFA is enabled for this account. The OAuth2 /auth/token "
                "endpoint cannot complete an MFA challenge. Use /auth/login "
                "and /auth/login/mfa instead, or authenticate with an API key."
            ),
        )

    # Update last login
    user.last_login = datetime.now(UTC)
    user.failed_login_attempts = 0
    await session.commit()

    # SECURITY: clear the per-username rate-limit window now that this
    # identifier has been successfully authenticated.
    await reset_auth_user_rate_limit(identifier)

    await _audit_auth_event(action="login", request=request, user=user, method="oauth2")

    tv = getattr(user, "token_version", 0) or 0
    access_token, access_jti = _create_access_with_jti(
        subject=str(user.id),
        extra_claims={
            "role": user.role,
            "org_id": str(user.organization_id) if user.organization_id else None,
        },
        token_version=tv,
    )
    refresh_token, refresh_jti = _create_refresh_with_jti(subject=str(user.id), token_version=tv)

    # Record this session so /logout can revoke just this device
    # (instead of bumping token_version and killing every browser).
    await _upsert_session(
        session,
        user_id=user.id,
        refresh_jti=refresh_jti,
        access_jti=access_jti,
        request=request,
    )
    await session.commit()

    # Set httpOnly cookies for browser clients
    from app.core.cookies import set_auth_cookies

    set_auth_cookies(response, access_token, refresh_token)

    auth_events_total.labels(event_type="login", status="success").inc()
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.post("/login", response_model=BrowserAuthResponse)
async def login(
    request: Request,
    response: Response,
    login_data: LoginRequest,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """
    JSON login endpoint.

    Alternative to OAuth2 form-based login.
    Returns ``require_mfa: true`` + a short-lived ``mfa_token`` when the user
    has two-factor authentication enabled.
    """
    # SECURITY: enforce auth-specific rate limit (5/min per IP).
    # Fail-closed on /auth/* if Redis is down (see Fix 4).
    await check_auth_rate_limit(
        request.client.host if request.client else "unknown",
        path=request.url.path,
    )

    # Accept email or username in the 'login' field
    identifier = login_data.login
    # "Remember me" opt-in — extends the refresh window for this session.
    remember_me = bool(getattr(login_data, "remember_me", False))

    # SECURITY: per-username
    # sliding window. Same generic 401 as wrong-password to avoid
    # enumeration via 429 oracle.
    if await check_auth_user_rate_limit(identifier):
        _dummy_verify(login_data.password)
        auth_events_total.labels(event_type="login", status="failure").inc()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email/username or password",
        )

    result = await session.execute(
        select(User).where(
            or_(User.email == identifier, User.username == identifier),
            User.deleted_at.is_(None),
        )
    )
    user = result.scalar_one_or_none()

    # SECURITY: timing-safe failure when user does not exist.
    # Run Argon2id against a dummy hash so the response time matches the
    # "user exists with wrong password" path.  Error message is identical.
    if user is None:
        _dummy_verify(login_data.password)
        await _audit_failed_login(identifier=identifier, request=request)
        await record_auth_user_failure(identifier)
        auth_events_total.labels(event_type="login", status="failure").inc()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email/username or password",
        )

    # SECURITY: check lockout BEFORE password verification to avoid Argon2 DoS.
    # Dummy-verify on the locked-out branch to normalize timing.
    if user.locked_until and user.locked_until > datetime.now(UTC):
        _dummy_verify(login_data.password)
        await _audit_failed_login(identifier=identifier, request=request)
        await record_auth_user_failure(identifier)
        auth_events_total.labels(event_type="login", status="locked").inc()
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail="Account is temporarily locked due to too many failed attempts. Try again later.",
        )

    if not verify_password(login_data.password, user.hashed_password):
        user.failed_login_attempts = (user.failed_login_attempts or 0) + 1
        if user.failed_login_attempts >= 5:
            user.locked_until = datetime.now(UTC) + timedelta(minutes=30)
        await session.commit()
        await _audit_failed_login(identifier=identifier, request=request)
        await record_auth_user_failure(identifier)
        auth_events_total.labels(event_type="login", status="failure").inc()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email/username or password",
        )

    if not user.is_active:
        # SECURITY: see /token above — return the identical
        # 401 as wrong-password to prevent disabled-account enumeration.
        logger.info("Login attempt on inactive account: user_id=%s", user.id)
        await _audit_failed_login(identifier=identifier, request=request)
        await record_auth_user_failure(identifier)
        auth_events_total.labels(event_type="login", status="failure").inc()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email/username or password",
        )

    # Check if MFA is required
    if user.mfa_enabled and user.mfa_secret:
        # SECURITY: embed the current token_version in the
        # mfa_pending token so that a password change / logout-all /
        # admin-forced revocation between initial /login and /login/mfa
        # invalidates the pending challenge.
        mfa_tv = getattr(user, "token_version", 0) or 0
        mfa_token = create_access_token(
            subject=str(user.id),
            expires_delta=timedelta(minutes=5),
            # Carry the remember-me choice through the MFA challenge so the
            # final tokens issued by /login/mfa honour it.
            extra_claims={"type": "mfa_pending", "aud": "freesdn-mfa", "rmb": remember_me},
            token_version=mfa_tv,
        )
        auth_events_total.labels(event_type="login", status="mfa_required").inc()
        return {"require_mfa": True, "mfa_token": mfa_token}

    # Update last login
    user.last_login = datetime.now(UTC)
    user.failed_login_attempts = 0
    await session.commit()

    # SECURITY: clear the per-username rate-limit window on success.
    await reset_auth_user_rate_limit(identifier)

    await _audit_auth_event(action="login", request=request, user=user)

    tv = getattr(user, "token_version", 0) or 0
    access_token, access_jti = _create_access_with_jti(
        subject=str(user.id),
        extra_claims={
            "role": user.role,
            "org_id": str(user.organization_id) if user.organization_id else None,
        },
        token_version=tv,
    )
    refresh_token, refresh_jti = _create_refresh_with_jti(
        subject=str(user.id), token_version=tv, remember_me=remember_me
    )

    await _upsert_session(
        session,
        user_id=user.id,
        refresh_jti=refresh_jti,
        access_jti=access_jti,
        request=request,
    )
    await session.commit()

    # Set httpOnly cookies for browser clients
    from app.core.cookies import set_auth_cookies

    set_auth_cookies(
        response,
        access_token,
        refresh_token,
        refresh_max_age=int(_refresh_token_ttl(remember_me).total_seconds()),
    )

    auth_events_total.labels(event_type="login", status="success").inc()
    # SECURITY: return a slim response that carries NO raw
    # bearer tokens. The access + refresh tokens are delivered exclusively via
    # httpOnly cookies set above — leaking them in the JSON body would expose
    # them to JavaScript (XSS exfiltration).
    return BrowserAuthResponse(expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60)


@router.post("/refresh", response_model=BrowserAuthResponse)
async def refresh_token(
    request: Request,
    response: Response,
    refresh_data: RefreshTokenRequest | None = None,
    session: AsyncSession = Depends(get_session),
) -> Any:
    """
    Refresh access token using refresh token.

    Accepts refresh token from JSON body OR httpOnly cookie.
    """
    # Get refresh token from body or cookie
    from app.core.cookies import REFRESH_COOKIE

    raw_refresh = (refresh_data.refresh_token if refresh_data else None) or request.cookies.get(
        REFRESH_COOKIE
    )
    if not raw_refresh:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No refresh token provided",
        )

    payload = await verify_token(raw_refresh, token_type="refresh")
    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
        )

    # Atomically consume the old refresh token (rotation). R6: use a
    # SET-NX claim instead of a plain blacklist write so two concurrent
    # requests presenting the SAME refresh token can't both pass and both mint
    # a fresh pair (which would orphan a per-device session row and defeat
    # targeted revocation). Exactly one caller wins the claim; the loser 401s.
    from app.core.token_blacklist import claim_token_jti

    old_jti = payload.get("jti")
    old_exp = payload.get("exp")
    if old_jti and old_exp:
        claimed = await claim_token_jti(old_jti, old_exp)
        if not claimed:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token has already been used",
            )

    user_id = payload.get("sub")
    result = await session.execute(
        select(User).where(User.id == UUID(user_id), User.deleted_at.is_(None))
    )
    user = result.scalar_one_or_none()

    if user is None or not user.is_active:
        # SECURITY: do not leak whether the sub-id references
        # a real user; use the same generic error as other refresh failures.
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
        )

    # SECURITY: reject refresh tokens minted before a password change / logout-all
    tv = getattr(user, "token_version", 0) or 0
    if payload.get("tv", 0) != tv:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session has been revoked",
        )

    # SECURITY: if the session bound to this
    # refresh-jti has been individually revoked, refuse to rotate.
    if old_jti:
        from app.models import UserSession

        res = await session.execute(
            select(UserSession.revoked_at, UserSession.is_revoked).where(
                UserSession.refresh_jti == str(old_jti)
            )
        )
        sess_row = res.first()
        if sess_row is not None and (sess_row[0] is not None or bool(sess_row[1])):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Session has been revoked",
            )

    access_token, access_jti = _create_access_with_jti(
        subject=str(user.id),
        extra_claims={
            "role": user.role,
            "org_id": str(user.organization_id) if user.organization_id else None,
        },
        token_version=tv,
    )
    # Preserve the "remember me" window across rotation: the incoming refresh
    # token carries the rmb claim, so the rotated token keeps the long session
    # instead of silently shrinking to the default window.
    remember_me = bool(payload.get("rmb", False))
    new_refresh_token, new_refresh_jti = _create_refresh_with_jti(
        subject=str(user.id), token_version=tv, remember_me=remember_me
    )

    # Rotate the session row in place so we keep one row per device
    # across the lifetime of the user's sign-in.
    await _upsert_session(
        session,
        user_id=user.id,
        refresh_jti=new_refresh_jti,
        access_jti=access_jti,
        request=request,
        previous_refresh_jti=str(old_jti) if old_jti else None,
    )
    await session.commit()

    # Set httpOnly cookies for browser clients
    from app.core.cookies import set_auth_cookies

    set_auth_cookies(
        response,
        access_token,
        new_refresh_token,
        refresh_max_age=int(_refresh_token_ttl(remember_me).total_seconds()),
    )

    # SECURITY: slim response — no raw tokens in JSON body.
    return BrowserAuthResponse(expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60)


def _enrich_user_response(user: User) -> UserResponse:
    """Build a UserResponse with real permissions derived from the user's role.

    NOTE: role
    information flows from ``user.role`` (the DB-loaded value), NOT from
    any ``role`` claim embedded in the JWT. The JWT ``role`` claim exists
    only as a hint for clients displaying UI; the DB value is the sole
    source of truth for permission decisions. Any future endpoint reading
    ``token_claims["role"]`` for authz is a bug — read ``current_user.role``
    instead.
    """
    from app.core.dependencies import DEFAULT_ROLE_PERMISSIONS

    role_str = user.role.value if hasattr(user.role, "value") else str(user.role)
    permissions = DEFAULT_ROLE_PERMISSIONS.get(role_str, [])
    is_superuser = role_str == "super_admin"
    is_org_admin = role_str in ("org_admin", "admin", "super_admin")

    response = UserResponse.model_validate(user)
    response.permissions = permissions
    response.is_superuser = is_superuser
    response.is_org_admin = is_org_admin
    return response


@router.get("/me", response_model=UserResponse)
async def get_current_user_info(
    current_user: Annotated[User, Depends(_get_active_user)],
) -> Any:
    """Get current authenticated user information."""
    return _enrich_user_response(current_user)


@router.post("/password")
async def change_password(
    request: Request,
    password_data: PasswordChangeRequest,
    current_user: Annotated[User, Depends(_get_active_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Change current user's password."""
    if not verify_password(password_data.current_password, current_user.hashed_password):
        await _audit_auth_event(
            action="password_change", request=request, user=current_user, status_="failure"
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect",
        )

    # Validate new password strength
    is_valid, errors = validate_password_strength(password_data.new_password)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Password too weak: {'; '.join(errors)}",
        )

    current_user.hashed_password = get_password_hash(password_data.new_password)
    # SECURITY: invalidate all existing sessions after password change
    current_user.token_version = (getattr(current_user, "token_version", 0) or 0) + 1
    # SECURITY: invalidate API keys too so they can't outlive the bump
    from app.models.api_keys import revoke_user_api_keys

    await revoke_user_api_keys(session, current_user.id)
    await session.commit()

    await _audit_auth_event(action="password_change", request=request, user=current_user)
    return {"message": "Password updated successfully. All other sessions have been revoked."}


@router.post("/logout")
async def logout(
    request: Request,
    response: Response,
    current_user: Annotated[User, Depends(_get_active_user)],
    token: Annotated[str | None, Depends(oauth2_scheme)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """
    Per-device logout.

    Blacklists the current access token AND flips ``revoked_at`` on the
    Session row bound to this device. The user's OTHER devices stay
    signed in. To kill every session for the user (the old behaviour),
    call ``POST /auth/logout-all`` instead.
    """
    from app.core.token_blacklist import blacklist_token

    if not token:
        from app.core.cookies import ACCESS_COOKIE

        token = request.cookies.get(ACCESS_COOKIE)

    payload = await decode_token(token) if token else None
    access_jti = payload.get("jti") if payload else None
    if payload:
        exp = payload.get("exp")
        if access_jti and exp:
            await blacklist_token(access_jti, exp)

    # Also blacklist + revoke the refresh-token JTI if the refresh
    # cookie is present, so the refresh endpoint cannot mint new
    # access tokens for this device.
    from app.core.cookies import REFRESH_COOKIE

    refresh_cookie_val = request.cookies.get(REFRESH_COOKIE)
    if refresh_cookie_val:
        rpayload = await decode_token(refresh_cookie_val)
        if rpayload:
            r_jti = rpayload.get("jti")
            r_exp = rpayload.get("exp")
            if r_jti and r_exp:
                await blacklist_token(r_jti, r_exp)
            if r_jti:
                await _revoke_session_by_refresh_jti(session, str(r_jti))

    if access_jti:
        await _revoke_session_by_access_jti(session, str(access_jti))

    await session.commit()

    # Clear httpOnly cookies on THIS device only
    from app.core.cookies import clear_auth_cookies

    clear_auth_cookies(response)

    await _audit_auth_event(action="logout", request=request, user=current_user)
    return {"message": "Successfully logged out"}


@router.post("/logout-all")
async def logout_all(
    response: Response,
    current_user: Annotated[User, Depends(_get_active_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """
    Global logout — invalidate every session for this user.

    Bumps ``token_version`` (so every existing access/refresh token
    becomes invalid) AND flips ``revoked_at`` on every Session row.
    Also revokes API keys, matching the prior /logout semantics.
    """
    from app.models import UserSession
    from app.models.api_keys import revoke_user_api_keys

    # Bump token_version for cryptographic invalidation
    current_user.token_version = (getattr(current_user, "token_version", 0) or 0) + 1
    await revoke_user_api_keys(session, current_user.id)

    # Flip revoked_at on every session row for this user (so the
    # session-listing UI shows them as revoked, not just stale)
    now = datetime.now(UTC)
    res = await session.execute(
        select(UserSession).where(
            UserSession.user_id == current_user.id,
            UserSession.revoked_at.is_(None),
        )
    )
    for row in res.scalars().all():
        row.revoked_at = now
        row.is_revoked = True

    await session.commit()

    from app.core.cookies import clear_auth_cookies

    clear_auth_cookies(response)

    return {"message": "All sessions have been revoked"}


# ─── Session management ──────────────────────────────────────────────


@router.get("/sessions")
async def list_sessions(
    current_user: Annotated[User, Depends(_get_active_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """List the current user's active sessions for a "manage sessions"
    UI. Returns metadata only — never the raw refresh token / JTI.
    """
    from app.models import UserSession

    res = await session.execute(
        select(UserSession)
        .where(UserSession.user_id == current_user.id)
        .order_by(UserSession.created_at.desc())
    )
    rows = res.scalars().all()
    return {
        "sessions": [
            {
                "id": str(row.id),
                "user_agent": row.user_agent,
                "ip_address": row.ip_address,
                "created_at": row.created_at.isoformat() if row.created_at else None,
                "last_seen_at": (row.last_used_at.isoformat() if row.last_used_at else None),
                "revoked_at": (row.revoked_at.isoformat() if row.revoked_at else None),
                "is_revoked": row.revoked_at is not None or bool(row.is_revoked),
            }
            for row in rows
        ]
    }


@router.delete("/sessions/{session_id}")
async def revoke_session(
    session_id: UUID,
    current_user: Annotated[User, Depends(_get_active_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Revoke a specific session for the current user.

    Tenant scoping: the row's ``user_id`` MUST match ``current_user``;
    otherwise return 404 (not 403, to avoid leaking that the id exists).
    """
    from app.models import UserSession

    res = await session.execute(
        select(UserSession).where(
            UserSession.id == session_id,
            UserSession.user_id == current_user.id,
        )
    )
    row = res.scalar_one_or_none()
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found",
        )

    if row.revoked_at is None:
        row.revoked_at = datetime.now(UTC)
        row.is_revoked = True
        await session.commit()

    return {"message": "Session revoked"}


# ==========================================================================
# Registration
# ==========================================================================


@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register(
    request: Request,
    data: RegisterRequest,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """
    Self-registration endpoint.

    Creates a new user with the VIEWER role.  Registration can be
    disabled via the ``ALLOW_REGISTRATION`` env-var / setting.
    """
    # SECURITY: enforce auth-specific rate limit (5/min per IP).
    # Pass the path so Redis-down fails closed on /auth/*.
    await check_auth_rate_limit(
        request.client.host if request.client else "unknown",
        path=request.url.path,
    )

    if not settings.ALLOW_REGISTRATION:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Registration is currently disabled",
        )

    # do NOT reveal whether the email already exists. A
    # distinct 409 here is an unauthenticated enumeration oracle. Since register
    # returns only a generic message (no auto-login token), we can return the
    # SAME generic response for an existing email WITHOUT creating a user — new
    # and duplicate are then indistinguishable to the caller.
    _GENERIC_REGISTER_OK = {
        "message": "If the information provided is valid, your account has been created."
    }

    existing = await session.execute(
        select(User).where(
            User.email == data.email.lower(),
            User.deleted_at.is_(None),
        )
    )
    if existing.scalar_one_or_none():
        return _GENERIC_REGISTER_OK

    # Check username uniqueness
    target_username = data.email.split("@")[0]
    existing_username = await session.execute(
        select(User).where(
            User.username == target_username,
            User.deleted_at.is_(None),
        )
    )
    if existing_username.scalar_one_or_none():
        # Append random suffix to avoid collision
        import secrets as _sec

        target_username = f"{target_username}_{_sec.token_hex(3)}"

    full_name = f"{data.first_name} {data.last_name}".strip() or None

    # Validate password strength
    is_valid, errors = validate_password_strength(data.password)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Password too weak: {'; '.join(errors)}",
        )

    user = User(
        email=data.email.lower(),
        username=target_username,
        full_name=full_name,
        hashed_password=get_password_hash(data.password),
        role="viewer",
        is_active=True,
    )
    session.add(user)
    try:
        await session.commit()
    except IntegrityError:
        await session.rollback()
        # same generic response on the race (don't leak existence).
        return _GENERIC_REGISTER_OK

    return _GENERIC_REGISTER_OK


# ==========================================================================
# Password Reset
# ==========================================================================


@router.post("/password/reset-request")
async def request_password_reset(
    data: PasswordResetRequestSchema,
    request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """
    Request a password-reset link.

    Always returns 200 regardless of whether the email exists (prevents
    account enumeration).  When SMTP is configured the reset link is
    emailed; otherwise the token is returned in the response for dev/
    self-hosted convenience.

    Rate limited: 5 reset requests per IP per hour, and 3 per email per hour.
    This prevents email-bombing attacks against specific users.
    """
    # SECURITY: enforce auth-specific rate limit (5/min per IP) as defence-in-depth.
    # Pass the path so Redis-down fails closed on /auth/*.
    client_ip = request.client.host if request.client else "unknown"
    await check_auth_rate_limit(client_ip, path=request.url.path)

    # Additional Redis-based per-IP and per-email rate limiting
    email_key = data.email.lower()
    try:
        from app.core.redis_client import get_async_redis

        r = get_async_redis(decode_responses=True)
        now_ts = time.time()
        window_start = now_ts - 3600  # 1 hour window

        async with r.pipeline() as pipe:
            # Per-IP: 5 resets/hour
            ip_key = f"auth:pw_reset_ip:{client_ip}"
            pipe.zremrangebyscore(ip_key, "-inf", window_start)
            pipe.zcard(ip_key)
            pipe.zadd(ip_key, {str(now_ts): now_ts})
            pipe.expire(ip_key, 3700)
            # Per-email: 3 resets/hour
            em_key = f"auth:pw_reset_email:{email_key}"
            pipe.zremrangebyscore(em_key, "-inf", window_start)
            pipe.zcard(em_key)
            pipe.zadd(em_key, {str(now_ts): now_ts})
            pipe.expire(em_key, 3700)
            results = await pipe.execute()
        await r.aclose()

        ip_count = results[1]
        email_count = results[5]
        if ip_count >= 5 or email_count >= 3:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many password reset requests. Please try again later.",
                headers={"Retry-After": "3600"},
            )
    except HTTPException:
        raise
    except Exception:
        pass  # Redis unavailable — fail open (don't block legitimate resets)

    # the existing-user branch does extra work (token mint + DB
    # provider lookup + email send) that a non-existent email skips, leaking
    # account existence via response timing. Flatten it with a fixed latency
    # floor applied to BOTH branches before returning.
    _reset_floor_start = time.monotonic()
    _RESET_LATENCY_FLOOR_S = 0.5

    result = await session.execute(
        select(User).where(User.email == data.email.lower(), User.deleted_at.is_(None))
    )
    user = result.scalar_one_or_none()

    response: dict[str, Any] = {"message": "If the email exists, a reset link has been sent"}

    if user:
        # SECURITY: embed the user's current token_version so that
        # any out-of-band credential rotation (password change, logout-all,
        # prior reset) between link issuance and redemption invalidates this
        # token. The /password/reset endpoint re-verifies the tv claim.
        reset_token = create_access_token(
            subject=str(user.id),
            expires_delta=timedelta(hours=1),
            token_version=getattr(user, "token_version", 0) or 0,
            extra_claims={"type": "password_reset"},
        )
        # log user_id, not email, so the log stream isn't a free
        # email enumeration oracle for anyone with log read access.
        logger.info("Password reset token generated", extra={"user_id": str(user.id)})

        # Build the reset URL once — used to email it, or (in DEBUG, with no
        # email provider) to surface it directly for self-hosted recovery.
        frontend_url = getattr(settings, "FRONTEND_URL", None) or (
            settings.CORS_ORIGINS[0] if settings.CORS_ORIGINS else "http://localhost:3000"
        )
        reset_url = f"{frontend_url}/reset-password?token={reset_token}"

        email_sent = False
        try:
            from app.services.notification import NotificationChannel, NotificationService

            notification_svc = NotificationService(db=session)
            providers = await notification_svc.list_providers(
                organization_id=user.organization_id,
                channel=NotificationChannel.EMAIL.value,
                enabled_only=True,
            )
            if providers:
                await notification_svc.send(
                    channel=NotificationChannel.EMAIL,
                    recipient=user.email,
                    title="FreeSDN Password Reset",
                    body=f"Use the following link to reset your password: {reset_url}\n\nThis link expires in 1 hour.",
                    body_html=(
                        f"<p>You requested a password reset for your FreeSDN account.</p>"
                        f'<p><a href="{reset_url}">Click here to reset your password</a></p>'
                        f"<p>This link expires in 1 hour. If you did not request this, you can safely ignore this email.</p>"
                    ),
                    organization_id=user.organization_id,
                )
                email_sent = True
                logger.info(
                    "Password reset email sent",
                    extra={"user_id": str(user.id)},
                )
            else:
                # Self-hosted installs frequently have no email provider. Make
                # this loud server-side instead of silently swallowing the reset.
                logger.warning(
                    "Password reset requested but NO enabled email provider is "
                    "configured for the organization — the reset link cannot be "
                    "delivered. Configure an email notification provider (or run "
                    "with DEBUG to surface the link in the API response).",
                    extra={"user_id": str(user.id)},
                )
        except Exception:
            logger.warning(
                "Failed to send password reset email",
                extra={"user_id": str(user.id)},
                exc_info=True,
            )

        # Dev / self-hosted escape hatch: if the link could not be emailed and
        # the server is explicitly in DEBUG mode, return it so the operator can
        # still complete the reset. NEVER surfaced in production.
        if not email_sent and getattr(settings, "DEBUG", False):
            response["reset_url"] = reset_url

    # pad to the latency floor so existing vs non-existing emails
    # return in indistinguishable time. (DEBUG reset_url is dev-only and not a
    # production enumeration concern.)
    _elapsed = time.monotonic() - _reset_floor_start
    if _elapsed < _RESET_LATENCY_FLOOR_S:
        await asyncio.sleep(_RESET_LATENCY_FLOOR_S - _elapsed)

    return response


@router.post("/password/reset")
async def reset_password(
    data: PasswordResetConfirmSchema,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Consume a password-reset token and set a new password."""
    payload = await decode_token(data.token)
    if payload is None or payload.get("type") != "password_reset":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired reset token",
        )

    from app.core.token_blacklist import blacklist_token as _blacklist
    from app.core.token_blacklist import is_token_blacklisted as _is_blacklisted

    reset_jti = payload.get("jti")
    reset_exp = payload.get("exp")

    # SECURITY: blacklist the reset token FIRST to prevent race conditions.
    # If two requests arrive simultaneously, only the first will proceed.
    if reset_jti:
        if await _is_blacklisted(reset_jti):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired reset token",
            )
        if reset_exp:
            await _blacklist(reset_jti, reset_exp)

    user_id = payload.get("sub")
    # SECURITY: SELECT FOR UPDATE to prevent concurrent password resets
    result = await session.execute(
        select(User).where(User.id == UUID(user_id), User.deleted_at.is_(None)).with_for_update()
    )
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired reset token",
        )

    # SECURITY: verify the reset token's tv claim matches the
    # user's current token_version. This ensures that if the user already
    # rotated their credentials via a different path (password change,
    # logout-all, a previously redeemed reset, etc.), the stale reset link
    # from before that rotation is rejected.
    token_tv = int(payload.get("tv", 0) or 0)
    user_tv = int(getattr(user, "token_version", 0) or 0)
    if token_tv != user_tv:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Reset token is no longer valid. Request a new reset link.",
        )

    # Validate new password strength
    is_valid, errors = validate_password_strength(data.new_password)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Password too weak: {'; '.join(errors)}",
        )

    user.hashed_password = get_password_hash(data.new_password)
    user.failed_login_attempts = 0
    user.locked_until = None
    # SECURITY: invalidate ALL existing sessions — attacker's stolen tokens die instantly
    user.token_version = (getattr(user, "token_version", 0) or 0) + 1
    # SECURITY: also revoke API keys so they die with the bump
    from app.models.api_keys import revoke_user_api_keys

    await revoke_user_api_keys(session, user.id)
    await session.commit()

    return {
        "message": "Password has been reset successfully. All existing sessions have been revoked."
    }


# ==========================================================================
# MFA (TOTP)
# ==========================================================================


@router.post("/mfa/setup", response_model=MfaSetupResponse)
async def mfa_setup(
    current_user: Annotated[User, Depends(_get_active_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
    data: MfaSetupRequest | None = None,
) -> Any:
    """
    Begin MFA enrolment — returns a TOTP secret + provisioning URI.

    The new secret is staged in ``mfa_pending_secret`` and only promoted to
    the live ``mfa_secret`` when the user confirms with a valid code via
    ``POST /auth/mfa/enable`` — so an abandoned re-enrolment never clobbers a
    working authenticator.

    Re-enrolling on an account that ALREADY has MFA enabled requires step-up
    re-authentication: the request body must carry the account password.
    Without this, anyone holding a live access token for the victim could
    silently rebind the second factor to a device they control.
    """
    # step-up re-auth when re-enrolling an already-protected
    # account. Mirrors the verify_password gate on /mfa/disable.
    if current_user.mfa_enabled:
        if (
            data is None
            or not data.password
            or not verify_password(data.password, current_user.hashed_password)
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Password confirmation is required to re-enroll MFA.",
            )

    try:
        import pyotp
    except ImportError:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="MFA is not available (pyotp package not installed)",
        )

    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=current_user.email, issuer_name="FreeSDN")

    # Generate backup codes
    import secrets as _secrets

    # token_hex(5) = 10 hex chars (~40 bits/code), up from 8 chars (~32 bits).
    # The login backup-code branch length-gate below must match (== 10).
    backup_codes = [_secrets.token_hex(5).upper() for _ in range(10)]

    # SECURITY: persist hashed backup codes so they survive TOTP device loss.
    # Stage BOTH secret and codes in the pending columns — the live
    # mfa_secret/mfa_backup_codes are untouched until enable confirms.
    import json as _json

    from app.core.security import get_password_hash as _hash

    hashed_codes = [_hash(code) for code in backup_codes]
    current_user.mfa_pending_secret = encrypt_field(secret)
    current_user.mfa_pending_backup_codes = _json.dumps(hashed_codes)
    await session.commit()

    return MfaSetupResponse(secret=secret, uri=uri, backup_codes=backup_codes)


@router.post("/mfa/enable")
async def mfa_enable(
    data: MfaEnableRequest,
    current_user: Annotated[User, Depends(_get_active_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Confirm MFA enrolment by verifying a TOTP code."""
    # verify against the PENDING secret from /mfa/setup. Fall back
    # to the live secret for backward-compat with an enrolment that was begun
    # before this change (pending column still NULL).
    pending_secret = getattr(current_user, "mfa_pending_secret", None)
    secret_enc = pending_secret or current_user.mfa_secret
    if not secret_enc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Call /auth/mfa/setup first",
        )

    try:
        import pyotp  # noqa: F401  (presence check; verify_totp_single_use uses pyotp)

        from app.core.security import verify_totp_single_use

        # Single-use per timestep, matching the login path — so an enrolment
        # code cannot be replayed within its ~90s window.
        code_valid, matched_step = verify_totp_single_use(
            decrypt_field(secret_enc),
            data.code,
            getattr(current_user, "mfa_last_totp_step", None),
        )
        if not code_valid:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid MFA code",
            )
        current_user.mfa_last_totp_step = matched_step
    except ImportError:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="MFA is not available (pyotp package not installed)",
        )

    # Promote the confirmed pending secret/codes to live, then clear staging.
    if pending_secret:
        current_user.mfa_secret = pending_secret
        current_user.mfa_backup_codes = getattr(current_user, "mfa_pending_backup_codes", None)
        current_user.mfa_pending_secret = None
        current_user.mfa_pending_backup_codes = None

    current_user.mfa_enabled = True
    # bump token_version on enrolment so any access/refresh token
    # minted during the pre-MFA window is invalidated — parity with
    # /mfa/disable and the service-layer confirm_mfa. This forces the caller to
    # re-login right after enabling MFA (expected, same as a password change).
    current_user.token_version = (getattr(current_user, "token_version", 0) or 0) + 1
    await session.commit()

    return {"message": "MFA enabled successfully"}


@router.post("/mfa/disable")
async def mfa_disable(
    data: MfaDisableRequest,
    current_user: Annotated[User, Depends(_get_active_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Disable MFA (requires password confirmation)."""
    if not verify_password(data.password, current_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect password",
        )

    current_user.mfa_enabled = False
    current_user.mfa_secret = None
    # NOTE: when MFA
    # is disabled, the user's security posture has changed. Bump
    # token_version so any tokens issued while MFA was ON are forced to
    # re-authenticate. Without this, an attacker who stole an active
    # access token from the victim could keep using it AFTER the user
    # voluntarily lowered their account's security floor by disabling MFA.
    current_user.mfa_backup_codes = None
    current_user.token_version = (getattr(current_user, "token_version", 0) or 0) + 1
    await session.commit()

    return {"message": "MFA disabled successfully"}


@router.post("/login/mfa", response_model=BrowserAuthResponse)
async def login_mfa(
    request: Request,
    response: Response,
    data: MfaLoginRequest,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """
    Complete login when MFA is required.

    The ``mfa_token`` is a short-lived JWT issued during the initial login
    attempt.  The ``code`` is the 6-digit TOTP or an 8-char backup code.
    """
    # SECURITY: enforce auth-specific rate limit to prevent TOTP brute-force.
    # Fail-closed on /auth/* if Redis is down (see Fix 4).
    await check_auth_rate_limit(
        request.client.host if request.client else "unknown",
        path=request.url.path,
    )

    # Decode with MFA-specific audience to prevent token misuse
    import jwt as _jwt
    from jwt.exceptions import PyJWTError as _PyJWTError

    try:
        payload = _jwt.decode(
            data.mfa_token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM],
            options={"require": ["exp", "iat", "sub"]},
            audience="freesdn-mfa",
            issuer="freesdn",
        )
    except _PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired MFA token",
        )

    # Check token revocation
    from app.core.token_blacklist import is_token_blacklisted

    mfa_jti_check = payload.get("jti")
    if mfa_jti_check and await is_token_blacklisted(mfa_jti_check):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired MFA token",
        )

    # Validate token type is specifically mfa_pending
    if payload.get("type") != "mfa_pending":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid MFA token type",
        )

    # SECURITY: blacklist the MFA pending token so it cannot be replayed
    from app.core.token_blacklist import blacklist_token as _blacklist

    mfa_jti = payload.get("jti")
    mfa_exp = payload.get("exp")
    if mfa_jti and mfa_exp:
        await _blacklist(mfa_jti, mfa_exp)

    user_id = payload.get("sub")
    # SECURITY: lock the user row FOR UPDATE so concurrent
    # /login/mfa requests serialize through the backup-code (and TOTP-step)
    # consume. Without the lock, two parallel requests presenting the SAME
    # backup code both read the same JSON list, both match, both pop+commit —
    # the one-time code authenticates N sessions and a consumed code can be
    # resurrected by a lost update. Mirrors the password-reset path.
    result = await session.execute(
        select(User).where(User.id == UUID(user_id), User.deleted_at.is_(None)).with_for_update()
    )
    user = result.scalar_one_or_none()
    if user is None or not user.mfa_enabled or not user.mfa_secret:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid MFA session",
        )

    # SECURITY: every account-state gate that /login applies
    # must also run here, otherwise /login/mfa becomes a bypass path.
    # Without these checks a disabled / locked / soft-deleted user whose
    # mfa_pending token is still within its 5-minute window can complete
    # MFA and be issued a full access token.
    if getattr(user, "deleted_at", None) is not None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid MFA session",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is disabled",
        )

    if user.locked_until and user.locked_until > datetime.now(UTC):
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail="Account is temporarily locked due to too many failed attempts. Try again later.",
        )

    # Reject mfa_pending tokens whose tv claim is stale. This prevents
    # reuse of a pending challenge after password change / logout-all /
    # admin-forced revocation (which bump user.token_version).
    token_tv = int(payload.get("tv", 0) or 0)
    user_tv = int(getattr(user, "token_version", 0) or 0)
    if token_tv != user_tv:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="MFA session is no longer valid. Please log in again.",
        )

    # Verify TOTP code or backup code.
    # enforce single-use per timestep so an observed code can't be
    # replayed in a parallel login within its ~90s window.
    code_valid, matched_step = verify_totp_single_use(
        decrypt_field(user.mfa_secret),
        data.code,
        getattr(user, "mfa_last_totp_step", None),
    )
    if code_valid:
        user.mfa_last_totp_step = matched_step

    # If TOTP fails, check backup codes.
    # NOTE: backup codes are
    # exactly 8 hex chars (see /mfa/setup), TOTP codes are 6 digits.
    # Length is a cheap discriminator that lets us short-circuit BEFORE
    # paying ~300ms per stored hash × N codes (default 10) of Argon2.
    # A submitter of a 6-digit TOTP that fails will no longer trigger
    # 10× Argon2 verify calls.
    if not code_valid and user.mfa_backup_codes and len(data.code) == 10:
        import json as _json

        try:
            stored_hashes = _json.loads(user.mfa_backup_codes)
            for i, hashed_code in enumerate(stored_hashes):
                if verify_password(data.code, hashed_code):
                    # SECURITY: consume the backup code (one-time use)
                    stored_hashes.pop(i)
                    user.mfa_backup_codes = _json.dumps(stored_hashes)
                    code_valid = True
                    break
        except (ValueError, TypeError):
            pass

    if not code_valid:
        await _audit_failed_login(
            identifier=(user.email or user.username or str(user.id)),
            request=request,
            reason="mfa_failed",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid MFA code",
        )

    # Successful MFA verification — issue tokens
    user.last_login = datetime.now(UTC)
    user.failed_login_attempts = 0
    await session.commit()

    # Clear the per-username failure window — MFA pass implies the
    # password+TOTP were both correct.
    if user.email:
        await reset_auth_user_rate_limit(user.email)
    if user.username:
        await reset_auth_user_rate_limit(user.username)

    await _audit_auth_event(action="login", request=request, user=user, method="mfa")

    tv = getattr(user, "token_version", 0) or 0
    access_token, access_jti = _create_access_with_jti(
        subject=str(user.id),
        extra_claims={
            "role": user.role,
            "org_id": str(user.organization_id) if user.organization_id else None,
        },
        token_version=tv,
    )
    # Honour the remember-me choice carried from /login via the mfa_pending token.
    remember_me = bool(payload.get("rmb", False))
    refresh_token, refresh_jti = _create_refresh_with_jti(
        subject=str(user.id), token_version=tv, remember_me=remember_me
    )

    await _upsert_session(
        session,
        user_id=user.id,
        refresh_jti=refresh_jti,
        access_jti=access_jti,
        request=request,
    )
    await session.commit()

    # Set httpOnly cookies for browser clients
    from app.core.cookies import set_auth_cookies

    set_auth_cookies(
        response,
        access_token,
        refresh_token,
        refresh_max_age=int(_refresh_token_ttl(remember_me).total_seconds()),
    )

    # SECURITY: slim response — no raw tokens in JSON body.
    return BrowserAuthResponse(expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60)


# ==========================================================================
# Profile
# ==========================================================================


@router.patch("/me", response_model=UserResponse)
async def update_profile(
    data: ProfileUpdateRequest,
    current_user: Annotated[User, Depends(_get_active_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Update the current user's profile fields."""
    _ALLOWED_PROFILE_FIELDS = {"full_name", "username", "language", "timezone", "avatar_url"}
    update_data = data.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        if field not in _ALLOWED_PROFILE_FIELDS:
            continue
        setattr(current_user, field, value)

    try:
        await session.commit()
    except IntegrityError:
        # username (and email) carry a UNIQUE index; a colliding update would
        # otherwise surface as an opaque 500. Report it as a 409 conflict and
        # keep the wording generic so it isn't a username-enumeration oracle.
        await session.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="That username is already taken.",
        )
    await session.refresh(current_user)
    return _enrich_user_response(current_user)

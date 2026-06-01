# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Middleware Module
===============================

FastAPI middleware for:
- Rate limiting
- Request logging
- Error handling
- Request ID tracking
"""

import logging
import re
import time
import uuid
from collections.abc import Awaitable, Callable
from typing import Any

from fastapi import FastAPI, Request, Response, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from app.core.logging import request_id_var

logger = logging.getLogger(__name__)

# Allowed characters for client-supplied X-Request-ID. Anything else is
# ignored and the server generates a fresh UUID instead.
_REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9\-_]{1,128}$")


# ===========================================
# CSRF Protection Middleware
# ===========================================


class CSRFMiddleware(BaseHTTPMiddleware):
    """
    Double-submit cookie CSRF protection.

    For state-changing methods (POST, PUT, PATCH, DELETE), requires the
    ``X-CSRF-Token`` header to match the ``freesdn_csrf`` cookie value.

    Exempt paths (literal, set-lookup — NOT prefix matching):
      - Auth login/register/token endpoints (no session yet)
      - OAuth2 token endpoint (form-based, CORS-protected)
      - Public SSO flow endpoints (OIDC/SAML/LDAP authentication)
      - Password reset request/confirm
      - Setup wizard endpoints
      - Health checks
      - WebSocket upgrade (uses its own auth)

    Administrative endpoints (SSO providers CRUD, test-connection, etc.)
    are NOT exempt and must carry a CSRF token.
    """

    # Literal path prefixes that are always exempt. Kept narrow —
    # everything else must be an exact match in _CSRF_EXEMPT_PATHS.
    _EXEMPT_PREFIX_WHITELIST = (
        "/health",
        "/api/v1/health",
        "/api/v1/ws",  # WebSocket upgrade paths — have their own auth
    )

    # The exact set of paths that are CSRF-exempt because they're part of
    # the public authentication flow and cannot reasonably carry a CSRF
    # token. Administrative endpoints (providers CRUD, test-connection)
    # are NOT exempt.
    _CSRF_EXEMPT_PATHS: frozenset[str] = frozenset(
        {
            # Setup wizard — runs before any session exists
            "/api/v1/setup/status",
            "/api/v1/setup/admin",
            "/api/v1/setup/organization",
            "/api/v1/setup/controllers",
            "/api/v1/setup/modules",
            "/api/v1/setup/complete",
            # SSO flow — literal paths only, NOT a prefix
            "/api/v1/auth/sso/providers/public",  # list providers, GET only
            "/api/v1/auth/sso/oidc/authorize",
            "/api/v1/auth/sso/oidc/callback",
            "/api/v1/auth/sso/saml/login",
            "/api/v1/auth/sso/saml/callback",
            "/api/v1/auth/sso/ldap/authenticate",
            # Password reset flow
            # NOTE: the actual routes registered
            # in endpoints/auth.py use ``-`` not ``/`` for the action segment
            # (``reset-request`` / ``reset``, NOT ``reset/request`` /
            # ``reset/confirm``). With the old values, every legitimate
            # password-reset POST was rejected with 403 "CSRF token missing"
            # because the no-cookie pre-auth client could not present one.
            "/api/v1/auth/password/reset-request",
            "/api/v1/auth/password/reset",
            # Standard login (no cookie yet so no CSRF token to present)
            "/api/v1/auth/login",
            "/api/v1/auth/register",
            "/api/v1/auth/token",
            "/api/v1/auth/refresh",
            "/api/v1/auth/login/mfa",
        }
    )

    _SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

    # CSRF-exempt endpoints that nonetheless SET session cookies. They have no
    # pre-session CSRF token to present, so a cross-site auto-submitting form
    # (esp. the form-urlencoded /auth/token) could silently log a victim into an
    # ATTACKER-controlled account (login CSRF / session fixation). We gate these
    # on a same-origin / CORS-allowlisted Origin instead.
    _LOGIN_COOKIE_PATHS = frozenset(
        {
            "/api/v1/auth/login",
            "/api/v1/auth/token",
            "/api/v1/auth/login/mfa",
            "/api/v1/auth/refresh",
        }
    )

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        # Skip safe (read-only) methods
        if request.method in self._SAFE_METHODS:
            return await call_next(request)

        # Skip exempt paths — literal set lookup (NOT prefix match) so that
        # admin endpoints nested under /api/v1/auth/sso/* (providers CRUD,
        # test-connection, etc.) still require CSRF.
        path = request.url.path
        if path in self._CSRF_EXEMPT_PATHS:
            # Login-CSRF guard: cookie-setting login endpoints reject a
            # cross-origin browser POST. Non-browser clients (no Origin/Referer)
            # are unaffected — they are not a browser-CSRF vector.
            if path in self._LOGIN_COOKIE_PATHS and not self._origin_allowed(request):
                return JSONResponse(
                    status_code=status.HTTP_403_FORBIDDEN,
                    content={"error": {"code": 403, "message": "cross-origin login blocked"}},
                )
            return await call_next(request)
        # A tiny whitelist of legitimate prefix matches (health, WS upgrade).
        if any(path.startswith(p) for p in self._EXEMPT_PREFIX_WHITELIST):
            return await call_next(request)

        # Skip CSRF only if X-API-Key is present AND no session cookie is
        # present. SECURITY: If both an API key header and a cookie are
        # present, an attacker with XSS could send fake X-API-Key: junk
        # with credentials:'include' to bypass CSRF while still riding on
        # the victim's cookie session. Require the cookie to be absent.
        from app.core.cookies import ACCESS_COOKIE

        has_cookie = ACCESS_COOKIE in request.cookies
        if request.headers.get("X-API-Key") and not has_cookie:
            return await call_next(request)

        # Skip CSRF only if using Bearer token AND no cookie auth present.
        # SECURITY: If both Bearer header and cookie exist, enforce CSRF —
        # an attacker could send "Authorization: Bearer garbage" to bypass
        # CSRF while the cookie fallback authenticates with the victim's session.
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer ") and not has_cookie:
            return await call_next(request)

        # For cookie-based auth: enforce CSRF
        csrf_cookie = request.cookies.get("freesdn_csrf")
        csrf_header = request.headers.get("X-CSRF-Token")

        if not csrf_cookie or not csrf_header:
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"error": {"code": 403, "message": "CSRF token missing"}},
            )

        if not _constant_time_compare(csrf_cookie, csrf_header):
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"error": {"code": 403, "message": "CSRF token mismatch"}},
            )

        return await call_next(request)

    @staticmethod
    def _origin_allowed(request: Request) -> bool:
        """True if a login POST's browser Origin is same-origin or CORS-listed.

        Returns True when there is no Origin/Referer at all (curl / mobile /
        server-to-server clients are not a browser-CSRF vector). When a browser
        does send an Origin (or we can derive one from Referer), it must match
        the request's own origin or an entry in ``settings.CORS_ORIGINS`` — the
        same allowlist the SPA is served from. A cross-site attacker form posts
        its own Origin, which matches neither, and is rejected.
        """
        from urllib.parse import urlparse

        from app.core.config import settings

        origin = request.headers.get("origin")
        if not origin:
            referer = request.headers.get("referer")
            if not referer:
                return True  # no browser-supplied origin → not a CSRF vector
            parsed_ref = urlparse(referer)
            if not parsed_ref.scheme or not parsed_ref.netloc:
                return True
            origin = f"{parsed_ref.scheme}://{parsed_ref.netloc}"

        if origin in set(settings.CORS_ORIGINS or []):
            return True

        # Same-origin fallback: compare against the request's public origin,
        # honouring the reverse-proxy forwarded headers the app runs behind.
        fwd_proto = request.headers.get("x-forwarded-proto", "").split(",")[0].strip()
        host = request.headers.get("x-forwarded-host") or request.headers.get("host")
        scheme = fwd_proto or request.url.scheme
        if host:
            return origin == f"{scheme}://{host}"
        return False


def _constant_time_compare(a: str, b: str) -> bool:
    """Constant-time string comparison to prevent timing attacks."""
    import hmac

    return hmac.compare_digest(a.encode(), b.encode())


# ===========================================
# Request ID Middleware
# ===========================================


class RequestIDMiddleware(BaseHTTPMiddleware):
    """
    Adds a unique request ID to each request for tracing.

    The ID is read from ``X-Request-ID`` (preserving upstream IDs from
    reverse proxies) or generated. It is stored in:
      - ``request.state.request_id`` for handlers to access synchronously
      - the ``request_id_var`` ContextVar so log records emitted anywhere
        inside the request lifecycle automatically include it in JSON output

    The ID is echoed back as ``X-Request-ID`` for client-side correlation.
    Also injects standard security response headers.
    """

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        # Distinguish client-supplied IDs from server-generated ones so
        # that log poisoning / forged correlation IDs are visible as
        # ``ext-`` in logs. Only accept a tightly-validated format.
        client_supplied = request.headers.get("X-Request-ID", "").strip()
        if client_supplied and _REQUEST_ID_PATTERN.match(client_supplied):
            request_id = f"ext-{client_supplied[:120]}"
        else:
            request_id = str(uuid.uuid4())

        # Store in request state for access in handlers
        request.state.request_id = request_id

        # Set ContextVar so structured logs inside this request include it.
        token = request_id_var.set(request_id)
        try:
            response = await call_next(request)
        finally:
            request_id_var.reset(token)

        response.headers["X-Request-ID"] = request_id

        # ── Security Headers ──────────────────────────────────────────
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), payment=()"
        )
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        # Content-Security-Policy — restrict resource loading.
        # connect-src is 'self' ONLY: same-origin WebSocket (wss://same-host)
        # is already covered by 'self', so we do not need the ws:/wss:
        # wildcards. Removing them prevents data exfiltration to
        # attacker-controlled WebSocket endpoints in the event of an XSS.
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: blob:; "
            "font-src 'self'; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'"
        )
        # HSTS — when requests come over HTTPS (or via reverse proxy)
        proto = request.headers.get("X-Forwarded-Proto", request.url.scheme)
        if proto == "https":
            response.headers["Strict-Transport-Security"] = (
                "max-age=63072000; includeSubDomains; preload"
            )

        return response


# ===========================================
# Request Logging Middleware
# ===========================================


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """
    Logs all HTTP requests with timing information.
    """

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        start_time = time.time()

        # Get request info
        request_id = getattr(request.state, "request_id", "unknown")
        method = request.method
        path = request.url.path
        client_ip = request.client.host if request.client else "unknown"

        # Log request start
        logger.info(
            "Request started",
            extra={
                "request_id": request_id,
                "method": method,
                "path": path,
                "client_ip": client_ip,
            },
        )

        # Process request
        response = await call_next(request)

        # Calculate duration
        duration_ms = (time.time() - start_time) * 1000

        # Log request completion
        log_method = logger.info if response.status_code < 400 else logger.warning
        log_method(
            "Request completed",
            extra={
                "request_id": request_id,
                "method": method,
                "path": path,
                "status_code": response.status_code,
                "duration_ms": round(duration_ms, 2),
                "client_ip": client_ip,
            },
        )

        # Add timing header
        response.headers["X-Response-Time"] = f"{duration_ms:.2f}ms"

        return response


# ===========================================
# Rate Limiting Middleware
# ===========================================


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Redis-backed sliding-window rate limiter.

    Uses a sorted set per client key with timestamps as scores.

    Fail-mode policy:
      - For ``/api/v1/auth/*`` routes: fail CLOSED with 503 when Redis
        is unreachable. Otherwise an attacker who can DoS Redis would
        defeat the credential-stuffing protections (per-IP burst and
        per-username windows) and the endpoint-level
        ``check_auth_rate_limit()`` simultaneously.
      - For every other route: fail OPEN (allow the request) to prevent
        a Redis blip from taking the whole product down. The normal
        global request rate is much higher than the auth limits, so the
        DoS risk of skipping a few rate-limit decisions is acceptable.
    """

    # Path prefix whose requests must be rejected on Redis failure.
    _FAIL_CLOSED_PREFIX = "/api/v1/auth/"

    def __init__(
        self,
        app: ASGIApp,
        requests_per_minute: int = 60,
        burst_limit: int = 10,
    ):
        super().__init__(app)
        self.requests_per_minute = requests_per_minute
        self.burst_limit = burst_limit
        self._redis: Any = None
        self._redis_loop: Any = None

    def _get_redis(self) -> Any:
        """Lazy-init async Redis client, re-created if the running event loop
        changed since it was built.

        A ``redis.asyncio`` client is bound to the event loop it was created on.
        In production there is ONE loop for the app's lifetime, so this caches once
        and never re-creates. Under pytest-asyncio (a fresh loop per test) the
        cached client would otherwise be bound to a closed loop and every command
        would raise — which the rate limiter catches as 'Redis unavailable' and
        fail-closes (503) on /auth/*. Keying the cache on the loop self-heals that
        without changing prod behavior."""
        import asyncio

        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None
        if self._redis is None or self._redis_loop is not loop:
            from app.core.redis_client import get_async_redis

            self._redis = get_async_redis(
                decode_responses=True,
                socket_connect_timeout=2,
                socket_timeout=2,
            )
            self._redis_loop = loop
        return self._redis

    def _get_client_key(self, request: Request) -> str:
        """Return the rate-limit bucket key for this request.

        Prefer a per-USER bucket so that many users behind one NAT/CGNAT
        egress IP (e.g. a corporate office or VPN concentrator) don't all
        share — and exhaust — a single per-IP budget, and so a busy SPA
        gets its own envelope. We derive the user from the ``freesdn_access``
        cookie's JWT ``sub`` claim.

        SECURITY: pre-auth, we MUST NOT trust any *unverified*
        user-supplied header/cookie as a bucket key — an attacker could
        otherwise rotate the value on every request and get a fresh bucket
        each time, effectively bypassing the limit. We therefore only honour
        the cookie when its signature/issuer/audience VERIFY against our
        SECRET_KEY (cheap, local, no network/Redis roundtrip). A forged or
        rotated token fails verification and falls straight through to the
        per-IP bucket. We deliberately skip the blacklist/token_version
        checks here (those are a heavier, post-auth concern handled at the
        endpoint layer) — a revoked-but-still-unexpired token only affects
        which rate bucket the caller lands in, never authorization.
        """
        sub = self._verified_subject(request)
        if sub:
            return f"rl:user:{sub}"
        client_ip = request.client.host if request.client else "unknown"
        return f"rl:ip:{client_ip}"

    @staticmethod
    def _verified_subject(request: Request) -> str | None:
        """Return the signature-verified JWT ``sub`` from the access cookie.

        Returns ``None`` if there is no cookie or it fails verification.
        Verification is a local HMAC check (no DB/Redis), so this is cheap
        enough to run on every request.
        """
        from app.core.cookies import ACCESS_COOKIE

        token = request.cookies.get(ACCESS_COOKIE)
        if not token:
            return None
        try:
            import jwt

            from app.core.config import settings

            payload = jwt.decode(
                token,
                settings.SECRET_KEY,
                algorithms=[settings.ALGORITHM],
                options={"require": ["exp", "iat", "sub"]},
                audience="freesdn-api",
                issuer="freesdn",
            )
        except Exception:
            return None
        if payload.get("type") != "access":
            return None
        sub = payload.get("sub")
        return str(sub) if sub else None

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        # Skip rate limiting for health checks (/, /live, /ready, /db, etc.).
        # Probe traffic from k8s readiness probes and L4/L7 load balancers
        # hits these every few seconds — being rate-limited would mark the
        # backend unhealthy under load. Prefix match (was exact match — bug).
        path = request.url.path
        if (
            path == "/health"
            or path.startswith("/health/")
            or path == "/api/v1/health"
            or path.startswith("/api/v1/health/")
        ):
            return await call_next(request)
        # Stream tokens are lightweight JWT minting (already behind auth)
        if re.match(r"^/api/v1/cameras/[0-9a-fA-F\-]+/stream-token$", request.url.path):
            return await call_next(request)

        client_key = self._get_client_key(request)
        now = time.time()
        window_start = now - 60.0
        burst_start = now - 1.0

        try:
            r = self._get_redis()
            pipe = r.pipeline()
            # Remove expired entries
            pipe.zremrangebyscore(client_key, 0, window_start)
            # Count requests in last minute
            pipe.zcard(client_key)
            # Count requests in last second (burst)
            pipe.zcount(client_key, burst_start, "+inf")
            # Add current request
            pipe.zadd(client_key, {f"{now}:{uuid.uuid4().hex[:8]}": now})
            # Set TTL so keys auto-expire
            pipe.expire(client_key, 120)
            results = await pipe.execute()

            minute_count = results[1]
            burst_count = results[2]
        except Exception:
            # Redis down.
            # SECURITY: fail CLOSED on /auth/* — otherwise an
            # attacker who DoS-es Redis would simultaneously defeat the
            # global per-IP burst limit AND the endpoint-level credential
            # stuffing guards. For every other route we still fail open
            # so a Redis blip doesn't take the whole site down.
            if request.url.path.startswith(self._FAIL_CLOSED_PREFIX):
                logger.error(
                    "Rate limiter Redis unavailable on auth route %s; failing closed",
                    request.url.path,
                )
                return JSONResponse(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    content={
                        "error": {
                            "code": 503,
                            "message": (
                                "Authentication temporarily unavailable. Please retry shortly."
                            ),
                        }
                    },
                    headers={"Retry-After": "10"},
                )
            logger.debug("Rate limiter Redis unavailable, allowing request")
            return await call_next(request)

        # Check burst limit
        if burst_count >= self.burst_limit:
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "detail": "Rate limit exceeded (burst)",
                    "retry_after": 1,
                },
                headers={"Retry-After": "1"},
            )

        # Check per-minute limit
        if minute_count >= self.requests_per_minute:
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "detail": "Rate limit exceeded",
                    "retry_after": 60,
                },
                headers={"Retry-After": "60"},
            )

        # Add rate limit headers
        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(self.requests_per_minute)
        response.headers["X-RateLimit-Remaining"] = str(
            max(0, self.requests_per_minute - minute_count - 1)
        )
        return response


# ===========================================
# Global Exception Handler
# ===========================================

from fastapi import HTTPException
from fastapi.exceptions import RequestValidationError

from app.adapters.exceptions import (
    AdapterAuthenticationError,
    AdapterConfirmationRequiredError,
    AdapterConnectionError,
    AdapterError,
    AdapterNotFoundError,
    AdapterRateLimitError,
    AdapterReadOnlyError,
    AdapterTimeoutError,
)


def setup_exception_handlers(app: FastAPI) -> None:
    """Configure global exception handlers."""

    # ── Adapter exceptions → structured HTTP responses ────────────────

    @app.exception_handler(AdapterConnectionError)
    async def adapter_connection_handler(
        request: Request, exc: AdapterConnectionError
    ) -> JSONResponse:
        """Gateway/adapter unreachable → 502 Bad Gateway."""
        request_id = getattr(request.state, "request_id", None)
        logger.warning("Adapter connection error: %s", exc, extra={"request_id": request_id})
        return JSONResponse(
            status_code=status.HTTP_502_BAD_GATEWAY,
            content={
                "error": {
                    "code": 502,
                    "type": "adapter_connection_error",
                    "message": str(exc),
                    "request_id": request_id,
                }
            },
        )

    @app.exception_handler(AdapterAuthenticationError)
    async def adapter_auth_handler(
        request: Request, exc: AdapterAuthenticationError
    ) -> JSONResponse:
        """Bad credentials for the upstream device → 502 with auth hint."""
        request_id = getattr(request.state, "request_id", None)
        logger.warning("Adapter auth error: %s", exc, extra={"request_id": request_id})
        return JSONResponse(
            status_code=status.HTTP_502_BAD_GATEWAY,
            content={
                "error": {
                    "code": 502,
                    "type": "adapter_authentication_error",
                    "message": str(exc),
                    "request_id": request_id,
                }
            },
        )

    @app.exception_handler(AdapterNotFoundError)
    async def adapter_not_found_handler(
        request: Request, exc: AdapterNotFoundError
    ) -> JSONResponse:
        """Resource not found on the upstream device → 404."""
        request_id = getattr(request.state, "request_id", None)
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={
                "error": {
                    "code": 404,
                    "type": "adapter_not_found",
                    "message": str(exc),
                    "request_id": request_id,
                }
            },
        )

    @app.exception_handler(AdapterTimeoutError)
    async def adapter_timeout_handler(request: Request, exc: AdapterTimeoutError) -> JSONResponse:
        """Upstream device timed out → 504 Gateway Timeout."""
        request_id = getattr(request.state, "request_id", None)
        logger.warning("Adapter timeout: %s", exc, extra={"request_id": request_id})
        return JSONResponse(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            content={
                "error": {
                    "code": 504,
                    "type": "adapter_timeout",
                    "message": str(exc),
                    "request_id": request_id,
                }
            },
        )

    @app.exception_handler(AdapterRateLimitError)
    async def adapter_rate_limit_handler(
        request: Request, exc: AdapterRateLimitError
    ) -> JSONResponse:
        """Upstream device rate-limited us → 429."""
        request_id = getattr(request.state, "request_id", None)
        return JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            content={
                "error": {
                    "code": 429,
                    "type": "adapter_rate_limit",
                    "message": str(exc),
                    "request_id": request_id,
                }
            },
        )

    @app.exception_handler(AdapterConfirmationRequiredError)
    async def adapter_confirmation_required_handler(
        request: Request, exc: AdapterConfirmationRequiredError
    ) -> JSONResponse:
        """Destructive op needs explicit confirmation → 409 Conflict.

        type=confirmation_required lets the UI detect this, show a type-to-confirm
        dialog, and resubmit with confirmed=true. More specific than the
        AdapterError catch-all, so FastAPI routes here.
        """
        request_id = getattr(request.state, "request_id", None)
        return JSONResponse(
            status_code=status.HTTP_409_CONFLICT,
            content={
                "error": {
                    "code": 409,
                    "type": "confirmation_required",
                    "message": str(exc),
                    "request_id": request_id,
                }
            },
        )

    @app.exception_handler(AdapterReadOnlyError)
    async def adapter_read_only_handler(
        request: Request, exc: AdapterReadOnlyError
    ) -> JSONResponse:
        """Write refused by the ADAPTER_READ_ONLY safety → 403 Forbidden.

        This is a policy refusal, NOT a server fault: the write was blocked
        before it reached the device. Surfacing it as 403 (with the
        set-the-flag guidance) keeps a safe, expected refusal from looking
        like an opaque 500/502 crash. More specific than the AdapterError
        catch-all below, so FastAPI routes read-only errors here.
        """
        request_id = getattr(request.state, "request_id", None)
        logger.info("Adapter write refused (read-only): %s", exc, extra={"request_id": request_id})
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={
                "error": {
                    "code": 403,
                    "type": "adapter_read_only",
                    "message": str(exc),
                    "request_id": request_id,
                }
            },
        )

    @app.exception_handler(AdapterError)
    async def adapter_generic_handler(request: Request, exc: AdapterError) -> JSONResponse:
        """Catch-all for any other adapter error.

        Default → 502 Bad Gateway (a genuine upstream/device fault). BUT some
        adapter API errors (UniFi / FreePBX / Grandstream ``*APIError``) carry the
        upstream device's own ``status_code``. When that is a CLIENT error (4xx)
        the device rejected the *request itself* — bad input, a conflict, a
        not-found — which is operator-correctable, not a gateway fault. Surfacing
        the real 4xx (e.g. "400 invalid VLAN tag", "409 name already exists")
        instead of an opaque 502 lets the UI show the actual reason and the
        operator fix their input.

        EXCEPT the auth family (401/403/407): a device-side "unauthorized /
        forbidden" means the GATEWAY's stored credentials for the device are
        wrong — it is NOT the operator's own session. Surfacing it as a literal
        401 would trip the SPA's axios interceptor (which token-refreshes on ANY
        401 and logs the operator out if that refresh fails — see
        frontend/src/lib/api/client.ts), signing someone out of FreeSDN over an
        upstream device-credential failure. So those stay 502, like 5xx / missing
        status_code. (UniFi already routes device-401 to AdapterAuthenticationError
        → 502 via the handler above; this guards the other vendors' generic
        ``*APIError`` which can carry 401/403 and reach this catch-all.)
        """
        request_id = getattr(request.state, "request_id", None)
        upstream_status = getattr(exc, "status_code", None)
        _AUTH_FAMILY = (401, 403, 407)
        if (
            isinstance(upstream_status, int)
            and 400 <= upstream_status < 500
            and upstream_status not in _AUTH_FAMILY
        ):
            http_status = upstream_status
            # Client-correctable input error, not a server fault — log at info.
            logger.info(
                "Adapter rejected request (upstream %s): %s",
                upstream_status,
                exc,
                extra={"request_id": request_id},
            )
        else:
            http_status = status.HTTP_502_BAD_GATEWAY
            logger.warning("Adapter error: %s", exc, extra={"request_id": request_id})
        return JSONResponse(
            status_code=http_status,
            content={
                "error": {
                    "code": http_status,
                    "type": "adapter_error",
                    "message": str(exc),
                    "request_id": request_id,
                }
            },
        )

    # ── Standard HTTP exceptions ──────────────────────────────────────

    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
        """Handle HTTP exceptions with consistent format."""
        request_id = getattr(request.state, "request_id", None)

        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": {
                    "code": exc.status_code,
                    "message": exc.detail,
                    "request_id": request_id,
                }
            },
            headers=exc.headers,
        )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        """Handle validation errors with detailed messages."""
        request_id = getattr(request.state, "request_id", None)

        errors = []
        for error in exc.errors():
            field = ".".join(str(loc) for loc in error["loc"])
            errors.append(
                {
                    "field": field,
                    "message": error["msg"],
                    "type": error["type"],
                }
            )

        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={
                "error": {
                    "code": 422,
                    "message": "Validation error",
                    "details": errors,
                    "request_id": request_id,
                }
            },
        )

    @app.exception_handler(Exception)
    async def generic_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        """Handle unexpected exceptions."""
        request_id = getattr(request.state, "request_id", None)

        logger.exception(f"Unhandled exception: {exc}", extra={"request_id": request_id})

        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error": {
                    "code": 500,
                    "message": "Internal server error",
                    "request_id": request_id,
                }
            },
        )


# ===========================================
# Middleware Setup Helper
# ===========================================


class BodySizeLimitMiddleware(BaseHTTPMiddleware):
    """Reject requests whose body exceeds ``max_bytes``.

    Backstop against DoS / DB-bloat via huge stage payloads. Pydantic
    bounds ``notes`` and ``target_id`` per-field, but ``payload`` is a
    free-form dict — without a body cap a writer could POST 100 MB of
    JSON to ``/changes/{feature}`` and inflate
    ``adapter_pending_changes`` indefinitely.

    The cap is enforced two ways:
      1. A fast ``Content-Length`` pre-check that rejects an oversize
         declared body before the handler runs.
      2. A streaming byte counter wrapped around the ASGI ``receive``
         channel. This catches a chunked / streaming request that omits
         ``Content-Length`` entirely (the header-only check would let
         that bypass the cap), and it aborts as soon as the *running*
         total crosses the limit — without ever buffering the whole body
         in memory.

    1 MB is generous for any single Omada config op; the typical
    payload is < 4 KB.
    """

    def __init__(self, app: ASGIApp, max_bytes: int = 1_048_576) -> None:
        super().__init__(app)
        self.max_bytes = max_bytes

    async def dispatch(self, request: Request, call_next):  # type: ignore[override]
        max_bytes = self.max_bytes

        # 1. Fast path: reject an oversize *declared* Content-Length up front.
        cl = request.headers.get("content-length")
        if cl is not None:
            try:
                if int(cl) > max_bytes:
                    return JSONResponse(
                        status_code=413,
                        content={"detail": (f"request body exceeds {max_bytes}-byte limit")},
                    )
            except ValueError:
                # Bad header — let the framework reject it normally.
                pass

        # 2. Streaming guard: wrap ``receive`` to count actual body bytes so a
        # chunked / Content-Length-less request can't slip past the cap. We
        # flag the breach and let the downstream handler observe a truncated
        # body (more_body=False) rather than feeding it unbounded data; the
        # request is then rejected with 413 instead of being processed.
        #
        # The body is streamed lazily by whoever first consumes it downstream
        # (Starlette's BaseHTTPMiddleware reads it via this request's
        # ``_receive``), so wrapping ``_receive`` here — before any
        # consumption — means every actual body chunk is counted as it
        # arrives, with no full-body buffering.
        original_receive = request.receive
        state = {"total": 0, "exceeded": False}

        async def limited_receive() -> Any:
            message = await original_receive()
            if message.get("type") == "http.request":
                state["total"] += len(message.get("body", b"") or b"")
                if state["total"] > max_bytes:
                    state["exceeded"] = True
                    # Stop the stream so the handler doesn't keep receiving
                    # attacker-controlled bytes; it sees an empty terminal chunk.
                    return {"type": "http.request", "body": b"", "more_body": False}
            return message

        request._receive = limited_receive  # type: ignore[attr-defined]

        response = await call_next(request)
        if state["exceeded"]:
            return JSONResponse(
                status_code=413,
                content={"detail": (f"request body exceeds {max_bytes}-byte limit")},
            )
        return response


class TrailingSlashNormalizeMiddleware(BaseHTTPMiddleware):
    """Make trailing-slash spelling client-irrelevant.

    Why this exists: FastAPI's built-in ``redirect_slashes=True`` emits a
    307 with the *internal* host in the ``Location`` header when running
    behind a reverse proxy (Vite dev / nginx / Traefik / k8s ingress).
    The browser then tries to resolve ``http://api:8000/...`` (the
    docker-internal alias) and the request hangs forever as "pending".
    Turning the FastAPI redirect off (``redirect_slashes=False``) stops
    the leak but ``/sites`` would now 404 because the registered route
    is ``/sites/``.

    This middleware consults the actual route table once and builds a
    set of canonical paths. On each request, if the incoming path
    doesn't match any registered route but a slash-flipped version
    does, we rewrite the request scope's ``path`` to the canonical
    spelling before routing — both ``/sites`` and ``/sites/`` reach
    the same handler with no client-visible redirect.

    Dynamic-segment routes (e.g. ``/sites/{id}``) are matched via the
    compiled regex Starlette built for them; we cache those at startup
    too.

    The OpenAPI docs / static asset paths are passed through untouched.
    """

    def __init__(self, app: Any) -> None:
        super().__init__(app)
        # Caches populated lazily from the live app instance the first
        # time we see a request — the app's router isn't fully wired
        # at __init__ time when the middleware is constructed.
        self._slash_paths: set[str] | None = None  # exact paths ending in /
        self._no_slash_paths: set[str] | None = None  # exact paths NOT ending in /

    def _ensure_route_caches(self, scope_app: Any) -> None:
        if self._slash_paths is not None:
            return
        slash: set[str] = set()
        no_slash: set[str] = set()
        try:
            # Build the static-path caches from the OpenAPI schema — fastapi's
            # canonical, full-path route inventory. We can't walk ``app.routes``
            # for this anymore: fastapi 0.137+ wraps each ``include_router`` in an
            # opaque ``_IncludedRouter`` whose ``.routes`` is empty and ``.path``
            # is None, so a tree-walk surfaces zero API paths (it would silently
            # disable this trailing-slash normalizer for every API endpoint). The
            # schema stays correct across versions. Only static (param-less) paths
            # matter here — dynamic routes are matched by Starlette's regex anyway.
            # Generated once per process, then cached on the instance.
            for path in scope_app.openapi().get("paths", {}) or {}:
                if not isinstance(path, str) or "{" in path:
                    continue
                if path.endswith("/") and len(path) > 1:
                    slash.add(path)
                else:
                    no_slash.add(path)
        except Exception:
            # Never let route introspection failure poison the request
            # path. If something goes wrong we just degrade to no-op.
            pass
        self._slash_paths = slash
        self._no_slash_paths = no_slash

    async def dispatch(self, request: Request, call_next):
        path = request.scope.get("path", "")
        # OpenAPI/swagger UI and any static asset under /docs/ keep
        # whatever slash they came in with — they're not API endpoints.
        if path.startswith("/api/v1/docs") or path.startswith("/static"):
            return await call_next(request)

        self._ensure_route_caches(request.app)
        slash_paths = self._slash_paths or set()
        no_slash_paths = self._no_slash_paths or set()

        # Path matches an existing route exactly: pass through.
        if path in slash_paths or path in no_slash_paths:
            return await call_next(request)

        # No exact match — try the slash-flipped variant.
        if path.endswith("/"):
            stripped = path.rstrip("/") or "/"
            if stripped in no_slash_paths:
                request.scope["path"] = stripped
                if "raw_path" in request.scope:
                    raw = request.scope["raw_path"] or b""
                    if raw.endswith(b"/") and len(raw) > 1:
                        request.scope["raw_path"] = raw.rstrip(b"/")
        else:
            added = path + "/"
            if added in slash_paths:
                request.scope["path"] = added
                if "raw_path" in request.scope:
                    raw = request.scope["raw_path"] or b""
                    if not raw.endswith(b"/"):
                        request.scope["raw_path"] = raw + b"/"

        return await call_next(request)


def setup_middleware(app: FastAPI, enable_rate_limiting: bool = True) -> None:
    """Add all middleware to the FastAPI app."""

    # Order matters - first added = outermost = runs first/last

    # 1. Request ID (outermost)
    app.add_middleware(RequestIDMiddleware)

    # 2. Request logging
    app.add_middleware(RequestLoggingMiddleware)

    # 3. Path normalisation — strip trailing slashes BEFORE routing so
    # both ``/foo`` and ``/foo/`` reach the same handler without the
    # 307-redirect-leak through ``http://api:8000/...``. Must come
    # before route resolution; placed early in the chain.
    app.add_middleware(TrailingSlashNormalizeMiddleware)

    # 4. Body-size cap — reject oversize requests before they hit
    # CSRF / route handlers / the staging service.
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=1_048_576)

    # 5. CSRF protection (inside rate limiting, outside route handlers)
    app.add_middleware(CSRFMiddleware)

    # 6. Rate limiting — production-tunable via RATE_LIMIT_RPM /
    # RATE_LIMIT_BURST (see config.py). Generous defaults so a busy SPA and
    # multiple users behind one NAT egress IP aren't 429'd; the bucket is
    # keyed per-authenticated-user when an access cookie is present (falling
    # back to per-IP). The stricter per-auth-endpoint limits are enforced
    # separately and are unaffected by these knobs.
    if enable_rate_limiting:
        from app.core.config import settings

        app.add_middleware(
            RateLimitMiddleware,
            requests_per_minute=settings.RATE_LIMIT_RPM,
            burst_limit=settings.RATE_LIMIT_BURST,
        )

    # Setup exception handlers
    setup_exception_handlers(app)

# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Cookie Utilities for httpOnly Auth
================================================

Provides helpers for setting/clearing httpOnly authentication cookies
and CSRF token management.

Design:
  - ``freesdn_access``: httpOnly, Secure, SameSite=Lax — access JWT
  - ``freesdn_refresh``: httpOnly, Secure, SameSite=Lax, Path=/api/v1/auth/refresh — refresh JWT
  - ``freesdn_csrf``: NOT httpOnly (JS-readable), Secure, SameSite=Lax,
    Path=/api/v1/, no Domain attribute — CSRF double-submit token.
    The Path+Domain combination simulates the ``__Host-`` cookie prefix
    without renaming the cookie (a future commit can rename atomically
    with the frontend reads in client.ts / authStore.ts / useWebSocket.ts).
"""

import secrets
from typing import Literal

from fastapi import Response

from app.core.config import settings

# Cookie names (prefixed to avoid collisions)
ACCESS_COOKIE = "freesdn_access"
REFRESH_COOKIE = "freesdn_refresh"
CSRF_COOKIE = "freesdn_csrf"

# CSRF header name (must match frontend)
CSRF_HEADER = "X-CSRF-Token"


def _is_secure() -> bool:
    """Use Secure flag in production/staging."""
    return settings.ENVIRONMENT in ("production", "staging")


def _samesite() -> Literal["lax", "strict", "none"]:
    """SameSite=Lax allows SSO redirects; Strict would break OIDC/SAML flows."""
    return "lax"


def generate_csrf_token() -> str:
    """Generate a cryptographically secure CSRF token."""
    return secrets.token_urlsafe(32)


def set_auth_cookies(
    response: Response,
    access_token: str,
    refresh_token: str,
    csrf_token: str | None = None,
    refresh_max_age: int | None = None,
) -> str:
    """
    Set httpOnly auth cookies on the response.

    Returns the CSRF token (generated if not provided) so it can be
    included in the response body for initial setup.

    ``refresh_max_age`` (seconds) overrides the refresh-cookie lifetime — used
    by the "remember me" flow to extend the session. The CSRF cookie is tied to
    the SAME window (see below): if it expired first the frontend would treat
    the user as logged-out while the refresh token was still valid. When unset,
    both default to ``REFRESH_TOKEN_EXPIRE_DAYS``.
    """
    if csrf_token is None:
        csrf_token = generate_csrf_token()

    secure = _is_secure()
    samesite = _samesite()

    refresh_age = (
        refresh_max_age
        if refresh_max_age is not None
        else settings.REFRESH_TOKEN_EXPIRE_DAYS * 86400
    )

    # Access token cookie — httpOnly, sent on all API requests
    response.set_cookie(
        key=ACCESS_COOKIE,
        value=access_token,
        httponly=True,
        secure=secure,
        samesite=samesite,
        max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        path=f"{settings.API_V1_PREFIX}/",
    )

    # Refresh token cookie — httpOnly, scoped to refresh endpoint only
    # Tighter path reduces attack surface (cookie not sent to /auth/me, /auth/login, etc.)
    response.set_cookie(
        key=REFRESH_COOKIE,
        value=refresh_token,
        httponly=True,
        secure=secure,
        samesite=samesite,
        max_age=refresh_age,
        path=f"{settings.API_V1_PREFIX}/auth/refresh",
    )

    # CSRF token cookie — NOT httpOnly (JS reads it to set X-CSRF-Token header)
    # NOTE: the CSRF cookie used
    # to expire with the access token (~15min), which meant the moment
    # the access token expired the browser dropped the CSRF cookie too.
    # ``refreshSession()`` in the frontend gates on the presence of the
    # CSRF cookie ("if no CSRF cookie, definitely not authenticated"), so
    # a user with a still-valid refresh token would be force-logged-out
    # because the CSRF cookie evaporated first. Tie the CSRF cookie's
    # lifetime to the refresh window instead — it's a non-sensitive
    # double-submit value, NOT a credential.
    #
    # NOTE: tighten the Path
    # from "/" to f"{API_V1_PREFIX}/" so the cookie is only attached to
    # API calls (NOT, e.g., static assets or third-party iframes that
    # happen to share the origin). Also omit the Domain attribute — when
    # Domain is unset the browser pins the cookie to the EXACT host,
    # preventing a sibling subdomain XSS from lifting it.
    #
    # The cookie is intentionally NOT named ``__Host-freesdn_csrf``: the
    # frontend reads it by the ``freesdn_csrf`` name (client.ts, authStore.ts,
    # useWebSocket.ts), so the name and those reads would have to change
    # together to avoid invalidating in-flight sessions. The current attributes
    # (Path + Secure + no Domain) match what ``__Host-`` enforces — just without
    # browser-level syntax validation, so a misconfigured proxy could still set
    # Domain and weaken the cookie.
    # NOTE (CSRF cookie path regression): an earlier change
    # tightened Path to /api/v1/ for defense-in-depth
    # (cookie not attached to static assets / iframes on the same host).
    # But that broke the actual functionality: the SPA runs at "/" and
    # ``getCookie('freesdn_csrf')`` reads via ``document.cookie``, which
    # only includes cookies whose Path is a prefix of the current
    # document path. With Path=/api/v1/, the SPA at / could never read
    # the cookie → every mutation returned 403 "CSRF token missing".
    # Verified end-to-end via browser MCP against the running stack.
    #
    # Returning Path to "/" restores the intended flow. The cookie is
    # still SameSite=Lax + Secure + host-only (no Domain), so the
    # third-party iframe / cross-origin attack surface is limited by
    # SameSite. The original "static assets" concern is moot for a
    # cookie carrying a CSRF double-submit value (non-sensitive token).
    response.set_cookie(
        key=CSRF_COOKIE,
        value=csrf_token,
        httponly=False,
        secure=secure,
        samesite=samesite,
        max_age=refresh_age,
        path="/",
        # domain= intentionally omitted — host-only cookie
    )

    return csrf_token


def clear_auth_cookies(response: Response) -> None:
    """Remove all auth cookies (logout)."""
    secure = _is_secure()
    samesite = _samesite()

    for name, path in [
        (ACCESS_COOKIE, f"{settings.API_V1_PREFIX}/"),
        (REFRESH_COOKIE, f"{settings.API_V1_PREFIX}/auth/refresh"),
        # CSRF cookie set at Path=/ (Fix 17 reverted Fix 3's narrowing —
        # see set_csrf_cookie() comment). Clearing must use the same
        # Path or the browser won't erase it.
        (CSRF_COOKIE, "/"),
    ]:
        response.set_cookie(
            key=name,
            value="",
            httponly=name != CSRF_COOKIE,
            secure=secure,
            samesite=samesite,
            max_age=0,
            path=path,
        )

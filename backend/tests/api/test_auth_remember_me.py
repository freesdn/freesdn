# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Regression tests for the "remember me" extended-session flow.

Covers the three places the remember-me window must hold:
  1. ``set_auth_cookies(refresh_max_age=...)`` extends BOTH the refresh and
     the CSRF cookie (CSRF must not evict first — that force-logs-out a user
     whose refresh token is still valid).
  2. ``_create_refresh_with_jti(remember_me=True)`` mints a longer-lived token
     and stamps the ``rmb`` claim.
  3. ``/auth/refresh`` PRESERVES the long window across rotation by reading the
     ``rmb`` claim back — without this the session silently shrinks to the
     default window on the first token rotation.
"""
from __future__ import annotations

import re
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import jwt
import pytest
from fastapi import Response
from starlette.requests import Request

from app.api.v1.endpoints.auth import (
    _create_refresh_with_jti,
    _refresh_token_ttl,
    refresh_token,
)
from app.core.config import settings
from app.core.cookies import CSRF_COOKIE, REFRESH_COOKIE, set_auth_cookies

_DEFAULT_AGE = settings.REFRESH_TOKEN_EXPIRE_DAYS * 86400
_REMEMBER_AGE = settings.REMEMBER_ME_REFRESH_TOKEN_EXPIRE_DAYS * 86400


def _max_age(headers: list[str], cookie_name: str) -> int | None:
    for h in headers:
        if h.startswith(f"{cookie_name}="):
            m = re.search(r"Max-Age=(\d+)", h)
            if m:
                return int(m.group(1))
    return None


def _claims(token: str) -> dict:
    return jwt.decode(token, options={"verify_signature": False})


def _token_window_days(token: str) -> int:
    c = _claims(token)
    return round((c["exp"] - c["iat"]) / 86400)


def _make_request(cookies: dict[str, str]) -> Request:
    cookie_value = "; ".join(f"{k}={v}" for k, v in cookies.items())
    return Request({"type": "http", "headers": [(b"cookie", cookie_value.encode())]})


# --------------------------------------------------------------------------- #
# 1. Cookie window
# --------------------------------------------------------------------------- #
def test_set_auth_cookies_extends_refresh_and_csrf_with_remember_me() -> None:
    response = Response()
    set_auth_cookies(response, "access", "refresh", refresh_max_age=_REMEMBER_AGE)
    headers = response.headers.getlist("set-cookie")

    # Both the refresh AND the CSRF cookie must carry the extended window —
    # if the CSRF cookie expired first the frontend would treat the user as
    # logged out while the refresh token was still valid.
    assert _max_age(headers, REFRESH_COOKIE) == _REMEMBER_AGE
    assert _max_age(headers, CSRF_COOKIE) == _REMEMBER_AGE
    assert _REMEMBER_AGE > _DEFAULT_AGE


def test_set_auth_cookies_default_window_without_remember_me() -> None:
    response = Response()
    set_auth_cookies(response, "access", "refresh")  # no override
    headers = response.headers.getlist("set-cookie")
    assert _max_age(headers, REFRESH_COOKIE) == _DEFAULT_AGE
    assert _max_age(headers, CSRF_COOKIE) == _DEFAULT_AGE


# --------------------------------------------------------------------------- #
# 2. Token TTL + rmb claim
# --------------------------------------------------------------------------- #
def test_refresh_token_ttl_helper() -> None:
    assert _refresh_token_ttl(True).days == settings.REMEMBER_ME_REFRESH_TOKEN_EXPIRE_DAYS
    assert _refresh_token_ttl(False).days == settings.REFRESH_TOKEN_EXPIRE_DAYS


def test_create_refresh_with_jti_remember_me_extends_and_marks() -> None:
    tok, jti = _create_refresh_with_jti(subject=str(uuid4()), token_version=0, remember_me=True)
    assert jti
    claims = _claims(tok)
    assert claims.get("rmb") is True
    assert _token_window_days(tok) == settings.REMEMBER_ME_REFRESH_TOKEN_EXPIRE_DAYS


def test_create_refresh_with_jti_default_has_no_rmb() -> None:
    tok, _ = _create_refresh_with_jti(subject=str(uuid4()), token_version=0, remember_me=False)
    claims = _claims(tok)
    assert "rmb" not in claims
    assert _token_window_days(tok) == settings.REFRESH_TOKEN_EXPIRE_DAYS


# --------------------------------------------------------------------------- #
# 3. /auth/refresh preserves the window across rotation
# --------------------------------------------------------------------------- #
async def _run_refresh(rmb_claim: bool) -> list[str]:
    """Drive the refresh endpoint with a refresh token carrying ``rmb=rmb_claim``
    and return the resulting Set-Cookie headers."""
    uid = uuid4()
    fake_user = SimpleNamespace(
        id=uid, is_active=True, token_version=0, role="viewer", organization_id=None
    )
    user_result = MagicMock()
    user_result.scalar_one_or_none.return_value = fake_user
    sess_result = MagicMock()
    sess_result.first.return_value = None  # session not revoked

    session = AsyncMock()
    session.execute = AsyncMock(side_effect=[user_result, sess_result])

    response = Response()
    payload = {"sub": str(uid), "tv": 0, "jti": "old-jti", "exp": 9999999999}
    if rmb_claim:
        payload["rmb"] = True

    with patch(
        "app.api.v1.endpoints.auth.verify_token", new=AsyncMock(return_value=payload)
    ), patch(
        "app.core.token_blacklist.claim_token_jti", new=AsyncMock(return_value=True)
    ), patch(
        "app.api.v1.endpoints.auth._upsert_session", new=AsyncMock()
    ):
        await refresh_token(
            request=_make_request({REFRESH_COOKIE: "old-refresh"}),
            response=response,
            refresh_data=None,
            session=session,
        )
    return response.headers.getlist("set-cookie")


@pytest.mark.asyncio
async def test_refresh_endpoint_preserves_remember_me_window() -> None:
    headers = await _run_refresh(rmb_claim=True)
    # The rotated refresh token + cookies KEEP the extended window.
    assert _max_age(headers, REFRESH_COOKIE) == _REMEMBER_AGE
    assert _max_age(headers, CSRF_COOKIE) == _REMEMBER_AGE
    # And the new refresh token itself still carries rmb so the NEXT rotation
    # also preserves it.
    refresh_cookie = next(h for h in headers if h.startswith(f"{REFRESH_COOKIE}="))
    new_tok = refresh_cookie.split("=", 1)[1].split(";", 1)[0]
    assert _claims(new_tok).get("rmb") is True


@pytest.mark.asyncio
async def test_refresh_endpoint_default_window_when_not_remember_me() -> None:
    headers = await _run_refresh(rmb_claim=False)
    assert _max_age(headers, REFRESH_COOKIE) == _DEFAULT_AGE
    assert _max_age(headers, CSRF_COOKIE) == _DEFAULT_AGE

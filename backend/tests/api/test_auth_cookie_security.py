# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Regression tests for cookie-based auth and CSRF protection."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from fastapi import FastAPI, HTTPException, Response
from httpx import ASGITransport
from starlette.requests import Request

from app.api.v1.endpoints.auth import _get_authenticated_user, logout
from app.core.middleware import CSRFMiddleware


def _make_request(*, cookies: dict[str, str] | None = None, headers: dict[str, str] | None = None) -> Request:
    raw_headers: list[tuple[bytes, bytes]] = []
    if cookies:
        cookie_value = "; ".join(f"{key}={value}" for key, value in cookies.items())
        raw_headers.append((b"cookie", cookie_value.encode()))
    if headers:
        raw_headers.extend((key.lower().encode(), value.encode()) for key, value in headers.items())
    return Request({"type": "http", "headers": raw_headers})


@pytest.mark.asyncio
async def test_get_authenticated_user_accepts_access_cookie() -> None:
    request = _make_request(cookies={"freesdn_access": "cookie-token"})
    fake_user = SimpleNamespace(is_active=True, token_version=3)

    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = fake_user
    mock_session = AsyncMock()
    mock_session.execute.return_value = mock_result

    with patch(
        "app.api.v1.endpoints.auth.verify_token",
        new=AsyncMock(return_value={"sub": "11111111-1111-1111-1111-111111111111", "tv": 3}),
    ):
        user = await _get_authenticated_user(request=request, token=None, session=mock_session)

    assert user is fake_user


@pytest.mark.asyncio
async def test_get_authenticated_user_rejects_stale_token_version() -> None:
    request = _make_request(cookies={"freesdn_access": "cookie-token"})
    fake_user = SimpleNamespace(is_active=True, token_version=4)

    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = fake_user
    mock_session = AsyncMock()
    mock_session.execute.return_value = mock_result

    with patch(
        "app.api.v1.endpoints.auth.verify_token",
        new=AsyncMock(return_value={"sub": "11111111-1111-1111-1111-111111111111", "tv": 3}),
    ):
        with pytest.raises(HTTPException) as exc_info:
            await _get_authenticated_user(request=request, token=None, session=mock_session)

    assert exc_info.value.status_code == 401


@pytest.mark.asyncio
async def test_logout_uses_cookie_token_when_bearer_header_missing() -> None:
    request = _make_request(cookies={"freesdn_access": "cookie-token"})
    response = Response()
    from uuid import uuid4
    current_user = SimpleNamespace(id=uuid4(), token_version=4)
    # Per-device logout: /logout now does NOT bump token_version
    # and revokes ONLY the current device's session row. The function
    # calls ``_revoke_session_by_access_jti`` which does
    # ``await session.execute(...).scalar_one_or_none()`` — so the mock
    # has to return a real Result-like object, not auto-generate one.
    session = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None  # no session row to revoke
    session.execute = AsyncMock(return_value=mock_result)

    with patch(
        "app.api.v1.endpoints.auth.decode_token",
        new=AsyncMock(return_value={"jti": "logout-jti", "exp": 9999999999}),
    ), patch(
        "app.core.token_blacklist.blacklist_token",
        new=AsyncMock(),
    ) as mock_blacklist, patch(
        "app.models.api_keys.revoke_user_api_keys",
        new=AsyncMock(return_value=0),
    ):
        result = await logout(
            request=request,
            response=response,
            current_user=current_user,
            token=None,
            session=session,
        )

    assert result == {"message": "Successfully logged out"}
    # token_version is NO LONGER bumped on per-device /logout (only on
    # /logout-all). Previous assertion `== 5` updated to `== 4`.
    assert current_user.token_version == 4
    mock_blacklist.assert_awaited_once_with("logout-jti", 9999999999)
    session.commit.assert_awaited_once()
    set_cookie_headers = response.headers.getlist("set-cookie")
    assert any("freesdn_access=" in header and "Max-Age=0" in header for header in set_cookie_headers)
    assert any("freesdn_refresh=" in header and "Max-Age=0" in header for header in set_cookie_headers)


def _csrf_test_app() -> FastAPI:
    app = FastAPI()
    app.add_middleware(CSRFMiddleware)

    @app.post("/protected")
    async def protected() -> dict[str, bool]:
        return {"ok": True}

    return app


@pytest.mark.asyncio
async def test_csrf_middleware_rejects_cookie_auth_without_header() -> None:
    transport = ASGITransport(app=_csrf_test_app())
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post("/protected", cookies={"freesdn_csrf": "csrf-token"})

    assert response.status_code == 403
    assert response.json()["error"]["message"] == "CSRF token missing"


@pytest.mark.asyncio
async def test_csrf_middleware_allows_matching_cookie_and_header() -> None:
    transport = ASGITransport(app=_csrf_test_app())
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/protected",
            cookies={"freesdn_csrf": "csrf-token"},
            headers={"X-CSRF-Token": "csrf-token"},
        )

    assert response.status_code == 200
    assert response.json() == {"ok": True}


@pytest.mark.asyncio
async def test_csrf_middleware_skips_bearer_authenticated_requests() -> None:
    transport = ASGITransport(app=_csrf_test_app())
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/protected",
            headers={"Authorization": "Bearer api-token"},
        )

    assert response.status_code == 200
    assert response.json() == {"ok": True}

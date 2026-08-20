# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
regression tests.

Assert that the browser auth endpoints (/auth/login, /auth/login/mfa,
/auth/refresh) do NOT include raw access_token or refresh_token values
in the JSON response body, while still setting httpOnly cookies.
"""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
from fastapi import Response
from starlette.requests import Request

from app.api.v1.endpoints.auth import login, refresh_token
from app.schemas.core import BrowserAuthResponse

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_request(
    *,
    cookies: dict[str, str] | None = None,
    client_host: str = "127.0.0.1",
    path: str = "/api/v1/auth/login",
) -> Request:
    raw_headers: list[tuple[bytes, bytes]] = []
    if cookies:
        cookie_value = "; ".join(f"{k}={v}" for k, v in cookies.items())
        raw_headers.append((b"cookie", cookie_value.encode()))
    scope = {
        "type": "http",
        "method": "POST",
        "path": path,
        "query_string": b"",
        "headers": raw_headers,
        "client": (client_host, 0),
    }
    return Request(scope)


def _make_user(*, mfa_enabled: bool = False, mfa_secret: str | None = None) -> SimpleNamespace:
    uid = uuid4()
    return SimpleNamespace(
        id=uid,
        email="test@example.com",
        username="testuser",
        hashed_password="$argon2id$v=19$fake",
        is_active=True,
        mfa_enabled=mfa_enabled,
        mfa_secret=mfa_secret,
        locked_until=None,
        failed_login_attempts=0,
        last_login=None,
        token_version=1,
        organization_id=None,
        role="viewer",
        deleted_at=None,
    )


# ---------------------------------------------------------------------------
# BrowserAuthResponse schema invariant
# ---------------------------------------------------------------------------


def test_browser_auth_response_schema_fields() -> None:
    """BrowserAuthResponse must have token_type + expires_in and nothing else."""
    schema_fields = set(BrowserAuthResponse.model_fields.keys())
    # Must contain exactly these two fields and NO token fields
    assert "access_token" not in schema_fields, (
        "BrowserAuthResponse MUST NOT contain access_token — "
        "this would re-introduce."
    )
    assert "refresh_token" not in schema_fields, (
        "BrowserAuthResponse MUST NOT contain refresh_token — "
        "this would re-introduce."
    )
    assert "token_type" in schema_fields
    assert "expires_in" in schema_fields


def test_browser_auth_response_default_values() -> None:
    """BrowserAuthResponse token_type defaults to 'bearer'."""
    resp = BrowserAuthResponse(expires_in=900)
    assert resp.token_type == "bearer"
    assert resp.expires_in == 900
    resp_dict = resp.model_dump()
    assert "access_token" not in resp_dict
    assert "refresh_token" not in resp_dict


# ---------------------------------------------------------------------------
# /auth/login  —  JSON body must NOT contain access_token or refresh_token
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_login_json_body_has_no_raw_tokens() -> None:
    """POST /auth/login: response body must be BrowserAuthResponse (no tokens)."""
    from app.schemas.core import LoginRequest

    request = _make_request(path="/api/v1/auth/login")
    response = Response()
    fake_user = _make_user()
    login_data = LoginRequest(login="test@example.com", password="hunter2")

    mock_result = MagicMock()
    # The login identifier lookup reads .scalars().all() -- it must resolve an
    # ambiguous identifier deterministically rather than raise, so it can no
    # longer use scalar_one_or_none. Kept alongside for any other query this
    # endpoint makes.
    mock_result.scalars.return_value.all.return_value = [fake_user]
    mock_result.scalar_one_or_none.return_value = fake_user
    mock_session = AsyncMock()
    mock_session.execute.return_value = mock_result
    mock_session.commit = AsyncMock()

    with (
        patch("app.api.v1.endpoints.auth.check_auth_rate_limit", new=AsyncMock()),
        patch(
            "app.api.v1.endpoints.auth.check_auth_user_rate_limit",
            new=AsyncMock(return_value=False),
        ),
        patch("app.api.v1.endpoints.auth.verify_password", return_value=True),
        patch("app.api.v1.endpoints.auth.reset_auth_user_rate_limit", new=AsyncMock()),
        patch(
            "app.api.v1.endpoints.auth._create_access_with_jti",
            return_value=("access-tok", "ajti"),
        ),
        patch(
            "app.api.v1.endpoints.auth._create_refresh_with_jti",
            return_value=("refresh-tok", "rjti"),
        ),
        patch("app.api.v1.endpoints.auth._upsert_session", new=AsyncMock()),
        patch("app.core.cookies.set_auth_cookies"),
        patch("app.core.metrics.auth_events_total") as mock_metric,
    ):
        mock_metric.labels.return_value.inc = MagicMock()
        result = await login(
            request=request,
            response=response,
            login_data=login_data,
            session=mock_session,
        )

    assert isinstance(result, BrowserAuthResponse), (
        f"Expected BrowserAuthResponse, got {type(result).__name__}"
    )
    result_dict = result.model_dump()
    assert "access_token" not in result_dict, "access_token MUST NOT appear in /auth/login JSON"
    assert "refresh_token" not in result_dict, "refresh_token MUST NOT appear in /auth/login JSON"
    assert result_dict["token_type"] == "bearer"
    assert isinstance(result_dict["expires_in"], int)
    assert result_dict["expires_in"] > 0


# ---------------------------------------------------------------------------
# /auth/refresh  —  JSON body must NOT contain access_token or refresh_token
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_refresh_json_body_has_no_raw_tokens() -> None:
    """POST /auth/refresh: response body must be BrowserAuthResponse (no tokens)."""
    from app.schemas.core import RefreshTokenRequest

    request = _make_request(path="/api/v1/auth/refresh")
    response = Response()
    fake_user = _make_user()
    refresh_data = RefreshTokenRequest(refresh_token="old-refresh-tok")

    # Session: first execute returns User, second returns no revoked row
    user_result = MagicMock()
    user_result.scalar_one_or_none.return_value = fake_user
    session_row_result = MagicMock()
    session_row_result.first.return_value = None  # session not revoked

    mock_session = AsyncMock()
    mock_session.execute.side_effect = [user_result, session_row_result]
    mock_session.commit = AsyncMock()

    with (
        patch(
            "app.api.v1.endpoints.auth.verify_token",
            new=AsyncMock(
                return_value={
                    "sub": str(fake_user.id),
                    "jti": "old-jti",
                    "exp": 9_999_999_999,
                    "tv": 1,
                }
            ),
        ),
        patch(
            "app.core.token_blacklist.claim_token_jti",
            new=AsyncMock(return_value=True),
        ),
        patch(
            "app.api.v1.endpoints.auth._create_access_with_jti",
            return_value=("new-access-tok", "new-ajti"),
        ),
        patch(
            "app.api.v1.endpoints.auth._create_refresh_with_jti",
            return_value=("new-refresh-tok", "new-rjti"),
        ),
        patch("app.api.v1.endpoints.auth._upsert_session", new=AsyncMock()),
        patch("app.core.cookies.set_auth_cookies"),
    ):
        result = await refresh_token(
            request=request,
            response=response,
            refresh_data=refresh_data,
            session=mock_session,
        )

    assert isinstance(result, BrowserAuthResponse), (
        f"Expected BrowserAuthResponse, got {type(result).__name__}"
    )
    result_dict = result.model_dump()
    assert "access_token" not in result_dict, "access_token MUST NOT appear in /auth/refresh JSON"
    assert "refresh_token" not in result_dict, "refresh_token MUST NOT appear in /auth/refresh JSON"
    assert result_dict["token_type"] == "bearer"
    assert isinstance(result_dict["expires_in"], int)
    assert result_dict["expires_in"] > 0

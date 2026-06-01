# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from app.core.dependencies import CurrentUser
from app.modules.cameras.api import _authenticate_media_request


def _make_request(*, headers: dict[str, str] | None = None) -> Request:
    raw_headers: list[tuple[bytes, bytes]] = []
    if headers:
        raw_headers.extend((key.lower().encode(), value.encode()) for key, value in headers.items())
    return Request({"type": "http", "headers": raw_headers})


@pytest.mark.asyncio
async def test_authenticate_media_request_rejects_stale_token_version() -> None:
    request = _make_request(headers={"Authorization": "Bearer media-token"})
    session = AsyncMock()

    with patch(
        "app.core.security.verify_token",
        new=AsyncMock(return_value={"sub": "user-1", "tv": 2}),
    ), patch(
        "app.core.dependencies._get_user_by_id",
        new=AsyncMock(return_value=SimpleNamespace(is_active=True, token_version=3)),
    ):
        with pytest.raises(HTTPException) as exc_info:
            await _authenticate_media_request(request, session, None)

    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "Session has been revoked"


@pytest.mark.asyncio
async def test_authenticate_media_request_accepts_matching_token_version() -> None:
    request = _make_request(headers={"Authorization": "Bearer media-token"})
    session = AsyncMock()
    fake_user = SimpleNamespace(
        id="user-1",
        is_active=True,
        token_version=3,
        organization_id="org-1",
        role="viewer",
        site_access=[],
    )

    with patch(
        "app.core.security.verify_token",
        new=AsyncMock(return_value={"sub": "user-1", "tv": 3}),
    ), patch(
        "app.core.dependencies._get_user_by_id",
        new=AsyncMock(return_value=fake_user),
    ):
        principal = await _authenticate_media_request(request, session, None)

    # Returns a CurrentUser wrapping the ORM user (NOT the raw user), so the
    # media path carries the same principal interface as the rest of the app.
    assert isinstance(principal, CurrentUser)
    assert principal.user is fake_user
    assert principal.organization_id == "org-1"


@pytest.mark.asyncio
async def test_authenticate_media_request_returns_principal_with_site_access_method() -> None:
    """Regression: _authenticate_media_request must return a principal that
    exposes ``can_access_site`` — _enforce_camera_access -> assert_can_access_site
    calls it on the result. Returning the raw ORM ``User`` (no such method)
    raised "'User' object has no attribute 'can_access_site'" and 500'd every
    snapshot / MJPEG request.
    """
    import uuid

    request = _make_request(headers={"Authorization": "Bearer media-token"})
    session = AsyncMock()
    granted = uuid.uuid4()
    other = uuid.uuid4()
    # A site-limited user (one grant) — exercises the real grant logic, not the
    # super_admin/org_admin bypass.
    fake_user = SimpleNamespace(
        id=uuid.uuid4(),
        is_active=True,
        token_version=1,
        organization_id=uuid.uuid4(),
        role="viewer",
        site_access=[SimpleNamespace(site_id=granted, access_level="read")],
    )

    with patch(
        "app.core.security.verify_token",
        new=AsyncMock(return_value={"sub": str(fake_user.id), "tv": 1}),
    ), patch(
        "app.core.dependencies._get_user_by_id",
        new=AsyncMock(return_value=fake_user),
    ):
        principal = await _authenticate_media_request(request, session, None)

    # The exact call that previously crashed must now work, with correct semantics.
    assert principal.can_access_site(granted) is True
    assert principal.can_access_site(other) is False

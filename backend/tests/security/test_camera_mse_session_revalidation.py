# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""The live camera relay asks whether the viewer is still signed in.

``/cameras/{id}/live/mse`` authenticated with ``authenticate_websocket``, which
checks only a token's signature and claims. The realtime socket follows that
with a database check (account disabled or deleted, session signed out,
organization retired); the camera relay never did. So a disabled user's token,
or the token of a session that had signed out, opened a live camera feed for as
long as the token had left to run, and the feed then stayed up for as long as
the browser kept it open.

The first group uses a real user row in PostgreSQL; the go2rtc side is replaced
because no camera exists here.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import get_password_hash
from app.models.core import Organization, User


async def _viewer(db: AsyncSession) -> tuple[Organization, User]:
    org = Organization(id=uuid4(), name="MSE probe", slug="mse-" + uuid4().hex[:12])
    db.add(org)
    await db.flush()
    tag = uuid4().hex[:12]
    user = User(
        id=uuid4(),
        email=f"mse-{tag}@example.com",
        username=f"mse-{tag}",
        hashed_password=get_password_hash("Mse-Viewer-Passw0rd!"),
        role="org_admin",
        is_active=True,
        is_verified=True,
        organization_id=org.id,
    )
    db.add(user)
    await db.flush()
    return org, user


def _socket() -> Any:
    ws = MagicMock()
    ws.cookies = {"freesdn_access": "cookie-token"}
    ws.close = AsyncMock()
    ws.accept = AsyncMock()
    return ws


def _camera_session(camera_id: Any) -> Any:
    cam = SimpleNamespace(id=camera_id, site_id=uuid4(), deleted_at=None, channel_id=1)
    result = MagicMock()
    result.scalar_one_or_none.return_value = cam
    session = MagicMock()
    session.execute = AsyncMock(return_value=result)
    return session


def _auth(org: Organization, user: User, tv: int) -> dict[str, Any]:
    return {
        "user_id": str(user.id),
        "organization_id": str(org.id),
        "role": "org_admin",
        "token_version": tv,
        "access_jti": None,
    }


@contextlib.contextmanager
def _relay_up_to_credentials(auth: dict[str, Any], credentials: AsyncMock) -> Any:
    """Everything before the viewer check passes; go2rtc is never reached."""
    with (
        patch(
            "app.api.v1.endpoints.websocket._validate_ws_origin", new=AsyncMock(return_value=True)
        ),
        patch(
            "app.api.v1.endpoints.websocket.authenticate_websocket",
            new=AsyncMock(return_value=auth),
        ),
        patch(
            "app.modules.cameras.service.CameraAccessService.check_access",
            new=AsyncMock(return_value={"has_access": True, "can_live": True}),
        ),
        patch("app.modules.cameras.api._resolve_credentials", new=credentials),
        patch(
            "app.modules.cameras.api._ensure_go2rtc_stream",
            new=AsyncMock(side_effect=RuntimeError("go2rtc is not part of this test")),
        ),
    ):
        yield


@pytest.fixture
def real_db(db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch) -> AsyncSession:
    @contextlib.asynccontextmanager
    async def _factory() -> AsyncIterator[AsyncSession]:
        yield db_session

    monkeypatch.setattr("app.db.async_session_factory", _factory)
    return db_session


@pytest.mark.parametrize("state", ["disabled", "signed_out", "organization_deleted"])
async def test_a_dead_session_cannot_open_a_live_feed(real_db: AsyncSession, state: str) -> None:
    from app.modules.cameras.api import live_mse_ws

    org, user = await _viewer(real_db)
    auth = _auth(org, user, user.token_version or 0)
    if state == "disabled":
        user.is_active = False
    elif state == "signed_out":
        user.token_version = (user.token_version or 0) + 1
    else:
        org.deleted_at = datetime.now(UTC)
    await real_db.flush()
    credentials = AsyncMock(return_value=("192.0.2.30", 554, "viewer", "not-a-secret"))
    ws = _socket()
    camera_id = uuid4()

    with _relay_up_to_credentials(auth, credentials):
        await live_mse_ws(ws, camera_id, _camera_session(camera_id), token=None, quality="main")

    credentials.assert_not_awaited()
    ws.accept.assert_not_called()
    ws.close.assert_awaited()


async def test_control_a_live_session_gets_as_far_as_the_camera(real_db: AsyncSession) -> None:
    from app.modules.cameras.api import live_mse_ws

    org, user = await _viewer(real_db)
    credentials = AsyncMock(return_value=("192.0.2.30", 554, "viewer", "not-a-secret"))
    ws = _socket()
    camera_id = uuid4()

    with _relay_up_to_credentials(_auth(org, user, user.token_version or 0), credentials):
        await live_mse_ws(ws, camera_id, _camera_session(camera_id), token=None, quality="main")

    credentials.assert_awaited()


async def test_a_running_feed_ends_when_the_session_is_revoked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The relay re-checks on the realtime socket's interval and tears down."""
    from app.api.v1.endpoints import websocket as realtime
    from app.modules.cameras import api as cameras_api

    checks: list[bool] = []

    async def _revalidate(_info: Any) -> bool:
        checks.append(not checks)  # live at connect, revoked at the first re-check
        return checks[-1]

    class _Upstream:
        async def recv(self) -> bytes:
            await asyncio.Event().wait()
            return b""

        async def send(self, _message: Any) -> None:
            return None

    @contextlib.asynccontextmanager
    async def _connect(*_args: Any, **_kwargs: Any) -> AsyncIterator[_Upstream]:
        yield _Upstream()

    async def _browser_idle() -> dict[str, Any]:
        await asyncio.Event().wait()
        return {}

    monkeypatch.setattr(realtime, "_WS_REVALIDATION_INTERVAL_SECONDS", 0.05)
    monkeypatch.setattr(realtime, "_revalidate_ws_session", _revalidate)
    monkeypatch.setattr("websockets.connect", _connect)
    monkeypatch.setattr(cameras_api._nvr_limiter, "acquire", AsyncMock(return_value=True))
    monkeypatch.setattr(cameras_api._nvr_limiter, "release", AsyncMock())
    ws = _socket()
    ws.receive = AsyncMock(side_effect=_browser_idle)
    camera_id = uuid4()
    auth = {
        "user_id": str(uuid4()),
        "organization_id": str(uuid4()),
        "role": "org_admin",
        "token_version": 0,
        "access_jti": None,
    }

    with (
        patch(
            "app.api.v1.endpoints.websocket._validate_ws_origin", new=AsyncMock(return_value=True)
        ),
        patch(
            "app.api.v1.endpoints.websocket.authenticate_websocket",
            new=AsyncMock(return_value=auth),
        ),
        patch(
            "app.modules.cameras.service.CameraAccessService.check_access",
            new=AsyncMock(return_value={"has_access": True, "can_live": True}),
        ),
        patch(
            "app.modules.cameras.api._resolve_credentials",
            new=AsyncMock(return_value=("192.0.2.30", 554, "viewer", "not-a-secret")),
        ),
        patch("app.modules.cameras.api._ensure_go2rtc_stream", new=AsyncMock()),
    ):
        await asyncio.wait_for(
            cameras_api.live_mse_ws(
                ws, camera_id, _camera_session(camera_id), token=None, quality="main"
            ),
            timeout=5,
        )

    ws.accept.assert_awaited()
    assert checks[:2] == [True, False], checks
    ws.close.assert_awaited()

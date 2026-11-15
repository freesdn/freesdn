"""A running MJPEG camera feed ends once the viewer's session is no longer live.

The viewer was checked only when the feed opened, and the feed then ran for as
long as the browser kept it, so a disabled account or a signed-out session
went on watching. It is now rechecked on the realtime socket's interval, as
the live MSE relay does (tests/security/test_camera_mse_session_revalidation.py).
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest

from app.api.v1.endpoints import websocket as realtime
from app.modules.cameras import api as cameras_api


@pytest.fixture
def feed(monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    """An MJPEG feed served from the snapshot cache, with every device call mocked."""
    camera = SimpleNamespace(
        id=uuid4(), organization_id=uuid4(), site_id=uuid4(), deleted_at=None, channel_id=1
    )
    viewer = SimpleNamespace(
        id=uuid4(), organization_id=camera.organization_id, token_claims={"tv": 3, "jti": "j1"}
    )
    state = SimpleNamespace(camera=camera, live=True, checks=[])

    async def _revalidate(info: Any) -> bool:
        state.checks.append((info.user_id, info.token_version, info.access_jti))
        return state.live

    async def _frame(_key: str) -> bytes:
        return b"\xff\xd8jpeg\xff\xd9"

    def _no_native(_url: str) -> Any:
        raise ValueError("native MJPEG skipped in this test")

    cache = SimpleNamespace(
        subscribe=AsyncMock(return_value="k"),
        unsubscribe=AsyncMock(),
        get_frame=lambda _key: None,
        wait_frame=_frame,
    )
    monkeypatch.setattr(
        cameras_api, "_authenticate_media_request", AsyncMock(return_value=viewer)
    )
    monkeypatch.setattr(cameras_api, "_enforce_camera_access", AsyncMock())
    monkeypatch.setattr(
        cameras_api,
        "_resolve_credentials",
        AsyncMock(return_value=("192.0.2.90", 80, "viewer", "synthetic")),
    )
    monkeypatch.setattr(cameras_api, "_pin_url_to_resolved_ip", _no_native)
    monkeypatch.setattr(cameras_api, "_snapshot_cache", cache)
    monkeypatch.setattr(cameras_api._nvr_limiter, "acquire", AsyncMock(return_value=True))
    monkeypatch.setattr(cameras_api._nvr_limiter, "release", AsyncMock())
    monkeypatch.setattr(realtime, "_WS_REVALIDATION_INTERVAL_SECONDS", 0)
    monkeypatch.setattr(realtime, "_revalidate_ws_session", _revalidate)
    return state


async def _open(state: SimpleNamespace) -> Any:
    request = SimpleNamespace(cookies={}, headers={}, is_disconnected=AsyncMock(return_value=False))
    service = SimpleNamespace(get_camera=AsyncMock(return_value=state.camera))
    response = await cameras_api.stream_mjpeg(
        state.camera.id, request, service, None, quality="sub", max_fps=0, token=None
    )
    return response.body_iterator


async def test_a_running_feed_ends_when_the_session_is_revoked(feed) -> None:
    frames = await _open(feed)
    first = [await anext(frames) for _ in range(3)]  # one frame: boundary, jpeg, CRLF
    assert first[1] == b"\xff\xd8jpeg\xff\xd9"

    feed.live = False
    rest: list[bytes] = []
    async for chunk in frames:
        rest.append(chunk)
        if len(rest) > 30:  # the old feed never ended; stop reading it
            await frames.aclose()
            break

    assert len(rest) <= 3, "the feed ends at the next check, not when the browser leaves"
    assert feed.checks, "the session was rechecked while the feed ran"
    user_id, token_version, jti = feed.checks[-1]
    assert token_version == 3 and jti == "j1"


async def test_a_live_session_keeps_its_feed(feed) -> None:
    frames = await _open(feed)
    chunks = [await anext(frames) for _ in range(30)]

    assert chunks.count(b"\xff\xd8jpeg\xff\xd9") == 10
    assert feed.checks, "rechecked, and still live"
    await frames.aclose()

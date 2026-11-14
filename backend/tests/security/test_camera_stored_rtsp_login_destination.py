"""A stored RTSP URL gets the stored camera or NVR login only when it points at
the stored host of the device that login belongs to, and is then opened on the
checked address. A camera record whose ``rtsp_main_stream`` names any other
host (an attacker's RTSP server) is opened without the login, so HLS start,
codec detection and the RTSP stream URL can no longer send the recorder's
password to a host of the record's choosing."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from app.core.dependencies import CurrentUser, _load_user_permissions
from app.models.core import User
from app.modules.cameras import api
from app.modules.cameras import service as camera_service

SECRET = "nvr-s3cret"
CHECKED = "10.1.2.9"  # what the stored host resolved to and was accepted as


def _camera(stored_url: str | None, ip_address: str, nvr_id: Any = None) -> SimpleNamespace:
    return SimpleNamespace(
        id=uuid4(),
        organization_id=uuid4(),
        site_id=None,
        nvr_id=nvr_id,
        ip_address=ip_address,
        channel_id=1,
        rtsp_main_stream=stored_url,
    )


async def _admin() -> CurrentUser:
    user = User(
        id=uuid4(),
        email="a@example.com",
        organization_id=uuid4(),
        role="org_admin",
        hashed_password="x",
        is_active=True,
    )
    return CurrentUser(user=user, permissions=await _load_user_permissions(user), scoped=False)


@pytest.fixture
def opened(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """The RTSP URLs HLS start and codec detection hand to ffmpeg/ffprobe."""
    urls: list[str] = []

    async def _hls(operation: str, **params: Any) -> dict[str, Any]:
        urls.append(params["rtsp_url"])
        return {"session_id": "s", "playlist_url": "/p"}

    async def _probe(self: Any, rtsp_url: str) -> dict[str, Any]:
        urls.append(rtsp_url)
        return {"codec": "h264", "needs_transcode": False}

    monkeypatch.setattr(api, "_enforce_camera_access", AsyncMock())
    monkeypatch.setattr(api, "take_device_turn", AsyncMock())
    monkeypatch.setattr(api, "_shared_hls_request", _hls)
    monkeypatch.setattr(camera_service.TranscodeService, "detect_codec", _probe)
    monkeypatch.setattr(
        api, "_resolve_credentials", AsyncMock(return_value=(CHECKED, 80, "admin", SECRET))
    )
    return urls


async def _open_both(camera: SimpleNamespace) -> None:
    service = SimpleNamespace(get_camera=AsyncMock(return_value=camera))
    user = await _admin()
    await api.start_hls_stream(
        camera.id, api.HLSSessionStartRequest(quality="source"), user, service, MagicMock()
    )
    await api.get_codec_info(camera.id, user, service, MagicMock())


async def test_a_stored_url_on_another_host_gets_no_login(opened: list[str]) -> None:
    stored = "rtsp://attacker.example:8554/live"
    await _open_both(_camera(stored, ip_address="cam.example"))
    assert opened == [stored, stored]
    assert not any(SECRET in url for url in opened)


async def test_a_stored_url_on_the_cameras_own_host_is_pinned_and_gets_the_login(
    opened: list[str],
) -> None:
    await _open_both(
        _camera("rtsp://CAM.example.:554/Streaming/Channels/101", ip_address="cam.example")
    )
    expected = f"rtsp://admin:{SECRET}@{CHECKED}:554/Streaming/Channels/101"
    assert opened == [expected, expected]


async def test_the_nvr_login_goes_only_to_the_nvrs_own_host(
    opened: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        api, "_camera_nvr", AsyncMock(return_value=SimpleNamespace(ip_address="nvr.example"))
    )
    await _open_both(_camera("rtsp://nvr.example/Streaming/Channels/201", "10.9.9.9", uuid4()))
    assert opened == [f"rtsp://admin:{SECRET}@{CHECKED}/Streaming/Channels/201"] * 2

    opened.clear()
    # The NVR's login is not sent to any other host, the camera's own included.
    await _open_both(_camera("rtsp://10.9.9.9/Streaming/Channels/201", "10.9.9.9", uuid4()))
    assert opened == ["rtsp://10.9.9.9/Streaming/Channels/201"] * 2


@pytest.mark.parametrize(
    "stored",
    [
        "rtsp://cam.example@attacker.example/live",  # userinfo that names the camera
        "rtsp://attacker.example/cam.example",
        "rtsp://cam.example.attacker.example/live",
    ],
)
async def test_lookalike_hosts_get_no_login(opened: list[str], stored: str) -> None:
    await _open_both(_camera(stored, ip_address="cam.example"))
    assert not any(SECRET in url for url in opened)


async def test_no_stored_url_uses_the_checked_address(opened: list[str]) -> None:
    await _open_both(_camera(None, ip_address="cam.example"))
    expected = f"rtsp://admin:{SECRET}@{CHECKED}:554/Streaming/Channels/101"
    assert opened == [expected, expected]


async def _rtsp_stream_url(monkeypatch: pytest.MonkeyPatch, stored: str) -> str:
    camera = SimpleNamespace(
        id=uuid4(),
        site_id=None,
        ip_address="cam.example",
        port=554,
        username="admin",
        password_encrypted="enc",
        rtsp_main_stream=stored,
        rtsp_sub_stream=None,
    )
    monkeypatch.setattr(camera_service, "decrypt_credential", lambda _enc: SECRET)
    db = MagicMock()
    db.execute = AsyncMock(return_value=MagicMock(scalar_one_or_none=lambda: camera))
    return await camera_service.StreamService(db).get_stream_url(camera.id, "main", "rtsp")


async def test_rtsp_stream_url_carries_the_login_only_to_the_cameras_host(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert SECRET not in await _rtsp_stream_url(monkeypatch, "rtsp://attacker.example/live")
    assert await _rtsp_stream_url(monkeypatch, "rtsp://cam.example:554/live") == (
        f"rtsp://admin:{SECRET}@cam.example:554/live"
    )

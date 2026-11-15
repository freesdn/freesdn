"""A camera write has no controller row, so it names the device it reaches
(the camera, or the NVR it is reached through) and waits for that device's
turn: a poll in flight on it refuses the write with 503 before it is sent."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from uuid import uuid4

import pytest
import pytest_asyncio
from fastapi import HTTPException

import app.core.runtime_flags as rf
from app.core.config import settings
from app.core.dependencies import DEFAULT_ROLE_PERMISSIONS, CurrentUser
from app.core.device_slot import device_slots, host_slot_key, nvr_slot_key
from app.models.core import Organization, Site, User
from app.modules.cameras import api
from app.modules.cameras.config_write import staged_camera_write

HOST = "192.0.2.66"


@pytest.fixture
def mode(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(rf, "is_adapter_read_only", lambda: False)
    monkeypatch.setattr(settings, "DEVICE_WRITE_SLOT_WAIT_SECONDS", 0.2)


@pytest_asyncio.fixture
async def camera(db_session) -> Any:
    org = Organization(name="cam turns", slug=uuid4().hex)
    db_session.add(org)
    await db_session.flush()
    site = Site(name="s", slug=uuid4().hex, organization_id=org.id)
    db_session.add(site)
    await db_session.commit()
    # Stored at HOST and reached directly: HOST is the device's slot. (The
    # write used to key on the adapter's host; that is now the checked address
    # the connection is pinned to, so the stored host has to be on the record.)
    return SimpleNamespace(
        id=uuid4(),
        organization_id=org.id,
        site_id=site.id,
        name="gate",
        ip_address=HOST,
        nvr_id=None,
    )


class _Busy:
    """The device's slot held by a poll for the duration of the block."""

    def __init__(self, key: str | None = None) -> None:
        self.key = key or host_slot_key(HOST, fallback="unused")

    def __enter__(self) -> None:
        self.lease = device_slots.try_acquire(self.key, "camera poll", ttl=30)
        assert self.lease is not None

    def __exit__(self, *_exc: Any) -> None:
        device_slots.release(self.lease)


async def test_a_camera_config_write_waits_for_the_devices_turn(
    db_session, camera, mode
) -> None:
    applied: list[str] = []

    async def capture() -> dict[str, Any]:
        return {"enabled": False}

    async def apply() -> dict[str, Any]:
        applied.append("apply")
        return {"success": True}

    with _Busy(), pytest.raises(HTTPException) as busy:
        await staged_camera_write(
            db=db_session,
            actor_id=None,
            organization_id=None,
            camera=camera,
            slot_key=api._camera_slot_key(camera, HOST),
            feature="motion_detection",
            capture=capture,
            apply=apply,
        )

    assert busy.value.status_code == 503
    assert applied == []


async def test_a_ptz_tour_start_waits_for_the_cameras_turn(
    db_session, camera, mode, monkeypatch
) -> None:
    calls: list[str] = []

    class _Camera:
        host = HOST

        async def start_patrol(self, *_a: Any, **_k: Any) -> dict[str, Any]:
            calls.append("start_patrol")
            return {"success": True}

        async def disconnect(self) -> None:
            return None

    async def _adapter(_camera: Any, _session: Any) -> tuple[Any, int]:
        return _Camera(), 1

    class _Service:
        async def get_camera(self, *_a: Any, **_k: Any) -> Any:
            return camera

    monkeypatch.setattr(api, "_get_adapter_for_camera", _adapter)
    user = User(
        id=uuid4(),
        email="admin@example.com",
        username="admin",
        organization_id=camera.organization_id,
        role="org_admin",
        hashed_password="x",
        is_active=True,
    )
    principal = CurrentUser(user=user, permissions=list(DEFAULT_ROLE_PERMISSIONS["org_admin"]))

    with _Busy(), pytest.raises(HTTPException) as busy:
        await api.start_ptz_tour(camera.id, 1, principal, _Service(), db_session)
    assert busy.value.status_code == 503
    assert calls == [], "nothing is sent while the camera is busy"

    out = await api.start_ptz_tour(camera.id, 1, principal, _Service(), db_session)
    assert out.success is True and calls == ["start_patrol"]


async def test_a_recorder_stored_by_name_is_one_lock_for_api_and_poller(
    db_session, camera, mode, monkeypatch
) -> None:
    """An NVR stored as ``nvr.example`` that resolves to 10.1.2.9: the camera
    API connects to the checked address, but takes the turn the health poll
    takes (``nvr_slot_key``, the stored name), not a second lock on the IP."""
    nvr = SimpleNamespace(id=uuid4(), ip_address="nvr.example")
    camera.nvr_id = nvr.id
    camera.ip_address = "10.9.9.9"
    calls: list[str] = []

    async def _nvr(_camera: Any, _session: Any) -> Any:
        return nvr

    class _Recorder:
        host = "10.1.2.9"  # the pinned connection address

        async def start_patrol(self, *_a: Any, **_k: Any) -> dict[str, Any]:
            calls.append("start_patrol")
            return {"success": True}

        async def disconnect(self) -> None:
            return None

    async def _adapter(_camera: Any, _session: Any) -> tuple[Any, int]:
        return _Recorder(), 1

    class _Service:
        async def get_camera(self, *_a: Any, **_k: Any) -> Any:
            return camera

    monkeypatch.setattr(api, "_camera_nvr", _nvr)
    monkeypatch.setattr(api, "_get_adapter_for_camera", _adapter)
    assert await api._camera_device_slot(camera, db_session) == nvr_slot_key(nvr)
    user = User(
        id=uuid4(),
        email="admin2@example.com",
        username="admin2",
        organization_id=camera.organization_id,
        role="org_admin",
        hashed_password="x",
        is_active=True,
    )
    principal = CurrentUser(user=user, permissions=list(DEFAULT_ROLE_PERMISSIONS["org_admin"]))

    with _Busy(nvr_slot_key(nvr)), pytest.raises(HTTPException) as busy:
        await api.start_ptz_tour(camera.id, 1, principal, _Service(), db_session)
    assert busy.value.status_code == 503
    assert calls == [], "the poll holds the recorder's one lock"

    # Under the pinned address there is no lock at all: holding it blocks nothing.
    with _Busy(host_slot_key("10.1.2.9", fallback="unused")):
        out = await api.start_ptz_tour(camera.id, 1, principal, _Service(), db_session)
    assert out.success is True and calls == ["start_patrol"]


async def test_a_live_read_takes_the_stored_hosts_turn(db_session, camera, monkeypatch) -> None:
    taken: list[str] = []

    async def _turn(key: str) -> None:
        taken.append(key)

    monkeypatch.setattr(api, "take_device_turn", _turn)
    camera.ip_address = "Cam.Example."
    await api._camera_turn(camera, db_session)
    assert taken == ["host:cam.example"]

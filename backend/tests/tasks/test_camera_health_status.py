# SPDX-License-Identifier: AGPL-3.0-only
"""The NVR health poll keeps camera and recorder status current.

Found on the live fleet (four Hikvision NVRs, 64 cameras): every recorder
answered its channel status list, but refused the per-camera stream details
(``/ISAPI/Streaming/channels/{ch}01/trackinfo``) with HTTP 403. The poll then
dropped the camera, online/offline reading included, never updated a camera's
status or last seen nor the recorder's, and logged nothing. No health snapshot
was ever stored, and every camera kept the status it had at onboarding, so a
camera going dark went unnoticed. Real PostgreSQL and Valkey; the recorder is a
double.
"""

from __future__ import annotations

import logging
from types import SimpleNamespace
from typing import Any
from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy import delete, select

from app.core.crypto import encrypt_credential
from app.db.session import CelerySessionLocal
from app.models.core import Organization, Site


@pytest_asyncio.fixture
async def site():
    org_id, site_id = uuid4(), uuid4()
    async with CelerySessionLocal() as db:
        db.add(Organization(id=org_id, name="camera health", slug=f"chs-{org_id.hex}"))
        await db.flush()
        db.add(Site(id=site_id, organization_id=org_id, name="s", slug=f"chs-{site_id.hex}"))
        await db.commit()
    try:
        yield SimpleNamespace(org=org_id, site=site_id)
    finally:
        from app.modules.cameras.models import NVR, Camera, CameraHealthSnapshot

        async with CelerySessionLocal() as db:
            cams = select(Camera.id).where(Camera.organization_id == org_id)
            await db.execute(
                delete(CameraHealthSnapshot).where(CameraHealthSnapshot.camera_id.in_(cams))
            )
            await db.execute(delete(Camera).where(Camera.organization_id == org_id))
            await db.execute(delete(NVR).where(NVR.organization_id == org_id))
            await db.execute(delete(Site).where(Site.id == site_id))
            await db.execute(delete(Organization).where(Organization.id == org_id))
            await db.commit()


async def _fleet(
    site: Any,
    monkeypatch: Any,
    *,
    camera_status: str,
    recorder: type,
    nvr_status: str = "unknown",
) -> Any:
    from app.modules.cameras import service
    from app.modules.cameras.models import NVR, Camera

    nvr_id, cam_id = uuid4(), uuid4()
    async with CelerySessionLocal() as db:
        db.add(
            NVR(
                id=nvr_id,
                organization_id=site.org,
                site_id=site.site,
                name="nvr",
                ip_address="10.99.0.5",
                port=80,
                vendor="hikvision",
                username="admin",
                password_encrypted=encrypt_credential("synthetic"),
                status=nvr_status,
            )
        )
        await db.flush()
        db.add(
            Camera(
                id=cam_id,
                organization_id=site.org,
                site_id=site.site,
                nvr_id=nvr_id,
                name="lobby",
                ip_address="10.99.0.5",
                channel_id=1,
                status=camera_status,
            )
        )
        await db.commit()

    published: list[Any] = []

    class Bus:
        async def publish(self, event: Any) -> None:
            published.append(event)

    monkeypatch.setattr("app.adapters.hikvision.adapter.HikvisionAdapter", recorder)
    monkeypatch.setattr(service, "get_event_bus", lambda: Bus())
    return SimpleNamespace(nvr=nvr_id, camera=cam_id, published=published)


def _recorder(
    *,
    online: bool,
    track: dict[str, Any],
    connect_error: Exception | None = None,
    status_list_available: bool = True,
):
    class Recorder:
        def __init__(self, **_kw: Any) -> None:
            pass

        async def connect(self) -> bool:
            if connect_error is not None:
                raise connect_error
            return True

        async def disconnect(self) -> None:
            return None

        async def get_channel_status_list(self) -> list[dict[str, Any]]:
            # The real adapter answers [] when the list is refused or fails.
            return [{"id": 1, "online": online}] if status_list_available else []

        async def get_channel_track_info(self, channel: int) -> dict[str, Any]:
            return track

    return Recorder


REFUSED = {"error": "HTTP 403"}
DETAILS = {"tracks": [{"bitrate_kbps": 2048, "codec": "H.265"}]}


async def _rows(fleet: Any) -> tuple[Any, Any, list[Any]]:
    from app.modules.cameras.models import NVR, Camera, CameraHealthSnapshot

    async with CelerySessionLocal() as db:
        camera = await db.get(Camera, fleet.camera)
        nvr = await db.get(NVR, fleet.nvr)
        snaps = (
            (
                await db.execute(
                    select(CameraHealthSnapshot).where(
                        CameraHealthSnapshot.camera_id == fleet.camera
                    )
                )
            )
            .scalars()
            .all()
        )
    return camera, nvr, list(snaps)


async def test_refused_stream_details_still_record_online_and_last_seen(site, monkeypatch):
    """Fails on the old poll: nothing was saved and nothing was updated."""
    from app.tasks import cameras

    fleet = await _fleet(
        site, monkeypatch, camera_status="unknown", recorder=_recorder(online=True, track=REFUSED)
    )
    out = await cameras._poll_single_nvr_health(fleet.nvr)
    assert out["saved"] == 1 and out["online"] == 1 and out["offline"] == 0
    camera, nvr, snaps = await _rows(fleet)
    assert camera.status == "online" and camera.last_seen is not None
    assert nvr.status == "online" and nvr.last_seen is not None
    (snap,) = snaps
    assert snap.is_online is True and snap.bitrate_kbps is None


async def test_a_channel_reported_offline_marks_the_camera_offline_and_publishes(site, monkeypatch):
    """Fails on the old poll: the camera stayed "online" with no event."""
    from app.tasks import cameras

    fleet = await _fleet(
        site, monkeypatch, camera_status="online", recorder=_recorder(online=False, track=DETAILS)
    )
    out = await cameras._poll_single_nvr_health(fleet.nvr)
    assert out["offline"] == 1 and out["status_changes"] == 1
    camera, _nvr, _snaps = await _rows(fleet)
    assert camera.status == "offline"
    (event,) = fleet.published
    assert event.event_type == "camera.status.offline"
    assert event.payload["camera_id"] == str(fleet.camera)


async def test_a_camera_coming_back_publishes_online(site, monkeypatch):
    from app.tasks import cameras

    fleet = await _fleet(
        site, monkeypatch, camera_status="offline", recorder=_recorder(online=True, track=DETAILS)
    )
    await cameras._poll_single_nvr_health(fleet.nvr)
    camera, _nvr, (snap,) = await _rows(fleet)
    assert camera.status == "online" and snap.bitrate_kbps == 2048
    (event,) = fleet.published
    assert event.event_type == "camera.status.online"


async def test_maintenance_is_left_to_the_operator(site, monkeypatch):
    from app.tasks import cameras

    fleet = await _fleet(
        site,
        monkeypatch,
        camera_status="maintenance",
        recorder=_recorder(online=False, track=DETAILS),
    )
    await cameras._poll_single_nvr_health(fleet.nvr)
    camera, _nvr, _snaps = await _rows(fleet)
    assert camera.status == "maintenance" and fleet.published == []


async def test_a_failed_poll_leaves_the_recorder_status_as_it_was(site, monkeypatch):
    """A refused login or a wrong port does not show that the recorder is down."""
    from app.tasks import cameras

    fleet = await _fleet(
        site,
        monkeypatch,
        camera_status="online",
        nvr_status="online",
        recorder=_recorder(online=True, track=DETAILS, connect_error=OSError("no route")),
    )
    out = await cameras._poll_single_nvr_health(fleet.nvr)
    assert out["error"] == "Health poll failed"
    camera, nvr, _snaps = await _rows(fleet)
    assert nvr.status == "online" and camera.status == "online"


async def test_an_unavailable_status_list_keeps_stream_details_and_status(site, monkeypatch):
    """The inverse of the 403 case: details answer, the channel list does not.

    Fails on candidate 1 of 26.11.2, which dropped the reading; 26.11.1 kept it.
    """
    from app.tasks import cameras

    fleet = await _fleet(
        site,
        monkeypatch,
        camera_status="offline",
        recorder=_recorder(online=True, track=DETAILS, status_list_available=False),
    )
    out = await cameras._poll_single_nvr_health(fleet.nvr)
    assert out["saved"] == 1 and out["online"] == 0 and out["offline"] == 0
    camera, _nvr, (snap,) = await _rows(fleet)
    assert snap.bitrate_kbps == 2048
    assert camera.status == "offline" and fleet.published == []


async def test_a_recorder_in_maintenance_stays_in_maintenance(site, monkeypatch):
    from app.tasks import cameras

    fleet = await _fleet(
        site,
        monkeypatch,
        camera_status="online",
        nvr_status="maintenance",
        recorder=_recorder(online=True, track=DETAILS),
    )
    await cameras._poll_single_nvr_health(fleet.nvr)
    _camera, nvr, _snaps = await _rows(fleet)
    assert nvr.status == "maintenance" and nvr.last_seen is not None


async def test_refused_details_are_logged_once_per_recorder(site, monkeypatch, caplog):
    """Fails on the old poll: the refusal was counted and never logged."""
    from app.tasks import cameras

    fleet = await _fleet(
        site, monkeypatch, camera_status="online", recorder=_recorder(online=True, track=REFUSED)
    )
    with caplog.at_level(logging.DEBUG, logger="app.tasks.cameras"):
        await cameras._poll_single_nvr_health(fleet.nvr)
        await cameras._poll_single_nvr_health(fleet.nvr)
    refused = [r for r in caplog.records if "refused stream details" in r.getMessage()]
    assert [r.levelno for r in refused] == [logging.WARNING, logging.DEBUG]


@pytest.fixture(autouse=True)
def _fresh_refusal_log(monkeypatch):
    from app.tasks import cameras

    monkeypatch.setattr(cameras, "_REFUSED_LOGGED", set())

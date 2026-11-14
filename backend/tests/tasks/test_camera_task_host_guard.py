# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""The camera Celery tasks check a stored NVR host before sending it the login.

The camera and NVR endpoints validate a host (a plain hostname or IP address,
never loopback, link-local or cloud metadata; see the CHANGELOG entry "A camera
or NVR host must be a plain hostname or IP address"). The background tasks
read ``nvr.ip_address`` back from the row and paste it into ISAPI and RTSP URLs
with the stored login, so a row stored before that check was tightened, or
written by any other path, went out unchecked. HikvisionAdapter's own
constructor check strips a leading ``http://`` and checks only what is left,
and none of it refused a public address, which the snapshot path already does
for the same stored login.

Real PostgreSQL. The adapter is replaced by a recorder, so nothing is
contacted; the test is whether the task builds an adapter at all.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

import app.tasks.cameras as cam_tasks
from app.core.crypto import encrypt_credential
from app.models.core import Organization, Site
from app.modules.cameras.host_guard import CameraHostRefused, check_stored_camera_host
from app.modules.cameras.models import NVR, Camera, EvidenceArchive

# Each was storable before the host check was tightened (or by a direct write).
REFUSED_HOSTS = [
    "169.254.169.254",  # cloud metadata
    "127.0.0.1",
    "[::1]",
    "http://10.0.0.5@169.254.169.254",  # URL syntax: never a plain host
    "10.0.0.5:8080/ISAPI#",
    "8.8.8.8",  # public: the stored login must not leave the LAN
]


class _Recorder:
    built: list[str] = []

    def __init__(self, host: str, **_kw: object) -> None:
        _Recorder.built.append(host)

    async def connect(self) -> bool:
        return True

    async def disconnect(self) -> None:
        return None

    async def get_channel_status_list(self) -> list[dict]:
        return []

    async def get_event_state(self) -> dict:
        return {"events": []}

    async def stream_video_clip(self, **_kw: object):
        yield b""


@pytest.fixture
def recorder(monkeypatch, db_session):
    _Recorder.built = []
    monkeypatch.setattr("app.adapters.hikvision.adapter.HikvisionAdapter", _Recorder)

    class _Ctx:
        async def __aenter__(self):
            return db_session

        async def __aexit__(self, *exc):
            return False

    monkeypatch.setattr(cam_tasks, "AsyncSessionLocal", lambda: _Ctx())
    return _Recorder


async def _nvr(db_session, host: str) -> NVR:
    suffix = uuid4().hex[:8]
    org = Organization(name="Cam Org", slug=f"camg-{suffix}")
    db_session.add(org)
    await db_session.flush()
    site = Site(name="Cam Site", slug=f"camg-site-{suffix}", organization_id=org.id)
    db_session.add(site)
    await db_session.flush()
    nvr = NVR(
        organization_id=org.id,
        site_id=site.id,
        name="nvr",
        ip_address=host,
        username="admin",
        password_encrypted=encrypt_credential("stored-secret"),
    )
    db_session.add(nvr)
    await db_session.flush()
    return nvr


@pytest.mark.parametrize("host", REFUSED_HOSTS)
def test_the_point_of_use_check_refuses_what_the_endpoints_refuse(host: str) -> None:
    with pytest.raises(CameraHostRefused):
        check_stored_camera_host(host)


def test_a_private_address_passes() -> None:
    assert check_stored_camera_host(" 10.20.30.40 ") == "10.20.30.40"


@pytest.mark.parametrize("host", REFUSED_HOSTS)
async def test_health_poll_does_not_contact_a_refused_host(db_session, recorder, host):
    nvr = await _nvr(db_session, host)
    result = await cam_tasks._poll_single_nvr_health(nvr.id)
    assert recorder.built == []
    assert result["error"] == "NVR host refused"


@pytest.mark.parametrize("host", REFUSED_HOSTS)
async def test_alert_ingest_does_not_contact_a_refused_host(db_session, recorder, host):
    nvr = await _nvr(db_session, host)
    result = await cam_tasks._ingest_nvr_alerts(nvr.id)
    assert recorder.built == []
    assert result["error"] == "NVR host refused"


async def test_evidence_archive_does_not_contact_a_refused_host(db_session, recorder):
    nvr = await _nvr(db_session, "169.254.169.254")
    cam = Camera(
        organization_id=nvr.organization_id,
        site_id=nvr.site_id,
        nvr_id=nvr.id,
        name="cam",
        ip_address="10.0.0.9",
        channel_id=1,
    )
    db_session.add(cam)
    await db_session.flush()
    now = datetime.now(UTC)
    arch = EvidenceArchive(
        organization_id=nvr.organization_id,
        camera_id=cam.id,
        start_time=now - timedelta(minutes=5),
        end_time=now,
        status="pending",
    )
    db_session.add(arch)
    await db_session.flush()

    result = await cam_tasks._archive_evidence(arch.id)

    assert recorder.built == []
    assert result["status"] == "failed"
    await db_session.refresh(arch)
    assert arch.status == "failed"
    assert (arch.error or "").startswith("NVR host refused")


async def test_a_private_host_is_still_polled(db_session, recorder):
    nvr = await _nvr(db_session, "10.20.30.40")
    result = await cam_tasks._poll_single_nvr_health(nvr.id)
    assert recorder.built == ["10.20.30.40"]
    assert "error" not in result

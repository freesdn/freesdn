"""A camera behind a soft-deleted NVR is not reached with that NVR's stored
credentials (the API-side lookup now matches CameraService/StreamService)."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from app.core.crypto import encrypt_credential
from app.models.core import Organization, Site
from app.modules.cameras.api import _resolve_credentials
from app.modules.cameras.models import NVR, Camera


async def _camera_behind_an_nvr(db_session) -> tuple[NVR, Camera]:
    org = Organization(name="camera creds", slug=uuid4().hex)
    db_session.add(org)
    await db_session.flush()
    site = Site(name="s", slug=uuid4().hex, organization_id=org.id)
    db_session.add(site)
    await db_session.flush()
    nvr = NVR(
        site_id=site.id,
        organization_id=org.id,
        name="nvr1",
        ip_address="192.0.2.65",
        port=8000,
        vendor="hikvision",
        username="nvr-user",
        password_encrypted=encrypt_credential("nvr-secret"),
    )
    db_session.add(nvr)
    await db_session.flush()
    cam = Camera(
        organization_id=org.id,
        site_id=site.id,
        nvr_id=nvr.id,
        name="cam",
        ip_address="192.0.2.66",
        port=80,
        username="cam-user",
        password_encrypted=encrypt_credential("cam-secret"),
        channel_id=1,
    )
    db_session.add(cam)
    await db_session.commit()
    return nvr, cam


async def test_a_live_nvr_lends_the_camera_its_credentials(db_session) -> None:
    _nvr, cam = await _camera_behind_an_nvr(db_session)

    assert await _resolve_credentials(cam, db_session) == (
        "192.0.2.65",
        8000,
        "nvr-user",
        "nvr-secret",
    )


async def test_a_soft_deleted_nvrs_credentials_are_never_used(db_session) -> None:
    nvr, cam = await _camera_behind_an_nvr(db_session)
    nvr.deleted_at = datetime.now(UTC)
    await db_session.commit()

    assert await _resolve_credentials(cam, db_session) == (
        "192.0.2.66",
        80,
        "cam-user",
        "cam-secret",
    )

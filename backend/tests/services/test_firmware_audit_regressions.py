"""Safety and persistence regressions from the September 2026 audit."""

import hashlib
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest

from app.api.v1.endpoints.firmware import _validate_job_access
from app.core.dependencies import CurrentUser
from app.models.core import Organization, Site, User, UserRole
from app.models.devices import Device
from app.schemas.firmware import UpgradeJobCreate
from app.services.firmware import PersistentFirmwareService as Service


async def test_typed_multisite_job_persists_and_obeys_all_target_grants(db_session):
    from fastapi import HTTPException

    org = Organization(id=uuid4(), name="Firmware regression", slug=uuid4().hex)
    db_session.add(org)
    await db_session.flush()
    sites = [
        Site(id=uuid4(), organization_id=org.id, name=f"Site {i}", slug=uuid4().hex)
        for i in range(2)
    ]
    user = User(
        id=uuid4(),
        organization_id=org.id,
        email=f"{uuid4().hex}@example.invalid",
        username=uuid4().hex,
        hashed_password="not-a-login",
        role=UserRole.ORG_ADMIN,
    )
    db_session.add_all([*sites, user])
    await db_session.flush()
    devices = [
        Device(id=uuid4(), site_id=site.id, name="Disconnected fixture", device_type="switch")
        for site in sites
    ]
    db_session.add_all(devices)
    await db_session.flush()
    schedule = await Service.create_schedule(
        db_session,
        {
            "organization_id": org.id,
            "name": "Serialization fixture",
            "device_ids": [d.id for d in devices],
            "is_enabled": False,
        },
        user.id,
    )
    assert schedule.device_ids == [str(d.id) for d in devices]
    await Service.update_schedule(db_session, schedule.id, {"device_ids": [devices[1].id]})
    assert schedule.device_ids == [str(devices[1].id)]
    body = UpgradeJobCreate(device_ids=[d.id for d in devices])
    job = await Service.create_job(
        db_session, {**body.model_dump(), "organization_id": org.id}, user.id
    )
    assert job.device_ids == [str(d.id) for d in devices]
    assert job.site_id is None
    assert set(job.target_site_ids) == {str(s.id) for s in sites}
    unrestricted = CurrentUser(user=user, permissions=["*"])
    _validate_job_access(unrestricted, job)
    listed = await Service.list_jobs(db_session, organization_id=org.id)
    assert job.id in {item.id for item in listed["items"]}
    denied = await Service.list_jobs(db_session, organization_id=org.id, site_ids={sites[0].id})
    assert denied["total"] == 0
    allowed = await Service.list_jobs(
        db_session, organization_id=org.id, site_ids={s.id for s in sites}
    )
    assert allowed["total"] == 1
    foreign = await Service.list_jobs(db_session, organization_id=uuid4())
    assert foreign["total"] == 0
    foreign_user = CurrentUser(
        user=SimpleNamespace(id=uuid4(), organization_id=uuid4(), role=UserRole.ORG_ADMIN),
        permissions=["*"],
    )
    with pytest.raises(HTTPException) as exc:
        _validate_job_access(foreign_user, job)
    assert exc.value.status_code == 404
    # Exercise the original typed API entry point, including an omitted site.
    # No queue or adapter is involved while catalog execution is unavailable.
    from app.api.v1.endpoints.firmware import create_job

    created = await create_job(body, session=db_session, user=unrestricted)
    assert created.status == "failed"
    assert created.organization_id == org.id
    assert created.successful == 0
    assert created.error_message
    result = await Service.run_upgrade_job(db_session, job.id)
    assert result["status"] == "failed" and result["operation_attempted"] is False
    assert job.successful == 0 and job.failed == 2
    assert all(d["status"] == "failed" for d in job.devices)
    assert (await Service.run_upgrade_job(db_session, job.id))["skipped"] == "already terminal"
    cancelled = await Service.cancel_job(db_session, job.id)
    assert cancelled.status == "failed"  # A terminal failure is never rewritten as cancellation.


@pytest.mark.parametrize("bad_checksum", [False, True])
async def test_cache_requires_real_verified_bytes(tmp_path, monkeypatch, bad_checksum):
    import app.core.security_utils as security
    import app.services.firmware as module

    content = b"firmware bytes, not a deployed device image"
    fw = SimpleNamespace(
        id=uuid4(),
        checksum_sha256=hashlib.sha256(content).hexdigest(),
        file_path=None,
        is_cached=False,
        download_url="https://vendor.invalid/file",
    )
    monkeypatch.setattr(module, "FIRMWARE_DIR", tmp_path)
    monkeypatch.setattr(Service, "get_firmware", AsyncMock(return_value=fw))

    async def download(*args, **kwargs):
        assert kwargs["max_response_bytes"] == security.MAX_FIRMWARE_UPLOAD_BYTES
        assert kwargs["allowed_schemes"] == frozenset({"https"})
        kwargs["download_to"].write(b"corrupt" if bad_checksum else content)

    monkeypatch.setattr(security, "safe_http_request", download)
    session = AsyncMock()
    if bad_checksum:
        with pytest.raises(ValueError, match="checksum mismatch"):
            await Service.cache_firmware(session, fw.id)
        assert not fw.is_cached and fw.file_path is None
        assert list(tmp_path.iterdir()) == []
    else:
        await Service.cache_firmware(session, fw.id)
        assert fw.is_cached and Path(fw.file_path).read_bytes() == content
        assert fw.file_size_bytes == len(content)
        assert not list(tmp_path.glob("*.part"))


async def test_cache_without_checksum_never_downloads(monkeypatch):
    import app.core.security_utils as security

    fw = SimpleNamespace(checksum_sha256=None)
    monkeypatch.setattr(Service, "get_firmware", AsyncMock(return_value=fw))
    download = AsyncMock()
    monkeypatch.setattr(security, "safe_http_request", download)
    with pytest.raises(ValueError, match="SHA-256"):
        await Service.cache_firmware(AsyncMock(), uuid4())
    download.assert_not_called()

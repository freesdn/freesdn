# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
``POST /backups/import`` could not ingest any file FreeSDN produces -- and
reported success for all of them.

``create_backup`` moved the payload to the v2 ``BackupArchive`` shape
(``{manifest, contributors:{core:{sites,...}}}``) but ``import_config`` was
never updated: it still did ``data = config.get("data", config)`` and then
``data.get("sites")``. A v2 archive has no ``data`` key, so ``data`` became the
archive ENVELOPE, every ``model_map`` lookup returned ``[]``, and the metadata
block read ``version: null / created_at: null / product_version: null``.

The failure was invisible because ``import_config`` returns
``{"success": false, ...}`` inside an HTTP 200. The Backups page never checks
``success`` and never renders ``message``, so a rejected file opened the preview
dialog showing "Devices 0 / Sites 0 / Created: Unknown", and clicking Import
produced a second 200 and a green "Import complete" toast. Nothing was imported,
in every case.

These tests cover the v2 round trip (the shape the product actually writes) and
the legacy pre-v2 envelope, which must keep working.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import uuid
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio

from app.services.backup import BackupService
from app.services.backup_contributors import (
    BackupArchive,
    BackupManifest,
    ContributorEntry,
)

ORG = uuid.uuid4()


def _fsdn(payload_obj: Any, *, encrypted: bool = False) -> bytes:
    """Build a .fsdn file exactly the way ``create_backup`` step 4 does."""
    raw = (
        payload_obj.model_dump_json(indent=2).encode("utf-8")
        if hasattr(payload_obj, "model_dump_json")
        else json.dumps(payload_obj, default=str).encode("utf-8")
    )
    compressed = gzip.compress(raw)
    header = {
        "backup_id": str(uuid.uuid4()),
        "checksum": hashlib.sha256(compressed).hexdigest(),
        "encrypted": encrypted,
        "compressed": True,
        "secrets": False,
        "key_id": None,
        "created_at": datetime.now(UTC).isoformat(),
        "version": "2.0",
    }
    hb = json.dumps(header).encode("utf-8")
    return len(hb).to_bytes(4, "big") + hb + compressed


def _v2_archive() -> BackupArchive:
    core = {
        "sites": [
            {
                "id": str(uuid.uuid4()),
                "name": "HQ",
                "slug": "hq",
                "organization_id": str(ORG),
            },
            {
                "id": str(uuid.uuid4()),
                "name": "DC",
                "slug": "dc",
                "organization_id": str(ORG),
            },
        ],
        "controllers": [
            {"id": str(uuid.uuid4()), "name": "omada-1", "organization_id": str(ORG)},
        ],
    }
    core["controllers"][0].update(
        site_id=core["sites"][0]["id"],
        controller_type="omada",
        host="192.0.2.70",
        port=443,
    )
    return BackupArchive(
        manifest=BackupManifest(
            backup_id=str(uuid.uuid4()),
            created_at=datetime(2026, 8, 20, 3, 0, tzinfo=UTC),
            organization_id=str(ORG),
            source_version="26.08.4",
            contributors=[
                ContributorEntry(
                    id="core",
                    schema_version="1.0.0",
                    counts={"sites": 2, "controllers": 1},
                )
            ],
        ),
        contributors={"core": core},
    )


def _service() -> BackupService:
    """A BackupService whose session answers every lookup with "not found",
    so a dry run walks the full record loop without a database."""
    session = MagicMock()
    empty = MagicMock()
    empty.scalars.return_value.first.return_value = None
    session.execute = AsyncMock(return_value=empty)
    session.rollback = AsyncMock()
    BackupService._contributors_initialized = True
    return BackupService(session)


# ── the v2 shape the product actually writes ─────────────────────────


async def test_a_v2_archive_imports_its_records() -> None:
    """The whole defect in one assert: today's own backup format, read back.

    Mutation caught: restoring ``data = config.get("data", config)`` as the
    only branch -- ``would_import`` goes back to ``{}``.
    """
    out = await _service().import_config(
        _fsdn(_v2_archive()), dry_run=True, organization_id=ORG
    )
    assert out["success"] is True
    assert out["would_import"]["sites"]["created"] == 2
    assert out["would_import"]["controllers"]["created"] == 1


async def test_a_v2_archive_reports_its_provenance() -> None:
    """The import-preview dialog renders ``created_at`` and ``product_version``
    and nothing else. Both were null for every v2 archive, so the operator was
    asked to confirm an import of a file the UI could not describe.

    Mutation caught: reading the pre-v2 envelope keys (``version`` /
    ``freesdn_version``) off a v2 archive -- both come back None.
    """
    out = await _service().import_config(
        _fsdn(_v2_archive()), dry_run=True, organization_id=ORG
    )
    meta = out["metadata"]
    assert meta["product_version"] == "26.08.4"
    assert meta["created_at"] is not None
    assert meta["created_at"].startswith("2026-08-20")
    assert meta["version"] == "2.0"


# ── the legacy shape must keep working ───────────────────────────────


async def test_the_pre_v2_envelope_still_imports() -> None:
    """Old .fsdn files on disk carry ``{version, schema_version, data:{...}}``.
    Teaching the reader the v2 shape must not orphan them.

    Mutation caught: routing every payload through BackupArchive.model_validate
    -- the legacy envelope fails validation and the file is rejected outright.
    """
    legacy = {
        "version": "2.0",
        "schema_version": 2,
        "created_at": "2026-01-02T03:04:05+00:00",
        "freesdn_version": "26.01.0",
        "organization_id": str(ORG),
        "data": {"sites": [{"id": str(uuid.uuid4()), "name": "HQ", "slug": "hq"}]},
    }
    out = await _service().import_config(
        _fsdn(legacy), dry_run=True, organization_id=ORG
    )
    assert out["success"] is True
    assert out["would_import"]["sites"]["created"] == 1
    assert out["metadata"]["product_version"] == "26.01.0"
    assert out["metadata"]["created_at"] == "2026-01-02T03:04:05+00:00"


# ── rejections stay rejections ───────────────────────────────────────


async def test_an_encrypted_fsdn_is_still_refused_not_silently_emptied() -> None:
    """``/backups/{id}/download`` emits an encrypted .fsdn and the file picker
    accepts it. It must come back as an explicit refusal with a reason, never
    as a success with an empty summary.

    Mutation caught: dropping the ``header["encrypted"]`` guard in
    _parse_fsdn_file, which would hand gzip garbage to json.loads.
    """
    out = await _service().import_config(
        _fsdn(_v2_archive(), encrypted=True), dry_run=True, organization_id=ORG
    )
    assert out["success"] is False
    assert "restore endpoint" in out["message"]


async def test_an_unparseable_archive_is_refused_with_a_reason() -> None:
    """A .fsdn whose payload is neither shape must say so rather than import
    nothing under a green banner.

    Mutation caught: falling back to ``config.get("data", config)`` on a
    validation failure instead of returning success=False.
    """
    out = await _service().import_config(
        _fsdn({"manifest": {"nonsense": True}}), dry_run=True, organization_id=ORG
    )
    assert out["success"] is False
    assert "Unrecognized" in out["message"]


# ── the endpoint must not dress a refusal as a success ───────────────


class _UploadFile:
    def __init__(self, data: bytes) -> None:
        self._data = data
        self._done = False

    async def read(self, size: int = -1) -> bytes:
        if self._done:
            return b""
        self._done = True
        return self._data


class _Principal:
    is_superuser = True
    organization_id = ORG
    _scoped = False


async def _call_endpoint(data: bytes) -> Any:
    from app.api.v1.endpoints import backups as backups_api

    session = MagicMock()
    empty = MagicMock()
    empty.scalars.return_value.first.return_value = None
    session.execute = AsyncMock(return_value=empty)
    session.rollback = AsyncMock()
    BackupService._contributors_initialized = True
    return await backups_api.import_config(
        session,
        _Principal(),
        file=_UploadFile(data),
        dry_run=True,
        overwrite_existing=False,
    )


async def test_a_refused_file_comes_back_as_400_not_200() -> None:
    """``import_config`` returns success=false inside an HTTP 200. The Backups
    page never checks ``success`` and never renders ``message``, so the refusal
    reached the operator as a preview dialog full of zeros followed by a green
    "Import complete" toast. axios only raises on a non-2xx.

    Mutation caught: deleting the ``if not result.get("success")`` guard in
    backups.py -- the call returns a dict again instead of raising.
    """
    from fastapi import HTTPException

    try:
        result = await _call_endpoint(_fsdn(_v2_archive(), encrypted=True))
    except HTTPException as exc:
        assert exc.status_code == 400
        # The reason must travel: the UI renders `detail` via getApiErrorMessage.
        assert "restore endpoint" in str(exc.detail)
    else:
        raise AssertionError(f"a refused import returned HTTP 200: {result}")


async def test_a_good_file_still_returns_its_summary() -> None:
    """The guard must only fire on a refusal.

    Mutation caught: inverting the check, or raising on every response.
    """
    result = await _call_endpoint(_fsdn(_v2_archive()))
    assert result["success"] is True
    assert result["would_import"]["sites"]["created"] == 2


IMPORT_PRIVATE_MARKER = "synthetic-import-private-value-do-not-publish"


@pytest.mark.parametrize("failure", [ValueError, RuntimeError])
async def test_import_parser_exception_text_is_not_operator_feedback(
    monkeypatch, caplog, failure
):
    service = _service()

    def fail(_data):
        raise failure(IMPORT_PRIVATE_MARKER)

    monkeypatch.setattr(service, "_parse_fsdn_file", fail)
    result = await service.import_config(_fsdn(_v2_archive()), organization_id=ORG)
    assert result["success"] is False
    assert "Invalid .fsdn" in result["message"]
    assert IMPORT_PRIVATE_MARKER not in json.dumps(result) + caplog.text
    service.db.execute.assert_not_awaited()


async def test_import_manifest_validation_does_not_echo_uploaded_values(caplog):
    archive = _v2_archive().model_dump(mode="json")
    archive["manifest"]["backup_id"] = [IMPORT_PRIVATE_MARKER]
    result = await _service().import_config(_fsdn(archive), organization_id=ORG)
    assert result["success"] is False
    assert "Unrecognized .fsdn" in result["message"]
    assert IMPORT_PRIVATE_MARKER not in json.dumps(result) + caplog.text


async def test_import_checksum_refusal_remains_actionable():
    data = _fsdn(_v2_archive()) + b"corruption"
    result = await _service().import_config(data, organization_id=ORG)
    assert result["success"] is False
    assert "Checksum verification failed" in result["message"]


async def test_import_decompression_limit_refusal_remains_actionable(monkeypatch):
    from app.services import backup

    original = backup._bounded_gunzip
    monkeypatch.setattr(
        backup, "_bounded_gunzip", lambda payload: original(payload, limit=32)
    )
    result = await _service().import_config(_fsdn(_v2_archive()), organization_id=ORG)
    assert result["success"] is False
    assert "Decompressed backup exceeds" in result["message"]


@pytest.mark.parametrize("failure", [ValueError, RuntimeError])
async def test_import_commit_failure_rolls_back_without_exposing_exception(
    caplog, failure
):
    service = _service()
    service.db.commit = AsyncMock(side_effect=failure(IMPORT_PRIVATE_MARKER))
    service.db.rollback = AsyncMock()
    result = await service.import_config(
        _fsdn(_v2_archive()), dry_run=False, organization_id=ORG
    )
    assert result["success"] is False and result["dry_run"] is False
    assert "no changes were applied" in result["message"]
    assert IMPORT_PRIVATE_MARKER not in json.dumps(result) + caplog.text
    assert "imported" not in result
    service.db.commit.assert_awaited_once()
    service.db.rollback.assert_awaited_once()


@pytest.mark.parametrize("failure", [ValueError, RuntimeError])
async def test_import_request_lookup_failure_is_generic_http_500(caplog, failure):
    from fastapi import FastAPI
    from httpx import ASGITransport, AsyncClient

    from app.api.v1.endpoints import backups

    session = _service().db
    session.execute.side_effect = failure(IMPORT_PRIVATE_MARKER)
    session.rollback = AsyncMock()
    api = FastAPI()
    api.include_router(backups.router)

    async def request_session():
        try:
            yield session
        except Exception:
            await session.rollback()
            raise

    api.dependency_overrides[backups.get_session] = request_session
    api.dependency_overrides[backups.get_current_active_user] = _Principal
    async with AsyncClient(
        transport=ASGITransport(app=api), base_url="http://owned"
    ) as client:
        response = await client.post(
            "/import", files={"file": ("config.fsdn", _fsdn(_v2_archive()))}
        )
    assert response.status_code == 500
    assert "Configuration import failed" in response.json()["detail"]
    assert IMPORT_PRIVATE_MARKER not in response.text + caplog.text
    session.rollback.assert_awaited_once()


@pytest_asyncio.fixture
async def import_database():
    from sqlalchemy.ext.asyncio import AsyncSession

    from app.db.session import create_test_engine
    from app.models import Organization

    engine = create_test_engine()
    try:
        async with engine.connect() as connection:
            outer = await connection.begin()
            try:
                async with AsyncSession(
                    connection,
                    expire_on_commit=False,
                    autoflush=False,
                    join_transaction_mode="create_savepoint",
                ) as session:
                    organization = Organization(
                        name="Import diagnostic fixture", slug=uuid.uuid4().hex
                    )
                    session.add(organization)
                    await session.commit()
                    yield session, organization.id
            finally:
                await outer.rollback()
    finally:
        await engine.dispose()


async def test_real_import_constraint_failure_rolls_back_all_rows_and_hides_sql(
    import_database, caplog
):
    from sqlalchemy import select

    from app.models import Site

    session, organization_id = import_database
    slug = uuid.uuid4().hex
    records = [
        {
            "id": str(uuid.uuid4()),
            "name": "Duplicate import",
            "slug": slug,
            "description": IMPORT_PRIVATE_MARKER,
        }
        for _ in range(2)
    ]
    result = await BackupService(session).import_config(
        _fsdn({"sites": records}), dry_run=False, organization_id=organization_id
    )
    assert result["success"] is False
    assert "no changes were applied" in result["message"]
    assert IMPORT_PRIVATE_MARKER not in json.dumps(result) + caplog.text
    assert "IntegrityError" in caplog.text
    assert (
        await session.execute(
            select(Site).where(Site.organization_id == organization_id)
        )
    ).scalars().all() == []


async def test_real_import_success_and_preview_keep_their_write_semantics(
    import_database,
):
    from sqlalchemy import select

    from app.models import Site

    session, organization_id = import_database
    data = _fsdn(
        {
            "sites": [
                {
                    "id": str(uuid.uuid4()),
                    "name": "Import survivor",
                    "slug": uuid.uuid4().hex,
                }
            ]
        }
    )
    service = BackupService(session)
    preview = await service.import_config(data, organization_id=organization_id)
    assert preview["success"] and preview["would_import"]["sites"]["created"] == 1
    assert (
        await session.execute(
            select(Site).where(Site.organization_id == organization_id)
        )
    ).scalars().all() == []
    applied = await service.import_config(
        data, dry_run=False, organization_id=organization_id
    )
    assert applied["success"] and applied["imported"]["sites"]["created"] == 1
    rows = (
        (
            await session.execute(
                select(Site).where(Site.organization_id == organization_id)
            )
        )
        .scalars()
        .all()
    )
    assert len(rows) == 1 and rows[0].name == "Import survivor"


@pytest.mark.parametrize(
    "engine_name",
    [
        "engine",
        "_audit_engine",
        "readiness_engine",
        "security_engine",
        "_celery_engine",
        "logdb_engine",
        "readiness_logdb_engine",
        "_celery_logdb_engine",
        "create_test_engine",
    ],
)
async def test_shared_database_engine_logs_sql_without_bound_values(
    engine_name, caplog
):
    from sqlalchemy import text

    from app.db import session as database

    engine = getattr(database, engine_name)
    if engine_name == "create_test_engine":
        engine = engine()
    if engine is None:
        pytest.skip("LogDB must be configured to exercise its engine")
    original_echo = engine.echo
    try:
        engine.echo = True
        async with engine.connect() as connection:
            result = await connection.execute(
                text("SELECT CAST(:value AS TEXT)"), {"value": IMPORT_PRIVATE_MARKER}
            )
            assert result.scalar_one() == IMPORT_PRIVATE_MARKER
        assert "SELECT" in caplog.text
        assert IMPORT_PRIVATE_MARKER not in caplog.text
    finally:
        engine.echo = original_echo
        await engine.dispose()


@pytest_asyncio.fixture
async def import_scope_database(import_database):
    from app.models import Controller, Device, Organization, Site

    session, organization_id = import_database
    foreign = Organization(name="Foreign import fixture", slug=uuid.uuid4().hex)
    session.add(foreign)
    await session.flush()
    local_site = Site(
        organization_id=organization_id, name="Owned site", slug=uuid.uuid4().hex
    )
    foreign_site = Site(
        organization_id=foreign.id, name="Foreign site", slug=uuid.uuid4().hex
    )
    session.add_all([local_site, foreign_site])
    await session.flush()
    controller = Controller(
        site_id=foreign_site.id,
        name="Foreign controller",
        controller_type="omada",
        host="192.0.2.71",
        port=443,
    )
    session.add(controller)
    await session.flush()
    device = Device(
        site_id=foreign_site.id,
        controller_id=controller.id,
        name="Foreign device",
        device_type="switch",
    )
    session.add(device)
    await session.commit()
    return session, organization_id, local_site, foreign_site, controller, device


@pytest.mark.parametrize("resource", ["controllers", "devices"])
@pytest.mark.parametrize("operation", ["insert", "update"])
async def test_import_does_not_write_records_owned_through_a_foreign_site(
    import_scope_database, resource, operation
):
    from sqlalchemy import select

    from app.models import Controller, Device

    session, organization_id, _local_site, foreign_site, controller, device = (
        import_scope_database
    )
    existing = controller if resource == "controllers" else device
    model = Controller if resource == "controllers" else Device
    original_name = existing.name
    proposed_name = "Cross-organization import must be refused"
    record = {
        "id": str(existing.id if operation == "update" else uuid.uuid4()),
        "name": proposed_name,
        "site_id": str(foreign_site.id),
    }
    if resource == "controllers":
        record.update(controller_type="omada", host="192.0.2.72", port=443)
    else:
        record.update(device_type="switch", controller_id=str(controller.id))
    await BackupService(session).import_config(
        _fsdn({resource: [record]}),
        dry_run=False,
        overwrite_existing=True,
        organization_id=organization_id,
    )
    await session.refresh(existing)
    assert existing.name == original_name
    rows = (
        (await session.execute(select(model).where(model.name == proposed_name)))
        .scalars()
        .all()
    )
    assert rows == []


async def test_import_device_cannot_reference_a_foreign_controller(
    import_scope_database,
):
    from sqlalchemy import select

    from app.models import Device

    session, organization_id, local_site, _foreign_site, controller, _device = (
        import_scope_database
    )
    record = {
        "id": str(uuid.uuid4()),
        "name": "Invalid controller reference",
        "site_id": str(local_site.id),
        "controller_id": str(controller.id),
        "device_type": "switch",
    }
    await BackupService(session).import_config(
        _fsdn({"devices": [record]}), dry_run=False, organization_id=organization_id
    )
    rows = (
        (await session.execute(select(Device).where(Device.name == record["name"])))
        .scalars()
        .all()
    )
    assert rows == []


@pytest.mark.parametrize(
    "field,original,uploaded",
    [
        ("token_version", 12, 0),
        ("mfa_enabled", True, False),
        (
            "mfa_backup_codes",
            "synthetic-existing-encrypted-codes",
            "synthetic-replacement",
        ),
        ("mfa_pending_secret", "synthetic-pending-secret", "synthetic-replacement"),
        ("auth_provider", "oidc", "local"),
        ("external_id", "synthetic-established-subject", "synthetic-other-subject"),
    ],
)
async def test_config_merge_preserves_existing_account_security_state(
    import_database, field, original, uploaded
):
    from app.models import User

    session, organization_id = import_database
    identity = uuid.uuid4().hex
    user = User(
        organization_id=organization_id,
        username=identity,
        email=identity + "@example.invalid",
        hashed_password="synthetic-disabled-login-fixture",
        **{field: original},
    )
    session.add(user)
    await session.commit()
    result = await BackupService(session).import_config(
        _fsdn(
            {
                "users": [
                    {
                        "id": str(user.id),
                        "full_name": "Allowed profile update",
                        field: uploaded,
                    }
                ]
            }
        ),
        dry_run=False,
        overwrite_existing=True,
        organization_id=organization_id,
    )
    assert result["success"] is True
    await session.refresh(user)
    assert getattr(user, field) == original
    assert user.full_name == "Allowed profile update"


async def test_organization_import_does_not_modify_an_unscoped_account(import_database):
    from app.models import User

    session, organization_id = import_database
    identity = uuid.uuid4().hex
    user = User(
        organization_id=None,
        username=identity,
        email=identity + "@example.invalid",
        hashed_password="synthetic-disabled-login-fixture",
        full_name="Global account",
    )
    session.add(user)
    await session.commit()
    await BackupService(session).import_config(
        _fsdn({"users": [{"id": str(user.id), "full_name": "Must not apply"}]}),
        dry_run=False,
        overwrite_existing=True,
        organization_id=organization_id,
    )
    await session.refresh(user)
    assert user.organization_id is None and user.full_name == "Global account"


async def test_import_new_site_controller_device_chain_keeps_its_references(
    import_database,
):
    from sqlalchemy import select

    from app.models import Controller, Device, Site

    session, organization_id = import_database
    site_id, controller_id, device_id = (str(uuid.uuid4()) for _ in range(3))
    payload = {
        "sites": [
            {"id": site_id, "name": "Imported chain site", "slug": uuid.uuid4().hex}
        ],
        "controllers": [
            {
                "id": controller_id,
                "site_id": site_id,
                "name": "Imported chain controller",
                "controller_type": "omada",
                "host": "192.0.2.73",
                "port": 443,
            }
        ],
        "devices": [
            {
                "id": device_id,
                "site_id": site_id,
                "controller_id": controller_id,
                "name": "Imported chain device",
                "device_type": "switch",
            }
        ],
    }
    result = await BackupService(session).import_config(
        _fsdn(payload), dry_run=False, organization_id=organization_id
    )
    assert result["success"] is True
    site = (
        await session.execute(select(Site).where(Site.name == "Imported chain site"))
    ).scalar_one()
    controller = (
        await session.execute(
            select(Controller).where(Controller.name == "Imported chain controller")
        )
    ).scalar_one()
    device = (
        await session.execute(
            select(Device).where(Device.name == "Imported chain device")
        )
    ).scalar_one()
    assert site.organization_id == organization_id
    assert controller.site_id == device.site_id == site.id
    assert device.controller_id == controller.id


@pytest.mark.parametrize("dry_run", [True, False])
async def test_import_validates_the_whole_plan_before_writing(
    import_scope_database, dry_run
):
    from sqlalchemy import select

    from app.models import Site

    session, organization_id, _local_site, foreign_site, _controller, _device = (
        import_scope_database
    )
    new_id = uuid.uuid4()
    payload = {
        "sites": [
            {"id": str(new_id), "name": "Must roll back", "slug": uuid.uuid4().hex}
        ],
        "controllers": [
            {
                "id": str(uuid.uuid4()),
                "site_id": str(foreign_site.id),
                "name": "Foreign reference",
                "controller_type": "omada",
                "host": "192.0.2.80",
                "port": 443,
            }
        ],
    }
    result = await BackupService(session).import_config(
        _fsdn(payload), dry_run=dry_run, organization_id=organization_id
    )
    assert result["success"] is False
    assert (
        await session.execute(select(Site).where(Site.id == new_id))
    ).scalar_one_or_none() is None


async def test_import_preview_counts_updates_without_mutating_existing_rows(
    import_scope_database,
):
    session, organization_id, site, _foreign_site, _controller, _device = (
        import_scope_database
    )
    original_name = site.name
    payload = _fsdn({"sites": [{"id": str(site.id), "name": "Reviewed update"}]})
    result = await BackupService(session).import_config(
        payload, dry_run=True, overwrite_existing=True, organization_id=organization_id
    )
    assert result["success"] and result["would_import"]["sites"]["updated"] == 1
    assert site.name == original_name
    await session.refresh(site)
    assert site.name == original_name
    applied = await BackupService(session).import_config(
        payload, dry_run=False, overwrite_existing=True, organization_id=organization_id
    )
    assert applied["success"] and applied["imported"]["sites"]["updated"] == 1
    await session.refresh(site)
    assert site.name == "Reviewed update"


@pytest.mark.parametrize(
    "payload",
    [
        {"sites": {}},
        {"sites": [None]},
        {"sites": [{"id": "bad-id", "name": "Bad", "slug": "bad"}]},
        {
            "sites": [
                {"id": "11111111-1111-1111-1111-111111111111", "name": "Missing slug"}
            ]
        },
        {
            "sites": [
                {"id": "11111111-1111-1111-1111-111111111111", "name": 7, "slug": "bad"}
            ]
        },
        {
            "sites": [
                {
                    "id": "11111111-1111-1111-1111-111111111111",
                    "name": "Bad",
                    "slug": "bad",
                    "settings": [],
                }
            ]
        },
    ],
    ids=[
        "section-not-list",
        "record-not-object",
        "invalid-id",
        "required-field",
        "field-type",
        "structured-field",
    ],
)
async def test_import_rejects_malformed_resource_data_before_mutation(
    import_database, payload
):
    from sqlalchemy import select

    from app.models import Site

    session, organization_id = import_database
    result = await BackupService(session).import_config(
        _fsdn(payload), dry_run=False, organization_id=organization_id
    )
    assert result["success"] is False and result["message"]
    assert (
        await session.execute(
            select(Site).where(Site.organization_id == organization_id)
        )
    ).scalars().all() == []


async def test_import_rejects_duplicate_record_ids_in_preview_and_apply(
    import_database,
):
    from sqlalchemy import select

    from app.models import Site

    session, organization_id = import_database
    identifier = str(uuid.uuid4())
    data = _fsdn(
        {
            "sites": [
                {"id": identifier, "name": "First", "slug": uuid.uuid4().hex},
                {"id": identifier, "name": "Second", "slug": uuid.uuid4().hex},
            ]
        }
    )
    for dry_run in (True, False):
        result = await BackupService(session).import_config(
            data, dry_run=dry_run, organization_id=organization_id
        )
        assert result["success"] is False
    assert (
        await session.execute(
            select(Site).where(Site.organization_id == organization_id)
        )
    ).scalars().all() == []


@pytest.mark.parametrize(
    "reference_kind",
    [
        "foreign-credential",
        "other-site-credential",
        "foreign-site-group",
        "deleted-site",
    ],
)
async def test_import_requires_live_scoped_references(
    import_scope_database, reference_kind
):
    from sqlalchemy import select

    from app.models import Controller, Credential, Site
    from app.models.enterprise import SiteGroup

    session, organization_id, local_site, foreign_site, _controller, _device = (
        import_scope_database
    )
    record = {
        "id": str(uuid.uuid4()),
        "site_id": str(local_site.id),
        "name": "Reference rejection",
        "controller_type": "omada",
        "host": "192.0.2.81",
        "port": 443,
    }
    model = Controller
    resource = "controllers"
    if reference_kind == "foreign-site-group":
        group = SiteGroup(
            organization_id=foreign_site.organization_id, name=uuid.uuid4().hex
        )
        session.add(group)
        await session.commit()
        record = {
            "id": str(uuid.uuid4()),
            "name": "Reference rejection",
            "slug": uuid.uuid4().hex,
            "site_group_id": str(group.id),
        }
        model, resource = Site, "sites"
    elif reference_kind == "deleted-site":
        local_site.deleted_at = datetime.now(UTC)
        await session.commit()
    else:
        scoped_site = Site(
            organization_id=organization_id,
            name="Credential-only site",
            slug=uuid.uuid4().hex,
        )
        session.add(scoped_site)
        await session.flush()
        credential = Credential(
            organization_id=foreign_site.organization_id
            if reference_kind == "foreign-credential"
            else organization_id,
            site_id=None if reference_kind == "foreign-credential" else scoped_site.id,
            name="Scoped fixture",
            credential_type="ssh",
        )
        session.add(credential)
        await session.commit()
        record["credential_id"] = str(credential.id)
    result = await BackupService(session).import_config(
        _fsdn({resource: [record]}), dry_run=False, organization_id=organization_id
    )
    assert result["success"] is False
    assert (
        await session.execute(select(model).where(model.name == "Reference rejection"))
    ).scalars().all() == []


async def test_new_imported_profile_is_disabled_and_cannot_receive_archived_authentication(
    import_database,
):
    from sqlalchemy import select

    from app.core.security import verify_password
    from app.models import User, UserRole

    session, organization_id = import_database
    identifier = uuid.uuid4()
    identity = uuid.uuid4().hex
    payload = _fsdn(
        {
            "users": [
                {
                    "id": str(identifier),
                    "email": identity + "@example.invalid",
                    "username": identity,
                    "full_name": "Imported profile",
                    "role": "super_admin",
                    "hashed_password": "synthetic-source-hash",
                    "is_active": True,
                    "is_verified": True,
                    "mfa_enabled": True,
                    "token_version": 999,
                    "auth_provider": "oidc",
                    "external_id": "synthetic-source-subject",
                }
            ]
        }
    )
    preview = await BackupService(session).import_config(
        payload, organization_id=organization_id
    )
    assert preview["success"] and preview["would_import"]["users"]["created"] == 1
    assert "disabled" in preview["message"]
    assert (
        await session.execute(select(User).where(User.id == identifier))
    ).scalar_one_or_none() is None
    result = await BackupService(session).import_config(
        payload, dry_run=False, organization_id=organization_id
    )
    assert result["success"] and "disabled" in result["message"]
    user = (
        await session.execute(select(User).where(User.id == identifier))
    ).scalar_one()
    assert (
        user.organization_id == organization_id and user.full_name == "Imported profile"
    )
    assert user.role == UserRole.VIEWER and not user.is_active and not user.is_verified
    assert not user.mfa_enabled and user.token_version == 0
    assert user.auth_provider is None and user.external_id is None
    assert user.hashed_password != "synthetic-source-hash"
    assert not verify_password("!", user.hashed_password)


@pytest.mark.parametrize("identity_field", ["email", "username"])
async def test_existing_user_login_identity_is_not_rewritten_by_config_import(
    import_database, identity_field
):
    from app.models import User

    session, organization_id = import_database
    identifier = uuid.uuid4().hex
    user = User(
        organization_id=organization_id,
        username=identifier,
        email=identifier + "@example.invalid",
        hashed_password="synthetic-disabled-login-fixture",
    )
    session.add(user)
    await session.commit()
    original = getattr(user, identity_field)
    result = await BackupService(session).import_config(
        _fsdn(
            {
                "users": [
                    {
                        "id": str(user.id),
                        identity_field: "replacement@example.invalid",
                        "full_name": "Safe profile",
                    }
                ]
            }
        ),
        dry_run=False,
        overwrite_existing=True,
        organization_id=organization_id,
    )
    assert result["success"] is True
    await session.refresh(user)
    assert (
        getattr(user, identity_field) == original and user.full_name == "Safe profile"
    )


async def test_import_preserves_controller_secret_config_while_updating_nonsecret_options(
    import_scope_database,
):
    from app.models import Controller

    session, organization_id, site, _foreign_site, _controller, _device = (
        import_scope_database
    )
    controller = Controller(
        site_id=site.id,
        name="Local config",
        controller_type="omada",
        host="192.0.2.82",
        port=443,
        config={
            "password": "synthetic-existing-ciphertext",
            "client_secret": "synthetic-existing-client",
            "option": "old",
        },
    )
    session.add(controller)
    await session.commit()
    result = await BackupService(session).import_config(
        _fsdn(
            {
                "controllers": [
                    {
                        "id": str(controller.id),
                        "config": {
                            "password": "synthetic-uploaded-password",
                            "client_secret": "synthetic-uploaded-secret",
                            "option": "new",
                        },
                    }
                ]
            }
        ),
        dry_run=False,
        overwrite_existing=True,
        organization_id=organization_id,
    )
    assert result["success"] is True
    await session.refresh(controller)
    assert controller.config == {
        "password": "synthetic-existing-ciphertext",
        "client_secret": "synthetic-existing-client",
        "option": "new",
    }


async def test_import_controller_move_requires_a_consistent_final_device_graph(
    import_scope_database,
):
    from app.models import Controller, Device, Site

    session, organization_id, site, _foreign_site, _controller, _device = (
        import_scope_database
    )
    destination = Site(
        organization_id=organization_id, name="New local site", slug=uuid.uuid4().hex
    )
    controller = Controller(
        site_id=site.id,
        name="Local mover",
        controller_type="omada",
        host="192.0.2.83",
        port=443,
    )
    session.add_all([destination, controller])
    await session.flush()
    device = Device(
        site_id=site.id,
        controller_id=controller.id,
        name="Local child",
        device_type="switch",
    )
    session.add(device)
    await session.commit()
    origin_id, destination_id, controller_id, device_id = (
        site.id,
        destination.id,
        controller.id,
        device.id,
    )
    payload = {
        "controllers": [{"id": str(controller_id), "site_id": str(destination_id)}]
    }
    rejected = await BackupService(session).import_config(
        _fsdn(payload),
        dry_run=False,
        overwrite_existing=True,
        organization_id=organization_id,
    )
    assert rejected["success"] is False
    await session.refresh(controller)
    await session.refresh(device)
    assert controller.site_id == device.site_id == origin_id
    payload["devices"] = [{"id": str(device_id), "site_id": str(destination_id)}]
    accepted = await BackupService(session).import_config(
        _fsdn(payload),
        dry_run=False,
        overwrite_existing=True,
        organization_id=organization_id,
    )
    assert accepted["success"] is True
    await session.refresh(controller)
    await session.refresh(device)
    assert controller.site_id == device.site_id == destination_id


async def test_export_includes_the_real_user_profile_name(import_database):
    from app.models import User

    session, organization_id = import_database
    identity = uuid.uuid4().hex
    user = User(
        organization_id=organization_id,
        username=identity,
        email=identity + "@example.invalid",
        full_name="Profile name that must survive export",
        hashed_password="synthetic-disabled-login-fixture",
    )
    session.add(user)
    await session.commit()
    collected = await BackupService(session).collect_backup_data(
        organization_id=organization_id
    )
    record = next(r for r in collected["data"]["users"] if r["id"] == str(user.id))
    assert record["full_name"] == user.full_name


async def test_import_locks_reference_ownership_until_the_transaction_finishes():
    import asyncio

    from sqlalchemy import delete, select, text, update
    from sqlalchemy.exc import DBAPIError
    from sqlalchemy.ext.asyncio import AsyncSession

    from app.db.session import create_test_engine
    from app.models import Device, Organization, Site

    engine = create_test_engine()
    org_a, org_b, site_id, device_id = (uuid.uuid4() for _ in range(4))
    ready, release = asyncio.Event(), asyncio.Event()
    try:
        async with AsyncSession(engine, expire_on_commit=False) as setup:
            setup.add_all(
                [
                    Organization(
                        id=org_a, name="Owned lock fixture", slug=uuid.uuid4().hex
                    ),
                    Organization(
                        id=org_b, name="Foreign lock fixture", slug=uuid.uuid4().hex
                    ),
                ]
            )
            await setup.flush()
            setup.add(
                Site(
                    id=site_id,
                    organization_id=org_a,
                    name="Locked import reference",
                    slug=uuid.uuid4().hex,
                )
            )
            await setup.commit()
        async with AsyncSession(
            engine, expire_on_commit=False, autoflush=False
        ) as session:
            original_commit = session.commit

            async def held_commit():
                ready.set()
                await release.wait()
                await original_commit()

            session.commit = held_commit
            task = asyncio.create_task(
                BackupService(session).import_config(
                    _fsdn(
                        {
                            "devices": [
                                {
                                    "id": str(device_id),
                                    "site_id": str(site_id),
                                    "name": "Owned locked device",
                                    "device_type": "switch",
                                }
                            ]
                        }
                    ),
                    dry_run=False,
                    organization_id=org_a,
                )
            )
            try:
                await asyncio.wait_for(ready.wait(), timeout=10)
                async with AsyncSession(engine) as contender:
                    await contender.execute(text("SET LOCAL lock_timeout = '500ms'"))
                    with pytest.raises(DBAPIError) as rejected:
                        await contender.execute(
                            update(Site)
                            .where(Site.id == site_id)
                            .values(organization_id=org_b)
                        )
                    assert rejected.value.orig.sqlstate == "55P03"
                    await contender.rollback()
            finally:
                release.set()
                result = await asyncio.wait_for(task, timeout=10)
            assert result["success"] is True
        async with AsyncSession(engine) as check:
            row = (
                await check.execute(select(Device).where(Device.id == device_id))
            ).scalar_one()
            site = (
                await check.execute(select(Site).where(Site.id == site_id))
            ).scalar_one()
            assert row.site_id == site.id and site.organization_id == org_a
    finally:
        release.set()
        async with AsyncSession(engine) as cleanup:
            await cleanup.execute(
                delete(Organization).where(Organization.id.in_([org_a, org_b]))
            )
            await cleanup.commit()
        await engine.dispose()


async def test_import_failed_commit_restores_existing_profiles_as_well_as_new_rows(
    import_database,
):
    from sqlalchemy import select

    from app.models import Site, User

    session, organization_id = import_database
    identity = uuid.uuid4().hex
    user = User(
        organization_id=organization_id,
        username=identity,
        email=identity + "@example.invalid",
        full_name="Profile before transaction",
        hashed_password="synthetic-disabled-login-fixture",
    )
    session.add(user)
    await session.commit()
    slug = uuid.uuid4().hex
    result = await BackupService(session).import_config(
        _fsdn(
            {
                "sites": [
                    {"id": str(uuid.uuid4()), "name": "Duplicate", "slug": slug}
                    for _ in range(2)
                ],
                "users": [{"id": str(user.id), "full_name": "Must be rolled back"}],
            }
        ),
        dry_run=False,
        overwrite_existing=True,
        organization_id=organization_id,
    )
    assert result["success"] is False
    await session.refresh(user)
    assert user.full_name == "Profile before transaction"
    assert (
        await session.execute(
            select(Site).where(Site.organization_id == organization_id)
        )
    ).scalars().all() == []


@pytest.mark.parametrize("dry_run", [True, False])
async def test_import_refreshes_preloaded_reference_ownership(dry_run):
    from sqlalchemy import delete, select, update
    from sqlalchemy.ext.asyncio import AsyncSession

    from app.db.session import create_test_engine
    from app.models import Device, Organization, Site

    engine = create_test_engine()
    org_a, org_b, site_id, device_id = (uuid.uuid4() for _ in range(4))
    try:
        async with AsyncSession(engine, expire_on_commit=False) as setup:
            setup.add_all(
                [
                    Organization(
                        id=org_a, name="Original cache owner", slug=uuid.uuid4().hex
                    ),
                    Organization(
                        id=org_b, name="Current cache owner", slug=uuid.uuid4().hex
                    ),
                ]
            )
            await setup.flush()
            setup.add(
                Site(
                    id=site_id,
                    organization_id=org_a,
                    name="Previously loaded site",
                    slug=uuid.uuid4().hex,
                )
            )
            await setup.commit()
        async with AsyncSession(
            engine, expire_on_commit=False, autoflush=False
        ) as session:
            preloaded = (
                await session.execute(select(Site).where(Site.id == site_id))
            ).scalar_one()
            assert preloaded.organization_id == org_a
            async with AsyncSession(engine) as changed:
                await changed.execute(
                    update(Site).where(Site.id == site_id).values(organization_id=org_b)
                )
                await changed.commit()
            # Keep this stale identity-map object strongly referenced until import.
            assert preloaded.organization_id == org_a
            result = await BackupService(session).import_config(
                _fsdn(
                    {
                        "devices": [
                            {
                                "id": str(device_id),
                                "site_id": str(site_id),
                                "name": "Must be refused",
                                "device_type": "switch",
                            }
                        ]
                    }
                ),
                dry_run=dry_run,
                organization_id=org_a,
            )
            assert result["success"] is False
        async with AsyncSession(engine) as check:
            assert (
                await check.execute(select(Device).where(Device.id == device_id))
            ).scalar_one_or_none() is None
            site = (
                await check.execute(select(Site).where(Site.id == site_id))
            ).scalar_one()
            assert site.organization_id == org_b
    finally:
        async with AsyncSession(engine) as cleanup:
            await cleanup.execute(
                delete(Organization).where(Organization.id.in_([org_a, org_b]))
            )
            await cleanup.commit()
        await engine.dispose()


@pytest.mark.parametrize("dry_run", [True, False])
@pytest.mark.parametrize(
    "field,value,accepted",
    [
        ("settings", {"label": "owned configuration"}, True),
        ("settings", [], False),
        ("subnets", ["192.0.2.0/24"], True),
        ("subnets", {"cidr": "192.0.2.0/24"}, False),
    ],
    ids=["settings-object", "settings-array", "subnets-array", "subnets-object"],
)
async def test_import_json_shapes_are_checked_in_preview_and_apply(
    import_database, dry_run, field, value, accepted
):
    from sqlalchemy import select

    from app.models import Site

    session, organization_id = import_database
    identifier = uuid.uuid4()
    result = await BackupService(session).import_config(
        _fsdn({"sites": [{"id": str(identifier), "name": "Structured settings", "slug": uuid.uuid4().hex, field: value}]}),
        dry_run=dry_run,
        organization_id=organization_id,
    )
    assert result["success"] is accepted
    row = (await session.execute(select(Site).where(Site.id == identifier))).scalar_one_or_none()
    if accepted and not dry_run:
        assert row is not None and getattr(row, field) == value
    else:
        assert row is None

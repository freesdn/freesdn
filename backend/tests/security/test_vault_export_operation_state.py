"""Planned real SQL/HTTP operation snapshots. Not external storage/hardware tests."""

import asyncio
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
import pytest_asyncio
from fastapi import Depends, Request
from sqlalchemy import delete, text, update
from sqlalchemy.dialects import postgresql
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import CurrentUser, get_current_user
from app.models.api_keys import APIKey
from app.models.core import Controller, Site, User
from app.modules.backup.models import Backup, StorageLocation
from app.schemas.backup import BackupCreate
from app.services import vault_export_operation_state as module
from app.services.vault_export_authority import VaultExportAuthority
from tests.security.test_vault_export_authority import credentials, real_wait
from tests.security.test_vault_export_authority import owned_export as owned_export


@pytest_asyncio.fixture
async def operations(owned_export):
    f = owned_export
    f.site, f.location, f.controller, f.backup = uuid4(), uuid4(), uuid4(), uuid4()
    f.operation_pause = False
    f.operation_started = asyncio.Event()
    f.operation_proceed = asyncio.Event()
    f.expected = None
    f.last = None
    f.data = {
        "name": "Owned operation vault",
        "include_secrets": True,
        "passphrase": "Owned operation sealing phrase",
        "storage_type": "truenas",
        "storage_location_id": str(f.location),
    }
    f.observed = {"version": 1, "sha256": "a" * 64, "bytes": 1234}
    app = f.client._transport.app

    @app.post("/owned/operation/resolve")
    async def resolve(request: Request, user: CurrentUser = Depends(get_current_user)):
        body = await request.json()
        operation = body["operation"]
        authority = await VaultExportAuthority.capture(
            request,
            user,
            action="create" if operation == "create" else "download",
            secret_key=f.secret,
        )
        if operation == "create":
            intent = module.ExportIntent.creation(BackupCreate.model_validate(body["request"]))
        else:
            intent = module.ExportIntent.download(
                f.backup,
                operation=operation,
                legacy_acknowledged=operation != "download_recorded",
                observed_identity=f.observed if operation == "download_legacy" else None,
            )
        f.operation_started.set()
        if f.operation_pause:
            await f.operation_proceed.wait()
        f.last = await module.resolve_current_operation(
            authority, intent, expected_binding=f.expected
        )
        return {"binding": f.last.binding, "credential_expiry": f.last.credential_expires_at}

    try:
        async with AsyncSession(f.engine) as db:
            db.add(
                Site(
                    id=f.site, organization_id=f.org, name="Owned operation site", slug=uuid4().hex
                )
            )
            await db.flush()
            db.add(
                Controller(
                    id=f.controller,
                    site_id=f.site,
                    name="Owned backup controller",
                    controller_type="truenas",
                    host="nas.example.invalid",
                    port=443,
                    use_ssl=True,
                    verify_ssl=True,
                    is_active=True,
                    config={"username": "owned", "password": "Owned encrypted reference"},
                )
            )
            db.add(
                StorageLocation(
                    id=f.location,
                    organization_id=f.org,
                    name="Owned operation location",
                    storage_type="truenas",
                    is_active=True,
                    config={"controller_id": str(f.controller), "dataset_path": "tank/backup"},
                )
            )
            await db.flush()
            db.add(
                Backup(
                    id=f.backup,
                    organization_id=f.org,
                    name="Owned existing vault",
                    backup_type="full",
                    status="completed",
                    site_id=f.site,
                    include_secrets=True,
                    is_encrypted=True,
                    storage_type="truenas",
                    storage_location_id=f.location,
                    storage_path="truenas://owned/backup.fsdnvault",
                    metadata_json={"artifact_identity": f.observed},
                )
            )
            await db.commit()
        yield f
    finally:
        f.operation_proceed.set()
        async with AsyncSession(f.engine) as db:
            await db.execute(delete(Backup).where(Backup.id == f.backup))
            await db.execute(delete(StorageLocation).where(StorageLocation.id == f.location))
            await db.execute(delete(Controller).where(Controller.id == f.controller))
            await db.execute(delete(Site).where(Site.id == f.site))
            await db.commit()
        # Cached fixture callbacks must not retain completed request resources.
        f = None


async def call(f, kind, operation, headers=None):
    if headers is None:
        headers, _ = credentials(f, kind)
    return await f.client.post(
        "/owned/operation/resolve",
        headers=headers,
        json={"operation": operation, "request": f.data},
    )


@pytest.mark.parametrize("kind", ["jwt", "key"])
@pytest.mark.parametrize(
    "operation", ["create", "download_recorded", "observe_legacy", "download_legacy"]
)
@pytest.mark.parametrize("backend", ["local", "truenas"])
async def test_actual_current_rows_preserve_valid_operations_and_credential_expiry(
    operations, kind, operation, backend
):
    f = operations
    expires = datetime.now(UTC) + timedelta(seconds=45)
    async with AsyncSession(f.engine) as db:
        await db.execute(update(APIKey).where(APIKey.id == f.key_id).values(expires_at=expires))
        if backend == "local":
            await db.execute(
                update(StorageLocation)
                .where(StorageLocation.id == f.location)
                .values(storage_type="local", config={"path": "/owned/not-opened"})
            )
            await db.execute(
                update(Backup)
                .where(Backup.id == f.backup)
                .values(storage_type="local", storage_path="owned.fsdnvault")
            )
        if operation in ("observe_legacy", "download_legacy"):
            await db.execute(update(Backup).where(Backup.id == f.backup).values(metadata_json={}))
        await db.commit()
    headers, claims = credentials(f, kind)
    response = await call(f, kind, operation, headers)
    assert response.status_code == 200, response.text
    assert response.json()["credential_expiry"] == (
        int(expires.timestamp()) if kind == "key" else claims["exp"]
    )
    assert f.last.storage.descriptor.storage_type == backend
    assert "Owned encrypted reference" not in response.text
    if backend == "truenas":
        assert str(f.controller) in f.last.storage.controller_json
        assert str(f.org) in f.last.storage.controller_json
    # Every selected field is compiled against real mapped columns. This does
    # not replace the actual successful SQL invocation above.
    statement = module._statement(f.last.authority, f.last.intent, f.last.intent.checked()[0])
    sql = str(statement.compile(dialect=postgresql.dialect()))
    assert "vault_controller_site" in sql and "core.controllers" in sql
    assert "FOR UPDATE" not in sql and "INSERT INTO" not in sql


@pytest.mark.parametrize("kind", ["jwt", "key"])
@pytest.mark.parametrize("operation", ["create", "download_recorded"])
@pytest.mark.parametrize(
    "change",
    [
        "controller-host",
        "controller-credentials",
        "storage-config",
        "controller-inactive",
        "site-foreign",
        "site-deleted",
        "controller-deleted",
    ],
)
async def test_changed_destination_or_referenced_owner_refuses_old_binding(
    operations, kind, operation, change
):
    f = operations
    headers, _ = credentials(f, kind)
    first = await call(f, kind, operation, headers)
    assert first.status_code == 200, first.text
    f.expected = first.json()["binding"]
    async with AsyncSession(f.engine) as db:
        if change == "controller-host":
            statement = (
                update(Controller)
                .where(Controller.id == f.controller)
                .values(host="changed.example.invalid")
            )
        elif change == "controller-credentials":
            statement = (
                update(Controller)
                .where(Controller.id == f.controller)
                .values(config={"password": "Changed owned ciphertext"})
            )
        elif change == "storage-config":
            statement = (
                update(StorageLocation)
                .where(StorageLocation.id == f.location)
                .values(config={"controller_id": str(f.controller), "dataset_path": "tank/other"})
            )
        elif change == "controller-inactive":
            statement = (
                update(Controller).where(Controller.id == f.controller).values(is_active=False)
            )
        elif change == "site-foreign":
            statement = update(Site).where(Site.id == f.site).values(organization_id=f.other_org)
        elif change == "site-deleted":
            statement = update(Site).where(Site.id == f.site).values(deleted_at=datetime.now(UTC))
        else:
            statement = (
                update(Controller)
                .where(Controller.id == f.controller)
                .values(deleted_at=datetime.now(UTC))
            )
        await db.execute(statement)
        await db.commit()
    second = await call(f, kind, operation, headers)
    assert second.status_code == 409, second.text
    assert "Changed owned ciphertext" not in second.text


@pytest.mark.parametrize("kind", ["jwt", "key"])
@pytest.mark.parametrize(
    "change", ["unchanged", "actor-disabled", "controller-host", "site-foreign", "backup-deleted"]
)
async def test_current_state_after_actual_relation_wait(operations, kind, change, record_property):
    f = operations
    headers, _ = credentials(f, kind)
    operation = "download_recorded"
    first = await call(f, kind, operation, headers)
    assert first.status_code == 200, first.text
    f.expected = first.json()["binding"]
    f.operation_pause = True
    f.operation_started.clear()
    task = None
    try:
        async with AsyncSession(f.engine) as holder:
            await holder.execute(
                text("LOCK TABLE backup.storage_locations IN ACCESS EXCLUSIVE MODE")
            )
            holder_pid = await holder.scalar(text("SELECT pg_backend_pid()"))
            task = asyncio.create_task(call(f, kind, operation, headers))
            await asyncio.wait_for(f.operation_started.wait(), 5)
            f.operation_proceed.set()
            waiters = await real_wait(f, task, holder_pid)
            record_property("genuine_operation_relation_wait", bool(waiters))
            if change == "actor-disabled":
                await holder.execute(update(User).where(User.id == f.user).values(is_active=False))
            elif change == "controller-host":
                await holder.execute(
                    update(Controller)
                    .where(Controller.id == f.controller)
                    .values(host="later.example.invalid")
                )
            elif change == "site-foreign":
                await holder.execute(
                    update(Site).where(Site.id == f.site).values(organization_id=f.other_org)
                )
            elif change == "backup-deleted":
                await holder.execute(delete(Backup).where(Backup.id == f.backup))
            await holder.commit()
        response = await asyncio.wait_for(task, 10)
        expected = {
            "unchanged": 200,
            "actor-disabled": 401,
            "controller-host": 409,
            "site-foreign": 409,
            "backup-deleted": 404,
        }[change]
        assert response.status_code == expected, response.text
        if change == "unchanged":
            assert response.json()["binding"] == f.expected
    finally:
        f.operation_proceed.set()
        if task is not None and not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)


async def test_current_expiring_key_after_actual_relation_wait(operations, record_property):
    f = operations
    headers, _ = credentials(f, "key")
    f.operation_pause = True
    task = None
    try:
        async with AsyncSession(f.engine) as holder:
            await holder.execute(
                text("LOCK TABLE backup.storage_locations IN ACCESS EXCLUSIVE MODE")
            )
            holder_pid = await holder.scalar(text("SELECT pg_backend_pid()"))
            task = asyncio.create_task(call(f, "key", "create", headers))
            await asyncio.wait_for(f.operation_started.wait(), 5)
            f.operation_proceed.set()
            waiters = await real_wait(f, task, holder_pid)
            record_property("genuine_operation_relation_wait", bool(waiters))
            await holder.execute(
                update(APIKey)
                .where(APIKey.id == f.key_id)
                .values(expires_at=datetime.now(UTC) - timedelta(seconds=1))
            )
            await holder.commit()
        response = await asyncio.wait_for(task, 10)
        assert response.status_code == 401, response.text
    finally:
        f.operation_proceed.set()
        if task is not None and not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

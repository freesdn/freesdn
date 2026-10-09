"""Real PostgreSQL/task/backup commits; owned local files and synthetic organizations."""

import asyncio
import contextvars
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest
from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.pool import NullPool

from app.models.core import Organization
from app.modules.backup.models import Backup, BackupSchedule
from app.services.backup import BackupService, LocalStorageBackend
from app.tasks import backup as tasks

WORKER = contextvars.ContextVar("backup_test_worker", default="single")


@pytest.mark.parametrize(
    "values",
    [
        {"timezone": "No/Such_Zone"},
        {"timezone": ""},
        {"cron_expression": "not a schedule"},
        {"cron_expression": "0 2 31 2 *"},
        {"cron_expression": ""},
    ],
)
def test_invalid_stored_timing_fails_before_creating_an_archive(scheduler, values):
    f = scheduler

    async def change():
        async with AsyncSession(f.engine) as db:
            await db.execute(
                update(BackupSchedule).where(BackupSchedule.id == f.schedule_id).values(**values)
            )
            await db.commit()

    asyncio.run(change())
    result = tasks.run_scheduled_backups.run()
    assert result["triggered"] == 0 and result["errors"] == 1
    assert f.records()[0] == []


def test_schedule_service_persists_timezone_and_reenable_semantics(scheduler):
    from zoneinfo import ZoneInfo

    f = scheduler

    async def exercise():
        async with AsyncSession(f.engine, expire_on_commit=False) as db:
            service = BackupService(db)
            row = await service.create_schedule(
                name="Local calendar",
                organization_id=f.organization_id,
                cron_expression="0 2 * * *",
                timezone="Asia/Kathmandu",
            )
            assert row.next_run_at.astimezone(ZoneInfo("Asia/Kathmandu")).hour == 2
            row = await service.update_schedule(row.id, timezone="America/New_York")
            local = row.next_run_at.astimezone(ZoneInfo("America/New_York"))
            assert (local.hour, local.minute) == (2, 0)
            with pytest.raises(ValueError):
                await service.update_schedule(
                    row.id, name="Must not apply", timezone="No/Such_Zone"
                )
            assert row.name == "Local calendar" and row.timezone == "America/New_York"
            row.next_run_at = datetime.now(UTC) - timedelta(days=4)
            row.is_enabled = False
            await db.commit()
            row = await service.update_schedule(row.id, is_enabled=True)
            assert row.is_enabled and row.next_run_at > datetime.now(UTC)
            await service.toggle_schedule(row.id, False)
            assert not row.is_enabled
            await service.toggle_schedule(row.id, True)
            assert row.is_enabled and row.next_run_at > datetime.now(UTC)

    asyncio.run(exercise())


def test_schedule_http_validation_and_invalid_legacy_enable(scheduler):
    from fastapi import FastAPI
    from httpx import ASGITransport, AsyncClient

    from app.api.v1.endpoints import backups
    from app.models import UserRole

    f = scheduler
    api = FastAPI()
    api.include_router(backups.router)
    user = SimpleNamespace(id=uuid4(), role=UserRole.SUPER_ADMIN, organization_id=f.organization_id)

    async def session():
        async with AsyncSession(f.engine, expire_on_commit=False) as db:
            yield db

    api.dependency_overrides[backups.get_session] = session
    api.dependency_overrides[backups.get_current_active_user] = lambda: user

    async def exercise():
        async with AsyncClient(transport=ASGITransport(app=api), base_url="http://owned") as client:
            for payload in [
                {"name": "Invalid", "cron_expression": "0 2 * * *", "timezone": "No/Such_Zone"},
                {"name": "Invalid", "cron_expression": "0 2 31 2 *"},
            ]:
                response = await client.post("/schedules", json=payload)
                assert response.status_code == 422, response.text
            response = await client.put(
                f"/schedules/{f.schedule_id}", json={"timezone": "No/Such_Zone"}
            )
            assert response.status_code == 422, response.text
            async with AsyncSession(f.engine) as db:
                await db.execute(
                    update(BackupSchedule)
                    .where(BackupSchedule.id == f.schedule_id)
                    .values(timezone="No/Such_Zone", is_enabled=False)
                )
                await db.commit()
            response = await client.post(
                f"/schedules/{f.schedule_id}/toggle", json={"is_enabled": True}
            )
            assert response.status_code == 400, response.text
            # Bad legacy timing can still be disabled and repaired.
            response = await client.post(
                f"/schedules/{f.schedule_id}/toggle", json={"is_enabled": False}
            )
            assert response.status_code == 200, response.text
            response = await client.put(
                f"/schedules/{f.schedule_id}", json={"timezone": "UTC", "is_enabled": True}
            )
            assert response.status_code == 200, response.text
            assert datetime.fromisoformat(response.json()["next_run_at"]) > datetime.now(UTC)

    asyncio.run(exercise())


@pytest.fixture
def scheduler(tmp_path, monkeypatch):
    engine = create_async_engine(os.environ["DATABASE_URL"], poolclass=NullPool)
    f = SimpleNamespace(
        engine=engine,
        organization_id=uuid4(),
        schedule_id=uuid4(),
        changed_after_selection=None,
        sessions={},
        overlap=False,
        a_selected=threading.Event(),
        b_selected=threading.Event(),
        a_saved=threading.Event(),
        b_finished=threading.Event(),
        root=tmp_path / "archives",
    )

    async def seed():
        async with AsyncSession(engine, expire_on_commit=False) as db:
            db.add(Organization(id=f.organization_id, name="Owned scheduler", slug=uuid4().hex))
            await db.flush()
            db.add(
                BackupSchedule(
                    id=f.schedule_id,
                    organization_id=f.organization_id,
                    name="Owned scheduled backup",
                    cron_expression="0 2 * * *",
                    timezone="UTC",
                    is_enabled=True,
                    next_run_at=datetime.now(UTC) - timedelta(minutes=5),
                    include_devices=False,
                    include_users=False,
                    include_automation=False,
                    include_vlans=False,
                    include_ssids=False,
                    max_backups=10,
                )
            )
            await db.commit()

    asyncio.run(seed())

    async def bounded_wait(event):
        assert await asyncio.to_thread(event.wait, 15), "Owned synchronization point timed out"

    class ObservedSession(AsyncSession):
        async def commit(self):
            completed = any(
                isinstance(row, Backup)
                and row.schedule_id == f.schedule_id
                and row.status == "completed"
                for row in self.identity_map.values()
            )
            await super().commit()
            # The real BackupService has durably committed the new archive here,
            # but its caller has not yet advanced the schedule. Let B inspect it.
            if f.overlap and WORKER.get() == "A" and completed and not f.a_saved.is_set():
                f.a_saved.set()
                await bounded_wait(f.b_finished)

    @asynccontextmanager
    async def session_factory():
        label = WORKER.get()
        ordinal = f.sessions.get(label, 0)
        f.sessions[label] = ordinal + 1
        async with ObservedSession(engine, expire_on_commit=False) as db:
            yield db
        if ordinal == 0:
            if f.changed_after_selection:
                async with AsyncSession(engine) as writer:
                    if f.changed_after_selection == "delete":
                        await writer.execute(
                            delete(BackupSchedule).where(BackupSchedule.id == f.schedule_id)
                        )
                    else:
                        await writer.execute(
                            update(BackupSchedule)
                            .where(BackupSchedule.id == f.schedule_id)
                            .values(**f.changed_after_selection)
                        )
                    await writer.commit()
            if f.overlap:
                if label == "A":
                    f.a_selected.set()
                    await bounded_wait(f.b_selected)
                else:
                    f.b_selected.set()
                    await bounded_wait(f.a_saved)

    async def owned_storage(self, *_args):
        return LocalStorageBackend({"path": str(f.root)}), None

    monkeypatch.setattr(tasks, "AsyncSessionLocal", session_factory)
    monkeypatch.setattr(BackupService, "_resolve_storage", owned_storage)

    async def records():
        async with AsyncSession(engine) as db:
            rows = (
                (
                    await db.execute(
                        select(Backup).where(Backup.organization_id == f.organization_id)
                    )
                )
                .scalars()
                .all()
            )
            schedule = await db.get(BackupSchedule, f.schedule_id)
            return [
                (r.status, r.storage_path) for r in rows
            ], None if schedule is None else schedule.next_run_at

    f.records = lambda: asyncio.run(records())
    yield f

    async def cleanup():
        async with AsyncSession(engine) as db:
            await db.execute(delete(Backup).where(Backup.organization_id == f.organization_id))
            await db.execute(
                delete(BackupSchedule).where(BackupSchedule.organization_id == f.organization_id)
            )
            await db.execute(delete(Organization).where(Organization.id == f.organization_id))
            await db.commit()
        await engine.dispose()

    asyncio.run(cleanup())


@pytest.mark.parametrize("change", ["disable", "defer", "unset", "soft-delete", "delete"])
def test_schedule_is_rechecked_after_selection(scheduler, change):
    f = scheduler
    f.changed_after_selection = {
        "disable": {"is_enabled": False},
        "defer": {"next_run_at": datetime.now(UTC) + timedelta(days=1)},
        "unset": {"next_run_at": None},
        "soft-delete": {"deleted_at": datetime.now(UTC)},
        "delete": "delete",
    }[change]
    result = tasks.run_scheduled_backups.run()
    records, _ = f.records()
    assert records == [], "A schedule that became ineligible must not create an archive"
    assert result["triggered"] == 0
    assert result["errors"] == 0, "An obsolete selection is a skip, not a backup failure"


def test_due_schedule_creates_one_real_archive_and_advances(scheduler):
    f = scheduler
    result = tasks.run_scheduled_backups.run()
    records, next_run = f.records()
    assert result["triggered"] == 1 and result["errors"] == 0
    assert len(records) == 1 and records[0][0] == "completed"
    assert (f.root / records[0][1]).is_file()
    assert next_run > datetime.now(UTC)
    again = tasks.run_scheduled_backups.run()
    assert again["triggered"] == 0 and len(f.records()[0]) == 1


@pytest.mark.parametrize("state", ["disabled", "deleted", "future", "unset"])
def test_initially_ineligible_schedule_is_not_selected(scheduler, state):
    f = scheduler
    values = {
        "disabled": {"is_enabled": False},
        "deleted": {"deleted_at": datetime.now(UTC)},
        "future": {"next_run_at": datetime.now(UTC) + timedelta(days=1)},
        "unset": {"next_run_at": None},
    }[state]

    async def change():
        async with AsyncSession(f.engine) as db:
            await db.execute(
                update(BackupSchedule).where(BackupSchedule.id == f.schedule_id).values(**values)
            )
            await db.commit()

    asyncio.run(change())
    result = tasks.run_scheduled_backups.run()
    assert result["due"] == result["triggered"] == result["errors"] == 0
    assert f.records()[0] == []


def test_failed_storage_attempt_keeps_failure_record_and_remains_retryable(scheduler, monkeypatch):
    f = scheduler

    async def fail(*_args):
        raise OSError("Owned simulated storage failure")

    monkeypatch.setattr(LocalStorageBackend, "save", fail)
    result = tasks.run_scheduled_backups.run()
    records, next_run = f.records()
    assert result["triggered"] == 0 and result["errors"] == 1
    assert records == [("failed", None)]
    assert next_run < datetime.now(UTC)


def test_retention_and_schedule_updates_commit_on_separate_connections(scheduler):
    f = scheduler
    assert tasks.run_scheduled_backups.run()["triggered"] == 1
    original_path = f.root / f.records()[0][0][1]
    assert original_path.is_file()

    async def due_again():
        async with AsyncSession(f.engine) as db:
            await db.execute(
                update(BackupSchedule)
                .where(BackupSchedule.id == f.schedule_id)
                .values(max_backups=1, next_run_at=datetime.now(UTC) - timedelta(minutes=1))
            )
            await db.commit()

    asyncio.run(due_again())
    result = tasks.run_scheduled_backups.run()
    records, next_run = f.records()
    assert result["triggered"] == 1 and result["errors"] == 0
    assert len(records) == 1 and records[0][0] == "completed"
    assert not original_path.exists() and (f.root / records[0][1]).is_file()
    assert next_run > datetime.now(UTC)


def test_overlapping_stale_pickers_do_not_duplicate_a_committed_backup(scheduler):
    f = scheduler
    f.overlap = True

    def run(label):
        token = WORKER.set(label)
        try:
            return tasks.run_scheduled_backups.run()
        finally:
            if label == "B":
                f.b_finished.set()
            WORKER.reset(token)

    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(run, "A")
        assert f.a_selected.wait(15)
        second = pool.submit(run, "B")
        results = [first.result(timeout=30), second.result(timeout=30)]
    records, next_run = f.records()
    assert f.a_saved.is_set() and f.b_selected.is_set()
    assert len(records) == 1, "Two workers created backups for the same due occurrence"
    assert records[0][0] == "completed" and (f.root / records[0][1]).is_file()
    assert sum(r["triggered"] for r in results) == 1
    assert sum(r["errors"] for r in results) == 0
    assert next_run > datetime.now(UTC)


async def _owned_archive_ids(f):
    async with AsyncSession(f.engine) as db:
        return list(
            (
                await db.execute(
                    select(Backup.id)
                    .where(Backup.organization_id == f.organization_id)
                    .order_by(Backup.created_at.asc())
                )
            ).scalars()
        )


async def _make_owned_schedule_due(f):
    async with AsyncSession(f.engine) as db:
        await db.execute(
            update(BackupSchedule)
            .where(BackupSchedule.id == f.schedule_id)
            .values(next_run_at=datetime.now(UTC) - timedelta(minutes=1))
        )
        await db.commit()


@pytest.mark.parametrize("failure", ["false", "permission", "transport", "configuration"])
def test_http_delete_failure_keeps_real_archive_and_catalog_until_retry(
    scheduler, monkeypatch, caplog, failure
):
    from fastapi import FastAPI
    from httpx import ASGITransport, AsyncClient

    from app.api.v1.endpoints import backups
    from app.models import UserRole
    from app.services.backup_transport import StorageConfigurationError

    f = scheduler
    assert tasks.run_scheduled_backups.run()["triggered"] == 1
    backup_id = asyncio.run(_owned_archive_ids(f))[0]
    path = f.root / f.records()[0][0][1]
    original_delete = LocalStorageBackend.delete
    original_resolve = BackupService._resolve_storage
    private_marker = "synthetic-delete-failure-must-not-be-echoed"

    async def fail_delete(*_):
        if failure == "false":
            return False
        if failure == "permission":
            raise PermissionError(private_marker)
        raise OSError(private_marker)

    async def fail_resolve(*_):
        raise StorageConfigurationError(private_marker)

    if failure == "configuration":
        monkeypatch.setattr(BackupService, "_resolve_storage", fail_resolve)
    else:
        monkeypatch.setattr(LocalStorageBackend, "delete", fail_delete)

    api = FastAPI()
    api.include_router(backups.router, prefix="/backups")
    user = SimpleNamespace(id=uuid4(), role=UserRole.SUPER_ADMIN, organization_id=f.organization_id)

    async def session():
        async with AsyncSession(f.engine, expire_on_commit=False) as db:
            yield db

    api.dependency_overrides[backups.get_session] = session
    api.dependency_overrides[backups.get_current_active_user] = lambda: user

    async def exercise():
        async with AsyncClient(transport=ASGITransport(app=api), base_url="http://owned") as client:
            response = await client.delete(f"/backups/{backup_id}")
            assert response.status_code == 503
            assert "retained" in response.json()["detail"]
            assert private_marker not in response.text
            assert path.is_file()
            assert await _owned_archive_ids(f) == [backup_id]
            monkeypatch.setattr(LocalStorageBackend, "delete", original_delete)
            monkeypatch.setattr(BackupService, "_resolve_storage", original_resolve)
            response = await client.delete(f"/backups/{backup_id}")
            assert response.status_code == 204
            assert not path.exists() and await _owned_archive_ids(f) == []

    asyncio.run(exercise())
    assert private_marker not in caplog.text


@pytest.mark.parametrize("failure", ["false", "permission", "database"])
def test_retention_failure_is_visible_without_replaying_the_successful_slot(
    scheduler, monkeypatch, failure
):
    from sqlalchemy import text

    f = scheduler
    assert tasks.run_scheduled_backups.run()["triggered"] == 1
    old_path = f.root / f.records()[0][0][1]

    async def due():
        async with AsyncSession(f.engine) as db:
            await db.execute(
                update(BackupSchedule)
                .where(BackupSchedule.id == f.schedule_id)
                .values(max_backups=1, next_run_at=datetime.now(UTC) - timedelta(minutes=1))
            )
            await db.commit()

    asyncio.run(due())
    original_delete = LocalStorageBackend.delete
    original_service_delete = BackupService.delete_backup

    async def storage_failure(*_):
        if failure == "false":
            return False
        raise PermissionError("owned retention refusal")

    async def database_failure(self, *_):
        await self.db.execute(text("SELECT 1 / 0"))

    if failure == "database":
        monkeypatch.setattr(BackupService, "delete_backup", database_failure)
    else:
        monkeypatch.setattr(LocalStorageBackend, "delete", storage_failure)
    result = tasks.run_scheduled_backups.run()
    records, next_run = f.records()
    assert result["triggered"] == 1 and result["errors"] == 1 and result["retention_errors"] == 1
    assert len(records) == 2 and old_path.is_file()
    assert next_run > datetime.now(UTC)
    assert tasks.run_scheduled_backups.run()["triggered"] == 0
    assert len(f.records()[0]) == 2
    monkeypatch.setattr(LocalStorageBackend, "delete", original_delete)
    monkeypatch.setattr(BackupService, "delete_backup", original_service_delete)
    asyncio.run(_make_owned_schedule_due(f))
    result = tasks.run_scheduled_backups.run()
    assert result["triggered"] == 1 and result["retention_errors"] == 0
    records, _ = f.records()
    assert len(records) == 1 and not old_path.exists()
    assert len(list(f.root.rglob("*.fsdn"))) == 1


@pytest.mark.parametrize("failure", ["storage", "database"])
def test_expiry_batch_retains_failed_record_and_continues_after_rollback(
    scheduler, monkeypatch, failure
):
    from sqlalchemy import text

    f = scheduler
    assert tasks.run_scheduled_backups.run()["triggered"] == 1
    asyncio.run(_make_owned_schedule_due(f))
    assert tasks.run_scheduled_backups.run()["triggered"] == 1
    ids = asyncio.run(_owned_archive_ids(f))
    assert len(ids) == 2
    original = BackupService.delete_backup

    async def fail_first(self, backup_id):
        if backup_id == ids[0]:
            if failure == "database":
                await self.db.execute(text("SELECT 1 / 0"))
            raise PermissionError("owned expiry refusal")
        return await original(self, backup_id)

    monkeypatch.setattr(BackupService, "delete_backup", fail_first)

    async def exercise():
        async with AsyncSession(f.engine, expire_on_commit=False) as db:
            await db.execute(
                update(Backup)
                .where(Backup.organization_id == f.organization_id)
                .values(expires_at=datetime.now(UTC) - timedelta(days=1))
            )
            await db.commit()
            count = await BackupService(db).cleanup_expired_backups()
            assert count == 1
        assert await _owned_archive_ids(f) == [ids[0]]
        monkeypatch.setattr(BackupService, "delete_backup", original)
        async with AsyncSession(f.engine, expire_on_commit=False) as db:
            assert await BackupService(db).cleanup_expired_backups() == 1
        assert await _owned_archive_ids(f) == []

    asyncio.run(exercise())
    assert list(f.root.rglob("*.fsdn")) == []


def test_local_delete_is_idempotent_after_confirmed_absence(tmp_path):
    backend = LocalStorageBackend({"path": str(tmp_path)})

    async def exercise():
        path = await backend.save(str(uuid4()), b"owned configuration fixture", "owned.fsdn")
        assert await backend.delete(path) is True
        assert await backend.delete(path) is True

    asyncio.run(exercise())


def test_sftp_delete_missing_is_success_but_stat_still_reports_missing(monkeypatch):
    from contextlib import contextmanager

    from app.services.backup import SFTPStorageBackend

    def missing(*_):
        raise FileNotFoundError("owned fixture file is absent")

    @contextmanager
    def connected(*_):
        yield SimpleNamespace(remove=missing, stat=missing)

    monkeypatch.setattr("app.services.backup.sftp_connection", connected)
    backend = SFTPStorageBackend.__new__(SFTPStorageBackend)
    backend.host = "owned.invalid"
    backend.port = 22
    backend.username = "synthetic"
    backend.password = None
    backend.private_key_path = None
    backend.config = {}
    assert backend._run("delete", "/owned/absent.fsdn", None) is True
    assert backend._run("exists", "/owned/absent.fsdn", None) is False


def _diagnostic_api(f):
    from fastapi import FastAPI

    from app.api.v1.endpoints import backups

    app = FastAPI()
    app.include_router(backups.router, prefix="/backups")
    # Authentication is outside this diagnostic-response test. No real user,
    # credentials or external destination is used; nullable audit identity.
    user = SimpleNamespace(id=None, role="super_admin", organization_id=f.organization_id)

    async def session():
        async with AsyncSession(f.engine, expire_on_commit=False) as db:
            yield db

    app.dependency_overrides[backups.get_session] = session
    app.dependency_overrides[backups.get_current_active_user] = lambda: user
    return app


@pytest.mark.parametrize("failure", [ValueError, OSError])
@pytest.mark.parametrize("entrypoint", ["scheduled", "background", "api"])
def test_creation_failure_diagnostics_exclude_provider_text(
    scheduler, monkeypatch, caplog, failure, entrypoint
):
    import json

    from httpx import ASGITransport, AsyncClient

    f = scheduler
    marker = "synthetic-provider-private-detail-must-not-escape"

    async def unavailable(*_):
        raise failure(marker)

    monkeypatch.setattr(LocalStorageBackend, "save", unavailable)
    options = {"name": "Owned failed backup", "include_devices": False, "include_users": False,
               "include_automation": False, "include_vlans": False, "include_ssids": False}
    if entrypoint == "scheduled":
        result = tasks.run_scheduled_backups.run()
        assert result["triggered"] == 0 and result["errors"] == 1
    elif entrypoint == "background":
        result = tasks.run_backup.run({**options, "organization_id": str(f.organization_id)})
        assert result["success"] is False
    else:
        async def request():
            async with AsyncClient(transport=ASGITransport(app=_diagnostic_api(f), raise_app_exceptions=False), base_url="http://owned") as client:
                response = await client.post("/backups/", json=options)
                assert response.status_code >= 400
                return {"body": response.text}
        result = asyncio.run(request())

    async def failed_rows():
        async with AsyncSession(f.engine) as db:
            return list((await db.execute(select(Backup.status, Backup.error_message).where(Backup.organization_id == f.organization_id))).all())

    rows = asyncio.run(failed_rows())
    assert len(rows) == 1 and rows[0][0] == "failed" and rows[0][1]
    assert marker not in rows[0][1], "Catalog must not persist arbitrary provider diagnostics"
    assert marker not in json.dumps(result), "API/task response must not echo provider diagnostics"
    assert marker not in caplog.text, "Logs must not retain provider exception text/tracebacks"


@pytest.mark.parametrize("failure", [ValueError, OSError])
@pytest.mark.parametrize("entrypoint", ["service", "api"])
def test_restore_failure_diagnostics_exclude_provider_text(
    scheduler, monkeypatch, caplog, failure, entrypoint
):
    from httpx import ASGITransport, AsyncClient

    from app.modules.backup.models import RestoreJob

    f = scheduler
    assert tasks.run_scheduled_backups.run()["triggered"] == 1
    backup_id = asyncio.run(_owned_archive_ids(f))[0]
    marker = "synthetic-restore-private-detail-must-not-escape"

    async def unavailable(*_):
        raise failure(marker)

    monkeypatch.setattr(LocalStorageBackend, "load", unavailable)

    async def exercise():
        response_text = ""
        if entrypoint == "service":
            async with AsyncSession(f.engine, expire_on_commit=False) as db:
                with pytest.raises(failure):
                    await BackupService(db).restore_from_backup(backup_id, dry_run=True, organization_id=f.organization_id)
        else:
            async with AsyncClient(transport=ASGITransport(app=_diagnostic_api(f), raise_app_exceptions=False), base_url="http://owned") as client:
                response = await client.post("/backups/restore", json={"backup_id": str(backup_id), "dry_run": True})
                assert response.status_code >= 400
                response_text = response.text
        async with AsyncSession(f.engine) as db:
            rows = list((await db.execute(select(RestoreJob.status, RestoreJob.error_message).where(RestoreJob.backup_id == backup_id))).all())
        assert len(rows) == 1 and rows[0][0] == "failed" and rows[0][1]
        assert marker not in rows[0][1], "Restore job must not persist arbitrary provider diagnostics"
        assert marker not in response_text, "Restore API must not echo provider diagnostics"

    asyncio.run(exercise())
    assert marker not in caplog.text

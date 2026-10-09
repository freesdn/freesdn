# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Restore job/API outcomes must distinguish failed sections from completion."""

from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest
from sqlalchemy import select

from app.models.core import Organization, Site, User
from app.modules.backup.models import Backup, RestoreJob, StorageLocation
from app.services.backup import BackupService, LocalStorageBackend
from app.services.backup_contributors import (
    BackupContributorRegistry,
    ContributorPayload,
    RestoreResult,
)


class OutcomeContributor:
    schema_version = "1.0.0"
    depends_on = ()
    default_included = True

    def __init__(self, identifier, site_id, mode="success"):
        self.contributor_id = identifier
        self.site_id = site_id
        self.mode = mode

    async def collect(self, session, organization_id, options):
        return ContributorPayload(
            schema_version=self.schema_version,
            counts={"sites": 1},
            data={"site_id": str(self.site_id)},
        )

    async def restore(self, session, organization_id, payload, *, dry_run, options):
        if self.mode == "raised-error":
            raise RuntimeError("Owned synthetic module refusal")
        if self.mode in {"reported-error", "reported-error-empty"}:
            return RestoreResult(
                contributor_id=self.contributor_id,
                status="error",
                errors=[] if self.mode == "reported-error-empty" else ["Owned synthetic module refusal"],
            )
        if self.mode == "skipped-records":
            return RestoreResult(
                contributor_id=self.contributor_id,
                status="dry_run_ok" if dry_run else "ok",
                skipped={"sites": 1},
                warnings=["Owned configuration deliberately preserved"],
            )
        if not dry_run:
            site = await session.get(Site, UUID(payload.data["site_id"]))
            site.description = "Restored by " + self.contributor_id
            await session.flush()
        return RestoreResult(
            contributor_id=self.contributor_id,
            status="error" if self.mode == "reported-partial" else "dry_run_ok" if dry_run else "ok",
            updated={"sites": 1},
            errors=["Owned refusal after a write"] if self.mode == "reported-partial" else [],
        )


async def make_archive(db, tmp_path, monkeypatch, mode):
    import app.services.backup_contributors as contributors

    org = Organization(name="Owned outcome test", slug=uuid4().hex)
    db.add(org)
    await db.flush()
    identity = uuid4().hex
    owner = User(
        organization_id=org.id,
        username=identity,
        email=identity + "@example.invalid",
        hashed_password="owned-unusable-outcome-test-hash",
        role="super_admin",
    )
    sites = [
        Site(organization_id=org.id, name="Owned outcome site", slug=uuid4().hex,
             description="Original configuration")
        for _ in range(2)
    ]
    location = StorageLocation(
        organization_id=org.id, name="Owned outcome archives", storage_type="local",
        config={"path": str(tmp_path)}, is_active=True,
    )
    db.add_all([owner, location, *sites])
    await db.flush()
    first = OutcomeContributor("a_outcome", sites[0].id, mode)
    second = OutcomeContributor("z_success", sites[1].id)
    creation = BackupContributorRegistry()
    creation.register(first)
    creation.register(second)
    current_registry = [creation]
    monkeypatch.setattr(contributors, "get_registry", lambda: current_registry[0])
    monkeypatch.setattr(BackupService, "_contributors_initialized", True)
    original_resolve = BackupService._resolve_storage

    async def owned_storage(service, storage_type="local", storage_location_id=None):
        # Route the application's hard-coded default /data/backups into this
        # disposable location. The real backend, encryption and rollback-slot
        # creation still execute; no pre-existing deployment path is touched.
        assert storage_type == "local"
        return await original_resolve(service, storage_type, storage_location_id or location.id)

    monkeypatch.setattr(BackupService, "_resolve_storage", owned_storage)
    backup = await BackupService(db).create_backup(
        name="Owned outcome source", organization_id=org.id, created_by_id=owner.id,
        storage_location_id=location.id, is_encrypted=True,
        include_devices=False, include_users=False, include_automation=False,
    )
    assert backup.status == "completed" and not backup.error_message
    raw = await LocalStorageBackend({"path": str(tmp_path)}).load(backup.storage_path)
    assert raw and b"Original configuration" not in raw
    if mode == "missing":
        restoration = BackupContributorRegistry()
        restoration.register(second)
        current_registry[0] = restoration
    elif mode == "schema-mismatch":
        first.schema_version = "2.0.0"
    return SimpleNamespace(
        org=org.id, owner=owner.id, backup=backup.id, sites=[s.id for s in sites],
        selected=[second.contributor_id] if mode == "skipped" else None,
    )


@pytest.mark.parametrize("dry_run", [False, True])
@pytest.mark.parametrize(
    "mode", ["success", "reported-error", "reported-error-empty", "raised-error", "reported-partial",
             "missing", "schema-mismatch", "skipped", "skipped-records"],
)
async def test_restore_http_and_persisted_job_report_the_real_outcome(
    db_session, async_client, tmp_path, monkeypatch, mode, dry_run
):
    from app.api.v1.endpoints import backups as backups_api
    from app.main import app

    f = await make_archive(db_session, tmp_path, monkeypatch, mode)

    async def owned_principal():
        return SimpleNamespace(id=f.owner, organization_id=f.org, is_superuser=True, _scoped=False)

    monkeypatch.setitem(app.dependency_overrides, backups_api.get_current_active_user, owned_principal)
    response = await async_client.post(
        "/api/v1/backups/restore",
        json={"backup_id": str(f.backup), "dry_run": dry_run,
              "overwrite_existing": True, "contributors": f.selected},
        headers={"Authorization": "Bearer owned-outcome-fixture"},
    )
    assert response.status_code == 200
    body = response.json()
    failed = mode not in {"success", "skipped", "skipped-records"}
    assert body["status"] == ("failed" if failed else "completed")
    # Intentional preserved records must not inflate the failed-row counter.
    # Missing modules and rolled-back writes have known skipped row counts;
    # other refusals only have a module-level failure, not a known row count.
    known_failed_rows = int(mode == "missing" or (mode == "reported-partial" and not dry_run))
    assert body["items_failed"] == known_failed_rows
    assert body["dry_run"] is dry_run and body["progress"] == 100
    assert body["completed_at"] is not None
    report = body["dry_run_report" if dry_run else "restore_log"]
    assert report["summary"]["contributors_failed"] == int(failed)
    if failed:
        assert body["error_message"]
    else:
        assert body["error_message"] is None
    job = await db_session.get(RestoreJob, UUID(body["id"]))
    await db_session.refresh(job)
    assert job.status == body["status"] and job.error_message == body["error_message"]
    assert job.items_failed == body["items_failed"]
    assert job.items_restored == report["summary"]["total_created"] + report["summary"]["total_updated"]
    second_description = await db_session.scalar(select(Site.description).where(Site.id == f.sites[1]))
    assert second_description == ("Original configuration" if dry_run else "Restored by z_success")
    if not dry_run:
        first_description = await db_session.scalar(select(Site.description).where(Site.id == f.sites[0]))
        assert first_description == ("Restored by a_outcome" if mode == "success" else "Original configuration")
    slots = list(
        (await db_session.execute(select(Backup).where(Backup.rollback_for_restore_job_id == job.id))).scalars()
    )
    assert len(slots) == (0 if dry_run else 1)
    assert all(slot.status == "completed" and slot.is_encrypted for slot in slots)

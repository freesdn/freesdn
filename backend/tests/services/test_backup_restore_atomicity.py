# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""A contributor's reported failure must roll back its real database writes."""

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy import select

from app.models.core import Organization, Site
from app.services.backup import BackupService
from app.services.backup_contributors import (
    BackupArchive,
    BackupContributorRegistry,
    BackupManifest,
    ContributorEntry,
    ContributorPayload,
    RestoreResult,
)


class WritingContributor:
    schema_version = "1.0.0"
    depends_on = ()
    default_included = True

    def __init__(self, identifier, *, mode="ok", flush=True, existing_id=None):
        self.contributor_id = identifier
        self.mode = mode
        self.flush = flush
        self.existing_id = existing_id
        self.created_id = uuid4()
        self.calls = []

    async def collect(self, session, organization_id, options):
        return ContributorPayload(schema_version=self.schema_version)

    async def restore(self, session, organization_id, payload, *, dry_run, options):
        self.calls.append(dry_run)
        if not dry_run:
            if self.existing_id is not None:
                row = await session.get(Site, self.existing_id)
                row.description = "Partially overwritten"
            session.add(
                Site(
                    id=self.created_id,
                    organization_id=organization_id,
                    name="Owned contributor row",
                    slug=uuid4().hex,
                )
            )
            if self.flush:
                await session.flush()
        if self.mode == "exception":
            raise RuntimeError("Owned synthetic contributor refusal")
        return RestoreResult(
            contributor_id=self.contributor_id,
            status="error" if self.mode == "reported-error" else "dry_run_ok" if dry_run else "ok",
            created={"sites": 1},
            updated={"sites": 1} if self.existing_id is not None else {},
            skipped={"other_records": 3} if self.mode == "reported-error" else {},
            errors=["Owned synthetic contributor refusal"] if self.mode == "reported-error" else [],
        )


async def setup_restore(db, monkeypatch, *, mode, flush=True):
    import app.services.backup_contributors as contributors

    org = Organization(name="Owned restore transaction", slug=uuid4().hex)
    db.add(org)
    await db.flush()
    existing = Site(
        organization_id=org.id,
        name="Before restore",
        slug=uuid4().hex,
        description="Original configuration",
    )
    db.add(existing)
    await db.flush()
    first = WritingContributor("a_partial", mode=mode, flush=flush, existing_id=existing.id)
    second = WritingContributor("z_independent", flush=flush)
    registry = BackupContributorRegistry()
    registry.register(first)
    registry.register(second)
    assert [c.contributor_id for c in registry.topological_order()] == [
        first.contributor_id, second.contributor_id
    ]
    monkeypatch.setattr(contributors, "get_registry", lambda: registry)
    monkeypatch.setattr(BackupService, "_contributors_initialized", True)
    archive = BackupArchive(
        manifest=BackupManifest(
            backup_id=str(uuid4()),
            created_at=datetime.now(UTC),
            organization_id=str(org.id),
            contributors=[
                ContributorEntry(id=first.contributor_id, schema_version="1.0.0", counts={"sites": 2}),
                ContributorEntry(id=second.contributor_id, schema_version="1.0.0", counts={"sites": 1}),
            ],
        ),
        contributors={first.contributor_id: {}, second.contributor_id: {}},
    )
    return org.id, existing.id, first, second, archive


@pytest.mark.parametrize("mode", ["reported-error", "exception"])
@pytest.mark.parametrize("flush", [False, True])
@pytest.mark.parametrize("commit_outer", [False, True])
async def test_failed_contributor_cannot_leave_partial_changes(
    db_session, monkeypatch, mode, flush, commit_outer
):
    org, existing, first, second, archive = await setup_restore(
        db_session, monkeypatch, mode=mode, flush=flush
    )
    report = await BackupService(db_session)._dispatch_restore_via_contributors(
        archive, organization_id=org, dry_run=False, restore_options={}
    )
    if commit_outer:
        await db_session.commit()
    description = await db_session.scalar(select(Site.description).where(Site.id == existing))
    assert description == "Original configuration"
    assert await db_session.get(Site, first.created_id) is None
    assert await db_session.get(Site, second.created_id) is not None
    assert first.calls == second.calls == [False]
    by_id = {row["contributor_id"]: row for row in report["contributors"]}
    assert by_id[first.contributor_id]["status"] == "error"
    assert not by_id[first.contributor_id]["created"]
    assert not by_id[first.contributor_id]["updated"]
    assert report["summary"]["total_created"] == 1
    assert report["summary"]["total_updated"] == 0
    assert report["summary"]["contributors_failed"] == 1
    assert report["summary"]["contributors_ok"] == 1
    if mode == "reported-error":
        assert by_id[first.contributor_id]["skipped"] == {"sites": 2, "other_records": 3}
        assert by_id[first.contributor_id]["errors"] == ["Owned synthetic contributor refusal"]


@pytest.mark.parametrize("dry_run", [False, True])
@pytest.mark.parametrize("flush", [False, True])
async def test_successful_contributors_keep_their_normal_apply_and_preview_behavior(
    db_session, monkeypatch, dry_run, flush
):
    org, existing, first, second, archive = await setup_restore(
        db_session, monkeypatch, mode="ok", flush=flush
    )
    report = await BackupService(db_session)._dispatch_restore_via_contributors(
        archive, organization_id=org, dry_run=dry_run, restore_options={}
    )
    await db_session.commit()
    description = await db_session.scalar(select(Site.description).where(Site.id == existing))
    assert description == ("Original configuration" if dry_run else "Partially overwritten")
    for identifier in (first.created_id, second.created_id):
        assert (await db_session.get(Site, identifier) is None) is dry_run
    assert report["summary"]["total_created"] == 2
    assert report["summary"]["total_updated"] == 1
    assert report["summary"]["contributors_failed"] == 0
    assert report["summary"]["contributors_ok"] == 2


async def test_real_core_failure_after_profile_change_rolls_back_its_section(db_session, monkeypatch):
    import app.services.backup_contributors as contributors
    from app.services.backup_contributors import CoreBackupContributor

    org, existing, _first, second, archive = await setup_restore(
        db_session, monkeypatch, mode="ok"
    )
    registry = BackupContributorRegistry()
    registry.register(CoreBackupContributor())
    registry.register(second)
    monkeypatch.setattr(contributors, "get_registry", lambda: registry)
    archive.manifest.contributors = [
        ContributorEntry(id="core", schema_version="1.0.0", counts={"sites": 1, "users": 1}),
        ContributorEntry(id=second.contributor_id, schema_version="1.0.0", counts={"sites": 1}),
    ]
    archive.contributors = {
        "core": {
            "sites": [{"id": str(existing), "description": "Partially overwritten"}],
            # Valid JSON can still contain a malformed record. The real core
            # contributor catches the resulting Python error and reports it.
            "users": [None],
        },
        second.contributor_id: {},
    }
    report = await BackupService(db_session)._dispatch_restore_via_contributors(
        archive, organization_id=org, dry_run=False,
        restore_options={"restore_users": True, "overwrite_existing": True},
    )
    await db_session.commit()
    assert await db_session.scalar(select(Site.description).where(Site.id == existing)) == (
        "Original configuration"
    )
    assert await db_session.get(Site, second.created_id) is not None
    by_id = {r["contributor_id"]: r for r in report["contributors"]}
    assert by_id["core"]["status"] == "error" and by_id["core"]["errors"]
    assert report["summary"]["contributors_ok"] == report["summary"]["contributors_failed"] == 1

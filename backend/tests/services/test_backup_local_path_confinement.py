# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Local backup storage stays inside /data/backups or a server-configured root.

A local (or NFS) storage location's ``path`` was used as given. An org admin
could point it at any directory the application user can write, and every
backup or connection test then wrote files there: the application's own code
tree, the VPN sidecar's config volumes. Now the path must resolve, after ``..``
and symlinks, inside /data/backups or one of BACKUP_LOCAL_EXTRA_ROOTS, which
only the server's environment can set. A location created before this is kept
and flagged, and backups through it fail with the reason and raise an event.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.core import Organization
from app.modules.backup.models import Backup, BackupStatus, StorageLocation
from app.services import backup as backup_module
from app.services.backup import BackupService, LocalStorageBackend
from app.services.backup_transport import (
    LocalBackupPathError,
    StorageConfigurationError,
    confine_local_backup_path,
)


@pytest.fixture
def roots(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> tuple[Path, Path]:
    """One allowed extra root and one directory outside every root."""
    allowed = tmp_path / "allowed"
    outside = tmp_path / "outside"
    allowed.mkdir()
    outside.mkdir()
    monkeypatch.setattr(settings, "BACKUP_LOCAL_EXTRA_ROOTS", f"relative/ignored,{allowed}")
    return allowed, outside


def test_the_backup_volume_is_always_allowed(roots) -> None:
    assert confine_local_backup_path("/data/backups/site-a") == "/data/backups/site-a"
    assert confine_local_backup_path(None) == "/data/backups"


def test_a_configured_extra_root_is_allowed(roots) -> None:
    allowed, _ = roots
    assert confine_local_backup_path(str(allowed / "nightly")) == str(allowed / "nightly")


@pytest.mark.parametrize(
    "path",
    [
        "/etc/freesdn",
        "/data/backups/../../app",
        "/data/backups-evil",
        "relative/backups",
        "relative/ignored",
    ],
)
def test_a_path_outside_every_root_is_refused(roots, path: str) -> None:
    with pytest.raises(LocalBackupPathError):
        confine_local_backup_path(path)


def test_a_symlink_out_of_an_allowed_root_is_refused(roots) -> None:
    allowed, outside = roots
    (allowed / "escape").symlink_to(outside, target_is_directory=True)
    with pytest.raises(LocalBackupPathError):
        confine_local_backup_path(str(allowed / "escape" / "nightly"))


def test_the_backend_refuses_before_writing_anything(roots) -> None:
    _, outside = roots
    with pytest.raises(LocalBackupPathError):
        LocalStorageBackend({"path": str(outside)})
    assert list(outside.iterdir()) == []


async def _org(db: AsyncSession) -> Organization:
    org = Organization(name="Backup roots", slug=f"backup-roots-{uuid4().hex[:8]}")
    db.add(org)
    await db.flush()
    return org


async def test_creating_or_moving_a_location_outside_the_roots_is_refused(
    roots, db_session: AsyncSession
) -> None:
    allowed, outside = roots
    org = await _org(db_session)
    svc = BackupService(db_session)

    with pytest.raises(StorageConfigurationError):
        await svc.create_storage_location(
            name="outside",
            storage_type="local",
            config={"path": str(outside)},
            organization_id=org.id,
        )
    with pytest.raises(StorageConfigurationError):
        await svc.create_storage_location(
            name="nfs outside",
            storage_type="nfs",
            config={"path": str(outside)},
            organization_id=org.id,
        )
    inside = await svc.create_storage_location(
        name="inside",
        storage_type="local",
        config={"path": str(allowed)},
        organization_id=org.id,
    )
    with pytest.raises(StorageConfigurationError):
        await svc.update_storage_location(inside.id, config={"path": str(outside)})


async def test_an_existing_outside_location_is_flagged_and_its_backups_fail_loudly(
    roots, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, outside = roots
    org = await _org(db_session)
    legacy = StorageLocation(
        name="pre-upgrade",
        organization_id=org.id,
        storage_type="local",
        config={"path": str(outside)},
        is_active=True,
    )
    db_session.add(legacy)
    await db_session.flush()
    assert legacy.local_path_review_required is True

    published: list[Any] = []

    class _Bus:
        async def publish(self, event: Any) -> None:
            published.append(event)

    import app.core.events as events

    monkeypatch.setattr(events, "get_event_bus", lambda: _Bus())

    name = f"refused-{uuid4().hex[:8]}"
    with pytest.raises(LocalBackupPathError):
        await BackupService(db_session).create_backup(
            name=name,
            organization_id=org.id,
            storage_location_id=legacy.id,
            include_users=False,
        )

    backup = (await db_session.execute(select(Backup).where(Backup.name == name))).scalar_one()
    assert backup.status == BackupStatus.FAILED
    assert "outside the allowed backup storage" in (backup.error_message or "")
    assert [e.event_type for e in published] == ["backup.storage.path_refused"]
    assert published[0].payload["storage_location_id"] == str(legacy.id)
    assert list(outside.iterdir()) == []


def test_the_reason_reaches_the_job_result() -> None:
    """The Celery task reports backup_failure_detail; it must keep this reason."""
    err = LocalBackupPathError("Local backup path '/x' is outside the allowed backup storage")
    assert backup_module.backup_failure_detail(err, "generic") == str(err)

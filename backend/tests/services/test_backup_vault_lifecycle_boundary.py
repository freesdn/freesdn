# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Full account restore coordinates with actual lifecycle ownership and batches."""

import asyncio
import copy
from uuid import uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.user_lifecycle import lock_user_lifecycle
from app.models.core import User
from app.services.backup import BackupService
from tests.services.test_backup_vault_security_roundtrip import export_vault, source_fixture
from tests.services.test_backup_vault_security_roundtrip import vault_db as vault_db


async def restore(db, archive, org_id):
    return await BackupService(db)._dispatch_restore_via_contributors(
        archive, organization_id=org_id, dry_run=False,
        restore_options={"overwrite_existing": True, "restore_users": True,
                         "restore_devices": False, "include_secrets": True},
    )


@pytest.mark.parametrize("other_owner", [False, True], ids=["same-transaction", "other-transaction"])
async def test_restore_coordinates_with_real_lifecycle_owner_without_waiting(vault_db, tmp_path, monkeypatch, other_owner):
    f = await source_fixture(vault_db, tmp_path, monkeypatch)
    archive = await export_vault(f)
    org_id, user_id = f.org.id, f.user.id
    before = (await f.db.execute(select(*User.__table__.columns).where(User.id == user_id))).mappings().one()
    async with AsyncSession(f.db.bind) as competing:
        await lock_user_lifecycle(competing if other_owner else f.db)
        try:
            # A restore caller may already own row locks. Refuse a foreign
            # lifecycle owner promptly rather than introduce reverse lock waits.
            report = await asyncio.wait_for(restore(f.db, archive, org_id), timeout=2)
        finally:
            await competing.rollback()
    await f.db.commit()
    after = (await f.db.execute(select(*User.__table__.columns).where(User.id == user_id))).mappings().one()
    if other_owner:
        assert report["summary"]["contributors_failed"] == 1
        assert dict(after) == dict(before)
    else:
        assert report["summary"]["contributors_failed"] == report["summary"]["total_errors"] == 0
        assert after["token_version"] > before["token_version"]


@pytest.mark.parametrize("new_first", [False, True], ids=["retiring-admin-first", "new-admin-first"])
async def test_valid_full_vault_admin_replacement_is_order_independent(vault_db, tmp_path, monkeypatch, new_first):
    f = await source_fixture(vault_db, tmp_path, monkeypatch)
    archive = await export_vault(f)
    org_id, user_id = f.org.id, f.user.id
    old = archive.contributors["core"]["users"][0]
    new = copy.deepcopy(old)
    new_id, username = uuid4(), uuid4().hex
    f.db.info["owned_user_ids"].append(new_id)
    new.update(id=str(new_id), username=username, email=username + "@example.com")
    old["is_active"] = False
    archive.contributors["core"]["users"] = [new, old] if new_first else [old, new]
    report = await restore(f.db, archive, org_id)
    await f.db.commit()
    assert report["summary"]["contributors_failed"] == report["summary"]["total_errors"] == 0
    active = (await f.db.execute(select(User.id).where(User.organization_id == org_id,
                                                      User.is_active.is_(True), User.role == "super_admin",
                                                      User.deleted_at.is_(None)))).scalars().all()
    assert active == [new_id]
    assert await f.db.scalar(select(User.is_active).where(User.id == user_id)) is False

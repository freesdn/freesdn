# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""A restore caller holding a row must not wait behind the inverse lock owner."""

import asyncio

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.user_lifecycle import lock_user_lifecycle
from app.models.core import User
from app.services.backup import BackupService
from tests.services.test_backup_vault_security_roundtrip import export_vault, source_fixture
from tests.services.test_backup_vault_security_roundtrip import vault_db as vault_db


async def test_real_inverse_wait_is_refused_without_deadlock_or_caller_commit(vault_db, tmp_path, monkeypatch, request):
    f = await source_fixture(vault_db, tmp_path, monkeypatch)
    archive = await export_vault(f)
    org_id, user_id = f.org.id, f.user.id
    await f.db.execute(select(User.id).where(User.id == user_id).with_for_update())
    owner_pid = await f.db.scalar(text("select pg_backend_pid()"))
    ready = asyncio.Event()
    peer = {}

    async def inverse_owner():
        async with f.db.bind.connect() as connection:
            async with AsyncSession(bind=connection) as db:
                peer["pid"] = await db.scalar(text("select pg_backend_pid()"))
                await lock_user_lifecycle(db)
                ready.set()
                # Match the actual lifecycle-before-User order. The test does
                # not claim to execute an authenticated administrative route.
                await db.execute(select(User.id).where(User.id == user_id).with_for_update())
                await db.rollback()

    other = asyncio.create_task(inverse_owner())
    try:
        await asyncio.wait_for(ready.wait(), 5)
        for _ in range(200):
            blocking = await f.db.scalar(text("select pg_blocking_pids(:pid)"), {"pid": peer["pid"]})
            if owner_pid in blocking:
                break
            await asyncio.sleep(0.01)
        else:
            raise AssertionError("Real inverse User-row wait was never established")
        report = await asyncio.wait_for(BackupService(f.db)._dispatch_restore_via_contributors(
            archive, organization_id=org_id, dry_run=False,
            restore_options={"overwrite_existing": True, "restore_users": True,
                             "restore_devices": False, "include_secrets": True},
        ), timeout=2)
        assert report["summary"]["contributors_failed"] == 1
        assert "Account lifecycle changes are in progress" in str(report["contributors"][0]["errors"])
        assert not other.done(), "Restore must not commit or roll back the caller's preheld row lock"
        assert await f.db.scalar(select(User.token_version).where(User.id == user_id)) == 17
        await f.db.rollback()
        await asyncio.wait_for(other, 5)
        request.node.user_properties.append(("pg_blocking_pids_inverse_wait_verified", True))
    finally:
        await f.db.rollback()
        if not other.done():
            other.cancel()
        await asyncio.gather(other, return_exceptions=True)

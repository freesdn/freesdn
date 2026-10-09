# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Account and profile restore coordinate with actual authenticated grant writes."""

import asyncio

import pytest
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_session
from app.main import app
from app.models.core import Site, User
from app.services.backup import BackupService
from tests.services.test_backup_vault_security_roundtrip import export_vault
from tests.services.test_backup_vault_security_roundtrip import vault_db as vault_db
from tests.services.test_site_grant_mutation_boundaries import (
    client_for,
    grant_fixture,
    grant_state,
)


@pytest.mark.parametrize("credential", ["jwt", "api-key"])
@pytest.mark.parametrize("include_secrets", [False, True], ids=["profile-only", "account-security"])
async def test_restore_refuses_inverse_wait_with_actual_grant_route(vault_db, tmp_path, monkeypatch,
                                                                   credential, include_secrets, request):
    g = await grant_fixture(vault_db, tmp_path, monkeypatch, credential)
    archive = await export_vault(g.f)
    original_name = g.sites[0].name
    g.sites[0].name = "Owned uncommitted caller change"
    await g.f.db.flush()  # Preserve caller-owned Site lock and uncommitted work.
    holder_pid = await g.f.db.scalar(text("select pg_backend_pid()"))
    observed = {}

    async def pinned_request_session():
        async with g.f.db.bind.connect() as connection:
            async with AsyncSession(bind=connection, expire_on_commit=False, autoflush=False) as db:
                observed["pid"] = await db.scalar(text("select pg_backend_pid()"))
                try:
                    yield db
                    await db.commit()
                except BaseException:
                    await db.rollback()
                    raise

    monkeypatch.setitem(app.dependency_overrides, get_session, pinned_request_session)
    # Save identities before rollback expires the fixture's ORM objects.
    site_id, user_id, org_id = g.sites[0].id, g.f.user.id, g.f.org.id
    async with client_for(g) as client:
        task = asyncio.create_task(client.post(f"/api/v1/organizations/{org_id}/site-access",
                                               json={"user_id": str(user_id), "site_id": str(site_id),
                                                     "access_level": "read"}))
        try:
            async with asyncio.timeout(10):
                while True:
                    if observed.get("pid") is not None and holder_pid in await g.f.db.scalar(
                        text("select pg_blocking_pids(:pid)"), {"pid": observed["pid"]},
                    ):
                        break
                    assert not task.done(), "Grant route did not reach its actual Site-row wait"
                    await asyncio.sleep(0.01)
            assert holder_pid != observed["pid"]
            report = await asyncio.wait_for(BackupService(g.f.db)._dispatch_restore_via_contributors(
                archive, organization_id=org_id, dry_run=False,
                restore_options={"overwrite_existing": True, "restore_users": True,
                                 "restore_devices": False, "include_secrets": include_secrets},
            ), timeout=2)
            assert report["summary"]["contributors_failed"] == 1
            assert "Account lifecycle changes are in progress" in str(report["contributors"][0]["errors"])
            assert not task.done(), "Restore must leave the caller's preheld Site lock intact"
            assert await g.f.db.scalar(select(Site.name).where(Site.id == site_id)) == "Owned uncommitted caller change"
            async with AsyncSession(g.f.db.bind) as observer:
                assert await observer.scalar(select(Site.name).where(Site.id == site_id)) == original_name
                assert await observer.scalar(select(User.token_version).where(User.id == user_id)) == 17
            await g.f.db.rollback()
            response = await asyncio.wait_for(task, timeout=10)
            assert response.status_code == 201, response.text
            assert await g.f.db.scalar(select(Site.name).where(Site.id == site_id)) == original_name
            # Refresh expired identities before using the shared state helper.
            await g.f.db.refresh(g.f.user)
            assert await grant_state(g) == [(str(site_id), "read")]
            request.node.user_properties.extend([("genuine_authenticated_grant_inverse_wait", True),
                                                  ("caller_transaction_preserved", True),
                                                  ("grant_status_after_caller_rollback", response.status_code)])
        finally:
            await g.f.db.rollback()
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)

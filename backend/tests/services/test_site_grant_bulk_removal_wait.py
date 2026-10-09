# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Bulk removal must roll back if its last row wait outlives authority."""

import asyncio
from datetime import UTC, datetime

import pytest
from sqlalchemy import select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_session
from app.main import app
from app.models.api_keys import APIKey
from app.models.core import User, UserSession, UserSiteAccess
from tests.services.test_backup_vault_security_roundtrip import vault_db as vault_db
from tests.services.test_site_grant_mutation_boundaries import (
    client_for,
    grant_fixture,
    grant_state,
)


@pytest.mark.parametrize("credential", ["jwt", "api-key"])
@pytest.mark.parametrize("change", ["unchanged", "actor-revoked", "credential-revoked"])
async def test_bulk_removal_rechecks_after_grant_delete_wait(vault_db, tmp_path, monkeypatch, credential, change, request):
    g = await grant_fixture(vault_db, tmp_path, monkeypatch, credential)
    grant = UserSiteAccess(user_id=g.f.user.id, site_id=g.sites[0].id, access_level="read")
    g.f.db.add(grant)
    await g.f.db.commit()
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
    await g.f.db.execute(select(UserSiteAccess.id).where(UserSiteAccess.id == grant.id).with_for_update())
    holder_pid = await g.f.db.scalar(text("select pg_backend_pid()"))
    async with client_for(g) as client:
        task = asyncio.create_task(client.put(f"/api/v1/organizations/{g.f.org.id}/site-access/bulk",
                                               json={"user_id": str(g.f.user.id), "site_ids": [], "access_level": "read"}))
        try:
            async with asyncio.timeout(10):
                while True:
                    if observed.get("pid") is not None and holder_pid in await g.f.db.scalar(
                        text("select pg_blocking_pids(:pid)"), {"pid": observed["pid"]},
                    ):
                        break
                    assert not task.done(), "Bulk removal ended without its real Grant-row wait"
                    await asyncio.sleep(0.01)
            assert holder_pid != observed["pid"]
            if change == "actor-revoked":
                await g.f.db.execute(update(User).where(User.id == g.actor.id).values(token_version=1))
            elif change == "credential-revoked":
                if credential == "jwt":
                    await g.f.db.execute(update(UserSession).where(UserSession.id == g.device.id)
                                         .values(is_revoked=True, revoked_at=datetime.now(UTC)))
                else:
                    await g.f.db.execute(update(APIKey).where(APIKey.id == g.key.id).values(is_active=False))
            await g.f.db.commit()
            response = await asyncio.wait_for(task, timeout=10)
            actual = await grant_state(g)
            request.node.user_properties.extend([("genuine_grant_delete_wait", True),
                                                  ("response_status", response.status_code),
                                                  ("committed_grants", repr(actual))])
            assert (response.status_code, actual) == ((200, []) if change == "unchanged" else
                                                      (401, [(str(g.sites[0].id), "read")]))
        finally:
            await g.f.db.rollback()
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)

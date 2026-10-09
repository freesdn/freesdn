# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Actual grant routes must revalidate tenant ownership after parent-row waits.

Private probes only. A cross-organization grant row would establish a failed
ownership invariant, not by itself successful access to another tenant's data.
"""

import asyncio
from uuid import uuid4

import httpx
import pytest
from sqlalchemy import select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, get_password_hash
from app.db.session import get_session
from app.main import app
from app.models.api_keys import APIKey, generate_api_key
from app.models.core import Organization, Site, User, UserSiteAccess
from tests.services.test_backup_vault_security_roundtrip import source_fixture
from tests.services.test_backup_vault_security_roundtrip import vault_db as vault_db


@pytest.mark.parametrize("credential", ["jwt", "api-key"])
@pytest.mark.parametrize("route", ["single", "bulk"])
@pytest.mark.parametrize("parent", ["user", "site"])
@pytest.mark.parametrize("moved", [False, True], ids=["unchanged-control", "moved-organization"])
async def test_grant_wait_cannot_commit_foreign_parent(vault_db, tmp_path, monkeypatch, credential, route, parent, moved, request):
    f = await source_fixture(vault_db, tmp_path, monkeypatch)
    f.user.role = "operator"
    org_id, user_id = f.org.id, f.user.id
    other_org = Organization(id=uuid4(), name="Owned grant target organization", slug=uuid4().hex)
    site = Site(id=uuid4(), organization_id=org_id, name="Owned grant site", slug=uuid4().hex)
    identity = uuid4().hex
    actor = User(id=uuid4(), organization_id=org_id, username=identity, email=identity + "@example.com",
                 hashed_password=get_password_hash("Owned grant actor password"), role="super_admin",
                 is_active=True, is_verified=True, token_version=0)
    f.db.add_all([other_org, site, actor])
    f.db.info["owned_org_ids"].append(other_org.id)
    f.db.info["owned_user_ids"].append(actor.id)
    await f.db.flush()
    if credential == "jwt":
        headers = {"Authorization": "Bearer " + create_access_token(subject=str(actor.id), token_version=0)}
    else:
        raw, prefix, key_hash = generate_api_key()
        f.db.add(APIKey(user_id=actor.id, name="Owned grant request key", key_prefix=prefix,
                        key_hash=key_hash, scopes=[], is_active=True))
        headers = {"X-API-Key": raw}
    await f.db.commit()
    site_id, other_org_id = site.id, other_org.id
    observed = {}

    async def pinned_request_session():
        async with f.db.bind.connect() as connection:
            async with AsyncSession(bind=connection, expire_on_commit=False, autoflush=False) as db:
                observed["pid"] = await db.scalar(text("select pg_backend_pid()"))
                try:
                    yield db
                    await db.commit()
                except BaseException:
                    await db.rollback()
                    raise

    monkeypatch.setitem(app.dependency_overrides, get_session, pinned_request_session)
    model, row_id = (User, user_id) if parent == "user" else (Site, site_id)
    await f.db.execute(select(model.id).where(model.id == row_id).with_for_update())
    holder_pid = await f.db.scalar(text("select pg_backend_pid()"))
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False, client=("198.19.17.21", 45123))
    async with httpx.AsyncClient(transport=transport, base_url="http://test", headers=headers) as client:
        if route == "single":
            task = asyncio.create_task(client.post(f"/api/v1/organizations/{org_id}/site-access",
                                                  json={"user_id": str(user_id), "site_id": str(site_id), "access_level": "read"}))
        else:
            task = asyncio.create_task(client.put(f"/api/v1/organizations/{org_id}/site-access/bulk",
                                                 json={"user_id": str(user_id), "site_ids": [str(site_id)], "access_level": "read"}))
        try:
            for _ in range(500):
                if observed.get("pid") is not None:
                    blockers = await f.db.scalar(text("select pg_blocking_pids(:pid)"), {"pid": observed["pid"]})
                    if holder_pid in blockers:
                        break
                assert not task.done(), "Request never reached a genuine parent-row lock wait"
                await asyncio.sleep(0.01)
            else:
                raise AssertionError("Genuine PostgreSQL parent-row wait was not established")
            assert holder_pid != observed["pid"]
            if moved:
                await f.db.execute(update(model).where(model.id == row_id).values(organization_id=other_org_id))
            await f.db.commit()
            response = await asyncio.wait_for(task, timeout=5)
            grants = (await f.db.execute(select(UserSiteAccess.site_id).where(UserSiteAccess.user_id == user_id))).scalars().all()
            request.node.user_properties.extend([("genuine_parent_row_wait", True),
                                                  ("response_status", response.status_code),
                                                  ("observed_grants", len(grants))])
            if moved:
                # Record committed grant state with the failed status assertion.
                assert (response.status_code in {400, 403, 404}, grants) == (True, [])
            else:
                assert response.status_code == (201 if route == "single" else 200), response.text
                assert grants == [site_id]
        finally:
            await f.db.rollback()
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)

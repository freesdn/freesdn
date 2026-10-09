# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Real HTTP grant replacement, deletion, and post-wait authority contracts.

All rows and credentials are disposable. SQL changes establish precisely timed
revocations; they do not qualify the separate administrative mutation routes.
"""

import asyncio
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

import httpx
import pytest
from sqlalchemy import select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, decode_token, get_password_hash
from app.db.session import get_session
from app.main import app
from app.models.api_keys import APIKey, generate_api_key
from app.models.core import Organization, Site, User, UserSession, UserSiteAccess
from tests.services.test_backup_vault_security_roundtrip import source_fixture
from tests.services.test_backup_vault_security_roundtrip import vault_db as vault_db


async def grant_fixture(vault_db, tmp_path, monkeypatch, credential):
    f = await source_fixture(vault_db, tmp_path, monkeypatch)
    f.user.role = "operator"
    identity = uuid4().hex
    actor = User(id=uuid4(), organization_id=f.org.id, username=identity,
                 email=identity + "@example.com", role="super_admin",
                 hashed_password=get_password_hash("Owned grant boundary password"),
                 is_active=True, is_verified=True, token_version=0)
    sites = [Site(id=uuid4(), organization_id=f.org.id, name="Owned grant boundary site",
                  slug=uuid4().hex) for _ in range(3)]
    f.db.add_all([actor, *sites])
    f.db.info["owned_user_ids"].append(actor.id)
    await f.db.flush()
    token = create_access_token(subject=str(actor.id), token_version=0)
    claims = await decode_token(token)
    assert claims is not None
    device = UserSession(id=uuid4(), user_id=actor.id, access_jti=claims["jti"],
                         created_at=datetime.now(UTC), expires_at=datetime.now(UTC) + timedelta(minutes=10))
    raw, prefix, key_hash = generate_api_key()
    key = APIKey(id=uuid4(), user_id=actor.id, name="Owned grant boundary key",
                 key_prefix=prefix, key_hash=key_hash, scopes=[], is_active=True)
    f.db.add_all([device, key])
    await f.db.commit()
    headers = {"Authorization": "Bearer " + token} if credential == "jwt" else {"X-API-Key": raw}
    return SimpleNamespace(f=f, sites=sites, actor=actor, key=key, device=device, headers=headers)


def client_for(g):
    peer = uuid4().int
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, raise_app_exceptions=False,
                                     client=(f"198.19.{peer >> 8 & 255}.{peer & 255}", 45251)),
        base_url="http://test", headers=g.headers,
    )


async def grant_state(g):
    rows = (await g.f.db.execute(select(UserSiteAccess.site_id, UserSiteAccess.access_level)
                                 .where(UserSiteAccess.user_id == g.f.user.id))).all()
    return sorted((str(row.site_id), row.access_level) for row in rows)


@pytest.mark.parametrize("credential", ["jwt", "api-key"])
@pytest.mark.parametrize("replacement", ["same", "overlap", "disjoint", "empty"])
async def test_bulk_replacement_preserves_requested_set(vault_db, tmp_path, monkeypatch, credential, replacement, request):
    g = await grant_fixture(vault_db, tmp_path, monkeypatch, credential)
    for site in g.sites[:2]:
        g.f.db.add(UserSiteAccess(user_id=g.f.user.id, site_id=site.id, access_level="read"))
    await g.f.db.commit()
    indices = {"same": [0, 1], "overlap": [1, 2], "disjoint": [2], "empty": []}[replacement]
    desired = [g.sites[i].id for i in indices]
    async with client_for(g) as client:
        response = await client.put(f"/api/v1/organizations/{g.f.org.id}/site-access/bulk",
                                    json={"user_id": str(g.f.user.id), "site_ids": list(map(str, desired)),
                                          "access_level": "write"})
    actual = await grant_state(g)
    request.node.user_properties.extend([("response_status", response.status_code),
                                          ("committed_grants", repr(actual))])
    assert (response.status_code, actual) == (200, sorted((str(sid), "write") for sid in desired))
    assert sorted((row["site_id"], row["access_level"]) for row in response.json()) == actual


@pytest.mark.parametrize("credential", ["jwt", "api-key"])
@pytest.mark.parametrize("ownership", ["valid", "foreign-user", "foreign-site"])
async def test_delete_checks_both_parent_organizations(vault_db, tmp_path, monkeypatch, credential, ownership, request):
    g = await grant_fixture(vault_db, tmp_path, monkeypatch, credential)
    grant = UserSiteAccess(id=uuid4(), user_id=g.f.user.id, site_id=g.sites[0].id, access_level="read")
    g.f.db.add(grant)
    if ownership != "valid":
        foreign = Organization(id=uuid4(), name="Owned foreign grant organization", slug=uuid4().hex)
        g.f.db.add(foreign)
        g.f.db.info["owned_org_ids"].append(foreign.id)
        await g.f.db.flush()
        if ownership == "foreign-user":
            g.f.user.organization_id = foreign.id
        else:
            g.sites[0].organization_id = foreign.id
    await g.f.db.commit()
    async with client_for(g) as client:
        response = await client.delete(f"/api/v1/organizations/{g.f.org.id}/site-access/{grant.id}")
    actual = await grant_state(g)
    request.node.user_properties.extend([("response_status", response.status_code),
                                          ("committed_grants", repr(actual))])
    expected = [] if ownership == "valid" else [(str(g.sites[0].id), "read")]
    assert (response.status_code, actual) == (204 if ownership == "valid" else 404, expected)


@pytest.mark.parametrize("credential", ["jwt", "api-key"])
@pytest.mark.parametrize("route,wait_parent", [("single", "site"), ("bulk", "site"),
                                              ("delete", "site"), ("delete", "grant")])
@pytest.mark.parametrize("change", ["unchanged", "actor-revoked", "credential-revoked"])
async def test_grant_write_rechecks_authority_after_final_wait(vault_db, tmp_path, monkeypatch, credential,
                                                              route, wait_parent, change, request):
    g = await grant_fixture(vault_db, tmp_path, monkeypatch, credential)
    grant = None
    if route == "delete":
        grant = UserSiteAccess(id=uuid4(), user_id=g.f.user.id, site_id=g.sites[0].id, access_level="read")
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
    model, row_id = (Site, g.sites[0].id) if wait_parent == "site" else (UserSiteAccess, grant.id)
    await g.f.db.execute(select(model.id).where(model.id == row_id).with_for_update())
    holder_pid = await g.f.db.scalar(text("select pg_backend_pid()"))
    async with client_for(g) as client:
        base = f"/api/v1/organizations/{g.f.org.id}/site-access"
        if route == "single":
            task = asyncio.create_task(client.post(base, json={"user_id": str(g.f.user.id),
                                                              "site_id": str(g.sites[0].id), "access_level": "read"}))
        elif route == "bulk":
            task = asyncio.create_task(client.put(base + "/bulk", json={"user_id": str(g.f.user.id),
                                                                       "site_ids": [str(g.sites[0].id)], "access_level": "read"}))
        else:
            task = asyncio.create_task(client.delete(base + "/" + str(grant.id)))
        try:
            async with asyncio.timeout(10):
                while True:
                    if observed.get("pid") is not None and holder_pid in await g.f.db.scalar(
                        text("select pg_blocking_pids(:pid)"), {"pid": observed["pid"]},
                    ):
                        break
                    assert not task.done(), "No actual PostgreSQL wait at the selected final write boundary"
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
            permitted = change == "unchanged"
            present = (permitted and route != "delete") or (not permitted and route == "delete")
            expected = [(str(g.sites[0].id), "read")] if present else []
            expected_status = {"single": 201, "bulk": 200, "delete": 204}[route] if permitted else 401
            request.node.user_properties.extend([("genuine_database_wait", True),
                                                  ("response_status", response.status_code),
                                                  ("committed_grants", repr(actual))])
            assert (response.status_code, actual) == (expected_status, expected)
        finally:
            await g.f.db.rollback()
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)

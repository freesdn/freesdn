# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Actual concurrent user mutations must preserve a usable administrator."""

import asyncio
from datetime import timedelta
from uuid import uuid4

import httpx
import pytest
from fastapi import HTTPException
from sqlalchemy import delete, func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token
from app.db.session import create_test_engine, get_session
from app.main import app
from app.models.api_keys import APIKey, generate_api_key
from app.models.core import Organization, User
from app.models.security_audit import AuditLogRecord
from app.setup.api import require_setup_incomplete
from app.setup.service import SetupService

SCENARIOS = [
    ("platform_mutual", "disable", False),
    ("platform_mutual", "delete", False),
    ("platform_null_org", "disable", False),
    ("platform_null_org", "delete", False),
    ("organization", "disable", False),
    ("organization", "delete", False),
    ("organization", "demote", False),
    ("organization", "disable", True),
    ("organization", "delete", True),
    ("organization", "demote", True),
    ("platform_independent", "disable", True),
    ("platform_independent", "delete", True),
]


async def reaches_holder(observer, pid, holder_pid):
    """Accept direct waits before and transitive waits after serialization."""
    todo, seen = [pid], set()
    while todo:
        current = todo.pop()
        if current in seen:
            continue
        seen.add(current)
        blockers = await observer.scalar(text("SELECT pg_blocking_pids(:pid)"), {"pid": current})
        if holder_pid in blockers:
            return True
        todo.extend(blockers)
    return False


@pytest.mark.parametrize("credential", ["jwt", "api_key"])
@pytest.mark.parametrize("scope,action,survivor", SCENARIOS)
async def test_simultaneous_admin_removal_keeps_a_usable_administrator(
    monkeypatch, credential, scope, action, survivor,
):
    engine = create_test_engine()
    org_ids = [uuid4(), uuid4()]
    target_ids = [uuid4(), uuid4()]
    external_actor_id, survivor_id = uuid4(), uuid4()
    mutual = scope in {"platform_mutual", "platform_null_org"}
    actor_ids = [target_ids[1], target_ids[0]] if mutual else [external_actor_id] * 2
    owned_ids = list(dict.fromkeys([*target_ids, *actor_ids, *([survivor_id] if scope == "organization" and survivor else [])]))
    credentials, keys = {}, []
    for actor in set(actor_ids):
        if credential == "jwt":
            credentials[actor] = {"Authorization": "Bearer " + create_access_token(
                str(actor), token_version=17, expires_delta=timedelta(minutes=2),
            )}
        else:
            raw, prefix, key_hash = generate_api_key()
            credentials[actor] = {"X-API-Key": raw}
            keys.append(APIKey(id=uuid4(), user_id=actor, name="Owned lifecycle key",
                               key_prefix=prefix, key_hash=key_hash, scopes=[], is_active=True))
    pids = []

    async def independent_session():
        # API-key last_used commits must not change the physical connection
        # whose actual wait graph this fixture observes.
        async with engine.connect() as connection:
            async with AsyncSession(bind=connection, expire_on_commit=False, autoflush=False) as session:
                pids.append(await session.scalar(text("SELECT pg_backend_pid()")))
                try:
                    yield session
                    await session.commit()
                except BaseException:
                    await session.rollback()
                    raise

    monkeypatch.setitem(app.dependency_overrides, get_session, independent_session)
    try:
        async with AsyncSession(engine) as seed:
            if mutual:
                # Never delete unrelated fixture rows to manufacture this state.
                assert await seed.scalar(select(func.count()).select_from(User).where(
                    User.role == "super_admin", User.deleted_at.is_(None),
                )) == 0
            seed.add_all([Organization(id=org_id, name="Owned lifecycle race", slug=uuid4().hex) for org_id in org_ids])
            await seed.flush()
            for user_id in owned_ids:
                name = "owned-admin-race-" + uuid4().hex
                role = "org_admin" if scope == "organization" and user_id != external_actor_id else "super_admin"
                # The independent platform survivor must also satisfy the
                # unchanged per-organization last-admin guard.
                org = org_ids[1] if user_id == external_actor_id and scope == "organization" else org_ids[0]
                if scope == "platform_null_org":
                    org = None
                seed.add(User(id=user_id, organization_id=org, username=name, email=name + "@example.com",
                              full_name="Owned lifecycle actor", role=role, hashed_password="!",
                              is_active=True, is_verified=True, token_version=17))
            await seed.flush()
            seed.add_all(keys)
            await seed.commit()
        peer = uuid4().int
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app, raise_app_exceptions=False,
                                          client=(f"198.19.{peer >> 8 & 255}.{peer & 255}", 45131)),
            base_url="http://test",
        ) as client:
            for actor in set(actor_ids):
                assert (await client.get("/api/v1/users/", headers=credentials[actor])).status_code == 200
            pids.clear()
            async with AsyncSession(engine, expire_on_commit=False) as holder:
                await holder.execute(select(User.id).where(User.id.in_(target_ids)).order_by(User.id).with_for_update())
                holder_pid = await holder.scalar(text("SELECT pg_backend_pid()"))

                async def mutate(index):
                    url = "/api/v1/users/" + str(target_ids[index])
                    headers = credentials[actor_ids[index]]
                    if action == "delete":
                        return await client.delete(url, headers=headers)
                    body = {"is_active": False} if action == "disable" else {"role": "viewer"}
                    return await client.patch(url, headers=headers, json=body)

                requests = [asyncio.create_task(mutate(index)) for index in range(2)]
                try:
                    async with asyncio.timeout(10):
                        while len(pids) < 2:
                            assert not any(request.done() for request in requests)
                            await asyncio.sleep(0.01)
                        assert len(pids) == len(set(pids)) == 2
                        async with AsyncSession(engine) as observer:
                            while True:
                                paths = [await reaches_holder(observer, pid, holder_pid) for pid in pids]
                                if all(paths):
                                    break
                                assert not any(request.done() for request in requests)
                                await asyncio.sleep(0.02)
                    assert not any(request.done() for request in requests)
                    await holder.commit()
                    responses = await asyncio.wait_for(asyncio.gather(*requests), timeout=15)
                    statuses = [response.status_code for response in responses]
                    success_status = 204 if action == "delete" else 200
                    expected_successes = 2 if survivor else 1
                    async with AsyncSession(engine) as check:
                        conditions = [User.deleted_at.is_(None), User.is_active.is_(True)]
                        if scope == "organization":
                            conditions += [User.organization_id == org_ids[0], User.role.in_(["org_admin", "super_admin"])]
                        else:
                            conditions += [User.id.in_(owned_ids), User.role == "super_admin"]
                        remaining = await check.scalar(select(func.count()).select_from(User).where(*conditions))
                        assert statuses.count(success_status) == expected_successes and remaining == 1, {
                            "statuses": statuses, "remaining_usable_admins": remaining,
                        }
                        if not survivor:
                            assert sum(status in {400, 401, 403, 409} for status in statuses) == 1
                        if mutual:
                            with pytest.raises(HTTPException) as denied:
                                await require_setup_incomplete(SetupService(check))
                            assert denied.value.status_code == 403
                finally:
                    await holder.rollback()
                    for request in requests:
                        if not request.done():
                            request.cancel()
                    await asyncio.gather(*requests, return_exceptions=True)
    finally:
        async with AsyncSession(engine) as cleanup:
            await cleanup.execute(delete(AuditLogRecord).where(AuditLogRecord.actor_id.in_([str(i) for i in owned_ids])))
            await cleanup.execute(delete(APIKey).where(APIKey.user_id.in_(owned_ids)))
            await cleanup.execute(delete(User).where(User.id.in_(owned_ids)))
            await cleanup.execute(delete(Organization).where(Organization.id.in_(org_ids)))
            await cleanup.commit()
        await engine.dispose()
        # Override callables may remain classified after fixture cleanup.
        # All owned requests and database cleanup have finished.
        engine = None

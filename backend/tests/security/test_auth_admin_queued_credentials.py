# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Queued administrator writes must not outlive their initiating authority."""

import asyncio
import hashlib
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import httpx
import pytest
from sqlalchemy import delete, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, decode_token, get_password_hash
from app.core.token_blacklist import blacklist_token
from app.core.user_lifecycle import lock_user_lifecycle
from app.db.session import create_test_engine, get_session
from app.main import app
from app.models.api_keys import APIKey, generate_api_key
from app.models.core import Organization, TokenRevocation, User, UserSession
from app.models.security_audit import AuditLogRecord
from app.services.backup import BackupService
from app.services.backup_contributors import (
    BackupArchive,
    BackupContributorRegistry,
    BackupManifest,
    ContributorEntry,
    CoreBackupContributor,
)

COMMON = ["restore", "restore_rollback", "unchanged", "inactive", "soft_deleted",
          "hard_deleted", "role_changed", "organization_changed", "counter_changed",
          "password_changed"]
CASES = [(credential, change) for credential in ("jwt", "api_key") for change in COMMON]
CASES += [("api_key", change) for change in (
    "key_revoked", "key_expired", "key_deleted", "key_read_only", "key_tenant_narrowed",
)]
CASES += [("jwt", change) for change in ("session_revoked", "token_blacklisted", "token_expired")]


async def restore_actor(session, org_id, actor_id, *, expect_busy=False):
    from app.services.backup_contributors.account_security import collect_snapshot

    data = await collect_snapshot(session, org_id)
    assert [row["id"] for row in data["users"]] == [str(actor_id)]
    data["users"][0].update(full_name="Recovered administrator", token_version=17)
    archive = BackupArchive(
        manifest=BackupManifest(backup_id=str(uuid4()), created_at=datetime.now(UTC),
                                organization_id=str(org_id), contributors=[
                                    ContributorEntry(id="core", schema_version="2.0.0", counts={"users": 1}),
                                ]),
        contributors={"core": data},
    )
    report = await BackupService(session)._dispatch_restore_via_contributors(
        archive, organization_id=org_id, dry_run=False,
        restore_options={"include_secrets": True, "restore_users": True,
                         "overwrite_existing": True, "restore_devices": False},
    )
    if expect_busy:
        assert report["summary"]["contributors_failed"] == 1
        assert report["summary"]["total_errors"] > 0
        assert "Account lifecycle changes are in progress" in str(report["contributors"][0]["errors"])
        assert session.is_active and session.in_transaction()
    else:
        assert report["summary"]["contributors_failed"] == report["summary"]["total_errors"] == 0


@pytest.mark.parametrize("wait_point", ["lifecycle", "target"])
@pytest.mark.parametrize("action", ["update", "delete"])
@pytest.mark.parametrize("credential,change", CASES)
async def test_queued_administrator_revalidates_authority(monkeypatch, request, action, credential, change, wait_point):
    import app.services.backup_contributors as contributors

    registry = BackupContributorRegistry()
    registry.register(CoreBackupContributor())
    monkeypatch.setattr(contributors, "get_registry", lambda: registry)
    engine = create_test_engine()
    org_ids, actor_id, target_id = [uuid4(), uuid4()], uuid4(), uuid4()
    raw_key, prefix, key_hash = generate_api_key()
    key_id, session_id = uuid4(), uuid4()
    token = create_access_token(str(actor_id), token_version=17,
                                expires_delta=timedelta(seconds=5 if change == "token_expired" else 120))
    claims = await decode_token(token)
    assert claims is not None
    jti_hash = hashlib.sha256(claims["jti"].encode()).hexdigest()
    pids = []

    async def independent_session():
        # Pin the real request connection across API-key last_used commits.
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
            seed.add_all([Organization(id=org_id, name="Owned queued authority", slug=uuid4().hex) for org_id in org_ids])
            await seed.flush()
            for user_id, org_id, role, label in [(actor_id, org_ids[0], "super_admin", "Actor"),
                                                  (target_id, org_ids[1], "viewer", "Original target")]:
                name = "owned-admin-queue-" + uuid4().hex
                seed.add(User(id=user_id, organization_id=org_id, username=name, email=name + "@example.com",
                              full_name=label, hashed_password=get_password_hash("Owned queued account password"), role=role,
                              is_active=True, is_verified=True, token_version=17))
            await seed.flush()
            seed.add_all([
                APIKey(id=key_id, user_id=actor_id, name="Owned queued key", key_prefix=prefix,
                       key_hash=key_hash, scopes=[], is_active=True),
                UserSession(id=session_id, user_id=actor_id, access_jti=claims["jti"],
                            created_at=datetime.now(UTC), expires_at=datetime.now(UTC) + timedelta(minutes=2)),
            ])
            await seed.commit()
        peer = uuid4().int
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app, raise_app_exceptions=False,
                                          client=(f"198.19.{peer >> 8 & 255}.{peer & 255}", 45135)),
            base_url="http://test",
        ) as client:
            headers = {"Authorization": "Bearer " + token} if credential == "jwt" else {"X-API-Key": raw_key}
            assert (await client.get("/api/v1/users/" + str(target_id), headers=headers)).status_code == 200
            pids.clear()
            async with AsyncSession(engine, expire_on_commit=False) as holder:
                if wait_point == "lifecycle":
                    await lock_user_lifecycle(holder)
                else:
                    await holder.execute(select(User.id).where(User.id == target_id).with_for_update())
                holder_pid = await holder.scalar(text("SELECT pg_backend_pid()"))
                url = "/api/v1/users/" + str(target_id)
                pending = asyncio.create_task(
                    client.patch(url, headers=headers, json={"full_name": "Queued mutation"})
                    if action == "update" else client.delete(url, headers=headers)
                )
                try:
                    async with asyncio.timeout(10):
                        while not pids:
                            assert not pending.done(), "Request ended before the expected database wait"
                            await asyncio.sleep(0.01)
                        assert len(pids) == 1
                        async with AsyncSession(engine) as observer:
                            while holder_pid not in await observer.scalar(
                                text("SELECT pg_blocking_pids(:pid)"), {"pid": pids[0]},
                            ):
                                assert not pending.done()
                                await asyncio.sleep(0.02)
                    assert not pending.done()
                    if change in {"restore", "restore_rollback"}:
                        # At the target wait the request already owns lifecycle.
                        # Recovery must refuse the inverse lock order, leaving
                        # the caller and initiating credentials untouched.
                        expect_busy = wait_point == "target"
                        await asyncio.wait_for(restore_actor(holder, org_ids[0], actor_id, expect_busy=expect_busy), timeout=2)
                        if expect_busy:
                            assert not pending.done()
                            assert holder_pid in await holder.scalar(
                                text("SELECT pg_blocking_pids(:pid)"), {"pid": pids[0]},
                            )
                            actor = (await holder.execute(select(User.token_version, User.full_name)
                                     .where(User.id == actor_id))).one()
                            assert tuple(actor) == (17, "Actor")
                            assert await holder.scalar(select(APIKey.is_active).where(APIKey.id == key_id))
                            assert not await holder.scalar(select(UserSession.is_revoked).where(UserSession.id == session_id))
                            request.node.user_properties.append(("restore_refused_inverse_lifecycle_wait", True))
                    elif change == "inactive":
                        await holder.execute(update(User).where(User.id == actor_id).values(is_active=False))
                    elif change == "soft_deleted":
                        await holder.execute(update(User).where(User.id == actor_id).values(deleted_at=datetime.now(UTC)))
                    elif change == "hard_deleted":
                        await holder.execute(delete(User).where(User.id == actor_id))
                    elif change == "role_changed":
                        await holder.execute(update(User).where(User.id == actor_id).values(role="viewer"))
                    elif change == "organization_changed":
                        await holder.execute(update(User).where(User.id == actor_id).values(organization_id=org_ids[1]))
                    elif change == "counter_changed":
                        await holder.execute(update(User).where(User.id == actor_id).values(token_version=1001))
                    elif change == "password_changed":
                        await holder.execute(update(User).where(User.id == actor_id).values(hashed_password="!changed"))
                    elif change == "key_revoked":
                        await holder.execute(update(APIKey).where(APIKey.id == key_id).values(is_active=False))
                    elif change == "key_deleted":
                        await holder.execute(delete(APIKey).where(APIKey.id == key_id))
                    elif change == "key_expired":
                        await holder.execute(update(APIKey).where(APIKey.id == key_id).values(expires_at=datetime.now(UTC) - timedelta(seconds=1)))
                    elif change in {"key_read_only", "key_tenant_narrowed"}:
                        scopes = ["network:read"] if change == "key_read_only" else ["user:" + action]
                        await holder.execute(update(APIKey).where(APIKey.id == key_id).values(scopes=scopes))
                    elif change == "session_revoked":
                        await holder.execute(update(UserSession).where(UserSession.id == session_id).values(is_revoked=True, revoked_at=datetime.now(UTC)))
                    elif change == "token_blacklisted":
                        await blacklist_token(claims["jti"], claims["exp"])
                    elif change == "token_expired":
                        await asyncio.sleep(max(0, claims["exp"] - datetime.now(UTC).timestamp()) + 0.05)
                    else:
                        assert change == "unchanged"
                    if change == "restore_rollback":
                        await holder.rollback()
                    else:
                        await holder.commit()
                    response = await asyncio.wait_for(pending, timeout=10)
                    permitted = change in {"unchanged", "restore_rollback"} or (
                        wait_point == "target" and change == "restore"
                    )
                    assert response.status_code == ((200 if action == "update" else 204) if permitted else 401), {
                        "status": response.status_code, "credential": credential, "change": change,
                    }
                    async with AsyncSession(engine) as check:
                        target = await check.get(User, target_id)
                        assert target is not None and target.organization_id == org_ids[1]
                        assert target.full_name == ("Queued mutation" if permitted and action == "update" else "Original target")
                        assert (target.deleted_at is not None) == (permitted and action == "delete")
                        assert target.token_version == (18 if permitted and action == "delete" else 17)
                        if permitted:
                            assert (await check.get(User, actor_id)).token_version == 17
                    if wait_point == "target" and change in {"restore", "restore_rollback"}:
                        # Once the owner completes, retry the unchanged recovery
                        # contract. No locks, authentication or writes are mocked.
                        async with AsyncSession(engine, expire_on_commit=False) as retry:
                            await restore_actor(retry, org_ids[0], actor_id)
                            await retry.commit()
                        async with AsyncSession(engine) as check:
                            assert (await check.get(User, actor_id)).token_version == 18
                            assert not (await check.get(APIKey, key_id)).is_active
                            assert (await check.get(UserSession, session_id)).is_revoked
                        assert (await client.get("/api/v1/users/" + str(target_id), headers=headers)).status_code == 401
                        request.node.user_properties.append(("restore_retry_after_lifecycle_release_revoked_credentials", True))
                finally:
                    await holder.rollback()
                    if not pending.done():
                        pending.cancel()
                    await asyncio.gather(pending, return_exceptions=True)
    finally:
        async with AsyncSession(engine) as cleanup:
            await cleanup.execute(delete(AuditLogRecord).where(AuditLogRecord.actor_id == str(actor_id)))
            await cleanup.execute(delete(APIKey).where(APIKey.user_id == actor_id))
            await cleanup.execute(delete(UserSession).where(UserSession.user_id == actor_id))
            await cleanup.execute(delete(User).where(User.id.in_([actor_id, target_id])))
            await cleanup.execute(delete(Organization).where(Organization.id.in_(org_ids)))
            await cleanup.execute(delete(TokenRevocation).where(TokenRevocation.jti_hash == jti_hash))
            await cleanup.commit()
        await engine.dispose()
        # Override callables may remain classified after fixture cleanup.
        # All owned requests and database cleanup have finished.
        engine = None

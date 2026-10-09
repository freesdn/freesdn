# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Credential issuance must revalidate after a real PostgreSQL user-lock wait.

Independent committed sessions, real JWT/API-key authentication and dispatcher.
No authorization, transaction, lock-wait or revocation helper is replaced.
"""

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
from app.db.session import create_test_engine, get_session
from app.main import app
from app.models.api_keys import APIKey, generate_api_key
from app.models.core import Organization, TokenRevocation, User, UserSession
from app.services.backup import BackupService
from app.services.backup_contributors import (
    BackupArchive,
    BackupContributorRegistry,
    BackupManifest,
    ContributorEntry,
    CoreBackupContributor,
)

COMMON_CHANGES = ["restore", "restore_rollback", "unchanged", "inactive", "soft_deleted",
                  "hard_deleted", "role_changed", "organization_changed"]
CASES = [(credential, change) for credential in ["jwt", "api_key"] for change in COMMON_CHANGES]
CASES += [("api_key", "key_revoked"), ("api_key", "key_expired"),
          ("jwt", "session_revoked"), ("jwt", "token_blacklisted"), ("jwt", "token_expired")]


async def wait_for_actual_lock(engine, request_pid, holder_pid):
    async with AsyncSession(engine) as observer:
        async with asyncio.timeout(10):
            while True:
                blockers = await observer.scalar(text("SELECT pg_blocking_pids(:pid)"), {"pid": request_pid})
                if holder_pid in blockers:
                    return
                await asyncio.sleep(0.02)


async def restore_account(session, org_id, user_id):
    # Use the actual complete source snapshot. Missing MFA/provider fields in
    # a legacy partial archive must not bypass the new recovery policy merely
    # to reach this independently asserted post-lock credential check.
    from app.services.backup_contributors.account_security import collect_snapshot

    data = await collect_snapshot(session, org_id)
    assert [row["id"] for row in data["users"]] == [str(user_id)]
    data["users"][0].update(full_name="Recovered account", token_version=17)
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
    assert report["summary"]["contributors_failed"] == report["summary"]["total_errors"] == 0


@pytest.mark.parametrize("credential,change", CASES)
async def test_queued_key_creation_revalidates_after_database_lock(monkeypatch, credential, change):
    import app.services.backup_contributors as contributors

    registry = BackupContributorRegistry()
    registry.register(CoreBackupContributor())
    monkeypatch.setattr(contributors, "get_registry", lambda: registry)
    engine = create_test_engine()
    org_ids, user_id = [uuid4(), uuid4()], uuid4()
    name = "owned-key-race-" + uuid4().hex
    parent_key, prefix, key_hash = generate_api_key()
    parent_id, session_id = uuid4(), uuid4()
    token = create_access_token(str(user_id), token_version=17,
                                expires_delta=timedelta(seconds=5 if change == "token_expired" else 120))
    claims = await decode_token(token)
    assert claims is not None
    jti_hash = hashlib.sha256(claims["jti"].encode()).hexdigest()
    pids = []

    async def independent_session():
        # Pin a physical connection so API-key auth's last_used commit cannot
        # change the PID whose genuine blocking relation we inspect.
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
            seed.add_all([Organization(id=org_id, name="Owned key race", slug=uuid4().hex) for org_id in org_ids])
            await seed.flush()
            seed.add(User(id=user_id, organization_id=org_ids[0], username=name,
                          email=name + "@example.com",
                          hashed_password=get_password_hash("Owned key-race account password"), full_name="Owned actor",
                          role="super_admin", is_active=True, is_verified=True, token_version=17))
            await seed.flush()
            seed.add_all([
                APIKey(id=parent_id, user_id=user_id, name="Owned parent", key_prefix=prefix,
                       key_hash=key_hash, scopes=[], is_active=True),
                UserSession(id=session_id, user_id=user_id, access_jti=claims["jti"],
                            created_at=datetime.now(UTC), expires_at=datetime.now(UTC) + timedelta(minutes=2)),
            ])
            await seed.commit()
        peer = uuid4().int
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app, raise_app_exceptions=False, client=(f"198.19.{peer >> 8 & 255}.{peer & 255}", 45124)),
            base_url="http://test",
        ) as client:
            headers = {"Authorization": "Bearer " + token} if credential == "jwt" else {"X-API-Key": parent_key}
            # Verify the real principal can access this API before the race.
            assert (await client.get("/api/v1/backups/stats", headers=headers)).status_code == 200
            pids.clear()
            async with AsyncSession(engine, expire_on_commit=False) as holder:
                await holder.execute(select(User.id).where(User.id == user_id).with_for_update())
                holder_pid = await holder.scalar(text("SELECT pg_backend_pid()"))
                request = asyncio.create_task(client.post("/api/v1/api-keys/", headers=headers,
                                                         json={"name": name, "scopes": []}))
                try:
                    async with asyncio.timeout(10):
                        while not pids:
                            assert not request.done(), "Request ended before the expected database wait"
                            await asyncio.sleep(0.01)
                    assert len(pids) == 1
                    await wait_for_actual_lock(engine, pids[0], holder_pid)
                    assert not request.done(), "Must still be waiting after authenticating"
                    if change in {"restore", "restore_rollback"}:
                        await restore_account(holder, org_ids[0], user_id)
                    elif change == "inactive":
                        await holder.execute(update(User).where(User.id == user_id).values(is_active=False))
                    elif change == "soft_deleted":
                        await holder.execute(update(User).where(User.id == user_id).values(deleted_at=datetime.now(UTC)))
                    elif change == "hard_deleted":
                        await holder.execute(delete(User).where(User.id == user_id))
                    elif change == "role_changed":
                        await holder.execute(update(User).where(User.id == user_id).values(role="viewer"))
                    elif change == "organization_changed":
                        await holder.execute(update(User).where(User.id == user_id).values(organization_id=org_ids[1]))
                    elif change == "key_revoked":
                        await holder.execute(update(APIKey).where(APIKey.id == parent_id).values(is_active=False))
                    elif change == "key_expired":
                        await holder.execute(update(APIKey).where(APIKey.id == parent_id).values(expires_at=datetime.now(UTC) - timedelta(seconds=1)))
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
                    response = await asyncio.wait_for(request, timeout=10)
                    permitted = change in {"unchanged", "restore_rollback"}
                    assert response.status_code == (201 if permitted else 401), {"status": response.status_code, "change": change}
                    async with AsyncSession(engine) as check:
                        children = list((await check.scalars(select(APIKey).where(APIKey.user_id == user_id, APIKey.id != parent_id))).all())
                        assert len(children) == int(permitted)
                        if permitted:
                            assert children[0].is_active and children[0].name == name
                            assert (await check.get(User, user_id)).token_version == 17
                    if permitted:
                        # A genuine created child remains usable after no-op or rollback.
                        assert (await client.get("/api/v1/backups/stats", headers={"X-API-Key": response.json()["key"]})).status_code == 200
                finally:
                    await holder.rollback()
                    if not request.done():
                        request.cancel()
                    await asyncio.gather(request, return_exceptions=True)
    finally:
        async with AsyncSession(engine) as cleanup:
            await cleanup.execute(delete(APIKey).where(APIKey.user_id == user_id))
            await cleanup.execute(delete(UserSession).where(UserSession.user_id == user_id))
            await cleanup.execute(delete(User).where(User.id == user_id))
            await cleanup.execute(delete(Organization).where(Organization.id.in_(org_ids)))
            await cleanup.execute(delete(TokenRevocation).where(TokenRevocation.jti_hash == jti_hash))
            await cleanup.commit()
        await engine.dispose()
        # Override callables may remain classified after fixture cleanup.
        # All owned requests and database cleanup have finished.
        engine = None

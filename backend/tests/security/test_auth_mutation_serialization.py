# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Real account-lock waits must not rewind recovery or authorize stale writes."""

import asyncio
import hashlib
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import httpx
import pytest
from sqlalchemy import delete, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, decode_token, get_password_hash, verify_password
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

CHANGES = [
    "restore", "restore_with_key", "restore_rollback", "unchanged",
    "password_changed", "token_version_changed", "inactive", "soft_deleted",
    "hard_deleted", "role_changed", "organization_changed", "session_revoked",
    "token_blacklisted", "token_expired",
]


async def wait_for_account_wait(engine, request_pid, holder_pid):
    async with AsyncSession(engine) as observer:
        async with asyncio.timeout(10):
            while True:
                blockers = await observer.scalar(text("SELECT pg_blocking_pids(:pid)"), {"pid": request_pid})
                if holder_pid in blockers:
                    return
                await asyncio.sleep(0.02)


async def recover_existing_account(session, org_id, user_id):
    from app.services.backup_contributors.account_security import collect_snapshot

    # Preserve the original future-counter and actual restore/rollback race;
    # build its supported archive from independently validated source state.
    data = await collect_snapshot(session, org_id)
    assert [row["id"] for row in data["users"]] == [str(user_id)]
    data["users"][0].update(full_name="Recovered account", token_version=1000)
    archive = BackupArchive(
        manifest=BackupManifest(backup_id=str(uuid4()), created_at=datetime.now(UTC),
                                organization_id=str(org_id), contributors=[
                                    ContributorEntry(id="core", schema_version="2.0.0", counts={"users": 1}),
                                ]),
        contributors={"core": data},
    )
    return await BackupService(session)._dispatch_restore_via_contributors(
        archive, organization_id=org_id, dry_run=False,
        restore_options={"include_secrets": True, "restore_users": True,
                         "overwrite_existing": True, "restore_devices": False},
    )


@pytest.mark.parametrize("endpoint", ["password", "logout-all"])
@pytest.mark.parametrize("change", CHANGES)
async def test_auth_mutation_wait_preserves_newer_account_state(monkeypatch, endpoint, change):
    import app.services.backup_contributors as contributors

    registry = BackupContributorRegistry()
    registry.register(CoreBackupContributor())
    monkeypatch.setattr(contributors, "get_registry", lambda: registry)
    engine = create_test_engine()
    org_ids, user_id, parent_id, session_id = [uuid4(), uuid4()], uuid4(), uuid4(), uuid4()
    original_password, proposed_password, rotated_password = ["Owned!Aa7-" + uuid4().hex for _ in range(3)]
    original_hash, rotated_hash = get_password_hash(original_password), get_password_hash(rotated_password)
    name = "owned-auth-mutation-" + uuid4().hex
    parent_key, prefix, key_hash = generate_api_key()
    token = create_access_token(str(user_id), token_version=17,
                                expires_delta=timedelta(seconds=5 if change == "token_expired" else 120))
    historical_token = create_access_token(str(user_id), token_version=18)
    claims = await decode_token(token)
    assert claims is not None
    jti_hash = hashlib.sha256(claims["jti"].encode()).hexdigest()
    pids = []

    async def independent_session():
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
            seed.add_all([Organization(id=oid, name="Owned auth mutation", slug=uuid4().hex) for oid in org_ids])
            await seed.flush()
            seed.add(User(id=user_id, organization_id=org_ids[0], username=name,
                          email=name + "@example.com", hashed_password=original_hash,
                          full_name="Owned actor", role="super_admin", is_active=True,
                          is_verified=True, token_version=17))
            await seed.flush()
            seed.add(UserSession(id=session_id, user_id=user_id, access_jti=claims["jti"],
                                 created_at=datetime.now(UTC), expires_at=datetime.now(UTC) + timedelta(minutes=2)))
            if change == "restore_with_key":
                seed.add(APIKey(id=parent_id, user_id=user_id, name="Owned key", key_prefix=prefix,
                                key_hash=key_hash, scopes=[], is_active=True))
            await seed.commit()
        peer = uuid4().int
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app, raise_app_exceptions=False,
                                          client=(f"198.19.{peer >> 8 & 255}.{peer & 255}", 45126)),
            base_url="http://test",
        ) as client:
            headers = {"Authorization": "Bearer " + token}
            assert (await client.get("/api/v1/auth/me", headers=headers)).status_code == 200
            assert (await client.get("/api/v1/auth/me", headers={"Authorization": "Bearer " + historical_token})).status_code == 401
            if change == "restore_with_key":
                assert (await client.get("/api/v1/backups/stats", headers={"X-API-Key": parent_key})).status_code == 200
            pids.clear()
            async with AsyncSession(engine, expire_on_commit=False) as holder:
                await holder.execute(select(User.id).where(User.id == user_id).with_for_update())
                holder_pid = await holder.scalar(text("SELECT pg_backend_pid()"))
                payload = {"current_password": original_password, "new_password": proposed_password} if endpoint == "password" else {}
                request = asyncio.create_task(client.post("/api/v1/auth/" + endpoint, headers=headers, json=payload))
                try:
                    async with asyncio.timeout(10):
                        while not pids:
                            assert not request.done(), "Request ended before the expected wait"
                            await asyncio.sleep(0.01)
                    assert len(pids) == 1
                    await wait_for_account_wait(engine, pids[0], holder_pid)
                    assert not request.done(), "A genuine blocking account transaction is required"
                    restore_report = None
                    if change in {"restore", "restore_with_key", "restore_rollback"}:
                        restore_report = await recover_existing_account(holder, org_ids[0], user_id)
                    elif change == "password_changed":
                        await holder.execute(update(User).where(User.id == user_id).values(hashed_password=rotated_hash))
                    elif change == "token_version_changed":
                        await holder.execute(update(User).where(User.id == user_id).values(token_version=1001))
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
                    if restore_report is not None:
                        assert restore_report["summary"]["contributors_failed"] == restore_report["summary"]["total_errors"] == 0, restore_report
                    permitted = change in {"unchanged", "restore_rollback"}
                    async with AsyncSession(engine) as check:
                        user = await check.get(User, user_id)
                        observed_counter = user.token_version if user else None
                        historical_status = (await client.get("/api/v1/auth/me", headers={"Authorization": "Bearer " + historical_token})).status_code
                        assert response.status_code == (200 if permitted else 401), {
                            "status": response.status_code, "change": change,
                            "counter": observed_counter, "historical_token_status": historical_status,
                        }
                        if change == "hard_deleted":
                            assert user is None
                        else:
                            expected_counter = 18 if permitted else (1001 if change in {"restore", "restore_with_key", "token_version_changed"} else 17)
                            assert user.token_version == expected_counter
                            expected_password = proposed_password if permitted and endpoint == "password" else (rotated_password if change == "password_changed" else original_password)
                            assert verify_password(expected_password, user.hashed_password)
                        if change in {"restore", "restore_with_key", "token_version_changed"}:
                            assert historical_status == 401
                        if change == "restore_with_key":
                            assert not (await check.get(APIKey, parent_id)).is_active
                    if permitted and endpoint == "password":
                        # Reauthentication uses the actual browser login path.
                        login = await client.post("/api/v1/auth/login", json={"login": name, "password": proposed_password})
                        assert login.status_code == 200
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


@pytest.mark.parametrize("endpoint", ["password", "logout-all"])
@pytest.mark.parametrize("counter", [-1, 2**31 - 1])
async def test_auth_mutation_refuses_invalid_or_exhausted_counter(monkeypatch, endpoint, counter):
    engine = create_test_engine()
    user_id, org_id = uuid4(), uuid4()
    original_password, new_password = ["Owned!Aa7-" + uuid4().hex for _ in range(2)]
    original_hash = get_password_hash(original_password)
    token = create_access_token(str(user_id), token_version=counter)

    async def independent_session():
        async with AsyncSession(engine, expire_on_commit=False, autoflush=False) as session:
            try:
                yield session
                await session.commit()
            except BaseException:
                await session.rollback()
                raise

    monkeypatch.setitem(app.dependency_overrides, get_session, independent_session)
    try:
        async with AsyncSession(engine) as seed:
            seed.add(Organization(id=org_id, name="Owned exhausted counter", slug=uuid4().hex))
            await seed.flush()
            name = "owned-counter-" + uuid4().hex
            seed.add(User(id=user_id, organization_id=org_id, username=name, email=name + "@example.com",
                          full_name="Owned actor", hashed_password=original_hash,
                          role="super_admin", is_active=True, is_verified=True, token_version=counter))
            await seed.commit()
        peer = uuid4().int
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app, raise_app_exceptions=False,
                                          client=(f"198.19.{peer >> 8 & 255}.{peer & 255}", 45127)),
            base_url="http://test",
        ) as client:
            headers = {"Authorization": "Bearer " + token}
            assert (await client.get("/api/v1/auth/me", headers=headers)).status_code == 200
            payload = {"current_password": original_password, "new_password": new_password} if endpoint == "password" else {}
            response = await client.post("/api/v1/auth/" + endpoint, headers=headers, json=payload)
            assert response.status_code == 409, {"status": response.status_code, "counter": counter}
            async with AsyncSession(engine) as check:
                user = await check.get(User, user_id)
                assert user.token_version == counter and user.hashed_password == original_hash
    finally:
        async with AsyncSession(engine) as cleanup:
            await cleanup.execute(delete(UserSession).where(UserSession.user_id == user_id))
            await cleanup.execute(delete(User).where(User.id == user_id))
            await cleanup.execute(delete(Organization).where(Organization.id == org_id))
            await cleanup.commit()
        await engine.dispose()
        # Override callables may remain classified after fixture cleanup.
        # All owned requests and database cleanup have finished.
        engine = None

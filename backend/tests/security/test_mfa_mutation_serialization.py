# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Actual MFA endpoints must authorize refreshed state after a database wait."""

import asyncio
import hashlib
import json
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

import httpx
import pyotp
import pytest
from sqlalchemy import delete, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import (
    create_access_token,
    decode_token,
    get_password_hash,
    verify_password,
    verify_totp_single_use,
)
from app.core.security_utils import decrypt_field, encrypt_field
from app.core.token_blacklist import blacklist_token
from app.db.session import create_test_engine, get_session
from app.main import app
from app.models.core import Organization, TokenRevocation, User, UserSession
from app.services.backup import BackupService
from app.services.backup_contributors import (
    BackupArchive,
    BackupContributorRegistry,
    BackupManifest,
    ContributorEntry,
    CoreBackupContributor,
)

MFA_FIELDS = ("mfa_enabled", "mfa_secret", "mfa_backup_codes", "mfa_pending_secret",
              "mfa_pending_backup_codes", "mfa_last_totp_step")
ENDPOINTS = ["setup", "enable", "disable"]
CHANGES = ["restore", "restore_rollback", "unchanged", "session_revoked", "token_blacklisted", "token_expired"]


@asynccontextmanager
async def owned_actor(monkeypatch, endpoint, *, counter=17, lifetime=120):
    import app.services.backup_contributors as contributors

    registry = BackupContributorRegistry()
    registry.register(CoreBackupContributor())
    monkeypatch.setattr(contributors, "get_registry", lambda: registry)
    engine = create_test_engine()
    org_id, user_id, session_id = uuid4(), uuid4(), uuid4()
    name, password = "owned-mfa-race-" + uuid4().hex, "Owned!Aa7-" + uuid4().hex
    password_hash = get_password_hash(password)
    live_seed, pending_seed = pyotp.random_base32(), pyotp.random_base32()
    codes = json.dumps([get_password_hash(uuid4().hex[:10])])
    initial = {
        "mfa_enabled": endpoint != "enable",
        "mfa_secret": encrypt_field(live_seed) if endpoint != "enable" else None,
        "mfa_backup_codes": codes if endpoint != "enable" else None,
        "mfa_pending_secret": encrypt_field(pending_seed) if endpoint == "enable" else None,
        "mfa_pending_backup_codes": codes if endpoint == "enable" else None,
        "mfa_last_totp_step": None,
    }
    code_at = datetime.now(UTC)
    totp = pyotp.TOTP(pending_seed)
    code, step = totp.at(code_at), totp.timecode(code_at)
    payload = {"code": code} if endpoint == "enable" else {"password": password}
    token = create_access_token(str(user_id), token_version=counter, expires_delta=timedelta(seconds=lifetime))
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
            seed.add(Organization(id=org_id, name="Owned MFA race", slug=uuid4().hex))
            await seed.flush()
            seed.add(User(id=user_id, organization_id=org_id, username=name, email=name + "@example.com",
                          full_name="Owned actor", role="super_admin", is_active=True, is_verified=True,
                          hashed_password=password_hash, token_version=counter, **initial))
            await seed.flush()
            seed.add(UserSession(id=session_id, user_id=user_id, access_jti=claims["jti"],
                                 created_at=datetime.now(UTC), expires_at=datetime.now(UTC) + timedelta(minutes=2)))
            await seed.commit()
        peer = uuid4().int
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app, raise_app_exceptions=False,
                                          client=(f"198.19.{peer >> 8 & 255}.{peer & 255}", 45129)),
            base_url="http://test",
        ) as client:
            headers = {"Authorization": "Bearer " + token}
            assert (await client.get("/api/v1/auth/me", headers=headers)).status_code == 200
            pids.clear()
            yield SimpleNamespace(engine=engine, org_id=org_id, user_id=user_id, session_id=session_id,
                                  client=client, headers=headers, claims=claims, pids=pids,
                                  initial=initial, payload=payload, code=code, step=step,
                                  live_seed=live_seed, pending_seed=pending_seed, name=name, password=password)
    finally:
        async with AsyncSession(engine) as cleanup:
            await cleanup.execute(delete(UserSession).where(UserSession.user_id == user_id))
            await cleanup.execute(delete(User).where(User.id == user_id))
            await cleanup.execute(delete(Organization).where(Organization.id == org_id))
            await cleanup.execute(delete(TokenRevocation).where(TokenRevocation.jti_hash == jti_hash))
            await cleanup.commit()
        await engine.dispose()
        # Override callables may remain classified after fixture cleanup.
        # All owned requests and database cleanup have finished.
        engine = None


async def wait_for_actual_lock(f, holder_pid, request):
    async with asyncio.timeout(10):
        while not f.pids:
            assert not request.done(), "Request ended before the required account wait"
            await asyncio.sleep(0.01)
        assert len(f.pids) == 1
        async with AsyncSession(f.engine) as observer:
            while holder_pid not in await observer.scalar(text("SELECT pg_blocking_pids(:pid)"), {"pid": f.pids[0]}):
                assert not request.done()
                await asyncio.sleep(0.02)
    assert not request.done()


def semantic_mfa(values):
    # Field ciphertext is randomized on a real restore. Compare its meaning
    # before capturing the exact restored bytes that a stale request must retain.
    return {
        key: (decrypt_field(value) if key in {"mfa_secret", "mfa_pending_secret"}
              else json.loads(value) if key in {"mfa_backup_codes", "mfa_pending_backup_codes"} and value is not None
              else value)
        for key, value in values.items()
    }


async def recover_account(holder, f):
    from app.services.backup_contributors.account_security import collect_snapshot

    data = await collect_snapshot(holder, f.org_id)
    assert [row["id"] for row in data["users"]] == [str(f.user_id)]
    data["users"][0].update(full_name="Recovered account", token_version=1000)
    archive = BackupArchive(
        manifest=BackupManifest(backup_id=str(uuid4()), created_at=datetime.now(UTC),
                                organization_id=str(f.org_id), contributors=[
                                    ContributorEntry(id="core", schema_version="2.0.0", counts={"users": 1}),
                                ]),
        contributors={"core": data},
    )
    report = await BackupService(holder)._dispatch_restore_via_contributors(
        archive, organization_id=f.org_id, dry_run=False,
        restore_options={"include_secrets": True, "restore_users": True,
                         "overwrite_existing": True, "restore_devices": False},
    )
    assert report["summary"]["contributors_failed"] == report["summary"]["total_errors"] == 0
    restored = dict((await holder.execute(
        select(*(getattr(User, field) for field in MFA_FIELDS)).where(User.id == f.user_id),
    )).mappings().one())
    assert semantic_mfa(restored) == semantic_mfa(f.initial)
    return restored


@pytest.mark.parametrize("endpoint", ENDPOINTS)
@pytest.mark.parametrize("change", CHANGES)
async def test_mfa_change_revalidates_after_real_account_wait(monkeypatch, endpoint, change):
    async with owned_actor(monkeypatch, endpoint, lifetime=5 if change == "token_expired" else 120) as f:
        async with AsyncSession(f.engine, expire_on_commit=False) as holder:
            await holder.execute(select(User.id).where(User.id == f.user_id).with_for_update())
            holder_pid = await holder.scalar(text("SELECT pg_backend_pid()"))
            request = asyncio.create_task(f.client.post("/api/v1/auth/mfa/" + endpoint, headers=f.headers, json=f.payload))
            try:
                await wait_for_actual_lock(f, holder_pid, request)
                expected_mfa = dict(f.initial)
                if change in {"restore", "restore_rollback"}:
                    restored_mfa = await recover_account(holder, f)
                    if change == "restore":
                        expected_mfa = restored_mfa
                elif change == "session_revoked":
                    await holder.execute(update(UserSession).where(UserSession.id == f.session_id).values(is_revoked=True, revoked_at=datetime.now(UTC)))
                elif change == "token_blacklisted":
                    await blacklist_token(f.claims["jti"], f.claims["exp"])
                elif change == "token_expired":
                    await asyncio.sleep(max(0, f.claims["exp"] - datetime.now(UTC).timestamp()) + 0.05)
                else:
                    assert change == "unchanged"
                if change == "restore_rollback":
                    await holder.rollback()
                else:
                    await holder.commit()
                response = await asyncio.wait_for(request, timeout=10)
                permitted = change in {"unchanged", "restore_rollback"}
                async with AsyncSession(f.engine) as check:
                    user = await check.get(User, f.user_id)
                    assert response.status_code == (200 if permitted else 401), {"status": response.status_code, "counter": user.token_version, "change": change}
                    if not permitted:
                        assert user.token_version == (1001 if change == "restore" else 17)
                        assert {field: getattr(user, field) for field in MFA_FIELDS} == expected_mfa
                    elif endpoint == "setup":
                        assert user.token_version == 17 and user.mfa_enabled
                        assert decrypt_field(user.mfa_secret) == f.live_seed
                        assert decrypt_field(user.mfa_pending_secret) == response.json()["secret"]
                        returned_codes, hashes = response.json()["backup_codes"], json.loads(user.mfa_pending_backup_codes)
                        assert len(returned_codes) == len(hashes) == 10
                        assert verify_password(returned_codes[0], hashes[0])
                    elif endpoint == "enable":
                        assert user.token_version == 18 and user.mfa_enabled
                        assert decrypt_field(user.mfa_secret) == f.pending_seed
                        assert user.mfa_pending_secret is user.mfa_pending_backup_codes is None
                        assert user.mfa_backup_codes == f.initial["mfa_pending_backup_codes"]
                        fresh_headers = {"Authorization": "Bearer " + create_access_token(str(f.user_id), token_version=18)}
                        replay = await f.client.post("/api/v1/auth/mfa/enable", headers=fresh_headers, json=f.payload)
                        assert replay.status_code == 400
                    else:
                        assert user.token_version == 18 and not user.mfa_enabled
                        assert user.mfa_secret is user.mfa_backup_codes is None
                        login = await f.client.post("/api/v1/auth/login", json={"login": f.name, "password": f.password})
                        assert login.status_code == 200
            finally:
                await holder.rollback()
                if not request.done():
                    request.cancel()
                await asyncio.gather(request, return_exceptions=True)


@pytest.mark.parametrize("endpoint", ENDPOINTS)
@pytest.mark.parametrize("counter", [-1, 2**31 - 1])
async def test_mfa_change_refuses_invalid_or_exhausted_counter(monkeypatch, endpoint, counter):
    async with owned_actor(monkeypatch, endpoint, counter=counter) as f:
        response = await f.client.post("/api/v1/auth/mfa/" + endpoint, headers=f.headers, json=f.payload)
        assert response.status_code == 409, {"status": response.status_code, "counter": counter}
        async with AsyncSession(f.engine) as check:
            user = await check.get(User, f.user_id)
            assert user.token_version == counter
            assert {field: getattr(user, field) for field in MFA_FIELDS} == f.initial


@pytest.mark.parametrize("change", ["pending_seed_rotated", "totp_consumed"])
async def test_mfa_confirmation_observes_latest_seed_and_consumed_step(monkeypatch, change):
    async with owned_actor(monkeypatch, "enable") as f:
        async with AsyncSession(f.engine, expire_on_commit=False) as holder:
            await holder.execute(select(User.id).where(User.id == f.user_id).with_for_update())
            holder_pid = await holder.scalar(text("SELECT pg_backend_pid()"))
            request = asyncio.create_task(f.client.post("/api/v1/auth/mfa/enable", headers=f.headers, json=f.payload))
            try:
                await wait_for_actual_lock(f, holder_pid, request)
                expected = dict(f.initial)
                if change == "pending_seed_rotated":
                    new_seed = pyotp.random_base32()
                    while verify_totp_single_use(new_seed, f.code, None)[0]:
                        new_seed = pyotp.random_base32()
                    expected["mfa_pending_secret"] = encrypt_field(new_seed)
                    await holder.execute(update(User).where(User.id == f.user_id).values(mfa_pending_secret=expected["mfa_pending_secret"]))
                else:
                    expected["mfa_last_totp_step"] = f.step
                    await holder.execute(update(User).where(User.id == f.user_id).values(mfa_last_totp_step=f.step))
                await holder.commit()
                response = await asyncio.wait_for(request, timeout=10)
                assert response.status_code == 400, {"status": response.status_code, "change": change}
                async with AsyncSession(f.engine) as check:
                    user = await check.get(User, f.user_id)
                    assert user.token_version == 17
                    assert {field: getattr(user, field) for field in MFA_FIELDS} == expected
            finally:
                await holder.rollback()
                if not request.done():
                    request.cancel()
                await asyncio.gather(request, return_exceptions=True)


@pytest.mark.parametrize("endpoint", ENDPOINTS)
async def test_mfa_mutation_keeps_real_step_up_and_code_refusals(monkeypatch, endpoint):
    async with owned_actor(monkeypatch, endpoint) as f:
        if endpoint == "enable":
            wrong_code = f"{(int(f.code) + 1) % 1000000:06d}"
            while verify_totp_single_use(f.pending_seed, wrong_code, None)[0]:
                wrong_code = f"{(int(wrong_code) + 1) % 1000000:06d}"
            payload = {"code": wrong_code}
        else:
            payload = {"password": "Wrong!Aa7-" + uuid4().hex}
        response = await f.client.post("/api/v1/auth/mfa/" + endpoint, headers=f.headers, json=payload)
        assert response.status_code == (403 if endpoint == "setup" else 400)
        async with AsyncSession(f.engine) as check:
            user = await check.get(User, f.user_id)
            assert user.token_version == 17
            assert {field: getattr(user, field) for field in MFA_FIELDS} == f.initial

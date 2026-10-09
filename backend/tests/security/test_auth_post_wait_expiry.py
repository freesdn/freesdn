# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Private, unrun probes of real password-reset and MFA database waits.

No signature, clock, factor verifier, claim or authorization result is replaced.
Connection factories use the owned PostgreSQL database and expose physical PIDs.
Expiry uses real elapsed time; observations precede the contract assertions.
These are not email delivery, external IdP or packaged acceptance tests.
"""

import asyncio
import hashlib
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

import httpx
import jwt
import pyotp
import pytest
from sqlalchemy import delete, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.security import create_access_token, get_password_hash, verify_password
from app.core.security_utils import encrypt_field
from app.db.session import create_test_engine, get_session
from app.main import app
from app.models.api_keys import APIKey, generate_api_key
from app.models.core import Organization, TokenRevocation, User, UserSession


@asynccontextmanager
async def owned_account(monkeypatch, *, counter=17, mfa=False):
    import app.core.token_blacklist as revocations

    engine = create_test_engine()
    org_id, user_id, key_id = uuid4(), uuid4(), uuid4()
    name = "owned-post-wait-" + uuid4().hex
    original_password, proposed_password = ["Owned!Aa7-" + uuid4().hex for _ in range(2)]
    original_hash = get_password_hash(original_password)
    seed = pyotp.random_base32()
    _, prefix, key_hash = generate_api_key()
    request_pids, claim_pids, owned_jti_hashes = [], [], []

    async def request_session():
        async with engine.connect() as connection:
            async with AsyncSession(bind=connection, expire_on_commit=False, autoflush=False) as session:
                request_pids.append(await session.scalar(text("SELECT pg_backend_pid()")))
                try:
                    yield session
                    await session.commit()
                except BaseException:
                    await session.rollback()
                    raise

    @asynccontextmanager
    async def security_session():
        # Capture a PID before yielding, but leave a fresh transaction for
        # claim_token_jti's actual session.begin(). No caller commit occurs.
        async with engine.connect() as connection:
            pid = await connection.scalar(text("SELECT pg_backend_pid()"))
            await connection.rollback()
            async with AsyncSession(bind=connection, expire_on_commit=False) as session:
                claim_pids.append(pid)
                yield session

    monkeypatch.setitem(app.dependency_overrides, get_session, request_session)
    monkeypatch.setattr(revocations, "security_session_factory", security_session)
    try:
        async with AsyncSession(engine) as session:
            session.add(Organization(id=org_id, name="Owned post-wait", slug=uuid4().hex))
            await session.flush()
            session.add(User(id=user_id, organization_id=org_id, username=name,
                             email=name + "@example.com", full_name="Owned account",
                             hashed_password=original_hash, role="viewer", is_active=True,
                             is_verified=True, token_version=counter, mfa_enabled=mfa,
                             mfa_secret=encrypt_field(seed) if mfa else None,
                             mfa_last_totp_step=123456 if mfa else None))
            await session.flush()
            session.add(APIKey(id=key_id, user_id=user_id, name="Owned preserved key",
                               key_prefix=prefix, key_hash=key_hash, scopes=[], is_active=True))
            await session.commit()
        peer = uuid4().int
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app, raise_app_exceptions=False,
                                          client=(f"198.19.{peer >> 8 & 255}.{peer & 255}", 45231)),
            base_url="http://test",
        ) as client:
            yield SimpleNamespace(engine=engine, user_id=user_id, org_id=org_id,
                                  key_id=key_id, name=name, counter=counter, seed=seed,
                                  original_hash=original_hash, proposed_password=proposed_password,
                                  client=client, request_pids=request_pids, claim_pids=claim_pids,
                                  owned_jti_hashes=owned_jti_hashes)
    finally:
        async with AsyncSession(engine) as cleanup:
            await cleanup.execute(delete(APIKey).where(APIKey.user_id == user_id))
            await cleanup.execute(delete(UserSession).where(UserSession.user_id == user_id))
            await cleanup.execute(delete(User).where(User.id == user_id))
            await cleanup.execute(delete(Organization).where(Organization.id == org_id))
            if owned_jti_hashes:
                await cleanup.execute(delete(TokenRevocation).where(TokenRevocation.jti_hash.in_(owned_jti_hashes)))
            await cleanup.commit()
        await engine.dispose()
        # Override callables may remain classified after fixture cleanup.
        # All owned requests and database cleanup have finished.
        engine = None


def purpose_token(f, *, mfa=False, expires=False):
    audience = "freesdn-mfa" if mfa else "freesdn-api"
    token = create_access_token(str(f.user_id), token_version=f.counter,
                                expires_delta=timedelta(seconds=8 if expires else 120),
                                extra_claims={"type": "mfa_pending" if mfa else "password_reset",
                                              "aud": audience, "rmb": False})
    claims = jwt.decode(token, settings.jwt_signing_key, algorithms=[settings.ALGORITHM],
                        audience=audience, issuer="freesdn")
    f.owned_jti_hashes.append(hashlib.sha256(claims["jti"].encode()).hexdigest())
    return token, claims


async def genuine_wait(f, task, candidates, holder_pid):
    async with AsyncSession(f.engine) as observer:
        async with asyncio.timeout(10):
            while True:
                assert not task.done(), "Request finished before the required real PostgreSQL wait"
                for pid in set(candidates):
                    blockers = await observer.scalar(text("SELECT pg_blocking_pids(:pid)"), {"pid": pid})
                    if holder_pid in blockers:
                        return pid
                await asyncio.sleep(0.02)


async def snapshot(f):
    async with AsyncSession(f.engine) as observer:
        user = await observer.get(User, f.user_id)
        key = await observer.get(APIKey, f.key_id)
        claim = await observer.get(TokenRevocation, f.owned_jti_hashes[0])
        return {
            "user_exists": user is not None,
            "durable_purpose_claim": claim is not None,
            "password_unchanged": user is not None and user.hashed_password == f.original_hash,
            "proposed_password_installed": user is not None and verify_password(f.proposed_password, user.hashed_password),
            "counter": user.token_version if user else None,
            "key_active": key.is_active if key else None,
            "last_totp_step": user.mfa_last_totp_step if user else None,
        }


RESET_WAITS = [
    ("user", "unchanged"), ("user", "expired"), ("user", "counter_committed"),
    ("user", "counter_rollback"), ("user", "deleted"),
    ("claim", "unchanged"), ("claim", "expired"), ("claim", "committed_claim"),
]


@pytest.mark.parametrize("wait_kind,change", RESET_WAITS)
async def test_password_reset_rechecks_after_real_wait(monkeypatch, request, wait_kind, change):
    async with owned_account(monkeypatch) as f:
        token, claims = purpose_token(f, expires=change == "expired")
        async with AsyncSession(f.engine) as holder:
            if wait_kind == "user":
                await holder.execute(select(User.id).where(User.id == f.user_id).with_for_update())
            else:
                holder.add(TokenRevocation(jti_hash=f.owned_jti_hashes[0],
                                            expires_at=datetime.fromtimestamp(claims["exp"], UTC)))
                await holder.flush()
            holder_pid = await holder.scalar(text("SELECT pg_backend_pid()"))
            task = asyncio.create_task(f.client.post("/api/v1/auth/password/reset", json={
                "token": token, "new_password": f.proposed_password,
            }))
            try:
                pid = await genuine_wait(f, task, f.request_pids if wait_kind == "user" else f.claim_pids, holder_pid)
                if change == "expired":
                    await asyncio.sleep(max(0, claims["exp"] - datetime.now(UTC).timestamp()) + 0.1)
                elif change.startswith("counter_"):
                    await holder.execute(update(User).where(User.id == f.user_id).values(token_version=1001))
                elif change == "deleted":
                    await holder.execute(delete(User).where(User.id == f.user_id))
                expired_at_release = datetime.now(UTC).timestamp() >= claims["exp"]
                if change in {"counter_committed", "deleted", "committed_claim"}:
                    await holder.commit()
                else:
                    await holder.rollback()
                response = await asyncio.wait_for(task, timeout=15)
                observed = await snapshot(f)
                request.node.user_properties.extend([
                    ("genuine_postgres_wait", pid != holder_pid),
                    ("purpose_token_expired_at_release", expired_at_release),
                    ("HTTP_status", response.status_code), *observed.items(),
                ])
                allowed = change in {"unchanged", "counter_rollback"}
                assert response.status_code == 200 if allowed else response.status_code in {400, 401, 409}
                if change == "deleted":
                    assert observed["user_exists"] is False
                elif allowed:
                    assert observed["durable_purpose_claim"]
                    assert observed["proposed_password_installed"] and observed["counter"] == 18
                    assert observed["key_active"] is False
                    login = await f.client.post("/api/v1/auth/login", json={"login": f.name, "password": f.proposed_password})
                    assert login.status_code == 200
                    assert (await f.client.get("/api/v1/auth/me")).status_code == 200
                else:
                    assert observed["password_unchanged"] and observed["key_active"]
                    assert observed["counter"] == (1001 if change == "counter_committed" else 17)
            finally:
                await holder.rollback()
                if not task.done():
                    task.cancel()
                await asyncio.gather(task, return_exceptions=True)


@pytest.mark.parametrize("counter", [-1, 2**31 - 1, 2**31 - 2])
async def test_password_reset_counter_bounds_and_last_valid_value(monkeypatch, request, counter):
    async with owned_account(monkeypatch, counter=counter) as f:
        token, _ = purpose_token(f)
        response = await f.client.post("/api/v1/auth/password/reset", json={
            "token": token, "new_password": f.proposed_password,
        })
        observed = await snapshot(f)
        request.node.user_properties.extend([("HTTP_status", response.status_code), *observed.items()])
        allowed = counter == 2**31 - 2
        assert response.status_code == (200 if allowed else 409)
        assert observed["counter"] == (counter + 1 if allowed else counter)
        assert observed["password_unchanged"] is not allowed
        assert observed["key_active"] is not allowed
        if allowed:
            assert observed["proposed_password_installed"] and observed["durable_purpose_claim"]


@pytest.mark.parametrize("change", ["unchanged", "expired", "committed_claim"])
async def test_mfa_issuer_rechecks_after_real_claim_wait(monkeypatch, request, change):
    async with owned_account(monkeypatch, mfa=True) as f:
        token, claims = purpose_token(f, mfa=True, expires=change == "expired")
        async with AsyncSession(f.engine) as holder:
            holder.add(TokenRevocation(jti_hash=f.owned_jti_hashes[0],
                                        expires_at=datetime.fromtimestamp(claims["exp"], UTC)))
            await holder.flush()
            holder_pid = await holder.scalar(text("SELECT pg_backend_pid()"))
            task = asyncio.create_task(f.client.post("/api/v1/auth/login/mfa", json={
                "mfa_token": token, "code": pyotp.TOTP(f.seed).now(),
            }))
            try:
                pid = await genuine_wait(f, task, f.claim_pids, holder_pid)
                if change == "expired":
                    await asyncio.sleep(max(0, claims["exp"] - datetime.now(UTC).timestamp()) + 0.1)
                expired_at_release = datetime.now(UTC).timestamp() >= claims["exp"]
                if change == "committed_claim":
                    await holder.commit()
                else:
                    await holder.rollback()
                response = await asyncio.wait_for(task, timeout=15)
                observed = await snapshot(f)
                me = await f.client.get("/api/v1/auth/me")
                accepted = me.status_code == 200 and me.json().get("id") == str(f.user_id)
                request.node.user_properties.extend([
                    ("genuine_postgres_claim_wait", pid != holder_pid),
                    ("purpose_token_expired_at_release", expired_at_release),
                    ("HTTP_status", response.status_code), ("ordinary_access_accepted", accepted),
                    *observed.items(),
                ])
                allowed = change == "unchanged"
                assert response.status_code == (200 if allowed else 401)
                assert accepted is allowed
                if allowed:
                    assert observed["durable_purpose_claim"]
                assert observed["password_unchanged"] and observed["key_active"]
                assert observed["counter"] == 17
                assert (observed["last_totp_step"] > 123456) if allowed else observed["last_totp_step"] == 123456
            finally:
                await holder.rollback()
                if not task.done():
                    task.cancel()
                await asyncio.gather(task, return_exceptions=True)

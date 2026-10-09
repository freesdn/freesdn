"""AFTER-only current-auth and real PostgreSQL commit-fence contracts, unrun.

The protected HTTP route is an owned harness, not a lifecycle endpoint. Session
rows are explicit fixtures, not proof of successful browser/IdP session creation.
No authentication, factor result, revocation result or clock is replaced.
"""

import asyncio
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

import httpx
import pytest
import pytest_asyncio
from fastapi import Depends, FastAPI, Request
from sqlalchemy import delete, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import token_blacklist as tokens
from app.core.dependencies import CurrentUser, get_current_user
from app.core.token_authority_lock import lock_token_authority
from app.db.session import get_session
from app.main import app as product_app
from app.models.api_keys import APIKey
from app.models.core import User, UserSession
from app.services.agent_signing_authority import SigningLifecycleAuthority
from app.services.agent_signing_commit_fence import lock_current_signing_authority
from tests.security.test_agent_signing_authority import credentials
from tests.security.test_agent_signing_authority import (
    owned_signing as owned_signing,
)


@pytest_asyncio.fixture
async def commit_fence(owned_signing):
    f = owned_signing
    g = SimpleNamespace(f=f, factored=asyncio.Event(), proceed=asyncio.Event(),
                        locked=asyncio.Event(), finish=asyncio.Event(), pids=[],
                        pause_before=False, pause_after=False, mutate_inside=False)
    app = FastAPI(exception_handlers=product_app.exception_handlers)

    async def request_session():
        async with AsyncSession(f.engine, expire_on_commit=False, autoflush=False) as db:
            yield db

    app.dependency_overrides[get_session] = request_session

    @app.post("/owned/signing-fence")
    async def guarded(request: Request, user: CurrentUser = Depends(get_current_user)):
        authority = await SigningLifecycleAuthority.capture(
            request, user, command=f.command, secret_key=f.secret
        )
        factor = await authority.confirm_local(command=f.command, password=f.password)
        g.factor = factor
        g.factored.set()
        if g.pause_before:
            await g.proceed.wait()
        async with AsyncSession(f.engine, expire_on_commit=False, autoflush=False) as db, db.begin():
            g.pids.append(await db.scalar(text("SELECT pg_backend_pid()")))
            fence = await lock_current_signing_authority(db, factor=factor, command=f.command)
            g.locked.set()
            if g.pause_after:
                await g.finish.wait()
            if g.mutate_inside:
                await db.execute(update(User).where(User.id == f.user).values(is_active=False))
            await fence.recheck()
        g.completed = True
        return {"accepted": True}

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, raise_app_exceptions=False), base_url="http://test",
    ) as client:
        g.client = client
        try:
            yield g
        finally:
            g.proceed.set()
            g.finish.set()
    # Cached fixture callbacks must not retain completed request resources.
    f = g = None


async def tracked_credentials(g, kind, *, tracking="current", expires=120):
    headers, claims = credentials(g.f, kind, expires=expires)
    g.claims = claims
    if kind == "jwt" and tracking != "missing":
        async with AsyncSession(g.f.engine) as db, db.begin():
            for _ in range(2 if tracking == "duplicate" else 1):
                db.add(UserSession(id=uuid4(), user_id=g.f.user, refresh_jti=uuid4().hex,
                                   access_jti=claims["jti"], created_at=datetime.now(UTC),
                                   expires_at=datetime.now(UTC) + timedelta(minutes=10),
                                   is_revoked=False))
    return headers


async def waiting_on(g, task, candidates, holder):
    async with AsyncSession(g.f.engine) as observer, asyncio.timeout(5):
        while True:
            assert not task.done(), "Mutation finished before its required real row/advisory wait"
            for pid in candidates():
                if holder in await observer.scalar(text("SELECT pg_blocking_pids(:p)"), {"p": pid}):
                    return pid
            await asyncio.sleep(0.01)


@pytest.mark.parametrize("kind,mutation", [
    ("jwt", "user"), ("key", "user"), ("jwt", "session"),
    ("key", "key"), ("jwt", "blacklist"),
])
async def test_guard_holds_actual_credential_mutation_until_sql_decision_finishes(commit_fence, kind, mutation):
    g, pids = commit_fence, []
    headers = await tracked_credentials(g, kind)
    g.pause_after = True
    request = asyncio.create_task(g.client.post("/owned/signing-fence", headers=headers))
    await asyncio.wait_for(g.locked.wait(), 5)

    async def mutate():
        if mutation == "blacklist":
            await tokens.blacklist_token(g.claims["jti"], g.claims["exp"])
            return
        async with AsyncSession(g.f.engine) as db, db.begin():
            pids.append(await db.scalar(text("SELECT pg_backend_pid()")))
            if mutation == "user":
                await db.execute(update(User).where(User.id == g.f.user).values(is_active=False))
            elif mutation == "key":
                await db.execute(delete(APIKey).where(APIKey.id == g.f.key_id))
            else:
                await db.execute(update(UserSession).where(UserSession.access_jti == g.claims["jti"])
                                 .values(is_revoked=True, revoked_at=datetime.now(UTC)))

    task = asyncio.create_task(mutate())
    try:
        await waiting_on(g, task, lambda: list(g.f.pids) + pids, g.pids[-1])
        g.finish.set()
        first = await asyncio.wait_for(request, 5)
        await asyncio.wait_for(task, 5)
        assert first.status_code == 200 and first.json() == {"accepted": True}
        second = await g.client.post("/owned/signing-fence", headers=headers)
        assert second.status_code in (401, 403)
    finally:
        g.finish.set()
        await asyncio.gather(request, task, return_exceptions=True)


@pytest.mark.parametrize("kind,resource", [
    ("jwt", "user"), ("key", "user"), ("jwt", "session"),
    ("key", "key"), ("jwt", "revocation"),
])
async def test_guard_refuses_inverse_lock_order_without_waiting(commit_fence, kind, resource):
    g = commit_fence
    headers = await tracked_credentials(g, kind)
    g.pause_before = True
    request = asyncio.create_task(g.client.post("/owned/signing-fence", headers=headers))
    await asyncio.wait_for(g.factored.wait(), 5)
    async with AsyncSession(g.f.engine) as holder, holder.begin():
        if resource == "revocation":
            await lock_token_authority(holder, g.claims["jti"])
        elif resource == "user":
            await holder.execute(select(User).where(User.id == g.f.user).with_for_update())
        elif resource == "key":
            await holder.execute(select(APIKey).where(APIKey.id == g.f.key_id).with_for_update())
        else:
            await holder.execute(select(UserSession).where(UserSession.access_jti == g.claims["jti"])
                                 .with_for_update())
        g.proceed.set()
        result = await asyncio.wait_for(request, 2)
        assert result.status_code == 409
        assert not g.locked.is_set() and not getattr(g, "completed", False)
    # A released lock does not permanently disable the legitimate command.
    result = await g.client.post("/owned/signing-fence", headers=headers)
    assert result.status_code == 200


@pytest.mark.parametrize("kind", ["jwt", "key"])
@pytest.mark.parametrize("transition", ["unchanged", "disabled", "counter", "unverified"])
async def test_state_committed_after_factors_is_read_again_under_fence(commit_fence, kind, transition):
    g = commit_fence
    headers = await tracked_credentials(g, kind)
    g.pause_before = True
    task = asyncio.create_task(g.client.post("/owned/signing-fence", headers=headers))
    await asyncio.wait_for(g.factored.wait(), 5)
    changes = {"unchanged": {}, "disabled": {"is_active": False},
               "counter": {"token_version": 18}, "unverified": {"is_verified": False}}[transition]
    if changes:
        async with AsyncSession(g.f.engine) as db, db.begin():
            await db.execute(update(User).where(User.id == g.f.user).values(**changes))
    g.proceed.set()
    response = await asyncio.wait_for(task, 5)
    assert response.status_code == (200 if transition == "unchanged" else 401)
    assert g.locked.is_set() == (transition == "unchanged")


@pytest.mark.parametrize("tracking", ["current", "missing", "duplicate"])
async def test_jwt_requires_one_actual_current_session_for_signing_commit(commit_fence, tracking):
    g = commit_fence
    headers = await tracked_credentials(g, "jwt", tracking=tracking)
    response = await g.client.post("/owned/signing-fence", headers=headers)
    assert response.status_code == (200 if tracking == "current" else 401)
    assert g.locked.is_set() == (tracking == "current")


@pytest.mark.parametrize("kind", ["jwt", "key"])
async def test_final_guard_refusal_rolls_back_caller_write(commit_fence, kind):
    g = commit_fence
    headers = await tracked_credentials(g, kind)
    g.mutate_inside = True
    response = await g.client.post("/owned/signing-fence", headers=headers)
    assert response.status_code == 401 and g.locked.is_set()
    async with AsyncSession(g.f.engine) as observer:
        assert await observer.scalar(select(User.is_active).where(User.id == g.f.user)) is True


async def test_actual_credential_expiry_after_factor_refuses_before_fence(commit_fence):
    g = commit_fence
    headers = await tracked_credentials(g, "jwt", expires=3)
    g.pause_before = True
    task = asyncio.create_task(g.client.post("/owned/signing-fence", headers=headers))
    await asyncio.wait_for(g.factored.wait(), 5)
    await asyncio.sleep(max(0, g.claims["exp"] - datetime.now(UTC).timestamp()) + 0.05)
    g.proceed.set()
    response = await asyncio.wait_for(task, 5)
    assert response.status_code == 401 and not g.locked.is_set()

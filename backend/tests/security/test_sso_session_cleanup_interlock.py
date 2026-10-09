# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Owned PostgreSQL callback/logout/reaper interlock, not worker or IdP acceptance."""

import asyncio
import json
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

import httpx
import jwt
import pytest
from jwt.algorithms import RSAAlgorithm
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, decode_token
from app.db.session import get_session
from app.main import app
from app.models.api_keys import APIKey, generate_api_key
from app.models.core import UserSession
from app.models.sso import SSOSession
from app.services import sso as sso_module
from app.services.sso import SSOAuthError, SSOCallbackError, SSOService
from app.tasks import maintenance
from tests.security.test_sso_oidc_identity_validation import (
    owned_signing_keys as owned_signing_keys,
)
from tests.services.test_backup_vault_security_roundtrip import source_fixture
from tests.services.test_backup_vault_security_roundtrip import vault_db as vault_db


async def wait_for_owned_blocker(db, task, state, holder_pid):
    async with asyncio.timeout(8):
        while not task.done():
            if state.get("pid") is not None:
                actual = await db.scalar(text("select pg_blocking_pids(:pid)"), {"pid": state["pid"]})
                if holder_pid in actual:
                    state["verified_blocker_pid"] = holder_pid
                    return True
            await asyncio.sleep(0.01)
    return False


def sqlstate(exc):
    visited = set()
    while isinstance(exc, BaseException) and id(exc) not in visited:
        visited.add(id(exc))
        value = getattr(exc, "sqlstate", None) or getattr(exc, "pgcode", None)
        if value:
            return value
        exc = getattr(exc, "orig", None) or exc.__cause__ or exc.__context__
    return "none"


@pytest.mark.parametrize("contended", [False, True])
async def test_expired_session_reaper_preserves_logout_and_callback_progress(
    vault_db, tmp_path, monkeypatch, request, owned_signing_keys, contended,
):
    f = await source_fixture(vault_db, tmp_path, monkeypatch, protocol="oidc")
    f.user.mfa_enabled = False
    f.user.mfa_secret = None
    f.user.mfa_backup_codes = None
    issuer = "https://interlock.example.invalid/" + uuid4().hex
    f.provider.oidc_issuer = issuer
    now = datetime.now(UTC)
    expiry = now + (timedelta(seconds=5) if contended else timedelta(seconds=-1))
    state, nonce = uuid4().hex, uuid4().hex
    flow = SSOSession(id=uuid4(), provider_id=f.provider.id, state=state, nonce=nonce,
                      created_at=now, expires_at=expiry, redirect_uri="http://test/auth/sso/callback")
    live_flow = SSOSession(id=uuid4(), provider_id=f.provider.id, state=uuid4().hex, nonce=uuid4().hex,
                           created_at=now, expires_at=now + timedelta(minutes=10))
    token = create_access_token(str(f.user.id), token_version=17)
    token_claims = await decode_token(token)
    assert token_claims is not None
    current = UserSession(id=uuid4(), user_id=f.user.id, access_jti=token_claims["jti"],
                          created_at=now, expires_at=now + timedelta(minutes=10), is_revoked=False)
    expired = UserSession(id=uuid4(), user_id=f.user.id, access_jti=uuid4().hex,
                          created_at=now - timedelta(days=2), expires_at=now - timedelta(seconds=1),
                          is_revoked=False)
    _, prefix, key_hash = generate_api_key()
    key = APIKey(id=uuid4(), user_id=f.user.id, name="Owned interlock key",
                 key_prefix=prefix, key_hash=key_hash, scopes=[], is_active=True)
    f.db.add_all([flow, live_flow, current, expired, key])
    await f.db.commit()
    flow_id, live_flow_id, current_id, expired_id, key_id = flow.id, live_flow.id, current.id, expired.id, key.id
    account_email, account_username = f.user.email, f.user.username
    # This isolated module must not exercise maintenance over unknown rows.
    assert set((await f.db.scalars(select(UserSession.id))).all()) == {current_id, expired_id}
    assert set((await f.db.scalars(select(SSOSession.id))).all()) == {flow_id, live_flow_id}
    await f.db.rollback()
    signing_key, _ = owned_signing_keys
    claims = {"iss": issuer, "sub": "owned-external-subject", "aud": "owned-client",
              "iat": now, "exp": now + timedelta(minutes=5), "nonce": nonce,
              "mail": account_email, "preferred_username": account_username, "name": "Owned callback"}
    encoded = jwt.encode(claims, signing_key, algorithm="RS256", headers={"kid": "owned-key"})
    jwk = json.loads(RSAAlgorithm.to_jwk(signing_key.public_key()))
    jwk.update(kid="owned-key", use="sig", alg="RS256")

    async def owned_transport(method, url, **kwargs):
        assert kwargs.get("allow_hosts") == frozenset({"interlock.example.invalid", "identity.example.invalid"})
        if url == issuer + "/.well-known/openid-configuration":
            assert method == "GET"
            return httpx.Response(200, json={"issuer": issuer, "authorization_endpoint": issuer + "/authorize",
                                           "token_endpoint": issuer + "/token", "jwks_uri": issuer + "/jwks"})
        if url == issuer + "/token":
            assert method == "POST"
            return httpx.Response(200, json={"id_token": encoded, "token_type": "Bearer"})
        if url == issuer + "/jwks":
            assert method == "GET"
            return httpx.Response(200, json={"keys": [jwk]})
        raise AssertionError("Unexpected owned interlock upstream URL")

    monkeypatch.setattr(sso_module, "safe_http_request", owned_transport)
    callback_state, logout_state, cleanup_state = {}, {}, {}

    @asynccontextmanager
    async def pinned_cleanup_session():
        async with f.db.bind.connect() as connection:
            async with AsyncSession(bind=connection, expire_on_commit=False, autoflush=False) as session:
                cleanup_state["pid"] = await session.scalar(text("select pg_backend_pid()"))
                yield session

    # Bridge only the synchronous task entry point. The actual async body,
    # predicates, SQL order and transaction remain production code. This is
    # not a Celery worker qualification and does not replace global asyncio.
    monkeypatch.setattr(maintenance, "AsyncSessionLocal", pinned_cleanup_session)
    monkeypatch.setattr(maintenance, "asyncio", SimpleNamespace(run=lambda coroutine: coroutine))

    async def http_session():
        async with f.db.bind.connect() as connection:
            async with AsyncSession(bind=connection, expire_on_commit=False, autoflush=False) as session:
                logout_state["pid"] = await session.scalar(text("select pg_backend_pid()"))
                try:
                    yield session
                    await session.commit()
                except BaseException as exc:
                    logout_state["sqlstate"] = sqlstate(exc)
                    await session.rollback()
                    raise

    monkeypatch.setitem(app.dependency_overrides, get_session, http_session)

    async def callback():
        async with f.db.bind.connect() as connection:
            async with AsyncSession(bind=connection, expire_on_commit=False, autoflush=False) as session:
                callback_state["pid"] = await session.scalar(text("select pg_backend_pid()"))
                try:
                    result = await SSOService(session).oidc_callback(state, "owned-code")
                    await session.commit()
                    callback_state["access_issued"] = bool(result.access_token)
                except (SSOAuthError, SSOCallbackError):
                    callback_state["refused"] = True
                    await session.rollback()
                except BaseException as exc:
                    callback_state["sqlstate"] = sqlstate(exc)
                    await session.rollback()
                    raise

    peer = uuid4().int
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False,
                                   client=(f"198.19.{(peer >> 8) & 255}.{peer & 255}", 45133))
    tasks = []
    first_cleanup = None
    logout_status = None
    first_cleanup_pid = None
    waits = {"logout_on_key": False, "callback_on_logout": False,
             "cleanup_on_callback": False, "logout_on_cleanup": False}
    outcomes = []
    try:
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            assert (await client.get("/api/v1/auth/me", headers={"Authorization": "Bearer " + token})).status_code == 200
            if contended:
                logout_state.clear()
                await f.db.execute(select(APIKey.id).where(APIKey.id == key_id).with_for_update())
                holder_pid = await f.db.scalar(text("select pg_backend_pid()"))
                logout_task = asyncio.create_task(client.post("/api/v1/auth/logout-all", headers={"Authorization": "Bearer " + token}))
                tasks.append(logout_task)
                waits["logout_on_key"] = await wait_for_owned_blocker(f.db, logout_task, logout_state, holder_pid)
                assert waits["logout_on_key"], "Actual logout must lock User then wait on the owned key"
                callback_task = asyncio.create_task(callback())
                tasks.append(callback_task)
                waits["callback_on_logout"] = await wait_for_owned_blocker(f.db, callback_task, callback_state, logout_state["pid"])
                assert waits["callback_on_logout"], "Actual callback must own SSO state before waiting on User"
                await asyncio.sleep(max(0, (expiry - datetime.now(UTC)).total_seconds()) + 0.02)
                cleanup_task = asyncio.create_task(maintenance.cleanup_orphan_sessions.run())
                tasks.append(cleanup_task)
                waits["cleanup_on_callback"] = await wait_for_owned_blocker(f.db, cleanup_task, cleanup_state, callback_state["pid"])
                first_cleanup_pid = cleanup_state["pid"]
                # A skip-locked reaper may already have completed; preserve
                # both behaviors instead of requiring the proposed defect.
                await f.db.commit()
                waits["logout_on_cleanup"] = await wait_for_owned_blocker(f.db, logout_task, logout_state, cleanup_state["pid"])
                outcomes = await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), timeout=12)
                if isinstance(outcomes[0], httpx.Response):
                    logout_status = outcomes[0].status_code
                first_cleanup = outcomes[2]
            else:
                first_cleanup = await maintenance.cleanup_orphan_sessions.run()
        # An explicit later maintenance invocation verifies eventual cleanup
        # after held work ends. It never replaces the first observed outcome.
        retry_cleanup = await maintenance.cleanup_orphan_sessions.run()
        async with AsyncSession(f.db.bind) as observer:
            old_user_remaining = await observer.get(UserSession, expired_id) is not None
            live_user = await observer.get(UserSession, current_id)
            expired_flow_remaining = await observer.get(SSOSession, flow_id) is not None
            live_flow_remaining = await observer.get(SSOSession, live_flow_id) is not None
        codes = [sqlstate(o) for o in outcomes if isinstance(o, BaseException)]
        codes += [callback_state.get("sqlstate", "none"), logout_state.get("sqlstate", "none")]
        first_success = isinstance(first_cleanup, dict) and first_cleanup.get("success") is True
        request.node.user_properties.extend([
            ("actual_callback_and_logout_SQL", contended),
            ("actual_reaper_SQL_sync_bridge_only", True),
            ("genuine_logout_key_wait", waits["logout_on_key"]),
            ("genuine_callback_user_wait", waits["callback_on_logout"]),
            ("genuine_cleanup_SSO_wait", waits["cleanup_on_callback"]),
            ("genuine_logout_session_wait", waits["logout_on_cleanup"]),
            ("deadlock_SQLSTATE_observed", "40P01" in codes),
            ("other_SQLSTATEs", sorted({c for c in codes if c not in {"none", "40P01"}})),
            ("first_cleanup_success", first_success),
            ("logout_status", logout_status if contended else "not-run"),
            ("callback_controlled_refusal", callback_state.get("refused", False)),
            ("callback_access_issued", callback_state.get("access_issued", False)),
            ("explicit_later_cleanup_success", retry_cleanup["success"]),
            ("expired_rows_removed", not old_user_remaining and not expired_flow_remaining),
            ("live_rows_retained", live_user is not None and live_flow_remaining),
        ])
        assert "40P01" not in codes and all(c == "none" for c in codes)
        assert first_success and retry_cleanup["success"]
        assert not old_user_remaining and not expired_flow_remaining
        assert live_user is not None and live_flow_remaining
        if contended:
            assert logout_status == 200 and callback_state.get("refused") and not callback_state.get("access_issued")
            assert live_user.is_revoked and len({holder_pid, logout_state["pid"], callback_state["pid"], first_cleanup_pid}) == 4
    finally:
        await f.db.rollback()
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

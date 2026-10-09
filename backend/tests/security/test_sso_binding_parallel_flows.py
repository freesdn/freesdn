# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Real concurrent post-verification sign-ins, not upstream IdP acceptance."""

import asyncio
from uuid import uuid4

import httpx
import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.main import app
from app.models.core import User
from app.models.sso import SSOProtocol, SSOProvider, SSOProviderStatus
from app.services.sso import SSOAuthError, SSOService
from tests.services.test_backup_vault_security_roundtrip import source_fixture
from tests.services.test_backup_vault_security_roundtrip import vault_db as vault_db


async def provision(f, provider_id, email, username, subject, observed):
    async with f.db.bind.connect() as connection:
        async with AsyncSession(bind=connection, expire_on_commit=False, autoflush=False) as session:
            observed["pid"] = await session.scalar(text("select pg_backend_pid()"))
            provider = await session.get(SSOProvider, provider_id)
            svc = SSOService(session)
            try:
                user = await svc._provision_or_update_user(
                    provider, {"email": email, "username": username}, {"sub": subject},
                )
                observed["user_id"] = user.id
                if user.id not in f.db.info["owned_user_ids"]:
                    f.db.info["owned_user_ids"].append(user.id)
                result = await svc._issue_tokens(user, provider)
                await session.commit()
                return result
            except SSOAuthError:
                observed["refused"] = True
                await session.rollback()
            except IntegrityError:
                observed["database_error"] = True
                await session.rollback()
    return None


async def accepted_identity(result):
    if result is None or not result.access_token:
        return None
    peer = uuid4().int
    transport = httpx.ASGITransport(
        app=app, raise_app_exceptions=False,
        client=(f"198.19.{(peer >> 8) & 255}.{peer & 255}", 45129),
    )
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/v1/auth/me", headers={
            "Authorization": "Bearer " + result.access_token,
        })
    return response.json()["id"] if response.status_code == 200 else None


async def wait_on(db, task, observed, blockers, *, peers=()):
    for _ in range(500):
        if observed.get("pid") is not None:
            # Follow only physically observed request PIDs. Each edge is read
            # from PostgreSQL, never inferred from a pending coroutine.
            owned = {state.get("pid") for state in peers} - {None}
            pending = [(observed["pid"], [observed["pid"]])]
            visited = set()
            while pending:
                pid, path = pending.pop()
                if pid in visited:
                    continue
                visited.add(pid)
                actual = await db.scalar(text("select pg_blocking_pids(:pid)"), {"pid": pid})
                for holder in actual:
                    if holder in blockers:
                        observed["verified_wait_path"] = [*path, holder]
                        return True
                    if holder in owned and holder not in visited:
                        pending.append((holder, [*path, holder]))
        if task.done():
            return False
        await asyncio.sleep(0.01)
    raise AssertionError("Owned sign-in neither completed nor reached the expected real wait")


async def fixture_provider(f):
    provider = SSOProvider(
        id=uuid4(), organization_id=f.org.id, name="Owned parallel identity provider",
        slug=uuid4().hex, protocol=SSOProtocol.OIDC, status=SSOProviderStatus.ACTIVE,
        oidc_issuer="https://parallel.example.invalid", oidc_client_id="owned-client",
        jit_provisioning=True, default_role="viewer", extra_settings={},
    )
    f.db.add(provider)
    await f.db.flush()
    return provider


@pytest.mark.parametrize("same_account", [True, False])
async def test_parallel_established_signins_preserve_both_valid_requests(
    vault_db, tmp_path, monkeypatch, request, same_account,
):
    f = await source_fixture(vault_db, tmp_path, monkeypatch)
    provider = await fixture_provider(f)
    users = []
    for _ in range(1 if same_account else 2):
        name = uuid4().hex
        user = User(
            id=uuid4(), organization_id=f.org.id, username=name, email=name + "@example.com",
            role="viewer", hashed_password="!SSO_MANAGED", auth_provider="oidc",
            external_id=uuid4().hex, sso_provider_id=provider.id, token_version=17,
            is_active=True, is_verified=True, mfa_enabled=False,
        )
        f.db.add(user)
        f.db.info["owned_user_ids"].append(user.id)
        users.append(user)
    await f.db.commit()
    provider_id = provider.id
    ids = [u.id for u in users]
    inputs = [(u.email, u.username, u.external_id, u.id) for u in users]
    if same_account:
        inputs.append(inputs[0])
    await f.db.execute(select(User.id).where(User.id.in_(ids)).order_by(User.id).with_for_update())
    holder_pid = await f.db.scalar(text("select pg_backend_pid()"))
    observed = [{}, {}]
    tasks = [asyncio.create_task(provision(f, provider_id, *entry[:3], state))
             for entry, state in zip(inputs, observed, strict=True)]
    try:
        waits = [await wait_on(f.db, task, state, {holder_pid}, peers=observed)
                 for task, state in zip(tasks, observed, strict=True)]
        await f.db.commit()
        results = await asyncio.wait_for(asyncio.gather(*tasks), timeout=5)
        accepted = [await accepted_identity(result) for result in results]
        request.node.user_properties.extend([
            ("two_genuine_account_row_waits", waits == [True, True]),
            ("maximum_verified_owned_wait_path_edges", max(len(s.get("verified_wait_path", [])) - 1 for s in observed)),
            ("three_distinct_physical_connections", len({holder_pid, *[s["pid"] for s in observed]}) == 3),
            ("both_ordinary_requests_accepted_by_HTTP", accepted == [str(i[3]) for i in inputs]),
            ("no_refusal_or_SQL_error", not any(s.get("refused") or s.get("database_error") for s in observed)),
        ])
        assert waits == [True, True]
        assert accepted == [str(i[3]) for i in inputs]
        assert not any(s.get("refused") or s.get("database_error") for s in observed)
    finally:
        await f.db.rollback()
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


@pytest.mark.parametrize("same_email", [True, False])
async def test_concurrent_JIT_keeps_one_binding_and_allows_explicit_retry(
    vault_db, tmp_path, monkeypatch, request, same_email,
):
    f = await source_fixture(vault_db, tmp_path, monkeypatch)
    provider = await fixture_provider(f)
    await f.db.commit()
    provider_id = provider.id
    first_name, second_name = uuid4().hex, uuid4().hex
    first_email = first_name + "@example.com"
    second_email = first_email if same_email else second_name + "@example.com"
    await f.db.execute(select(SSOProvider.id).where(SSOProvider.id == provider_id).with_for_update())
    holder_pid = await f.db.scalar(text("select pg_backend_pid()"))
    observed = [{}, {}]
    first = asyncio.create_task(provision(f, provider_id, first_email, first_name, "same-owned-subject", observed[0]))
    second = None
    try:
        first_wait = await wait_on(f.db, first, observed[0], {holder_pid})
        assert first_wait, "First JIT must reach a real resource wait"
        second = asyncio.create_task(provision(f, provider_id, second_email, second_name, "same-owned-subject", observed[1]))
        second_wait = await wait_on(f.db, second, observed[1], {holder_pid, observed[0]["pid"]})
        await f.db.commit()
        results = await asyncio.wait_for(asyncio.gather(first, second), timeout=5)
        async with AsyncSession(f.db.bind) as observer:
            committed_ids = list((await observer.scalars(select(User.id).where(
                User.sso_provider_id == provider_id, User.external_id == "same-owned-subject",
                User.deleted_at.is_(None),
            ))).all())
        initial_accepted = [await accepted_identity(result) for result in results]
        retry_state = {}
        retry = await provision(f, provider_id, second_email, second_name, "same-owned-subject", retry_state)
        retry_accepted = await accepted_identity(retry)
        request.node.user_properties.extend([
            ("first_JIT_genuine_provider_wait", first_wait),
            ("second_JIT_direct_or_transitive_wait", second_wait),
            ("three_distinct_physical_connections", len({holder_pid, *[s["pid"] for s in observed]}) == 3),
            ("committed_external_binding_count", len(committed_ids)),
            ("second_initial_request_controlled_refusal", observed[1].get("refused", False)),
            ("second_initial_request_SQL_error", observed[1].get("database_error", False)),
            ("first_request_accepted_by_HTTP", initial_accepted[0] == str(observed[0]["user_id"])),
            ("second_initial_access_accepted_by_HTTP", initial_accepted[1] is not None),
            ("retry_accepted_first_identity", retry_accepted == str(observed[0]["user_id"])),
        ])
        assert committed_ids == [observed[0]["user_id"]]
        assert observed[1].get("refused") and not observed[1].get("database_error")
        assert initial_accepted == [str(observed[0]["user_id"]), None]
        assert retry_accepted == str(observed[0]["user_id"])
    finally:
        await f.db.rollback()
        for task in (first, second):
            if task is not None and not task.done():
                task.cancel()
        await asyncio.gather(*[t for t in (first, second) if t is not None], return_exceptions=True)

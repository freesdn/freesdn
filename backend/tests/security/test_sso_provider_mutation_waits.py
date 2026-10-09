# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Unqualified probes: real provider-row waits must not outlive ownership/auth.

Management HTTP requests only, with disposable rows and no identity-provider
network exchange. These inputs are not frozen or runtime-qualified yet.
"""

import asyncio
from datetime import UTC, datetime
from uuid import uuid4

import httpx
import pytest
from sqlalchemy import delete, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token
from app.db.session import get_session
from app.main import app
from app.models.api_keys import APIKey, generate_api_key
from app.models.core import Organization, User
from app.models.sso import SSOProtocol, SSOProvider, SSOProviderStatus
from tests.services.test_backup_vault_security_roundtrip import source_fixture
from tests.services.test_backup_vault_security_roundtrip import vault_db as vault_db

COMMON = [
    "unchanged", "provider_moved", "provider_deleted", "provider_removed",
    "actor_disabled", "actor_deleted", "actor_moved", "actor_demoted",
]
CASES = [(credential, transition) for credential in ("jwt", "api_key") for transition in COMMON]
CASES += [("jwt", "token_version"), ("api_key", "key_revoked"),
          ("api_key", "key_scoped"), ("api_key", "key_expired")]


async def provider_state(db, provider_id):
    row = (await db.execute(select(
        SSOProvider.organization_id, SSOProvider.name, SSOProvider.deleted_at,
        SSOProvider.updated_by, SSOProvider.updated_at,
    ).where(SSOProvider.id == provider_id))).one_or_none()
    return tuple(row) if row is not None else None


@pytest.mark.parametrize("route", ["update", "delete"])
@pytest.mark.parametrize("credential,transition", CASES)
async def test_provider_mutation_rechecks_after_genuine_wait(
    vault_db, tmp_path, monkeypatch, request, route, credential, transition,
):
    f = await source_fixture(vault_db, tmp_path, monkeypatch)
    actor_id, org_id = f.user.id, f.org.id
    f.user.role = "org_admin"
    f.user.token_version = 17
    other = Organization(id=uuid4(), name="Owned provider-wait organization", slug=uuid4().hex)
    provider = SSOProvider(
        id=uuid4(), organization_id=org_id, name="Owned provider before wait", slug=uuid4().hex,
        protocol=SSOProtocol.OIDC, status=SSOProviderStatus.ACTIVE,
        oidc_issuer="https://owned-idp.example.invalid", oidc_client_id="owned-client",
        jit_provisioning=False, default_role="viewer",
    )
    f.db.add_all([other, provider])
    f.db.info["owned_org_ids"].append(other.id)
    key_id = None
    if credential == "jwt":
        headers = {"Authorization": "Bearer " + create_access_token(subject=str(actor_id), token_version=17)}
    else:
        raw, prefix, key_hash = generate_api_key()
        key_id = uuid4()
        f.db.add(APIKey(id=key_id, user_id=actor_id, name="Owned provider-wait key", key_prefix=prefix,
                        key_hash=key_hash, scopes=[], is_active=True))
        headers = {"X-API-Key": raw}
    await f.db.commit()
    provider_id, other_id = provider.id, other.id
    observed = {}

    async def pinned_request_session():
        # API-key authentication may commit last_used; the physical connection
        # remains pinned, so the actual blocked request PID cannot be guessed.
        async with f.db.bind.connect() as connection:
            async with AsyncSession(bind=connection, expire_on_commit=False, autoflush=False) as session:
                observed["pid"] = await session.scalar(text("select pg_backend_pid()"))
                try:
                    yield session
                    await session.commit()
                except BaseException:
                    await session.rollback()
                    raise

    monkeypatch.setitem(app.dependency_overrides, get_session, pinned_request_session)
    await f.db.execute(select(SSOProvider.id).where(SSOProvider.id == provider_id).with_for_update())
    holder_pid = await f.db.scalar(text("select pg_backend_pid()"))
    address = uuid4().int
    peer = f"198.19.{(address >> 8) & 255}.{address & 255}"
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False, client=(peer, 45123))
    url = f"/api/v1/auth/sso/providers/{provider_id}"
    async with httpx.AsyncClient(transport=transport, base_url="http://test", headers=headers) as client:
        operation = client.patch(url, json={"name": "Owned queued provider edit"}) if route == "update" else client.delete(url)
        task = asyncio.create_task(operation)
        try:
            for _ in range(500):
                if observed.get("pid") is not None:
                    blockers = await f.db.scalar(text("select pg_blocking_pids(:pid)"), {"pid": observed["pid"]})
                    if holder_pid in blockers:
                        break
                assert not task.done(), "HTTP request did not reach the owned provider-row wait"
                await asyncio.sleep(0.01)
            else:
                raise AssertionError("A genuine provider-row wait was not established")
            assert holder_pid != observed["pid"]
            now = datetime.now(UTC)
            if transition == "provider_moved":
                await f.db.execute(update(SSOProvider).where(SSOProvider.id == provider_id).values(organization_id=other_id))
            elif transition == "provider_deleted":
                await f.db.execute(update(SSOProvider).where(SSOProvider.id == provider_id).values(deleted_at=now))
            elif transition == "provider_removed":
                await f.db.execute(delete(SSOProvider).where(SSOProvider.id == provider_id))
            elif transition in {"actor_disabled", "actor_deleted", "actor_moved", "actor_demoted", "token_version"}:
                changes = {
                    "actor_disabled": {"is_active": False}, "actor_deleted": {"deleted_at": now},
                    "actor_moved": {"organization_id": other_id}, "actor_demoted": {"role": "viewer"},
                    "token_version": {"token_version": 18},
                }
                await f.db.execute(update(User).where(User.id == actor_id).values(**changes[transition]))
            elif transition in {"key_revoked", "key_scoped", "key_expired"}:
                assert key_id is not None
                changes = {"key_revoked": {"is_active": False}, "key_scoped": {"scopes": ["network:read"]},
                           "key_expired": {"expires_at": datetime(2000, 1, 1, tzinfo=UTC)}}
                await f.db.execute(update(APIKey).where(APIKey.id == key_id).values(**changes[transition]))
            else:
                assert transition == "unchanged"
            expected = await provider_state(f.db, provider_id)
            await f.db.commit()
            response = await asyncio.wait_for(task, timeout=5)
            async with AsyncSession(f.db.bind) as observer:
                actual = await provider_state(observer, provider_id)
            request.node.user_properties.extend([
                ("genuine_provider_row_wait", True), ("response_status", response.status_code),
                ("provider_state_unchanged_after_wait", actual == expected),
            ])
            if transition == "unchanged":
                assert response.status_code == (200 if route == "update" else 204), response.text
                assert actual is not None and actual[0] == org_id
                if route == "update":
                    assert actual[1] == "Owned queued provider edit" and actual[2] is None and actual[3] == actor_id
                else:
                    assert actual[1] == "Owned provider before wait" and actual[2] is not None
            else:
                # Both observed status and durable state are evaluated before
                # the assertion, retaining evidence even when refusal fails.
                assert (response.status_code in {401, 403, 404}, actual == expected) == (True, True)
        finally:
            await f.db.rollback()
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)

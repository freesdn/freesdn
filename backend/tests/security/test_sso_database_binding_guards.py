# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Independent SQL writers cannot race JIT into duplicate external identities.

Provisioning starts after external verification; no IdP/TLS exchange is claimed.
Database outcomes and protected API acceptance are recorded before assertions.
"""

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


@pytest.mark.parametrize("active", [True, False], ids=["active-holder", "disabled-holder"])
@pytest.mark.parametrize("action", ["commit", "rollback", "no-writer-control"])
async def test_jit_handles_independent_binding_writers_without_duplicates_or_sql_errors(
    vault_db, tmp_path, monkeypatch, action, active, record_property,
):
    f = await source_fixture(vault_db, tmp_path, monkeypatch)
    provider = SSOProvider(
        id=uuid4(), organization_id=f.org.id, name="Owned independent binding writer",
        slug=uuid4().hex, protocol=SSOProtocol.OIDC, status=SSOProviderStatus.ACTIVE,
        oidc_issuer="https://owned-binding.example.com", oidc_client_id="owned-client",
        jit_provisioning=True, default_role="viewer", extra_settings={},
    )
    f.db.add(provider)
    await f.db.commit()
    provider_id, org_id = provider.id, f.org.id
    first_id = uuid4()
    if action != "no-writer-control":
        f.db.add(User(
            id=first_id, organization_id=org_id, username=first_id.hex,
            email=first_id.hex + "@example.com", role="viewer",
            hashed_password="!SSO_MANAGED", auth_provider="oidc",
            external_id="owned-shared-subject", sso_provider_id=provider_id,
            token_version=17, is_active=active, is_verified=True, mfa_enabled=False,
        ))
        f.db.info["owned_user_ids"].append(first_id)
        # Deliberately no application advisory lock: old independent writers
        # still have to obey the database uniqueness invariant.
        await f.db.flush()
    holder_pid = await f.db.scalar(text("SELECT pg_backend_pid()"))
    observations = {}
    identity = uuid4().hex

    async def sign_in(label):
        observed = observations.setdefault(label, {})
        async with f.db.bind.connect() as connection:
            async with AsyncSession(bind=connection, expire_on_commit=False, autoflush=False) as db:
                observed["pid"] = await db.scalar(text("SELECT pg_backend_pid()"))
                live = await db.get(SSOProvider, provider_id)
                svc = SSOService(db)
                try:
                    user = await svc._provision_or_update_user(
                        live, {"email": identity + "@example.com", "username": identity},
                        {"sub": "owned-shared-subject"},
                    )
                    observed["user_id"] = str(user.id)
                    if user.id not in f.db.info["owned_user_ids"]:
                        f.db.info["owned_user_ids"].append(user.id)
                    response = await svc._issue_tokens(user, live)
                    await db.commit()
                    return response
                except SSOAuthError:
                    observed["refused"] = True
                    await db.rollback()
                except IntegrityError as exc:
                    # A real uniqueness error escaping the service is not a
                    # controlled refusal. Preserve its type, never its values.
                    observed["database_error"] = type(exc).__name__
                    await db.rollback()
        return None

    async def accepted(response):
        if response is None or not response.access_token:
            return None
        peer = uuid4().int
        transport = httpx.ASGITransport(
            app=app, raise_app_exceptions=False,
            client=(f"198.19.{(peer >> 8) & 255}.{peer & 255}", 45147),
        )
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            result = await client.get("/api/v1/auth/me", headers={
                "Authorization": "Bearer " + response.access_token,
            })
        return result.json()["id"] if result.status_code == 200 else None

    task = asyncio.create_task(sign_in("first"))
    waited = False
    try:
        for _ in range(500):
            pid = observations.get("first", {}).get("pid")
            if pid is not None:
                blockers = await f.db.scalar(text("SELECT pg_blocking_pids(:pid)"), {"pid": pid})
                if holder_pid in blockers:
                    waited = True
                    break
            if task.done():
                break  # Absence of enforcement is a product observation before the patch.
            await asyncio.sleep(0.01)
        if action == "commit":
            await f.db.commit()
        else:
            await f.db.rollback()
        response = await asyncio.wait_for(task, timeout=5)
        accepted_id = await accepted(response)
        retry = await sign_in("retry")
        retry_accepted_id = await accepted(retry)
        async with AsyncSession(f.db.bind) as observer:
            rows = (await observer.execute(select(User.id, User.is_active).where(
                User.sso_provider_id == provider_id,
                User.external_id == "owned-shared-subject", User.deleted_at.is_(None),
            ).order_by(User.id))).all()
        first = observations["first"]
        record_property("genuine_independent_writer_wait", waited)
        record_property("distinct_physical_connections", holder_pid != first["pid"])
        record_property("service_refused", first.get("refused", False))
        record_property("unhandled_database_error", first.get("database_error", "none"))
        record_property("protected_HTTP_accepted_access", accepted_id is not None)
        record_property("durable_binding_count", len(rows))
        record_property("retry_protected_HTTP_accepted_access", retry_accepted_id is not None)
        record_property("retry_resolved_original_holder", retry_accepted_id == str(first_id))
        assert holder_pid != first["pid"]
        if action == "commit":
            assert waited and first.get("refused", False) and response is None
            assert not first.get("database_error") and accepted_id is None
            assert rows == [(first_id, active)]
            if active:
                assert retry_accepted_id == str(first_id)
            else:
                assert retry is None and observations["retry"].get("refused", False)
        else:
            assert not first.get("refused") and not first.get("database_error")
            assert accepted_id == first["user_id"] == retry_accepted_id
            assert len(rows) == 1 and str(rows[0][0]) == accepted_id and rows[0][1] is True
    finally:
        await f.db.rollback()
        if not task.done():
            task.cancel()
        await asyncio.gather(task, return_exceptions=True)

# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Private post-verification probes with actual PostgreSQL lock waits.

The upstream assertion is supplied after its verifier boundary. No external
IdP or TLS acceptance is claimed. Protected HTTP acceptance is observed
separately from token issuance and from a requested refusal contract.
"""

import asyncio
from datetime import UTC, datetime
from uuid import uuid4

import httpx
import pytest
from sqlalchemy import delete, select, text, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm.exc import StaleDataError

from app.main import app
from app.models.core import Organization, User
from app.models.sso import SSOProtocol, SSOProvider, SSOProviderStatus
from app.services.sso import SSOAuthError, SSOService
from tests.security.test_sso_existing_account_binding import account_binding
from tests.services.test_backup_vault_security_roundtrip import source_fixture
from tests.services.test_backup_vault_security_roundtrip import vault_db as vault_db

CASES = [("existing", s) for s in [
    "unchanged", "disabled", "deleted", "removed", "moved", "role_changed",
    "token_version", "mfa_enabled", "binding_changed", "locked", "negative_counter",
    "exhausted_counter",
]] + [("new_jit", s) for s in [
    "unchanged", "provider_disabled", "provider_deleted", "provider_removed",
    "provider_moved", "client_changed", "trust_changed", "role_mapping_changed",
]]


@pytest.mark.parametrize("kind,transition", CASES)
async def test_sso_provisioning_rechecks_after_real_resource_wait(
    vault_db, tmp_path, monkeypatch, request, kind, transition,
):
    f = await source_fixture(vault_db, tmp_path, monkeypatch)
    other = Organization(id=uuid4(), name="Owned SSO wait destination", slug=uuid4().hex)
    provider = SSOProvider(
        id=uuid4(), organization_id=f.org.id, name="Owned SSO wait provider",
        slug=uuid4().hex, protocol=SSOProtocol.OIDC, status=SSOProviderStatus.ACTIVE,
        oidc_issuer="https://owned-wait.example.invalid", oidc_client_id="owned-client",
        jit_provisioning=True, default_role="viewer", extra_settings={},
    )
    f.db.add_all([other, provider])
    f.db.info["owned_org_ids"].append(other.id)
    await f.db.flush()
    uid = uuid4() if kind == "existing" else None
    identity = uuid4().hex
    email = identity + "@example.com"
    if uid is not None:
        f.db.add(User(
            id=uid, organization_id=f.org.id, username=identity, email=email,
            role="viewer", hashed_password="!SSO_MANAGED", auth_provider="oidc",
            external_id="owned-subject", sso_provider_id=provider.id,
            token_version=17, is_active=True, is_verified=True, mfa_enabled=False,
        ))
        f.db.info["owned_user_ids"].append(uid)
    await f.db.commit()
    provider_id, org_id, other_id = provider.id, f.org.id, other.id
    mfa_secret, mfa_codes = f.user.mfa_secret, f.user.mfa_backup_codes
    if kind == "existing":
        await f.db.execute(select(User.id).where(User.id == uid).with_for_update())
    else:
        # The uncorrected JIT INSERT must acquire its real provider FK lock.
        # A corrected implementation may instead wait while validating the
        # provider itself; both must be genuine waits on this physical holder.
        await f.db.execute(select(SSOProvider.id).where(
            SSOProvider.id == provider_id,
        ).with_for_update())
    holder_pid = await f.db.scalar(text("select pg_backend_pid()"))
    observed = {}

    async def sign_in():
        async with f.db.bind.connect() as connection:
            async with AsyncSession(bind=connection, expire_on_commit=False, autoflush=False) as session:
                observed["pid"] = await session.scalar(text("select pg_backend_pid()"))
                live = await session.get(SSOProvider, provider_id)
                svc = SSOService(session)
                try:
                    user = await svc._provision_or_update_user(
                        live, {"email": email, "username": identity}, {"sub": "owned-subject"},
                    )
                    observed["returned_id"] = user.id
                    if user.id not in f.db.info["owned_user_ids"]:
                        f.db.info["owned_user_ids"].append(user.id)
                    result = await svc._issue_tokens(user, live)
                    await session.commit()
                    return result
                except SSOAuthError:
                    observed["refused"] = True
                    await session.rollback()
                except (IntegrityError, StaleDataError) as exc:
                    # Real stale DELETE/FK failures are product observations,
                    # not successful policy refusals. Unexpected exceptions
                    # still escape and invalidate the fixture interpretation.
                    observed["database_error"] = type(exc).__name__
                    await session.rollback()
        return None

    task = asyncio.create_task(sign_in())
    try:
        for _ in range(500):
            if observed.get("pid") is not None:
                blockers = await f.db.scalar(text("select pg_blocking_pids(:pid)"), {
                    "pid": observed["pid"],
                })
                if holder_pid in blockers:
                    break
            assert not task.done(), "Sign-in did not reach the owned resource-row wait"
            await asyncio.sleep(0.01)
        else:
            raise AssertionError("Actual PostgreSQL wait was not established")
        assert holder_pid != observed["pid"]
        now = datetime.now(UTC)
        if kind == "existing":
            changes = {
                "disabled": {"is_active": False}, "deleted": {"deleted_at": now},
                "moved": {"organization_id": other_id}, "role_changed": {"role": "operator"},
                "token_version": {"token_version": 18},
                "mfa_enabled": {"mfa_enabled": True, "mfa_secret": mfa_secret,
                                "mfa_backup_codes": mfa_codes, "token_version": 18},
                "binding_changed": {"external_id": "replaced-owned-subject"},
                "locked": {"locked_until": datetime(2099, 1, 1, tzinfo=UTC)},
                "negative_counter": {"token_version": -1},
                "exhausted_counter": {"token_version": 2147483647},
            }
            if transition == "removed":
                await f.db.execute(delete(User).where(User.id == uid))
            elif transition != "unchanged":
                await f.db.execute(update(User).where(User.id == uid).values(**changes[transition]))
        else:
            changes = {
                "provider_disabled": {"status": SSOProviderStatus.INACTIVE},
                "provider_deleted": {"deleted_at": now},
                "provider_moved": {"organization_id": other_id},
                "client_changed": {"oidc_client_id": "changed-owned-client"},
                "trust_changed": {"extra_settings": {"trust_idp_mfa": True}},
                "role_mapping_changed": {"default_role": "org_admin"},
            }
            if transition == "provider_removed":
                await f.db.execute(delete(SSOProvider).where(SSOProvider.id == provider_id))
            elif transition != "unchanged":
                await f.db.execute(update(SSOProvider).where(
                    SSOProvider.id == provider_id,
                ).values(**changes[transition]))
        expected = await account_binding(f.db, uid)
        await f.db.commit()
        result = await asyncio.wait_for(task, timeout=5)
        async with AsyncSession(f.db.bind) as observer:
            actual = await account_binding(observer, uid)
            rows = (await observer.execute(select(User.id, User.organization_id).where(
                User.email == email,
            ))).all()
        accepted_id = None
        if result is not None and result.access_token:
            peer = uuid4().int
            transport = httpx.ASGITransport(
                app=app, raise_app_exceptions=False,
                client=(f"198.19.{(peer >> 8) & 255}.{peer & 255}", 45128),
            )
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                response = await client.get("/api/v1/auth/me", headers={
                    "Authorization": "Bearer " + result.access_token,
                })
            if response.status_code == 200:
                accepted_id = response.json()["id"]
        refused = observed.get("refused", False)
        request.node.user_properties.extend([
            ("genuine_resource_row_wait", True),
            ("distinct_physical_postgres_connections", True),
            ("post_verifier_boundary_only", True),
            ("service_refused", refused),
            ("database_error", observed.get("database_error", "none")),
            ("credential_response_returned", result is not None),
            ("protected_HTTP_accepted_access", accepted_id is not None),
            ("existing_security_matches_committed_transition", actual == expected),
            ("new_account_committed", kind == "new_jit" and bool(rows)),
        ])
        if transition == "unchanged":
            assert not refused and result is not None and accepted_id == str(observed["returned_id"])
            assert len(rows) == 1 and rows[0][1] == org_id
        else:
            assert refused and result is None and accepted_id is None
            assert actual == expected
            if kind == "new_jit":
                assert not rows
    finally:
        await f.db.rollback()
        if not task.done():
            task.cancel()
        await asyncio.gather(task, return_exceptions=True)

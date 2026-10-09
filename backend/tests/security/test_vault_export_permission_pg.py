"""Planned actual HTTP/PG/factor/default-claim final permission comparison.

Owned routes stop at a permission sentinel; they do not access archives. No
public route, external IdP, TrueNAS network or deployment acceptance is implied.
"""

import asyncio
import hashlib
import time
from datetime import UTC, datetime, timedelta

import anyio
import pytest
import pytest_asyncio
from fastapi import Depends, Request
from sqlalchemy import func, insert, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import CurrentUser, get_current_user
from app.models.api_keys import APIKey
from app.models.core import TokenRevocation, User
from app.modules.backup.models import Backup, StorageLocation
from app.schemas.backup import BackupCreate
from app.services import vault_export_permission as module
from app.services.vault_export_authority import VaultExportAuthority
from app.services.vault_export_operation_state import ExportIntent, resolve_current_operation
from tests.security.test_vault_export_authority import credentials, real_wait
from tests.security.test_vault_export_authority import owned_export as owned_export
from tests.security.test_vault_export_operation_state import operations as operations


@pytest_asyncio.fixture
async def permission_http(operations):
    f = operations
    f.permission_count = 0
    f.verified = None
    app = f.client._transport.app

    def intent(body):
        operation = body["operation"]
        if operation == "create":
            return ExportIntent.creation(BackupCreate.model_validate(body["request"]))
        return ExportIntent.download(
            f.backup,
            operation=operation,
            legacy_acknowledged=operation == "observe_legacy",
        )

    async def capture(request, user, operation):
        return await VaultExportAuthority.capture(
            request,
            user,
            action="create" if operation == "create" else "download",
            secret_key=f.secret,
        )

    @app.post("/owned/permission/issue")
    async def issue(request: Request, user: CurrentUser = Depends(get_current_user)):
        body = await request.json()
        selected = intent(body)
        authority = await capture(request, user, selected.operation)
        initial = await resolve_current_operation(authority, selected)
        factor = await authority.confirm_local(password=body["password"])
        token = await module.issue_after_factors(
            factor, selected, initiating_binding=initial.binding
        )
        current = await resolve_current_operation(factor.authority, selected)
        f.verified = module._verify(token, current)
        f.proof_hash = hashlib.sha256(f.verified.jti.encode()).hexdigest()
        f.token_hashes.add(f.proof_hash)
        return {"proof": token, "expires": f.verified.expires_at}

    @app.post("/owned/permission/use")
    async def use(request: Request, user: CurrentUser = Depends(get_current_user)):
        body = await request.json()
        selected = intent(body)
        authority = await capture(request, user, selected.operation)
        permission = await module.consume_export_permission(authority, selected, body["proof"])
        await permission.check()
        f.permission_count += 1
        return {"accepted": True}

    yield f
    assert module._REDEMPTION_WORK.borrowed_tokens == 0
    # Cached fixture callbacks must not retain completed request resources.
    f = None


async def issue(f, kind, operation, *, short=False):
    # Real password verification and authority reads need setup headroom under
    # the complete suite's load. Expiry cases still wait for the actual issued
    # deadline while PostgreSQL blocks redemption; no production clock or
    # verifier is replaced.
    credential_seconds = 30 if short else 120
    if operation == "observe_legacy" or (short and kind == "key"):
        async with AsyncSession(f.engine) as db:
            if operation == "observe_legacy":
                await db.execute(
                    update(Backup).where(Backup.id == f.backup).values(metadata_json={})
                )
            if short and kind == "key":
                await db.execute(
                    update(APIKey)
                    .where(APIKey.id == f.key_id)
                    .values(
                        expires_at=datetime.now(UTC) + timedelta(seconds=credential_seconds),
                    )
                )
            await db.commit()
    headers, _ = credentials(f, kind, expires=credential_seconds)
    body = {"operation": operation, "request": f.data, "password": f.password}
    response = await f.client.post("/owned/permission/issue", headers=headers, json=body)
    assert response.status_code == 200, response.text
    body.pop("password")
    body["proof"] = response.json()["proof"]
    return headers, body


async def claimed(f):
    async with AsyncSession(f.engine) as db:
        return await db.scalar(
            select(func.count())
            .select_from(TokenRevocation)
            .where(
                TokenRevocation.jti_hash == f.proof_hash,
            )
        )


@pytest.mark.parametrize("kind", ["jwt", "key"])
@pytest.mark.parametrize("operation", ["create", "download_recorded", "observe_legacy"])
async def test_real_password_current_rows_claim_and_replay(permission_http, kind, operation):
    f = permission_http
    headers, body = await issue(f, kind, operation)
    assert await claimed(f) == 0
    first = await f.client.post("/owned/permission/use", headers=headers, json=body)
    second = await f.client.post("/owned/permission/use", headers=headers, json=body)
    assert (first.status_code, second.status_code, f.permission_count, await claimed(f)) == (
        200,
        401,
        1,
        1,
    )


@pytest.mark.parametrize("kind", ["jwt", "key"])
@pytest.mark.parametrize("operation", ["create", "download_recorded", "observe_legacy"])
async def test_competing_real_claims_have_exactly_one_permission(permission_http, kind, operation):
    f = permission_http
    headers, body = await issue(f, kind, operation)
    results = await asyncio.gather(
        *[f.client.post("/owned/permission/use", headers=headers, json=body) for _ in range(2)]
    )
    assert sorted(r.status_code for r in results) == [200, 401]
    assert f.permission_count == 1 and await claimed(f) == 1


@pytest.mark.parametrize("kind", ["jwt", "key"])
@pytest.mark.parametrize(
    "change", ["none", "actor-inactive", "counter", "destination", "catalogue", "expiry"]
)
async def test_default_claim_real_wait_revalidates_before_permission(
    permission_http, kind, change, record_property
):
    f = permission_http
    headers, body = await issue(f, kind, "download_recorded", short=change == "expiry")
    if change == "expiry":
        remaining = f.verified.expires_at - time.time()
        record_property("credential_seconds_remaining_after_real_factor", remaining)
        assert remaining > 0
    async with AsyncSession(f.engine) as holder:
        blocker = await holder.scalar(text("SELECT pg_backend_pid()"))
        await holder.execute(
            insert(TokenRevocation).values(
                jti_hash=f.proof_hash,
                expires_at=datetime.now(UTC) + timedelta(minutes=5),
            )
        )
        task = asyncio.create_task(
            f.client.post("/owned/permission/use", headers=headers, json=body)
        )
        try:
            waited = await real_wait(f, task, blocker)
            record_property("default_claim_actual_pg_wait", bool(waited))
            assert f.permission_count == 0
            if change == "expiry":
                await anyio.sleep(max(0, f.verified.expires_at - time.time()) + 0.03)
            elif change != "none":
                async with AsyncSession(f.engine) as writer:
                    if change == "actor-inactive":
                        statement = update(User).where(User.id == f.user).values(is_active=False)
                    elif change == "counter":
                        statement = update(User).where(User.id == f.user).values(token_version=18)
                    elif change == "destination":
                        statement = (
                            update(StorageLocation)
                            .where(StorageLocation.id == f.location)
                            .values(
                                config={
                                    "controller_id": str(f.controller),
                                    "dataset_path": "tank/changed",
                                },
                            )
                        )
                    else:
                        statement = (
                            update(Backup)
                            .where(Backup.id == f.backup)
                            .values(storage_path="changed.fsdnvault")
                        )
                    await writer.execute(statement)
                    await writer.commit()
            await holder.rollback()  # Claim may now insert and commit its own tombstone.
            response = await task
        finally:
            await holder.rollback()
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)
    assert await claimed(f) == 1
    if change == "none":
        assert response.status_code == 200 and f.permission_count == 1
    else:
        assert response.status_code in (401, 409) and f.permission_count == 0, response.text


@pytest.mark.parametrize("kind", ["jwt", "key"])
@pytest.mark.parametrize("cancellation", ["asyncio", "anyio"])
async def test_cancellation_during_real_claim_wait_drains_and_spends(
    permission_http, kind, cancellation, record_property
):
    f = permission_http
    headers, body = await issue(f, kind, "download_recorded")
    scope_state = {}

    async def use():
        with anyio.CancelScope() as scope:
            scope_state["scope"] = scope
            result = await f.client.post("/owned/permission/use", headers=headers, json=body)
            scope_state["result"] = result

    async with AsyncSession(f.engine) as holder:
        blocker = await holder.scalar(text("SELECT pg_backend_pid()"))
        await holder.execute(
            insert(TokenRevocation).values(
                jti_hash=f.proof_hash,
                expires_at=datetime.now(UTC) + timedelta(minutes=5),
            )
        )
        task = asyncio.create_task(use())
        try:
            waited = await real_wait(f, task, blocker)
            record_property("cancelled_claim_actual_pg_wait", bool(waited))
            if cancellation == "asyncio":
                for _ in range(3):
                    task.cancel()
                    await anyio.sleep(0.01)
            else:
                scope_state["scope"].cancel()
                await anyio.sleep(0.03)
            assert not task.done() and f.permission_count == 0
            assert module._REDEMPTION_WORK.borrowed_tokens == 1
            await holder.rollback()
            await asyncio.gather(task, return_exceptions=True)
        finally:
            await holder.rollback()
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)
    assert "result" not in scope_state and f.permission_count == 0 and await claimed(f) == 1
    replay = await f.client.post("/owned/permission/use", headers=headers, json=body)
    assert replay.status_code == 401 and f.permission_count == 0


@pytest.mark.parametrize("kind", ["jwt", "key"])
async def test_wrong_password_creates_no_proof_or_claim(permission_http, kind):
    f = permission_http
    headers, _ = credentials(f, kind)
    async with AsyncSession(f.engine) as db:
        before = await db.scalar(select(func.count()).select_from(TokenRevocation))
    response = await f.client.post(
        "/owned/permission/issue",
        headers=headers,
        json={
            "operation": "create",
            "request": f.data,
            "password": "Incorrect owned comparison input",
        },
    )
    assert response.status_code == 401 and f.verified is None and f.permission_count == 0
    async with AsyncSession(f.engine) as db:
        after = await db.scalar(select(func.count()).select_from(TokenRevocation))
    assert after == before

"""Planned real-PG/HTTP journal reservation contracts, not runtime evidence.

The server-side request/budget are assigned by this owned harness, not accepted
as an unrestricted public API. Real auth, migrations and journal SQL remain.
No publication/deletion/file cleanup or packet-loss/crash test is claimed.
"""

import asyncio
import hashlib
import json
from contextlib import asynccontextmanager
from dataclasses import asdict, replace
from uuid import UUID, uuid4

import httpx
import pytest
import pytest_asyncio
from fastapi import Depends, FastAPI, Request
from sqlalchemy import select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import CurrentUser, get_current_user
from app.db.session import get_session
from app.main import app as product_app
from app.models.agent_release_operations import AgentReleaseOperation
from app.models.api_keys import APIKey
from app.models.core import User
from app.schemas.agent_downloads import AgentReleaseCreate
from app.services import agent_release_reservation as coordinator
from app.services.agent_release_authority import ReleaseMutationAuthority
from app.services.agent_release_request import ReleasePublicationRequest, ReleaseReservationBudget
from tests.db.conftest import maintenance_engine as maintenance_engine
from tests.services import test_agent_release_operation_status as status_probes
from tests.services import test_agent_signing_lifecycle as lifecycle_probes


def request_for(organization_id, *, operation_id=None, release_id=None, storage="owned", notes="", size=5):
    release_id = release_id or uuid4()
    payload = AgentReleaseCreate(
        version="1.0.0", platform="Linux", agent_type="Daemon",
        download_url=f"/api/v1/agents/releases/{release_id}/binary" if storage == "owned" else "/public/agent",
        checksum_sha256="A" * 64, file_size=size, release_notes=notes,
    )
    return ReleasePublicationRequest.create(operation_id=operation_id or uuid4(), release_id=release_id,
                                           organization_id=organization_id, storage_kind=storage, payload=payload,
                                           is_latest=True, filename="agent.bin" if storage == "owned" else None)


@pytest.mark.parametrize("notes", ["x" * 20000, "🦉" * 20000, "\x01" * 20000])
def test_full_supported_notes_bind_without_journal_truncation(notes):
    request = request_for(uuid4(), notes=notes)
    assert request.metadata()["release_notes"] == notes and len(request.request_bytes()) < 65536
    assert request.metadata()["platform"] == "linux" and request.metadata()["checksum_sha256"] == "a" * 64
    assert request.request_sha256() == hashlib.sha256(request.request_bytes()).hexdigest()
    rebuilt = request_for(request.organization_id, operation_id=request.operation_id,
                          release_id=request.release_id, notes=notes)
    assert rebuilt == request and rebuilt.request_bytes() == request.request_bytes()
    changed = request_for(request.organization_id, operation_id=request.operation_id,
                          release_id=request.release_id, notes=notes[:-1]+"z")
    assert changed.request_bytes() != request.request_bytes()


@pytest.mark.parametrize("field,value", [
    ("operation_id", UUID(int=0)), ("release_id", "not-a-uuid"), ("organization_id", UUID(int=0)),
    ("storage_kind", "legacy"), ("metadata_bytes", b"{}"), ("metadata_bytes", b"[]"),
])
def test_invalid_request_identity_or_noncanonical_metadata_refused(field, value):
    request = request_for(uuid4())
    with pytest.raises(ValueError):
        replace(request, **{field: value})


@pytest.mark.parametrize("field,value", [
    ("platform", "Linux"), ("checksum_sha256", "A" * 64), ("file_size", True),
    ("file_size", 524288001), ("is_latest", "yes"), ("filename", "../agent"),
    ("download_url", "https://example.invalid/other"), ("authorization", "unexpected metadata"),
    ("release_notes", "bad\x00text"),
])
def test_constructor_cannot_bypass_normalization_size_or_allowlist(field, value):
    request = request_for(uuid4())
    payload = request.metadata()
    payload[field] = value
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    with pytest.raises(ValueError):
        replace(request, metadata_bytes=encoded)


@pytest.mark.parametrize("value", [True, 0, -1, 9223372036854775808])
def test_reservation_budget_is_bounded_trusted_policy(value):
    with pytest.raises(ValueError):
        ReleaseReservationBudget(value, 100, 1000000, 1000000)


@pytest_asyncio.fixture
async def reservation(maintenance_engine, monkeypatch, tmp_path):
    context = asynccontextmanager(status_probes.inspected.__wrapped__)
    async with context(maintenance_engine, monkeypatch, tmp_path) as f:
        f.publication = request_for(f.org)
        f.budget = ReleaseReservationBudget(100, 100, 2000000000, 2000000000)
        f.action = "reserve"
        app = FastAPI(exception_handlers=product_app.exception_handlers)

        async def request_session():
            async with AsyncSession(f.engine, expire_on_commit=False, autoflush=False) as db:
                yield db

        app.dependency_overrides[get_session] = request_session

        @app.post("/owned/release-reservation")
        async def execute(request: Request, user: CurrentUser = Depends(get_current_user)):
            authority = await ReleaseMutationAuthority.capture(request, user, secret_key=f.secret)
            result = await coordinator.execute_release_reservation(
                authority=authority, request=f.publication, budget=f.budget, action=f.action
            )
            return asdict(result)

        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),
                                     base_url="http://test") as client:
            f.reservation_client = client
            yield f


async def call(f, credential):
    return await f.reservation_client.post("/owned/release-reservation", headers=credential)


async def journal(f):
    async with AsyncSession(f.engine) as db:
        return [dict(row) for row in (await db.execute(select(AgentReleaseOperation.__table__)
                .order_by(AgentReleaseOperation.operation_id))).mappings()]


async def assert_leases_free(f, request):
    async with f.engine.connect() as db:
        acquired = []
        try:
            for key in coordinator._lease_keys(request.operation_id, request.release_id):
                assert await db.scalar(text("SELECT pg_try_advisory_lock(CAST(:key AS bigint))"), {"key": key}) is True
                acquired.append(key)
        finally:
            for key in acquired:
                assert await db.scalar(text("SELECT pg_advisory_unlock(CAST(:key AS bigint))"), {"key": key}) is True
            await db.commit()


@pytest.mark.parametrize("credential_kind", ["jwt", "key"])
async def test_real_reservation_exact_replay_and_cancellation_keep_history(reservation, credential_kind):
    f = reservation
    credential = await lifecycle_probes.headers(f, credential_kind)
    first = await call(f, credential)
    assert first.status_code == 200 and first.json()["created"] is True
    before = await journal(f)
    assert len(before) == 1 and before[0]["request_bytes"] == f.publication.request_bytes()
    assert before[0]["requested_by"] == f.user and before[0]["phase"] == "reserved"
    replay = await call(f, credential)
    assert replay.status_code == 200 and replay.json()["created"] is False and await journal(f) == before
    f.action = "cancel"
    cancelled = await call(f, credential)
    assert cancelled.status_code == 200 and cancelled.json()["decision"] == "cancelled"
    after = await journal(f)
    assert len(after) == 1 and after[0]["transition_sequence"] == 1 and after[0]["prepared_at"] is None
    assert after[0]["requested_by"] == f.user and after[0]["last_transition_by"] == f.user
    assert (await call(f, credential)).status_code == 200 and await journal(f) == after
    assert not f.root.exists()
    await assert_leases_free(f, f.publication)


@pytest.mark.parametrize("action", ["reserve", "cancel"])
@pytest.mark.parametrize("credential_kind", ["jwt", "key"])
async def test_actual_committed_journal_survives_controlled_lost_acknowledgment(reservation, monkeypatch, action, credential_kind):
    f = reservation
    credential = await lifecycle_probes.headers(f, credential_kind)
    if action == "cancel":
        assert (await call(f, credential)).status_code == 200
    f.action = action
    original = coordinator._commit_phase
    fail_once = True

    async def commit_then_lose_ack(db):
        nonlocal fail_once
        await original(db)
        if fail_once:
            fail_once = False
            raise ConnectionError("Owned controlled exception after actual commit")

    monkeypatch.setattr(coordinator, "_commit_phase", commit_then_lose_ack)
    failed = await call(f, credential)
    observed = await journal(f)
    assert failed.status_code == 503 and len(observed) == 1
    assert observed[0]["phase"] == ("reserved" if action == "reserve" else "decided")
    assert observed[0]["decision"] == (None if action == "reserve" else "cancelled")
    retried = await call(f, credential)
    assert retried.status_code == 200 and retried.json()["created"] is False
    assert await journal(f) == observed and not f.root.exists()
    await assert_leases_free(f, f.publication)


@pytest.mark.parametrize("binding", ["notes", "release", "organization", "storage"])
async def test_reusing_operation_for_different_request_preserves_original(reservation, binding):
    f = reservation
    credential = await lifecycle_probes.headers(f)
    assert (await call(f, credential)).status_code == 200
    original = f.publication
    before = await journal(f)
    f.publication = request_for(f.other_org if binding == "organization" else f.org,
                               operation_id=original.operation_id,
                               release_id=uuid4() if binding == "release" else original.release_id,
                               notes="changed" if binding == "notes" else "",
                               storage="external" if binding == "storage" else "owned")
    assert (await call(f, credential)).status_code == 409 and await journal(f) == before
    assert not f.root.exists()


@pytest.mark.parametrize("shared", ["operation", "release"])
async def test_actual_session_lease_excludes_competing_owner_between_transactions(reservation, monkeypatch, record_property, shared):
    f = reservation
    credential = await lifecycle_probes.headers(f)
    ready, proceed = asyncio.Event(), asyncio.Event()
    original = coordinator._OperationOwner.phase
    request = f.publication

    async def hold_owner_before_phase(self, function):
        assert not self.db.in_transaction()
        f.owner = self
        ready.set()
        await proceed.wait()
        return await original(self, function)

    monkeypatch.setattr(coordinator._OperationOwner, "phase", hold_owner_before_phase)
    first = asyncio.create_task(call(f, credential))
    try:
        await asyncio.wait_for(ready.wait(), 10)
        async with f.engine.connect() as observer:
            observer_pid = await observer.scalar(text("SELECT pg_backend_pid()"))
            assert observer_pid != f.owner.pid
            for key in f.owner.keys:
                assert await observer.scalar(text("SELECT pg_try_advisory_lock(CAST(:key AS bigint))"), {"key": key}) is False
            record_property("actual_session_lease_exclusion", True)
        f.publication = request_for(f.org, operation_id=request.operation_id if shared == "operation" else uuid4(),
                                   release_id=request.release_id if shared == "release" else uuid4())
        rejected = await call(f, credential)
        assert rejected.status_code == 409 and await journal(f) == []
        proceed.set()
        accepted = await asyncio.wait_for(first, 10)
        assert accepted.status_code == 200 and len(await journal(f)) == 1
        await assert_leases_free(f, request)
    finally:
        proceed.set()
        if not first.done():
            await asyncio.wait_for(first, 10)


async def test_lost_lock_acquisition_acknowledgment_does_not_leak_pooled_ownership(reservation, monkeypatch):
    f = reservation
    credential = await lifecycle_probes.headers(f)
    original = AsyncSession.scalar
    fail_once = True

    async def lose_granted_lock_result(self, statement, *args, **kwargs):
        nonlocal fail_once
        value = await original(self, statement, *args, **kwargs)
        if fail_once and str(statement).startswith("SELECT pg_try_advisory_lock("):
            assert value is True
            fail_once = False
            f.lost_pid = await original(self, text("SELECT pg_backend_pid()"))
            raise ConnectionError("Owned exception after actual lock grant")
        return value

    monkeypatch.setattr(AsyncSession, "scalar", lose_granted_lock_result)
    response = await call(f, credential)
    assert response.status_code == 503 and await journal(f) == [] and not f.root.exists()
    await assert_leases_free(f, f.publication)
    async with f.engine.connect() as db:
        assert not await db.scalar(text("SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE pid=:pid)"), {"pid": f.lost_pid})


@pytest.mark.parametrize("loss", ["unlock", "invalidate"])
async def test_lost_session_or_connection_is_not_implicitly_reacquired(reservation, monkeypatch, loss):
    f = reservation
    credential = await lifecycle_probes.headers(f)
    original = coordinator._OperationOwner.phase

    async def lose_ownership_before_phase(self, function):
        if loss == "unlock":
            await self.db.execute(text("SELECT pg_advisory_unlock_all()"))
            await self.db.commit()
        else:
            await self.connection.invalidate()
        return await original(self, function)

    monkeypatch.setattr(coordinator._OperationOwner, "phase", lose_ownership_before_phase)
    result = await call(f, credential)
    assert result.status_code == 503 and await journal(f) == [] and not f.root.exists()
    await assert_leases_free(f, f.publication)


@pytest.mark.parametrize("change", ["disabled", "role", "organization", "key-revoked"])
async def test_actual_authority_change_after_lease_prevents_reservation(reservation, monkeypatch, change):
    f = reservation
    credential = await lifecycle_probes.headers(f)
    original = coordinator._OperationOwner.phase

    async def change_before_phase(self, function):
        async with f.engine.begin() as db:
            if change == "key-revoked":
                await db.execute(update(APIKey).where(APIKey.id == f.key_id).values(is_active=False))
            else:
                fields = {"disabled": {"is_active": False}, "role": {"role": "viewer"},
                          "organization": {"organization_id": f.other_org}}[change]
                await db.execute(update(User).where(User.id == f.user).values(**fields))
        return await original(self, function)

    monkeypatch.setattr(coordinator._OperationOwner, "phase", change_before_phase)
    result = await call(f, credential)
    assert result.status_code in (401, 403) and await journal(f) == [] and not f.root.exists()
    await assert_leases_free(f, f.publication)


@pytest.mark.parametrize("limit", ["global_history", "organization_history", "global_owned_bytes", "organization_owned_bytes"])
async def test_serialized_declared_capacity_refuses_new_intent_without_blocking_exact_replay_or_cancel(reservation, limit):
    f = reservation
    f.budget = replace(f.budget, **{limit: 1 if "history" in limit else 8})
    credential = await lifecycle_probes.headers(f)
    assert (await call(f, credential)).status_code == 200
    original = f.publication
    before = await journal(f)
    f.publication = request_for(f.org)
    rejected = await call(f, credential)
    assert rejected.status_code == 409 and await journal(f) == before
    f.publication = original
    assert (await call(f, credential)).status_code == 200 and await journal(f) == before
    f.action = "cancel"
    assert (await call(f, credential)).status_code == 200 and len(await journal(f)) == 1
    assert not f.root.exists()


async def test_external_metadata_keeps_supported_ten_gib_range_without_claiming_owned_bytes(reservation):
    f = reservation
    f.publication = request_for(f.org, storage="external", size=10*1024**3)
    f.budget = replace(f.budget, global_owned_bytes=1, organization_owned_bytes=1)
    response = await call(f, await lifecycle_probes.headers(f))
    rows = await journal(f)
    assert response.status_code == 200 and len(rows) == 1
    assert rows[0]["expected_size"] == 10*1024**3 and rows[0]["artifact_id"] is None
    assert not f.root.exists()


async def test_cancel_missing_operation_does_not_allocate_history(reservation):
    f = reservation
    f.action = "cancel"
    result = await call(f, await lifecycle_probes.headers(f))
    assert result.status_code == 404 and await journal(f) == [] and not f.root.exists()


async def test_fresh_real_credential_can_resolve_intent_after_original_key_revocation(reservation):
    f = reservation
    old_credential = await lifecycle_probes.headers(f)
    assert (await call(f, old_credential)).status_code == 200
    before = await journal(f)
    async with f.engine.begin() as db:
        await db.execute(update(APIKey).where(APIKey.id == f.key_id).values(is_active=False))
    f.action = "cancel"
    assert (await call(f, old_credential)).status_code == 401 and await journal(f) == before
    current_credential = await lifecycle_probes.headers(f, "jwt")
    response = await call(f, current_credential)
    after = await journal(f)
    assert response.status_code == 200 and len(after) == 1 and after[0]["decision"] == "cancelled"
    assert after[0]["requested_by"] == before[0]["requested_by"] == f.user
    assert after[0]["request_bytes"] == before[0]["request_bytes"] and not f.root.exists()


async def test_actual_database_rejection_rolls_back_cancellation_without_losing_reservation(reservation):
    f = reservation
    credential = await lifecycle_probes.headers(f)
    assert (await call(f, credential)).status_code == 200
    before = await journal(f)
    async with f.engine.begin() as db:
        await db.execute(text("""CREATE FUNCTION agents.reject_owned_cancel_probe() RETURNS trigger
            LANGUAGE plpgsql AS $owned$
            BEGIN RAISE EXCEPTION 'Owned cancellation rejection' USING ERRCODE='23514'; END
            $owned$"""))
        await db.execute(text("""CREATE TRIGGER reject_owned_cancel_probe AFTER UPDATE
            ON agents.agent_release_operations FOR EACH ROW
            EXECUTE FUNCTION agents.reject_owned_cancel_probe()"""))
    f.action = "cancel"
    result = await call(f, credential)
    assert result.status_code == 503 and await journal(f) == before and not f.root.exists()
    await assert_leases_free(f, f.publication)

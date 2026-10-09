"""Planned real PostgreSQL/auth/ASGI and owned local-file preparation contracts.

Not executed or collected. The isolated HTTP route is a harness, not a public
endpoint. Controlled exceptions and thread gates are not power/network-loss or
container/NFS qualification. Original reservation/storage contracts are retained.
"""

import asyncio
import hashlib
import threading
from contextlib import asynccontextmanager
from dataclasses import asdict, replace
from datetime import UTC, datetime, timedelta

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
from app.models.agents import AgentRelease
from app.models.api_keys import APIKey
from app.models.core import Organization, User
from app.services import agent_release_preparation as preparation
from app.services import agent_release_reservation as reservation_code
from app.services.agent_release_artifact_store import ArtifactBusy, ArtifactLease
from app.services.agent_release_authority import ReleaseMutationAuthority
from app.services.agent_release_request import _encode
from tests.db.conftest import maintenance_engine as maintenance_engine
from tests.services import test_agent_release_artifact_store as file_probes
from tests.services import test_agent_release_reservation as reservation_probes
from tests.services import test_agent_signing_lifecycle as lifecycle_probes


@pytest_asyncio.fixture
async def prepared(maintenance_engine, monkeypatch, tmp_path):
    context = asynccontextmanager(reservation_probes.reservation.__wrapped__)
    async with context(maintenance_engine, monkeypatch, tmp_path) as f:
        f.artifacts = tmp_path / "release-artifacts"
        f.artifacts.mkdir(mode=0o700)
        f.data = b"hello"
        metadata = f.publication.metadata()
        metadata["checksum_sha256"] = hashlib.sha256(f.data).hexdigest()
        f.publication = replace(f.publication, metadata_bytes=_encode(metadata))
        f.preparation_mode = "upload"
        f.captured_authority = None
        app = FastAPI(exception_handlers=product_app.exception_handlers)

        async def request_session():
            async with AsyncSession(f.engine, expire_on_commit=False, autoflush=False) as db:
                yield db

        app.dependency_overrides[get_session] = request_session

        @app.post("/owned/release-preparation")
        async def execute(request: Request, user: CurrentUser = Depends(get_current_user)):
            f.captured_authority = await ReleaseMutationAuthority.capture(request, user, secret_key=f.secret)
            result = await preparation.execute_release_preparation(
                authority=f.captured_authority, request=f.publication, budget=f.budget,
                root=str(f.artifacts), mode=f.preparation_mode,
                source=request.stream() if f.preparation_mode == "upload" else None,
            )
            return asdict(result)

        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),
                                     base_url="http://test") as client:
            f.preparation_client = client
            yield f


async def call(f, credential, *, content=None):
    return await f.preparation_client.post("/owned/release-preparation", headers=credential,
                                           content=f.data if content is None else content)


def files(f):
    return file_probes._snapshot(f.artifacts)


async def assert_no_release(f):
    async with AsyncSession(f.engine) as db:
        assert (await db.execute(select(AgentRelease.id))).all() == []


def verify_owned(f):
    with ArtifactLease.acquire(str(f.artifacts), preparation._intent(f.publication), mode="shared") as lease:
        receipt = lease.verify_prepared()
        assert receipt.intent.payload_sha256 == hashlib.sha256(f.data).hexdigest()
        assert lease.read(0, 1048576) == f.data


@pytest.mark.parametrize("credential_kind", ["jwt", "key"])
@pytest.mark.parametrize("data", [b"", b"hello", b"a" * 1048576])
async def test_real_owned_upload_and_explicit_resume_keep_prepared_history(prepared, credential_kind, data):
    f = prepared
    f.data = data
    metadata = f.publication.metadata()
    metadata.update(checksum_sha256=hashlib.sha256(data).hexdigest(), file_size=len(data))
    f.publication = replace(f.publication, metadata_bytes=_encode(metadata))
    credential = await lifecycle_probes.headers(f, credential_kind)
    response = await call(f, credential)
    observed = await reservation_probes.journal(f)
    assert response.status_code == 200 and response.json()["phase"] == "prepared"
    assert response.json()["publication_or_storage_authorized"] is False
    assert len(observed) == 1 and observed[0]["phase"] == "prepared" and observed[0]["transition_sequence"] == 1
    assert observed[0]["decision"] is None and observed[0]["prepared_at"] is not None
    await assert_no_release(f)
    verify_owned(f)
    before = files(f)
    assert (await call(f, credential)).status_code == 409 and files(f) == before
    f.preparation_mode = "resume"
    resumed = await call(f, credential, content=b"")
    assert resumed.status_code == 200 and await reservation_probes.journal(f) == observed and files(f) == before
    await reservation_probes.assert_leases_free(f, f.publication)


@pytest.mark.parametrize("stage", ["reserved", "prepared"])
@pytest.mark.parametrize("credential_kind", ["jwt", "key"])
async def test_actual_commit_then_controlled_ack_loss_preserves_decision_and_file(prepared, monkeypatch, stage, credential_kind):
    f = prepared
    credential = await lifecycle_probes.headers(f, credential_kind)
    original = reservation_code._commit_phase
    triggered = False

    async def lose_after_commit(db):
        nonlocal triggered
        phase = await db.scalar(select(AgentReleaseOperation.phase).where(
            AgentReleaseOperation.operation_id == f.publication.operation_id
        ))
        await original(db)
        if phase == stage and not triggered:
            triggered = True
            raise ConnectionError("Owned controlled exception after actual commit")

    monkeypatch.setattr(reservation_code, "_commit_phase", lose_after_commit)
    response = await call(f, credential)
    observed = await reservation_probes.journal(f)
    assert triggered and response.status_code == 503
    assert len(observed) == 1 and observed[0]["phase"] == stage and observed[0]["decision"] is None
    if stage == "reserved":
        assert files(f) == {}
        assert (await call(f, credential)).status_code == 200
    else:
        verify_owned(f)
        before = files(f)
        f.preparation_mode = "resume"
        assert (await call(f, credential, content=b"")).status_code == 200
        assert files(f) == before and await reservation_probes.journal(f) == observed
    await assert_no_release(f)
    await reservation_probes.assert_leases_free(f, f.publication)


@pytest.mark.parametrize("shape", ["short", "long", "wrong-hash", "oversized-chunk", "source-error"])
async def test_bad_or_interrupted_body_preserves_partial_object_without_automatic_retry(prepared, shape):
    f = prepared
    credential = await lifecycle_probes.headers(f)

    async def body():
        if shape == "source-error":
            yield b"he"
            raise RuntimeError("Owned source exception")
        yield {"short": b"he", "long": b"hello!", "wrong-hash": b"other",
               "oversized-chunk": b"a" * 1048577}.get(shape, b"")

    response = await call(f, credential, content=body())
    observed = await reservation_probes.journal(f)
    assert response.status_code in (409, 413, 503) and observed[0]["phase"] == "reserved"
    before = files(f)
    assert any(p.endswith("/allocation.json") for p in before) and not any(p.endswith("/prepared.json") for p in before)
    assert (await call(f, credential)).status_code == 409 and files(f) == before
    f.preparation_mode = "resume"
    assert (await call(f, credential, content=b"")).status_code in (409, 503) and files(f) == before
    assert await reservation_probes.journal(f) == observed
    await assert_no_release(f)
    await reservation_probes.assert_leases_free(f, f.publication)


@pytest.mark.parametrize("state", ["missing", "reserved-no-file", "cancelled", "prepared-missing-file"])
async def test_resume_never_invents_operation_or_reallocates_missing_storage(prepared, state):
    f = prepared
    credential = await lifecycle_probes.headers(f)
    if state != "missing":
        assert (await reservation_probes.call(f, credential)).status_code == 200
    if state == "cancelled":
        f.action = "cancel"
        assert (await reservation_probes.call(f, credential)).status_code == 200
    if state == "prepared-missing-file":
        async with f.engine.begin() as db:
            await db.execute(update(AgentReleaseOperation).where(
                AgentReleaseOperation.operation_id == f.publication.operation_id
            ).values(phase="prepared", transition_sequence=1, prepared_at=await db.scalar(text("SELECT clock_timestamp()"))))
    before = await reservation_probes.journal(f)
    f.preparation_mode = "resume"
    response = await call(f, credential, content=b"")
    assert response.status_code in (404, 409, 503)
    assert await reservation_probes.journal(f) == before and files(f) == {}
    await assert_no_release(f)


async def test_real_SQL_prepared_rejection_keeps_verified_bytes_for_explicit_resume(prepared):
    f = prepared
    credential = await lifecycle_probes.headers(f)
    async with f.engine.begin() as db:
        await db.execute(text("CREATE FUNCTION agents.owned_refuse_prepared() RETURNS trigger LANGUAGE plpgsql AS $$ "
                              "BEGIN IF NEW.phase='prepared' THEN RAISE EXCEPTION 'owned rejection'; END IF; "
                              "RETURN NEW; END $$"))
        await db.execute(text("CREATE TRIGGER owned_refuse_prepared AFTER UPDATE ON agents.agent_release_operations "
                              "FOR EACH ROW EXECUTE FUNCTION agents.owned_refuse_prepared()"))
    response = await call(f, credential)
    observed = await reservation_probes.journal(f)
    assert response.status_code == 503 and observed[0]["phase"] == "reserved"
    verify_owned(f)
    before = files(f)
    async with f.engine.begin() as db:
        await db.execute(text("DROP TRIGGER owned_refuse_prepared ON agents.agent_release_operations"))
        await db.execute(text("DROP FUNCTION agents.owned_refuse_prepared()"))
    f.preparation_mode = "resume"
    assert (await call(f, credential, content=b"")).status_code == 200 and files(f) == before
    assert (await reservation_probes.journal(f))[0]["phase"] == "prepared"
    await assert_no_release(f)


@pytest.mark.parametrize("change", ["disabled", "deleted", "role", "token-version", "key-revoked", "key-expired", "destination-inactive"])
async def test_real_authority_or_destination_change_during_body_wait_refuses_further_write(prepared, change):
    f = prepared
    credential = await lifecycle_probes.headers(f, "key" if change.startswith("key-") else "jwt")
    ready, proceed = asyncio.Event(), asyncio.Event()

    async def body():
        ready.set()
        await proceed.wait()
        yield f.data

    task = asyncio.create_task(call(f, credential, content=body()))
    try:
        await asyncio.wait_for(ready.wait(), 10)
        async with f.engine.begin() as db:
            if change.startswith("key-"):
                fields = {"is_active": False} if change == "key-revoked" else {"expires_at": datetime.now(UTC)-timedelta(seconds=1)}
                await db.execute(update(APIKey).where(APIKey.id == f.key_id).values(**fields))
            elif change == "destination-inactive":
                await db.execute(update(Organization).where(Organization.id == f.org).values(is_active=False))
            else:
                fields = {"disabled": {"is_active": False}, "deleted": {"deleted_at": datetime.now(UTC)},
                          "role": {"role": "viewer"}, "token-version": {"token_version": 100}}[change]
                await db.execute(update(User).where(User.id == f.user).values(**fields))
        before = files(f)
        proceed.set()
        response = await asyncio.wait_for(task, 10)
        assert response.status_code in (401, 403, 404) and files(f) == before
        assert (await reservation_probes.journal(f))[0]["phase"] == "reserved"
        await assert_no_release(f)
    finally:
        proceed.set()
        if not task.done():
            await asyncio.wait_for(task, 10)


async def test_stream_wait_holds_session_leases_but_no_account_or_table_locks(prepared, monkeypatch, record_property):
    f = prepared
    credential = await lifecycle_probes.headers(f)
    original = preparation._preparation_state
    ready, proceed = asyncio.Event(), asyncio.Event()

    async def remember(owner):
        f.owner = owner
        return await original(owner)

    async def body():
        ready.set()
        await proceed.wait()
        yield f.data

    monkeypatch.setattr(preparation, "_preparation_state", remember)
    task = asyncio.create_task(call(f, credential, content=body()))
    try:
        await asyncio.wait_for(ready.wait(), 10)
        assert not f.owner.db.in_transaction()
        async with f.engine.begin() as observer:
            assert await observer.scalar(text("SELECT pg_backend_pid()")) != f.owner.pid
            for key in f.owner.keys:
                assert await observer.scalar(text("SELECT pg_try_advisory_lock(CAST(:key AS bigint))"), {"key": key}) is False
            await observer.execute(text("LOCK TABLE agents.agent_release_operations IN ROW EXCLUSIVE MODE NOWAIT"))
            await observer.execute(select(User.id).where(User.id == f.user).with_for_update(nowait=True))
            record_property("body_wait_session_lease_and_released_SQL_locks", True)
        with pytest.raises(ArtifactBusy):
            ArtifactLease.acquire(str(f.artifacts), preparation._intent(f.publication), mode="exclusive")
        proceed.set()
        assert (await asyncio.wait_for(task, 10)).status_code == 200
    finally:
        proceed.set()
        if not task.done():
            await asyncio.wait_for(task, 10)


@pytest.mark.parametrize("boundary", ["acquired", "readback"])
@pytest.mark.parametrize("change", ["key-revoked", "destination-inactive"])
async def test_current_authority_and_destination_rechecked_after_actual_storage_io(prepared, monkeypatch, boundary, change):
    f = prepared
    credential = await lifecycle_probes.headers(f, "key")
    ready, proceed = asyncio.Event(), asyncio.Event()
    acquire = preparation._PreparationStorage.acquire
    run = preparation._PreparationStorage.run

    async def held_acquire(self, *args, **kwargs):
        result = await acquire(self, *args, **kwargs)
        ready.set()
        await proceed.wait()
        return result

    async def held_readback(self, method, *args):
        result = await run(self, method, *args)
        if method == "finish":
            ready.set()
            await proceed.wait()
        return result

    if boundary == "acquired":
        monkeypatch.setattr(preparation._PreparationStorage, "acquire", held_acquire)
    else:
        monkeypatch.setattr(preparation._PreparationStorage, "run", held_readback)
    task = asyncio.create_task(call(f, credential))
    try:
        await asyncio.wait_for(ready.wait(), 10)
        async with f.engine.begin() as db:
            if change == "key-revoked":
                await db.execute(update(APIKey).where(APIKey.id == f.key_id).values(is_active=False))
            else:
                await db.execute(update(Organization).where(Organization.id == f.org).values(is_active=False))
        before = files(f)
        proceed.set()
        response = await asyncio.wait_for(task, 10)
        assert response.status_code in (401, 403, 404) and files(f) == before
        assert (await reservation_probes.journal(f))[0]["phase"] == "reserved"
        if boundary == "acquired":
            assert not any(p.endswith("/payload") for p in before)
        else:
            verify_owned(f)
        await assert_no_release(f)
        await reservation_probes.assert_leases_free(f, f.publication)
    finally:
        proceed.set()
        if not task.done():
            await asyncio.wait_for(task, 10)


@pytest.mark.parametrize("event", ["request-cancel", "connection-loss"])
async def test_actual_file_worker_drains_before_ownership_release(prepared, monkeypatch, record_property, event):
    f = prepared
    credential = await lifecycle_probes.headers(f)
    entered, release = threading.Event(), threading.Event()
    original_append = ArtifactLease.append
    original_state = preparation._preparation_state

    def held_append(lease, chunk):
        entered.set()
        assert release.wait(10), "Owned test must release worker"
        return original_append(lease, chunk)

    async def remember(owner):
        f.owner = owner
        return await original_state(owner)

    monkeypatch.setattr(ArtifactLease, "append", held_append)
    monkeypatch.setattr(preparation, "_preparation_state", remember)
    task = asyncio.create_task(call(f, credential))
    try:
        assert await asyncio.to_thread(entered.wait, 10)
        if event == "request-cancel":
            task.cancel()
            await asyncio.sleep(0)
            assert not task.done()
            async with f.engine.connect() as observer:
                for key in f.owner.keys:
                    assert await observer.scalar(text("SELECT pg_try_advisory_lock(CAST(:key AS bigint))"), {"key": key}) is False
        else:
            await f.owner.connection.invalidate()
            competing = await call(f, credential)
            assert competing.status_code == 409
        with pytest.raises(ArtifactBusy):
            ArtifactLease.acquire(str(f.artifacts), preparation._intent(f.publication), mode="exclusive")
        assert (await reservation_probes.journal(f))[0]["phase"] == "reserved"
        record_property("filesystem_lifetime_retained_while_worker_live", True)
        release.set()
        if event == "request-cancel":
            with pytest.raises(asyncio.CancelledError):
                await asyncio.wait_for(task, 10)
            assert (await reservation_probes.journal(f))[0]["phase"] == "prepared"
            verify_owned(f)
        else:
            assert (await asyncio.wait_for(task, 10)).status_code == 503
            assert (await reservation_probes.journal(f))[0]["phase"] == "reserved"
            assert (f.artifacts / str(f.publication.operation_id) / "payload").read_bytes() == f.data
        await assert_no_release(f)
        await reservation_probes.assert_leases_free(f, f.publication)
    finally:
        release.set()
        if not task.done():
            try:
                await asyncio.wait_for(task, 10)
            except asyncio.CancelledError:
                pass

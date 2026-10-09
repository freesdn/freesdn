"""Planned owned PostgreSQL/real-auth inspection contracts; not run yet.

The route below is a harness, not a published endpoint. No production journal
writer, mutation coordinator, filesystem cleanup or crash guarantee is claimed.
Owned seed transitions execute the actual model/migration guards; old fixtures
and assertions remain unchanged. Authentication and authority are not mocked.
"""

import asyncio
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import httpx
import pytest
import pytest_asyncio
from fastapi import Depends, FastAPI, Request
from sqlalchemy import insert, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import CurrentUser, get_current_user
from app.db.session import get_session
from app.main import app as product_app
from app.models.agent_release_operations import AgentReleaseOperation
from app.models.agents import AgentRelease
from app.models.api_keys import APIKey
from app.models.core import User
from app.services import agent_release_operation_status as inspection
from app.services.agent_release_authority import ReleaseMutationAuthority, ReleaseMutationFence
from tests.db.conftest import maintenance_engine as maintenance_engine
from tests.db.conftest import run_alembic
from tests.db.test_agent_release_operation_migration import values
from tests.services import test_agent_signing_lifecycle as lifecycle_probes


@pytest_asyncio.fixture
async def inspected(maintenance_engine, monkeypatch, tmp_path):
    context = asynccontextmanager(lifecycle_probes.owned_lifecycle.__wrapped__)
    async with context(maintenance_engine, monkeypatch, tmp_path) as f:
        await asyncio.to_thread(run_alembic, f.engine.url,
                                "upgrade", "026_agent_release_size")
        f.operation_id = uuid4()
        f.last_authority = None
        app = FastAPI(exception_handlers=product_app.exception_handlers)

        async def request_session():
            async with AsyncSession(f.engine, expire_on_commit=False, autoflush=False) as db:
                yield db

        app.dependency_overrides[get_session] = request_session

        @app.get("/owned/release-operation")
        async def get_status(request: Request, user: CurrentUser = Depends(get_current_user)):
            f.last_authority = await ReleaseMutationAuthority.capture(request, user, secret_key=f.secret)
            result = await inspection.inspect_release_operation(f.last_authority, operation_id=f.operation_id)
            return result.public()

        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),
                                     base_url="http://test") as client:
            f.inspection_client = client
            yield f


async def seed(f, *, kind="publish", decision=None, phase="reserved", organization=None, live=False):
    row = values(kind=kind, organization=organization if organization is not None else f.org)
    if kind == "delete":
        predecessor = await seed(f, decision="published", phase="decided", organization=organization)
        for name in ("release_id", "organization_id", "artifact_id", "expected_sha256", "expected_size"):
            row[name] = predecessor[name]
    async with AsyncSession(f.engine) as db, db.begin():
        await db.execute(insert(AgentReleaseOperation).values(**row))
        if phase != "reserved":
            row.update(phase="prepared", transition_sequence=1, prepared_at=await db.scalar(text("SELECT clock_timestamp()")))
            await db.execute(update(AgentReleaseOperation).where(
                AgentReleaseOperation.operation_id == row["operation_id"]
            ).values(phase=row["phase"], transition_sequence=1, prepared_at=row["prepared_at"]))
        if phase in ("decided", "cleaned"):
            row.update(phase="decided", transition_sequence=2, decision=decision, decided_at=await db.scalar(text("SELECT clock_timestamp()")))
            await db.execute(update(AgentReleaseOperation).where(
                AgentReleaseOperation.operation_id == row["operation_id"]
            ).values(phase=row["phase"], transition_sequence=2, decision=decision, decided_at=row["decided_at"]))
        if phase == "cleaned":
            row.update(phase="cleaned", transition_sequence=3, cleaned_at=await db.scalar(text("SELECT clock_timestamp()")))
            await db.execute(update(AgentReleaseOperation).where(
                AgentReleaseOperation.operation_id == row["operation_id"]
            ).values(phase=row["phase"], transition_sequence=3, cleaned_at=row["cleaned_at"]))
        if live:
            await add_release(db, row)
    f.operation_id = row["operation_id"]
    return row


async def add_release(db, row):
    await db.execute(insert(AgentRelease).values(
        id=row["release_id"], organization_id=row["organization_id"], version="owned-status",
        platform="linux", agent_type="daemon", download_url="https://example.invalid/owned",
        checksum_sha256=row["expected_sha256"], file_size=row["expected_size"],
        is_latest=False, is_prerelease=False,
    ))


async def retained(f):
    async with AsyncSession(f.engine) as db:
        snapshots = []
        for model, column in [
            (AgentReleaseOperation, AgentReleaseOperation.operation_id), (AgentRelease, AgentRelease.id)
        ]:
            rows = await db.execute(select(model.__table__).order_by(column))
            snapshots.append([dict(row) for row in rows.mappings()])
        return tuple(snapshots)


@pytest.mark.parametrize("credential", ["jwt", "key"])
@pytest.mark.parametrize("kind,phase,decision,live", [
    ("publish", "reserved", None, False), ("publish", "prepared", None, False),
    ("publish", "decided", "published", True), ("publish", "decided", "cancelled", False),
    ("publish", "cleaned", "cancelled", False), ("delete", "decided", "deleted", False),
    ("delete", "decided", "cancelled", True), ("delete", "cleaned", "deleted", False),
])
async def test_retained_status_is_scoped_read_only_and_not_a_cleanup_grant(inspected, credential, kind, phase, decision, live):
    f = inspected
    row = await seed(f, kind=kind, phase=phase, decision=decision, live=live)
    before = await retained(f)
    response = await f.inspection_client.get("/owned/release-operation", headers=await lifecycle_probes.headers(f, credential))
    after = await retained(f)
    assert response.status_code == 200 and after == before and not f.root.exists()
    body = response.json()
    assert set(body["operation"]) == set(inspection._PUBLIC_FIELDS)
    assert body["operation"]["phase"] == phase and body["operation"]["decision"] == decision
    assert body["operation"]["requested_by"] == str(row["requested_by"]) != str(f.user)
    assert body["release_row_present"] is live and body["observed_at"]
    assert body["storage_checked"] is body["authorization_granted"] is False
    assert body["all_artifact_references_checked"] is body["absence_authorizes_retry_or_cleanup"] is False


@pytest.mark.parametrize("credential", ["jwt", "key"])
async def test_missing_operation_is_not_cancelled_or_absence_authority(inspected, credential):
    f = inspected
    before = await retained(f)
    response = await f.inspection_client.get("/owned/release-operation", headers=await lifecycle_probes.headers(f, credential))
    assert response.status_code == 404 and await retained(f) == before and not f.root.exists()
    assert "operation" not in response.json() and "authorization_granted" not in response.json()


@pytest.mark.parametrize("mode", ["tenant-jwt", "tenant-key", "scoped-platform-key", "unscoped-platform-key"])
async def test_real_permission_and_tenant_ceiling_preserved(inspected, mode):
    f = inspected
    await seed(f, organization=f.other_org)
    async with AsyncSession(f.engine) as db, db.begin():
        if mode.startswith("tenant"):
            await db.execute(update(User).where(User.id == f.user).values(role="admin"))
        if mode == "scoped-platform-key":
            await db.execute(update(APIKey).where(APIKey.id == f.key_id).values(scopes=["agent:admin"]))
    before = await retained(f)
    response = await f.inspection_client.get("/owned/release-operation", headers=await lifecycle_probes.headers(
        f, "jwt" if mode.endswith("jwt") else "key"
    ))
    assert response.status_code == (200 if mode == "unscoped-platform-key" else 404)
    assert await retained(f) == before and not f.root.exists()


@pytest.mark.parametrize("table", ["agents.agent_release_operations", "agents.agent_releases"])
async def test_uncommitted_writer_is_busy_not_missing_or_cancelled(inspected, table):
    f = inspected
    await seed(f)
    credential = await lifecycle_probes.headers(f)
    before = await retained(f)
    async with f.engine.connect() as holder, holder.begin():
        # SQL identifier is one of two fixed test parameters, never request data.
        await holder.execute(text("LOCK TABLE " + table + " IN ROW EXCLUSIVE MODE"))
        response = await f.inspection_client.get("/owned/release-operation", headers=credential)
        assert response.status_code == 409 and "operation" not in response.json()
    after = await f.inspection_client.get("/owned/release-operation", headers=credential)
    assert after.status_code == 200 and await retained(f) == before and not f.root.exists()


@pytest.mark.parametrize("change", ["disabled", "deleted", "organization", "role", "token-version", "key-revoked", "key-expired"])
async def test_late_real_account_or_credential_change_prevents_disclosure(inspected, monkeypatch, change):
    f = inspected
    await seed(f)
    credential = await lifecycle_probes.headers(f, "key" if change.startswith("key-") else "jwt")
    ready, proceed = asyncio.Event(), asyncio.Event()
    original = inspection._read_snapshot

    async def pause_after_owned_read(*args, **kwargs):
        result = await original(*args, **kwargs)
        ready.set()
        await proceed.wait()
        return result

    monkeypatch.setattr(inspection, "_read_snapshot", pause_after_owned_read)
    task = asyncio.create_task(f.inspection_client.get("/owned/release-operation", headers=credential))
    try:
        await asyncio.wait_for(ready.wait(), 10)
        async with AsyncSession(f.engine) as db, db.begin():
            if change.startswith("key-"):
                fields = {"is_active": False} if change == "key-revoked" else {"expires_at": datetime.now(UTC)-timedelta(seconds=1)}
                await db.execute(update(APIKey).where(APIKey.id == f.key_id).values(**fields))
            else:
                fields = {"disabled": {"is_active": False}, "deleted": {"deleted_at": datetime.now(UTC)},
                          "organization": {"organization_id": f.other_org}, "role": {"role": "viewer"},
                          "token-version": {"token_version": 18}}[change]
                await db.execute(update(User).where(User.id == f.user).values(**fields))
        before = await retained(f)
        proceed.set()
        response = await asyncio.wait_for(task, 10)
        assert response.status_code in (401, 403) and "operation" not in response.json()
        assert await retained(f) == before and not f.root.exists()
    finally:
        proceed.set()
        if not task.done():
            await asyncio.wait_for(task, 10)


@pytest.mark.parametrize("target", ["journal", "release"])
async def test_real_writer_waits_for_inspection_and_snapshot_does_not_predict_future(inspected, monkeypatch, record_property, target):
    f = inspected
    row = await seed(f)
    credential = await lifecycle_probes.headers(f)
    ready, proceed = asyncio.Event(), asyncio.Event()
    original = ReleaseMutationFence.recheck
    calls = 0

    async def pause_before_unlock(self):
        nonlocal calls
        await original(self)
        calls += 1
        if calls == 2:
            f.inspection_pid = await self.session.scalar(text("SELECT pg_backend_pid()"))
            ready.set()
            await proceed.wait()

    monkeypatch.setattr(ReleaseMutationFence, "recheck", pause_before_unlock)
    task = asyncio.create_task(f.inspection_client.get("/owned/release-operation", headers=credential))
    writer_task = None
    try:
        await asyncio.wait_for(ready.wait(), 10)
        async with f.engine.connect() as writer:
            writer_pid = await writer.scalar(text("SELECT pg_backend_pid()"))
            await writer.rollback()

            async def write_after_lock():
                async with AsyncSession(bind=writer) as db, db.begin():
                    if target == "release":
                        await add_release(db, row)
                    else:
                        await db.execute(update(AgentReleaseOperation).where(
                            AgentReleaseOperation.operation_id == row["operation_id"]
                        ).values(phase="prepared", transition_sequence=1, prepared_at=await db.scalar(text("SELECT clock_timestamp()"))))

            writer_task = asyncio.create_task(write_after_lock())
            async with f.engine.connect() as observer:
                async with asyncio.timeout(10):
                    while True:
                        assert not task.done() and not writer_task.done()
                        blockers = await observer.scalar(text("SELECT pg_blocking_pids(:pid)"), {"pid": writer_pid})
                        if blockers:
                            assert writer_pid != f.inspection_pid and f.inspection_pid in blockers
                            record_property("actual_writer_wait", True)
                            break
                        await asyncio.sleep(0.01)
            proceed.set()
            response = await asyncio.wait_for(task, 10)
            await asyncio.wait_for(writer_task, 10)
        assert response.status_code == 200
        assert response.json()["operation"]["phase"] == "reserved"
        assert response.json()["release_row_present"] is False
        fresh = await f.inspection_client.get("/owned/release-operation", headers=credential)
        assert fresh.status_code == 200
        assert fresh.json()["operation"]["phase"] == ("prepared" if target == "journal" else "reserved")
        assert fresh.json()["release_row_present"] is (target == "release")
    finally:
        proceed.set()
        if not task.done():
            await asyncio.wait_for(task, 10)
        if writer_task is not None and not writer_task.done():
            await asyncio.wait_for(writer_task, 10)


async def test_missing_database_table_is_unavailable_not_a_safe_absence(inspected):
    f = inspected
    await seed(f)
    credential = await lifecycle_probes.headers(f)
    before = await retained(f)
    async with f.engine.begin() as db:
        await db.execute(text("ALTER TABLE agents.agent_release_operations RENAME TO retained_owned_test_history"))
    try:
        response = await f.inspection_client.get("/owned/release-operation", headers=credential)
        assert response.status_code == 503 and "operation" not in response.json()
        assert not f.root.exists()
    finally:
        async with f.engine.begin() as db:
            await db.execute(text("ALTER TABLE agents.retained_owned_test_history RENAME TO agent_release_operations"))
    assert await retained(f) == before


@pytest.mark.parametrize("damage", ["missing-predecessor", "wrong-release-scope"])
async def test_actual_retained_association_conflict_never_grants_cleanup(inspected, damage):
    f = inspected
    if damage == "missing-predecessor":
        row = values(kind="delete", organization=f.org)
        async with f.engine.begin() as db:
            await db.execute(insert(AgentReleaseOperation).values(**row))
        f.operation_id = row["operation_id"]
    else:
        row = await seed(f, phase="decided", decision="published", live=True)
        async with f.engine.begin() as db:
            await db.execute(update(AgentRelease).where(AgentRelease.id == row["release_id"])
                             .values(organization_id=f.other_org))
    before = await retained(f)
    response = await f.inspection_client.get("/owned/release-operation", headers=await lifecycle_probes.headers(f))
    assert response.status_code == 409 and "operation" not in response.json()
    assert await retained(f) == before and not f.root.exists()

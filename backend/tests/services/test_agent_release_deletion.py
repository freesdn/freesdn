"""Planned real-PG/auth/ASGI deletion decisions, never runtime evidence.

Files belong only to the owned fixture. Deletion service must not touch them;
cleanup and replacement-after-retirement require their own later qualification.
"""

import asyncio
import hashlib
from contextlib import asynccontextmanager
from dataclasses import asdict, replace
from datetime import UTC, datetime
from uuid import uuid4

import httpx
import pytest
import pytest_asyncio
from fastapi import Depends, FastAPI, Request
from sqlalchemy import delete, insert, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import CurrentUser, get_current_user
from app.db.session import get_session
from app.main import app as product_app
from app.models.agent_release_operations import AgentReleaseOperation
from app.models.agents import AgentRelease
from app.models.api_keys import APIKey
from app.models.core import Organization, User
from app.services import agent_release_deletion as deletion
from app.services import agent_release_reservation as reservation_code
from app.services.agent_release_authority import ReleaseMutationAuthority
from app.services.agent_release_delete_request import ReleaseDeletionRequest
from app.services.agent_release_request import _encode
from tests.db.conftest import maintenance_engine as maintenance_engine
from tests.services import test_agent_release_preparation as preparation_probes
from tests.services import test_agent_release_publication as publication_probes
from tests.services import test_agent_release_reservation as reservation_probes
from tests.services import test_agent_signing_lifecycle as lifecycle_probes


def sample():
    return {"id": uuid4(), "organization_id": uuid4(), "version": "old", "platform": "Linux",
            "agent_type": "Daemon", "download_url": "/legacy/agent", "checksum_sha256": "A" * 64,
            "file_size": 5, "release_notes": "🦉" * 20000, "min_backend_version": "", "is_prerelease": False,
            "is_latest": True, "filename": "../untrusted-legacy-name", "signature": None,
            "published_at": datetime(2026, 1, 1, tzinfo=UTC), "download_count": 7}


def test_deletion_snapshot_binds_original_text_case_time_and_ignores_only_download_count():
    row = sample()
    request = ReleaseDeletionRequest.capture(operation_id=uuid4(), release=row)
    assert request.matches(row) and request.matches({**row, "download_count": 900})
    assert request.metadata()["platform"] == "linux" and request.metadata()["agent_type"] == "daemon"
    assert request.metadata()["filename"] == "../untrusted-legacy-name"
    assert len(request.request_bytes()) < 65536 and request.request_sha256() == hashlib.sha256(request.request_bytes()).hexdigest()
    assert not request.matches({**row, "platform": "linux"})
    assert not request.matches({**row, "is_latest": False})


@pytest.mark.parametrize("field,value", [("checksum_sha256", "unknown"), ("file_size", -1), ("file_size", True),
    ("file_size", 10737418241), ("is_latest", 1), ("platform", "unknown"), ("signature", "x" * 4097),
    ("published_at", "2026-01-01T00:00:00"), ("release_notes", "bad\x00text"), ("authorization", "unexpected")])
def test_unrepresentable_deletion_metadata_is_not_invented_or_truncated(field, value):
    request = ReleaseDeletionRequest.capture(operation_id=uuid4(), release=sample())
    metadata = request.metadata()
    metadata[field] = value
    with pytest.raises(ValueError):
        replace(request, metadata_bytes=_encode(metadata))


@pytest_asyncio.fixture
async def remover(maintenance_engine, monkeypatch, tmp_path):
    context = asynccontextmanager(publication_probes.publisher.__wrapped__)
    async with context(maintenance_engine, monkeypatch, tmp_path) as f:
        f.deletion = None
        f.deletion_action = "delete"
        app = FastAPI(exception_handlers=product_app.exception_handlers)

        async def request_session():
            async with AsyncSession(f.engine, expire_on_commit=False, autoflush=False) as db:
                yield db

        app.dependency_overrides[get_session] = request_session

        @app.post("/owned/release-deletion")
        async def execute(request: Request, user: CurrentUser = Depends(get_current_user)):
            authority = await ReleaseMutationAuthority.capture(request, user, secret_key=f.secret)
            result = await deletion.execute_release_deletion(authority=authority, request=f.deletion,
                                                               budget=f.budget, action=f.deletion_action)
            return asdict(result)

        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),
                                     base_url="http://test") as client:
            f.remover = client
            yield f


async def call(f, credential):
    return await f.remover.post("/owned/release-deletion", headers=credential)


async def target(f, credential, *, storage="owned", organization=None):
    if storage in ("owned", "external"):
        publication_probes.configure(f, storage=storage, organization=organization)
        await publication_probes.prepare_owned(f, credential)
        assert (await publication_probes.call(f, credential)).status_code == 200
        rid = f.publication.release_id
    else:
        rid = await publication_probes.seed(f, organization=organization)
        async with f.engine.begin() as db:
            await db.execute(update(AgentRelease).where(AgentRelease.id == rid).values(filename="../unverified-name"))
    row = next(r for r in await publication_probes.releases(f) if r["id"] == rid)
    f.deletion = ReleaseDeletionRequest.capture(operation_id=uuid4(), release=row)
    return row


async def state(f):
    return await publication_probes.releases(f), await reservation_probes.journal(f), preparation_probes.files(f)


async def delete_row(f):
    return next(r for r in await reservation_probes.journal(f) if r["operation_id"] == f.deletion.operation_id)


@pytest.mark.parametrize("kind", ["jwt", "key"])
@pytest.mark.parametrize("storage", ["owned", "external", "legacy"])
async def test_actual_deletion_commits_decision_but_preserves_all_file_bytes(remover, kind, storage):
    f = remover
    credential = await lifecycle_probes.headers(f, kind)
    await target(f, credential, storage=storage, organization=f.org)
    unrelated = await publication_probes.seed(f, organization=f.other_org)
    before_files = preparation_probes.files(f)
    response = await call(f, credential)
    rows, history, after_files = await state(f)
    assert response.status_code == 200 and response.json()["decision"] == "deleted"
    assert response.json()["newly_changed"] is True
    assert response.json()["bytes_removed"] is response.json()["cleanup_authorized"] is False
    assert response.json()["cleanup_disposition"] == {"owned": "pending-owned-verification", "external": "no-owned-file", "legacy": "retain-unverified"}[storage]
    assert [r["id"] for r in rows] == [unrelated] and after_files == before_files
    row = await delete_row(f)
    assert row["phase"] == "decided" and row["transition_sequence"] == 2 and row["cleaned_at"] is None
    assert row["storage_kind"] == storage and row["requested_by"] == f.user
    assert row["prepared_at"] <= row["decided_at"]
    observed = rows, history, after_files
    replay = await call(f, credential)
    assert replay.status_code == 200 and replay.json()["newly_changed"] is False and await state(f) == observed
    if storage == "owned":
        preparation_probes.verify_owned(f)
    await reservation_probes.assert_leases_free(f, f.deletion)


@pytest.mark.parametrize("stage", ["reserved", "deleted"])
async def test_actual_commit_ack_loss_never_removes_bytes_or_infers_failed_decision(remover, monkeypatch, stage):
    f = remover
    credential = await lifecycle_probes.headers(f)
    await target(f, credential, organization=f.org)
    before_files = preparation_probes.files(f)
    original = reservation_code._commit_phase
    fired = False

    async def lose_after_commit(db):
        nonlocal fired
        row = (await db.execute(select(AgentReleaseOperation.__table__).where(
            AgentReleaseOperation.operation_id == f.deletion.operation_id))).mappings().one_or_none()
        await original(db)
        if row is not None and not fired and (row["phase"] == stage or row["decision"] == stage):
            fired = True
            raise ConnectionError("Owned controlled exception after actual deletion commit")

    monkeypatch.setattr(reservation_code, "_commit_phase", lose_after_commit)
    response = await call(f, credential)
    assert fired and response.status_code == 503 and preparation_probes.files(f) == before_files
    row = await delete_row(f)
    assert row["decision"] == (None if stage == "reserved" else "deleted")
    assert bool(await publication_probes.releases(f)) is (stage == "reserved")
    assert (await call(f, credential)).status_code == 200
    assert (await delete_row(f))["decision"] == "deleted" and preparation_probes.files(f) == before_files
    preparation_probes.verify_owned(f)


@pytest.mark.parametrize("failure", ["delete", "decision"])
async def test_real_SQL_rejection_preserves_release_and_rolls_back_both_transitions(remover, failure):
    f = remover
    credential = await lifecycle_probes.headers(f)
    await target(f, credential, organization=f.org)
    before_rows = await publication_probes.releases(f)
    before_files = preparation_probes.files(f)
    async with f.engine.begin() as db:
        if failure == "delete":
            await db.execute(text("CREATE FUNCTION agents.owned_refuse_delete() RETURNS trigger LANGUAGE plpgsql AS $$ "
                                  "BEGIN RAISE EXCEPTION 'owned delete refusal'; END $$"))
            await db.execute(text("CREATE TRIGGER owned_refuse_delete AFTER DELETE ON agents.agent_releases "
                                  "FOR EACH ROW EXECUTE FUNCTION agents.owned_refuse_delete()"))
        else:
            await db.execute(text("CREATE FUNCTION agents.owned_refuse_delete() RETURNS trigger LANGUAGE plpgsql AS $$ "
                                  "BEGIN IF NEW.decision='deleted' THEN RAISE EXCEPTION 'owned decision refusal'; END IF; "
                                  "RETURN NEW; END $$"))
            await db.execute(text("CREATE TRIGGER owned_refuse_delete AFTER UPDATE ON agents.agent_release_operations "
                                  "FOR EACH ROW EXECUTE FUNCTION agents.owned_refuse_delete()"))
    response = await call(f, credential)
    assert response.status_code == 503 and await publication_probes.releases(f) == before_rows
    assert preparation_probes.files(f) == before_files
    row = await delete_row(f)
    assert row["phase"] == "reserved" and row["prepared_at"] is None and row["decision"] is None
    preparation_probes.verify_owned(f)


@pytest.mark.parametrize("stage", ["reserved", "prepared"])
async def test_cancelled_deletion_preserves_live_release_and_cannot_later_delete_it(remover, stage):
    f = remover
    credential = await lifecycle_probes.headers(f)
    await target(f, credential, organization=f.org)
    f.deletion_action = "reserve"
    assert (await call(f, credential)).status_code == 200
    if stage == "prepared":
        # Reservation timestamps come from PostgreSQL, whose clock can differ
        # from this native test process on a separate machine.
        async with f.engine.begin() as db:
            await db.execute(update(AgentReleaseOperation).where(
                AgentReleaseOperation.operation_id == f.deletion.operation_id
            ).values(phase="prepared", transition_sequence=1, prepared_at=await db.scalar(text("SELECT clock_timestamp()"))))
    rows, _, files = await state(f)
    f.deletion_action = "cancel"
    response = await call(f, credential)
    assert response.status_code == 200 and response.json()["cleanup_disposition"] == "preserve-live"
    assert await publication_probes.releases(f) == rows and preparation_probes.files(f) == files
    observed = await state(f)
    assert (await call(f, credential)).status_code == 200 and await state(f) == observed
    f.deletion_action = "delete"
    assert (await call(f, credential)).status_code == 409 and await state(f) == observed
    preparation_probes.verify_owned(f)


async def test_confirmed_retry_does_not_delete_a_later_replacement_row(remover):
    f = remover
    credential = await lifecycle_probes.headers(f)
    original = await target(f, credential, organization=f.org)
    assert (await call(f, credential)).status_code == 200
    async with f.engine.begin() as db:
        await db.execute(insert(AgentRelease).values(**{**original, "version": "later replacement", "download_count": 77}))
    before = await state(f)
    replay = await call(f, credential)
    assert replay.status_code == 200 and replay.json()["newly_changed"] is False and await state(f) == before
    assert replay.json()["cleanup_authorized"] is False


@pytest.mark.parametrize("change", ["version", "signature", "latest", "url", "owner", "deleted", "count-control"])
async def test_actual_target_change_after_reservation_is_rechecked_without_file_cleanup(remover, monkeypatch, change):
    f = remover
    credential = await lifecycle_probes.headers(f)
    await target(f, credential, organization=f.org)
    original = deletion._reserve
    ready, proceed = asyncio.Event(), asyncio.Event()

    async def hold(owner, budget):
        result = await original(owner, budget)
        ready.set()
        await proceed.wait()
        return result

    monkeypatch.setattr(deletion, "_reserve", hold)
    task = asyncio.create_task(call(f, credential))
    try:
        await asyncio.wait_for(ready.wait(), 10)
        async with f.engine.begin() as db:
            if change == "deleted":
                await db.execute(delete(AgentRelease).where(AgentRelease.id == f.deletion.release_id))
            else:
                values = {"version": {"version": "changed"}, "signature": {"signature": None},
                          "latest": {"is_latest": False}, "url": {"download_url": "/changed"},
                          "owner": {"organization_id": f.other_org}, "count-control": {"download_count": 44}}[change]
                await db.execute(update(AgentRelease).where(AgentRelease.id == f.deletion.release_id).values(**values))
        before = await state(f)
        proceed.set()
        response = await asyncio.wait_for(task, 10)
        if change == "count-control":
            assert response.status_code == 200 and await publication_probes.releases(f) == []
            assert preparation_probes.files(f) == before[2]
        else:
            assert response.status_code in (404, 409) and await state(f) == before
    finally:
        proceed.set()
        if not task.done():
            await asyncio.wait_for(task, 10)


@pytest.mark.parametrize("change", ["key-revoked", "role", "counter", "destination-inactive-control"])
async def test_actual_authority_change_after_reservation_and_retired_destination_policy(remover, monkeypatch, change):
    f = remover
    credential = await lifecycle_probes.headers(f, "key" if change == "key-revoked" else "jwt")
    await target(f, credential, organization=f.org)
    original = deletion._reserve

    async def alter_after_ack(owner, budget):
        result = await original(owner, budget)
        async with f.engine.begin() as db:
            if change == "key-revoked":
                await db.execute(update(APIKey).where(APIKey.id == f.key_id).values(is_active=False))
            elif change == "destination-inactive-control":
                await db.execute(update(Organization).where(Organization.id == f.org).values(is_active=False))
            else:
                await db.execute(update(User).where(User.id == f.user).values(
                    **({"role": "viewer"} if change == "role" else {"token_version": 101})))
        return result

    monkeypatch.setattr(deletion, "_reserve", alter_after_ack)
    files = preparation_probes.files(f)
    response = await call(f, credential)
    assert preparation_probes.files(f) == files
    if change == "destination-inactive-control":
        # Withdrawal does not activate or publish into the disabled destination.
        assert response.status_code == 200 and await publication_probes.releases(f) == []
    else:
        assert response.status_code in (401, 403) and len(await publication_probes.releases(f)) == 1
        assert (await delete_row(f))["phase"] == "reserved"


@pytest.mark.parametrize("mode", ["tenant-jwt", "scoped-platform-key", "unscoped-platform-key"])
async def test_actual_deletion_permission_ceiling_applies_to_reviewed_target(remover, mode):
    f = remover
    await target(f, await lifecycle_probes.headers(f), organization=f.other_org)
    async with f.engine.begin() as db:
        if mode == "tenant-jwt":
            await db.execute(update(User).where(User.id == f.user).values(role="org_admin"))
        elif mode == "scoped-platform-key":
            await db.execute(update(APIKey).where(APIKey.id == f.key_id).values(scopes=["agent:admin"]))
    before = await state(f)
    response = await call(f, await lifecycle_probes.headers(f, "jwt" if mode == "tenant-jwt" else "key"))
    assert response.status_code == (200 if mode == "unscoped-platform-key" else 404)
    if mode != "unscoped-platform-key":
        assert await state(f) == before
    else:
        assert preparation_probes.files(f) == before[2]


async def test_independent_connection_observes_no_half_deletion_before_commit(remover, monkeypatch, record_property):
    f = remover
    credential = await lifecycle_probes.headers(f)
    await target(f, credential, organization=f.org)
    original = reservation_code._commit_phase
    ready, proceed = asyncio.Event(), asyncio.Event()

    async def hold(db):
        decision = await db.scalar(select(AgentReleaseOperation.decision).where(
            AgentReleaseOperation.operation_id == f.deletion.operation_id))
        if decision == "deleted":
            f.deleting_pid = await db.scalar(text("SELECT pg_backend_pid()"))
            ready.set()
            await proceed.wait()
        await original(db)

    monkeypatch.setattr(reservation_code, "_commit_phase", hold)
    task = asyncio.create_task(call(f, credential))
    try:
        await asyncio.wait_for(ready.wait(), 10)
        async with f.engine.connect() as db:
            assert await db.scalar(text("SELECT pg_backend_pid()")) != f.deleting_pid
            assert await db.scalar(select(AgentRelease.id).where(AgentRelease.id == f.deletion.release_id)) == f.deletion.release_id
            assert await db.scalar(select(AgentReleaseOperation.phase).where(
                AgentReleaseOperation.operation_id == f.deletion.operation_id)) == "reserved"
            record_property("deletion_uncommitted_state_not_visible_on_independent_connection", True)
        proceed.set()
        assert (await asyncio.wait_for(task, 10)).status_code == 200
    finally:
        proceed.set()
        if not task.done():
            await asyncio.wait_for(task, 10)


@pytest.mark.parametrize("action", ["delete", "cancel"])
async def test_missing_target_or_operation_never_fabricates_a_deletion_decision(remover, action):
    f = remover
    f.deletion = ReleaseDeletionRequest.capture(operation_id=uuid4(), release=sample())
    f.deletion_action = action
    before = await state(f)
    response = await call(f, await lifecycle_probes.headers(f))
    assert response.status_code == 404 and await state(f) == before


@pytest.mark.parametrize("location", ["/legacy/agent", "agent.bin", "file:///tmp/owned", "https:///invalid"])
async def test_unknown_legacy_locations_are_retained_without_path_resolution(remover, location):
    f = remover
    credential = await lifecycle_probes.headers(f)
    rid = await publication_probes.seed(f, organization=f.org)
    async with f.engine.begin() as db:
        await db.execute(update(AgentRelease).where(AgentRelease.id == rid).values(filename=None, download_url=location))
    row = next(r for r in await publication_probes.releases(f) if r["id"] == rid)
    f.deletion = ReleaseDeletionRequest.capture(operation_id=uuid4(), release=row)
    response = await call(f, credential)
    assert response.status_code == 200 and response.json()["cleanup_disposition"] == "retain-unverified"
    assert (await delete_row(f))["artifact_id"] is None and preparation_probes.files(f) == {}

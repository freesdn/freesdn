"""Planned real-PG/native-guard/auth/file cleanup integration, not runtime proof.

Only isolated owned artifacts and keys are created by the future fixture. All
source guards, first outcomes and previous test bytes remain unchanged.
"""

import asyncio
import hashlib
import threading
from contextlib import asynccontextmanager
from dataclasses import asdict, replace
from datetime import UTC, datetime
from uuid import uuid4

import httpx
import pytest
import pytest_asyncio
from fastapi import Depends, FastAPI, Request
from sqlalchemy import insert, select, text, update
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import CurrentUser, get_current_user
from app.db.session import get_session
from app.main import app as product_app
from app.models.agent_release_operations import AgentReleaseOperation
from app.models.agents import AgentRelease
from app.models.api_keys import APIKey
from app.models.core import User
from app.services import agent_release_cleanup_coordinator as cleanup_code
from app.services import agent_release_reservation as reservation_code
from app.services.agent_release_artifact_store import ArtifactBusy, ArtifactLease
from app.services.agent_release_authority import ReleaseMutationAuthority
from app.services.agent_release_preparation import _intent
from app.services.agent_release_reference_validation import validate_release_reference_installation
from app.services.agent_release_request import ReleaseReservationBudget, _encode
from tests.db.conftest import maintenance_engine as maintenance_engine
from tests.db.conftest import run_alembic
from tests.services import test_agent_release_deletion as deletion_probes
from tests.services import test_agent_release_preparation as preparation_probes
from tests.services import test_agent_release_publication as publication_probes
from tests.services import test_agent_release_reservation as reservation_probes
from tests.services import test_agent_signing_lifecycle as lifecycle_probes


@pytest_asyncio.fixture
async def cleaner(maintenance_engine, monkeypatch, tmp_path):
    context = asynccontextmanager(deletion_probes.remover.__wrapped__)
    async with context(maintenance_engine, monkeypatch, tmp_path) as f:
        await asyncio.to_thread(run_alembic, f.engine.url, "upgrade", "027_agent_release_references")
        f.cleanup_request = None
        f.cleanup_root = None
        app = FastAPI(exception_handlers=product_app.exception_handlers)

        async def request_session():
            async with AsyncSession(f.engine, expire_on_commit=False, autoflush=False) as db:
                yield db

        app.dependency_overrides[get_session] = request_session

        @app.post("/owned/release-cleanup")
        async def execute(request: Request, user: CurrentUser = Depends(get_current_user)):
            authority = await ReleaseMutationAuthority.capture(request, user, secret_key=f.secret)
            result = await cleanup_code.execute_release_cleanup(
                authority=authority, request=f.cleanup_request, root=f.cleanup_root,
            )
            return asdict(result)

        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),
                                     base_url="http://test") as client:
            f.cleaner = client
            yield f


async def call(f, credential):
    return await f.cleaner.post("/owned/release-cleanup", headers=credential)


async def operation(f):
    return next(r for r in await reservation_probes.journal(f) if r["operation_id"] == f.cleanup_request.operation_id)


def payload(f):
    return f.artifacts / str(f.publication.operation_id) / "payload"


async def prepare(f, credential, scenario="owned-delete"):
    if scenario in ("owned-cancel", "external-cancel", "missing-cancel"):
        publication_probes.configure(f, organization=f.org, storage="external" if scenario == "external-cancel" else "owned")
        if scenario == "owned-cancel":
            assert (await preparation_probes.call(f, credential)).status_code == 200
        else:
            f.action = "reserve"
            assert (await reservation_probes.call(f, credential)).status_code == 200
        f.action = "cancel"
        assert (await reservation_probes.call(f, credential)).status_code == 200
        f.cleanup_request = f.publication
        f.cleanup_root = None if scenario == "external-cancel" else str(f.artifacts)
    else:
        storage = {"owned-delete": "owned", "external-delete": "external", "legacy-delete": "legacy", "delete-cancel": "owned"}[scenario]
        await deletion_probes.target(f, credential, storage=storage, organization=f.org)
        if scenario == "delete-cancel":
            f.deletion_action = "reserve"
            assert (await deletion_probes.call(f, credential)).status_code == 200
            f.deletion_action = "cancel"
        assert (await deletion_probes.call(f, credential)).status_code == 200
        f.cleanup_request = f.deletion
        f.cleanup_root = str(f.artifacts) if scenario == "owned-delete" else None


@pytest.mark.parametrize("kind", ["jwt", "key"])
@pytest.mark.parametrize("scenario", ["owned-delete", "owned-cancel", "external-delete", "external-cancel", "delete-cancel", "legacy-delete"])
async def test_actual_cleanup_dispositions_preserve_or_remove_only_owned_payload(cleaner, kind, scenario):
    f = cleaner
    credential = await lifecycle_probes.headers(f, kind)
    await prepare(f, credential, scenario)
    unrelated = f.artifacts / "unrelated-evidence"
    unrelated.write_bytes(b"preserve other owned evidence")
    before = preparation_probes.files(f)
    response = await call(f, credential)
    row = await operation(f)
    assert response.status_code == 200 and not response.json()["authorization_granted"]
    assert unrelated.read_bytes() == b"preserve other owned evidence"
    owned = scenario in ("owned-delete", "owned-cancel")
    complete = scenario != "legacy-delete"
    assert response.json()["complete"] is complete
    assert response.json()["payload_absence_verified_this_call"] is owned
    assert row["phase"] == ("cleaned" if complete else "decided")
    if owned:
        assert not payload(f).exists()
        for name in ("intent.json", "retired.json", "cleaned.json"):
            assert (payload(f).parent / name).is_file()
    else:
        assert preparation_probes.files(f) == before
    stable = await deletion_probes.state(f)
    replay = await call(f, credential)
    assert replay.status_code == 200 and not replay.json()["newly_recorded"]
    assert await deletion_probes.state(f) == stable
    await reservation_probes.assert_leases_free(f, f.cleanup_request)


@pytest.mark.parametrize("stage", ["missing", "reserved", "prepared", "published"])
async def test_unconfirmed_operations_never_start_storage_cleanup(cleaner, stage):
    f = cleaner
    credential = await lifecycle_probes.headers(f)
    publication_probes.configure(f, organization=f.org)
    f.cleanup_request, f.cleanup_root = f.publication, str(f.artifacts)
    if stage == "reserved":
        assert (await reservation_probes.call(f, credential)).status_code == 200
    elif stage in ("prepared", "published"):
        assert (await preparation_probes.call(f, credential)).status_code == 200
        if stage == "published":
            assert (await publication_probes.call(f, credential)).status_code == 200
    before = await deletion_probes.state(f)
    response = await call(f, credential)
    assert response.status_code == (404 if stage == "missing" else 409)
    assert await deletion_probes.state(f) == before


async def test_cancelled_missing_object_is_not_fabricated_or_marked_complete(cleaner):
    f = cleaner
    credential = await lifecycle_probes.headers(f)
    await prepare(f, credential, "missing-cancel")
    before = await deletion_probes.state(f)
    response = await call(f, credential)
    assert response.status_code == 503 and await deletion_probes.state(f) == before
    assert not payload(f).parent.exists() and (await operation(f))["phase"] == "decided"


@pytest.mark.parametrize("timing", ["before-commit", "after-commit"])
async def test_cleanup_ack_uncertainty_preserves_file_history_and_exact_explicit_retry(cleaner, monkeypatch, timing):
    f = cleaner
    credential = await lifecycle_probes.headers(f)
    await prepare(f, credential)
    original = reservation_code._commit_phase
    fired = False

    async def uncertain(db):
        nonlocal fired
        phase = await db.scalar(select(AgentReleaseOperation.phase).where(
            AgentReleaseOperation.operation_id == f.cleanup_request.operation_id))
        fault = phase == "cleaned" and not fired
        if fault:
            fired = True
            if timing == "before-commit":
                raise ConnectionError("Owned controlled precommit exception")
        await original(db)
        if fault:
            raise ConnectionError("Owned controlled lost postcommit acknowledgment")

    monkeypatch.setattr(reservation_code, "_commit_phase", uncertain)
    response = await call(f, credential)
    assert fired and response.status_code == 503 and not payload(f).exists()
    assert (await operation(f))["phase"] == ("cleaned" if timing == "after-commit" else "decided")
    files = preparation_probes.files(f)
    retry = await call(f, credential)
    assert retry.status_code == 200 and retry.json()["complete"]
    assert preparation_probes.files(f) == files and (await operation(f))["phase"] == "cleaned"


async def test_late_real_SQL_rejection_cannot_recreate_removed_bytes(cleaner, monkeypatch):
    f = cleaner
    credential = await lifecycle_probes.headers(f)
    await prepare(f, credential)
    async with f.engine.begin() as db:
        await db.execute(text("CREATE TABLE public.owned_cleanup_rejection(value integer CHECK(value > 0))"))
    original = reservation_code._commit_phase
    fired = False

    async def reject(db):
        nonlocal fired
        phase = await db.scalar(select(AgentReleaseOperation.phase).where(
            AgentReleaseOperation.operation_id == f.cleanup_request.operation_id))
        if phase == "cleaned" and not fired:
            fired = True
            # Actual PostgreSQL constraint error inside the transaction AFTER
            # cleanup SQL, not an application exception replacing DB behavior.
            await db.execute(text("INSERT INTO public.owned_cleanup_rejection VALUES(-1)"))
        await original(db)

    monkeypatch.setattr(reservation_code, "_commit_phase", reject)
    response = await call(f, credential)
    assert fired and response.status_code == 503 and not payload(f).exists()
    assert (await operation(f))["phase"] == "decided"
    files = preparation_probes.files(f)
    assert (await call(f, credential)).status_code == 200
    assert preparation_probes.files(f) == files and (await operation(f))["phase"] == "cleaned"


@pytest.mark.parametrize("stage", ["after-retire", "before-cleanup", "after-cleanup"])
async def test_controlled_worker_boundary_failures_preserve_retryable_decision(cleaner, monkeypatch, stage):
    f = cleaner
    credential = await lifecycle_probes.headers(f)
    await prepare(f, credential)
    original = cleanup_code._CleanupStorage.run
    fired = False

    async def fail(storage, method, decision):
        nonlocal fired
        if not fired and stage == "before-cleanup" and method == "cleanup_retired":
            fired = True
            raise OSError("Owned controlled pre-cleanup boundary")
        result = await original(storage, method, decision)
        if not fired and ((stage == "after-retire" and method == "retire")
                          or (stage == "after-cleanup" and method == "cleanup_retired")):
            fired = True
            raise OSError("Owned controlled post-worker boundary")
        return result

    monkeypatch.setattr(cleanup_code._CleanupStorage, "run", fail)
    response = await call(f, credential)
    assert fired and response.status_code == 503 and (await operation(f))["phase"] == "decided"
    assert payload(f).exists() is (stage != "after-cleanup")
    assert (await call(f, credential)).status_code == 200
    assert not payload(f).exists() and (await operation(f))["phase"] == "cleaned"


@pytest.mark.parametrize("stage", ["retire", "cleanup_retired"])
@pytest.mark.parametrize("change", ["key", "counter", "role", "organization"])
async def test_actual_late_authority_change_stops_next_phase_and_keeps_true_file_outcome(cleaner, monkeypatch, stage, change):
    f = cleaner
    credential = await lifecycle_probes.headers(f, "key" if change == "key" else "jwt")
    await prepare(f, credential)
    original = cleanup_code._CleanupStorage.run
    fired = False

    async def alter(storage, method, decision):
        nonlocal fired
        result = await original(storage, method, decision)
        if method == stage and not fired:
            fired = True
            async with f.engine.begin() as db:
                if change == "key":
                    await db.execute(update(APIKey).where(APIKey.id == f.key_id).values(is_active=False))
                else:
                    values = {"counter": {"token_version": 101}, "role": {"role": "viewer"},
                              "organization": {"organization_id": f.other_org}}[change]
                    await db.execute(update(User).where(User.id == f.user).values(**values))
        return result

    monkeypatch.setattr(cleanup_code._CleanupStorage, "run", alter)
    response = await call(f, credential)
    assert fired and response.status_code in (401, 403)
    assert payload(f).exists() is (stage == "retire")
    assert (await operation(f))["phase"] == "decided"


@pytest.mark.parametrize("drift", ["new-trigger", "immutable-trigger", "birth-index", "function"])
async def test_native_guard_drift_after_retirement_prevents_unlink(cleaner, monkeypatch, drift):
    f = cleaner
    credential = await lifecycle_probes.headers(f)
    await prepare(f, credential)
    original = cleanup_code._CleanupStorage.run
    fired = False

    async def alter(storage, method, decision):
        nonlocal fired
        result = await original(storage, method, decision)
        if method == "retire" and not fired:
            fired = True
            statement = {
                "new-trigger": "ALTER TABLE agents.agent_releases DISABLE TRIGGER release_reference_deferred",
                "immutable-trigger": "ALTER TABLE agents.agent_release_operations DISABLE TRIGGER guard_release_operation",
                "birth-index": "DROP INDEX agents.uq_release_operation_owned_object",
                "function": "ALTER FUNCTION agents.check_release_references() SECURITY DEFINER",
            }[drift]
            async with f.engine.begin() as db:
                await db.execute(text(statement))
        return result

    monkeypatch.setattr(cleanup_code._CleanupStorage, "run", alter)
    response = await call(f, credential)
    assert fired and response.status_code == 503
    assert payload(f).read_bytes() == f.data and (await operation(f))["phase"] == "decided"


async def test_actual_reinsertion_between_retirement_and_unlink_is_refused(cleaner, monkeypatch, record_property):
    f = cleaner
    credential = await lifecycle_probes.headers(f)
    row = await deletion_probes.target(f, credential, organization=f.org)
    assert (await deletion_probes.call(f, credential)).status_code == 200
    f.cleanup_request, f.cleanup_root = f.deletion, str(f.artifacts)
    original = cleanup_code._CleanupStorage.run
    checked = False

    async def attempt(storage, method, decision):
        nonlocal checked
        result = await original(storage, method, decision)
        if method == "retire":
            with pytest.raises(DBAPIError) as caught:
                async with f.engine.begin() as db:
                    await db.execute(insert(AgentRelease).values(**row))
            assert getattr(caught.value.orig, "sqlstate", None) == "23514"
            assert payload(f).read_bytes() == f.data
            checked = True
            record_property("reference_recreation_refused_between_retirement_and_unlink", True)
        return result

    monkeypatch.setattr(cleanup_code._CleanupStorage, "run", attempt)
    response = await call(f, credential)
    assert checked and response.status_code == 200 and not payload(f).exists()


async def test_replacement_payload_after_completed_cleanup_is_preserved_and_refused(cleaner):
    f = cleaner
    credential = await lifecycle_probes.headers(f)
    await prepare(f, credential)
    assert (await call(f, credential)).status_code == 200
    payload(f).write_bytes(b"unrelated replacement")
    payload(f).chmod(0o600)
    before = await deletion_probes.state(f)
    response = await call(f, credential)
    assert response.status_code == 409 and await deletion_probes.state(f) == before


async def test_another_pending_owned_operation_after_retirement_prevents_unlink(cleaner, monkeypatch):
    f = cleaner
    credential = await lifecycle_probes.headers(f)
    await prepare(f, credential)
    publication = next(r for r in await reservation_probes.journal(f) if r["kind"] == "publish")
    pending = {**publication, "operation_id": uuid4(), "kind": "delete", "phase": "reserved",
               "decision": None, "transition_sequence": 0, "prepared_at": None, "decided_at": None,
               "cleaned_at": None, "created_at": datetime.now(UTC)}
    original = cleanup_code._CleanupStorage.run
    fired = False

    async def add_pending(storage, method, decision):
        nonlocal fired
        result = await original(storage, method, decision)
        if method == "retire" and not fired:
            fired = True
            async with f.engine.begin() as db:
                await db.execute(insert(AgentReleaseOperation).values(**pending))
        return result

    monkeypatch.setattr(cleanup_code._CleanupStorage, "run", add_pending)
    response = await call(f, credential)
    assert fired and response.status_code == 409 and payload(f).read_bytes() == f.data
    assert (await operation(f))["phase"] == "decided"


async def test_old_database_revision_cannot_enable_file_cleanup(cleaner):
    f = cleaner
    await asyncio.to_thread(run_alembic, f.engine.url, "downgrade", "026_agent_release_size")
    credential = await lifecycle_probes.headers(f)
    await prepare(f, credential)
    before = await deletion_probes.state(f)
    response = await call(f, credential)
    assert response.status_code == 503 and await deletion_probes.state(f) == before


@pytest.mark.parametrize("scenario", ["pending-delete", "cancelled-delete", "deleted-cleaned", "cancelled-publish-cleaned"])
async def test_declared_capacity_releases_only_exact_completed_payload_cleanup(cleaner, scenario):
    f = cleaner
    credential = await lifecycle_probes.headers(f)
    await prepare(f, credential, "delete-cancel" if scenario == "cancelled-delete"
                  else "owned-cancel" if scenario == "cancelled-publish-cleaned" else "owned-delete")
    if scenario != "pending-delete":
        assert (await call(f, credential)).status_code == 200
    prior = await reservation_probes.journal(f)
    f.budget = ReleaseReservationBudget(100, 100, len(f.data), len(f.data))
    f.publication = reservation_probes.request_for(f.org, size=len(f.data))
    f.action = "reserve"
    response = await reservation_probes.call(f, credential)
    released = scenario in ("deleted-cleaned", "cancelled-publish-cleaned")
    assert response.status_code == (200 if released else 409)
    current = await reservation_probes.journal(f)
    assert all(row in current for row in prior)
    assert len(current) == len(prior) + int(released)


@pytest.mark.parametrize("scope", ["same-organization", "different-organization"])
async def test_capacity_keeps_other_live_publication_and_counts_completed_birth_only_once(cleaner, scope):
    f = cleaner
    credential = await lifecycle_probes.headers(f)
    await prepare(f, credential)
    first_request = f.cleanup_request
    second = reservation_probes.request_for(f.org if scope == "same-organization" else f.other_org, size=len(f.data))
    metadata = second.metadata()
    metadata["checksum_sha256"] = hashlib.sha256(f.data).hexdigest()
    f.publication = replace(second, metadata_bytes=_encode(metadata))
    await publication_probes.prepare_owned(f, credential)
    assert (await publication_probes.call(f, credential)).status_code == 200
    other_files = {k: v for k, v in preparation_probes.files(f).items() if k.startswith(str(second.operation_id))}
    assert other_files
    f.cleanup_request = first_request
    assert (await call(f, credential)).status_code == 200
    assert {k: v for k, v in preparation_probes.files(f).items() if k.startswith(str(second.operation_id))} == other_files
    f.budget = ReleaseReservationBudget(100, 100, len(f.data), len(f.data))
    f.publication = reservation_probes.request_for(f.org, size=1)
    f.action = "reserve"
    before = await reservation_probes.journal(f)
    response = await reservation_probes.call(f, credential)
    # The other organization's bytes still consume global capacity.
    assert response.status_code == 409 and await reservation_probes.journal(f) == before


@pytest.mark.parametrize("configuration", ["valid", "no-locks", "journal-only", "release-only", "snapshot", "replica"])
async def test_native_inspection_requires_actual_origin_current_transaction_and_both_fences(cleaner, configuration):
    f = cleaner
    async with f.engine.begin() as db:
        if configuration == "snapshot":
            await db.execute(text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ"))
        if configuration == "replica":
            await db.execute(text("SET LOCAL session_replication_role = replica"))
        if configuration not in ("no-locks", "release-only"):
            await db.execute(text("LOCK TABLE agents.agent_release_operations IN SHARE ROW EXCLUSIVE MODE NOWAIT"))
        if configuration not in ("no-locks", "journal-only"):
            await db.execute(text("LOCK TABLE agents.agent_releases IN SHARE MODE NOWAIT"))
        if configuration == "valid":
            assert await db.run_sync(validate_release_reference_installation) is None
        else:
            with pytest.raises(RuntimeError):
                await db.run_sync(validate_release_reference_installation)
    assert await reservation_probes.journal(f) == []


@pytest.mark.parametrize("failure", ["request-cancel", "connection-loss"])
async def test_filesystem_worker_drains_before_cleanup_ownership_is_released(cleaner, monkeypatch, failure, record_property):
    f = cleaner
    credential = await lifecycle_probes.headers(f)
    await prepare(f, credential)
    captured = None
    state_original = cleanup_code._state

    async def capture(owner):
        nonlocal captured
        captured = owner
        return await state_original(owner)

    monkeypatch.setattr(cleanup_code, "_state", capture)
    entered, proceed = threading.Event(), threading.Event()
    original = ArtifactLease.cleanup_retired

    def hold(lease, decision):
        entered.set()
        if not proceed.wait(10):
            raise RuntimeError("Owned cleanup worker release was not signalled")
        return original(lease, decision)

    monkeypatch.setattr(ArtifactLease, "cleanup_retired", hold)
    task = asyncio.create_task(call(f, credential))
    try:
        assert await asyncio.to_thread(entered.wait, 10) and captured is not None
        if failure == "request-cancel":
            task.cancel()
        else:
            await captured.connection.invalidate()
        with pytest.raises(ArtifactBusy):
            ArtifactLease.acquire(str(f.artifacts), _intent(f.publication), mode="shared")
        assert payload(f).exists()
        record_property("cleanup_worker_retains_exclusive_file_lifetime_until_drain", True)
        proceed.set()
        if failure == "request-cancel":
            with pytest.raises(asyncio.CancelledError):
                await task
        else:
            assert (await asyncio.wait_for(task, 10)).status_code == 503
        assert not payload(f).exists()
    finally:
        proceed.set()
        if not task.done():
            try:
                await asyncio.wait_for(task, 10)
            except asyncio.CancelledError:
                pass
    monkeypatch.setattr(ArtifactLease, "cleanup_retired", original)
    assert (await call(f, credential)).status_code == 200
    assert (await operation(f))["phase"] == "cleaned"

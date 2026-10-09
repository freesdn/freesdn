"""Planned actual-PG/auth/signing/ASGI/file atomic publication contracts.

Uncollected/unexecuted. Owned key initialization is part of the future fixture;
no deployed keys, external URL, browser or hardware is accessed. Controlled
commit exceptions do not establish packet-loss or crash behavior.
"""

import asyncio
from contextlib import asynccontextmanager
from dataclasses import asdict, replace
from datetime import UTC, datetime, timedelta
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
from app.models.agent_signing import AgentSigningIdentity
from app.models.agents import AgentRelease
from app.models.api_keys import APIKey
from app.models.core import Organization, User
from app.services import agent_release_publication as publication
from app.services import agent_release_reservation as reservation_code
from app.services.agent_release_authority import ReleaseMutationAuthority
from app.services.agent_release_request import _encode
from app.services.release_signing import build_release_manifest
from app.services.release_signing_async import verify_manifest_async
from tests.db.conftest import maintenance_engine as maintenance_engine
from tests.services import test_agent_release_preparation as preparation_probes
from tests.services import test_agent_release_reservation as reservation_probes
from tests.services import test_agent_signing_lifecycle as lifecycle_probes


@pytest_asyncio.fixture
async def publisher(maintenance_engine, monkeypatch, tmp_path):
    context = asynccontextmanager(preparation_probes.prepared.__wrapped__)
    async with context(maintenance_engine, monkeypatch, tmp_path) as f:
        response = await f.lifecycle_client.post("/owned/signing-lifecycle", headers=await lifecycle_probes.headers(f))
        assert response.status_code == 200 and response.json()["state"] == "activated"
        app = FastAPI(exception_handlers=product_app.exception_handlers)

        async def request_session():
            async with AsyncSession(f.engine, expire_on_commit=False, autoflush=False) as db:
                yield db

        app.dependency_overrides[get_session] = request_session

        @app.post("/owned/release-publication")
        async def execute(request: Request, user: CurrentUser = Depends(get_current_user)):
            authority = await ReleaseMutationAuthority.capture(request, user, secret_key=f.secret)
            result = await publication.execute_release_publication(
                authority=authority, request=f.publication, budget=f.budget,
                root=str(f.artifacts) if f.publication.storage_kind == "owned" else None,
            )
            return asdict(result)

        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),
                                     base_url="http://test") as client:
            f.publisher = client
            yield f


def configure(f, *, storage="owned", organization=None, latest=True, notes="full notes", size=None):
    metadata = f.publication.metadata()
    metadata.update(is_latest=latest, release_notes=notes)
    if storage == "external":
        metadata.update(download_url="https://artifacts.example.invalid/agent", filename=None)
    if size is not None:
        metadata["file_size"] = size
    f.publication = replace(f.publication, storage_kind=storage,
                            organization_id=organization, metadata_bytes=_encode(metadata))


async def call(f, credential):
    return await f.publisher.post("/owned/release-publication", headers=credential)


async def prepare_owned(f, credential):
    if f.publication.storage_kind == "owned":
        assert (await preparation_probes.call(f, credential)).status_code == 200


async def releases(f):
    async with AsyncSession(f.engine) as db:
        return [dict(r) for r in (await db.execute(select(AgentRelease.__table__).order_by(AgentRelease.id))).mappings()]


async def seed(f, *, organization, version="older", platform="linux", latest=True):
    identity = uuid4()
    async with f.engine.begin() as db:
        await db.execute(insert(AgentRelease).values(id=identity, organization_id=organization,
                         version=version, platform=platform, agent_type="daemon", download_url="/legacy/control",
                         checksum_sha256="b" * 64, file_size=5, signature=None, is_latest=latest,
                         is_prerelease=False, release_notes="control", min_backend_version="", download_count=0))
    return identity


@pytest.mark.parametrize("credential_kind", ["jwt", "key"])
@pytest.mark.parametrize("storage", ["owned", "external"])
@pytest.mark.parametrize("scope", ["global", "organization", "scoped-key"])
async def test_atomic_publication_preserves_real_scope_and_signs_actual_manifest(publisher, credential_kind, storage, scope):
    f = publisher
    if scope == "organization":
        async with f.engine.begin() as db:
            await db.execute(update(User).where(User.id == f.user).values(role="org_admin"))
    if scope == "scoped-key":
        async with f.engine.begin() as db:
            await db.execute(update(APIKey).where(APIKey.id == f.key_id).values(scopes=["agent:admin"]))
    organization = None if scope == "global" else f.org
    configure(f, storage=storage, organization=organization, notes="🦉" * 20000)
    credential = await lifecycle_probes.headers(f, credential_kind)
    old = await seed(f, organization=organization)
    other_org = await seed(f, organization=f.other_org)
    other_platform = await seed(f, organization=organization, platform="windows")
    await prepare_owned(f, credential)
    files_before = preparation_probes.files(f)
    response = await call(f, credential)
    state = {r["id"]: r for r in await releases(f)}
    journal = await reservation_probes.journal(f)
    assert response.status_code == 200 and response.json()["newly_published"] is True
    assert response.json()["signature_verified_this_call"] is True
    assert response.json()["artifact_verified_this_call"] is (storage == "owned")
    assert response.json()["publication_or_storage_authorized"] is False
    assert state[f.publication.release_id]["is_latest"] and not state[old]["is_latest"]
    assert state[other_org]["is_latest"] and state[other_platform]["is_latest"]
    row = state[f.publication.release_id]
    assert row["organization_id"] == organization and row["release_notes"] == "🦉" * 20000
    assert row["file_size"] == 5 and row["download_count"] == 0
    assert len(journal) == 1 and journal[0]["phase"] == "decided" and journal[0]["decision"] == "published"
    assert journal[0]["transition_sequence"] == 2 and journal[0]["prepared_at"] <= journal[0]["decided_at"]
    manifest = build_release_manifest(digest_hex=row["checksum_sha256"], version=row["version"],
                                     platform=row["platform"], agent_type=row["agent_type"], channel="stable")
    assert await verify_manifest_async(manifest, row["signature"]) is not None
    assert preparation_probes.files(f) == files_before
    await reservation_probes.assert_leases_free(f, f.publication)


@pytest.mark.parametrize("storage", ["owned", "external"])
async def test_actual_published_commit_ack_exception_never_unlinks_or_repeats_publication(publisher, monkeypatch, storage):
    f = publisher
    configure(f, storage=storage, organization=f.org)
    credential = await lifecycle_probes.headers(f)
    await prepare_owned(f, credential)
    original = reservation_code._commit_phase
    triggered = False

    async def commit_then_fail(db):
        nonlocal triggered
        decision = await db.scalar(select(AgentReleaseOperation.decision).where(
            AgentReleaseOperation.operation_id == f.publication.operation_id
        ))
        await original(db)
        if decision == "published" and not triggered:
            triggered = True
            raise ConnectionError("Owned exception after actual published commit")

    monkeypatch.setattr(reservation_code, "_commit_phase", commit_then_fail)
    response = await call(f, credential)
    observed = await releases(f), await reservation_probes.journal(f), preparation_probes.files(f)
    assert triggered and response.status_code == 503
    assert len(observed[0]) == 1 and observed[1][0]["decision"] == "published"

    async def must_not_resign(_request):
        raise AssertionError("A confirmed retry must not sign or republish")

    monkeypatch.setattr(publication, "_signature", must_not_resign)
    retried = await call(f, credential)
    assert retried.status_code == 200 and retried.json()["newly_published"] is False
    assert retried.json()["artifact_verified_this_call"] is retried.json()["signature_verified_this_call"] is False
    assert (await releases(f), await reservation_probes.journal(f), preparation_probes.files(f)) == observed
    if storage == "owned":
        preparation_probes.verify_owned(f)


@pytest.mark.parametrize("storage", ["owned", "external"])
@pytest.mark.parametrize("failure", ["insert", "decision"])
async def test_real_SQL_rejection_rolls_back_latest_row_and_journal_together(publisher, storage, failure):
    f = publisher
    configure(f, storage=storage, organization=f.org)
    credential = await lifecycle_probes.headers(f)
    old = await seed(f, organization=f.org)
    await prepare_owned(f, credential)
    before = await releases(f), preparation_probes.files(f)
    async with f.engine.begin() as db:
        if failure == "insert":
            await db.execute(text("CREATE FUNCTION agents.owned_refuse_publish() RETURNS trigger LANGUAGE plpgsql AS $$ "
                                  "BEGIN RAISE EXCEPTION 'owned insert refusal'; END $$"))
            await db.execute(text("CREATE TRIGGER owned_refuse_publish AFTER INSERT ON agents.agent_releases "
                                  "FOR EACH ROW EXECUTE FUNCTION agents.owned_refuse_publish()"))
        else:
            await db.execute(text("CREATE FUNCTION agents.owned_refuse_publish() RETURNS trigger LANGUAGE plpgsql AS $$ "
                                  "BEGIN IF NEW.decision='published' THEN RAISE EXCEPTION 'owned decision refusal'; END IF; "
                                  "RETURN NEW; END $$"))
            await db.execute(text("CREATE TRIGGER owned_refuse_publish AFTER UPDATE ON agents.agent_release_operations "
                                  "FOR EACH ROW EXECUTE FUNCTION agents.owned_refuse_publish()"))
    response = await call(f, credential)
    rows, journal = await releases(f), await reservation_probes.journal(f)
    assert response.status_code == 503 and (rows, preparation_probes.files(f)) == before
    assert next(row for row in rows if row["id"] == old)["is_latest"]
    assert journal[0]["phase"] == ("prepared" if storage == "owned" else "reserved")
    assert journal[0]["decision"] is None
    if storage == "owned":
        preparation_probes.verify_owned(f)
    await reservation_probes.assert_leases_free(f, f.publication)


@pytest.mark.parametrize("storage", ["owned", "external"])
async def test_observer_cannot_see_half_publication_before_actual_commit(publisher, monkeypatch, record_property, storage):
    f = publisher
    configure(f, storage=storage, organization=f.org)
    credential = await lifecycle_probes.headers(f)
    old = await seed(f, organization=f.org)
    await prepare_owned(f, credential)
    ready, proceed = asyncio.Event(), asyncio.Event()
    original = reservation_code._commit_phase

    async def hold_before_commit(db):
        decision = await db.scalar(select(AgentReleaseOperation.decision).where(
            AgentReleaseOperation.operation_id == f.publication.operation_id
        ))
        if decision == "published":
            f.owner_pid = await db.scalar(text("SELECT pg_backend_pid()"))
            ready.set()
            await proceed.wait()
        await original(db)

    monkeypatch.setattr(reservation_code, "_commit_phase", hold_before_commit)
    task = asyncio.create_task(call(f, credential))
    try:
        await asyncio.wait_for(ready.wait(), 10)
        async with f.engine.connect() as db:
            assert await db.scalar(text("SELECT pg_backend_pid()")) != f.owner_pid
            assert await db.scalar(select(AgentRelease.is_latest).where(AgentRelease.id == old)) is True
            assert await db.scalar(select(AgentRelease.id).where(AgentRelease.id == f.publication.release_id)) is None
            assert await db.scalar(select(AgentReleaseOperation.decision).where(
                AgentReleaseOperation.operation_id == f.publication.operation_id)) is None
            record_property("publication_uncommitted_state_not_visible_on_independent_connection", True)
        proceed.set()
        assert (await asyncio.wait_for(task, 10)).status_code == 200
    finally:
        proceed.set()
        if not task.done():
            await asyncio.wait_for(task, 10)


@pytest.mark.parametrize("change", ["disabled", "deleted", "role", "counter", "key-revoked", "key-expired", "destination-inactive", "destination-deleted"])
async def test_actual_changes_after_signing_refuse_final_mutation(publisher, monkeypatch, change):
    f = publisher
    configure(f, organization=f.org)
    credential = await lifecycle_probes.headers(f, "key" if change.startswith("key-") else "jwt")
    await seed(f, organization=f.org)
    await prepare_owned(f, credential)
    ready, proceed = asyncio.Event(), asyncio.Event()
    original = publication._signature

    async def held(request):
        result = await original(request)
        ready.set()
        await proceed.wait()
        return result

    monkeypatch.setattr(publication, "_signature", held)
    task = asyncio.create_task(call(f, credential))
    try:
        await asyncio.wait_for(ready.wait(), 10)
        async with f.engine.begin() as db:
            if change.startswith("destination-"):
                fields = {"is_active": False} if change.endswith("inactive") else {"deleted_at": datetime.now(UTC)}
                await db.execute(update(Organization).where(Organization.id == f.org).values(**fields))
            elif change.startswith("key-"):
                fields = {"is_active": False} if change.endswith("revoked") else {"expires_at": datetime.now(UTC)-timedelta(seconds=1)}
                await db.execute(update(APIKey).where(APIKey.id == f.key_id).values(**fields))
            else:
                fields = {"disabled": {"is_active": False}, "deleted": {"deleted_at": datetime.now(UTC)},
                          "role": {"role": "viewer"}, "counter": {"token_version": 100}}[change]
                await db.execute(update(User).where(User.id == f.user).values(**fields))
        before = await releases(f), await reservation_probes.journal(f), preparation_probes.files(f)
        proceed.set()
        response = await asyncio.wait_for(task, 10)
        assert response.status_code in (401, 403, 404)
        assert (await releases(f), await reservation_probes.journal(f), preparation_probes.files(f)) == before
    finally:
        proceed.set()
        if not task.done():
            await asyncio.wait_for(task, 10)


@pytest.mark.parametrize("later", ["another-latest", "row-deleted", "download-count"])
async def test_confirmed_retry_does_not_recreate_repromote_or_reset_later_state(publisher, monkeypatch, later):
    f = publisher
    configure(f, organization=f.org)
    credential = await lifecycle_probes.headers(f)
    await prepare_owned(f, credential)
    assert (await call(f, credential)).status_code == 200
    async with f.engine.begin() as db:
        if later == "row-deleted":
            await db.execute(delete(AgentRelease).where(AgentRelease.id == f.publication.release_id))
        else:
            await db.execute(update(AgentRelease).where(AgentRelease.id == f.publication.release_id).values(
                **({"is_latest": False} if later == "another-latest" else {"download_count": 77})))
    if later == "another-latest":
        await seed(f, organization=f.org, version="later")
    before = await releases(f), await reservation_probes.journal(f), preparation_probes.files(f)

    async def never(_request):
        raise AssertionError("Historical retry must not sign")

    monkeypatch.setattr(publication, "_signature", never)
    response = await call(f, credential)
    assert response.status_code == 200 and response.json()["newly_published"] is False
    assert response.json()["release_row_present"] is (later != "row-deleted")
    assert (await releases(f), await reservation_probes.journal(f), preparation_probes.files(f)) == before


@pytest.mark.parametrize("storage,latest,expected", [("owned", True, 503), ("owned", False, 200), ("external", True, 503), ("external", False, 503)])
async def test_actual_private_key_loss_preserves_explicit_unsigned_upload_policy(publisher, storage, latest, expected):
    f = publisher
    configure(f, storage=storage, organization=f.org, latest=latest)
    credential = await lifecycle_probes.headers(f)
    await prepare_owned(f, credential)
    # Only this owned fixture's key file; never any installation/deployed key.
    (f.root / ".signing-key.pem").unlink()
    before = await lifecycle_probes.snapshot(f), preparation_probes.files(f)
    response = await call(f, credential)
    assert response.status_code == expected and preparation_probes.files(f) == before[1]
    assert (await lifecycle_probes.snapshot(f))[2] == before[0][2]
    rows = await releases(f)
    if expected == 200:
        assert len(rows) == 1 and rows[0]["signature"] is None and rows[0]["is_latest"] is False
        assert response.json()["signature_verified_this_call"] is False
    else:
        assert rows == [] and (await reservation_probes.journal(f))[0]["decision"] is None


async def test_external_size_compatibility_keeps_ten_gib_without_claiming_file_verification(publisher):
    f = publisher
    configure(f, storage="external", organization=f.org, size=10737418240)
    response = await call(f, await lifecycle_probes.headers(f))
    assert response.status_code == 200 and response.json()["artifact_verified_this_call"] is False
    assert (await releases(f))[0]["file_size"] == 10737418240 and preparation_probes.files(f) == {}


@pytest.mark.parametrize("damage", ["missing", "replaced", "cancelled"])
async def test_unavailable_or_cancelled_owned_artifact_never_creates_release(publisher, damage):
    f = publisher
    configure(f, organization=f.org)
    credential = await lifecycle_probes.headers(f)
    await prepare_owned(f, credential)
    path = f.artifacts / str(f.publication.operation_id) / "payload"
    if damage == "missing":
        path.unlink()
    elif damage == "replaced":
        path.unlink()
        path.write_bytes(f.data)
        path.chmod(0o600)
    else:
        f.action = "cancel"
        assert (await reservation_probes.call(f, credential)).status_code == 200
    before = await releases(f), await reservation_probes.journal(f), preparation_probes.files(f)
    response = await call(f, credential)
    assert response.status_code in (409, 503)
    assert (await releases(f), await reservation_probes.journal(f), preparation_probes.files(f)) == before


@pytest.mark.parametrize("fault", ["invalid-signature", "unexpected-exception"])
async def test_unexpected_signing_fault_is_not_downgraded_to_unsigned(publisher, monkeypatch, fault):
    f = publisher
    configure(f, organization=f.org, latest=False)
    credential = await lifecycle_probes.headers(f)
    await prepare_owned(f, credential)

    async def broken(_manifest):
        if fault == "unexpected-exception":
            raise RuntimeError("Owned unexpected signer exception")
        return "A" * 100  # Bounded but invalid DER; the actual verifier must reject.

    monkeypatch.setattr(publication, "sign_manifest_async", broken)
    before = await releases(f), await reservation_probes.journal(f), preparation_probes.files(f)
    response = await call(f, credential)
    assert response.status_code == 503
    assert (await releases(f), await reservation_probes.journal(f), preparation_probes.files(f)) == before


@pytest.mark.parametrize("change", ["conflicting-release", "identity-row-lock"])
async def test_final_real_SQL_state_is_checked_after_signature_work(publisher, monkeypatch, change):
    f = publisher
    configure(f, organization=f.org)
    credential = await lifecycle_probes.headers(f)
    await prepare_owned(f, credential)
    ready, proceed = asyncio.Event(), asyncio.Event()
    original = publication._signature

    async def held(request):
        result = await original(request)
        ready.set()
        await proceed.wait()
        return result

    monkeypatch.setattr(publication, "_signature", held)
    task = asyncio.create_task(call(f, credential))
    try:
        await asyncio.wait_for(ready.wait(), 10)
        async with f.engine.connect() as holder, holder.begin():
            if change == "identity-row-lock":
                await holder.execute(select(AgentSigningIdentity.singleton_id).where(
                    AgentSigningIdentity.singleton_id == 1).with_for_update())
            else:
                await holder.execute(insert(AgentRelease).values(id=f.publication.release_id,
                    organization_id=f.org, version="conflict", platform="linux", agent_type="daemon",
                    download_url="/unrelated", checksum_sha256="c" * 64, file_size=3,
                    is_latest=False, is_prerelease=False, release_notes="other writer", min_backend_version=""))
                await holder.commit()
            before = await releases(f), await reservation_probes.journal(f), preparation_probes.files(f)
            proceed.set()
            response = await asyncio.wait_for(task, 10)
            assert response.status_code == (409 if change == "conflicting-release" else 503)
            assert (await releases(f), await reservation_probes.journal(f), preparation_probes.files(f)) == before
    finally:
        proceed.set()
        if not task.done():
            await asyncio.wait_for(task, 10)

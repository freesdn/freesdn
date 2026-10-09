"""AFTER-only consumer/enrollment contracts on owned PostgreSQL and files.

No runtime outcome is claimed. Actual routers, authentication, SQL and signing
are used in the design; parent fixture Redis/session limitations remain explicit.
"""

import asyncio
import base64
import hashlib
from contextlib import asynccontextmanager
from uuid import UUID, uuid4

import httpx
import pytest
import pytest_asyncio
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import FastAPI, HTTPException
from sqlalchemy import delete, select, text, update
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.endpoints import agent_downloads, agent_release_upload, agents
from app.api.v1.endpoints.agent_release_operations import (
    ReleaseOperationPolicy,
    create_release_operation_router,
)
from app.db.session import get_session
from app.main import app as product_app
from app.models.agent_signing import AgentSigningEnrollment
from app.models.agents import AgentRelease, RemoteAgent
from app.models.core import Site, User
from app.schemas.agent_downloads import AgentReleaseCreate
from app.schemas.agent_release_operations import encode_release_command
from app.services import agent_signing_lifecycle as lifecycle
from app.services.agent_release_request import ReleasePublicationRequest, ReleaseReservationBudget
from app.services.release_signing import build_release_manifest, canonical_manifest_bytes
from tests.db.conftest import maintenance_engine as maintenance_engine
from tests.db.conftest import run_alembic
from tests.services import test_agent_release_upload_stream as stream
from tests.services import test_agent_signing_lifecycle as lifecycle_probes
from tests.services import test_agent_signing_operator as operator_probes


@pytest_asyncio.fixture
async def consumers(maintenance_engine, monkeypatch, tmp_path):
    context = asynccontextmanager(operator_probes.operator.__wrapped__)
    async with context(maintenance_engine, monkeypatch, tmp_path) as f:
        await asyncio.to_thread(run_alembic, f.engine.url, "upgrade", "027_agent_release_references")
        f.site = uuid4()
        f.binary_root = tmp_path / "owned-binaries"
        f.binary_root.mkdir(mode=0o700)
        monkeypatch.setenv("FREESDN_AGENT_RELEASE_DIR", str(f.binary_root))
        async with AsyncSession(f.engine) as db, db.begin():
            db.add(Site(id=f.site, organization_id=f.org, name="Owned signing site", slug=uuid4().hex))
        app = FastAPI(exception_handlers=product_app.exception_handlers)
        # Specific release routes before the generic /{agent_id} paths.
        app.include_router(agent_release_upload.router, prefix="/api/v1/agents")
        app.include_router(agent_downloads.router, prefix="/api/v1/agents")
        app.include_router(agents.router, prefix="/api/v1/agents")
        app.include_router(create_release_operation_router(ReleaseOperationPolicy(
            root=str(f.binary_root), budget=ReleaseReservationBudget(100, 100, 1073741824, 1073741824),
        )), prefix="/api/v1/agents")

        async def request_session():
            async with AsyncSession(f.engine, expire_on_commit=False, autoflush=False) as db:
                yield db

        app.dependency_overrides[get_session] = request_session
        try:
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),
                                         base_url="http://test") as client:
                f.consumers = client
                yield f
        finally:
            async with AsyncSession(f.engine) as db, db.begin():
                # Actual agent lifecycle deletion must cascade pins; do not
                # disable a pin guard to make owned fixture cleanup succeed.
                await db.execute(delete(RemoteAgent).where(RemoteAgent.organization_id == f.org))
                await db.execute(delete(Site).where(Site.id == f.site))


async def initialize(f):
    headers = await lifecycle_probes.headers(f)
    result = await f.operator_client.post(operator_probes.PREFIX + "/execute-local", headers=headers,
                                         json=operator_probes.execute_body(f))
    assert result.status_code == 200 and result.json()["state"] == "activated"
    return headers


async def enroll(f, headers):
    return await f.consumers.post("/api/v1/agents/register", headers=headers,
                                  json={"name": "Owned agent", "site_id": str(f.site), "agent_type": "site"})


async def enrollment_rows(f):
    async with AsyncSession(f.engine) as db:
        agents_rows = (await db.execute(select(RemoteAgent.id).where(RemoteAgent.organization_id == f.org))).scalars().all()
        pins = [dict(row) for row in (await db.execute(select(AgentSigningEnrollment.__table__))).mappings()]
    return agents_rows, pins


@pytest.mark.parametrize("legacy_files", [False, True])
async def test_public_key_without_trusted_record_never_provisions_or_adopts(consumers, legacy_files):
    f = consumers
    if legacy_files:
        lifecycle_probes.pair(f)
    before = await lifecycle_probes.snapshot(f)
    result = await f.consumers.get("/api/v1/agents/releases/public-key")
    assert result.status_code == 503 and await lifecycle_probes.snapshot(f) == before
    assert f.root.exists() is legacy_files


@pytest.mark.parametrize("lost", ["private", "public", "all"])
async def test_public_distribution_survives_private_storage_loss_without_repair(consumers, lost):
    f = consumers
    await initialize(f)
    trusted = (f.root / ".public-key.pem").read_bytes()
    before = await lifecycle_probes.snapshot(f)
    names = {"private": [".signing-key.pem"], "public": [".public-key.pem"], "all": list(before[2])}[lost]
    for name in names:
        (f.root / name).unlink()
    damaged = await lifecycle_probes.snapshot(f)
    result = await f.consumers.get("/api/v1/agents/releases/public-key")
    assert result.status_code == 200 and result.content == trusted
    assert await lifecycle_probes.snapshot(f) == damaged


async def retained_command(f, headers, action):
    intent = f.publication
    return await f.consumers.post(f"/api/v1/agents/release-operations/{intent.operation_id}/{action}",
        headers={**headers, "Content-Type": "application/json"}, content=encode_release_command(intent))


async def publish(f, headers, route):
    release_id = uuid4()
    async with AsyncSession(f.engine) as db:
        role = await db.scalar(select(User.role).where(User.id == f.user))
    external = route == "url"
    payload = AgentReleaseCreate(version="1.2.3", platform="Linux", agent_type="Daemon",
        download_url="https://downloads.example.invalid/owned-agent" if external else f"/api/v1/agents/releases/{release_id}/binary",
        checksum_sha256="AB"*32 if external else hashlib.sha256(b"owned").hexdigest(), file_size=5)
    f.publication = ReleasePublicationRequest.create(operation_id=uuid4(), release_id=release_id,
        organization_id=None if role == "super_admin" else f.org, storage_kind="external" if external else "owned",
        payload=payload, is_latest=True, filename=None if external else "owned-agent")
    reserved = await retained_command(f, headers, "reserve")
    assert reserved.status_code == 200
    if not external:
        response = await f.consumers.post(f"/api/v1/agents/release-operations/{f.publication.operation_id}/upload",
            headers={**headers, "Content-Type": stream.CONTENT_TYPE},
            content=stream.prefix(f.publication) + b"owned" + stream.suffix())
        assert response.status_code == 200 and response.json()["result"]["phase"] == "prepared"
    return await retained_command(f, headers, "publish")


@pytest.mark.parametrize("route", ["url", "upload"])
@pytest.mark.parametrize("role", ["super_admin", "org_admin"])
async def test_actual_publish_routes_sign_under_the_trusted_identity_and_keep_org_scope(consumers, route, role):
    f = consumers
    await initialize(f)
    if role != "super_admin":
        async with AsyncSession(f.engine) as db, db.begin():
            await db.execute(update(User).where(User.id == f.user).values(role=role))
    headers = await lifecycle_probes.headers(f)
    result = await publish(f, headers, route)
    assert result.status_code == 200
    async with AsyncSession(f.engine) as db:
        rows = (await db.execute(select(AgentRelease))).scalars().all()
        assert len(rows) == 1
        row = rows[0]
        assert row.organization_id == (None if role == "super_admin" else f.org)
        assert row.platform == "linux" and row.agent_type == "daemon"
        expected = "ab"*32 if route == "url" else hashlib.sha256(b"owned").hexdigest()
        assert row.checksum_sha256 == expected and row.is_latest
        signature = base64.b64decode(row.signature, validate=True)
        manifest = build_release_manifest(digest_hex=expected, version="1.2.3", platform="linux",
                                          agent_type="daemon", channel="stable")
    public = (await f.consumers.get("/api/v1/agents/releases/public-key")).content
    key = serialization.load_pem_public_key(public)
    key.verify(signature, canonical_manifest_bytes(manifest), ec.ECDSA(hashes.SHA256()))


@pytest.mark.parametrize("route", ["url", "upload"])
@pytest.mark.parametrize("storage", ["private_missing", "all_missing", "foreign_private", "valid"])
async def test_publish_never_replaces_missing_or_wrong_private_identity(consumers, route, storage):
    f = consumers
    headers = await initialize(f)
    if storage == "private_missing":
        (f.root / ".signing-key.pem").unlink()
    elif storage == "all_missing":
        for path in f.root.iterdir():
            if path.is_file():
                path.unlink()
    elif storage == "foreign_private":
        foreign = ec.generate_private_key(ec.SECP256R1()).private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
        (f.root / ".signing-key.pem").write_bytes(foreign)
    damaged = await lifecycle_probes.snapshot(f)
    result = await publish(f, headers, route)
    async with AsyncSession(f.engine) as db:
        releases = (await db.execute(select(AgentRelease.id))).scalars().all()
    assert result.status_code == (200 if storage == "valid" else 503)
    assert len(releases) == (1 if storage == "valid" else 0)
    assert (await lifecycle_probes.snapshot(f))[2] == damaged[2]
    if storage != "valid":
        # Failed signing preserves the acknowledged operation and prepared
        # payload. Remove it only through an explicit same-intent decision.
        cancelled = await retained_command(f, headers, "cancel")
        assert cancelled.status_code == 200 and cancelled.json()["result"]["decision"] == "cancelled"
        cleaned = await retained_command(f, headers, "cleanup")
        assert cleaned.status_code == 200 and cleaned.json()["result"]["complete"]
        assert not list(f.binary_root.glob("*/payload"))
        async with AsyncSession(f.engine) as db:
            assert not (await db.execute(select(AgentRelease.id))).scalars().all()
        assert (await lifecycle_probes.snapshot(f))[2] == damaged[2]


@pytest.mark.parametrize("kind", ["jwt", "key"])
@pytest.mark.parametrize("role", ["super_admin", "org_admin"])
async def test_enrollment_pin_and_credential_commit_together(consumers, kind, role):
    f = consumers
    await initialize(f)
    async with AsyncSession(f.engine) as db, db.begin():
        await db.execute(update(User).where(User.id == f.user).values(role=role))
    result = await enroll(f, await lifecycle_probes.headers(f, kind))
    assert result.status_code == 200
    body = result.json()
    ids, pins = await enrollment_rows(f)
    assert ids == [UUID(body["agent_id"])] and len(pins) == 1
    pin = pins[0]
    assert pin["agent_id"] == ids[0] and pin["enrolled_by"] == f.user
    assert pin["installation_id"] == f.command.installation_id and pin["identity_epoch"] == 1
    assert pin["public_key_sha256"] == body["release_key_sha256"] == hashlib.sha256((f.root/".public-key.pem").read_bytes()).hexdigest()
    assert body["agent_key"] not in str(pin)


@pytest.mark.parametrize("kind", ["jwt", "key"])
@pytest.mark.parametrize("state", ["absent", "pending", "legacy_files"])
async def test_untrusted_enrollment_never_commits_an_agent_credential(consumers, monkeypatch, kind, state):
    f = consumers
    if state == "legacy_files":
        lifecycle_probes.pair(f)
    elif state == "pending":
        original = lifecycle._phase

        async def after_pending(*args, **kwargs):
            value = await original(*args, **kwargs)
            if isinstance(value, tuple):
                raise HTTPException(503, "Owned interruption after pending commit")
            return value

        monkeypatch.setattr(lifecycle, "_phase", after_pending)
        response = await f.operator_client.post(operator_probes.PREFIX+"/execute-local",
            headers=await lifecycle_probes.headers(f), json=operator_probes.execute_body(f))
        assert response.status_code == 503
    before = await lifecycle_probes.snapshot(f)
    result = await enroll(f, await lifecycle_probes.headers(f, kind))
    assert result.status_code == 503 and "agent_key" not in result.text
    assert await enrollment_rows(f) == ([], []) and await lifecycle_probes.snapshot(f) == before


@pytest.mark.parametrize("kind", ["jwt", "key"])
async def test_late_actual_pin_insert_error_rolls_back_new_agent(consumers, kind):
    f = consumers
    await initialize(f)
    async with AsyncSession(f.engine) as db, db.begin():
        await db.execute(text("""CREATE FUNCTION agents.owned_pin_failure() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN RAISE EXCEPTION 'Owned pin INSERT failure' USING ERRCODE='23514'; END $$"""))
        await db.execute(text("""CREATE TRIGGER zz_owned_pin_failure BEFORE INSERT ON agents.agent_signing_enrollments
            FOR EACH ROW EXECUTE FUNCTION agents.owned_pin_failure()"""))
    result = await enroll(f, await lifecycle_probes.headers(f, kind))
    assert result.status_code == 500 and "agent_key" not in result.text
    assert await enrollment_rows(f) == ([], [])


@pytest.mark.parametrize("mutation", ["fingerprint", "installation", "epoch", "delete", "truncate"])
async def test_existing_pin_cannot_be_rewritten_or_removed_independently(consumers, mutation):
    f = consumers
    headers = await initialize(f)
    assert (await enroll(f, headers)).status_code == 200
    before = await enrollment_rows(f)
    async with AsyncSession(f.engine) as db:
        with pytest.raises(DBAPIError):
            async with db.begin():
                if mutation == "delete":
                    await db.execute(delete(AgentSigningEnrollment))
                elif mutation == "truncate":
                    await db.execute(text("TRUNCATE agents.agent_signing_enrollments"))
                else:
                    values = {"fingerprint": {"public_key_sha256": "a"*64},
                              "installation": {"installation_id": uuid4()}, "epoch": {"identity_epoch": 2}}[mutation]
                    await db.execute(update(AgentSigningEnrollment).values(**values))
    assert await enrollment_rows(f) == before
    async with AsyncSession(f.engine) as db, db.begin():
        await db.execute(delete(RemoteAgent).where(RemoteAgent.id == before[0][0]))
    assert await enrollment_rows(f) == ([], [])


async def test_empty_schema_round_trip_and_no_legacy_agent_pin_backfill(consumers):
    f = consumers
    await asyncio.to_thread(run_alembic, f.engine.url, "downgrade", "023_agent_signing_identity")
    async with AsyncSession(f.engine) as db, db.begin():
        db.add(RemoteAgent(id=uuid4(), organization_id=f.org, site_id=f.site, name="Owned legacy agent",
                           agent_key=hashlib.sha256(uuid4().bytes).hexdigest(), agent_type="site"))
    await asyncio.to_thread(run_alembic, f.engine.url, "upgrade", "024_agent_signing_enrollment")
    ids, pins = await enrollment_rows(f)
    assert len(ids) == 1 and pins == []
    assert (await f.consumers.get("/api/v1/agents/releases/public-key")).status_code == 503


async def test_downgrade_with_a_retained_pin_refuses_and_preserves_rows(consumers):
    f = consumers
    headers = await initialize(f)
    assert (await enroll(f, headers)).status_code == 200
    before = await enrollment_rows(f)
    result = await asyncio.to_thread(run_alembic, f.engine.url, "downgrade", "023_agent_signing_identity", expect_success=False)
    assert result.returncode != 0 and "Enrollment downgrade refused" in result.stderr
    assert await enrollment_rows(f) == before


@pytest.mark.parametrize("drift", ["disabled_trigger", "nullable_pin", "dropped_check", "changed_function"])
async def test_upgrade_refuses_preexisting_schema_drift_instead_of_repairing_it(consumers, drift):
    f = consumers
    statements = {
        "disabled_trigger": "ALTER TABLE agents.agent_signing_enrollments DISABLE TRIGGER guard_signing_enrollment",
        "nullable_pin": "ALTER TABLE agents.agent_signing_enrollments ALTER COLUMN public_key_sha256 DROP NOT NULL",
        "dropped_check": "ALTER TABLE agents.agent_signing_enrollments DROP CONSTRAINT ck_agent_signing_enrollments_fingerprint",
        "changed_function": "ALTER FUNCTION agents.guard_signing_enrollment() SECURITY DEFINER",
    }
    async with AsyncSession(f.engine) as db, db.begin():
        await db.execute(text(statements[drift]))
    await asyncio.to_thread(run_alembic, f.engine.url, "stamp", "023_agent_signing_identity")
    result = await asyncio.to_thread(run_alembic, f.engine.url, "upgrade", "024_agent_signing_enrollment", expect_success=False)
    assert result.returncode != 0
    assert "Enrollment" in result.stderr and ("differs" in result.stderr or "refused" in result.stderr)

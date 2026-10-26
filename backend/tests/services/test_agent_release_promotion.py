"""AFTER-only promotion contracts; source prepared, no runtime result claimed.

Owned PostgreSQL, real authentication/routers/manifest crypto. Parent Redis and
seeded-session limits remain. No external artifact fetch or hardware acceptance.
"""
import asyncio
import base64
import hashlib
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import httpx
import pytest
import pytest_asyncio
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import FastAPI
from sqlalchemy import delete, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.endpoints import agent_downloads, agent_release_upload, agents
from app.api.v1.endpoints.agent_release_operations import (
    ReleaseOperationPolicy,
    create_release_operation_router,
)
from app.core.security import verify_token
from app.core.token_blacklist import blacklist_token
from app.db.session import get_session
from app.main import app as product_app
from app.models.agent_release_operations import AgentReleaseOperation
from app.models.agents import AgentRelease
from app.models.api_keys import APIKey
from app.models.core import User, UserSession
from app.schemas.agent_downloads import AgentReleaseCreate
from app.services import agent_release_promotion as promotion_service
from app.services import agent_release_publication as publication_service
from app.services.agent_release_request import ReleasePublicationRequest, ReleaseReservationBudget
from app.services.release_signing import build_release_manifest, canonical_manifest_bytes
from app.services.release_signing_async import sign_manifest_async
from tests.db.conftest import maintenance_engine as maintenance_engine
from tests.harness_wait import HARNESS_WAIT_SECONDS
from tests.services import test_agent_release_upload_stream as stream
from tests.services import test_agent_signing_consumers as consumer_probes
from tests.services import test_agent_signing_lifecycle as lifecycle_probes


@pytest_asyncio.fixture
async def promotion(maintenance_engine, monkeypatch, tmp_path):
    context = asynccontextmanager(consumer_probes.consumers.__wrapped__)
    async with context(maintenance_engine, monkeypatch, tmp_path) as f:
        await consumer_probes.initialize(f)
        f.request_pids = []
        app = FastAPI(exception_handlers=product_app.exception_handlers)
        for router in [agent_release_upload.router, agent_downloads.router, agents.router]:
            app.include_router(router, prefix="/api/v1/agents")
        app.include_router(create_release_operation_router(ReleaseOperationPolicy(
            root=str(f.binary_root), budget=ReleaseReservationBudget(100, 100, 1073741824, 1073741824),
        )), prefix="/api/v1/agents")

        async def request_session():
            # Session commits never release this pinned physical request connection.
            async with f.engine.connect() as connection:
                f.request_pids.append(await connection.scalar(text("SELECT pg_backend_pid()")))
                await connection.rollback()
                async with AsyncSession(bind=connection, expire_on_commit=False, autoflush=False) as db:
                    yield db

        app.dependency_overrides[get_session] = request_session
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),
                                     base_url="http://test") as client:
            f.promoter = client
            yield f


async def prepare_for_busy_bucket(f, headers, route):
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
    reserved = await consumer_probes.retained_command(f, headers, "reserve")
    assert reserved.status_code == 200
    if not external:
        response = await f.consumers.post(f"/api/v1/agents/release-operations/{f.publication.operation_id}/upload",
            headers={**headers, "Content-Type": stream.CONTENT_TYPE},
            content=stream.prefix(f.publication) + b"owned" + stream.suffix())
        assert response.status_code == 200 and response.json()["result"]["phase"] == "prepared"


async def assert_retained_and_explicitly_cleanup(f, route):
    # A failed publication cannot erase acknowledged journal or owned bytes.
    async with AsyncSession(f.engine) as db:
        row = (await db.execute(select(AgentReleaseOperation.__table__).where(
            AgentReleaseOperation.operation_id == f.publication.operation_id,
        ))).mappings().one()
    assert row["decision"] is None
    assert row["phase"] == ("prepared" if route == "upload" else "reserved")
    payloads = list(f.binary_root.glob("*/payload"))
    assert [p.read_bytes() for p in payloads] == ([b"owned"] if route == "upload" else [])
    # Fresh API-key requests recapture the current account counter. Do not
    # rewind the mutated account or reuse the rejected in-flight authority.
    fresh = await lifecycle_probes.headers(f, "key")
    cancelled = await consumer_probes.retained_command(f, fresh, "cancel")
    assert cancelled.status_code == 200 and cancelled.json()["result"]["decision"] == "cancelled"
    cleaned = await consumer_probes.retained_command(f, fresh, "cleanup")
    assert cleaned.status_code == 200 and cleaned.json()["result"]["complete"] is True
    assert not list(f.binary_root.glob("*/payload"))


async def seed(f, *, organization=None, version="1.2.0", latest=False):
    manifest = build_release_manifest(digest_hex="a"*64, version=version, platform="linux", agent_type="daemon", channel="stable")
    signature = await sign_manifest_async(manifest)
    rid = uuid4()
    async with AsyncSession(f.engine) as db, db.begin():
        db.add(AgentRelease(id=rid, version=version, platform="linux", agent_type="daemon", download_url="https://artifacts.example.invalid/agent",
                            checksum_sha256="a"*64, signature=signature, organization_id=organization, is_latest=latest,
                            is_prerelease=False, file_size=5, release_notes="Owned fixture", min_backend_version="", download_count=0))
    return rid


async def rows(f):
    async with AsyncSession(f.engine) as db:
        return [dict(r) for r in (await db.execute(select(AgentRelease.__table__).order_by(AgentRelease.id))).mappings()]


async def promote(f, rid, headers):
    return await f.promoter.patch(f"/api/v1/agents/releases/{rid}/promote", headers=headers)


async def wait_for_target(f, task, holder_pid, record_property):
    async with AsyncSession(f.engine) as observer, asyncio.timeout(HARNESS_WAIT_SECONDS):
        while True:
            assert not task.done(), "Request did not reach its actual target-row wait"
            for pid in f.request_pids:
                if holder_pid in await observer.scalar(text("SELECT pg_blocking_pids(:pid)"), {"pid": pid}):
                    assert pid != holder_pid
                    record_property("genuine_target_row_wait", True)
                    return
            await asyncio.sleep(0.01)


@pytest.mark.parametrize("kind", ["jwt", "key"])
@pytest.mark.parametrize("scope", ["global", "organization", "scoped_key"])
async def test_valid_signature_promotes_only_its_bucket(promotion, kind, scope):
    f = promotion
    if scope == "organization":
        async with AsyncSession(f.engine) as db, db.begin():
            await db.execute(update(User).where(User.id == f.user).values(role="org_admin"))
    if scope == "scoped_key":
        # JWT remains unscoped; this control still promotes an own-org target.
        async with AsyncSession(f.engine) as db, db.begin():
            await db.execute(update(APIKey).where(APIKey.id == f.key_id).values(scopes=["agent:admin"]))
    org = None if scope == "global" else f.org
    old = await seed(f, organization=org, version="1.0.0", latest=True)
    target = await seed(f, organization=org)
    untouched = await seed(f, organization=f.other_org, latest=True)
    before = await lifecycle_probes.snapshot(f)
    result = await promote(f, target, await lifecycle_probes.headers(f, kind))
    state = {r["id"]: r for r in await rows(f)}
    assert result.status_code == 200
    assert state[target]["is_latest"] and not state[old]["is_latest"] and state[untouched]["is_latest"]
    assert await lifecycle_probes.snapshot(f) == before


@pytest.mark.parametrize("kind", ["jwt", "key"])
@pytest.mark.parametrize("mutation", ["missing", "malformed", "oversized", "other_key", "version", "digest", "channel", "platform", "type", "uppercase_digest", "empty_version"])
async def test_invalid_existing_release_preserves_previous_latest(promotion, kind, mutation):
    f = promotion
    await seed(f, version="1.0.0", latest=True)
    target = await seed(f)
    values = {"missing": {"signature": None}, "malformed": {"signature": "not-base64!"},
              "oversized": {"signature": "A"*129}, "version": {"version": "9.0.0"},
              "digest": {"checksum_sha256": "b"*64}, "channel": {"is_prerelease": True},
              "platform": {"platform": "windows"}, "type": {"agent_type": "desktop"},
              "uppercase_digest": {"checksum_sha256": "A"*64}, "empty_version": {"version": ""}}
    if mutation == "other_key":
        payload = canonical_manifest_bytes(build_release_manifest(digest_hex="a"*64, version="1.2.0", platform="linux", agent_type="daemon", channel="stable"))
        values[mutation] = {"signature": base64.b64encode(ec.generate_private_key(ec.SECP256R1()).sign(payload, ec.ECDSA(hashes.SHA256()))).decode()}
    async with AsyncSession(f.engine) as db, db.begin():
        await db.execute(update(AgentRelease).where(AgentRelease.id == target).values(**values[mutation]))
    before = await rows(f)
    files = await lifecycle_probes.snapshot(f)
    result = await promote(f, target, await lifecycle_probes.headers(f, kind))
    after = await rows(f)
    assert result.status_code == 409 and after == before
    assert await lifecycle_probes.snapshot(f) == files


async def test_valid_promotion_survives_private_key_loss_without_repair(promotion):
    f = promotion
    target = await seed(f)
    for p in f.root.iterdir():
        if p.is_file():
            p.unlink()
    before = await lifecycle_probes.snapshot(f)
    result = await promote(f, target, await lifecycle_probes.headers(f))
    assert result.status_code == 200 and await lifecycle_probes.snapshot(f) == before


@pytest.mark.parametrize("kind", ["jwt", "key"])
@pytest.mark.parametrize("mutation", ["version", "owner", "deleted", "signature", "download_url", "download_count_control"])
async def test_rechecks_actual_target_after_row_wait(promotion, kind, mutation, record_property):
    f = promotion
    await seed(f, version="1.0.0", latest=True)
    target = await seed(f)
    headers = await lifecycle_probes.headers(f, kind)
    task = None
    async with AsyncSession(f.engine) as holder:
        await holder.execute(select(AgentRelease.id).where(AgentRelease.id == target).with_for_update())
        pid = await holder.scalar(text("SELECT pg_backend_pid()"))
        try:
            task = asyncio.create_task(promote(f, target, headers))
            await wait_for_target(f, task, pid, record_property)
            if mutation == "deleted":
                await holder.execute(delete(AgentRelease).where(AgentRelease.id == target))
            else:
                values = {"version": {"version": "8.0.0"}, "owner": {"organization_id": f.other_org},
                          "signature": {"signature": None}, "download_url": {"download_url": "https://artifacts.example.invalid/changed"},
                          "download_count_control": {"download_count": 7}}[mutation]
                await holder.execute(update(AgentRelease).where(AgentRelease.id == target).values(**values))
            expected = [dict(r) for r in (await holder.execute(select(AgentRelease.__table__).order_by(AgentRelease.id))).mappings()]
            await holder.commit()
            result = await asyncio.wait_for(task, 6)
            actual = await rows(f)
            if mutation == "download_count_control":
                assert result.status_code == 200
                assert next(r for r in actual if r["id"] == target)["download_count"] == 7
            else:
                assert result.status_code in {404, 409} and actual == expected
        finally:
            await holder.rollback()
            if task is not None and not task.done():
                await asyncio.wait_for(task, 6)


@pytest.mark.parametrize("kind", ["jwt", "key"])
@pytest.mark.parametrize("mutation", ["disabled", "deleted", "role", "organization", "counter", "password"])
async def test_current_actor_refused_after_actual_target_wait(promotion, kind, mutation, record_property):
    f = promotion
    await seed(f, version="1.0.0", latest=True)
    target = await seed(f)
    headers = await lifecycle_probes.headers(f, kind)
    before = await rows(f)
    task = None
    async with AsyncSession(f.engine) as holder:
        await holder.execute(select(AgentRelease.id).where(AgentRelease.id == target).with_for_update())
        pid = await holder.scalar(text("SELECT pg_backend_pid()"))
        try:
            task = asyncio.create_task(promote(f, target, headers))
            await wait_for_target(f, task, pid, record_property)
            values = {"disabled": {"is_active": False}, "deleted": {"deleted_at": datetime.now(UTC)},
                      "role": {"role": "viewer"}, "organization": {"organization_id": f.other_org},
                      "counter": {"token_version": 18}, "password": {"hashed_password": "!DISABLED"}}[mutation]
            await holder.execute(update(User).where(User.id == f.user).values(**values))
            await holder.commit()
            result = await asyncio.wait_for(task, 6)
            after = await rows(f)
            assert result.status_code in {401, 403} and after == before
        finally:
            await holder.rollback()
            if task is not None and not task.done():
                await asyncio.wait_for(task, 6)


@pytest.mark.parametrize("mutation", ["revoked", "scopes", "expiry", "key_hash", "jwt_blacklist", "jwt_session"])
async def test_current_credential_refused_after_actual_target_wait(promotion, mutation, record_property):
    f = promotion
    await seed(f, version="1.0.0", latest=True)
    target = await seed(f)
    kind = "jwt" if mutation.startswith("jwt") else "key"
    headers = await lifecycle_probes.headers(f, kind)
    claims = await verify_token(headers["Authorization"].split(" ", 1)[1]) if kind == "jwt" else None
    before = await rows(f)
    task = None
    async with AsyncSession(f.engine) as holder:
        await holder.execute(select(AgentRelease.id).where(AgentRelease.id == target).with_for_update())
        pid = await holder.scalar(text("SELECT pg_backend_pid()"))
        try:
            task = asyncio.create_task(promote(f, target, headers))
            await wait_for_target(f, task, pid, record_property)
            if mutation == "jwt_blacklist":
                await blacklist_token(claims["jti"], claims["exp"])
            elif mutation == "jwt_session":
                await holder.execute(update(UserSession).where(UserSession.access_jti == claims["jti"]).values(is_revoked=True))
            else:
                values = {"revoked": {"is_active": False}, "scopes": {"scopes": ["agent:read"]},
                          "expiry": {"expires_at": datetime.now(UTC)-timedelta(seconds=1)},
                          "key_hash": {"key_hash": "0"*64}}[mutation]
                await holder.execute(update(APIKey).where(APIKey.id == f.key_id).values(**values))
            await holder.commit()
            result = await asyncio.wait_for(task, 6)
            after = await rows(f)
            assert result.status_code in {401, 403} and after == before
        finally:
            await holder.rollback()
            if task is not None and not task.done():
                await asyncio.wait_for(task, 6)


async def test_late_sql_error_restores_previous_latest(promotion):
    f = promotion
    await seed(f, version="1.0.0", latest=True)
    target = await seed(f)
    async with AsyncSession(f.engine) as db, db.begin():
        await db.execute(text("""CREATE FUNCTION agents.owned_promotion_fail() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN IF NEW.is_latest THEN RAISE EXCEPTION 'Owned late promotion failure' USING ERRCODE='23514'; END IF; RETURN NEW; END $$"""))
        await db.execute(text(f"""CREATE TRIGGER zz_owned_promotion_fail BEFORE UPDATE ON agents.agent_releases
            FOR EACH ROW WHEN (NEW.id = '{target}'::uuid) EXECUTE FUNCTION agents.owned_promotion_fail()"""))
    before = await rows(f)
    result = await promote(f, target, await lifecycle_probes.headers(f))
    assert result.status_code == 500 and await rows(f) == before


@pytest.mark.parametrize("route", ["url", "upload"])
@pytest.mark.parametrize("kind", ["jwt", "key"])
async def test_publisher_refuses_authority_changed_after_actual_crypto(promotion, monkeypatch, route, kind):
    f = promotion
    await seed(f, version="1.0.0", latest=True)
    before = await rows(f)
    verified, resume = asyncio.Event(), asyncio.Event()
    original = publication_service.verify_manifest_async

    async def pause_after_crypto(*args, **kwargs):
        identity = await original(*args, **kwargs)
        verified.set()
        await resume.wait()
        return identity

    monkeypatch.setattr(publication_service, "verify_manifest_async", pause_after_crypto)
    f.consumers = f.promoter
    task = asyncio.create_task(consumer_probes.publish(f, await lifecycle_probes.headers(f, kind), route))
    try:
        await asyncio.wait_for(verified.wait(), HARNESS_WAIT_SECONDS)
        async with AsyncSession(f.engine) as db, db.begin():
            await db.execute(update(User).where(User.id == f.user).values(token_version=18))
        resume.set()
        result = await asyncio.wait_for(task, 6)
        after = await rows(f)
        assert result.status_code == 401 and after == before
        await assert_retained_and_explicitly_cleanup(f, route)
        assert await rows(f) == before
    finally:
        resume.set()
        # Retrieve a completed task exception as well as drain a pending task.
        await asyncio.wait_for(task, 6)


@pytest.mark.parametrize("route", ["url", "upload", "promotion"])
async def test_all_latest_writers_refuse_an_owned_busy_bucket(promotion, route):
    f = promotion
    target = await seed(f)
    headers = await lifecycle_probes.headers(f)
    before = await rows(f)
    if route != "promotion":
        f.consumers = f.promoter
        await prepare_for_busy_bucket(f, headers, route)
    async with AsyncSession(f.engine) as holder:
        await promotion_service.lock_release_bucket(holder, None, "linux", "daemon")
        if route == "promotion":
            result = await promote(f, target, headers)
        else:
            result = await consumer_probes.retained_command(f, headers, "publish")
        after = await rows(f)
        assert result.status_code == 409 and after == before
        await holder.rollback()
    if route != "promotion":
        await assert_retained_and_explicitly_cleanup(f, route)
        assert await rows(f) == before
    elif f.binary_root.exists():
        assert not list(f.binary_root.iterdir())


@pytest.mark.parametrize("kind,role,target_scope,scopes,expected", [
    ("jwt", "org_admin", "foreign", None, 404),
    ("key", "org_admin", "foreign", None, 404),
    ("key", "super_admin", "global", ["agent:admin"], 404),
    ("key", "super_admin", "own", ["agent:read"], 403),
])
async def test_promotion_preserves_org_and_explicit_scope_ceiling(promotion, kind, role, target_scope, scopes, expected):
    f = promotion
    target_org = {"foreign": f.other_org, "global": None, "own": f.org}[target_scope]
    target = await seed(f, organization=target_org)
    async with AsyncSession(f.engine) as db, db.begin():
        await db.execute(update(User).where(User.id == f.user).values(role=role))
        await db.execute(update(APIKey).where(APIKey.id == f.key_id).values(scopes=scopes))
    before = await rows(f)
    result = await promote(f, target, await lifecycle_probes.headers(f, kind))
    assert result.status_code == expected and await rows(f) == before


@pytest.mark.parametrize("kind", ["jwt", "key"])
@pytest.mark.parametrize("provider", ["oidc", "ldap"])
async def test_existing_supported_provider_credentials_remain_usable(promotion, kind, provider):
    # Starts AFTER external authentication; no actual IdP or LDAP exchange claim.
    from app.models.sso import SSOProvider

    f = promotion
    target = await seed(f, organization=f.org)
    async with AsyncSession(f.engine) as db, db.begin():
        await db.execute(update(SSOProvider).where(SSOProvider.id == f.provider).values(protocol=provider))
        await db.execute(update(User).where(User.id == f.user).values(auth_provider=provider, sso_provider_id=f.provider, external_id="owned-subject"))
    result = await promote(f, target, await lifecycle_probes.headers(f, kind))
    assert result.status_code == 200
    assert next(r for r in await rows(f) if r["id"] == target)["is_latest"]


async def test_promotion_without_identity_does_not_initialize(maintenance_engine, monkeypatch, tmp_path):
    context = asynccontextmanager(consumer_probes.consumers.__wrapped__)
    async with context(maintenance_engine, monkeypatch, tmp_path) as f:
        rid = uuid4()
        async with AsyncSession(f.engine) as db, db.begin():
            db.add(AgentRelease(id=rid, version="1.2.0", platform="linux", agent_type="daemon", download_url="https://artifacts.example.invalid/agent",
                                checksum_sha256="a"*64, signature="B"*96, organization_id=None, is_latest=False,
                                is_prerelease=False, file_size=5, release_notes="", min_backend_version="", download_count=0))
        before = await rows(f)
        f.promoter = f.consumers
        files = await lifecycle_probes.snapshot(f)
        result = await promote(f, rid, await lifecycle_probes.headers(f))
        assert result.status_code == 503 and await rows(f) == before
        assert await lifecycle_probes.snapshot(f) == files and not f.root.exists()


@pytest.mark.parametrize("kind", ["jwt", "key"])
@pytest.mark.parametrize("cross_deadline", [False, True])
async def test_final_fence_clock_keeps_api_key_and_jwt_deadlines(promotion, monkeypatch, kind, cross_deadline, record_property):
    from app.services import agent_release_authority as authority_module

    f = promotion
    await seed(f, version="1.0.0", latest=True)
    target = await seed(f)
    async with AsyncSession(f.engine) as db, db.begin():
        await db.execute(update(APIKey).where(APIKey.id == f.key_id).values(expires_at=datetime.now(UTC)+timedelta(minutes=5)))
    before = await rows(f)
    base_datetime = authority_module.datetime
    state = {"future": False, "final": False, "rechecks": 0}

    class ControlledClock:
        @staticmethod
        def now(tz=None):
            return base_datetime.now(tz)+(timedelta(days=1) if state["future"] else timedelta(0))

    original_validate = authority_module.ReleaseMutationAuthority.validate
    original_recheck = authority_module.ReleaseMutationFence.recheck

    def validated_then_clock_moves(self, row):
        original_validate(self, row)
        if state["final"] and cross_deadline:
            state["future"] = True

    async def final_recheck(self):
        state["rechecks"] += 1
        state["final"] = state["rechecks"] == 2
        return await original_recheck(self)

    monkeypatch.setattr(authority_module, "datetime", ControlledClock)
    monkeypatch.setattr(authority_module.ReleaseMutationAuthority, "validate", validated_then_clock_moves)
    monkeypatch.setattr(authority_module.ReleaseMutationFence, "recheck", final_recheck)
    result = await promote(f, target, await lifecycle_probes.headers(f, kind))
    after = await rows(f)
    assert state["rechecks"] == 2
    record_property("controlled_final_clock_after_actual_sql_validation", True)
    if cross_deadline:
        assert result.status_code == 401 and after == before
    else:
        assert result.status_code == 200 and next(r for r in after if r["id"] == target)["is_latest"]

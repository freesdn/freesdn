"""AFTER-only private lifecycle contracts on owned PostgreSQL and key files.

Not collected/run. The HTTP harness uses real authentication/local factors and
the actual coordinator, but is not a shipped endpoint or browser/IdP workflow.
Every database is created from the retained baseline and actual migrations.
"""

import asyncio
import hashlib
from contextlib import asynccontextmanager
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import httpx
import pytest
import pytest_asyncio
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import Depends, FastAPI, HTTPException, Request
from sqlalchemy import insert, select, text, update
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.pool import NullPool

from app.core.agent_signing_binding import SigningCommand
from app.core.dependencies import CurrentUser, get_current_user
from app.db import session as sessions
from app.db.session import get_session
from app.main import app as product_app
from app.models.agent_signing import AgentSigningIdentity, AgentSigningIntent
from app.models.agents import AgentRelease
from app.models.core import User, UserSession
from app.services import agent_signing_lifecycle as lifecycle
from app.services.agent_signing_authority import SigningLifecycleAuthority
from tests.db.conftest import build_pre_fix_database, drop_scratch_database, run_alembic
from tests.db.conftest import maintenance_engine as maintenance_engine
from tests.security import test_agent_signing_authority as authority_probes


@pytest_asyncio.fixture
async def owned_lifecycle(maintenance_engine, monkeypatch, tmp_path):
    name = "owned_signing_lifecycle_" + uuid4().hex[:10]
    url = await asyncio.to_thread(build_pre_fix_database, maintenance_engine, name)
    engine = None
    try:
        await asyncio.to_thread(run_alembic, url, "upgrade", "023_agent_signing_identity")
        engine = create_async_engine(url.set(drivername="postgresql+asyncpg"), hide_parameters=True,
                                     poolclass=NullPool, connect_args={"timeout": 3, "command_timeout": 5})
        monkeypatch.setattr(authority_probes, "create_test_engine", lambda: engine)
        monkeypatch.setattr(sessions, "security_engine", engine)
        root = tmp_path / "owned-key-store"
        monkeypatch.setenv("FREESDN_SIGNING_KEY_DIR", str(root))
        monkeypatch.setenv("FREESDN_AGENT_RELEASE_DIR", str(root))
        # Reuse real account/factor/credential setup in this exclusively owned
        # scratch database. Its enclosing finally drops the whole database; row
        # deletion here could violate the retained-reference guards under test.
        context = asynccontextmanager(authority_probes.owned_signing.__wrapped__)
        async with context(monkeypatch, disposable_database=url.database) as f:
            f.root, f.last_factor = root, None
            f.command = SigningCommand("initialize", uuid4(), uuid4(), 1)
            app = FastAPI(exception_handlers=product_app.exception_handlers)

            async def request_session():
                async with AsyncSession(engine, expire_on_commit=False, autoflush=False) as db:
                    yield db

            app.dependency_overrides[get_session] = request_session

            @app.post("/owned/signing-lifecycle")
            async def execute(request: Request, user: CurrentUser = Depends(get_current_user)):
                authority = await SigningLifecycleAuthority.capture(
                    request, user, command=f.command, secret_key=f.secret
                )
                f.last_factor = await authority.confirm_local(command=f.command, password=f.password)
                result = await lifecycle.execute_signing_lifecycle(factor=f.last_factor, command=f.command)
                return {"state": result.state, "operation": str(result.operation_id),
                        "fingerprint": result.public_key_sha256}

            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),
                                         base_url="http://test") as client:
                f.lifecycle_client = client
                yield f
    finally:
        if engine is not None:
            await engine.dispose()
        await asyncio.to_thread(drop_scratch_database, maintenance_engine, name)
        engine = None


async def headers(f, kind="key", *, expires=120):
    result, claims = authority_probes.credentials(f, kind, expires=expires)
    if claims:
        async with AsyncSession(f.engine) as db, db.begin():
            db.add(UserSession(id=uuid4(), user_id=f.user, access_jti=claims["jti"], refresh_jti=uuid4().hex,
                               created_at=datetime.now(UTC), expires_at=datetime.now(UTC)+timedelta(minutes=10),
                               is_revoked=False))
    return result


async def snapshot(f):
    async with AsyncSession(f.engine) as db:
        intents = [dict(r) for r in (await db.execute(select(AgentSigningIntent.__table__)
                   .order_by(AgentSigningIntent.created_at))).mappings()]
        identities = [dict(r) for r in (await db.execute(select(AgentSigningIdentity.__table__))).mappings()]
    files = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in f.root.iterdir() if p.is_file()} if f.root.exists() else {}
    return intents, identities, files


def pair(f, *, crlf=False):
    key = ec.generate_private_key(ec.SECP256R1())
    private = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
    public = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    if crlf:
        public = public.replace(b"\n", b"\r\n")
    f.root.mkdir(mode=0o700)
    for name, value in [(".signing-key.pem", private), (".public-key.pem", public)]:
        p = f.root / name
        p.write_bytes(value)
        p.chmod(0o600)
    return hashlib.sha256(public).hexdigest()


@pytest.mark.parametrize("kind", ["jwt", "key"])
async def test_fresh_initialization_commits_intent_before_usable_identity(owned_lifecycle, kind):
    f = owned_lifecycle
    credential = await headers(f, kind)
    result = await f.lifecycle_client.post("/owned/signing-lifecycle", headers=credential)
    intents, identities, files = await snapshot(f)
    assert result.status_code == 200 and result.json()["state"] == "activated"
    assert len(intents) == len(identities) == 1
    assert intents[0]["operation_id"] == identities[0]["operation_id"] == f.command.operation_id
    assert identities[0]["public_key_sha256"] == files[".public-key.pem"] == result.json()["fingerprint"]
    assert intents[0]["created_at"] <= intents[0]["prepared_at"] <= identities[0]["activated_at"]
    before = await snapshot(f)
    with pytest.raises(HTTPException) as denied:
        await lifecycle.execute_signing_lifecycle(factor=f.last_factor, command=f.command)
    assert denied.value.status_code == 401 and await snapshot(f) == before


@pytest.mark.parametrize("kind", ["jwt", "key"])
@pytest.mark.parametrize("phase", ["pending", "prepared", "activated"])
async def test_committed_phase_survives_lost_response_without_implicit_recreation(owned_lifecycle, monkeypatch, kind, phase):
    f = owned_lifecycle
    credential = await headers(f, kind)
    original = lifecycle._phase
    failure = {"enabled": True}

    async def after_commit(*args, **kwargs):
        result = await original(*args, **kwargs)
        row = result[0] if isinstance(result, tuple) else result
        if failure["enabled"] and row["state"] == phase:
            raise HTTPException(503, "Owned lost response after actual committed phase")
        return result

    monkeypatch.setattr(lifecycle, "_phase", after_commit)
    first = await f.lifecycle_client.post("/owned/signing-lifecycle", headers=credential)
    before = await snapshot(f)
    assert first.status_code == 503 and before[0][0]["state"] == phase
    failure["enabled"] = False
    f.command = replace(f.command, action="resume")
    resumed = await f.lifecycle_client.post("/owned/signing-lifecycle", headers=credential)
    after = await snapshot(f)
    if phase == "pending":
        assert resumed.status_code == 409 and after == before
        assert not after[1] and not after[2]
    else:
        assert resumed.status_code == 200 and after[0][0]["state"] == "activated"
        assert len(after[1]) == 1 and after[2] == before[2]


@pytest.mark.parametrize("crlf", [False, True])
@pytest.mark.parametrize("expectation", ["matching", "wrong"])
async def test_explicit_adoption_preserves_raw_public_pin_and_refuses_wrong_expectation(owned_lifecycle, crlf, expectation):
    f = owned_lifecycle
    fingerprint = pair(f, crlf=crlf)
    f.command = replace(f.command, action="adopt", expected_public_sha256=fingerprint if expectation == "matching" else "0"*64)
    before = await snapshot(f)
    result = await f.lifecycle_client.post("/owned/signing-lifecycle", headers=await headers(f))
    after = await snapshot(f)
    assert all(after[2][name] == value for name,value in before[2].items())
    if expectation == "matching":
        assert result.status_code == 200 and after[1][0]["public_key_sha256"] == fingerprint
    else:
        assert result.status_code == 409 and after[0][0]["state"] == "pending" and not after[1]
        assert after[2] == before[2]


@pytest.mark.parametrize("lost", ["private", "public", "all"])
async def test_active_recovery_never_rotates_missing_private_material(owned_lifecycle, lost):
    f = owned_lifecycle
    credential = await headers(f)
    first = await f.lifecycle_client.post("/owned/signing-lifecycle", headers=credential)
    assert first.status_code == 200
    original = await snapshot(f)
    names = {"private": [".signing-key.pem"], "public": [".public-key.pem"],
             "all": list(original[2])}[lost]
    for name in names:
        (f.root / name).unlink()
    damaged = await snapshot(f)
    f.command = replace(f.command, action="recover", expected_public_sha256=original[1][0]["public_key_sha256"])
    result = await f.lifecycle_client.post("/owned/signing-lifecycle", headers=credential)
    after = await snapshot(f)
    if lost == "public":
        assert result.status_code == 200 and after == original
    else:
        assert result.status_code == 409 and after == damaged


async def test_pending_cancellation_retains_history_and_allows_separate_explicit_initialization(owned_lifecycle, monkeypatch):
    f = owned_lifecycle
    credential = await headers(f)
    original = lifecycle._phase

    async def stop_after_pending(*args, **kwargs):
        result = await original(*args, **kwargs)
        if isinstance(result, tuple) and result[1]:
            raise HTTPException(503, "Owned interruption after pending commit")
        return result

    monkeypatch.setattr(lifecycle, "_phase", stop_after_pending)
    assert (await f.lifecycle_client.post("/owned/signing-lifecycle", headers=credential)).status_code == 503
    monkeypatch.setattr(lifecycle, "_phase", original)
    f.command = replace(f.command, action="cancel")
    assert (await f.lifecycle_client.post("/owned/signing-lifecycle", headers=credential)).status_code == 200
    cancelled = await snapshot(f)
    assert cancelled[0][0]["state"] == "cancelled" and not cancelled[1] and not cancelled[2]
    old_operation = f.command.operation_id
    f.command = replace(f.command, action="initialize", operation_id=uuid4())
    assert (await f.lifecycle_client.post("/owned/signing-lifecycle", headers=credential)).status_code == 200
    after = await snapshot(f)
    assert [r["state"] for r in after[0]] == ["cancelled", "activated"]
    assert after[0][0]["operation_id"] == old_operation and after[0][0] == cancelled[0][0]


@pytest.mark.parametrize("kind", ["jwt", "key"])
@pytest.mark.parametrize("mutation", ["disabled", "counter"])
async def test_authority_committed_after_real_storage_prevents_preparation_and_activation(owned_lifecycle, monkeypatch, kind, mutation):
    f = owned_lifecycle
    original = lifecycle._storage

    async def changed_after_io(function):
        result = await original(function)
        async with AsyncSession(f.engine) as db, db.begin():
            await db.execute(update(User).where(User.id == f.user).values(
                **({"is_active": False} if mutation == "disabled" else {"token_version": 18})
            ))
        return result

    monkeypatch.setattr(lifecycle, "_storage", changed_after_io)
    result = await f.lifecycle_client.post("/owned/signing-lifecycle", headers=await headers(f, kind))
    state = await snapshot(f)
    assert result.status_code == 401 and state[0][0]["state"] == "pending" and not state[1]
    assert set(state[2]) == {".signing-key.pem", ".public-key.pem", ".signing-identity.sha256"}


async def test_real_late_identity_insert_failure_rolls_back_activation_only(owned_lifecycle):
    f = owned_lifecycle
    async with AsyncSession(f.engine) as db, db.begin():
        await db.execute(text("""CREATE FUNCTION agents.owned_refuse_identity() RETURNS trigger LANGUAGE plpgsql
          AS $$ BEGIN RAISE EXCEPTION 'owned identity insert failure'; END; $$"""))
        await db.execute(text("""CREATE TRIGGER zz_owned_refusal BEFORE INSERT ON agents.agent_signing_identities
          FOR EACH ROW EXECUTE FUNCTION agents.owned_refuse_identity()"""))
    credential = await headers(f)
    result = await f.lifecycle_client.post("/owned/signing-lifecycle", headers=credential)
    before = await snapshot(f)
    assert result.status_code == 503 and before[0][0]["state"] == "prepared" and not before[1]
    async with AsyncSession(f.engine) as db, db.begin():
        await db.execute(text("DROP TRIGGER zz_owned_refusal ON agents.agent_signing_identities"))
        await db.execute(text("DROP FUNCTION agents.owned_refuse_identity()"))
    f.command = replace(f.command, action="resume")
    assert (await f.lifecycle_client.post("/owned/signing-lifecycle", headers=credential)).status_code == 200
    after = await snapshot(f)
    assert after[0][0]["state"] == "activated" and len(after[1]) == 1 and after[2] == before[2]


async def test_other_physical_connection_owns_global_operation_before_claim_or_storage(owned_lifecycle):
    f = owned_lifecycle
    credential = await headers(f)
    async with AsyncSession(f.engine) as holder:
        try:
            await holder.execute(text("SELECT pg_advisory_lock(CAST(:k AS bigint))"), {"k": lifecycle._OPERATION_LOCK})
            result = await f.lifecycle_client.post("/owned/signing-lifecycle", headers=credential)
            assert result.status_code == 409 and await snapshot(f) == ([], [], {})
        finally:
            await holder.execute(text("SELECT pg_advisory_unlock(CAST(:k AS bigint))"), {"k": lifecycle._OPERATION_LOCK})
            await holder.commit()
    assert (await f.lifecycle_client.post("/owned/signing-lifecycle", headers=credential)).status_code == 200


async def test_agent_release_history_prevents_fresh_initialization(owned_lifecycle):
    f = owned_lifecycle
    async with AsyncSession(f.engine) as db, db.begin():
        db.add(AgentRelease(version="99.0.1", platform="linux-amd64", agent_type="daemon",
                            download_url="https://example.invalid/owned-agent", checksum_sha256="0"*64,
                            organization_id=f.org))
    result = await f.lifecycle_client.post("/owned/signing-lifecycle", headers=await headers(f))
    assert result.status_code == 409 and await snapshot(f) == ([], [], {})


@pytest.mark.parametrize("deadline", ["expired", "malformed", "future"])
async def test_deferred_database_deadline_guard_preserves_original_direct_schema_contract(owned_lifecycle, deadline):
    f = owned_lifecycle
    value = {"expired": str(int(datetime.now(UTC).timestamp())-1), "malformed": "not-a-time",
             "future": str(int(datetime.now(UTC).timestamp())+60)}[deadline]

    async def write():
        async with AsyncSession(f.engine) as db, db.begin():
            await db.execute(text("SELECT set_config('freesdn.signing_deadline', :v, true)"), {"v": value})
            await db.execute(insert(AgentSigningIntent).values(
                operation_id=f.command.operation_id, singleton_id=1, installation_id=f.command.installation_id,
                identity_epoch=1, kind="initialize", expected_public_sha256=None, state="pending",
                requested_by=f.user, created_at=datetime.now(UTC),
            ))
            # Deferred rather than silently refusing before the real commit.
            assert await db.scalar(select(AgentSigningIntent.state)) == "pending"

    if deadline == "future":
        await write()
        assert (await snapshot(f))[0][0]["state"] == "pending"
    else:
        with pytest.raises(DBAPIError):
            await write()
        assert await snapshot(f) == ([], [], {})

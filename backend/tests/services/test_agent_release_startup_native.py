# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Owned native PG/files and actual factory/middleware/auth diagnostic contracts.

The entire application lifespan (hardware/module/background startup) is not run.
Its release prerequisite function is invoked directly against the isolated
database; the normal factory/router/middleware serves the resulting observation.
No auth, reference validator, signing implementation or file I/O is replaced.
"""

import asyncio
import hashlib
import time
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import text, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.agent_release_runtime_policy import ReleaseRuntimePolicy
from app.core.config import settings
from app.core.security import create_access_token, verify_token
from app.db.session import get_session
from app.main import create_application
from app.models.api_keys import APIKey
from app.models.core import User, UserSession
from app.services.agent_release_startup import observe_release_startup
from tests.db.conftest import maintenance_engine as maintenance_engine
from tests.db.conftest import run_alembic
from tests.services import test_agent_signing_lifecycle as signing

PATH = "/api/v1/agents/release-runtime"


@pytest_asyncio.fixture
async def runtime(maintenance_engine, monkeypatch, tmp_path, request):
    context = asynccontextmanager(signing.owned_lifecycle.__wrapped__)
    async with context(maintenance_engine, monkeypatch, tmp_path) as fixture:
        revision = getattr(request, "param", "027_agent_release_references")
        if revision != "023_agent_signing_identity":
            await asyncio.to_thread(run_alembic, fixture.engine.url, "upgrade", revision)
        parent = tmp_path / "legacy-artifacts"
        parent.mkdir(mode=0o700)
        fixture.legacy = parent / "preserved-legacy.bin"
        fixture.legacy.write_bytes(b"existing legacy data must not be adopted")
        monkeypatch.setattr(settings, "FREESDN_AGENT_RELEASE_DIR", str(parent))
        monkeypatch.setattr(settings, "FREESDN_AGENT_MANAGED_RELEASE_DIR", "")
        monkeypatch.setattr(settings, "CORS_ORIGINS", ["https://owned-browser.invalid"])
        fixture.policy = ReleaseRuntimePolicy.from_settings(settings)
        fixture.application = create_application()
        assert fixture.application.state.agent_release_policy == fixture.policy
        assert fixture.application.state.agent_release_startup is None

        async def connection():
            async with AsyncSession(fixture.engine, expire_on_commit=False, autoflush=False) as db:
                yield db

        fixture.application.dependency_overrides[get_session] = connection
        try:
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=fixture.application, raise_app_exceptions=False),
                base_url="http://owned-test", follow_redirects=False,
            ) as client:
                fixture.http = client
                yield fixture
        finally:
            # This app instance owns its middleware Redis client. Do not close
            # unrelated global clients or a pre-existing service.
            layer = fixture.application.middleware_stack
            seen = set()
            while layer is not None and id(layer) not in seen:
                seen.add(id(layer))
                if type(layer).__name__ == "RateLimitMiddleware" and layer._redis is not None:
                    await layer._redis.aclose()
                layer = getattr(layer, "app", None)


async def initialize_identity(fixture):
    response = await fixture.lifecycle_client.post(
        "/owned/signing-lifecycle", headers=await signing.headers(fixture),
    )
    assert response.status_code == 200 and response.json()["state"] == "activated"


async def schema_snapshot(fixture):
    async with fixture.engine.connect() as db:
        functions = (await db.execute(text("""
            SELECT p.proname,pg_get_functiondef(p.oid)
            FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
            WHERE n.nspname='agents' ORDER BY p.proname,p.oid
        """))).all()
        triggers = (await db.execute(text("""
            SELECT c.relname,t.tgname,t.tgenabled::text,pg_get_triggerdef(t.oid)
            FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid
            JOIN pg_namespace n ON n.oid=c.relnamespace
            WHERE n.nspname='agents' AND NOT t.tgisinternal ORDER BY c.relname,t.tgname
        """))).all()
        revision = await db.scalar(text("SELECT version_num FROM alembic_version"))
    return list(map(tuple, functions)), list(map(tuple, triggers)), revision


def files(root):
    root = Path(root)
    if not root.exists():
        return None
    return {str(p.relative_to(root)): (p.stat().st_mode, hashlib.sha256(p.read_bytes()).hexdigest())
            for p in root.rglob("*") if p.is_file()}


async def observe(fixture):
    result = await observe_release_startup(fixture.policy)
    fixture.application.state.agent_release_startup = result
    return result


@pytest.mark.parametrize("storage_ready", (True, False))
@pytest.mark.parametrize("schema_ready", (True, False))
@pytest.mark.parametrize("identity_ready", (True, False))
async def test_actual_prerequisites_are_independent_and_never_repair_existing_state(
    runtime, storage_ready, schema_ready, identity_ready, record_property,
):
    f = runtime
    if identity_ready:
        await initialize_identity(f)
    if not storage_ready:
        Path(f.policy.managed_root).mkdir(mode=0o700)
        (Path(f.policy.managed_root) / "unrelated").write_bytes(b"unmarked existing evidence")
    if not schema_ready:
        async with f.engine.begin() as db:
            await db.execute(text("ALTER TABLE agents.agent_releases DISABLE TRIGGER release_reference_deferred"))
    before_schema = await schema_snapshot(f)
    before_signing = await signing.snapshot(f)
    before_storage = files(f.policy.managed_root)
    before_legacy = f.legacy.read_bytes()
    result = await observe(f)
    assert (result.storage, result.reference_schema, result.signing_identity) == tuple(
        "observed" if valid else "unavailable" for valid in (storage_ready, schema_ready, identity_ready)
    )
    assert await schema_snapshot(f) == before_schema
    assert await signing.snapshot(f) == before_signing
    assert f.legacy.read_bytes() == before_legacy
    if not storage_ready:
        assert files(f.policy.managed_root) == before_storage
    else:
        assert set(files(f.policy.managed_root)) == {".freesdn-managed-artifacts-v1"}
    record_property("native_prerequisite_states_preserved", True)
    record_property("actual_reference_and_identity_observations", result.public())


@pytest.mark.parametrize("runtime", ["023_agent_signing_identity"], indirect=True)
async def test_old_database_is_reported_without_implicit_upgrade_and_explicit_upgrade_recovers(runtime):
    f = runtime
    await initialize_identity(f)
    previous = await schema_snapshot(f)
    previous_keys = await signing.snapshot(f)
    missing = await observe(f)
    assert missing.reference_schema == "unavailable" and missing.signing_identity == "observed"
    assert await schema_snapshot(f) == previous and await signing.snapshot(f) == previous_keys
    await asyncio.to_thread(run_alembic, f.engine.url, "upgrade", "027_agent_release_references")
    upgraded = await observe(f)
    assert upgraded.all_observed
    assert (await schema_snapshot(f))[2] == "027_agent_release_references"
    assert await signing.snapshot(f) == previous_keys


async def test_real_table_lock_conflict_is_refused_without_retaining_connections(runtime, record_property):
    f = runtime
    await initialize_identity(f)
    async with f.engine.connect() as holder, holder.begin():
        await holder.execute(text("LOCK TABLE agents.agent_releases IN ACCESS EXCLUSIVE MODE"))
        holder_pid = await holder.scalar(text("SELECT pg_backend_pid()"))
        async with f.engine.connect() as inspector:
            held = await inspector.scalar(text("""
                SELECT EXISTS(SELECT 1 FROM pg_locks WHERE pid=:pid AND granted
                  AND relation='agents.agent_releases'::regclass AND mode='AccessExclusiveLock')
            """), {"pid": holder_pid})
        assert held
        record_property("genuine_conflicting_table_lock", True)
        started = time.monotonic()
        result = await observe(f)
        assert time.monotonic() - started < 5
        assert result.reference_schema == "unavailable"
        assert result.storage == result.signing_identity == "observed"
        async with f.engine.connect() as inspector:
            leftovers = (await inspector.execute(text("""
                SELECT pid FROM pg_stat_activity WHERE datname=current_database()
                  AND pid NOT IN (pg_backend_pid(),:holder)
            """), {"holder": holder_pid})).all()
        assert leftovers == []
    assert (await observe(f)).all_observed


async def test_missing_private_signing_file_is_not_recreated_or_misrepresented_as_key_verification(runtime):
    f = runtime
    await initialize_identity(f)
    (f.root / ".signing-key.pem").unlink()
    missing = await signing.snapshot(f)
    result = await observe(f)
    # This field attests retained public identity, not private signing-file
    # availability or signing authority. Actual operations revalidate storage.
    assert result.signing_identity == "observed"
    assert result.public()["observation_only"] and result.public()["actions_revalidate_current_state"]
    assert await signing.snapshot(f) == missing and not (f.root / ".signing-key.pem").exists()


@pytest.mark.parametrize("kind", ("jwt", "key"))
@pytest.mark.parametrize("state", ("authorized", "viewer", "inactive", "revoked", "expired", "pending"))
async def test_actual_application_diagnostics_require_current_authority(runtime, kind, state):
    f = runtime
    credential = await signing.headers(f, kind)
    if state == "expired" and kind == "jwt":
        # The normal fixture helper verifies expiry while decoding its issued
        # token. Sign an expired token through the real issuer directly; no
        # authentication decoder or clock is replaced for this refusal probe.
        expired = create_access_token(str(f.user), token_version=17, expires_delta=timedelta(seconds=-120))
        credential = {"Authorization": "Bearer " + expired}
    if state != "pending":
        await observe(f)
    async with f.engine.begin() as db:
        if state == "viewer":
            await db.execute(update(User).where(User.id == f.user).values(role="viewer"))
        elif state == "inactive":
            await db.execute(update(User).where(User.id == f.user).values(is_active=False))
        elif state == "revoked" and kind == "jwt":
            token = credential["Authorization"].split(" ", 1)[1]
            claims = await verify_token(token)
            assert claims and claims["jti"]
            await db.execute(update(UserSession).where(UserSession.access_jti == claims["jti"]).values(is_revoked=True))
        elif state == "revoked":
            await db.execute(update(APIKey).where(APIKey.id == f.key_id).values(is_active=False))
        elif state == "expired" and kind == "key":
            await db.execute(update(APIKey).where(APIKey.id == f.key_id).values(expires_at=datetime.now(UTC) - timedelta(minutes=2)))
    before = await signing.snapshot(f)
    response = await f.http.get(PATH, headers=credential)
    expected = {"authorized": 200, "viewer": 403, "inactive": 401, "revoked": 401, "expired": 401, "pending": 503}[state]
    assert response.status_code == expected
    assert await signing.snapshot(f) == before
    assert str(f.root) not in response.text and f.password not in response.text
    assert str(f.policy.managed_root) not in response.text
    if state == "authorized":
        body = response.json()
        expected = f.application.state.agent_release_startup.public()
        # Public date-time serialization uses Z; require the exact instant and
        # UTC offset rather than the internal Python +00:00 spelling.
        assert type(body["checked_at"]) is str
        instant = datetime.fromisoformat(body["checked_at"])
        assert instant == f.application.state.agent_release_startup.checked_at
        assert instant.utcoffset() == timedelta(0)
        assert {key: value for key, value in body.items() if key != "checked_at"} == {
            key: value for key, value in expected.items() if key != "checked_at"
        }
        assert body["signing_identity"] == "unavailable" and body["observation_only"] is True
    if state in ("authorized", "pending"):
        # The real application middleware applies its stronger shared policy
        # to both successful and failed responses; do not weaken that policy.
        assert response.headers["cache-control"] == "no-store, no-cache, must-revalidate"
        assert response.headers["pragma"] == "no-cache"


@pytest.mark.parametrize("scope,expected", (("agent:admin", 200), ("agent:read", 403)))
async def test_actual_superuser_api_key_still_obeys_scope_ceiling(runtime, scope, expected):
    f = runtime
    credential = await signing.headers(f, "key")
    async with f.engine.begin() as db:
        await db.execute(update(APIKey).where(APIKey.id == f.key_id).values(scopes=[scope]))
    await observe(f)
    response = await f.http.get(PATH, headers=credential)
    assert response.status_code == expected


async def test_anonymous_request_cannot_read_cached_startup_observation(runtime):
    await observe(runtime)
    response = await runtime.http.get(PATH)
    assert response.status_code == 401 and "checked_at" not in response.text


@pytest.mark.parametrize("origin,expected", (("https://owned-browser.invalid", 200), ("https://other.invalid", 400)))
async def test_real_cors_preflight_preserves_origin_gate_and_release_context_headers(runtime, origin, expected):
    response = await runtime.http.options(PATH, headers={
        "Origin": origin, "Access-Control-Request-Method": "GET",
        "Access-Control-Request-Headers": "Authorization,X-FreeSDN-Release-Actor,X-FreeSDN-Release-Organization",
    })
    assert response.status_code == expected
    if expected == 200:
        assert response.headers["access-control-allow-origin"] == origin
        assert response.headers["access-control-allow-credentials"] == "true"
    else:
        assert "access-control-allow-origin" not in response.headers


async def test_factory_state_is_per_application_and_route_precedes_agent_id_wildcard(runtime):
    f = runtime
    await observe(f)
    other = create_application()
    assert other.state.agent_release_startup is None
    assert f.application.state.agent_release_startup is not None
    def ordered_paths(routes, prefix=""):
        # The installed FastAPI retains included routers and prefix context.
        # Traverse actual definitions in order; real HTTP tests above also
        # prove that the static diagnostic route wins over the UUID wildcard.
        for route in routes:
            nested = getattr(route, "original_router", None)
            if nested is not None:
                yield from ordered_paths(nested.routes, prefix + route.include_context.prefix)
            elif getattr(route, "path", None) is not None:
                yield prefix + route.path

    paths = list(ordered_paths(f.application.routes))
    assert paths.index(PATH) < paths.index("/api/v1/agents/{agent_id}")
    assert PATH in f.application.openapi()["paths"]
    # Merely building another factory must not erase the first observation or
    # perform storage provisioning/SQL. Its policy is a separate frozen value.
    assert other.state.agent_release_policy == f.policy
    assert other.state.agent_release_policy is not f.application.state.agent_release_policy

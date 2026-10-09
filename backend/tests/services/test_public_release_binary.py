# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Actual public factory/auth/SQL/file download contracts on owned resources.

The full background/hardware lifespan is not run. Only the database dependency
is redirected; authentication, route selection, signature verification, middleware
and file delivery remain real. Controlled I/O boundaries are not host-loss proof.
"""

import hashlib
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import delete, insert, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.db.session import get_session
from app.main import create_application
from app.models.agents import AgentRelease, RemoteAgent
from app.models.api_keys import APIKey
from app.models.core import User
from app.services import agent_release_binary as binary
from app.services.release_signing import build_release_manifest
from app.services.release_signing_async import sign_manifest_async
from tests.db.conftest import maintenance_engine as maintenance_engine
from tests.services import test_agent_release_delivery as readers


@pytest_asyncio.fixture
async def public_reader(maintenance_engine, monkeypatch, tmp_path):
    async with asynccontextmanager(readers.reader.__wrapped__)(maintenance_engine, monkeypatch, tmp_path) as f:
        f.legacy_root = tmp_path / "legacy-release-files"
        f.legacy_root.mkdir(mode=0o755)
        monkeypatch.setattr(settings, "FREESDN_AGENT_RELEASE_DIR", str(f.legacy_root))
        monkeypatch.setattr(settings, "FREESDN_AGENT_MANAGED_RELEASE_DIR", str(f.artifacts))
        app = create_application()

        async def connection():
            async with AsyncSession(f.engine, expire_on_commit=False, autoflush=False) as db:
                yield db

        app.dependency_overrides[get_session] = connection
        # Independent in-process test clients retain the real IP rate limiter;
        # neither forwarding headers nor a disabled limiter grants a bypass.
        client_bytes = uuid4().bytes
        unique_client = f"198.18.{client_bytes[0]}.{client_bytes[1]}"
        try:
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app, raise_app_exceptions=False, client=(unique_client, 123)),
                base_url="http://owned-test", follow_redirects=False,
            ) as client:
                f.public_client = client
                yield f
        finally:
            layer = app.middleware_stack
            seen = set()
            while layer is not None and id(layer) not in seen:
                seen.add(id(layer))
                if type(layer).__name__ == "RateLimitMiddleware" and layer._redis is not None:
                    await layer._redis.aclose()
                layer = getattr(layer, "app", None)
            # FastAPI caches the per-test dependency closure, which captures f.
            # Do not let that retained fixture keep a closed client/full app alive.
            # The client has already closed; no assertion or request runs afterward.
            f.public_client = None


def path(f):
    return f"/api/v1/agents/releases/{f.release_id}/binary"


async def seed(f, storage, organization, *, data=b"0123456789"):
    if storage == "managed":
        await readers.publish(f, organization=organization, data=data)
        f.release_id = f.publication.release_id
        return
    f.release_id = uuid4()
    f.data = data
    name = "old-agent_linux.bin"
    digest = hashlib.sha256(data).hexdigest()
    signature = await sign_manifest_async(build_release_manifest(digest_hex=digest, version="26.1",
        platform="linux", agent_type="daemon", channel="stable"))
    async with f.engine.begin() as db:
        await db.execute(insert(AgentRelease).values(id=f.release_id, organization_id=organization,
            version="26.1", platform="linux", agent_type="daemon", download_url=path(f),
            checksum_sha256=digest, file_size=len(data), release_notes="preserved older release",
            min_backend_version="", is_prerelease=False, is_latest=True,
            filename=None if storage == "legacy-null" else name, signature=signature,
            published_at=datetime.now(UTC), download_count=0))
    f.legacy_path = f.legacy_root / (str(f.release_id) + "-" + name)
    f.legacy_path.write_bytes(data)
    f.legacy_path.chmod(0o644)


async def row(f):
    async with f.engine.connect() as db:
        return (await db.execute(select(AgentRelease.__table__).where(AgentRelease.id == f.release_id))).mappings().one_or_none()


def files(f):
    return {str(p.relative_to(f.legacy_root)): (p.stat().st_mode, hashlib.sha256(p.read_bytes()).hexdigest())
            for p in f.legacy_root.iterdir() if p.is_file()}


@pytest.mark.parametrize("storage", ("managed", "legacy-explicit", "legacy-null"))
@pytest.mark.parametrize("kind", ("jwt", "key", "agent"))
@pytest.mark.parametrize("target", ("own", "global", "other"))
async def test_public_route_preserves_principal_and_organization_rules(public_reader, storage, kind, target):
    f = public_reader
    await seed(f, storage, {"own": f.org, "global": None, "other": f.other_org}[target])
    if kind != "agent":
        async with f.engine.begin() as db:
            await db.execute(update(User).where(User.id == f.user).values(role="viewer"))
    before = files(f)
    response = await f.public_client.get(path(f), headers=await readers.credentials(f, kind))
    assert response.status_code == (404 if target == "other" else 200)
    if target != "other":
        assert response.content == f.data
        assert response.headers["content-length"] == str(len(f.data))
        assert response.headers["etag"] == '"' + hashlib.sha256(f.data).hexdigest() + '"'
        assert response.headers["cache-control"] == "no-store, no-cache, must-revalidate"
        assert (await row(f))["download_count"] == 1
    else:
        assert response.content != f.data and (await row(f))["download_count"] == 0
    assert files(f) == before


@pytest.mark.parametrize("kind,status", (("read-key", 200), ("admin-key", 200), ("wrong-scope", 403)))
async def test_public_scoped_key_ceiling_is_not_replaced_by_superuser_role(public_reader, kind, status):
    f = public_reader
    await seed(f, "legacy-explicit", f.org)
    response = await f.public_client.get(path(f), headers=await readers.credentials(f, kind))
    assert response.status_code == status
    assert (await row(f))["download_count"] == int(status == 200)


@pytest.mark.parametrize("method", ("GET", "HEAD"))
@pytest.mark.parametrize("requested,status,body", (
    (None, 200, b"0123456789"), ("bytes=2-5", 206, b"2345"),
    ("bytes=100-", 416, b""), ("invalid", 400, None), ("bytes=0-1,8-9", 206, None),
))
async def test_public_legacy_ranges_and_head_preserve_exact_headers(public_reader, method, requested, status, body):
    f = public_reader
    await seed(f, "legacy-null", f.org)
    headers = await readers.credentials(f, "agent")
    if requested:
        headers["Range"] = requested
    response = await f.public_client.request(method, path(f), headers=headers)
    assert response.status_code == status
    if method == "HEAD":
        assert response.content == b""
    elif body is not None:
        assert response.content == body
    elif requested == "bytes=0-1,8-9":
        assert b"\r\n\r\n01\r\n" in response.content and b"\r\n\r\n89\r\n" in response.content
        assert len(response.content) == int(response.headers["content-length"])
    assert (await row(f))["download_count"] == int(method == "GET" and status in (200, 206))


@pytest.mark.parametrize("change", ("agent-disabled", "agent-key", "agent-org", "user-counter", "key-expiry", "key-scope", "release-owner", "release-deleted"))
async def test_public_legacy_rechecks_real_changes_after_actual_hashing(public_reader, monkeypatch, change):
    f = public_reader
    await seed(f, "legacy-explicit", f.org)
    kind = "agent" if change.startswith("agent") else "jwt" if change == "user-counter" else "key"
    credential = await readers.credentials(f, kind)
    original = binary._LegacyReadStorage.acquire
    fired = False

    async def alter(storage, root, expected):
        nonlocal fired
        prepared = await original(storage, root, expected)
        async with f.engine.begin() as db:
            if change.startswith("agent"):
                values = {"agent-disabled": {"is_enabled": False}, "agent-key": {"agent_key": "a" * 64},
                          "agent-org": {"organization_id": f.other_org}}[change]
                await db.execute(update(RemoteAgent).where(RemoteAgent.id == f.agent_id).values(**values))
            elif change == "user-counter":
                await db.execute(update(User).where(User.id == f.user).values(token_version=901))
            elif change.startswith("key"):
                values = {"expires_at": datetime.now(UTC) - timedelta(seconds=1)} if change == "key-expiry" else {"scopes": ["backup:read"]}
                await db.execute(update(APIKey).where(APIKey.id == f.key_id).values(**values))
            elif change == "release-owner":
                await db.execute(update(AgentRelease).where(AgentRelease.id == f.release_id).values(organization_id=f.other_org))
            else:
                await db.execute(delete(AgentRelease).where(AgentRelease.id == f.release_id))
        fired = True
        return prepared

    monkeypatch.setattr(binary._LegacyReadStorage, "acquire", alter)
    response = await f.public_client.get(path(f), headers=credential)
    assert fired and response.status_code in (401, 403, 404, 409)
    assert response.content != f.data and f.legacy_path.read_bytes() == f.data
    current = await row(f)
    assert current is None if change == "release-deleted" else current["download_count"] == 0


@pytest.mark.parametrize("fault", ("no-signature", "invalid-signature", "external-url", "wrong-checksum", "ambiguous-null"))
async def test_unknown_legacy_data_has_explicit_refusal_without_repair(public_reader, fault):
    f = public_reader
    await seed(f, "legacy-null" if fault == "ambiguous-null" else "legacy-explicit", f.org)
    if fault == "ambiguous-null":
        (f.legacy_root / (str(f.release_id) + "-other.bin")).write_bytes(f.data)
    else:
        values = {"no-signature": {"signature": None}, "invalid-signature": {"signature": "invalid"},
                  "external-url": {"download_url": "https://external.invalid/artifact"},
                  "wrong-checksum": {"checksum_sha256": "0" * 64}}[fault]
        async with f.engine.begin() as db:
            await db.execute(update(AgentRelease).where(AgentRelease.id == f.release_id).values(**values))
    before, before_files = dict(await row(f)), files(f)
    response = await f.public_client.get(path(f), headers=await readers.credentials(f, "agent"))
    assert response.status_code in (409, 503) and response.content != f.data
    assert dict(await row(f)) == before and files(f) == before_files
    assert str(f.legacy_root) not in response.text and f.password not in response.text


@pytest.mark.parametrize("fault", ("payload", "signature"))
async def test_managed_failure_never_uses_matching_legacy_lookalike(public_reader, fault):
    f = public_reader
    await seed(f, "managed", f.org)
    metadata = f.publication.metadata()
    lookalike = f.legacy_root / (str(f.release_id) + "-" + metadata["filename"])
    lookalike.write_bytes(f.data)
    if fault == "payload":
        (f.artifacts / str(f.publication.operation_id) / "payload").write_bytes(b"bad")
    else:
        async with f.engine.begin() as db:
            await db.execute(update(AgentRelease).where(AgentRelease.id == f.release_id).values(signature="invalid"))
    response = await f.public_client.get(path(f), headers=await readers.credentials(f, "agent"))
    assert response.status_code == 503 and response.content != f.data
    assert lookalike.read_bytes() == f.data and (await row(f))["download_count"] == 0


@pytest.mark.parametrize("change", ("deleted", "owner"))
async def test_legacy_selection_is_revalidated_before_opening_files(public_reader, monkeypatch, change):
    f = public_reader
    await seed(f, "legacy-explicit", f.org)
    original = binary._observe_local
    fired = False

    async def alter(*args, **kwargs):
        nonlocal fired
        observed = await original(*args, **kwargs)
        if kwargs.get("classify"):
            assert observed == "legacy"
            async with f.engine.begin() as db:
                if change == "deleted":
                    await db.execute(delete(AgentRelease).where(AgentRelease.id == f.release_id))
                else:
                    await db.execute(update(AgentRelease).where(AgentRelease.id == f.release_id).values(organization_id=f.other_org))
            fired = True
        return observed

    monkeypatch.setattr(binary, "_observe_local", alter)
    response = await f.public_client.get(path(f), headers=await readers.credentials(f, "agent"))
    assert fired and response.status_code == 404 and f.legacy_path.read_bytes() == f.data

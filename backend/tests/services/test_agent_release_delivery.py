"""Planned real PostgreSQL/auth/ASGI/owned-file reader contracts; not executed.

HEAD is explicit in this private harness, not a claim about the public GET route.
Controlled waits/errors are not host-loss, real-network or deployed-agent proof.
"""

import asyncio
import hashlib
import threading
from contextlib import asynccontextmanager
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import httpx
import pytest
import pytest_asyncio
from fastapi import Depends, FastAPI, HTTPException, Request
from sqlalchemy import insert, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import CurrentUser, get_current_user_optional
from app.db.session import get_session
from app.main import app as product_app
from app.models.agents import AgentRelease, RemoteAgent
from app.models.api_keys import APIKey
from app.models.core import User
from app.services import agent_release_delivery as delivery
from app.services import agent_release_publication as publication_code
from app.services import agent_release_reservation as reservation_code
from app.services.agent_release_artifact_store import ArtifactBusy, ArtifactLease
from app.services.agent_release_delete_request import ReleaseDeletionRequest
from app.services.agent_release_preparation import _intent
from app.services.agent_release_read_authority import capture_release_read_authority
from app.services.agent_release_request import _encode
from app.services.release_signing import SigningKeyError
from tests.db.conftest import maintenance_engine as maintenance_engine
from tests.services import test_agent_release_cleanup_coordinator as cleanup_probes
from tests.services import test_agent_release_deletion as deletion_probes
from tests.services import test_agent_release_preparation as preparation_probes
from tests.services import test_agent_release_publication as publication_probes
from tests.services import test_agent_signing_lifecycle as lifecycle_probes


@pytest_asyncio.fixture
async def reader(maintenance_engine, monkeypatch, tmp_path):
    context = asynccontextmanager(cleanup_probes.cleaner.__wrapped__)
    async with context(maintenance_engine, monkeypatch, tmp_path) as f:
        f.capture_only, f.read_authority, f.reader_response = False, None, None
        f.agent_id = uuid4()
        f.agent_key = "owned-reader-" + uuid4().hex
        async with f.engine.begin() as db:
            await db.execute(insert(RemoteAgent).values(id=f.agent_id, name="owned-reader",
                agent_key=hashlib.sha256(f.agent_key.encode()).hexdigest(), organization_id=f.org,
                is_approved=True, is_enabled=True))
        app = FastAPI(exception_handlers=product_app.exception_handlers)

        async def request_session():
            async with AsyncSession(f.engine, expire_on_commit=False, autoflush=False) as db:
                yield db

        app.dependency_overrides[get_session] = request_session

        @app.api_route("/owned/read-binary", methods=["GET", "HEAD"])
        async def fetch(request: Request, user: CurrentUser | None = Depends(get_current_user_optional)):
            f.read_authority = await capture_release_read_authority(request, user, secret_key=f.secret)
            if f.capture_only:
                return {"captured": True}
            f.reader_response = delivery.ManagedReleaseResponse(authority=f.read_authority,
                release_id=f.publication.release_id, root=str(f.artifacts))
            return f.reader_response

        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),
                                     base_url="http://test") as client:
            f.read_client = client
            yield f


async def publish(f, *, organization, data=b"0123456789", latest=True):
    f.data = data
    metadata = f.publication.metadata()
    metadata.update(file_size=len(data), checksum_sha256=hashlib.sha256(data).hexdigest(), is_latest=latest)
    f.publication = replace(f.publication, organization_id=organization, metadata_bytes=_encode(metadata))
    credential = await lifecycle_probes.headers(f)
    await publication_probes.prepare_owned(f, credential)
    assert (await publication_probes.call(f, credential)).status_code == 200
    return credential


async def credentials(f, kind):
    if kind == "agent":
        return {"X-Agent-ID": str(f.agent_id), "X-Agent-Key": f.agent_key}
    if kind in ("read-key", "admin-key", "wrong-scope"):
        scopes = {"read-key": ["agent:read"], "admin-key": ["agent:admin"], "wrong-scope": ["backup:read"]}[kind]
        async with f.engine.begin() as db:
            await db.execute(update(APIKey).where(APIKey.id == f.key_id).values(scopes=scopes))
    return await lifecycle_probes.headers(f, "jwt" if kind == "jwt" else "key")


async def capture(f, credential):
    f.capture_only = True
    try:
        assert (await f.read_client.get("/owned/read-binary", headers=credential)).status_code == 200
    finally:
        f.capture_only = False
    return delivery.ManagedReleaseResponse(authority=f.read_authority, release_id=f.publication.release_id,
                                            root=str(f.artifacts))


def scope(*, method="GET", headers=()):
    return {"type": "http", "method": method, "path": "/owned/read-binary", "headers": list(headers),
            "extensions": {"http.response.pathsend": {}}, "asgi": {"version": "3.0", "spec_version": "2.4"}}


async def receive_forever():
    await asyncio.Event().wait()


def completed(messages):
    return any(m["type"] == "http.response.body" and not m.get("more_body", False) for m in messages)


async def counter(f):
    async with AsyncSession(f.engine) as db:
        return await db.scalar(select(AgentRelease.download_count).where(AgentRelease.id == f.publication.release_id))


@pytest.mark.parametrize("kind", ["jwt", "key", "agent", "read-key", "admin-key"])
@pytest.mark.parametrize("target", ["own", "global", "other"])
async def test_real_dual_principal_scope_and_verified_bytes(reader, kind, target):
    f = reader
    await publish(f, organization={"own": f.org, "global": None, "other": f.other_org}[target])
    if kind in ("jwt", "key"):
        async with f.engine.begin() as db:
            await db.execute(update(User).where(User.id == f.user).values(role="viewer"))
    credential = await credentials(f, kind)
    before = preparation_probes.files(f)
    response = await f.read_client.get("/owned/read-binary", headers=credential)
    assert response.status_code == (404 if target == "other" else 200)
    if target != "other":
        assert response.content == f.data
        assert response.headers["content-length"] == str(len(f.data))
        assert response.headers["etag"] == '"' + hashlib.sha256(f.data).hexdigest() + '"'
        assert response.headers["cache-control"] == "private, no-store"
        assert await counter(f) == 1
    else:
        assert await counter(f) == 0
    assert preparation_probes.files(f) == before
    with ArtifactLease.acquire(str(f.artifacts), _intent(f.publication), mode="exclusive"):
        pass


@pytest.mark.parametrize("kind", ["jwt", "key"])
async def test_unscoped_platform_operator_retains_cross_org_download(reader, kind):
    f = reader
    await publish(f, organization=f.other_org)
    response = await f.read_client.get("/owned/read-binary", headers=await credentials(f, kind))
    assert response.status_code == 200 and response.content == f.data


@pytest.mark.parametrize("operator", ["viewer", "super_admin"])
async def test_authenticated_operator_precedence_never_switches_to_agent_scope(reader, operator):
    f = reader
    await publish(f, organization=f.other_org)
    async with f.engine.begin() as db:
        await db.execute(update(RemoteAgent).where(RemoteAgent.id == f.agent_id).values(organization_id=f.other_org))
        await db.execute(update(User).where(User.id == f.user).values(role=operator))
    credential = {**await credentials(f, "agent"), **await credentials(f, "jwt")}
    response = await f.read_client.get("/owned/read-binary", headers=credential)
    assert response.status_code == (404 if operator == "viewer" else 200)
    assert await counter(f) == int(operator == "super_admin")


@pytest.mark.parametrize("storage", ["legacy", "external"])
async def test_unmanaged_release_never_adopts_glob_or_fetches_external_bytes(reader, storage):
    f = reader
    admin = await lifecycle_probes.headers(f)
    row = await deletion_probes.target(f, admin, storage=storage, organization=f.org)
    # The harness chooses by f.publication.release_id, including a legacy row
    # with no publication operation; its retained request is not used as authority.
    f.publication = replace(f.publication, release_id=row["id"], storage_kind="external",
        metadata_bytes=_encode({**f.publication.metadata(), "filename": None}))
    sentinel = f.artifacts / (str(row["id"]) + "-legacy.bin")
    sentinel.write_bytes(b"unverified legacy control")
    before = preparation_probes.files(f)
    response = await f.read_client.get("/owned/read-binary", headers=await credentials(f, "agent"))
    assert response.status_code == 409 and await counter(f) == 0
    assert preparation_probes.files(f) == before


@pytest.mark.parametrize("kind", ["wrong-scope", "absent", "bad-agent", "disabled-agent", "unapproved-agent", "deleted-agent"])
async def test_denied_principals_cannot_deliver_or_count(reader, kind):
    f = reader
    await publish(f, organization=None)
    credential = await credentials(f, "wrong-scope" if kind == "wrong-scope" else "agent")
    if kind == "absent":
        credential = {}
    elif kind == "bad-agent":
        credential["X-Agent-Key"] = "owned-incorrect-reader-key"
    elif kind in ("disabled-agent", "unapproved-agent", "deleted-agent"):
        values = {"disabled-agent": {"is_enabled": False}, "unapproved-agent": {"is_approved": False},
                  "deleted-agent": {"deleted_at": datetime.now(UTC)}}[kind]
        async with f.engine.begin() as db:
            await db.execute(update(RemoteAgent).where(RemoteAgent.id == f.agent_id).values(**values))
    response = await f.read_client.get("/owned/read-binary", headers=credential)
    assert response.status_code == (403 if kind == "wrong-scope" else 401)
    assert await counter(f) == 0 and preparation_probes.files(f)


@pytest.mark.parametrize("requested,status,body", [
    (None, 200, b"0123456789"), ("bytes=2-5", 206, b"2345"), ("bytes=-3", 206, b"789"),
    ("bytes=8-", 206, b"89"), ("bytes=0-3,2-5", 206, b"012345"),
    ("bytes=100-", 416, b""), ("nonsense", 400, None), ("bytes=8-2", 400, None),
])
async def test_http_range_compatibility_uses_owned_reader(reader, requested, status, body):
    f = reader
    await publish(f, organization=f.org)
    credential = await credentials(f, "agent")
    if requested is not None:
        credential["Range"] = requested
    response = await f.read_client.get("/owned/read-binary", headers=credential)
    assert response.status_code == status
    if body is not None:
        assert response.content == body
    assert await counter(f) == int(status in (200, 206))
    if status == 416:
        assert response.headers["content-range"] == "bytes */10"


@pytest.mark.parametrize("method", ["GET", "HEAD"])
async def test_multipart_has_exact_length_and_never_pathsend(reader, method):
    f = reader
    await publish(f, organization=f.org)
    response = await capture(f, await credentials(f, "agent"))
    messages = []

    async def send(message):
        messages.append(message)

    await response(scope(method=method, headers=[(b"range", b"bytes=0-1,8-9")]), receive_forever, send)
    assert completed(messages) and all(m["type"] != "http.response.pathsend" for m in messages)
    headers = dict(messages[0]["headers"])
    body = b"".join(m.get("body", b"") for m in messages)
    assert messages[0]["status"] == 206
    assert b"multipart/byteranges" in headers[b"content-type"]
    if method == "GET":
        assert len(body) == int(headers[b"content-length"])
        assert b"\r\n\r\n01\r\n" in body and b"\r\n\r\n89\r\n" in body
    else:
        assert body == b"" and await counter(f) == 0


@pytest.mark.parametrize("validator", ["etag", "date", "mismatch"])
async def test_if_range_preserves_matching_and_fallback_semantics(reader, validator):
    f = reader
    await publish(f, organization=f.org)
    credential = await credentials(f, "agent")
    first = await f.read_client.get("/owned/read-binary", headers=credential)
    marker = first.headers["etag" if validator == "etag" else "last-modified"] if validator != "mismatch" else '"other"'
    response = await f.read_client.get("/owned/read-binary", headers={**credential, "Range": "bytes=0-1", "If-Range": marker})
    assert response.status_code == (200 if validator == "mismatch" else 206)
    assert response.content == (f.data if validator == "mismatch" else f.data[:2])


@pytest.mark.parametrize("case", ["empty", "too-many-ranges", "count-saturated", "count-negative"])
async def test_empty_range_bound_and_counter_boundaries(reader, case):
    f = reader
    await publish(f, organization=f.org, data=b"" if case == "empty" else b"0123456789")
    credential = await credentials(f, "agent")
    if case == "too-many-ranges":
        credential["Range"] = "bytes=" + ",".join(["0-0"] * 101)
    elif case.startswith("count-"):
        async with f.engine.begin() as db:
            await db.execute(update(AgentRelease).where(AgentRelease.id == f.publication.release_id)
                             .values(download_count=2147483647 if case == "count-saturated" else -1))
    response = await f.read_client.get("/owned/read-binary", headers=credential)
    assert response.status_code == 200 and response.content == f.data
    assert await counter(f) == (2147483647 if case == "count-saturated" else 1)


@pytest.mark.parametrize("change", ["agent-disabled", "agent-key", "agent-organization", "user-counter", "key-expiry", "key-scope"])
async def test_actual_authority_change_after_hashing_prevents_headers(reader, monkeypatch, change):
    f = reader
    await publish(f, organization=f.org)
    kind = "agent" if change.startswith("agent-") else "jwt" if change == "user-counter" else "key"
    credential = await credentials(f, kind)
    original = delivery._ReadStorage.acquire
    fired = False

    async def alter(storage, root, intent):
        nonlocal fired
        result = await original(storage, root, intent)
        async with f.engine.begin() as db:
            if change.startswith("agent-"):
                values = {"agent-disabled": {"is_enabled": False}, "agent-key": {"agent_key": "b" * 64},
                          "agent-organization": {"organization_id": f.other_org}}[change]
                await db.execute(update(RemoteAgent).where(RemoteAgent.id == f.agent_id).values(**values))
            elif change == "user-counter":
                await db.execute(update(User).where(User.id == f.user).values(token_version=900))
            else:
                values = {"expires_at": datetime.now(UTC) - timedelta(seconds=1)} if change == "key-expiry" else {"scopes": ["backup:read"]}
                await db.execute(update(APIKey).where(APIKey.id == f.key_id).values(**values))
        fired = True
        return result

    monkeypatch.setattr(delivery._ReadStorage, "acquire", alter)
    response = await f.read_client.get("/owned/read-binary", headers=credential)
    assert fired and response.status_code in (401, 403) and response.content != f.data
    assert await counter(f) == 0 and preparation_probes.files(f)


@pytest.mark.parametrize("change", ["agent-disabled", "release-deleted"])
async def test_change_after_first_chunk_aborts_without_completion(reader, change):
    f = reader
    admin = await publish(f, organization=f.org, data=b"x" * 131091)
    response = await capture(f, await credentials(f, "agent"))
    messages = []
    fired = False

    async def send(message):
        nonlocal fired
        messages.append(message)
        if not fired and message["type"] == "http.response.body" and message.get("body"):
            fired = True
            if change == "agent-disabled":
                async with f.engine.begin() as db:
                    await db.execute(update(RemoteAgent).where(RemoteAgent.id == f.agent_id).values(is_enabled=False))
            else:
                row = next(r for r in await publication_probes.releases(f) if r["id"] == f.publication.release_id)
                f.deletion = ReleaseDeletionRequest.capture(operation_id=uuid4(), release=row)
                assert (await deletion_probes.call(f, admin)).status_code == 200
                f.cleanup_request, f.cleanup_root = f.deletion, str(f.artifacts)
                assert (await cleanup_probes.call(f, admin)).status_code == 409

    with pytest.raises(RuntimeError):
        await response(scope(), receive_forever, send)
    assert fired and not completed(messages)
    assert b"".join(m.get("body", b"") for m in messages) == f.data[:65536]
    with ArtifactLease.acquire(str(f.artifacts), _intent(f.publication), mode="exclusive"):
        pass
    if change == "release-deleted":
        assert (await cleanup_probes.call(f, admin)).status_code == 200
    else:
        assert await counter(f) == 0


@pytest.mark.parametrize("fault", ["replacement", "native-drift", "invalid-signature"])
async def test_changed_verified_inputs_refuse_without_repair(reader, monkeypatch, fault):
    f = reader
    await publish(f, organization=f.org)
    original = delivery._ReadStorage.acquire
    fired = False

    async def alter(storage, root, intent):
        nonlocal fired
        result = await original(storage, root, intent)
        if fault == "replacement":
            path = f.artifacts / str(f.publication.operation_id) / "payload"
            path.unlink()
            path.write_bytes(b"replacement")
            path.chmod(0o600)
        else:
            async with f.engine.begin() as db:
                if fault == "native-drift":
                    await db.execute(text("ALTER TABLE agents.agent_releases DISABLE TRIGGER release_reference_deferred"))
                else:
                    await db.execute(update(AgentRelease).where(AgentRelease.id == f.publication.release_id).values(signature="invalid-owned-signature"))
        fired = True
        return result

    monkeypatch.setattr(delivery._ReadStorage, "acquire", alter)
    response = await f.read_client.get("/owned/read-binary", headers=await credentials(f, "agent"))
    assert fired and response.status_code in (409, 503) and response.content != f.data
    assert await counter(f) == 0


@pytest.mark.parametrize("latest", [False, True])
async def test_only_explicit_nonlatest_unsigned_artifact_can_be_read(reader, monkeypatch, latest):
    f = reader

    async def unavailable(manifest):
        assert manifest
        raise SigningKeyError("Owned controlled signing unavailability")

    monkeypatch.setattr(publication_code, "sign_manifest_async", unavailable)
    await publish(f, organization=f.org, latest=False)
    if latest:
        async with f.engine.begin() as db:
            await db.execute(update(AgentRelease).where(AgentRelease.id == f.publication.release_id).values(is_latest=True))
    response = await f.read_client.get("/owned/read-binary", headers=await credentials(f, "agent"))
    assert response.status_code == (409 if latest else 200)
    if not latest:
        assert response.content == f.data


@pytest.mark.parametrize("ending", ["disconnect", "task-cancel", "send-failure"])
async def test_active_file_worker_is_drained_before_shared_lifetime_closes(reader, monkeypatch, ending, record_property):
    f = reader
    await publish(f, organization=f.org, data=b"x" * 65537)
    response = await capture(f, await credentials(f, "agent"))
    messages = []
    entered, proceed = threading.Event(), threading.Event()
    disconnected = asyncio.Event()
    original = ArtifactLease.read

    def held(lease, offset, size):
        if size == 65536:
            entered.set()
            if not proceed.wait(10):
                raise RuntimeError("Owned reader gate not released")
        return original(lease, offset, size)

    async def receive():
        await disconnected.wait()
        return {"type": "http.disconnect"}

    async def send(message):
        messages.append(message)
        if ending == "send-failure" and message["type"] == "http.response.body" and message.get("body"):
            raise OSError("Owned controlled send failure")

    monkeypatch.setattr(ArtifactLease, "read", held)
    task = asyncio.create_task(response(scope(), receive, send))
    try:
        assert await asyncio.to_thread(entered.wait, 10)
        if ending == "disconnect":
            disconnected.set()
        elif ending == "task-cancel":
            task.cancel()
            await asyncio.sleep(0)
            task.cancel()
        with pytest.raises(ArtifactBusy):
            ArtifactLease.acquire(str(f.artifacts), _intent(f.publication), mode="exclusive")
        record_property("reader_worker_retains_shared_file_lifetime_until_drain", True)
        proceed.set()
        if ending == "task-cancel":
            with pytest.raises(asyncio.CancelledError):
                await task
        elif ending == "send-failure":
            with pytest.raises(RuntimeError):
                await task
        else:
            await task
        assert not completed(messages)
    finally:
        proceed.set()
        if not task.done():
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
    with ArtifactLease.acquire(str(f.artifacts), _intent(f.publication), mode="exclusive"):
        pass
    assert await counter(f) == 0


async def test_response_construction_is_lazy_and_reuse_is_refused(reader):
    f = reader
    await publish(f, organization=f.org)
    response = await capture(f, await credentials(f, "agent"))
    assert response._storage.lease is None
    messages = []

    async def send(message):
        messages.append(message)

    await response(scope(), receive_forever, send)
    before = list(messages)
    with pytest.raises(HTTPException) as caught:
        await response(scope(), receive_forever, send)
    assert getattr(caught.value, "status_code", None) == 409 and messages == before


@pytest.mark.parametrize("principal", ["jwt", "agent"])
async def test_read_authority_cannot_be_reused_as_mutation_authority(reader, principal):
    f = reader
    await publish(f, organization=f.org)
    await capture(f, await credentials(f, principal))
    before = await deletion_probes.state(f)
    with pytest.raises(HTTPException) as caught:
        await reservation_code.execute_release_reservation(authority=f.read_authority,
            request=f.publication, budget=f.budget, action="cancel")
    assert caught.value.status_code == 422 and await deletion_probes.state(f) == before


@pytest.mark.parametrize("original_latest", [True, False])
async def test_unsigned_read_requires_original_opt_in_not_just_current_demotion(reader, original_latest):
    f = reader
    await publish(f, organization=f.org, latest=original_latest)
    async with f.engine.begin() as db:
        await db.execute(update(AgentRelease).where(AgentRelease.id == f.publication.release_id)
                         .values(is_latest=False, signature=None))
    before = preparation_probes.files(f)
    response = await f.read_client.get("/owned/read-binary", headers=await credentials(f, "agent"))
    assert response.status_code == (409 if original_latest else 200)
    assert await counter(f) == int(not original_latest)
    assert preparation_probes.files(f) == before


@pytest.mark.parametrize("malformed", ["é" * 64, "not-a-digest"])
async def test_malformed_retained_agent_hash_refuses_without_comparison_type_error(reader, malformed):
    f = reader
    await publish(f, organization=f.org)
    async with f.engine.begin() as db:
        await db.execute(update(RemoteAgent).where(RemoteAgent.id == f.agent_id).values(agent_key=malformed))
    response = await f.read_client.get("/owned/read-binary", headers=await credentials(f, "agent"))
    assert response.status_code == 401 and await counter(f) == 0

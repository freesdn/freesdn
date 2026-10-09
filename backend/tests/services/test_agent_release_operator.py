"""Planned actual router/auth/PostgreSQL operation contracts; not executed.

Only this isolated harness registers the private router. Owned artifacts are
prepared through the existing isolated coordinator harness, not a public upload.
No IdP, hardware, customer data or deployed signing key is used.
"""

import json
from contextlib import asynccontextmanager
from dataclasses import replace
from uuid import uuid4

import httpx
import pytest
import pytest_asyncio
from fastapi import FastAPI
from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.endpoints.agent_release_operations import (
    ReleaseOperationPolicy,
    create_release_operation_router,
)
from app.db.session import get_session
from app.main import app as product_app
from app.models.api_keys import APIKey
from app.models.core import User
from app.schemas.agent_release_operations import MAX_COMMAND_BYTES, decode_release_command
from app.services.agent_release_delete_request import ReleaseDeletionRequest
from app.services.agent_release_request import _encode
from tests.db.conftest import maintenance_engine as maintenance_engine
from tests.services import test_agent_release_cleanup_coordinator as cleanup_probes
from tests.services import test_agent_release_deletion as deletion_probes
from tests.services import test_agent_release_preparation as preparation_probes
from tests.services import test_agent_release_publication as publication_probes
from tests.services import test_agent_release_reservation as reservation_probes
from tests.services import test_agent_signing_lifecycle as lifecycle_probes


def envelope(command):
    value = {"kind": "delete" if type(command) is ReleaseDeletionRequest else "publish",
             "operation_id": str(command.operation_id), "release_id": str(command.release_id),
             "organization_id": str(command.organization_id) if command.organization_id is not None else None,
             "metadata": json.loads(command.metadata_bytes)}
    if value["kind"] == "publish":
        value["storage_kind"] = command.storage_kind
    return value


@pytest.mark.parametrize("notes", ["x" * 20000, "🦉" * 20000, "\x01" * 20000])
def test_supported_metadata_survives_json_without_commitment_changes(notes):
    original = reservation_probes.request_for(uuid4(), notes=notes)
    restored = decode_release_command(_encode(envelope(original)))
    assert restored == original and restored.request_bytes() == original.request_bytes()
    assert restored.metadata()["release_notes"] == notes


@pytest.mark.parametrize("change", ["root", "budget", "authority", "zero-operation", "legacy", "bool-size", "string-latest", "extra-metadata", "metadata-array"])
def test_json_cannot_add_authority_or_relax_operation_contract(change):
    value = envelope(reservation_probes.request_for(uuid4()))
    if change in ("root", "budget", "authority"):
        value[change] = {"untrusted": "owned-control"}
    elif change == "zero-operation":
        value["operation_id"] = "00000000-0000-0000-0000-000000000000"
    elif change == "legacy":
        value["storage_kind"] = "legacy"
    elif change == "bool-size":
        value["metadata"]["file_size"] = True
    elif change == "string-latest":
        value["metadata"]["is_latest"] = "true"
    elif change == "extra-metadata":
        value["metadata"]["signature"] = "client-must-not-sign"
    else:
        value["metadata"] = []
    with pytest.raises(ValueError):
        decode_release_command(_encode(value))


@pytest.mark.parametrize("raw", [b"", b"[]", b"{", b'{"kind":"publish","kind":"delete"}', b'{"metadata":{"x":1,"x":2}}', b'{"value":NaN}', b'{"value":Infinity}', b'{"value":"\\ud800"}', b'\xff'])
def test_malformed_ambiguous_or_nonfinite_json_is_refused(raw):
    with pytest.raises((ValueError, UnicodeError)):
        decode_release_command(raw)


@pytest_asyncio.fixture
async def operator(maintenance_engine, monkeypatch, tmp_path):
    context = asynccontextmanager(cleanup_probes.cleaner.__wrapped__)
    async with context(maintenance_engine, monkeypatch, tmp_path) as f:
        app = FastAPI(exception_handlers=product_app.exception_handlers)

        async def request_session():
            async with AsyncSession(f.engine, expire_on_commit=False, autoflush=False) as db:
                yield db

        app.dependency_overrides[get_session] = request_session
        app.include_router(create_release_operation_router(ReleaseOperationPolicy(str(f.artifacts), f.budget)))
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),
                                     base_url="http://test") as client:
            f.operator_client = client
            yield f


async def call(f, credential, action, command=None, *, raw=None, extra_headers=None, path_id=None):
    command = command or f.publication
    return await f.operator_client.post(f"/release-operations/{path_id or command.operation_id}/{action}",
        content=_encode(envelope(command)) if raw is None else raw,
        headers={**credential, "Content-Type": "application/json", **(extra_headers or {})})


@pytest.mark.parametrize("kind", ["jwt", "key"])
async def test_real_reserve_status_exact_replay_and_cancel(operator, kind):
    f = operator
    credential = await lifecycle_probes.headers(f, kind)
    before = preparation_probes.files(f)
    first = await call(f, credential, "reserve")
    assert first.status_code == 200 and first.json()["result"]["created"] is True
    assert first.json()["intent_sha256"] == f.publication.request_sha256()
    assert first.json()["authorization_granted"] is False
    assert first.headers["cache-control"] == "private, no-store"
    saved = await reservation_probes.journal(f)
    assert saved[0]["request_bytes"] == f.publication.request_bytes()
    status = await f.operator_client.get(f"/release-operations/{f.publication.operation_id}", headers=credential)
    assert status.status_code == 200 and status.json()["operation"]["phase"] == "reserved"
    assert status.json()["authorization_granted"] is False
    assert "request_bytes" not in status.text and "artifact_id" not in status.text
    assert (await call(f, credential, "reserve")).status_code == 200
    assert await reservation_probes.journal(f) == saved
    cancelled = await call(f, credential, "cancel")
    assert cancelled.status_code == 200 and cancelled.json()["result"]["decision"] == "cancelled"
    stable = await deletion_probes.state(f)
    assert (await call(f, credential, "cancel")).status_code == 200 and await deletion_probes.state(f) == stable
    assert preparation_probes.files(f) == before
    await reservation_probes.assert_leases_free(f, f.publication)


@pytest.mark.parametrize("kind", ["jwt", "key"])
@pytest.mark.parametrize("storage", ["owned", "external"])
async def test_real_publish_delete_and_explicit_cleanup(operator, kind, storage):
    f = operator
    credential = await lifecycle_probes.headers(f, kind)
    publication_probes.configure(f, organization=f.org, storage=storage)
    if storage == "owned":
        await publication_probes.prepare_owned(f, credential)
        resumed = await call(f, credential, "resume")
        assert resumed.status_code == 200 and resumed.json()["result"]["phase"] == "prepared"
    published = await call(f, credential, "publish")
    assert published.status_code == 200 and published.json()["result"]["newly_published"] is True
    row = next(r for r in await publication_probes.releases(f) if r["id"] == f.publication.release_id)
    assert row["signature"] is not None
    deletion = ReleaseDeletionRequest.capture(operation_id=uuid4(), release=row)
    before = preparation_probes.files(f)
    deleted = await call(f, credential, "delete", deletion)
    assert deleted.status_code == 200 and deleted.json()["result"]["decision"] == "deleted"
    assert preparation_probes.files(f) == before
    cleaned = await call(f, credential, "cleanup", deletion)
    assert cleaned.status_code == 200 and cleaned.json()["result"]["complete"] is True
    assert cleaned.json()["result"]["payload_absence_verified_this_call"] is (storage == "owned")
    state = await deletion_probes.state(f)
    assert (await call(f, credential, "cleanup", deletion)).status_code == 200
    assert await deletion_probes.state(f) == state
    replay = await call(f, credential, "publish")
    assert replay.status_code == 200 and replay.json()["result"]["newly_published"] is False
    assert replay.json()["result"]["release_row_present"] is False
    assert await deletion_probes.state(f) == state


@pytest.mark.parametrize("change", ["different-intent", "path-id", "extra-root", "unsupported-action", "absent-resume", "unknown-cancel", "unknown-cleanup"])
async def test_refusals_preserve_actual_database_and_file_state(operator, change):
    f = operator
    credential = await lifecycle_probes.headers(f)
    if change == "different-intent":
        assert (await call(f, credential, "reserve")).status_code == 200
    before = await deletion_probes.state(f)
    action, command, raw, path_id = "reserve", f.publication, None, None
    if change == "different-intent":
        command = replace(command, metadata_bytes=_encode({**command.metadata(), "release_notes": "different"}))
    elif change == "path-id":
        path_id = uuid4()
    elif change == "extra-root":
        raw = _encode({**envelope(command), "root": "/untrusted-client-input"})
    elif change == "unsupported-action":
        action = "delete"
    else:
        action = {"absent-resume": "resume", "unknown-cancel": "cancel", "unknown-cleanup": "cleanup"}[change]
    response = await call(f, credential, action, command, raw=raw, path_id=path_id)
    expected = {"different-intent": 409, "path-id": 422, "extra-root": 422, "unsupported-action": 422,
                "absent-resume": 404, "unknown-cancel": 404, "unknown-cleanup": 404}[change]
    assert response.status_code == expected and await deletion_probes.state(f) == before
    assert response.headers["cache-control"] == "private, no-store"


@pytest.mark.parametrize("fault,status", [("too-large", 413), ("bad-type", 415), ("encoding", 415), ("length-mismatch", 400), ("duplicate", 422)])
async def test_bounded_ingress_refuses_before_reservation(operator, fault, status):
    f = operator
    credential = await lifecycle_probes.headers(f)
    before = await deletion_probes.state(f)
    raw, headers = _encode(envelope(f.publication)), {}
    if fault == "too-large":
        raw = b" " * (MAX_COMMAND_BYTES + 1)
    elif fault == "bad-type":
        headers["Content-Type"] = "application/octet-stream"
    elif fault == "encoding":
        headers["Content-Encoding"] = "gzip"
    elif fault == "length-mismatch":
        headers["Content-Length"] = "1"
    else:
        raw = b'{"kind":"publish","kind":"delete"}'
    response = await call(f, credential, "reserve", raw=raw, extra_headers=headers)
    assert response.status_code == status and await deletion_probes.state(f) == before
    assert response.headers["cache-control"] == "private, no-store"


@pytest.mark.parametrize("kind", ["jwt", "key"])
@pytest.mark.parametrize("change", ["disabled", "role", "other-org", "credential"])
async def test_actual_authority_change_during_request_body_refuses_mutation(operator, kind, change):
    f = operator
    credential = await lifecycle_probes.headers(f, kind)
    # The caller is an organization admin so a changed destination is denied.
    async with f.engine.begin() as db:
        await db.execute(update(User).where(User.id == f.user).values(role="admin"))
    raw = _encode(envelope(f.publication))
    before = await deletion_probes.state(f)

    async def body():
        yield raw[:1]
        async with f.engine.begin() as db:
            if change == "credential" and kind == "key":
                await db.execute(update(APIKey).where(APIKey.id == f.key_id).values(is_active=False))
            else:
                values = {"disabled": {"is_active": False}, "role": {"role": "viewer"},
                          "other-org": {"organization_id": f.other_org}, "credential": {"token_version": 91}}[change]
                await db.execute(update(User).where(User.id == f.user).values(**values))
        yield raw[1:]

    response = await f.operator_client.post(f"/release-operations/{f.publication.operation_id}/reserve", content=body(),
                                            headers={**credential, "Content-Type": "application/json"})
    assert response.status_code in (401, 403, 404) and await deletion_probes.state(f) == before
    assert response.headers["cache-control"] == "private, no-store"

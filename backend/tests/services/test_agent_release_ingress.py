"""Planned actual auth/PG/file/upload through the shipped body middleware.

The real API prefix matters. The separate fault case deliberately lowers only
its middleware ceiling to force a short reproducible boundary; it does not
qualify the production 500 MiB/proxy/deployment envelope.
"""

import hashlib
from contextlib import asynccontextmanager
from dataclasses import replace

import httpx
import pytest
import pytest_asyncio
from fastapi import FastAPI
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.endpoints.agent_release_operations import (
    ReleaseOperationPolicy,
    create_release_operation_router,
)
from app.core import middleware
from app.core.middleware import BodySizeLimitMiddleware
from app.db.session import get_session
from app.main import app as product_app
from app.services.agent_release_request import _encode
from tests.db.conftest import maintenance_engine as maintenance_engine
from tests.services import test_agent_release_deletion as deletion_probes
from tests.services import test_agent_release_operator as operator_probes
from tests.services import test_agent_release_reservation as reservation_probes
from tests.services import test_agent_release_upload_stream as upload_probes
from tests.services import test_agent_signing_lifecycle as lifecycle_probes


@pytest_asyncio.fixture
async def ingress(maintenance_engine, monkeypatch, tmp_path):
    context = asynccontextmanager(operator_probes.operator.__wrapped__)
    async with context(maintenance_engine, monkeypatch, tmp_path) as f:
        app = FastAPI(exception_handlers=product_app.exception_handlers)

        async def request_session():
            async with AsyncSession(f.engine, expire_on_commit=False, autoflush=False) as db:
                yield db

        app.dependency_overrides[get_session] = request_session
        app.include_router(create_release_operation_router(ReleaseOperationPolicy(str(f.artifacts), f.budget)),
                           prefix="/api/v1/agents")
        app.add_middleware(BodySizeLimitMiddleware)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),
                                     base_url="http://test") as client:
            f.edge_client = client
            yield f


async def call(f, credential, source, *, headers=None):
    return await f.edge_client.post(f"/api/v1/agents/release-operations/{f.publication.operation_id}/upload",
        content=source, headers={**credential, "Content-Type": upload_probes.CONTENT_TYPE, **(headers or {})})


@pytest.mark.parametrize("kind", ["jwt", "key"])
@pytest.mark.parametrize("declared", [False, True])
async def test_real_prefixed_upload_over_one_mib_reaches_prepared_state(ingress, kind, declared):
    f = ingress
    upload_probes.configure(f, bytes(range(256)) * 8193)
    raw = upload_probes.prefix(f.publication) + f.data + upload_probes.suffix()

    async def source():
        for i in range(0, len(raw), 65536):
            yield raw[i:i+65536]

    response = await call(f, await lifecycle_probes.headers(f, kind), raw if declared else source())
    assert response.status_code == 200 and response.json()["result"]["phase"] == "prepared"
    assert upload_probes.payload(f).read_bytes() == f.data
    assert hashlib.sha256(upload_probes.payload(f).read_bytes()).hexdigest() == f.publication.metadata()["checksum_sha256"]
    rows, journal, _ = await deletion_probes.state(f)
    assert not rows and journal[0]["phase"] == "prepared"
    await reservation_probes.assert_leases_free(f, f.publication)


@pytest.mark.parametrize("kind", ["jwt", "key"])
async def test_global_counter_failure_cannot_commit_a_prepared_prefix(ingress, monkeypatch, kind):
    f = ingress
    credential = await lifecycle_probes.headers(f, kind)
    upload_probes.configure(f, b"p" * 65536 + b"unfinished-at-global-boundary")
    raw = upload_probes.prefix(f.publication) + f.data + upload_probes.suffix()
    # Isolated fault injection only. Parser, file-size, admission and time
    # guards are unchanged; this does not validate a 500 MiB transfer.
    monkeypatch.setattr(middleware, "_RELEASE_OPERATION_UPLOAD_MAX_BYTES", len(raw) + 8)

    async def source():
        yield raw
        yield b"ignored-by-parser-epilogue-overflows-global-limit"

    response = await call(f, credential, source())
    rows, journal, _ = await deletion_probes.state(f)
    assert response.status_code == 413 and not rows and len(journal) == 1
    assert journal[0]["phase"] == "reserved" and journal[0]["decision"] is None
    assert not (upload_probes.payload(f).parent / "prepared.json").exists()
    assert upload_probes.payload(f).read_bytes() == f.data[:65536]
    await reservation_probes.assert_leases_free(f, f.publication)
    assert (await operator_probes.call(f, credential, "cancel")).status_code == 200
    assert (await operator_probes.call(f, credential, "cleanup")).status_code == 200
    assert not upload_probes.payload(f).exists()


@pytest.mark.parametrize("kind", ["jwt", "key"])
async def test_private_json_command_keeps_global_and_precise_command_bounds(ingress, kind):
    f = ingress
    credential = await lifecycle_probes.headers(f, kind)
    before = await deletion_probes.state(f)
    body = _encode(operator_probes.envelope(f.publication)) + b" " * 1048577
    response = await f.edge_client.post(f"/api/v1/agents/release-operations/{f.publication.operation_id}/reserve",
                                       content=body, headers={**credential, "Content-Type": "application/json"})
    assert response.status_code == 413 and await deletion_probes.state(f) == before


async def test_valid_maximum_notes_command_and_small_upload_still_work(ingress):
    f = ingress
    credential = await lifecycle_probes.headers(f)
    f.publication = replace(f.publication, metadata_bytes=_encode({**f.publication.metadata(), "release_notes": "🦉" * 20000}))
    response = await call(f, credential, upload_probes.prefix(f.publication) + f.data + upload_probes.suffix())
    assert response.status_code == 200 and response.json()["result"]["phase"] == "prepared"
    rows, journal, _ = await deletion_probes.state(f)
    assert not rows and journal[0]["request_bytes"] == f.publication.request_bytes()

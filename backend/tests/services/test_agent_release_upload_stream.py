"""Planned actual multipart/router/PG/file contracts, not runtime observations.

The existing isolated operator fixture installs native guards and uses real
authentication/coordinators. Transport slicing/disconnect/commit faults are
controlled inputs; they do not prove deployed proxy, disk or host-loss behavior.
"""

import hashlib
from contextlib import asynccontextmanager
from dataclasses import replace
from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy import update
from starlette.requests import ClientDisconnect, Request

from app.models.api_keys import APIKey
from app.models.core import User
from app.services import agent_release_reservation as reservation_code
from app.services.agent_release_artifact_store import ArtifactLease
from app.services.agent_release_preparation import _intent
from app.services.agent_release_request import _encode
from app.services.agent_release_upload_stream import owned_upload_stream
from tests.db.conftest import maintenance_engine as maintenance_engine
from tests.services import test_agent_release_deletion as deletion_probes
from tests.services import test_agent_release_operator as operator_probes
from tests.services import test_agent_release_preparation as preparation_probes
from tests.services import test_agent_release_reservation as reservation_probes
from tests.services import test_agent_signing_lifecycle as lifecycle_probes

BOUNDARY = b"FreeSDN-owned-upload-qualification"
CONTENT_TYPE = "multipart/form-data; boundary=" + BOUNDARY.decode()


@pytest_asyncio.fixture
async def uploader(maintenance_engine, monkeypatch, tmp_path):
    context = asynccontextmanager(operator_probes.operator.__wrapped__)
    async with context(maintenance_engine, monkeypatch, tmp_path) as f:
        yield f


def configure(f, data):
    f.data = data
    f.publication = replace(f.publication, metadata_bytes=_encode({**f.publication.metadata(),
        "file_size": len(data), "checksum_sha256": hashlib.sha256(data).hexdigest()}))


def prefix(command):
    return (b"--" + BOUNDARY + b'\r\nContent-Disposition: form-data; name="intent"\r\n'
            b"Content-Type: application/json\r\n\r\n" + _encode(operator_probes.envelope(command))
            + b"\r\n--" + BOUNDARY + b'\r\nContent-Disposition: form-data; name="file"; filename="transport.bin"\r\n'
            b"Content-Type: application/octet-stream\r\n\r\n")


def suffix():
    return b"\r\n--" + BOUNDARY + b"--\r\n"


async def upload(f, credential, body, *, headers=None):
    return await f.operator_client.post(f"/release-operations/{f.publication.operation_id}/upload", content=body,
        headers={**credential, "Content-Type": CONTENT_TYPE, **(headers or {})})


def payload(f):
    return f.artifacts / str(f.publication.operation_id) / "payload"


@pytest.mark.parametrize("kind", ["jwt", "key"])
@pytest.mark.parametrize("shape", ["empty", "binary", "false-boundaries"])
@pytest.mark.parametrize("chunk_size", [1, 257, 131073, 1048577])
async def test_real_streaming_upload_and_explicit_publication(uploader, kind, shape, chunk_size):
    f = uploader
    data = {"empty": b"", "binary": bytes(range(256)) * 33,
            "false-boundaries": (b"\r\n--" + BOUNDARY + b"-not-a-delimiter\x00") * 7}[shape]
    configure(f, data)
    raw = prefix(f.publication) + data + suffix()

    async def body():
        for i in range(0, len(raw), chunk_size):
            yield raw[i:i+chunk_size]

    credential = await lifecycle_probes.headers(f, kind)
    response = await upload(f, credential, body())
    assert response.status_code == 200 and response.json()["result"]["phase"] == "prepared"
    assert response.json()["intent_sha256"] == f.publication.request_sha256()
    assert response.json()["authorization_granted"] is False
    assert response.headers["cache-control"] == "private, no-store"
    assert payload(f).read_bytes() == data
    with ArtifactLease.acquire(str(f.artifacts), _intent(f.publication), mode="shared") as lease:
        assert lease.verify_prepared().intent.size == len(data)
    rows, history, _ = await deletion_probes.state(f)
    assert not rows and len(history) == 1 and history[0]["phase"] == "prepared"
    assert (await operator_probes.call(f, credential, "publish")).status_code == 200
    await reservation_probes.assert_leases_free(f, f.publication)


async def test_acknowledged_reservation_precedes_first_binary_receive(uploader, record_property):
    f = uploader
    configure(f, b"owned-data")
    observed = False

    async def body():
        nonlocal observed
        yield prefix(f.publication)
        rows, journal, _ = await deletion_probes.state(f)
        observed = not rows and len(journal) == 1 and journal[0]["phase"] == "reserved" and payload(f).exists()
        assert observed and payload(f).read_bytes() == b""
        yield f.data + suffix()

    response = await upload(f, await lifecycle_probes.headers(f), body())
    assert response.status_code == 200 and observed
    record_property("acknowledged_reservation_before_first_binary_receive", observed)


@pytest.mark.parametrize("fault,status", [("no-boundary", 400), ("truncated-closing", 400), ("missing-file", 400),
    ("extra-part", 400), ("file-first", 400), ("duplicate-header", 400), ("oversize-payload", 413),
    ("short-payload", 400), ("wrong-digest", 409), ("wrong-path-intent", 422)])
async def test_invalid_upload_cannot_become_prepared_or_published(uploader, fault, status):
    f = uploader
    configure(f, b"owned-bytes")
    begin, data, end = prefix(f.publication), f.data, suffix()
    if fault == "no-boundary":
        end = b""
    elif fault == "truncated-closing":
        end = suffix()[:-4]
    elif fault == "missing-file":
        begin = begin.split(b'\r\n--' + BOUNDARY + b'\r\nContent-Disposition: form-data; name="file"')[0]
        data = b""
    elif fault == "extra-part":
        end = b"\r\n--" + BOUNDARY + b'\r\nContent-Disposition: form-data; name="extra"\r\n\r\nextra' + suffix()
    elif fault == "file-first":
        begin = begin.replace(b'name="intent"', b'name="file"', 1)
    elif fault == "duplicate-header":
        begin = begin.replace(b"Content-Type: application/json\r\n", b"Content-Type: application/json\r\nContent-Type: application/json\r\n", 1)
    elif fault == "oversize-payload":
        data += b"x"
    elif fault == "short-payload":
        data = data[:-1]
    elif fault == "wrong-digest":
        data = b"X" * len(data)
    else:
        begin = prefix(replace(f.publication, operation_id=uuid4()))
    response = await upload(f, await lifecycle_probes.headers(f), begin + data + end)
    rows, journal, _ = await deletion_probes.state(f)
    assert response.status_code == status and not rows
    assert all(r["phase"] == "reserved" and r["decision"] is None for r in journal)
    assert not (payload(f).parent / "prepared.json").exists()
    await reservation_probes.assert_leases_free(f, f.publication)


@pytest.mark.parametrize("fault,status", [("type", 415), ("encoding", 415), ("length", 400), ("huge-length", 413), ("long-boundary", 415)])
async def test_header_refusal_never_allocates_history_or_managed_storage(uploader, fault, status):
    f = uploader
    configure(f, b"owned")
    headers = {"type": {"Content-Type": "application/octet-stream"}, "encoding": {"Content-Encoding": "gzip"},
               "length": {"Content-Length": "nonsense"}, "huge-length": {"Content-Length": "999999999"},
               "long-boundary": {"Content-Type": "multipart/form-data; boundary=" + "a" * 71}}[fault]
    before = await deletion_probes.state(f)
    response = await upload(f, await lifecycle_probes.headers(f), prefix(f.publication) + f.data + suffix(), headers=headers)
    assert response.status_code == status and await deletion_probes.state(f) == before


@pytest.mark.parametrize("kind", ["jwt", "key"])
async def test_revocation_during_body_wait_preserves_only_already_written_bytes(uploader, kind):
    f = uploader
    configure(f, b"a" * 65536 + b"never-accepted")
    credential = await lifecycle_probes.headers(f, kind)

    async def body():
        yield prefix(f.publication)
        yield f.data[:65536]
        async with f.engine.begin() as db:
            if kind == "key":
                await db.execute(update(APIKey).where(APIKey.id == f.key_id).values(is_active=False))
            else:
                await db.execute(update(User).where(User.id == f.user).values(token_version=101))
        yield f.data[65536:] + suffix()

    response = await upload(f, credential, body())
    rows, journal, _ = await deletion_probes.state(f)
    assert response.status_code == 401 and not rows and journal[0]["phase"] == "reserved"
    assert payload(f).read_bytes() == f.data[:65536]
    assert not (payload(f).parent / "prepared.json").exists()


@pytest.mark.parametrize("disconnect", [False, True])
async def test_partial_framing_or_disconnect_retains_explicit_cancel_cleanup_path(uploader, disconnect):
    f = uploader
    configure(f, b"p" * 65536 + b"unfinished-owned-content")
    credential = await lifecycle_probes.headers(f)

    async def body():
        yield prefix(f.publication)
        yield f.data[:65536]
        if disconnect:
            raise ClientDisconnect()

    response = await upload(f, credential, body())
    assert response.status_code == 400 and payload(f).read_bytes() == f.data[:65536]
    before = await deletion_probes.state(f)
    repeated = await upload(f, credential, prefix(f.publication) + f.data + suffix())
    assert repeated.status_code == 409 and await deletion_probes.state(f) == before
    assert (await operator_probes.call(f, credential, "cancel")).status_code == 200
    cleaned = await operator_probes.call(f, credential, "cleanup")
    assert cleaned.status_code == 200 and cleaned.json()["result"]["complete"] is True
    assert not payload(f).exists() and (payload(f).parent / "cleaned.json").exists()


@pytest.mark.parametrize("timing", ["before", "after"])
async def test_unconfirmed_reservation_never_starts_managed_file_work(uploader, monkeypatch, timing):
    f = uploader
    configure(f, b"owned-after-confirmation")
    original = reservation_code._commit_phase
    fired = False

    async def uncertain(db):
        nonlocal fired
        if fired:
            return await original(db)
        fired = True
        if timing == "after":
            await original(db)
        raise RuntimeError("controlled reservation acknowledgment loss")

    monkeypatch.setattr(reservation_code, "_commit_phase", uncertain)
    credential = await lifecycle_probes.headers(f)
    files_before = preparation_probes.files(f)
    response = await upload(f, credential, prefix(f.publication) + f.data + suffix())
    assert response.status_code == 503 and fired and preparation_probes.files(f) == files_before
    rows, journal, _ = await deletion_probes.state(f)
    assert not rows and len(journal) == int(timing == "after")
    if journal:
        assert journal[0]["phase"] == "reserved"
    # A separate explicit identical-intent request after observing the outcome.
    monkeypatch.setattr(reservation_code, "_commit_phase", original)
    retry = await upload(f, credential, prefix(f.publication) + f.data + suffix())
    assert retry.status_code == 200 and payload(f).read_bytes() == f.data


@pytest.mark.parametrize("fault,status", [("absent", 401), ("viewer", 403), ("key-scope", 403), ("other-org", 404)])
async def test_denied_authority_never_requests_binary_or_allocates_files(uploader, fault, status):
    f = uploader
    configure(f, b"private-owned-file")
    async with f.engine.begin() as db:
        if fault in ("viewer", "other-org"):
            await db.execute(update(User).where(User.id == f.user).values(role="viewer" if fault == "viewer" else "admin"))
        elif fault == "key-scope":
            await db.execute(update(APIKey).where(APIKey.id == f.key_id).values(scopes=["backup:read"]))
    if fault == "other-org":
        f.publication = replace(f.publication, organization_id=f.other_org)
    credential = {} if fault == "absent" else await lifecycle_probes.headers(f, "key" if fault == "key-scope" else "jwt")
    binary_requested = False

    async def body():
        nonlocal binary_requested
        yield prefix(f.publication)
        binary_requested = True
        yield f.data + suffix()

    before = await deletion_probes.state(f)
    response = await upload(f, credential, body())
    assert response.status_code == status and not binary_requested
    assert await deletion_probes.state(f) == before


@pytest.mark.parametrize("fragment", [1, 257, 1048577])
async def test_parser_coalesces_transport_without_spool_or_changed_payload(fragment):
    data = bytes(range(256)) * 257
    command = reservation_probes.request_for(uuid4(), size=len(data))
    command = replace(command, metadata_bytes=_encode({**command.metadata(),
        "checksum_sha256": hashlib.sha256(data).hexdigest()}))
    raw = prefix(command) + data + suffix()
    offset = 0

    async def receive():
        nonlocal offset
        chunk = raw[offset:offset + fragment]
        offset += len(chunk)
        return {"type": "http.request", "body": chunk, "more_body": offset < len(raw)}

    request = Request({"type": "http", "method": "POST", "path": "/owned/parser",
                       "headers": [(b"content-type", CONTENT_TYPE.encode())]}, receive=receive)
    async with owned_upload_stream(request, command.operation_id) as stream:
        assert await stream.read_intent() == command
        blocks = [chunk async for chunk in stream.chunks()]
        assert [len(chunk) for chunk in blocks] == [65536, 256]
        assert b"".join(blocks) == data and stream.ended and stream.eof
    assert stream.closed

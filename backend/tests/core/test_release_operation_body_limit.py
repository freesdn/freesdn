"""Planned real ASGI middleware overflow and route-cap contracts; unexecuted.

No middleware mocks in core cases. A recorded handler write is an acceptance
probe, not a substitute for the separate actual PostgreSQL/upload cases.
"""

import json

import httpx
import pytest
from fastapi import FastAPI, Request

from app.core.middleware import _RELEASE_OPERATION_UPLOAD_MAX_BYTES, BodySizeLimitMiddleware
from app.schemas.agent_release_operations import MAX_COMMAND_BYTES
from app.services.agent_release_upload_stream import _MAX_FILE, _OVERHEAD

OP = "19a2a76c-f2ef-4a64-9ae7-9347c49cb218"
UPLOAD = f"/api/v1/agents/release-operations/{OP}/upload"


def app_for(mode="raw", limit=256):
    app = FastAPI()
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=limit)
    accepted = []

    @app.api_route("/{path:path}", methods=["POST", "PUT", "GET"])
    async def consume(request: Request, path: str):
        if mode == "json":
            value = await request.json()
        elif mode == "form":
            value = dict(await request.form())
        else:
            value = len(await request.body())
        accepted.append(value)
        return {"received": value}

    return app, accepted


def valid_prefix(mode):
    return {"raw": (b"valid payload", "application/octet-stream"),
            "json": (b'{"value":"valid"}', "application/json"),
            "form": (b"value=valid", "application/x-www-form-urlencoded")}[mode]


@pytest.mark.parametrize("mode", ["raw", "json", "form"])
async def test_stream_overflow_is_not_successful_eof_that_accepts_a_valid_prefix(mode):
    app, accepted = app_for(mode)
    first, media = valid_prefix(mode)

    async def source():
        yield first
        yield b" " * 257

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post("/control", content=source(), headers={"Content-Type": media})
    assert response.status_code == 413 and accepted == []


@pytest.mark.parametrize("mode", ["raw", "json", "form"])
async def test_normal_chunked_completion_still_reaches_the_handler(mode):
    app, accepted = app_for(mode)
    first, media = valid_prefix(mode)

    async def source():
        yield first[:3]
        yield first[3:]

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post("/control", content=source(), headers={"Content-Type": media})
    assert response.status_code == 200 and len(accepted) == 1
    assert response.json()["received"] == (len(first) if mode == "raw" else {"value": "valid"})


@pytest.mark.parametrize("upper", [False, True])
@pytest.mark.parametrize("trailing", [False, True])
@pytest.mark.parametrize("declared", [False, True])
async def test_exact_upload_path_accepts_real_bytes_above_control_plane_cap(upper, trailing, declared):
    app, accepted = app_for(limit=1048576)
    path = UPLOAD.replace(OP, OP.upper()) if upper else UPLOAD
    if trailing:
        path += "/"
    data = b"a" * (1048576 + 4096)

    async def source():
        yield data[:65536]
        yield data[65536:]

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(path, content=data if declared else source())
    assert response.status_code == 200 and accepted == [len(data)]


@pytest.mark.parametrize("path,method", [
    (f"/api/v1/agents/release-operations/{OP}/publish", "POST"),
    (f"/api/v1/agents/release-operations/{OP}/reserve", "POST"),
    (f"/api/v1/agents/release-operations/{OP}/cleanup", "POST"),
    (UPLOAD + "/extra", "POST"), (UPLOAD + "-other", "POST"),
    (UPLOAD.replace(OP, "not-a-uuid"), "POST"), (UPLOAD.replace("/agents/", "/agents-other/"), "POST"),
    ("/api/v1/agents/release-operation-intents/review", "POST"),
    (UPLOAD, "GET"), (UPLOAD, "PUT"),
])
async def test_new_upload_ceiling_does_not_expand_other_actions_or_similar_paths(path, method):
    app, accepted = app_for(limit=1048576)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        response = await client.request(method, path, content=b"", headers={"Content-Length": "1048577"})
    assert response.status_code == 413 and accepted == []


def test_documented_private_wire_ceiling_equals_existing_parser_allowance():
    assert _RELEASE_OPERATION_UPLOAD_MAX_BYTES == 524660736
    assert _RELEASE_OPERATION_UPLOAD_MAX_BYTES == _MAX_FILE + MAX_COMMAND_BYTES + _OVERHEAD


async def test_private_upload_declared_overflow_never_enters_the_handler():
    app, accepted = app_for()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(UPLOAD, content=b"", headers={"Content-Length": str(_RELEASE_OPERATION_UPLOAD_MAX_BYTES + 1)})
    assert response.status_code == 413 and accepted == []


async def test_overflow_remains_a_failed_receive_without_consuming_more_source():
    app = FastAPI()
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=16)
    failed = []
    consumed = 0

    @app.post("/control")
    async def consume(request: Request):
        await request.receive()
        for _ in range(2):
            try:
                await request.receive()
            except Exception:
                failed.append(True)
        return {"failed_receives": len(failed)}

    async def source():
        nonlocal consumed
        for value in (b"a", b"b" * 16, b"must-not-be-read"):
            consumed += 1
            yield value

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post("/control", content=source())
    assert response.status_code == 413 and failed == [True, True] and consumed == 2


async def test_unrelated_handler_failure_is_not_hidden_by_overflow():
    app = FastAPI()
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=16)

    @app.post("/control")
    async def consume(request: Request):
        try:
            await request.body()
        except Exception as error:
            raise RuntimeError("independent-owned-handler-failure") from error
        return {}

    async def source():
        yield json.dumps({"a": 1}).encode()
        yield b" " * 17

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        with pytest.raises(Exception, match="independent-owned-handler-failure"):
            await client.post("/control", content=source())

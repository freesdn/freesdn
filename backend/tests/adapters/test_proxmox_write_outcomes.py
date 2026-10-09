# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Exercise real client → adapter boundaries, including swallowed exceptions."""

import httpx
import pytest

from app.adapters.exceptions import AdapterOutcomeUnknownError
from app.adapters.proxmox.adapter import ProxmoxAdapter
from app.adapters.proxmox.client import ProxmoxClient, ProxmoxClientConfig
from app.adapters.validation import validate_upid
from app.services.adapter_staging import outcome_is_unknown

UPID = "UPID:pve1:00001234:00ABCDEF:00000000:qmstart:101:root@pam!audit:"


def connected(handler):
    client = ProxmoxClient(ProxmoxClientConfig(host="192.0.2.1"))
    client._http = httpx.AsyncClient(
        transport=httpx.MockTransport(handler), base_url="https://pve.invalid"
    )
    client._authenticated = True
    adapter = ProxmoxAdapter(host="192.0.2.1", username="root", password="fixture")
    adapter._client = client
    adapter._connected = True
    return adapter, client


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "error",
    [
        httpx.ReadTimeout,
        httpx.WriteTimeout,
        httpx.ReadError,
        httpx.WriteError,
        httpx.RemoteProtocolError,
        httpx.DecodingError,
    ],
)
async def test_write_uncertainty_survives_adapter_and_is_never_retried(error):
    calls = []

    def dispatch(request):
        calls.append(request.method)
        raise error("sensitive upstream response", request=request)

    adapter, client = connected(dispatch)
    try:
        with pytest.raises(AdapterOutcomeUnknownError) as caught:
            await adapter.start_vm("pve1", 101, force=True)
        assert outcome_is_unknown(caught.value)
        assert "sensitive" not in str(caught.value)
        assert calls == ["POST"]
    finally:
        await client._http.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("error", [httpx.ConnectTimeout, httpx.PoolTimeout, httpx.ConnectError])
async def test_pre_dispatch_failure_remains_definite(error):
    calls = []

    def dispatch(request):
        calls.append(request.method)
        raise error("not connected", request=request)

    adapter, client = connected(dispatch)
    try:
        result = await adapter.start_vm("pve1", 101, force=True)
        assert not result.success
        assert calls == ["POST"]
    finally:
        await client._http.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "status,body",
    [
        (500, b'{"errors":{"reason":"failed"}}'),
        (502, b"gateway error"),
        (503, b"unavailable"),
        (504, b"timeout"),
        (200, b"<html>login</html>"),
        (200, b"{}"),
        (200, b"[]"),
        (204, b""),
        (302, b'{"data":null}'),
    ],
)
async def test_ambiguous_write_response_is_not_false_success_or_rejection(status, body):
    calls = []

    def dispatch(request):
        calls.append(request.method)
        return httpx.Response(status, content=body)

    adapter, client = connected(dispatch)
    try:
        with pytest.raises(AdapterOutcomeUnknownError):
            await adapter.start_vm("pve1", 101, force=True)
        assert calls == ["POST"]
    finally:
        await client._http.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [400, 401, 403, 404, 409])
async def test_explicit_rejection_remains_failure_without_replay(status):
    calls = []

    def dispatch(request):
        calls.append(request.method)
        return httpx.Response(status, json={"errors": {"field": "rejected"}})

    adapter, client = connected(dispatch)
    try:
        assert not (await adapter.start_vm("pve1", 101, force=True)).success
        assert calls == ["POST"]
    finally:
        await client._http.aclose()


@pytest.mark.asyncio
async def test_null_data_is_a_valid_synchronous_acknowledgement():
    _, client = connected(lambda _request: httpx.Response(200, json={"data": None}))
    try:
        assert (
            await client.put("/nodes/pve1/qemu/101/config", data={"name": "test"}, force=True)
            is None
        )
    finally:
        await client._http.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["timeout", "bad_body", "server_error"])
async def test_upload_does_not_swallow_unknown_outcome(tmp_path, failure):
    path = tmp_path / "fixture.iso"
    path.write_bytes(b"fixture only")
    calls = []

    def dispatch(request):
        calls.append(request.method)
        if failure == "timeout":
            raise httpx.ReadTimeout("lost acknowledgement", request=request)
        return httpx.Response(200 if failure == "bad_body" else 502, content=b"invalid")

    adapter, client = connected(dispatch)
    try:
        with pytest.raises(AdapterOutcomeUnknownError):
            await adapter.upload_to_storage(
                "pve1", "local", "fixture.iso", "application/x-iso9660-image", str(path), force=True
            )
        assert calls == ["POST"]
    finally:
        await client._http.aclose()


@pytest.mark.asyncio
async def test_task_status_rejects_wrong_provider_identity():
    adapter, client = connected(
        lambda _request: httpx.Response(
            200,
            json={
                "data": {
                    "upid": UPID.replace("101:", "102:"),
                    "node": "pve1",
                    "status": "stopped",
                    "exitstatus": "OK",
                }
            },
        )
    )
    try:
        assert not (await adapter.get_task_status("pve1", UPID)).success
    finally:
        await client._http.aclose()


def test_api_token_task_id_is_accepted_but_url_injection_is_not():
    from fastapi import HTTPException

    assert validate_upid(UPID) == UPID
    for suffix in ["\n", "/status", "?x=1", "#fragment", "%2f", "..", "\\path"]:
        with pytest.raises(HTTPException):
            validate_upid(UPID + suffix)

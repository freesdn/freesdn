"""Actual OPNsense HTTP client/adapter parsing with synthetic HTTP transport."""

import asyncio
import json
from uuid import uuid4

import httpx
import pytest
import pytest_asyncio

from app.adapters.opnsense.adapter import OPNsenseAdapter

SECRET = "owned-private-certificate-diagnostic"
ROW = {
    "uuid": str(uuid4()),
    "dn_commonname": "owned.example.test",
    "descr": "Owned α",
    "valid_to": "1900000000",
    "prv": SECRET,
    "crt_payload": SECRET,
}


def envelope(rows=None):
    rows = [ROW] if rows is None else rows
    return {"rows": rows, "total": len(rows), "rowCount": len(rows), "current": 1}


@pytest_asyncio.fixture
async def wire():
    adapter = OPNsenseAdapter(
        host="192.0.2.55", username="owned-key", password="owned-secret", verify_ssl=True
    )
    client = adapter._api
    client.max_retries = 1
    state = {"body": envelope(), "status": 200, "error": None, "requests": []}

    async def response(request):
        state["requests"].append((request.method, request.url.path, json.loads(request.content)))
        if state["error"]:
            raise state["error"]
        return httpx.Response(state["status"], json=state["body"])

    client._client = httpx.AsyncClient(
        base_url=client.base_url, transport=httpx.MockTransport(response)
    )
    try:
        yield adapter, state
    finally:
        await adapter.disconnect()


@pytest.mark.parametrize("kind", ["empty", "one", "two", "unknown-expiry"])
async def test_complete_inventory_preserves_public_fields_only(wire, kind):
    adapter, state = wire
    rows = [] if kind == "empty" else [ROW]
    if kind == "two":
        rows = [ROW, {**ROW, "uuid": str(uuid4())}]
    if kind == "unknown-expiry":
        rows = [{"uuid": str(uuid4()), "descr": "Unknown expiry"}]
    state["body"] = envelope(rows)
    result = await adapter.get_certificates()
    assert result.success is True and result.data["count"] == len(rows)
    assert [r["uuid"] for r in result.data["certificates"]] == [r["uuid"] for r in rows]
    assert SECRET not in str(result.data)
    if kind == "one":
        assert result.data["certificates"][0]["valid_to"] == "1900000000"
        assert result.data["certificates"][0]["dn_commonname"] == "owned.example.test"
    assert state["requests"] == [("POST", "/api/trust/cert/search", {"current": 1, "rowCount": -1})]


def malformed(kind):
    if kind in ["null", "array", "text", "missing"]:
        return {"null": None, "array": [], "text": SECRET, "missing": {}}[kind]
    body = envelope()
    if kind in ["row-text", "row-null", "duplicate", "no-id", "bool-id", "nested-name"]:
        body = envelope(
            {
                "row-text": [SECRET],
                "row-null": [None],
                "duplicate": [ROW, ROW],
                "no-id": [{"descr": SECRET}],
                "bool-id": [{**ROW, "uuid": False}],
                "nested-name": [{**ROW, "dn_commonname": {"secret": SECRET}}],
            }[kind]
        )
    elif kind == "partial":
        body["total"] = 2
    elif kind == "rowcount":
        body["rowCount"] = 0
    elif kind == "wrong-page":
        body["current"] = 2
    elif kind == "bool-total":
        body["total"] = True
    elif kind == "missing-total":
        del body["total"]
    elif kind == "string-total":
        body["total"] = "1"
    elif kind == "rows-object":
        body["rows"] = {"owned": ROW}
    elif kind == "refused":
        body = {"result": "failed", "message": SECRET}
    return body


@pytest.mark.parametrize(
    "kind",
    [
        "null",
        "array",
        "text",
        "missing",
        "row-text",
        "row-null",
        "duplicate",
        "no-id",
        "bool-id",
        "nested-name",
        "partial",
        "rowcount",
        "wrong-page",
        "bool-total",
        "missing-total",
        "string-total",
        "rows-object",
        "refused",
    ],
)
async def test_malformed_or_incomplete_inventory_fails_safely(wire, kind, caplog):
    adapter, state = wire
    state["body"] = malformed(kind)
    result = await adapter.get_certificates()
    assert result.success is False and result.data is None
    assert result.error == "Certificate inventory could not be retrieved"
    assert result.error_code == "CERTIFICATE_LIST_FAILED"
    assert SECRET not in caplog.text and "Traceback" not in caplog.text


@pytest.mark.parametrize("failure", [401, 403, 503, "connection", "timeout"])
async def test_transport_failure_is_safe(wire, failure, caplog):
    adapter, state = wire
    state["body"] = {"message": SECRET}
    if isinstance(failure, int):
        state["status"] = failure
    else:
        state["error"] = (httpx.ConnectError if failure == "connection" else httpx.ReadTimeout)(
            SECRET
        )
    result = await adapter.get_certificates()
    assert result.success is False and result.data is None
    assert result.error == "Certificate inventory could not be retrieved"
    assert result.error_code == "CERTIFICATE_LIST_FAILED"
    assert SECRET not in caplog.text and "Traceback" not in caplog.text


async def test_cancellation_is_not_converted(wire):
    adapter, state = wire
    state["error"] = asyncio.CancelledError("owned")
    with pytest.raises(asyncio.CancelledError):
        await adapter.get_certificates()


async def test_retry_diagnostics_do_not_log_private_device_text(wire, monkeypatch, caplog):
    adapter, state = wire
    adapter._api.max_retries = 3
    state["error"] = httpx.ReadTimeout(SECRET)

    async def no_delay(_delay):
        return None

    monkeypatch.setattr("app.adapters.opnsense.client.asyncio.sleep", no_delay)
    result = await adapter.get_certificates()
    assert result.success is False and len(state["requests"]) == 3
    assert SECRET not in caplog.text and "Traceback" not in caplog.text

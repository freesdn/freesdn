"""Actual OPNsense client/adapter with an explicitly controlled HTTPX transport."""

import asyncio
import json

import httpx
import pytest
import pytest_asyncio

from app.adapters.opnsense.adapter import OPNsenseAdapter
from app.core.config import settings

SECRET = "owned-backup-mutation-private-diagnostic"
FILENAME = "config-1720000000.xml"
OPERATIONS = ["delete", "revert"]


@pytest_asyncio.fixture
async def wire(monkeypatch):
    monkeypatch.setattr(settings, "ADAPTER_READ_ONLY", True)
    adapter = OPNsenseAdapter(
        host="192.0.2.55",
        username="owned-key",
        password="owned-secret",
        verify_ssl=True,
        direct_write_force=True,
    )
    client = adapter._api
    client.max_retries = 3
    state = {"body": {}, "status": 200, "error": None, "requests": []}

    async def respond(request):
        state["requests"].append((request.method, request.url.path, json.loads(request.content)))
        if state["error"]:
            raise state["error"]
        return httpx.Response(state["status"], json=state["body"])

    client._client = httpx.AsyncClient(
        base_url=client.base_url, transport=httpx.MockTransport(respond)
    )
    try:
        yield adapter, client, state
    finally:
        await adapter.disconnect()


@pytest.mark.parametrize("operation", OPERATIONS)
async def test_filename_is_a_path_argument_and_body_is_a_valid_empty_object(wire, operation):
    _, client, state = wire
    state["body"] = {"status": operation + "d" if operation == "delete" else "reverted"}
    await getattr(client, operation + "_backup")(FILENAME, force=True)
    assert state["requests"] == [("POST", f"/api/core/backup/{operation}Backup/{FILENAME}", {})]


@pytest.mark.parametrize("operation", OPERATIONS)
async def test_success_is_exact_and_discards_arbitrary_provider_fields(wire, operation):
    adapter, _, state = wire
    expected = "deleted" if operation == "delete" else "reverted"
    state["body"] = {"status": expected, "message": SECRET, "config": SECRET}
    result = await getattr(adapter, operation + "_backup")(FILENAME)
    assert result.success is True
    assert result.data == {"status": expected, "filename": FILENAME}
    assert result.message == ("Backup deleted" if operation == "delete" else "Backup reverted")
    assert state["requests"] == [("POST", f"/api/core/backup/{operation}Backup/{FILENAME}", {})]


@pytest.mark.parametrize("operation", OPERATIONS)
@pytest.mark.parametrize(
    "kind",
    [
        "failed",
        "not-found",
        "missing",
        "null",
        "list",
        "text",
        "boolean",
        "other-action",
        "saved",
        "unknown",
    ],
)
async def test_refused_or_unknown_outcomes_do_not_report_success(wire, operation, kind, caplog):
    adapter, _, state = wire
    state["body"] = {
        "failed": {"status": "failed", "message": SECRET},
        "not-found": {"status": "not_found", "message": SECRET},
        "missing": {"message": SECRET},
        "null": None,
        "list": [],
        "text": SECRET,
        "boolean": {"status": True},
        "other-action": {"status": "reverted" if operation == "delete" else "deleted"},
        "saved": {"status": "saved"},
        "unknown": {"status": SECRET},
    }[kind]
    result = await getattr(adapter, operation + "_backup")(FILENAME)
    assert result.success is False and result.data is None
    assert result.error_code == (
        "NOT_FOUND" if kind == "not-found" else f"BACKUP_{operation.upper()}_FAILED"
    )
    assert result.error == (
        "Backup not found" if kind == "not-found" else "Backup operation could not be confirmed"
    )
    assert len(state["requests"]) == 1
    assert SECRET not in caplog.text and "Traceback" not in caplog.text


@pytest.mark.parametrize("operation", OPERATIONS)
@pytest.mark.parametrize(
    "filename", ["", ".", "..", "../config.xml", "config.xml\n", "a" * 129, "config%2fsecret.xml"]
)
async def test_client_rejects_unsafe_or_unrepresentable_filename_before_transport(
    wire, operation, filename
):
    _, client, state = wire
    with pytest.raises(ValueError, match="Invalid backup filename"):
        await getattr(client, operation + "_backup")(filename, force=True)
    assert not state["requests"]


@pytest.mark.parametrize("operation", OPERATIONS)
@pytest.mark.parametrize("filename", [".", "..", "config.xml\n", "a" * 129])
async def test_adapter_invalid_filename_has_safe_validation_outcome(
    wire, operation, filename, caplog
):
    adapter, _, state = wire
    result = await getattr(adapter, operation + "_backup")(filename)
    assert result.success is False and result.data is None
    assert result.error_code == "INVALID_CONFIG" and result.error == "Invalid backup filename"
    assert not state["requests"] and "Traceback" not in caplog.text


@pytest.mark.parametrize("operation", OPERATIONS)
@pytest.mark.parametrize("failure", [401, 403, 503, "timeout", "connection", "body-refusal"])
async def test_failures_are_not_replayed_and_do_not_log_provider_diagnostics(
    wire, operation, failure, caplog
):
    adapter, _, state = wire
    state["body"] = {"message": SECRET}
    if isinstance(failure, int):
        state["status"] = failure
    elif failure == "body-refusal":
        state["body"] = {"result": "failed", "message": SECRET}
    else:
        state["error"] = (httpx.ReadTimeout if failure == "timeout" else httpx.ConnectError)(SECRET)
    result = await getattr(adapter, operation + "_backup")(FILENAME)
    assert result.success is False and result.error_code == f"BACKUP_{operation.upper()}_FAILED"
    assert result.error == "Backup operation could not be confirmed" and result.data is None
    assert len(state["requests"]) == 1
    assert SECRET not in caplog.text and "Traceback" not in caplog.text


@pytest.mark.parametrize("operation", OPERATIONS)
async def test_direct_adapter_write_is_still_blocked_without_explicit_force(wire, operation):
    adapter, _, state = wire
    adapter._direct_write_force = False
    result = await getattr(adapter, operation + "_backup")(FILENAME)
    assert result.success is False and not state["requests"]


@pytest.mark.parametrize("operation", OPERATIONS)
async def test_cancellation_is_not_converted_to_a_failed_or_successful_result(wire, operation):
    adapter, _, state = wire
    state["error"] = asyncio.CancelledError("owned")
    with pytest.raises(asyncio.CancelledError):
        await getattr(adapter, operation + "_backup")(FILENAME)
    assert len(state["requests"]) == 1

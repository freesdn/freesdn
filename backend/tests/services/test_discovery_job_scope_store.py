# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Ownership store failures and Celery diagnostics must not become public data."""

import asyncio
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from app.services import discovery_jobs as jobs


@pytest.fixture
def fixture(monkeypatch):
    scope = jobs.DiscoveryJobScope(
        version=1,
        task_id=uuid4(),
        task_name=jobs.DISCOVERY_TASK,
        organization_id=uuid4(),
        site_id=uuid4(),
    )
    client = SimpleNamespace(
        get=AsyncMock(return_value=scope.model_dump_json()),
        set=AsyncMock(return_value=True),
        aclose=AsyncMock(),
    )
    factory = MagicMock(return_value=client)
    monkeypatch.setattr(jobs, "get_async_redis", factory)
    return SimpleNamespace(scope=scope, client=client, factory=factory)


@pytest.mark.asyncio
async def test_reservation_uses_expiring_non_overwriting_identity_and_closes(fixture):
    f = fixture
    assert await jobs.reserve_discovery_scope(f.scope) is True
    f.client.set.assert_awaited_once_with(
        jobs.SCOPE_PREFIX + str(f.scope.task_id), f.scope.model_dump_json(), nx=True, ex=86400
    )
    f.factory.assert_called_once_with(
        decode_responses=True, socket_timeout=2, socket_connect_timeout=2
    )
    f.client.aclose.assert_awaited_once()
    f.client.set.return_value = None
    assert await jobs.reserve_discovery_scope(f.scope) is False


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["get", "set"])
async def test_store_failure_has_safe_diagnostic_and_closes(fixture, operation):
    f = fixture
    getattr(f.client, operation).side_effect = RuntimeError("synthetic-private-redis-endpoint")
    with pytest.raises(jobs.DiscoveryScopeUnavailable) as error:
        if operation == "get":
            await jobs.get_discovery_scope(str(f.scope.task_id))
        else:
            await jobs.reserve_discovery_scope(f.scope)
    assert "synthetic-private" not in str(error.value)
    f.client.aclose.assert_awaited_once()


@pytest.mark.asyncio
async def test_cancellation_is_not_converted_into_success_or_provider_error(fixture):
    fixture.client.get.side_effect = asyncio.CancelledError()
    with pytest.raises(asyncio.CancelledError):
        await jobs.get_discovery_scope(str(fixture.scope.task_id))
    fixture.client.aclose.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize("value", ["not-a-task", "", "../private", None, 42])
async def test_invalid_identity_never_opens_store(fixture, value):
    assert await jobs.get_discovery_scope(value) is None
    fixture.factory.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "invalid",
    [
        "missing",
        "oversized",
        "invalid-json",
        "array",
        "unknown-field",
        "wrong-id",
        "wrong-kind",
        "wrong-version",
        "missing-org",
        "bad-site",
    ],
)
async def test_invalid_record_cannot_authorize_any_result(fixture, invalid):
    f = fixture
    data = f.scope.model_dump(mode="json")
    mutations = {
        "unknown-field": ("result", {"devices_found": 3}),
        "wrong-id": ("task_id", str(uuid4())),
        "wrong-kind": ("task_name", "backup.run"),
        "wrong-version": ("version", 2),
        "missing-org": ("organization_id", None),
        "bad-site": ("site_id", "invalid"),
    }
    if invalid in mutations:
        key, value = mutations[invalid]
        data[key] = value
    raw = {"missing": None, "oversized": " " * 2049, "invalid-json": "{", "array": "[]"}.get(
        invalid, json.dumps(data)
    )
    f.client.get.return_value = raw
    assert await jobs.get_discovery_scope(str(f.scope.task_id)) is None
    f.client.aclose.assert_awaited_once()


@pytest.mark.asyncio
async def test_valid_scope_roundtrip_preserves_identity_without_task_payload(fixture):
    assert await jobs.get_discovery_scope(str(fixture.scope.task_id)) == fixture.scope
    fixture.client.aclose.assert_awaited_once()


@pytest.mark.parametrize(
    "state", ["PENDING", "RECEIVED", "STARTED", "PROGRESS", "RETRY", "FAILURE", "REVOKED"]
)
def test_non_success_does_not_access_exception_or_traceback(monkeypatch, state):
    class BackendResult:
        @property
        def result(self):
            raise AssertionError("Must not deserialize a diagnostic payload")

        @property
        def traceback(self):
            raise AssertionError("Must not read a traceback")

    value = BackendResult()
    value.state = state
    monkeypatch.setattr("celery.result.AsyncResult", lambda *_args, **_kwargs: value)
    identity = uuid4()
    result = jobs.discovery_status(identity)
    assert result["status"] == state.lower() and result["task_id"] == str(identity)
    assert result["progress"] == result["devices_found"] == 0


@pytest.mark.parametrize(
    "payload",
    [
        None,
        [],
        "private",
        {"devices_found": True},
        {"devices_found": -1},
        {"devices_found": 2**31},
        {"devices_found": "2"},
        {"devices_found": 1.2},
    ],
)
def test_malformed_success_count_is_unavailable(monkeypatch, payload):
    monkeypatch.setattr(
        "celery.result.AsyncResult",
        lambda *_args, **_kwargs: SimpleNamespace(state="SUCCESS", result=payload),
    )
    with pytest.raises(jobs.DiscoveryScopeUnavailable):
        jobs.discovery_status(uuid4())


@pytest.mark.parametrize(
    "payload,expected",
    [
        ({"total_devices_discovered": 77, "devices_found": 9}, 77),
        ({"devices_found": 12}, 12),
        ({}, 0),
    ],
)
def test_valid_success_only_exposes_allowlisted_aggregate(monkeypatch, payload, expected):
    payload = {
        **payload,
        "controller_errors": "synthetic-private-diagnostic",
        "credentials": "synthetic-private",
    }
    monkeypatch.setattr(
        "celery.result.AsyncResult",
        lambda *_args, **_kwargs: SimpleNamespace(state="SUCCESS", result=payload),
    )
    result = jobs.discovery_status(uuid4())
    assert result["status"] == "success" and result["devices_found"] == expected
    assert result["progress"] == 100 and "synthetic-private" not in json.dumps(result)


@pytest.mark.parametrize(
    "payload,state,message",
    [
        ({"success": False, "error": "synthetic-private"}, "failure", "Discovery task failed"),
        ({"skipped": True}, "success", "Discovery skipped because another run is active"),
    ],
)
def test_explicit_task_failure_and_skip_keep_fixed_messages(monkeypatch, payload, state, message):
    monkeypatch.setattr(
        "celery.result.AsyncResult",
        lambda *_args, **_kwargs: SimpleNamespace(state="SUCCESS", result=payload),
    )
    result = jobs.discovery_status(uuid4())
    assert result["status"] == state and result["message"] == message


def test_unknown_backend_state_is_unavailable(monkeypatch):
    monkeypatch.setattr(
        "celery.result.AsyncResult",
        lambda *_args, **_kwargs: SimpleNamespace(state="synthetic-private-state"),
    )
    with pytest.raises(jobs.DiscoveryScopeUnavailable) as error:
        jobs.discovery_status(uuid4())
    assert "synthetic-private" not in str(error.value)

# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Raw failure details must not escape the Fabric executor's normalization boundary."""

import asyncio
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest

from app.core.fabric import executor as module
from app.core.fabric.execution import ArtifactRef, OperationContext, OperationResult
from app.core.fabric.executor import OperationExecutor
from app.core.fabric.operations import Operation, OperationTier

CANARY = "qualification-only-private-detail"
DETAIL = "postgresql://synthetic:" + CANARY + "@fixture.invalid/db payload=" + CANARY


def operation(*, write=False, overlay=False, plugin=False, handler=None):
    return Operation(
        id="plugin.probe.read" if plugin else "probe.read",
        title="Owned test operation",
        handler=handler,
        permission="network.write" if write else "network.view",
        feature="overlay.wireguard" if overlay else "network.port" if write else None,
        write=write,
        tier=OperationTier.PLUGIN if plugin else OperationTier.NATIVE,
        provider_id="probe",
    )


def assert_private(result, caplog, code):
    assert not result.success and result.error_code == code
    assert CANARY not in json.dumps(result.to_dict())
    assert CANARY not in caplog.text
    assert all(record.exc_info is None for record in caplog.records)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "error", [RuntimeError(DETAIL), ConnectionError(DETAIL), ValueError(DETAIL)]
)
async def test_native_handler_failure_does_not_expose_raw_details(error, caplog):
    handler = AsyncMock(side_effect=error)
    result = await OperationExecutor().execute(
        operation(handler=handler), OperationContext(uuid4(), {})
    )
    assert_private(result, caplog, "EXEC_ERROR")
    handler.assert_awaited_once()


@pytest.mark.asyncio
async def test_plugin_exception_is_private_in_both_response_and_log(caplog):
    handler = AsyncMock(side_effect=RuntimeError(DETAIL))
    result = await OperationExecutor().execute(
        operation(plugin=True, handler=handler), OperationContext(uuid4(), {})
    )
    assert_private(result, caplog, "PLUGIN_ERROR")


@pytest.mark.asyncio
async def test_target_lookup_failure_is_private(monkeypatch, caplog):
    monkeypatch.setattr(module, "_controller_in_org", AsyncMock(side_effect=RuntimeError(DETAIL)))
    ctx = OperationContext(uuid4(), {"controller_id": str(uuid4())}, db=object())
    result = await OperationExecutor().execute(operation(write=True), ctx)
    assert_private(result, caplog, "EXEC_ERROR")


@pytest.mark.asyncio
@pytest.mark.parametrize("overlay", [False, True])
async def test_staging_failure_is_private_and_not_retried(monkeypatch, caplog, overlay):
    from app.services.adapter_staging import AdapterStagingService

    monkeypatch.setattr(
        module, "_controller_in_org", AsyncMock(return_value=SimpleNamespace(site_id=uuid4()))
    )
    stage = AsyncMock(side_effect=RuntimeError(DETAIL))
    monkeypatch.setattr(AdapterStagingService, "stage_change", stage)
    ctx = OperationContext(uuid4(), {"controller_id": str(uuid4())}, db=object())
    result = await OperationExecutor().execute(operation(write=True, overlay=overlay), ctx)
    assert_private(result, caplog, "STAGE_FAILED")
    stage.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["read", "persist"])
async def test_artifact_failure_is_private_and_does_not_stage(monkeypatch, caplog, failure):
    from app.core.fabric.durable_store import durable_store
    from app.services.adapter_staging import AdapterStagingService

    monkeypatch.setattr(
        module, "_controller_in_org", AsyncMock(return_value=SimpleNamespace(site_id=uuid4()))
    )
    artifact = ArtifactRef("handle", "image/jpeg", 3, "synthetic-digest")
    read = AsyncMock(
        return_value=(b"jpg", artifact),
        side_effect=RuntimeError(DETAIL) if failure == "read" else None,
    )
    put = AsyncMock(side_effect=RuntimeError(DETAIL))
    stage = AsyncMock()
    monkeypatch.setattr(durable_store, "put", put)
    monkeypatch.setattr(AdapterStagingService, "stage_change", stage)
    ctx = OperationContext(
        uuid4(),
        {"controller_id": str(uuid4())},
        db=object(),
        artifacts=SimpleNamespace(get=read),
        input_artifact=artifact,
    )
    result = await OperationExecutor().execute(operation(write=True), ctx)
    assert_private(result, caplog, "ARTIFACT_UNAVAILABLE")
    stage.assert_not_awaited()
    assert put.await_count == int(failure == "persist")


@pytest.mark.asyncio
@pytest.mark.parametrize("cleanup_fails", [False, True])
async def test_staging_failure_keeps_cleanup_without_disclosing_details(
    monkeypatch, caplog, cleanup_fails
):
    from app.core.fabric.durable_store import durable_store
    from app.services.adapter_staging import AdapterStagingService

    monkeypatch.setattr(
        module, "_controller_in_org", AsyncMock(return_value=SimpleNamespace(site_id=uuid4()))
    )
    artifact = ArtifactRef("handle", "image/jpeg", 3, "synthetic-digest")
    monkeypatch.setattr(
        durable_store, "put", AsyncMock(return_value={"durable_token": "owned-token"})
    )
    delete = AsyncMock(side_effect=RuntimeError(DETAIL) if cleanup_fails else None)
    monkeypatch.setattr(durable_store, "delete", delete)
    monkeypatch.setattr(
        AdapterStagingService, "stage_change", AsyncMock(side_effect=RuntimeError(DETAIL))
    )
    ctx = OperationContext(
        uuid4(),
        {"controller_id": str(uuid4())},
        db=object(),
        artifacts=SimpleNamespace(get=AsyncMock(return_value=(b"jpg", artifact))),
        input_artifact=artifact,
    )
    result = await OperationExecutor().execute(operation(write=True), ctx)
    assert_private(result, caplog, "STAGE_FAILED")
    delete.assert_awaited_once_with("owned-token", ctx.organization_id)


@pytest.mark.asyncio
@pytest.mark.parametrize("plugin", [False, True])
async def test_cancellation_still_propagates(plugin):
    handler = AsyncMock(side_effect=asyncio.CancelledError())
    with pytest.raises(asyncio.CancelledError):
        await OperationExecutor().execute(
            operation(plugin=plugin, handler=handler), OperationContext(uuid4(), {})
        )


@pytest.mark.asyncio
async def test_success_result_is_preserved():
    expected = OperationResult.ok({"count": 2})
    result = await OperationExecutor().execute(
        operation(handler=AsyncMock(return_value=expected)), OperationContext(uuid4(), {})
    )
    assert result is expected


@pytest.mark.asyncio
async def test_declared_handler_refusal_keeps_its_public_message():
    expected = OperationResult.fail("The selected target is unavailable", "NOT_FOUND")
    result = await OperationExecutor().execute(
        operation(handler=AsyncMock(return_value=expected)), OperationContext(uuid4(), {})
    )
    assert result is expected


@pytest.mark.asyncio
async def test_invoke_api_failure_bridge_does_not_expose_exception(monkeypatch, caplog):
    from app.adapters.exceptions import AdapterError
    from app.api.v1.endpoints.fabric import InvokeIn, invoke_operation
    from app.core.fabric.registry import fabric_registry

    op = operation(handler=AsyncMock(side_effect=RuntimeError(DETAIL)))
    monkeypatch.setattr(fabric_registry, "get_operation", lambda _id: op)
    user = SimpleNamespace(
        organization_id=uuid4(),
        id=uuid4(),
        is_site_limited=False,
        has_permission=lambda _permission: True,
    )
    db = SimpleNamespace(rollback=AsyncMock(), commit=AsyncMock())
    with pytest.raises(AdapterError) as error:
        await invoke_operation(op.id, InvokeIn(), user, db)
    assert CANARY not in str(error.value) and CANARY not in caplog.text
    db.rollback.assert_awaited_once()
    db.commit.assert_not_awaited()

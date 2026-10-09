# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Built-in notification and webhook failures must not reveal transport details."""

import asyncio
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest

from app.core.fabric.builtin_ops import builtin_operations
from app.core.fabric.execution import OperationContext
from app.core.fabric.executor import OperationExecutor

CANARY = "qualification-only-builtin-private-detail"
DETAIL = "https://fixture.invalid/hook?token=" + CANARY


def prepare(monkeypatch, op_id, *, error=None, status=202):
    from app.core import security_utils
    from app.services import notification_helpers
    from app.services.notification import DeliveryResult, DeliveryStatus, NotificationChannel

    result = (
        [DeliveryResult(True, NotificationChannel.EMAIL, DeliveryStatus.SENT)]
        if op_id == "fabric.notify"
        else SimpleNamespace(status_code=status, text="ack")
    )
    call = AsyncMock(side_effect=error, return_value=result)
    if op_id == "fabric.notify":
        monkeypatch.setattr(notification_helpers, "dispatch_notifications", call)
    else:
        monkeypatch.setattr(security_utils, "safe_http_request", call)
    op = next(op for op in builtin_operations() if op.id == op_id)
    ctx = OperationContext(
        uuid4(), {"url": "https://fixture.invalid/hook", "channels": {}}, db=object()
    )
    return op, ctx, call


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("op_id", "error", "code"),
    [
        ("fabric.notify", RuntimeError(DETAIL), "NOTIFY_ERROR"),
        ("fabric.webhook", ValueError(DETAIL), "SSRF_BLOCKED"),
        ("fabric.webhook", ConnectionError(DETAIL), "DELIVERY_ERROR"),
    ],
)
async def test_builtin_failure_does_not_disclose_private_detail(
    monkeypatch, caplog, op_id, error, code
):
    op, ctx, call = prepare(monkeypatch, op_id, error=error)
    result = await OperationExecutor().execute(op, ctx)
    assert not result.success and result.error_code == code
    assert CANARY not in json.dumps(result.to_dict())
    assert CANARY not in caplog.text
    assert all(record.exc_info is None for record in caplog.records)
    call.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize("op_id", ["fabric.notify", "fabric.webhook"])
async def test_builtin_cancellation_propagates_without_retry(monkeypatch, op_id):
    op, ctx, call = prepare(monkeypatch, op_id, error=asyncio.CancelledError())
    with pytest.raises(asyncio.CancelledError):
        await OperationExecutor().execute(op, ctx)
    call.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize("op_id", ["fabric.notify", "fabric.webhook"])
async def test_builtin_success_preserves_output(monkeypatch, op_id):
    op, ctx, call = prepare(monkeypatch, op_id)
    result = await OperationExecutor().execute(op, ctx)
    expected = (
        {"dispatched": 1}
        if op_id == "fabric.notify"
        else {"status_code": 202, "ok": True, "response": "ack"}
    )
    assert result.success and result.output == expected
    call.assert_awaited_once()


@pytest.mark.asyncio
async def test_webhook_bad_status_remains_a_failure(monkeypatch):
    op, ctx, call = prepare(monkeypatch, "fabric.webhook", status=503)
    result = await OperationExecutor().execute(op, ctx)
    assert not result.success and result.error_code == "BAD_STATUS"
    call.assert_awaited_once()

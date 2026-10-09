# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Handler-owned failures must remain private through the actual operation catalog."""

import asyncio
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, PropertyMock
from uuid import uuid4

import pytest

from app.core.config import settings
from app.core.fabric.execution import OperationContext
from app.core.fabric.executor import OperationExecutor
from app.modules.network.module import NetworkModule
from app.modules.voip.module import VoIPModule

CANARY = "qualification-only-handler-private-detail"
DETAIL = "synthetic service connection failed: credential=" + CANARY
CASES = [
    (
        "vpn.overlay.status",
        "get_status_summary",
        {"connected": 1},
        {"connected": 1, "mode": "tailscale"},
    ),
    (
        "vpn.overlay.peers",
        "discover_overlay_devices",
        [{"online": True}],
        {"peers": [{"online": True}], "count": 1},
    ),
    (
        "vpn.routes.list",
        "discover_vpn_accessible_subnets",
        ["192.0.2.0/24"],
        {"routes": ["192.0.2.0/24"], "count": 1},
    ),
    ("voip.phone.live_status", "get_phone_live_status", {"registered": True}, {"registered": True}),
    (
        "voip.pbx.active_calls",
        "get_pbx_active_calls",
        [{"state": "ringing"}],
        {"calls": [{"state": "ringing"}], "count": 1},
    ),
    (
        "voip.pbx.list_extensions",
        "list_extensions",
        ([SimpleNamespace(extension_number="101", display_name="Fixture", is_active=True)], 1),
        {"total": 1, "extensions": [{"extension": "101", "name": "Fixture", "active": True}]},
    ),
    ("voip.pbx.originate_call", "originate_call", {"accepted": True}, {"accepted": True}),
]


def prepare(monkeypatch, case, *, error=None, constructor_error=False):
    from app.modules.voip import service as voip_service
    from app.services import overlay_discovery, vpn_integration

    op_id, method, response, _ = case
    monkeypatch.setattr(type(settings), "resolved_vpn_mode", PropertyMock(return_value="tailscale"))
    call = AsyncMock(side_effect=error, return_value=response)
    factory = None
    if op_id == "vpn.overlay.peers":
        monkeypatch.setattr(overlay_discovery, method, call)
    else:
        factory = Mock(
            side_effect=RuntimeError(DETAIL) if constructor_error else None,
            return_value=SimpleNamespace(**{method: call}),
        )
        module, name = (
            (voip_service, "VoIPService")
            if op_id.startswith("voip.")
            else (vpn_integration, "VPNManagerService")
        )
        monkeypatch.setattr(module, name, factory)
    provider = VoIPModule() if op_id.startswith("voip.") else NetworkModule()
    op = next(op for op in provider.get_operations() if op.id == op_id)
    ctx = OperationContext(
        uuid4(),
        {
            "phone_id": str(uuid4()),
            "pbx_id": str(uuid4()),
            "extension": "101",
            "destination": "102",
        },
        db=object(),
        accessible_site_ids=[uuid4()],
    )
    return op, ctx, call, factory


def assert_private(result, caplog, op_id):
    assert not result.success
    assert result.error_code == (
        "ORIGINATE_ERROR" if op_id.endswith("originate_call") else "READ_ERROR"
    )
    assert CANARY not in json.dumps(result.to_dict())
    assert CANARY not in caplog.text
    assert all(record.exc_info is None for record in caplog.records)


@pytest.mark.asyncio
@pytest.mark.parametrize("case", CASES, ids=[case[0] for case in CASES])
async def test_handler_service_failure_stays_private_through_executor(monkeypatch, caplog, case):
    op, ctx, call, _ = prepare(monkeypatch, case, error=RuntimeError(DETAIL))
    result = await OperationExecutor().execute(op, ctx)
    assert_private(result, caplog, op.id)
    call.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "case",
    [case for case in CASES if case[0] != "vpn.overlay.peers"],
    ids=[case[0] for case in CASES if case[0] != "vpn.overlay.peers"],
)
async def test_handler_constructor_failure_stays_private(monkeypatch, caplog, case):
    op, ctx, call, factory = prepare(monkeypatch, case, constructor_error=True)
    result = await OperationExecutor().execute(op, ctx)
    assert_private(result, caplog, op.id)
    factory.assert_called_once()
    call.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("case", CASES, ids=[case[0] for case in CASES])
async def test_handler_cancellation_propagates_without_retry(monkeypatch, case):
    op, ctx, call, _ = prepare(monkeypatch, case, error=asyncio.CancelledError())
    with pytest.raises(asyncio.CancelledError):
        await OperationExecutor().execute(op, ctx)
    call.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize("case", CASES, ids=[case[0] for case in CASES])
async def test_handler_success_output_and_voip_scope_preserved(monkeypatch, case):
    op, ctx, call, factory = prepare(monkeypatch, case)
    result = await OperationExecutor().execute(op, ctx)
    assert result.success and result.output == case[3]
    call.assert_awaited_once()
    if op.id.startswith("voip."):
        factory.assert_called_once_with(
            ctx.db, organization_id=ctx.organization_id, accessible_site_ids=ctx.accessible_site_ids
        )
    if op.id.endswith("originate_call"):
        from uuid import UUID

        call.assert_awaited_once_with(
            UUID(ctx.params["pbx_id"]), "101", "102", caller_id=None, context="from-internal"
        )

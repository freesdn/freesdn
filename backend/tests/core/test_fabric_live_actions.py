# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""A live action (not a read, never staged) must refuse while ADAPTER_READ_ONLY is
on and must never be an AI tool. ``voip.pbx.originate_call`` did neither: the
FreePBX adapter deliberately lets force=True call control through read-only mode,
VoIPService always passes force=True, and the AI bridge registered the op as a
tool with no confirmation step.
"""

from __future__ import annotations

from unittest.mock import AsyncMock
from uuid import uuid4

import pytest

from app.core.fabric.execution import OperationContext, OperationResult
from app.core.fabric.executor import operation_executor
from app.core.fabric.operations import Operation, OperationTier

# ── live actions ────────────────────────────────────────────────────────────


def _live(handler) -> Operation:
    return Operation(
        id="test.live_action",
        title="Live",
        permission="test.perm",
        live_action=True,
        handler=handler,
        tier=OperationTier.NATIVE,
        provider_id="test",
    )


@pytest.mark.parametrize("read_only", [True, False])
async def test_live_actions_refuse_while_read_only(monkeypatch, read_only):
    import app.core.runtime_flags as flags

    handler = AsyncMock(return_value=OperationResult.ok(output={"called": True}))
    monkeypatch.setattr(flags, "is_adapter_read_only", lambda: read_only)
    result = await operation_executor.execute(_live(handler), OperationContext(uuid4(), {}))
    if read_only:
        assert (result.success, result.error_code) == (False, "READ_ONLY")
        handler.assert_not_called()
    else:
        assert result.success and result.output == {"called": True}


def test_originate_is_declared_a_live_action():
    from app.modules.voip.module import VoIPModule

    op = {o.id: o for o in VoIPModule().get_operations()}["voip.pbx.originate_call"]
    assert op.live_action and not op.write and op.permission == "voip.manage_phones"
    assert "read-only env lock" not in op.description
    assert op.to_catalog_dict()["live_action"] is True


@pytest.mark.parametrize(
    "kwargs",
    [
        {"live_action": True, "permission": None},
        {"live_action": True, "write": True, "feature": "x"},
    ],
)
def test_a_live_action_cannot_be_permissionless_or_staged(kwargs):
    base = {"id": "test.bad", "title": "Bad", "permission": "test.perm", "provider_id": "test"}
    with pytest.raises(ValueError):
        Operation(**{**base, **kwargs})


def test_live_actions_are_never_ai_tools(monkeypatch):
    from app.core.fabric import ai_bridge
    from app.core.fabric.registry import fabric_registry
    from app.modules.ai import tools

    async def handler(ctx):
        return OperationResult.ok()

    read = Operation(
        id="test.read_status",
        title="Read",
        permission="test.perm",
        handler=handler,
        provider_id="test",
    )
    registry: dict = {}
    monkeypatch.setattr(fabric_registry, "list_operations", lambda: [_live(handler), read])
    monkeypatch.setattr(tools, "TOOL_REGISTRY", registry)
    monkeypatch.setattr(tools, "register_tool", lambda tool: registry.__setitem__(tool.name, tool))
    monkeypatch.setattr(ai_bridge, "_WRAPPED", set())
    assert ai_bridge.register_fabric_ops_as_ai_tools() == 1
    assert list(registry) == [ai_bridge._ai_tool_name("test.read_status")]

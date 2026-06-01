# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Tests for the P3 convergence bridges (additive): native Fabric operations
become invokable as AI tools AND as automation FABRIC_OPERATION actions, reusing
the executor (writes STAGE, org from the caller — never the args)."""

from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest

from app.core.fabric.execution import OperationResult
from app.core.fabric.operations import Operation, OperationTier


def _read_op():
    return Operation(
        id="z.read",
        title="Z read",
        permission="z.view",
        handler=lambda _c: None,
        tier=OperationTier.NATIVE,
        provider_id="z",
    )


def _write_op():
    return Operation(
        id="z.write",
        title="Z write",
        write=True,
        feature="z.f",
        permission="z.write",
        tier=OperationTier.NATIVE,
        provider_id="z",
    )


def _plugin_op():
    return Operation(
        id="plugin.acme.y",
        title="p",
        permission="plugin.acme.y",
        handler=lambda _c: None,
        tier=OperationTier.PLUGIN,
        provider_id="acme",
    )


class TestAIToolBridge:
    def test_registers_native_skips_plugin_and_is_idempotent(self, monkeypatch) -> None:
        import app.core.fabric.ai_bridge as br
        from app.core.fabric.registry import fabric_registry
        from app.modules.ai.tools import TOOL_REGISTRY

        monkeypatch.setattr(
            fabric_registry, "list_operations", lambda: [_read_op(), _write_op(), _plugin_op()]
        )
        # Dotted op-ids are sanitized to provider-legal tool names (z.read -> z_read);
        # _WRAPPED is keyed by the original op.id, TOOL_REGISTRY by the tool name.
        for k in ("z.read", "z.write"):
            br._WRAPPED.discard(k)
        for k in ("z_read", "z_write"):
            TOOL_REGISTRY.pop(k, None)
        try:
            added = br.register_fabric_ops_as_ai_tools()
            assert added == 2
            assert "z_read" in TOOL_REGISTRY and "z_write" in TOOL_REGISTRY  # sanitized names
            assert "plugin.acme.y" not in TOOL_REGISTRY  # plugins have their own bridge
            assert TOOL_REGISTRY["z_read"].permission == "z.view"
            assert TOOL_REGISTRY["z_write"].permission == "z.write"  # write op IS wrapped (stages)
            # idempotent re-run adds nothing
            assert br.register_fabric_ops_as_ai_tools() == 0
        finally:
            for k in ("z_read", "z_write"):
                TOOL_REGISTRY.pop(k, None)
            for k in ("z.read", "z.write"):
                br._WRAPPED.discard(k)

    def test_does_not_override_existing_tool(self, monkeypatch) -> None:
        import app.core.fabric.ai_bridge as br
        from app.core.fabric.registry import fabric_registry
        from app.modules.ai.tools import TOOL_REGISTRY, AITool, register_tool

        # The hand-written tool uses the SANITIZED name the Fabric op would map to
        # (z.read -> z_read), so the collision path is actually exercised.
        sentinel = AITool(
            name="z_read",
            description="hand-written",
            parameters={},
            handler=lambda **_k: None,
            permission="z.view",
        )
        register_tool(sentinel)
        br._WRAPPED.discard("z.read")
        monkeypatch.setattr(fabric_registry, "list_operations", lambda: [_read_op()])
        try:
            br.register_fabric_ops_as_ai_tools()
            assert TOOL_REGISTRY["z_read"] is sentinel  # not overridden
        finally:
            TOOL_REGISTRY.pop("z_read", None)
            br._WRAPPED.discard("z.read")

    @pytest.mark.asyncio
    async def test_handler_builds_org_scoped_context(self, monkeypatch) -> None:
        import app.core.fabric.ai_bridge as br
        import app.core.fabric.executor as ex

        captured: dict = {}

        async def fake_exec(o, ctx):
            captured.update(op=o.id, org=ctx.organization_id, params=ctx.params, actor=ctx.actor_id)
            return OperationResult.ok(output={"ok": True})

        monkeypatch.setattr(ex.operation_executor, "execute", fake_exec)
        op = _read_op()
        user = SimpleNamespace(organization_id=uuid.uuid4(), id=uuid.uuid4())
        res = await br._make_handler(op)(user, object(), camera_id="c1")
        assert res["success"] is True and res["output"] == {"ok": True}
        # org + actor from the authenticated user, params from the LLM args
        assert captured["org"] == user.organization_id and captured["actor"] == user.id
        assert captured["params"] == {"camera_id": "c1"}


class TestAutomationFabricAction:
    def _handler(self):
        from app.services.automation import ActionType, automation_engine

        return automation_engine._action_handlers[ActionType.FABRIC_OPERATION]

    @pytest.mark.asyncio
    async def test_requires_org_context(self) -> None:
        r = await self._handler()({"operation_id": "z.read", "__context__": {}})
        assert r["success"] is False

    @pytest.mark.asyncio
    async def test_requires_operation_id(self) -> None:
        r = await self._handler()({"__context__": {"organization_id": str(uuid.uuid4())}})
        assert r["success"] is False

    @pytest.mark.asyncio
    async def test_unknown_op_rejected(self, monkeypatch) -> None:
        from app.core.fabric.registry import fabric_registry

        monkeypatch.setattr(fabric_registry, "get_operation", lambda _i: None)
        r = await self._handler()(
            {"operation_id": "nope", "__context__": {"organization_id": str(uuid.uuid4())}}
        )
        assert r["success"] is False and "unknown" in r["error"]

    @pytest.mark.asyncio
    async def test_plugin_op_rejected(self, monkeypatch) -> None:
        from app.core.fabric.registry import fabric_registry

        monkeypatch.setattr(fabric_registry, "get_operation", lambda _i: _plugin_op())
        r = await self._handler()(
            {"operation_id": "plugin.acme.y", "__context__": {"organization_id": str(uuid.uuid4())}}
        )
        assert r["success"] is False and "not native" in r["error"]

    @pytest.mark.asyncio
    async def test_native_op_runs_executor_org_from_context(self, monkeypatch) -> None:
        import app.core.fabric.executor as ex
        from app.core.fabric.registry import fabric_registry

        monkeypatch.setattr(fabric_registry, "get_operation", lambda _i: _read_op())
        captured: dict = {}

        async def fake_exec(o, ctx):
            captured.update(org=ctx.organization_id, params=ctx.params, actor=ctx.actor_id)
            return OperationResult.ok(output={"done": True})

        monkeypatch.setattr(ex.operation_executor, "execute", fake_exec)

        class _FakeCM:
            async def __aenter__(self):
                return object()

            async def __aexit__(self, *a):
                return False

        import app.db as appdb

        monkeypatch.setattr(appdb, "async_session_factory", lambda: _FakeCM())
        # added a fire-time author-permission re-check; this test is
        # about org/param routing, so allow the gate.
        import app.core.fabric.runtime as _fabric_rt

        async def _allow(*_a, **_k):
            return True

        monkeypatch.setattr(_fabric_rt, "fabric_permission_checker", _allow)
        org, actor = uuid.uuid4(), uuid.uuid4()
        r = await self._handler()(
            {
                "operation_id": "z.read",
                "operation_params": {"a": 1},
                "__context__": {"organization_id": str(org), "actor_id": str(actor)},
            }
        )
        assert r["success"] is True
        # org + actor from the rule context, params from operation_params
        assert (
            captured["org"] == org and captured["actor"] == actor and captured["params"] == {"a": 1}
        )

    @pytest.mark.asyncio
    async def test_native_op_denied_when_author_lost_permission(self, monkeypatch) -> None:
        """a rule whose author no longer holds the op permission
        (demoted/suspended/cross-org) is DENIED at fire time — the executor must
        not run (parity with Fabric Connections' Negotiator gate)."""
        import app.core.fabric.executor as ex
        import app.core.fabric.runtime as _fabric_rt
        from app.core.fabric.registry import fabric_registry

        monkeypatch.setattr(fabric_registry, "get_operation", lambda _i: _read_op())

        async def _deny(*_a, **_k):
            return False

        monkeypatch.setattr(_fabric_rt, "fabric_permission_checker", _deny)

        async def _boom(_o, _ctx):
            raise AssertionError("executor must not run when the author lost permission")

        monkeypatch.setattr(ex.operation_executor, "execute", _boom)
        r = await self._handler()(
            {
                "operation_id": "z.read",
                "operation_params": {},
                "__context__": {
                    "organization_id": str(uuid.uuid4()),
                    "actor_id": str(uuid.uuid4()),
                },
            }
        )
        assert r["success"] is False and "permission" in r["error"]

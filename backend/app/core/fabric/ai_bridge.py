# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""FreeSDN Fabric — AI-tool bridge (P3 convergence, additive).

Registers every NATIVE Fabric Operation as an invokable AI-assistant tool, so
the AI assistant draws from the SAME catalog as the Negotiator and (now) the
automation engine — the convergence thesis. Purely additive: existing
hand-written AI tools are never modified or removed; a Fabric op whose id
collides with an existing tool is skipped (the hand-written one wins).

Safety (enforced by reuse, not re-implemented):
  * The AI invocation path (``AIService._execute_tool``) checks
    ``user.has_permission(tool.permission)`` BEFORE the handler runs, so the
    executor's "permission already checked" assumption holds and the AI gate
    reads the same ``op.permission`` as everything else.
  * The handler reuses ``operation_executor`` — a native WRITE op STAGES through
    the dual-gate (returns ``staged_change_id``) and is NEVER auto-applied; the
    AI only ever learns it *staged* a change.
  * Org-scoped fail-closed: ``organization_id`` comes from the authenticated
    ``user``, never from LLM-supplied args; a cross-tenant ``controller_id`` in
    the args is rejected by the executor's ``_controller_in_org`` guard.
  * Plugin ops are NOT wrapped here — they already reach the AI via the
    ``PluginAIBridge`` (``plugin_{id}_`` tools).
"""

from __future__ import annotations

import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

# Idempotency ledger — op-ids we've already wrapped (so a re-entrant load is a
# no-op rather than a double-register).
_WRAPPED: set[str] = set()


def _ai_tool_name(op_id: str) -> str:
    """Map a dotted Fabric op-id to a provider-legal tool name.

    The Anthropic/OpenAI tool-calling APIs require function names matching
    ``^[A-Za-z0-9_-]{1,64}$`` — but Fabric op-ids are dotted (``cameras.snapshot``),
    which the provider REJECTS with a 400, breaking every chat request. Map any
    illegal char (``.`` etc.) to ``_`` and cap length. The handler dispatches via
    the captured ``op`` (not the name), so renaming is safe.
    """
    name = re.sub(r"[^A-Za-z0-9_-]", "_", op_id)[:64]
    return name or "fabric_op"


def _make_handler(op: Any):  # noqa: ANN201 — returns an async tool handler
    """Build an AI-tool handler that runs ``op`` through the Fabric executor.

    The AI invocation path supplies ``user`` + ``db`` + the LLM tool-call args;
    we map them 1:1 into an OperationContext (org/actor from the authenticated
    user, never from the args).
    """

    async def _handler(user: Any, db: Any, **kwargs: Any) -> dict[str, Any]:
        from app.core.fabric.execution import OperationContext
        from app.core.fabric.executor import operation_executor

        ctx = OperationContext(
            organization_id=user.organization_id,
            params=kwargs,
            actor_id=getattr(user, "id", None),
            db=db,
            artifacts=None,
            trigger={},
            logger=logging.getLogger("fabric.ai_bridge"),
        )
        result = await operation_executor.execute(op, ctx)
        return result.to_dict()

    return _handler


def register_fabric_ops_as_ai_tools() -> int:
    """Register native Fabric operations as AI tools. Returns the count added.

    Additive + idempotent + fail-soft: a bad op never aborts the batch, an
    op-id already in the registry is left untouched, and a re-run adds nothing.
    """
    from app.core.fabric.operations import OperationTier
    from app.core.fabric.registry import fabric_registry
    from app.modules.ai.tools import TOOL_REGISTRY, AITool, register_tool

    added = 0
    for op in fabric_registry.list_operations():
        try:
            # Native only (plugins have their own AI bridge); a permission is
            # required (the AI gate calls has_permission(permission) — None would
            # break it, and permissionless sinks like fabric.notify aren't tools);
            # the op must be runnable (a handler, or a write that stages).
            if op.tier is not OperationTier.NATIVE:
                continue
            if not op.permission:
                continue
            if op.handler is None and not op.write:
                continue
            if op.id in _WRAPPED:
                continue
            tool_name = _ai_tool_name(op.id)  # provider-legal (op-ids are dotted)
            if tool_name in TOOL_REGISTRY:
                logger.warning(
                    "Fabric AI bridge: tool name %r already registered; not overriding", tool_name
                )
                _WRAPPED.add(op.id)
                continue

            tool = AITool(
                name=tool_name,
                description=op.description or op.title,
                parameters=op.input_schema or {"type": "object", "properties": {}},
                handler=_make_handler(op),
                permission=op.permission,
            )
            # Fail loudly if a refactor ever diverges the two gates.
            assert tool.permission == op.permission  # noqa: S101
            register_tool(tool)
            _WRAPPED.add(op.id)
            added += 1
        except Exception:
            logger.exception(
                "Fabric AI bridge: failed to wrap operation %s", getattr(op, "id", "?")
            )

    if added:
        logger.info("Fabric AI bridge: registered %d Fabric operation(s) as AI tools", added)
    return added

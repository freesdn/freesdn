# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway MikroTik Queues / QoS service
=================================================

Read-and-stage for MikroTik RouterOS QoS: simple queues, queue tree
(HTB), and queue types (kind: pcq / sfq / red / fq-codec / …).

Supported features::

    mikrotik.queues.simple   create | update | delete
    mikrotik.queues.tree     create | update | delete
    mikrotik.queues.type     create | update | delete

Production safety: every write is staged. The applier passes
``force=True`` so the read-only gate at the client layer lets the
sanctioned write through.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from fastapi import HTTPException

from app.services.adapter_base import GatewayServiceBase

_APPLY: dict[tuple[str, str], str] = {
    # Simple queues
    ("mikrotik.queues.simple", "create"): "add_simple_queue",
    ("mikrotik.queues.simple", "update"): "update_simple_queue",
    ("mikrotik.queues.simple", "delete"): "delete_simple_queue",
    # Queue tree (HTB)
    ("mikrotik.queues.tree", "create"): "add_queue_tree",
    ("mikrotik.queues.tree", "update"): "update_queue_tree",
    ("mikrotik.queues.tree", "delete"): "delete_queue_tree",
    # Queue types
    ("mikrotik.queues.type", "create"): "add_queue_type",
    ("mikrotik.queues.type", "update"): "update_queue_type",
    ("mikrotik.queues.type", "delete"): "delete_queue_type",
}


class GatewayMikrotikQueuesService(GatewayServiceBase):
    """Live reads + staged writes for MikroTik QoS config."""

    SUPPORTED_CONTROLLER_TYPE = "mikrotik"

    # ── Live reads ───────────────────────────────────────────────────

    async def list_simple(
        self,
        controller_id: UUID,
        organization_id: UUID,
        *,
        is_superuser: bool = False,
    ) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(
            controller_id, organization_id, is_superuser=is_superuser
        )
        client = await self._get_client(ctrl)
        return {
            "controller_id": controller_id,
            "items": await client.get_simple_queues(),
            "fetched_at": datetime.now(UTC),
        }

    async def list_tree(
        self,
        controller_id: UUID,
        organization_id: UUID,
        *,
        is_superuser: bool = False,
    ) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(
            controller_id, organization_id, is_superuser=is_superuser
        )
        client = await self._get_client(ctrl)
        return {
            "controller_id": controller_id,
            "items": await client.get_queue_tree(),
            "fetched_at": datetime.now(UTC),
        }

    async def list_types(
        self,
        controller_id: UUID,
        organization_id: UUID,
        *,
        is_superuser: bool = False,
    ) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(
            controller_id, organization_id, is_superuser=is_superuser
        )
        client = await self._get_client(ctrl)
        return {
            "controller_id": controller_id,
            "items": await client.get_queue_types(),
            "fetched_at": datetime.now(UTC),
        }

    # ── Apply path ───────────────────────────────────────────────────

    def build_applier(self, change: Any) -> Any:
        async def _apply(c: Any) -> Any:
            ctrl = await self._resolve_controller_or_gateway(c.controller_id, c.organization_id)
            client = await self._get_client(ctrl)
            payload = c.payload or {}
            target_id = c.target_id

            method_name = _APPLY.get((c.feature, c.operation))
            if method_name is None:
                raise HTTPException(
                    400,
                    detail=(f"no applier for feature={c.feature!r} operation={c.operation!r}"),
                )
            method = getattr(client, method_name, None)
            if method is None:
                raise HTTPException(
                    501,
                    detail=(
                        f"MikroTik adapter has no method {method_name!r}; missing implementation"
                    ),
                )

            # All queue features are row-scoped with the same shape:
            #   create(payload), update(id, payload), delete(id).
            if c.operation == "create":
                return await method(payload, force=True)
            if c.operation == "update":
                if not target_id:
                    raise HTTPException(
                        400,
                        detail=(f"update on {c.feature!r} requires target_id"),
                    )
                return await method(target_id, payload, force=True)
            if c.operation == "delete":
                if not target_id:
                    raise HTTPException(
                        400,
                        detail=(f"delete on {c.feature!r} requires target_id"),
                    )
                return await method(target_id, force=True)
            raise HTTPException(
                400,
                detail=(f"unhandled operation={c.operation!r} for feature={c.feature!r}"),
            )

        return _apply

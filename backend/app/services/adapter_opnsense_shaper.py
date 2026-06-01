# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway OPNsense Traffic Shaper service
====================================================

Read-and-stage for the OPNsense traffic shaper (ipfw dummynet pipes,
queues, and rules). Mirrors the shape of
``adapter_opnsense_firewall.py`` so the same Pending Changes UX
applies to QoS policy.

- Reads run live against the controller.
- Writes are STAGED in ``core.adapter_pending_changes`` (table is
  vendor-agnostic despite the historical name).
- Apply uses the existing dispatcher in ``gateway_vpn.apply_change``
  and the dual-gate (``ADAPTER_READ_ONLY=false`` AND ``force=true``).

Supported features::

    opnsense.shaper.pipe         create | update | delete
    opnsense.shaper.queue        create | update | delete
    opnsense.shaper.rule         create | update | delete
    opnsense.shaper.apply        create  (commit staged config)

The applier passes ``force=True`` to the OPNsense client so the write
actually reaches the controller — every write outside the applier is
refused at the client layer by the ``ADAPTER_READ_ONLY`` gate.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from fastapi import HTTPException

from app.adapters.validation import validate_id
from app.services.adapter_base import GatewayServiceBase

# (feature, operation) → bound client method name.
_APPLY: dict[tuple[str, str], str] = {
    # Pipes (bandwidth limiters).
    ("opnsense.shaper.pipe", "create"): "add_shaper_pipe",
    ("opnsense.shaper.pipe", "update"): "update_shaper_pipe",
    ("opnsense.shaper.pipe", "delete"): "delete_shaper_pipe",
    # Queues (weighted classes inside a pipe).
    ("opnsense.shaper.queue", "create"): "add_shaper_queue",
    ("opnsense.shaper.queue", "update"): "update_shaper_queue",
    ("opnsense.shaper.queue", "delete"): "delete_shaper_queue",
    # Rules (traffic → pipe/queue mapping).
    ("opnsense.shaper.rule", "create"): "add_shaper_rule",
    ("opnsense.shaper.rule", "update"): "update_shaper_rule",
    ("opnsense.shaper.rule", "delete"): "delete_shaper_rule",
    # Apply (commit pipes + queues + rules to dummynet).
    ("opnsense.shaper.apply", "create"): "apply_shaper_changes",
}


class GatewayOpnsenseShaperService(GatewayServiceBase):
    """Live reads + staged writes for OPNsense traffic shaper config."""

    SUPPORTED_CONTROLLER_TYPE = "opnsense"

    # ── Live reads ───────────────────────────────────────────────────

    async def list_pipes(self, controller_id: UUID, organization_id: UUID) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(controller_id, organization_id)
        client = await self._get_client(ctrl)
        try:
            items = await client.get_shaper_pipes()
        finally:
            await client.close()  # Item 14
        return {
            "controller_id": controller_id,
            "items": items,
            "fetched_at": datetime.now(UTC),
        }

    async def list_queues(self, controller_id: UUID, organization_id: UUID) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(controller_id, organization_id)
        client = await self._get_client(ctrl)
        try:
            items = await client.get_shaper_queues()
        finally:
            await client.close()  # Item 14
        return {
            "controller_id": controller_id,
            "items": items,
            "fetched_at": datetime.now(UTC),
        }

    async def list_rules(self, controller_id: UUID, organization_id: UUID) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(controller_id, organization_id)
        client = await self._get_client(ctrl)
        try:
            items = await client.get_shaper_rules()
        finally:
            await client.close()  # Item 14
        return {
            "controller_id": controller_id,
            "items": items,
            "fetched_at": datetime.now(UTC),
        }

    # ── Apply path ───────────────────────────────────────────────────

    def build_applier(self, change: Any) -> Any:
        """Return an awaitable that pushes ``change`` to the controller.

        Every call passes ``force=True`` to the OPNsense client so it
        satisfies the client-layer read-only check — that gate is
        the bottom-of-stack safety; this applier is the top of the
        sanctioned write path.
        """

        async def _apply(c: Any) -> Any:
            ctrl = await self._resolve_controller_or_gateway(c.controller_id, c.organization_id)
            client = await self._get_client(ctrl)
            try:
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
                            f"OPNsense adapter has no method {method_name!r}; "
                            "missing implementation"
                        ),
                    )

                # Dispatch by feature/operation. Each call gets force=True.
                if c.feature in (
                    "opnsense.shaper.pipe",
                    "opnsense.shaper.queue",
                    "opnsense.shaper.rule",
                ):
                    if c.operation == "create":
                        return await method(payload, force=True)
                    if c.operation == "update":
                        if not target_id:
                            raise HTTPException(
                                400,
                                detail=(f"update on {c.feature} requires target_id"),
                            )
                        # Defense-in-depth: re-validate at apply time.
                        validate_id(str(target_id), label="target_id")
                        return await method(target_id, payload, force=True)
                    if c.operation == "delete":
                        if not target_id:
                            raise HTTPException(
                                400,
                                detail=(f"delete on {c.feature} requires target_id"),
                            )
                        validate_id(str(target_id), label="target_id")
                        return await method(target_id, force=True)
                if c.feature == "opnsense.shaper.apply":
                    # No payload, no target — just commit.
                    return await method(force=True)
                raise HTTPException(400, detail=f"unhandled feature={c.feature!r}")
            finally:
                await client.close()  # Item 14

        return _apply

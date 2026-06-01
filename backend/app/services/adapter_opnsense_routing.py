# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway OPNsense Routing service
============================================

Read-and-stage for OPNsense static routes plus live reads for the
kernel routing table and gateway health. Mirrors the shape of
``adapter_opnsense_firewall.py`` so the same Pending Changes UX
applies. The contract:

- Reads run live against the controller.
- Writes are STAGED in ``core.adapter_pending_changes`` (table is
  vendor-agnostic despite the historical name).
- Apply uses the existing dispatcher in ``gateway_vpn.apply_change``
  and the dual-gate (``ADAPTER_READ_ONLY=false`` AND ``force=true``).

Supported features::

    opnsense.routing.static_route   create | update | delete
    opnsense.routing.apply          create  (commit staged routes)

The applier passes ``force=True`` to the OPNsense client so the
write actually reaches the controller — every write outside the
applier is refused at the client layer by the
``ADAPTER_READ_ONLY`` gate.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from fastapi import HTTPException

from app.adapters.validation import validate_id
from app.services.adapter_base import GatewayServiceBase
from app.services.adapter_redaction import redact_secrets

# (feature, operation) → bound client method name. The applier
# uses this to dispatch — same pattern Omada services use.
_APPLY: dict[tuple[str, str], str] = {
    ("opnsense.routing.static_route", "create"): "add_static_route",
    ("opnsense.routing.static_route", "update"): "update_static_route",
    ("opnsense.routing.static_route", "delete"): "delete_static_route",
    # ``apply`` commits the staged route changes to the running kernel
    # via the OPNsense ``reconfigure`` action.
    ("opnsense.routing.apply", "create"): "apply_route_changes",
}


class GatewayOpnsenseRoutingService(GatewayServiceBase):
    """Live reads + staged writes for OPNsense routing config."""

    SUPPORTED_CONTROLLER_TYPE = "opnsense"

    # ── Live reads ───────────────────────────────────────────────────

    async def list_static_routes(
        self, controller_id: UUID, organization_id: UUID
    ) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(controller_id, organization_id)
        client = await self._get_client(ctrl)
        try:
            routes = await client.get_static_routes()
        finally:
            await client.close()  # Item 14
        # BGP/OSPF auth keys can ride in description / comment fields
        # operators paste credentials into.
        return {
            "controller_id": controller_id,
            "items": ([redact_secrets(r) for r in routes] if isinstance(routes, list) else routes),
            "fetched_at": datetime.now(UTC),
        }

    async def get_routing_table(self, controller_id: UUID, organization_id: UUID) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(controller_id, organization_id)
        client = await self._get_client(ctrl)
        try:
            table = await client.get_routing_table()
        finally:
            await client.close()  # Item 14
        return {
            "controller_id": controller_id,
            "table": table,
            "fetched_at": datetime.now(UTC),
        }

    async def get_gateway_status(
        self, controller_id: UUID, organization_id: UUID
    ) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(controller_id, organization_id)
        client = await self._get_client(ctrl)
        try:
            status_data = await client.get_gateway_status()
        finally:
            await client.close()  # Item 14
        return {
            "controller_id": controller_id,
            "status": status_data,
            "fetched_at": datetime.now(UTC),
        }

    # ── Apply path ───────────────────────────────────────────────────

    def build_applier(self, change: Any) -> Any:
        """Return an awaitable that pushes ``change`` to the controller.

        Every call passes ``force=True`` to the OPNsense client so it
        satisfies the client-layer read-only check — that gate
        is the bottom-of-stack safety; this applier is the top of the
        sanctioned write path. The dispatcher
        (``gateway_vpn.apply_change``) is what actually opens the
        gate via ``AdapterStagingService.apply_change``'s dual-gate
        check.
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

                # Dispatch by feature/operation. Each call gets force=True
                # so the read-only gate lets the write through.
                if c.feature == "opnsense.routing.static_route":
                    if c.operation == "create":
                        return await method(payload, force=True)
                    if c.operation == "update":
                        if not target_id:
                            raise HTTPException(
                                400,
                                detail=(
                                    "update on opnsense.routing.static_route requires target_id"
                                ),
                            )
                        # Defense-in-depth: re-validate at apply time.
                        # A manually-inserted DB row shouldn't bypass.
                        validate_id(str(target_id), label="target_id")
                        return await method(target_id, payload, force=True)
                    if c.operation == "delete":
                        if not target_id:
                            raise HTTPException(
                                400,
                                detail=(
                                    "delete on opnsense.routing.static_route requires target_id"
                                ),
                            )
                        validate_id(str(target_id), label="target_id")
                        return await method(target_id, force=True)
                if c.feature == "opnsense.routing.apply":
                    # No payload, no target — just commit.
                    return await method(force=True)
                raise HTTPException(400, detail=f"unhandled feature={c.feature!r}")
            finally:
                await client.close()  # Item 14

        return _apply

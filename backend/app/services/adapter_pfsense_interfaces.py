# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway pfSense Interfaces service
==============================================

Read-and-stage for pfSense interface configuration: physical interface
overview, interface stats, and VLAN sub-interfaces. Mirrors
``adapter_opnsense_interfaces.py`` so the same Pending Changes UX
applies to L2/L3 plumbing.

- Reads run live against the controller.
- Writes are STAGED in ``core.adapter_pending_changes``.
- Apply uses the existing dispatcher in ``gateway_vpn.apply_change``
  and the dual-gate (``ADAPTER_READ_ONLY=false`` AND ``force=true``).

Supported features::

    pfsense.interfaces.vlan         create | update | delete

The applier passes ``force=True`` to the pfSense client so the write
actually reaches the controller — every write outside the applier is
refused at the client layer by the ``ADAPTER_READ_ONLY`` gate.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from fastapi import HTTPException

from app.services.adapter_base import GatewayServiceBase
from app.services.adapter_redaction import redact_secrets

# (feature, operation) → bound client method name.
_APPLY: dict[tuple[str, str], str] = {
    # VLAN sub-interface CRUD.
    ("pfsense.interfaces.vlan", "create"): "add_vlan",
    ("pfsense.interfaces.vlan", "update"): "update_vlan",
    ("pfsense.interfaces.vlan", "delete"): "delete_vlan",
}


class GatewayPfsenseInterfacesService(GatewayServiceBase):
    """Live reads + staged writes for pfSense interface config."""

    SUPPORTED_CONTROLLER_TYPE = "pfsense"

    # ── Live reads ───────────────────────────────────────────────────

    async def list_interfaces(self, controller_id: UUID, organization_id: UUID) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(controller_id, organization_id)
        client = await self._get_client(ctrl)
        items = await client.get_interfaces()
        return {
            "controller_id": controller_id,
            "items": ([redact_secrets(i) for i in items] if isinstance(items, list) else items),
            "fetched_at": datetime.now(UTC),
        }

    async def get_interface_stats(
        self, controller_id: UUID, organization_id: UUID
    ) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(controller_id, organization_id)
        client = await self._get_client(ctrl)
        items = await client.get_interface_stats()
        return {
            "controller_id": controller_id,
            "items": items,
            "fetched_at": datetime.now(UTC),
        }

    async def list_vlans(self, controller_id: UUID, organization_id: UUID) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(controller_id, organization_id)
        client = await self._get_client(ctrl)
        items = await client.get_vlans()
        return {
            "controller_id": controller_id,
            "items": ([redact_secrets(i) for i in items] if isinstance(items, list) else items),
            "fetched_at": datetime.now(UTC),
        }

    # ── Apply path ───────────────────────────────────────────────────

    def build_applier(self, change: Any) -> Any:
        """Return an awaitable that pushes ``change`` to the controller.

        Every call passes ``force=True`` to the pfSense client so it
        satisfies the client-layer read-only check.
        """

        async def _apply(c: Any) -> Any:
            # Fast-fail BEFORE building a network client.
            method_name = _APPLY.get((c.feature, c.operation))
            if method_name is None:
                raise HTTPException(
                    400,
                    detail=(f"no applier for feature={c.feature!r} operation={c.operation!r}"),
                )

            ctrl = await self._resolve_controller_or_gateway(c.controller_id, c.organization_id)
            client = await self._get_client(ctrl)
            payload = c.payload or {}
            target_id = c.target_id

            method = getattr(client, method_name, None)
            if method is None:
                raise HTTPException(
                    501,
                    detail=(
                        f"pfSense adapter has no method {method_name!r}; missing implementation"
                    ),
                )

            if c.feature == "pfsense.interfaces.vlan":
                if c.operation == "create":
                    return await method(payload, force=True)
                if c.operation in ("update", "delete"):
                    if not target_id:
                        raise HTTPException(
                            400,
                            detail=(
                                f"{c.operation} on pfsense.interfaces.vlan "
                                "requires target_id (VLAN id)"
                            ),
                        )
                    try:
                        vlan_id = int(target_id)
                    except (TypeError, ValueError) as exc:
                        raise HTTPException(
                            400,
                            detail=("pfsense.interfaces.vlan target_id must be a numeric VLAN id"),
                        ) from exc
                    if c.operation == "update":
                        return await method(vlan_id, payload, force=True)
                    return await method(vlan_id, force=True)
            raise HTTPException(400, detail=f"unhandled feature={c.feature!r}")

        return _apply

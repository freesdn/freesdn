# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway pfSense DHCP service
========================================

Read-and-stage for pfSense DHCP. Mirrors ``adapter_pfsense_firewall.py``:
live reads, staged writes, shared apply dispatcher.

- Reads run live against the controller.
- Writes are STAGED in ``core.adapter_pending_changes`` (table is
  vendor-agnostic despite the historical name).
- Apply uses the shared dispatcher in ``gateway_vpn.apply_change``
  and the dual-gate (``ADAPTER_READ_ONLY=false`` AND ``force=true``).

Supported features::

    pfsense.dhcp.static_mapping   create | delete   (target_id = mapping id)
    pfsense.dhcp.server           update            (target_id = interface,
                                                     e.g. 'lan')

The applier passes ``force=True`` to the pfSense client so the write
actually reaches the firewall — every write outside the applier is
refused at the client layer by the ``ADAPTER_READ_ONLY`` gate.

Note: pfSense client does not currently expose an ``update`` for
static mappings, an ``apply`` for the dhcpd config, or a delete-server
verb. Those features are omitted until the adapter grows them — see
report at end of staging task.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from fastapi import HTTPException

from app.adapters.validation import validate_id
from app.services.adapter_base import GatewayServiceBase

# (feature, operation) → bound client method name.
#
# ``static_mapping.update`` is omitted — pfSense client has no
# update verb. ``server.update`` keys off the interface name carried
# in ``target_id`` (e.g. ``lan``, ``opt1``).
_APPLY: dict[tuple[str, str], str] = {
    ("pfsense.dhcp.static_mapping", "create"): "add_dhcp_static_mapping",
    ("pfsense.dhcp.static_mapping", "delete"): "delete_dhcp_static_mapping",
    ("pfsense.dhcp.server", "update"): "update_dhcp_server",
}


class GatewayPfsenseDhcpService(GatewayServiceBase):
    """Live reads + staged writes for pfSense DHCP config."""

    SUPPORTED_CONTROLLER_TYPE = "pfsense"

    # ── Live reads ───────────────────────────────────────────────────

    async def list_servers(self, controller_id: UUID, organization_id: UUID) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(controller_id, organization_id)
        client = await self._get_client(ctrl)
        servers = await client.get_dhcp_servers()
        return {
            "controller_id": controller_id,
            "items": servers,
            "fetched_at": datetime.now(UTC),
        }

    async def list_leases(self, controller_id: UUID, organization_id: UUID) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(controller_id, organization_id)
        client = await self._get_client(ctrl)
        leases = await client.get_dhcp_leases()
        return {
            "controller_id": controller_id,
            "items": leases,
            "fetched_at": datetime.now(UTC),
        }

    async def list_static_mappings(
        self,
        controller_id: UUID,
        organization_id: UUID,
        interface: str = "lan",
    ) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(controller_id, organization_id)
        client = await self._get_client(ctrl)
        mappings = await client.get_dhcp_static_mappings(interface)
        return {
            "controller_id": controller_id,
            "interface": interface,
            "items": mappings,
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

            if c.feature == "pfsense.dhcp.static_mapping":
                if c.operation == "create":
                    return await method(payload, force=True)
                if c.operation == "delete":
                    if not target_id:
                        raise HTTPException(
                            400,
                            detail=(
                                "delete on pfsense.dhcp.static_mapping "
                                "requires target_id (mapping id)"
                            ),
                        )
                    try:
                        mapping_id = int(target_id)
                    except (TypeError, ValueError) as exc:
                        raise HTTPException(
                            400,
                            detail=(
                                "pfsense.dhcp.static_mapping target_id must be a numeric mapping id"
                            ),
                        ) from exc
                    return await method(mapping_id, force=True)
            if c.feature == "pfsense.dhcp.server":
                if c.operation == "update":
                    if not target_id:
                        raise HTTPException(
                            400,
                            detail=(
                                "update on pfsense.dhcp.server requires "
                                "target_id (interface name, e.g. 'lan')"
                            ),
                        )
                    # ``target_id`` is the interface name and lands in
                    # the pfSense URL query. DB-stored values must be
                    # re-validated before they reach the client to
                    # block a path-traversal smuggle from a corrupted
                    # staging row.
                    validate_id(target_id, label="interface")
                    return await method(target_id, payload, force=True)
            raise HTTPException(400, detail=f"unhandled feature={c.feature!r}")

        return _apply

# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway OPNsense DHCP service
=========================================

Read-and-stage for OPNsense DHCP. Covers BOTH the legacy ISC DHCPv4
backend (static mappings + reconfigure) AND the modern KEA DHCPv4
backend (subnets + reconfigure) introduced in OPNsense 24.7+. Same
shape as ``adapter_opnsense_firewall.py``: live reads, staged writes,
shared apply dispatcher.

- Reads run live against the controller.
- Writes are STAGED in ``core.adapter_pending_changes``.
- Apply uses the shared dispatcher in ``gateway_vpn.apply_change``
  and the dual-gate (``ADAPTER_READ_ONLY=false`` AND ``force=true``).

Supported features::

    opnsense.dhcp.static_mapping   create | update | delete   (ISC dhcpd)
    opnsense.dhcp.apply            create  (commit ISC dhcpd config)
    opnsense.dhcp.kea_subnet       create | update | delete   (KEA 24.7+)
    opnsense.dhcp.kea_apply        create  (commit KEA config)

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
    # ISC dhcpd static mappings.
    ("opnsense.dhcp.static_mapping", "create"): "add_dhcp_static_mapping",
    ("opnsense.dhcp.static_mapping", "update"): "update_dhcp_static_mapping",
    ("opnsense.dhcp.static_mapping", "delete"): "delete_dhcp_static_mapping",
    ("opnsense.dhcp.apply", "create"): "apply_dhcp_changes",
    # KEA DHCPv4 subnets (OPNsense 24.7+ replacement backend).
    # The OPNsense client uses ``set_kea_dhcpv4_subnet`` for update
    # (set verb on the controller side) and ``del_kea_dhcpv4_subnet``
    # for delete — map both into the same feature key so the UI is
    # consistent with the rest of the gateway pattern.
    ("opnsense.dhcp.kea_subnet", "create"): "add_kea_dhcpv4_subnet",
    ("opnsense.dhcp.kea_subnet", "update"): "set_kea_dhcpv4_subnet",
    ("opnsense.dhcp.kea_subnet", "delete"): "del_kea_dhcpv4_subnet",
    ("opnsense.dhcp.kea_apply", "create"): "apply_kea_changes",
}


class GatewayOpnsenseDhcpService(GatewayServiceBase):
    """Live reads + staged writes for OPNsense DHCP config."""

    SUPPORTED_CONTROLLER_TYPE = "opnsense"

    # ── Live reads ───────────────────────────────────────────────────

    async def list_leases(self, controller_id: UUID, organization_id: UUID) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(controller_id, organization_id)
        client = await self._get_client(ctrl)
        # close the httpx pool deterministically.
        try:
            leases = await client.get_dhcp_leases()
        finally:
            await client.close()
        return {
            "controller_id": controller_id,
            "items": leases,
            "fetched_at": datetime.now(UTC),
        }

    async def list_static_mappings(
        self, controller_id: UUID, organization_id: UUID
    ) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(controller_id, organization_id)
        client = await self._get_client(ctrl)
        try:
            mappings = await client.get_dhcp_static_mappings()
        finally:
            await client.close()
        return {
            "controller_id": controller_id,
            "items": mappings,
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

                # Dispatch by feature/operation. Each call gets force=True
                # so the read-only gate lets the write through — the
                # operator already passed force=true at the apply
                # endpoint, which is the high-level dual-gate.
                if c.feature in (
                    "opnsense.dhcp.static_mapping",
                    "opnsense.dhcp.kea_subnet",
                ):
                    if c.operation == "create":
                        return await method(payload, force=True)
                    if c.operation == "update":
                        if not target_id:
                            raise HTTPException(
                                400,
                                detail=(f"update on {c.feature} requires target_id"),
                            )
                        # Defense-in-depth: re-validate at apply time
                        # so a manually-inserted DB row can't bypass.
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
                if c.feature in (
                    "opnsense.dhcp.apply",
                    "opnsense.dhcp.kea_apply",
                ):
                    # No payload, no target — just commit.
                    return await method(force=True)
                raise HTTPException(400, detail=f"unhandled feature={c.feature!r}")
            finally:
                # close the httpx pool deterministically.
                await client.close()

        return _apply

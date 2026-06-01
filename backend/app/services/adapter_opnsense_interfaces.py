# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway OPNsense Interfaces service
================================================

Read-and-stage for OPNsense interface configuration: physical
interface overview, ARP/NDP tables, and VLAN sub-interfaces. Mirrors
the shape of ``adapter_opnsense_firewall.py`` so the same Pending
Changes UX applies to L2/L3 plumbing.

- Reads run live against the controller.
- Writes are STAGED in ``core.adapter_pending_changes`` (table is
  vendor-agnostic despite the historical name).
- Apply uses the existing dispatcher in ``gateway_vpn.apply_change``
  and the dual-gate (``ADAPTER_READ_ONLY=false`` AND ``force=true``).

Supported features::

    opnsense.interfaces.vlan         create | update | delete
    opnsense.interfaces.vlan_apply   create  (commit staged VLAN config)

The applier passes ``force=True`` to the OPNsense client so the write
actually reaches the controller — every write outside the applier is
refused at the client layer by the ``ADAPTER_READ_ONLY`` gate.

Notes on shape:
- ``opnsense.interfaces.assignment`` (update) was specified in the
  feature design but the OPNsense client does not currently expose
  ``update_interface_assignment``. Until a write method lands in the
  adapter, that feature is omitted; the read path
  (``GET /assignment``) IS exposed for parity with the spec.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from fastapi import HTTPException

from app.adapters.validation import validate_id
from app.services.adapter_base import GatewayServiceBase
from app.services.adapter_redaction import redact_secrets

# (feature, operation) → bound client method name.
_APPLY: dict[tuple[str, str], str] = {
    # VLAN sub-interface CRUD.
    ("opnsense.interfaces.vlan", "create"): "add_vlan_item",
    ("opnsense.interfaces.vlan", "update"): "update_vlan_item",
    ("opnsense.interfaces.vlan", "delete"): "delete_vlan_item",
    # Apply (commits VLAN config to the running kernel).
    ("opnsense.interfaces.vlan_apply", "create"): "apply_vlan_changes",
}


class GatewayOpnsenseInterfacesService(GatewayServiceBase):
    """Live reads + staged writes for OPNsense interface config."""

    SUPPORTED_CONTROLLER_TYPE = "opnsense"

    # ── Live reads ───────────────────────────────────────────────────

    async def list_interfaces(self, controller_id: UUID, organization_id: UUID) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(controller_id, organization_id)
        client = await self._get_client(ctrl)
        try:
            items = await client.get_interfaces()
        finally:
            await client.close()  # Item 14
        return {
            "controller_id": controller_id,
            "items": ([redact_secrets(i) for i in items] if isinstance(items, list) else items),
            "fetched_at": datetime.now(UTC),
        }

    async def list_arp(self, controller_id: UUID, organization_id: UUID) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(controller_id, organization_id)
        client = await self._get_client(ctrl)
        try:
            items = await client.get_arp_table()
        finally:
            await client.close()  # Item 14
        return {
            "controller_id": controller_id,
            "items": items,
            "fetched_at": datetime.now(UTC),
        }

    async def list_ndp(self, controller_id: UUID, organization_id: UUID) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(controller_id, organization_id)
        client = await self._get_client(ctrl)
        try:
            items = await client.get_ndp_table()
        finally:
            await client.close()  # Item 14
        return {
            "controller_id": controller_id,
            "items": items,
            "fetched_at": datetime.now(UTC),
        }

    async def list_vlans(self, controller_id: UUID, organization_id: UUID) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(controller_id, organization_id)
        client = await self._get_client(ctrl)
        try:
            items = await client.get_vlan_items()
        finally:
            await client.close()  # Item 14
        return {
            "controller_id": controller_id,
            "items": items,
            "fetched_at": datetime.now(UTC),
        }

    async def get_assignment(self, controller_id: UUID, organization_id: UUID) -> dict[str, Any]:
        """Return all assignable interfaces and their current config.

        OPNsense exposes the full assignment table via the same
        ``/api/interfaces/overview/export`` endpoint; the adapter
        method ``get_interface_list`` is the canonical read.
        """
        ctrl = await self._resolve_controller_or_gateway(controller_id, organization_id)
        client = await self._get_client(ctrl)
        try:
            items = await client.get_interface_list()
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
                if c.feature == "opnsense.interfaces.vlan":
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
                if c.feature == "opnsense.interfaces.vlan_apply":
                    # No payload, no target — just commit.
                    return await method(force=True)
                raise HTTPException(400, detail=f"unhandled feature={c.feature!r}")
            finally:
                await client.close()  # Item 14

        return _apply

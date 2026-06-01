# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway MikroTik Interfaces service
==============================================

Read-and-stage for RouterOS interface configuration: physical
ethernet, bridge interfaces and bridge ports/VLAN tables, VLAN
sub-interfaces, plus enable/disable toggles. Mirrors the shape of
``adapter_opnsense_interfaces.py`` so the same Pending Changes UX
covers MikroTik L2 plumbing.

- Reads run live against the controller.
- Writes are STAGED in ``core.adapter_pending_changes``.
- Apply uses the existing dispatcher in ``gateway_vpn.apply_change``
  and the dual-gate (``ADAPTER_READ_ONLY=false`` AND ``force=true``).

Supported features::

    mikrotik.interfaces.toggle        create  (target_id=iface id, payload {enabled: bool})
    mikrotik.interfaces.vlan          create | update | delete
    mikrotik.interfaces.bridge_vlan   create | delete

Bridge VLAN entries are immutable on RouterOS — the canonical
"update" idiom is delete-then-recreate, so update is not exposed.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from fastapi import HTTPException

from app.services.adapter_base import GatewayServiceBase
from app.services.adapter_redaction import redact_secrets

# (feature, operation) → bound MikroTik client method name. The
# applier dispatches by these tuples; entries that depend on payload
# (``toggle``) are resolved inline.
_APPLY: dict[tuple[str, str], str] = {
    # Toggle is a payload-driven enable/disable — applier picks the
    # exact method, this entry just acts as a presence marker.
    ("mikrotik.interfaces.toggle", "create"): "enable_interface",
    # VLAN sub-interfaces — full CRUD.
    ("mikrotik.interfaces.vlan", "create"): "add_vlan_interface",
    ("mikrotik.interfaces.vlan", "update"): "update_vlan_interface",
    ("mikrotik.interfaces.vlan", "delete"): "delete_vlan_interface",
    # Bridge VLANs — add+delete only (RouterOS doesn't natively
    # patch bridge/vlan rows).
    ("mikrotik.interfaces.bridge_vlan", "create"): "add_bridge_vlan",
    ("mikrotik.interfaces.bridge_vlan", "delete"): "delete_bridge_vlan",
}


class GatewayMikrotikInterfacesService(GatewayServiceBase):
    """Live reads + staged writes for RouterOS interface config."""

    SUPPORTED_CONTROLLER_TYPE = "mikrotik"

    # ── Live reads ───────────────────────────────────────────────────

    # Defensive redaction on every read — RouterOS interface
    # comments are operator scratch space and have been seen to
    # carry credentials.

    async def list_interfaces(
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
        items = await client.get_interfaces()
        return {
            "controller_id": controller_id,
            "items": [redact_secrets(i) for i in items],
            "fetched_at": datetime.now(UTC),
        }

    async def list_ethernet(
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
        items = await client.get_ethernet_interfaces()
        return {
            "controller_id": controller_id,
            "items": [redact_secrets(i) for i in items],
            "fetched_at": datetime.now(UTC),
        }

    async def list_bridges(
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
        items = await client.get_bridge_interfaces()
        return {
            "controller_id": controller_id,
            "items": [redact_secrets(i) for i in items],
            "fetched_at": datetime.now(UTC),
        }

    async def list_bridge_ports(
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
        items = await client.get_bridge_ports()
        return {
            "controller_id": controller_id,
            "items": [redact_secrets(i) for i in items],
            "fetched_at": datetime.now(UTC),
        }

    async def list_bridge_vlans(
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
        items = await client.get_bridge_vlans()
        return {
            "controller_id": controller_id,
            "items": [redact_secrets(i) for i in items],
            "fetched_at": datetime.now(UTC),
        }

    async def list_vlans(
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
        items = await client.get_vlan_interfaces()
        return {
            "controller_id": controller_id,
            "items": [redact_secrets(i) for i in items],
            "fetched_at": datetime.now(UTC),
        }

    # ── Apply path ───────────────────────────────────────────────────

    def build_applier(self, change: Any) -> Any:
        """Return an awaitable that pushes ``change`` to the controller.

        Every call passes ``force=True`` so the client-layer
        read-only gate lets the write through. The high-level
        dual-gate already cleared at the apply endpoint.
        """

        async def _apply(c: Any) -> Any:
            ctrl = await self._resolve_controller_or_gateway(c.controller_id, c.organization_id)
            client = await self._get_client(ctrl)
            payload = c.payload or {}
            target_id = c.target_id

            # Toggle is payload-driven — pick enable vs disable up
            # front instead of plumbing both into the dispatch table.
            if c.feature == "mikrotik.interfaces.toggle":
                if c.operation != "create":
                    raise HTTPException(
                        400,
                        detail=("interfaces.toggle only supports operation='create'"),
                    )
                if not target_id:
                    raise HTTPException(
                        400,
                        detail=("interfaces.toggle requires target_id (interface id)"),
                    )
                enabled = bool(payload.get("enabled", False))
                method_name = "enable_interface" if enabled else "disable_interface"
                method = getattr(client, method_name, None)
                if method is None:
                    raise HTTPException(
                        501,
                        detail=(f"MikroTik adapter has no method {method_name!r}"),
                    )
                return await method(target_id, force=True)

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

            # Universal target_id guard — RouterOS PATCH/DELETE on a
            # missing id would interpolate ``None`` into the URL path.
            if c.operation in ("update", "delete") and not target_id:
                raise HTTPException(
                    400,
                    detail=(f"feature {c.feature!r} requires a target_id for {c.operation!r}"),
                )

            # VLAN sub-interfaces. ``add_vlan_interface`` takes
            # (name, vlan_id, interface, **kw) — destructure the
            # payload so callers can submit a flat dict the same way
            # OPNsense and Omada services accept.
            if c.feature == "mikrotik.interfaces.vlan":
                if c.operation == "create":
                    name = payload.get("name")
                    vlan_id = payload.get("vlan-id") or payload.get("vlan_id")
                    interface = payload.get("interface")
                    if not (name and vlan_id is not None and interface):
                        raise HTTPException(
                            400,
                            detail=("vlan create requires payload {name, vlan-id, interface}"),
                        )
                    # Drop ``force`` from the spread — the applier
                    # already passes force=True; if a staged payload
                    # includes it we'd hit "got multiple values".
                    extra = {
                        k: v
                        for k, v in payload.items()
                        if k
                        not in {
                            "name",
                            "vlan-id",
                            "vlan_id",
                            "interface",
                            "force",
                        }
                    }
                    return await method(name, int(vlan_id), interface, force=True, **extra)
                if c.operation == "update":
                    return await method(target_id, payload, force=True)
                if c.operation == "delete":
                    return await method(target_id, force=True)

            # Bridge VLAN — add takes (bridge, vlan-ids, **kw),
            # delete takes the entry id.
            if c.feature == "mikrotik.interfaces.bridge_vlan":
                if c.operation == "create":
                    bridge = payload.get("bridge")
                    vlan_ids = payload.get("vlan-ids") or payload.get("vlan_ids")
                    if not (bridge and vlan_ids):
                        raise HTTPException(
                            400,
                            detail=("bridge_vlan create requires payload {bridge, vlan-ids}"),
                        )
                    extra = {
                        k: v
                        for k, v in payload.items()
                        if k not in {"bridge", "vlan-ids", "vlan_ids", "force"}
                    }
                    return await method(bridge, vlan_ids, force=True, **extra)
                if c.operation == "delete":
                    return await method(target_id, force=True)
            raise HTTPException(400, detail=f"unhandled feature={c.feature!r}")

        return _apply

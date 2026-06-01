# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway MikroTik IP service
=======================================

Read-and-stage for RouterOS Layer 3 plumbing: IP addresses on
interfaces, IP pools (DHCP / PPP backing), and the ARP table.
Mirrors the shape of the OPNsense / pfSense gateway services.

- Reads run live against the controller.
- Writes are STAGED in ``core.adapter_pending_changes``.
- Apply uses the existing dispatcher in ``gateway_vpn.apply_change``
  and the dual-gate (``ADAPTER_READ_ONLY=false`` AND ``force=true``).

Supported features::

    mikrotik.ip.address    create | delete  (target_id = address id on delete)
    mikrotik.ip.pool       create | update | delete

The IP-address row is immutable on RouterOS in practice (operators
delete + re-add to renumber); only create/delete are exposed.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from fastapi import HTTPException

from app.services.adapter_base import GatewayServiceBase
from app.services.adapter_redaction import redact_secrets

# (feature, operation) → bound MikroTik client method name.
_APPLY: dict[tuple[str, str], str] = {
    # IP addresses — create + delete only (RouterOS doesn't expose a
    # PATCH for ``/ip/address`` rows in any consistent way; renumber
    # is delete + re-add).
    ("mikrotik.ip.address", "create"): "add_ip_address",
    ("mikrotik.ip.address", "delete"): "delete_ip_address",
    # IP pools — full CRUD.
    ("mikrotik.ip.pool", "create"): "add_ip_pool",
    ("mikrotik.ip.pool", "update"): "update_ip_pool",
    ("mikrotik.ip.pool", "delete"): "delete_ip_pool",
}


class GatewayMikrotikIPService(GatewayServiceBase):
    """Live reads + staged writes for RouterOS L3 (IP) config."""

    SUPPORTED_CONTROLLER_TYPE = "mikrotik"

    # ── Live reads ───────────────────────────────────────────────────

    # Defensive redaction on every read — operator comments on
    # address rows have been observed to contain credentials.

    async def list_addresses(
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
        items = await client.get_ip_addresses()
        return {
            "controller_id": controller_id,
            "items": [redact_secrets(i) for i in items],
            "fetched_at": datetime.now(UTC),
        }

    async def list_pools(
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
        items = await client.get_ip_pools()
        return {
            "controller_id": controller_id,
            "items": [redact_secrets(i) for i in items],
            "fetched_at": datetime.now(UTC),
        }

    async def list_arp(
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
        items = await client.get_arp_table()
        return {
            "controller_id": controller_id,
            "items": [redact_secrets(i) for i in items],
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

            # Universal target_id guard — RouterOS PATCH/DELETE on a
            # missing id would interpolate ``None`` into the URL path.
            if c.operation in ("update", "delete") and not target_id:
                raise HTTPException(
                    400,
                    detail=(f"feature {c.feature!r} requires a target_id for {c.operation!r}"),
                )

            # IP addresses: create takes (address, interface, **kw);
            # delete takes the row id.
            if c.feature == "mikrotik.ip.address":
                if c.operation == "create":
                    address = payload.get("address")
                    interface = payload.get("interface")
                    if not (address and interface):
                        raise HTTPException(
                            400,
                            detail=("ip.address create requires payload {address, interface}"),
                        )
                    # Drop ``force`` from the spread — applier
                    # already passes force=True; collisions would
                    # raise TypeError.
                    extra = {
                        k: v
                        for k, v in payload.items()
                        if k not in {"address", "interface", "force"}
                    }
                    return await method(address, interface, force=True, **extra)
                if c.operation == "delete":
                    return await method(target_id, force=True)

            # IP pools: create takes (name, ranges, **kw); update
            # takes (id, dict); delete takes the row id.
            if c.feature == "mikrotik.ip.pool":
                if c.operation == "create":
                    name = payload.get("name")
                    ranges = payload.get("ranges")
                    if not (name and ranges):
                        raise HTTPException(
                            400,
                            detail=("ip.pool create requires payload {name, ranges}"),
                        )
                    extra = {
                        k: v for k, v in payload.items() if k not in {"name", "ranges", "force"}
                    }
                    return await method(name, ranges, force=True, **extra)
                if c.operation == "update":
                    return await method(target_id, payload, force=True)
                if c.operation == "delete":
                    return await method(target_id, force=True)
            raise HTTPException(400, detail=f"unhandled feature={c.feature!r}")

        return _apply

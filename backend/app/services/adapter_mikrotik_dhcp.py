# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway MikroTik DHCP service
========================================

Read-and-stage for RouterOS DHCP server: server instances, static
lease mappings, and per-subnet network/option records. Mirrors the
shape of ``adapter_opnsense_dhcp.py`` so the same Pending Changes UX
covers MikroTik DHCP plumbing.

- Reads run live against the controller.
- Writes are STAGED in ``core.adapter_pending_changes``.
- Apply uses the existing dispatcher in ``gateway_vpn.apply_change``
  and the dual-gate (``ADAPTER_READ_ONLY=false`` AND ``force=true``).

Supported features::

    mikrotik.dhcp.server         create | update | delete
    mikrotik.dhcp.lease_static   create | update | delete  (target_id = lease id)
    mikrotik.dhcp.network        create | update | delete

Static lease "update" maps to ``update_dhcp_static_lease`` (PATCH on
``/ip/dhcp-server/lease/{id}``). Dynamic leases are read-only —
operators "make static" by creating a static lease and waiting for
the dynamic row to expire.
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
    # DHCP server instances — full CRUD.
    ("mikrotik.dhcp.server", "create"): "add_dhcp_server",
    ("mikrotik.dhcp.server", "update"): "update_dhcp_server",
    ("mikrotik.dhcp.server", "delete"): "delete_dhcp_server",
    # Static lease mappings — full CRUD. Adapter exposes
    # update_dhcp_static_lease for the PATCH path.
    ("mikrotik.dhcp.lease_static", "create"): "add_dhcp_static_lease",
    ("mikrotik.dhcp.lease_static", "update"): "update_dhcp_static_lease",
    ("mikrotik.dhcp.lease_static", "delete"): "delete_dhcp_lease",
    # Per-subnet network records (gateway/dns/options) — full CRUD.
    ("mikrotik.dhcp.network", "create"): "add_dhcp_network",
    ("mikrotik.dhcp.network", "update"): "update_dhcp_network",
    ("mikrotik.dhcp.network", "delete"): "delete_dhcp_network",
}


class GatewayMikrotikDHCPService(GatewayServiceBase):
    """Live reads + staged writes for RouterOS DHCP config."""

    SUPPORTED_CONTROLLER_TYPE = "mikrotik"

    # ── Live reads ───────────────────────────────────────────────────

    # Defensive redaction on every read response — DHCP option
    # rows can carry secrets in option 60/77/82 vendor fields or in
    # comment metadata.

    async def list_servers(
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
        items = await client.get_dhcp_servers()
        return {
            "controller_id": controller_id,
            "items": [redact_secrets(i) for i in items],
            "fetched_at": datetime.now(UTC),
        }

    async def list_leases(
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
        items = await client.get_dhcp_leases()
        return {
            "controller_id": controller_id,
            "items": [redact_secrets(i) for i in items],
            "fetched_at": datetime.now(UTC),
        }

    async def list_networks(
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
        items = await client.get_dhcp_networks()
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

            # DHCP servers + networks: create takes a flat dict;
            # update takes (id, dict); delete takes id.
            if c.feature in (
                "mikrotik.dhcp.server",
                "mikrotik.dhcp.network",
            ):
                if c.operation == "create":
                    return await method(payload, force=True)
                if c.operation == "update":
                    return await method(target_id, payload, force=True)
                if c.operation == "delete":
                    return await method(target_id, force=True)

            # Static leases: create takes (mac, address, **kw);
            # update takes (id, dict); delete takes id.
            if c.feature == "mikrotik.dhcp.lease_static":
                if c.operation == "create":
                    mac = payload.get("mac-address") or payload.get("mac_address")
                    address = payload.get("address")
                    if not (mac and address):
                        raise HTTPException(
                            400,
                            detail=("lease_static create requires payload {mac-address, address}"),
                        )
                    # Drop ``force`` from the spread — if a staged
                    # payload includes it (operator copy-paste, or
                    # a UI bug) we'd hit ``TypeError: got multiple
                    # values for 'force'`` since the applier already
                    # passes force=True explicitly. Same for any
                    # other reserved kwarg that the client method
                    # signature defines.
                    extra = {
                        k: v
                        for k, v in payload.items()
                        if k
                        not in {
                            "mac-address",
                            "mac_address",
                            "address",
                            "force",
                        }
                    }
                    return await method(mac, address, force=True, **extra)
                if c.operation == "update":
                    return await method(target_id, payload, force=True)
                if c.operation == "delete":
                    return await method(target_id, force=True)
            raise HTTPException(400, detail=f"unhandled feature={c.feature!r}")

        return _apply

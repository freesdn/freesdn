# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway MikroTik DNS service
========================================

Read-and-stage for RouterOS DNS: the singleton ``/ip/dns`` settings
object (servers, allow-remote-requests, cache size), static A/AAAA
records, and the DNS resolver cache (read-only). Mirrors the shape
of the OPNsense / pfSense gateway services.

- Reads run live against the controller.
- Writes are STAGED in ``core.adapter_pending_changes``.
- Apply uses the existing dispatcher in ``gateway_vpn.apply_change``
  and the dual-gate (``ADAPTER_READ_ONLY=false`` AND ``force=true``).

Supported features::

    mikrotik.dns.settings   update         (no target_id — singleton)
    mikrotik.dns.static     create | update | delete

The DNS cache is a read-only snapshot of resolver state — there is
no "write" feature; it's exposed via ``GET /cache`` for diagnostics.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from fastapi import HTTPException

from app.services.adapter_base import GatewayServiceBase

# (feature, operation) → bound MikroTik client method name. The
# applier reads this to dispatch by shape.
_APPLY: dict[tuple[str, str], str] = {
    # DNS settings is a singleton object (``/ip/dns`` returns one
    # row); the only sensible operation is ``update`` and there is
    # no target_id.
    ("mikrotik.dns.settings", "update"): "update_dns_settings",
    # DNS static records — full CRUD. ``update_dns_static_entry`` was
    # added to the client alongside the matching create/delete pair.
    ("mikrotik.dns.static", "create"): "add_dns_static_entry",
    ("mikrotik.dns.static", "update"): "update_dns_static_entry",
    ("mikrotik.dns.static", "delete"): "delete_dns_static_entry",
}


class GatewayMikrotikDNSService(GatewayServiceBase):
    """Live reads + staged writes for RouterOS DNS config."""

    SUPPORTED_CONTROLLER_TYPE = "mikrotik"

    # ── Live reads ───────────────────────────────────────────────────

    async def get_settings(
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
        # ``get_dns_settings`` returns a single dict — wrap it like
        # the other read endpoints for shape consistency.
        item = await client.get_dns_settings()
        return {
            "controller_id": controller_id,
            "item": item,
            "fetched_at": datetime.now(UTC),
        }

    async def list_static(
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
        items = await client.get_dns_static_entries()
        return {
            "controller_id": controller_id,
            "items": items,
            "fetched_at": datetime.now(UTC),
        }

    async def list_cache(
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
        items = await client.get_dns_cache()
        return {
            "controller_id": controller_id,
            "items": items,
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

            # Universal target_id guard for row-scoped features.
            # ``mikrotik.dns.settings`` is a singleton (no id) so it's
            # exempted from this check; the static-record paths below
            # require a target_id on update/delete.
            if (
                c.feature == "mikrotik.dns.static"
                and c.operation in ("update", "delete")
                and not target_id
            ):
                raise HTTPException(
                    400,
                    detail=(f"feature {c.feature!r} requires a target_id for {c.operation!r}"),
                )

            # DNS settings — singleton PATCH; no target_id.
            if c.feature == "mikrotik.dns.settings":
                if c.operation == "update":
                    return await method(payload, force=True)

            # Static DNS records: create takes (name, address, **kw);
            # update takes (id, dict); delete takes id.
            if c.feature == "mikrotik.dns.static":
                if c.operation == "create":
                    name = payload.get("name")
                    address = payload.get("address")
                    if not (name and address):
                        raise HTTPException(
                            400,
                            detail=("dns.static create requires payload {name, address}"),
                        )
                    # Drop ``force`` from the spread — applier
                    # already passes force=True explicitly; a
                    # ``force`` key in the staged payload would
                    # raise TypeError on collision.
                    extra = {
                        k: v for k, v in payload.items() if k not in {"name", "address", "force"}
                    }
                    return await method(name, address, force=True, **extra)
                if c.operation == "update":
                    return await method(target_id, payload, force=True)
                if c.operation == "delete":
                    return await method(target_id, force=True)
            raise HTTPException(400, detail=f"unhandled feature={c.feature!r}")

        return _apply

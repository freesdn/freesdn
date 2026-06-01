# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Advanced routing: VRRP, IPv6 static routes, BGP, live routing table.
Reads run live; writes stage.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from fastapi import HTTPException

from app.services.adapter_base import GatewayServiceBase
from app.services.adapter_redaction import redact_list, redact_secrets

_APPLY: dict[tuple[str, str], str] = {
    ("routing.vrrp", "update"): "update_vrrp_config",
    ("routing.ipv6_static", "create"): "create_static_ipv6_route",
    ("routing.ipv6_static", "update"): "update_static_ipv6_route",
    ("routing.ipv6_static", "delete"): "delete_static_ipv6_route",
    ("routing.bgp", "update"): "update_bgp_config",
}

_READ: dict[str, str] = {
    "vrrp": "get_vrrp_config",
    "bgp": "get_bgp_config",
    "ipv6_static": "list_static_ipv6_routes",
    "bgp_neighbors": "get_bgp_neighbors",
    "routing_table": "get_routing_table",
}


class GatewayRoutingService(GatewayServiceBase):
    SUPPORTED_CONTROLLER_TYPE = "omada"

    async def get_routing_data(
        self,
        controller_id: UUID,
        organization_id: UUID,
        site_id: UUID,
        what: str,
        family: str = "ipv4",
    ) -> dict[str, Any]:
        method_name = _READ.get(what)
        if method_name is None:
            raise HTTPException(400, detail=f"unknown what={what!r}; expected {sorted(_READ)}")
        _, client, omada_site_id = await self._resolve_site_context(
            controller_id, organization_id, site_id
        )
        if what == "routing_table":
            data = await client.get_routing_table(omada_site_id, family=family)
        else:
            data = await getattr(client, method_name)(omada_site_id)
        # redact device-native routing secrets (BGP neighbor MD5 `password`,
        # VRRP group `authKey`) before returning to a network:read (viewer) caller —
        # parity with the VPN sibling (adapter_omada_vpn) which redacts every read.
        redacted = redact_list(data) if isinstance(data, list) else redact_secrets(data)
        return {
            "controller_id": controller_id,
            "site_id": site_id,
            "what": what,
            "data": redacted,
            "fetched_at": datetime.now(UTC),
        }

    def build_applier(self, change: Any) -> Any:
        async def _apply(c: Any) -> Any:
            ctrl = await self._get_controller(c.controller_id, c.organization_id)
            client = await self._get_client(ctrl)
            omada_site_id = c.omada_site_id or ""
            payload = c.payload or {}
            target_id = c.target_id

            method_name = _APPLY.get((c.feature, c.operation))
            if method_name is None:
                raise HTTPException(400, detail=f"no applier for {c.feature!r}/{c.operation!r}")
            method = getattr(client, method_name)

            if c.feature == "routing.ipv6_static":
                if c.operation == "create":
                    return await method(omada_site_id, payload)
                if c.operation == "update":
                    return await method(omada_site_id, target_id, payload)
                if c.operation == "delete":
                    return await method(omada_site_id, target_id)

            return await method(omada_site_id, payload)

        return _apply

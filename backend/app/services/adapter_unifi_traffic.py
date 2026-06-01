# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""FreeSDN — Gateway UniFi Traffic service (v2: traffic rules / routes / QoS).

Features (``unifi.traffic.*``): create/update/delete for traffic-rules,
traffic-routes and qos-rules. Generic reads + applier via the shared base.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from app.services.adapter_unifi_common import GatewayUniFiServiceBase

_APPLY: dict[tuple[str, str], str] = {
    ("unifi.traffic.create_rule", "create"): "create_traffic_rule",
    ("unifi.traffic.update_rule", "update"): "update_traffic_rule",
    ("unifi.traffic.delete_rule", "delete"): "delete_traffic_rule",
    ("unifi.traffic.create_route", "create"): "create_traffic_route",
    ("unifi.traffic.update_route", "update"): "update_traffic_route",
    ("unifi.traffic.delete_route", "delete"): "delete_traffic_route",
    ("unifi.traffic.create_qos", "create"): "create_qos_rule",
    ("unifi.traffic.update_qos", "update"): "update_qos_rule",
    ("unifi.traffic.delete_qos", "delete"): "delete_qos_rule",
}


class GatewayUniFiTrafficService(GatewayUniFiServiceBase):
    """Live reads + staged writes for UniFi traffic rules / routes / QoS."""

    FEATURE_PREFIX = "unifi.traffic."
    APPLY_MAP = _APPLY

    async def list_rules(
        self, controller_id: UUID, organization_id: UUID, site: str, *, is_superuser: bool = False
    ) -> dict[str, Any]:
        return await self._read_collection(
            "list_traffic_rules", controller_id, organization_id, site, is_superuser=is_superuser
        )

    async def list_routes(
        self, controller_id: UUID, organization_id: UUID, site: str, *, is_superuser: bool = False
    ) -> dict[str, Any]:
        return await self._read_collection(
            "list_traffic_routes", controller_id, organization_id, site, is_superuser=is_superuser
        )

    async def list_qos(
        self, controller_id: UUID, organization_id: UUID, site: str, *, is_superuser: bool = False
    ) -> dict[str, Any]:
        return await self._read_collection(
            "list_qos_rules", controller_id, organization_id, site, is_superuser=is_superuser
        )

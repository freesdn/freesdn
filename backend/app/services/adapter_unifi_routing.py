# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""FreeSDN — Gateway UniFi Routing service (static routes).

Features (``unifi.routing.*``): create/update/delete for static routes.
Generic reads + applier via the shared base.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from app.services.adapter_unifi_common import GatewayUniFiServiceBase

_APPLY: dict[tuple[str, str], str] = {
    ("unifi.routing.create", "create"): "create_route",
    ("unifi.routing.update", "update"): "update_route",
    ("unifi.routing.delete", "delete"): "delete_route",
}


class GatewayUniFiRoutingService(GatewayUniFiServiceBase):
    """Live reads + staged writes for UniFi static routes."""

    FEATURE_PREFIX = "unifi.routing."
    APPLY_MAP = _APPLY

    async def list_routing(
        self, controller_id: UUID, organization_id: UUID, site: str, *, is_superuser: bool = False
    ) -> dict[str, Any]:
        return await self._read_collection(
            "list_routing", controller_id, organization_id, site, is_superuser=is_superuser
        )

# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""FreeSDN — Gateway UniFi VPN service (VPN networks).

Features (``unifi.vpn.*``): create/update/delete for VPN networks.
Generic reads + applier via the shared base.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from app.services.adapter_unifi_common import GatewayUniFiServiceBase

_APPLY: dict[tuple[str, str], str] = {
    ("unifi.vpn.create", "create"): "create_vpn",
    ("unifi.vpn.update", "update"): "update_vpn",
    ("unifi.vpn.delete", "delete"): "delete_vpn",
}


class GatewayUniFiVpnService(GatewayUniFiServiceBase):
    """Live reads + staged writes for UniFi VPN networks."""

    FEATURE_PREFIX = "unifi.vpn."
    APPLY_MAP = _APPLY

    async def list_vpn_networks(
        self, controller_id: UUID, organization_id: UUID, site: str, *, is_superuser: bool = False
    ) -> dict[str, Any]:
        return await self._read_collection(
            "list_vpn_networks", controller_id, organization_id, site, is_superuser=is_superuser
        )

# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""FreeSDN — Gateway UniFi WLAN Groups service (WLAN groups).

Features (``unifi.wlangroups.*``): create/update/delete for WLAN groups.
Generic reads + applier via the shared base.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from app.services.adapter_unifi_common import GatewayUniFiServiceBase

_APPLY: dict[tuple[str, str], str] = {
    ("unifi.wlangroups.create", "create"): "create_wlan_group",
    ("unifi.wlangroups.update", "update"): "update_wlan_group",
    ("unifi.wlangroups.delete", "delete"): "delete_wlan_group",
}


class GatewayUniFiWlanGroupsService(GatewayUniFiServiceBase):
    """Live reads + staged writes for UniFi WLAN groups."""

    FEATURE_PREFIX = "unifi.wlangroups."
    APPLY_MAP = _APPLY

    async def list_wlan_groups(
        self, controller_id: UUID, organization_id: UUID, site: str, *, is_superuser: bool = False
    ) -> dict[str, Any]:
        return await self._read_collection(
            "list_wlan_groups", controller_id, organization_id, site, is_superuser=is_superuser
        )

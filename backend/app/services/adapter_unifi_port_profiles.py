# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""FreeSDN — Gateway UniFi Port Profiles service (switch port profiles).

Features (``unifi.portprofiles.*``): create/update/delete for port profiles.
Generic reads + applier via the shared base.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from app.services.adapter_unifi_common import GatewayUniFiServiceBase

_APPLY: dict[tuple[str, str], str] = {
    ("unifi.portprofiles.create", "create"): "create_port_profile",
    ("unifi.portprofiles.update", "update"): "update_port_profile",
    ("unifi.portprofiles.delete", "delete"): "delete_port_profile",
}


class GatewayUniFiPortProfilesService(GatewayUniFiServiceBase):
    """Live reads + staged writes for UniFi switch port profiles."""

    FEATURE_PREFIX = "unifi.portprofiles."
    APPLY_MAP = _APPLY

    async def list_port_profiles(
        self, controller_id: UUID, organization_id: UUID, site: str, *, is_superuser: bool = False
    ) -> dict[str, Any]:
        return await self._read_collection(
            "list_port_profiles", controller_id, organization_id, site, is_superuser=is_superuser
        )

# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""FreeSDN — Gateway UniFi DNS service (v2 static-DNS + v1 dynamic-DNS).

Features (``unifi.dns.*``): create/update/delete for static-dns records and
dynamic-dns configs. Generic reads + applier via the shared base.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from app.services.adapter_unifi_common import GatewayUniFiServiceBase

_APPLY: dict[tuple[str, str], str] = {
    ("unifi.dns.create_static", "create"): "create_static_dns",
    ("unifi.dns.update_static", "update"): "update_static_dns",
    ("unifi.dns.delete_static", "delete"): "delete_static_dns",
    ("unifi.dns.create_dynamic", "create"): "create_dynamic_dns",
    ("unifi.dns.update_dynamic", "update"): "update_dynamic_dns",
    ("unifi.dns.delete_dynamic", "delete"): "delete_dynamic_dns",
}


class GatewayUniFiDnsService(GatewayUniFiServiceBase):
    """Live reads + staged writes for UniFi static + dynamic DNS."""

    FEATURE_PREFIX = "unifi.dns."
    APPLY_MAP = _APPLY

    async def list_static(
        self, controller_id: UUID, organization_id: UUID, site: str, *, is_superuser: bool = False
    ) -> dict[str, Any]:
        return await self._read_collection(
            "list_static_dns", controller_id, organization_id, site, is_superuser=is_superuser
        )

    async def list_dynamic(
        self, controller_id: UUID, organization_id: UUID, site: str, *, is_superuser: bool = False
    ) -> dict[str, Any]:
        return await self._read_collection(
            "list_dynamic_dns", controller_id, organization_id, site, is_superuser=is_superuser
        )

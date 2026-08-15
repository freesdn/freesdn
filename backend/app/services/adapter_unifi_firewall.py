# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway UniFi Firewall service
=========================================

Live reads + staged writes for the UniFi firewall surface: the v2
zone-based-firewall policy engine (policies + zones + NAT) and the v1
classic firewall (groups + legacy rules).

Features (``unifi.firewall.*``)::

    create_policy / update_policy / delete_policy   (v2 ZBF policies)
    create_zone   / update_zone   / delete_zone     (v2 ZBF zones)
    create_nat    / update_nat    / delete_nat       (v2 NAT rules)
    create_group  / update_group  / delete_group     (v1 firewall groups)
    create_rule   / update_rule   / delete_rule       (v1 legacy rules)

Every write rides the adapter dual-gate (the staged applier opts in with
``force=True`` after the staging gate clears). The destructive deletes are
registered in ``adapter_staging._CATASTROPHIC_EVENT_PREFIXES``.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from app.services.adapter_unifi_common import GatewayUniFiServiceBase

# (feature, operation) -> adapter method name. The generic create/update/delete
# dispatch in the base service supplies (site, [target_id], [payload], force).
_APPLY: dict[tuple[str, str], str] = {
    ("unifi.firewall.create_policy", "create"): "create_firewall_policy",
    ("unifi.firewall.update_policy", "update"): "update_firewall_policy",
    ("unifi.firewall.delete_policy", "delete"): "delete_firewall_policy",
    ("unifi.firewall.create_zone", "create"): "create_firewall_zone",
    ("unifi.firewall.update_zone", "update"): "update_firewall_zone",
    ("unifi.firewall.delete_zone", "delete"): "delete_firewall_zone",
    ("unifi.firewall.create_nat", "create"): "create_nat_rule",
    ("unifi.firewall.update_nat", "update"): "update_nat_rule",
    ("unifi.firewall.delete_nat", "delete"): "delete_nat_rule",
    ("unifi.firewall.create_group", "create"): "create_firewall_group",
    ("unifi.firewall.update_group", "update"): "update_firewall_group",
    ("unifi.firewall.delete_group", "delete"): "delete_firewall_group",
    ("unifi.firewall.create_rule", "create"): "create_firewall_rule",
    ("unifi.firewall.update_rule", "update"): "update_firewall_rule",
    ("unifi.firewall.delete_rule", "delete"): "delete_firewall_rule",
}


class GatewayUniFiFirewallService(GatewayUniFiServiceBase):
    """Live reads + staged writes for the UniFi firewall surface."""

    SUPPORTED_CONTROLLER_TYPE = "unifi"
    FEATURE_PREFIX = "unifi.firewall."
    APPLY_MAP = _APPLY

    async def list_policies(
        self, controller_id: UUID, organization_id: UUID, site: str, *, is_superuser: bool = False
    ) -> dict[str, Any]:
        return await self._read_collection(
            "list_firewall_policies",
            controller_id,
            organization_id,
            site,
            is_superuser=is_superuser,
        )

    async def list_zones(
        self, controller_id: UUID, organization_id: UUID, site: str, *, is_superuser: bool = False
    ) -> dict[str, Any]:
        return await self._read_collection(
            "list_firewall_zones", controller_id, organization_id, site, is_superuser=is_superuser
        )

    async def zone_matrix(
        self, controller_id: UUID, organization_id: UUID, site: str, *, is_superuser: bool = False
    ) -> dict[str, Any]:
        return await self._read_collection(
            "get_firewall_zone_matrix",
            controller_id,
            organization_id,
            site,
            is_superuser=is_superuser,
        )

    async def list_nat(
        self, controller_id: UUID, organization_id: UUID, site: str, *, is_superuser: bool = False
    ) -> dict[str, Any]:
        return await self._read_collection(
            "list_nat_rules", controller_id, organization_id, site, is_superuser=is_superuser
        )

    async def list_groups(
        self, controller_id: UUID, organization_id: UUID, site: str, *, is_superuser: bool = False
    ) -> dict[str, Any]:
        return await self._read_collection(
            "list_firewall_groups", controller_id, organization_id, site, is_superuser=is_superuser
        )

    async def list_rules(
        self, controller_id: UUID, organization_id: UUID, site: str, *, is_superuser: bool = False
    ) -> dict[str, Any]:
        return await self._read_collection(
            "list_firewall_rules", controller_id, organization_id, site, is_superuser=is_superuser
        )

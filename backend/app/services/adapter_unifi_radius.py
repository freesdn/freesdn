# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""FreeSDN — Gateway UniFi RADIUS service (built-in RADIUS user accounts).

Reads + staged CRUD for the controller's built-in RADIUS user store
(``unifi.radius.*``), used by WPA-Enterprise SSIDs and RADIUS-authenticated
switch ports. Every write rides the staged dual-gate; a delete is gated by the
central ``enforce_unifi_preflight`` "any delete needs confirmed=true" rule.

The adapter's ``create/update/delete_radius_user`` share the uniform
``(site, [account_id], [payload], *, force)`` shape, so the generic base
applier (APPLY_MAP) dispatches them with no per-feature wiring.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from app.services.adapter_unifi_common import GatewayUniFiServiceBase

_APPLY: dict[tuple[str, str], str] = {
    ("unifi.radius.create_user", "create"): "create_radius_user",
    ("unifi.radius.update_user", "update"): "update_radius_user",
    ("unifi.radius.delete_user", "delete"): "delete_radius_user",
}


class GatewayUniFiRadiusService(GatewayUniFiServiceBase):
    """Live reads + staged writes for UniFi built-in RADIUS users."""

    FEATURE_PREFIX = "unifi.radius."
    APPLY_MAP = _APPLY

    async def list_users(
        self, controller_id: UUID, organization_id: UUID, site: str, *, is_superuser: bool = False
    ) -> dict[str, Any]:
        return await self._read_collection(
            "list_radius_users", controller_id, organization_id, site, is_superuser=is_superuser
        )

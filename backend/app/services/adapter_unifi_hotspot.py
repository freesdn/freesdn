# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""FreeSDN — Gateway UniFi Hotspot service (guest portal: operators + vouchers).

Reads + staged writes for the UniFi guest-portal surface (``unifi.hotspot.*``),
matching the Omada hotspot capability:

  * hotspot OPERATORS — portal-admin accounts (create / delete);
  * guest VOUCHERS    — time/quota-limited access codes (create / revoke).

Operators are id-based and would fit the generic base applier, but vouchers are
NOT: ``create_voucher`` takes keyword args (count / expire / quota / note) and
maps to a ``cmd/hotspot`` command rather than a REST create, and ``revoke``
deletes by ``_id``. So this service overrides ``build_applier`` to dispatch each
feature to the right call shape. Every write rides the staged dual-gate; a
delete/revoke is gated by the central ``enforce_unifi_preflight`` confirm rule.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from fastapi import HTTPException

from app.services.adapter_unifi_common import GatewayUniFiServiceBase


class GatewayUniFiHotspotService(GatewayUniFiServiceBase):
    """Live reads + staged writes for UniFi hotspot operators + guest vouchers."""

    FEATURE_PREFIX = "unifi.hotspot."

    async def list_operators(
        self, controller_id: UUID, organization_id: UUID, site: str, *, is_superuser: bool = False
    ) -> dict[str, Any]:
        return await self._read_collection(
            "list_hotspot_operators",
            controller_id,
            organization_id,
            site,
            is_superuser=is_superuser,
        )

    async def list_vouchers(
        self, controller_id: UUID, organization_id: UUID, site: str, *, is_superuser: bool = False
    ) -> dict[str, Any]:
        return await self._read_collection(
            "list_vouchers", controller_id, organization_id, site, is_superuser=is_superuser
        )

    def build_applier(self, change: Any) -> Any:
        async def _apply(c: Any) -> Any:
            ctrl = await self._resolve_controller_or_gateway(c.controller_id, c.organization_id)
            adapter = await self._get_adapter(ctrl)
            payload = c.payload or {}
            site = payload.get("site") or getattr(adapter, "_default_site", "default")

            if c.feature == "unifi.hotspot.create_operator":
                return await adapter.create_hotspot_operator(site, self._body(payload), force=True)
            if c.feature == "unifi.hotspot.delete_operator":
                if not c.target_id:
                    raise HTTPException(
                        400, detail="delete_operator requires target_id (operator _id)"
                    )
                return await adapter.delete_hotspot_operator(site, c.target_id, force=True)
            if c.feature == "unifi.hotspot.create_voucher":
                # Keyword shape, NOT an id-based payload: count / expire_minutes /
                # quota / note. Defaults mirror the adapter (1 voucher, 60 min, 1 use).
                return await adapter.create_voucher(
                    site,
                    count=int(payload.get("count", 1)),
                    expire_minutes=int(payload.get("expire_minutes", 60)),
                    quota=int(payload.get("quota", 1)),
                    note=payload.get("note"),
                    force=True,
                )
            if c.feature == "unifi.hotspot.revoke_voucher":
                if not c.target_id:
                    raise HTTPException(
                        400, detail="revoke_voucher requires target_id (voucher _id)"
                    )
                return await adapter.revoke_voucher(site, c.target_id, force=True)

            raise HTTPException(400, detail=f"unhandled feature={c.feature!r}")

        return _apply

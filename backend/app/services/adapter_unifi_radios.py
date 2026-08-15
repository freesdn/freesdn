# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""FreeSDN — Gateway UniFi Radios service (AP RF management).

Reads APs + their radio_table; stages per-radio tuning (channel / tx-power /
band-width) via ``unifi.radios.update`` (target_id = device mac, payload.radio
picks the band). update_radio is device-targeted, so this overrides the base
applier rather than using the generic id-based create/update/delete dispatch.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from fastapi import HTTPException

from app.services.adapter_unifi_common import GatewayUniFiServiceBase

_RADIO_FIELDS = ("channel", "tx_power_mode", "tx_power", "ht")


class GatewayUniFiRadiosService(GatewayUniFiServiceBase):
    """Live reads + staged per-radio tuning for UniFi APs."""

    FEATURE_PREFIX = "unifi.radios."

    async def list_radios(
        self, controller_id: UUID, organization_id: UUID, site: str, *, is_superuser: bool = False
    ) -> dict[str, Any]:
        return await self._read_collection(
            "list_radios", controller_id, organization_id, site, is_superuser=is_superuser
        )

    def build_applier(self, change: Any) -> Any:
        async def _apply(c: Any) -> Any:
            ctrl = await self._resolve_controller_or_gateway(c.controller_id, c.organization_id)
            adapter = await self._get_adapter(ctrl)
            payload = c.payload or {}
            site = payload.get("site") or getattr(adapter, "_default_site", "default")
            if c.feature != "unifi.radios.update":
                raise HTTPException(400, detail=f"unhandled feature={c.feature!r}")
            mac = c.target_id or payload.get("mac")
            radio = payload.get("radio")
            if not mac or not radio:
                raise HTTPException(
                    400,
                    detail="unifi.radios.update requires target_id (device mac) + payload.radio",
                )
            fields = {k: payload[k] for k in _RADIO_FIELDS if k in payload}
            return await adapter.update_radio(site, mac, radio, force=True, **fields)

        return _apply

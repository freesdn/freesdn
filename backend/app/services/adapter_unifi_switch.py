# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""FreeSDN — Gateway UniFi Switch service (per-port management).

Reads switches + their port_table/port_overrides; stages per-port writes:
advanced settings (STP/storm/op-mode/aggregation/isolation), PoE mode, port
profile, and PoE power-cycle. All are device-targeted (target_id = switch mac,
payload.port_idx picks the port), so a custom applier replaces the base.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from fastapi import HTTPException

from app.services.adapter_unifi_common import (
    GatewayUniFiServiceBase,
    enforce_unifi_site_grant,
)


class GatewayUniFiSwitchService(GatewayUniFiServiceBase):
    """Live reads + staged per-port writes for UniFi switches."""

    FEATURE_PREFIX = "unifi.switch."

    async def list_switches(
        self, controller_id: UUID, organization_id: UUID, site: str, *, is_superuser: bool = False
    ) -> dict[str, Any]:
        return await self._read_collection(
            "list_switches", controller_id, organization_id, site, is_superuser=is_superuser
        )

    async def list_ports(
        self,
        controller_id: UUID,
        organization_id: UUID,
        site: str,
        device_mac: str,
        *,
        is_superuser: bool = False,
    ) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(
            controller_id, organization_id, is_superuser=is_superuser
        )
        enforce_unifi_site_grant(ctrl, site)
        adapter = await self._get_adapter(ctrl)
        data = await adapter.list_switch_ports(site, device_mac)
        return {
            "controller_id": controller_id,
            "site": site,
            "device_mac": device_mac,
            "ports": data,
            "fetched_at": datetime.now(UTC),
        }

    def build_applier(self, change: Any) -> Any:
        async def _apply(c: Any) -> Any:
            ctrl = await self._resolve_controller_or_gateway(c.controller_id, c.organization_id)
            adapter = await self._get_adapter(ctrl)
            payload = c.payload or {}
            site = payload.get("site") or getattr(adapter, "_default_site", "default")
            mac = c.target_id or payload.get("mac")
            if not mac:
                raise HTTPException(400, detail=f"{c.feature} requires target_id (switch mac)")
            port_idx = payload.get("port_idx")
            if port_idx is None:
                raise HTTPException(400, detail=f"{c.feature} requires payload.port_idx")
            port_idx = int(port_idx)

            if c.feature == "unifi.switch.update_port":
                settings = payload.get("settings")
                if not isinstance(settings, dict):
                    settings = {
                        k: v
                        for k, v in payload.items()
                        if k not in {"site", "mac", "port_idx", "settings"}
                    }
                return await adapter.update_switch_port(site, mac, port_idx, settings, force=True)
            if c.feature == "unifi.switch.set_poe":
                poe_mode = payload.get("poe_mode")
                if not poe_mode:
                    raise HTTPException(
                        400, detail="unifi.switch.set_poe requires payload.poe_mode"
                    )
                return await adapter.set_port_poe_on_site(site, mac, port_idx, poe_mode, force=True)
            if c.feature == "unifi.switch.port_profile":
                profile_id = payload.get("profile_id")
                if not profile_id:
                    raise HTTPException(
                        400, detail="unifi.switch.port_profile requires payload.profile_id"
                    )
                return await adapter.update_port_override(
                    site, mac, port_idx, profile_id, force=True
                )
            if c.feature == "unifi.switch.power_cycle":
                return await adapter.power_cycle_port(site, mac, port_idx, force=True)
            raise HTTPException(400, detail=f"unhandled feature={c.feature!r}")

        return _apply

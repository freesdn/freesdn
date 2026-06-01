# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway WiFi advanced service
=======================================================

Read-and-stage for the WLAN-group / SSID advanced knobs (band steering,
802.11r/k/v, WPA3, MU-MIMO, RSSI thresholds), per-SSID MAC filter,
surveillance VLAN, walled garden, voucher templates, 6 GHz radio,
locate-AP.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from fastapi import HTTPException

from app.services.adapter_base import GatewayServiceBase
from app.services.adapter_redaction import redact_list, redact_secrets

# (feature, operation) → client method name
_APPLY: dict[tuple[str, str], str] = {
    # WLAN group advanced
    ("wifi.wlan_group.advanced", "update"): "update_wlan_group_advanced",
    # SSID advanced
    ("wifi.ssid.advanced", "update"): "update_ssid_advanced",
    # SSID MAC filter
    ("wifi.ssid.mac_filter", "update"): "update_ssid_mac_filter",
    # Surveillance VLAN
    ("wifi.surveillance_vlan", "update"): "update_surveillance_vlan_config",
    # Walled garden
    ("wifi.walled_garden", "create"): "create_walled_garden_entry",
    ("wifi.walled_garden", "update"): "update_walled_garden_entry",
    ("wifi.walled_garden", "delete"): "delete_walled_garden_entry",
    # Voucher templates
    ("wifi.voucher_template", "create"): "create_voucher_template",
    ("wifi.voucher_template", "update"): "update_voucher_template",
    ("wifi.voucher_template", "delete"): "delete_voucher_template",
    # 6 GHz radio
    ("wifi.radio_6ghz", "update"): "update_radio_6ghz",
    # Locate AP (cmd, modeled as create-once)
    ("wifi.locate_ap", "create"): "locate_ap",
    # WIDS / WIPS
    ("wifi.wids_wips", "update"): "update_wids_wips_config",
    # Mesh deeper config
    ("wifi.mesh_detail", "update"): "update_mesh_detail_config",
    # Regulatory domain
    ("wifi.regulatory", "update"): "update_regulatory_domain",
    # DFS
    ("wifi.dfs", "update"): "update_dfs_config",
    # Channel-pilot scheduler + force-run
    ("wifi.channel_pilot", "update"): "update_channel_pilot_schedule",
    ("wifi.channel_pilot.run", "create"): "trigger_channel_optimization",
}


# Read-config name → client method (single-site arg)
_READ: dict[str, str] = {
    "wids_wips": "get_wids_wips_config",
    "mesh_detail": "get_mesh_detail_config",
    "regulatory": "get_regulatory_domain",
    "dfs": "get_dfs_config",
    "channel_pilot": "get_channel_pilot_schedule",
}


class GatewayWifiService(GatewayServiceBase):
    """Live reads + staged writes for WiFi advanced features."""

    SUPPORTED_CONTROLLER_TYPE = "omada"

    async def get_wlan_group_advanced(
        self,
        controller_id: UUID,
        organization_id: UUID,
        site_id: UUID,
        wlan_id: str,
    ) -> dict[str, Any]:
        _, client, omada_site_id = await self._resolve_site_context(
            controller_id, organization_id, site_id
        )
        # redact any secret material the vendor echoes on read.
        item = redact_secrets(await client.get_wlan_group_advanced(omada_site_id, wlan_id))
        return {
            "controller_id": controller_id,
            "site_id": site_id,
            "wlan_id": wlan_id,
            "item": item,
            "fetched_at": datetime.now(UTC),
        }

    async def get_ssid_advanced(
        self,
        controller_id: UUID,
        organization_id: UUID,
        site_id: UUID,
        wlan_id: str,
        ssid_id: str,
    ) -> dict[str, Any]:
        _, client, omada_site_id = await self._resolve_site_context(
            controller_id, organization_id, site_id
        )
        # The SSID payload carries pskSetting.securityKey (live WPA PSK).
        # redact_secrets (camelCase-aware) masks it.
        item = redact_secrets(await client.get_ssid_advanced(omada_site_id, wlan_id, ssid_id))
        return {
            "controller_id": controller_id,
            "site_id": site_id,
            "wlan_id": wlan_id,
            "ssid_id": ssid_id,
            "item": item,
            "fetched_at": datetime.now(UTC),
        }

    async def get_surveillance_vlan(
        self, controller_id: UUID, organization_id: UUID, site_id: UUID
    ) -> dict[str, Any]:
        _, client, omada_site_id = await self._resolve_site_context(
            controller_id, organization_id, site_id
        )
        item = redact_secrets(await client.get_surveillance_vlan_config(omada_site_id))
        return {
            "controller_id": controller_id,
            "site_id": site_id,
            "item": item,
            "fetched_at": datetime.now(UTC),
        }

    async def list_walled_garden(
        self,
        controller_id: UUID,
        organization_id: UUID,
        site_id: UUID,
        portal_id: str,
    ) -> dict[str, Any]:
        _, client, omada_site_id = await self._resolve_site_context(
            controller_id, organization_id, site_id
        )
        items = redact_list(await client.list_walled_garden_entries(omada_site_id, portal_id))
        return {
            "controller_id": controller_id,
            "site_id": site_id,
            "portal_id": portal_id,
            "items": items,
            "fetched_at": datetime.now(UTC),
        }

    async def list_voucher_templates(
        self,
        controller_id: UUID,
        organization_id: UUID,
        site_id: UUID,
        portal_id: str,
    ) -> dict[str, Any]:
        _, client, omada_site_id = await self._resolve_site_context(
            controller_id, organization_id, site_id
        )
        items = redact_list(await client.list_voucher_templates(omada_site_id, portal_id))
        return {
            "controller_id": controller_id,
            "site_id": site_id,
            "portal_id": portal_id,
            "items": items,
            "fetched_at": datetime.now(UTC),
        }

    async def get_wifi_config(
        self,
        controller_id: UUID,
        organization_id: UUID,
        site_id: UUID,
        config_name: str,
    ) -> dict[str, Any]:
        method_name = _READ.get(config_name)
        if method_name is None:
            raise HTTPException(
                400,
                detail=(f"unknown wifi config={config_name!r}; expected one of {sorted(_READ)}"),
            )
        _, client, omada_site_id = await self._resolve_site_context(
            controller_id, organization_id, site_id
        )
        item = redact_secrets(await getattr(client, method_name)(omada_site_id))
        return {
            "controller_id": controller_id,
            "site_id": site_id,
            "config_name": config_name,
            "item": item,
            "fetched_at": datetime.now(UTC),
        }

    async def list_wids_wips_events(
        self,
        controller_id: UUID,
        organization_id: UUID,
        site_id: UUID,
        limit: int = 100,
    ) -> dict[str, Any]:
        _, client, omada_site_id = await self._resolve_site_context(
            controller_id, organization_id, site_id
        )
        items = await client.get_wids_wips_events(omada_site_id, limit=limit)
        return {
            "controller_id": controller_id,
            "site_id": site_id,
            "items": items,
            "fetched_at": datetime.now(UTC),
        }

    def build_applier(self, change: Any) -> Any:
        async def _apply(c: Any) -> Any:
            ctrl = await self._get_controller(c.controller_id, c.organization_id)
            client = await self._get_client(ctrl)
            omada_site_id = c.omada_site_id or ""
            payload = c.payload or {}
            target_id = c.target_id

            method_name = _APPLY.get((c.feature, c.operation))
            if method_name is None:
                raise HTTPException(
                    400,
                    detail=(f"no applier for feature={c.feature!r} operation={c.operation!r}"),
                )
            method = getattr(client, method_name)

            # Most WiFi writes need an entity-context arg before payload.
            # We carry that context inside payload itself (e.g.
            # payload.wlan_id, payload.ssid_id, payload.portal_id, payload.mac).
            if c.feature == "wifi.wlan_group.advanced":
                return await method(omada_site_id, payload["wlan_id"], payload["config"])
            if c.feature == "wifi.ssid.advanced":
                return await method(
                    omada_site_id,
                    payload["wlan_id"],
                    payload["ssid_id"],
                    payload["config"],
                )
            if c.feature == "wifi.ssid.mac_filter":
                return await method(
                    omada_site_id,
                    payload["wlan_id"],
                    payload["ssid_id"],
                    payload["config"],
                )
            if c.feature == "wifi.surveillance_vlan":
                return await method(omada_site_id, payload)
            if c.feature == "wifi.walled_garden":
                portal_id = payload["portal_id"]
                cfg = payload.get("config", {})
                if c.operation == "create":
                    return await method(omada_site_id, portal_id, cfg)
                if c.operation == "update":
                    return await method(omada_site_id, portal_id, target_id, cfg)
                if c.operation == "delete":
                    return await method(omada_site_id, portal_id, target_id)
            if c.feature == "wifi.voucher_template":
                portal_id = payload["portal_id"]
                cfg = payload.get("config", {})
                if c.operation == "create":
                    return await method(omada_site_id, portal_id, cfg)
                if c.operation == "update":
                    return await method(omada_site_id, portal_id, target_id, cfg)
                if c.operation == "delete":
                    return await method(omada_site_id, portal_id, target_id)
            if c.feature == "wifi.radio_6ghz":
                return await method(omada_site_id, payload["mac"], payload["config"])
            if c.feature == "wifi.locate_ap":
                return await method(
                    omada_site_id,
                    payload["mac"],
                    duration_seconds=payload.get("duration_seconds", 60),
                )
            if c.feature == "wifi.channel_pilot.run":
                # Force-run takes only the site arg, no payload.
                return await method(omada_site_id)
            # Site-scoped single-payload writes:
            # wids_wips, mesh_detail, regulatory, dfs, channel_pilot.
            if c.feature in (
                "wifi.wids_wips",
                "wifi.mesh_detail",
                "wifi.regulatory",
                "wifi.dfs",
                "wifi.channel_pilot",
            ):
                return await method(omada_site_id, payload)
            raise HTTPException(400, detail=f"unhandled feature={c.feature!r}")

        return _apply

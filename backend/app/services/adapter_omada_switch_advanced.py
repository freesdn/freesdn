# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Switch advanced service: sFlow, multi-session port mirror, LLDP-MED,
QinQ, per-port jumbo, PoE budget, per-switch voice VLAN, MSTP.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from fastapi import HTTPException

from app.services.adapter_base import GatewayServiceBase

_APPLY: dict[tuple[str, str], str] = {
    ("switch.sflow", "update"): "update_switch_sflow_config",
    ("switch.mirror_session", "create"): "create_switch_mirror_session",
    ("switch.mirror_session", "update"): "update_switch_mirror_session",
    ("switch.mirror_session", "delete"): "delete_switch_mirror_session",
    ("switch.lldp_med", "update"): "update_switch_lldp_med_config",
    ("switch.qinq", "update"): "update_switch_qinq_config",
    ("switch.per_port_jumbo", "update"): "update_switch_per_port_jumbo",
    ("switch.poe_budget", "update"): "update_switch_poe_budget",
    ("switch.voice_vlan_per_switch", "update"): "update_switch_voice_vlan_per_switch",
    ("switch.mstp", "update"): "update_switch_mstp_config",
}

_READ_PER_SWITCH: dict[str, str] = {
    "sflow": "get_switch_sflow_config",
    "lldp_med": "get_switch_lldp_med_config",
    "qinq": "get_switch_qinq_config",
    "poe_budget": "get_switch_poe_budget",
    "voice_vlan": "get_switch_voice_vlan_per_switch",
    "mstp": "get_switch_mstp_config",
}


class GatewaySwitchAdvancedService(GatewayServiceBase):
    SUPPORTED_CONTROLLER_TYPE = "omada"

    async def get_switch_config(
        self,
        controller_id: UUID,
        organization_id: UUID,
        site_id: UUID,
        mac: str,
        config_name: str,
    ) -> dict[str, Any]:
        method_name = _READ_PER_SWITCH.get(config_name)
        if method_name is None:
            raise HTTPException(
                400,
                detail=f"unknown config={config_name!r}; expected one of {sorted(_READ_PER_SWITCH)}",
            )
        _, client, omada_site_id = await self._resolve_site_context(
            controller_id, organization_id, site_id
        )
        item = await getattr(client, method_name)(omada_site_id, mac)
        return {
            "controller_id": controller_id,
            "site_id": site_id,
            "mac": mac,
            "config_name": config_name,
            "item": item,
            "fetched_at": datetime.now(UTC),
        }

    async def list_mirror_sessions(
        self,
        controller_id: UUID,
        organization_id: UUID,
        site_id: UUID,
        mac: str,
    ) -> dict[str, Any]:
        _, client, omada_site_id = await self._resolve_site_context(
            controller_id, organization_id, site_id
        )
        items = await client.list_switch_mirror_sessions(omada_site_id, mac)
        return {
            "controller_id": controller_id,
            "site_id": site_id,
            "mac": mac,
            "items": items,
            "fetched_at": datetime.now(UTC),
        }

    async def get_per_port_jumbo(
        self,
        controller_id: UUID,
        organization_id: UUID,
        site_id: UUID,
        mac: str,
        port_id: int,
    ) -> dict[str, Any]:
        _, client, omada_site_id = await self._resolve_site_context(
            controller_id, organization_id, site_id
        )
        item = await client.get_switch_per_port_jumbo(omada_site_id, mac, port_id)
        return {
            "controller_id": controller_id,
            "site_id": site_id,
            "mac": mac,
            "port_id": port_id,
            "item": item,
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
                    detail=f"no applier for {c.feature!r}/{c.operation!r}",
                )
            method = getattr(client, method_name)

            mac = payload["mac"]
            cfg = payload.get("config", {})

            if c.feature == "switch.mirror_session":
                if c.operation == "create":
                    return await method(omada_site_id, mac, cfg)
                if c.operation == "update":
                    return await method(omada_site_id, mac, target_id, cfg)
                if c.operation == "delete":
                    return await method(omada_site_id, mac, target_id)

            if c.feature == "switch.per_port_jumbo":
                return await method(omada_site_id, mac, payload["port_id"], cfg)

            # Plain per-switch updates (sflow, lldp_med, qinq, poe_budget,
            # voice_vlan_per_switch, mstp)
            return await method(omada_site_id, mac, cfg)

        return _apply

# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway OpenWrt service
==================================

Consolidated read service for OpenWrt gateways. Wraps the existing
``OpenWRTAdapter`` (2400 LOC, 114 methods) under the gateway-service
contract so the firewall module's UI can drive it through the same
``/gateway-openwrt-*`` URL family as MikroTik / OPNsense / pfSense.

Scope (this file): read endpoints across the core operational
surface (device info, interfaces, firewall, DHCP, port forwards,
ARP, system info). Staged writes for firewall + port_forward +
source_nat + dhcp.static_host + dns.override shipped in commit
``2e9d8db`` via the per-domain services ``adapter_openwrt_firewall``
and ``adapter_openwrt_dhcp`` — they hook into the same shared apply
pipeline as MikroTik / pfSense / OPNsense. Additional write surfaces
(interfaces, wireguard, openvpn, static routes) remain deferred.

The adapter's ``test_connection()`` previously called
``self._api.disconnect()`` at the end which invalidated every
subsequent read in the same context block. Fixed in the adapter;
service tests now flow uninterrupted.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from fastapi import HTTPException

from app.services.adapter_base import GatewayServiceBase
from app.services.adapter_redaction import redact_secrets


class GatewayOpenWrtService(GatewayServiceBase):
    """Live reads for OpenWrt gateways via ubus JSON-RPC."""

    SUPPORTED_CONTROLLER_TYPE = "openwrt"

    # ── Live reads ───────────────────────────────────────────────────

    async def get_device_info(
        self,
        controller_id: UUID,
        organization_id: UUID,
        *,
        is_superuser: bool = False,
    ) -> dict[str, Any]:
        """Board, system, uptime, memory snapshot.

        Returns ``{controller_id, info, fetched_at}`` where ``info``
        has hostname / model / version / kernel / uptime / memory / load.
        """
        ctrl = await self._resolve_controller_or_gateway(
            controller_id,
            organization_id,
            is_superuser=is_superuser,
        )
        client = await self._get_adapter(ctrl)
        result = await client.get_device_info()
        if not result.success:
            raise HTTPException(502, detail=result.error or "device info failed")
        return {
            "controller_id": controller_id,
            "info": redact_secrets(result.data or {}),
            "fetched_at": datetime.now(UTC),
        }

    async def list_interfaces(
        self,
        controller_id: UUID,
        organization_id: UUID,
        *,
        is_superuser: bool = False,
    ) -> dict[str, Any]:
        """Network interfaces with status + IPs.

        Returns ``{controller_id, items, fetched_at}`` where ``items``
        is a list of ``{name, device, up, ipv4, ipv4_mask, ipv6,
        gateway, ...}`` dicts.
        """
        ctrl = await self._resolve_controller_or_gateway(
            controller_id,
            organization_id,
            is_superuser=is_superuser,
        )
        client = await self._get_adapter(ctrl)
        result = await client.get_interfaces()
        if not result.success:
            raise HTTPException(502, detail=result.error or "list interfaces failed")
        return {
            "controller_id": controller_id,
            "items": [redact_secrets(i) for i in (result.data or [])],
            "fetched_at": datetime.now(UTC),
        }

    async def list_firewall_rules(
        self,
        controller_id: UUID,
        organization_id: UUID,
        *,
        is_superuser: bool = False,
    ) -> dict[str, Any]:
        """Firewall rules from UCI ``firewall.rule`` sections.

        Returns ``{controller_id, items, fetched_at}``. Items carry
        the UCI section name as ``uci_name`` — that's the handle
        for any later update/delete operation.
        """
        ctrl = await self._resolve_controller_or_gateway(
            controller_id,
            organization_id,
            is_superuser=is_superuser,
        )
        client = await self._get_adapter(ctrl)
        result = await client.get_firewall_rules()
        if not result.success:
            raise HTTPException(502, detail=result.error or "list firewall rules failed")
        data = result.data or {}
        rules = data.get("rules", []) if isinstance(data, dict) else data
        return {
            "controller_id": controller_id,
            "items": [redact_secrets(i) for i in (rules if isinstance(rules, list) else [])],
            "count": data.get("count", 0) if isinstance(data, dict) else 0,
            "fetched_at": datetime.now(UTC),
        }

    async def list_port_forwards(
        self,
        controller_id: UUID,
        organization_id: UUID,
        *,
        is_superuser: bool = False,
    ) -> dict[str, Any]:
        """Port forwards (UCI ``firewall.redirect`` sections)."""
        ctrl = await self._resolve_controller_or_gateway(
            controller_id,
            organization_id,
            is_superuser=is_superuser,
        )
        client = await self._get_adapter(ctrl)
        result = await client.get_port_forwards()
        if not result.success:
            raise HTTPException(502, detail=result.error or "list port forwards failed")
        data = result.data or {}
        forwards = data.get("port_forwards", []) if isinstance(data, dict) else data
        return {
            "controller_id": controller_id,
            "items": [redact_secrets(i) for i in (forwards if isinstance(forwards, list) else [])],
            "count": data.get("count", 0) if isinstance(data, dict) else 0,
            "fetched_at": datetime.now(UTC),
        }

    async def list_dhcp_leases(
        self,
        controller_id: UUID,
        organization_id: UUID,
        *,
        is_superuser: bool = False,
    ) -> dict[str, Any]:
        """Active DHCP leases (IPv4 + IPv6) via ``luci-rpc.getDHCPLeases``.

        Note: ``dhcp.ipv4leases`` returns "Access denied" on OpenWrt
        24.10+ via ubus RPC. The LuCI RPC package wraps the lease
        read with proper ACLs. Adapter handles the fallback.
        """
        ctrl = await self._resolve_controller_or_gateway(
            controller_id,
            organization_id,
            is_superuser=is_superuser,
        )
        client = await self._get_adapter(ctrl)
        result = await client.get_dhcp_leases()
        if not result.success:
            raise HTTPException(502, detail=result.error or "list DHCP leases failed")
        data = result.data or {}
        leases = data.get("leases", []) if isinstance(data, dict) else data
        return {
            "controller_id": controller_id,
            "items": leases if isinstance(leases, list) else [],
            "count": data.get("count", 0) if isinstance(data, dict) else 0,
            "fetched_at": datetime.now(UTC),
        }

    async def list_dhcp_static_mappings(
        self,
        controller_id: UUID,
        organization_id: UUID,
        *,
        is_superuser: bool = False,
    ) -> dict[str, Any]:
        """Static DHCP mappings (reservations)."""
        ctrl = await self._resolve_controller_or_gateway(
            controller_id,
            organization_id,
            is_superuser=is_superuser,
        )
        client = await self._get_adapter(ctrl)
        result = await client.get_dhcp_static_mappings()
        if not result.success:
            raise HTTPException(502, detail=result.error or "list DHCP static mappings failed")
        data = result.data or {}
        mappings = data.get("static_mappings", []) if isinstance(data, dict) else data
        return {
            "controller_id": controller_id,
            "items": [redact_secrets(i) for i in (mappings if isinstance(mappings, list) else [])],
            "count": data.get("count", 0) if isinstance(data, dict) else 0,
            "fetched_at": datetime.now(UTC),
        }

    async def list_arp_table(
        self,
        controller_id: UUID,
        organization_id: UUID,
        *,
        is_superuser: bool = False,
    ) -> dict[str, Any]:
        """Neighbor / ARP table — what MAC/IP pairs the router has seen."""
        ctrl = await self._resolve_controller_or_gateway(
            controller_id,
            organization_id,
            is_superuser=is_superuser,
        )
        client = await self._get_adapter(ctrl)
        result = await client.get_arp_table()
        if not result.success:
            raise HTTPException(502, detail=result.error or "list ARP table failed")
        data = result.data or {}
        entries = data.get("entries", []) if isinstance(data, dict) else data
        return {
            "controller_id": controller_id,
            "items": [redact_secrets(i) for i in (entries if isinstance(entries, list) else [])],
            "count": data.get("count", 0) if isinstance(data, dict) else 0,
            "fetched_at": datetime.now(UTC),
        }

    async def get_summary(
        self,
        controller_id: UUID,
        organization_id: UUID,
        *,
        is_superuser: bool = False,
    ) -> dict[str, Any]:
        """One-shot rollup: device info + interface count + rule count etc.

        Designed for the dashboard card so the UI gets everything it
        needs to render the gateway tile in one request.
        """
        ctrl = await self._resolve_controller_or_gateway(
            controller_id,
            organization_id,
            is_superuser=is_superuser,
        )
        client = await self._get_adapter(ctrl)
        result = await client.get_device_summary()
        if not result.success:
            raise HTTPException(502, detail=result.error or "summary failed")
        return {
            "controller_id": controller_id,
            "summary": redact_secrets(result.data or {}),
            "fetched_at": datetime.now(UTC),
        }

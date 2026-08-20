# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway Sync Service
====================================

Periodic data synchronisation from brain devices.
Refreshes the imported-cache tables (firewall rules, NAT,
VPN, IDS, DHCP leases, interfaces) without modifying anything
on the device.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.events import Event, EventCategory, get_event_bus
from app.modules.firewall.models import (
    GatewayConnection,
    GatewaySyncLog,
    GatewaySyncStatus,
)
from app.modules.gateway.adapter_helpers import build_adapter
from app.modules.gateway.models import (
    ImportedDHCPLease,
    ImportedFirewallRule,
    ImportedInterface,
    ImportedNATRule,
    ImportedVPNTunnel,
)

logger = logging.getLogger(__name__)


def _normalize_vpn_tunnels(data: Any) -> list[dict[str, Any]]:
    """Flatten a vendor's ``get_vpn_status`` payload into tunnel dicts.

    This used to be ``data.get("tunnels", [])``, and NO supported brain
    firewall returns a top-level ``tunnels`` list:

      OPNsense  {"wireguard": {...}, "openvpn": {...}, "ipsec": ...}
      pfSense   {"openvpn": ..., "wireguard": {"tunnels": [...], ...}, ...}
      MikroTik  {"ipsec": {...}, "wireguard": {...}, "l2tp": ..., "pptp": ...}
      OpenWrt   {"tunnels": {"wireguard": [...], "openvpn": [...]}}

    So three vendors yielded ``[]`` and the Gateway VPN Tunnels table stayed
    permanently empty, while OpenWrt yielded a DICT -- truthy, so it reached
    ``_upsert_vpn_tunnels``, whose ``for t in tunnels`` then iterated the KEYS
    and produced rows from the strings "wireguard" and "openvpn" before failing
    into the except above. Either way nobody ever saw a tunnel.

    Deliberately conservative: this walks the shapes those four adapters
    actually return and tags each tunnel with the protocol it came from. It
    does not try to guess at unknown shapes -- an unrecognised payload yields
    nothing, which is the same as today rather than a table of garbage.
    """
    if not isinstance(data, dict):
        return []

    out: list[dict[str, Any]] = []

    def _add(items: Any, vpn_type: str) -> None:
        if isinstance(items, dict):
            # A mapping of name -> tunnel, or a single tunnel object.
            items = list(items.values()) if all(isinstance(v, dict) for v in items.values()) else []
        if not isinstance(items, list):
            return
        for item in items:
            if not isinstance(item, dict):
                continue
            out.append({**item, "type": item.get("type") or vpn_type})

    # OpenWrt nests everything under "tunnels"; the others are top-level.
    root = data.get("tunnels") if isinstance(data.get("tunnels"), dict) else data

    for vpn_type in ("wireguard", "openvpn", "ipsec", "l2tp", "pptp"):
        section = root.get(vpn_type)
        if section is None:
            continue
        if isinstance(section, list):
            _add(section, vpn_type)
        elif isinstance(section, dict):
            # pfSense: {"tunnels": [...]}; OPNsense: {"status": ..., "peers": [...]};
            # MikroTik: {"interfaces": [...], "peers": [...]}.
            for key in ("tunnels", "interfaces", "instances", "providers", "peers", "status"):
                if key in section:
                    _add(section[key], vpn_type)

    return out


class SyncService:
    """Refreshes imported-cache tables from brain devices."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def sync_gateway(
        self,
        gateway_id: UUID,
        *,
        org_id: UUID | None = None,
    ) -> dict[str, Any]:
        """Full sync of read-only data from a single gateway device.

        When called from an API endpoint, pass org_id to scope the query.
        Background tasks may omit org_id for internal sync operations.
        """
        q = select(GatewayConnection).where(
            GatewayConnection.id == gateway_id,
            GatewayConnection.deleted_at.is_(None),
        )
        if org_id is not None:
            q = q.where(GatewayConnection.org_id == org_id)
        result = await self.db.execute(q)
        gw = result.scalar_one_or_none()
        if gw is None:
            logger.warning("Gateway %s not found for sync", gateway_id)
            return {"status": "not_found"}

        if not gw.sync_enabled:
            return {"status": "sync_disabled"}

        adapter = build_adapter(gw)
        t0 = datetime.now(UTC)
        synced: dict[str, int] = {}

        try:
            async with adapter:
                # Resilience (audit): every _upsert_* below does a
                # delete-all-then-insert "replace". A device that is reachable
                # but momentarily returns an EMPTY list (a fetch glitch, an
                # oversize-config fallback, an MVC plugin hiccup) would otherwise
                # WIPE the configured device's imported rules/NAT/VPN/interfaces/
                # leases to zero — a dangerously misleading view of a security
                # device until the next good sync. So SKIP the replace whenever
                # the incoming list is empty; keep the last-known data instead.
                # A genuinely-emptied set self-corrects on the next non-empty
                # sync (or a manual re-import).

                # Sync firewall rules
                try:
                    fw_result = await adapter.get_firewall_rules()
                    rules = (
                        fw_result.data.get("rules", [])
                        if (fw_result.success and fw_result.data)
                        else []
                    )
                    if rules:
                        synced["firewall_rules"] = await self._upsert_firewall_rules(gw, rules)
                except Exception as exc:
                    logger.warning("Failed to sync firewall rules: %s", exc)

                # Sync NAT rules
                try:
                    nat_result = await adapter.get_nat_rules()
                    nat = (
                        nat_result.data.get("rules", [])
                        if (nat_result.success and nat_result.data)
                        else []
                    )
                    if nat:
                        synced["nat_rules"] = await self._upsert_nat_rules(gw, nat)
                except Exception as exc:
                    logger.warning("Failed to sync NAT rules: %s", exc)

                # Sync VPN tunnels
                try:
                    vpn_result = await adapter.get_vpn_status()
                    tunnels = _normalize_vpn_tunnels(
                        vpn_result.data if (vpn_result.success and vpn_result.data) else None
                    )
                    if tunnels:
                        synced["vpn_tunnels"] = await self._upsert_vpn_tunnels(gw, tunnels)
                except Exception as exc:
                    logger.warning("Failed to sync VPN tunnels: %s", exc)

                # Sync interfaces
                try:
                    iface_result = await adapter.get_interfaces()
                    ifaces = (
                        iface_result.data.get("interfaces", [])
                        if (iface_result.success and iface_result.data)
                        else []
                    )
                    if ifaces:
                        synced["interfaces"] = await self._upsert_interfaces(gw, ifaces)
                except Exception as exc:
                    logger.warning("Failed to sync interfaces: %s", exc)

                # Sync DHCP leases
                try:
                    dhcp_result = await adapter.get_dhcp_leases()
                    leases = (
                        dhcp_result.data.get("leases", [])
                        if (dhcp_result.success and dhcp_result.data)
                        else []
                    )
                    if leases:
                        synced["dhcp_leases"] = await self._upsert_dhcp_leases(gw, leases)
                except Exception as exc:
                    logger.warning("Failed to sync DHCP leases: %s", exc)

            # Update gateway sync state
            gw.sync_status = GatewaySyncStatus.SUCCESS
            gw.last_sync_at = datetime.now(UTC)
            gw.last_sync_error = None
            elapsed = int((datetime.now(UTC) - t0).total_seconds() * 1000)
            gw.last_sync_duration_ms = elapsed
            gw.is_online = True
            gw.last_seen_at = datetime.now(UTC)

            # Write sync log
            self.db.add(
                GatewaySyncLog(
                    gateway_id=gw.id,
                    started_at=t0,
                    finished_at=datetime.now(UTC),
                    duration_ms=elapsed,
                    status="success",
                    items_synced=synced,
                    error_message=None,
                )
            )
            await self.db.flush()
            # Emit sync-complete event so drift detection can run
            try:
                bus = get_event_bus()
                await bus.publish(
                    Event(
                        event_type="gateway.sync.completed",
                        category=EventCategory.SYSTEM,
                        source="gateway.sync_service",
                        payload={
                            "gateway_id": str(gateway_id),
                            "site_id": str(gw.site_id) if gw.site_id else None,
                            "synced": synced,
                            "duration_ms": elapsed,
                        },
                    )
                )
            except Exception:
                logger.debug("Failed to emit sync event", exc_info=True)
            return {"status": "success", "synced": synced}

        except Exception as exc:
            logger.error("Gateway sync failed for %s: %s", gateway_id, exc)
            gw.sync_status = GatewaySyncStatus.FAILED
            gw.last_sync_error = str(exc)[:500]
            await self.db.flush()
            return {"status": "failed", "error": f"Sync failed ({type(exc).__name__})"}

    # ── Upsert Helpers ───────────────────────────────────────────────────

    async def _upsert_firewall_rules(
        self, gw: GatewayConnection, rules: list[dict[str, Any]]
    ) -> int:
        """Replace-all approach: delete existing, insert fresh."""
        now = datetime.now(UTC)
        await self.db.execute(
            delete(ImportedFirewallRule).where(
                ImportedFirewallRule.device_id == gw.id,
            )
        )
        for idx, r in enumerate(rules):
            row = ImportedFirewallRule(
                organization_id=gw.org_id,
                site_id=gw.site_id,
                device_id=gw.id,
                external_id=r.get("uuid", r.get("id", str(idx))),
                name=r.get("description", r.get("name", f"rule-{idx}")),
                description=r.get("description"),
                rule_index=idx,
                direction=r.get("direction", "in"),
                action=r.get("action", "pass"),
                protocol=r.get("protocol", "any"),
                source=r.get("source", {}),
                destination=r.get("destination", {}),
                is_enabled=r.get("enabled", True),
                hit_count=r.get("evaluations", 0),
                last_synced_at=now,
                raw_data=r,
            )
            self.db.add(row)
        await self.db.flush()
        return len(rules)

    async def _upsert_nat_rules(self, gw: GatewayConnection, rules: list[dict[str, Any]]) -> int:
        now = datetime.now(UTC)
        await self.db.execute(delete(ImportedNATRule).where(ImportedNATRule.device_id == gw.id))
        for r in rules:
            row = ImportedNATRule(
                organization_id=gw.org_id,
                site_id=gw.site_id,
                device_id=gw.id,
                external_id=r.get("uuid", r.get("id", "")),
                name=r.get("description", ""),
                nat_type=r.get("type", "dnat"),
                source=r.get("source", {}),
                destination=r.get("destination", {}),
                translation=r.get("target", {}),
                is_enabled=r.get("enabled", True),
                last_synced_at=now,
                raw_data=r,
            )
            self.db.add(row)
        await self.db.flush()
        return len(rules)

    async def _upsert_vpn_tunnels(
        self, gw: GatewayConnection, tunnels: list[dict[str, Any]]
    ) -> int:
        now = datetime.now(UTC)
        await self.db.execute(delete(ImportedVPNTunnel).where(ImportedVPNTunnel.device_id == gw.id))
        for t in tunnels:
            row = ImportedVPNTunnel(
                organization_id=gw.org_id,
                site_id=gw.site_id,
                device_id=gw.id,
                external_id=t.get("uuid", t.get("id", "")),
                name=t.get("description", t.get("name", "")),
                vpn_type=t.get("type", "ipsec"),
                status=t.get("status", "down"),
                local_config=t.get("local", {}),
                remote_config=t.get("remote", {}),
                stats=t.get("stats", {}),
                last_synced_at=now,
                raw_data=t,
            )
            self.db.add(row)
        await self.db.flush()
        return len(tunnels)

    async def _upsert_interfaces(
        self, gw: GatewayConnection, interfaces: list[dict[str, Any]]
    ) -> int:
        now = datetime.now(UTC)
        await self.db.execute(delete(ImportedInterface).where(ImportedInterface.device_id == gw.id))
        for iface in interfaces:
            row = ImportedInterface(
                organization_id=gw.org_id,
                site_id=gw.site_id,
                device_id=gw.id,
                external_id=iface.get("identifier", iface.get("if", "")),
                name=iface.get("description", iface.get("name", "")),
                description=iface.get("description"),
                if_type=iface.get("type"),
                mac_address=iface.get("macaddr"),
                mtu=iface.get("mtu"),
                is_enabled=iface.get("enabled", True),
                is_up=iface.get("status", "") == "up",
                ipv4_address=iface.get("ipaddr"),
                ipv4_subnet=iface.get("subnet"),
                vlan_tag=iface.get("vlan"),
                parent_interface=iface.get("if"),
                stats=iface.get("statistics", {}),
                last_synced_at=now,
                raw_data=iface,
            )
            self.db.add(row)
        await self.db.flush()
        return len(interfaces)

    async def _upsert_dhcp_leases(self, gw: GatewayConnection, leases: list[dict[str, Any]]) -> int:
        now = datetime.now(UTC)
        await self.db.execute(delete(ImportedDHCPLease).where(ImportedDHCPLease.device_id == gw.id))
        for l in leases:
            row = ImportedDHCPLease(
                organization_id=gw.org_id,
                site_id=gw.site_id,
                device_id=gw.id,
                ip_address=l.get("address", ""),
                mac_address=l.get("mac", ""),
                hostname=l.get("hostname"),
                interface=l.get("if"),
                status=l.get("state", l.get("binding_state")),
                starts=l.get("starts"),
                ends=l.get("ends"),
                last_synced_at=now,
            )
            self.db.add(row)
        await self.db.flush()
        return len(leases)

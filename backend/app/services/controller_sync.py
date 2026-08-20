# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Controller Deep Sync Service
==========================================

After device discovery, this service performs a *deep sync* that imports
the full operational state of a controller into FreeSDN:

  • Switch ports  → DevicePort records
  • VLANs / Networks  → Network records
  • WiFi / SSIDs  → WifiNetwork records
  • Port profiles  → PortProfile records
  • LAG groups  → LinkAggregationGroup records
  • Topology links  → TopologyLink records
  • Clients  → DeviceClient records

Each sync method is idempotent: it upserts by ``external_id`` so
repeated runs converge to the controller's current state.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.base import AdapterResult
from app.models.core import Controller
from app.models.devices import (
    Device,
    DeviceClient,
    DevicePort,
    DeviceStatus,
    DeviceType,
    PortStatus,
    PortType,
)
from app.modules.network.models import (
    LinkAggregationGroup,
    Network,
    PortProfile,
    TopologyLink,
    WifiNetwork,
)

logger = logging.getLogger(__name__)

# deep_sync_controller runs every 5 min (celery beat) and writes
# the FULL device-controlled entity lists straight into DB rows. A compromised/
# brownfield controller could return millions of ports/networks/clients → row
# flood + unbounded JSONB blobs. Cap each list and validate each metadata blob
# the same way the sibling device_sync already guards plugin ingestion. Caps are
# generous vs. real hardware (a stack tops out well under these).
from app.services.device_sync import _validate_metadata  # noqa: E402

_MAX_PORTS = 4096
_MAX_NETWORKS = 4096
_MAX_SSIDS = 512
_MAX_PORT_PROFILES = 4096
_MAX_LAGS = 256
_MAX_CLIENTS = 10_000


def _cap(items: list[Any], limit: int, what: str) -> list[Any]:
    """Bound a device-reported list before it becomes DB rows."""
    if items is not None and len(items) > limit:
        logger.warning(
            "controller-sync: %s list of %d exceeds cap %d — truncating", what, len(items), limit
        )
        return items[:limit]
    return items


def _safe_meta(raw: Any) -> dict[str, Any]:
    """Validate a device-reported JSONB blob (size/depth) before persisting,
    nulling to {} on rejection — mirrors device_sync."""
    return _validate_metadata(raw) or {}


def _unwrap(result: Any, fallback: Any = None) -> Any:
    """Unwrap an AdapterResult to its .data, or return raw non-AdapterResult values."""
    if isinstance(result, AdapterResult):
        return result.data if result.success else fallback
    return result


# =====================================================================
# Main orchestrator
# =====================================================================


async def deep_sync_controller(
    session: AsyncSession,
    adapter: Any,  # BaseAdapter (connected)
    controller: Controller,
    site_id: UUID,
    *,
    sync_ports: bool = True,
    sync_networks: bool = True,
    sync_wifi: bool = True,
    sync_profiles: bool = True,
    sync_lags: bool = True,
    sync_topology: bool = True,
    sync_clients: bool = True,
) -> dict[str, Any]:
    """
    Perform a full deep sync for a controller + site.

    ``adapter`` must already be connected (inside ``async with adapter:``).
    Returns a summary dict.
    """
    summary: dict[str, Any] = {
        "controller_id": str(controller.id),
        "site_id": str(site_id),
    }

    # Build device lookup  mac → Device  for this controller
    result = await session.execute(
        select(Device).where(
            Device.controller_id == controller.id,
            Device.deleted_at.is_(None),
        )
    )
    devices = result.scalars().all()
    mac_to_device: dict[str, Device] = {}
    for d in devices:
        if d.mac_address:
            key = d.mac_address.upper().replace("-", ":").replace(".", ":")
            mac_to_device[key] = d
            # Also store raw uppercase key for exact match
            raw_key = d.mac_address.upper()
            if raw_key != key:
                mac_to_device[raw_key] = d

    # --- Switch Ports -----------------------------------------------
    if sync_ports:
        try:
            async with session.begin_nested():
                summary["ports"] = await _sync_switch_ports(
                    session,
                    adapter,
                    controller,
                    mac_to_device,
                )
        except Exception:
            logger.exception("Deep sync ports failed")
            summary["ports"] = {"error": True}

    # --- VLANs / Networks -------------------------------------------
    if sync_networks:
        try:
            async with session.begin_nested():
                summary["networks"] = await _sync_networks(
                    session,
                    adapter,
                    controller,
                    site_id,
                )
        except Exception:
            logger.exception("Deep sync networks failed")
            summary["networks"] = {"error": True}

    # --- WiFi / SSIDs -----------------------------------------------
    if sync_wifi:
        try:
            async with session.begin_nested():
                summary["wifi"] = await _sync_wifi_networks(
                    session,
                    adapter,
                    controller,
                    site_id,
                )
        except Exception:
            logger.exception("Deep sync WiFi failed")
            summary["wifi"] = {"error": True}

    # --- Port Profiles ----------------------------------------------
    if sync_profiles:
        try:
            async with session.begin_nested():
                summary["profiles"] = await _sync_port_profiles(
                    session,
                    adapter,
                    controller,
                    site_id,
                )
        except Exception:
            logger.exception("Deep sync port profiles failed")
            summary["profiles"] = {"error": True}

    # --- LAG Groups -------------------------------------------------
    if sync_lags:
        try:
            async with session.begin_nested():
                summary["lags"] = await _sync_lag_groups(
                    session,
                    adapter,
                    controller,
                    mac_to_device,
                )
        except Exception:
            logger.exception("Deep sync LAGs failed")
            summary["lags"] = {"error": True}

    # --- Topology ---------------------------------------------------
    if sync_topology:
        try:
            async with session.begin_nested():
                summary["topology"] = await _sync_topology(
                    session,
                    adapter,
                    controller,
                    mac_to_device,
                )
        except Exception:
            logger.exception("Deep sync topology failed")
            summary["topology"] = {"error": True}

    # --- Clients ----------------------------------------------------
    if sync_clients:
        try:
            async with session.begin_nested():
                summary["clients"] = await _sync_clients(
                    session,
                    adapter,
                    controller,
                    mac_to_device,
                )
        except Exception:
            logger.exception("Deep sync clients failed")
            summary["clients"] = {"error": True}

    # --- Device Details (PoE budget, radio config, temperature) -----
    try:
        async with session.begin_nested():
            summary["device_details"] = await _sync_device_details(
                session,
                adapter,
                controller,
                mac_to_device,
            )
    except Exception:
        logger.exception("Deep sync device details failed")
        summary["device_details"] = {"error": True}

    # --- Controller Metadata (CPU, memory, version, counts) ---------
    try:
        summary["controller_meta"] = await _sync_controller_metadata(
            session,
            adapter,
            controller,
        )
    except Exception:
        logger.exception("Deep sync controller metadata failed")
        summary["controller_meta"] = {"error": True}

    # --- Firmware Status (per device) --------------------------------
    try:
        async with session.begin_nested():
            summary["firmware"] = await _sync_firmware_status(
                session,
                adapter,
                controller,
                mac_to_device,
            )
    except Exception:
        logger.exception("Deep sync firmware status failed")
        summary["firmware"] = {"error": True}

    await session.commit()
    return summary


# =====================================================================
# Switch Ports
# =====================================================================


async def _sync_switch_ports(
    session: AsyncSession,
    adapter: Any,
    controller: Controller,
    mac_to_device: dict[str, Device],
) -> dict[str, Any]:
    """Sync ports for every switch managed by this controller."""
    total_synced = 0
    devices_synced = 0

    switches = [d for d in mac_to_device.values() if d.device_type == DeviceType.SWITCH]

    # Batch-load all existing ports for all switches (avoid N+1)
    switch_ids = [d.id for d in switches]
    all_ports_map: dict[Any, dict[int, DevicePort]] = {}
    if switch_ids:
        all_ports_result = await session.execute(
            select(DevicePort).where(
                DevicePort.device_id.in_(switch_ids),
            )
        )
        for p in all_ports_result.scalars().all():
            all_ports_map.setdefault(p.device_id, {})[p.port_number] = p

    # Fetch all switch ports concurrently (adapter's internal semaphore
    # controls per-controller rate limiting)
    async def _fetch_ports(dev: Device) -> tuple[Device, list[dict[str, Any]]]:
        try:
            raw = _unwrap(await adapter.get_ports(dev.mac_address), [])
            return (dev, raw or [])
        except Exception:
            logger.warning("Could not fetch ports for %s", dev.name)
            return (dev, [])

    fetch_results = await asyncio.gather(
        *(_fetch_ports(d) for d in switches),
        return_exceptions=True,
    )

    for item in fetch_results:
        if isinstance(item, BaseException):
            logger.error("Port fetch raised exception: %s", item)
            continue
        device: Device = item[0]  # type: ignore[index]
        raw_ports: list[dict[str, Any]] = item[1]  # type: ignore[index]
        if not raw_ports:
            continue

        existing_map = all_ports_map.get(device.id, {})

        for p in _cap(raw_ports, _MAX_PORTS, "ports"):
            port_num = p.get("port") or p.get("port_number") or p.get("index", 0)
            if not port_num:
                continue

            status_str = str(p.get("status", "unknown")).lower()
            port_status = _map_port_status(status_str, p.get("link_up"))

            speed = p.get("speed") or p.get("maxSpeed") or p.get("speed_mbps")
            if isinstance(speed, str):
                try:
                    speed = int(speed.replace("Mbps", "").replace("Gbps", "000").strip())
                except ValueError:
                    speed = None

            if port_num in existing_map:
                dp = existing_map[port_num]
            else:
                dp = DevicePort(device_id=device.id, port_number=port_num)
                session.add(dp)

            dp.name = p.get("name") or p.get("label") or f"Port {port_num}"
            dp.port_type = _map_port_type(p)
            dp.status = port_status
            dp.is_enabled = bool(p.get("enabled", True))
            dp.is_poe_enabled = bool(p.get("poe_enabled", False) or p.get("poeEnabled", False))
            _vlan = p.get("native_vlan") or p.get("vlan") or p.get("pvid")
            dp.vlan_id = int(_vlan) if _vlan is not None else None
            dp.speed_mbps = speed
            raw_duplex = p.get("duplex", "auto")
            if isinstance(raw_duplex, int):
                dp.duplex = {0: "auto", 1: "half", 2: "full"}.get(raw_duplex, "auto")
            else:
                dp.duplex = str(raw_duplex) if raw_duplex is not None else "auto"
            dp.poe_power_watts = p.get("poe_power") or p.get("poePower")
            _poe_class = p.get("poe_class") or p.get("poeClass")
            dp.poe_class = int(_poe_class) if _poe_class is not None else None
            dp.tx_bytes = int(p.get("tx_bytes") or p.get("txBytes") or 0)
            dp.rx_bytes = int(p.get("rx_bytes") or p.get("rxBytes") or 0)
            dp.tx_packets = int(p.get("tx_packets") or p.get("txPkts") or 0)
            dp.rx_packets = int(p.get("rx_packets") or p.get("rxPkts") or 0)
            dp.errors = int(p.get("tx_errors", 0) or 0) + int(p.get("rx_errors", 0) or 0)
            _mac = p.get("neighbor_mac") or p.get("lldpNeighborMac")
            dp.connected_mac = str(_mac) if _mac else None
            dp.port_metadata = _safe_meta(p)  # size/depth-validated

            total_synced += 1
        devices_synced += 1

    await session.flush()
    return {"devices_synced": devices_synced, "ports_synced": total_synced}


# =====================================================================
# VLANs / Networks
# =====================================================================


async def _sync_networks(
    session: AsyncSession,
    adapter: Any,
    controller: Controller,
    site_id: UUID,
) -> dict[str, Any]:
    """Import VLANs / networks from the controller."""
    raw_vlans = _unwrap(await adapter.get_vlans(), [])
    if not raw_vlans:
        return {"synced": 0}

    # Index existing
    existing = await session.execute(
        select(Network).where(
            Network.controller_id == controller.id,
            Network.deleted_at.is_(None),
        )
    )
    ext_map: dict[str, Network] = {
        n.external_id: n for n in existing.scalars().all() if n.external_id
    }

    synced = 0
    for v in _cap(raw_vlans, _MAX_NETWORKS, "networks"):
        ext_id = str(v.get("id") or v.get("networkId") or v.get("vlan_id", ""))
        if not ext_id:
            continue

        if ext_id in ext_map:
            net = ext_map[ext_id]
        else:
            net = Network(
                controller_id=controller.id,
                site_id=site_id,
                external_id=ext_id,
            )
            session.add(net)

        net.name = v.get("name") or f"VLAN {v.get('vlan_id', '?')}"
        net.vlan_id = v.get("vlan_id") or v.get("vlan") or v.get("vid") or 0
        net.description = v.get("description") or v.get("purpose")
        net.purpose = v.get("purpose")
        # gatewaySubnet can be "ip/mask" string or {"gateway": ..., "mask": ...} dict
        gw_subnet = v.get("gatewaySubnet")
        if isinstance(gw_subnet, str) and "/" in gw_subnet:
            net.gateway = gw_subnet.split("/")[0]
            net.subnet = gw_subnet
            net.cidr = gw_subnet
        elif isinstance(gw_subnet, dict):
            net.gateway = gw_subnet.get("gateway") or v.get("gateway")
            net.subnet = v.get("subnet")
        else:
            net.gateway = v.get("gateway")
            net.subnet = v.get("subnet")
        net.subnet_mask = v.get("subnet_mask") or v.get("mask")
        if not net.cidr:
            net.cidr = v.get("cidr")
        # dhcpSettings can be a dict with "enable" key
        dhcp_settings = v.get("dhcpSettings")
        if isinstance(dhcp_settings, dict):
            net.dhcp_enabled = bool(dhcp_settings.get("enable", False))
            ip_ranges = dhcp_settings.get("ipRangePool", [])
            if ip_ranges and isinstance(ip_ranges, list) and isinstance(ip_ranges[0], dict):
                net.dhcp_start = ip_ranges[0].get("start")
                net.dhcp_end = ip_ranges[0].get("end")
        else:
            net.dhcp_enabled = bool(v.get("dhcp_enabled") or v.get("dhcpEnable"))
            net.dhcp_start = v.get("dhcp_start") or (
                v.get("dhcpRange", {}).get("start")
                if isinstance(v.get("dhcpRange"), dict)
                else None
            )
            net.dhcp_end = v.get("dhcp_end") or (
                v.get("dhcpRange", {}).get("end") if isinstance(v.get("dhcpRange"), dict) else None
            )
        net.domain = v.get("domain")
        net.network_metadata = _safe_meta(v)
        synced += 1

    await session.flush()
    return {"synced": synced}


# =====================================================================
# WiFi / SSIDs
# =====================================================================


async def _sync_wifi_networks(
    session: AsyncSession,
    adapter: Any,
    controller: Controller,
    site_id: UUID,
) -> dict[str, Any]:
    """Import SSIDs from the controller."""
    raw_ssids = _unwrap(await adapter.get_ssids(), [])
    if not raw_ssids:
        return {"synced": 0}

    existing = await session.execute(
        select(WifiNetwork).where(
            WifiNetwork.controller_id == controller.id,
            WifiNetwork.deleted_at.is_(None),
        )
    )
    ext_map: dict[str, WifiNetwork] = {
        w.external_id: w for w in existing.scalars().all() if w.external_id
    }

    seen_ext_ids: set[str] = set()
    synced = 0
    for s in _cap(raw_ssids, _MAX_SSIDS, "ssids"):
        ext_id = str(s.get("id") or s.get("ssidId") or s.get("wlanId") or "")
        if not ext_id:
            continue
        seen_ext_ids.add(ext_id)

        if ext_id in ext_map:
            wifi = ext_map[ext_id]
        else:
            wifi = WifiNetwork(
                controller_id=controller.id,
                site_id=site_id,
                external_id=ext_id,
            )
            session.add(wifi)

        wifi.ssid = s.get("name") or s.get("ssid") or "Unnamed"
        wifi.security = (
            s.get("security")
            if isinstance(s.get("security"), str)
            else _map_security(s.get("security") or s.get("wpaMode") or "")
        )
        wifi.band = (
            s.get("band")
            if isinstance(s.get("band"), str)
            and s.get("band") in ("2.4ghz", "5ghz", "both", "all", "6ghz")
            else _map_band(s.get("band") or s.get("radioBand") or "both")
        )
        wifi.vlan_id = s.get("vlan_id") or s.get("vlanId")
        wifi.enabled = (
            s.get("enabled", True) if isinstance(s.get("enabled"), bool) else s.get("enable", True)
        )
        wifi.hidden = s.get("hidden", False) or s.get("broadcast", True) is False
        wifi.client_isolation = bool(s.get("client_isolation") or s.get("clientIsolation"))
        wifi.band_steering = bool(
            s.get("band_steering") or s.get("bandSteering") or s.get("bandSteer")
        )
        wifi.fast_roaming = bool(
            s.get("fast_roaming") or s.get("dot11rEnable") or s.get("enable11r")
        )
        wifi.rate_limit_enabled = bool(s.get("rate_limit_enabled") or s.get("rateLimitEnable"))
        wifi.rate_limit_up = s.get("rate_limit_up")
        wifi.rate_limit_down = s.get("rate_limit_down")

        # Store full metadata including raw Omada data
        meta = dict(s)
        raw_data = meta.pop("_raw", None)
        if raw_data:
            meta["_omada_raw"] = raw_data
        wifi.wifi_metadata = _safe_meta(meta)  # size/depth-validated
        synced += 1

    # Remove stale WiFi networks no longer on the controller
    for ext_id, wifi in ext_map.items():
        if ext_id not in seen_ext_ids:
            from datetime import datetime

            wifi.deleted_at = datetime.now(UTC)

    await session.flush()
    return {"synced": synced}


# =====================================================================
# Port Profiles
# =====================================================================


async def _sync_port_profiles(
    session: AsyncSession,
    adapter: Any,
    controller: Controller,
    site_id: UUID,
) -> dict[str, Any]:
    """Import port profiles from the controller."""
    try:
        raw_profiles = _unwrap(await adapter.get_port_profiles(), [])
    except Exception:
        logger.debug("Adapter does not support get_port_profiles")
        return {"synced": 0}

    if not raw_profiles:
        return {"synced": 0}

    existing = await session.execute(
        select(PortProfile).where(
            PortProfile.controller_id == controller.id,
            PortProfile.deleted_at.is_(None),
        )
    )
    ext_map: dict[str, PortProfile] = {
        p.external_id: p for p in existing.scalars().all() if p.external_id
    }

    synced = 0
    for p in _cap(raw_profiles, _MAX_PORT_PROFILES, "port_profiles"):
        ext_id = str(p.get("id") or p.get("profileId") or "")
        if not ext_id:
            continue

        if ext_id in ext_map:
            prof = ext_map[ext_id]
        else:
            prof = PortProfile(
                controller_id=controller.id,
                site_id=site_id,
                external_id=ext_id,
            )
            session.add(prof)

        prof.name = p.get("name") or "Unnamed"
        prof.description = p.get("description")
        prof.profile_type = p.get("type") or p.get("profileType") or "custom"
        prof.native_vlan = p.get("native_vlan") or p.get("nativeNetworkId")
        tagged = p.get("tagged_vlans") or p.get("taggedNetworkIds")
        if isinstance(tagged, list):
            prof.tagged_vlans = [int(v) for v in tagged if str(v).isdigit()]
        prof.voice_vlan = p.get("voice_vlan") or p.get("voiceNetworkId")
        prof.poe_enabled = p.get("poe_enabled") if isinstance(p.get("poe_enabled"), bool) else None
        prof.stp_enabled = p.get("stp_enabled") if isinstance(p.get("stp_enabled"), bool) else None
        prof.profile_metadata = _safe_meta(p)
        synced += 1

    await session.flush()
    return {"synced": synced}


# =====================================================================
# LAG Groups
# =====================================================================


async def _sync_lag_groups(
    session: AsyncSession,
    adapter: Any,
    controller: Controller,
    mac_to_device: dict[str, Device],
) -> dict[str, Any]:
    """Import LAG groups for each switch."""
    total_synced = 0

    switches = [d for d in mac_to_device.values() if d.device_type == DeviceType.SWITCH]

    # Batch-load all existing LAGs for all switches (avoid N+1)
    switch_ids = [d.id for d in switches]
    all_lags_map: dict[Any, dict[int, LinkAggregationGroup]] = {}
    if switch_ids:
        all_lags_result = await session.execute(
            select(LinkAggregationGroup).where(
                LinkAggregationGroup.device_id.in_(switch_ids),
            )
        )
        for lag_obj in all_lags_result.scalars().all():
            all_lags_map.setdefault(lag_obj.device_id, {})[lag_obj.lag_id] = lag_obj

    for device in switches:
        try:
            raw_lags = _unwrap(await adapter.get_switch_lag_groups(device.mac_address), [])
        except Exception:
            continue

        if not raw_lags:
            continue

        ext_map = all_lags_map.get(device.id, {})

        for lg in _cap(raw_lags, _MAX_LAGS, "lags"):
            lag_id = lg.get("lag_id") or lg.get("lagId") or lg.get("trunkId") or 0
            if not lag_id:
                continue

            if lag_id in ext_map:
                lag = ext_map[lag_id]
            else:
                lag = LinkAggregationGroup(
                    device_id=device.id,
                    lag_id=lag_id,
                )
                session.add(lag)

            lag.name = lg.get("name") or f"LAG {lag_id}"
            lag.external_id = str(lg.get("id") or lg.get("trunkId") or lag_id)
            lag.mode = lg.get("mode") or lg.get("type") or "lacp"
            members = lg.get("member_ports") or lg.get("ports") or lg.get("memberPorts") or []
            lag.member_ports = [int(m) for m in members if str(m).isdigit()]
            lag.lacp_mode = lg.get("lacp_mode") or lg.get("lacpMode") or "active"
            lag.lacp_timeout = lg.get("lacp_timeout") or "long"
            lag.status = lg.get("status") or "up"
            lag.active_ports = lg.get("active_ports") or len(lag.member_ports)
            lag.aggregate_speed = lg.get("aggregate_speed") or 0
            lag.lag_metadata = _safe_meta(lg)
            total_synced += 1

    await session.flush()
    return {"synced": total_synced}


# =====================================================================
# Topology
# =====================================================================


async def _sync_topology(
    session: AsyncSession,
    adapter: Any,
    controller: Controller,
    mac_to_device: dict[str, Device],
) -> dict[str, Any]:
    """
    Build topology links from device uplink / downlink / LLDP data.

    Attempts the enriched ``get_topology_data()`` adapter call first, which
    fetches type-specific detail endpoints (switches/{mac}, eaps/{mac},
    gateways/{mac}) containing the real ``uplink``, ``downlink``, and
    ``lldpNeighbors`` arrays.  Falls back to the legacy metadata-based
    approach when the enriched method is not available.
    """
    links_created = 0
    client_links_created = 0

    # Clear old topology for this controller's devices
    device_ids = [d.id for d in mac_to_device.values()]
    if device_ids:
        await session.execute(
            delete(TopologyLink).where(TopologyLink.source_device_id.in_(device_ids))
        )

    # ------------------------------------------------------------------
    # Try enriched topology (Enterprise upgrade) – falls back gracefully
    # ------------------------------------------------------------------
    enriched_topology: dict[str, Any] | None = None
    if hasattr(adapter, "get_topology_data"):
        try:
            enriched_topology = _unwrap(await adapter.get_topology_data())
        except Exception:
            logger.debug("Enriched topology not available; falling back to legacy")

    if enriched_topology and enriched_topology.get("links"):
        # Use enriched device-to-device links
        for link_data in enriched_topology["links"]:
            src_mac = (link_data.get("source_mac") or "").upper()
            tgt_mac = (link_data.get("target_mac") or "").upper()
            src_device = mac_to_device.get(src_mac)
            tgt_device = mac_to_device.get(tgt_mac)
            if not src_device or not tgt_device or src_device.id == tgt_device.id:
                continue

            link = TopologyLink(
                source_device_id=src_device.id,
                target_device_id=tgt_device.id,
                source_port=link_data.get("source_port"),
                target_port=link_data.get("target_port"),
                status=link_data.get("status", "up"),
                link_type=link_data.get("link_type", "ethernet"),
                discovered_via=link_data.get("discovered_via", "controller"),
            )
            session.add(link)
            links_created += 1

        # Build client → device topology links from enriched client data
        if enriched_topology.get("clients"):
            for cl in enriched_topology["clients"]:
                target_mac = (cl.get("target_device_mac") or "").upper()
                target_device = mac_to_device.get(target_mac)
                if not target_device:
                    continue
                client_mac = (cl.get("client_mac") or "").upper()
                if not client_mac:
                    continue
                # Store client-device link as topology link with special type
                link = TopologyLink(
                    source_device_id=target_device.id,
                    target_device_id=target_device.id,  # self-ref; client has no device row
                    source_port=str(cl.get("target_port")) if cl.get("target_port") else None,
                    target_port=None,
                    status="up",
                    link_type=cl.get("connection_type", "wired"),
                    discovered_via="client_association",
                )
                session.add(link)
                client_links_created += 1

    else:
        # ------------------------------------------------------------------
        # Legacy: derive links from device metadata & LLDP port data
        # ------------------------------------------------------------------
        # Batch-load all ports for LLDP neighbor discovery (avoid N+1)
        all_device_ids = [d.id for d in mac_to_device.values()]
        device_ports_map: dict[Any, list[DevicePort]] = {}
        if all_device_ids:
            _ports_result = await session.execute(
                select(DevicePort).where(
                    DevicePort.device_id.in_(all_device_ids),
                )
            )
            for _p in _ports_result.scalars().all():
                device_ports_map.setdefault(_p.device_id, []).append(_p)

        for device in mac_to_device.values():
            meta = device.device_metadata or {}

            # Common Omada patterns: "uplinkDeviceMac", "downlinkList"
            uplink_mac = (
                meta.get("uplinkDeviceMac")
                or (
                    meta.get("uplink", {}).get("mac")
                    if isinstance(meta.get("uplink"), dict)
                    else None
                )
                or meta.get("uplinkMac")
            )
            uplink_port = meta.get("uplinkPort") or (
                meta.get("uplink", {}).get("port") if isinstance(meta.get("uplink"), dict) else None
            )

            if uplink_mac:
                target = mac_to_device.get(uplink_mac.upper())
                if target and target.id != device.id:
                    link = TopologyLink(
                        source_device_id=device.id,
                        target_device_id=target.id,
                        source_port=str(uplink_port) if uplink_port else None,
                        target_port=None,
                        speed=_guess_speed(meta),
                        status="up" if device.status == DeviceStatus.ONLINE else "down",
                        link_type="trunk" if meta.get("isTrunk") else "ethernet",
                        discovered_via="controller",
                    )
                    session.add(link)
                    links_created += 1

            # Check LLDP neighbour port data stored in port_metadata
            for port in device_ports_map.get(device.id, []):
                nbr_mac = port.connected_mac or (port.port_metadata or {}).get("lldpNeighborMac")
                if nbr_mac:
                    nbr_device = mac_to_device.get(nbr_mac.upper())
                    if nbr_device and nbr_device.id != device.id:
                        # Avoid duplicate (we already created uplink link)
                        if uplink_mac and nbr_mac.upper() == uplink_mac.upper():
                            continue
                        link = TopologyLink(
                            source_device_id=device.id,
                            target_device_id=nbr_device.id,
                            source_port=str(port.port_number),
                            target_port=(port.port_metadata or {}).get("lldpNeighborPort"),
                            status="up",
                            link_type="ethernet",
                            discovered_via="lldp",
                        )
                        session.add(link)
                        links_created += 1

    await session.flush()
    return {
        "links_created": links_created,
        "client_links_created": client_links_created,
        "used_enriched": enriched_topology is not None and bool(enriched_topology.get("links")),
    }


# =====================================================================
# Clients
# =====================================================================


async def _sync_clients(
    session: AsyncSession,
    adapter: Any,
    controller: Controller,
    mac_to_device: dict[str, Device],
) -> dict[str, Any]:
    """Import connected clients from the controller."""
    try:
        raw_clients = _unwrap(await adapter.get_clients(), [])
    except Exception:
        logger.debug("Adapter does not support get_clients")
        return {"synced": 0}

    if not raw_clients:
        return {"synced": 0}

    # Index existing clients by MAC
    device_ids = [d.id for d in mac_to_device.values()]
    existing = (
        await session.execute(select(DeviceClient).where(DeviceClient.device_id.in_(device_ids)))
        if device_ids
        else None
    )
    mac_map: dict[str, DeviceClient] = {}
    if existing:
        mac_map = {c.mac_address.upper(): c for c in existing.scalars().all() if c.mac_address}

    synced = 0
    for c in _cap(raw_clients, _MAX_CLIENTS, "clients"):
        client_mac = (c.get("mac") or c.get("mac_address") or "").upper()
        if not client_mac:
            continue

        # Find the device this client is connected to (wireless via AP or wired via switch)
        # Normalized adapter output uses snake_case: ap_mac, switch_mac
        # Raw Omada uses camelCase: apMac, switchMac, connectDevMac
        connected_dev_mac = (
            (
                c.get("ap_mac")
                or c.get("apMac")
                or c.get("connectDevMac")
                or c.get("switch_mac")
                or c.get("switchMac")
                or ""
            )
            .upper()
            .replace("-", ":")
            .replace(".", ":")
        )
        # Normalize for lookup (mac_to_device keys are already uppercase)
        connected_device = mac_to_device.get(connected_dev_mac)
        if not connected_device:
            # Try without separator normalization (exact match)
            raw_mac = (
                c.get("ap_mac")
                or c.get("apMac")
                or c.get("connectDevMac")
                or c.get("switch_mac")
                or c.get("switchMac")
                or ""
            ).upper()
            connected_device = mac_to_device.get(raw_mac)
        if not connected_device:
            # Skip clients whose connected device is unknown
            continue

        if client_mac in mac_map:
            dc = mac_map[client_mac]
        else:
            dc = DeviceClient(
                device_id=connected_device.id,
                mac_address=client_mac,
            )
            session.add(dc)
            mac_map[client_mac] = dc

        dc.device_id = connected_device.id
        dc.hostname = c.get("hostname") or c.get("name")
        dc.ip_address = c.get("ip") or c.get("ip_address")
        dc.ssid = c.get("ssid") or c.get("ssidName")
        dc.band = c.get("band") or c.get("radioType")
        dc.channel = c.get("channel")
        # Prefer rssi (dBm) over signal (percentage 0-100)
        dc.signal_dbm = c.get("rssi") or c.get("signal_dbm") or c.get("signal")
        dc.noise_dbm = c.get("noise_dbm")
        dc.is_online = c.get("active", True) if isinstance(c.get("active"), bool) else True
        # Traffic — normalized output uses download/upload
        dc.tx_bytes = c.get("upload") or c.get("tx_bytes") or c.get("txBytes", 0)
        dc.rx_bytes = c.get("download") or c.get("rx_bytes") or c.get("rxBytes", 0)
        dc.tx_rate_mbps = _rate_kbps_to_mbps(c.get("tx_rate") or c.get("txRate"))
        dc.rx_rate_mbps = _rate_kbps_to_mbps(c.get("rx_rate") or c.get("rxRate"))
        dc.last_seen = datetime.now(UTC)
        # Merge, do not replace.
        #
        # This was a wholesale ``dc.client_metadata = _safe_meta(c)``, and
        # ``blocked`` is FreeSDN-owned state: ``POST /network/clients/{id}/block``
        # pushes to the controller, checks the AdapterResult, and then records
        # ``client_metadata["blocked"] = True`` here. The controller payload has
        # no such key (only Omada reports one), so the next sync -- minutes
        # later -- overwrote the dict and the flag was gone.
        #
        # The client stayed blocked on the controller, which is the part that
        # matters and always worked. What broke was FreeSDN's memory of it: the
        # Clients page showed the client as normal, the "blocked" filter
        # (``client_metadata["blocked"]`` in modules/network/service.py) matched
        # nothing, and the stats card counted zero blocked clients. An operator
        # looking for who they had blocked found no one.
        incoming = _safe_meta(c)
        merged = dict(dc.client_metadata or {})
        merged.update(incoming)
        # An adapter that genuinely reports block state (Omada does) wins, since
        # the controller is the authority. Otherwise keep what we recorded.
        if "blocked" not in incoming and "blocked" in (dc.client_metadata or {}):
            merged["blocked"] = (dc.client_metadata or {})["blocked"]
        dc.client_metadata = merged
        synced += 1

    await session.flush()
    return {"synced": synced}


# =====================================================================
# Device Details (PoE, radio, temperature, uptime)
# =====================================================================


async def _sync_device_details(
    session: AsyncSession,
    adapter: Any,
    controller: Controller,
    mac_to_device: dict[str, Device],
) -> dict[str, Any]:
    """Fetch per-device details (PoE budget, radio config, etc.) and store in device_metadata."""
    enriched = 0

    # Fetch all device details concurrently (adapter rate-limits internally)
    async def _fetch_detail(mac: str, dev: Device) -> tuple[str, Device, dict[str, Any]]:
        try:
            if dev.device_type == DeviceType.SWITCH:
                return (mac, dev, _unwrap(await adapter.get_switch_detail(mac), {}) or {})
            elif dev.device_type == DeviceType.ACCESS_POINT:
                return (mac, dev, _unwrap(await adapter.get_ap_detail(mac), {}) or {})
            elif dev.device_type in (DeviceType.ROUTER, DeviceType.GATEWAY):
                return (mac, dev, _unwrap(await adapter.get_gateway_detail(mac), {}) or {})
        except Exception:
            logger.debug("Could not fetch detail for %s", dev.name)
        return (mac, dev, {})

    items = [
        (m, d)
        for m, d in mac_to_device.items()
        if d.device_type
        in (DeviceType.SWITCH, DeviceType.ACCESS_POINT, DeviceType.ROUTER, DeviceType.GATEWAY)
    ]
    fetch_results = await asyncio.gather(
        *(_fetch_detail(m, d) for m, d in items),
        return_exceptions=True,
    )

    for item in fetch_results:
        if isinstance(item, BaseException):
            logger.error("Detail fetch raised exception: %s", item)
            continue
        _mac, device, detail = item
        if not detail:
            continue

        # Merge enrichment data into device_metadata
        meta = dict(device.device_metadata or {})

        # Common fields
        for key in (
            "cpu_usage",
            "memory_usage",
            "uptime",
            "firmware_version",
            "hardware_version",
            "serial_number",
            "led_setting",
        ):
            if detail.get(key) is not None:
                meta[key] = detail[key]

        # Switch-specific
        if device.device_type == DeviceType.SWITCH:
            for key in (
                "poe_budget_watts",
                "poe_consumed_watts",
                "poe_remaining_watts",
                "poe_ports",
                "supports_poe",
                "temperature",
                "lldp_enabled",
                "number_of_ports",
                "uplink_device_mac",
                "uplink_device_name",
                "uplink_port",
                "downlinks",
                "ipv6_address",
                "controller_connection_ip",
                "model_version",
                "fan_status",
                "poe_total_power",
                "client_count",
            ):
                if detail.get(key) is not None:
                    meta[key] = detail[key]

        # AP-specific
        elif device.device_type == DeviceType.ACCESS_POINT:
            for key in (
                "radios",
                "mesh_enabled",
                "led_enabled",
                "clients",
                "lan_port_vlan_enabled",
                "lan_port_vlan_id",
                "lan_port_poe_enabled",
            ):
                if detail.get(key) is not None:
                    meta[key] = detail[key]

        # Gateway-specific
        elif device.device_type in (DeviceType.ROUTER, DeviceType.GATEWAY):
            for key in (
                "wan_ports",
                "wan_port_count",
                "lan_port_count",
                "wan_ip",
                "public_ip",
            ):
                if detail.get(key) is not None:
                    meta[key] = detail[key]

        device.device_metadata = meta

        # Also update top-level Device fields from detail data
        if detail.get("uptime") is not None:
            device.uptime_seconds = int(detail["uptime"])
        if detail.get("cpu_usage") is not None:
            device.cpu_usage_percent = float(detail["cpu_usage"])
        if detail.get("memory_usage") is not None:
            device.memory_usage_percent = float(detail["memory_usage"])
        if detail.get("temperature") is not None:
            device.temperature_celsius = float(detail["temperature"])
        if detail.get("firmware_version"):
            device.firmware_version = detail["firmware_version"]
        if detail.get("serial_number"):
            device.serial_number = detail["serial_number"]
        enriched += 1

    await session.flush()
    return {"enriched": enriched}


# =====================================================================
# Controller Metadata (health, version, counts)
# =====================================================================


async def _sync_controller_metadata(
    session: AsyncSession,
    adapter: Any,
    controller: Controller,
) -> dict[str, Any]:
    """Fetch controller-level health and store in controller.config."""
    status_data: dict[str, Any] = {}
    sysinfo_data: dict[str, Any] = {}

    if hasattr(adapter, "get_controller_status"):
        status_data = _unwrap(await adapter.get_controller_status(), {}) or {}
    if hasattr(adapter, "get_system_info"):
        sysinfo_data = _unwrap(await adapter.get_system_info(), {}) or {}

    if not status_data and not sysinfo_data:
        return {"skipped": True}

    runtime = {
        "cpu_util": status_data.get("cpuUtil") or status_data.get("cpu"),
        "mem_util": status_data.get("memUtil") or status_data.get("memory"),
        "disk_util": status_data.get("diskUtil") or status_data.get("disk"),
        "uptime": sysinfo_data.get("uptimeLong") or sysinfo_data.get("uptime"),
        "version": sysinfo_data.get("controllerVer") or sysinfo_data.get("firmwareVersion"),
        "model": sysinfo_data.get("model"),
        "device_count": sysinfo_data.get("deviceAccount") or sysinfo_data.get("deviceCount"),
        "site_count": sysinfo_data.get("siteNum") or sysinfo_data.get("siteCount"),
        "client_count": sysinfo_data.get("clientNum") or sysinfo_data.get("clientCount"),
    }
    # Remove None values
    runtime = {k: v for k, v in runtime.items() if v is not None}

    config = dict(controller.config or {})
    config["runtime_status"] = runtime
    controller.config = config
    await session.flush()
    return {"synced": True, **runtime}


# =====================================================================
# Firmware Status
# =====================================================================


async def _sync_firmware_status(
    session: AsyncSession,
    adapter: Any,
    controller: Controller,
    mac_to_device: dict[str, Device],
) -> dict[str, Any]:
    """Fetch firmware overview and store per-device upgrade status."""
    if not hasattr(adapter, "get_firmware_overview"):
        return {"skipped": True}

    try:
        overview = _unwrap(await adapter.get_firmware_overview())
    except Exception:
        logger.debug("Firmware overview not available")
        return {"skipped": True}

    if not overview:
        return {"skipped": True}

    # overview is a dict with device_firmware list
    fw_list = overview.get("device_firmware") or overview.get("devices") or []
    if not fw_list and isinstance(overview, list):
        fw_list = overview

    updated = 0
    for fw in fw_list:
        mac = (fw.get("mac") or "").upper().replace("-", ":")
        device = mac_to_device.get(mac)
        if not device:
            continue

        meta = dict(device.device_metadata or {})
        meta["firmware"] = {
            "current_version": fw.get("current_version") or fw.get("firmwareVersion"),
            "latest_version": fw.get("latest_version") or fw.get("latestFirmwareVersion"),
            "needs_upgrade": fw.get("needs_upgrade", False),
            "release_date": fw.get("release_date"),
        }
        device.device_metadata = meta
        updated += 1

    await session.flush()
    return {"devices_checked": len(fw_list), "updated": updated}


# =====================================================================
# Helpers
# =====================================================================


def _rate_kbps_to_mbps(val: float | int | None) -> float | None:
    """Convert a rate from Kbit/s (Omada) to Mbit/s for storage."""
    if val is None:
        return None
    return round(val / 1000.0, 2)


def _map_port_status(raw: str, link_up: bool | None = None) -> PortStatus:
    if link_up is True:
        return PortStatus.UP
    if link_up is False:
        return PortStatus.DOWN
    mapping = {
        "up": PortStatus.UP,
        "down": PortStatus.DOWN,
        "disabled": PortStatus.DISABLED,
        "linkup": PortStatus.UP,
        "linkdown": PortStatus.DOWN,
    }
    return mapping.get(raw, PortStatus.UNKNOWN)


def _map_port_type(p: dict[str, Any]) -> PortType:
    raw = str(p.get("type") or p.get("port_type") or p.get("media") or "").lower()
    if "sfp+" in raw or "10g" in raw:
        return PortType.SFP_PLUS
    if "sfp" in raw:
        return PortType.SFP
    if "qsfp" in raw:
        return PortType.QSFP
    return PortType.ETHERNET


def _map_security(raw: str) -> str:
    raw_l = raw.lower().replace("-", "_").replace(" ", "_")
    if "wpa3" in raw_l and "enterprise" in raw_l:
        return "wpa3_enterprise"
    if "wpa3" in raw_l:
        return "wpa3_personal"
    if "wpa2" in raw_l and "wpa3" in raw_l:
        return "wpa2_wpa3_personal"
    if "wpa2" in raw_l and "enterprise" in raw_l:
        return "wpa2_enterprise"
    if "wpa2" in raw_l:
        return "wpa2_personal"
    if "wpa" in raw_l:
        return "wpa_wpa2_personal"
    if "open" in raw_l or "none" in raw_l:
        return "open"
    return raw_l or "wpa2_personal"


def _map_band(raw: str) -> str:
    raw_l = raw.lower().replace(" ", "")
    if "6" in raw_l:
        return "6ghz"
    if "5" in raw_l and "2" in raw_l:
        return "both"
    if "5" in raw_l:
        return "5ghz"
    if "2" in raw_l:
        return "2.4ghz"
    return "both"


def _guess_speed(meta: dict[str, Any]) -> str | None:
    speed = meta.get("uplinkSpeed") or meta.get("linkSpeed")
    if speed:
        return str(speed)
    return None

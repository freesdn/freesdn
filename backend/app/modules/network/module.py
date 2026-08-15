# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN Network Module - Main Module Class
==========================================

The Network module provides core networking functionality for FreeSDN.
This includes VLANs, WiFi networks, PoE management, and switch configuration.
"""

import logging
from typing import Any
from uuid import UUID

from fastapi import APIRouter

from app.modules.base import BaseModule, ModuleCapability
from app.modules.manifest import (
    ModuleDashboardWidget,
    ModuleFeatureFlag,
    ModuleManifest,
    ModuleNavItem,
    ModulePermission,
)

logger = logging.getLogger(__name__)


async def _fabric_client_list_handler(ctx: Any) -> Any:
    """Fabric read handler for ``network.client.list`` — connected clients for
    the org (org-scoped via NetworkClientService.list)."""
    from app.core.fabric.execution import OperationResult

    if ctx.db is None:
        return OperationResult.fail("network.client.list requires a DB session", "NO_DB")
    try:
        from app.modules.network.service import NetworkClientService

        site_id = ctx.params.get("site_id")
        site_uuid = UUID(str(site_id)) if site_id else None
        limit = int(ctx.params.get("limit") or 50)
        clients, total = await NetworkClientService(ctx.db).list(
            ctx.organization_id,
            site_id=site_uuid,
            is_online=ctx.params.get("is_online"),
            limit=max(1, min(limit, 200)),
        )
    except Exception as exc:  # noqa: BLE001
        return OperationResult.fail(f"network.client.list failed: {exc}", "READ_ERROR")

    def _row(c: Any) -> dict[str, Any]:
        return {
            "id": str(getattr(c, "id", "")),
            "hostname": getattr(c, "hostname", None),
            "mac_address": getattr(c, "mac_address", None),
            "ip_address": getattr(c, "ip_address", None),
            "is_online": getattr(c, "is_online", None),
            "connection_type": getattr(c, "connection_type", None),
        }

    return OperationResult.ok(output={"total": total, "clients": [_row(c) for c in clients]})


async def _fabric_overlay_status_handler(ctx: Any) -> Any:
    """Fabric read handler for ``vpn.overlay.status`` — the aggregate VPN/overlay
    connection summary for this controller node (Tailscale/NetBird/WireGuard/
    OpenVPN): per-provider connection counts + state.

    Node-local state — one overlay daemon per appliance, no per-tenant dimension
    — so it needs no DB and ignores ``ctx.organization_id`` (safe in the
    single-tenant-appliance model: it returns only local connection state, not
    peer identities). A safe read; failures normalize to a result, never a 500."""
    from app.core.config import settings
    from app.core.fabric.execution import OperationResult

    # When VPN is off (the default), no overlay daemon is reachable from the api —
    # return immediately rather than invoking the tailscale/netbird CLIs (which
    # block ~10s on connect-retry timeouts). Same guard as discover_overlay_devices.
    if settings.resolved_vpn_mode == "off":
        return OperationResult.ok(
            output={
                "mode": "off",
                "total_connections": 0,
                "connected": 0,
                "disconnected": 0,
                "error": 0,
                "connections": [],
            }
        )
    try:
        from app.services.vpn_integration import VPNManagerService

        summary = await VPNManagerService().get_status_summary()
    except Exception as exc:  # noqa: BLE001 - normalize for the executor
        return OperationResult.fail(f"vpn.overlay.status failed: {exc}", "READ_ERROR")
    summary.setdefault("mode", settings.resolved_vpn_mode)
    return OperationResult.ok(output=summary)


async def _fabric_overlay_peers_handler(ctx: Any) -> Any:
    """Fabric read handler for ``vpn.overlay.peers`` — the adoptable devices found
    on the connected overlay mesh (tailnet/netbird), each classified into a
    suggested adapter type. Node-local discovery (returns [] capless / when VPN is
    off — the off-guard lives in ``discover_overlay_devices``); a safe read."""
    from app.core.fabric.execution import OperationResult

    try:
        from app.services.overlay_discovery import discover_overlay_devices

        peers = await discover_overlay_devices()
    except Exception as exc:  # noqa: BLE001 - normalize for the executor
        return OperationResult.fail(f"vpn.overlay.peers failed: {exc}", "READ_ERROR")
    return OperationResult.ok(output={"peers": peers, "count": len(peers)})


async def _fabric_vpn_routes_handler(ctx: Any) -> Any:
    """Fabric read handler for ``vpn.routes.list`` — subnets reachable through any
    connected VPN provider (Tailscale advertised routes / NetBird routes /
    WireGuard allowed-IPs). Node-local; a safe read, off-guarded so it doesn't
    block on the overlay CLIs when VPN is off (the default)."""
    from app.core.config import settings
    from app.core.fabric.execution import OperationResult

    if settings.resolved_vpn_mode == "off":
        return OperationResult.ok(output={"routes": [], "count": 0, "mode": "off"})
    try:
        from app.services.vpn_integration import VPNManagerService

        routes = await VPNManagerService().discover_vpn_accessible_subnets()
    except Exception as exc:  # noqa: BLE001 - normalize for the executor
        return OperationResult.fail(f"vpn.routes.list failed: {exc}", "READ_ERROR")
    return OperationResult.ok(output={"routes": routes, "count": len(routes)})


class NetworkModule(BaseModule):
    """
    Network Module for FreeSDN.

    Provides VLAN management, WiFi network configuration,
    PoE control, and switch port management.
    """

    @classmethod
    def get_manifest(cls) -> ModuleManifest:
        """Return the module manifest."""
        return ModuleManifest(
            id="network",
            name="Network Management",
            version="1.0.0",
            description="Core networking functionality including VLANs, WiFi, PoE, and switch management",
            author="FreeSDN Team",
            license="AGPL-3.0-only",
            category="core",
            icon="network",
            color="#3B82F6",  # Blue
            # Dependencies - network module has no dependencies (it's core)
            dependencies=[],
            # Capabilities this module provides
            capabilities=[
                ModuleCapability.DEVICE_MANAGEMENT,
                ModuleCapability.NETWORK_DISCOVERY,
                ModuleCapability.VLAN_MANAGEMENT,
                ModuleCapability.WIFI_MANAGEMENT,
                ModuleCapability.POE_CONTROL,
                ModuleCapability.PORT_MANAGEMENT,
                ModuleCapability.TRAFFIC_ANALYTICS,
                ModuleCapability.TOPOLOGY_MAPPING,
                ModuleCapability.DEVICE_BACKUP,
                ModuleCapability.BULK_OPERATIONS,
            ],
            # Required capabilities from other modules (none for core module)
            required_capabilities=[],
            # Device types this module supports
            device_types=[
                "switch",
                "router",
                "access_point",
                "gateway",
                "firewall",
            ],
            # Permissions this module defines
            permissions=[
                ModulePermission(
                    code="network.view",
                    name="View Network",
                    description="View network devices and configuration",
                    resource="network",
                    action="read",
                ),
                ModulePermission(
                    code="network.manage",
                    name="Manage Network",
                    description="Create, modify, and delete network configuration",
                    resource="network",
                    action="update",
                ),
                ModulePermission(
                    code="network.vlan.manage",
                    name="Manage VLANs",
                    description="Create, modify, and delete VLANs",
                    resource="vlan",
                    action="update",
                ),
                ModulePermission(
                    code="network.wifi.manage",
                    name="Manage WiFi",
                    description="Create, modify, and delete WiFi networks",
                    resource="wifi",
                    action="update",
                ),
                ModulePermission(
                    code="network.poe.control",
                    name="Control PoE",
                    description="Enable and disable PoE on ports",
                    resource="poe",
                    action="execute",
                ),
                ModulePermission(
                    code="network.firmware.upgrade",
                    name="Firmware Upgrade",
                    description="Upgrade device firmware",
                    resource="firmware",
                    action="execute",
                ),
            ],
            # Navigation items for the UI sidebar (flat style with parent= references)
            nav_items=[
                ModuleNavItem(
                    path="/network",
                    label="Network",
                    icon="network",
                    order=10,
                    permission="network.view",
                ),
                ModuleNavItem(
                    path="/network/devices",
                    label="Devices",
                    icon="server",
                    order=1,
                    parent="/network",
                    permission="network.view",
                ),
                ModuleNavItem(
                    path="/network/vlans",
                    label="VLANs",
                    icon="layers",
                    order=2,
                    parent="/network",
                    permission="network.vlan.manage",
                ),
                ModuleNavItem(
                    path="/network/wifi",
                    label="WiFi Networks",
                    icon="wifi",
                    order=3,
                    parent="/network",
                    permission="network.wifi.manage",
                ),
                ModuleNavItem(
                    path="/network/ports",
                    label="Switch Ports",
                    icon="plug",
                    order=4,
                    parent="/network",
                    permission="network.manage",
                ),
                ModuleNavItem(
                    path="/network/topology",
                    label="Topology",
                    icon="git-branch",
                    order=5,
                    parent="/network",
                    permission="network.view",
                ),
            ],
            # Dashboard widgets
            widgets=[
                ModuleDashboardWidget(
                    id="network.device_status",
                    name="Device Status",
                    description="Overview of network device health",
                    component="NetworkDeviceStatus",
                    default_size="medium",
                    refresh_interval=30,
                ),
                ModuleDashboardWidget(
                    id="network.traffic_chart",
                    name="Network Traffic",
                    description="Real-time network traffic chart",
                    component="NetworkTrafficChart",
                    default_size="large",
                    refresh_interval=10,
                ),
                ModuleDashboardWidget(
                    id="network.vlan_summary",
                    name="VLAN Summary",
                    description="Overview of VLANs and their usage",
                    component="VlanSummaryWidget",
                    default_size="small",
                    refresh_interval=60,
                ),
                ModuleDashboardWidget(
                    id="network.wifi_clients",
                    name="WiFi Clients",
                    description="Connected wireless clients",
                    component="WifiClientsWidget",
                    default_size="medium",
                    refresh_interval=15,
                ),
            ],
            # Feature flags for granular control
            feature_flags=[
                ModuleFeatureFlag(
                    id="network.advanced_poe",
                    name="Advanced PoE Management",
                    description="Enable advanced PoE scheduling and budgeting",
                    default_enabled=False,
                ),
                ModuleFeatureFlag(
                    id="network.topology_auto",
                    name="Auto Topology Discovery",
                    description="Automatically discover and map network topology",
                    default_enabled=True,
                ),
                ModuleFeatureFlag(
                    id="network.traffic_analytics",
                    name="Traffic Analytics",
                    description="Enable detailed traffic analytics and reporting",
                    default_enabled=True,
                ),
                ModuleFeatureFlag(
                    id="network.bulk_firmware",
                    name="Bulk Firmware Updates",
                    description="Allow firmware updates on multiple devices at once",
                    default_enabled=False,
                ),
            ],
            # Default settings
            default_settings={
                "discovery_interval": 300,  # 5 minutes
                "topology_refresh": 600,  # 10 minutes
                "traffic_retention_days": 30,
                "auto_backup_enabled": True,
                "backup_retention_count": 5,
                "poe_budget_warning_threshold": 80,  # percent
            },
            # API routes prefix
            api_prefix="/network",
        )

    @property
    def manifest(self) -> ModuleManifest:
        """Return the module manifest."""
        return self.get_manifest()

    def get_router(self) -> APIRouter:
        """Return the FastAPI router for network endpoints."""
        from app.modules.network.api import router

        return router

    def get_backup_contributor(self):  # type: ignore[no-untyped-def]
        """Expose the VPN backup contributor (VPNConnectionRecord). Config
        snapshots exclude the secret fields; a Full/vault backup carries them
        decrypted-then-passphrase-sealed and re-keys them at restore. See
        app/modules/network/backup.py."""
        from app.modules.network.backup import VpnBackupContributor

        return VpnBackupContributor()

    def __init__(self) -> None:
        """Initialize the Network module."""
        super().__init__()
        self._discovery_task: Any | None = None
        self._topology_task: Any | None = None
        logger.info("NetworkModule initialized")

    def get_operations(self):  # type: ignore[no-untyped-def]
        """Fabric operations. The read (``network.client.list``) is a mid-chain
        step. Most network WRITES (wifi/switch/profile/VLAN) ride the staging
        pipeline per their exact applier features and surface via Pending
        Changes. We expose two curated cross-system WRITES — ``network.client.block``
        and ``network.device.reboot`` — so the Fabric can auto-respond to an event
        (e.g. a camera/IDS detection → block the offending Wi-Fi client, or a
        health signal → reboot an AP). SAFE BY DESIGN: both only STAGE through the
        Omada bulk pipeline; an operator applies via the dual-gate, and the
        catastrophic-preflight gate still governs the apply. The negotiator never
        force-applies a device write."""
        from app.core.fabric.operations import Operation, OperationTier

        # Both writes stage through the Omada bulk service (features ``bulk.*``);
        # they target an Omada controller via controller_id and a FreeSDN site_id
        # (the applier resolves the controller's omada_site_id from it).
        _bulk_schema = {
            "type": "object",
            "properties": {
                "controller_id": {"type": "string", "description": "Target Omada controller id."},
                "site_id": {
                    "type": "string",
                    "format": "uuid",
                    "description": "FreeSDN site the devices/clients belong to.",
                },
                "macs": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "MAC addresses to act on.",
                },
            },
            "required": ["controller_id", "site_id", "macs"],
        }
        # Overlay (daemon) VPN write ops. Connection-bound ops name a stored VPN
        # connection record; singleton ops act on the one node-local daemon.
        _overlay_conn_schema = {
            "type": "object",
            "properties": {
                "connection_id": {
                    "type": "string",
                    "description": "VPN connection record id (the tunnel to act on).",
                }
            },
            "required": ["connection_id"],
        }
        _overlay_singleton_schema = {"type": "object", "properties": {}, "required": []}

        def _overlay_write_op(op_id, title, desc, *, singleton=False):  # type: ignore[no-untyped-def]
            return Operation(
                id=op_id,
                title=title,
                description=desc,
                input_schema=_overlay_singleton_schema if singleton else _overlay_conn_schema,
                permission="vpn:write",
                write=True,
                feature=op_id,
                handler=None,
                tier=OperationTier.NATIVE,
                provider_id="network",
            )

        _SAFE = (
            " SAFE BY DESIGN: only STAGES into Pending Changes; an operator applies "
            "through the dual-gate. The Fabric never force-applies. Reversible."
        )
        return [
            Operation(
                id="network.client.list",
                title="List network clients",
                description="Connected clients for the organization (optionally one site).",
                input_schema={
                    "type": "object",
                    "properties": {
                        "site_id": {"type": "string", "format": "uuid"},
                        "is_online": {"type": "boolean"},
                        "limit": {"type": "integer", "minimum": 1, "maximum": 200},
                    },
                    "required": [],
                },
                produces=("application/json",),
                permission="network:read",
                write=False,
                handler=_fabric_client_list_handler,
                tier=OperationTier.NATIVE,
                provider_id="network",
            ),
            Operation(
                id="vpn.overlay.status",
                title="VPN / overlay status",
                description=(
                    "Aggregate Tailscale/NetBird/WireGuard/OpenVPN connection summary for "
                    "this controller node — per-provider connection counts and state. A "
                    "safe read (node-local, no org dimension): wire it as a mid-chain step "
                    "or use it as the auto-projected AI tool to ask 'is the overlay up?'."
                ),
                input_schema={"type": "object", "properties": {}, "required": []},
                produces=("application/json",),
                permission="vpn:read",
                write=False,
                handler=_fabric_overlay_status_handler,
                tier=OperationTier.NATIVE,
                provider_id="network",
            ),
            Operation(
                id="vpn.overlay.peers",
                title="List overlay peers",
                description=(
                    "Adoptable devices on the connected overlay mesh (tailnet/netbird), "
                    "each classified into a suggested adapter type — the discovery "
                    "inventory as a wireable read (e.g. ask the AI tool 'what's on my "
                    "tailnet?'). Returns [] when VPN is off."
                ),
                input_schema={"type": "object", "properties": {}, "required": []},
                produces=("application/json",),
                permission="vpn:read",
                write=False,
                handler=_fabric_overlay_peers_handler,
                tier=OperationTier.NATIVE,
                provider_id="network",
            ),
            Operation(
                id="vpn.routes.list",
                title="List VPN-accessible subnets",
                description=(
                    "Subnets reachable through any connected VPN provider (Tailscale "
                    "advertised routes, NetBird routes, WireGuard allowed-IPs) — what the "
                    "overlay can reach. A safe read; [] when VPN is off."
                ),
                input_schema={"type": "object", "properties": {}, "required": []},
                produces=("application/json",),
                permission="vpn:read",
                write=False,
                handler=_fabric_vpn_routes_handler,
                tier=OperationTier.NATIVE,
                provider_id="network",
            ),
            # Overlay (daemon) VPN writes — let the Fabric stage a connect/disconnect
            # in response to a connectivity event (e.g. overlay.peer.offline → stage a
            # reconnect for operator approval). Connect/disconnect (+ tailscale
            # reconnect) only; the irreversible tailscale up/logout are NOT exposed.
            _overlay_write_op(
                "overlay.wireguard.connect",
                "Connect WireGuard overlay (staged)",
                "Bring up a configured WireGuard tunnel on the appliance." + _SAFE,
            ),
            _overlay_write_op(
                "overlay.wireguard.disconnect",
                "Disconnect WireGuard overlay (staged)",
                "Bring down a WireGuard tunnel on the appliance." + _SAFE,
            ),
            _overlay_write_op(
                "overlay.openvpn.connect",
                "Connect OpenVPN overlay (staged)",
                "Bring up a configured OpenVPN client tunnel on the appliance." + _SAFE,
            ),
            _overlay_write_op(
                "overlay.openvpn.disconnect",
                "Disconnect OpenVPN overlay (staged)",
                "Bring down an OpenVPN client tunnel on the appliance." + _SAFE,
            ),
            _overlay_write_op(
                "overlay.netbird.connect",
                "Connect NetBird overlay (staged)",
                "Register + bring up the NetBird peer using the connection's setup key." + _SAFE,
            ),
            _overlay_write_op(
                "overlay.netbird.disconnect",
                "Disconnect NetBird overlay (staged)",
                "Bring down the node-local NetBird daemon." + _SAFE,
                singleton=True,
            ),
            _overlay_write_op(
                "overlay.tailscale.disconnect",
                "Disconnect Tailscale overlay (staged)",
                "Bring the node-local Tailscale daemon down (keeps auth; reversible "
                "via reconnect)." + _SAFE,
                singleton=True,
            ),
            _overlay_write_op(
                "overlay.tailscale.reconnect",
                "Reconnect Tailscale overlay (staged)",
                "Bring the node-local Tailscale daemon back up (keep-auth)." + _SAFE,
                singleton=True,
            ),
            Operation(
                id="network.client.block",
                title="Block Wi-Fi client(s) (staged)",
                description=(
                    "Stage a block of one or more Wi-Fi clients by MAC on an Omada "
                    "controller — the automated response to a security event (e.g. a "
                    "camera intrusion or IDS detection that carries the client MAC). "
                    "SAFE BY DESIGN: only STAGES into Pending Changes; an operator "
                    "applies through the dual-gate. The Fabric never force-applies."
                ),
                input_schema=_bulk_schema,
                produces=("application/json",),
                permission="network:write",
                write=True,
                feature="bulk.client.block",
                handler=None,
                tier=OperationTier.NATIVE,
                provider_id="network",
            ),
            Operation(
                id="network.device.reboot",
                title="Reboot network device(s) (staged)",
                description=(
                    "Stage a reboot of one or more Omada-managed devices (APs/switches) "
                    "by MAC — an operational auto-response (e.g. a health-degraded "
                    "signal). Stages through the bulk pipeline; an operator applies via "
                    "the dual-gate (reboot is classified DESTRUCTIVE, not catastrophic)."
                ),
                input_schema=_bulk_schema,
                produces=("application/json",),
                permission="network:write",
                write=True,
                feature="bulk.device.reboot",
                handler=None,
                tier=OperationTier.NATIVE,
                provider_id="network",
            ),
        ]

    def get_emitted_events(self):  # type: ignore[no-untyped-def]
        """Fabric event sources: VLAN + WiFi lifecycle (network/service.py)."""
        from app.core.fabric.operations import EventSpec, OperationTier

        _vlan = {
            "type": "object",
            "properties": {
                "vlan_id": {"type": "integer"},
                "vlan_uuid": {"type": "string"},
                "name": {"type": "string"},
                "site_id": {"type": "string"},
                "organization_id": {"type": "string"},
            },
        }
        _wifi = {
            "type": "object",
            "properties": {
                "ssid": {"type": "string"},
                "wifi_uuid": {"type": "string"},
                "site_id": {"type": "string"},
                "vlan_id": {"type": "integer"},
                "organization_id": {"type": "string"},
            },
        }
        # Overlay-mesh discovery — the exact dict `discover_overlay_devices()`
        # returns (overlay_discovery.py), plus the org id the negotiator requires.
        _overlay_peer = {
            "type": "object",
            "properties": {
                "source": {"type": "string", "description": "tailscale | netbird"},
                "hostname": {"type": "string"},
                "magic_dns": {"type": "string"},
                "address": {"type": "string", "description": "overlay (tailnet/netbird) IP"},
                "online": {"type": "boolean"},
                "os": {"type": "string"},
                "tags": {"type": "array", "items": {"type": "string"}},
                "suggested_type": {"type": "string", "description": "classified adapter type"},
                "confidence": {"type": "string", "description": "high | medium | low"},
                "already_adopted": {"type": "boolean"},
                "adopted_device_id": {"type": "string"},
                "organization_id": {"type": "string"},
            },
        }
        return [
            EventSpec(
                event_type="overlay.peer.discovered",
                title="Overlay peer discovered",
                description=(
                    "An adoptable device was found on the connected overlay mesh "
                    "(tailnet/netbird) and is not already managed — wire it to notify an "
                    "operator or kick off adoption. Deduplicated per peer, so it fires on "
                    "first sighting rather than every discovery poll."
                ),
                payload_schema=_overlay_peer,
                tier=OperationTier.NATIVE,
                provider_id="network",
            ),
            EventSpec(
                event_type="overlay.peer.online",
                title="Overlay peer online",
                description=(
                    "An overlay-mesh peer came online (was previously offline) — emitted by "
                    "the overlay poller on transition. Wire it to re-sync or notify when a "
                    "remote site/box rejoins the tailnet/netbird mesh."
                ),
                payload_schema=_overlay_peer,
                tier=OperationTier.NATIVE,
                provider_id="network",
            ),
            EventSpec(
                event_type="overlay.peer.offline",
                title="Overlay peer offline",
                description=(
                    "An overlay-mesh peer went offline / dropped off the mesh — emitted by the "
                    "overlay poller on transition. Wire it to alert an operator that a remote "
                    "site/box is no longer reachable over the overlay."
                ),
                payload_schema=_overlay_peer,
                tier=OperationTier.NATIVE,
                provider_id="network",
            ),
            EventSpec(
                event_type="overlay.connection.changed",
                title="Overlay peer metadata changed",
                description=(
                    "An overlay peer's hostname, OS, ACL tags, or classified type changed while "
                    "it stayed connected (e.g. it was retagged or renamed)."
                ),
                payload_schema={
                    "type": "object",
                    "properties": {
                        "organization_id": {"type": "string"},
                        "prev": _overlay_peer,
                        "now": _overlay_peer,
                    },
                },
                tier=OperationTier.NATIVE,
                provider_id="network",
            ),
            EventSpec(
                event_type="overlay.status.unreachable",
                title="Overlay enumeration unreachable",
                description=(
                    "The overlay-mesh enumeration is unavailable (the Tailscale/NetBird daemon "
                    "is down or unreadable from the controller)."
                ),
                payload_schema={
                    "type": "object",
                    "properties": {
                        "organization_id": {"type": "string"},
                        "detail": {"type": "string"},
                    },
                },
                tier=OperationTier.NATIVE,
                provider_id="network",
            ),
            EventSpec(
                event_type="overlay.status.online",
                title="Overlay enumeration online",
                description="The overlay-mesh enumeration is reachable again (recovery).",
                payload_schema={
                    "type": "object",
                    "properties": {"organization_id": {"type": "string"}},
                },
                tier=OperationTier.NATIVE,
                provider_id="network",
            ),
            EventSpec(
                event_type="network.vlan.created",
                title="VLAN created",
                description="A VLAN was created on a controller.",
                payload_schema=_vlan,
                tier=OperationTier.NATIVE,
                provider_id="network",
            ),
            EventSpec(
                event_type="network.vlan.updated",
                title="VLAN updated",
                description="A VLAN's configuration changed.",
                payload_schema=_vlan,
                tier=OperationTier.NATIVE,
                provider_id="network",
            ),
            EventSpec(
                event_type="network.vlan.deleted",
                title="VLAN deleted",
                description="A VLAN was removed.",
                payload_schema=_vlan,
                tier=OperationTier.NATIVE,
                provider_id="network",
            ),
            EventSpec(
                event_type="network.wifi.created",
                title="WiFi network created",
                description="A WiFi SSID was created.",
                payload_schema=_wifi,
                tier=OperationTier.NATIVE,
                provider_id="network",
            ),
            EventSpec(
                event_type="network.wifi.updated",
                title="WiFi network updated",
                description="A WiFi SSID's configuration changed.",
                payload_schema=_wifi,
                tier=OperationTier.NATIVE,
                provider_id="network",
            ),
            EventSpec(
                event_type="network.wifi.deleted",
                title="WiFi network deleted",
                description="A WiFi SSID was removed.",
                payload_schema=_wifi,
                tier=OperationTier.NATIVE,
                provider_id="network",
            ),
            *self._omada_event_specs(),
        ]

    def _omada_event_specs(self):  # type: ignore[no-untyped-def]
        """Fabric event sources emitted by the Omada controller monitor
        (``app/tasks/omada_monitor.py``) on state transitions. Lets an operator
        wire Omada conditions as triggers (e.g. ``omada.event.device_offline →
        fabric.notify``, ``omada.event.rogue_ap → firewall.block_ip``)."""
        from app.adapters.omada.event_types import (
            DEVICE_OFFLINE,
            EVENT_META,
            FIRMWARE_AVAILABLE,
            GENERIC,
            POE_OVERLOAD,
            ROGUE_AP,
            event_type_for,
        )
        from app.core.fabric.operations import EventSpec, OperationTier

        # An Omada alert event — controller routing fields + the normalized class
        # and the raw category/message (preserved for fidelity, never for routing).
        _alert = {
            "type": "object",
            "properties": {
                "controller_id": {"type": "string"},
                "controller_name": {"type": "string"},
                "host": {"type": "string"},
                "alert_id": {"type": "string"},
                "category": {"type": "string", "description": "canonical class"},
                "raw_category": {"type": "string"},
                "message": {"type": "string"},
                "level": {"type": "string"},
                "device_mac": {"type": "string"},
                "device_name": {"type": "string"},
                "client_mac": {"type": "string"},
            },
        }
        _reach = {
            "type": "object",
            "properties": {
                "controller_id": {"type": "string"},
                "controller_name": {"type": "string"},
                "host": {"type": "string"},
                "detail": {"type": "string"},
            },
        }
        specs = [
            EventSpec(
                event_type="omada.event.controller_unreachable",
                title="Omada controller unreachable",
                description="The Omada controller stopped responding to health polls.",
                payload_schema=_reach,
                tier=OperationTier.NATIVE,
                provider_id="network",
            ),
            EventSpec(
                event_type="omada.event.controller_online",
                title="Omada controller back online",
                description="The Omada controller recovered after being unreachable.",
                payload_schema=_reach,
                tier=OperationTier.NATIVE,
                provider_id="network",
            ),
        ]
        for canonical in (DEVICE_OFFLINE, ROGUE_AP, POE_OVERLOAD, FIRMWARE_AVAILABLE, GENERIC):
            title, desc = EVENT_META[canonical]
            specs.append(
                EventSpec(
                    event_type=event_type_for(canonical),
                    title=title,
                    description=desc,
                    payload_schema=_alert,
                    tier=OperationTier.NATIVE,
                    provider_id="network",
                )
            )
        return specs

    async def on_load(self) -> None:
        """Called when the module is loaded."""
        logger.info("Network module v%s loading...", self.manifest.version)
        # Initialize database tables, register event handlers, etc.
        await super().on_load()

    async def on_start(self, organization_id: UUID, db: Any = None) -> None:
        """Called when the module is started for an organization."""
        logger.info("Network module starting for org %s...", organization_id)

        await super().on_start(organization_id, db)
        logger.info("Network module started")

    async def on_stop(self, organization_id: UUID, db: Any = None) -> None:
        """Called when the module is stopped for an organization."""
        logger.info("Network module stopping for org %s...", organization_id)

        # Cancel background tasks
        if self._discovery_task:
            self._discovery_task.cancel()
        if self._topology_task:
            self._topology_task.cancel()

        await super().on_stop(organization_id, db)
        logger.info("Network module stopped")

    async def on_unload(self) -> None:
        """Called when the module is unloaded."""
        logger.info("Network module unloading...")
        await super().on_unload()

    async def health_check(self) -> dict[str, Any]:
        """Return module health status."""
        return {
            "status": "healthy",
            "module": self.manifest.id,
            "version": self.manifest.version,
            "state": self.state.value,
            "checks": {
                "discovery_task": self._discovery_task is not None
                and not self._discovery_task.done()
                if self._discovery_task
                else False,
                "topology_task": self._topology_task is not None and not self._topology_task.done()
                if self._topology_task
                else False,
            },
        }

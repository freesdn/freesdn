# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN Firewall Module - Main Module Class
===========================================

The Firewall module provides unified network security and gateway
management including:
  - Firewall rules, NAT, VPN, IDS/IPS
  - External gateway integrations (OPNsense, pfSense, MikroTik, OpenWrt)
  - Cross-gateway orchestration (VLAN distribution, drift detection)
  - Brownfield import wizard
  - Live diagnostics (ping, traceroute, DNS lookup)
"""

import logging
from collections.abc import Callable
from typing import Any

from fastapi import APIRouter

from app.modules.base import BaseModule, DeviceSource, ModuleCapability
from app.modules.manifest import (
    ModuleCategory,
    ModuleManifest,
    ModuleNavItem,
    ModulePermission,
    ModuleWidget,
)

logger = logging.getLogger(__name__)


async def _fabric_search_alerts_handler(ctx: Any) -> Any:
    """Fabric read handler for ``firewall.search_alerts`` — recent IDS/IPS +
    security alerts for the org (org-scoped via FirewallService)."""
    from app.core.fabric.execution import OperationResult

    if ctx.db is None:
        return OperationResult.fail("firewall.search_alerts requires a DB session", "NO_DB")
    try:
        from app.modules.firewall.service import FirewallService

        svc = FirewallService(ctx.db, ctx.organization_id)
        limit = int(ctx.params.get("limit") or 50)
        alerts = await svc.search_alerts(
            severity=ctx.params.get("severity") or None,
            is_acknowledged=ctx.params.get("is_acknowledged"),
            limit=max(1, min(limit, 200)),
        )
    except Exception as exc:  # noqa: BLE001 — normalize for the executor
        return OperationResult.fail(f"firewall.search_alerts failed: {exc}", "READ_ERROR")

    def _row(a: Any) -> dict[str, Any]:
        ts = getattr(a, "created_at", None) or getattr(a, "timestamp", None)
        return {
            "id": str(getattr(a, "id", "")),
            "severity": getattr(a, "severity", None),
            "signature": getattr(a, "signature", None) or getattr(a, "message", None),
            "device_id": str(getattr(a, "device_id", "") or "") or None,
            "source_ip": getattr(a, "source_ip", None),
            "dest_ip": getattr(a, "dest_ip", None),
            "is_acknowledged": getattr(a, "is_acknowledged", None),
            "created_at": ts.isoformat() if hasattr(ts, "isoformat") else None,
        }

    rows = [_row(a) for a in alerts]
    return OperationResult.ok(output={"count": len(rows), "alerts": rows})


class FirewallModule(BaseModule):
    """
    Firewall Module for FreeSDN.

    Provides unified network security and gateway orchestration:
    - Firewall rule management
    - NAT (Network Address Translation)
    - VPN management (IPSec, OpenVPN, WireGuard)
    - IDS/IPS (Intrusion Detection/Prevention)
    - Traffic monitoring and logging
    - External gateway integrations
    - Cross-gateway VLAN distribution & drift detection
    - Brownfield import wizard
    """

    @classmethod
    def get_manifest(cls) -> ModuleManifest:
        """Return the module manifest."""
        return ModuleManifest(
            id="firewall",
            name="Firewall",
            version="1.0.0",
            description=(
                "Firewall rules, NAT, VPN, IDS/IPS, gateway integrations, "
                "and cross-gateway orchestration with drift detection"
            ),
            author="FreeSDN Team",
            license="AGPL-3.0-only",
            category=ModuleCategory.SECURITY,
            icon="shield",
            color="#DC2626",  # Red
            # Dependencies
            dependencies=[],
            # Capabilities — includes former gateway module capabilities
            capabilities=[
                ModuleCapability.FIREWALL_RULES,
                ModuleCapability.NAT_MANAGEMENT,
                ModuleCapability.VPN_MANAGEMENT,
                ModuleCapability.IDS_IPS,
                ModuleCapability.GATEWAY_ORCHESTRATION,
                ModuleCapability.VLAN_DISTRIBUTION,
                ModuleCapability.SITE_ROLE_MAP,
                ModuleCapability.DRIFT_DETECTION,
                ModuleCapability.BROWNFIELD_IMPORT,
            ],
            # Required capabilities from other modules
            required_capabilities=[],
            # Device types this module supports
            device_types=[
                "firewall",
                "router",
                "utm",
                "vpn_gateway",
            ],
            # Permissions — merged firewall + gateway
            permissions=[
                ModulePermission(
                    code="firewall.view",
                    name="View Firewall",
                    description="View firewall rules and configuration",
                    resource="firewall",
                    action="read",
                ),
                ModulePermission(
                    code="firewall.manage_rules",
                    name="Manage Rules",
                    description="Create, edit, and delete firewall rules",
                    resource="rule",
                    action="update",
                ),
                ModulePermission(
                    code="firewall.manage_nat",
                    name="Manage NAT",
                    description="Configure NAT rules and port forwarding",
                    resource="nat",
                    action="update",
                ),
                ModulePermission(
                    code="firewall.manage_vpn",
                    name="Manage VPN",
                    description="Configure VPN tunnels and connections",
                    resource="vpn",
                    action="update",
                ),
                ModulePermission(
                    code="firewall.manage_ids",
                    name="Manage IDS/IPS",
                    description="Configure intrusion detection and prevention",
                    resource="ids",
                    action="update",
                ),
                ModulePermission(
                    code="firewall.view_logs",
                    name="View Logs",
                    description="View firewall and security logs",
                    resource="log",
                    action="read",
                ),
                ModulePermission(
                    code="firewall.manage_gateways",
                    name="Manage Gateways",
                    description="Add, edit, and remove firewall gateway integrations",
                    resource="gateway",
                    action="update",
                ),
                # Orchestration permissions (from gateway module)
                ModulePermission(
                    code="gateway.view",
                    name="View Orchestration",
                    description="View orchestration topology and canonical resources",
                    resource="gateway",
                    action="read",
                ),
                ModulePermission(
                    code="gateway.manage_topology",
                    name="Manage Topology",
                    description="Create and edit site role maps (brain / limb)",
                    resource="topology",
                    action="update",
                ),
                ModulePermission(
                    code="gateway.manage_vlans",
                    name="Manage Canonical VLANs",
                    description="Create, edit, and delete canonical VLAN definitions",
                    resource="vlan",
                    action="update",
                ),
                ModulePermission(
                    code="gateway.manage_dhcp",
                    name="Manage DHCP",
                    description="Manage DHCP scopes and reservations",
                    resource="dhcp",
                    action="update",
                ),
                ModulePermission(
                    code="gateway.manage_dns",
                    name="Manage DNS",
                    description="Manage DNS overrides and records",
                    resource="dns",
                    action="update",
                ),
                ModulePermission(
                    code="gateway.distribute",
                    name="Distribute Resources",
                    description="Push canonical resources to gateway devices",
                    resource="distribution",
                    action="execute",
                ),
                ModulePermission(
                    code="gateway.import",
                    name="Brownfield Import",
                    description="Run the brownfield import wizard",
                    resource="import",
                    action="execute",
                ),
                ModulePermission(
                    code="gateway.drift",
                    name="Drift Detection",
                    description="View and resolve configuration drift events",
                    resource="drift",
                    action="update",
                ),
                ModulePermission(
                    code="gateway.diagnostics",
                    name="Run Diagnostics",
                    description="Execute live diagnostics (ping, traceroute, DNS lookup)",
                    resource="diagnostics",
                    action="execute",
                ),
            ],
            # Navigation items — merged
            nav_items=[
                ModuleNavItem(
                    path="/firewall",
                    label="Firewall",
                    icon="shield",
                    order=35,
                    permission="firewall.view",
                ),
                ModuleNavItem(
                    path="/firewall/rules",
                    label="Rules",
                    icon="list",
                    order=1,
                    parent="/firewall",
                    permission="firewall.view",
                ),
                ModuleNavItem(
                    path="/firewall/nat",
                    label="NAT",
                    icon="arrow-right-left",
                    order=2,
                    parent="/firewall",
                    permission="firewall.view",
                ),
                ModuleNavItem(
                    path="/firewall/vpn",
                    label="VPN",
                    icon="lock",
                    order=3,
                    parent="/firewall",
                    permission="firewall.view",
                ),
                ModuleNavItem(
                    path="/firewall/ids",
                    label="IDS/IPS",
                    icon="alert-triangle",
                    order=4,
                    parent="/firewall",
                    permission="firewall.view",
                ),
                ModuleNavItem(
                    path="/firewall/logs",
                    label="Logs",
                    icon="file-text",
                    order=5,
                    parent="/firewall",
                    permission="firewall.view_logs",
                ),
                ModuleNavItem(
                    path="/firewall/gateways",
                    label="Gateways",
                    icon="server",
                    order=6,
                    parent="/firewall",
                    permission="firewall.view",
                ),
                # Orchestration nav items (under firewall parent)
                ModuleNavItem(
                    path="/firewall/orchestration",
                    label="Orchestration",
                    icon="git-merge",
                    order=7,
                    parent="/firewall",
                    permission="gateway.view",
                ),
            ],
            # Dashboard widgets — merged
            widgets=[
                ModuleWidget(
                    id="firewall_status",
                    name="Firewall Status",
                    description="Overview of firewall status and blocked traffic",
                    component="FirewallStatusWidget",
                    default_size="medium",
                    refresh_interval=60,
                    permission="firewall.view",
                ),
                ModuleWidget(
                    id="vpn_connections",
                    name="VPN Connections",
                    description="Active VPN tunnel status",
                    component="VPNConnectionsWidget",
                    default_size="small",
                    refresh_interval=30,
                    permission="firewall.view",
                ),
                ModuleWidget(
                    id="threat_alerts",
                    name="Threat Alerts",
                    description="Recent IDS/IPS alerts",
                    component="ThreatAlertsWidget",
                    default_size="medium",
                    refresh_interval=30,
                    permission="firewall.view",
                ),
                ModuleWidget(
                    id="gateway_topology",
                    name="Site Topology",
                    description="Brain / limb map with sync status",
                    component="GatewayTopologyWidget",
                    default_size="large",
                    refresh_interval=30,
                    permission="gateway.view",
                ),
                ModuleWidget(
                    id="vlan_distribution",
                    name="VLAN Distribution",
                    description="Canonical VLAN distribution status per site",
                    component="VLANDistributionWidget",
                    default_size="medium",
                    refresh_interval=60,
                    permission="gateway.view",
                ),
                ModuleWidget(
                    id="drift_summary",
                    name="Drift Summary",
                    description="Unresolved drift events by severity",
                    component="DriftSummaryWidget",
                    default_size="small",
                    refresh_interval=60,
                    permission="gateway.drift",
                ),
                ModuleWidget(
                    id="gateway_health",
                    name="Gateway Health",
                    description="Online / offline status and last-sync times",
                    component="GatewayHealthWidget",
                    default_size="medium",
                    refresh_interval=30,
                    permission="gateway.view",
                ),
            ],
            # Settings schema — merged
            settings_schema={
                "type": "object",
                "properties": {
                    "default_policy": {
                        "type": "string",
                        "enum": ["allow", "deny"],
                        "default": "deny",
                        "description": "Default firewall policy",
                    },
                    "log_blocked": {
                        "type": "boolean",
                        "default": True,
                        "description": "Log blocked connections",
                    },
                    "ids_enabled": {
                        "type": "boolean",
                        "default": True,
                        "description": "Enable IDS/IPS",
                    },
                    "ids_mode": {
                        "type": "string",
                        "enum": ["detect", "prevent"],
                        "default": "detect",
                        "description": "IDS/IPS mode",
                    },
                    "log_retention_days": {
                        "type": "integer",
                        "minimum": 7,
                        "maximum": 365,
                        "default": 30,
                        "description": "Firewall log retention period",
                    },
                    # Orchestration settings (from gateway)
                    "sync_interval_minutes": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 1440,
                        "default": 5,
                        "description": "Data sync interval for brain devices (minutes)",
                    },
                    "drift_check_interval_minutes": {
                        "type": "integer",
                        "minimum": 5,
                        "maximum": 1440,
                        "default": 15,
                        "description": "Drift detection interval (minutes)",
                    },
                    "distribution_lock_ttl_seconds": {
                        "type": "integer",
                        "minimum": 60,
                        "maximum": 3600,
                        "default": 300,
                        "description": "Maximum lock duration for distribution jobs",
                    },
                    "auto_remediate_drift": {
                        "type": "boolean",
                        "default": False,
                        "description": "Automatically reapply canonical config on drift",
                    },
                    "import_retention_days": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 365,
                        "default": 90,
                        "description": "Days to retain completed import sessions",
                    },
                },
            },
            # Default settings — merged
            default_settings={
                "default_policy": "deny",
                "log_blocked": True,
                "ids_enabled": True,
                "ids_mode": "detect",
                "log_retention_days": 30,
                "sync_interval_minutes": 5,
                "drift_check_interval_minutes": 15,
                "distribution_lock_ttl_seconds": 300,
                "auto_remediate_drift": False,
                "import_retention_days": 90,
            },
        )

    @property
    def manifest(self) -> ModuleManifest:
        """Return the module manifest."""
        return self.get_manifest()

    _router: APIRouter | None = None

    def get_router(self) -> APIRouter:
        """Return the FastAPI router for firewall + gateway orchestration endpoints."""
        if FirewallModule._router is None:
            from app.modules.firewall.api import router
            from app.modules.firewall.gateway_api import router as gw_router

            # Include gateway sub-router on the main firewall router
            router.include_router(gw_router)

            # Include gateway orchestration routers (from gateway module code)
            try:
                from app.modules.gateway.api.canonical_api import router as canonical_router  # noqa: I001
                from app.modules.gateway.api.dashboard_api import router as dashboard_router
                from app.modules.gateway.api.distribution_api import router as distribution_router
                from app.modules.gateway.api.drift_api import router as drift_router
                from app.modules.gateway.api.import_api import router as import_router
                from app.modules.gateway.api.passthrough_api import router as passthrough_router
                from app.modules.gateway.api.reconciliation_api import (
                    router as reconciliation_router,
                )
                from app.modules.gateway.api.role_map_api import router as role_map_router
                from app.modules.gateway.api.template_api import router as template_router

                orchestration = APIRouter(tags=["Gateway Orchestration"])
                orchestration.include_router(role_map_router)
                orchestration.include_router(canonical_router)
                orchestration.include_router(distribution_router)
                orchestration.include_router(import_router)
                orchestration.include_router(drift_router)
                orchestration.include_router(dashboard_router)
                orchestration.include_router(passthrough_router)
                orchestration.include_router(template_router)
                orchestration.include_router(reconciliation_router)
                router.include_router(orchestration)
            except ImportError:
                logger.warning("Gateway orchestration code not available — skipping")

            FirewallModule._router = router
        return FirewallModule._router

    def get_device_sources(self) -> list[DeviceSource]:
        """Declare firewall devices and gateways managed by this module."""
        from app.modules.firewall.models import FirewallDevice, GatewayConnection

        return [
            DeviceSource(
                model=FirewallDevice,
                device_type="firewall",
                external_id_prefix="firewall",
                status_is_boolean=True,
                status_field="is_online",
                default_manufacturer="OPNsense",
            ),
            DeviceSource(
                model=GatewayConnection,
                device_type="firewall",
                external_id_prefix="gateway",
                field_map={
                    "name": "name",
                    "manufacturer": "vendor",
                    "model": "detected_model",
                    "firmware_version": "detected_version",
                    "ip_address": "host",
                    "last_seen": "last_seen_at",
                    "site_id": "site_id",
                },
                status_is_boolean=True,
                status_field="is_online",
                default_manufacturer="opnsense",
                name_resolver=lambda gw: (
                    getattr(gw, "name", None)
                    or getattr(gw, "detected_hostname", None)
                    or "Firewall"
                ),
                site_id_resolver=lambda row, fallback: getattr(row, "site_id", None) or fallback,
            ),
        ]

    def get_models(self) -> list[type]:
        """Return SQLAlchemy models for this module (firewall + gateway orchestration)."""
        from app.modules.firewall.models import (
            FirewallDevice,
            FirewallLog,
            FirewallRule,
            GatewayConnection,
            GatewaySyncLog,
            IDSAlert,
            NATRule,
            VPNTunnel,
        )

        models: list[type] = [
            FirewallDevice,
            FirewallRule,
            NATRule,
            VPNTunnel,
            IDSAlert,
            FirewallLog,
            GatewayConnection,
            GatewaySyncLog,
        ]

        # Include gateway orchestration models
        try:
            from app.modules.gateway.models import ALL_MODELS

            models.extend(ALL_MODELS)
        except ImportError:
            logger.warning("Gateway orchestration models not available")

        return models

    def get_tasks(self) -> dict[str, Callable[..., Any]]:
        """Return Celery tasks for this module."""
        return {}

    def get_backup_contributor(self):  # type: ignore[no-untyped-def]
        """Expose the Firewall portable-config contributor to the backup
        framework. See app/modules/firewall/backup.py for the
        captured/excluded scope (devices + rules + NAT + VPN + gateway
        connections; NOT logs/alerts/credentials)."""
        from app.modules.firewall.backup import FirewallBackupContributor

        return FirewallBackupContributor()

    def get_event_handlers(self) -> dict[str, Any]:
        """Register event handlers for cross-module integration."""
        try:
            from app.modules.gateway.events.handlers import get_handlers

            return get_handlers()
        except ImportError:
            return {}

    def get_operations(self):  # type: ignore[no-untyped-def]
        """Fabric operations. Most firewall *writes* ride the staging pipeline
        per-vendor (opnsense.firewall.*/…) and surface in the Pending Changes UI.
        We expose ONE curated cross-system write — ``firewall.block_ip`` — so the
        Fabric can auto-respond to a threat event (e.g. an IDS-critical alert) by
        STAGING a block; it's never auto-applied (operator sign-off via the
        dual-gate), exactly the safe contract the executor enforces for writes."""
        from app.core.fabric.operations import Operation, OperationTier

        return [
            Operation(
                id="firewall.search_alerts",
                title="Search firewall/IDS alerts",
                description="Recent IDS/IPS + security alerts for the organization.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "severity": {"type": "string"},
                        "is_acknowledged": {"type": "boolean"},
                        "limit": {"type": "integer", "minimum": 1, "maximum": 200},
                    },
                    "required": [],
                },
                produces=("application/json",),
                permission="firewall.view_logs",
                write=False,
                handler=_fabric_search_alerts_handler,
                tier=OperationTier.NATIVE,
                provider_id="firewall",
            ),
            Operation(
                id="firewall.block_ip",
                title="Block a source IP (staged firewall rule)",
                description=(
                    "Stage a block rule for a source IP on a firewall gateway — the "
                    "automated response to a threat (e.g. an IDS-critical alert "
                    "carrying the attacker's source IP). SAFE BY DESIGN: the Fabric "
                    "only STAGES the rule into Pending Changes; an operator applies "
                    "it through the dual-gate. The negotiator never force-applies a "
                    "device write, so an automated source can never silently mutate "
                    "the firewall."
                ),
                input_schema={
                    "type": "object",
                    "properties": {
                        "controller_id": {
                            "type": "string",
                            "description": "Target firewall gateway id.",
                        },
                        "source_net": {
                            "type": "string",
                            "description": "Source IP/CIDR to block (e.g. the IDS src_ip).",
                        },
                        "action": {
                            "type": "string",
                            "description": "block | reject (default block)",
                        },
                        "interface": {"type": "string", "description": "e.g. wan (default wan)"},
                        "description": {"type": "string"},
                    },
                    "required": ["controller_id", "source_net"],
                },
                produces=("application/json",),
                permission="firewall.manage_rules",
                write=True,
                feature="opnsense.firewall.rule",
                handler=None,
                tier=OperationTier.NATIVE,
                provider_id="firewall",
            ),
        ]

    def get_emitted_events(self):  # type: ignore[no-untyped-def]
        """Fabric event sources from the gateway-orchestration submodule.

        (Firewall *rule/NAT/VPN* changes surface on the universal
        ``controller.change.*`` stream via the staging pipeline — no separate
        declaration needed. These two are the gateway brain/limb signals.)
        """
        from app.core.fabric.operations import EventSpec, OperationTier

        return [
            EventSpec(
                event_type="gateway.sync.completed",
                title="Gateway sync completed",
                description="A brain→limb reconciliation/sync finished for a site gateway.",
                payload_schema={
                    "type": "object",
                    "properties": {
                        "gateway_id": {"type": "string"},
                        "site_id": {"type": "string"},
                        "synced": {"type": "integer"},
                        "duration_ms": {"type": "integer"},
                    },
                },
                tier=OperationTier.NATIVE,
                provider_id="firewall",
            ),
            EventSpec(
                event_type="gateway.brain.offline",
                title="Gateway brain offline",
                description="The brain (authoritative gateway) device stopped responding.",
                payload_schema={
                    "type": "object",
                    "properties": {
                        "device_id": {"type": "string"},
                        "site_id": {"type": "string"},
                    },
                },
                tier=OperationTier.NATIVE,
                provider_id="firewall",
            ),
            *self._gateway_health_events(),
        ]

    @staticmethod
    def _gateway_health_events():  # type: ignore[no-untyped-def]
        """firewall.event.* transition sources emitted by the firewall.poll_health
        monitor (app/tasks/firewall_monitor.py)."""
        from app.core.fabric.operations import EventSpec, OperationTier

        _p = {
            "type": "object",
            "properties": {
                "gateway_id": {"type": "string"},
                "gateway_name": {"type": "string"},
                "vendor": {"type": "string"},
                "host": {"type": "string"},
                "gateway": {"type": "string"},
                "status": {"type": "string"},
                "new_signatures": {"type": "array", "items": {"type": "string"}},
                "count": {"type": "integer"},
            },
        }

        def _ev(et, title, desc):
            return EventSpec(
                event_type=et,
                title=title,
                description=desc,
                payload_schema=_p,
                tier=OperationTier.NATIVE,
                provider_id="firewall",
            )

        return [
            _ev(
                "firewall.event.ids_critical",
                "IDS critical signature",
                "A new critical IDS/IPS signature fired (diffed by signature id).",
            ),
            _ev(
                "firewall.event.wan_down",
                "WAN/gateway down",
                "A monitored gateway went down or unreachable.",
            ),
            _ev(
                "firewall.event.wan_up",
                "WAN/gateway recovered",
                "A previously-down gateway came back up.",
            ),
            _ev(
                "firewall.event.gateway_unreachable",
                "Firewall unreachable",
                "The firewall appliance stopped responding to the monitor.",
            ),
            _ev(
                "firewall.event.gateway_online",
                "Firewall online",
                "The firewall appliance became reachable again.",
            ),
        ]

    async def on_load(self) -> None:
        """Called when module is loaded."""
        await super().on_load()
        logger.info("Firewall module loaded (includes gateway orchestration)")

    async def on_unload(self) -> None:
        """Called when module is unloaded."""
        await super().on_unload()
        logger.info("Firewall module unloaded")

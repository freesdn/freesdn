# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway Orchestration Module
===========================================

NOTE: This module is NOT loaded standalone.  The module loader excludes
"gateway" (see EXCLUDED_MODULES in loader.py).  All gateway orchestration
routes, models, and event handlers are loaded by FirewallModule
(app.modules.firewall.module) which imports directly from this package.
The code stays here so FirewallModule can import it, but GatewayModule
will never be registered in the module registry on its own.

Cross-platform orchestration module that coordinates VLANs,
DHCP, DNS, and firewall resources across heterogeneous gateway
devices using the Site Role Map (brain / limb) topology.
"""

import logging
from typing import Any

from fastapi import APIRouter

from app.modules.base import BaseModule, ModuleCapability
from app.modules.manifest import (
    ModuleCategory,
    ModuleDependency,
    ModuleManifest,
    ModuleNavItem,
    ModulePermission,
    ModuleWidget,
)

logger = logging.getLogger(__name__)


class GatewayModule(BaseModule):
    """
    Gateway Orchestration Module for FreeSDN.

    Provides cross-platform orchestration capabilities:
    - Site Role Map (brain / limb topology)
    - Canonical VLAN / DHCP / DNS management
    - Tiered distribution engine with saga-pattern rollback
    - Continuous drift detection and remediation
    - Brownfield import wizard
    - Read-only imported-cache dashboard
    - Live passthrough diagnostics (ping, traceroute, DNS lookup)
    """

    @classmethod
    def get_manifest(cls) -> ModuleManifest:
        return ModuleManifest(
            id="gateway",
            name="Gateway Orchestration",
            version="1.0.0",
            description=(
                "Cross-platform orchestration of VLANs, DHCP, DNS, "
                "and firewall resources across heterogeneous gateways"
            ),
            author="FreeSDN Team",
            license="AGPL-3.0-only",
            category=ModuleCategory.NETWORK,
            icon="git-merge",
            color="#7C3AED",  # Purple
            # ── Dependencies ────────────────────────────────────────
            dependencies=[
                ModuleDependency(
                    module_id="firewall",
                    min_version="1.0.0",
                    optional=False,
                ),
            ],
            # ── Capabilities ────────────────────────────────────────
            capabilities=[
                ModuleCapability.GATEWAY_ORCHESTRATION,
                ModuleCapability.VLAN_DISTRIBUTION,
                ModuleCapability.SITE_ROLE_MAP,
                ModuleCapability.DRIFT_DETECTION,
                ModuleCapability.BROWNFIELD_IMPORT,
            ],
            required_capabilities=[
                ModuleCapability.FIREWALL_RULES,
            ],
            # ── Device types ────────────────────────────────────────
            device_types=[
                "firewall",
                "router",
                "utm",
                "vpn_gateway",
            ],
            # ── Permissions ─────────────────────────────────────────
            permissions=[
                ModulePermission(
                    code="gateway.view",
                    name="View Gateway Orchestration",
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
            # ── Navigation ──────────────────────────────────────────
            nav_items=[
                ModuleNavItem(
                    path="/gateway",
                    label="Gateway",
                    icon="git-merge",
                    order=36,
                    permission="gateway.view",
                ),
                ModuleNavItem(
                    path="/gateway/topology",
                    label="Topology",
                    icon="network",
                    order=1,
                    parent="/gateway",
                    permission="gateway.view",
                ),
                ModuleNavItem(
                    path="/gateway/vlans",
                    label="VLANs",
                    icon="layers",
                    order=2,
                    parent="/gateway",
                    permission="gateway.view",
                ),
                ModuleNavItem(
                    path="/gateway/dhcp",
                    label="DHCP",
                    icon="wifi",
                    order=3,
                    parent="/gateway",
                    permission="gateway.view",
                ),
                ModuleNavItem(
                    path="/gateway/dns",
                    label="DNS",
                    icon="globe",
                    order=4,
                    parent="/gateway",
                    permission="gateway.view",
                ),
                ModuleNavItem(
                    path="/gateway/distribution",
                    label="Distribution",
                    icon="send",
                    order=5,
                    parent="/gateway",
                    permission="gateway.view",
                ),
                ModuleNavItem(
                    path="/gateway/drift",
                    label="Drift",
                    icon="alert-circle",
                    order=6,
                    parent="/gateway",
                    permission="gateway.drift",
                ),
                ModuleNavItem(
                    path="/gateway/import",
                    label="Import Wizard",
                    icon="upload",
                    order=7,
                    parent="/gateway",
                    permission="gateway.import",
                ),
                ModuleNavItem(
                    path="/gateway/dashboard",
                    label="Dashboard",
                    icon="bar-chart-2",
                    order=8,
                    parent="/gateway",
                    permission="gateway.view",
                ),
                ModuleNavItem(
                    path="/gateway/reconciliation",
                    label="Reconciliation",
                    icon="refresh-cw",
                    order=9,
                    parent="/gateway",
                    permission="gateway.import",
                ),
                ModuleNavItem(
                    path="/gateway/diagnostics",
                    label="Diagnostics",
                    icon="activity",
                    order=10,
                    parent="/gateway",
                    permission="gateway.diagnostics",
                ),
            ],
            # ── Dashboard Widgets ───────────────────────────────────
            widgets=[
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
            # ── Settings ────────────────────────────────────────────
            settings_schema={
                "type": "object",
                "properties": {
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
            default_settings={
                "sync_interval_minutes": 5,
                "drift_check_interval_minutes": 15,
                "distribution_lock_ttl_seconds": 300,
                "auto_remediate_drift": False,
                "import_retention_days": 90,
            },
        )

    @property
    def manifest(self) -> ModuleManifest:
        return self.get_manifest()

    def get_router(self) -> APIRouter:
        """Return composed FastAPI router for all gateway endpoints."""
        from app.modules.gateway.api.canonical_api import router as canonical_router
        from app.modules.gateway.api.dashboard_api import router as dashboard_router
        from app.modules.gateway.api.distribution_api import router as distribution_router
        from app.modules.gateway.api.drift_api import router as drift_router
        from app.modules.gateway.api.import_api import router as import_router
        from app.modules.gateway.api.passthrough_api import router as passthrough_router
        from app.modules.gateway.api.reconciliation_api import router as reconciliation_router
        from app.modules.gateway.api.role_map_api import router as role_map_router
        from app.modules.gateway.api.template_api import router as template_router

        root = APIRouter(tags=["Gateway Orchestration"])
        root.include_router(role_map_router)
        root.include_router(canonical_router)
        root.include_router(distribution_router)
        root.include_router(import_router)
        root.include_router(drift_router)
        root.include_router(dashboard_router)
        root.include_router(passthrough_router)
        root.include_router(template_router)
        root.include_router(reconciliation_router)
        return root

    def get_models(self) -> list[type]:
        from app.modules.gateway.models import ALL_MODELS

        return list(ALL_MODELS)

    def get_tasks(self) -> dict[str, Any]:
        return {}

    def get_event_handlers(self) -> dict[str, Any]:
        """Register event handlers for cross-module integration."""
        from app.modules.gateway.events.handlers import get_handlers

        return get_handlers()

    def get_emitted_events(self):  # type: ignore[no-untyped-def]
        """Fabric event sources: the VLAN distribution lifecycle.

        This folds the network Distribution Engine into the Fabric orchestration
        plane WITHOUT touching its device-write path: distribution keeps its own
        tiered apply + compensation-plan saga (writes still ride each vendor
        adapter's ADAPTER_READ_ONLY/force gate), and merely *surfaces* its outcome
        as a first-class Fabric trigger. An operator can now wire any downstream
        Fabric operation (notify, snapshot, log, ticket) to a completed or failed
        distribution — observability/orchestration only, no new write authority.
        """
        from app.core.fabric.operations import EventSpec, OperationTier

        _dist = {
            "type": "object",
            "properties": {
                "distribution_id": {"type": "string"},
                "resource_type": {"type": "string"},
                "resource_id": {"type": "string"},
                "site_id": {"type": "string"},
                "organization_id": {"type": "string"},
                "action": {"type": "string"},
                "status": {"type": "string"},
                "steps_total": {"type": "integer"},
                "steps_succeeded": {"type": "integer"},
                "rollback_required": {"type": "boolean"},
            },
        }
        return [
            EventSpec(
                event_type="gateway.distribution.completed",
                title="VLAN distribution completed",
                description=(
                    "A canonical VLAN was distributed (or retracted) across a site's "
                    "brain + limb devices and all tiers succeeded."
                ),
                payload_schema=_dist,
                tier=OperationTier.NATIVE,
                provider_id="gateway",
            ),
            EventSpec(
                event_type="gateway.distribution.failed",
                title="VLAN distribution failed",
                description=(
                    "A VLAN distribution failed mid-plan; a compensation/rollback "
                    "plan was persisted for operator review."
                ),
                payload_schema=_dist,
                tier=OperationTier.NATIVE,
                provider_id="gateway",
            ),
        ]

    async def on_load(self) -> None:
        await super().on_load()
        logger.info("Gateway orchestration module loaded")

    async def on_unload(self) -> None:
        await super().on_unload()
        logger.info("Gateway orchestration module unloaded")

# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN Hypervisor Module - Module Class
=========================================

Module registration for the hypervisor (Proxmox VE) module.
"""

import logging
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


class HypervisorModule(BaseModule):
    """
    Hypervisor Module for FreeSDN.

    Provides Proxmox VE hypervisor management:
    - Cluster status and resource overview
    - Node monitoring and management
    - VM (QEMU) lifecycle management
    - Container (LXC) lifecycle management
    - Storage pool and content management
    - Snapshot management
    - RRD monitoring data
    - Backup job management
    """

    @classmethod
    def get_manifest(cls) -> ModuleManifest:
        return ModuleManifest(
            id="hypervisor",
            name="Hypervisor",
            version="1.0.0",
            description="Proxmox VE hypervisor and virtual machine management",
            author="FreeSDN Team",
            license="AGPL-3.0-only",
            category=ModuleCategory.SYSTEM,
            icon="server",
            color="#7C3AED",  # Purple
            dependencies=[],
            capabilities=[
                ModuleCapability.DEVICE_MANAGEMENT,
                ModuleCapability.DEVICE_BACKUP,
                ModuleCapability.BULK_OPERATIONS,
            ],
            required_capabilities=[],
            device_types=["hypervisor"],
            permissions=[
                ModulePermission(
                    code="hypervisor.view",
                    name="View Hypervisor",
                    description="View cluster, nodes, VMs, and containers",
                    resource="hypervisor",
                    action="read",
                ),
                ModulePermission(
                    code="hypervisor.manage_vms",
                    name="Manage VMs",
                    description="Start, stop, reboot VMs and containers",
                    resource="vm",
                    action="update",
                ),
                ModulePermission(
                    code="hypervisor.manage_snapshots",
                    name="Manage Snapshots",
                    description="Create, rollback, and delete snapshots",
                    resource="snapshot",
                    action="update",
                ),
                ModulePermission(
                    code="hypervisor.manage_backups",
                    name="Manage Backups",
                    description="View and trigger backup jobs",
                    resource="backup",
                    action="update",
                ),
                ModulePermission(
                    code="hypervisor.manage_nodes",
                    name="Manage Nodes",
                    description="Reboot nodes and manage node settings",
                    resource="node",
                    action="update",
                ),
            ],
            nav_items=[
                ModuleNavItem(
                    path="/hypervisor",
                    label="Hypervisor",
                    icon="server",
                    order=30,
                    permission="hypervisor.view",
                ),
                ModuleNavItem(
                    path="/hypervisor/nodes",
                    label="Nodes",
                    icon="cpu",
                    order=1,
                    parent="/hypervisor",
                    permission="hypervisor.view",
                ),
                ModuleNavItem(
                    path="/hypervisor/vms",
                    label="Virtual Machines",
                    icon="monitor",
                    order=2,
                    parent="/hypervisor",
                    permission="hypervisor.view",
                ),
                ModuleNavItem(
                    path="/hypervisor/containers",
                    label="Containers",
                    icon="box",
                    order=3,
                    parent="/hypervisor",
                    permission="hypervisor.view",
                ),
                ModuleNavItem(
                    path="/hypervisor/storage",
                    label="Storage",
                    icon="hard-drive",
                    order=4,
                    parent="/hypervisor",
                    permission="hypervisor.view",
                ),
            ],
            widgets=[
                ModuleWidget(
                    id="hypervisor_overview",
                    name="Hypervisor Overview",
                    description="Cluster health and resource usage summary",
                    component="HypervisorOverviewWidget",
                    default_size="medium",
                    refresh_interval=30,
                    permission="hypervisor.view",
                ),
                ModuleWidget(
                    id="vm_status",
                    name="VM Status",
                    description="Running/stopped VM and container counts",
                    component="VMStatusWidget",
                    default_size="small",
                    refresh_interval=30,
                    permission="hypervisor.view",
                ),
            ],
            settings_schema={
                "type": "object",
                "properties": {
                    "sync_interval": {
                        "type": "integer",
                        "minimum": 30,
                        "maximum": 3600,
                        "default": 120,
                        "description": "Node sync interval in seconds",
                    },
                    "show_templates": {
                        "type": "boolean",
                        "default": False,
                        "description": "Show VM templates in the list",
                    },
                },
            },
            default_settings={
                "sync_interval": 120,
                "show_templates": False,
            },
        )

    @property
    def manifest(self) -> ModuleManifest:
        return self.get_manifest()

    _router: APIRouter | None = None

    def get_router(self) -> APIRouter:
        if HypervisorModule._router is None:
            from app.modules.hypervisor.api import router

            HypervisorModule._router = router
        return HypervisorModule._router

    def get_models(self) -> list[type]:
        from app.modules.hypervisor.models import ProxmoxNode, VirtualMachine

        return [ProxmoxNode, VirtualMachine]

    def get_operations(self):  # type: ignore[no-untyped-def]
        """Fabric operations: Proxmox VM actions as wiring TARGETS.

        All are device WRITES, so the Fabric routes them through the staged-
        change pipeline: invoking them STAGES a pending change (audited, under
        the Connection author's identity) that an operator must sign off to
        apply — the Fabric never auto-applies a device write. Each maps to a
        real staging applier (``GatewayProxmoxSnapshotService`` /
        ``GatewayProxmoxVmService``) so it actually applies on sign-off.

        These make "when <something> happens → snapshot / power a Proxmox VM"
        authorable as a Connection — e.g. the OPNsense→Proxmox scenario wires a
        ``controller.change.applied`` (vendor=opnsense) source to
        ``hypervisor.vm.snapshot``.
        """
        from app.core.fabric.operations import Operation, OperationTier

        _vm_target = {
            "controller_id": {
                "type": "string",
                "format": "uuid",
                "description": "Proxmox Controller (org-scoped, validated)",
            },
            "node": {"type": "string"},
            "vmid": {"type": "integer"},
            "vm_type": {"type": "string", "enum": ["qemu", "lxc"], "default": "qemu"},
        }
        ops = [
            Operation(
                id="hypervisor.vm.snapshot",
                title="Snapshot a Proxmox VM",
                description="Create a VM/container snapshot (stages; operator sign-off to apply).",
                input_schema={
                    "type": "object",
                    "properties": {
                        **_vm_target,
                        "snapname": {"type": "string"},
                        "description": {"type": "string"},
                    },
                    "required": ["controller_id", "node", "vmid", "snapname"],
                },
                permission="hypervisor.manage_snapshots",
                write=True,
                # Routes to the live proxmox.snapshot.create applier
                # (GatewayProxmoxSnapshotService) on operator sign-off.
                feature="proxmox.snapshot.create",
                tier=OperationTier.NATIVE,
                provider_id="hypervisor",
            ),
        ]
        # Power verbs as DISCRETE ops — each maps 1:1 to a real proxmox.vm.<verb>
        # applier (GatewayProxmoxVmService._APPLY), so a single static feature
        # routes correctly (a one-op-with-an-action param can't, since the
        # staging feature carries the verb).
        for verb, label in (
            ("start", "Start"),
            ("stop", "Stop"),
            ("shutdown", "Shut down"),
            ("reboot", "Reboot"),
        ):
            ops.append(
                Operation(
                    id=f"hypervisor.vm.{verb}",
                    title=f"{label} a Proxmox VM",
                    description=f"{label} a VM/container (stages; operator sign-off to apply).",
                    input_schema={
                        "type": "object",
                        "properties": dict(_vm_target),
                        "required": ["controller_id", "node", "vmid"],
                    },
                    permission="hypervisor.manage_vms",
                    write=True,
                    feature=f"proxmox.vm.{verb}",
                    tier=OperationTier.NATIVE,
                    provider_id="hypervisor",
                )
            )

        # Additional VM lifecycle verbs (suspend/resume) — vm-target only, all
        # map 1:1 to a real proxmox.vm.<verb> applier (create-semantics).
        for verb, label in (("suspend", "Suspend"), ("resume", "Resume")):
            ops.append(
                Operation(
                    id=f"hypervisor.vm.{verb}",
                    title=f"{label} a Proxmox VM",
                    description=f"{label} a VM/container (stages; operator sign-off to apply).",
                    input_schema={
                        "type": "object",
                        "properties": dict(_vm_target),
                        "required": ["controller_id", "node", "vmid"],
                    },
                    permission="hypervisor.manage_vms",
                    write=True,
                    feature=f"proxmox.vm.{verb}",
                    tier=OperationTier.NATIVE,
                    provider_id="hypervisor",
                )
            )

        # Migrate a VM/CT to another node (load-balancing / maintenance drain).
        ops.append(
            Operation(
                id="hypervisor.vm.migrate",
                title="Migrate a Proxmox VM",
                description="Migrate a VM/container to another node (stages; sign-off to apply).",
                input_schema={
                    "type": "object",
                    "properties": {
                        **_vm_target,
                        "target_node": {"type": "string"},
                        "online": {"type": "boolean", "default": True},
                    },
                    "required": ["controller_id", "node", "vmid", "target_node"],
                },
                permission="hypervisor.manage_vms",
                write=True,
                feature="proxmox.vm.migrate",
                tier=OperationTier.NATIVE,
                provider_id="hypervisor",
            )
        )

        # Clone a VM/CT to a new VMID (provision-from-template automations).
        ops.append(
            Operation(
                id="hypervisor.vm.clone",
                title="Clone a Proxmox VM",
                description="Clone a VM/container to a new VMID (stages; sign-off to apply).",
                input_schema={
                    "type": "object",
                    "properties": {
                        **_vm_target,
                        "newid": {"type": "integer"},
                        "name": {"type": "string"},
                    },
                    "required": ["controller_id", "node", "vmid", "newid"],
                },
                permission="hypervisor.manage_vms",
                write=True,
                feature="proxmox.vm.clone",
                tier=OperationTier.NATIVE,
                provider_id="hypervisor",
            )
        )

        # Node maintenance — reboot/shutdown a whole cluster node (manage_nodes).
        for verb, label in (("reboot", "Reboot"), ("shutdown", "Shut down")):
            ops.append(
                Operation(
                    id=f"hypervisor.node.{verb}",
                    title=f"{label} a Proxmox node",
                    description=f"{label} a cluster node (stages; operator sign-off to apply).",
                    input_schema={
                        "type": "object",
                        "properties": {
                            "controller_id": {"type": "string", "format": "uuid"},
                            "node": {"type": "string"},
                        },
                        "required": ["controller_id", "node"],
                    },
                    permission="hypervisor.manage_nodes",
                    write=True,
                    feature=f"proxmox.node.{verb}",
                    tier=OperationTier.NATIVE,
                    provider_id="hypervisor",
                )
            )
        return ops

    def get_emitted_events(self):  # type: ignore[no-untyped-def]
        """Fabric event sources emitted by the hypervisor.poll_health monitor on
        Proxmox cluster state transitions — this is what makes "something happens
        ON the cluster → trigger X" wireable (e.g. hypervisor.node.offline →
        fabric.notify, or hypervisor.cluster.inquorate → snapshot critical VMs).

        Built to match what tasks/hypervisor.py actually publishes, so the
        advertised triggers never drift from what fires.
        """
        from app.core.fabric.operations import EventSpec, OperationTier

        _p = {
            "type": "object",
            "properties": {
                "controller_id": {"type": "string"},
                "controller_name": {"type": "string"},
                "node": {"type": "string"},
                "node_count": {"type": "integer"},
            },
        }

        def _ev(et: str, title: str, desc: str) -> Any:
            return EventSpec(
                event_type=et,
                title=title,
                description=desc,
                payload_schema=_p,
                tier=OperationTier.NATIVE,
                provider_id="hypervisor",
            )

        return [
            _ev("hypervisor.node.offline", "Node offline", "A Proxmox node stopped responding."),
            _ev("hypervisor.node.online", "Node online", "A Proxmox node became reachable again."),
            _ev(
                "hypervisor.cluster.inquorate",
                "Cluster lost quorum",
                "The Proxmox cluster lost quorum (HA/fencing risk).",
            ),
            _ev(
                "hypervisor.cluster.quorate",
                "Cluster regained quorum",
                "The Proxmox cluster regained quorum.",
            ),
            _ev(
                "hypervisor.controller.unreachable",
                "Cluster unreachable",
                "The Proxmox cluster API stopped responding.",
            ),
            _ev(
                "hypervisor.controller.online",
                "Cluster online",
                "The Proxmox cluster API became reachable again.",
            ),
        ]

    def get_device_sources(self) -> list[DeviceSource]:
        from app.modules.hypervisor.models import ProxmoxNode

        return [
            DeviceSource(
                model=ProxmoxNode,
                device_type="hypervisor",
                external_id_prefix="pve",
                field_map={
                    "name": "node_name",
                    "manufacturer": "",
                    "model": "",
                    "firmware_version": "pve_version",
                    "ip_address": "ip_address",
                    "last_seen": "last_seen",
                    "site_id": "site_id",
                },
                status_field="status",
                status_map={"online": "online", "offline": "offline"},
                default_status="unknown",
                default_manufacturer="Proxmox",
            ),
        ]

    async def pre_device_sync(self, session: Any) -> None:
        """Refresh ProxmoxNode table from live Proxmox controllers before sync."""
        from sqlalchemy import select

        from app.models.core import Controller

        pve_controllers = (
            (
                await session.execute(
                    select(Controller).where(
                        Controller.controller_type == "proxmox",
                        Controller.is_active.is_(True),
                        Controller.deleted_at.is_(None),
                    )
                )
            )
            .scalars()
            .all()
        )

        if not pve_controllers:
            return

        from app.modules.hypervisor.service import HypervisorService

        svc = HypervisorService(session)
        for ctrl in pve_controllers:
            # Isolate each controller in its own SAVEPOINT. An unreachable
            # or misconfigured controller (e.g. a Proxmox host pointed at
            # the wrong IP) raises mid-flush, which would otherwise poison
            # the shared session and silently drop the nodes synced for the
            # HEALTHY controllers too. With a per-controller savepoint, a
            # failure rolls back only that controller's partial work and
            # the rest still persist.
            try:
                async with session.begin_nested():
                    count = await svc.sync_nodes(
                        ctrl.id,
                        site_id=ctrl.site_id,
                        controller=ctrl,
                    )
                logger.debug(
                    "Synced %d Proxmox nodes from controller %s",
                    count,
                    ctrl.name,
                )
            except Exception:
                logger.debug(
                    "Failed to sync nodes from controller %s",
                    ctrl.name,
                    exc_info=True,
                )
        await session.flush()

    async def on_load(self) -> None:
        await super().on_load()
        logger.info("Hypervisor module loaded")

    async def on_unload(self) -> None:
        await super().on_unload()
        logger.info("Hypervisor module unloaded")

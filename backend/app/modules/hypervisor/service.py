# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN Hypervisor Module - Service Layer
==========================================

Business logic for hypervisor operations.
Bridges API endpoints to the Proxmox adapter.
"""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.base import AdapterResult
from app.adapters.proxmox.adapter import ProxmoxAdapter
from app.adapters.proxmox.models import (
    ProxmoxClusterStatus,
    ProxmoxNodeInfo,
    ProxmoxVM,
)
from app.modules.hypervisor import dashboard_metrics
from app.modules.hypervisor.models import ProxmoxNode
from app.modules.hypervisor.schemas import (
    AlertHysteresisConfig,
    BackupAgeResponse,
    BackupJobResponse,
    CephDetailResponse,
    CephStatusResponse,
    ClusterNodeSummary,
    ClusterResourceItem,
    ClusterStatusResponse,
    ConsoleProxyResponse,
    DiskInfoResponse,
    FirewallRuleResponse,
    FleetClusterSummary,
    FleetDashboardResponse,
    FleetTaskStatistics,
    HAGroupResponse,
    HAResourceResponse,
    HypervisorDashboardResponse,
    HysteresisState,
    NetworkInterfaceResponse,
    NextVMIDResponse,
    NodeResponse,
    NodeServiceResponse,
    ResourcePoolResponse,
    RRDPointResponse,
    SnapshotResponse,
    StorageContentItem,
    StorageResponse,
    SyslogEntry,
    TaskDetailResponse,
    TaskLogEntry,
    TaskResponse,
    TaskStatistics,
    VMActionResponse,
    VMResponse,
)

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════
# LTTB DOWNSAMPLING
# ═══════════════════════════════════════════════════════════════════════════


def _lttb_downsample(
    data: list[dict],
    target_points: int,
    time_key: str = "time",
    value_key: str = "cpu",
) -> list[dict]:
    """Largest-Triangle-Three-Buckets (LTTB) downsampling.

    Reduces a time-series to *target_points* while preserving the visual
    shape.  Uses *value_key* (default ``cpu``) as the primary metric for
    triangle-area calculations.  If ``len(data) <= target_points``, the
    original list is returned unchanged.
    """
    n = len(data)
    if n <= target_points or target_points < 3:
        return data

    # Always keep first and last points
    sampled: list[dict] = [data[0]]
    bucket_size = (n - 2) / (target_points - 2)

    a_index = 0  # index of the previously selected point

    for i in range(1, target_points - 1):
        # Calculate bucket boundaries
        bucket_start = int((i - 1) * bucket_size) + 1
        bucket_end = int(i * bucket_size) + 1
        bucket_end = min(bucket_end, n - 1)

        next_bucket_start = int(i * bucket_size) + 1
        next_bucket_end = int((i + 1) * bucket_size) + 1
        next_bucket_end = min(next_bucket_end, n)

        # Average point of next bucket (used as the third vertex)
        avg_x = 0.0
        avg_y = 0.0
        count = next_bucket_end - next_bucket_start
        if count > 0:
            for j in range(next_bucket_start, next_bucket_end):
                avg_x += float(data[j].get(time_key, 0) or 0)
                avg_y += float(data[j].get(value_key, 0) or 0)
            avg_x /= count
            avg_y /= count

        # Point A (previously selected)
        a_x = float(data[a_index].get(time_key, 0) or 0)
        a_y = float(data[a_index].get(value_key, 0) or 0)

        # Find the point in the current bucket with the largest triangle area
        max_area = -1.0
        max_idx = bucket_start
        for j in range(bucket_start, bucket_end):
            bx = float(data[j].get(time_key, 0) or 0)
            by = float(data[j].get(value_key, 0) or 0)
            # Triangle area (doubled, sign doesn't matter)
            area = abs((a_x - avg_x) * (by - a_y) - (a_x - bx) * (avg_y - a_y))
            if area > max_area:
                max_area = area
                max_idx = j

        sampled.append(data[max_idx])
        a_index = max_idx

    sampled.append(data[-1])
    return sampled


# ═══════════════════════════════════════════════════════════════════════════
# ALERT HYSTERESIS
# ═══════════════════════════════════════════════════════════════════════════


def evaluate_with_hysteresis(
    current_value: float,
    threshold: float,
    operator: str,
    state: HysteresisState,
    config: AlertHysteresisConfig,
) -> tuple[HysteresisState, bool, bool]:
    """Evaluate a metric against a threshold with hysteresis.

    Returns ``(new_state, should_fire, should_resolve)``.

    Operators: gt, gte, lt, lte, eq.
    """
    _ops = {
        "gt": lambda v, t: v > t,
        "gte": lambda v, t: v >= t,
        "lt": lambda v, t: v < t,
        "lte": lambda v, t: v <= t,
        "eq": lambda v, t: v == t,
    }
    cmp = _ops.get(operator, _ops["gt"])
    breached = cmp(current_value, threshold)

    now = datetime.now(tz=UTC)

    if breached:
        new_breach = state.breach_count + 1
        new_state = HysteresisState(
            breach_count=new_breach,
            normal_count=0,
            is_fired=state.is_fired,
            last_value=current_value,
            last_checked=now,
        )
        should_fire = new_breach >= config.fire_after_consecutive and not state.is_fired
        if should_fire:
            new_state.is_fired = True
        return new_state, should_fire, False
    else:
        new_normal = state.normal_count + 1
        new_state = HysteresisState(
            breach_count=0,
            normal_count=new_normal,
            is_fired=state.is_fired,
            last_value=current_value,
            last_checked=now,
        )
        should_resolve = new_normal >= config.resolve_after_consecutive and state.is_fired
        if should_resolve:
            new_state.is_fired = False
        return new_state, False, should_resolve


# ═══════════════════════════════════════════════════════════════════════════
# MODULE-LEVEL CACHING & CONCURRENCY LIMITS
# ═══════════════════════════════════════════════════════════════════════════

# Short-lived observations: {controller_id: (response, collection start, config digest)}
_dashboard_cache: dict[str, tuple[HypervisorDashboardResponse, float, str]] = {}
_DASHBOARD_TTL = 10.0  # seconds
_DASHBOARD_READ_TIMEOUT = 15.0
_MAX_DASHBOARD_CACHE_SIZE = 100

# Fleet concurrency limit (max 5 simultaneous Proxmox connections)
_fleet_semaphore = asyncio.Semaphore(5)
_FLEET_TIMEOUT = 20.0  # seconds per-cluster timeout


# ═══════════════════════════════════════════════════════════════════════════
# DIRECT-PATH CATASTROPHIC GUARD
# ═══════════════════════════════════════════════════════════════════════════
#
# Power actions now use hypervisor_power and the staging chokepoint. Other
# writes below remain on the DIRECT (un-staged) path: unlike the staging
# applier (app/services/adapter_proxmox_vm.py) it runs NO catastrophic
# pre-flight (adapter_proxmox_preflight.assess/gate) and carries NO
# ``confirmed=true`` second factor. Under the default ``ADAPTER_READ_ONLY=True``
# every write here is already refused by the Proxmox client read-only gate; but
# once an operator clears that flag to use staging, the Proxmox client only
# blocks ``not force`` writes *while read-only is on* — so a write-enabled
# deployment would let an irreversible direct op fire here with no pre-flight.
#
# A handful of adapter methods (delete_vm / reboot_node / shutdown_node) already
# close this by raising UNCONDITIONALLY unless ``force=True`` (which only the
# staging applier passes). The CATASTROPHIC ops below — those the pre-flight
# classifier (adapter_proxmox_preflight._FEATURE_RISK) marks irreversible and
# that have NO adapter-level guard — are refused on the direct path and
# the operator is steered to the staged endpoints (which DO run the pre-flight +
# require confirmed=true). We deliberately scope this to the pre-flight's
# CATASTROPHIC set only: DESTRUCTIVE-but-recoverable ops (migrate, snapshot
# delete) and SAFE ops (create/clone/resize/config-update/template/power
# start-stop, reads, DB sync) are NOT blocked — the staged pre-flight gate
# itself only requires confirmation for CATASTROPHIC, so blocking them here
# would refuse legitimate flows the pre-flight would otherwise allow through.
_DIRECT_BLOCKED_OPS: dict[str, str] = {
    # CLUSTER/STORAGE-scoped catastrophic ops: staging-only. Guest-scoped destructive
    # ops (VM/CT delete, snapshot rollback) are allowed on the direct path with an
    # explicit confirmed=true second factor instead (and still honor read-only).
    "delete_storage_volume": "storage volume delete (irreversible)",
    # Backup restore OVERWRITES a live guest; prune PERMANENTLY deletes backup
    # archives. The staged proxmox.backup.* path runs the catastrophic pre-flight,
    # requires confirmed=true, and validates the archive volid allowlist
    # (_validate_archive). The direct path had NONE of that, so refuse it here and
    # steer operators to staging.
    "restore_backup": "backup restore (overwrites a guest)",
    "prune_backups": "backup prune (irreversible archive deletion)",
}


def _refuse_direct_catastrophic(op: str) -> None:
    """Block an irreversible/catastrophic op on the un-staged direct path.

    Raises ``ValueError`` (the hypervisor API maps this to HTTP 400) with
    guidance to use the staged endpoints, which run the catastrophic
    pre-flight and require ``confirmed=true``. Mirrors the adapter-level
    force-gate already enforced on delete_vm / reboot_node /
    shutdown_node, closing the same hole for the remaining catastrophic ops
    when ``ADAPTER_READ_ONLY=false``.
    """
    label = _DIRECT_BLOCKED_OPS.get(op, op)
    raise ValueError(
        f"{label} is catastrophic and cannot be applied on the direct path; "
        "stage it via the staged adapter endpoints (which run the pre-flight "
        "and require confirmed=true) to proceed."
    )


class HypervisorService:
    """Service for Proxmox hypervisor operations."""

    def __init__(self, db: AsyncSession):
        self.db = db

    # ═══════════════════════════════════════════════════════════════════════
    # ADAPTER CREATION
    # ═══════════════════════════════════════════════════════════════════════

    @staticmethod
    async def _get_adapter(controller: Any) -> ProxmoxAdapter:
        """Create a Proxmox adapter from a controller record."""
        from app.core.crypto import decrypt_credential

        config = controller.config or {}

        # Determine auth method
        token_id = config.get("token_id", "")
        token_secret_raw = config.get("token_secret", "")
        username = config.get("username", controller.username or "")
        password_raw = config.get("password", "")

        # Decrypt secrets
        token_secret = decrypt_credential(token_secret_raw) if token_secret_raw else ""
        password = decrypt_credential(password_raw) if password_raw else ""

        adapter = ProxmoxAdapter(
            host=controller.host,
            username=username,
            password=password,
            port=controller.port or 8006,
            use_ssl=controller.use_ssl if hasattr(controller, "use_ssl") else True,
            verify_ssl=controller.verify_ssl if hasattr(controller, "verify_ssl") else False,
            token_id=token_id,
            token_secret=token_secret,
            realm=config.get("realm", "pam"),
        )
        connected = await adapter.connect()
        if not connected:
            raise ConnectionError(f"Failed to connect to Proxmox at {controller.host}")
        return adapter

    async def preflight_preview(
        self,
        controller: Any,
        feature: str,
        operation: str,
        payload: dict[str, Any] | None,
    ) -> dict[str, Any]:
        """Read-only impact assessment for a prospective staged write (dry-run).

        Connects a (read-only) adapter and runs the pre-flight assessor:
        classifies destructiveness and runs READ-ONLY device checks (running
        guests on a node, VM power state, volume size). Mutates NOTHING —
        returns the assessment so an operator can preview impact and learn
        whether the write will require ``confirmed=true`` before staging it.
        """
        from app.services.adapter_proxmox_preflight import assess

        async with await self._get_adapter(controller) as adapter:
            result = await assess(feature, operation, payload or {}, adapter=adapter)
        return result.to_dict()

    # ═══════════════════════════════════════════════════════════════════════
    # DASHBOARD
    # ═══════════════════════════════════════════════════════════════════════

    async def get_dashboard(self, controller: Any) -> HypervisorDashboardResponse:
        """Return an explicitly aged observation; never extend TTL on cache hits."""
        ctrl_id = str(controller.id)
        fingerprint = dashboard_metrics.controller_fingerprint(controller)
        now = time.monotonic()
        cached = _dashboard_cache.get(ctrl_id)
        if cached and cached[2] == fingerprint and 0 <= now - cached[1] < _DASHBOARD_TTL:
            result = cached[0].model_copy(deep=True)
            result.observation_age_seconds = round(now - cached[1], 3)
            result.served_at = datetime.now(UTC)
            return result
        # An expired/config-changed entry must not survive a failed refresh.
        _dashboard_cache.pop(ctrl_id, None)
        result = await self._get_dashboard_uncached(controller)
        result.observation_age_seconds = round(max(0.0, time.monotonic() - now), 3)
        result.served_at = datetime.now(UTC)
        if len(_dashboard_cache) >= _MAX_DASHBOARD_CACHE_SIZE:
            oldest_keys = sorted(_dashboard_cache, key=lambda key: _dashboard_cache[key][1])[:10]
            for key in oldest_keys:
                _dashboard_cache.pop(key, None)
        _dashboard_cache[ctrl_id] = (result.model_copy(deep=True), now, fingerprint)
        return result

    async def _get_dashboard_uncached(self, controller: Any) -> HypervisorDashboardResponse:
        started = datetime.now(UTC)
        async with await self._get_adapter(controller) as adapter:
            try:
                cluster, resources, ha = await asyncio.wait_for(
                    asyncio.gather(
                        adapter.get_cluster_status(),
                        adapter.get_cluster_resources(),
                        adapter.get_ha_status(),
                        return_exceptions=True,
                    ),
                    timeout=_DASHBOARD_READ_TIMEOUT,
                )
            except TimeoutError as exc:
                raise ConnectionError("Proxmox dashboard read deadline exceeded") from exc
            for label, result in (("cluster status", cluster), ("resources", resources)):
                if not isinstance(result, AdapterResult) or not result.success:
                    raise ConnectionError(f"Proxmox {label} is unavailable")
            if not isinstance(cluster.data, ProxmoxClusterStatus) or not isinstance(
                resources.data, list
            ):
                raise ConnectionError("Proxmox dashboard response is malformed")
            return dashboard_metrics.aggregate(
                str(controller.id),
                cluster.data,
                resources.data,
                ha.data if isinstance(ha, AdapterResult) and ha.success else None,
                started,
            )

    # ═══════════════════════════════════════════════════════════════════════
    # CLUSTER
    # ═══════════════════════════════════════════════════════════════════════

    async def get_cluster_status(self, controller: Any) -> ClusterStatusResponse:
        """Get cluster status."""
        async with await self._get_adapter(controller) as adapter:
            result = await adapter.get_cluster_status()
            if not result.success:
                raise ValueError(result.error or "Failed to get cluster status")

            cs: ProxmoxClusterStatus = result.data
            return ClusterStatusResponse(
                name=cs.name,
                quorate=cs.quorate,
                node_count=cs.node_count,
                version=cs.version,
                nodes=[
                    ClusterNodeSummary(node=n.node, status=n.status, ip=n.ip, level=n.level)
                    for n in cs.nodes
                ],
            )

    async def get_cluster_resources(
        self, controller: Any, resource_type: str | None = None
    ) -> list[ClusterResourceItem]:
        """Get cluster resources."""
        async with await self._get_adapter(controller) as adapter:
            result = await adapter.get_cluster_resources(resource_type)
            if not result.success:
                return []

            items = []
            for r in result.data or []:
                if not isinstance(r, dict):
                    continue
                items.append(
                    ClusterResourceItem(
                        id=str(r.get("id", "")),
                        type=r.get("type", ""),
                        node=r.get("node", ""),
                        status=r.get("status", ""),
                        name=r.get("name", ""),
                        vmid=r.get("vmid"),
                        maxcpu=r.get("maxcpu"),
                        cpu=r.get("cpu"),
                        maxmem=r.get("maxmem"),
                        mem=r.get("mem"),
                        maxdisk=r.get("maxdisk"),
                        disk=r.get("disk"),
                        uptime=r.get("uptime"),
                        template=bool(r.get("template", 0)),
                    )
                )
            return items

    # ═══════════════════════════════════════════════════════════════════════
    # NODES
    # ═══════════════════════════════════════════════════════════════════════

    async def get_nodes(self, controller: Any) -> list[NodeResponse]:
        """Get all nodes with status (enriched with per-node detail)."""
        async with await self._get_adapter(controller) as adapter:
            result = await adapter.get_nodes()
            if not result.success:
                return []

            nodes = result.data or []

            # Enrich with per-node status (cpu_model, pve_version, kernel_version)
            async def _enrich(n: Any) -> Any:
                try:
                    detail = await adapter.get_node_status(n.node)
                    if detail.success and detail.data:
                        d = detail.data
                        n.cpu_model = d.cpu_model or n.cpu_model
                        n.pve_version = d.pve_version or n.pve_version
                        n.kernel_version = d.kernel_version or n.kernel_version
                except Exception:
                    pass
                return n

            nodes = await asyncio.gather(*[_enrich(n) for n in nodes], return_exceptions=True)

            return [self._node_to_response(n) for n in nodes if not isinstance(n, BaseException)]

    async def get_node_detail(self, controller: Any, node_name: str) -> NodeResponse:
        """Get detailed node status."""
        async with await self._get_adapter(controller) as adapter:
            result = await adapter.get_node_status(node_name)
            if not result.success:
                raise ValueError(result.error or f"Node '{node_name}' not found")
            return self._node_to_response(result.data)

    # ═══════════════════════════════════════════════════════════════════════
    # VMs
    # ═══════════════════════════════════════════════════════════════════════

    async def get_all_vms(self, controller: Any, vm_type: str | None = None) -> list[VMResponse]:
        """Get all VMs/containers across all nodes."""
        async with await self._get_adapter(controller) as adapter:
            result = await adapter.get_all_vms()
            if not result.success:
                return []

            vms = [
                self._vm_to_response(v)
                for v in (result.data or [])
                if vm_type is None or v.vm_type == vm_type
            ]
            return vms

    async def get_node_vms(self, controller: Any, node: str) -> list[VMResponse]:
        """Get VMs on a specific node."""
        async with await self._get_adapter(controller) as adapter:
            result = await adapter.get_vms(node)
            if not result.success:
                return []
            return [self._vm_to_response(v) for v in (result.data or [])]

    async def get_node_containers(self, controller: Any, node: str) -> list[VMResponse]:
        """Get containers on a specific node."""
        async with await self._get_adapter(controller) as adapter:
            result = await adapter.get_containers(node)
            if not result.success:
                return []
            return [self._vm_to_response(v) for v in (result.data or [])]

    async def get_vm_config(
        self, controller: Any, node: str, vmid: int, *, vm_type: str = "qemu"
    ) -> dict:
        """Get VM/container configuration."""
        async with await self._get_adapter(controller) as adapter:
            if vm_type == "lxc":
                result = await adapter.get_container_config(node, vmid)
            else:
                result = await adapter.get_vm_config(node, vmid)
            if not result.success:
                raise ValueError(result.error or "Failed to get VM config")
            return result.data or {}

    async def vm_action(
        self,
        controller: Any,
        node: str,
        vmid: int,
        action: str,
        vm_type: str = "qemu",
        *,
        current_user: Any = None,
        request_id: UUID | None = None,
        force: bool = False,
    ):
        """Submit one power intent through the durable staging claim."""
        from fastapi import HTTPException

        from app.services.hypervisor_power import HypervisorPowerService

        if current_user is None or request_id is None:
            raise HTTPException(400, detail="Power actions require an actor and request_id")
        return await HypervisorPowerService(self.db, current_user).execute(
            controller.id,
            node,
            vmid,
            action,
            vm_type,
            request_id=request_id,
            force=force,
        )

    # ═══════════════════════════════════════════════════════════════════════
    # SNAPSHOTS
    # ═══════════════════════════════════════════════════════════════════════

    async def get_snapshots(
        self, controller: Any, node: str, vmid: int, vm_type: str = "qemu"
    ) -> list[SnapshotResponse]:
        """Get snapshots for a VM or container."""
        async with await self._get_adapter(controller) as adapter:
            result = await adapter.get_snapshots(node, vmid, vm_type)
            if not result.success:
                return []
            return [
                SnapshotResponse(
                    name=s.name,
                    description=s.description,
                    created_at=s.created_at,
                    vmstate=s.vmstate,
                    parent=s.parent,
                )
                for s in (result.data or [])
            ]

    async def create_snapshot(
        self,
        controller: Any,
        node: str,
        vmid: int,
        snapname: str,
        description: str = "",
        vm_type: str = "qemu",
        vmstate: bool = False,
        *,
        current_user: Any = None,
        request_id: UUID | None = None,
        force: bool = False,
    ):
        from fastapi import HTTPException

        from app.services.hypervisor_operations import HypervisorOperationService

        if current_user is None or request_id is None:
            raise HTTPException(400, detail="Snapshot requires an actor and request_id")
        return await HypervisorOperationService(self.db, current_user).snapshot(
            controller.id,
            node,
            vmid,
            vm_type,
            "create",
            snapname,
            request_id=request_id,
            force=force,
            description=description,
            vmstate=vmstate,
        )

    async def rollback_snapshot(
        self,
        controller: Any,
        node: str,
        vmid: int,
        snapname: str,
        vm_type: str = "qemu",
        *,
        confirmed: bool = False,
        current_user: Any = None,
        request_id: UUID | None = None,
        force: bool = False,
    ):
        from fastapi import HTTPException

        from app.adapters.exceptions import AdapterConfirmationRequiredError
        from app.services.hypervisor_operations import HypervisorOperationService

        if not confirmed:
            raise AdapterConfirmationRequiredError(
                "Rolling back a snapshot discards guest state; confirmed=true is required",
                adapter_id="proxmox",
            )
        if current_user is None or request_id is None:
            raise HTTPException(400, detail="Snapshot requires an actor and request_id")
        return await HypervisorOperationService(self.db, current_user).snapshot(
            controller.id,
            node,
            vmid,
            vm_type,
            "rollback",
            snapname,
            request_id=request_id,
            force=force,
            confirmed=confirmed,
        )

    async def delete_snapshot(
        self,
        controller: Any,
        node: str,
        vmid: int,
        snapname: str,
        vm_type: str = "qemu",
        *,
        confirmed: bool = False,
        current_user: Any = None,
        request_id: UUID | None = None,
        force: bool = False,
    ):
        from fastapi import HTTPException

        from app.services.hypervisor_operations import HypervisorOperationService

        if current_user is None or request_id is None:
            raise HTTPException(400, detail="Snapshot requires an actor and request_id")
        return await HypervisorOperationService(self.db, current_user).snapshot(
            controller.id,
            node,
            vmid,
            vm_type,
            "delete",
            snapname,
            request_id=request_id,
            force=force,
            confirmed=confirmed,
        )

    # ═══════════════════════════════════════════════════════════════════════
    # STORAGE
    # ═══════════════════════════════════════════════════════════════════════

    async def get_storage(self, controller: Any, node: str) -> list[StorageResponse]:
        """Get storage pools."""
        async with await self._get_adapter(controller) as adapter:
            result = await adapter.get_storage(node)
            if not result.success:
                return []
            return [
                StorageResponse(
                    storage=s.storage,
                    node=s.node,
                    storage_type=s.storage_type,
                    content=s.content,
                    total=s.total,
                    used=s.used,
                    available=s.avail,
                    used_percent=s.used_percent,
                    active=s.active,
                    shared=s.shared,
                    enabled=s.enabled,
                )
                for s in (result.data or [])
            ]

    async def get_storage_content(
        self,
        controller: Any,
        node: str,
        storage: str,
        content_type: str | None = None,
        vmid: int | None = None,
    ) -> list[StorageContentItem]:
        """Get storage content."""
        async with await self._get_adapter(controller) as adapter:
            result = await adapter.get_storage_content(
                node,
                storage,
                content_type,
                vmid=vmid,
            )
            if not result.success:
                return []
            items = []
            for c in result.data or []:
                if not isinstance(c, dict):
                    continue
                items.append(
                    StorageContentItem(
                        volid=c.get("volid", ""),
                        content=c.get("content", ""),
                        format=c.get("format", ""),
                        size=int(c.get("size", 0)),
                        ctime=int(c.get("ctime", 0)),
                        vmid=c.get("vmid"),
                        notes=c.get("notes"),
                    )
                )
            return items

    # ═══════════════════════════════════════════════════════════════════════
    # NETWORK
    # ═══════════════════════════════════════════════════════════════════════

    async def get_node_network(self, controller: Any, node: str) -> list[NetworkInterfaceResponse]:
        """Get node network interfaces."""
        async with await self._get_adapter(controller) as adapter:
            result = await adapter.get_node_network(node)
            if not result.success:
                return []
            return [
                NetworkInterfaceResponse(
                    iface=i.iface,
                    node=i.node,
                    type=i.iface_type,
                    active=i.active,
                    address=i.address,
                    netmask=i.netmask,
                    gateway=i.gateway,
                    cidr=i.cidr,
                    bridge_ports=i.bridge_ports,
                    bond_slaves=i.bond_slaves,
                    method=i.method,
                    autostart=i.autostart,
                )
                for i in (result.data or [])
            ]

    # ═══════════════════════════════════════════════════════════════════════
    # TASKS
    # ═══════════════════════════════════════════════════════════════════════

    async def get_tasks(self, controller: Any, node: str, limit: int = 50) -> list[TaskResponse]:
        """Get recent tasks."""
        async with await self._get_adapter(controller) as adapter:
            result = await adapter.get_tasks(node, limit)
            if not result.success:
                raise ConnectionError("Task inventory unavailable")
            return [
                TaskResponse(
                    upid=t.upid,
                    node=t.node,
                    type=t.task_type,
                    status=t.status if t.status else "running",
                    user=t.user,
                    started_at=t.started_at,
                    ended_at=(datetime.fromtimestamp(t.endtime, tz=UTC) if t.endtime else None),
                    is_running=t.is_running,
                )
                for t in (result.data or [])
            ]

    # ═══════════════════════════════════════════════════════════════════════
    # MONITORING
    # ═══════════════════════════════════════════════════════════════════════

    async def get_node_rrd(
        self,
        controller: Any,
        node: str,
        timeframe: str = "hour",
        max_points: int = 500,
    ) -> list[RRDPointResponse]:
        """Get node RRD monitoring data with LTTB downsampling."""
        async with await self._get_adapter(controller) as adapter:
            result = await adapter.get_node_rrd(node, timeframe)
            if not result.success:
                return []
            points = [
                RRDPointResponse(
                    time=p.time,
                    cpu=p.cpu,
                    maxcpu=p.maxcpu,
                    mem=p.mem,
                    maxmem=p.maxmem,
                    netin=p.netin,
                    netout=p.netout,
                    diskread=p.diskread,
                    diskwrite=p.diskwrite,
                    iowait=p.iowait,
                )
                for p in (result.data or [])
            ]
            if len(points) > max_points:
                dicts = [p.model_dump() for p in points]
                dicts = _lttb_downsample(dicts, max_points)
                return [RRDPointResponse(**d) for d in dicts]
            return points

    async def get_vm_rrd(
        self,
        controller: Any,
        node: str,
        vmid: int,
        timeframe: str = "hour",
        max_points: int = 500,
    ) -> list[RRDPointResponse]:
        """Get VM RRD monitoring data with LTTB downsampling."""
        async with await self._get_adapter(controller) as adapter:
            result = await adapter.get_vm_rrd(node, vmid, timeframe)
            if not result.success:
                return []
            points = [
                RRDPointResponse(
                    time=p.time,
                    cpu=p.cpu,
                    maxcpu=p.maxcpu,
                    mem=p.mem,
                    maxmem=p.maxmem,
                    netin=p.netin,
                    netout=p.netout,
                    diskread=p.diskread,
                    diskwrite=p.diskwrite,
                    iowait=p.iowait,
                )
                for p in (result.data or [])
            ]
            if len(points) > max_points:
                dicts = [p.model_dump() for p in points]
                dicts = _lttb_downsample(dicts, max_points)
                return [RRDPointResponse(**d) for d in dicts]
            return points

    # ═══════════════════════════════════════════════════════════════════════
    # BACKUP
    # ═══════════════════════════════════════════════════════════════════════

    async def get_backup_jobs(self, controller: Any) -> list[BackupJobResponse]:
        """Get scheduled backup jobs."""
        async with await self._get_adapter(controller) as adapter:
            result = await adapter.get_backup_jobs()
            if not result.success:
                raise ConnectionError("Proxmox backup schedule inventory is unavailable")
            return [
                BackupJobResponse(
                    id=b.id,
                    schedule=b.schedule,
                    storage=b.storage,
                    vmid=b.vmid,
                    mode=b.mode,
                    compress=b.compress,
                    enabled=b.enabled,
                    mailto=b.mailto,
                    node=b.node,
                )
                for b in (result.data or [])
            ]

    async def run_backup(
        self,
        controller: Any,
        node: str,
        vmid: int,
        storage: str,
        mode: str = "snapshot",
        compress: str = "zstd",
        *,
        vm_type: str = "qemu",
        current_user: Any = None,
        request_id: UUID | None = None,
        force: bool = False,
    ):
        from fastapi import HTTPException

        from app.modules.hypervisor.schemas import BackupRunRequest
        from app.services.hypervisor_operations import HypervisorOperationService

        if current_user is None or request_id is None:
            raise HTTPException(400, detail="Backup requires an actor and request_id")
        return await HypervisorOperationService(self.db, current_user).backup(
            controller.id,
            node,
            vmid,
            vm_type,
            BackupRunRequest(
                request_id=request_id, force=force, storage=storage, mode=mode, compress=compress
            ),
        )

    # ═══════════════════════════════════════════════════════════════════════
    # CLONE / MIGRATE / RESIZE
    # ═══════════════════════════════════════════════════════════════════════

    async def clone_vm(
        self,
        controller: Any,
        node: str,
        vmid: int,
        newid: int,
        vm_type: str = "qemu",
        *,
        name: str = "",
        target: str = "",
        full: bool = True,
        storage: str = "",
        description: str = "",
        current_user: Any = None,
        request_id: UUID | None = None,
        force: bool = False,
    ):
        """Persist and claim a clone intent before dispatching it."""
        from fastapi import HTTPException

        from app.modules.hypervisor.schemas import CloneRequest
        from app.services.hypervisor_operations import HypervisorOperationService

        if current_user is None or request_id is None:
            raise HTTPException(400, detail="Clone requires an actor and request_id")
        return await HypervisorOperationService(self.db, current_user).clone(
            controller.id,
            node,
            vmid,
            vm_type,
            CloneRequest(
                request_id=request_id,
                force=force,
                newid=newid,
                name=name,
                target=target,
                full=full,
                storage=storage,
                description=description,
            ),
        )

    async def migrate_vm(
        self,
        controller: Any,
        node: str,
        vmid: int,
        target: str,
        vm_type: str = "qemu",
        online: bool = False,
        *,
        restart: bool = False,
        current_user: Any = None,
        request_id: UUID | None = None,
        force: bool = False,
    ):
        """Persist and claim a migration intent before dispatching it."""
        from fastapi import HTTPException

        from app.modules.hypervisor.schemas import MigrateRequest
        from app.services.hypervisor_operations import HypervisorOperationService

        if current_user is None or request_id is None:
            raise HTTPException(400, detail="Migration requires an actor and request_id")
        return await HypervisorOperationService(self.db, current_user).migrate(
            controller.id,
            node,
            vmid,
            vm_type,
            MigrateRequest(
                request_id=request_id, force=force, target=target, online=online, restart=restart
            ),
        )

    async def resize_disk(
        self,
        controller: Any,
        node: str,
        vmid: int,
        body: Any,
        vm_type: str = "qemu",
        *,
        current_user: Any = None,
    ):
        return await self._guest_change(
            controller, node, vmid, vm_type, "resize", body, current_user
        )

    async def update_config(
        self,
        controller: Any,
        node: str,
        vmid: int,
        body: Any,
        vm_type: str = "qemu",
        *,
        current_user: Any = None,
    ):
        return await self._guest_change(
            controller, node, vmid, vm_type, "config", body, current_user
        )

    async def convert_to_template(
        self,
        controller: Any,
        node: str,
        vmid: int,
        body: Any,
        vm_type: str = "qemu",
        *,
        current_user: Any = None,
    ):
        return await self._guest_change(
            controller, node, vmid, vm_type, "template", body, current_user
        )

    async def _guest_change(
        self,
        controller: Any,
        node: str,
        vmid: int,
        vm_type: str,
        action: str,
        body: Any,
        current_user: Any,
    ):
        from fastapi import HTTPException

        from app.services.hypervisor_operations import HypervisorOperationService

        if current_user is None:
            raise HTTPException(400, detail="Guest changes require an actor and reviewed intent")
        return await HypervisorOperationService(self.db, current_user).guest_change(
            controller.id, node, vmid, vm_type, action, body
        )

    # ═══════════════════════════════════════════════════════════════════════
    # CONSOLE
    # ═══════════════════════════════════════════════════════════════════════

    async def get_console_proxy(
        self,
        controller: Any,
        node: str,
        vmid: int,
        vm_type: str = "qemu",
        console_type: str = "vnc",
    ) -> ConsoleProxyResponse:
        """Get console proxy ticket."""
        async with await self._get_adapter(controller) as adapter:
            result = await adapter.get_console_proxy(node, vmid, vm_type, console_type)
            if not result.success:
                raise ValueError(result.error or "Console proxy failed")
            data = result.data or {}
            if isinstance(data, dict):
                return ConsoleProxyResponse(
                    ticket=data.get("ticket", ""),
                    port=data.get("port", ""),
                    user=data.get("user", ""),
                    cert=data.get("cert", ""),
                    upid=data.get("upid", ""),
                )
            return ConsoleProxyResponse()

    # ═══════════════════════════════════════════════════════════════════════
    # TASK DETAILS
    # ═══════════════════════════════════════════════════════════════════════

    async def get_task_status(self, controller: Any, node: str, upid: str) -> TaskDetailResponse:
        """Get detailed task status."""
        async with await self._get_adapter(controller) as adapter:
            result = await adapter.get_task_status(node, upid)
            if not result.success:
                raise ValueError(result.error or "Task not found")
            t = result.data
            return TaskDetailResponse(
                upid=t.upid,
                node=t.node,
                type=t.task_type,
                status=t.status,
                user=t.user,
                started_at=datetime.fromtimestamp(t.starttime, tz=UTC) if t.starttime else None,
                is_running=t.is_running,
                exitstatus=t.exitstatus,
            )

    async def get_task_log(
        self, controller: Any, node: str, upid: str, start: int = 0, limit: int = 50
    ) -> list[TaskLogEntry]:
        """Get task log output."""
        async with await self._get_adapter(controller) as adapter:
            result = await adapter.get_task_log(node, upid, start, limit)
            if not result.success:
                raise ConnectionError("Task log unavailable")
            return [TaskLogEntry(n=l.n, t=l.t) for l in (result.data or [])]

    # ═══════════════════════════════════════════════════════════════════════
    # FIREWALL
    # ═══════════════════════════════════════════════════════════════════════

    async def get_firewall_rules(
        self,
        controller: Any,
        node: str | None = None,
        vmid: int | None = None,
        vm_type: str = "qemu",
    ) -> list[FirewallRuleResponse]:
        """Get firewall rules at cluster, node, or VM level."""
        async with await self._get_adapter(controller) as adapter:
            result = await adapter.get_firewall_rules(node, vmid, vm_type)
            if not result.success:
                raise ConnectionError("Firewall rules unavailable")
            return [
                FirewallRuleResponse(
                    pos=r.pos,
                    type=r.type,
                    action=r.action,
                    enable=r.enable,
                    source=r.source,
                    dest=r.dest,
                    sport=r.sport,
                    dport=r.dport,
                    proto=r.proto,
                    macro=r.macro,
                    iface=r.iface,
                    log=r.log,
                    comment=r.comment,
                )
                for r in (result.data or [])
            ]

    # ═══════════════════════════════════════════════════════════════════════
    # GUEST FIREWALL (per VM/CT)
    # ═══════════════════════════════════════════════════════════════════════

    async def get_guest_firewall_rules(
        self, controller: Any, node: str, vm_type: str, vmid: int
    ) -> list[dict]:
        """Get firewall rules for a VM/CT."""
        async with await self._get_adapter(controller) as adapter:
            result = await adapter.get_guest_firewall_rules(node, vm_type, vmid)
            if not result.success:
                raise ConnectionError("Firewall rules unavailable")
            return result.data or []

    async def get_guest_firewall_options(
        self, controller: Any, node: str, vm_type: str, vmid: int
    ) -> dict:
        """Get firewall options for a VM/CT."""
        async with await self._get_adapter(controller) as adapter:
            result = await adapter.get_guest_firewall_options(node, vm_type, vmid)
            if not result.success:
                raise ConnectionError("Firewall options unavailable")
            return result.data or {}

    async def get_cluster_firewall_options(self, controller: Any) -> dict:
        """Get cluster-level firewall options."""
        async with await self._get_adapter(controller) as adapter:
            result = await adapter.get_cluster_firewall_options()
            if not result.success:
                raise ConnectionError("Firewall options unavailable")
            return result.data or {}

    # ═══════════════════════════════════════════════════════════════════════
    # NODE EXTRAS
    # ═══════════════════════════════════════════════════════════════════════

    async def get_node_services(self, controller: Any, node: str) -> list[NodeServiceResponse]:
        """Get node services."""
        async with await self._get_adapter(controller) as adapter:
            result = await adapter.get_node_services(node)
            if not result.success:
                raise ConnectionError("Firewall rules unavailable")
            return [
                NodeServiceResponse(
                    service=s.service,
                    name=s.name,
                    desc=s.desc,
                    state=s.state,
                )
                for s in (result.data or [])
            ]

    async def get_node_disks(self, controller: Any, node: str) -> list[DiskInfoResponse]:
        """Get node physical disks."""
        async with await self._get_adapter(controller) as adapter:
            result = await adapter.get_node_disks(node)
            if not result.success:
                raise ConnectionError("Firewall rules unavailable")
            return [
                DiskInfoResponse(
                    devpath=d.devpath,
                    model=d.model,
                    serial=d.serial,
                    size=d.size,
                    vendor=d.vendor,
                    wearout=d.wearout,
                    rpm=d.rpm,
                    disk_type=d.disk_type,
                    gpt=d.gpt,
                    health=d.health,
                )
                for d in (result.data or [])
            ]

    async def get_node_syslog(
        self, controller: Any, node: str, limit: int = 50, start: int = 0
    ) -> list[SyslogEntry]:
        """Get node syslog."""
        async with await self._get_adapter(controller) as adapter:
            result = await adapter.get_node_syslog(node, limit, start)
            if not result.success:
                raise ConnectionError("Firewall rules unavailable")
            return [
                SyslogEntry(n=int(e.get("n", 0)), t=e.get("t", ""))
                for e in (result.data or [])
                if isinstance(e, dict)
            ]

    # ═══════════════════════════════════════════════════════════════════════
    # HA
    # ═══════════════════════════════════════════════════════════════════════

    async def get_ha_resources(self, controller: Any) -> list[HAResourceResponse]:
        """Get HA-managed resources."""
        async with await self._get_adapter(controller) as adapter:
            result = await adapter.get_ha_resources()
            if not result.success:
                raise ConnectionError("Firewall rules unavailable")
            return [
                HAResourceResponse(
                    sid=r.sid,
                    state=r.state,
                    group=r.group,
                    max_relocate=r.max_relocate,
                    max_restart=r.max_restart,
                    comment=r.comment,
                    request_state=r.request_state,
                    status=r.status,
                    node=r.node,
                    crm_state=r.crm_state,
                )
                for r in (result.data or [])
            ]

    async def get_ha_groups(self, controller: Any) -> list[HAGroupResponse]:
        """Get HA groups."""
        async with await self._get_adapter(controller) as adapter:
            result = await adapter.get_ha_groups()
            if not result.success:
                raise ConnectionError("Firewall rules unavailable")
            return [
                HAGroupResponse(
                    group=g.group,
                    nodes=g.nodes,
                    nofailback=g.nofailback,
                    restricted=g.restricted,
                    comment=g.comment,
                )
                for g in (result.data or [])
            ]

    # ═══════════════════════════════════════════════════════════════════════
    # RESOURCE POOLS
    # ═══════════════════════════════════════════════════════════════════════

    async def get_pools(self, controller: Any) -> list[ResourcePoolResponse]:
        """Get resource pools."""
        async with await self._get_adapter(controller) as adapter:
            result = await adapter.get_pools()
            if not result.success:
                return []
            return [
                ResourcePoolResponse(poolid=p.poolid, comment=p.comment)
                for p in (result.data or [])
            ]

    # ═══════════════════════════════════════════════════════════════════════
    # CEPH
    # ═══════════════════════════════════════════════════════════════════════

    async def get_ceph_status(self, controller: Any, node: str) -> CephStatusResponse | None:
        """Get Ceph status (if available)."""
        async with await self._get_adapter(controller) as adapter:
            result = await adapter.get_ceph_status(node)
            if not result.success:
                return None
            cs = result.data
            return CephStatusResponse(
                health=cs.health,
                num_osds=cs.num_osds,
                num_osds_up=cs.num_osds_up,
                num_osds_in=cs.num_osds_in,
                num_pgs=cs.num_pgs,
                num_pools=cs.num_pools,
                total_bytes=cs.total_bytes,
                used_bytes=cs.used_bytes,
                avail_bytes=cs.avail_bytes,
                used_percent=cs.used_percent,
            )

    async def get_ceph_detail(self, controller: Any, node: str) -> CephDetailResponse:
        """Fetch full Ceph cluster detail: status + OSDs + pools + monitors + MDS + FS + CRUSH."""
        async with await self._get_adapter(controller) as adapter:
            results = await asyncio.gather(
                adapter.get_ceph_status(node),
                adapter.get_ceph_osd(node),
                adapter.get_ceph_pools(node),
                adapter.get_ceph_mon(node),
                adapter.get_ceph_mds(node),
                adapter.get_ceph_fs(node),
                adapter.get_ceph_crush_rules(node),
                return_exceptions=True,
            )
        return CephDetailResponse(
            status=results[0].data.raw
            if isinstance(results[0], AdapterResult)
            and results[0].success
            and hasattr(results[0].data, "raw")
            else None,
            osds=results[1].data
            if isinstance(results[1], AdapterResult) and results[1].success
            else None,
            pools=results[2].data
            if isinstance(results[2], AdapterResult) and results[2].success
            else None,
            monitors=results[3].data
            if isinstance(results[3], AdapterResult) and results[3].success
            else None,
            mds=results[4].data
            if isinstance(results[4], AdapterResult) and results[4].success
            else None,
            fs=results[5].data
            if isinstance(results[5], AdapterResult) and results[5].success
            else None,
            crush_rules=results[6].data
            if isinstance(results[6], AdapterResult) and results[6].success
            else None,
        )

    # ═══════════════════════════════════════════════════════════════════════
    # NODE SENSORS
    # ═══════════════════════════════════════════════════════════════════════

    async def get_node_sensors(self, controller: Any, node: str) -> dict:
        """Get sensor/temperature data from a node."""
        async with await self._get_adapter(controller) as adapter:
            result = await adapter.get_node_sensors(node)
            if not result.success:
                raise ValueError(result.error or "Failed to get node sensors")
            return result.data or {}

    # ═══════════════════════════════════════════════════════════════════════
    # FLEET TASK STATISTICS
    # ═══════════════════════════════════════════════════════════════════════

    async def get_fleet_task_statistics(self, controllers: list[Any]) -> FleetTaskStatistics:
        """Aggregate task stats across all controllers."""
        fleet_stats = FleetTaskStatistics()

        async def _fetch_one(ctrl: Any) -> tuple[str, TaskStatistics]:
            stats = TaskStatistics()
            try:
                async with _fleet_semaphore:
                    adapter = await self._get_adapter(ctrl)
                    async with adapter:
                        nodes_result = await adapter.get_nodes()
                        if not nodes_result.success or not nodes_result.data:
                            return str(ctrl.id), stats
                        # Get tasks from first online node
                        first_node = None
                        for n in nodes_result.data:
                            if n.status == "online":
                                first_node = n.node
                                break
                        if not first_node and nodes_result.data:
                            first_node = nodes_result.data[0].node
                        if not first_node:
                            return str(ctrl.id), stats
                        tasks_result = await adapter.get_tasks(first_node, limit=200)
                        if not tasks_result.success:
                            return str(ctrl.id), stats
                        for t in tasks_result.data or []:
                            stats.total += 1
                            task_type = t.task_type
                            stats.by_type[task_type] = stats.by_type.get(task_type, 0) + 1
                            if t.is_running:
                                stats.running += 1
                            elif t.status and "OK" in t.status.upper():
                                stats.ok += 1
                            elif t.status and ("WARN" in t.status.upper()):
                                stats.warning += 1
                            elif t.status and (
                                "ERROR" in t.status.upper() or "FAIL" in t.status.upper()
                            ):
                                stats.error += 1
                            else:
                                stats.ok += 1
            except Exception as e:
                logger.error("Fleet task stats error for %s: %s", getattr(ctrl, "host", "?"), e)
            return str(ctrl.id), stats

        results = await asyncio.gather(
            *[_fetch_one(c) for c in controllers],
            return_exceptions=True,
        )

        aggregate = TaskStatistics()
        for r in results:
            if isinstance(r, Exception):
                continue
            ctrl_id, stats = r
            fleet_stats.controllers[ctrl_id] = stats
            aggregate.total += stats.total
            aggregate.ok += stats.ok
            aggregate.warning += stats.warning
            aggregate.error += stats.error
            aggregate.running += stats.running
            for task_type, count in stats.by_type.items():
                aggregate.by_type[task_type] = aggregate.by_type.get(task_type, 0) + count

        fleet_stats.aggregate = aggregate
        return fleet_stats

    # ═══════════════════════════════════════════════════════════════════════
    # STORAGE VOLUME DELETE
    # ═══════════════════════════════════════════════════════════════════════

    async def get_next_vmid(self, controller: Any) -> NextVMIDResponse:
        """Get next available VMID."""
        async with await self._get_adapter(controller) as adapter:
            result = await adapter.get_next_vmid()
            if not result.success:
                raise ValueError(result.error or "Failed to get next VMID")
            return NextVMIDResponse(vmid=int(result.data))

    async def delete_vm(
        self,
        controller: Any,
        node: str,
        vmid: int,
        vm_type: str = "qemu",
        *,
        confirmed: bool = False,
        current_user: Any = None,
        request_id: UUID | None = None,
        expected_digest: str | None = None,
        force: bool = False,
    ) -> VMActionResponse:
        from fastapi import HTTPException

        from app.modules.hypervisor.schemas import DeleteVMRequest
        from app.services.hypervisor_operations import HypervisorOperationService

        if current_user is None or request_id is None or expected_digest is None:
            raise HTTPException(
                400, detail="Deletion requires an actor, request_id and reviewed digest"
            )
        return await HypervisorOperationService(self.db, current_user).delete(
            controller.id,
            node,
            vmid,
            vm_type,
            DeleteVMRequest(
                request_id=request_id,
                expected_digest=expected_digest,
                force=force,
                confirmed=confirmed,
            ),
        )

    # ═══════════════════════════════════════════════════════════════════════
    # HA MANAGEMENT
    # ═══════════════════════════════════════════════════════════════════════

    # ═══════════════════════════════════════════════════════════════════════
    # FLEET DASHBOARD (MULTI-CLUSTER)
    # ═══════════════════════════════════════════════════════════════════════

    async def get_fleet_dashboard(self, controllers: list[Any]) -> FleetDashboardResponse:
        """Aggregate registrations with explicit unknowns and per-controller failures."""
        started = datetime.now(UTC)

        async def _fetch_one(ctrl: Any) -> FleetClusterSummary:
            try:
                # Include semaphore wait and connection setup in the deadline.
                async with asyncio.timeout(_FLEET_TIMEOUT):
                    async with _fleet_semaphore:
                        dashboard = await self.get_dashboard(ctrl)
                return FleetClusterSummary(
                    **dashboard.model_dump(),
                    controller_name=ctrl.name or ctrl.host,
                    status="online",
                )
            except TimeoutError:
                error = "Cluster response timed out"
                logger.warning("Fleet dashboard: timeout for controller %s", ctrl.id)
            except Exception as exc:
                error = "Failed to observe cluster"
                logger.warning(
                    "Fleet dashboard failed for controller %s (%s)", ctrl.id, type(exc).__name__
                )
            return FleetClusterSummary(
                controller_id=str(ctrl.id),
                controller_name=ctrl.name or ctrl.host,
                error=error,
            )

        results = await asyncio.gather(*[_fetch_one(controller) for controller in controllers])
        return dashboard_metrics.fleet(results, started)

    # ═══════════════════════════════════════════════════════════════════════
    # BULK OPERATIONS
    # ═══════════════════════════════════════════════════════════════════════

    async def bulk_action(
        self,
        controller: Any,
        targets: list[dict],
        action: str,
        *,
        confirmed: bool = False,
        current_user: Any = None,
        force: bool = False,
    ) -> list[dict]:
        """Each target has its own durable claim; partial batches can be resumed by ID."""
        from types import SimpleNamespace

        from fastapi import HTTPException

        controller_id = controller.id

        target_controller = SimpleNamespace(id=controller_id)
        results = []
        for target in targets:
            try:
                if action == "delete":
                    receipt = await self.delete_vm(
                        target_controller,
                        target["node"],
                        target["vmid"],
                        target["vm_type"],
                        confirmed=confirmed,
                        current_user=current_user,
                        request_id=target.get("request_id"),
                        expected_digest=target.get("expected_digest"),
                        force=force,
                    )
                else:
                    receipt = await self.vm_action(
                        target_controller,
                        target["node"],
                        target["vmid"],
                        action,
                        target["vm_type"],
                        current_user=current_user,
                        request_id=target.get("request_id"),
                        force=force,
                    )
                data = receipt.model_dump()
                data.update(node=target["node"], success=receipt.status == "applied")
                if not data["success"]:
                    data["error"] = receipt.message
                results.append(data)
            except HTTPException as exc:
                results.append(
                    {
                        "vmid": target["vmid"],
                        "node": target["node"],
                        "success": False,
                        "request_id": target.get("request_id"),
                        "error": str(exc.detail),
                    }
                )
        return results

    async def bulk_migrate(
        self,
        controller: Any,
        targets: list[dict],
        target_node: str,
        online: bool = True,
        *,
        restart: bool = False,
        current_user: Any = None,
        force: bool = False,
    ) -> list[dict]:
        """Claim targets individually; a partial batch can resume with the same IDs."""
        from fastapi import HTTPException

        results = []
        # One AsyncSession must not run concurrent transactions. Provider tasks
        # run asynchronously after each accepted dispatch, without blocking here.
        for target in targets:
            try:
                receipt = await self.migrate_vm(
                    controller,
                    target["node"],
                    target["vmid"],
                    target_node,
                    target["vm_type"],
                    online=online if target["vm_type"] == "qemu" else False,
                    restart=restart if target["vm_type"] == "lxc" else False,
                    current_user=current_user,
                    request_id=target.get("request_id"),
                    force=force,
                )
                data = receipt.model_dump()
                data.update(node=target["node"], success=receipt.status == "applied")
                if not data["success"]:
                    data["error"] = receipt.message
                results.append(data)
            except HTTPException as exc:
                results.append(
                    {
                        "vmid": target["vmid"],
                        "node": target["node"],
                        "request_id": target.get("request_id"),
                        "success": False,
                        "error": str(exc.detail),
                    }
                )
        return results

    async def get_guest_agent_info(self, controller: Any, node: str, vmid: int) -> AdapterResult:
        """Get guest agent network info from a running QEMU VM."""
        async with await self._get_adapter(controller) as adapter:
            return await adapter.get_guest_agent_info(node, vmid)

    async def get_container_rrd(
        self,
        controller: Any,
        node: str,
        vmid: int,
        timeframe: str = "hour",
        max_points: int = 500,
    ) -> list[RRDPointResponse]:
        """Get RRD monitoring data for a container with LTTB downsampling."""
        async with await self._get_adapter(controller) as adapter:
            result = await adapter.get_container_rrd(node, vmid, timeframe)
            if not result.success:
                return []
            points = [
                RRDPointResponse(
                    time=p.time,
                    cpu=p.cpu,
                    maxcpu=p.maxcpu,
                    mem=p.mem,
                    maxmem=p.maxmem,
                    netin=p.netin,
                    netout=p.netout,
                    diskread=p.diskread,
                    diskwrite=p.diskwrite,
                    iowait=p.iowait,
                )
                for p in (result.data or [])
            ]
            if len(points) > max_points:
                dicts = [p.model_dump() for p in points]
                dicts = _lttb_downsample(dicts, max_points)
                return [RRDPointResponse(**d) for d in dicts]
            return points

    # ═══════════════════════════════════════════════════════════════════════
    # APT / UPDATES
    # ═══════════════════════════════════════════════════════════════════════

    async def get_node_apt_updates(self, controller: Any, node: str) -> AdapterResult:
        """Get available APT package updates for a node."""
        async with await self._get_adapter(controller) as adapter:
            return await adapter.get_node_apt_updates(node)

    async def refresh_node_apt(self, controller: Any, node: str) -> AdapterResult:
        """Refresh APT package index on a node."""
        async with await self._get_adapter(controller) as adapter:
            return await adapter.refresh_node_apt(node)

    async def get_node_apt_versions(self, controller: Any, node: str) -> AdapterResult:
        """Get installed package versions on a node."""
        async with await self._get_adapter(controller) as adapter:
            return await adapter.get_node_apt_versions(node)

    # ═══════════════════════════════════════════════════════════════════════
    # CERTIFICATES
    # ═══════════════════════════════════════════════════════════════════════

    async def get_node_certificates(self, controller: Any, node: str) -> AdapterResult:
        """Get node TLS certificates."""
        async with await self._get_adapter(controller) as adapter:
            return await adapter.get_node_certificates(node)

    # ═══════════════════════════════════════════════════════════════════════
    # SUBSCRIPTION
    # ═══════════════════════════════════════════════════════════════════════

    async def get_node_subscription(self, controller: Any, node: str) -> AdapterResult:
        """Get node subscription status."""
        async with await self._get_adapter(controller) as adapter:
            return await adapter.get_node_subscription(node)

    # ═══════════════════════════════════════════════════════════════════════
    # CROSS-CLUSTER MIGRATION
    # ═══════════════════════════════════════════════════════════════════════

    async def remote_migrate_vm(
        self,
        controller: Any,
        node: str,
        vmid: int,
        request: Any,
    ) -> AdapterResult:
        """Remote-migrate a QEMU VM to another cluster."""
        async with await self._get_adapter(controller) as adapter:
            target_endpoint = (
                f"apitoken={request.target_user}:{request.target_token}"
                f"@{request.target_host}:{request.target_port}"
            )
            if request.target_fingerprint:
                target_endpoint += f",fingerprint={request.target_fingerprint}"
            return await adapter.remote_migrate_vm(
                node=node,
                vmid=vmid,
                target_endpoint=target_endpoint,
                target_storage=request.target_storage,
                target_bridge=request.target_bridge,
                online=request.online,
                delete_source=request.delete_source,
            )

    async def remote_migrate_container(
        self,
        controller: Any,
        node: str,
        vmid: int,
        request: Any,
    ) -> AdapterResult:
        """Remote-migrate an LXC container to another cluster."""
        async with await self._get_adapter(controller) as adapter:
            target_endpoint = (
                f"apitoken={request.target_user}:{request.target_token}"
                f"@{request.target_host}:{request.target_port}"
            )
            if request.target_fingerprint:
                target_endpoint += f",fingerprint={request.target_fingerprint}"
            return await adapter.remote_migrate_container(
                node=node,
                vmid=vmid,
                target_endpoint=target_endpoint,
                target_storage=request.target_storage,
                target_bridge=request.target_bridge,
                online=request.online,
                delete_source=request.delete_source,
            )

    # ═══════════════════════════════════════════════════════════════════════
    # SDN
    # ═══════════════════════════════════════════════════════════════════════

    async def get_sdn_zones(self, controller: Any) -> AdapterResult:
        """Get SDN zones."""
        async with await self._get_adapter(controller) as adapter:
            return await adapter.get_sdn_zones()

    async def get_sdn_vnets(self, controller: Any) -> AdapterResult:
        """Get SDN vnets."""
        async with await self._get_adapter(controller) as adapter:
            return await adapter.get_sdn_vnets()

    async def get_sdn_controllers(self, controller: Any) -> AdapterResult:
        """Get SDN controllers."""
        async with await self._get_adapter(controller) as adapter:
            return await adapter.get_sdn_controllers()

    # ═══════════════════════════════════════════════════════════════════════
    # GUEST AGENT (EXEC / FILE)
    # ═══════════════════════════════════════════════════════════════════════

    async def agent_exec(
        self,
        controller: Any,
        node: str,
        vmid: int,
        command: str,
        input_data: str | None = None,
        *,
        confirmed: bool = False,
    ) -> AdapterResult:
        """Execute a command inside a VM via the QEMU guest agent.

        ``confirmed`` is the second factor (the operator acknowledging the exec);
        we never pass force, so the read-only gate still applies (no guest commands
        in monitor-only mode → 403).
        """
        async with await self._get_adapter(controller) as adapter:
            return await adapter.agent_exec(node, vmid, command, input_data, confirmed=confirmed)

    async def agent_exec_status(
        self, controller: Any, node: str, vmid: int, pid: int
    ) -> AdapterResult:
        """Get exec status/result from the QEMU guest agent."""
        async with await self._get_adapter(controller) as adapter:
            return await adapter.agent_exec_status(node, vmid, pid)

    async def agent_file_read(
        self, controller: Any, node: str, vmid: int, file: str
    ) -> AdapterResult:
        """Read a file inside a VM via the QEMU guest agent."""
        async with await self._get_adapter(controller) as adapter:
            return await adapter.agent_file_read(node, vmid, file)

    async def agent_file_write(
        self,
        controller: Any,
        node: str,
        vmid: int,
        file: str,
        content: str,
        *,
        confirmed: bool = False,
    ) -> AdapterResult:
        """Write a file inside a VM via the QEMU guest agent.

        ``confirmed`` is the second factor; force is never passed, so the read-only
        gate still applies (no guest writes in monitor-only mode → 403).
        """
        async with await self._get_adapter(controller) as adapter:
            return await adapter.agent_file_write(node, vmid, file, content, confirmed=confirmed)

    # ═══════════════════════════════════════════════════════════════════════
    # PENDING CONFIG
    # ═══════════════════════════════════════════════════════════════════════

    async def get_vm_pending_config(self, controller: Any, node: str, vmid: int) -> AdapterResult:
        """Get pending configuration changes for a QEMU VM."""
        async with await self._get_adapter(controller) as adapter:
            return await adapter.get_vm_pending_config(node, vmid)

    async def get_container_pending_config(
        self, controller: Any, node: str, vmid: int
    ) -> AdapterResult:
        """Get pending configuration changes for an LXC container."""
        async with await self._get_adapter(controller) as adapter:
            return await adapter.get_container_pending_config(node, vmid)

    # ═══════════════════════════════════════════════════════════════════════
    # CLUSTER EXTRAS
    # ═══════════════════════════════════════════════════════════════════════

    async def get_cluster_options(self, controller: Any) -> AdapterResult:
        """Get cluster-wide options."""
        async with await self._get_adapter(controller) as adapter:
            return await adapter.get_cluster_options()

    async def get_cluster_log(self, controller: Any, max_entries: int = 50) -> AdapterResult:
        """Get cluster log entries."""
        async with await self._get_adapter(controller) as adapter:
            return await adapter.get_cluster_log(max_entries)

    async def get_cluster_config_nodes(self, controller: Any) -> AdapterResult:
        """Get cluster corosync config nodes."""
        async with await self._get_adapter(controller) as adapter:
            return await adapter.get_cluster_config_nodes()

    async def get_cluster_replication(self, controller: Any) -> AdapterResult:
        """Get cluster replication jobs."""
        async with await self._get_adapter(controller) as adapter:
            return await adapter.get_cluster_replication()

    async def get_replication_log(self, controller: Any, replication_id: str) -> AdapterResult:
        """Get log for a specific replication job."""
        async with await self._get_adapter(controller) as adapter:
            return await adapter.get_replication_log(replication_id)

    # ═══════════════════════════════════════════════════════════════════════
    # DB SYNC
    # ═══════════════════════════════════════════════════════════════════════

    async def sync_nodes(self, controller_id: UUID, site_id: UUID | None, controller: Any) -> int:
        """Sync node data from Proxmox into DB. Returns count synced."""
        async with await self._get_adapter(controller) as adapter:
            result = await adapter.get_nodes()
            if not result.success:
                return 0

            now = datetime.now(UTC)

            # Batch-fetch all existing nodes for this controller (eliminates N+1)
            existing_stmt = select(ProxmoxNode).where(
                ProxmoxNode.controller_id == controller_id,
                ProxmoxNode.deleted_at.is_(None),
            )
            existing_rows = (await self.db.execute(existing_stmt)).scalars().all()
            existing_map = {r.node_name: r for r in existing_rows}

            count = 0
            for node_info in result.data or []:
                row = existing_map.get(node_info.node)

                if row is None:
                    row = ProxmoxNode(
                        controller_id=controller_id,
                        site_id=site_id,
                        node_name=node_info.node,
                    )
                    self.db.add(row)

                row.status = node_info.status
                row.cpu_count = node_info.maxcpu
                row.cpu_usage = node_info.cpu
                row.memory_total = node_info.maxmem
                row.memory_used = node_info.mem
                row.storage_total = node_info.maxdisk
                row.storage_used = node_info.disk
                row.uptime = node_info.uptime
                row.pve_version = node_info.pve_version
                row.kernel_version = node_info.kernel_version
                row.cpu_model = node_info.cpu_model
                row.subscription_level = node_info.level
                row.last_seen = now
                # Proxmox's node list returns the cluster node NAME, not
                # its management IP — so ip_address would stay NULL and
                # the synced hypervisor Device couldn't be correlated
                # with the host an agent discovered on the wire. For a
                # single-node install the controller's host IS the node's
                # management address, so stamp it. (Multi-node clusters
                # each have distinct IPs we can't attribute from here, so
                # we only do this when there's exactly one node.)
                if not getattr(row, "ip_address", None):
                    nodes = result.data or []
                    ctrl_host = getattr(controller, "host", None)
                    if len(nodes) == 1 and ctrl_host:
                        row.ip_address = ctrl_host
                count += 1

            await self.db.flush()
            return count

    # ═══════════════════════════════════════════════════════════════════════
    # HELPERS
    # ═══════════════════════════════════════════════════════════════════════

    # ═══════════════════════════════════════════════════════════════════════
    # DISK SMART
    # ═══════════════════════════════════════════════════════════════════════

    async def get_disk_smart(self, controller: Any, node: str, disk: str) -> dict:
        """Get SMART health data for a specific disk."""
        async with await self._get_adapter(controller) as adapter:
            result = await adapter.get_disk_smart(node, disk)
            if not result.success:
                raise ValueError(result.error or "Failed to fetch SMART data")
            return result.data or {}

    # ═══════════════════════════════════════════════════════════════════════
    # BACKUP AGE REPORT
    # ═══════════════════════════════════════════════════════════════════════

    async def get_backup_age_report(
        self, controller: Any, threshold_hours: int = 24
    ) -> BackupAgeResponse:
        """Collect archive observations with explicit incomplete/unknown states."""
        from app.modules.hypervisor.backup_age import collect_backup_age

        async with await self._get_adapter(controller) as adapter:
            return await collect_backup_age(adapter, threshold_hours)

    # ═══════════════════════════════════════════════════════════════════════
    # PRIVATE HELPERS
    # ═══════════════════════════════════════════════════════════════════════

    @staticmethod
    def _node_to_response(n: ProxmoxNodeInfo) -> NodeResponse:
        return NodeResponse(
            node=n.node,
            status=n.status,
            cpu_count=n.maxcpu,
            cpu_usage=n.cpu,
            cpu_percent=n.cpu_percent,
            memory_total=n.maxmem,
            memory_used=n.mem,
            memory_percent=n.mem_percent,
            storage_total=n.maxdisk,
            storage_used=n.disk,
            storage_percent=n.disk_percent,
            uptime=n.uptime,
            pve_version=n.pve_version,
            kernel_version=n.kernel_version,
            cpu_model=n.cpu_model,
            subscription_level=n.level,
        )

    # ═══════════════════════════════════════════════════════════════════════
    # PBS / BACKUP RESTORE / CLOUDINIT
    # ═══════════════════════════════════════════════════════════════════════

    async def restore_backup(
        self,
        controller: Any,
        node: str,
        vm_type: str,
        archive: str,
        vmid: int,
        storage: str | None = None,
        start: bool = False,
        unique: bool = True,
    ) -> dict:
        """Restore a VM/CT from a backup archive."""
        # refuse on the direct path — restore overwrites a live
        # guest and skipped the staged pre-flight / confirmed=true / archive-volid
        # validation. Route through the staged proxmox.backup.restore endpoint.
        _refuse_direct_catastrophic("restore_backup")
        async with await self._get_adapter(controller) as adapter:
            result = await adapter.restore_backup(
                node,
                vm_type,
                archive,
                vmid,
                storage,
                start,
                unique,
            )
            if not result.success:
                raise ValueError(result.error or "Failed to restore backup")
            return result.data

    async def get_prune_preview(
        self,
        controller: Any,
        node: str,
        storage: str,
        vmid: int | None = None,
    ) -> list:
        """Get prune preview for backup storage."""
        async with await self._get_adapter(controller) as adapter:
            result = await adapter.get_storage_prune_backups(node, storage, vmid)
            if not result.success:
                raise ValueError(result.error or "Failed to get prune preview")
            return result.data if isinstance(result.data, list) else []

    async def prune_backups(
        self,
        controller: Any,
        node: str,
        storage: str,
        keep_last: int | None = None,
        keep_hourly: int | None = None,
        keep_daily: int | None = None,
        keep_weekly: int | None = None,
        keep_monthly: int | None = None,
        keep_yearly: int | None = None,
        vmid: int | None = None,
    ) -> dict:
        """Execute backup pruning on storage."""
        # refuse on the direct path — prune permanently deletes backup
        # archives and skipped the staged pre-flight / confirmed=true. Route through
        # the staged proxmox.backup.prune endpoint. (get_prune_preview above is a
        # read and stays on the direct path.)
        _refuse_direct_catastrophic("prune_backups")
        async with await self._get_adapter(controller) as adapter:
            result = await adapter.prune_backups(
                node,
                storage,
                keep_last,
                keep_hourly,
                keep_daily,
                keep_weekly,
                keep_monthly,
                keep_yearly,
                vmid,
            )
            if not result.success:
                raise ValueError(result.error or "Failed to prune backups")
            return result.data

    async def get_cloudinit_config(self, controller: Any, node: str, vmid: int) -> dict:
        """Get CloudInit config for a QEMU VM."""
        async with await self._get_adapter(controller) as adapter:
            result = await adapter.get_guest_cloudinit(node, vmid)
            if not result.success:
                raise ValueError(result.error or "Failed to get CloudInit config")
            return result.data if isinstance(result.data, dict) else {}

    async def update_cloudinit_config(
        self, controller: Any, node: str, vmid: int, config: dict
    ) -> dict:
        """Update CloudInit config for a QEMU VM."""
        async with await self._get_adapter(controller) as adapter:
            result = await adapter.update_guest_cloudinit(node, vmid, config)
            if not result.success:
                raise ValueError(result.error or "Failed to update CloudInit config")
            return result.data

    async def regenerate_cloudinit(self, controller: Any, node: str, vmid: int) -> dict:
        """Regenerate CloudInit drive."""
        async with await self._get_adapter(controller) as adapter:
            result = await adapter.regenerate_cloudinit(node, vmid)
            if not result.success:
                raise ValueError(result.error or "Failed to regenerate CloudInit drive")
            return result.data

    # ═══════════════════════════════════════════════════════════════════════
    # HELPERS (static)
    # ═══════════════════════════════════════════════════════════════════════

    @staticmethod
    def _vm_to_response(v: ProxmoxVM) -> VMResponse:
        mem_mb = v.mem // (1024 * 1024) if v.mem > 0 else 0
        maxmem_mb = v.maxmem // (1024 * 1024) if v.maxmem > 0 else 0
        disk_gb = v.disk / (1024**3) if v.disk > 0 else 0
        maxdisk_gb = v.maxdisk / (1024**3) if v.maxdisk > 0 else 0

        return VMResponse(
            vmid=v.vmid,
            name=v.name,
            node=v.node,
            vm_type=v.vm_type,
            status=v.status,
            cpu_cores=v.cpus,
            cpu_usage=v.cpu,
            cpu_percent=v.cpu_percent,
            memory_mb=maxmem_mb,
            memory_used_mb=mem_mb,
            memory_percent=v.mem_percent,
            disk_gb=round(maxdisk_gb, 2),
            disk_used_gb=round(disk_gb, 2),
            disk_percent=v.disk_percent,
            net_in=v.netin,
            net_out=v.netout,
            uptime=v.uptime,
            tags=v.tag_list,
            template=v.template,
            ha_state=v.ha_state,
            lock=v.lock,
        )

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
from app.modules.hypervisor.models import ProxmoxNode
from app.modules.hypervisor.schemas import (
    AlertHysteresisConfig,
    BackupAgeReport,
    BackupAgeResponse,
    BackupJobResponse,
    CephDetailResponse,
    CephStatusResponse,
    ClusterNodeSummary,
    ClusterResourceItem,
    ClusterStatusResponse,
    ConsoleProxyResponse,
    CreateVMResponse,
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

# Dashboard TTL cache: {controller_id: (response, timestamp)}
_dashboard_cache: dict[str, tuple[Any, float]] = {}
_DASHBOARD_TTL = 10.0  # seconds
_MAX_DASHBOARD_CACHE_SIZE = 100

# Fleet concurrency limit (max 5 simultaneous Proxmox connections)
_fleet_semaphore = asyncio.Semaphore(5)
_FLEET_TIMEOUT = 20.0  # seconds per-cluster timeout


# ═══════════════════════════════════════════════════════════════════════════
# DIRECT-PATH CATASTROPHIC GUARD
# ═══════════════════════════════════════════════════════════════════════════
#
# This service is the DIRECT (un-staged) write path: unlike the staging
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
        """Get aggregated cluster dashboard with TTL cache."""
        ctrl_id = str(controller.id)
        cached = _dashboard_cache.get(ctrl_id)
        if cached and (time.monotonic() - cached[1]) < _DASHBOARD_TTL:
            return cached[0]

        result = await self._get_dashboard_uncached(controller)
        if len(_dashboard_cache) >= _MAX_DASHBOARD_CACHE_SIZE:
            # Evict oldest entries
            oldest_keys = sorted(
                _dashboard_cache.keys(),
                key=lambda k: _dashboard_cache[k][1],
            )[:10]
            for k in oldest_keys:
                _dashboard_cache.pop(k, None)
        _dashboard_cache[ctrl_id] = (result, time.monotonic())
        return result

    async def _get_dashboard_uncached(self, controller: Any) -> HypervisorDashboardResponse:
        """Get aggregated cluster dashboard (no cache)."""
        async with await self._get_adapter(controller) as adapter:
            # Fetch cluster status and all resources in parallel
            cluster_result, resources_result, ha_result = await asyncio.gather(
                adapter.get_cluster_status(),
                adapter.get_cluster_resources(),
                adapter.get_ha_status(),
                return_exceptions=True,
            )

            dashboard = HypervisorDashboardResponse()

            # Cluster info
            if not isinstance(cluster_result, Exception) and cluster_result.success:
                cs: ProxmoxClusterStatus = cluster_result.data
                dashboard.cluster_name = cs.name
                dashboard.quorate = cs.quorate
                dashboard.total_nodes = cs.node_count
                dashboard.online_nodes = sum(1 for n in cs.nodes if n.status == "online")

            # Resources
            if not isinstance(resources_result, Exception) and resources_result.success:
                resources = resources_result.data or []
                for r in resources:
                    rtype = r.get("type", "") if isinstance(r, dict) else ""
                    if rtype == "node":
                        dashboard.total_cpu_cores += int(r.get("maxcpu", 0))
                        cpu_frac = float(r.get("cpu", 0))
                        dashboard.cpu_usage_percent += cpu_frac * int(r.get("maxcpu", 0))
                        dashboard.total_memory_bytes += int(r.get("maxmem", 0))
                        dashboard.used_memory_bytes += int(r.get("mem", 0))
                        dashboard.total_storage_bytes += int(r.get("maxdisk", 0))
                        dashboard.used_storage_bytes += int(r.get("disk", 0))
                    elif rtype == "qemu":
                        dashboard.total_vms += 1
                        if r.get("status") == "running":
                            dashboard.running_vms += 1
                    elif rtype == "lxc":
                        dashboard.total_containers += 1
                        if r.get("status") == "running":
                            dashboard.running_containers += 1

                # Compute percentages
                if dashboard.total_cpu_cores > 0:
                    dashboard.cpu_usage_percent = round(
                        dashboard.cpu_usage_percent / dashboard.total_cpu_cores * 100, 1
                    )
                if dashboard.total_memory_bytes > 0:
                    dashboard.memory_usage_percent = round(
                        dashboard.used_memory_bytes / dashboard.total_memory_bytes * 100, 1
                    )
                if dashboard.total_storage_bytes > 0:
                    dashboard.storage_usage_percent = round(
                        dashboard.used_storage_bytes / dashboard.total_storage_bytes * 100, 1
                    )

            # HA
            if not isinstance(ha_result, Exception) and ha_result.success:
                ha_data = ha_result.data
                if isinstance(ha_data, list) and len(ha_data) > 0:
                    dashboard.ha_active = True

            return dashboard

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
    ) -> dict:
        """Execute a VM/container power action."""
        async with await self._get_adapter(controller) as adapter:
            action_map = {
                "qemu": {
                    "start": adapter.start_vm,
                    "stop": adapter.stop_vm,
                    "shutdown": adapter.shutdown_vm,
                    "reboot": adapter.reboot_vm,
                    "suspend": adapter.suspend_vm,
                    "resume": adapter.resume_vm,
                },
                "lxc": {
                    "start": adapter.start_container,
                    "stop": adapter.stop_container,
                    "shutdown": adapter.shutdown_container,
                    "reboot": adapter.reboot_container,
                },
            }

            type_actions = action_map.get(vm_type, {})
            fn = type_actions.get(action)
            if not fn:
                raise ValueError(f"Unsupported action '{action}' for type '{vm_type}'")

            result = await fn(node, vmid)
            if not result.success:
                raise ValueError(result.error or f"Action '{action}' failed")
            return result.data or {}

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
    ) -> dict:
        """Create a snapshot."""
        async with await self._get_adapter(controller) as adapter:
            result = await adapter.create_snapshot(
                node, vmid, snapname, description, vm_type, vmstate
            )
            if not result.success:
                raise ValueError(result.error or "Snapshot creation failed")
            return {"upid": result.data}

    async def rollback_snapshot(
        self,
        controller: Any,
        node: str,
        vmid: int,
        snapname: str,
        vm_type: str = "qemu",
        *,
        confirmed: bool = False,
    ) -> dict:
        """Rollback to a snapshot — discards all guest state since the snapshot.

        A guest-scoped destructive op: allowed on the direct path with an explicit
        ``confirmed`` second factor (the UI's type-to-confirm dialog supplies it).
        We do NOT pass ``force``, so the Proxmox client read-only gate still
        applies: a confirmed rollback is refused while read-only is ON (→ 403) and
        proceeds only in read-write mode.
        """
        if not confirmed:
            from app.adapters.exceptions import AdapterConfirmationRequiredError

            raise AdapterConfirmationRequiredError(
                "Rolling back a snapshot discards all guest state since it — "
                "resubmit with confirmed=true to proceed.",
                adapter_id="proxmox",
            )
        async with await self._get_adapter(controller) as adapter:
            result = await adapter.rollback_snapshot(node, vmid, snapname, vm_type)
            if not result.success:
                raise ValueError(result.error or "Snapshot rollback failed")
            return {"upid": result.data}

    async def delete_snapshot(
        self, controller: Any, node: str, vmid: int, snapname: str, vm_type: str = "qemu"
    ) -> dict:
        """Delete a snapshot."""
        async with await self._get_adapter(controller) as adapter:
            result = await adapter.delete_snapshot(node, vmid, snapname, vm_type)
            if not result.success:
                raise ValueError(result.error or "Snapshot deletion failed")
            return {"upid": result.data}

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
                return []
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
                return []
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
    ) -> dict:
        """Trigger a manual backup."""
        async with await self._get_adapter(controller) as adapter:
            result = await adapter.run_backup(node, vmid, storage, mode, compress)
            if not result.success:
                raise ValueError(result.error or "Backup failed")
            return {"upid": result.data}

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
    ) -> dict:
        """Clone a VM or container."""
        async with await self._get_adapter(controller) as adapter:
            if vm_type == "lxc":
                result = await adapter.clone_container(
                    node,
                    vmid,
                    newid,
                    hostname=name,
                    target=target,
                    full=full,
                    storage=storage,
                    description=description,
                )
            else:
                result = await adapter.clone_vm(
                    node,
                    vmid,
                    newid,
                    name=name,
                    target=target,
                    full=full,
                    storage=storage,
                    description=description,
                )
            if not result.success:
                raise ValueError(result.error or "Clone failed")
            return result.data or {}

    async def migrate_vm(
        self,
        controller: Any,
        node: str,
        vmid: int,
        target: str,
        vm_type: str = "qemu",
        online: bool = True,
    ) -> dict:
        """Migrate a VM or container to another node."""
        async with await self._get_adapter(controller) as adapter:
            if vm_type == "lxc":
                result = await adapter.migrate_container(node, vmid, target, online=online)
            else:
                result = await adapter.migrate_vm(node, vmid, target, online=online)
            if not result.success:
                raise ValueError(result.error or "Migration failed")
            return result.data or {}

    async def resize_disk(
        self,
        controller: Any,
        node: str,
        vmid: int,
        disk: str,
        size: str,
        vm_type: str = "qemu",
    ) -> dict:
        """Resize a VM/CT disk."""
        async with await self._get_adapter(controller) as adapter:
            if vm_type == "lxc":
                result = await adapter.resize_container_disk(node, vmid, disk, size)
            else:
                result = await adapter.resize_vm_disk(node, vmid, disk, size)
            if not result.success:
                raise ValueError(result.error or "Resize failed")
            return {"status": "ok"}

    async def update_config(
        self,
        controller: Any,
        node: str,
        vmid: int,
        config: dict,
        vm_type: str = "qemu",
    ) -> dict:
        """Update VM/CT configuration."""
        async with await self._get_adapter(controller) as adapter:
            if vm_type == "lxc":
                result = await adapter.update_container_config(node, vmid, config)
            else:
                result = await adapter.update_vm_config(node, vmid, config)
            if not result.success:
                raise ValueError(result.error or "Config update failed")
            return {"status": "ok"}

    async def convert_to_template(
        self,
        controller: Any,
        node: str,
        vmid: int,
        vm_type: str = "qemu",
    ) -> dict:
        """Convert VM/CT to template."""
        async with await self._get_adapter(controller) as adapter:
            result = await adapter.convert_to_template(node, vmid, vm_type)
            if not result.success:
                raise ValueError(result.error or "Template conversion failed")
            return {"status": "ok"}

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
                return []
            return [TaskLogEntry(n=l.n, t=l.t) for l in (result.data or [])]

    async def stop_task(self, controller: Any, node: str, upid: str) -> dict:
        """Stop a running task."""
        async with await self._get_adapter(controller) as adapter:
            result = await adapter.stop_task(node, upid)
            if not result.success:
                raise ValueError(result.error or "Failed to stop task")
            return {"status": "ok"}

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
                return []
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

    async def create_firewall_rule(
        self,
        controller: Any,
        node: str | None = None,
        vmid: int | None = None,
        vm_type: str = "qemu",
        **kwargs: Any,
    ) -> dict:
        """Create a firewall rule."""
        async with await self._get_adapter(controller) as adapter:
            result = await adapter.create_firewall_rule(
                node=node, vmid=vmid, vm_type=vm_type, **kwargs
            )
            if not result.success:
                raise ValueError(result.error or "Failed to create firewall rule")
            return {"status": "ok"}

    async def delete_firewall_rule(
        self,
        controller: Any,
        pos: int,
        node: str | None = None,
    ) -> dict:
        """Delete a firewall rule."""
        async with await self._get_adapter(controller) as adapter:
            result = await adapter.delete_firewall_rule(pos, node)
            if not result.success:
                raise ValueError(result.error or "Failed to delete firewall rule")
            return {"status": "ok"}

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
                return []
            return result.data or []

    async def create_guest_firewall_rule(
        self, controller: Any, node: str, vm_type: str, vmid: int, rule: dict
    ) -> dict:
        """Create a firewall rule on a VM/CT."""
        async with await self._get_adapter(controller) as adapter:
            result = await adapter.create_guest_firewall_rule(node, vm_type, vmid, rule)
            if not result.success:
                raise ValueError(result.error or "Failed to create guest firewall rule")
            return {"status": "ok"}

    async def delete_guest_firewall_rule(
        self, controller: Any, node: str, vm_type: str, vmid: int, pos: int
    ) -> dict:
        """Delete a firewall rule on a VM/CT."""
        async with await self._get_adapter(controller) as adapter:
            result = await adapter.delete_guest_firewall_rule(node, vm_type, vmid, pos)
            if not result.success:
                raise ValueError(result.error or "Failed to delete guest firewall rule")
            return {"status": "ok"}

    async def get_guest_firewall_options(
        self, controller: Any, node: str, vm_type: str, vmid: int
    ) -> dict:
        """Get firewall options for a VM/CT."""
        async with await self._get_adapter(controller) as adapter:
            result = await adapter.get_guest_firewall_options(node, vm_type, vmid)
            if not result.success:
                return {}
            return result.data or {}

    async def update_guest_firewall_options(
        self, controller: Any, node: str, vm_type: str, vmid: int, options: dict
    ) -> dict:
        """Update firewall options for a VM/CT."""
        async with await self._get_adapter(controller) as adapter:
            result = await adapter.update_guest_firewall_options(node, vm_type, vmid, options)
            if not result.success:
                raise ValueError(result.error or "Failed to update guest firewall options")
            return {"status": "ok"}

    async def get_cluster_firewall_options(self, controller: Any) -> dict:
        """Get cluster-level firewall options."""
        async with await self._get_adapter(controller) as adapter:
            result = await adapter.get_cluster_firewall_options()
            if not result.success:
                return {}
            return result.data or {}

    async def update_cluster_firewall_options(self, controller: Any, options: dict) -> dict:
        """Update cluster-level firewall options."""
        async with await self._get_adapter(controller) as adapter:
            result = await adapter.update_cluster_firewall_options(options)
            if not result.success:
                raise ValueError(result.error or "Failed to update cluster firewall options")
            return {"status": "ok"}

    # ═══════════════════════════════════════════════════════════════════════
    # NODE EXTRAS
    # ═══════════════════════════════════════════════════════════════════════

    async def shutdown_node(self, controller: Any, node: str, *, confirmed: bool = False) -> dict:
        """Shutdown a node (catastrophic — whole node offline, no auto-recovery).

        ``confirmed`` is the type-to-confirm second factor; we never pass force,
        so the read-only gate still applies (refused under read-only → 403).
        """
        async with await self._get_adapter(controller) as adapter:
            result = await adapter.shutdown_node(node, confirmed=confirmed)
            if not result.success:
                raise ValueError(result.error or "Node shutdown failed")
            return {"status": "ok"}

    async def reboot_node(self, controller: Any, node: str, *, confirmed: bool = False) -> dict:
        """Reboot a node (catastrophic — whole node and its guests offline).

        ``confirmed`` is the type-to-confirm second factor; we never pass force,
        so the read-only gate still applies (refused under read-only → 403).
        """
        async with await self._get_adapter(controller) as adapter:
            result = await adapter.reboot_node(node, confirmed=confirmed)
            if not result.success:
                raise ValueError(result.error or "Node reboot failed")
            return {"status": "ok"}

    async def get_node_services(self, controller: Any, node: str) -> list[NodeServiceResponse]:
        """Get node services."""
        async with await self._get_adapter(controller) as adapter:
            result = await adapter.get_node_services(node)
            if not result.success:
                return []
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
                return []
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
                return []
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
                return []
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
                return []
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

    async def delete_storage_volume(
        self, controller: Any, node: str, storage: str, volume: str
    ) -> dict:
        """Delete a storage volume."""
        _refuse_direct_catastrophic("delete_storage_volume")
        async with await self._get_adapter(controller) as adapter:
            result = await adapter.delete_storage_volume(node, storage, volume)
            if not result.success:
                raise ValueError(result.error or "Failed to delete volume")
            return {"status": "ok"}

    # ═══════════════════════════════════════════════════════════════════════
    # VM / CT CREATION
    # ═══════════════════════════════════════════════════════════════════════

    async def get_next_vmid(self, controller: Any) -> NextVMIDResponse:
        """Get next available VMID."""
        async with await self._get_adapter(controller) as adapter:
            result = await adapter.get_next_vmid()
            if not result.success:
                raise ValueError(result.error or "Failed to get next VMID")
            return NextVMIDResponse(vmid=int(result.data))

    async def create_vm(
        self,
        controller: Any,
        *,
        vmid: int | None = None,
        name: str = "",
        node: str,
        cores: int = 1,
        sockets: int = 1,
        memory: int = 2048,
        balloon: int = 0,
        ostype: str = "l26",
        storage: str = "local-lvm",
        disk_size: str = "32G",
        iso: str = "",
        net_bridge: str = "vmbr0",
        net_model: str = "virtio",
        cpu_type: str = "host",
        bios: str = "seabios",
        machine: str = "",
        start: bool = False,
        pool: str = "",
        description: str = "",
        onboot: bool = False,
        tags: str = "",
    ) -> CreateVMResponse:
        """Create a new QEMU VM."""
        async with await self._get_adapter(controller) as adapter:
            if vmid is None:
                id_result = await adapter.get_next_vmid()
                if not id_result.success:
                    raise ValueError("Failed to allocate VMID")
                vmid = int(id_result.data)

            result = await adapter.create_vm(
                node,
                vmid,
                name=name,
                cores=cores,
                sockets=sockets,
                memory=memory,
                balloon=balloon,
                ostype=ostype,
                storage=storage,
                disk_size=disk_size,
                iso=iso,
                net_bridge=net_bridge,
                net_model=net_model,
                cpu_type=cpu_type,
                bios=bios,
                machine=machine,
                start=start,
                pool=pool,
                description=description,
                onboot=onboot,
                tags=tags,
            )
            if not result.success:
                raise ValueError(result.error or "Failed to create VM")
            data = result.data or {}
            return CreateVMResponse(
                vmid=vmid,
                upid=str(data.get("upid", "")),
                message=f"VM {vmid} creation started on {node}",
            )

    async def create_container(
        self,
        controller: Any,
        *,
        vmid: int | None = None,
        hostname: str = "",
        node: str,
        ostemplate: str,
        cores: int = 1,
        memory: int = 512,
        swap: int = 512,
        storage: str = "local-lvm",
        rootfs_size: str = "8",
        net_bridge: str = "vmbr0",
        net_ip: str = "dhcp",
        password: str = "",
        ssh_public_keys: str = "",
        start: bool = False,
        pool: str = "",
        description: str = "",
        unprivileged: bool = True,
        onboot: bool = False,
        tags: str = "",
        nameserver: str = "",
        searchdomain: str = "",
    ) -> CreateVMResponse:
        """Create a new LXC container."""
        async with await self._get_adapter(controller) as adapter:
            if vmid is None:
                id_result = await adapter.get_next_vmid()
                if not id_result.success:
                    raise ValueError("Failed to allocate VMID")
                vmid = int(id_result.data)

            result = await adapter.create_container(
                node,
                vmid,
                ostemplate=ostemplate,
                hostname=hostname,
                cores=cores,
                memory=memory,
                swap=swap,
                storage=storage,
                rootfs_size=rootfs_size,
                net_bridge=net_bridge,
                net_ip=net_ip,
                password=password,
                ssh_public_keys=ssh_public_keys,
                start=start,
                pool=pool,
                description=description,
                unprivileged=unprivileged,
                onboot=onboot,
                tags=tags,
                nameserver=nameserver,
                searchdomain=searchdomain,
            )
            if not result.success:
                raise ValueError(result.error or "Failed to create container")
            data = result.data or {}
            return CreateVMResponse(
                vmid=vmid,
                upid=str(data.get("upid", "")),
                message=f"Container {vmid} creation started on {node}",
            )

    async def delete_vm(
        self,
        controller: Any,
        node: str,
        vmid: int,
        vm_type: str = "qemu",
        *,
        confirmed: bool = False,
    ) -> dict:
        """Delete a VM or container.

        Destroying a guest is irreversible, so ``confirmed`` must be true — the
        UI's type-to-confirm dialog supplies it. Without it the adapter's
        guard raises AdapterConfirmationRequiredError (→ HTTP 409), prompting the
        caller to confirm. ``confirmed`` is the second factor ONLY — we do NOT
        pass ``force`` (the staging read-only bypass), so the Proxmox client
        read-only gate still applies: a confirmed delete is refused while
        read-only is ON (→ 403) and proceeds only in read-write mode.
        """
        async with await self._get_adapter(controller) as adapter:
            result = await adapter.delete_vm(node, vmid, vm_type, confirmed=confirmed)
            if not result.success:
                raise ValueError(result.error or f"Failed to delete {vm_type} {vmid}")
            return result.data or {}

    # ═══════════════════════════════════════════════════════════════════════
    # HA MANAGEMENT
    # ═══════════════════════════════════════════════════════════════════════

    async def create_ha_resource(
        self,
        controller: Any,
        sid: str,
        *,
        group: str = "",
        max_relocate: int = 1,
        max_restart: int = 1,
        state: str = "started",
        comment: str = "",
    ) -> dict:
        """Add a VM/CT to HA management."""
        async with await self._get_adapter(controller) as adapter:
            result = await adapter.create_ha_resource(
                sid,
                group=group,
                max_relocate=max_relocate,
                max_restart=max_restart,
                state=state,
                comment=comment,
            )
            if not result.success:
                raise ValueError(result.error or "Failed to create HA resource")
            return {"status": "ok"}

    async def delete_ha_resource(self, controller: Any, sid: str) -> dict:
        """Remove a VM/CT from HA management."""
        async with await self._get_adapter(controller) as adapter:
            result = await adapter.delete_ha_resource(sid)
            if not result.success:
                raise ValueError(result.error or "Failed to delete HA resource")
            return {"status": "ok"}

    async def create_ha_group(
        self,
        controller: Any,
        group: str,
        nodes: str,
        *,
        nofailback: bool = False,
        restricted: bool = False,
        comment: str = "",
    ) -> dict:
        """Create an HA group."""
        async with await self._get_adapter(controller) as adapter:
            result = await adapter.create_ha_group(
                group,
                nodes,
                nofailback=nofailback,
                restricted=restricted,
                comment=comment,
            )
            if not result.success:
                raise ValueError(result.error or "Failed to create HA group")
            return {"status": "ok"}

    async def delete_ha_group(self, controller: Any, group: str) -> dict:
        """Delete an HA group."""
        async with await self._get_adapter(controller) as adapter:
            result = await adapter.delete_ha_group(group)
            if not result.success:
                raise ValueError(result.error or "Failed to delete HA group")
            return {"status": "ok"}

    # ═══════════════════════════════════════════════════════════════════════
    # FLEET DASHBOARD (MULTI-CLUSTER)
    # ═══════════════════════════════════════════════════════════════════════

    async def get_fleet_dashboard(self, controllers: list[Any]) -> FleetDashboardResponse:
        """Get aggregated fleet dashboard across multiple Proxmox clusters."""
        fleet = FleetDashboardResponse()
        fleet.total_clusters = len(controllers)

        async def _fetch_one(ctrl: Any) -> FleetClusterSummary:
            summary = FleetClusterSummary(
                controller_id=str(ctrl.id),
                controller_name=ctrl.name or ctrl.host,
            )
            try:
                async with _fleet_semaphore:
                    dashboard = await asyncio.wait_for(
                        self.get_dashboard(ctrl),
                        timeout=_FLEET_TIMEOUT,
                    )
                summary.cluster_name = dashboard.cluster_name
                summary.quorate = dashboard.quorate
                summary.total_nodes = dashboard.total_nodes
                summary.online_nodes = dashboard.online_nodes
                summary.total_vms = dashboard.total_vms
                summary.running_vms = dashboard.running_vms
                summary.total_containers = dashboard.total_containers
                summary.running_containers = dashboard.running_containers
                summary.total_cpu_cores = dashboard.total_cpu_cores
                summary.cpu_usage_percent = dashboard.cpu_usage_percent
                summary.total_memory_bytes = dashboard.total_memory_bytes
                summary.used_memory_bytes = dashboard.used_memory_bytes
                summary.memory_usage_percent = dashboard.memory_usage_percent
                summary.total_storage_bytes = dashboard.total_storage_bytes
                summary.used_storage_bytes = dashboard.used_storage_bytes
                summary.storage_usage_percent = dashboard.storage_usage_percent
                summary.status = "online"
            except TimeoutError:
                summary.status = "error"
                summary.error = "Cluster response timed out"
                logger.warning("Fleet dashboard: timeout for %s", ctrl.host)
            except Exception as e:
                summary.status = "error"
                summary.error = "Failed to connect to cluster"
                logger.error("Fleet dashboard error for %s: %s", ctrl.host, e)
            return summary

        results = await asyncio.gather(
            *[_fetch_one(c) for c in controllers],
            return_exceptions=True,
        )

        for r in results:
            if isinstance(r, Exception):
                continue
            fleet.clusters.append(r)
            if r.status == "online":
                fleet.online_clusters += 1
                fleet.total_nodes += r.total_nodes
                fleet.online_nodes += r.online_nodes
                fleet.total_vms += r.total_vms
                fleet.running_vms += r.running_vms
                fleet.total_containers += r.total_containers
                fleet.running_containers += r.running_containers
                fleet.total_cpu_cores += r.total_cpu_cores
                fleet.total_memory_bytes += r.total_memory_bytes
                fleet.used_memory_bytes += r.used_memory_bytes
                fleet.total_storage_bytes += r.total_storage_bytes
                fleet.used_storage_bytes += r.used_storage_bytes

        # Compute aggregate percentages
        if fleet.total_cpu_cores > 0:
            weighted_cpu = sum(
                c.cpu_usage_percent * c.total_cpu_cores
                for c in fleet.clusters
                if c.status == "online"
            )
            fleet.cpu_usage_percent = round(weighted_cpu / fleet.total_cpu_cores, 1)
        if fleet.total_memory_bytes > 0:
            fleet.memory_usage_percent = round(
                fleet.used_memory_bytes / fleet.total_memory_bytes * 100, 1
            )
        if fleet.total_storage_bytes > 0:
            fleet.storage_usage_percent = round(
                fleet.used_storage_bytes / fleet.total_storage_bytes * 100, 1
            )

        return fleet

    # ═══════════════════════════════════════════════════════════════════════
    # BULK OPERATIONS
    # ═══════════════════════════════════════════════════════════════════════

    async def bulk_action(
        self, controller: Any, targets: list[dict], action: str, *, confirmed: bool = False
    ) -> list[dict]:
        """Execute an action on multiple VMs/CTs concurrently.

        ``confirmed`` is the type-to-confirm second factor for action="delete"
        (irreversible). It is passed as confirmed= only — never as force — so each
        delete still honors the read-only gate (refused while read-only is ON).
        """
        sem = asyncio.Semaphore(5)

        async def _do_one(t: dict, adapter: Any) -> dict:
            async with sem:
                try:
                    if action == "delete":
                        result = await adapter.delete_vm(
                            t["node"], t["vmid"], vm_type=t["vm_type"], confirmed=confirmed
                        )
                    else:
                        method_map = {
                            "start": "start_vm" if t["vm_type"] == "qemu" else "start_container",
                            "stop": "stop_vm" if t["vm_type"] == "qemu" else "stop_container",
                            "shutdown": "shutdown_vm"
                            if t["vm_type"] == "qemu"
                            else "shutdown_container",
                            "reboot": "reboot_vm" if t["vm_type"] == "qemu" else "reboot_container",
                        }
                        method_name = method_map.get(action)
                        if not method_name:
                            return {
                                "vmid": t["vmid"],
                                "node": t["node"],
                                "success": False,
                                "error": f"Unknown action: {action}",
                            }
                        method = getattr(adapter, method_name)
                        result = await method(t["node"], t["vmid"])
                    if not result.success:
                        return {
                            "vmid": t["vmid"],
                            "node": t["node"],
                            "success": False,
                            "error": (result.error or "Unknown error")[:200],
                        }
                    upid = result.data
                    return {
                        "vmid": t["vmid"],
                        "node": t["node"],
                        "success": True,
                        "upid": str(upid) if upid else None,
                    }
                except Exception as e:
                    return {
                        "vmid": t["vmid"],
                        "node": t["node"],
                        "success": False,
                        "error": str(e)[:200],
                    }

        async with await self._get_adapter(controller) as adapter:
            results = await asyncio.gather(
                *[_do_one(t, adapter) for t in targets], return_exceptions=True
            )
        return [
            r
            if isinstance(r, dict)
            else {"vmid": 0, "node": "", "success": False, "error": str(r)[:200]}
            for r in results
        ]

    async def bulk_migrate(
        self, controller: Any, targets: list[dict], target_node: str, online: bool = True
    ) -> list[dict]:
        """Migrate multiple VMs/CTs to a target node concurrently."""
        sem = asyncio.Semaphore(3)

        async def _do_one(t: dict, adapter: Any) -> dict:
            async with sem:
                try:
                    if t["vm_type"] == "qemu":
                        result = await adapter.migrate_vm(t["node"], t["vmid"], target_node, online)
                    else:
                        result = await adapter.migrate_container(
                            t["node"], t["vmid"], target_node, online
                        )
                    if not result.success:
                        return {
                            "vmid": t["vmid"],
                            "node": t["node"],
                            "success": False,
                            "error": (result.error or "Unknown error")[:200],
                        }
                    upid = result.data
                    return {
                        "vmid": t["vmid"],
                        "node": t["node"],
                        "success": True,
                        "upid": str(upid) if upid else None,
                    }
                except Exception as e:
                    return {
                        "vmid": t["vmid"],
                        "node": t["node"],
                        "success": False,
                        "error": str(e)[:200],
                    }

        async with await self._get_adapter(controller) as adapter:
            results = await asyncio.gather(
                *[_do_one(t, adapter) for t in targets], return_exceptions=True
            )
        return [
            r
            if isinstance(r, dict)
            else {"vmid": 0, "node": "", "success": False, "error": str(r)[:200]}
            for r in results
        ]

    async def get_guest_agent_info(self, controller: Any, node: str, vmid: int) -> AdapterResult:
        """Get guest agent network info from a running QEMU VM."""
        async with await self._get_adapter(controller) as adapter:
            return await adapter.get_guest_agent_info(node, vmid)

    async def create_backup_job(self, controller: Any, **kwargs) -> AdapterResult:
        """Create a scheduled backup job."""
        async with await self._get_adapter(controller) as adapter:
            return await adapter.create_backup_job(**kwargs)

    async def update_backup_job(self, controller: Any, job_id: str, **kwargs) -> AdapterResult:
        """Update a backup job."""
        async with await self._get_adapter(controller) as adapter:
            return await adapter.update_backup_job(job_id, **kwargs)

    async def delete_backup_job(self, controller: Any, job_id: str) -> AdapterResult:
        """Delete a backup job."""
        async with await self._get_adapter(controller) as adapter:
            return await adapter.delete_backup_job(job_id)

    async def upload_to_storage(
        self,
        controller: Any,
        node: str,
        storage: str,
        filename: str,
        content_type: str,
        file_path: str,
    ) -> dict:
        """Upload a file (ISO/template) to storage."""
        async with await self._get_adapter(controller) as adapter:
            result = await adapter.upload_to_storage(
                node, storage, filename, content_type, file_path
            )
            if not result.success:
                raise ValueError(result.error or "Upload failed")
            return result.data or {}

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

    async def renew_node_acme_certificate(
        self, controller: Any, node: str, force: bool = False
    ) -> AdapterResult:
        """Renew ACME certificate on a node."""
        async with await self._get_adapter(controller) as adapter:
            return await adapter.renew_node_acme_certificate(node, force)

    async def upload_custom_certificate(
        self,
        controller: Any,
        node: str,
        *,
        certificates: str,
        key: str,
        force: bool = False,
        restart: bool = False,
    ) -> AdapterResult:
        """Upload a custom TLS certificate to a node."""
        async with await self._get_adapter(controller) as adapter:
            return await adapter.upload_custom_certificate(node, certificates, key, force, restart)

    async def delete_custom_certificate(
        self, controller: Any, node: str, restart: bool = False
    ) -> AdapterResult:
        """Delete custom certificate from a node."""
        async with await self._get_adapter(controller) as adapter:
            return await adapter.delete_custom_certificate(node, restart)

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

    async def create_sdn_zone(
        self, controller: Any, zone: str, zone_type: str, **kwargs: Any
    ) -> AdapterResult:
        """Create an SDN zone."""
        async with await self._get_adapter(controller) as adapter:
            return await adapter.create_sdn_zone(zone, zone_type, **kwargs)

    async def create_sdn_vnet(
        self, controller: Any, vnet: str, zone: str, **kwargs: Any
    ) -> AdapterResult:
        """Create an SDN vnet."""
        async with await self._get_adapter(controller) as adapter:
            return await adapter.create_sdn_vnet(vnet, zone, **kwargs)

    async def delete_sdn_zone(self, controller: Any, zone: str) -> AdapterResult:
        """Delete an SDN zone."""
        async with await self._get_adapter(controller) as adapter:
            return await adapter.delete_sdn_zone(zone)

    async def delete_sdn_vnet(self, controller: Any, vnet: str) -> AdapterResult:
        """Delete an SDN vnet."""
        async with await self._get_adapter(controller) as adapter:
            return await adapter.delete_sdn_vnet(vnet)

    async def apply_sdn(self, controller: Any) -> AdapterResult:
        """Apply pending SDN configuration changes."""
        async with await self._get_adapter(controller) as adapter:
            return await adapter.apply_sdn()

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
        """Generate a backup age report across all VMs.

        Fetches all VMs/CTs via cluster resources, then checks all
        backup-capable storage for the latest backup per VMID.
        """
        async with await self._get_adapter(controller) as adapter:
            # 1. Get all VMs and CTs
            res_result = await adapter.get_cluster_resources("vm")
            resources = res_result.data if res_result.success else []
            if not isinstance(resources, list):
                resources = []

            vm_map: dict[int, dict] = {}
            for r in resources:
                if not isinstance(r, dict):
                    continue
                vmid = r.get("vmid")
                if vmid is None:
                    continue
                vm_map[vmid] = {
                    "name": r.get("name", ""),
                    "node": r.get("node", ""),
                }

            # 2. Get storage list from ALL distinct nodes to find backup-capable storage
            distinct_nodes = list({v.get("node", "") for v in vm_map.values() if v.get("node")})
            if not distinct_nodes:
                first_node = next(iter(vm_map.values()), {}).get("node", "") if vm_map else ""
                distinct_nodes = [first_node] if first_node else []

            backup_storages: list[tuple[str, str]] = []  # (node, storage_name)
            # Fetch storage lists from all nodes in parallel
            storage_list_tasks = [adapter.get_storage(n) for n in distinct_nodes]
            storage_list_results = await asyncio.gather(*storage_list_tasks, return_exceptions=True)
            for node_name, result in zip(distinct_nodes, storage_list_results, strict=False):
                if isinstance(result, Exception):
                    continue
                storages = result.data if hasattr(result, "data") and result.data else []
                if not isinstance(storages, list):
                    continue
                for s in storages:
                    content = ""
                    if hasattr(s, "content"):
                        content = s.content
                    elif isinstance(s, dict):
                        content = s.get("content", "")
                    if "backup" in str(content):
                        storage_name = ""
                        if hasattr(s, "storage"):
                            storage_name = s.storage
                        elif isinstance(s, dict):
                            storage_name = s.get("storage", "")
                        if storage_name:
                            backup_storages.append((node_name, storage_name))

            # 3. Fetch backup content from each storage in parallel
            latest_backup: dict[int, float] = {}  # vmid -> epoch timestamp
            storage_tasks = []
            for node_name, storage_name in backup_storages:
                storage_tasks.append(
                    adapter.get_storage_content(node_name, storage_name, content_type="backup")
                )
            storage_results = await asyncio.gather(*storage_tasks, return_exceptions=True)
            for result in storage_results:
                if isinstance(result, Exception):
                    continue
                items = []
                if hasattr(result, "data") and result.data:
                    items = result.data if isinstance(result.data, list) else [result.data]
                elif isinstance(result, list):
                    items = result
                for item in items:
                    if not isinstance(item, dict):
                        continue
                    item_vmid = item.get("vmid")
                    ctime = item.get("ctime", 0)
                    if item_vmid is not None and ctime:
                        existing = latest_backup.get(item_vmid, 0)
                        if ctime > existing:
                            latest_backup[item_vmid] = ctime

            # 4. Build report
            now = datetime.now(tz=UTC)
            reports: list[BackupAgeReport] = []
            backed_up_count = 0
            stale_count = 0
            never_count = 0

            for vmid, info in sorted(vm_map.items()):
                last_ts = latest_backup.get(vmid)
                if last_ts:
                    last_dt = datetime.fromtimestamp(last_ts, tz=UTC)
                    age_h = (now - last_dt).total_seconds() / 3600
                    is_stale = age_h > threshold_hours
                    backed_up_count += 1
                    if is_stale:
                        stale_count += 1
                    reports.append(
                        BackupAgeReport(
                            vmid=vmid,
                            name=info.get("name"),
                            node=info.get("node", ""),
                            last_backup_time=last_dt,
                            age_hours=round(age_h, 1),
                            is_stale=is_stale,
                        )
                    )
                else:
                    never_count += 1
                    reports.append(
                        BackupAgeReport(
                            vmid=vmid,
                            name=info.get("name"),
                            node=info.get("node", ""),
                            is_stale=True,
                        )
                    )

            return BackupAgeResponse(
                threshold_hours=threshold_hours,
                total_vms=len(vm_map),
                backed_up=backed_up_count,
                stale=stale_count,
                never_backed_up=never_count,
                vms=reports,
            )

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

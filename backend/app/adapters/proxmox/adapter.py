# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Proxmox VE Adapter
=================================

Full adapter for Proxmox Virtual Environment.
Implements BaseAdapter for cluster, node, VM, container,
storage, and monitoring operations.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
from typing import Any, BinaryIO, ClassVar
from uuid import UUID

from app.adapters.base import (
    AdapterManifest,
    AdapterResult,
    BaseAdapter,
    DeviceTypeCapabilities,
    DiscoveredDevice,
)
from app.adapters.capabilities import Capability
from app.adapters.exceptions import (
    AdapterConfirmationRequiredError,
    AdapterConnectionError,
    AdapterOutcomeUnknownError,
)
from app.adapters.proxmox import constants as C
from app.adapters.proxmox.client import ProxmoxApiError, ProxmoxClient, ProxmoxClientConfig
from app.adapters.proxmox.constants import DEFAULT_PORT, VM_STATUS_MAP
from app.adapters.proxmox.models import (
    ProxmoxBackupJob,
    ProxmoxCephStatus,
    ProxmoxClusterStatus,
    ProxmoxDiskInfo,
    ProxmoxFirewallRule,
    ProxmoxHAGroup,
    ProxmoxHAResource,
    ProxmoxNetworkInterface,
    ProxmoxNodeInfo,
    ProxmoxNodeService,
    ProxmoxResourcePool,
    ProxmoxRRDPoint,
    ProxmoxSnapshot,
    ProxmoxStorage,
    ProxmoxTask,
    ProxmoxTaskDetail,
    ProxmoxTaskLog,
    ProxmoxVM,
)
from app.adapters.proxmox.permissions import permissions_at_path
from app.adapters.proxmox.sdn import native_flag
from app.modules.hypervisor.sdn_schemas import (
    SdnAttachmentInspection,
    SdnDependencyInspection,
    SdnDryRunObservation,
    SdnInspection,
)

logger = logging.getLogger(__name__)


def _open_binary_for_read(file_path: str) -> BinaryIO:
    """Open a file for binary read; designed to be run in an executor.

    kept as a module-level helper so the threadpool target is
    a top-level callable (no closure over ``self``) — which means
    the executor doesn't accidentally pin adapter state for the
    duration of the upload.

    On Unix, refuses to follow symlinks via ``O_NOFOLLOW`` so a
    storage operator who staged a malicious symlink in the upload
    directory can't redirect the read elsewhere. On Windows / older
    platforms without the flag, falls back to plain ``open``.
    """
    if hasattr(os, "O_NOFOLLOW"):
        fd = os.open(file_path, os.O_RDONLY | os.O_NOFOLLOW)
        return os.fdopen(fd, "rb")
    return open(file_path, "rb")


class ProxmoxAdapter(BaseAdapter):
    """
    Adapter for Proxmox Virtual Environment.

    Supports:
    - Cluster status and resource overview
    - Node management (status, network, storage, tasks)
    - VM (QEMU) lifecycle (start/stop/reboot/snapshot)
    - Container (LXC) lifecycle
    - Storage pool and content management
    - RRD monitoring data
    - Backup jobs
    """

    manifest: ClassVar[AdapterManifest] = AdapterManifest(
        id="proxmox",
        name="Proxmox VE",
        vendor="Proxmox Server Solutions GmbH",
        version="1.0.0",
        description="Proxmox Virtual Environment hypervisor management",
        controller_type="proxmox",
        supports_controller=True,
        supports_direct=False,
        supported_versions=["7.0", "7.1", "7.2", "7.3", "7.4", "8.0", "8.1", "8.2", "8.3"],
        device_types={
            "hypervisor": DeviceTypeCapabilities(
                module="hypervisor",
                capabilities=[
                    Capability.DEVICE_INFO,
                    Capability.DEVICE_REBOOT,
                    Capability.DEVICE_METRICS,
                    Capability.DEVICE_LOGS,
                    Capability.DEVICE_BACKUP,
                    # Existing hypervisor-tier surfaces.
                    Capability.COMPUTE_CLUSTER_STATUS,
                    Capability.COMPUTE_NODE_LIST,
                    Capability.COMPUTE_NODE_STATUS,
                    Capability.COMPUTE_VM_LIST,
                    Capability.COMPUTE_VM_CONTROL,
                    Capability.COMPUTE_VM_SNAPSHOT,
                    Capability.COMPUTE_VM_CONSOLE,
                    Capability.COMPUTE_VM_CONFIG,
                    Capability.COMPUTE_CONTAINER_LIST,
                    Capability.COMPUTE_CONTAINER_CONTROL,
                    Capability.COMPUTE_STORAGE_LIST,
                    Capability.COMPUTE_STORAGE_CONTENT,
                    Capability.COMPUTE_BACKUP_MANAGE,
                    Capability.COMPUTE_MONITORING,
                    Capability.COMPUTE_NETWORK,
                    Capability.COMPUTE_TASKS,
                    # Per-domain feature surfaces — backed by
                    # adapter_proxmox_* services + endpoints.
                    Capability.PROXMOX_VM_LIFECYCLE,
                    Capability.PROXMOX_VM_CONFIG,
                    Capability.PROXMOX_VM_CLONE,
                    Capability.PROXMOX_VM_MIGRATE,
                    Capability.PROXMOX_VM_GUEST_AGENT,
                    Capability.PROXMOX_VM_CLOUDINIT,
                    Capability.PROXMOX_CONTAINER_LIFECYCLE,
                    Capability.PROXMOX_CONTAINER_CONFIG,
                    Capability.PROXMOX_CONTAINER_CLONE,
                    Capability.PROXMOX_CONTAINER_MIGRATE,
                    Capability.PROXMOX_SNAPSHOT_CREATE,
                    Capability.PROXMOX_SNAPSHOT_ROLLBACK,
                    Capability.PROXMOX_SNAPSHOT_DELETE,
                    Capability.PROXMOX_STORAGE_VOLUME,
                    Capability.PROXMOX_STORAGE_UPLOAD,
                    Capability.PROXMOX_BACKUP_JOBS,
                    Capability.PROXMOX_BACKUP_RUN,
                    Capability.PROXMOX_BACKUP_RESTORE,
                    Capability.PROXMOX_BACKUP_PRUNE,
                    Capability.PROXMOX_NODE_CONTROL,
                    Capability.PROXMOX_NODE_CERTIFICATE,
                    Capability.PROXMOX_NODE_APT,
                    Capability.PROXMOX_NODE_SERVICE,
                    Capability.PROXMOX_CLUSTER_TASKS,
                    Capability.PROXMOX_CLUSTER_FIREWALL,
                    Capability.PROXMOX_HA_GROUPS,
                    Capability.PROXMOX_HA_RESOURCES,
                    Capability.PROXMOX_REPLICATION,
                    Capability.PROXMOX_SDN_ZONE,
                    Capability.PROXMOX_SDN_VNET,
                    Capability.PROXMOX_CEPH_STATUS,
                    Capability.PROXMOX_CEPH_MON,
                    Capability.PROXMOX_CEPH_OSD,
                    Capability.PROXMOX_CEPH_POOLS,
                    Capability.PROXMOX_FIREWALL_CLUSTER,
                    Capability.PROXMOX_FIREWALL_GUEST,
                ],
            ),
        },
        auth_methods=["api_token", "username_password"],
        rate_limit_calls_per_minute=120,
        rate_limit_concurrent=10,
        default_sync_interval=120,
        min_sync_interval=30,
        supports_real_time_events=False,
        supports_bulk_operations=True,
    )

    def __init__(
        self,
        host: str,
        username: str = "",
        password: str = "",
        *,
        port: int = DEFAULT_PORT,
        use_ssl: bool = True,
        verify_ssl: bool = False,
        token_id: str = "",
        token_secret: str = "",
        realm: str = "pam",
        transport: Any = None,
        **kwargs: Any,
    ):
        self.host = host
        self._client: ProxmoxClient | None = None
        # Optional httpx transport. The service layer that knows this device's
        # site passes ``agent_transport_for_site(...)`` here (via the create_adapter
        # **kwargs corridor) so an agent-only site is reached through the agent;
        # ``None`` (the default) builds a normal, overlay-aware client — today's
        # behavior unchanged. See docs.freesdn.org.
        self._transport = transport
        # Tracked so callers (including ``_get_proxmox_adapter`` helpers in
        # the gateway services) can short-circuit redundant ``connect()``
        # calls. Set inside ``connect()`` once authentication succeeds.
        self._connected: bool = False
        self._config = ProxmoxClientConfig(
            host=host,
            port=port,
            use_ssl=use_ssl,
            verify_ssl=verify_ssl,
            token_id=token_id,
            token_secret=token_secret,
            username=username,
            password=password,
            realm=realm,
        )

    # ── Context manager ────────────────────────────────────────────────────

    async def __aenter__(self) -> ProxmoxAdapter:
        await self.connect()
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.disconnect()

    # ── BaseAdapter required methods ───────────────────────────────────────

    async def connect(self) -> bool:
        """Connect and authenticate to Proxmox."""
        try:
            self._client = ProxmoxClient(self._config, transport=self._transport)
            await self._client.connect()
            # Mark connected so gateway services can short-circuit
            # redundant connect() calls. Failure leaves the flag False so
            # callers re-attempt instead of trusting a half-built client.
            self._connected = True
            return True
        except ProxmoxApiError as e:
            logger.error("Proxmox connect failed for %s: %s", self.host, e)
            raise AdapterConnectionError(
                f"Connection to {self.host} failed: {e}",
                adapter_id="proxmox",
            ) from e

    async def disconnect(self) -> None:
        """Close the connection."""
        if self._client:
            await self._client.close()
            self._client = None
        self._connected = False

    async def test_connection(self) -> AdapterResult:
        """Test connection by fetching cluster status."""
        try:
            client = ProxmoxClient(self._config, transport=self._transport)
            async with client:
                data = await client.get(C.CLUSTER_STATUS)
                if data is not None:
                    return AdapterResult.ok({"status": "connected", "cluster": data})
                return AdapterResult.fail("No data returned from cluster status")
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__, error_code="CONNECTION_ERROR")
        except Exception as e:
            return AdapterResult.fail(type(e).__name__, error_code="UNEXPECTED_ERROR")

    async def discover_devices(self) -> list[DiscoveredDevice]:
        """Discover PVE nodes as devices."""
        self._ensure_connected()
        try:
            nodes = await self._client.get(C.NODES)  # type: ignore[union-attr]
            if not isinstance(nodes, list):
                raise AdapterConnectionError("Invalid Proxmox node inventory", adapter_id="proxmox")

            devices = []
            node_names: set[str] = set()
            for n in nodes:
                node_name = n.get("node") if isinstance(n, dict) else None
                if (
                    not isinstance(node_name, str)
                    or not node_name.strip()
                    or node_name in node_names
                ):
                    raise AdapterConnectionError(
                        "Invalid Proxmox node inventory", adapter_id="proxmox"
                    )
                node_names.add(node_name)
                status = "online" if n.get("status") == "online" else "offline"
                devices.append(
                    DiscoveredDevice(
                        mac_address=f"proxmox-{node_name}",
                        ip_address=n.get("ip"),
                        name=node_name,
                        vendor="Proxmox",
                        model="PVE Node",
                        firmware_version=n.get("pveversion", ""),
                        device_type="hypervisor",
                        status=status,
                        serial_number=None,
                        raw_data=n,
                    )
                )
            return devices
        except ProxmoxApiError:
            logger.error("Proxmox node discovery failed")
            raise AdapterConnectionError(
                "Proxmox node discovery failed", adapter_id="proxmox"
            ) from None

    async def get_device_status(self, device_id: str) -> dict:
        """Get node status by node name."""
        self._ensure_connected()
        data = await self._client.get(C.NODE_STATUS.format(node=device_id))  # type: ignore[union-attr]
        return data if isinstance(data, dict) else {}

    async def get_device_info(self, device_id: str) -> DiscoveredDevice | None:
        """Get node info."""
        self._ensure_connected()
        try:
            data = await self._client.get(C.NODE_STATUS.format(node=device_id))  # type: ignore[union-attr]
            if not isinstance(data, dict):
                return None
            return DiscoveredDevice(
                mac_address=f"proxmox-{device_id}",
                ip_address=None,
                name=device_id,
                vendor="Proxmox",
                model="PVE Node",
                firmware_version=data.get("pveversion", ""),
                device_type="hypervisor",
                status="online" if data.get("uptime", 0) > 0 else "offline",
                raw_data=data,
            )
        except ProxmoxApiError:
            return None

    # ═══════════════════════════════════════════════════════════════════════
    # CLUSTER
    # ═══════════════════════════════════════════════════════════════════════

    async def get_cluster_status(self) -> AdapterResult:
        """Get validated cluster status without truthy-string quorum/online flags."""
        self._ensure_connected()
        try:
            data = await self._client.get(C.CLUSTER_STATUS)  # type: ignore[union-attr]
            if not isinstance(data, list) or not data or len(data) > 1025:
                raise ValueError("Invalid cluster status collection")
            cluster_info = None
            nodes: list[ProxmoxNodeInfo] = []
            names: set[str] = set()
            for item in data:
                if not isinstance(item, dict):
                    raise ValueError("Invalid cluster status row")
                if item.get("type") == "cluster":
                    if cluster_info is not None:
                        raise ValueError("Duplicate cluster status")
                    cluster_info = item
                elif item.get("type") == "node":
                    name = item.get("name")
                    if (
                        not isinstance(name, str)
                        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,62}", name)
                        or name in names
                    ):
                        raise ValueError("Invalid cluster node identity")
                    names.add(name)
                    nodes.append(
                        ProxmoxNodeInfo(
                            node=name,
                            status="online" if native_flag(item.get("online")) else "offline",
                            ip=item.get("ip"),
                            level=item.get("level", ""),
                        )
                    )
            if not nodes or (cluster_info is None and len(nodes) != 1):
                raise ValueError("Cluster membership is unavailable")
            name = cluster_info.get("name") if cluster_info else "pve"
            version = cluster_info.get("version", 0) if cluster_info else 0
            if (
                not isinstance(name, str)
                or len(name) > 255
                or type(version) is not int
                or version < 0
            ):
                raise ValueError("Invalid cluster metadata")
            return AdapterResult.ok(
                ProxmoxClusterStatus(
                    name=name,
                    quorate=native_flag(cluster_info.get("quorate"))
                    if cluster_info
                    else any(n.status == "online" for n in nodes),
                    node_count=len(nodes),
                    version=version,
                    nodes=nodes,
                )
            )
        except (ValueError, TypeError):
            return AdapterResult.fail(
                "Unexpected cluster status response", error_code="invalid_response"
            )
        except ProxmoxApiError as exc:
            return AdapterResult.fail(type(exc).__name__)

    async def get_cluster_resources(self, resource_type: str | None = None) -> AdapterResult:
        """Get unified cluster resource list (nodes, VMs, storage, etc.)."""
        self._ensure_connected()
        try:
            params = {}
            if resource_type:
                params["type"] = resource_type
            data = await self._client.get(C.CLUSTER_RESOURCES, params=params or None)  # type: ignore[union-attr]
            if not isinstance(data, list):
                return AdapterResult.fail(
                    "Unexpected inventory response", error_code="invalid_response"
                )
            return AdapterResult.ok(data)
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    async def get_ha_status(self) -> AdapterResult:
        """Get HA cluster status."""
        self._ensure_connected()
        try:
            data = await self._client.get(C.CLUSTER_HA_STATUS)  # type: ignore[union-attr]
            return AdapterResult.ok(data)
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    async def get_ha_configuration(self, kind: str) -> AdapterResult:
        """Raw HA configuration, retaining identities/defaults without empty fallbacks."""
        if kind not in {"resources", "groups"}:
            raise ValueError("Invalid HA configuration kind")
        self._ensure_connected()
        assert self._client is not None
        try:
            data = await self._client.get(f"/cluster/ha/{kind}")
            if not isinstance(data, list):
                return AdapterResult.fail("Malformed HA configuration response")
            return AdapterResult.ok(data)
        except ProxmoxApiError:
            return AdapterResult.fail("HA configuration unavailable")

    async def get_cluster_operation_state(self, *, include_groups: bool = False) -> AdapterResult:
        """Read-only impact review. Group API errors after rule migration fail closed."""
        self._ensure_connected()
        assert self._client is not None
        try:
            data = {
                "permissions": {
                    "/vms": permissions_at_path(
                        await self._client.get("/access/permissions", params={"path": "/vms"}),
                        "/vms",
                    )
                },
                "status": await self._client.get("/cluster/status"),
                "guests": await self._client.get("/cluster/resources", params={"type": "vm"}),
                "resources": await self._client.get("/cluster/ha/resources"),
            }
            if include_groups:
                data["groups"] = await self._client.get("/cluster/ha/groups")
            return AdapterResult.ok(data)
        except (ProxmoxApiError, ValueError):
            return AdapterResult.fail("Cluster impact unavailable")

    async def get_ha_resources(self) -> AdapterResult:
        """Get HA-managed resources."""
        self._ensure_connected()
        try:
            data = await self._client.get(C.CLUSTER_HA_RESOURCES)  # type: ignore[union-attr]
            if not isinstance(data, list):
                return AdapterResult.ok([])
            resources = [
                ProxmoxHAResource(
                    sid=r.get("sid", ""),
                    state=r.get("state", ""),
                    group=r.get("group", ""),
                    max_relocate=int(r.get("max_relocate", 1)),
                    max_restart=int(r.get("max_restart", 1)),
                    comment=r.get("comment", ""),
                    request_state=r.get("request_state", ""),
                    status=r.get("status", ""),
                    node=r.get("node", ""),
                    crm_state=r.get("crm_state", ""),
                )
                for r in data
            ]
            return AdapterResult.ok(resources)
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    async def get_ha_groups(self) -> AdapterResult:
        """Get HA groups."""
        self._ensure_connected()
        try:
            data = await self._client.get(C.CLUSTER_HA_GROUPS)  # type: ignore[union-attr]
            if not isinstance(data, list):
                return AdapterResult.ok([])
            groups = [
                ProxmoxHAGroup(
                    group=g.get("group", ""),
                    nodes=g.get("nodes", ""),
                    nofailback=bool(g.get("nofailback", 0)),
                    restricted=bool(g.get("restricted", 0)),
                    comment=g.get("comment", ""),
                )
                for g in data
            ]
            return AdapterResult.ok(groups)
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    # ═══════════════════════════════════════════════════════════════════════
    # NODES
    # ═══════════════════════════════════════════════════════════════════════

    async def get_nodes(self) -> AdapterResult:
        """Get all nodes with status."""
        self._ensure_connected()
        try:
            data = await self._client.get(C.NODES)  # type: ignore[union-attr]
            if not isinstance(data, list):
                return AdapterResult.ok([])

            nodes = [
                ProxmoxNodeInfo(
                    node=n.get("node", ""),
                    status="online" if n.get("status") == "online" else "offline",
                    cpu=float(n.get("cpu", 0)),
                    maxcpu=int(n.get("maxcpu", 0)),
                    mem=int(n.get("mem", 0)),
                    maxmem=int(n.get("maxmem", 0)),
                    disk=int(n.get("disk", 0)),
                    maxdisk=int(n.get("maxdisk", 0)),
                    uptime=int(n.get("uptime", 0)),
                    level=n.get("level", ""),
                )
                for n in data
            ]
            return AdapterResult.ok(nodes)
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    async def get_node_status(self, node: str) -> AdapterResult:
        """Get detailed node status."""
        self._ensure_connected()
        try:
            data = await self._client.get(C.NODE_STATUS.format(node=node))  # type: ignore[union-attr]
            if not isinstance(data, dict):
                return AdapterResult.fail("Unexpected response")

            info = ProxmoxNodeInfo(
                node=node,
                status="online" if data.get("uptime", 0) > 0 else "offline",
                cpu=float(data.get("cpu", 0)),
                maxcpu=int(data.get("cpuinfo", {}).get("cpus", 0)),
                mem=int(data.get("memory", {}).get("used", 0)),
                maxmem=int(data.get("memory", {}).get("total", 0)),
                disk=int(data.get("rootfs", {}).get("used", 0)),
                maxdisk=int(data.get("rootfs", {}).get("total", 0)),
                uptime=int(data.get("uptime", 0)),
                pve_version=data.get("pveversion", ""),
                kernel_version=data.get("kversion", ""),
                cpu_model=data.get("cpuinfo", {}).get("model", ""),
            )
            return AdapterResult.ok(info)
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    async def reboot_node(
        self, node: str, *, confirmed: bool = False, force: bool = False
    ) -> AdapterResult:
        """Reboot a node — takes the whole node and all its guests offline.

        Two distinct second factors, never interchangeable: ``confirmed`` is the
        operator's type-to-confirm acknowledgement on the DIRECT path (clears the
        gate but does NOT pass force, so the client read-only gate still
        applies — a confirmed reboot is refused while read-only is ON and proceeds
        only in read-write mode); ``force`` is the staging applier's read-only
        bypass, passed only after the apply chokepoint enforces read-only.
        """
        # catastrophic op — require an explicit second factor (confirmed
        # on the direct path, or force from the staging applier).
        if not force and not confirmed:
            raise AdapterConfirmationRequiredError(
                "Rebooting a node is catastrophic (takes the whole node and its "
                "guests offline) — resubmit with confirmed=true to proceed.",
                adapter_id="proxmox",
            )
        self._ensure_connected()
        try:
            data = await self._client.post(  # type: ignore[union-attr]
                C.NODE_COMMAND.format(node=node),
                data={"command": "reboot"},
                force=force,
            )
            return AdapterResult.ok(data)
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    async def shutdown_node(
        self, node: str, *, confirmed: bool = False, force: bool = False
    ) -> AdapterResult:
        """Shutdown a node — takes it down with no auto-recovery (needs
        physical/IPMI power-on).

        Two distinct second factors, never interchangeable: ``confirmed`` is the
        operator's type-to-confirm acknowledgement on the DIRECT path (clears the
        gate but does NOT pass force, so the client read-only gate still
        applies — refused while read-only is ON, proceeds only in read-write);
        ``force`` is the staging applier's read-only bypass.
        """
        # catastrophic op — require an explicit second factor (confirmed
        # on the direct path, or force from the staging applier).
        if not force and not confirmed:
            raise AdapterConfirmationRequiredError(
                "Shutting a node down is catastrophic (no auto-recovery; needs "
                "physical/IPMI power-on) — resubmit with confirmed=true to proceed.",
                adapter_id="proxmox",
            )
        self._ensure_connected()
        try:
            data = await self._client.post(  # type: ignore[union-attr]
                C.NODE_COMMAND.format(node=node),
                data={"command": "shutdown"},
                force=force,
            )
            return AdapterResult.ok(data)
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    async def get_node_services(self, node: str) -> AdapterResult:
        """Get node services."""
        self._ensure_connected()
        try:
            data = await self._client.get(C.NODE_SERVICES.format(node=node))  # type: ignore[union-attr]
            if not isinstance(data, list):
                return AdapterResult.ok([])
            services = [
                ProxmoxNodeService(
                    service=s.get("service", ""),
                    name=s.get("name", ""),
                    desc=s.get("desc", ""),
                    state=s.get("state", ""),
                    unit_state=s.get("unit-state", ""),
                )
                for s in data
            ]
            return AdapterResult.ok(services)
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    async def node_service_action(
        self,
        node: str,
        service: str,
        action: str,
        *,
        force: bool = False,
    ) -> AdapterResult:
        """Start/stop/restart a node service. ``force`` propagates to
        the read-only gate."""
        self._ensure_connected()
        try:
            data = await self._client.post(  # type: ignore[union-attr]
                C.NODE_SERVICE_ACTION.format(node=node, service=service, action=action),
                force=force,
            )
            return AdapterResult.ok(data)
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    async def get_node_syslog(
        self, node: str, limit: int = 50, start: int = 0, service: str | None = None
    ) -> AdapterResult:
        """Get node syslog entries."""
        self._ensure_connected()
        try:
            params: dict[str, Any] = {"limit": min(limit, 500), "start": start}
            if service:
                params["service"] = service
            data = await self._client.get(  # type: ignore[union-attr]
                C.NODE_SYSLOG.format(node=node), params=params
            )
            return AdapterResult.ok(data if isinstance(data, list) else [])
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    async def get_node_disks(self, node: str) -> AdapterResult:
        """Get physical disks on a node."""
        self._ensure_connected()
        try:
            data = await self._client.get(C.NODE_DISKS.format(node=node))  # type: ignore[union-attr]
            if not isinstance(data, list):
                return AdapterResult.ok([])
            disks = [
                ProxmoxDiskInfo(
                    devpath=d.get("devpath", ""),
                    model=d.get("model", ""),
                    serial=d.get("serial", ""),
                    size=int(d.get("size", 0)),
                    vendor=d.get("vendor", ""),
                    wearout=_float_or_none(d.get("wearout")),
                    rpm=d.get("rpm"),
                    disk_type="ssd" if d.get("rpm") == 0 else "hdd",
                    gpt=bool(d.get("gpt", 0)),
                    health=d.get("health", "UNKNOWN"),
                )
                for d in data
            ]
            return AdapterResult.ok(disks)
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    async def get_disk_smart(self, node: str, disk: str) -> AdapterResult:
        """Get SMART health data for a specific disk."""
        self._ensure_connected()
        try:
            data = await self._client.get(  # type: ignore[union-attr]
                C.NODE_DISKS_SMART.format(node=node),
                params={"disk": disk},
            )
            return AdapterResult.ok(data if isinstance(data, dict) else {})
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    async def get_node_dns(self, node: str) -> AdapterResult:
        """Get node DNS configuration."""
        self._ensure_connected()
        try:
            data = await self._client.get(C.NODE_DNS.format(node=node))  # type: ignore[union-attr]
            return AdapterResult.ok(data if isinstance(data, dict) else {})
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    async def get_node_time(self, node: str) -> AdapterResult:
        """Get node time/timezone info."""
        self._ensure_connected()
        try:
            data = await self._client.get(C.NODE_TIME.format(node=node))  # type: ignore[union-attr]
            return AdapterResult.ok(data if isinstance(data, dict) else {})
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    # ═══════════════════════════════════════════════════════════════════════
    # VIRTUAL MACHINES (QEMU)
    # ═══════════════════════════════════════════════════════════════════════

    async def get_vms(self, node: str) -> AdapterResult:
        """Get all VMs on a node."""
        self._ensure_connected()
        try:
            data = await self._client.get(C.NODE_QEMU.format(node=node))  # type: ignore[union-attr]
            if not isinstance(data, list):
                return AdapterResult.ok([])
            vms = [self._parse_vm(v, node, "qemu") for v in data]
            return AdapterResult.ok(vms)
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    async def get_all_vms(self) -> AdapterResult:
        """Get VMs across all nodes."""
        self._ensure_connected()
        try:
            # Pass resource_type="vm" to filter server-side (returns both qemu and lxc)
            result = await self.get_cluster_resources("vm")
            if not result.success:
                return result
            vms = [
                self._parse_vm(r, r.get("node", ""), r.get("type", "qemu"))
                for r in (result.data or [])
                if r.get("type") in ("qemu", "lxc")
            ]
            return AdapterResult.ok(vms)
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    async def get_vm_status(self, node: str, vmid: int) -> AdapterResult:
        """Get detailed VM status."""
        self._ensure_connected()
        try:
            data = await self._client.get(  # type: ignore[union-attr]
                C.QEMU_STATUS.format(node=node, vmid=vmid)
            )
            if not isinstance(data, dict):
                return AdapterResult.fail("Unexpected response")
            return AdapterResult.ok(self._parse_vm(data, node, "qemu"))
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    async def get_vm_config(self, node: str, vmid: int, *, current: bool = False) -> AdapterResult:
        """Get VM configuration."""
        self._ensure_connected()
        try:
            data = await self._client.get(  # type: ignore[union-attr]
                C.QEMU_CONFIG.format(node=node, vmid=vmid),
                **({"params": {"current": 1}} if current else {}),
            )
            return AdapterResult.ok(data if isinstance(data, dict) else {})
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    async def update_vm_config(
        self, node: str, vmid: int, config: dict[str, Any], *, force: bool = False
    ) -> AdapterResult:
        """Update VM configuration (CPU, memory, etc.)."""
        self._ensure_connected()
        try:
            data = await self._client.put(  # type: ignore[union-attr]
                C.QEMU_CONFIG.format(node=node, vmid=vmid), data=config, force=force
            )
            return AdapterResult.ok(data)
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    async def start_vm(self, node: str, vmid: int, *, force: bool = False) -> AdapterResult:
        """Start a VM."""
        return await self._vm_action(C.QEMU_START, node, vmid, "start", force=force)

    async def stop_vm(self, node: str, vmid: int, *, force: bool = False) -> AdapterResult:
        """Force stop a VM."""
        return await self._vm_action(C.QEMU_STOP, node, vmid, "stop", force=force)

    async def shutdown_vm(self, node: str, vmid: int, *, force: bool = False) -> AdapterResult:
        """Graceful shutdown of a VM."""
        return await self._vm_action(C.QEMU_SHUTDOWN, node, vmid, "shutdown", force=force)

    async def reboot_vm(self, node: str, vmid: int, *, force: bool = False) -> AdapterResult:
        """Reboot a VM."""
        return await self._vm_action(C.QEMU_REBOOT, node, vmid, "reboot", force=force)

    async def suspend_vm(self, node: str, vmid: int, *, force: bool = False) -> AdapterResult:
        """Suspend a VM."""
        return await self._vm_action(C.QEMU_SUSPEND, node, vmid, "suspend", force=force)

    async def resume_vm(self, node: str, vmid: int, *, force: bool = False) -> AdapterResult:
        """Resume a suspended VM."""
        return await self._vm_action(C.QEMU_RESUME, node, vmid, "resume", force=force)

    async def clone_vm(
        self,
        node: str,
        vmid: int,
        newid: int,
        *,
        name: str = "",
        target: str = "",
        full: bool = True,
        storage: str = "",
        description: str = "",
        force: bool = False,
    ) -> AdapterResult:
        """Clone a VM."""
        self._ensure_connected()
        try:
            payload: dict[str, Any] = {"newid": newid}
            if name:
                payload["name"] = name
            if target:
                payload["target"] = target
            if full:
                payload["full"] = 1
            if storage:
                payload["storage"] = storage
            if description:
                payload["description"] = description
            data = await self._client.post(  # type: ignore[union-attr]
                C.QEMU_CLONE.format(node=node, vmid=vmid), data=payload, force=force
            )
            return AdapterResult.ok({"upid": data, "newid": newid})
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    async def migrate_vm(
        self,
        node: str,
        vmid: int,
        target: str,
        online: bool = True,
        *,
        force: bool = False,
    ) -> AdapterResult:
        """Migrate a VM to another node."""
        self._ensure_connected()
        try:
            payload: dict[str, Any] = {"target": target}
            if online:
                payload["online"] = 1
            data = await self._client.post(  # type: ignore[union-attr]
                C.QEMU_MIGRATE.format(node=node, vmid=vmid), data=payload, force=force
            )
            return AdapterResult.ok({"upid": data, "target": target})
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    async def resize_vm_disk(
        self,
        node: str,
        vmid: int,
        disk: str,
        size: str,
        *,
        force: bool = False,
        digest: str | None = None,
    ) -> AdapterResult:
        """Resize a VM disk.

        Args:
            disk: Disk name (e.g., "scsi0", "virtio0")
            size: Size string (e.g., "+10G", "50G")
        """
        self._ensure_connected()
        try:
            data = await self._client.put(  # type: ignore[union-attr]
                C.QEMU_RESIZE.format(node=node, vmid=vmid),
                data={"disk": disk, "size": size, **({"digest": digest} if digest else {})},
                force=force,
            )
            return AdapterResult.ok(data)
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    async def convert_to_template(
        self,
        node: str,
        vmid: int,
        vm_type: str = "qemu",
        *,
        force: bool = False,
    ) -> AdapterResult:
        """Convert a VM/CT to a template."""
        self._ensure_connected()
        try:
            path = C.QEMU_TEMPLATE if vm_type == "qemu" else C.LXC_TEMPLATE
            data = await self._client.post(  # type: ignore[union-attr]
                path.format(node=node, vmid=vmid),
                force=force,
            )
            return AdapterResult.ok(data)
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    async def get_vm_vnc(self, node: str, vmid: int) -> AdapterResult:
        """Get VNC proxy ticket for console access."""
        self._ensure_connected()
        try:
            data = await self._client.post(  # type: ignore[union-attr]
                C.QEMU_VNCPROXY.format(node=node, vmid=vmid),
                data={"websocket": 1},
            )
            return AdapterResult.ok(data)
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    async def get_console_proxy(
        self,
        node: str,
        vmid: int,
        vm_type: str = "qemu",
        console_type: str = "vnc",
    ) -> AdapterResult:
        """Get console proxy ticket (VNC, SPICE, or xterm.js).

        Args:
            console_type: "vnc", "spice", or "term"
        """
        self._ensure_connected()
        try:
            if console_type == "spice":
                path = C.QEMU_SPICEPROXY.format(node=node, vmid=vmid)
            elif console_type == "term":
                path = (C.QEMU_TERMPROXY if vm_type == "qemu" else C.LXC_TERMPROXY).format(
                    node=node, vmid=vmid
                )
            else:
                path = (C.QEMU_VNCPROXY if vm_type == "qemu" else C.LXC_VNCPROXY).format(
                    node=node, vmid=vmid
                )

            data = await self._client.post(  # type: ignore[union-attr]
                path, data={"websocket": 1} if console_type != "spice" else None
            )
            return AdapterResult.ok(data)
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    async def create_vm(
        self,
        node: str,
        vmid: int,
        *,
        name: str = "",
        cores: int = 1,
        memory: int = 2048,
        sockets: int = 1,
        ostype: str = "l26",
        storage: str = "local-lvm",
        disk_size: str = "32G",
        iso: str = "",
        net_bridge: str = "vmbr0",
        net_model: str = "virtio",
        start: bool = False,
        pool: str = "",
        description: str = "",
        bios: str = "seabios",
        machine: str = "",
        cpu_type: str = "host",
        balloon: int = 0,
        onboot: bool = False,
        tags: str = "",
        force: bool = False,
    ) -> AdapterResult:
        """Create a new QEMU virtual machine."""
        self._ensure_connected()
        try:
            payload: dict[str, Any] = {
                "vmid": vmid,
                "cores": cores,
                "sockets": sockets,
                "memory": memory,
                "ostype": ostype,
                "cpu": cpu_type,
                "bios": bios,
                "scsi0": f"{storage}:{disk_size.removesuffix('G')}",
                "scsihw": "virtio-scsi-single",
                "net0": f"{net_model},bridge={net_bridge}",
            }
            if name:
                payload["name"] = name
            if iso:
                payload["ide2"] = f"{iso},media=cdrom"
            if start:
                payload["start"] = 1
            if pool:
                payload["pool"] = pool
            if description:
                payload["description"] = description
            if machine:
                payload["machine"] = machine
            payload["balloon"] = balloon
            if onboot:
                payload["onboot"] = 1
            if tags:
                payload["tags"] = tags
            data = await self._client.post(  # type: ignore[union-attr]
                C.NODE_QEMU.format(node=node), data=payload, force=force
            )
            return AdapterResult.ok({"upid": data, "vmid": vmid})
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    async def create_container(
        self,
        node: str,
        vmid: int,
        *,
        ostemplate: str,
        hostname: str = "",
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
        force: bool = False,
    ) -> AdapterResult:
        """Create a new LXC container."""
        self._ensure_connected()
        try:
            payload: dict[str, Any] = {
                "vmid": vmid,
                "ostemplate": ostemplate,
                "cores": cores,
                "memory": memory,
                "swap": swap,
                "rootfs": f"{storage}:{rootfs_size}",
                "net0": f"name=eth0,bridge={net_bridge},ip={net_ip}",
                "unprivileged": 1 if unprivileged else 0,
            }
            if hostname:
                payload["hostname"] = hostname
            if password:
                payload["password"] = password
            if ssh_public_keys:
                payload["ssh-public-keys"] = ssh_public_keys
            if start:
                payload["start"] = 1
            if pool:
                payload["pool"] = pool
            if description:
                payload["description"] = description
            if onboot:
                payload["onboot"] = 1
            if tags:
                payload["tags"] = tags
            if nameserver:
                payload["nameserver"] = nameserver
            if searchdomain:
                payload["searchdomain"] = searchdomain
            data = await self._client.post(  # type: ignore[union-attr]
                C.NODE_LXC.format(node=node), data=payload, force=force
            )
            return AdapterResult.ok({"upid": data, "vmid": vmid})
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    async def delete_vm(
        self,
        node: str,
        vmid: int,
        vm_type: str = "qemu",
        *,
        confirmed: bool = False,
        force: bool = False,
    ) -> AdapterResult:
        """Delete a VM or container.

        WARNING: irreversible.

        Two distinct second factors, NEVER interchangeable downstream:
        - ``confirmed`` — the operator's type-to-confirm acknowledgement on the
          DIRECT path. It satisfies the gate but does NOT pass
          ``force`` to the client, so the read-only gate still applies: a
          confirmed delete is refused while read-only is ON (→ 403) and
          proceeds only in read-write mode.
        - ``force`` — the staging applier's read-only bypass, passed only after
          the apply chokepoint (``adapter_staging.apply_change``) has itself
          enforced read-only. Direct callers must never pass it.
        """
        # irreversible op — require an explicit second factor. Either
        # confirmed (direct path) or force (staging path) clears it, so a direct
        # hypervisor route cannot destroy a VM off the audit trail unconfirmed.
        if not force and not confirmed:
            raise AdapterConfirmationRequiredError(
                "Destroying a VM/container is irreversible — resubmit with "
                "confirmed=true to proceed.",
                adapter_id="proxmox",
            )
        self._ensure_connected()
        try:
            path = C.NODE_LXC + "/{vmid}" if vm_type == "lxc" else C.NODE_QEMU + "/{vmid}"
            data = await self._client.delete(  # type: ignore[union-attr]
                path.format(node=node, vmid=vmid),
                force=force,
            )
            return AdapterResult.ok({"upid": data, "vmid": vmid})
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    async def assert_vmid_unused(self, vmid: int) -> AdapterResult:
        """Read the cluster's allocation index; an ACL-filtered guest list is insufficient."""
        self._ensure_connected()
        try:
            data = await self._client.get("/cluster/nextid", params={"vmid": vmid})  # type: ignore[union-attr]
            if type(data) is not int or data != vmid:
                return AdapterResult.fail("Invalid VMID availability response")
            return AdapterResult.ok(data)
        except ProxmoxApiError:
            return AdapterResult.fail("VMID availability could not be verified")

    async def get_next_vmid(self) -> AdapterResult:
        """Get next available VMID from the cluster."""
        self._ensure_connected()
        try:
            data = await self._client.get("/cluster/nextid")  # type: ignore[union-attr]
            if type(data) is not int or not 100 <= data <= 999999999:
                return AdapterResult.fail("Invalid next VMID response")
            return AdapterResult.ok(data)
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    async def create_ha_resource(
        self,
        sid: str,
        *,
        group: str = "",
        max_relocate: int = 1,
        max_restart: int = 1,
        state: str = "started",
        comment: str = "",
        force: bool = False,
    ) -> AdapterResult:
        """Add a VM/CT to HA management.

        ``force`` propagates to the read-only gate in the client; the
        staging applier passes ``force=True`` after the operator has
        cleared the dual-gate (env + apply param). Direct callers must
        not pass ``force=True``.
        """
        self._ensure_connected()
        try:
            payload: dict[str, Any] = {"sid": sid, "state": state}
            if group:
                payload["group"] = group
            payload["max_relocate"] = max_relocate
            payload["max_restart"] = max_restart
            if comment:
                payload["comment"] = comment
            data = await self._client.post(  # type: ignore[union-attr]
                C.CLUSTER_HA_RESOURCES,
                data=payload,
                force=force,
            )
            return AdapterResult.ok(data)
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    async def delete_ha_resource(self, sid: str, *, force: bool = False) -> AdapterResult:
        """Remove HA membership without purging rules. Never retry without this guard."""
        self._ensure_connected()
        try:
            data = await self._client.delete(  # type: ignore[union-attr]
                f"{C.CLUSTER_HA_RESOURCES}/{sid}",
                force=force,
                params={"purge": 0},
            )
            return AdapterResult.ok(data)
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    async def create_ha_group(
        self,
        group: str,
        nodes: str,
        *,
        nofailback: bool = False,
        restricted: bool = False,
        comment: str = "",
        force: bool = False,
    ) -> AdapterResult:
        """Create an HA group."""
        self._ensure_connected()
        try:
            payload: dict[str, Any] = {"group": group, "nodes": nodes}
            if nofailback:
                payload["nofailback"] = 1
            if restricted:
                payload["restricted"] = 1
            if comment:
                payload["comment"] = comment
            data = await self._client.post(  # type: ignore[union-attr]
                C.CLUSTER_HA_GROUPS,
                data=payload,
                force=force,
            )
            return AdapterResult.ok(data)
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    async def delete_ha_group(self, group: str, *, force: bool = False) -> AdapterResult:
        """Delete an HA group."""
        self._ensure_connected()
        try:
            data = await self._client.delete(  # type: ignore[union-attr]
                f"{C.CLUSTER_HA_GROUPS}/{group}",
                force=force,
            )
            return AdapterResult.ok(data)
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    async def get_guest_agent_info(self, node: str, vmid: int) -> AdapterResult:
        """Get QEMU guest agent network interfaces."""
        self._ensure_connected()
        try:
            data = await self._client.get(  # type: ignore[union-attr]
                C.QEMU_AGENT_NETWORK.format(node=node, vmid=vmid)
            )
            return AdapterResult.ok(data)
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    # ═══════════════════════════════════════════════════════════════════════
    # CONTAINERS (LXC)
    # ═══════════════════════════════════════════════════════════════════════

    async def get_containers(self, node: str) -> AdapterResult:
        """Get all containers on a node."""
        self._ensure_connected()
        try:
            data = await self._client.get(C.NODE_LXC.format(node=node))  # type: ignore[union-attr]
            if not isinstance(data, list):
                return AdapterResult.ok([])
            cts = [self._parse_vm(c, node, "lxc") for c in data]
            return AdapterResult.ok(cts)
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    async def get_container_status(self, node: str, vmid: int) -> AdapterResult:
        """Get detailed container status."""
        self._ensure_connected()
        try:
            data = await self._client.get(  # type: ignore[union-attr]
                C.LXC_STATUS.format(node=node, vmid=vmid)
            )
            if not isinstance(data, dict):
                return AdapterResult.fail("Unexpected response")
            return AdapterResult.ok(self._parse_vm(data, node, "lxc"))
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    async def get_container_config(
        self, node: str, vmid: int, *, current: bool = False
    ) -> AdapterResult:
        """Get container configuration."""
        self._ensure_connected()
        try:
            data = await self._client.get(  # type: ignore[union-attr]
                C.LXC_CONFIG.format(node=node, vmid=vmid),
                **({"params": {"current": 1}} if current else {}),
            )
            return AdapterResult.ok(data if isinstance(data, dict) else {})
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    async def update_container_config(
        self,
        node: str,
        vmid: int,
        config: dict[str, Any],
        *,
        force: bool = False,
    ) -> AdapterResult:
        """Update container configuration."""
        self._ensure_connected()
        try:
            data = await self._client.put(  # type: ignore[union-attr]
                C.LXC_CONFIG.format(node=node, vmid=vmid),
                data=config,
                force=force,
            )
            return AdapterResult.ok(data)
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    async def start_container(self, node: str, vmid: int, *, force: bool = False) -> AdapterResult:
        """Start a container."""
        return await self._vm_action(C.LXC_START, node, vmid, "start", force=force)

    async def stop_container(self, node: str, vmid: int, *, force: bool = False) -> AdapterResult:
        """Force stop a container."""
        return await self._vm_action(C.LXC_STOP, node, vmid, "stop", force=force)

    async def shutdown_container(
        self, node: str, vmid: int, *, force: bool = False
    ) -> AdapterResult:
        """Graceful shutdown of a container."""
        return await self._vm_action(C.LXC_SHUTDOWN, node, vmid, "shutdown", force=force)

    async def reboot_container(self, node: str, vmid: int, *, force: bool = False) -> AdapterResult:
        """Reboot a container."""
        return await self._vm_action(C.LXC_REBOOT, node, vmid, "reboot", force=force)

    async def clone_container(
        self,
        node: str,
        vmid: int,
        newid: int,
        *,
        hostname: str = "",
        target: str = "",
        full: bool = True,
        storage: str = "",
        description: str = "",
        force: bool = False,
    ) -> AdapterResult:
        """Clone a container."""
        self._ensure_connected()
        try:
            payload: dict[str, Any] = {"newid": newid}
            if hostname:
                payload["hostname"] = hostname
            if target:
                payload["target"] = target
            if full:
                payload["full"] = 1
            if storage:
                payload["storage"] = storage
            if description:
                payload["description"] = description
            data = await self._client.post(  # type: ignore[union-attr]
                C.LXC_CLONE.format(node=node, vmid=vmid),
                data=payload,
                force=force,
            )
            return AdapterResult.ok({"upid": data, "newid": newid})
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    async def migrate_container(
        self,
        node: str,
        vmid: int,
        target: str,
        online: bool = False,
        *,
        restart: bool = False,
        force: bool = False,
    ) -> AdapterResult:
        """Migrate a container to another node."""
        if online:
            return AdapterResult.fail(
                "LXC live migration is unsupported; choose offline or explicit restart"
            )
        self._ensure_connected()
        try:
            payload: dict[str, Any] = {"target": target}
            if restart:
                payload["restart"] = 1
            data = await self._client.post(  # type: ignore[union-attr]
                C.LXC_MIGRATE.format(node=node, vmid=vmid),
                data=payload,
                force=force,
            )
            return AdapterResult.ok({"upid": data, "target": target})
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    async def resize_container_disk(
        self,
        node: str,
        vmid: int,
        disk: str,
        size: str,
        *,
        force: bool = False,
        digest: str | None = None,
    ) -> AdapterResult:
        """Resize a container disk."""
        self._ensure_connected()
        try:
            data = await self._client.put(  # type: ignore[union-attr]
                C.LXC_RESIZE.format(node=node, vmid=vmid),
                data={"disk": disk, "size": size, **({"digest": digest} if digest else {})},
                force=force,
            )
            return AdapterResult.ok(data)
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    # ═══════════════════════════════════════════════════════════════════════
    # SNAPSHOTS
    # ═══════════════════════════════════════════════════════════════════════

    async def get_snapshots(self, node: str, vmid: int, vm_type: str = "qemu") -> AdapterResult:
        """Get snapshots for a VM or container."""
        self._ensure_connected()
        try:
            path_tpl = C.QEMU_SNAPSHOT_LIST if vm_type == "qemu" else C.LXC_SNAPSHOT_LIST
            data = await self._client.get(  # type: ignore[union-attr]
                path_tpl.format(node=node, vmid=vmid)
            )
            if not isinstance(data, list):
                return AdapterResult.ok([])
            snaps = [
                ProxmoxSnapshot(
                    name=s.get("name", ""),
                    description=s.get("description", ""),
                    snaptime=int(s.get("snaptime", 0)),
                    vmstate=bool(s.get("vmstate", 0)),
                    parent=s.get("parent"),
                )
                for s in data
                if s.get("name") != "current"
            ]
            return AdapterResult.ok(snaps)
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    async def create_snapshot(
        self,
        node: str,
        vmid: int,
        snapname: str,
        description: str = "",
        vm_type: str = "qemu",
        vmstate: bool = False,
        *,
        force: bool = False,
    ) -> AdapterResult:
        """Create a snapshot."""
        self._ensure_connected()
        try:
            path_tpl = C.QEMU_SNAPSHOT_CREATE if vm_type == "qemu" else C.LXC_SNAPSHOT_CREATE
            payload: dict[str, Any] = {"snapname": snapname}
            if description:
                payload["description"] = description
            if vmstate and vm_type == "qemu":
                payload["vmstate"] = 1
            data = await self._client.post(  # type: ignore[union-attr]
                path_tpl.format(node=node, vmid=vmid),
                data=payload,
                force=force,
            )
            return AdapterResult.ok(data)
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    async def rollback_snapshot(
        self,
        node: str,
        vmid: int,
        snapname: str,
        vm_type: str = "qemu",
        *,
        force: bool = False,
    ) -> AdapterResult:
        """Rollback to a snapshot.

        WARNING: catastrophic — discards all VM/CT state since the snapshot
        was taken. The dual-gate is the last guardrail.
        """
        self._ensure_connected()
        try:
            path_tpl = C.QEMU_SNAPSHOT_ROLLBACK if vm_type == "qemu" else C.LXC_SNAPSHOT_ROLLBACK
            data = await self._client.post(  # type: ignore[union-attr]
                path_tpl.format(node=node, vmid=vmid, snapname=snapname),
                force=force,
            )
            return AdapterResult.ok(data)
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    async def delete_snapshot(
        self,
        node: str,
        vmid: int,
        snapname: str,
        vm_type: str = "qemu",
        *,
        force: bool = False,
    ) -> AdapterResult:
        """Delete a snapshot.

        WARNING: irreversible — the only restore path for this snapshot
        is gone. The dual-gate is the last guardrail.
        """
        self._ensure_connected()
        try:
            path_tpl = C.QEMU_SNAPSHOT_DELETE if vm_type == "qemu" else C.LXC_SNAPSHOT_DELETE
            data = await self._client.delete(  # type: ignore[union-attr]
                path_tpl.format(node=node, vmid=vmid, snapname=snapname),
                force=force,
            )
            return AdapterResult.ok(data)
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    # ═══════════════════════════════════════════════════════════════════════
    # STORAGE
    # ═══════════════════════════════════════════════════════════════════════

    async def get_storage(self, node: str) -> AdapterResult:
        """Get storage pools for a node."""
        self._ensure_connected()
        try:
            data = await self._client.get(  # type: ignore[union-attr]
                C.NODE_STORAGE.format(node=node)
            )
            if not isinstance(data, list):
                return AdapterResult.fail(
                    "Unexpected inventory response", error_code="invalid_response"
                )
            pools = [
                ProxmoxStorage(
                    storage=s.get("storage", ""),
                    node=node,
                    storage_type=s.get("type", ""),
                    content=s.get("content", ""),
                    total=int(s.get("total", 0)),
                    used=int(s.get("used", 0)),
                    avail=int(s.get("avail", 0)),
                    active=bool(s.get("active", 1)),
                    shared=bool(s.get("shared", 0)),
                    enabled=bool(s.get("enabled", 1)),
                )
                for s in data
            ]
            return AdapterResult.ok(pools)
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    async def get_storage_content(
        self,
        node: str,
        storage: str,
        content_type: str | None = None,
        vmid: int | None = None,
    ) -> AdapterResult:
        """Get storage content (ISOs, backups, disk images)."""
        self._ensure_connected()
        try:
            params: dict[str, Any] = {}
            if content_type:
                params["content"] = content_type
            if vmid is not None:
                params["vmid"] = vmid
            data = await self._client.get(  # type: ignore[union-attr]
                C.NODE_STORAGE_CONTENT.format(node=node, storage=storage),
                params=params or None,
            )
            if not isinstance(data, list):
                return AdapterResult.fail(
                    "Unexpected inventory response", error_code="invalid_response"
                )
            return AdapterResult.ok(data)
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    async def get_storage_operation_state(self, node: str, storage: str) -> AdapterResult:
        """Raw storage identity, permissions and inventory; never empty fallbacks."""
        self._ensure_connected()
        try:
            cluster = await self._client.get("/cluster/status")
            config = await self._client.get(f"/storage/{storage}")
            status = await self._client.get(f"/nodes/{node}/storage/{storage}/status")
            permissions = await self._client.get(
                "/access/permissions", params={"path": f"/storage/{storage}"}
            )
            root_permissions = await self._client.get("/access/permissions", params={"path": "/"})
            permissions = {
                f"/storage/{storage}": permissions_at_path(permissions, f"/storage/{storage}"),
                "/": permissions_at_path(root_permissions, "/"),
            }
            content = await self._client.get(f"/nodes/{node}/storage/{storage}/content")
            return AdapterResult.ok(
                {
                    "cluster": cluster,
                    "config": config,
                    "status": status,
                    "permissions": permissions,
                    "content": content,
                }
            )
        except (ProxmoxApiError, ValueError):
            return AdapterResult.fail("Storage review unavailable")

    async def get_storage_guest_configs(self) -> AdapterResult:
        """Current, pending and snapshot configurations of visible guests.

        The caller requires global VM.Audit, but permission overrides and native
        operators remain outside FreeSDN's serialization boundary.
        """
        from app.adapters.validation import validate_id

        self._ensure_connected()
        try:
            guests = await self._client.get("/cluster/resources", params={"type": "vm"})
            if not isinstance(guests, list) or len(guests) > 256:
                return AdapterResult.fail("Guest inventory exceeds review limit or is malformed")
            configs = []
            seen = set()
            for guest in sorted(
                guests, key=lambda g: str(g.get("vmid")) if isinstance(g, dict) else ""
            ):
                if (
                    not isinstance(guest, dict)
                    or type(guest.get("vmid")) is not int
                    or not 100 <= guest["vmid"] <= 999999999
                    or guest.get("type") not in {"qemu", "lxc"}
                    or guest["vmid"] in seen
                ):
                    return AdapterResult.fail("Malformed guest inventory")
                seen.add(guest["vmid"])
                node = validate_id(guest.get("node"), label="node")
                path = f"/nodes/{node}/{guest['type']}/{guest['vmid']}"
                current = await self._client.get(f"{path}/config", params={"current": 1})
                pending = await self._client.get(f"{path}/config")
                snapshots = await self._client.get(f"{path}/snapshot")
                if (
                    not isinstance(current, dict)
                    or not current.get("digest")
                    or not isinstance(pending, dict)
                    or not pending.get("digest")
                    or not isinstance(snapshots, list)
                    or len(snapshots) > 64
                ):
                    return AdapterResult.fail("Guest configuration review incomplete")
                saved = []
                for snap in snapshots:
                    if not isinstance(snap, dict):
                        return AdapterResult.fail("Malformed snapshot inventory")
                    name = validate_id(snap.get("name"), label="snapshot")
                    if name != "current":
                        config = await self._client.get(f"{path}/snapshot/{name}/config")
                        if not isinstance(config, dict) or not config:
                            return AdapterResult.fail("Snapshot configuration unavailable")
                        saved.append({"name": name, "config": config})
                configs.append(
                    {
                        "node": node,
                        "vmid": guest["vmid"],
                        "type": guest["type"],
                        "current": current,
                        "pending": pending,
                        "snapshots": sorted(saved, key=lambda item: item["name"]),
                    }
                )
            return AdapterResult.ok(configs)
        except ProxmoxApiError:
            return AdapterResult.fail("Guest configuration review unavailable")

    async def upload_verified_storage_file(
        self,
        node: str,
        storage: str,
        filename: str,
        content: str,
        handle: BinaryIO,
        checksum: str,
        *,
        force: bool = False,
    ) -> AdapterResult:
        """Send the already-open verified source with a provider-enforced SHA256.

        The applier owns and closes the descriptor. Never reopen a supplied path.
        """
        self._ensure_connected()
        try:
            response = await self._client.post_multipart(
                C.NODE_STORAGE_UPLOAD.format(node=node, storage=storage),
                files={"filename": (filename, handle, "application/octet-stream")},
                data={"content": content, "checksum": checksum, "checksum-algorithm": "sha256"},
                force=force,
            )
            if 400 <= response.status_code < 500:
                return AdapterResult.fail("Provider rejected upload")
            try:
                body = response.json()
                if (
                    not 200 <= response.status_code < 300
                    or not isinstance(body, dict)
                    or "data" not in body
                ):
                    raise ValueError("envelope")
                return AdapterResult.ok(body["data"])
            except (ValueError, UnicodeError):
                raise AdapterOutcomeUnknownError(
                    "Upload acknowledgement unavailable", adapter_id="proxmox"
                ) from None
        except ProxmoxApiError:
            return AdapterResult.fail("Provider rejected upload")

    async def delete_storage_volume(
        self,
        node: str,
        storage: str,
        volume: str,
        *,
        force: bool = False,
    ) -> AdapterResult:
        """Delete a storage volume (ISO, backup, disk image).

        IRREVERSIBLE: dropping a backup volume here means the backup is
        gone. ``force`` propagates to the read-only gate; only the
        staging applier passes ``force=True``.
        """
        # irreversible — require force UNCONDITIONALLY so only the staging
        # applier (force=True) can delete a storage volume; the direct route is refused.
        if not force:
            raise AdapterConfirmationRequiredError(
                "Deleting a storage volume is irreversible — resubmit with "
                "confirmed=true to proceed.",
                adapter_id="proxmox",
            )
        self._ensure_connected()
        try:
            data = await self._client.delete(  # type: ignore[union-attr]
                C.NODE_STORAGE_VOLUME.format(node=node, storage=storage, volume=volume),
                force=force,
            )
            return AdapterResult.ok(data)
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    # ═══════════════════════════════════════════════════════════════════════
    # NETWORK
    # ═══════════════════════════════════════════════════════════════════════

    async def get_node_network(self, node: str) -> AdapterResult:
        """Get network interfaces for a node."""
        self._ensure_connected()
        try:
            data = await self._client.get(  # type: ignore[union-attr]
                C.NODE_NETWORK.format(node=node)
            )
            if not isinstance(data, list):
                return AdapterResult.ok([])
            ifaces = [
                ProxmoxNetworkInterface(
                    iface=i.get("iface", ""),
                    node=node,
                    iface_type=i.get("type", ""),
                    active=bool(i.get("active", 0)),
                    address=i.get("address"),
                    netmask=i.get("netmask"),
                    gateway=i.get("gateway"),
                    cidr=i.get("cidr"),
                    bridge_ports=i.get("bridge_ports"),
                    bond_slaves=i.get("slaves"),
                    method=i.get("method"),
                    autostart=bool(i.get("autostart", 0)),
                    comments=i.get("comments"),
                )
                for i in data
            ]
            return AdapterResult.ok(ifaces)
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    # ═══════════════════════════════════════════════════════════════════════
    # TASKS
    # ═══════════════════════════════════════════════════════════════════════

    async def get_tasks(self, node: str, limit: int = 50) -> AdapterResult:
        """Get recent tasks for a node."""
        self._ensure_connected()
        try:
            data = await self._client.get(  # type: ignore[union-attr]
                C.NODE_TASKS.format(node=node),
                params={"limit": min(limit, 200), "source": "all"},
            )
            if not isinstance(data, list) or any(not isinstance(t, dict) for t in data):
                return AdapterResult.fail("Task inventory unavailable or malformed")
            tasks = [
                ProxmoxTask(
                    upid=t.get("upid", ""),
                    node=node,
                    task_type=t.get("type", ""),
                    status="" if t.get("status") == "RUNNING" else t.get("status", ""),
                    user=t.get("user", ""),
                    starttime=int(t.get("starttime", 0)),
                    endtime=int(t.get("endtime", 0)),
                    pid=int(t.get("pid", 0)),
                    pstart=int(t.get("pstart", 0)),
                    id=t.get("id", ""),
                )
                for t in data
            ]
            return AdapterResult.ok(tasks)
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    async def get_task_status(self, node: str, upid: str) -> AdapterResult:
        """Get detailed task status."""
        self._ensure_connected()
        try:
            data = await self._client.get(  # type: ignore[union-attr]
                C.NODE_TASK_STATUS.format(node=node, upid=upid)
            )
            if not isinstance(data, dict):
                return AdapterResult.fail("Unexpected response")
            # Never substitute the requested ID for an unrelated provider reply.
            if data.get("upid") != upid or data.get("node") != node:
                return AdapterResult.fail("Task identity mismatch")
            return AdapterResult.ok(
                ProxmoxTaskDetail(
                    upid=upid,
                    node=node,
                    task_type=data.get("type", ""),
                    status=data.get("status", ""),
                    user=data.get("user", ""),
                    starttime=int(data.get("starttime", 0)),
                    pid=int(data.get("pid", 0)),
                    exitstatus=data.get("exitstatus", ""),
                )
            )
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    async def get_task_log(
        self, node: str, upid: str, start: int = 0, limit: int = 50
    ) -> AdapterResult:
        """Get task log output."""
        self._ensure_connected()
        try:
            data = await self._client.get(  # type: ignore[union-attr]
                C.NODE_TASK_LOG.format(node=node, upid=upid),
                params={"start": start, "limit": min(limit, 500)},
            )
            if not isinstance(data, list) or any(
                not isinstance(line, dict) or not isinstance(line.get("t"), str) for line in data
            ):
                return AdapterResult.fail("Task log unavailable or malformed")
            logs = [ProxmoxTaskLog(n=int(l.get("n", 0)), t=l["t"]) for l in data]
            return AdapterResult.ok(logs)
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    async def get_task_control_permissions(self, node: str) -> AdapterResult:
        """Read only the requested node's effective privilege map."""
        self._ensure_connected()
        path = f"/nodes/{node}"
        try:
            data = await self._client.get("/access/permissions", params={"path": path})
            return AdapterResult.ok(permissions_at_path(data, path))
        except (ProxmoxApiError, ValueError):
            return AdapterResult.fail("Task-control privileges unavailable")

    async def stop_task(self, node: str, upid: str, *, force: bool = False) -> AdapterResult:
        """Stop a running task.

        ``force`` propagates to the read-only gate; the staging
        applier passes ``force=True`` after the operator has cleared
        the dual-gate.
        """
        self._ensure_connected()
        try:
            data = await self._client.delete(  # type: ignore[union-attr]
                C.NODE_TASK_STOP.format(node=node, upid=upid),
                force=force,
            )
            return AdapterResult.ok(data)
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    # ═══════════════════════════════════════════════════════════════════════
    # MONITORING (RRD)
    # ═══════════════════════════════════════════════════════════════════════

    async def get_node_rrd(self, node: str, timeframe: str = "hour") -> AdapterResult:
        """Get node RRD monitoring data."""
        self._ensure_connected()
        try:
            data = await self._client.get(  # type: ignore[union-attr]
                C.NODE_RRDDATA.format(node=node),
                params={"timeframe": timeframe},
            )
            return self._parse_rrd(data)
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    async def get_vm_rrd(self, node: str, vmid: int, timeframe: str = "hour") -> AdapterResult:
        """Get VM RRD monitoring data."""
        self._ensure_connected()
        try:
            data = await self._client.get(  # type: ignore[union-attr]
                C.QEMU_RRDDATA.format(node=node, vmid=vmid),
                params={"timeframe": timeframe},
            )
            return self._parse_rrd(data)
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    async def get_container_rrd(
        self, node: str, vmid: int, timeframe: str = "hour"
    ) -> AdapterResult:
        """Get container RRD monitoring data."""
        self._ensure_connected()
        try:
            data = await self._client.get(  # type: ignore[union-attr]
                C.LXC_RRDDATA.format(node=node, vmid=vmid),
                params={"timeframe": timeframe},
            )
            return self._parse_rrd(data)
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    # ═══════════════════════════════════════════════════════════════════════
    # BACKUP
    # ═══════════════════════════════════════════════════════════════════════

    async def get_backup_jobs(self) -> AdapterResult:
        """Get scheduled backup jobs."""
        self._ensure_connected()
        try:
            data = await self._client.get(C.CLUSTER_BACKUP)  # type: ignore[union-attr]
            if not isinstance(data, list) or any(
                not isinstance(row, dict)
                or not isinstance(row.get("id"), str)
                or not row["id"]
                or type(row.get("enabled", 1)) not in (int, bool, str)
                or row.get("enabled", 1) not in (0, 1, "0", "1")
                for row in data
            ):
                return AdapterResult.fail("Backup job inventory is malformed")
            if len({row["id"] for row in data}) != len(data):
                return AdapterResult.fail("Backup job inventory has duplicate identities")
            jobs = [
                ProxmoxBackupJob(
                    id=b.get("id", ""),
                    schedule=b.get("schedule", ""),
                    storage=b.get("storage", ""),
                    vmid=str(b.get("vmid", "")),
                    mode=b.get("mode", ""),
                    compress=str(b.get("compress", "")),
                    enabled=b.get("enabled", 1) in (1, "1"),
                    mailnotification=b.get("mailnotification", "always"),
                    mailto=b.get("mailto", ""),
                    node=b.get("node"),
                    dow=b.get("dow"),
                )
                for b in data
            ]
            return AdapterResult.ok(jobs)
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    async def run_backup(
        self,
        node: str,
        vmid: int,
        storage: str,
        mode: str = "snapshot",
        compress: str = "zstd",
        *,
        force: bool = False,
    ) -> AdapterResult:
        """Trigger a manual backup (vzdump). ``force`` propagates to
        the read-only gate."""
        self._ensure_connected()
        try:
            data = await self._client.post(  # type: ignore[union-attr]
                C.NODE_VZDUMP.format(node=node),
                data={
                    "vmid": str(vmid),
                    "storage": storage,
                    "mode": mode,
                    "compress": compress,
                },
                force=force,
            )
            return AdapterResult.ok(data)
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    async def get_backup_job_configuration(self) -> AdapterResult:
        """Raw schedule configuration, including retention; malformed data is not empty."""
        self._ensure_connected()
        try:
            return AdapterResult.ok(await self._client.get(C.CLUSTER_BACKUP))
        except ProxmoxApiError:
            return AdapterResult.fail("Backup job configuration unavailable")

    async def get_backup_job_review_state(
        self, node: str | None, storage: str | None, vmids: list[int]
    ) -> AdapterResult:
        """Read explicit privilege paths and selected guest/storage state."""
        self._ensure_connected()
        try:
            permissions = {
                "/": permissions_at_path(
                    await self._client.get("/access/permissions", params={"path": "/"}), "/"
                )
            }
            result: dict[str, Any] = {"permissions": permissions}
            if node is not None and storage is not None:
                result["cluster"] = await self._client.get("/cluster/status")
                result["guests"] = await self._client.get(
                    "/cluster/resources", params={"type": "vm"}
                )
                result["storage"] = await self._client.get(f"/storage/{storage}")
                result["status"] = await self._client.get(f"/nodes/{node}/storage/{storage}/status")
                result["defaults"] = await self._client.get(
                    f"/nodes/{node}/vzdump/defaults", params={"storage": storage}
                )
                for path in [
                    f"/nodes/{node}",
                    f"/storage/{storage}",
                    *(f"/vms/{vmid}" for vmid in vmids),
                ]:
                    granted = await self._client.get("/access/permissions", params={"path": path})
                    permissions[path] = permissions_at_path(granted, path)
            return AdapterResult.ok(result)
        except (ProxmoxApiError, ValueError):
            return AdapterResult.fail("Backup job review unavailable")

    async def apply_reviewed_backup_job(
        self, action: str, job_id: str, settings: dict[str, Any], *, force: bool = False
    ) -> AdapterResult:
        """Internal reviewed dispatcher; the service validates action/options first."""
        self._ensure_connected()
        payload = {k: int(v) if isinstance(v, bool) else v for k, v in settings.items()}
        if action == "create":
            # Native POST returns null, so supply an ID instead of losing the
            # provider-generated ID when the response is lost.
            data = await self._client.post(
                C.CLUSTER_BACKUP,
                data={**payload, "id": job_id, "prune-backups": "keep-all=1"},
                force=force,
            )
        elif action == "update":
            data = await self._client.put(
                C.CLUSTER_BACKUP_JOB.format(jobid=job_id), data=payload, force=force
            )
        elif action == "delete":
            data = await self._client.delete(C.CLUSTER_BACKUP_JOB.format(jobid=job_id), force=force)
        else:
            raise ValueError("Unsupported reviewed backup job action")
        return AdapterResult.ok(data)

    async def create_backup_job(self, *, force: bool = False, **kwargs: Any) -> AdapterResult:
        """Create a scheduled backup job. ``force`` propagates to the
        read-only gate."""
        self._ensure_connected()
        try:
            payload: dict[str, Any] = {}
            for key in (
                "storage",
                "schedule",
                "vmid",
                "mode",
                "compress",
                "node",
                "enabled",
                "mailto",
                "mailnotification",
            ):
                if key in kwargs and kwargs[key] is not None:
                    val = kwargs[key]
                    if isinstance(val, bool):
                        payload[key] = 1 if val else 0
                    else:
                        payload[key] = val
            data = await self._client.post(  # type: ignore[union-attr]
                C.CLUSTER_BACKUP,
                data=payload,
                force=force,
            )
            return AdapterResult.ok(data)
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    async def update_backup_job(
        self, job_id: str, *, force: bool = False, **kwargs: Any
    ) -> AdapterResult:
        """Update a backup job. ``force`` propagates to the read-only gate."""
        self._ensure_connected()
        try:
            payload: dict[str, Any] = {}
            for key in (
                "storage",
                "schedule",
                "vmid",
                "mode",
                "compress",
                "node",
                "enabled",
                "mailto",
            ):
                if key in kwargs and kwargs[key] is not None:
                    val = kwargs[key]
                    if isinstance(val, bool):
                        payload[key] = 1 if val else 0
                    else:
                        payload[key] = val
            data = await self._client.put(  # type: ignore[union-attr]
                C.CLUSTER_BACKUP_JOB.format(jobid=job_id),
                data=payload,
                force=force,
            )
            return AdapterResult.ok(data)
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    async def delete_backup_job(self, job_id: str, *, force: bool = False) -> AdapterResult:
        """Delete a backup job. ``force`` propagates to the read-only gate."""
        self._ensure_connected()
        try:
            data = await self._client.delete(  # type: ignore[union-attr]
                C.CLUSTER_BACKUP_JOB.format(jobid=job_id),
                force=force,
            )
            return AdapterResult.ok(data)
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    async def upload_to_storage(
        self,
        node: str,
        storage: str,
        filename: str,
        content_type: str,
        file_path: str,
        *,
        force: bool = False,
    ) -> AdapterResult:
        """Upload a file (ISO/template) to storage via multipart POST.

        routed through ``ProxmoxClient.post_multipart`` so the
        breaker / read-only gate / path validator / metric emitters
        all run on the upload path — the previous implementation used
        ``self._client._http.post`` directly and bypassed every safety
        rail.
        """
        self._ensure_connected()
        try:
            path = C.NODE_STORAGE_UPLOAD.format(node=node, storage=storage)
            # Determine content category from content_type
            if "iso" in content_type.lower() or filename.lower().endswith(".iso"):
                pve_content = "iso"
            else:
                pve_content = "vztmpl"
            form_data = {"content": pve_content}
            # ``open(file_path, "rb")`` is a syscall that
            # blocks the event loop on the open + initial filesystem
            # metadata fetch. For NFS / remote-mounted storage that
            # latency can be tens of milliseconds — long enough to
            # stall every other coroutine sharing the loop. Run the
            # open in the default threadpool so the loop stays
            # responsive; the actual streaming I/O is handled by
            # httpx via the file object.
            loop = asyncio.get_running_loop()
            file_handle = await loop.run_in_executor(None, _open_binary_for_read, file_path)
            try:
                files = {"filename": (filename, file_handle, content_type)}
                resp = await self._client.post_multipart(  # type: ignore[union-attr]
                    path,
                    files=files,
                    data=form_data,
                    force=force,
                )
            finally:
                file_handle.close()
            if resp.status_code >= 400:
                # Generic message — don't echo response body which can
                # include URLs or path fragments.
                return AdapterResult.fail(f"Upload failed: HTTP {resp.status_code}")
            try:
                body = resp.json()
                if (
                    not 200 <= resp.status_code < 300
                    or not isinstance(body, dict)
                    or "data" not in body
                ):
                    raise ValueError("invalid upload acknowledgement")
                return AdapterResult.ok(body["data"])
            except (ValueError, UnicodeError) as e:
                raise AdapterOutcomeUnknownError(
                    "Proxmox upload returned an invalid acknowledgement; reconcile before retrying",
                    adapter_id="proxmox",
                ) from e
        except AdapterOutcomeUnknownError:
            raise
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)
        except Exception as e:
            # don't leak error details that may contain URLs,
            # filesystem paths or credentials.
            logger.exception(
                "Proxmox upload_to_storage failed for %s/%s/%s",
                node,
                storage,
                filename,
            )
            return AdapterResult.fail(type(e).__name__)

    # ═══════════════════════════════════════════════════════════════════════
    # FIREWALL
    # ═══════════════════════════════════════════════════════════════════════

    @staticmethod
    def _firewall_base(target: dict[str, Any]) -> str:
        from app.modules.hypervisor.firewall_schemas import FirewallTarget

        value = FirewallTarget.model_validate(target)
        if value.scope == "cluster":
            return "/cluster/firewall"
        if value.scope == "node":
            return f"/nodes/{value.node}/firewall"
        return f"/nodes/{value.node}/{value.vm_type}/{value.vmid}/firewall"

    async def get_firewall_configuration(self, target: dict[str, Any]) -> AdapterResult:
        """Preserve native digests and fields for review and independent readback."""
        self._ensure_connected()
        base = self._firewall_base(target)
        try:
            rules = await self._client.get(f"{base}/rules")
            options = await self._client.get(f"{base}/options")
            identity = None
            if target["scope"] == "guest":
                identity = await self._client.get(base.removesuffix("/firewall") + "/config")
                if not isinstance(identity, dict) or not isinstance(identity.get("digest"), str):
                    return AdapterResult.fail("Guest identity unavailable")
                identity = {"digest": identity["digest"]}
            return AdapterResult.ok({"rules": rules, "options": options, "identity": identity})
        except ProxmoxApiError:
            return AdapterResult.fail("Firewall configuration unavailable")

    async def get_firewall_permissions(self, target: dict[str, Any]) -> AdapterResult:
        self._ensure_connected()
        self._firewall_base(target)
        path = (
            "/"
            if target["scope"] == "cluster"
            else (
                f"/vms/{target['vmid']}"
                if target["scope"] == "guest"
                else f"/nodes/{target['node']}"
            )
        )
        try:
            result = await self._client.get("/access/permissions", params={"path": path})
            return AdapterResult.ok(permissions_at_path(result, path))
        except (ProxmoxApiError, ValueError):
            return AdapterResult.fail("Firewall privileges unavailable")

    async def apply_firewall_operation(
        self,
        target: dict[str, Any],
        action: str,
        data: dict[str, Any],
        pos: int | None = None,
        *,
        force: bool = False,
    ) -> AdapterResult:
        """One native write. Update/delete use Proxmox's locked digest check."""
        self._ensure_connected()
        base = self._firewall_base(target)
        if action not in ("create", "update", "delete", "move", "options"):
            raise ValueError("Unsupported firewall action")
        if action != "create" and not re.fullmatch(r"[a-f0-9]{40}", str(data.get("digest", ""))):
            raise ValueError("Native firewall digest required")
        if action in ("update", "delete", "move") and (type(pos) is not int or pos < 0):
            raise ValueError("Firewall position required")
        try:
            if action == "create":
                result = await self._client.post(f"{base}/rules", data=data, force=force)
            elif action == "delete":
                result = await self._client.delete(f"{base}/rules/{pos}", params=data, force=force)
            else:
                path = f"{base}/options" if action == "options" else f"{base}/rules/{pos}"
                result = await self._client.put(path, data=data, force=force)
            return AdapterResult.ok(result)
        except ProxmoxApiError:
            return AdapterResult.fail("Firewall write rejected")

    async def get_firewall_rules(
        self, node: str | None = None, vmid: int | None = None, vm_type: str = "qemu"
    ) -> AdapterResult:
        """Get firewall rules at cluster, node, or VM level."""
        self._ensure_connected()
        try:
            if vmid is not None and node:
                path = (
                    C.QEMU_FIREWALL_RULES if vm_type == "qemu" else C.LXC_FIREWALL_RULES
                ).format(node=node, vmid=vmid)
            elif node:
                path = C.NODE_FIREWALL_RULES.format(node=node)
            else:
                path = C.CLUSTER_FIREWALL_RULES
            data = await self._client.get(path)  # type: ignore[union-attr]
            if not isinstance(data, list) or any(not isinstance(r, dict) for r in data):
                return AdapterResult.fail("Malformed firewall rules")
            if any(
                not (
                    type(r.get("enable", 0)) in (int, bool)
                    and r.get("enable", 0) in (0, 1)
                    or isinstance(r.get("enable", 0), str)
                    and r["enable"] in ("0", "1")
                )
                for r in data
            ):
                return AdapterResult.fail("Malformed firewall flag")
            rules = [
                ProxmoxFirewallRule(
                    pos=int(r.get("pos", 0)),
                    type=r.get("type", ""),
                    action=r.get("action", ""),
                    enable=r.get("enable", 0) in (1, True, "1"),
                    source=r.get("source"),
                    dest=r.get("dest"),
                    sport=r.get("sport"),
                    dport=r.get("dport"),
                    proto=r.get("proto"),
                    macro=r.get("macro"),
                    iface=r.get("iface"),
                    log=r.get("log"),
                    comment=r.get("comment"),
                )
                for r in data
            ]
            return AdapterResult.ok(rules)
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    # Keep old method as alias for backwards compatibility
    async def get_node_firewall_rules(self, node: str) -> AdapterResult:
        """Get PVE firewall rules for a node."""
        return await self.get_firewall_rules(node=node)

    async def create_firewall_rule(
        self,
        *,
        node: str | None = None,
        vmid: int | None = None,
        vm_type: str = "qemu",
        action: str,
        rule_type: str = "in",
        enable: bool = True,
        source: str | None = None,
        dest: str | None = None,
        sport: str | None = None,
        dport: str | None = None,
        proto: str | None = None,
        macro: str | None = None,
        comment: str | None = None,
        force: bool = False,
    ) -> AdapterResult:
        """Create a firewall rule.

        ``force`` propagates to the read-only gate in the client; the
        staging applier passes ``force=True`` after the operator has
        cleared the dual-gate (env + apply param). Direct callers must
        not pass ``force=True``.
        """
        self._ensure_connected()
        try:
            if vmid is not None and node:
                path = (
                    C.QEMU_FIREWALL_RULES if vm_type == "qemu" else C.LXC_FIREWALL_RULES
                ).format(node=node, vmid=vmid)
            elif node:
                path = C.NODE_FIREWALL_RULES.format(node=node)
            else:
                path = C.CLUSTER_FIREWALL_RULES
            payload: dict[str, Any] = {
                "action": action,
                "type": rule_type,
                "enable": 1 if enable else 0,
            }
            for key, val in [
                ("source", source),
                ("dest", dest),
                ("sport", sport),
                ("dport", dport),
                ("proto", proto),
                ("macro", macro),
                ("comment", comment),
            ]:
                if val is not None:
                    payload[key] = val
            data = await self._client.post(path, data=payload, force=force)  # type: ignore[union-attr]
            return AdapterResult.ok(data)
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    async def delete_firewall_rule(
        self, pos: int, node: str | None = None, *, force: bool = False
    ) -> AdapterResult:
        """Delete a firewall rule by position."""
        self._ensure_connected()
        try:
            if node:
                path = C.NODE_FIREWALL_RULE.format(node=node, pos=pos)
            else:
                path = f"{C.CLUSTER_FIREWALL_RULES}/{pos}"
            data = await self._client.delete(path, force=force)  # type: ignore[union-attr]
            return AdapterResult.ok(data)
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    # ═══════════════════════════════════════════════════════════════════════
    # GUEST FIREWALL (per VM/CT)
    # ═══════════════════════════════════════════════════════════════════════

    async def get_guest_firewall_rules(self, node: str, vm_type: str, vmid: int) -> AdapterResult:
        """Get firewall rules for a VM/CT."""
        self._ensure_connected()
        try:
            base = C.QEMU_FIREWALL_RULES if vm_type == "qemu" else C.LXC_FIREWALL_RULES
            url = base.format(node=node, vmid=vmid)
            data = await self._client.get(url)  # type: ignore[union-attr]
            return (
                AdapterResult.ok(data)
                if isinstance(data, list) and all(isinstance(r, dict) for r in data)
                else AdapterResult.fail("Malformed firewall rules")
            )
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    async def create_guest_firewall_rule(
        self,
        node: str,
        vm_type: str,
        vmid: int,
        rule: dict[str, Any],
        *,
        force: bool = False,
    ) -> AdapterResult:
        """Create a firewall rule on a VM/CT.

        ``force`` propagates to the read-only gate; the staging applier
        passes ``force=True`` after the dual-gate clears.
        """
        self._ensure_connected()
        try:
            base = C.QEMU_FIREWALL_RULES if vm_type == "qemu" else C.LXC_FIREWALL_RULES
            url = base.format(node=node, vmid=vmid)
            data = await self._client.post(url, data=rule, force=force)  # type: ignore[union-attr]
            return AdapterResult.ok(data)
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    async def delete_guest_firewall_rule(
        self,
        node: str,
        vm_type: str,
        vmid: int,
        pos: int,
        *,
        force: bool = False,
    ) -> AdapterResult:
        """Delete a firewall rule on a VM/CT by position."""
        self._ensure_connected()
        try:
            base = C.QEMU_FIREWALL_RULE if vm_type == "qemu" else C.LXC_FIREWALL_RULE
            url = base.format(node=node, vmid=vmid, pos=pos)
            data = await self._client.delete(url, force=force)  # type: ignore[union-attr]
            return AdapterResult.ok(data)
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    async def get_guest_firewall_options(self, node: str, vm_type: str, vmid: int) -> AdapterResult:
        """Get firewall options for a VM/CT."""
        self._ensure_connected()
        try:
            base = C.QEMU_FIREWALL_OPTIONS if vm_type == "qemu" else C.LXC_FIREWALL_OPTIONS
            url = base.format(node=node, vmid=vmid)
            data = await self._client.get(url)  # type: ignore[union-attr]
            return (
                AdapterResult.ok(data)
                if isinstance(data, dict)
                else AdapterResult.fail("Malformed firewall options")
            )
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    async def update_guest_firewall_options(
        self,
        node: str,
        vm_type: str,
        vmid: int,
        options: dict[str, Any],
        *,
        force: bool = False,
    ) -> AdapterResult:
        """Update firewall options for a VM/CT.

        ``force`` propagates to the read-only gate; the staging applier
        passes ``force=True`` after the dual-gate clears.
        """
        self._ensure_connected()
        try:
            base = C.QEMU_FIREWALL_OPTIONS if vm_type == "qemu" else C.LXC_FIREWALL_OPTIONS
            url = base.format(node=node, vmid=vmid)
            data = await self._client.put(url, data=options, force=force)  # type: ignore[union-attr]
            return AdapterResult.ok(data)
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    async def get_cluster_firewall_options(self) -> AdapterResult:
        """Get cluster-level firewall options."""
        self._ensure_connected()
        try:
            data = await self._client.get(C.CLUSTER_FIREWALL_OPTIONS)  # type: ignore[union-attr]
            return (
                AdapterResult.ok(data)
                if isinstance(data, dict)
                else AdapterResult.fail("Malformed firewall options")
            )
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    async def update_cluster_firewall_options(
        self,
        options: dict[str, Any],
        *,
        force: bool = False,
    ) -> AdapterResult:
        """Update cluster-level firewall options.

        ``force`` propagates to the read-only gate; the staging applier
        passes ``force=True`` after the dual-gate clears.
        """
        self._ensure_connected()
        try:
            data = await self._client.put(  # type: ignore[union-attr]
                C.CLUSTER_FIREWALL_OPTIONS,
                data=options,
                force=force,
            )
            return AdapterResult.ok(data)
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    # ═══════════════════════════════════════════════════════════════════════
    # RESOURCE POOLS
    # ═══════════════════════════════════════════════════════════════════════

    async def get_pools(self) -> AdapterResult:
        """Get resource pools."""
        self._ensure_connected()
        try:
            data = await self._client.get(C.POOLS)  # type: ignore[union-attr]
            if not isinstance(data, list):
                return AdapterResult.ok([])
            pools = [
                ProxmoxResourcePool(
                    poolid=p.get("poolid", ""),
                    comment=p.get("comment", ""),
                )
                for p in data
            ]
            return AdapterResult.ok(pools)
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    async def get_pool_detail(self, poolid: str) -> AdapterResult:
        """Get pool details with members."""
        self._ensure_connected()
        try:
            data = await self._client.get(  # type: ignore[union-attr]
                C.POOL_DETAIL.format(poolid=poolid)
            )
            if not isinstance(data, dict):
                return AdapterResult.fail("Pool not found")
            return AdapterResult.ok(
                ProxmoxResourcePool(
                    poolid=data.get("poolid", poolid),
                    comment=data.get("comment", ""),
                    members=data.get("members", []),
                )
            )
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    # ═══════════════════════════════════════════════════════════════════════
    # CEPH
    # ═══════════════════════════════════════════════════════════════════════

    async def get_ceph_status(self, node: str) -> AdapterResult:
        """Get Ceph cluster status (if available)."""
        self._ensure_connected()
        try:
            data = await self._client.get(  # type: ignore[union-attr]
                C.NODE_CEPH_STATUS.format(node=node)
            )
            if not isinstance(data, dict):
                return AdapterResult.fail("Ceph not available")
            health = data.get("health", {})
            pgmap = data.get("pgmap", {})
            osdmap = data.get("osdmap", {}).get("osdmap", data.get("osdmap", {}))
            return AdapterResult.ok(
                ProxmoxCephStatus(
                    health=health.get("status", ""),
                    num_osds=int(osdmap.get("num_osds", 0)),
                    num_osds_up=int(osdmap.get("num_up_osds", 0)),
                    num_osds_in=int(osdmap.get("num_in_osds", 0)),
                    num_pgs=int(pgmap.get("num_pgs", 0)),
                    num_pools=int(pgmap.get("num_pools", 0)),
                    total_bytes=int(pgmap.get("bytes_total", 0)),
                    used_bytes=int(pgmap.get("bytes_used", 0)),
                    avail_bytes=int(pgmap.get("bytes_avail", 0)),
                    raw=data,
                )
            )
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    async def get_ceph_osd(self, node: str) -> AdapterResult:
        """Get Ceph OSD list."""
        self._ensure_connected()
        try:
            data = await self._client.get(  # type: ignore[union-attr]
                C.NODE_CEPH_OSD.format(node=node)
            )
            return AdapterResult.ok(data if isinstance(data, list) else [])
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    async def get_ceph_pools(self, node: str) -> AdapterResult:
        """Get Ceph pool list."""
        self._ensure_connected()
        try:
            data = await self._client.get(  # type: ignore[union-attr]
                C.NODE_CEPH_POOLS.format(node=node)
            )
            return AdapterResult.ok(data if isinstance(data, list) else [])
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    async def get_ceph_mon(self, node: str) -> AdapterResult:
        """Get Ceph monitor list."""
        self._ensure_connected()
        try:
            data = await self._client.get(  # type: ignore[union-attr]
                C.NODE_CEPH_MON.format(node=node)
            )
            return AdapterResult.ok(data if isinstance(data, list) else [])
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    async def get_ceph_mds(self, node: str) -> AdapterResult:
        """Get Ceph MDS (metadata server) list."""
        self._ensure_connected()
        try:
            data = await self._client.get(  # type: ignore[union-attr]
                C.NODE_CEPH_MDS.format(node=node)
            )
            return AdapterResult.ok(data if isinstance(data, list) else [])
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    async def get_ceph_fs(self, node: str) -> AdapterResult:
        """Get CephFS list."""
        self._ensure_connected()
        try:
            data = await self._client.get(  # type: ignore[union-attr]
                C.NODE_CEPH_FS.format(node=node)
            )
            return AdapterResult.ok(data if isinstance(data, list) else [])
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    async def get_ceph_crush_rules(self, node: str) -> AdapterResult:
        """Get Ceph CRUSH rules."""
        self._ensure_connected()
        try:
            data = await self._client.get(  # type: ignore[union-attr]
                C.NODE_CEPH_CRUSH_RULES.format(node=node)
            )
            return AdapterResult.ok(data if isinstance(data, list) else [])
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    async def get_node_sensors(self, node: str) -> AdapterResult:
        """Get sensor/temperature data from node status."""
        self._ensure_connected()
        try:
            data = await self._client.get(C.NODE_STATUS.format(node=node))  # type: ignore[union-attr]
            if not isinstance(data, dict):
                return AdapterResult.fail("Unexpected response")

            cpuinfo = data.get("cpuinfo", {})
            loadavg = data.get("loadavg", [])
            sensors = {
                "cpu_temp": None,
                "cpu_temps": [],
                "pveversion": data.get("pveversion"),
                "loadavg": loadavg if isinstance(loadavg, list) else None,
                "cpuinfo": cpuinfo if isinstance(cpuinfo, dict) else None,
                "kversion": data.get("kversion"),
            }

            # Proxmox thermal data is in thermalstate or sensor-named keys
            thermals = data.get("thermalstate", data.get("sensorsdata", {}))
            if isinstance(thermals, dict):
                temps = []
                for name, val in thermals.items():
                    if isinstance(val, (int, float)):
                        temps.append({"name": name, "value": val, "unit": "°C"})
                    elif isinstance(val, dict):
                        temps.append(
                            {
                                "name": name,
                                "value": val.get("value") or val.get("input"),
                                "unit": val.get("unit", "°C"),
                            }
                        )
                sensors["cpu_temps"] = temps
                if temps:
                    cpu_temps = [
                        t["value"]
                        for t in temps
                        if t.get("value") is not None and "cpu" in t["name"].lower()
                    ]
                    if cpu_temps:
                        sensors["cpu_temp"] = max(cpu_temps)

            return AdapterResult.ok(sensors)
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)
        except Exception:
            return AdapterResult.fail("Failed to read sensor data")

    # ═══════════════════════════════════════════════════════════════════════
    # REPLICATION
    # ═══════════════════════════════════════════════════════════════════════

    async def get_replication_jobs(self) -> AdapterResult:
        """Get storage replication jobs."""
        self._ensure_connected()
        try:
            data = await self._client.get(C.CLUSTER_REPLICATION)  # type: ignore[union-attr]
            return AdapterResult.ok(data if isinstance(data, list) else [])
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    # ═══════════════════════════════════════════════════════════════════════
    # APT / UPDATES
    # ═══════════════════════════════════════════════════════════════════════

    async def get_node_apt_updates(self, node: str) -> AdapterResult:
        """List available APT package updates for a node."""
        self._ensure_connected()
        try:
            data = await self._client.get(  # type: ignore[union-attr]
                C.NODE_APT_UPDATE.format(node=node)
            )
            return AdapterResult.ok(data if isinstance(data, list) else [])
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    async def refresh_node_apt(self, node: str, *, force: bool = False) -> AdapterResult:
        """Trigger APT database refresh on a node. Returns UPID.

        ``force`` propagates to the read-only gate.
        """
        self._ensure_connected()
        try:
            data = await self._client.post(  # type: ignore[union-attr]
                C.NODE_APT_UPDATE.format(node=node),
                force=force,
            )
            return AdapterResult.ok({"upid": data})
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    async def get_node_apt_versions(self, node: str) -> AdapterResult:
        """Get installed package versions on a node."""
        self._ensure_connected()
        try:
            data = await self._client.get(  # type: ignore[union-attr]
                C.NODE_APT_VERSIONS.format(node=node)
            )
            return AdapterResult.ok(data if isinstance(data, list) else [])
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    # ═══════════════════════════════════════════════════════════════════════
    # CERTIFICATES
    # ═══════════════════════════════════════════════════════════════════════

    async def get_node_certificates(self, node: str) -> AdapterResult:
        """List TLS certificates on a node."""
        self._ensure_connected()
        try:
            data = await self._client.get(  # type: ignore[union-attr]
                C.NODE_CERTIFICATES.format(node=node)
            )
            return (
                AdapterResult.ok(data)
                if isinstance(data, list)
                else AdapterResult.fail("Malformed certificate inventory")
            )
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    async def get_certificate_operation_state(
        self, node: str, *, acme: bool = False
    ) -> AdapterResult:
        """Raw node inventory and the TLS peer of that exact response."""
        self._ensure_connected()
        assert self._client is not None
        try:
            certificates, peer = await self._client.get_with_peer(
                C.NODE_CERTIFICATES.format(node=node)
            )
            status = await self._client.get(C.CLUSTER_STATUS)
            config = await self._client.get(f"/nodes/{node}/config") if acme else None
            return AdapterResult.ok(
                {"certificates": certificates, "peer": peer, "status": status, "config": config}
            )
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    async def renew_node_acme_certificate(
        self,
        node: str,
        acme_force: bool = False,
        *,
        force: bool = False,
    ) -> AdapterResult:
        """Renew ACME/Let's Encrypt certificate. Returns UPID.

        ``acme_force`` is the Proxmox API ``force=1`` flag (force renewal
        even if not yet expired). ``force`` propagates to the FreeSDN
        read-only gate.
        """
        self._ensure_connected()
        try:
            payload: dict[str, Any] = {}
            if acme_force:
                payload["force"] = 1
            data = await self._client.put(  # type: ignore[union-attr]
                C.NODE_CERTIFICATES_ACME.format(node=node),
                data=payload or None,
                force=force,
            )
            return AdapterResult.ok({"upid": data})
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    async def upload_custom_certificate(
        self,
        node: str,
        certificates: str,
        key: str,
        overwrite: bool = False,
        restart: bool = False,
        *,
        force: bool = False,
    ) -> AdapterResult:
        """Upload a custom TLS certificate.

        HIGH-RISK: replaces the node's TLS cert. A bad cert / key
        mismatch can lock the operator out of pveproxy. ``overwrite`` is
        the Proxmox API ``force=1`` flag (allow overwrite of existing
        cert); ``force`` propagates to the FreeSDN read-only gate.
        """
        self._ensure_connected()
        try:
            payload: dict[str, Any] = {"certificates": certificates, "key": key}
            if overwrite:
                payload["force"] = 1
            if restart:
                payload["restart"] = 1
            data = await self._client.post(  # type: ignore[union-attr]
                C.NODE_CERTIFICATES_CUSTOM.format(node=node),
                data=payload,
                force=force,
            )
            return AdapterResult.ok(data)
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    async def delete_custom_certificate(
        self,
        node: str,
        restart: bool = False,
        *,
        force: bool = False,
    ) -> AdapterResult:
        """Delete custom certificate and revert to self-signed.

        ``force`` propagates to the read-only gate. Item 7: ``restart``
        is passed via ``params={}`` rather than embedded in the path —
        appending ``?restart=1`` to the path made the URL fail
        ``_validate_path``'s safe-character regex.
        """
        # irreversible — require force UNCONDITIONALLY so only the staging
        # applier (force=True) can delete the custom cert; the direct route is refused.
        if not force:
            raise AdapterConfirmationRequiredError(
                "Deleting the custom certificate is irreversible — resubmit with "
                "confirmed=true to proceed.",
                adapter_id="proxmox",
            )
        self._ensure_connected()
        try:
            path = C.NODE_CERTIFICATES_CUSTOM.format(node=node)
            params: dict[str, Any] | None = {"restart": 1} if restart else None
            data = await self._client.delete(  # type: ignore[union-attr]
                path,
                force=force,
                params=params,
            )
            return AdapterResult.ok(data)
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    # ═══════════════════════════════════════════════════════════════════════
    # SUBSCRIPTION
    # ═══════════════════════════════════════════════════════════════════════

    async def get_node_subscription(self, node: str) -> AdapterResult:
        """Get subscription status for a node."""
        self._ensure_connected()
        try:
            data = await self._client.get(  # type: ignore[union-attr]
                C.NODE_SUBSCRIPTION.format(node=node)
            )
            return AdapterResult.ok(data if isinstance(data, dict) else {})
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    # ═══════════════════════════════════════════════════════════════════════
    # CROSS-CLUSTER MIGRATION
    # ═══════════════════════════════════════════════════════════════════════

    async def remote_migrate_vm(
        self,
        node: str,
        vmid: int,
        target_endpoint: str,
        target_storage: str,
        target_bridge: str | None = None,
        online: bool = True,
        delete_source: bool = True,
        *,
        force: bool = False,
    ) -> AdapterResult:
        """Initiate cross-cluster VM migration to a remote PVE cluster."""
        self._ensure_connected()
        try:
            payload: dict[str, Any] = {
                "target-endpoint": target_endpoint,
                "target-storage": target_storage,
            }
            if target_bridge:
                payload["target-bridge"] = target_bridge
            if online:
                payload["online"] = 1
            if delete_source:
                payload["delete"] = 1
            data = await self._client.post(  # type: ignore[union-attr]
                C.QEMU_REMOTE_MIGRATE.format(node=node, vmid=vmid),
                data=payload,
                force=force,
            )
            return AdapterResult.ok({"upid": data, "vmid": vmid})
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    async def remote_migrate_container(
        self,
        node: str,
        vmid: int,
        target_endpoint: str,
        target_storage: str,
        target_bridge: str | None = None,
        online: bool = True,
        delete_source: bool = True,
        restart: bool = False,
        *,
        force: bool = False,
    ) -> AdapterResult:
        """Initiate cross-cluster container migration."""
        self._ensure_connected()
        try:
            payload: dict[str, Any] = {
                "target-endpoint": target_endpoint,
                "target-storage": target_storage,
            }
            if target_bridge:
                payload["target-bridge"] = target_bridge
            if online:
                payload["online"] = 1
            if delete_source:
                payload["delete"] = 1
            if restart:
                payload["restart"] = 1
            data = await self._client.post(  # type: ignore[union-attr]
                C.LXC_REMOTE_MIGRATE.format(node=node, vmid=vmid),
                data=payload,
                force=force,
            )
            return AdapterResult.ok({"upid": data, "vmid": vmid})
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    # ═══════════════════════════════════════════════════════════════════════
    # SDN
    # ═══════════════════════════════════════════════════════════════════════

    async def inspect_sdn(self, controller_id: UUID) -> SdnInspection:
        self._ensure_connected()
        from app.adapters.proxmox.sdn import inspect_sdn

        return await inspect_sdn(self._client, controller_id)

    async def inspect_sdn_attachments(self, controller_id: UUID) -> SdnAttachmentInspection:
        self._ensure_connected()
        from app.adapters.proxmox.sdn_attachments import inspect_attachments

        return await inspect_attachments(self._client, controller_id)

    async def inspect_sdn_dependencies(self, controller_id: UUID) -> SdnDependencyInspection:
        from app.adapters.proxmox.sdn_dependencies import inspect_dependencies

        self._ensure_connected()
        return await inspect_dependencies(self._client, controller_id)

    async def get_sdn_dry_run(self, controller_id: UUID, node: str) -> SdnDryRunObservation:
        from app.adapters.proxmox.sdn import dry_run, validate_node

        validate_node(node)
        self._ensure_connected()
        return await dry_run(self._client, controller_id, node)

    async def _sdn_collection(self, resource: str) -> AdapterResult:
        self._ensure_connected()
        from app.adapters.proxmox.sdn import observe_collection

        observation = await observe_collection(self._client, resource, "configured")
        if observation.status != "available":
            return AdapterResult.fail("SDN collection " + observation.status)
        return AdapterResult.ok(observation.items)

    async def get_sdn_zones(self) -> AdapterResult:
        """Visible configured zones; not an unfiltered or running-state inventory."""
        return await self._sdn_collection("zones")

    async def get_sdn_vnets(self) -> AdapterResult:
        """Visible configured VNets; malformed data is a failure, not an empty list."""
        return await self._sdn_collection("vnets")

    async def get_sdn_controllers(self) -> AdapterResult:
        """Allowlisted configured controller fields, excluding secret material."""
        return await self._sdn_collection("controllers")

    # ═══════════════════════════════════════════════════════════════════════
    # GUEST AGENT (EXTENDED)
    # ═══════════════════════════════════════════════════════════════════════

    async def agent_exec(
        self,
        node: str,
        vmid: int,
        command: str,
        input_data: str | None = None,
        *,
        confirmed: bool = False,
        force: bool = False,
    ) -> AdapterResult:
        """Execute a command inside a VM via QEMU guest agent.

        EXTRA-SENSITIVE: arbitrary code execution on the guest. Requires an
        explicit second factor — ``confirmed`` on the direct path (the operator
        acknowledging the exec) or ``force`` from the staging applier. ``confirmed``
        does NOT bypass read-only: it clears the gate but leaves force
        False, so this POST is still refused while read-only is ON (monitor-only
        deployments run no guest commands). The staging/direct row IS the audit
        trail for who ran what on which guest.
        """
        # require an explicit second factor (confirmed on the direct
        # path, or force from the staging applier) before reaching the live agent.
        if not force and not confirmed:
            raise AdapterConfirmationRequiredError(
                "Guest-agent exec runs arbitrary code inside the guest — resubmit "
                "with confirmed=true to proceed.",
                adapter_id="proxmox",
            )
        self._ensure_connected()
        try:
            payload: dict[str, Any] = {"command": command}
            if input_data is not None:
                payload["input-data"] = input_data
            data = await self._client.post(  # type: ignore[union-attr]
                C.QEMU_AGENT_EXEC.format(node=node, vmid=vmid),
                data=payload,
                force=force,
            )
            return AdapterResult.ok(data)
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    async def agent_exec_status(self, node: str, vmid: int, pid: int) -> AdapterResult:
        """Get status of a guest agent command execution."""
        self._ensure_connected()
        try:
            data = await self._client.get(  # type: ignore[union-attr]
                C.QEMU_AGENT_EXEC_STATUS.format(node=node, vmid=vmid),
                params={"pid": pid},
            )
            return AdapterResult.ok(data)
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    async def agent_file_read(self, node: str, vmid: int, file: str) -> AdapterResult:
        """Read a file inside a VM via guest agent."""
        self._ensure_connected()
        try:
            data = await self._client.get(  # type: ignore[union-attr]
                C.QEMU_AGENT_FILE_READ.format(node=node, vmid=vmid),
                params={"file": file},
            )
            return AdapterResult.ok(data)
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    async def agent_file_write(
        self,
        node: str,
        vmid: int,
        file: str,
        content: str,
        *,
        confirmed: bool = False,
        force: bool = False,
    ) -> AdapterResult:
        """Write a file inside a VM via guest agent.

        EXTRA-SENSITIVE: arbitrary write to the guest filesystem (could drop a
        payload that bypasses guest security policies). Requires an explicit second
        factor — ``confirmed`` on the direct path or ``force`` from staging.
        ``confirmed`` does NOT bypass read-only (force stays False), so this POST is
        still refused while read-only is ON. The row IS the audit trail for who
        wrote what to which guest.
        """
        # require an explicit second factor (confirmed on the direct path,
        # or force from the staging applier) before reaching the live guest FS.
        if not force and not confirmed:
            raise AdapterConfirmationRequiredError(
                "Guest-agent file-write modifies the guest filesystem — resubmit "
                "with confirmed=true to proceed.",
                adapter_id="proxmox",
            )
        self._ensure_connected()
        try:
            data = await self._client.post(  # type: ignore[union-attr]
                C.QEMU_AGENT_FILE_WRITE.format(node=node, vmid=vmid),
                data={"file": file, "content": content},
                force=force,
            )
            return AdapterResult.ok(data)
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    # ═══════════════════════════════════════════════════════════════════════
    # PENDING CONFIG
    # ═══════════════════════════════════════════════════════════════════════

    async def get_vm_pending_config(self, node: str, vmid: int) -> AdapterResult:
        """Get pending configuration changes for a VM."""
        self._ensure_connected()
        try:
            data = await self._client.get(  # type: ignore[union-attr]
                C.QEMU_PENDING.format(node=node, vmid=vmid)
            )
            return AdapterResult.ok(data if isinstance(data, list) else [])
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    async def get_container_pending_config(self, node: str, vmid: int) -> AdapterResult:
        """Get pending configuration changes for a container."""
        self._ensure_connected()
        try:
            data = await self._client.get(  # type: ignore[union-attr]
                C.LXC_PENDING.format(node=node, vmid=vmid)
            )
            return AdapterResult.ok(data if isinstance(data, list) else [])
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    # ═══════════════════════════════════════════════════════════════════════
    # CLUSTER (EXTENDED)
    # ═══════════════════════════════════════════════════════════════════════

    async def get_cluster_options(self) -> AdapterResult:
        """Get cluster-wide options."""
        self._ensure_connected()
        try:
            data = await self._client.get(C.CLUSTER_OPTIONS)  # type: ignore[union-attr]
            return AdapterResult.ok(data if isinstance(data, dict) else {})
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    async def get_cluster_log(self, max_entries: int = 200) -> AdapterResult:
        """Get cluster log entries."""
        self._ensure_connected()
        try:
            data = await self._client.get(  # type: ignore[union-attr]
                C.CLUSTER_LOG, params={"max": min(max_entries, 500)}
            )
            return AdapterResult.ok(data if isinstance(data, list) else [])
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    async def get_cluster_config_nodes(self) -> AdapterResult:
        """Get cluster config node list (corosync membership)."""
        self._ensure_connected()
        try:
            data = await self._client.get(C.CLUSTER_CONFIG_NODES)  # type: ignore[union-attr]
            return AdapterResult.ok(data if isinstance(data, list) else [])
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    async def get_cluster_replication(self) -> AdapterResult:
        """Get storage replication status."""
        self._ensure_connected()
        try:
            data = await self._client.get(C.CLUSTER_REPLICATION)  # type: ignore[union-attr]
            return AdapterResult.ok(data if isinstance(data, list) else [])
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    async def get_replication_log(self, replication_id: str) -> AdapterResult:
        """Get log for a specific replication job."""
        self._ensure_connected()
        try:
            data = await self._client.get(  # type: ignore[union-attr]
                C.CLUSTER_REPLICATION_LOG.format(id=replication_id)
            )
            return AdapterResult.ok(data if isinstance(data, list) else [])
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    # ═══════════════════════════════════════════════════════════════════════
    # INTERNAL HELPERS
    # ═══════════════════════════════════════════════════════════════════════

    def _ensure_connected(self) -> None:
        """Raise if not connected."""
        if not self._client or not self._client.is_connected:
            raise ProxmoxApiError("Not connected. Call connect() first.")

    async def _vm_action(
        self,
        path_template: str,
        node: str,
        vmid: int,
        action: str,
        *,
        force: bool = False,
    ) -> AdapterResult:
        """Execute a VM/CT power action."""
        self._ensure_connected()
        try:
            data = await self._client.post(  # type: ignore[union-attr]
                path_template.format(node=node, vmid=vmid),
                force=force,
            )
            return AdapterResult.ok({"action": action, "vmid": vmid, "upid": data})
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    @staticmethod
    def _parse_vm(raw: dict, node: str, vm_type: str) -> ProxmoxVM:
        """Parse raw API data into ProxmoxVM."""
        status_raw = raw.get("status", raw.get("qmpstatus", "unknown"))
        return ProxmoxVM(
            vmid=int(raw.get("vmid", 0)),
            name=raw.get("name", f"VM {raw.get('vmid', '?')}"),
            node=raw.get("node", node),
            vm_type=vm_type if vm_type in ("qemu", "lxc") else raw.get("type", "qemu"),
            status=VM_STATUS_MAP.get(status_raw, status_raw),
            cpu=float(raw.get("cpu", 0)),
            cpus=int(raw.get("cpus", raw.get("maxcpu", 0))),
            mem=int(raw.get("mem", 0)),
            maxmem=int(raw.get("maxmem", 0)),
            disk=int(raw.get("disk", 0)),
            maxdisk=int(raw.get("maxdisk", 0)),
            netin=int(raw.get("netin", 0)),
            netout=int(raw.get("netout", 0)),
            uptime=int(raw.get("uptime", 0)),
            pid=int(raw.get("pid")) if raw.get("pid") is not None else None,
            tags=raw.get("tags", ""),
            template=bool(raw.get("template", 0)),
            lock=raw.get("lock"),
            ha_state=raw.get("hastate"),
        )

    # ═══════════════════════════════════════════════════════════════════════
    # PBS / BACKUP RESTORE / CLOUDINIT
    # ═══════════════════════════════════════════════════════════════════════

    async def get_storage_prune_backups(
        self, node: str, storage: str, vmid: int | None = None
    ) -> AdapterResult:
        """Get prune preview for backup storage."""
        self._ensure_connected()
        try:
            path = C.STORAGE_PRUNE_BACKUPS.format(node=node, storage=storage)
            params: dict[str, Any] = {}
            if vmid is not None:
                params["vmid"] = vmid
            data = await self._client.get(path, params=params or None)  # type: ignore[union-attr]
            return AdapterResult.ok(data)
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    async def prune_backups(
        self,
        node: str,
        storage: str,
        keep_last: int | None = None,
        keep_hourly: int | None = None,
        keep_daily: int | None = None,
        keep_weekly: int | None = None,
        keep_monthly: int | None = None,
        keep_yearly: int | None = None,
        vmid: int | None = None,
        *,
        force: bool = False,
    ) -> AdapterResult:
        """Execute backup pruning on storage.

        IRREVERSIBLE: deleted backup files cannot be recovered. ``force``
        propagates to the read-only gate; only the staging applier
        passes ``force=True``.
        """
        self._ensure_connected()
        try:
            path = C.STORAGE_PRUNE_BACKUPS.format(node=node, storage=storage)
            params: dict[str, Any] = {}
            if keep_last is not None:
                params["keep-last"] = keep_last
            if keep_hourly is not None:
                params["keep-hourly"] = keep_hourly
            if keep_daily is not None:
                params["keep-daily"] = keep_daily
            if keep_weekly is not None:
                params["keep-weekly"] = keep_weekly
            if keep_monthly is not None:
                params["keep-monthly"] = keep_monthly
            if keep_yearly is not None:
                params["keep-yearly"] = keep_yearly
            if vmid is not None:
                params["vmid"] = vmid
            # public ``delete()`` instead of poking the
            # private ``_request`` — keeps prune_backups on the same
            # safety rails (read-only gate, breaker, metrics) as every
            # other adapter caller.
            data = await self._client.delete(  # type: ignore[union-attr]
                path,
                params=params or None,
                force=force,
            )
            return AdapterResult.ok(data)
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    async def restore_backup(
        self,
        node: str,
        vm_type: str,
        archive: str,
        vmid: int,
        storage: str | None = None,
        start: bool = False,
        unique: bool = True,
        *,
        force: bool = False,
    ) -> AdapterResult:
        """Restore a VM/CT from backup archive.

        Treat recovery as destructive and require staged confirmation.
        ``unique`` controls regenerated MAC addresses, not overwrite permission.
        ``force`` opens FreeSDN's write gate; it is NOT sent as Proxmox's
        overwrite flag. An existing target may therefore be refused by Proxmox.
        """
        self._ensure_connected()
        try:
            if vm_type == "lxc":
                path = C.LXC_RESTORE.format(node=node)
                payload: dict[str, Any] = {"ostemplate": archive, "vmid": vmid, "restore": 1}
            else:
                path = C.QEMU_RESTORE.format(node=node)
                payload = {"archive": archive, "vmid": vmid}
            if storage:
                payload["storage"] = storage
            if start:
                payload["start"] = 1
            if unique:
                payload["unique"] = 1
            data = await self._client.post(path, data=payload, force=force)  # type: ignore[union-attr]
            return AdapterResult.ok(data)
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    async def get_guest_cloudinit(self, node: str, vmid: int) -> AdapterResult:
        """Get CloudInit config for a QEMU VM."""
        self._ensure_connected()
        try:
            data = await self._client.get(  # type: ignore[union-attr]
                C.QEMU_CLOUDINIT.format(node=node, vmid=vmid)
            )
            return AdapterResult.ok(data)
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    async def update_guest_cloudinit(
        self,
        node: str,
        vmid: int,
        config: dict,
        *,
        force: bool = False,
    ) -> AdapterResult:
        """Update CloudInit config for a QEMU VM."""
        self._ensure_connected()
        try:
            data = await self._client.put(  # type: ignore[union-attr]
                C.QEMU_CONFIG.format(node=node, vmid=vmid),
                data=config,
                force=force,
            )
            return AdapterResult.ok(data)
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    async def regenerate_cloudinit(
        self,
        node: str,
        vmid: int,
        *,
        force: bool = False,
    ) -> AdapterResult:
        """Regenerate CloudInit drive."""
        self._ensure_connected()
        try:
            data = await self._client.post(  # type: ignore[union-attr]
                C.QEMU_CLOUDINIT.format(node=node, vmid=vmid),
                force=force,
            )
            return AdapterResult.ok(data)
        except ProxmoxApiError as e:
            return AdapterResult.fail(type(e).__name__)

    @staticmethod
    def _parse_rrd(data: Any) -> AdapterResult:
        """Parse RRD data points."""
        if not isinstance(data, list):
            return AdapterResult.ok([])
        points = []
        for p in data:
            if not isinstance(p, dict):
                continue
            points.append(
                ProxmoxRRDPoint(
                    time=int(p.get("time", 0)),
                    cpu=_float_or_none(p.get("cpu")),
                    maxcpu=_float_or_none(p.get("maxcpu")),
                    mem=_float_or_none(p.get("mem")),
                    maxmem=_float_or_none(p.get("maxmem")),
                    netin=_float_or_none(p.get("netin")),
                    netout=_float_or_none(p.get("netout")),
                    diskread=_float_or_none(p.get("diskread")),
                    diskwrite=_float_or_none(p.get("diskwrite")),
                    iowait=_float_or_none(p.get("iowait")),
                )
            )
        return AdapterResult.ok(points)


def _float_or_none(val: Any) -> float | None:
    """Safely convert to float or return None."""
    if val is None:
        return None
    try:
        return float(val)
    except (ValueError, TypeError):
        return None

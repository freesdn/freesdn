# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN Hypervisor Module - Pydantic Schemas
=============================================

Request/response schemas for the hypervisor API.
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field, field_validator

# ═══════════════════════════════════════════════════════════════════════════
# CLUSTER
# ═══════════════════════════════════════════════════════════════════════════


class ClusterNodeSummary(BaseModel):
    node: str
    status: str
    ip: str | None = None
    level: str = ""


class ClusterStatusResponse(BaseModel):
    name: str
    quorate: bool
    node_count: int
    version: int
    nodes: list[ClusterNodeSummary] = []


class ClusterResourceItem(BaseModel):
    """Single item from /cluster/resources."""

    id: str = ""
    type: str = ""  # node, qemu, lxc, storage
    node: str = ""
    status: str = ""
    name: str = ""
    vmid: int | None = None
    maxcpu: float | None = None
    cpu: float | None = None
    maxmem: int | None = None
    mem: int | None = None
    maxdisk: int | None = None
    disk: int | None = None
    uptime: int | None = None
    template: bool = False


# ═══════════════════════════════════════════════════════════════════════════
# NODES
# ═══════════════════════════════════════════════════════════════════════════


class NodeResponse(BaseModel):
    id: UUID | None = None
    node: str
    status: str
    ip_address: str | None = None
    cpu_count: int = 0
    cpu_usage: float = 0.0
    cpu_percent: float = 0.0
    memory_total: int = 0
    memory_used: int = 0
    memory_percent: float = 0.0
    storage_total: int = 0
    storage_used: int = 0
    storage_percent: float = 0.0
    uptime: int = 0
    pve_version: str = ""
    kernel_version: str = ""
    cpu_model: str = ""
    subscription_level: str = ""


# ═══════════════════════════════════════════════════════════════════════════
# VMs & CONTAINERS
# ═══════════════════════════════════════════════════════════════════════════


class VMResponse(BaseModel):
    id: UUID | None = None
    vmid: int
    name: str
    node: str
    vm_type: str  # qemu | lxc
    status: str
    cpu_cores: int = 0
    cpu_usage: float = 0.0
    cpu_percent: float = 0.0
    memory_mb: int = 0
    memory_used_mb: int = 0
    memory_percent: float = 0.0
    disk_gb: float = 0.0
    disk_used_gb: float = 0.0
    disk_percent: float = 0.0
    ip_address: str | None = None
    net_in: int = 0
    net_out: int = 0
    uptime: int = 0
    tags: list[str] = []
    template: bool = False
    ha_state: str | None = None
    lock: str | None = None
    os_type: str | None = None


class VMActionRequest(BaseModel):
    action: str = Field(
        ...,
        pattern="^(start|stop|shutdown|reboot|suspend|resume)$",
        description="Power action to perform",
    )


class VMActionResponse(BaseModel):
    action: str
    vmid: int
    upid: str | None = None
    message: str = ""


# ═══════════════════════════════════════════════════════════════════════════
# SNAPSHOTS
# ═══════════════════════════════════════════════════════════════════════════


class SnapshotResponse(BaseModel):
    name: str
    description: str = ""
    created_at: datetime | None = None
    vmstate: bool = False
    parent: str | None = None


class SnapshotCreateRequest(BaseModel):
    snapname: str = Field(..., min_length=1, max_length=40, pattern="^[a-zA-Z0-9_-]+$")
    description: str = Field("", max_length=255)
    vmstate: bool = False


# ═══════════════════════════════════════════════════════════════════════════
# STORAGE
# ═══════════════════════════════════════════════════════════════════════════


class StorageResponse(BaseModel):
    storage: str
    node: str
    storage_type: str
    content: str
    total: int = 0
    used: int = 0
    available: int = 0
    used_percent: float = 0.0
    active: bool = True
    shared: bool = False
    enabled: bool = True


class StorageContentItem(BaseModel):
    volid: str = ""
    content: str = ""
    format: str = ""
    size: int = 0
    ctime: int = 0
    vmid: int | None = None
    notes: str | None = None


# ═══════════════════════════════════════════════════════════════════════════
# NETWORK
# ═══════════════════════════════════════════════════════════════════════════


class NetworkInterfaceResponse(BaseModel):
    iface: str
    node: str
    type: str
    active: bool = False
    address: str | None = None
    netmask: str | None = None
    gateway: str | None = None
    cidr: str | None = None
    bridge_ports: str | None = None
    bond_slaves: str | None = None
    method: str | None = None
    autostart: bool = False


# ═══════════════════════════════════════════════════════════════════════════
# TASKS
# ═══════════════════════════════════════════════════════════════════════════


class TaskResponse(BaseModel):
    upid: str
    node: str
    type: str
    status: str
    user: str = ""
    started_at: datetime | None = None
    ended_at: datetime | None = None
    is_running: bool = False


# ═══════════════════════════════════════════════════════════════════════════
# MONITORING
# ═══════════════════════════════════════════════════════════════════════════


class RRDPointResponse(BaseModel):
    time: int
    cpu: float | None = None
    maxcpu: float | None = None
    mem: float | None = None
    maxmem: float | None = None
    netin: float | None = None
    netout: float | None = None
    diskread: float | None = None
    diskwrite: float | None = None
    iowait: float | None = None


# ═══════════════════════════════════════════════════════════════════════════
# BACKUP
# ═══════════════════════════════════════════════════════════════════════════


class BackupJobResponse(BaseModel):
    id: str
    schedule: str
    storage: str
    vmid: str = ""
    mode: str = "snapshot"
    compress: str = "zstd"
    enabled: bool = True
    mailto: str = ""
    node: str | None = None


class BackupRunRequest(BaseModel):
    storage: str = Field(..., min_length=1, max_length=100)
    mode: str = Field("snapshot", pattern="^(snapshot|suspend|stop)$")
    compress: str = Field("zstd", pattern="^(zstd|lzo|gzip|none)$")


# ═══════════════════════════════════════════════════════════════════════════
# CLONE / MIGRATE / RESIZE
# ═══════════════════════════════════════════════════════════════════════════


class CloneRequest(BaseModel):
    newid: int = Field(..., ge=100, le=999999999, description="New VMID for the clone")
    name: str = Field("", max_length=128)
    target: str = Field("", max_length=63, description="Target node (empty = same node)")
    full: bool = True
    storage: str = Field("", max_length=63)
    description: str = Field("", max_length=255)


class MigrateRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=63, description="Target node name")
    online: bool = True


class ResizeDiskRequest(BaseModel):
    disk: str = Field(
        ...,
        min_length=1,
        max_length=20,
        pattern=r"^(scsi|virtio|ide|sata|efidisk|rootfs|mp)\d*$",
        description="Disk name (e.g., scsi0, virtio0)",
    )
    size: str = Field(
        ...,
        min_length=2,
        max_length=20,
        pattern=r"^\+?\d+[TGMK]?$",
        description="Size string (e.g., +10G, 50G)",
    )


class UpdateConfigRequest(BaseModel):
    """Partial VM/CT config update. All fields optional."""

    cores: int | None = Field(None, ge=1, le=512)
    memory: int | None = Field(None, ge=16, description="Memory in MB")
    balloon: int | None = Field(None, ge=0, description="Balloon memory in MB")
    name: str | None = Field(None, max_length=128)
    description: str | None = Field(None, max_length=8192)
    tags: str | None = Field(None, max_length=255)
    onboot: bool | None = None
    protection: bool | None = None


# ═══════════════════════════════════════════════════════════════════════════
# CONSOLE
# ═══════════════════════════════════════════════════════════════════════════


class ConsoleProxyResponse(BaseModel):
    ticket: str = ""
    port: int | str = ""
    user: str = ""
    cert: str = ""
    upid: str = ""


# ═══════════════════════════════════════════════════════════════════════════
# TASK DETAIL
# ═══════════════════════════════════════════════════════════════════════════


class TaskDetailResponse(BaseModel):
    upid: str
    node: str
    type: str
    status: str
    user: str = ""
    started_at: datetime | None = None
    is_running: bool = False
    exitstatus: str = ""


class TaskLogEntry(BaseModel):
    n: int
    t: str


# ═══════════════════════════════════════════════════════════════════════════
# FIREWALL
# ═══════════════════════════════════════════════════════════════════════════


class FirewallRuleResponse(BaseModel):
    pos: int
    type: str  # in, out, group
    action: str  # ACCEPT, DROP, REJECT
    enable: bool = True
    source: str | None = None
    dest: str | None = None
    sport: str | None = None
    dport: str | None = None
    proto: str | None = None
    macro: str | None = None
    iface: str | None = None
    log: str | None = None
    comment: str | None = None


class FirewallRuleCreateRequest(BaseModel):
    action: str = Field(..., pattern="^(ACCEPT|DROP|REJECT)$")
    type: str = Field("in", pattern="^(in|out|group)$")
    enable: bool = True
    source: str | None = Field(None, max_length=512)
    dest: str | None = Field(None, max_length=512)
    sport: str | None = Field(None, max_length=256)
    dport: str | None = Field(None, max_length=256)
    proto: str | None = Field(None, max_length=20)
    macro: str | None = Field(None, max_length=128)
    comment: str | None = Field(None, max_length=512)


# ═══════════════════════════════════════════════════════════════════════════
# NODE EXTRAS
# ═══════════════════════════════════════════════════════════════════════════


class DiskInfoResponse(BaseModel):
    devpath: str
    model: str = ""
    serial: str = ""
    size: int = 0
    vendor: str = ""
    wearout: float | None = None
    rpm: int | None = None
    disk_type: str = ""
    gpt: bool = False
    health: str = ""


class NodeServiceResponse(BaseModel):
    service: str
    name: str
    desc: str = ""
    state: str = ""


class SyslogEntry(BaseModel):
    n: int
    t: str


# ═══════════════════════════════════════════════════════════════════════════
# HA
# ═══════════════════════════════════════════════════════════════════════════


class HAResourceResponse(BaseModel):
    sid: str
    state: str
    group: str = ""
    max_relocate: int = 1
    max_restart: int = 1
    comment: str = ""
    request_state: str = ""
    status: str = ""
    node: str = ""
    crm_state: str = ""


class HAGroupResponse(BaseModel):
    group: str
    nodes: str = ""
    nofailback: bool = False
    restricted: bool = False
    comment: str = ""


# ═══════════════════════════════════════════════════════════════════════════
# RESOURCE POOLS
# ═══════════════════════════════════════════════════════════════════════════


class ResourcePoolResponse(BaseModel):
    poolid: str
    comment: str = ""
    members: list[dict] = []


# ═══════════════════════════════════════════════════════════════════════════
# CEPH
# ═══════════════════════════════════════════════════════════════════════════


class CephStatusResponse(BaseModel):
    health: str = ""
    num_osds: int = 0
    num_osds_up: int = 0
    num_osds_in: int = 0
    num_pgs: int = 0
    num_pools: int = 0
    total_bytes: int = 0
    used_bytes: int = 0
    avail_bytes: int = 0
    used_percent: float = 0.0


class CephOSD(BaseModel):
    id: int | None = None
    name: str | None = None
    host: str | None = None
    status: str | None = None  # up/down
    in_cluster: int | None = Field(None, alias="in")
    crush_weight: float | None = None
    device_class: str | None = None
    total_space: int | None = None
    used_space: int | None = None
    available_space: int | None = None
    apply_perc: float | None = None


class CephPool(BaseModel):
    pool: int | None = None
    pool_name: str | None = None
    size: int | None = None  # replication factor
    min_size: int | None = None
    pg_num: int | None = None
    crush_rule: int | None = None
    crush_rule_name: str | None = None
    bytes_used: int | None = None
    percent_used: float | None = None
    type: str | None = None  # replicated/erasure


class CephMonitor(BaseModel):
    name: str | None = None
    host: str | None = None
    addr: str | None = None
    rank: int | None = None
    quorum: bool | None = None


class CephMDS(BaseModel):
    name: str | None = None
    host: str | None = None
    addr: str | None = None
    state: str | None = None
    rank: int | None = None


class CephFS(BaseModel):
    name: str | None = None
    metadata_pool: str | None = None
    data_pool: str | None = None


class CephDetailResponse(BaseModel):
    status: dict | None = None
    osds: list[dict] | None = None
    pools: list[dict] | None = None
    monitors: list[dict] | None = None
    mds: list[dict] | None = None
    fs: list[dict] | None = None
    crush_rules: list[dict] | None = None


# ═══════════════════════════════════════════════════════════════════════════
# GUEST FIREWALL
# ═══════════════════════════════════════════════════════════════════════════


class GuestFirewallRule(BaseModel):
    pos: int | None = None
    type: str | None = None  # in/out/group
    action: str | None = None  # ACCEPT/DROP/REJECT
    source: str | None = None
    dest: str | None = None
    proto: str | None = None
    dport: str | None = None
    sport: str | None = None
    comment: str | None = None
    enable: int | None = None
    macro: str | None = None
    iface: str | None = None
    log: str | None = None


class CreateGuestFirewallRuleRequest(BaseModel):
    action: str = Field(..., pattern=r"^(ACCEPT|DROP|REJECT)$")
    type: str = Field("in", pattern=r"^(in|out|group)$")
    source: str | None = None
    dest: str | None = None
    proto: str | None = None
    dport: str | None = None
    sport: str | None = None
    comment: str | None = None
    enable: int = 1
    macro: str | None = None
    iface: str | None = None
    log: str | None = None


class GuestFirewallOptions(BaseModel):
    enable: bool | None = None
    dhcp: bool | None = None
    ipfilter: bool | None = None
    log_level_in: str | None = None
    log_level_out: str | None = None
    macfilter: bool | None = None
    ndp: bool | None = None
    policy_in: str | None = None
    policy_out: str | None = None
    radv: bool | None = None


class ClusterFirewallOptions(BaseModel):
    enable: int | None = None
    ebtables: int | None = None
    log_ratelimit: str | None = None
    policy_in: str | None = None
    policy_out: str | None = None


# ═══════════════════════════════════════════════════════════════════════════
# TASK STATISTICS
# ═══════════════════════════════════════════════════════════════════════════


class TaskStatistics(BaseModel):
    total: int = 0
    ok: int = 0
    warning: int = 0
    error: int = 0
    running: int = 0
    by_type: dict[str, int] = {}  # e.g. {"qmstart": 5, "vzdump": 3}


class FleetTaskStatistics(BaseModel):
    controllers: dict[str, TaskStatistics] = {}
    aggregate: TaskStatistics = TaskStatistics()


# ═══════════════════════════════════════════════════════════════════════════
# NODE SENSORS
# ═══════════════════════════════════════════════════════════════════════════


class NodeSensors(BaseModel):
    cpu_temp: float | None = None
    cpu_temps: list[dict] | None = None
    pveversion: str | None = None
    loadavg: list[str] | None = None
    cpuinfo: dict | None = None
    kversion: str | None = None


# ═══════════════════════════════════════════════════════════════════════════
# DASHBOARD SUMMARY
# ═══════════════════════════════════════════════════════════════════════════


class HypervisorDashboardResponse(BaseModel):
    """Aggregated cluster overview for the hypervisor dashboard."""

    cluster_name: str = ""
    quorate: bool = True
    total_nodes: int = 0
    online_nodes: int = 0
    total_vms: int = 0
    running_vms: int = 0
    total_containers: int = 0
    running_containers: int = 0
    total_cpu_cores: int = 0
    cpu_usage_percent: float = 0.0
    total_memory_bytes: int = 0
    used_memory_bytes: int = 0
    memory_usage_percent: float = 0.0
    total_storage_bytes: int = 0
    used_storage_bytes: int = 0
    storage_usage_percent: float = 0.0
    ha_active: bool = False


# ═══════════════════════════════════════════════════════════════════════════
# VM/CT CREATION
# ═══════════════════════════════════════════════════════════════════════════


class CreateVMRequest(BaseModel):
    """Request to create a new QEMU virtual machine."""

    vmid: int | None = Field(None, ge=100, le=999999999, description="VMID (auto if omitted)")
    name: str = Field("", max_length=128)
    node: str = Field(..., min_length=1, max_length=63, description="Target node")
    cores: int = Field(1, ge=1, le=512)
    sockets: int = Field(1, ge=1, le=4)
    memory: int = Field(2048, ge=16, description="Memory in MB")
    balloon: int = Field(0, ge=0, description="Balloon memory in MB (0 = disabled)")
    ostype: str = Field("l26", pattern="^(l26|l24|win11|win10|win8|win7|wxp|w2k|solaris|other)$")
    storage: str = Field("local-lvm", max_length=63)
    disk_size: str = Field("32G", max_length=20, description="e.g. 32G, 100G")
    iso: str = Field("", max_length=256, description="ISO volume (e.g. local:iso/ubuntu.iso)")
    net_bridge: str = Field("vmbr0", max_length=20)
    net_model: str = Field("virtio", pattern="^(virtio|e1000|rtl8139)$")
    cpu_type: str = Field("host", max_length=40)
    bios: str = Field("seabios", pattern="^(seabios|ovmf)$")
    machine: str = Field("", max_length=40)
    start_after_create: bool = False
    pool: str = Field("", max_length=63)
    description: str = Field("", max_length=8192)
    onboot: bool = False
    tags: str = Field("", max_length=255)


class CreateContainerRequest(BaseModel):
    """Request to create a new LXC container."""

    vmid: int | None = Field(None, ge=100, le=999999999, description="VMID (auto if omitted)")
    hostname: str = Field("", max_length=128)
    node: str = Field(..., min_length=1, max_length=63, description="Target node")
    ostemplate: str = Field(
        ...,
        min_length=1,
        max_length=256,
        description="CT template (e.g. local:vztmpl/debian-12.tar.zst)",
    )
    cores: int = Field(1, ge=1, le=128)
    memory: int = Field(512, ge=16, description="Memory in MB")
    swap: int = Field(512, ge=0, description="Swap in MB")
    storage: str = Field("local-lvm", max_length=63)
    rootfs_size: str = Field("8", max_length=20, description="Root disk size in GB")
    net_bridge: str = Field("vmbr0", max_length=20)
    net_ip: str = Field("dhcp", max_length=50, description="IP address or 'dhcp'")
    password: str = Field("", max_length=128, json_schema_extra={"writeOnly": True})
    ssh_public_keys: str = Field("", max_length=4096)
    start_after_create: bool = False
    pool: str = Field("", max_length=63)
    description: str = Field("", max_length=8192)
    unprivileged: bool = True
    onboot: bool = False
    tags: str = Field("", max_length=255)
    nameserver: str = Field("", max_length=256)
    searchdomain: str = Field("", max_length=256)


class CreateVMResponse(BaseModel):
    vmid: int
    upid: str = ""
    message: str = ""


class DeleteVMRequest(BaseModel):
    purge: bool = Field(False, description="Remove from backup jobs and HA too")


# ═══════════════════════════════════════════════════════════════════════════
# HA MANAGEMENT
# ═══════════════════════════════════════════════════════════════════════════


class HAResourceCreateRequest(BaseModel):
    sid: str = Field(..., min_length=1, max_length=128, description="VM/CT SID (e.g. vm:100)")
    group: str = Field("", max_length=63)
    max_relocate: int = Field(1, ge=0, le=10)
    max_restart: int = Field(1, ge=0, le=10)
    state: str = Field("started", pattern="^(started|stopped|disabled|ignored)$")
    comment: str = Field("", max_length=512)


class HAGroupCreateRequest(BaseModel):
    group: str = Field(..., min_length=1, max_length=63, pattern="^[a-zA-Z0-9_-]+$")
    nodes: str = Field(
        ...,
        min_length=1,
        max_length=512,
        description="Comma-separated node list with optional priority (e.g. node1:2,node2:1)",
    )
    nofailback: bool = False
    restricted: bool = False
    comment: str = Field("", max_length=512)


# ═══════════════════════════════════════════════════════════════════════════
# FLEET (MULTI-CLUSTER) DASHBOARD
# ═══════════════════════════════════════════════════════════════════════════


class FleetClusterSummary(BaseModel):
    """Summary of a single Proxmox cluster within the fleet."""

    controller_id: str
    controller_name: str
    cluster_name: str = ""
    quorate: bool = True
    total_nodes: int = 0
    online_nodes: int = 0
    total_vms: int = 0
    running_vms: int = 0
    total_containers: int = 0
    running_containers: int = 0
    total_cpu_cores: int = 0
    cpu_usage_percent: float = 0.0
    total_memory_bytes: int = 0
    used_memory_bytes: int = 0
    memory_usage_percent: float = 0.0
    total_storage_bytes: int = 0
    used_storage_bytes: int = 0
    storage_usage_percent: float = 0.0
    status: str = "online"  # online, offline, error
    error: str = ""


class FleetDashboardResponse(BaseModel):
    """Aggregated fleet dashboard across all Proxmox controllers."""

    total_clusters: int = 0
    online_clusters: int = 0
    total_nodes: int = 0
    online_nodes: int = 0
    total_vms: int = 0
    running_vms: int = 0
    total_containers: int = 0
    running_containers: int = 0
    total_cpu_cores: int = 0
    cpu_usage_percent: float = 0.0
    total_memory_bytes: int = 0
    used_memory_bytes: int = 0
    memory_usage_percent: float = 0.0
    total_storage_bytes: int = 0
    used_storage_bytes: int = 0
    storage_usage_percent: float = 0.0
    clusters: list[FleetClusterSummary] = []


class NextVMIDResponse(BaseModel):
    vmid: int


# ═══════════════════════════════════════════════════════════════════════════
# BULK OPERATIONS
# ═══════════════════════════════════════════════════════════════════════════


class BulkVMTarget(BaseModel):
    node: str = Field(..., min_length=1, max_length=63)
    vm_type: str = Field(..., pattern="^(qemu|lxc)$")
    vmid: int = Field(..., ge=100)


class BulkActionRequest(BaseModel):
    targets: list[BulkVMTarget] = Field(..., min_length=1, max_length=50)
    action: str = Field(..., pattern="^(start|stop|shutdown|reboot|delete)$")


class BulkMigrateRequest(BaseModel):
    targets: list[BulkVMTarget] = Field(..., min_length=1, max_length=50)
    target_node: str = Field(..., min_length=1, max_length=63)
    online: bool = True


class BulkActionResult(BaseModel):
    vmid: int
    node: str
    success: bool
    upid: str | None = None
    error: str | None = None


# ═══════════════════════════════════════════════════════════════════════════
# BACKUP JOB CRUD
# ═══════════════════════════════════════════════════════════════════════════


class BackupJobCreateRequest(BaseModel):
    storage: str = Field(..., min_length=1, max_length=100)
    schedule: str = Field(
        ..., min_length=1, max_length=128, description="Proxmox schedule format e.g. 'sat 02:00'"
    )
    vmid: str = Field("", max_length=255, description="Comma-separated VMIDs or empty for all")
    mode: str = Field("snapshot", pattern="^(snapshot|suspend|stop)$")
    compress: str = Field("zstd", pattern="^(zstd|lzo|gzip|none)$")
    node: str | None = Field(None, max_length=63)
    enabled: bool = True
    mailto: str = Field("", max_length=512)
    mailnotification: str = Field("always", pattern="^(always|failure)$")


class BackupJobUpdateRequest(BaseModel):
    storage: str | None = Field(None, max_length=100)
    schedule: str | None = Field(None, max_length=128)
    vmid: str | None = Field(None, max_length=255)
    mode: str | None = Field(None, pattern="^(snapshot|suspend|stop)$")
    compress: str | None = Field(None, pattern="^(zstd|lzo|gzip|none)$")
    node: str | None = Field(None, max_length=63)
    enabled: bool | None = None
    mailto: str | None = Field(None, max_length=512)


# ═══════════════════════════════════════════════════════════════════════════
# GUEST AGENT
# ═══════════════════════════════════════════════════════════════════════════


class GuestAgentNetworkInterface(BaseModel):
    name: str = ""
    mac_address: str = ""
    ip_addresses: list[str] = []


class GuestAgentInfoResponse(BaseModel):
    hostname: str = ""
    os_type: str = ""
    os_version: str = ""
    interfaces: list[GuestAgentNetworkInterface] = []


# ═══════════════════════════════════════════════════════════════════════════
# UPLOAD
# ═══════════════════════════════════════════════════════════════════════════


class UploadResponse(BaseModel):
    filename: str
    size: int = 0
    content_type: str = ""
    upid: str | None = None


# ═══════════════════════════════════════════════════════════════════════════
# APT / UPDATES
# ═══════════════════════════════════════════════════════════════════════════


class AptPackageUpdate(BaseModel):
    package: str
    title: str | None = None
    description: str | None = None
    arch: str | None = None
    old_version: str | None = None
    version: str | None = None
    origin: str | None = None
    priority: str | None = None


class AptRefreshResponse(BaseModel):
    upid: str


# ═══════════════════════════════════════════════════════════════════════════
# CERTIFICATES
# ═══════════════════════════════════════════════════════════════════════════


class NodeCertificate(BaseModel):
    filename: str | None = None
    fingerprint: str | None = None
    issuer: str | None = None
    subject: str | None = None
    notbefore: int | None = None
    notafter: int | None = None
    san: list[str] | None = None
    pem: str | None = None


class UploadCertificateRequest(BaseModel):
    certificates: str
    key: str
    force: bool = False
    restart: bool = False
    # replacing the node TLS cert can lock the operator out of
    # pveproxy. Require an explicit acknowledgement on the direct route (parity
    # with the destructive-op confirm class).
    confirmed: bool = False


# ═══════════════════════════════════════════════════════════════════════════
# SUBSCRIPTION
# ═══════════════════════════════════════════════════════════════════════════


class NodeSubscription(BaseModel):
    status: str | None = None
    level: str | None = None
    serverid: str | None = None
    checktime: str | None = None
    key: str | None = None
    productname: str | None = None
    regdate: str | None = None
    nextduedate: str | None = None
    url: str | None = None
    message: str | None = None


# ═══════════════════════════════════════════════════════════════════════════
# CROSS-CLUSTER MIGRATION
# ═══════════════════════════════════════════════════════════════════════════


class RemoteMigrateRequest(BaseModel):
    target_host: str
    target_port: int = 8006
    target_user: str = "root@pam"
    target_token: str  # API token secret
    target_fingerprint: str | None = None
    target_storage: str
    target_bridge: str | None = None
    online: bool = True
    # default to NOT deleting the source. A source-destroying remote
    # migration must be an explicit, confirmed choice — never the silent default —
    # so an operator who enables Proxmox writes can't lose the source VM/CT by
    # omitting a field. `confirmed` is required when delete_source is true.
    delete_source: bool = False
    confirmed: bool = False

    @field_validator("target_host")
    @classmethod
    def validate_target_host(cls, v: str) -> str:
        import ipaddress
        import socket

        v = v.strip()
        if not v:
            raise ValueError("target_host is required")
        if len(v) > 253:
            raise ValueError("target_host too long")

        def _check_addr(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> None:
            if (
                addr.is_private
                or addr.is_loopback
                or addr.is_link_local
                or addr.is_reserved
                or addr.is_multicast
            ):
                raise ValueError(
                    "target_host must not resolve to a private, loopback, link-local, reserved, or multicast address"
                )
            # Also block IPv4-mapped IPv6 addresses (::ffff:127.0.0.1)
            if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
                _check_addr(addr.ipv4_mapped)

        # Try to parse as IP address first
        try:
            addr = ipaddress.ip_address(v)
            _check_addr(addr)
            return v
        except ValueError as ip_err:
            if "must not" in str(ip_err):
                raise

        # Not a valid IP — treat as hostname: resolve and validate all addresses
        try:
            resolved = socket.getaddrinfo(v, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        except socket.gaierror:
            raise ValueError(f"target_host '{v}' could not be resolved")

        if not resolved:
            raise ValueError(f"target_host '{v}' resolved to no addresses")

        for _family, _, _, _, sockaddr in resolved:
            ip_str = sockaddr[0]
            try:
                addr = ipaddress.ip_address(ip_str)
                _check_addr(addr)
            except ValueError as e:
                if "must not" in str(e):
                    raise ValueError(
                        f"target_host '{v}' resolves to blocked address {ip_str}"
                    ) from e

        return v

    @field_validator("target_token")
    @classmethod
    def validate_target_token(cls, v: str) -> str:
        if len(v) > 512:
            raise ValueError("Token too long")
        return v


# ═══════════════════════════════════════════════════════════════════════════
# SDN
# ═══════════════════════════════════════════════════════════════════════════


class SdnZone(BaseModel):
    zone: str
    type: str
    nodes: str | None = None
    pending: dict | None = None
    state: str | None = None
    dns: str | None = None
    dnszone: str | None = None
    ipam: str | None = None
    mtu: int | None = None
    bridge: str | None = None
    tag: int | None = None


class SdnVnet(BaseModel):
    vnet: str
    zone: str
    alias: str | None = None
    tag: int | None = None
    vlanaware: bool | None = None
    type: str | None = None


class SdnController(BaseModel):
    controller: str
    type: str
    node: str | None = None
    state: str | None = None
    pending: dict | None = None


class CreateSdnZoneRequest(BaseModel):
    zone: str = Field(..., pattern=r"^[a-zA-Z0-9_-]+$", max_length=64)
    type: str = Field(
        ..., pattern=r"^[a-z]+$", max_length=32
    )  # e.g., "simple", "vlan", "qinq", "vxlan", "evpn"
    nodes: str | None = None
    bridge: str | None = None
    mtu: int | None = None
    dns: str | None = None
    dnszone: str | None = None
    tag: int | None = None


class CreateSdnVnetRequest(BaseModel):
    vnet: str = Field(..., pattern=r"^[a-zA-Z0-9_-]+$", max_length=64)
    zone: str = Field(..., pattern=r"^[a-zA-Z0-9_-]+$", max_length=64)
    alias: str | None = None
    tag: int | None = None
    vlanaware: bool = False


# ═══════════════════════════════════════════════════════════════════════════
# GUEST AGENT (EXEC / FILE)
# ═══════════════════════════════════════════════════════════════════════════


class AgentExecRequest(BaseModel):
    command: str = Field(..., max_length=4096)
    input_data: str | None = None


class AgentExecResult(BaseModel):
    pid: int | None = None
    exited: int | None = None
    exitcode: int | None = None
    out_data: str | None = None
    err_data: str | None = None
    signal: int | None = None
    out_truncated: bool | None = None
    err_truncated: bool | None = None


class AgentFileReadRequest(BaseModel):
    file: str = Field(..., max_length=4096, pattern=r"^/[^\x00]*$")


class AgentFileWriteRequest(BaseModel):
    file: str = Field(..., max_length=4096, pattern=r"^/[^\x00]*$")
    content: str = Field(..., max_length=1_048_576)


# ═══════════════════════════════════════════════════════════════════════════
# PENDING CONFIG
# ═══════════════════════════════════════════════════════════════════════════


class PendingConfigEntry(BaseModel):
    key: str
    value: str | None = None
    pending: str | None = None
    delete: int | None = None


# ═══════════════════════════════════════════════════════════════════════════
# CLUSTER EXTRAS
# ═══════════════════════════════════════════════════════════════════════════


class ClusterLogEntry(BaseModel):
    uid: str | None = None
    node: str | None = None
    tag: str | None = None
    pid: int | None = None
    user: str | None = None
    severity: str | None = None
    msg: str | None = None
    time: int | None = None
    id: str | None = None


class ClusterConfigNode(BaseModel):
    node: str
    nodeid: int | None = None
    ring0_addr: str | None = None
    name: str | None = None
    quorum_votes: int | None = None


class ReplicationJob(BaseModel):
    id: str
    type: str | None = None
    source: str | None = None
    target: str | None = None
    guest: int | None = None
    schedule: str | None = None
    rate: float | None = None
    comment: str | None = None
    disable: bool | None = None
    remove_job: str | None = None
    error: str | None = None
    duration: float | None = None
    next_sync: int | None = None
    last_sync: int | None = None
    fail_count: int | None = None


# ═══════════════════════════════════════════════════════════════════════════
# BACKUP AGE REPORT
# ═══════════════════════════════════════════════════════════════════════════


class BackupAgeReport(BaseModel):
    vmid: int
    name: str | None = None
    node: str
    last_backup_time: datetime | None = None
    age_hours: float | None = None
    is_stale: bool = False  # True if age > threshold


class BackupAgeResponse(BaseModel):
    threshold_hours: int
    total_vms: int
    backed_up: int
    stale: int
    never_backed_up: int
    vms: list[BackupAgeReport]


# ═══════════════════════════════════════════════════════════════════════════
# ALERT HYSTERESIS
# ═══════════════════════════════════════════════════════════════════════════


class AlertHysteresisConfig(BaseModel):
    """Prevents rapid alert flapping by requiring sustained state changes."""

    fire_after_consecutive: int = Field(
        default=3, ge=1, le=100, description="Fire after N consecutive threshold breaches"
    )
    resolve_after_consecutive: int = Field(
        default=2, ge=1, le=100, description="Resolve after N consecutive normal readings"
    )


class HysteresisState(BaseModel):
    breach_count: int = 0
    normal_count: int = 0
    is_fired: bool = False
    last_value: float | None = None
    last_checked: datetime | None = None


class HysteresisEvaluateRequest(BaseModel):
    """Request to evaluate hysteresis for an alert."""

    current_value: float
    threshold: float
    operator: str = Field(..., pattern="^(gt|gte|lt|lte|eq)$")
    state: HysteresisState = Field(default_factory=HysteresisState)
    config: AlertHysteresisConfig = Field(default_factory=AlertHysteresisConfig)


class HysteresisEvaluateResponse(BaseModel):
    """Result of hysteresis evaluation."""

    state: HysteresisState
    should_fire: bool = False
    should_resolve: bool = False


# ═══════════════════════════════════════════════════════════════════════════
# PBS / BACKUP RESTORE
# ═══════════════════════════════════════════════════════════════════════════


class RestoreBackupRequest(BaseModel):
    archive: str = Field(
        ...,
        max_length=512,
        description="Backup archive volume ID (e.g. local:backup/vzdump-qemu-100-2024_01_01.vma.zst)",
    )
    vmid: int = Field(..., ge=100, le=999999999)
    node: str = Field(..., pattern=r"^[a-zA-Z0-9._-]+$", max_length=64)
    vm_type: str = Field(..., pattern=r"^(qemu|lxc)$")
    storage: str | None = Field(None, pattern=r"^[a-zA-Z0-9._-]+$", max_length=64)
    start_after_restore: bool = False
    unique_mac: bool = True


class PruneBackupsRequest(BaseModel):
    node: str | None = Field(
        None,
        pattern=r"^[a-zA-Z0-9._-]+$",
        max_length=64,
        description="Ignored — node comes from path param",
    )
    storage: str | None = Field(
        None,
        pattern=r"^[a-zA-Z0-9._-]+$",
        max_length=64,
        description="Ignored — storage comes from path param",
    )
    keep_last: int | None = Field(None, ge=0, le=365)
    keep_hourly: int | None = Field(None, ge=0, le=365)
    keep_daily: int | None = Field(None, ge=0, le=365)
    keep_weekly: int | None = Field(None, ge=0, le=365)
    keep_monthly: int | None = Field(None, ge=0, le=365)
    keep_yearly: int | None = Field(None, ge=0, le=365)
    vmid: int | None = Field(None, ge=100)


# ═══════════════════════════════════════════════════════════════════════════
# CLOUDINIT
# ═══════════════════════════════════════════════════════════════════════════


class CloudInitConfig(BaseModel):
    ciuser: str | None = Field(None, max_length=64, description="Default user name")
    cipassword: str | None = Field(
        None,
        max_length=128,
        description="Password (write-only)",
        json_schema_extra={"writeOnly": True},
    )
    sshkeys: str | None = Field(
        None, max_length=8192, description="SSH public keys (URL-encoded, one per line)"
    )
    ipconfig0: str | None = Field(
        None,
        max_length=256,
        description="IP config for first NIC (e.g. ip=dhcp or ip=10.0.0.1/24,gw=10.0.0.1)",
    )
    ipconfig1: str | None = Field(None, max_length=256)
    ipconfig2: str | None = Field(None, max_length=256)
    nameserver: str | None = Field(None, max_length=256)
    searchdomain: str | None = Field(None, max_length=256)
    citype: str | None = Field(None, pattern=r"^(configdrive2|nocloud|opennebula)$")
    cicustom: str | None = Field(
        None, max_length=512, description="Custom cloud-init config (volume reference)"
    )


# ═══════════════════════════════════════════════════════════════════════════
# PRE-FLIGHT SAFETY (dry-run impact preview)
# ═══════════════════════════════════════════════════════════════════════════


class PreflightRequest(BaseModel):
    """Describe a prospective staged write to assess BEFORE staging it.

    No mutation happens — the assessor classifies the operation's
    destructiveness and runs READ-ONLY device checks to surface impact.
    """

    feature: str = Field(..., max_length=128, description="e.g. proxmox.vm.destroy")
    operation: str = Field("create", max_length=32, description="create | delete | update")
    payload: dict = Field(
        default_factory=dict,
        description="The change payload (node, vmid, snapname, volid, …) the write would carry",
    )


class PreflightResponse(BaseModel):
    feature: str
    operation: str
    risk: str = Field(..., description="safe | destructive | catastrophic")
    requires_confirmation: bool = Field(
        ..., description="True ⇒ the staged write must carry confirmed=true to apply"
    )
    warnings: list[str] = []
    impact: dict = {}

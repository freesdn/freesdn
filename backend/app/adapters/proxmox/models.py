# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Proxmox Normalized Models
========================================

Dataclasses for normalizing Proxmox API responses into
a consistent internal representation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime


@dataclass
class ProxmoxClusterStatus:
    """Cluster-level status summary."""

    name: str
    quorate: bool
    node_count: int
    version: int
    nodes: list[ProxmoxNodeInfo] = field(default_factory=list)


@dataclass
class ProxmoxNodeInfo:
    """Single PVE node information."""

    node: str
    status: str  # online | offline
    ip: str | None = None
    cpu: float = 0.0  # 0-1 ratio
    maxcpu: int = 0
    mem: int = 0  # bytes used
    maxmem: int = 0  # bytes total
    disk: int = 0  # bytes used
    maxdisk: int = 0  # bytes total
    uptime: int = 0  # seconds
    pve_version: str = ""
    kernel_version: str = ""
    cpu_model: str = ""
    level: str = ""  # subscription level

    @property
    def cpu_percent(self) -> float:
        return round(self.cpu * 100, 1)

    @property
    def mem_percent(self) -> float:
        if self.maxmem == 0:
            return 0.0
        return round(self.mem / self.maxmem * 100, 1)

    @property
    def disk_percent(self) -> float:
        if self.maxdisk == 0:
            return 0.0
        return round(self.disk / self.maxdisk * 100, 1)


@dataclass
class ProxmoxVM:
    """Virtual machine (QEMU) or container (LXC) info."""

    vmid: int
    name: str
    node: str
    vm_type: str  # "qemu" | "lxc"
    status: str  # running | stopped | paused
    cpu: float = 0.0  # 0-1 ratio
    cpus: int = 0
    mem: int = 0
    maxmem: int = 0
    disk: int = 0
    maxdisk: int = 0
    netin: int = 0
    netout: int = 0
    uptime: int = 0
    pid: int | None = None
    tags: str = ""
    template: bool = False
    lock: str | None = None
    ha_state: str | None = None

    @property
    def cpu_percent(self) -> float:
        return round(self.cpu * 100, 1)

    @property
    def mem_percent(self) -> float:
        if self.maxmem == 0:
            return 0.0
        return round(self.mem / self.maxmem * 100, 1)

    @property
    def disk_percent(self) -> float:
        if self.maxdisk == 0:
            return 0.0
        return round(self.disk / self.maxdisk * 100, 1)

    @property
    def tag_list(self) -> list[str]:
        if not self.tags:
            return []
        return [t.strip() for t in self.tags.split(";") if t.strip()]


@dataclass
class ProxmoxStorage:
    """Storage pool info."""

    storage: str
    node: str
    storage_type: str  # dir, lvm, zfspool, nfs, cifs, etc.
    content: str  # images, rootdir, iso, backup, etc.
    total: int = 0  # bytes
    used: int = 0  # bytes
    avail: int = 0  # bytes
    active: bool = True
    shared: bool = False
    enabled: bool = True

    @property
    def used_percent(self) -> float:
        if self.total == 0:
            return 0.0
        return round(self.used / self.total * 100, 1)


@dataclass
class ProxmoxTask:
    """Proxmox task entry."""

    upid: str
    node: str
    task_type: str
    status: str  # "" (running), "OK", or error string
    user: str = ""
    starttime: int = 0
    endtime: int = 0
    pid: int = 0
    pstart: int = 0
    id: str = ""

    @property
    def is_running(self) -> bool:
        return self.status == ""

    @property
    def is_ok(self) -> bool:
        return self.status == "OK"

    @property
    def started_at(self) -> datetime:
        return datetime.fromtimestamp(self.starttime, tz=UTC)


@dataclass
class ProxmoxNetworkInterface:
    """Node network interface."""

    iface: str
    node: str
    iface_type: str  # bridge, bond, eth, vlan, OVSBridge, etc.
    active: bool = False
    address: str | None = None
    netmask: str | None = None
    gateway: str | None = None
    cidr: str | None = None
    bridge_ports: str | None = None
    bond_slaves: str | None = None
    method: str | None = None  # static, dhcp, manual
    autostart: bool = False
    comments: str | None = None


@dataclass
class ProxmoxSnapshot:
    """VM/CT snapshot."""

    name: str
    description: str = ""
    snaptime: int = 0
    vmstate: bool = False
    parent: str | None = None

    @property
    def created_at(self) -> datetime | None:
        if self.snaptime == 0:
            return None
        return datetime.fromtimestamp(self.snaptime, tz=UTC)


@dataclass
class ProxmoxRRDPoint:
    """Single RRD data point."""

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


@dataclass
class ProxmoxBackupJob:
    """Scheduled backup job."""

    id: str
    schedule: str  # cron-like
    storage: str
    vmid: str = ""  # comma-separated VMIDs or empty for all
    mode: str = "snapshot"  # snapshot, suspend, stop
    compress: str = "zstd"  # zstd, lzo, gzip, none
    enabled: bool = True
    mailnotification: str = "always"
    mailto: str = ""
    node: str | None = None
    dow: str | None = None  # day of week


@dataclass
class ProxmoxFirewallRule:
    """Firewall rule (cluster, node, or VM level)."""

    pos: int  # position/priority
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
    log: str | None = None  # nolog, alert, crit, err, warning, notice, info, debug
    comment: str | None = None


@dataclass
class ProxmoxDiskInfo:
    """Physical disk information from a node."""

    devpath: str
    model: str = ""
    serial: str = ""
    size: int = 0  # bytes
    vendor: str = ""
    wearout: float | None = None  # SSD wear percentage
    rpm: int | None = None  # 0 = SSD
    disk_type: str = ""  # ssd, hdd
    gpt: bool = False
    health: str = ""  # PASSED, FAILED, UNKNOWN


@dataclass
class ProxmoxTaskLog:
    """Task log entry."""

    n: int  # line number
    t: str  # text content


@dataclass
class ProxmoxTaskDetail:
    """Detailed task status."""

    upid: str
    node: str
    task_type: str
    status: str  # running, stopped:OK, stopped:error
    user: str = ""
    starttime: int = 0
    pid: int = 0
    exitstatus: str = ""  # OK or error message

    @property
    def is_running(self) -> bool:
        return self.status == "running"

    @property
    def is_ok(self) -> bool:
        return self.exitstatus == "OK"


@dataclass
class ProxmoxHAResource:
    """HA-managed resource."""

    sid: str  # e.g. "vm:100"
    state: str  # started, stopped, disabled, error
    group: str = ""
    max_relocate: int = 1
    max_restart: int = 1
    comment: str = ""
    request_state: str = ""  # started, stopped, disabled
    status: str = ""  # detailed status text
    node: str = ""  # current node
    crm_state: str = ""  # started, request_stop, etc.

    @property
    def resource_type(self) -> str:
        return self.sid.split(":")[0] if ":" in self.sid else ""

    @property
    def vmid(self) -> int:
        try:
            return int(self.sid.split(":")[1]) if ":" in self.sid else 0
        except (ValueError, IndexError):
            return 0


@dataclass
class ProxmoxHAGroup:
    """HA group definition."""

    group: str
    nodes: str  # comma-separated node names with optional priority
    nofailback: bool = False
    restricted: bool = False
    comment: str = ""


@dataclass
class ProxmoxResourcePool:
    """Resource pool."""

    poolid: str
    comment: str = ""
    members: list[dict] = field(default_factory=list)


@dataclass
class ProxmoxCephStatus:
    """Ceph cluster status summary."""

    health: str = ""  # HEALTH_OK, HEALTH_WARN, HEALTH_ERR
    num_osds: int = 0
    num_osds_up: int = 0
    num_osds_in: int = 0
    num_pgs: int = 0
    num_pools: int = 0
    total_bytes: int = 0
    used_bytes: int = 0
    avail_bytes: int = 0
    raw: dict = field(default_factory=dict)

    @property
    def used_percent(self) -> float:
        if self.total_bytes == 0:
            return 0.0
        return round(self.used_bytes / self.total_bytes * 100, 1)


@dataclass
class ProxmoxNodeService:
    """Node service info."""

    service: str
    name: str
    desc: str = ""
    state: str = ""  # running, stopped
    unit_state: str = ""

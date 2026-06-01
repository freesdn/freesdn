# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Proxmox API Constants
===================================

API endpoint paths, default configuration, and status mappings
for Proxmox VE REST API (v2).
"""

# Default connection settings
DEFAULT_PORT = 8006
DEFAULT_TIMEOUT = 30.0
DEFAULT_VERIFY_SSL = False
API_BASE = "/api2/json"

# Rate limiting
RATE_LIMIT_RPM = 120
RATE_LIMIT_CONCURRENT = 10

# ── Cluster endpoints ──────────────────────────────────────────────────────
CLUSTER_STATUS = "/cluster/status"
CLUSTER_RESOURCES = "/cluster/resources"
CLUSTER_HA_STATUS = "/cluster/ha/status/current"
CLUSTER_HA_RESOURCES = "/cluster/ha/resources"
CLUSTER_HA_GROUPS = "/cluster/ha/groups"
CLUSTER_BACKUP = "/cluster/backup"
CLUSTER_BACKUP_JOB = "/cluster/backup/{jobid}"
CLUSTER_FIREWALL_RULES = "/cluster/firewall/rules"
CLUSTER_FIREWALL_ALIASES = "/cluster/firewall/aliases"
CLUSTER_FIREWALL_GROUPS = "/cluster/firewall/groups"
CLUSTER_FIREWALL_OPTIONS = "/cluster/firewall/options"

# ── Resource pools ─────────────────────────────────────────────────────────
POOLS = "/pools"
POOL_DETAIL = "/pools/{poolid}"

# ── Node endpoints ─────────────────────────────────────────────────────────
NODES = "/nodes"
NODE_STATUS = "/nodes/{node}/status"
NODE_NETWORK = "/nodes/{node}/network"
NODE_STORAGE = "/nodes/{node}/storage"
NODE_STORAGE_CONTENT = "/nodes/{node}/storage/{storage}/content"
NODE_STORAGE_VOLUME = "/nodes/{node}/storage/{storage}/content/{volume}"
NODE_STORAGE_UPLOAD = "/nodes/{node}/storage/{storage}/upload"
NODE_TASKS = "/nodes/{node}/tasks"
NODE_TASK_STATUS = "/nodes/{node}/tasks/{upid}/status"
NODE_TASK_LOG = "/nodes/{node}/tasks/{upid}/log"
NODE_TASK_STOP = "/nodes/{node}/tasks/{upid}"
NODE_RRDDATA = "/nodes/{node}/rrddata"
NODE_DISKS = "/nodes/{node}/disks/list"
NODE_DISKS_SMART = "/nodes/{node}/disks/smart"
NODE_SYSLOG = "/nodes/{node}/syslog"
NODE_SERVICES = "/nodes/{node}/services"
NODE_SERVICE_ACTION = "/nodes/{node}/services/{service}/{action}"
NODE_DNS = "/nodes/{node}/dns"
NODE_TIME = "/nodes/{node}/time"
NODE_APT_UPDATE = "/nodes/{node}/apt/update"
NODE_APT_VERSIONS = "/nodes/{node}/apt/versions"
NODE_APT_CHANGELOG = "/nodes/{node}/apt/changelog"
NODE_APT_REPOSITORIES = "/nodes/{node}/apt/repositories"

# ── VM (QEMU) endpoints ───────────────────────────────────────────────────
NODE_QEMU = "/nodes/{node}/qemu"
QEMU_STATUS = "/nodes/{node}/qemu/{vmid}/status/current"
QEMU_CONFIG = "/nodes/{node}/qemu/{vmid}/config"
QEMU_PENDING = "/nodes/{node}/qemu/{vmid}/pending"
QEMU_START = "/nodes/{node}/qemu/{vmid}/status/start"
QEMU_STOP = "/nodes/{node}/qemu/{vmid}/status/stop"
QEMU_SHUTDOWN = "/nodes/{node}/qemu/{vmid}/status/shutdown"
QEMU_REBOOT = "/nodes/{node}/qemu/{vmid}/status/reboot"
QEMU_SUSPEND = "/nodes/{node}/qemu/{vmid}/status/suspend"
QEMU_RESUME = "/nodes/{node}/qemu/{vmid}/status/resume"
QEMU_CLONE = "/nodes/{node}/qemu/{vmid}/clone"
QEMU_MIGRATE = "/nodes/{node}/qemu/{vmid}/migrate"
QEMU_RESIZE = "/nodes/{node}/qemu/{vmid}/resize"
QEMU_TEMPLATE = "/nodes/{node}/qemu/{vmid}/template"
QEMU_MOVE_DISK = "/nodes/{node}/qemu/{vmid}/move_disk"
QEMU_SNAPSHOT_LIST = "/nodes/{node}/qemu/{vmid}/snapshot"
QEMU_SNAPSHOT_CREATE = "/nodes/{node}/qemu/{vmid}/snapshot"
QEMU_SNAPSHOT_ROLLBACK = "/nodes/{node}/qemu/{vmid}/snapshot/{snapname}/rollback"
QEMU_SNAPSHOT_DELETE = "/nodes/{node}/qemu/{vmid}/snapshot/{snapname}"
QEMU_RRDDATA = "/nodes/{node}/qemu/{vmid}/rrddata"
QEMU_VNCPROXY = "/nodes/{node}/qemu/{vmid}/vncproxy"
QEMU_TERMPROXY = "/nodes/{node}/qemu/{vmid}/termproxy"
QEMU_VNCWEBSOCKET = "/nodes/{node}/qemu/{vmid}/vncwebsocket"
QEMU_SPICEPROXY = "/nodes/{node}/qemu/{vmid}/spiceproxy"
QEMU_AGENT = "/nodes/{node}/qemu/{vmid}/agent"
QEMU_AGENT_EXEC = "/nodes/{node}/qemu/{vmid}/agent/exec"
QEMU_AGENT_EXEC_STATUS = "/nodes/{node}/qemu/{vmid}/agent/exec-status"
QEMU_AGENT_FILE_READ = "/nodes/{node}/qemu/{vmid}/agent/file-read"
QEMU_AGENT_FILE_WRITE = "/nodes/{node}/qemu/{vmid}/agent/file-write"
QEMU_AGENT_NETWORK = "/nodes/{node}/qemu/{vmid}/agent/network-get-interfaces"
QEMU_FIREWALL_RULES = "/nodes/{node}/qemu/{vmid}/firewall/rules"
QEMU_FIREWALL_RULE = "/nodes/{node}/qemu/{vmid}/firewall/rules/{pos}"
QEMU_FIREWALL_OPTIONS = "/nodes/{node}/qemu/{vmid}/firewall/options"
QEMU_CLOUDINIT = "/nodes/{node}/qemu/{vmid}/cloudinit"

# ── Container (LXC) endpoints ─────────────────────────────────────────────
NODE_LXC = "/nodes/{node}/lxc"
LXC_STATUS = "/nodes/{node}/lxc/{vmid}/status/current"
LXC_CONFIG = "/nodes/{node}/lxc/{vmid}/config"
LXC_START = "/nodes/{node}/lxc/{vmid}/status/start"
LXC_STOP = "/nodes/{node}/lxc/{vmid}/status/stop"
LXC_SHUTDOWN = "/nodes/{node}/lxc/{vmid}/status/shutdown"
LXC_REBOOT = "/nodes/{node}/lxc/{vmid}/status/reboot"
LXC_CLONE = "/nodes/{node}/lxc/{vmid}/clone"
LXC_MIGRATE = "/nodes/{node}/lxc/{vmid}/migrate"
LXC_RESIZE = "/nodes/{node}/lxc/{vmid}/resize"
LXC_TEMPLATE = "/nodes/{node}/lxc/{vmid}/template"
LXC_SNAPSHOT_LIST = "/nodes/{node}/lxc/{vmid}/snapshot"
LXC_SNAPSHOT_CREATE = "/nodes/{node}/lxc/{vmid}/snapshot"
LXC_SNAPSHOT_ROLLBACK = "/nodes/{node}/lxc/{vmid}/snapshot/{snapname}/rollback"
LXC_SNAPSHOT_DELETE = "/nodes/{node}/lxc/{vmid}/snapshot/{snapname}"
LXC_RRDDATA = "/nodes/{node}/lxc/{vmid}/rrddata"
LXC_VNCPROXY = "/nodes/{node}/lxc/{vmid}/vncproxy"
LXC_TERMPROXY = "/nodes/{node}/lxc/{vmid}/termproxy"
LXC_FIREWALL_RULES = "/nodes/{node}/lxc/{vmid}/firewall/rules"
LXC_FIREWALL_RULE = "/nodes/{node}/lxc/{vmid}/firewall/rules/{pos}"
LXC_FIREWALL_OPTIONS = "/nodes/{node}/lxc/{vmid}/firewall/options"
LXC_PENDING = "/nodes/{node}/lxc/{vmid}/pending"

# ── Cross-cluster migration ──────────────────────────────────────────────
QEMU_REMOTE_MIGRATE = "/nodes/{node}/qemu/{vmid}/remote_migrate"
LXC_REMOTE_MIGRATE = "/nodes/{node}/lxc/{vmid}/remote_migrate"

# ── Node power ─────────────────────────────────────────────────────────────
NODE_COMMAND = "/nodes/{node}/status"

# ── Backup ─────────────────────────────────────────────────────────────────
NODE_VZDUMP = "/nodes/{node}/vzdump"
NODE_VZDUMP_EXTRACTCONFIG = "/nodes/{node}/vzdump/extractconfig"

# ── Firewall ───────────────────────────────────────────────────────────────
NODE_FIREWALL_RULES = "/nodes/{node}/firewall/rules"
NODE_FIREWALL_RULE = "/nodes/{node}/firewall/rules/{pos}"
NODE_FIREWALL_OPTIONS = "/nodes/{node}/firewall/options"
NODE_FIREWALL_LOG = "/nodes/{node}/firewall/log"

# ── Certificates ───────────────────────────────────────────────────────────
NODE_CERTIFICATES = "/nodes/{node}/certificates/info"
NODE_CERTIFICATES_ACME = "/nodes/{node}/certificates/acme/certificate"
NODE_CERTIFICATES_CUSTOM = "/nodes/{node}/certificates/custom"

# ── Subscription ───────────────────────────────────────────────────────────
NODE_SUBSCRIPTION = "/nodes/{node}/subscription"

# ── SDN ────────────────────────────────────────────────────────────────────
SDN_ZONES = "/cluster/sdn/zones"
SDN_VNETS = "/cluster/sdn/vnets"
SDN_CONTROLLERS = "/cluster/sdn/controllers"
SDN_SUBNETS = "/cluster/sdn/vnets/{vnet}/subnets"
SDN_APPLY = "/cluster/sdn"

# ── Cluster extended ──────────────────────────────────────────────────────
CLUSTER_OPTIONS = "/cluster/options"
CLUSTER_LOG = "/cluster/log"
CLUSTER_CONFIG_NODES = "/cluster/config/nodes"
CLUSTER_METRICS_SERVER = "/cluster/metrics/server"

# ── Replication ────────────────────────────────────────────────────────────
CLUSTER_REPLICATION = "/cluster/replication"
CLUSTER_REPLICATION_LOG = "/cluster/replication/{id}/log"

# ── PBS (Proxmox Backup Server) ───────────────────────────────────────────
# Note: PBS uses the same /api2/json base as PVE. The client already sets
# API_BASE as the httpx base_url, so these paths must NOT include /api2/json.
PBS_DATASTORES = "/admin/datastore"
PBS_DATASTORE_SNAPSHOTS = "/admin/datastore/{store}/snapshots"
PBS_DATASTORE_NAMESPACES = "/admin/datastore/{store}/namespace"
PBS_NODE_STATUS = "/nodes/{node}/status"
PBS_DATASTORE_STATUS = "/status/datastore-usage"

# ── Restore / Prune / File-restore ───────────────────────────────────────
QEMU_RESTORE = "/nodes/{node}/qemu"  # POST with archive param = restore
LXC_RESTORE = "/nodes/{node}/lxc"  # POST with ostemplate=backup:// = restore
STORAGE_PRUNE_BACKUPS = "/nodes/{node}/storage/{storage}/prunebackups"
STORAGE_FILE_RESTORE = "/nodes/{node}/storage/{storage}/file-restore/list"

# ── Ceph ───────────────────────────────────────────────────────────────────
NODE_CEPH_STATUS = "/nodes/{node}/ceph/status"
NODE_CEPH_OSD = "/nodes/{node}/ceph/osd"
NODE_CEPH_POOLS = "/nodes/{node}/ceph/pools"
NODE_CEPH_MON = "/nodes/{node}/ceph/mon"
NODE_CEPH_MDS = "/nodes/{node}/ceph/mds"
NODE_CEPH_FS = "/nodes/{node}/ceph/fs"
NODE_CEPH_CRUSH_RULES = "/nodes/{node}/ceph/rules"

# ── Status mappings ────────────────────────────────────────────────────────
VM_STATUS_MAP = {
    "running": "running",
    "stopped": "stopped",
    "paused": "paused",
    "suspended": "suspended",
    "prelaunch": "starting",
}

NODE_STATUS_MAP = {
    "online": "online",
    "offline": "offline",
    "unknown": "unknown",
}

# ── Task types ─────────────────────────────────────────────────────────────
TASK_TYPE_MAP = {
    "qmstart": "VM Start",
    "qmstop": "VM Stop",
    "qmshutdown": "VM Shutdown",
    "qmreboot": "VM Reboot",
    "qmsuspend": "VM Suspend",
    "qmresume": "VM Resume",
    "qmclone": "VM Clone",
    "qmmigrate": "VM Migrate",
    "qmresize": "VM Resize Disk",
    "qmtemplate": "VM Convert to Template",
    "qmsnapshot": "VM Snapshot",
    "qmrollback": "VM Rollback",
    "qmdelsnapshot": "VM Delete Snapshot",
    "vzcreate": "CT Create",
    "vzstart": "CT Start",
    "vzstop": "CT Stop",
    "vzshutdown": "CT Shutdown",
    "vzreboot": "CT Reboot",
    "vzclone": "CT Clone",
    "vzmigrate": "CT Migrate",
    "vzresize": "CT Resize",
    "vztemplate": "CT Convert to Template",
    "vzsnapshot": "CT Snapshot",
    "vzrollback": "CT Rollback",
    "vzdelsnapshot": "CT Delete Snapshot",
    "vzdump": "Backup",
    "vzrestore": "Restore",
    "imgcopy": "Image Copy",
    "download": "Download",
    "aptupdate": "APT Update",
    "move_disk": "Move Disk",
    "srvstart": "Service Start",
    "srvstop": "Service Stop",
    "srvrestart": "Service Restart",
    "startall": "Start All",
    "stopall": "Stop All",
}

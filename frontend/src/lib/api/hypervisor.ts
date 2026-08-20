// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN Hypervisor API Client
 * ==============================
 *
 * API functions for Proxmox VE hypervisor management.
 */

import { api } from './client';
import type { PendingChangeResponse } from './gatewayCommon';
import type {
  HypervisorBackupJob,
  HypervisorCephStatus,
  HypervisorClusterResource,
  HypervisorClusterStatus,
  HypervisorConsoleProxy,
  HypervisorDashboard,
  HypervisorDiskInfo,
  HypervisorFirewallRule,
  HypervisorHAGroup,
  HypervisorHAResource,
  HypervisorNetworkInterface,
  HypervisorNode,
  HypervisorNodeService,
  HypervisorRRDPoint,
  HypervisorResourcePool,
  HypervisorSnapshot,
  HypervisorStorage,
  HypervisorStorageContent,
  HypervisorSyslogEntry,
  HypervisorTask,
  HypervisorTaskDetail,
  HypervisorTaskLogEntry,
  HypervisorVM,
  CreateVMRequest,
  CreateContainerRequest,
  CreateVMResponse,
  FleetDashboard,
  NextVMIDResponse,
  BulkActionRequest,
  BulkActionResult,
  BulkMigrateRequest,
  GuestAgentInfo,
  BackupJobCreateRequest,
  BackupJobUpdateRequest,
} from './types';

// ── Request Types ─────────────────────────────────────────────────────

export interface RemoteMigrateRequest {
  target_host: string;
  target_port?: number;
  target_user?: string;
  target_token: string;
  target_fingerprint?: string;
  target_storage: string;
  target_bridge?: string;
  online?: boolean;
  delete_source?: boolean;
}

export interface CreateSdnZoneRequest {
  zone: string;
  type: string;
  nodes?: string;
  bridge?: string;
  mtu?: number;
  dns?: string;
  dnszone?: string;
  tag?: number;
}

export interface CreateSdnVnetRequest {
  vnet: string;
  zone: string;
  alias?: string;
  tag?: number;
  vlanaware?: boolean;
}

/** Validate vmType to prevent path injection. */
function safeVmType(vmType: string): 'qemu' | 'lxc' {
  if (vmType === 'qemu' || vmType === 'lxc') return vmType;
  throw new Error(`Invalid vmType: ${vmType}`);
}

/** Encode a path segment (node name, storage, snapshot name, etc.). */
const enc = encodeURIComponent;

export const hypervisorApi = {
  // ── Dashboard ──────────────────────────────────────────────────────
  getDashboard: (controllerId: string) =>
    api.get<HypervisorDashboard>(`/hypervisor/controllers/${enc(controllerId)}/dashboard`),

  // ── Fleet (Multi-Cluster) ─────────────────────────────────────────
  getFleetDashboard: (siteId?: string) =>
    api.get<FleetDashboard>('/hypervisor/fleet/dashboard', {
      params: siteId ? { site_id: siteId } : undefined,
    }),

  // ── Cluster ────────────────────────────────────────────────────────
  getClusterStatus: (controllerId: string) =>
    api.get<HypervisorClusterStatus>(`/hypervisor/controllers/${enc(controllerId)}/cluster/status`),

  getClusterResources: (controllerId: string, type?: string) =>
    api.get<HypervisorClusterResource[]>(`/hypervisor/controllers/${enc(controllerId)}/cluster/resources`, {
      params: type ? { type } : undefined,
    }),

  // ── Nodes ──────────────────────────────────────────────────────────
  getNodes: (controllerId: string) =>
    api.get<HypervisorNode[]>(`/hypervisor/controllers/${enc(controllerId)}/nodes`),

  getNode: (controllerId: string, node: string) =>
    api.get<HypervisorNode>(`/hypervisor/controllers/${enc(controllerId)}/nodes/${enc(node)}`),

  // ── VMs ────────────────────────────────────────────────────────────
  getAllVMs: (controllerId: string, type?: 'qemu' | 'lxc') =>
    api.get<HypervisorVM[]>(`/hypervisor/controllers/${enc(controllerId)}/vms`, {
      params: type ? { type } : undefined,
    }),

  getNodeVMs: (controllerId: string, node: string) =>
    api.get<HypervisorVM[]>(`/hypervisor/controllers/${enc(controllerId)}/nodes/${enc(node)}/vms`),

  getNodeContainers: (controllerId: string, node: string) =>
    api.get<HypervisorVM[]>(`/hypervisor/controllers/${enc(controllerId)}/nodes/${enc(node)}/containers`),

  getVMConfig: (controllerId: string, node: string, vmType: string, vmid: number) =>
    api.get<Record<string, unknown>>(
      `/hypervisor/controllers/${enc(controllerId)}/nodes/${enc(node)}/${safeVmType(vmType)}/${vmid}/config`
    ),

  vmAction: (
    controllerId: string,
    node: string,
    vmType: string,
    vmid: number,
    action: string
  ) =>
    api.post(`/hypervisor/controllers/${enc(controllerId)}/nodes/${enc(node)}/${safeVmType(vmType)}/${vmid}/action`, {
      action,
    }),

  // ── VM/CT Creation ────────────────────────────────────────────────
  getNextVMID: (controllerId: string) =>
    api.get<NextVMIDResponse>(`/hypervisor/controllers/${enc(controllerId)}/nextid`),

  createVM: (controllerId: string, data: CreateVMRequest) =>
    api.post<CreateVMResponse>(`/hypervisor/controllers/${enc(controllerId)}/vms`, data),

  createContainer: (controllerId: string, data: CreateContainerRequest) =>
    api.post<CreateVMResponse>(`/hypervisor/controllers/${enc(controllerId)}/containers`, data),

  // Destroying a guest is irreversible — this call is only reached after the
  // type-to-confirm dialog (DestructiveConfirmDialog) passes, so we send
  // confirmed=true to satisfy the backend's per-action confirmation gate.
  deleteVM: (controllerId: string, node: string, vmType: string, vmid: number) =>
    api.delete(`/hypervisor/controllers/${enc(controllerId)}/nodes/${enc(node)}/${safeVmType(vmType)}/${vmid}`, {
      params: { confirmed: true },
    }),

  // ── Snapshots ──────────────────────────────────────────────────────
  getSnapshots: (controllerId: string, node: string, vmType: string, vmid: number) =>
    api.get<HypervisorSnapshot[]>(
      `/hypervisor/controllers/${enc(controllerId)}/nodes/${enc(node)}/${safeVmType(vmType)}/${vmid}/snapshots`
    ),

  createSnapshot: (
    controllerId: string,
    node: string,
    vmType: string,
    vmid: number,
    data: { snapname: string; description?: string; vmstate?: boolean }
  ) =>
    api.post(
      `/hypervisor/controllers/${enc(controllerId)}/nodes/${enc(node)}/${safeVmType(vmType)}/${vmid}/snapshots`,
      data
    ),

  rollbackSnapshot: (
    controllerId: string,
    node: string,
    vmType: string,
    vmid: number,
    snapname: string
  ) =>
    api.post(
      `/hypervisor/controllers/${enc(controllerId)}/nodes/${enc(node)}/${safeVmType(vmType)}/${vmid}/snapshots/${enc(snapname)}/rollback`,
      undefined,
      { params: { confirmed: true } }
    ),

  deleteSnapshot: (
    controllerId: string,
    node: string,
    vmType: string,
    vmid: number,
    snapname: string
  ) =>
    api.delete(
      `/hypervisor/controllers/${enc(controllerId)}/nodes/${enc(node)}/${safeVmType(vmType)}/${vmid}/snapshots/${enc(snapname)}`,
      { params: { confirmed: true } }
    ),

  // ── Storage ────────────────────────────────────────────────────────
  getStorage: (controllerId: string, node: string) =>
    api.get<HypervisorStorage[]>(`/hypervisor/controllers/${enc(controllerId)}/nodes/${enc(node)}/storage`),

  getStorageContent: (
    controllerId: string,
    node: string,
    storage: string,
    filters?: { content?: string; vmid?: number }
  ) =>
    api.get<HypervisorStorageContent[]>(
      `/hypervisor/controllers/${enc(controllerId)}/nodes/${enc(node)}/storage/${enc(storage)}/content`,
      { params: filters || undefined }
    ),

  // ── Network ────────────────────────────────────────────────────────
  getNodeNetwork: (controllerId: string, node: string) =>
    api.get<HypervisorNetworkInterface[]>(
      `/hypervisor/controllers/${enc(controllerId)}/nodes/${enc(node)}/network`
    ),

  // ── Tasks ──────────────────────────────────────────────────────────
  getTasks: (controllerId: string, node: string, limit?: number) =>
    api.get<HypervisorTask[]>(`/hypervisor/controllers/${enc(controllerId)}/nodes/${enc(node)}/tasks`, {
      params: limit ? { limit } : undefined,
    }),

  // ── Monitoring ─────────────────────────────────────────────────────
  getNodeRRD: (controllerId: string, node: string, timeframe?: string, maxPoints?: number) =>
    api.get<HypervisorRRDPoint[]>(`/hypervisor/controllers/${enc(controllerId)}/nodes/${enc(node)}/rrd`, {
      params: { timeframe: timeframe || 'hour', ...(maxPoints ? { max_points: maxPoints } : {}) },
    }),

  getVMRRD: (controllerId: string, node: string, vmid: number, timeframe?: string, maxPoints?: number) =>
    api.get<HypervisorRRDPoint[]>(
      `/hypervisor/controllers/${enc(controllerId)}/nodes/${enc(node)}/qemu/${vmid}/rrd`,
      { params: { timeframe: timeframe || 'hour', ...(maxPoints ? { max_points: maxPoints } : {}) } }
    ),

  // ── Backup ─────────────────────────────────────────────────────────
  getBackupJobs: (controllerId: string) =>
    api.get<HypervisorBackupJob[]>(`/hypervisor/controllers/${enc(controllerId)}/backup/jobs`),

  runBackup: (
    controllerId: string,
    node: string,
    vmType: string,
    vmid: number,
    data: { storage: string; mode?: string; compress?: string }
  ) =>
    api.post(
      `/hypervisor/controllers/${enc(controllerId)}/nodes/${enc(node)}/${safeVmType(vmType)}/${vmid}/backup`,
      data
    ),

  // ── Clone / Migrate / Resize ───────────────────────────────────────
  cloneVM: (
    controllerId: string,
    node: string,
    vmType: string,
    vmid: number,
    data: { newid: number; name?: string; target?: string; full?: boolean; storage?: string; description?: string }
  ) =>
    api.post(`/hypervisor/controllers/${enc(controllerId)}/nodes/${enc(node)}/${safeVmType(vmType)}/${vmid}/clone`, data),

  migrateVM: (
    controllerId: string,
    node: string,
    vmType: string,
    vmid: number,
    data: { target: string; online?: boolean }
  ) =>
    api.post(`/hypervisor/controllers/${enc(controllerId)}/nodes/${enc(node)}/${safeVmType(vmType)}/${vmid}/migrate`, data),

  resizeDisk: (
    controllerId: string,
    node: string,
    vmType: string,
    vmid: number,
    data: { disk: string; size: string }
  ) =>
    api.put(`/hypervisor/controllers/${enc(controllerId)}/nodes/${enc(node)}/${safeVmType(vmType)}/${vmid}/resize`, data),

  updateConfig: (
    controllerId: string,
    node: string,
    vmType: string,
    vmid: number,
    data: Record<string, unknown>
  ) =>
    api.put(`/hypervisor/controllers/${enc(controllerId)}/nodes/${enc(node)}/${safeVmType(vmType)}/${vmid}/config`, data),

  convertToTemplate: (controllerId: string, node: string, vmType: string, vmid: number) =>
    api.post(`/hypervisor/controllers/${enc(controllerId)}/nodes/${enc(node)}/${safeVmType(vmType)}/${vmid}/template`),

  // ── Console ─────────────────────────────────────────────────────────
  getConsoleProxy: (
    controllerId: string,
    node: string,
    vmType: string,
    vmid: number,
    consoleType: 'vnc' | 'spice' | 'term' = 'vnc'
  ) =>
    api.post<HypervisorConsoleProxy>(
      `/hypervisor/controllers/${enc(controllerId)}/nodes/${enc(node)}/${safeVmType(vmType)}/${vmid}/console`,
      null,
      { params: { console_type: consoleType } }
    ),

  // ── Task Details ────────────────────────────────────────────────────
  getTaskStatus: (controllerId: string, node: string, upid: string) =>
    api.get<HypervisorTaskDetail>(
      `/hypervisor/controllers/${enc(controllerId)}/nodes/${enc(node)}/tasks/${enc(upid)}/status`
    ),

  getTaskLog: (controllerId: string, node: string, upid: string, start?: number, limit?: number) =>
    api.get<HypervisorTaskLogEntry[]>(
      `/hypervisor/controllers/${enc(controllerId)}/nodes/${enc(node)}/tasks/${enc(upid)}/log`,
      { params: { start: start || 0, limit: limit || 50 } }
    ),

  stopTask: (controllerId: string, node: string, upid: string) =>
    api.delete(`/hypervisor/controllers/${enc(controllerId)}/nodes/${enc(node)}/tasks/${enc(upid)}`),

  // ── Firewall ────────────────────────────────────────────────────────
  getClusterFirewallRules: (controllerId: string) =>
    api.get<HypervisorFirewallRule[]>(`/hypervisor/controllers/${enc(controllerId)}/firewall/rules`),

  getNodeFirewallRules: (controllerId: string, node: string) =>
    api.get<HypervisorFirewallRule[]>(`/hypervisor/controllers/${enc(controllerId)}/nodes/${enc(node)}/firewall/rules`),

  createNodeFirewallRule: (
    controllerId: string,
    node: string,
    data: { action: string; type?: string; enable?: boolean; source?: string; dest?: string; dport?: string; proto?: string; comment?: string }
  ) =>
    api.post(`/hypervisor/controllers/${enc(controllerId)}/nodes/${enc(node)}/firewall/rules`, data),

  deleteNodeFirewallRule: (controllerId: string, node: string, pos: number) =>
    api.delete(`/hypervisor/controllers/${enc(controllerId)}/nodes/${enc(node)}/firewall/rules/${enc(pos)}`, {
      params: { confirmed: true },
    }),

  // ── Node Extras ────────────────────────────────────────────────────
  // Node power ops are catastrophic (whole node + guests offline) and only
  // reached after the type-to-confirm dialog; thread confirmed=true so the
  // backend confirmation gate passes (still refused while read-only is on).
  shutdownNode: (controllerId: string, node: string) =>
    api.post(`/hypervisor/controllers/${enc(controllerId)}/nodes/${enc(node)}/shutdown`, undefined, {
      params: { confirmed: true },
    }),

  rebootNode: (controllerId: string, node: string) =>
    api.post(`/hypervisor/controllers/${enc(controllerId)}/nodes/${enc(node)}/reboot`, undefined, {
      params: { confirmed: true },
    }),

  getNodeServices: (controllerId: string, node: string) =>
    api.get<HypervisorNodeService[]>(`/hypervisor/controllers/${enc(controllerId)}/nodes/${enc(node)}/services`),

  getNodeDisks: (controllerId: string, node: string) =>
    api.get<HypervisorDiskInfo[]>(`/hypervisor/controllers/${enc(controllerId)}/nodes/${enc(node)}/disks`),

  getDiskSmart: (controllerId: string, node: string, disk: string) =>
    api.get(`/hypervisor/controllers/${enc(controllerId)}/nodes/${enc(node)}/disks/smart`, {
      params: { disk },
    }),

  getNodeSyslog: (controllerId: string, node: string, limit?: number, start?: number) =>
    api.get<HypervisorSyslogEntry[]>(`/hypervisor/controllers/${enc(controllerId)}/nodes/${enc(node)}/syslog`, {
      params: { limit: limit || 50, start: start || 0 },
    }),

  deleteStorageVolume: (controllerId: string, node: string, storage: string, volume: string) =>
    api.delete(`/hypervisor/controllers/${enc(controllerId)}/nodes/${enc(node)}/storage/${enc(storage)}/content/${enc(volume)}`, {
      params: { confirmed: true },
    }),

  // ── HA ──────────────────────────────────────────────────────────────
  getHAResources: (controllerId: string) =>
    api.get<HypervisorHAResource[]>(`/hypervisor/controllers/${enc(controllerId)}/ha/resources`),

  getHAGroups: (controllerId: string) =>
    api.get<HypervisorHAGroup[]>(`/hypervisor/controllers/${enc(controllerId)}/ha/groups`),

  createHAResource: (
    controllerId: string,
    data: { sid: string; group?: string; max_relocate?: number; max_restart?: number; state?: string; comment?: string }
  ) =>
    api.post(`/hypervisor/controllers/${enc(controllerId)}/ha/resources`, data),

  deleteHAResource: (controllerId: string, sid: string) =>
    api.delete(`/hypervisor/controllers/${enc(controllerId)}/ha/resources/${enc(sid)}`, {
      params: { confirmed: true },
    }),

  createHAGroup: (
    controllerId: string,
    data: { group: string; nodes: string; nofailback?: boolean; restricted?: boolean; comment?: string }
  ) =>
    api.post(`/hypervisor/controllers/${enc(controllerId)}/ha/groups`, data),

  deleteHAGroup: (controllerId: string, group: string) =>
    api.delete(`/hypervisor/controllers/${enc(controllerId)}/ha/groups/${enc(group)}`, {
      params: { confirmed: true },
    }),

  // ── Resource Pools ──────────────────────────────────────────────────
  getPools: (controllerId: string) =>
    api.get<HypervisorResourcePool[]>(`/hypervisor/controllers/${enc(controllerId)}/pools`),

  // ── Ceph ────────────────────────────────────────────────────────────
  getCephStatus: (controllerId: string, node: string) =>
    api.get<HypervisorCephStatus>(`/hypervisor/controllers/${enc(controllerId)}/nodes/${enc(node)}/ceph/status`),

  // ── Bulk Operations ────────────────────────────────────────────
  bulkAction: (controllerId: string, data: BulkActionRequest) =>
    api.post<BulkActionResult[]>(
      `/hypervisor/controllers/${enc(controllerId)}/bulk-action`,
      data,
      // Bulk delete is irreversible and only reached after the type-to-confirm
      // dialog; thread confirmed=true so the backend's confirmation gate passes.
      data.action === 'delete' ? { params: { confirmed: true } } : undefined
    ),

  bulkMigrate: (controllerId: string, data: BulkMigrateRequest) =>
    api.post<BulkActionResult[]>(`/hypervisor/controllers/${enc(controllerId)}/bulk-migrate`, data),

  // ── Guest Agent ────────────────────────────────────────────────
  getGuestAgentInfo: (controllerId: string, node: string, vmid: number) =>
    api.get<GuestAgentInfo>(`/hypervisor/controllers/${enc(controllerId)}/nodes/${enc(node)}/qemu/${vmid}/agent/info`),

  // ── Backup Job CRUD ────────────────────────────────────────────
  createBackupJob: (controllerId: string, data: BackupJobCreateRequest) =>
    api.post(`/hypervisor/controllers/${enc(controllerId)}/backup/jobs`, data),

  updateBackupJob: (controllerId: string, jobId: string, data: BackupJobUpdateRequest) =>
    api.put(`/hypervisor/controllers/${enc(controllerId)}/backup/jobs/${enc(jobId)}`, data),

  deleteBackupJob: (controllerId: string, jobId: string) =>
    api.delete(`/hypervisor/controllers/${enc(controllerId)}/backup/jobs/${enc(jobId)}`, {
      params: { confirmed: true },
    }),

  // ── Container RRD ──────────────────────────────────────────────
  getContainerRRD: (controllerId: string, node: string, vmid: number, timeframe?: string, maxPoints?: number) =>
    api.get<HypervisorRRDPoint[]>(
      `/hypervisor/controllers/${enc(controllerId)}/nodes/${enc(node)}/lxc/${vmid}/rrd`,
      { params: { timeframe: timeframe || 'hour', ...(maxPoints ? { max_points: maxPoints } : {}) } }
    ),

  // ── Storage Upload ─────────────────────────────────────────────
  uploadToStorage: (controllerId: string, node: string, storage: string, file: File, contentType: string) => {
    const formData = new FormData();
    formData.append('file', file);
    formData.append('content', contentType);
    return api.post(
      `/hypervisor/controllers/${enc(controllerId)}/nodes/${enc(node)}/storage/${enc(storage)}/upload`,
      formData,
      { headers: { 'Content-Type': 'multipart/form-data' } }
    );
  },

  // ── APT / Updates ───────────────────────────────────────────────
  getNodeAptUpdates: (cid: string, node: string) =>
    api.get(`/hypervisor/controllers/${enc(cid)}/nodes/${enc(node)}/apt/updates`),

  refreshNodeApt: (cid: string, node: string) =>
    api.post(`/hypervisor/controllers/${enc(cid)}/nodes/${enc(node)}/apt/refresh`),

  getNodeAptVersions: (cid: string, node: string) =>
    api.get(`/hypervisor/controllers/${enc(cid)}/nodes/${enc(node)}/apt/versions`),

  // ── Certificates ────────────────────────────────────────────────
  getNodeCertificates: (cid: string, node: string) =>
    api.get(`/hypervisor/controllers/${enc(cid)}/nodes/${enc(node)}/certificates`),

  renewAcmeCertificate: (cid: string, node: string) =>
    api.post(`/hypervisor/controllers/${enc(cid)}/nodes/${enc(node)}/certificates/acme/renew`),

  // `confirmed` is a REQUIRED body field: the endpoint 409s without it
  // (api.py: `if not body.confirmed`), because replacing a node's TLS cert can
  // lock the operator out of pveproxy. It was never sent, so the upload failed
  // 100% of the time. The operator has already supplied the cert and key in the
  // upload dialog and clicked Upload, so the acknowledgement is real.
  uploadCustomCertificate: (cid: string, node: string, data: { certificates: string; key: string; force?: boolean; restart?: boolean }) =>
    api.post(`/hypervisor/controllers/${enc(cid)}/nodes/${enc(node)}/certificates/custom`, {
      ...data,
      confirmed: true,
    }),

  deleteCustomCertificate: (cid: string, node: string) =>
    api.delete(`/hypervisor/controllers/${enc(cid)}/nodes/${enc(node)}/certificates/custom`, {
      params: { confirmed: true },
    }),

  // ── Subscription ────────────────────────────────────────────────
  getNodeSubscription: (cid: string, node: string) =>
    api.get(`/hypervisor/controllers/${enc(cid)}/nodes/${enc(node)}/subscription`),

  // ── Remote Migration ────────────────────────────────────────────
  remoteMigrateVM: (cid: string, node: string, vmid: number, data: RemoteMigrateRequest) =>
    api.post(`/hypervisor/controllers/${enc(cid)}/nodes/${enc(node)}/qemu/${vmid}/remote-migrate`, data),

  remoteMigrateContainer: (cid: string, node: string, vmid: number, data: RemoteMigrateRequest) =>
    api.post(`/hypervisor/controllers/${enc(cid)}/nodes/${enc(node)}/lxc/${vmid}/remote-migrate`, data),

  // ── SDN ─────────────────────────────────────────────────────────
  getSdnZones: (cid: string) =>
    api.get(`/hypervisor/controllers/${enc(cid)}/sdn/zones`),

  getSdnVnets: (cid: string) =>
    api.get(`/hypervisor/controllers/${enc(cid)}/sdn/vnets`),

  getSdnControllers: (cid: string) =>
    api.get(`/hypervisor/controllers/${enc(cid)}/sdn/controllers`),

  createSdnZone: (cid: string, data: CreateSdnZoneRequest) =>
    api.post(`/hypervisor/controllers/${enc(cid)}/sdn/zones`, data),

  createSdnVnet: (cid: string, data: CreateSdnVnetRequest) =>
    api.post(`/hypervisor/controllers/${enc(cid)}/sdn/vnets`, data),

  deleteSdnZone: (cid: string, zone: string) =>
    api.delete(`/hypervisor/controllers/${enc(cid)}/sdn/zones/${enc(zone)}`, {
      params: { confirmed: true },
    }),

  deleteSdnVnet: (cid: string, vnet: string) =>
    api.delete(`/hypervisor/controllers/${enc(cid)}/sdn/vnets/${enc(vnet)}`, {
      params: { confirmed: true },
    }),

  applySdn: (cid: string) =>
    api.post(`/hypervisor/controllers/${enc(cid)}/sdn/apply`),

  // ── Guest Agent (exec / file ops) ──────────────────────────────
  agentExec: (cid: string, node: string, vmid: number, data: { command: string; input_data?: string }) =>
    // Submitting a command IS the operator's intent — thread confirmed=true so the
    // backend's second-factor gate passes (still refused while read-only is on).
    api.post(`/hypervisor/controllers/${enc(cid)}/nodes/${enc(node)}/qemu/${vmid}/agent/exec`, data, {
      params: { confirmed: true },
    }),

  agentExecStatus: (cid: string, node: string, vmid: number, pid: number) =>
    api.get(`/hypervisor/controllers/${enc(cid)}/nodes/${enc(node)}/qemu/${vmid}/agent/exec-status/${pid}`),

  agentFileRead: (cid: string, node: string, vmid: number, data: { file: string }) =>
    api.post(`/hypervisor/controllers/${enc(cid)}/nodes/${enc(node)}/qemu/${vmid}/agent/file-read`, data),

  agentFileWrite: (cid: string, node: string, vmid: number, data: { file: string; content: string }) =>
    api.post(`/hypervisor/controllers/${enc(cid)}/nodes/${enc(node)}/qemu/${vmid}/agent/file-write`, data, {
      params: { confirmed: true },
    }),

  // ── Pending Config ──────────────────────────────────────────────
  getVmPendingConfig: (cid: string, node: string, vmid: number) =>
    api.get(`/hypervisor/controllers/${enc(cid)}/nodes/${enc(node)}/qemu/${vmid}/pending`),

  getContainerPendingConfig: (cid: string, node: string, vmid: number) =>
    api.get(`/hypervisor/controllers/${enc(cid)}/nodes/${enc(node)}/lxc/${vmid}/pending`),

  // ── Cluster (extended) ──────────────────────────────────────────
  getClusterOptions: (cid: string) =>
    api.get(`/hypervisor/controllers/${enc(cid)}/cluster/options`),

  // The query parameter is `max_entries` (api.py: `max_entries: int = Query(50,
  // ge=1, le=5000)`). Sending `max` was ignored, so the Cluster Log tab asked
  // for 200 entries and silently got the backend default of 50 -- and its own
  // count badge reported 50 as if that were all there was.
  getClusterLog: (cid: string, max?: number) =>
    api.get(`/hypervisor/controllers/${enc(cid)}/cluster/log`, { params: { max_entries: max } }),

  getClusterConfigNodes: (cid: string) =>
    api.get(`/hypervisor/controllers/${enc(cid)}/cluster/config/nodes`),

  getClusterReplication: (cid: string) =>
    api.get(`/hypervisor/controllers/${enc(cid)}/cluster/replication`),

  getReplicationLog: (cid: string, replicationId: string) =>
    api.get(`/hypervisor/controllers/${enc(cid)}/cluster/replication/${enc(replicationId)}/log`),

  // ── Guest Firewall ──────────────────────────────────────────────────
  getGuestFirewallRules: (cid: string, node: string, vmType: string, vmid: number) =>
    api.get(`/hypervisor/controllers/${enc(cid)}/nodes/${enc(node)}/${safeVmType(vmType)}/${vmid}/firewall/rules`),

  createGuestFirewallRule: (
    cid: string,
    node: string,
    vmType: string,
    vmid: number,
    data: { action: string; type?: string; enable?: boolean; source?: string; dest?: string; dport?: string; proto?: string; comment?: string }
  ) =>
    api.post(`/hypervisor/controllers/${enc(cid)}/nodes/${enc(node)}/${safeVmType(vmType)}/${vmid}/firewall/rules`, data),

  deleteGuestFirewallRule: (cid: string, node: string, vmType: string, vmid: number, pos: number) =>
    api.delete(`/hypervisor/controllers/${enc(cid)}/nodes/${enc(node)}/${safeVmType(vmType)}/${vmid}/firewall/rules/${enc(String(pos))}`, {
      params: { confirmed: true },
    }),

  getGuestFirewallOptions: (cid: string, node: string, vmType: string, vmid: number) =>
    api.get(`/hypervisor/controllers/${enc(cid)}/nodes/${enc(node)}/${safeVmType(vmType)}/${vmid}/firewall/options`),

  updateGuestFirewallOptions: (cid: string, node: string, vmType: string, vmid: number, data: Record<string, unknown>) =>
    api.put(`/hypervisor/controllers/${enc(cid)}/nodes/${enc(node)}/${safeVmType(vmType)}/${vmid}/firewall/options`, data),

  getClusterFirewallOptions: (cid: string) =>
    api.get(`/hypervisor/controllers/${enc(cid)}/cluster/firewall/options`),

  updateClusterFirewallOptions: (cid: string, data: Record<string, unknown>) =>
    api.put(`/hypervisor/controllers/${enc(cid)}/cluster/firewall/options`, data),

  // ── Ceph (detailed) ─────────────────────────────────────────────────
  getCephDetail: (cid: string, node: string) =>
    api.get(`/hypervisor/controllers/${enc(cid)}/nodes/${enc(node)}/ceph/detail`),

  // ── Fleet Task Statistics ───────────────────────────────────────────
  getFleetTaskStatistics: (siteId?: string) =>
    api.get('/hypervisor/fleet/task-statistics', {
      params: siteId ? { site_id: siteId } : undefined,
    }),

  // ── Node Sensors ────────────────────────────────────────────────────
  getNodeSensors: (cid: string, node: string) =>
    api.get(`/hypervisor/controllers/${enc(cid)}/nodes/${enc(node)}/sensors`),

  // ── Backup Age Report ────────────────────────────────────────────────
  getBackupAgeReport: (cid: string, thresholdHours?: number) =>
    api.get(`/hypervisor/controllers/${enc(cid)}/backup/age-report`, {
      params: { threshold_hours: thresholdHours || 24 },
    }),

  // ── Backup Restore / Prune (STAGED) ───────────────────────────────────
  //
  // These used to POST the direct hypervisor endpoints. Both are refused
  // there: `_refuse_direct_catastrophic` is the FIRST statement of
  // `HypervisorService.restore_backup` and `.prune_backups`, and the API maps
  // its ValueError to HTTP 400. So every click on Restore, "Prune Now" or
  // "Prune Backups" returned:
  //
  //   "backup restore (overwrites a guest) is catastrophic and cannot be
  //    applied on the direct path; stage it via the staged adapter endpoints
  //    (which run the pre-flight and require confirmed=true) to proceed."
  //
  // The guard is correct — restore overwrites a live guest, prune deletes
  // archives permanently, and the direct path had neither the pre-flight nor
  // the archive-volid allowlist. What was missing was the other half: the
  // staged endpoints it names were never reachable from the UI, so the
  // disaster-recovery action the product advertises could not be performed
  // from the product.
  //
  // Staging returns a pending change; the operator reviews and applies it
  // from the Pending Changes drawer, which supplies `confirmed: true` after
  // an explicit acknowledgement.
  stageBackupRestore: (
    cid: string,
    data: {
      node: string;
      vm_type: 'qemu' | 'lxc';
      archive: string;
      vmid: number;
      storage?: string;
      start?: boolean;
      unique?: boolean;
    },
  ) =>
    api.post<PendingChangeResponse>(
      `/gateway-proxmox-backup/${enc(cid)}/changes/proxmox.backup.restore`,
      { payload: data, target_id: String(data.vmid) },
      { params: { operation: 'create' } },
    ),

  getPrunePreview: (cid: string, node: string, storage: string, vmid?: number) =>
    api.get(`/hypervisor/controllers/${enc(cid)}/nodes/${enc(node)}/storage/${enc(storage)}/prune-preview`, { params: vmid ? { vmid } : undefined }),

  stageBackupPrune: (
    cid: string,
    data: {
      node: string;
      storage: string;
      keep_last?: number;
      keep_hourly?: number;
      keep_daily?: number;
      keep_weekly?: number;
      keep_monthly?: number;
      keep_yearly?: number;
      vmid?: number;
    },
  ) =>
    api.post<PendingChangeResponse>(
      `/gateway-proxmox-backup/${enc(cid)}/changes/proxmox.backup.prune`,
      { payload: data, target_id: `${data.node}:${data.storage}` },
      { params: { operation: 'create' } },
    ),

  // ── CloudInit ─────────────────────────────────────────────────────────
  getCloudInit: (cid: string, node: string, vmid: number) =>
    api.get(`/hypervisor/controllers/${enc(cid)}/nodes/${enc(node)}/qemu/${vmid}/cloudinit`),

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  updateCloudInit: (cid: string, node: string, vmid: number, data: Record<string, any>) =>
    api.put(`/hypervisor/controllers/${enc(cid)}/nodes/${enc(node)}/qemu/${vmid}/cloudinit`, data),

  regenerateCloudInit: (cid: string, node: string, vmid: number) =>
    api.post(`/hypervisor/controllers/${enc(cid)}/nodes/${enc(node)}/qemu/${vmid}/cloudinit/regenerate`),
};

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
import type { components } from './generated/openapi';

export type HypervisorOperationReceipt = components['schemas']['VMActionResponse'];
export type HypervisorPowerReceipt = HypervisorOperationReceipt;
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
} from './types';

export type TaskStopIntent = components['schemas']['TaskStopRequest'];
export type TaskStopReceipt = components['schemas']['TaskStopResponse'];
export type TaskStopReview = components['schemas']['TaskStopReviewResponse'];

export type BackupJobSettings = components['schemas']['BackupJobSettings'];
export type BackupJobReviewIntent = components['schemas']['BackupJobReviewRequest'];
export type BackupJobOperationIntent = components['schemas']['BackupJobOperationRequest'];
export type BackupJobReceipt = components['schemas']['BackupJobOperationResponse'];
export type BackupJobReview = components['schemas']['BackupJobReviewResponse'];

export type CertificateReviewIntent = components['schemas']['CertificateReviewRequest'];
export type CertificateOperationIntent = components['schemas']['CertificateOperationRequest'];
export type CertificateOperationReceipt = components['schemas']['CertificateOperationResponse'];
export interface CertificateReview {
  expected_digest: string;
  snapshot: {
    node: string; action: 'upload' | 'delete' | 'renew'; endpoint_node: string;
    overwrite: boolean; restart: boolean; acme_force: boolean; expected_domains: string[];
    candidate: { subject: string; san: string[]; notafter: number; fingerprint: string } | null;
    inventory: Record<string, { fingerprint: string }>;
  };
}

export type ClusterOperationIntent = components['schemas']['ClusterOperationRequest'];
export type ClusterOperationReceipt = components['schemas']['ClusterOperationResponse'];
export type ClusterOperationAction = 'node.reboot' | 'node.shutdown' | 'ha.resource.create' | 'ha.resource.delete' | 'ha.group.create' | 'ha.group.delete';
export type ClusterOperationSpec =
  | { action: 'node.reboot' | 'node.shutdown' | 'ha.resource.delete' | 'ha.group.delete'; target: string }
  | { action: 'ha.resource.create'; target: string; options: { sid: string; group: string; state: 'started'; max_restart: number; max_relocate: number; comment: string } }
  | { action: 'ha.group.create'; target: string; options: { group: string; nodes: string; nofailback: boolean; restricted: boolean; comment: string } };
export interface ClusterOperationReview {
  expected_digest: string;
  snapshot: {
    action: string; target: string; selected_group: string;
    cluster: { name: string; quorate: number | null };
    nodes: { name: string; online: number }[];
    guests: { vmid: number; type: string; node: string; status: string; name: string; template: number }[];
    resources: Record<string, unknown>[];
    groups: Record<string, unknown>[];
  };
}

export interface ReviewedGuestIntent {
  request_id: string;
  expected_digest: string;
}

export function reviewedGuestDigest(config: Record<string, unknown>): string | null {
  return typeof config.digest === 'string' && /^[0-9a-f]{40}$/.test(config.digest) ? config.digest : null;
}

export function reviewedDiskBytes(config: Record<string, unknown>, disk: string): number | null {
  const raw = config[disk];
  if (typeof raw !== 'string' || raw.includes('media=cdrom')) return null;
  const match = /(?:^|,)size=(\d+(?:\.\d+)?)([KMGT]?)(?:,|$)/.exec(raw);
  if (!match) return null;
  const units: Record<string, number> = { K: 1024, M: 1024 ** 2, G: 1024 ** 3, T: 1024 ** 4 };
  const bytes = Number(match[1]) * units[match[2] || 'G'];
  return Number.isSafeInteger(bytes) && bytes > 0 ? bytes : null;
}

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

export type SdnInspection = components['schemas']['SdnInspection'];
export type SdnAttachmentInspection = components['schemas']['SdnAttachmentInspection'];
export type SdnDependencyInspection = components['schemas']['SdnDependencyInspection'];
export type SdnDryRunObservation = components['schemas']['SdnDryRunObservation'];

/** Validate vmType to prevent path injection. */
function safeVmType(vmType: string): 'qemu' | 'lxc' {
  if (vmType === 'qemu' || vmType === 'lxc') return vmType;
  throw new Error(`Invalid vmType: ${vmType}`);
}

export type StorageReviewIntent = components['schemas']['StorageReviewRequest'];
export type StorageOperationIntent = components['schemas']['StorageOperationRequest'];
export type StorageOperationReceipt = components['schemas']['StorageOperationResponse'];

/** Encode a path segment (node name, storage, snapshot name, etc.). */
const enc = encodeURIComponent;

// getRandomValues also works on appliance LAN HTTP origins where randomUUID
// may be unavailable. Intent IDs must never fall back to Math.random().
export function newHypervisorRequestId(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/** PBS uses ct/vm namespaces, unlike file backups named vzdump-lxc/qemu. */
export function backupGuestType(archive: string, format?: string): 'qemu' | 'lxc' {
  if (format === 'pbs-ct' || /:backup\/ct\/[0-9]+\//.test(archive) || /(?:^|\/)vzdump-lxc-/.test(archive)) return 'lxc';
  return 'qemu';
}

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
    action: string,
    requestId: string = newHypervisorRequestId()
  ) =>
    api.post<HypervisorPowerReceipt>(`/hypervisor/controllers/${enc(controllerId)}/nodes/${enc(node)}/${safeVmType(vmType)}/${vmid}/action`, {
      action,
      request_id: requestId,
      force: true,
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
  deleteVM: (controllerId: string, node: string, vmType: string, vmid: number, intent: { request_id: string; expected_digest: string }) =>
    api.delete<HypervisorOperationReceipt>(`/hypervisor/controllers/${enc(controllerId)}/nodes/${enc(node)}/${safeVmType(vmType)}/${vmid}`, {
      data: { ...intent, force: true, confirmed: true },
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
    data: { snapname: string; description?: string; vmstate?: boolean; request_id?: string }
  ) =>
    api.post<HypervisorOperationReceipt>(
      `/hypervisor/controllers/${enc(controllerId)}/nodes/${enc(node)}/${safeVmType(vmType)}/${vmid}/snapshots`,
      { ...data, request_id: data.request_id ?? newHypervisorRequestId(), force: true }
    ),

  rollbackSnapshot: (
    controllerId: string,
    node: string,
    vmType: string,
    vmid: number,
    snapname: string,
    requestId: string = newHypervisorRequestId()
  ) =>
    api.post<HypervisorOperationReceipt>(
      `/hypervisor/controllers/${enc(controllerId)}/nodes/${enc(node)}/${safeVmType(vmType)}/${vmid}/snapshots/${enc(snapname)}/rollback`,
      { request_id: requestId, force: true },
      { params: { confirmed: true } }
    ),

  deleteSnapshot: (
    controllerId: string,
    node: string,
    vmType: string,
    vmid: number,
    snapname: string,
    requestId: string = newHypervisorRequestId()
  ) =>
    api.delete<HypervisorOperationReceipt>(
      `/hypervisor/controllers/${enc(controllerId)}/nodes/${enc(node)}/${safeVmType(vmType)}/${vmid}/snapshots/${enc(snapname)}`,
      { params: { confirmed: true, request_id: requestId, force: true } }
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
    data: { storage: string; mode?: string; compress?: string; request_id?: string }
  ) =>
    api.post<HypervisorOperationReceipt>(
      `/hypervisor/controllers/${enc(controllerId)}/nodes/${enc(node)}/${safeVmType(vmType)}/${vmid}/backup`,
      { ...data, request_id: data.request_id ?? newHypervisorRequestId(), force: true }
    ),

  // ── Clone / Migrate / Resize ───────────────────────────────────────
  cloneVM: (
    controllerId: string,
    node: string,
    vmType: string,
    vmid: number,
    data: { newid: number; name?: string; target?: string; full?: boolean; storage?: string; description?: string; request_id?: string }
  ) =>
    api.post<HypervisorOperationReceipt>(`/hypervisor/controllers/${enc(controllerId)}/nodes/${enc(node)}/${safeVmType(vmType)}/${vmid}/clone`, { ...data, request_id: data.request_id ?? newHypervisorRequestId(), force: true }),

  migrateVM: (
    controllerId: string,
    node: string,
    vmType: string,
    vmid: number,
    data: { target: string; online?: boolean; restart?: boolean; request_id?: string }
  ) =>
    api.post<HypervisorOperationReceipt>(`/hypervisor/controllers/${enc(controllerId)}/nodes/${enc(node)}/${safeVmType(vmType)}/${vmid}/migrate`, { ...data, request_id: data.request_id ?? newHypervisorRequestId(), force: true }),

  resizeDisk: (
    controllerId: string,
    node: string,
    vmType: string,
    vmid: number,
    data: ReviewedGuestIntent & { disk: string; size: string; current_size_bytes: number }
  ) =>
    api.put<HypervisorOperationReceipt>(`/hypervisor/controllers/${enc(controllerId)}/nodes/${enc(node)}/${safeVmType(vmType)}/${vmid}/resize`, { ...data, force: true }),

  updateConfig: (
    controllerId: string,
    node: string,
    vmType: string,
    vmid: number,
    data: ReviewedGuestIntent & Record<string, unknown>
  ) =>
    api.put<HypervisorOperationReceipt>(`/hypervisor/controllers/${enc(controllerId)}/nodes/${enc(node)}/${safeVmType(vmType)}/${vmid}/config`, { ...data, force: true }),

  convertToTemplate: (controllerId: string, node: string, vmType: string, vmid: number, data: ReviewedGuestIntent & { confirmed: boolean }) =>
    api.post<HypervisorOperationReceipt>(`/hypervisor/controllers/${enc(controllerId)}/nodes/${enc(node)}/${safeVmType(vmType)}/${vmid}/template`, { ...data, force: true }),

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

  reviewTaskStop: (controllerId: string, node: string, upid: string) =>
    api.post<TaskStopReview>(`/hypervisor/controllers/${enc(controllerId)}/nodes/${enc(node)}/tasks/${enc(upid)}/stop-review`),

  stopTask: (controllerId: string, node: string, upid: string, data: TaskStopIntent) =>
    api.delete<TaskStopReceipt>(`/hypervisor/controllers/${enc(controllerId)}/nodes/${enc(node)}/tasks/${enc(upid)}`, { data }),

  // ── Firewall ────────────────────────────────────────────────────────
  getClusterFirewallRules: (controllerId: string) =>
    api.get<HypervisorFirewallRule[]>(`/hypervisor/controllers/${enc(controllerId)}/firewall/rules`),

  getNodeFirewallRules: (controllerId: string, node: string) =>
    api.get<HypervisorFirewallRule[]>(`/hypervisor/controllers/${enc(controllerId)}/nodes/${enc(node)}/firewall/rules`),

  reviewFirewallOperation: (cid: string, data: FirewallReviewIntent) =>
    api.post<FirewallReview>(`/hypervisor/controllers/${enc(cid)}/firewall/operations/review`, data),
  submitFirewallOperation: (cid: string, data: FirewallOperationIntent) =>
    api.post<FirewallOperationReceipt>(`/hypervisor/controllers/${enc(cid)}/firewall/operations`, data),

  // ── Node Extras ────────────────────────────────────────────────────
  reviewClusterOperation: (controllerId: string, action: ClusterOperationAction, target: string, group = '') =>
    api.get<ClusterOperationReview>(`/hypervisor/controllers/${enc(controllerId)}/cluster-operations/review`, { params: { action, target, group } }),

  shutdownNode: (controllerId: string, node: string, data: ClusterOperationIntent) =>
    api.post<ClusterOperationReceipt>(`/hypervisor/controllers/${enc(controllerId)}/nodes/${enc(node)}/shutdown`, data),

  rebootNode: (controllerId: string, node: string, data: ClusterOperationIntent) =>
    api.post<ClusterOperationReceipt>(`/hypervisor/controllers/${enc(controllerId)}/nodes/${enc(node)}/reboot`, data),

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

  reviewStorageOperation: (controllerId: string, node: string, storage: string, data: StorageReviewIntent) =>
    api.post<components['schemas']['StorageOperationReview']>(`/hypervisor/controllers/${enc(controllerId)}/nodes/${enc(node)}/storage/${enc(storage)}/review`, data),

  deleteStorageVolume: (controllerId: string, node: string, storage: string, volume: string, data: StorageOperationIntent) =>
    api.delete<StorageOperationReceipt>(`/hypervisor/controllers/${enc(controllerId)}/nodes/${enc(node)}/storage/${enc(storage)}/content/${enc(volume)}`, { data }),

  // ── HA ──────────────────────────────────────────────────────────────
  getHAResources: (controllerId: string) =>
    api.get<HypervisorHAResource[]>(`/hypervisor/controllers/${enc(controllerId)}/ha/resources`),

  getHAGroups: (controllerId: string) =>
    api.get<HypervisorHAGroup[]>(`/hypervisor/controllers/${enc(controllerId)}/ha/groups`),

  createHAResource: (controllerId: string, data: components['schemas']['HAResourceCreateRequest']) =>
    api.post<ClusterOperationReceipt>(`/hypervisor/controllers/${enc(controllerId)}/ha/resources`, data),

  deleteHAResource: (controllerId: string, sid: string, data: ClusterOperationIntent) =>
    api.delete<ClusterOperationReceipt>(`/hypervisor/controllers/${enc(controllerId)}/ha/resources/${enc(sid)}`, { data }),

  createHAGroup: (controllerId: string, data: components['schemas']['HAGroupCreateRequest']) =>
    api.post<ClusterOperationReceipt>(`/hypervisor/controllers/${enc(controllerId)}/ha/groups`, data),

  deleteHAGroup: (controllerId: string, group: string, data: ClusterOperationIntent) =>
    api.delete<ClusterOperationReceipt>(`/hypervisor/controllers/${enc(controllerId)}/ha/groups/${enc(group)}`, { data }),

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
      data.action === 'delete' ? { ...data, force: true } : {
        ...data,
        force: true,
        targets: data.targets.map((target) => ({
          ...target,
          request_id: target.request_id ?? newHypervisorRequestId(),
        })),
      },
      // Bulk delete is irreversible and only reached after the type-to-confirm
      // dialog; thread confirmed=true so the backend's confirmation gate passes.
      data.action === 'delete' ? { params: { confirmed: true } } : undefined
    ),

  bulkMigrate: (controllerId: string, data: BulkMigrateRequest) =>
    api.post<BulkActionResult[]>(`/hypervisor/controllers/${enc(controllerId)}/bulk-migrate`, {
      ...data,
      force: true,
      targets: data.targets.map((target) => ({ ...target, request_id: target.request_id ?? newHypervisorRequestId() })),
    }),

  // ── Guest Agent ────────────────────────────────────────────────
  getGuestAgentInfo: (controllerId: string, node: string, vmid: number) =>
    api.get<GuestAgentInfo>(`/hypervisor/controllers/${enc(controllerId)}/nodes/${enc(node)}/qemu/${vmid}/agent/info`),

  // ── Backup Job CRUD ────────────────────────────────────────────
  reviewBackupJob: (controllerId: string, data: BackupJobReviewIntent) =>
    api.post<BackupJobReview>(`/hypervisor/controllers/${enc(controllerId)}/backup/jobs/review`, data),

  createBackupJob: (controllerId: string, data: BackupJobOperationIntent) =>
    api.post<BackupJobReceipt>(`/hypervisor/controllers/${enc(controllerId)}/backup/jobs`, data),

  updateBackupJob: (controllerId: string, jobId: string, data: BackupJobOperationIntent) =>
    api.put<BackupJobReceipt>(`/hypervisor/controllers/${enc(controllerId)}/backup/jobs/${enc(jobId)}`, data),

  deleteBackupJob: (controllerId: string, jobId: string, data: BackupJobOperationIntent) =>
    api.delete<BackupJobReceipt>(`/hypervisor/controllers/${enc(controllerId)}/backup/jobs/${enc(jobId)}`, { data }),

  // ── Container RRD ──────────────────────────────────────────────
  getContainerRRD: (controllerId: string, node: string, vmid: number, timeframe?: string, maxPoints?: number) =>
    api.get<HypervisorRRDPoint[]>(
      `/hypervisor/controllers/${enc(controllerId)}/nodes/${enc(node)}/lxc/${vmid}/rrd`,
      { params: { timeframe: timeframe || 'hour', ...(maxPoints ? { max_points: maxPoints } : {}) } }
    ),

  // ── Storage Upload ─────────────────────────────────────────────
  uploadToStorage: (controllerId: string, node: string, storage: string, file: File, data: StorageOperationIntent) => {
    const formData = new FormData();
    formData.append('file', file);
    formData.append('content', data.content || 'iso');
    formData.append('size', String(data.size));
    formData.append('request_id', data.request_id);
    formData.append('expected_digest', data.expected_digest);
    formData.append('force', String(data.force));
    formData.append('confirmed', String(data.confirmed));
    return api.post<StorageOperationReceipt>(
      `/hypervisor/controllers/${enc(controllerId)}/nodes/${enc(node)}/storage/${enc(storage)}/upload`,
      formData,
      { headers: { 'Content-Type': 'multipart/form-data' }, timeout: 0 }
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

  reviewCertificate: (cid: string, node: string, data: CertificateReviewIntent) =>
    api.post<CertificateReview>(`/hypervisor/controllers/${enc(cid)}/nodes/${enc(node)}/certificates/review`, data),

  renewAcmeCertificate: (cid: string, node: string, data: CertificateOperationIntent) =>
    api.post<CertificateOperationReceipt>(`/hypervisor/controllers/${enc(cid)}/nodes/${enc(node)}/certificates/acme/renew`, data),

  uploadCustomCertificate: (cid: string, node: string, data: CertificateOperationIntent) =>
    api.post<CertificateOperationReceipt>(`/hypervisor/controllers/${enc(cid)}/nodes/${enc(node)}/certificates/custom`, data),

  deleteCustomCertificate: (cid: string, node: string, data: CertificateOperationIntent) =>
    api.delete<CertificateOperationReceipt>(`/hypervisor/controllers/${enc(cid)}/nodes/${enc(node)}/certificates/custom`, { data }),

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

  inspectSdnAttachments: (cid: string) =>
    api.get<SdnAttachmentInspection>(`/hypervisor/controllers/${enc(cid)}/sdn/attachments`),
  inspectSdnDependencies: (cid: string) =>
    api.get<SdnDependencyInspection>(`/hypervisor/controllers/${enc(cid)}/sdn/dependencies`),

  inspectSdn: (cid: string) =>
    api.get<SdnInspection>(`/hypervisor/controllers/${enc(cid)}/sdn/inspection`),

  getSdnDryRun: (cid: string, node: string) =>
    api.get<SdnDryRunObservation>(`/hypervisor/controllers/${enc(cid)}/sdn/nodes/${enc(node)}/dry-run`),

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

  getGuestFirewallOptions: (cid: string, node: string, vmType: string, vmid: number) =>
    api.get(`/hypervisor/controllers/${enc(cid)}/nodes/${enc(node)}/${safeVmType(vmType)}/${vmid}/firewall/options`),

  getClusterFirewallOptions: (cid: string) =>
    api.get(`/hypervisor/controllers/${enc(cid)}/cluster/firewall/options`),

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
    requestId: string = newHypervisorRequestId(),
  ) =>
    api.post<PendingChangeResponse>(
      `/gateway-proxmox-backup/${enc(cid)}/changes/proxmox.backup.restore`,
      { payload: data, target_id: String(data.vmid), request_id: requestId },
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

export type FirewallTarget = components['schemas']['FirewallTarget'];
export type FirewallRuleSettings = components['schemas']['FirewallRuleSettings'];
export type FirewallReviewIntent = components['schemas']['FirewallReviewRequest'];
export type FirewallReview = components['schemas']['FirewallReviewResponse'];
export type FirewallOperationIntent = components['schemas']['FirewallOperationRequest'];
export type FirewallOperationReceipt = components['schemas']['FirewallOperationResponse'];

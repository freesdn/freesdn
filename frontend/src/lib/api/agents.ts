// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { api } from './client';
import type {
  AgentSummary, AgentDetail, AgentListResponse, AgentStats,
  AgentHeartbeat, AgentTask, AgentHealth,
  AgentRegisterRequest, AgentRegisterResponse,
  AgentCommandRequest, AgentCommandResponse, RemoteScanRequest,
  AgentReleaseLatest, DownloadsPageResponse, AgentReleaseSummary, AgentUpdateCheckResponse,
} from './types';

export const agentsApi = {
  // List agents (DB-backed, paginated)
  list: (params?: { status?: string; site_id?: string; agent_type?: string; is_approved?: boolean; page?: number; per_page?: number }) =>
    api.get<AgentListResponse>('/agents', { params }),

  // Get agent stats
  stats: () =>
    api.get<AgentStats>('/agents/stats'),

  // Register new agent for site
  register: (data: AgentRegisterRequest) =>
    api.post<AgentRegisterResponse>('/agents/register', data),

  // Get agents for a specific site
  getForSite: (siteId: string) =>
    api.get<AgentSummary[]>(`/agents/site/${siteId}`),

  // Get single agent detail
  get: (agentId: string) =>
    api.get<AgentDetail>(`/agents/${agentId}`),

  // Update agent
  update: (agentId: string, data: Partial<{ name: string; description: string; is_enabled: boolean; config: Record<string, unknown>; poll_interval: number }>) =>
    api.patch<AgentDetail>(`/agents/${agentId}`, data),

  // Approve agent
  approve: (agentId: string) =>
    api.post<AgentDetail>(`/agents/${agentId}/approve`),

  // Delete (soft-delete) agent
  disconnect: (agentId: string) =>
    api.delete(`/agents/${agentId}`),

  // Heartbeats
  getHeartbeats: (agentId: string, params?: { limit?: number; since_hours?: number }) =>
    api.get<AgentHeartbeat[]>(`/agents/${agentId}/heartbeats`, { params }),

  // Tasks
  createTask: (agentId: string, data: { task_type: string; task_data?: Record<string, unknown>; priority?: number }) =>
    api.post<AgentTask>(`/agents/${agentId}/tasks`, data),

  listTasks: (agentId: string, params?: { status?: string; limit?: number }) =>
    api.get<AgentTask[]>(`/agents/${agentId}/tasks`, { params }),

  updateTask: (taskId: string, data: Partial<{ status: string; progress: number; result: Record<string, unknown>; error_message: string }>) =>
    api.patch<AgentTask>(`/agents/tasks/${taskId}`, data),

  cancelTask: (taskId: string) =>
    api.delete(`/agents/tasks/${taskId}`),

  // Authentication
  verifyAuth: (agentId: string, agentKey: string) =>
    api.post('/agents/auth/verify', { agent_id: agentId, agent_key: agentKey }),

  // Maintenance
  cleanupStale: (timeoutSeconds?: number) =>
    api.post('/agents/cleanup/stale', null, { params: { timeout_seconds: timeoutSeconds } }),

  purgeHeartbeats: (days?: number) =>
    api.delete('/agents/heartbeats/old', { params: { days } }),

  // Legacy WebSocket-based methods (kept for compatibility)
  getHealth: (agentId: string) =>
    api.get<AgentHealth>(`/agents/${agentId}/health`),

  sendCommand: (agentId: string, data: AgentCommandRequest) =>
    api.post<AgentCommandResponse>(`/agents/${agentId}/command`, data),

  startRemoteScan: (siteId: string, data: RemoteScanRequest) =>
    api.post<{ scan_id: string; status: string; message: string }>(`/agents/site/${siteId}/scan`, data),

  getRemoteScanProgress: (siteId: string, scanId: string) =>
    api.get(`/agents/site/${siteId}/scan/${scanId}`),

  fingerprintRemote: (siteId: string, ipAddress: string) =>
    api.post(`/agents/site/${siteId}/fingerprint`, null, { params: { ip_address: ipAddress } }),

  // Interactive scan (operator-triggered, WS push). The agent is sent
  // a scan_network command immediately; the returned task_id is then
  // polled via getScanStatus until status is terminal.
  runScan: (
    agentId: string,
    data: { scan_type?: string; targets?: string[]; timeout_seconds?: number },
  ) =>
    api.post<{
      task_id: string;
      agent_id: string;
      scan_type: string;
      status: string;
      dispatched_at: string;
      message: string;
    }>(`/agents/${agentId}/scan`, data),

  getScanStatus: (agentId: string, taskId: string) =>
    api.get<AgentTask>(`/agents/${agentId}/scan/${taskId}`),

  // List interactive (operator-triggered) scan tasks for an agent.
  // Wraps the existing /agents/{id}/tasks endpoint with a default
  // limit suited to the AgentDetailPage panel.
  listAdHocScans: (agentId: string, limit: number = 25) =>
    api.get<AgentTask[]>(`/agents/${agentId}/tasks`, {
      params: { status: undefined, limit },
    }),

  // Deep-probe a single host via the agent's FINGERPRINT_DEVICE
  // command. Mirrors runScan's response shape and task lifecycle.
  fingerprintHost: (agentId: string, ipAddress: string) =>
    api.post<{
      task_id: string;
      agent_id: string;
      scan_type: string;
      status: string;
      dispatched_at: string;
      message: string;
    }>(`/agents/${agentId}/fingerprint`, { ip_address: ipAddress }),
};

export const agentDownloadsApi = {
  // Get aggregated downloads page data
  getPageData: () =>
    api.get<DownloadsPageResponse>('/agents/downloads/page'),

  // Get latest release for platform/type
  getLatest: (platform: string, agentType: string = 'daemon') =>
    api.get<AgentReleaseLatest>('/agents/downloads/latest', { params: { platform, agent_type: agentType } }),

  // List all versions
  listVersions: (includePrerelease: boolean = false) =>
    api.get<AgentReleaseSummary[]>('/agents/downloads/versions', { params: { include_prerelease: includePrerelease } }),

  // Check for updates
  checkUpdate: (currentVersion: string, platform: string, agentType: string = 'daemon') =>
    api.get<AgentUpdateCheckResponse>('/agents/updates/check', { params: { current_version: currentVersion, platform, agent_type: agentType } }),

  // Publish a release (admin)
  publishRelease: (data: {
    version: string;
    platform: string;
    agent_type: string;
    download_url: string;
    checksum_sha256: string;
    file_size: number;
    release_notes?: string;
    is_prerelease?: boolean;
  }) => api.post('/agents/downloads/releases', data),

};

export interface AgentReleaseDetail {
  id: string;
  version: string;
  platform: string;
  agent_type: string;
  download_url: string;
  checksum_sha256: string;
  file_size: number;
  release_notes: string;
  min_backend_version: string;
  is_latest: boolean;
  is_prerelease: boolean;
  published_at: string;
  download_count: number;
}

export interface AgentRunRow {
  id: string;
  schedule_id: string;
  schedule_name: string | null;
  status: string;
  device_count: number;
  duration_seconds: number | null;
  error_message: string | null;
  started_at: string;
  completed_at: string | null;
}

export interface AgentDiscoveryRow {
  id: string;
  ip_address: string;
  mac_address: string | null;
  hostname: string | null;
  vendor: string | null;
  device_type: string | null;
  is_adopted: boolean;
  adopted_device_id: string | null;
  first_seen: string | null;
  last_seen: string | null;
}

export interface AgentTopologyRow {
  id: string;
  protocol: string;
  local_interface: string;
  neighbor_chassis_id: string;
  neighbor_port_id: string;
  neighbor_system_name: string | null;
  vlan_id: number | null;
  first_seen: string | null;
  last_seen: string | null;
}

export interface AgentScheduleRowDetail {
  id: string;
  name: string;
  scan_type: string;
  cron: string;
  targets: string[];
  enabled: boolean;
  last_fired_at: string | null;
  is_pinned: boolean;
}

export const agentDetailApi = {
  runs: (agentId: string, limit = 50) =>
    api.get<AgentRunRow[]>(`/agents/${agentId}/runs`, { params: { limit } }),
  discoveries: (agentId: string, limit = 100) =>
    api.get<AgentDiscoveryRow[]>(`/agents/${agentId}/discoveries`, { params: { limit } }),
  topology: (agentId: string, limit = 200) =>
    api.get<AgentTopologyRow[]>(`/agents/${agentId}/topology-edges`, { params: { limit } }),
  schedules: (agentId: string) =>
    api.get<AgentScheduleRowDetail[]>(`/agents/${agentId}/schedules`),
};

export const agentReleasesApi = {
  // Upload a release binary (admin). Backend stores the file, computes
  // SHA-256, and returns the new AgentRelease with download_url pointing
  // at the backend's own /releases/{id}/binary endpoint.
  upload: (form: FormData, onUploadProgress?: (p: any) => void) =>
    api.post<AgentReleaseDetail>('/agents/releases/upload', form, {
      headers: { 'Content-Type': 'multipart/form-data' },
      onUploadProgress,
    }),

  // List all releases (admin view, raw rows newest-first).
  list: (params: { platform?: string; agent_type?: string } = {}) =>
    api.get<AgentReleaseDetail[]>('/agents/releases', { params }),

  promote: (releaseId: string) =>
    api.patch<AgentReleaseDetail>(`/agents/releases/${releaseId}/promote`),

  remove: (releaseId: string) =>
    api.delete(`/agents/releases/${releaseId}`),
};

// ============================================================================
// Scheduled scans (backend-managed, pushed to agents via WS update_schedule)
// ============================================================================

export interface AgentScheduleInput {
  name: string;
  scan_type: string;
  cron: string;
  targets: string[];
  interface?: string | null;
  enabled?: boolean;
  agent_id?: string | null;
  notification_channels?: Record<string, unknown>;
  notify_on_failure?: boolean;
  notify_on_new_devices?: number;
}

export interface AgentSchedule {
  id: string;
  organization_id: string;
  site_id: string;
  agent_id: string | null;
  name: string;
  scan_type: string;
  cron: string;
  targets: string[];
  interface: string | null;
  enabled: boolean;
  last_fired_at: string | null;
  notification_channels?: Record<string, unknown>;
  notify_on_failure?: boolean;
  notify_on_new_devices?: number;
  created_at: string;
  updated_at: string;
}

export interface FleetOverview {
  agents_total: number;
  agents_online: number;
  agents_offline: number;
  schedules_total: number;
  schedules_enabled: number;
  runs_24h: number;
  runs_24h_failed: number;
  discovered_hosts_total: number;
  discovered_hosts_unadopted: number;
  last_run_at: string | null;
}

export interface FleetRun {
  id: string;
  schedule_id: string;
  schedule_name: string | null;
  agent_id: string | null;
  agent_name: string | null;
  site_id: string;
  site_name: string | null;
  status: string;
  device_count: number;
  duration_seconds: number | null;
  error_message: string | null;
  started_at: string;
  completed_at: string | null;
}

export const agentFleetApi = {
  overview: () => api.get<FleetOverview>('/agents/fleet/overview'),
  runs: (params: { limit?: number; status?: string } = {}) =>
    api.get<FleetRun[]>('/agents/fleet/runs', { params }),
};

export interface AgentScheduleRun {
  id: string;
  schedule_id: string;
  agent_id: string | null;
  status: string;
  device_count: number;
  duration_seconds: number | null;
  error_message: string | null;
  started_at: string;
  completed_at: string | null;
}

export const agentSchedulesApi = {
  list: (params: { site_id?: string; agent_id?: string } = {}) =>
    api.get<AgentSchedule[]>('/agents/schedules', { params }),
  create: (siteId: string, data: AgentScheduleInput) =>
    api.post<AgentSchedule>('/agents/schedules', data, { params: { site_id: siteId } }),
  update: (scheduleId: string, data: AgentScheduleInput) =>
    api.patch<AgentSchedule>(`/agents/schedules/${scheduleId}`, data),
  remove: (scheduleId: string) =>
    api.delete(`/agents/schedules/${scheduleId}`),
  listRuns: (scheduleId: string, limit = 50) =>
    api.get<AgentScheduleRun[]>(`/agents/schedules/${scheduleId}/runs`, {
      params: { limit },
    }),
};

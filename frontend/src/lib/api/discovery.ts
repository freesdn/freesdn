// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { api } from './client';
import type {
  ScanRequest, ScanResponse, ScanProgress, ScanResults, DiscoveredDevice,
  ControllerDiscoveryRequest, Driver, DriverDetails,
  AdoptDeviceRequest, AdoptDeviceResponse, BulkAdoptResponse,
  TestCredentialRequest, TestCredentialResponse,
  MatchDriverRequest, MatchDriverResponse, ScanHistoryItem,
} from './types';

export const discoveryApi = {
  startScan: (request: ScanRequest) =>
    api.post<ScanResponse>('/discovery/scan', request),

  getScanProgress: (scanId: string) =>
    api.get<ScanProgress>(`/discovery/scan/${scanId}/progress`),

  getScanResults: (scanId: string) =>
    api.get<ScanResults>(`/discovery/scan/${scanId}/results`),

  getLatestResults: () =>
    api.get<ScanResults>('/discovery/scans/latest/results'),

  cancelScan: (scanId: string) =>
    api.post(`/discovery/scan/${scanId}/cancel`),

  deleteScan: (scanId: string) =>
    api.delete(`/discovery/scan/${scanId}`),

  fingerprintDevice: (ip: string, ports?: number[], timeout?: number) =>
    api.post<DiscoveredDevice>('/discovery/fingerprint', { ip_address: ip, ports, timeout }),

  discoverFromController: (request: ControllerDiscoveryRequest) =>
    api.post<ScanResults>('/discovery/controller', request),

  discoverController: (controllerId: string, opts?: { sync?: boolean }) =>
    api.post<{ status: string; controller_id: string; stats?: Record<string, unknown>; message?: string }>(
      `/discovery/controllers/${controllerId}?sync=${opts?.sync ?? false}`
    ),

  discoverAll: () =>
    api.post<{ status: string; message: string }>('/discovery/all'),

  listDrivers: () =>
    api.get<Driver[]>('/discovery/drivers'),

  getDriverDetails: (driverId: string) =>
    api.get<DriverDetails>(`/discovery/drivers/${driverId}`),

  adoptDevice: (data: AdoptDeviceRequest) =>
    api.post<AdoptDeviceResponse>('/discovery/adopt', data),

  bulkAdoptDevices: (devices: AdoptDeviceRequest[]) =>
    api.post<BulkAdoptResponse>('/discovery/adopt/bulk', { devices }),

  testCredentials: (data: TestCredentialRequest) =>
    api.post<TestCredentialResponse>('/discovery/test-credentials', data),

  matchDrivers: (data: MatchDriverRequest) =>
    api.post<MatchDriverResponse>('/discovery/match-drivers', data),

  startAgentScan: (data: { agent_id: string; targets: string[]; scan_type?: string }) =>
    api.post<{ task_id: string; agent_id: string; status: string; message: string }>('/discovery/agent-scan', data),

  getAgentScanStatus: (taskId: string) =>
    api.get<{ task_id: string; status: string; progress: number; result: unknown }>(`/discovery/agent-scan/${taskId}`),

  getScanHistory: (limit?: number) =>
    api.get<ScanHistoryItem[]>('/discovery/scans/history', { params: { limit } }),

  // Persistent agent-discovered hosts (devices.discovered_hosts table).
  // Survives across scans + agent restarts; backend dedup keys on
  // (site_id, mac_address) primary with (site_id, ip_address) fallback.
  listDiscoveredHosts: (params: {
    site_id?: string;
    show_adopted?: boolean;
    show_ignored?: boolean;
    limit?: number;
    offset?: number;
  } = {}) =>
    api.get<AgentDiscoveredHost[]>('/discovery/discovered-hosts', { params }),

  // Agent-discovered topology graph: hosts + subnet groupings + LLDP edges.
  getDiscoveryTopology: (params: {
    site_id?: string;
    include_adopted?: boolean;
    limit?: number;
  } = {}) =>
    api.get<DiscoveryTopologyGraph>('/discovery/topology', { params }),
};

export interface DiscoveryTopologyHostNode {
  id: string;
  type: 'host';
  ip_address: string;
  mac_address: string | null;
  hostname: string | null;
  vendor: string | null;
  device_type: string | null;
  discovered_via: string[];
  is_adopted: boolean;
  adopted_device_id: string | null;
  site_id: string;
  subnet_id: string | null;
  last_seen: string | null;
}

export interface DiscoveryTopologySubnetNode {
  id: string;
  type: 'subnet';
  cidr: string;
  label: string;
  site_id: string;
  site_name: string;
  vlan_id: number | null;
  host_count: number;
}

export type DiscoveryTopologyNode =
  | DiscoveryTopologyHostNode
  | DiscoveryTopologySubnetNode;

export interface DiscoveryTopologyEdge {
  id: string;
  source: string;
  target: string;
  type: string;
  protocol?: string;
  local_interface?: string;
  neighbor_system_name?: string | null;
  neighbor_port_id?: string;
  vlan_id?: number | null;
  neighbor_device_id?: string | null;
}

export interface DiscoveryTopologySubnetSummary {
  id: string;
  cidr: string;
  label: string;
  site_id: string;
  site_name: string;
  vlan_id: number | null;
  host_count: number;
}

export interface DiscoveryTopologyGraph {
  nodes: DiscoveryTopologyNode[];
  edges: DiscoveryTopologyEdge[];
  subnets: DiscoveryTopologySubnetSummary[];
}

export interface AgentDiscoveredHost {
  id: string;
  site_id: string;
  organization_id: string;
  ip_address: string;
  mac_address: string | null;
  hostname: string | null;
  vendor: string | null;
  device_type: string | null;
  discovered_via: string[];
  open_ports: number[];
  services: Record<string, unknown>;
  mdns_services: string[];
  ssdp_info: Record<string, unknown> | null;
  http_title: string | null;
  http_server: string | null;
  lldp_chassis_id: string | null;
  lldp_port_id: string | null;
  lldp_system_name: string | null;
  lldp_capabilities: string[] | null;
  likely_device_types: string[];
  recommended_driver: string | null;
  is_adopted: boolean;
  adopted_device_id: string | null;
  ignored: boolean;
  first_seen: string | null;
  last_seen: string | null;
  discovered_by_agent_id: string | null;
  // Set when FreeSDN already knows this IP/MAC (controller appliance or
  // a managed / controller-synced device). null = genuinely new.
  known_as: {
    kind: 'controller' | 'controller_device' | 'device';
    name: string;
    detail: string;
    ref_type: string;
    ref_id: string;
    controller_type?: string;
    device_type?: string;
  } | null;
}

// Onboarding flows are served under ``/discovery/...``.

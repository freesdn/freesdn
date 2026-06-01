// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { api } from './client';
import type {
  VPNConnection, VPNConnectionCreate, VPNConnectionUpdate,
  VPNProviderInfo, VPNStatusSummary, VPNSubnet, SiteVPNConfig,
  TailscaleStatus, TailscaleNode, TailscaleSetupStatus,
  TailscaleAuthKeyLogin, TailscaleInteractiveLogin, TailscaleLoginResponse,
  TailscaleConfigureRequest, TailscaleActionResponse,
  NetbirdStatus, NetbirdPeer, BrainVPNDiscovery,
  VPNReconnectStatus, VPNEventList, VPNEventSummary,
  VPNHealthCheckRecord, VPNPreflightResult, VPNDeviceReachability,
  VPNMetricsBucket, VPNAggregateMetrics,
  VPNTunnelTemplate, VPNTunnelTemplateCreate, SiteToSiteTunnel,
  VPNDashboard, SiteVPNConfigList, VPNRouteConflictsResult,
  VPNCertExpiryResult, VPNKeyExchangeResult,
} from './types';

// P2 · Overlay mesh discovery — the connected tailnet/netbird as a device inventory.
export interface OverlayDiscoveredDevice {
  source: string; // 'tailscale' | 'netbird'
  hostname: string;
  magic_dns: string;
  address: string;
  online: boolean;
  os: string;
  tags: string[];
  suggested_type: string;
  confidence: string; // 'high' | 'medium' | 'low'
  already_adopted?: boolean; // cross-transport identity: already a managed device
  adopted_device_id?: string | null;
}
export interface OverlayDiscoveryResult {
  devices: OverlayDiscoveredDevice[];
  count: number;
  mode: string; // 'off' | 'sidecar' | 'userspace'
}

export const vpnApi = {
  // Providers
  listProviders: () =>
    api.get<{ providers: VPNProviderInfo[] }>('/vpn/providers'),

  // Overall status summary
  getStatus: () =>
    api.get<VPNStatusSummary>('/vpn/status'),

  // Connection CRUD
  listConnections: () =>
    api.get<VPNConnection[]>('/vpn/connections'),

  createConnection: (data: VPNConnectionCreate) =>
    api.post<VPNConnection>('/vpn/connections', data),

  getConnection: (id: string) =>
    api.get<VPNConnection>(`/vpn/connections/${encodeURIComponent(id)}`),

  updateConnection: (id: string, data: VPNConnectionUpdate) =>
    api.put<VPNConnection>(`/vpn/connections/${encodeURIComponent(id)}`, data),

  deleteConnection: (id: string) =>
    api.delete(`/vpn/connections/${encodeURIComponent(id)}`),

  connectionAction: (id: string, action: 'connect' | 'disconnect') =>
    api.post<{ success: boolean; message: string; connection_id: string }>(`/vpn/connections/${encodeURIComponent(id)}/action`, { action }),

  // Health History
  getHealthHistory: (id: string, hours?: number, limit?: number) =>
    api.get<VPNHealthCheckRecord[]>(`/vpn/connections/${encodeURIComponent(id)}/health-history`, {
      params: { hours, limit },
    }),

  // Reconnect Status
  getReconnectStatus: (id: string) =>
    api.get<VPNReconnectStatus>(`/vpn/connections/${encodeURIComponent(id)}/reconnect-status`),

  resetReconnect: (id: string) =>
    api.post<{ success: boolean; message: string }>(`/vpn/connections/${encodeURIComponent(id)}/reconnect-reset`),

  // Connection Metrics
  getConnectionMetrics: (id: string, hours?: number, interval?: '5m' | '1h' | '1d') =>
    api.get<VPNMetricsBucket[]>(`/vpn/connections/${encodeURIComponent(id)}/metrics`, {
      params: { hours, interval },
    }),

  // Subnets & connectivity
  listSubnets: () =>
    api.get<VPNSubnet[]>('/vpn/subnets'),

  checkConnectivity: (target: string) =>
    api.post<{ target: string; reachable: boolean; latency_ms?: number; connection_type?: string }>('/vpn/connectivity', { target }),

  // Pre-flight Checks
  preflight: {
    site: (siteId: string) =>
      api.post<VPNPreflightResult>(`/vpn/preflight/site/${encodeURIComponent(siteId)}`),
    device: (deviceId: string) =>
      api.post<VPNPreflightResult>(`/vpn/preflight/device/${encodeURIComponent(deviceId)}`),
  },

  // VPN Events
  events: {
    list: (params?: { site_id?: string; event_type?: string; severity?: string; hours?: number; limit?: number; offset?: number }) =>
      api.get<VPNEventList>('/vpn/events', { params }),
    summary: (hours?: number) =>
      api.get<VPNEventSummary>('/vpn/events/summary', { params: { hours } }),
  },

  // Aggregate Metrics
  getAggregateMetrics: () =>
    api.get<VPNAggregateMetrics>('/vpn/metrics/aggregate'),

  // Health Config
  updateHealthConfig: (siteId: string, params: { health_check_interval?: number; health_check_ip?: string; latency_threshold_ms?: number }) =>
    api.put(`/vpn/sites/${encodeURIComponent(siteId)}/health-config`, null, { params }),

  // Site Device Reachability
  getSiteReachability: (siteId: string) =>
    api.get<{ site_id: string; devices: VPNDeviceReachability[] }>(`/vpn/sites/${encodeURIComponent(siteId)}/reachability`),

  // Dashboard Widget
  getDashboard: () =>
    api.get<VPNDashboard>('/vpn/dashboard'),

  // P2 · Overlay mesh discovery (the tailnet/netbird peers as adoptable devices)
  getDiscovery: () =>
    api.get<OverlayDiscoveryResult>('/vpn/discovery'),

  // Tailscale endpoints
  tailscale: {
    getStatus: () =>
      api.get<TailscaleStatus>('/vpn/tailscale/status'),

    listDevices: () =>
      api.get<TailscaleNode[]>('/vpn/tailscale/devices'),

    getDevice: (name: string) =>
      api.get<TailscaleNode>(`/vpn/tailscale/devices/${encodeURIComponent(name)}`),

    ping: (target: string) =>
      api.post<{ target: string; reachable: boolean; latency_ms?: number }>('/vpn/tailscale/ping', null, { params: { target } }),

    discoverSubnet: (subnet: string) =>
      api.get(`/vpn/tailscale/discover/${encodeURIComponent(subnet)}`),

    // Setup & enrollment
    setup: {
      getStatus: () =>
        api.get<TailscaleSetupStatus>('/vpn/tailscale/setup/status'),

      startDaemon: () =>
        api.post<TailscaleActionResponse>('/vpn/tailscale/setup/start-daemon'),

      loginAuthKey: (data: TailscaleAuthKeyLogin) =>
        api.post<TailscaleLoginResponse>('/vpn/tailscale/setup/login-authkey', data),

      loginInteractive: (data?: TailscaleInteractiveLogin) =>
        api.post<TailscaleLoginResponse>('/vpn/tailscale/setup/login-interactive', data || {}),

      configure: (data: TailscaleConfigureRequest) =>
        api.post<TailscaleActionResponse>('/vpn/tailscale/setup/configure', data),

      disconnect: () =>
        api.post<TailscaleActionResponse>('/vpn/tailscale/setup/disconnect'),

      reconnect: () =>
        api.post<TailscaleActionResponse>('/vpn/tailscale/setup/reconnect'),

      logout: () =>
        api.post<TailscaleActionResponse>('/vpn/tailscale/setup/logout'),
    },
  },

  // WireGuard endpoints
  wireguard: {
    listInterfaces: () =>
      api.get<string[]>('/vpn/wireguard/interfaces'),

    getInterface: (iface: string) =>
      api.get<{ interface: string; healthy: boolean; status: string; last_handshake?: string }>(`/vpn/wireguard/interfaces/${encodeURIComponent(iface)}`),
  },

  // Netbird endpoints
  netbird: {
    getStatus: () =>
      api.get<NetbirdStatus>('/vpn/netbird/status'),

    listPeers: () =>
      api.get<NetbirdPeer[]>('/vpn/netbird/peers'),

    ping: (target: string) =>
      api.post<{ target: string; reachable: boolean; latency_ms?: number }>('/vpn/netbird/ping', null, { params: { target } }),
  },

  // OpenVPN endpoints
  openvpn: {
    listConnections: () =>
      api.get('/vpn/openvpn/connections'),

    getConnection: (name: string) =>
      api.get(`/vpn/openvpn/connections/${encodeURIComponent(name)}`),
  },

  // Site VPN configuration
  getSiteConfig: (siteId: string) =>
    api.get<SiteVPNConfig>(`/vpn/sites/${encodeURIComponent(siteId)}/config`),

  updateSiteConfig: (siteId: string, config: Partial<SiteVPNConfig>) =>
    api.put<SiteVPNConfig>(`/vpn/sites/${encodeURIComponent(siteId)}/config`, config),

  testSiteVPN: (siteId: string) =>
    api.post(`/vpn/sites/${encodeURIComponent(siteId)}/test`),

  // WireGuard agent provisioning
  provisionAgentWireGuard: (data: {
    site_id: string;
    server_public_key: string;
    server_endpoint: string;
    agent_address: string;
    site_subnets?: string[];
  }) => api.post<{
    agent_private_key: string;
    agent_public_key: string;
    agent_config: string;
    server_peer_block: string;
    agent_address: string;
    site_id: string;
    site_name: string;
  }>('/vpn/wireguard/provision-agent', data),

  // Brain VPN integration · connect via site's brain (firewall/gateway)
  brain: {
    discoverServers: (controllerId: string) =>
      api.get<BrainVPNDiscovery>(`/vpn/brain/${encodeURIComponent(controllerId)}/servers`),

    importConfig: (controllerId: string, data: {
      vpn_type: string;
      vpn_server_id: string;
      site_id?: string;
    }) => api.post<{
      success: boolean;
      message: string;
      vpn_config_id: string;
      vpn_type: string;
      vpn_endpoint: string;
      remote_subnets: string[];
    }>(`/vpn/brain/${encodeURIComponent(controllerId)}/import`, data),

    syncSubnets: (controllerId: string) =>
      api.post<{
        success: boolean;
        message: string;
        discovered: string[];
        added: number;
        total: number;
        controller: string;
      }>(`/vpn/brain/${encodeURIComponent(controllerId)}/sync-subnets`),
  },

  // OpenVPN config import
  importOpenVPNConfig: (data: {
    site_id: string;
    config_content: string;
    description?: string;
  }) => api.post<{
    success: boolean;
    message: string;
    vpn_config_id: string;
    vpn_endpoint: string;
    protocol: string;
    port: number;
  }>('/vpn/openvpn/import-config', data),

  // S2S Tunnel Orchestration
  orchestration: {
    listTemplates: (limit?: number, offset?: number) =>
      api.get<{ templates: VPNTunnelTemplate[]; total: number }>('/vpn/templates', { params: { limit, offset } }),

    createTemplate: (data: VPNTunnelTemplateCreate) =>
      api.post<VPNTunnelTemplate>('/vpn/templates', data),

    listTunnels: (status?: string, limit?: number, offset?: number) =>
      api.get<{ tunnels: SiteToSiteTunnel[]; total: number }>('/vpn/tunnels', { params: { status, limit, offset } }),

    getTunnel: (id: string) =>
      api.get<SiteToSiteTunnel>(`/vpn/tunnels/${encodeURIComponent(id)}`),

    getTunnelHealthHistory: (id: string, hours?: number, limit?: number) =>
      api.get<VPNHealthCheckRecord[]>(`/vpn/tunnels/${encodeURIComponent(id)}/health-history`, {
        params: { hours, limit },
      }),

    createTunnel: (data: { template_id: string; site_a_id: string; site_b_id: string; gateway_a_device_id?: string; gateway_b_device_id?: string }) =>
      api.post<SiteToSiteTunnel>('/vpn/tunnels', data),

    createMesh: (data: { template_id: string; site_ids: string[] }) =>
      api.post<SiteToSiteTunnel[]>('/vpn/tunnels/mesh', data),

    tunnelAction: (id: string, action: 'enable' | 'disable' | 'reprovision') =>
      api.post<{ success: boolean; message: string; tunnel_id: string; new_status: string }>(`/vpn/tunnels/${encodeURIComponent(id)}/action`, { action }),

    teardownTunnel: (id: string) =>
      api.delete(`/vpn/tunnels/${encodeURIComponent(id)}`),

    updateTemplate: (id: string, data: Partial<VPNTunnelTemplateCreate> & { mtu?: number; mss_clamp?: number }) =>
      api.put<VPNTunnelTemplate>(`/vpn/templates/${encodeURIComponent(id)}`, data),

    generateKeys: (tunnelId: string, params?: { site_a_endpoint?: string; site_b_endpoint?: string; site_a_port?: number; site_b_port?: number; mtu?: number }) =>
      api.post<VPNKeyExchangeResult>(`/vpn/tunnels/${encodeURIComponent(tunnelId)}/generate-keys`, null, { params }),

    pushConfig: (tunnelId: string, side: 'a' | 'b') =>
      api.post<{ success: boolean; message: string; device_id?: string }>(`/vpn/tunnels/${encodeURIComponent(tunnelId)}/push-config/${side}`),
  },

  // Multi-VPN Per Site
  siteConfigs: {
    list: (siteId: string) =>
      api.get<SiteVPNConfigList>(`/vpn/sites/${encodeURIComponent(siteId)}/configs`),

    create: (siteId: string, data: Partial<SiteVPNConfig>) =>
      api.post<SiteVPNConfig>(`/vpn/sites/${encodeURIComponent(siteId)}/configs`, data),

    remove: (siteId: string, configId: string) =>
      api.delete(`/vpn/sites/${encodeURIComponent(siteId)}/configs/${encodeURIComponent(configId)}`),

    setPrimary: (siteId: string, configId: string) =>
      api.put<{ success: boolean; primary_config_id: string }>(`/vpn/sites/${encodeURIComponent(siteId)}/configs/${encodeURIComponent(configId)}/primary`),
  },

  // Route Conflict Detection
  getRouteConflicts: () =>
    api.get<VPNRouteConflictsResult>('/vpn/routes/conflicts'),

  // Certificate Lifecycle
  certs: {
    getExpiring: (days?: number) =>
      api.get<VPNCertExpiryResult>('/vpn/certs/expiring', { params: { days } }),

    scan: () =>
      api.post<{ scanned: number; updated: number; errors: number }>('/vpn/certs/scan'),
  },
};

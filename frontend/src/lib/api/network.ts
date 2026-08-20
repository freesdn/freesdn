// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { api } from './client';
import type {
  SwitchSummary, SwitchPort, SwitchPortProfile, SwitchLAG,
  STPConfig, ACLRule, IGMPConfig, MirrorConfig, StaticRoute,
  DHCPSnoopingConfig, QoSConfig, MACTableEntry, LLDPNeighbor,
  SwitchEvent, SwitchClient, BandwidthControl, StormControl,
  CableTestResult, PingResult, TracerouteResult,
  OUIVlanApplyRequest, OUIVlanApplyResult, CLIProfileApplyRequest, CLIProfileApplyResult,
  AccessPointSummary, AccessPointDetail, APRadio, APSsidOverride, APClient, APFirmwareInfo,
  PoEPortStatus, PoESwitchSummary, PoESchedule,
  Vlan, VlanCreate, VlanUpdate, VlanListResponse,
  WifiNetwork, WifiNetworkCreate, WifiNetworkUpdate, WifiNetworkListResponse,
  NetworkClient, NetworkClientUpdate, NetworkClientListResponse,
  NetworkDevice, NetworkDeviceListResponse,
  SwitchPortConfig, SwitchPortUpdate,
  NetworkTopology, NetworkSummary,
  PaginatedResponse,
} from './types';

export const accessPointsApi = {
  // List & Detail
  listAccessPoints: (params?: { site_id?: string; status?: string; page?: number; per_page?: number }) =>
    api.get<PaginatedResponse<AccessPointSummary>>('/access-points/', { params }),

  getAccessPoint: (apId: string) =>
    api.get<AccessPointDetail>(`/access-points/${apId}`),

  // Clients
  getClients: (apId: string) =>
    api.get<APClient[]>(`/access-points/${apId}/clients`),

  // Radios
  getRadios: (apId: string) =>
    api.get<APRadio[]>(`/access-points/${apId}/radios`),

  updateRadio: (apId: string, band: string, data: Partial<APRadio>) =>
    api.patch(`/access-points/${apId}/radios/${band}`, data),

  // SSID Overrides
  getSsidOverrides: (apId: string) =>
    api.get<APSsidOverride[]>(`/access-points/${apId}/ssid-overrides`),

  updateSsidOverrides: (apId: string, data: APSsidOverride[]) =>
    api.put(`/access-points/${apId}/ssid-overrides`, data),

  // LAN Port
  getLanPort: (apId: string) =>
    api.get(`/access-points/${apId}/lan-port`),

  updateLanPort: (apId: string, data: { vlan_enable?: boolean; vlan_id?: number }) =>
    api.patch(`/access-points/${apId}/lan-port`, data),

  // Actions
  //
  // These three take a destructive-action acknowledgement as a QUERY parameter
  // and reject the call without it, so every one of them failed after the
  // operator had already confirmed in the UI dialog. Note the backend spells it
  // two different ways -- `confirm` for reboot (access_points.py) and
  // `confirmed` for forget/upgrade -- which is exactly the sort of asymmetry a
  // path+verb contract check cannot see.
  //
  // AccessPointsPage gates all three behind openConfirmDialog/handleConfirmAction,
  // so the operator HAS acknowledged by the time these run.
  reboot: (apId: string) =>
    api.post(`/access-points/${apId}/reboot?confirm=true`),

  locate: (apId: string) =>
    api.post(`/access-points/${apId}/locate`),

  adopt: (apId: string) =>
    api.post(`/access-points/${apId}/adopt`),

  forget: (apId: string) =>
    api.post(`/access-points/${apId}/forget?confirmed=true`),

  upgrade: (apId: string) =>
    api.post(`/access-points/${apId}/upgrade?confirmed=true`),

  setLed: (apId: string, enabled: boolean) =>
    api.patch(`/access-points/${apId}/led`, { setting: enabled ? 1 : 0 }),  // body: LEDUpdateIn.setting

  setMesh: (apId: string, enabled: boolean) =>
    api.patch(`/access-points/${apId}/mesh`, { enabled }),  // body: MeshUpdateIn.enabled

  rename: (apId: string, name: string) =>
    api.patch(`/access-points/${apId}/name`, { name }),

  getFirmware: (apId: string) =>
    api.get<APFirmwareInfo>(`/access-points/${apId}/firmware`),

  getRfScan: (apId: string) =>
    api.get(`/access-points/${apId}/rf-scan`),

  setLocation: (apId: string, data: { latitude: number; longitude: number; height?: number }) =>
    api.patch(`/access-points/${apId}/location`, data),
};

export const switchesApi = {
  // Switches
  listSwitches: (params?: {
    site_id?: string;
    status?: string;
    vendor?: string;
    poe_capable?: boolean;
    page?: number;
    per_page?: number;
  }) => api.get<PaginatedResponse<SwitchSummary>>('/switches/', { params }),

  getSwitch: (switchId: string) =>
    api.get<SwitchSummary>(`/switches/${switchId}`),

  // VLANs
  getVlans: (switchId: string) =>
    api.get<Array<{
      id: string;
      vlan_id: number;
      name: string;
      description?: string;
      purpose?: string;
      gateway?: string;
      subnet?: string;
      cidr?: string;
      dhcp_enabled?: boolean;
      untagged_ports: number;
      tagged_ports: number;
    }>>(`/switches/${switchId}/vlans`),

  // Ports
  listPorts: (switchId: string, params?: {
    status?: string;
    vlan_id?: number;
    poe_enabled?: boolean;
  }) => api.get<SwitchPort[]>(`/switches/${switchId}/ports`, { params }),

  getPort: (switchId: string, portIndex: number) =>
    api.get<SwitchPort>(`/switches/${switchId}/ports/${portIndex}`),

  updatePort: (switchId: string, portIndex: number, data: Partial<SwitchPort>) =>
    api.patch<SwitchPort>(`/switches/${switchId}/ports/${portIndex}`, data),

  bulkUpdatePorts: (switchId: string, data: {
    port_ids: string[];
    updates: Partial<SwitchPort>;
  }) => api.post<SwitchPort[]>(`/switches/${switchId}/ports/bulk`, data),

  // Port Profiles
  listProfiles: (siteId?: string) =>
    api.get<SwitchPortProfile[]>('/switches/profiles', { params: { site_id: siteId } }),

  getProfile: (profileId: string) =>
    api.get<SwitchPortProfile>(`/switches/profiles/${profileId}`),

  createProfile: (data: Partial<SwitchPortProfile>) =>
    api.post<SwitchPortProfile>('/switches/profiles', data),

  updateProfile: (profileId: string, data: Partial<SwitchPortProfile>) =>
    api.put<SwitchPortProfile>(`/switches/profiles/${profileId}`, data),

  deleteProfile: (profileId: string) =>
    api.delete(`/switches/profiles/${profileId}`),

  applyProfile: (switchId: string, data: {
    profile_id: string;
    port_ids: string[];
  }) => api.post(`/switches/${switchId}/apply-profile`, data),

  // LAGs
  listLAGs: (switchId: string) =>
    api.get<SwitchLAG[]>(`/switches/${switchId}/lags`),

  createLAG: (switchId: string, data: Partial<SwitchLAG>) =>
    api.post<SwitchLAG>(`/switches/${switchId}/lags`, data),

  updateLAG: (switchId: string, lagId: number, data: Partial<SwitchLAG>) =>
    api.put<SwitchLAG>(`/switches/${switchId}/lags/${lagId}`, data),

  deleteLAG: (switchId: string, lagId: number) =>
    api.delete(`/switches/${switchId}/lags/${lagId}`),

  // Port Actions
  togglePort: (switchId: string, portIndex: number, enabled: boolean) =>
    api.post(`/switches/${switchId}/ports/${portIndex}/toggle`, { enabled }),

  togglePoe: (switchId: string, portIndex: number, enabled: boolean) =>
    api.post(`/switches/${switchId}/ports/${portIndex}/poe`, { enabled }),

  cyclePoe: (switchId: string, portIndex: number) =>
    api.post(`/switches/${switchId}/ports/${portIndex}/poe/cycle`),

  // STP / RSTP
  getStpConfig: (switchId: string) =>
    api.get<STPConfig>(`/switches/${switchId}/stp`),
  updateStpConfig: (switchId: string, config: Partial<STPConfig>) =>
    api.put(`/switches/${switchId}/stp`, config),

  // ACL Rules
  getAclRules: (switchId: string) =>
    api.get<ACLRule[]>(`/switches/${switchId}/acl`),
  createAclRule: (switchId: string, config: Partial<ACLRule>) =>
    api.post(`/switches/${switchId}/acl`, config),
  updateAclRule: (switchId: string, ruleId: string, config: Partial<ACLRule>) =>
    api.put(`/switches/${switchId}/acl/${ruleId}`, config),
  deleteAclRule: (switchId: string, ruleId: string) =>
    api.delete(`/switches/${switchId}/acl/${ruleId}`),

  // IGMP Snooping
  getIgmpConfig: (switchId: string) =>
    api.get<IGMPConfig>(`/switches/${switchId}/igmp`),
  updateIgmpConfig: (switchId: string, config: Partial<IGMPConfig>) =>
    api.put(`/switches/${switchId}/igmp`, config),

  // Port Isolation
  setPortIsolation: (switchId: string, portIndex: number, enabled: boolean) =>
    api.post(`/switches/${switchId}/ports/${portIndex}/isolation`, { enabled }),

  // Port Mirroring
  getMirrorConfig: (switchId: string) =>
    api.get<MirrorConfig>(`/switches/${switchId}/mirror`),
  updateMirrorConfig: (switchId: string, config: Partial<MirrorConfig>) =>
    api.put(`/switches/${switchId}/mirror`, config),

  // Static Routes
  getStaticRoutes: (switchId: string) =>
    api.get<StaticRoute[]>(`/switches/${switchId}/routes`),

  // DHCP
  getDhcpConfig: (switchId: string) =>
    api.get(`/switches/${switchId}/dhcp`),
  getDhcpSnoopingConfig: (switchId: string) =>
    api.get<DHCPSnoopingConfig>(`/switches/${switchId}/dhcp/snooping`),
  updateDhcpSnoopingConfig: (switchId: string, config: Partial<DHCPSnoopingConfig>) =>
    api.put(`/switches/${switchId}/dhcp/snooping`, config),

  // QoS
  getQosConfig: (switchId: string) =>
    api.get<QoSConfig>(`/switches/${switchId}/qos`),
  updateQosConfig: (switchId: string, config: Partial<QoSConfig>) =>
    api.put(`/switches/${switchId}/qos`, config),

  // Refresh switch data (triggers live sync from controller)
  refreshSwitch: (switchId: string) =>
    api.post<{ success: boolean; clients_synced: number; connected_clients: number; mac_table_entries: number; controller_reported_clients: number }>(`/switches/${switchId}/refresh`),

  // MAC Address Table
  getMacTable: (switchId: string) =>
    api.get<MACTableEntry[]>(`/switches/${switchId}/mac-table`),

  // LLDP Neighbors
  getLldpNeighbors: (switchId: string) =>
    api.get<LLDPNeighbor[]>(`/switches/${switchId}/lldp`),

  // Port LLDP Toggle
  setPortLldp: (switchId: string, portIndex: number, enabled: boolean) =>
    api.post(`/switches/${switchId}/ports/${portIndex}/lldp`, { enabled }),

  // Port Flow Control
  setPortFlowControl: (switchId: string, portIndex: number, enabled: boolean) =>
    api.post(`/switches/${switchId}/ports/${portIndex}/flow-control`, { enabled }),

  // Port Speed/Duplex
  setPortSpeedDuplex: (switchId: string, portIndex: number, speed: string, duplex: string) =>
    api.post(`/switches/${switchId}/ports/${portIndex}/speed`, { speed, duplex }),

  // Port Loopback Detection
  setPortLoopbackDetect: (switchId: string, portIndex: number, enabled: boolean) =>
    api.post(`/switches/${switchId}/ports/${portIndex}/loopback-detect`, { enabled }),

  // Device Events & Alerts
  getEvents: (switchId: string, limit?: number) =>
    api.get<SwitchEvent[]>(`/switches/${switchId}/events`, { params: { limit: limit ?? 100 } }),
  getAlerts: (switchId: string, limit?: number) =>
    api.get<SwitchEvent[]>(`/switches/${switchId}/alerts`, { params: { limit: limit ?? 100 } }),

  // Connected Clients
  getClients: (switchId: string) =>
    api.get<SwitchClient[]>(`/switches/${switchId}/clients`),

  // Bandwidth Control
  setPortBandwidth: (switchId: string, portIndex: number, config: BandwidthControl) =>
    api.post(`/switches/${switchId}/ports/${portIndex}/bandwidth`, config),

  // Storm Control
  setPortStormControl: (switchId: string, portIndex: number, config: StormControl) =>
    api.post(`/switches/${switchId}/ports/${portIndex}/storm-control`, config),

  // PoE Schedules (via adapter/controller)
  getPoESchedules: (switchId: string) =>
    api.get(`/switches/${switchId}/poe-schedules`),
  createPoESchedule: (switchId: string, config: Record<string, unknown>) =>
    api.post(`/switches/${switchId}/poe-schedules`, config),
  updatePoESchedule: (switchId: string, scheduleId: string, config: Record<string, unknown>) =>
    api.put(`/switches/${switchId}/poe-schedules/${scheduleId}`, config),
  deletePoESchedule: (switchId: string, scheduleId: string) =>
    api.delete(`/switches/${switchId}/poe-schedules/${scheduleId}`),

  // Diagnostics
  runCableTest: (switchId: string, port: number) =>
    api.post<CableTestResult>(`/switches/${switchId}/diagnostics/cable-test`, { port }),
  runPing: (switchId: string, target: string, count?: number) =>
    api.post<PingResult>(`/switches/${switchId}/diagnostics/ping`, { target, count: count ?? 5 }),
  runTraceroute: (switchId: string, target: string, maxHops?: number) =>
    api.post<TracerouteResult>(`/switches/${switchId}/diagnostics/traceroute`, { target, max_hops: maxHops ?? 30 }),

  // OUI VLAN Assignment
  applyOuiVlan: (switchId: string, data: OUIVlanApplyRequest) =>
    api.post<OUIVlanApplyResult>(`/switches/${switchId}/oui-vlan/apply`, data),

  // CLI Profiles
  applyCLIProfile: (switchId: string, data: CLIProfileApplyRequest) =>
    api.post<CLIProfileApplyResult>(`/switches/${switchId}/cli-profile/apply`, data),

  // Bulk VLAN port assignments
  bulkVlanAssignment: (switchId: string, data: { assignments: Array<{ port_index: number; native_vlan: number | null; tagged_vlans: number[] }> }) =>
    api.put(`/switches/${switchId}/vlans/port-assignments`, data),
};

export const poeApi = {
  // List PoE ports with filtering
  listPorts: (params?: {
    site_id?: string;
    device_id?: string;
    status?: string;
    enabled?: boolean;
    page?: number;
    page_size?: number;
  }) => api.get<PoEPortStatus[]>('/poe/ports', { params }),

  // Get PoE switch/device summaries
  listSwitches: (siteId?: string) =>
    api.get<PoESwitchSummary[]>('/poe/devices', { params: { site_id: siteId } }),

  // Get single switch/device PoE summary
  getSwitch: (deviceId: string) =>
    api.get<PoESwitchSummary>(`/poe/devices/${deviceId}`),

  // Get all ports for a specific device
  getDevicePorts: (deviceId: string) =>
    api.get<PoEPortStatus[]>(`/poe/devices/${deviceId}/ports`),

  // Update port PoE settings
  updatePort: (portId: string, data: {
    poe_enabled?: boolean;
    poe_mode?: string;
    power_limit?: number;
    priority?: number;
  }) => api.patch(`/poe/ports/${portId}`, data),

  // Cycle PoE port (reset)
  cyclePort: (portId: string) =>
    api.post(`/poe/ports/${portId}/reset`),

  // Bulk PoE update
  bulkUpdate: (data: {
    port_ids: string[];
    poe_enabled?: boolean;
    poe_mode?: string;
    power_limit?: number;
  }) => api.post('/poe/ports/bulk', data),

  // Schedules
  listSchedules: (siteId?: string) =>
    api.get<PoESchedule[]>('/poe/schedules', { params: { site_id: siteId } }),

  createSchedule: (siteId: string, data: Omit<PoESchedule, 'id' | 'affected_ports' | 'next_trigger'>) =>
    api.post<PoESchedule>('/poe/schedules', data, { params: { site_id: siteId } }),

  updateSchedule: (id: string, data: Partial<PoESchedule>) =>
    api.put<PoESchedule>(`/poe/schedules/${id}`, data),

  deleteSchedule: (id: string) =>
    api.delete(`/poe/schedules/${id}`),
};

// Network API
export const networkApi = {
  // VLANs
  vlans: {
    list: (params?: { site_id?: string; skip?: number; limit?: number }) =>
      api.get<VlanListResponse>('/network/vlans', { params }),

    get: (id: string) =>
      api.get<Vlan>(`/network/vlans/${id}`),

    create: (data: VlanCreate) =>
      api.post<Vlan>('/network/vlans', data),

    update: (id: string, data: VlanUpdate) =>
      api.patch<Vlan>(`/network/vlans/${id}`, data),

    delete: (id: string) =>
      api.delete(`/network/vlans/${id}`),
  },

  // WiFi Networks
  wifi: {
    list: (params?: { site_id?: string; enabled?: boolean; skip?: number; limit?: number }) =>
      api.get<WifiNetworkListResponse>('/network/wifi', { params }),

    get: (id: string) =>
      api.get<WifiNetwork>(`/network/wifi/${id}`),

    create: (data: WifiNetworkCreate) =>
      api.post<WifiNetwork>('/network/wifi', data),

    update: (id: string, data: WifiNetworkUpdate) =>
      api.patch<WifiNetwork>(`/network/wifi/${id}`, data),

    delete: (id: string) =>
      api.delete(`/network/wifi/${id}`),

    toggle: (id: string, enabled: boolean) =>
      api.post<WifiNetwork>(`/network/wifi/${id}/toggle`, { enabled }),
  },

  // Network Clients
  clients: {
    list: (params?: {
      site_id?: string;
      connection_type?: string;
      status?: string;
      blocked?: boolean;
      search?: string;
      skip?: number;
      limit?: number;
    }) => api.get<NetworkClientListResponse>('/network/clients', { params }),

    get: (id: string) =>
      api.get<NetworkClient>(`/network/clients/${id}`),

    update: (id: string, data: NetworkClientUpdate) =>
      api.put<NetworkClient>(`/network/clients/${id}`, data),

    block: (id: string) =>
      api.post<NetworkClient>(`/network/clients/${id}/block`),

    unblock: (id: string) =>
      api.post<NetworkClient>(`/network/clients/${id}/unblock`),
  },

  // Network Devices (switches, APs, etc.)
  devices: {
    list: (params?: { site_id?: string; device_type?: string; status?: string; skip?: number; limit?: number }) =>
      api.get<NetworkDeviceListResponse>('/network/devices', { params }),

    get: (id: string) =>
      api.get<NetworkDevice>(`/network/devices/${id}`),
  },

  // Switch Ports
  ports: {
    listByDevice: (deviceId: string) =>
      api.get<SwitchPortConfig[]>(`/network/devices/${deviceId}/ports`),

    get: (deviceId: string, portNumber: number) =>
      api.get<SwitchPortConfig>(`/network/devices/${deviceId}/ports/${portNumber}`),

    update: (deviceId: string, portNumber: number, data: SwitchPortUpdate) =>
      api.patch<SwitchPortConfig>(`/network/devices/${deviceId}/ports/${portNumber}`, data),

    setPoe: (deviceId: string, portNumber: number, enabled: boolean) =>
      api.post<SwitchPortConfig>(`/network/devices/${deviceId}/ports/${portNumber}/poe`, { enabled }),

    setVlan: (deviceId: string, portNumber: number, nativeVlan: number, taggedVlans?: number[]) =>
      api.post<SwitchPortConfig>(`/network/devices/${deviceId}/ports/${portNumber}/vlan`, {
        native_vlan: nativeVlan,
        tagged_vlans: taggedVlans,
      }),
  },

  // Network Topology
  topology: {
    get: (siteId?: string) =>
      api.get<NetworkTopology>('/network/topology', { params: { site_id: siteId } }),
  },

  // Network Summary
  summary: {
    get: (siteId?: string) =>
      api.get<NetworkSummary>('/network/summary', { params: { site_id: siteId } }),
  },

  // VLAN Alignment
  getVlanAlignment: (siteId: string) =>
    api.get('/network/vlans/alignment', { params: { site_id: siteId } }),

  distributeVlan: (sourceNetworkId: string, targetControllerIds: string[]) =>
    api.post('/network/vlans/distribute', {
      source_network_id: sourceNetworkId,
      target_controller_ids: targetControllerIds,
    }),
};

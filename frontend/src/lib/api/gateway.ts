// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { api } from './client';
import type {
  GatewayConnection, GatewayConnectionCreate, GatewayConnectionUpdate,
  GatewayTestRequest, GatewayTestResponse, GatewaySummary, GatewaySyncLog,
  GatewayRulePushRequest, GatewayWriteResponse,
  DNSOverrideRequest, DNSDomainOverrideRequest,
  DHCPStaticMappingRequest, PortForwardRequest, SourceNATRuleRequest,
  AliasRequest, WireGuardServerRequest, WireGuardPeerRequest,
  OpenVPNInstanceRequest, StaticRouteRequest,
  IDSSettingsUpdateRequest, IDSControlRequest,
  ShaperPipeRequest, ShaperQueueRequest, ShaperRuleRequest,
  DiagnosticPingRequest, DiagnosticTracerouteRequest, DiagnosticDNSLookupRequest,
  ServiceControlRequest,
  SiteRoleMapResponse, SiteRoleMapUpdate, TopologyValidationResult,
  CanonicalVLANCreate, CanonicalVLANUpdate, CanonicalVLANResponse,
  CanonicalVLANDetailResponse, CanonicalVLANListResponse,
  DHCPScopeCreate, DHCPScopeResponse, DHCPReservationCreate, DHCPReservationResponse,
  DNSRecordCreate, DNSRecordUpdate, DNSRecordResponse,
  DistributionTriggerRequest, DistributionRetractRequest, DistributionResponse,
  DriftEventResponse, DriftResolveRequest, DriftSummaryResponse, DriftCheckResponse,
  SuppressionRuleCreate, SuppressionRuleResponse,
  ImportSessionCreate, ImportSessionStep, ImportSessionResponse,
  GatewayDashboardOverview,
  ImportedFirewallRuleResponse, ImportedNATRuleResponse,
  ImportedVPNTunnelResponse, ImportedIDSEventResponse,
  ImportedInterfaceResponse, ImportedDHCPLeaseResponse,
  VLANTemplateCreate, VLANTemplateUpdate, VLANTemplateResponse,
  VLANTemplateListResponse, TemplateApplyResponse,
  GatewayPingRequest, GatewayTracerouteRequest, GatewayDNSLookupRequest,
  GatewayServiceRestartRequest,
} from './types';

// Helper to encode path segments safely. All path-segment interpolations
// in this file (gateway IDs, vendor IDs, filenames, service names, etc.)
// flow through this, never let raw values land in a URL.
const enc = (segment: string) => encodeURIComponent(String(segment ?? ''));

export const gatewayApi = {
  // CRUD
  getAll: (params?: { site_id?: string; vendor?: string; is_online?: boolean; skip?: number; limit?: number }) =>
    api.get<{ items: GatewayConnection[]; total: number }>('/firewall/gateways', { params }),

  getById: (id: string) =>
    api.get<GatewayConnection>(`/firewall/gateways/${enc(id)}`),

  create: (data: GatewayConnectionCreate) =>
    api.post<GatewayConnection>('/firewall/gateways', data),

  update: (id: string, data: GatewayConnectionUpdate) =>
    api.patch<GatewayConnection>(`/firewall/gateways/${enc(id)}`, data),

  delete: (id: string) =>
    api.delete(`/firewall/gateways/${enc(id)}`),

  // Summary
  getSummary: (params?: { site_id?: string }) =>
    api.get<GatewaySummary>('/firewall/gateways/summary', { params }),

  // Connection Test
  testConnection: (data: GatewayTestRequest) =>
    api.post<GatewayTestResponse>('/firewall/gateways/test', data),

  // Optional overrides test edited-but-unsaved settings (e.g. a toggled
  // Verify SSL, or changed host/port) against the gateway's STORED creds, so
  // the edit dialog's Test Connection honors the live form without saving first.
  testExisting: (id: string, overrides?: { verify_ssl?: boolean; host?: string; port?: number }) =>
    api.post<GatewayTestResponse>(`/firewall/gateways/${enc(id)}/test`, overrides ?? {}),

  // Sync
  triggerSync: (id: string, fullSync?: boolean) =>
    api.post(`/firewall/gateways/${enc(id)}/sync`, { full_sync: fullSync }),

  getSyncLogs: (id: string, params?: { skip?: number; limit?: number }) =>
    api.get<GatewaySyncLog[]>(`/firewall/gateways/${enc(id)}/sync-logs`, { params }),

  // Live Data
  getStatus: (id: string) =>
    api.get(`/firewall/gateways/${enc(id)}/status`),

  getFirewallRules: (id: string) =>
    api.get(`/firewall/gateways/${enc(id)}/firewall-rules`),

  getNATRules: (id: string) =>
    api.get(`/firewall/gateways/${enc(id)}/nat-rules`),

  getVPN: (id: string) =>
    api.get(`/firewall/gateways/${enc(id)}/vpn`),

  getInterfaces: (id: string) =>
    api.get(`/firewall/gateways/${enc(id)}/interfaces`),

  getDHCP: (id: string) =>
    api.get(`/firewall/gateways/${enc(id)}/dhcp`),

  getServices: (id: string) =>
    api.get(`/firewall/gateways/${enc(id)}/services`),

  // Rule Push
  pushRule: (id: string, data: GatewayRulePushRequest) =>
    api.post(`/firewall/gateways/${enc(id)}/firewall-rules`, data),

  deleteVendorRule: (id: string, vendorRuleId: string) =>
    api.delete(`/firewall/gateways/${enc(id)}/firewall-rules/${enc(vendorRuleId)}`),

  // DNS Host Overrides
  getDNSOverrides: (id: string) =>
    api.get(`/firewall/gateways/${enc(id)}/dns/overrides`),

  createDNSOverride: (id: string, data: DNSOverrideRequest) =>
    api.post<GatewayWriteResponse>(`/firewall/gateways/${enc(id)}/dns/overrides`, data),

  updateDNSOverride: (id: string, vendorId: string, data: DNSOverrideRequest) =>
    api.put<GatewayWriteResponse>(`/firewall/gateways/${enc(id)}/dns/overrides/${enc(vendorId)}`, data),

  deleteDNSOverride: (id: string, vendorId: string) =>
    api.delete<GatewayWriteResponse>(`/firewall/gateways/${enc(id)}/dns/overrides/${enc(vendorId)}`),

  // DNS Domain Overrides
  getDNSDomainOverrides: (id: string) =>
    api.get(`/firewall/gateways/${enc(id)}/dns/domain-overrides`),

  createDNSDomainOverride: (id: string, data: DNSDomainOverrideRequest) =>
    api.post<GatewayWriteResponse>(`/firewall/gateways/${enc(id)}/dns/domain-overrides`, data),

  updateDNSDomainOverride: (id: string, vendorId: string, data: DNSDomainOverrideRequest) =>
    api.put<GatewayWriteResponse>(`/firewall/gateways/${enc(id)}/dns/domain-overrides/${enc(vendorId)}`, data),

  deleteDNSDomainOverride: (id: string, vendorId: string) =>
    api.delete<GatewayWriteResponse>(`/firewall/gateways/${enc(id)}/dns/domain-overrides/${enc(vendorId)}`),

  // DHCP Static Mappings
  getDHCPStaticMappings: (id: string) =>
    api.get(`/firewall/gateways/${enc(id)}/dhcp/static-mappings`),

  createDHCPStaticMapping: (id: string, data: DHCPStaticMappingRequest) =>
    api.post<GatewayWriteResponse>(`/firewall/gateways/${enc(id)}/dhcp/static-mappings`, data),

  updateDHCPStaticMapping: (id: string, vendorId: string, data: DHCPStaticMappingRequest) =>
    api.put<GatewayWriteResponse>(`/firewall/gateways/${enc(id)}/dhcp/static-mappings/${enc(vendorId)}`, data),

  deleteDHCPStaticMapping: (id: string, vendorId: string) =>
    api.delete<GatewayWriteResponse>(`/firewall/gateways/${enc(id)}/dhcp/static-mappings/${enc(vendorId)}`),

  // Port Forwards
  getPortForwards: (id: string) =>
    api.get(`/firewall/gateways/${enc(id)}/port-forwards`),

  createPortForward: (id: string, data: PortForwardRequest) =>
    api.post<GatewayWriteResponse>(`/firewall/gateways/${enc(id)}/port-forwards`, data),

  updatePortForward: (id: string, vendorId: string, data: PortForwardRequest) =>
    api.put<GatewayWriteResponse>(`/firewall/gateways/${enc(id)}/port-forwards/${enc(vendorId)}`, data),

  deletePortForward: (id: string, vendorId: string) =>
    api.delete<GatewayWriteResponse>(`/firewall/gateways/${enc(id)}/port-forwards/${enc(vendorId)}`),

  // Source NAT
  createSourceNATRule: (id: string, data: SourceNATRuleRequest) =>
    api.post<GatewayWriteResponse>(`/firewall/gateways/${enc(id)}/source-nat`, data),

  deleteSourceNATRule: (id: string, vendorId: string) =>
    api.delete<GatewayWriteResponse>(`/firewall/gateways/${enc(id)}/source-nat/${enc(vendorId)}`),

  // Aliases
  getAliases: (id: string) =>
    api.get(`/firewall/gateways/${enc(id)}/aliases`),

  createAlias: (id: string, data: AliasRequest) =>
    api.post<GatewayWriteResponse>(`/firewall/gateways/${enc(id)}/aliases`, data),

  updateAlias: (id: string, vendorId: string, data: AliasRequest) =>
    api.put<GatewayWriteResponse>(`/firewall/gateways/${enc(id)}/aliases/${enc(vendorId)}`, data),

  deleteAlias: (id: string, vendorId: string) =>
    api.delete<GatewayWriteResponse>(`/firewall/gateways/${enc(id)}/aliases/${enc(vendorId)}`),

  // WireGuard
  getWireGuard: (id: string) =>
    api.get(`/firewall/gateways/${enc(id)}/wireguard`),

  createWireGuardServer: (id: string, data: WireGuardServerRequest) =>
    api.post<GatewayWriteResponse>(`/firewall/gateways/${enc(id)}/wireguard/servers`, data),

  deleteWireGuardServer: (id: string, vendorId: string) =>
    api.delete<GatewayWriteResponse>(`/firewall/gateways/${enc(id)}/wireguard/servers/${enc(vendorId)}`),

  createWireGuardPeer: (id: string, data: WireGuardPeerRequest) =>
    api.post<GatewayWriteResponse>(`/firewall/gateways/${enc(id)}/wireguard/peers`, data),

  deleteWireGuardPeer: (id: string, vendorId: string) =>
    api.delete<GatewayWriteResponse>(`/firewall/gateways/${enc(id)}/wireguard/peers/${enc(vendorId)}`),

  // OpenVPN
  getOpenVPN: (id: string) =>
    api.get(`/firewall/gateways/${enc(id)}/openvpn`),

  createOpenVPNInstance: (id: string, data: OpenVPNInstanceRequest) =>
    api.post<GatewayWriteResponse>(`/firewall/gateways/${enc(id)}/openvpn/instances`, data),

  deleteOpenVPNInstance: (id: string, vendorId: string) =>
    api.delete<GatewayWriteResponse>(`/firewall/gateways/${enc(id)}/openvpn/instances/${enc(vendorId)}`),

  killOpenVPNSession: (id: string, sessionId: string) =>
    api.post<GatewayWriteResponse>(`/firewall/gateways/${enc(id)}/openvpn/sessions/${enc(sessionId)}/kill`),

  // IPsec
  getIPsec: (id: string) =>
    api.get(`/firewall/gateways/${enc(id)}/ipsec`),

  connectIPsecTunnel: (id: string, vendorId: string) =>
    api.post<GatewayWriteResponse>(`/firewall/gateways/${enc(id)}/ipsec/${enc(vendorId)}/connect`),

  disconnectIPsecTunnel: (id: string, vendorId: string) =>
    api.post<GatewayWriteResponse>(`/firewall/gateways/${enc(id)}/ipsec/${enc(vendorId)}/disconnect`),

  // Routing
  getStaticRoutes: (id: string) =>
    api.get(`/firewall/gateways/${enc(id)}/routes/static`),

  createStaticRoute: (id: string, data: StaticRouteRequest) =>
    api.post<GatewayWriteResponse>(`/firewall/gateways/${enc(id)}/routes/static`, data),

  deleteStaticRoute: (id: string, vendorId: string) =>
    api.delete<GatewayWriteResponse>(`/firewall/gateways/${enc(id)}/routes/static/${enc(vendorId)}`),

  getRoutingTable: (id: string) =>
    api.get(`/firewall/gateways/${enc(id)}/routes/table`),

  // ARP
  getARPTable: (id: string) =>
    api.get(`/firewall/gateways/${enc(id)}/arp`),

  // Gateway Health / WAN
  getGatewayHealth: (id: string) =>
    api.get(`/firewall/gateways/${enc(id)}/health`),

  // IDS / IPS
  getIDSSettings: (id: string) =>
    api.get(`/firewall/gateways/${enc(id)}/ids/settings`),

  updateIDSSettings: (id: string, data: IDSSettingsUpdateRequest) =>
    api.put<GatewayWriteResponse>(`/firewall/gateways/${enc(id)}/ids/settings`, data),

  getIDSAlerts: (id: string, params?: { limit?: number }) =>
    api.get(`/firewall/gateways/${enc(id)}/ids/alerts`, { params }),

  // Traffic Shaper
  getShaperPipes: (id: string) =>
    api.get(`/firewall/gateways/${enc(id)}/shaper/pipes`),

  createShaperPipe: (id: string, data: ShaperPipeRequest) =>
    api.post<GatewayWriteResponse>(`/firewall/gateways/${enc(id)}/shaper/pipes`, data),

  deleteShaperPipe: (id: string, vendorId: string) =>
    api.delete<GatewayWriteResponse>(`/firewall/gateways/${enc(id)}/shaper/pipes/${enc(vendorId)}`),

  getShaperQueues: (id: string) =>
    api.get(`/firewall/gateways/${enc(id)}/shaper/queues`),

  getShaperRules: (id: string) =>
    api.get(`/firewall/gateways/${enc(id)}/shaper/rules`),

  // Backups
  getBackups: (id: string) =>
    api.get(`/firewall/gateways/${enc(id)}/backups`),

  createBackup: (id: string) =>
    api.post<GatewayWriteResponse>(`/firewall/gateways/${enc(id)}/backups`),

  revertBackup: (id: string, filename: string) =>
    api.post<GatewayWriteResponse>(`/firewall/gateways/${enc(id)}/backups/${enc(filename)}/revert`),

  // Firmware
  getFirmware: (id: string) =>
    api.get(`/firewall/gateways/${enc(id)}/firmware`),

  // Diagnostics
  runPing: (id: string, data: DiagnosticPingRequest) =>
    api.post(`/firewall/gateways/${enc(id)}/diagnostics/ping`, data),

  runTraceroute: (id: string, data: DiagnosticTracerouteRequest) =>
    api.post(`/firewall/gateways/${enc(id)}/diagnostics/traceroute`, data),

  runDNSLookup: (id: string, data: DiagnosticDNSLookupRequest) =>
    api.post(`/firewall/gateways/${enc(id)}/diagnostics/dns-lookup`, data),

  // Logs
  getSystemLog: (id: string, params?: { limit?: number }) =>
    api.get(`/firewall/gateways/${enc(id)}/logs/system`, { params }),

  getFirewallLog: (id: string, params?: { limit?: number }) =>
    api.get(`/firewall/gateways/${enc(id)}/logs/firewall`, { params }),

  // Device Summary
  getDeviceSummary: (id: string) =>
    api.get(`/firewall/gateways/${enc(id)}/device-summary`),

  // Service Control
  controlService: (id: string, serviceName: string, data: ServiceControlRequest) =>
    api.post<GatewayWriteResponse>(`/firewall/gateways/${enc(id)}/services/${enc(serviceName)}/control`, data),

  // Reboot
  rebootGateway: (id: string) =>
    api.post<GatewayWriteResponse>(`/firewall/gateways/${enc(id)}/reboot`),

  // Halt
  haltGateway: (id: string) =>
    api.post<GatewayWriteResponse>(`/firewall/gateways/${enc(id)}/halt`),

  // Firmware extras
  getFirmwareChangelog: (id: string) =>
    api.get(`/firewall/gateways/${enc(id)}/firmware/changelog`),

  firmwareCheck: (id: string) =>
    api.post(`/firewall/gateways/${enc(id)}/firmware/check`),

  firmwareUpdate: (id: string) =>
    api.post<GatewayWriteResponse>(`/firewall/gateways/${enc(id)}/firmware/update`),

  getFirmwareUpgradeStatus: (id: string) =>
    api.get(`/firewall/gateways/${enc(id)}/firmware/upgrade-status`),

  getInstalledPackages: (id: string) =>
    api.get(`/firewall/gateways/${enc(id)}/packages`),

  getInstalledPlugins: (id: string) =>
    api.get(`/firewall/gateways/${enc(id)}/plugins`),

  // Config download + Backup delete
  downloadConfig: (id: string) =>
    api.get(`/firewall/gateways/${enc(id)}/config/download`),

  deleteBackup: (id: string, filename: string) =>
    api.delete<GatewayWriteResponse>(`/firewall/gateways/${enc(id)}/backups/${enc(filename)}`),

  // Interfaces extras (NDP, ARP flush, VIPs)
  getNDPTable: (id: string) =>
    api.get(`/firewall/gateways/${enc(id)}/ndp`),

  flushARPTable: (id: string) =>
    api.post<GatewayWriteResponse>(`/firewall/gateways/${enc(id)}/arp/flush`),

  getVIPStatus: (id: string) =>
    api.get(`/firewall/gateways/${enc(id)}/vips`),

  // Firewall rule extras (toggle, update)
  toggleFirewallRule: (id: string, vendorRuleId: string) =>
    api.post<GatewayWriteResponse>(`/firewall/gateways/${enc(id)}/firewall-rules/${enc(vendorRuleId)}/toggle`),

  updateFirewallRule: (id: string, vendorRuleId: string, data: GatewayRulePushRequest) =>
    api.put<GatewayWriteResponse>(`/firewall/gateways/${enc(id)}/firewall-rules/${enc(vendorRuleId)}`, data),

  // Source NAT update
  updateSourceNATRule: (id: string, vendorId: string, data: SourceNATRuleRequest) =>
    api.put<GatewayWriteResponse>(`/firewall/gateways/${enc(id)}/source-nat/${enc(vendorId)}`, data),

  // DNS extras (Unbound status)
  getUnboundStatus: (id: string) =>
    api.get(`/firewall/gateways/${enc(id)}/dns/unbound-status`),

  // WireGuard updates + handshakes
  updateWireGuardServer: (id: string, vendorId: string, data: WireGuardServerRequest) =>
    api.put<GatewayWriteResponse>(`/firewall/gateways/${enc(id)}/wireguard/servers/${enc(vendorId)}`, data),

  updateWireGuardPeer: (id: string, vendorId: string, data: WireGuardPeerRequest) =>
    api.put<GatewayWriteResponse>(`/firewall/gateways/${enc(id)}/wireguard/peers/${enc(vendorId)}`, data),

  getWireGuardHandshakes: (id: string) =>
    api.get(`/firewall/gateways/${enc(id)}/wireguard/handshakes`),

  // OpenVPN update + sessions
  updateOpenVPNInstance: (id: string, vendorId: string, data: OpenVPNInstanceRequest) =>
    api.put<GatewayWriteResponse>(`/firewall/gateways/${enc(id)}/openvpn/instances/${enc(vendorId)}`, data),

  getOpenVPNSessions: (id: string) =>
    api.get(`/firewall/gateways/${enc(id)}/openvpn/sessions`),

  // IPsec extras (status, apply)
  getIPsecStatus: (id: string) =>
    api.get(`/firewall/gateways/${enc(id)}/ipsec/status`),

  applyIPsecChanges: (id: string) =>
    api.post<GatewayWriteResponse>(`/firewall/gateways/${enc(id)}/ipsec/apply`),

  // Static Route update
  updateStaticRoute: (id: string, vendorId: string, data: StaticRouteRequest) =>
    api.put<GatewayWriteResponse>(`/firewall/gateways/${enc(id)}/routes/static/${enc(vendorId)}`, data),

  // IDS full CRUD (rulesets, rules, status, control)
  getIDSRulesets: (id: string) =>
    api.get(`/firewall/gateways/${enc(id)}/ids/rulesets`),

  getIDSRules: (id: string) =>
    api.get(`/firewall/gateways/${enc(id)}/ids/rules`),

  toggleIDSRule: (id: string, sid: string) =>
    api.post<GatewayWriteResponse>(`/firewall/gateways/${enc(id)}/ids/rules/${enc(sid)}/toggle`),

  dropIDSAlertLog: (id: string) =>
    api.delete<GatewayWriteResponse>(`/firewall/gateways/${enc(id)}/ids/alerts`),

  getIDSStatus: (id: string) =>
    api.get(`/firewall/gateways/${enc(id)}/ids/status`),

  controlIDS: (id: string, data: IDSControlRequest) =>
    api.post<GatewayWriteResponse>(`/firewall/gateways/${enc(id)}/ids/control`, data),

  // Shaper full CRUD (pipe update, queue CRUD, rule CRUD)
  updateShaperPipe: (id: string, vendorId: string, data: ShaperPipeRequest) =>
    api.put<GatewayWriteResponse>(`/firewall/gateways/${enc(id)}/shaper/pipes/${enc(vendorId)}`, data),

  createShaperQueue: (id: string, data: ShaperQueueRequest) =>
    api.post<GatewayWriteResponse>(`/firewall/gateways/${enc(id)}/shaper/queues`, data),

  updateShaperQueue: (id: string, vendorId: string, data: ShaperQueueRequest) =>
    api.put<GatewayWriteResponse>(`/firewall/gateways/${enc(id)}/shaper/queues/${enc(vendorId)}`, data),

  deleteShaperQueue: (id: string, vendorId: string) =>
    api.delete<GatewayWriteResponse>(`/firewall/gateways/${enc(id)}/shaper/queues/${enc(vendorId)}`),

  createShaperRule: (id: string, data: ShaperRuleRequest) =>
    api.post<GatewayWriteResponse>(`/firewall/gateways/${enc(id)}/shaper/rules`, data),

  updateShaperRule: (id: string, vendorId: string, data: ShaperRuleRequest) =>
    api.put<GatewayWriteResponse>(`/firewall/gateways/${enc(id)}/shaper/rules/${enc(vendorId)}`, data),

  deleteShaperRule: (id: string, vendorId: string) =>
    api.delete<GatewayWriteResponse>(`/firewall/gateways/${enc(id)}/shaper/rules/${enc(vendorId)}`),

  // Diagnostics extras
  getConnections: (id: string) =>
    api.get(`/firewall/gateways/${enc(id)}/diagnostics/connections`),

  getPFInfo: (id: string) =>
    api.get(`/firewall/gateways/${enc(id)}/diagnostics/pf-info`),

  getPFStatistics: (id: string) =>
    api.get(`/firewall/gateways/${enc(id)}/diagnostics/pf-statistics`),

  // Monitoring
  getTemperature: (id: string) =>
    api.get(`/firewall/gateways/${enc(id)}/monitoring/temperature`),

  getDiskUsage: (id: string) =>
    api.get(`/firewall/gateways/${enc(id)}/monitoring/disk-usage`),

  getTrafficStats: (id: string) =>
    api.get(`/firewall/gateways/${enc(id)}/monitoring/traffic`),

  // System extras
  getCronJobs: (id: string) =>
    api.get(`/firewall/gateways/${enc(id)}/cron-jobs`),

  // Tailscale VPN
  getTailscaleStatus: (id: string) =>
    api.get(`/firewall/gateways/${enc(id)}/tailscale`),

  // VLAN / LAGG / Virtual IP Devices
  getVLANDevices: (id: string) =>
    api.get(`/firewall/gateways/${enc(id)}/vlans`),

  getLAGGDevices: (id: string) =>
    api.get(`/firewall/gateways/${enc(id)}/laggs`),

  getVirtualIPs: (id: string) =>
    api.get(`/firewall/gateways/${enc(id)}/virtual-ips`),

  // HAProxy (Load Balancer)
  getHAProxyStatus: (id: string) =>
    api.get(`/firewall/gateways/${enc(id)}/haproxy`),

  getHAProxyServers: (id: string) =>
    api.get(`/firewall/gateways/${enc(id)}/haproxy/servers`),

  getHAProxyBackends: (id: string) =>
    api.get(`/firewall/gateways/${enc(id)}/haproxy/backends`),

  getHAProxyFrontends: (id: string) =>
    api.get(`/firewall/gateways/${enc(id)}/haproxy/frontends`),

  // Certificate Management (Trust Store)
  getTrustOverview: (id: string) =>
    api.get(`/firewall/gateways/${enc(id)}/certificates`),

  getCertificates: (id: string) =>
    api.get(`/firewall/gateways/${enc(id)}/certificates/certs`),

  getCertificateAuthorities: (id: string) =>
    api.get(`/firewall/gateways/${enc(id)}/certificates/cas`),

  // ACME / Let's Encrypt
  getACMEOverview: (id: string) =>
    api.get(`/firewall/gateways/${enc(id)}/acme`),

  getACMECertificates: (id: string) =>
    api.get(`/firewall/gateways/${enc(id)}/acme/certificates`),

  // Syslog Forwarding
  getSyslogDestinations: (id: string) =>
    api.get(`/firewall/gateways/${enc(id)}/syslog`),

  // Dynamic DNS
  getDynDNSAccounts: (id: string) =>
    api.get(`/firewall/gateways/${enc(id)}/dyndns`),

  // Captive Portal
  getCaptivePortalZones: (id: string) =>
    api.get(`/firewall/gateways/${enc(id)}/captive-portal`),

  getCaptivePortalSessions: (id: string) =>
    api.get(`/firewall/gateways/${enc(id)}/captive-portal/sessions`),

  // High Availability / Config Sync
  getHAStatus: (id: string) =>
    api.get(`/firewall/gateways/${enc(id)}/ha-status`),

  // Kea DHCP (DHCPv4/v6)
  getKeaDHCPv4Subnets: (id: string) =>
    api.get(`/firewall/gateways/${enc(id)}/kea/dhcpv4/subnets`),

  getKeaDHCPv4Reservations: (id: string) =>
    api.get(`/firewall/gateways/${enc(id)}/kea/dhcpv4/reservations`),

  getKeaDHCPv4Leases: (id: string) =>
    api.get(`/firewall/gateways/${enc(id)}/kea/dhcpv4/leases`),

  getKeaDHCPv6Subnets: (id: string) =>
    api.get(`/firewall/gateways/${enc(id)}/kea/dhcpv6/subnets`),

  // 1:1 NAT (Binat)
  getOneToOneNatRules: (id: string) =>
    api.get(`/firewall/gateways/${enc(id)}/nat/onetoone`),

  // Network Bridges
  getBridges: (id: string) =>
    api.get(`/firewall/gateways/${enc(id)}/bridges`),

  // DHCP Relay
  getDhcpRelay: (id: string) =>
    api.get(`/firewall/gateways/${enc(id)}/dhcp-relay`),

  // Web Proxy / Squid
  getProxySettings: (id: string) =>
    api.get(`/firewall/gateways/${enc(id)}/proxy`),
  getProxyBlacklists: (id: string) =>
    api.get(`/firewall/gateways/${enc(id)}/proxy/blacklists`),

  // CrowdSec IPS
  getCrowdSecStatus: (id: string) =>
    api.get(`/firewall/gateways/${enc(id)}/crowdsec`),

  // Telegraf
  getTelegrafStatus: (id: string) =>
    api.get(`/firewall/gateways/${enc(id)}/telegraf`),

  // Monit
  getMonitStatus: (id: string) =>
    api.get(`/firewall/gateways/${enc(id)}/monit`),

  // NetFlow / sFlow
  getNetFlowStatus: (id: string) =>
    api.get(`/firewall/gateways/${enc(id)}/netflow`),

  // Cross-cutting: Bulk Rule Operations
  bulkRuleOperation: (id: string, action: 'enable' | 'disable' | 'delete', ruleUuids: string[]) =>
    api.post(`/firewall/gateways/${enc(id)}/rules/bulk`, { action, rule_uuids: ruleUuids }),

  // Cross-cutting: Config Diff
  getConfigDiff: (id: string) =>
    api.get(`/firewall/gateways/${enc(id)}/config/diff`),

  // Cross-cutting: Trigger Backup
  triggerConfigBackup: (id: string) =>
    api.post(`/firewall/gateways/${enc(id)}/backup/trigger`),

  // Cross-cutting: Certificate Expiry
  getCertificateExpiry: (id: string, daysThreshold: number = 30) =>
    api.get(`/firewall/gateways/${enc(id)}/certificates/expiry`, { params: { days_threshold: daysThreshold } }),

  // Deep health check
  getHealthCheck: (id: string) =>
    api.get(`/firewall/gateways/${enc(id)}/health-check`),
};

export const gatewayOrchApi = {
  // Topology (Role Maps)
  getTopology: (siteId: string) =>
    api.get<SiteRoleMapResponse>(`/firewall/topology/${enc(siteId)}`),
  updateTopology: (siteId: string, data: SiteRoleMapUpdate) =>
    api.put<SiteRoleMapResponse>(`/firewall/topology/${enc(siteId)}`, data),
  deleteTopology: (siteId: string) =>
    api.delete(`/firewall/topology/${enc(siteId)}`),
  validateTopology: (siteId: string, data: SiteRoleMapUpdate) =>
    api.post<TopologyValidationResult>(`/firewall/topology/${enc(siteId)}/validate`, data),

  // Canonical VLANs
  getVlans: (params?: { site_id?: string; limit?: number; offset?: number }) =>
    api.get<CanonicalVLANListResponse>('/firewall/vlans', { params }),
  getVlan: (id: string) =>
    api.get<CanonicalVLANDetailResponse>(`/firewall/vlans/${enc(id)}`),
  createVlan: (data: CanonicalVLANCreate) =>
    api.post<CanonicalVLANResponse>('/firewall/vlans', data),
  updateVlan: (id: string, data: CanonicalVLANUpdate) =>
    api.patch<CanonicalVLANResponse>(`/firewall/vlans/${enc(id)}`, data),
  deleteVlan: (id: string) =>
    api.delete(`/firewall/vlans/${enc(id)}`),

  // DHCP
  getDhcpScopes: (params?: { site_id?: string }) =>
    api.get<DHCPScopeResponse[]>('/firewall/dhcp/scopes', { params }),
  createDhcpScope: (data: DHCPScopeCreate) =>
    api.post<DHCPScopeResponse>('/firewall/dhcp/scopes', data),
  createDhcpReservation: (data: DHCPReservationCreate) =>
    api.post<DHCPReservationResponse>('/firewall/dhcp/reservations', data),
  deleteDhcpReservation: (id: string) =>
    api.delete(`/firewall/dhcp/reservations/${enc(id)}`),

  // DNS
  getDnsRecords: (params?: { site_id?: string }) =>
    api.get<DNSRecordResponse[]>('/firewall/dns/records', { params }),
  createDnsRecord: (data: DNSRecordCreate) =>
    api.post<DNSRecordResponse>('/firewall/dns/records', data),
  updateDnsRecord: (id: string, data: DNSRecordUpdate) =>
    api.patch<DNSRecordResponse>(`/firewall/dns/records/${enc(id)}`, data),
  deleteDnsRecord: (id: string) =>
    api.delete(`/firewall/dns/records/${enc(id)}`),

  // Distribution
  getDistributions: (params?: { site_id?: string; limit?: number; offset?: number }) =>
    api.get<{ items: DistributionResponse[]; total: number }>('/firewall/distribution', { params }),
  getDistribution: (id: string) =>
    api.get<DistributionResponse>(`/firewall/distribution/${enc(id)}`),
  triggerDistribution: (data: DistributionTriggerRequest) =>
    api.post<DistributionResponse>('/firewall/distribution/trigger', data),
  retryDistribution: (id: string) =>
    api.post<DistributionResponse>(`/firewall/distribution/${enc(id)}/retry`),
  rollbackDistribution: (id: string) =>
    api.post<DistributionResponse>(`/firewall/distribution/${enc(id)}/rollback`),
  retractDistribution: (data: DistributionRetractRequest) =>
    api.post<DistributionResponse>('/firewall/distribution/retract', data),

  // Drift Detection
  getDriftEvents: (params?: { site_id?: string; severity?: string; resolved?: boolean; limit?: number; offset?: number }) =>
    api.get<{ items: DriftEventResponse[]; total: number }>('/firewall/drift/events', { params }),
  getDriftSummary: (params?: { site_id?: string }) =>
    api.get<DriftSummaryResponse>('/firewall/drift/summary', { params }),
  triggerDriftCheck: (siteId: string) =>
    api.post<DriftCheckResponse>(`/firewall/drift/check/${enc(siteId)}`),
  resolveDriftEvent: (id: string, data: DriftResolveRequest) =>
    api.post<DriftEventResponse>(`/firewall/drift/events/${enc(id)}/resolve`, data),
  getSuppressions: (params?: { site_id?: string; active_only?: boolean }) =>
    api.get<SuppressionRuleResponse[]>('/firewall/drift/suppressions', { params }),
  createSuppression: (data: SuppressionRuleCreate) =>
    api.post<SuppressionRuleResponse>('/firewall/drift/suppressions', data),
  deleteSuppression: (id: string) =>
    api.delete(`/firewall/drift/suppressions/${enc(id)}`),

  // Import Wizard
  getImportSessions: (params?: { site_id?: string; limit?: number; offset?: number }) =>
    api.get<ImportSessionResponse[]>('/firewall/import/sessions', { params }),
  startImport: (data: ImportSessionCreate) =>
    api.post<ImportSessionResponse>('/firewall/import/start', data),
  getImportSession: (id: string) =>
    api.get<ImportSessionResponse>(`/firewall/import/${enc(id)}`),
  advanceImport: (id: string, data: ImportSessionStep) =>
    api.post<ImportSessionResponse>(`/firewall/import/${enc(id)}/step`, data),
  cancelImport: (id: string) =>
    api.post(`/firewall/import/${enc(id)}/cancel`),

  // Dashboard
  getDashboardOverview: (params?: { site_id?: string }) =>
    api.get<GatewayDashboardOverview>('/firewall/dashboard/overview', { params }),
  getFirewallRules: (params?: { device_id?: string; site_id?: string; limit?: number; offset?: number }) =>
    api.get<{ items: ImportedFirewallRuleResponse[]; total: number }>('/firewall/dashboard/firewall-rules', { params }),
  getNatRules: (params?: { device_id?: string; site_id?: string; limit?: number; offset?: number }) =>
    api.get<{ items: ImportedNATRuleResponse[]; total: number }>('/firewall/dashboard/nat-rules', { params }),
  getVpnTunnels: (params?: { device_id?: string; site_id?: string; limit?: number; offset?: number }) =>
    api.get<{ items: ImportedVPNTunnelResponse[]; total: number }>('/firewall/dashboard/vpn-tunnels', { params }),
  getIdsEvents: (params?: { device_id?: string; site_id?: string; limit?: number; offset?: number }) =>
    api.get<{ items: ImportedIDSEventResponse[]; total: number }>('/firewall/dashboard/ids-events', { params }),
  getInterfaces: (params?: { device_id?: string; site_id?: string; limit?: number; offset?: number }) =>
    api.get<{ items: ImportedInterfaceResponse[]; total: number }>('/firewall/dashboard/interfaces', { params }),
  getDhcpLeases: (params?: { device_id?: string; site_id?: string; limit?: number; offset?: number }) =>
    api.get<{ items: ImportedDHCPLeaseResponse[]; total: number }>('/firewall/dashboard/dhcp-leases', { params }),

  // Diagnostics (Passthrough)
  ping: (data: GatewayPingRequest) =>
    api.post('/firewall/diagnostics/ping', data),
  traceroute: (data: GatewayTracerouteRequest) =>
    api.post('/firewall/diagnostics/traceroute', data),
  dnsLookup: (data: GatewayDNSLookupRequest) =>
    api.post('/firewall/diagnostics/dns-lookup', data),
  createBackup: (gatewayId: string) =>
    api.post('/firewall/diagnostics/backup', null, { params: { gateway_id: gatewayId } }),
  getFirmware: (gatewayId: string) =>
    api.get(`/firewall/diagnostics/firmware/${enc(gatewayId)}`),
  restartService: (data: GatewayServiceRestartRequest) =>
    api.post('/firewall/diagnostics/restart-service', data),

  // Reconciliation, mounted at /firewall/* because Gateway was
  // merged into the Firewall module (backend code stays in
  // ``modules/gateway/`` but the route prefix follows ``module.id``).
  // Calling /gateway/reconciliation/* used to 404 silently, breaking
  // the GatewayPage Reconciliation tab end-to-end.
  importFromBrain: (siteId: string, dryRun: boolean = false) =>
    api.post(`/firewall/reconciliation/${enc(siteId)}/import`, { dry_run: dryRun }),
  checkAlignment: (siteId: string) =>
    api.get(`/firewall/reconciliation/${enc(siteId)}/alignment`),
  distributeToLimbs: (siteId: string, data: { vlan_ids?: number[]; dry_run?: boolean }) =>
    api.post(`/firewall/reconciliation/${enc(siteId)}/distribute`, data),

  // VLAN Templates
  getTemplates: (params?: { limit?: number; offset?: number }) =>
    api.get<VLANTemplateListResponse>('/firewall/templates', { params }),
  getTemplate: (id: string) =>
    api.get<VLANTemplateResponse>(`/firewall/templates/${enc(id)}`),
  createTemplate: (data: VLANTemplateCreate) =>
    api.post<VLANTemplateResponse>('/firewall/templates', data),
  updateTemplate: (id: string, data: VLANTemplateUpdate) =>
    api.patch<VLANTemplateResponse>(`/firewall/templates/${enc(id)}`, data),
  deleteTemplate: (id: string) =>
    api.delete(`/firewall/templates/${enc(id)}`),
  applyTemplate: (templateId: string, siteId: string) =>
    api.post<TemplateApplyResponse>(`/firewall/templates/${enc(templateId)}/apply/${enc(siteId)}`),
};

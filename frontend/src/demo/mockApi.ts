// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import type {
  AxiosAdapter,
  AxiosInstance,
  AxiosResponse,
  InternalAxiosRequestConfig,
} from 'axios';
import { demoWriteMessage } from './mode';
import { getDemoHypervisorDashboard, getDemoHypervisorFleetDashboard } from './hypervisorDashboard';

// Single source for the version the demo reports. It was hardcoded to
// '26.06.1-demo', which is why Settings > About read 26.06.1 long after the
// demo had been rebuilt: the bundle was current, this string was not.
const DEMO_VERSION = '26.10.0-demo';
import {
  alertInstances,
  alertRuleStats,
  alertRules,
  alerts,
  apRadios,
  auditLogs,
  auditRollup,
  cameras,
  controllers,
  correlationRules,
  correlationStats,
  dashboardSummary,
  demoActiveCalls,
  demoBackupManifest,
  demoBackupSchedules,
  demoBackupStats,
  demoBackupStorageTypes,
  demoBackups,
  demoBoundPhones,
  demoCallLogs,
  demoCallQueues,
  demoCallStats,
  demoCameraAccessGrants,
  demoCameraEvents,
  demoCameraGroups,
  demoCameraHealth,
  demoCameraReports,
  demoCameraViews,
  demoCameras,
  demoDids,
  demoEvidenceArchives,
  demoHealthHistory,
  demoHypervisorAptUpdates,
  demoHypervisorBackupAgeReport,
  demoHypervisorBackupJobs,
  demoHypervisorCephDetail,
  demoHypervisorCephStatus,
  demoHypervisorCertificates,
  demoHypervisorClusterConfigNodes,
  demoHypervisorClusterLog,
  demoHypervisorClusterResources,
  demoHypervisorClusterStatus,
  demoHypervisorDiskSmart,
  demoHypervisorFirewallRules,
  demoHypervisorGuestAgent,
  demoHypervisorGuestRrd,
  demoHypervisorGuests,
  demoHypervisorHaGroups,
  demoHypervisorHaResources,
  demoHypervisorNodeDisks,
  demoHypervisorNodeNetwork,
  demoHypervisorNodeRrd,
  demoHypervisorNodeSensors,
  demoHypervisorNodeServices,
  demoHypervisorNodes,
  demoHypervisorPools,
  demoHypervisorPrunePreview,
  demoHypervisorReplicationJobs,
  demoHypervisorReplicationLog,
  demoHypervisorSdnControllers,
  demoHypervisorSdnVnets,
  demoHypervisorSdnZones,
  demoHypervisorSnapshots,
  demoHypervisorStorageContent,
  demoHypervisorStorages,
  demoHypervisorSubscriptions,
  demoHypervisorTaskLog,
  demoHypervisorTaskStats,
  demoHypervisorTasks,
  demoIds,
  demoIvrs,
  demoLogHourly,
  demoNvrHolidays,
  demoNvrNetwork,
  demoNvrStorage,
  demoNvrSystemInfo,
  demoNvrs,
  demoPbxSystems,
  demoRecordingTemplates,
  demoRestoreJobs,
  demoRingGroups,
  demoRxBytes24h,
  demoSipTrunks,
  demoStagedChanges,
  demoStorageInventory,
  demoStorageLocations,
  demoSystemLogs,
  demoTrafficSeries,
  demoTxBytes24h,
  demoUser,
  demoVoicemailBoxes,
  demoVoicemailStats,
  demoVoicemails,
  demoVoipDiscoveryScans,
  demoVoipExtensions,
  demoVoipFirmwareTracks,
  demoVoipFleetDashboard,
  demoVoipPhones,
  demoVoipTemplates,
  devices,
  enterpriseAnalytics,
  filterPendingChanges,
  firewallGatewaySummary,
  firewallGateways,
  firewallIdsAlertStats,
  firewallIdsAlerts,
  firewallLogs,
  firewallNatRules,
  firewallRules,
  firewallVpnStats,
  firewallVpnTunnels,
  gatewayLiveData,
  getDemoCameraSnapshotPath,
  inAppNotifications,
  incidentEvents,
  incidents,
  logsHealth,
  metricDefinitions,
  moduleNavItems,
  modules,
  networkClients,
  networkDevices,
  networkVlans,
  notificationProviderTypes,
  notificationProviders,
  organizations,
  pendingChangeDomainPrefixes,
  pendingChanges,
  securityAnomalies,
  securityEventTypes,
  securityEvents,
  securitySummary,
  sites,
  switchLags,
  switchPortFixtures,
  topologyLinks,
  wifiNetworks,
} from './fixtures';

type AnyRecord = Record<string, unknown>;

const iso = (minutesAgo = 0) => new Date(Date.now() - minutesAgo * 60_000).toISOString();

function toPath(config: InternalAxiosRequestConfig): string {
  const raw = config.url || '/';
  const base = config.baseURL || window.location.origin;
  const url = new URL(raw, base);
  return url.pathname.replace(/^\/api\/v1/, '').replace(/\/+$/, '') || '/';
}

function params(config: InternalAxiosRequestConfig): AnyRecord {
  return (config.params && typeof config.params === 'object') ? config.params as AnyRecord : {};
}

function paginated<T>(items: T[], page = 1, perPage = 100) {
  return {
    items,
    total: items.length,
    page,
    per_page: perPage,
    pages: Math.max(1, Math.ceil(items.length / perPage)),
  };
}

function emptyList() {
  const data = [] as unknown as unknown[] & AnyRecord;
  data.items = [];
  data.total = 0;
  data.page = 1;
  data.per_page = 100;
  data.pages = 1;
  return data;
}

function response<T>(
  config: InternalAxiosRequestConfig,
  data: T,
  status = 200,
  headers: Record<string, string> = {},
): AxiosResponse<T> {
  return {
    data,
    status,
    statusText: status === 204 ? 'No Content' : 'OK',
    headers,
    config,
  };
}

function demoWriteResponse(config: InternalAxiosRequestConfig) {
  if (typeof window !== 'undefined') {
    window.dispatchEvent(new CustomEvent('freesdn-demo-write-blocked', {
      detail: { method: (config.method || 'post').toUpperCase(), path: toPath(config) },
    }));
  }

  return response(config, {
    success: true,
    demo: true,
    read_only: true,
    message: demoWriteMessage,
  }, (config.method || '').toLowerCase() === 'delete' ? 204 : 200);
}

function findById<T extends { id: string }>(items: T[], id: string | undefined) {
  return items.find((item) => item.id === id) || items[0] || null;
}

function switchPorts(deviceId: string) {
  return Array.from({ length: 12 }, (_, index) => ({
    id: `${deviceId}-port-${index + 1}`,
    device_id: deviceId,
    port_index: index + 1,
    port_type: index >= 10 ? 'sfp' : 'ethernet',
    name: index >= 10 ? `SFP ${index - 9}` : `Port ${index + 1}`,
    enabled: index !== 7,
    auto_negotiation: true,
    mtu: 1500,
    flow_control: false,
    vlan_config: { mode: index === 0 ? 'trunk' : 'access', native_vlan: index === 0 ? 10 : 20, tagged_vlans: index === 0 ? [10, 20, 30, 40] : [] },
    poe_config: { enabled: index < 8, mode: 'auto', priority: 1 },
    status: {
      link_status: index === 7 ? 'down' : 'up',
      link_speed: index >= 10 ? 10000 : 1000,
      link_duplex: 'full',
      tx_bytes: 28_400_000 + index * 1000,
      rx_bytes: 42_800_000 + index * 1400,
      tx_packets: 12_400 + index * 100,
      rx_packets: 18_500 + index * 120,
      tx_errors: 0,
      rx_errors: index === 6 ? 2 : 0,
      tx_utilization: 4 + index,
      rx_utilization: 7 + index,
      poe_status: index < 8 ? 'delivering' : undefined,
      poe_power_draw: index < 8 ? 6.5 + index : undefined,
      neighbor_device: index === 0 ? 'HQ-FW-01' : undefined,
    },
  }));
}

function health() {
  return {
    status: 'healthy',
    checks: { database: 'healthy', redis: 'healthy', celery: 'healthy' },
    components: {
      database: { status: 'healthy', latency_ms: 4 },
      redis: { status: 'healthy', latency_ms: 2 },
      celery: { status: 'healthy', queue_depth: 3 },
    },
    timestamp: new Date().toISOString(),
  };
}

function modulesEnvelope() {
  return { modules, total: modules.length };
}

function networkSummary() {
  return {
    devices: {
      total: devices.length,
      online: devices.filter((device) => device.status === 'online').length,
      offline: devices.filter((device) => device.status === 'offline').length,
      by_type: {
        switch: devices.filter((device) => device.device_type === 'switch').length,
        access_point: devices.filter((device) => device.device_type === 'access_point').length,
        gateway: devices.filter((device) => device.device_type === 'firewall').length,
        other: devices.filter((device) => !['switch', 'access_point', 'firewall'].includes(device.device_type)).length,
      },
    },
    clients: { total: 94, online: 88, wired: 36, wireless: 58, blocked: 2 },
    total_vlans: 4,
    total_wifi_networks: 3,
  };
}

function networkTopology() {
  return {
    nodes: devices.map((device) => ({
      id: device.id,
      label: device.name,
      type: device.device_type,
      status: device.status,
      site_id: device.site_id,
    })),
    links: [
      { id: 'edge-fw-core', source: 'dev-fw-hq', target: 'dev-sw-core', type: 'uplink' },
      { id: 'edge-core-ap', source: 'dev-sw-core', target: 'dev-ap-lobby', type: 'ethernet' },
      { id: 'edge-core-camera', source: 'dev-sw-core', target: 'cam-front-door', type: 'poe' },
    ],
  };
}

const hypervisorDashboard = {
  cluster_name: 'PVE Cluster A',
  quorate: true,
  total_nodes: 1,
  online_nodes: 1,
  total_vms: 2,
  running_vms: 2,
  total_containers: 1,
  running_containers: 1,
  total_cpu_cores: 32,
  cpu_usage_percent: 36,
  total_memory_bytes: 137_438_953_472,
  used_memory_bytes: 97_600_000_000,
  memory_usage_percent: 71,
  total_storage_bytes: 24_000_000_000_000,
  used_storage_bytes: 14_800_000_000_000,
  storage_usage_percent: 62,
  ha_active: true,
};

const hypervisorNodes = [{
  id: 'pve-node-01',
  node: 'pve-node-01',
  status: 'online',
  ip_address: '10.20.0.11',
  cpu_count: 32,
  cpu_usage: 0.36,
  cpu_percent: 36,
  memory_total: 137_438_953_472,
  memory_used: 97_600_000_000,
  memory_percent: 71,
  storage_total: 24_000_000_000_000,
  storage_used: 14_800_000_000_000,
  storage_percent: 62,
  uptime: 24_880_000,
  pve_version: '8.3.2',
  kernel_version: '6.8.12-8-pve',
  cpu_model: 'Intel Xeon Silver 4314',
  subscription_level: 'community',
}];

const hypervisorGuests = [
  { id: 'vm-101', vmid: 101, name: 'auth-01', node: 'pve-node-01', vm_type: 'qemu', status: 'running', cpu_cores: 2, cpu_usage: 0.18, cpu_percent: 18, memory_mb: 4096, memory_used_mb: 2460, memory_percent: 60, disk_gb: 64, disk_used_gb: 28.4, disk_percent: 44, ip_address: '10.20.10.21', net_in: 12_400_000, net_out: 9_800_000, uptime: 1_248_000, tags: ['identity'], template: false, ha_state: 'started', lock: null, os_type: 'linux' },
  { id: 'vm-204', vmid: 204, name: 'nms-worker-01', node: 'pve-node-01', vm_type: 'qemu', status: 'running', cpu_cores: 4, cpu_usage: 0.24, cpu_percent: 24, memory_mb: 8192, memory_used_mb: 6144, memory_percent: 75, disk_gb: 120, disk_used_gb: 72.8, disk_percent: 61, ip_address: '10.20.10.44', net_in: 28_100_000, net_out: 18_400_000, uptime: 880_000, tags: ['worker'], template: false, ha_state: null, lock: null, os_type: 'linux' },
  { id: 'ct-310', vmid: 310, name: 'grafana', node: 'pve-node-01', vm_type: 'lxc', status: 'running', cpu_cores: 2, cpu_usage: 0.11, cpu_percent: 11, memory_mb: 2048, memory_used_mb: 960, memory_percent: 47, disk_gb: 32, disk_used_gb: 11.2, disk_percent: 35, ip_address: '10.20.10.55', net_in: 6_800_000, net_out: 5_100_000, uptime: 620_000, tags: ['observability'], template: false, ha_state: null, lock: null, os_type: 'debian' },
];

const hypervisorStorage = [{
  storage: 'local-zfs',
  node: 'pve-node-01',
  storage_type: 'zfspool',
  content: 'images,rootdir',
  total: 24_000_000_000_000,
  used: 14_800_000_000_000,
  available: 9_200_000_000_000,
  used_percent: 62,
  active: true,
  shared: false,
  enabled: true,
}];

function hypervisorFleetDashboard() {
  return {
    total_clusters: 1,
    online_clusters: 1,
    ...hypervisorDashboard,
    clusters: [{
      controller_id: demoIds.proxmox,
      controller_name: 'PVE Cluster A',
      cluster_name: 'PVE Cluster A',
      quorate: true,
      total_nodes: hypervisorDashboard.total_nodes,
      online_nodes: hypervisorDashboard.online_nodes,
      total_vms: hypervisorDashboard.total_vms,
      running_vms: hypervisorDashboard.running_vms,
      total_containers: hypervisorDashboard.total_containers,
      running_containers: hypervisorDashboard.running_containers,
      total_cpu_cores: hypervisorDashboard.total_cpu_cores,
      cpu_usage_percent: hypervisorDashboard.cpu_usage_percent,
      total_memory_bytes: hypervisorDashboard.total_memory_bytes,
      used_memory_bytes: hypervisorDashboard.used_memory_bytes,
      memory_usage_percent: hypervisorDashboard.memory_usage_percent,
      total_storage_bytes: hypervisorDashboard.total_storage_bytes,
      used_storage_bytes: hypervisorDashboard.used_storage_bytes,
      storage_usage_percent: hypervisorDashboard.storage_usage_percent,
      status: 'online',
      error: '',
    }],
  };
}

const installedPlugins = [{
  plugin_id: 'plugin-n8n',
  name: 'n8n Bridge',
  version: '1.0.0',
  description: 'Sample automation bridge for the static demo.',
  author: 'FreeSDN',
  license: 'AGPL-3.0-only',
  homepage: 'https://freesdn.org',
  is_active: true,
  status: 'installed',
  plugin_dir: 'n8n-bridge',
  manifest_cache: { capabilities: ['automation.triggers', 'automation.actions'] },
  installed_from: 'demo-fixture',
}];

const marketplacePlugins = [{
  plugin_id: 'plugin-n8n',
  slug: 'n8n-bridge',
  name: 'n8n Bridge',
  short_description: 'Connect FreeSDN events to n8n workflows.',
  author_name: 'FreeSDN',
  category: 'automation',
  tags: ['automation', 'webhooks'],
  latest_version: '1.0.0',
  icon_url: null,
  download_count: 1280,
  rating: 4.7,
  rating_count: 18,
  is_verified: true,
  is_featured: true,
  status: 'published',
}];


/* ==== demo: network fleet (devices, switch ports, VLANs, WiFi/SSIDs, clients, topology) ==== */
/* ── NETWORK FLEET · module-level helpers (place ABOVE `routeGet`) ────────── */

type FleetDevice = (typeof networkDevices)[number];

/** Site filter shared by every fleet route (`?site_id=` from useSiteStore). */
function bySite<T extends { site_id?: string | null }>(items: T[], q: AnyRecord): T[] {
  return q.site_id ? items.filter((item) => item.site_id === q.site_id) : items;
}

function fleetDevices(q: AnyRecord): FleetDevice[] {
  let list = bySite(networkDevices, q);
  if (q.device_type) list = list.filter((d) => d.device_type === q.device_type);
  if (q.status) list = list.filter((d) => d.status === q.status);
  return list;
}

/** Fixtures freeze `last_seen` at their own epoch; re-anchor it to the live
 *  clock so the demo never renders "84 days ago" for a healthy device. */
function fresh<T extends { seen_minutes: number }>(d: T) {
  return { ...d, last_seen: iso(d.seen_minutes), updated_at: iso(d.seen_minutes) };
}

function healthOf(status: string, seed: number) {
  if (status === 'offline') return { score: 12, label: 'critical' };
  if (status === 'degraded') return { score: 58 + (seed % 7), label: 'warning' };
  return { score: 90 + (seed % 9), label: 'healthy' };
}

function poeClass(watts: number) {
  if (watts <= 0) return undefined;
  if (watts <= 4) return 1;
  if (watts <= 7) return 2;
  if (watts <= 15.4) return 3;
  return 4;
}

/** Ports for any switch: hand-authored where `switchPortFixtures` has them,
 *  otherwise derived from the device row so all 25 switches show a real panel.
 *  Uplink ports are labelled and neighboured from `topologyLinks`. */
function fleetPortSpec(deviceId: string) {
  const authored = switchPortFixtures.filter((p) => p.sw === deviceId);
  if (authored.length) return authored;

  const d = networkDevices.find((x) => x.id === deviceId);
  if (!d || !d.total_ports) return [];

  const total = d.total_ports;
  const sfpCount = d.sfp_ports;
  const rj45 = total - sfpCount;
  // Admin-disabled ports sit at the end of the copper block, never on the SFP
  // uplinks. Placing them at the end of the whole panel silently downed the
  // uplinks and made ports_up disagree with the device row.
  const disabledFrom = (rj45 > 0 ? rj45 : total) - d.ports_disabled + 1;
  const uplinkSfp = rj45 > 0 ? Math.min(sfpCount, 2, d.ports_up) : 0;
  const accessUp = d.ports_up - uplinkSfp;

  const peers = topologyLinks
    .filter((l) => l.source_id === deviceId || l.target_id === deviceId)
    .map((l) => (l.source_id === deviceId
      ? { port: l.source_port, remote: l.target_port, peerId: l.target_id }
      : { port: l.target_port, remote: l.source_port, peerId: l.source_id }));

  const poeUp: number[] = [];
  const spec = Array.from({ length: total }, (_, index) => {
    const i = index + 1;
    const kind = i > rj45 ? 'sfp' : 'ethernet';
    const sfpIndex = kind === 'sfp' ? i - rj45 : 0;
    const on = kind === 'sfp' && rj45 > 0 ? true : i < disabledFrom;
    const up = on && (
      (kind === 'sfp' && rj45 > 0 && sfpIndex <= uplinkSfp)
      || (kind === 'ethernet' && i <= accessUp)
      || (rj45 === 0 && i <= d.ports_up)
    );
    const poe = kind === 'ethernet' && i <= d.poe_ports;
    if (up && poe) poeUp.push(i);
    return {
      sw: deviceId,
      i,
      name: kind === 'sfp' ? `SFP ${sfpIndex}` : `Port ${i}`,
      kind,
      mode: kind === 'sfp' ? 'trunk' : 'access',
      vlan: kind === 'sfp' ? 99 : on ? 10 : 1,
      tagged: kind === 'sfp' ? [10, 20, 30, 40, 50] : ([] as number[]),
      on,
      poe,
      w: 0,
      link: up ? 'up' : 'down',
      speed: up ? (kind === 'sfp' ? 10000 : 1000) : 0,
      rxErr: up && i % 17 === 0 ? 2 : 0,
      txErr: 0,
      peer: null as string | null,
      peerPort: null as string | null,
    };
  });

  // Spread the switch's reported PoE draw over the ports actually delivering.
  const share = poeUp.length ? d.poe_used / poeUp.length : 0;
  poeUp.forEach((portIndex, n) => {
    spec[portIndex - 1].w = Math.round((share + ((n % 3) - 1) * 1.2) * 10) / 10;
  });
  if (poeUp.length) {
    // Absorb the rounding residual so the ports sum to the switch's poe_used.
    const drift = d.poe_used - poeUp.reduce((sum, portIndex) => sum + spec[portIndex - 1].w, 0);
    const last = spec[poeUp[poeUp.length - 1] - 1];
    last.w = Math.round((last.w + drift) * 10) / 10;
  }

  // Seat each neighbour on the port its own label names (Te1/0/25 -> port 25)
  // when that port is up, so LLDP, the ports table and the topology agree.
  const freeUp = spec.filter((p) => p.link === 'up').map((p) => p.i);
  const taken = new Set<number>();
  const seat = (label: string) => {
    const parsed = Number((label.match(/(\d+)$/) || [])[1]);
    // A label like Te1/0/25, sfp-sfpplus1 or UniFi's "Port 25" on a 24-copper
    // switch names a fibre port; seat it on one, so a 10G uplink never lands
    // on an access port.
    const wantsSfp = /sfp|te\d|xg/i.test(label) || (parsed > rj45 && parsed <= total);
    const pool = freeUp.filter((i) => (spec[i - 1].kind === 'sfp') === wantsSfp);
    if (parsed && pool.includes(parsed) && !taken.has(parsed)) return { slot: parsed, exact: true };
    const slot = pool.find((i) => !taken.has(i)) ?? freeUp.find((i) => !taken.has(i));
    return slot ? { slot, exact: false } : null;
  };
  peers.forEach((peer) => {
    const seated = seat(peer.port);
    if (!seated) return;
    taken.add(seated.slot);
    const port = spec[seated.slot - 1];
    const peerDevice = networkDevices.find((x) => x.id === peer.peerId);
    if (seated.exact && peer.port) port.name = peer.port;
    port.peer = peerDevice ? peerDevice.name : null;
    port.peerPort = peer.remote;
    if (peerDevice && peerDevice.device_type === 'switch') port.mode = 'trunk';
  });

  return spec;
}

/** Nested SwitchPort shape (`SwitchesPage` flattens `status` / `vlan_config`). */
function fleetPorts(deviceId: string) {
  return fleetPortSpec(deviceId).map((p) => {
    const fast = p.speed >= 10000;
    const rx = p.link === 'up' ? 4_100_000_000 + p.i * 318_000_000 + (fast ? 900_000_000_000 : 0) : 0;
    const tx = p.link === 'up' ? 2_600_000_000 + p.i * 214_000_000 + (fast ? 640_000_000_000 : 0) : 0;
    return {
      id: `${p.sw}-port-${p.i}`,
      device_id: p.sw,
      port_index: p.i,
      port_type: p.kind,
      name: p.name,
      description: undefined,
      enabled: p.on,
      speed: p.link === 'up' ? String(p.speed) : 'auto',
      duplex: p.link === 'up' ? 'full' : undefined,
      auto_negotiation: true,
      mtu: 1500,
      flow_control: false,
      vlan_config: { mode: p.mode, native_vlan: p.vlan, tagged_vlans: p.tagged },
      poe_config: { enabled: p.poe, mode: p.poe ? 'auto' : 'off', power_limit: p.poe ? 30 : undefined },
      stp_config: { enabled: true, mode: 'rstp', guard: p.kind === 'sfp' ? 'root' : 'bpdu', bpdu_filter: false, bpdu_guard: p.kind !== 'sfp' },
      security_config: { enabled: false, mac_limit: undefined, violation_action: undefined, dot1x_enabled: false, dot1x_mode: undefined },
      status: {
        link_status: p.link,
        link_speed: p.link === 'up' ? p.speed : undefined,
        link_duplex: p.link === 'up' ? 'full' : undefined,
        tx_bytes: tx,
        rx_bytes: rx,
        tx_packets: Math.round(tx / 1180),
        rx_packets: Math.round(rx / 1240),
        tx_errors: p.txErr,
        rx_errors: p.rxErr,
        tx_utilization: p.link === 'up' ? (fast ? 8 + (p.i % 9) : 2 + (p.i % 11)) : 0,
        rx_utilization: p.link === 'up' ? (fast ? 14 + (p.i % 11) : 4 + (p.i % 13)) : 0,
        poe_status: p.poe ? (p.w > 0 ? 'delivering' : 'searching') : undefined,
        poe_power_draw: p.poe ? p.w : undefined,
        poe_class: poeClass(p.w),
        stp_state: p.link === 'up' ? 'forwarding' : 'disabled',
        stp_role: p.kind === 'sfp' && p.link === 'up' ? 'root' : 'designated',
        neighbor_device: p.peer ?? undefined,
        neighbor_port: p.peerPort ?? undefined,
        neighbor_ip: undefined,
      },
      last_status_change: iso(p.i * 37),
    };
  });
}

function switchSummary(d: FleetDevice) {
  return {
    ...fresh(d),
    model_version: d.hardware_version,
    controller_connection_ip: d.ip_address,
    temperature: d.temperature || undefined,
  };
}

function apSummary(d: FleetDevice) {
  return {
    ...fresh(d),
    clients: d.connected_clients,
    radios: apRadios.filter((r) => r.device_id === d.id),
  };
}

/** Clients associated with one AP (`APClient`). */
function apClients(apId: string) {
  // Hand each client the band its SSID actually runs on, drawing down the
  // per-radio client quota so the Clients tab agrees with the Radios tab.
  const quota: Record<string, number> = {};
  apRadios.filter((r) => r.device_id === apId).forEach((r) => { quota[r.band] = r.clients; });
  const ssidBand = (ssid: string | null) => {
    const net = wifiNetworks.find((w) => w.ssid === ssid);
    if (!net) return null;
    return net.band === '2.4ghz' ? '2g' : net.band === '6ghz' ? '6g' : net.band === '5ghz' ? '5g' : null;
  };
  const rows = networkClients.filter((c) => c.dev === apId && c.type === 'wireless' && c.status === 'online');
  return [...rows].sort((a, b) => Number(!!ssidBand(b.ssid)) - Number(!!ssidBand(a.ssid))).map((c) => {
    const fixed = ssidBand(c.ssid);
    const band = fixed && quota[fixed] > 0
      ? fixed
      : (['6g', '5g', '2g'].find((b) => quota[b] > 0) || '5g');
    quota[band] = (quota[band] || 0) - 1;
    return {
      mac_address: c.mac,
      name: c.host || c.mac,
      ip_address: c.ip || '',
      ssid: c.ssid || '',
      band,
      signal: c.sig ?? 0,
      rx_rate: band === '2g' ? 144400 : 573000,
      tx_rate: band === '2g' ? 144400 : 866000,
      uptime: 3600 + c.m * 60,
    };
  });
}

/** VLAN a client sits on, read off its address inside the site plan. */
function vlanFromIp(ip: string | null) {
  const octet = (ip || '').split('.')[2];
  const known = ['0', '10', '20', '30', '40', '50'];
  if (!known.includes(octet)) return 10;
  return octet === '0' ? 99 : Number(octet);
}

/** Access ports a client could plausibly be patched into, in port order. */
function clientPorts(switchId: string, needed: number) {
  const up = fleetPortSpec(switchId).filter((p) => p.link === 'up' && !p.peer);
  const idle = up.filter((p) => p.w === 0);
  return (idle.length >= needed ? idle : up).map((p) => p.i);
}

function switchClients(switchId: string) {
  // A controller reports current associations, so an offline client (or every
  // client of an offline switch) is not in this list.
  const attached = networkClients.filter((c) => c.dev === switchId && c.status === 'online');
  const ports = clientPorts(switchId, attached.length);
  return attached.map((c, index) => ({
    mac_address: c.mac,
    name: c.host || c.mac,
    hostname: c.host || undefined,
    ip_address: c.ip || undefined,
    connection_type: c.type,
    ssid: c.ssid || undefined,
    switch_mac: networkDevices.find((d) => d.id === switchId)?.mac_address,
    switch_port: ports[index],
    vlan_id: vlanFromIp(c.ip),
    uptime: 3600 + c.m * 60,
    download: c.rx,
    upload: c.tx,
    blocked: c.blocked,
    guest: (c.ssid || '').includes('Guest'),
    last_seen: iso(c.m),
  }));
}

function poePorts(deviceId: string) {
  const d = networkDevices.find((x) => x.id === deviceId);
  return fleetPortSpec(deviceId).filter((p) => p.poe).map((p) => ({
    port_id: `${p.sw}-port-${p.i}`,
    port_index: p.i,
    port_name: p.name,
    device_id: p.sw,
    device_name: d?.name || p.sw,
    poe_enabled: p.on,
    poe_mode: p.on ? 'auto' : 'off',
    poe_status: !p.on ? 'disabled' : p.w > 0 ? 'delivering' : 'searching',
    power_draw: p.w,
    power_limit: 30,
    power_class: poeClass(p.w),
    voltage: p.w > 0 ? 53.4 : 0,
    current: p.w > 0 ? Math.round((p.w / 53.4) * 1000) / 1000 : 0,
    pd_type: p.w > 15.4 ? '802.3bt' : p.w > 0 ? '802.3at' : undefined,
  }));
}

function fleetTopologyGraph(q: AnyRecord) {
  const nodes = bySite(networkDevices, q).map((d, index) => {
    const health = healthOf(d.status, index);
    return {
      id: d.id,
      label: d.name,
      device_type: d.device_type,
      status: d.status,
      ip_address: d.ip_address,
      mac_address: d.mac_address,
      model: d.model,
      site_id: d.site_id,
      site_name: d.site_name,
      health_score: q.include_health === false ? null : health.score,
      health_status: q.include_health === false ? null : health.label,
      x: null,
      y: null,
      pinned: false,
      layer: d.topology_layer,
      metadata: { vendor: d.vendor, firmware_version: d.firmware_version },
    };
  });
  const ids = new Set(nodes.map((n) => n.id));
  const statusOf = (id: string) => networkDevices.find((d) => d.id === id)?.status;
  const edges = topologyLinks
    .filter((l) => ids.has(l.source_id) && ids.has(l.target_id))
    .map((l, index) => ({
      id: `link-${index + 1}`,
      source_id: l.source_id,
      target_id: l.target_id,
      source_port: l.source_port,
      target_port: l.target_port,
      speed: l.speed,
      status: statusOf(l.source_id) === 'offline' || statusOf(l.target_id) === 'offline' ? 'down' : 'up',
      link_type: l.speed === '10G' ? 'uplink' : 'ethernet',
      discovered_via: 'lldp',
      metadata: {},
    }));
  const tally = (key: 'device_type' | 'status') => nodes.reduce<Record<string, number>>((acc, n) => {
    acc[n[key]] = (acc[n[key]] || 0) + 1;
    return acc;
  }, {});
  const connected = new Set(edges.flatMap((e) => [e.source_id, e.target_id]));
  return {
    nodes,
    edges,
    site_id: (q.site_id as string) || null,
    // Stable: TopologyPage keys its layout off generated_at and re-lays out the
    // canvas whenever it changes, so this must not be Date.now().
    generated_at: '2026-06-07T14:30:00.000Z',
    stats: {
      total_nodes: nodes.length,
      total_edges: edges.length,
      nodes_by_type: tally('device_type'),
      nodes_by_status: tally('status'),
      links_by_status: edges.reduce<Record<string, number>>((acc, e) => {
        acc[e.status] = (acc[e.status] || 0) + 1;
        return acc;
      }, {}),
      orphan_count: nodes.filter((n) => !connected.has(n.id)).length,
    },
  };
}

function fleetNetworkSummary(q: AnyRecord) {
  const scoped = bySite(networkDevices, q);
  const clients = bySite(networkClients.map((c) => ({ ...c, site_id: c.site })), q);
  return {
    devices: {
      total: scoped.length,
      online: scoped.filter((d) => d.status === 'online').length,
      offline: scoped.filter((d) => d.status === 'offline').length,
      by_type: {
        switch: scoped.filter((d) => d.device_type === 'switch').length,
        access_point: scoped.filter((d) => d.device_type === 'access_point').length,
        gateway: scoped.filter((d) => ['gateway', 'firewall'].includes(d.device_type)).length,
        router: scoped.filter((d) => d.device_type === 'router').length,
        other: scoped.filter((d) => !['switch', 'access_point', 'gateway', 'firewall', 'router'].includes(d.device_type)).length,
      },
    },
    clients: {
      total: clients.length,
      online: clients.filter((c) => c.status === 'online').length,
      wired: clients.filter((c) => c.type === 'wired').length,
      wireless: clients.filter((c) => c.type === 'wireless').length,
      blocked: clients.filter((c) => c.blocked).length,
    },
    total_vlans: bySite(networkVlans, q).length,
    total_wifi_networks: bySite(wifiNetworks, q).length,
  };
}

/* ==== demo: Pending/staged changes (the approval queue) + the Firewall module (gateways, rules, NAT, aliases, IDS/event feed) ==== */

/* ==== demo: cameras and VoIP ==== */
  // ── Cameras ────────────────────────────────────────────────────────────────

/* ==== demo: hypervisor, storage, backup ==== */
  // ── Storage: live TrueNAS inventory (StoragePage) ─────────────────────
  // Every controller id answers, because /controllers/ does not yet honour
  // the controller_type filter the page passes; the page falls back to
  // devices[0], which is not the TrueNAS row.

/* ==== demo: Dashboard, alerts, analytics, security audit, notifications (the first screens a visitor sees) ==== */
  // ═══ Dashboard · alerts · analytics · security audit ═══════════════════
  // Placement matters: every branch below must sit ABOVE the three catch-alls
  //   if (path.startsWith('/analytics/')) return emptyList();
  //   if (path.startsWith('/enterprise') || ... '/alert-rules' ... '/correlation') return emptyList();
  //   if (path.startsWith('/security') || path.startsWith('/audit') || path.startsWith('/logs')) ...
  // or it is dead code and the page renders empty.

  // ── Analytics · alerts and metrics ──────────────────────────────────────

async function routeGet(path: string, config: InternalAxiosRequestConfig) {
  const q = params(config);

  /* ==== demo: network fleet (devices, switch ports, VLANs, WiFi/SSIDs, clients, topology) ==== */

/* ── NETWORK FLEET · routes (place INSIDE `routeGet`, before the generic
   /devices, /switches, /access-points, /network, /poe and /topology handlers
   listed in `notes` -- those must be REPLACED, not kept) ─────────────────── */

  // ── Devices ───────────────────────────────────────────────────────────────
  if (path === '/devices/stats/summary') {
    const scoped = fleetDevices(q);
    const count = (key: 'device_type' | 'status') => scoped.reduce<Record<string, number>>((acc, d) => {
      acc[d[key]] = (acc[d[key]] || 0) + 1;
      return acc;
    }, {});
    return {
      // DevicesPage reads total_devices / online_devices / offline_devices
      // (DeviceAggStats); the old total/online/offline keys rendered zeros.
      total_devices: scoped.length,
      online_devices: scoped.filter((d) => d.status === 'online').length,
      offline_devices: scoped.filter((d) => d.status === 'offline').length,
      by_type: count('device_type'),
      by_status: count('status'),
    };
  }
  if (/^\/devices\/[^/]+\/ports/.test(path)) return fleetPorts(path.split('/')[2]);
  if (/^\/devices\/[^/]+\/capabilities$/.test(path)) return { device_id: path.split('/')[2], capabilities: ['reboot', 'locate', 'poe', 'status'], actions: [] };
  if (path === '/devices') return paginated(fleetDevices(q).map(fresh), Number(q.page || 1), Number(q.per_page || 500));
  if (/^\/devices\/[^/]+$/.test(path)) {
    const raw = networkDevices.find((d) => d.id === path.split('/')[2]);
    return raw ? fresh(raw) : null;
  }

  // ── Switches ──────────────────────────────────────────────────────────────
  if (path === '/switches/profiles') return [];
  if (/^\/switches\/[^/]+\/ports$/.test(path)) return fleetPorts(path.split('/')[2]);
  if (/^\/switches\/[^/]+\/ports\/\d+$/.test(path)) {
    const [, , switchId, , portIndex] = path.split('/');
    return fleetPorts(switchId).find((p) => p.port_index === Number(portIndex)) || null;
  }
  if (/^\/switches\/[^/]+\/vlans$/.test(path)) {
    const sw = networkDevices.find((d) => d.id === path.split('/')[2]);
    const ports = fleetPortSpec(sw?.id || '');
    return networkVlans.filter((v) => v.site_id === sw?.site_id).map((v) => ({
      id: v.id,
      vlan_id: v.vlan_id,
      name: v.name,
      description: v.description,
      purpose: v.purpose,
      gateway: v.gateway,
      subnet: v.subnet,
      cidr: v.cidr,
      dhcp_enabled: v.dhcp_enabled,
      untagged_ports: ports.filter((p) => p.vlan === v.vlan_id).length,
      tagged_ports: ports.filter((p) => p.tagged.includes(v.vlan_id)).length,
    }));
  }
  if (/^\/switches\/[^/]+\/lags$/.test(path)) return switchLags.filter((l) => l.device_id === path.split('/')[2]);
  if (/^\/switches\/[^/]+\/clients$/.test(path)) return switchClients(path.split('/')[2]);
  if (/^\/switches\/[^/]+\/lldp$/.test(path)) {
    const switchId = path.split('/')[2];
    return fleetPortSpec(switchId).filter((p) => p.peer).map((p) => ({
      port_index: p.i,
      port_name: p.name,
      neighbor_device: p.peer,
      neighbor_port: p.peerPort,
      neighbor_ip: networkDevices.find((d) => d.name === p.peer)?.ip_address,
      neighbor_mac: networkDevices.find((d) => d.name === p.peer)?.mac_address,
      chassis_id: networkDevices.find((d) => d.name === p.peer)?.mac_address,
      system_name: p.peer,
      system_description: networkDevices.find((d) => d.name === p.peer)?.model,
    }));
  }
  if (/^\/switches\/[^/]+\/mac-table$/.test(path)) {
    const switchId = path.split('/')[2];
    const attached = networkClients.filter((c) => c.dev === switchId && c.status === 'online');
    const ports = clientPorts(switchId, attached.length);
    return attached.map((c, index) => ({
      mac_address: c.mac,
      vlan_id: vlanFromIp(c.ip),
      port: ports[index],
      type: 'dynamic',
    })).concat(fleetPortSpec(switchId).filter((p) => p.peer).map((p) => ({
      mac_address: networkDevices.find((d) => d.name === p.peer)?.mac_address || '',
      vlan_id: 99,
      port: p.i,
      type: 'dynamic',
    })));
  }
  if (path === '/switches') {
    const rows = fleetDevices(q).filter((d) => d.device_type === 'switch').map(switchSummary);
    return paginated(rows, Number(q.page || 1), Number(q.per_page || 200));
  }
  if (/^\/switches\/[^/]+$/.test(path)) {
    const sw = networkDevices.find((d) => d.id === path.split('/')[2] && d.device_type === 'switch');
    return sw ? switchSummary(sw) : null;
  }

  // ── Access points ─────────────────────────────────────────────────────────
  if (/^\/access-points\/[^/]+\/clients$/.test(path)) return apClients(path.split('/')[2]);
  if (/^\/access-points\/[^/]+\/radios$/.test(path)) return apRadios.filter((r) => r.device_id === path.split('/')[2]);
  if (/^\/access-points\/[^/]+\/firmware$/.test(path)) {
    const ap = networkDevices.find((d) => d.id === path.split('/')[2]);
    return { curFwVer: ap?.firmware_version || '1.0.0', latestFwVer: ap?.update_available ? '1.1.0' : ap?.firmware_version, needUpgrade: !!ap?.update_available };
  }
  if (path === '/access-points') {
    const rows = fleetDevices(q).filter((d) => d.device_type === 'access_point').map(apSummary);
    return paginated(rows, Number(q.page || 1), Number(q.per_page || 200));
  }
  if (/^\/access-points\/[^/]+$/.test(path)) {
    const ap = networkDevices.find((d) => d.id === path.split('/')[2] && d.device_type === 'access_point');
    if (!ap) return null;
    return { ...apSummary(ap), lan_port_vlan_enabled: true, lan_port_vlan_id: 99, lan_port_poe_enabled: null, ssid_overrides: [], location: null };
  }

  // ── Network module ────────────────────────────────────────────────────────
  if (path === '/network/summary') return fleetNetworkSummary(q);
  if (path === '/network/topology') {
    const graph = fleetTopologyGraph(q);
    return {
      nodes: graph.nodes.map((n) => ({
        id: n.id,
        name: n.label,
        device_type: n.device_type,
        ip_address: n.ip_address,
        status: n.status,
        model: n.model,
        vendor: networkDevices.find((d) => d.id === n.id)?.vendor,
      })),
      links: graph.edges.map((e) => ({
        source: e.source_id,
        target: e.target_id,
        source_port: e.source_port,
        target_port: e.target_port,
        speed: e.speed,
        status: e.status,
      })),
    };
  }
  if (path === '/network/vlans' || /^\/network\/vlans\/[^/]+$/.test(path)) {
    const one = networkVlans.find((v) => v.id === path.split('/')[3]);
    if (one) return one;
    const items = bySite(networkVlans, q);
    return { items, total: items.length, skip: Number(q.skip || 0), limit: Number(q.limit || 500) };
  }
  if (path === '/network/wifi' || /^\/network\/wifi\/[^/]+$/.test(path)) {
    const one = wifiNetworks.find((w) => w.id === path.split('/')[3]);
    if (one) return one;
    let items = bySite(wifiNetworks, q);
    if (q.enabled !== undefined) items = items.filter((w) => w.enabled === q.enabled);
    return { items, total: items.length, skip: Number(q.skip || 0), limit: Number(q.limit || 500) };
  }
  if (path === '/network/clients' || /^\/network\/clients\/[^/]+$/.test(path)) {
    const toClient = (c: (typeof networkClients)[number]) => ({
      id: c.id,
      mac_address: c.mac,
      ip_address: c.ip ?? undefined,
      hostname: c.host ?? undefined,
      display_name: c.host ?? undefined,
      connection_type: c.type,
      status: c.status,
      blocked: c.blocked,
      connected_device_id: c.dev,
      ssid: c.ssid ?? undefined,
      signal_strength: c.sig,
      rx_bytes: c.rx,
      tx_bytes: c.tx,
      first_seen: iso(c.m + 60 * 24 * 9),
      last_seen: iso(c.m),
      site_id: c.site,
    });
    const one = networkClients.find((c) => c.id === path.split('/')[3]);
    if (one) return toClient(one);
    let items = networkClients.filter((c) => !q.site_id || c.site === q.site_id).map(toClient);
    if (q.connection_type) items = items.filter((c) => c.connection_type === q.connection_type);
    if (q.status) items = items.filter((c) => c.status === q.status);
    if (q.blocked !== undefined) items = items.filter((c) => c.blocked === q.blocked);
    return { items, total: items.length, skip: Number(q.skip || 0), limit: Number(q.limit || 500) };
  }
  if (/^\/network\/devices\/[^/]+\/ports/.test(path)) {
    return fleetPorts(path.split('/')[3]).map((p) => ({
      id: p.id,
      device_id: p.device_id,
      port_number: p.port_index,
      name: p.name,
      enabled: p.enabled,
      poe_enabled: p.poe_config.enabled,
      native_vlan: p.vlan_config.native_vlan,
      tagged_vlans: p.vlan_config.tagged_vlans,
      status: p.enabled ? p.status.link_status : 'disabled',
      speed: p.speed,
      duplex: p.duplex,
      poe_power_draw: p.status.poe_power_draw,
      rx_bytes: p.status.rx_bytes,
      tx_bytes: p.status.tx_bytes,
    }));
  }
  if (path === '/network/devices' || /^\/network\/devices\/[^/]+$/.test(path)) {
    const toNetDevice = (d: FleetDevice) => ({
      id: d.id,
      name: d.name,
      device_type: d.device_type,
      model: d.model,
      vendor: d.vendor,
      firmware_version: d.firmware_version,
      ip_address: d.ip_address,
      mac_address: d.mac_address,
      status: d.status,
      uptime: d.uptime,
      site_id: d.site_id,
      capabilities: { poe: d.poe_ports > 0, vlans: d.device_type === 'switch', radios: d.device_type === 'access_point' },
    });
    const one = networkDevices.find((d) => d.id === path.split('/')[3]);
    if (one) return toNetDevice(one);
    const items = fleetDevices(q).map(toNetDevice);
    return { items, total: items.length, skip: Number(q.skip || 0), limit: Number(q.limit || 500) };
  }

  // ── PoE ───────────────────────────────────────────────────────────────────
  if (path === '/poe/devices' || /^\/poe\/devices\/[^/]+$/.test(path) || /^\/poe\/devices\/[^/]+\/ports$/.test(path)) {
    const poeSwitch = (d: FleetDevice) => ({
      device_id: d.id,
      device_name: d.name,
      model: d.model,
      power_budget: d.poe_budget,
      power_used: d.poe_used,
      power_available: Math.max(0, d.poe_budget - d.poe_used),
      power_percentage: d.poe_budget ? Math.round((d.poe_used / d.poe_budget) * 100) : 0,
      total_poe_ports: d.poe_ports,
      active_poe_ports: fleetPortSpec(d.id).filter((p) => p.poe && p.w > 0).length,
      disabled_poe_ports: fleetPortSpec(d.id).filter((p) => p.poe && !p.on).length,
      fault_poe_ports: 0,
      near_budget: d.poe_budget > 0 && d.poe_used / d.poe_budget > 0.85,
      over_budget: false,
    });
    if (path.endsWith('/ports')) return poePorts(path.split('/')[3]);
    const one = networkDevices.find((d) => d.id === path.split('/')[3]);
    if (one) return poeSwitch(one);
    return bySite(networkDevices, q).filter((d) => d.poe_budget > 0).map(poeSwitch);
  }
  if (path === '/poe/ports') {
    const scoped = bySite(networkDevices, q).filter((d) => d.poe_budget > 0);
    const rows = scoped.flatMap((d) => poePorts(d.id));
    return q.device_id ? rows.filter((p) => p.device_id === q.device_id) : rows;
  }

  // ── Topology (enterprise graph) ───────────────────────────────────────────
  if (path === '/topology/graph') return fleetTopologyGraph(q);
  if (/^\/topology\/layout\/[^/]+$/.test(path)) return null;

  /* ==== demo: Pending/staged changes (the approval queue) + the Firewall module (gateways, rules, NAT, aliases, IDS/event feed) ==== */
  // ── Staged writes (the approval queue) ──────────────────────────────
  //
  // Every device mutation in FreeSDN lands in ``adapter_pending_changes``
  // and only reaches the device behind an explicit apply, so the demo
  // serves a real queue. Applying/discarding are POSTs and hit the demo
  // read-only guard, which is the same wall an operator meets with
  // ADAPTER_READ_ONLY=true.

  // Batched fast path: PendingChangesDrawer + PendingChangesBadge
  // (listChangesForGateway). The gateway id doubles as the controller id.
  const changesByGateway = path.match(/^\/gateway-vpn\/changes\/by-gateway\/([^/]+)$/);
  if (changesByGateway) {
    return filterPendingChanges(pendingChanges, {
      controllerId: changesByGateway[1],
      status: typeof q.status === 'string' ? q.status : 'all',
    });
  }

  // Per-domain lists behind PendingChangesPage (/gateway/pending) and the
  // feature pages. Each backend route filters on a feature prefix, so the
  // demo does too, otherwise one change would appear in five domains.
  const changesByDomain = path.match(
    /^\/gateway-(vpn|firmware|profiles|firewall|wifi|switch-advanced|routing|hotspot|bulk|system|storage)\/([^/]+)(?:\/sites\/([^/]+))?\/changes$/,
  );
  if (changesByDomain) {
    return filterPendingChanges(pendingChanges, {
      controllerId: changesByDomain[2],
      siteId: changesByDomain[3],
      featurePrefixes: pendingChangeDomainPrefixes[changesByDomain[1]],
      status: typeof q.status === 'string' ? q.status : 'pending',
    });
  }

  // Historical per-vendor fanout (the fallback listChangesForGateway uses
  // when the batched endpoint 404s).
  const changesByVendor = path.match(
    /^\/gateway-(mikrotik|pfsense|opnsense|openwrt|unifi|freepbx|proxmox)-[a-z-]+\/([^/]+)\/changes$/,
  );
  if (changesByVendor) {
    return filterPendingChanges(pendingChanges, {
      controllerId: changesByVendor[2],
      featurePrefixes: [`${changesByVendor[1]}.`],
      status: typeof q.status === 'string' ? q.status : 'pending',
    });
  }

  // ── Firewall module: gateway connections ────────────────────────────
  if (path === '/firewall/gateways/summary') return firewallGatewaySummary;
  if (path === '/firewall/gateways') {
    const owned = firewallGateways
      .filter((g) => !q.site_id || g.site_id === q.site_id)
      .filter((g) => !q.vendor || g.vendor === q.vendor);
    return { items: owned, total: owned.length };
  }
  const gatewaySub = path.match(/^\/firewall\/gateways\/([^/]+)\/(.+)$/);
  if (gatewaySub) {
    // Keyed by the URL tail; an absent key degrades to {} so the detail
    // page's `?? []` renders an honest empty table instead of crashing.
    const bundle = gatewayLiveData[gatewaySub[1]] as AnyRecord | undefined;
    if (bundle && gatewaySub[2] in bundle) return bundle[gatewaySub[2]] as AnyRecord;
    return {};
  }
  const gatewayOne = path.match(/^\/firewall\/gateways\/([^/]+)$/);
  if (gatewayOne) {
    return firewallGateways.find((g) => g.id === gatewayOne[1]) ?? firewallGateways[0];
  }

  // ── Firewall module: normalized local-DB records ────────────────────
  if (path === '/firewall/rules') {
    return paginated(firewallRules.filter((r) => !q.site_id || r.site_id === q.site_id));
  }
  const oneRule = path.match(/^\/firewall\/rules\/([^/]+)$/);
  if (oneRule) return firewallRules.find((r) => r.id === oneRule[1]) ?? null;
  if (path === '/firewall/nat') {
    return paginated(firewallNatRules.filter((r) => !q.site_id || r.site_id === q.site_id));
  }
  const oneNat = path.match(/^\/firewall\/nat\/([^/]+)$/);
  if (oneNat) return firewallNatRules.find((r) => r.id === oneNat[1]) ?? null;
  if (path === '/firewall/vpn/stats') return firewallVpnStats;
  if (path === '/firewall/vpn') {
    return paginated(firewallVpnTunnels.filter((t) => !q.site_id || t.site_id === q.site_id));
  }
  const oneVpn = path.match(/^\/firewall\/vpn\/([^/]+)$/);
  if (oneVpn) return firewallVpnTunnels.find((t) => t.id === oneVpn[1]) ?? null;
  if (path === '/firewall/ids/alerts/stats') return firewallIdsAlertStats;
  if (path === '/firewall/ids/alerts') {
    return paginated(
      firewallIdsAlerts
        .filter((a) => !q.site_id || a.site_id === q.site_id)
        .filter((a) => !q.severity || a.severity === q.severity),
    );
  }
  if (path === '/firewall/logs') {
    return paginated(
      firewallLogs
        .filter((l) => !q.site_id || l.site_id === q.site_id)
        .filter((l) => !q.action || l.action === q.action),
    );
  }

  /* ==== demo: cameras and VoIP ==== */
  if (path === '/cameras' || path === '/cameras/') {
    const limit = Number(q.limit || 100);
    const offset = Number(q.offset || 0);
    let rows = demoCameras;
    if (q.site_id) rows = rows.filter((c) => c.site_id === q.site_id);
    if (q.status) rows = rows.filter((c) => c.status === q.status);
    if (q.camera_type) rows = rows.filter((c) => c.camera_type === q.camera_type);
    if (q.search) {
      const needle = String(q.search).toLowerCase();
      rows = rows.filter((c) => `${c.name} ${c.location} ${c.ip_address} ${c.model}`.toLowerCase().includes(needle));
    }
    return { ...paginated(rows.slice(offset, offset + limit), 1, limit), total: rows.length };
  }
  if (path === '/cameras/streams/stats') return { active_streams: 0, target_fps: 0, frame_interval_ms: 0, per_nvr: {}, overloaded_nvrs: [], snapshot_cache_channels: demoCameras.length };
  if (path === '/cameras/events/unacknowledged/count') return { count: demoCameraEvents.filter((e) => !e.is_acknowledged).length };
  if (path === '/cameras/events' || path === '/cameras/events/') {
    let rows = demoCameraEvents;
    if (q.camera_id) rows = rows.filter((e) => e.camera_id === q.camera_id);
    if (q.event_type) rows = rows.filter((e) => e.event_type === q.event_type);
    // start_time/end_time are deliberately NOT applied: fixtures.ts pins `now`
    // to a fixed date, so a real "last 24h" window would match nothing and the
    // events tab would render empty. See notes.
    if (q.acknowledged !== undefined && q.acknowledged !== null) {
      const want = q.acknowledged === true || q.acknowledged === 'true';
      rows = rows.filter((e) => e.is_acknowledged === want);
    }
    const limit = Number(q.limit || 50);
    const offset = Number(q.offset || 0);
    return { ...paginated(rows.slice(offset, offset + limit), 1, limit), total: rows.length };
  }
  if (/^\/cameras\/events\/[^/]+$/.test(path)) return demoCameraEvents.find((e) => e.id === path.split('/')[3]) ?? null;
  if (path === '/cameras/groups' || path === '/cameras/groups/') {
    return { items: demoCameraGroups.map((g) => ({ ...g, camera_count: g.camera_ids.length })), total: demoCameraGroups.length };
  }
  if (/^\/cameras\/groups\/[^/]+$/.test(path)) {
    const group = demoCameraGroups.find((g) => g.id === path.split('/')[3]) ?? demoCameraGroups[0];
    return {
      ...group,
      camera_count: group.camera_ids.length,
      cameras: group.camera_ids.map((cid, i) => {
        const cam = demoCameras.find((c) => c.id === cid);
        return { camera_id: cid, sort_order: i, name: cam?.name ?? cid, status: cam?.status ?? 'unknown' };
      }),
    };
  }
  if (path === '/cameras/views' || path === '/cameras/views/') return { items: demoCameraViews, total: demoCameraViews.length };
  if (path === '/cameras/health/fleet-summary') {
    const online = demoCameraHealth.filter((h) => h.is_online);
    const totalKbps = online.reduce((sum, h) => sum + (h.bitrate_kbps ?? 0), 0);
    return {
      total_cameras: demoCameras.length,
      online_cameras: online.length,
      offline_cameras: demoCameras.length - online.length,
      avg_bitrate_kbps: Math.round(totalKbps / Math.max(1, online.length)),
      total_bandwidth_mbps: Math.round(totalKbps / 100) / 10,
    };
  }
  if (path === '/cameras/reports' || path === '/cameras/reports/') return { items: demoCameraReports, total: demoCameraReports.length };
  if (/^\/cameras\/reports\/[^/]+$/.test(path)) return demoCameraReports.find((r) => r.id === path.split('/')[3]) ?? demoCameraReports[0];
  if (path === '/cameras/evidence') {
    const rows = q.camera_id ? demoEvidenceArchives.filter((e) => e.camera_id === q.camera_id) : demoEvidenceArchives;
    return { items: rows };
  }
  if (path === '/cameras/recording-templates' || path === '/cameras/recording-templates/') return demoRecordingTemplates;
  if (path === '/cameras/recordings/search') return { items: [], total: 0 };
  if (path === '/cameras/access/grants') {
    const rows = q.camera_id
      ? demoCameraAccessGrants.filter((g) => g.camera_id === q.camera_id || g.camera_id === null)
      : demoCameraAccessGrants;
    return { items: rows, total: rows.length };
  }
  if (path.startsWith('/cameras/access/check/')) return { has_access: true, access_level: 'full', can_live: true, can_playback: true, can_ptz: true, can_export: true, can_configure: false, grant_source: 'role:super_admin' };
  if (path === '/cameras/push/vapid-key') return { enabled: false, public_key: '' };

  // NVRs, before the /cameras/{id} catch-alls below.
  if (path === '/cameras/nvrs/stats') {
    const rows = q.site_id ? demoNvrs.filter((n) => n.site_id === q.site_id) : demoNvrs;
    return {
      total: rows.length,
      online: rows.filter((n) => n.status === 'online').length,
      offline: rows.filter((n) => n.status === 'offline').length,
      error: 0,
      total_channels: rows.reduce((sum, n) => sum + n.channel_count, 0),
      total_cameras: demoCameras.filter((c) => rows.some((n) => n.id === c.nvr_id)).length,
    };
  }
  if (path === '/cameras/nvrs/health/time-drift') {
    return { items: demoNvrs.map((n) => ({ nvr_id: n.id, nvr_name: n.name, drift_seconds: 0, threshold_seconds: 30, checked_at: iso(2), status: 'ok' })), total: demoNvrs.length };
  }
  if (path === '/cameras/nvrs' || path === '/cameras/nvrs/') {
    const rows = q.site_id ? demoNvrs.filter((n) => n.site_id === q.site_id) : demoNvrs;
    const items = rows.map((n) => ({
      ...n,
      cameras: demoCameras.filter((c) => c.nvr_id === n.id).map((c) => ({ id: c.id, name: c.name, status: c.status })),
    }));
    return { ...paginated(items, 1, 200), total: rows.length };
  }
  if (/^\/cameras\/nvrs\/[^/]+\/channels$/.test(path)) {
    const nvrId = path.split('/')[3];
    const items = demoCameras.filter((c) => c.nvr_id === nvrId).map((c) => ({
      id: c.id, name: c.name, channel_id: c.channel_id, ip_address: c.ip_address, status: c.status,
      camera_type: c.camera_type, has_ptz: c.has_ptz, has_audio: c.has_audio, model: c.model,
      vendor: c.vendor, is_recording: c.is_recording,
    }));
    return { items, total: items.length };
  }
  if (/^\/cameras\/nvrs\/[^/]+\/channel-status$/.test(path)) {
    const nvrId = path.split('/')[3];
    return {
      nvr_id: nvrId,
      channels: demoCameras.filter((c) => c.nvr_id === nvrId).map((c) => ({ id: c.channel_id, name: c.name, online: c.status !== 'offline', ip_address: c.ip_address })),
    };
  }
  if (/^\/cameras\/nvrs\/[^/]+\/storage$/.test(path)) {
    const nvrId = path.split('/')[3];
    const store = demoNvrStorage.find((s) => s.nvr_id === nvrId) ?? demoNvrStorage[0];
    return store;
  }
  if (/^\/cameras\/nvrs\/[^/]+\/system-info$/.test(path)) {
    const nvrId = path.split('/')[3];
    const info = demoNvrSystemInfo.find((s) => s.nvr_id === nvrId) ?? demoNvrSystemInfo[0];
    const store = demoNvrStorage.find((s) => s.nvr_id === nvrId) ?? demoNvrStorage[0];
    const net = demoNvrNetwork.find((s) => s.nvr_id === nvrId) ?? demoNvrNetwork[0];
    return {
      data: {
        device: info.device,
        system_status: info.system_status,
        time: info.time,
        network_interfaces: net.interfaces,
        storage: store,
        recording_tracks: demoCameras.filter((c) => c.nvr_id === nvrId).map((c) => ({
          id: String(c.channel_id), channel: c.channel_id, track_type: 'video', enabled: c.is_recording,
          description: c.name, codec: c.vendor === 'hikvision' ? 'H.265' : 'H.264', loop_enable: true, src_url: c.rtsp_main_stream,
        })),
      },
    };
  }
  if (/^\/cameras\/nvrs\/[^/]+\/network$/.test(path)) {
    const net = demoNvrNetwork.find((s) => s.nvr_id === path.split('/')[3]) ?? demoNvrNetwork[0];
    return { data: { time: net.time, interfaces: net.interfaces } };
  }
  if (/^\/cameras\/nvrs\/[^/]+\/recording-status$/.test(path)) {
    const nvrId = path.split('/')[3];
    return {
      data: demoCameras.filter((c) => c.nvr_id === nvrId).map((c) => ({
        id: String(c.channel_id), channel: c.channel_id, track_type: 'video', enabled: c.is_recording,
        description: c.name, codec: c.vendor === 'hikvision' ? 'H.265' : 'H.264', loop_enable: true, src_url: c.rtsp_main_stream,
      })),
    };
  }
  if (/^\/cameras\/nvrs\/[^/]+\/holidays$/.test(path)) return { holidays: demoNvrHolidays };
  if (/^\/cameras\/nvrs\/[^/]+$/.test(path)) return demoNvrs.find((n) => n.id === path.split('/')[3]) ?? demoNvrs[0];

  // Per-camera routes.
  if (/^\/cameras\/[^/]+\/snapshot$/.test(path) || /^\/cameras\/[^/]+\/playback-frame$/.test(path)) {
    const imagePath = getDemoCameraSnapshotPath(path.split('/')[2]);
    if (typeof fetch === 'function') {
      const image = await fetch(imagePath);
      if (image.ok) return image.blob();
    }
    return new Blob([], { type: 'image/jpeg' });
  }
  if (/^\/cameras\/[^/]+\/stream-token$/.test(path)) return { token: 'demo-stream-token' };
  if (/^\/cameras\/[^/]+\/timeline$/.test(path)) {
    // 24 hourly recording segments ending "now", the shape RecordingTimeline reads.
    const segments = Array.from({ length: 24 }, (_, i) => ({
      start: iso((24 - i) * 60),
      end: iso((23 - i) * 60),
      type: i % 6 === 0 ? 'motion' : 'continuous',
    }));
    return { segments, supported: true };
  }
  if (/^\/cameras\/[^/]+\/health\/history$/.test(path)) {
    const cameraId = path.split('/')[2];
    const base = demoCameraHealth.find((h) => h.camera_id === cameraId) ?? demoCameraHealth[0];
    return {
      camera_id: cameraId,
      snapshots: Array.from({ length: 48 }, (_, i) => ({
        ...base,
        bitrate_kbps: base.bitrate_kbps === null ? null : Math.round(base.bitrate_kbps * (0.88 + ((i * 7) % 25) / 100)),
        captured_at: iso((47 - i) * 30),
      })),
    };
  }
  if (/^\/cameras\/[^/]+\/health$/.test(path)) {
    const cameraId = path.split('/')[2];
    return demoCameraHealth.find((h) => h.camera_id === cameraId) ?? demoCameraHealth[0];
  }
  if (/^\/cameras\/[^/]+\/smart-capabilities$/.test(path)) {
    const cam = demoCameras.find((c) => c.id === path.split('/')[2]);
    const hik = cam?.vendor === 'hikvision';
    return { motion_detection: true, line_crossing: hik, intrusion_detection: hik, privacy_mask: hik, face_detection: hik, vehicle_detection: true, person_detection: true };
  }
  if (/^\/cameras\/[^/]+\/motion-detection$/.test(path)) return { enabled: true, sensitivity_level: 60, grid_map: 'ffffffffffffffffffffff' };
  if (/^\/cameras\/[^/]+\/privacy-masks$/.test(path)) return { enabled: false, regions: [] };
  if (/^\/cameras\/[^/]+\/line-crossing$/.test(path)) return { enabled: true, rules: [{ id: 1, enabled: true, sensitivity: 50, direction: 'both', coordinates: [{ x: 120, y: 540 }, { x: 880, y: 540 }] }] };
  if (/^\/cameras\/[^/]+\/intrusion-detection$/.test(path)) return { enabled: true, rules: [{ id: 1, enabled: true, sensitivity: 55, time_threshold: 5, coordinates: [{ x: 180, y: 220 }, { x: 820, y: 220 }, { x: 820, y: 780 }, { x: 180, y: 780 }] }] };
  if (/^\/cameras\/[^/]+\/face-detection$/.test(path)) return { enabled: false, sensitivity: 50, snap_interval: 2, generation_speed: 3, min_width: 64, min_height: 64, max_width: 1024, max_height: 1024 };
  if (/^\/cameras\/[^/]+\/recording-schedule$/.test(path)) {
    return {
      supported: true,
      enabled: true,
      days: [1, 2, 3, 4, 5, 6, 7].map((d) => ({
        id: d,
        action_type: 'record',
        time_blocks: [{ id: `${d}-1`, begin_time: '00:00:00', end_time: '24:00:00', record_type: d <= 5 ? 'continuous' : 'motion' }],
      })),
    };
  }
  if (/^\/cameras\/[^/]+\/holiday-schedule$/.test(path)) return { enabled: false, days: [] };
  if (/^\/cameras\/[^/]+\/ptz\/tours$/.test(path)) {
    const cam = demoCameras.find((c) => c.id === path.split('/')[2]);
    if (!cam?.has_ptz) return [];
    return [{ id: 1, name: 'Perimeter patrol', enabled: true, actions: [{ id: 1, preset_id: 1, dwell: 20, speed: 40 }, { id: 2, preset_id: 2, dwell: 20, speed: 40 }, { id: 3, preset_id: 3, dwell: 30, speed: 40 }] }];
  }
  if (/^\/cameras\/[^/]+\/ptz\/presets$/.test(path)) {
    const cam = demoCameras.find((c) => c.id === path.split('/')[2]);
    if (!cam?.has_ptz) return { items: [] };
    return { items: [{ id: 1, name: 'Home', enabled: true }, { id: 2, name: 'Entrance', enabled: true }, { id: 3, name: 'Car park', enabled: true }, { id: 4, name: 'Loading dock', enabled: true }] };
  }
  if (/^\/cameras\/[^/]+\/image$/.test(path)) return { brightness: 50, contrast: 52, saturation: 50, sharpness: 48, hue: 50, wdr_enabled: true, wdr_level: 40, noise_reduction_enabled: true, noise_reduction_level: 30, ir_cut_filter: 'auto', exposure_mode: 'auto', backlight_mode: 'off' };
  if (/^\/cameras\/[^/]+\/codec-info$/.test(path)) {
    const health = demoCameraHealth.find((h) => h.camera_id === path.split('/')[2]) ?? demoCameraHealth[0];
    return { codec: health.codec === 'H.265' ? 'h265' : 'h264', resolution: `${health.resolution_width ?? 0}x${health.resolution_height ?? 0}`, bitrate_kbps: health.bitrate_kbps };
  }
  if (/^\/cameras\/[^/]+$/.test(path)) return demoCameras.find((c) => c.id === path.split('/')[2]) ?? null;
  if (path.startsWith('/cameras')) return emptyList();

  // ── VoIP ───────────────────────────────────────────────────────────────────
  if (path === '/voip/fleet/dashboard') return demoVoipFleetDashboard;
  if (path === '/voip/phones/stats') {
    const rows = q.site_id ? demoVoipPhones.filter((p) => p.site_id === q.site_id) : demoVoipPhones;
    return {
      total: rows.length,
      online: rows.filter((p) => p.status === 'online').length,
      offline: rows.filter((p) => p.status === 'offline').length,
      in_call: rows.filter((p) => p.status === 'in_call').length,
    };
  }
  if (path === '/voip/phones' || path === '/voip/phones/') {
    let rows = demoVoipPhones;
    if (q.site_id) rows = rows.filter((p) => p.site_id === q.site_id);
    if (q.pbx_id) rows = rows.filter((p) => p.pbx_id === q.pbx_id);
    if (q.status) rows = rows.filter((p) => p.status === q.status);
    if (q.lifecycle_state) rows = rows.filter((p) => p.lifecycle_state === q.lifecycle_state);
    if (q.vendor) rows = rows.filter((p) => p.vendor === q.vendor);
    if (q.search) {
      const needle = String(q.search).toLowerCase();
      rows = rows.filter((p) => `${p.name} ${p.ip_address} ${p.mac_address} ${p.model} ${p.extension ?? ''}`.toLowerCase().includes(needle));
    }
    const limit = Number(q.limit || 100);
    const offset = Number(q.offset || 0);
    return { ...paginated(rows.slice(offset, offset + limit), 1, limit), total: rows.length };
  }
  if (/^\/voip\/phones\/[^/]+\/config-preview$/.test(path)) {
    const phone = demoVoipPhones.find((p) => p.id === path.split('/')[3]);
    return [
      '# FreeSDN generated provisioning file (demo, credentials omitted)',
      `# device   : ${phone?.model ?? 'unknown'} ${phone?.mac_address ?? ''}`,
      `# template : ${phone?.config_template_id ?? 'none'}`,
      'P270 = ' + (phone?.extension ?? ''),
      'P271 = 1',
      'P47  = ' + (phone?.sip_server ?? ''),
      'P34  = ********  # SIP password is never rendered in the demo',
      'P8  = 30        # voice VLAN',
    ].join('\n');
  }
  if (/^\/voip\/phones\/[^/]+\/live-status$/.test(path)) {
    const phone = demoVoipPhones.find((p) => p.id === path.split('/')[3]);
    return { phone_state: phone?.status === 'in_call' ? 'in_call' : phone?.status === 'ringing' ? 'ringing' : 'available', active_lines: [], total_lines: 2, lockout: 'ok' };
  }
  if (/^\/voip\/phones\/[^/]+$/.test(path)) return demoVoipPhones.find((p) => p.id === path.split('/')[3]) ?? null;

  if (path === '/voip/extensions' || path === '/voip/extensions/') {
    const sitePbxIds = demoPbxSystems.filter((p) => !q.site_id || p.site_id === q.site_id).map((p) => p.id);
    const rows = demoVoipExtensions.filter((e) => sitePbxIds.includes(e.pbx_id));
    const limit = Number(q.limit || 100);
    const offset = Number(q.offset || 0);
    return { items: rows.slice(offset, offset + limit), total: rows.length };
  }
  if (path === '/voip/ring-groups' || path === '/voip/ring-groups/') {
    const sitePbxIds = demoPbxSystems.filter((p) => !q.site_id || p.site_id === q.site_id).map((p) => p.id);
    const rows = demoRingGroups
      .filter((g) => sitePbxIds.includes(g.pbx_id))
      .filter((g) => !q.pbx_id || g.pbx_id === q.pbx_id);
    return { items: rows, total: rows.length };
  }
  if (path === '/voip/call-logs/stats') return demoCallStats;
  if (path === '/voip/call-logs' || path === '/voip/call-logs/') {
    const sitePbxIds = demoPbxSystems.filter((p) => !q.site_id || p.site_id === q.site_id).map((p) => p.id);
    let rows = demoCallLogs.filter((c) => sitePbxIds.includes(c.pbx_id));
    if (q.pbx_id) rows = rows.filter((c) => c.pbx_id === q.pbx_id);
    if (q.direction) rows = rows.filter((c) => c.direction === q.direction);
    if (q.call_status) rows = rows.filter((c) => c.status === q.call_status);
    if (q.caller) rows = rows.filter((c) => c.caller_number.includes(String(q.caller)));
    if (q.callee) rows = rows.filter((c) => c.callee_number.includes(String(q.callee)));
    const limit = Number(q.limit || 100);
    return { items: rows.slice(0, limit), total: rows.length };
  }
  if (path === '/voip/voicemails/stats') return demoVoicemailStats;
  if (path === '/voip/voicemails' || path === '/voip/voicemails/') {
    const sitePbxIds = demoPbxSystems.filter((p) => !q.site_id || p.site_id === q.site_id).map((p) => p.id);
    let rows = demoVoicemails.filter((v) => sitePbxIds.includes(v.pbx_id));
    if (q.extension_number) rows = rows.filter((v) => v.extension_number === q.extension_number);
    if (q.folder) rows = rows.filter((v) => v.folder === q.folder);
    if (q.is_read !== undefined && q.is_read !== null) rows = rows.filter((v) => v.is_read === (q.is_read === true || q.is_read === 'true'));
    const limit = Number(q.limit || 100);
    const offset = Number(q.offset || 0);
    return { items: rows.slice(offset, offset + limit), total: rows.length };
  }
  if (/^\/voip\/voicemails\/[^/]+$/.test(path)) return demoVoicemails.find((v) => v.id === path.split('/')[3]) ?? null;

  if (path === '/voip/templates' || path === '/voip/templates/') {
    const rows = q.site_id ? demoVoipTemplates.filter((t) => t.site_id === q.site_id) : demoVoipTemplates;
    return { items: rows, total: rows.length };
  }
  if (/^\/voip\/templates\/[^/]+$/.test(path)) return demoVoipTemplates.find((t) => t.id === path.split('/')[3]) ?? demoVoipTemplates[0];
  if (path === '/voip/firmware/compliance') {
    const groups = Object.values(
      demoVoipPhones.reduce<Record<string, { vendor: string; model: string; recommended_version: string | null; total_phones: number; compliant: number; non_compliant: number; unknown: number; versions: Record<string, number> }>>((acc, p) => {
        const key = `${p.vendor}/${p.model}`;
        acc[key] = acc[key] ?? { vendor: p.vendor, model: p.model, recommended_version: p.firmware_target, total_phones: 0, compliant: 0, non_compliant: 0, unknown: 0, versions: {} };
        acc[key].total_phones += 1;
        if (p.firmware_target === null) acc[key].unknown += 1;
        else if (p.firmware_version === p.firmware_target) acc[key].compliant += 1;
        else acc[key].non_compliant += 1;
        acc[key].versions[p.firmware_version] = (acc[key].versions[p.firmware_version] ?? 0) + 1;
        return acc;
      }, {}),
    );
    return { groups };
  }
  if (path === '/voip/firmware' || path === '/voip/firmware/') {
    let rows = demoVoipFirmwareTracks;
    if (q.vendor) rows = rows.filter((f) => f.vendor === q.vendor);
    if (q.model) rows = rows.filter((f) => f.model === q.model);
    return { items: rows, total: rows.length };
  }
  if (path === '/voip/discovery/scans') {
    const rows = q.site_id ? demoVoipDiscoveryScans.filter((s) => s.site_id === q.site_id) : demoVoipDiscoveryScans;
    return { items: rows, total: rows.length };
  }
  if (/^\/voip\/discovery\/scans\/[^/]+\/status$/.test(path)) {
    const scan = demoVoipDiscoveryScans.find((s) => s.id === path.split('/')[4]) ?? demoVoipDiscoveryScans[0];
    return { scan_id: scan.id, status: scan.status, devices_found: scan.devices_found, started_at: scan.started_at, completed_at: scan.completed_at, progress: { phase: 'done', percent: 100, message: 'Scan complete', devices_found: scan.devices_found, log: [], devices: [] } };
  }
  if (/^\/voip\/discovery\/scans\/[^/]+$/.test(path)) return demoVoipDiscoveryScans.find((s) => s.id === path.split('/')[4]) ?? demoVoipDiscoveryScans[0];

  // PBX collection + per-PBX sub-resources.
  if (path === '/voip/pbx' || path === '/voip/pbx/') {
    const rows = q.site_id ? demoPbxSystems.filter((p) => p.site_id === q.site_id) : demoPbxSystems;
    return { items: rows, total: rows.length };
  }
  if (/^\/voip\/pbx\/[^/]+\/dashboard$/.test(path)) {
    const pbxId = path.split('/')[3];
    const pbx = demoPbxSystems.find((p) => p.id === pbxId) ?? demoPbxSystems[0];
    const exts = demoVoipExtensions.filter((e) => e.pbx_id === pbx.id);
    const boxes = demoVoicemailBoxes.filter((b) => b.pbx_id === pbx.id);
    const phones = demoVoipPhones.filter((p) => p.pbx_id === pbx.id);
    return {
      pbx_id: pbx.id,
      name: pbx.name,
      pbx_type: pbx.pbx_type,
      status: 'online',
      ip_address: pbx.ip_address,
      api_port: pbx.api_port,
      sip_port: pbx.sip_port,
      total_extensions: exts.length,
      online_extensions: phones.filter((p) => p.sip_registered).length,
      total_trunks: demoSipTrunks.filter((t) => t.pbx_id === pbx.id).length,
      active_calls: demoActiveCalls.filter((c) => c.pbx_id === pbx.id).length,
      calls_today: demoCallLogs.filter((c) => c.pbx_id === pbx.id).length,
      voicemail_boxes: boxes.length,
      unread_voicemails: demoVoicemails.filter((v) => v.pbx_id === pbx.id && !v.is_read).length,
      ring_groups: demoRingGroups.filter((g) => g.pbx_id === pbx.id).length,
      queues: demoCallQueues.filter((qq) => qq.pbx_id === pbx.id).length,
      ivrs: demoIvrs.filter((i) => i.pbx_id === pbx.id).length,
      dids: demoDids.filter((d) => d.pbx_id === pbx.id).length,
      ami_connected: true,
      ari_connected: true,
      rest_available: true,
      asterisk_version: String(pbx.settings.asterisk_version),
      last_sync: pbx.last_seen,
      needs_reload: Boolean(pbx.settings.needs_reload),
    };
  }
  if (/^\/voip\/pbx\/[^/]+\/system-info$/.test(path)) {
    const pbx = demoPbxSystems.find((p) => p.id === path.split('/')[3]) ?? demoPbxSystems[0];
    return {
      host: pbx.ip_address,
      asterisk_version: String(pbx.settings.asterisk_version),
      freepbx_version: String(pbx.settings.freepbx_version),
      ami_connected: true,
      ari_connected: true,
      rest_available: true,
      ari_info: { version: '8.0.0', build: 'demo' },
      freepbx_status: { modules_enabled: 47, needs_reload: Boolean(pbx.settings.needs_reload) },
    };
  }
  if (/^\/voip\/pbx\/[^/]+\/extensions\/[^/]+$/.test(path)) {
    const pbxId = path.split('/')[3];
    const extNumber = path.split('/')[5];
    const ext = demoVoipExtensions.find((e) => e.pbx_id === pbxId && e.extension_number === extNumber);
    if (!ext) return null;
    return { ...ext, bound_phones: demoBoundPhones.filter((b) => b.extension_id === ext.id) };
  }
  if (/^\/voip\/pbx\/[^/]+\/extensions$/.test(path)) {
    const pbxId = path.split('/')[3];
    const items = demoVoipExtensions
      .filter((e) => e.pbx_id === pbxId)
      .map((e) => ({ ...e, bound_phones: demoBoundPhones.filter((b) => b.extension_id === e.id) }));
    return { items, total: items.length };
  }
  if (/^\/voip\/pbx\/[^/]+\/trunks\/[^/]+$/.test(path)) {
    const pbxId = path.split('/')[3];
    const trunkId = path.split('/')[5];
    return demoSipTrunks.find((t) => t.pbx_id === pbxId && t.trunk_id === trunkId) ?? demoSipTrunks[0];
  }
  if (/^\/voip\/pbx\/[^/]+\/trunks$/.test(path)) {
    const rows = demoSipTrunks.filter((t) => t.pbx_id === path.split('/')[3]);
    return { items: rows, total: rows.length };
  }
  if (/^\/voip\/pbx\/[^/]+\/queues$/.test(path)) {
    const rows = demoCallQueues.filter((c) => c.pbx_id === path.split('/')[3]);
    return { items: rows, total: rows.length };
  }
  if (/^\/voip\/pbx\/[^/]+\/ivrs$/.test(path)) {
    const rows = demoIvrs.filter((i) => i.pbx_id === path.split('/')[3]);
    return { items: rows, total: rows.length };
  }
  if (/^\/voip\/pbx\/[^/]+\/dids$/.test(path)) {
    const rows = demoDids.filter((d) => d.pbx_id === path.split('/')[3]);
    return { items: rows, total: rows.length };
  }
  if (/^\/voip\/pbx\/[^/]+\/active-calls$/.test(path)) {
    const rows = demoActiveCalls.filter((c) => c.pbx_id === path.split('/')[3]);
    return { items: rows, total: rows.length };
  }
  if (/^\/voip\/pbx\/[^/]+\/voicemail-boxes$/.test(path)) {
    const rows = demoVoicemailBoxes.filter((b) => b.pbx_id === path.split('/')[3]);
    return { items: rows, total: rows.length };
  }
  if (/^\/voip\/pbx\/[^/]+\/ring-groups$/.test(path)) {
    const rows = demoRingGroups.filter((g) => g.pbx_id === path.split('/')[3]);
    return { items: rows, total: rows.length };
  }
  if (/^\/voip\/pbx\/[^/]+\/call-logs$/.test(path)) {
    const rows = demoCallLogs.filter((c) => c.pbx_id === path.split('/')[3]);
    return { items: rows.slice(0, Number(q.limit || 100)), total: rows.length };
  }
  if (/^\/voip\/pbx\/[^/]+\/config$/.test(path)) {
    const pbxId = path.split('/')[3];
    const pbx = demoPbxSystems.find((p) => p.id === pbxId) ?? demoPbxSystems[0];
    return {
      pbx_id: pbx.id,
      pbx_name: pbx.name,
      pbx_type: pbx.pbx_type,
      synced_at: pbx.last_seen,
      extensions: demoVoipExtensions.filter((e) => e.pbx_id === pbx.id),
      ring_groups: demoRingGroups.filter((g) => g.pbx_id === pbx.id),
      trunks: demoSipTrunks.filter((t) => t.pbx_id === pbx.id),
      queues: demoCallQueues.filter((c) => c.pbx_id === pbx.id),
      ivrs: demoIvrs.filter((i) => i.pbx_id === pbx.id),
      dids: demoDids.filter((d) => d.pbx_id === pbx.id),
      voicemail_boxes: demoVoicemailBoxes.filter((b) => b.pbx_id === pbx.id),
      outbound_routes: [],
      followme: [],
      announcements: [],
      paging_groups: [],
      daynight: [],
      blacklist: [],
      certificates: [],
      admin_users: [],
    };
  }
  if (/^\/voip\/pbx\/[^/]+\/(outbound-routes|followme|announcements|paging|daynight|blacklist|certificates|admin-users)$/.test(path)) {
    return { items: [], total: 0 };
  }
  if (/^\/voip\/pbx\/[^/]+$/.test(path)) return demoPbxSystems.find((p) => p.id === path.split('/')[3]) ?? null;
  if (path.startsWith('/voip')) return emptyList();

  /* ==== demo: hypervisor, storage, backup ==== */
  if (/^\/controllers\/[^/]+\/storage$/.test(path)) return demoStorageInventory;

  // ── Hypervisor (Proxmox VE) ───────────────────────────────────────────
  if (path === '/hypervisor/fleet/dashboard') return getDemoHypervisorFleetDashboard();
  if (path === '/hypervisor/fleet/task-statistics') {
    // FleetTaskStatistics nests the counters under `aggregate`; the Fleet tab
    // unwraps that key, and a flat payload leaves every counter undefined.
    return {
      controllers: { [demoIds.proxmox]: demoHypervisorTaskStats },
      aggregate: demoHypervisorTaskStats,
    };
  }

  const hv = path.match(/^\/hypervisor\/controllers\/[^/]+(\/.*)?$/);
  if (hv) {
    const rest = hv[1] || '';
    const hvNode = rest.match(/^\/nodes\/([^/]+)(\/.*)?$/);

    if (hvNode) {
      const node = hvNode[1];
      const sub = hvNode[2] || '';

      // Guest-scoped: /qemu/<vmid>/… or /lxc/<vmid>/…
      const guestPath = sub.match(/^\/(?:qemu|lxc)\/(\d+)(\/.*)?$/);
      if (guestPath) {
        const vmid = Number(guestPath[1]);
        const leaf = guestPath[2] || '';
        const guest = demoHypervisorGuests.find((g) => g.vmid === vmid) || null;
        if (leaf === '/snapshots') return demoHypervisorSnapshots.filter((s) => s.vmid === vmid);
        if (leaf === '/rrd') return demoHypervisorGuestRrd;
        if (leaf === '/agent/info') return demoHypervisorGuestAgent;
        if (leaf === '/firewall/rules') return demoHypervisorFirewallRules.slice(0, 3);
        if (leaf === '/firewall/options') {
          return { enable: true, policy_in: 'DROP', policy_out: 'ACCEPT', dhcp: true, macfilter: true, ndp: true, ipfilter: false, log_level_in: 'nolog', log_level_out: 'nolog' };
        }
        if (leaf === '/pending') return [];
        if (leaf === '/cloudinit') {
          return { user: 'demo', ssh_keys: [], nameserver: '10.20.0.1', searchdomain: 'demo.local', ipconfig0: 'ip=dhcp' };
        }
        if (leaf === '/config') {
          if (!guest) return {};
          return {
            name: guest.name,
            cores: guest.cpu_cores,
            sockets: 2,
            memory: guest.memory_mb,
            ostype: guest.os_type,
            onboot: 1,
            agent: 'enabled=1',
            boot: 'order=scsi0;ide2;net0',
            scsihw: 'virtio-scsi-single',
            scsi0: `ceph-vm:vm-${guest.vmid}-disk-0,size=${guest.disk_gb}G,discard=on`,
            net0: `virtio=02:00:00:20:10:${String(guest.vmid % 100).padStart(2, '0')},bridge=vmbr0,tag=10`,
            tags: guest.tags.join(';'),
            description: `Demo guest ${guest.name} on ${guest.node}`,
          };
        }
        return guest;
      }

      if (sub === '') return demoHypervisorNodes.find((n) => n.node === node) || demoHypervisorNodes[0];
      if (sub === '/vms') return demoHypervisorGuests.filter((g) => g.node === node && g.vm_type === 'qemu');
      if (sub === '/containers') return demoHypervisorGuests.filter((g) => g.node === node && g.vm_type === 'lxc');
      if (sub === '/storage') return demoHypervisorStorages.filter((s) => s.node === node);
      if (sub === '/network') return demoHypervisorNodeNetwork.filter((i) => i.node === node);
      if (sub === '/services') return demoHypervisorNodeServices.filter((s) => s.node === node);
      if (sub === '/disks') return demoHypervisorNodeDisks.filter((d) => d.node === node);
      if (sub === '/disks/smart') return demoHypervisorDiskSmart;
      if (sub === '/sensors') return demoHypervisorNodeSensors.find((s) => s.node === node) || demoHypervisorNodeSensors[0];
      if (sub === '/subscription') return demoHypervisorSubscriptions.find((s) => s.node === node) || demoHypervisorSubscriptions[0];
      if (sub === '/apt/updates') return demoHypervisorAptUpdates.filter((u) => u.node === node);
      if (sub === '/apt/versions') return demoHypervisorAptUpdates.filter((u) => u.node === node);
      if (sub === '/certificates') return demoHypervisorCertificates.filter((c) => c.node === node);
      if (sub === '/ceph/status') return demoHypervisorCephStatus;
      if (sub === '/ceph/detail') return demoHypervisorCephDetail;
      if (sub === '/firewall/rules') return demoHypervisorFirewallRules;
      if (sub === '/rrd') return demoHypervisorNodeRrd;
      if (sub === '/syslog') return demoHypervisorClusterLog.map((e, i) => ({ n: i + 1, t: `${new Date(e.time * 1000).toISOString()} ${e.node} ${e.tag}: ${e.msg}` }));
      if (sub === '/tasks') return demoHypervisorTasks.filter((t) => t.node === node).slice(0, Number(q.limit || 50));
      if (/^\/tasks\/[^/]+\/status$/.test(sub)) {
        const running = demoHypervisorTasks.find((t) => t.node === node && t.is_running) || demoHypervisorTasks[0];
        return { ...running, exitstatus: running.is_running ? '' : running.status };
      }
      if (/^\/tasks\/[^/]+\/log$/.test(sub)) return demoHypervisorTaskLog;

      const hvStore = sub.match(/^\/storage\/([^/]+)\/(content|prune-preview)$/);
      if (hvStore) {
        const store = hvStore[1];
        if (hvStore[2] === 'prune-preview') {
          return demoHypervisorPrunePreview.filter((p) => !q.vmid || p.vmid === Number(q.vmid));
        }
        return demoHypervisorStorageContent
          .filter((v) => v.storage === store)
          .filter((v) => !q.content || v.content === q.content)
          .filter((v) => !q.vmid || v.vmid === Number(q.vmid));
      }
      return emptyList();
    }

    if (rest === '/dashboard') return getDemoHypervisorDashboard();
    if (rest === '/cluster/status') return demoHypervisorClusterStatus;
    if (rest === '/cluster/resources') {
      return q.type ? demoHypervisorClusterResources.filter((r) => r.type === q.type) : demoHypervisorClusterResources;
    }
    if (rest === '/cluster/log') return demoHypervisorClusterLog.slice(0, Number(q.max_entries || 200));
    if (rest === '/cluster/replication') return demoHypervisorReplicationJobs;
    if (/^\/cluster\/replication\/[^/]+\/log$/.test(rest)) return demoHypervisorReplicationLog;
    if (rest === '/cluster/config/nodes') return demoHypervisorClusterConfigNodes;
    if (rest === '/cluster/options') return { keyboard: 'en-us', migration: { type: 'secure', network: '10.20.99.0/24' }, ha: { shutdown_policy: 'migrate' }, mac_prefix: '02:00:00' };
    if (rest === '/cluster/firewall/options') return { enable: 1, policy_in: 'DROP', policy_out: 'ACCEPT', log_ratelimit: 'enable=1,rate=1/second,burst=5', ebtables: 1 };
    if (rest === '/firewall/rules') return demoHypervisorFirewallRules;
    if (rest === '/ha/resources') return demoHypervisorHaResources;
    if (rest === '/ha/groups') return demoHypervisorHaGroups;
    if (rest === '/pools') return demoHypervisorPools;
    if (rest === '/nextid') return { vmid: 171 };
    if (rest === '/backup/jobs') return demoHypervisorBackupJobs;
    if (rest === '/backup/age-report') return demoHypervisorBackupAgeReport;
    if (rest === '/sdn/zones') return demoHypervisorSdnZones;
    if (rest === '/sdn/vnets') return demoHypervisorSdnVnets;
    if (rest === '/sdn/controllers') return demoHypervisorSdnControllers;
    if (rest === '/nodes') return demoHypervisorNodes;
    if (rest === '/vms') {
      return q.type ? demoHypervisorGuests.filter((g) => g.vm_type === q.type) : demoHypervisorGuests;
    }
    return emptyList();
  }
  if (path.startsWith('/hypervisor/nodes')) return demoHypervisorNodes;
  if (path.startsWith('/hypervisor/vms')) return paginated(demoHypervisorGuests);
  if (path.startsWith('/hypervisor')) return emptyList();

  // ── Backups: config snapshots, schedules, destinations, restore points ─
  if (path === '/backups/stats') return demoBackupStats;
  if (path === '/backups/storage-locations/types/supported') return demoBackupStorageTypes;
  if (path === '/backups/storage-locations') {
    return demoStorageLocations
      .filter((l) => !q.storage_type || l.storage_type === q.storage_type)
      .filter((l) => q.is_active === undefined || String(l.is_active) === String(q.is_active));
  }
  if (/^\/backups\/storage-locations\/[^/]+$/.test(path)) {
    return findById(demoStorageLocations, path.split('/')[3]);
  }
  if (path === '/backups/schedules') {
    return demoBackupSchedules.filter((s) => !q.site_id || s.site_id === q.site_id || s.site_id === null);
  }
  if (/^\/backups\/schedules\/[^/]+$/.test(path)) {
    return findById(demoBackupSchedules, path.split('/')[3]);
  }
  if (/^\/backups\/restore\/[^/]+$/.test(path)) {
    return findById(demoRestoreJobs, path.split('/')[3]);
  }
  if (path === '/backups/export') {
    return new Blob(
      [JSON.stringify({ format: 'fsdn', version: '2.1', demo: true, note: 'Read-only FreeSDN demo export. No device credentials are included.' }, null, 2)],
      { type: 'application/json' },
    );
  }
  if (/^\/backups\/[^/]+\/manifest$/.test(path)) {
    const backupId = path.split('/')[2];
    const source = demoBackups.find((b) => b.id === backupId) || demoBackups[0];
    return { backup_id: source.id, created_at: source.created_at, ...demoBackupManifest };
  }
  if (/^\/backups\/[^/]+\/download$/.test(path)) {
    const backupId = path.split('/')[2];
    const source = demoBackups.find((b) => b.id === backupId) || demoBackups[0];
    return new Blob(
      [JSON.stringify({ format: 'fsdn', version: '2.1', demo: true, backup: source.name, note: 'Placeholder archive for the read-only demo.' }, null, 2)],
      { type: 'application/json' },
    );
  }
  if (path === '/backups') {
    const search = String(q.search || '').toLowerCase();
    const rows = demoBackups
      .filter((b) => !q.status || b.status === q.status)
      .filter((b) => !q.backup_type || b.backup_type === q.backup_type)
      .filter((b) => !q.storage_type || b.storage_type === q.storage_type)
      // Org-wide backups (site_id null) cover every site, so they stay visible
      // when the site switcher narrows to one site.
      .filter((b) => !q.site_id || b.site_id === q.site_id || b.site_id === null)
      .filter((b) => !search || b.name.toLowerCase().includes(search) || (b.description || '').toLowerCase().includes(search));
    return paginated(rows, Number(q.page || 1), Number(q.per_page || 50));
  }
  if (/^\/backups\/[^/]+$/.test(path)) return findById(demoBackups, path.split('/')[2]);
  if (path.startsWith('/backups')) return emptyList();

  // ── Staged writes awaiting review (Pending Changes drawer / badge) ─────
  // Shared route: every gateway vendor's drawer reads it, filtered by ?vendor.
  if (/^\/gateway-vpn\/changes\/by-gateway\/[^/]+$/.test(path)) {
    const gatewayId = path.split('/')[4];
    return demoStagedChanges
      .filter((c) => c.controller_id === gatewayId)
      .filter((c) => !q.status || q.status === 'all' || c.status === q.status);
  }
  if (/^\/gateway-storage\/[^/]+\/changes$/.test(path)) {
    return demoStagedChanges.filter((c) => c.controller_id === path.split('/')[2]);
  }

  /* ==== demo: Dashboard, alerts, analytics, security audit, notifications (the first screens a visitor sees) ==== */
  if (path === '/analytics/alerts' || path === '/analytics/alerts/') {
    const filtered = alerts.filter((a) => (
      (!q.status || a.status === q.status)
      && (!q.severity || a.severity === q.severity)
      && (!q.site_id || a.site_id === q.site_id)
    ));
    return filtered.slice(0, Number(q.limit || 50));
  }
  if (/^\/analytics\/alerts\/[^/]+$/.test(path)) return findById(alerts, path.split('/')[3]);
  if (path === '/analytics/metrics/definitions') {
    return metricDefinitions.filter((m) => !q.category || m.category === q.category);
  }
  if (/^\/analytics\/metrics\/definitions\/[^/]+$/.test(path)) {
    const metricName = path.split('/')[4];
    return metricDefinitions.find((m) => m.name === metricName) || metricDefinitions[0];
  }
  if (/^\/analytics\/sites\/[^/]+\/traffic$/.test(path)) {
    return {
      site_id: path.split('/')[3],
      period_hours: Number(q.hours || 24),
      total_rx_bytes: demoRxBytes24h,
      total_tx_bytes: demoTxBytes24h,
      peak_rx_bps: 940_000_000,
      peak_tx_bps: 316_000_000,
      avg_rx_bps: Math.round((demoRxBytes24h * 8) / 86_400),
      avg_tx_bps: Math.round((demoTxBytes24h * 8) / 86_400),
      data_points: demoTrafficSeries.map((p) => ({
        timestamp: p.timestamp,
        rx_bps: p.rx_mbps * 1_000_000,
        tx_bps: p.tx_mbps * 1_000_000,
        clients: p.clients,
      })),
      top_clients: [
        { mac: '02:00:00:10:20:01', ip: '10.10.10.44', hostname: 'finance-laptop', rx: 88_400_000_000, tx: 12_100_000_000 },
        { mac: '02:00:00:10:20:07', ip: '10.10.10.62', hostname: 'design-ws-02', rx: 64_900_000_000, tx: 21_800_000_000 },
        { mac: '02:00:00:10:40:21', ip: '10.10.40.21', hostname: 'cam-front-door', rx: 1_200_000_000, tx: 48_600_000_000 },
      ],
      top_applications: [
        { app: 'Video conferencing', rx: 96_400_000_000, tx: 74_200_000_000, connections: 1_284 },
        { app: 'Cloud storage sync', rx: 128_900_000_000, tx: 34_100_000_000, connections: 642 },
        { app: 'Camera streams (RTSP)', rx: 4_200_000_000, tx: 212_400_000_000, connections: 96 },
        { app: 'Web browsing', rx: 74_800_000_000, tx: 9_600_000_000, connections: 8_412 },
      ],
      traffic_by_category: { productivity: 0.34, video: 0.28, surveillance: 0.21, backup: 0.11, other: 0.06 },
    };
  }

  // ── Alert-rules engine ──────────────────────────────────────────────────
  if (path === '/alert-rules/stats') return alertRuleStats;
  if (path === '/alert-rules/rules') {
    const filtered = alertRules.filter((r) => (
      (!q.status || r.status === q.status) && (!q.type || r.rule_type === q.type)
    ));
    return { rules: filtered, total: filtered.length };
  }
  if (/^\/alert-rules\/rules\/[^/]+$/.test(path)) return findById(alertRules, path.split('/')[3]);
  if (path === '/alert-rules/alerts') {
    const filtered = alertInstances.filter((a) => (
      (!q.status || a.status === q.status)
      && (!q.severity || a.severity === q.severity)
      && (!q.rule_id || a.rule_id === q.rule_id)
      && (!q.site_id || a.site_id === q.site_id)
    ));
    const offset = Number(q.offset || 0);
    return { alerts: filtered.slice(offset, offset + Number(q.limit || 200)), total: filtered.length };
  }
  if (/^\/alert-rules\/alerts\/[^/]+$/.test(path)) return findById(alertInstances, path.split('/')[3]);

  // ── Correlation engine ──────────────────────────────────────────────────
  if (path === '/correlation/stats') return correlationStats;
  if (path === '/correlation/rules') {
    const filtered = correlationRules.filter((r) => !q.status || r.status === q.status);
    return { rules: filtered, total: filtered.length };
  }
  if (/^\/correlation\/rules\/[^/]+$/.test(path)) return findById(correlationRules, path.split('/')[3]);
  if (path === '/correlation/incidents') {
    const filtered = incidents.filter((i) => (
      (!q.status || i.status === q.status)
      && (!q.severity || i.severity === q.severity)
      && (!q.site_id || i.site_id === q.site_id)
    ));
    const offset = Number(q.offset || 0);
    return { incidents: filtered.slice(offset, offset + Number(q.limit || 200)), total: filtered.length };
  }
  if (/^\/correlation\/incidents\/[^/]+\/events$/.test(path)) return incidentEvents[path.split('/')[3]] ?? [];
  if (/^\/correlation\/incidents\/[^/]+$/.test(path)) return findById(incidents, path.split('/')[3]);

  // ── Security audit ──────────────────────────────────────────────────────
  if (path === '/security/events') {
    // SecurityAuditPage's filter offers `login_failure`; the backend event
    // name is `login_failed`. Accept both so the dropdown is not a dead end.
    const wantedType = q.event_type ? String(q.event_type).replace('login_failure', 'login_failed') : '';
    const search = q.search ? String(q.search).toLowerCase() : '';
    const filtered = securityEvents.filter((e) => (
      (!wantedType || e.event_type === wantedType)
      && (!q.severity || e.severity === q.severity)
      && (
        !search
        || e.event_type.includes(search)
        || e.user_email.toLowerCase().includes(search)
        || e.source_ip.includes(search)
      )
    ));
    const page = Number(q.page || 1);
    const pageSize = Number(q.page_size || 20);
    return {
      items: filtered.slice((page - 1) * pageSize, page * pageSize),
      total: filtered.length,
      page,
      page_size: pageSize,
    };
  }
  if (path === '/security/summary') return securitySummary;
  if (path === '/security/anomalies') return securityAnomalies;
  if (path === '/security/event-types') return { event_types: securityEventTypes };

  // ── Audit trail ─────────────────────────────────────────────────────────
  // /audit/security is the unified /alerts console; /audit/security-events is
  // the Security page. Same rows, same envelope.
  if (path === '/audit/security' || path === '/audit/security-events') {
    const search = q.search ? String(q.search).toLowerCase() : '';
    const filtered = securityEvents.filter((e) => (
      (!q.severity || e.severity === q.severity)
      && (
        !search
        || e.event_type.includes(search)
        || e.user_email.toLowerCase().includes(search)
        || e.ip_address.includes(search)
      )
    ));
    const page = Number(q.page || 1);
    const perPage = Number(q.per_page || 50);
    return {
      items: filtered.slice((page - 1) * perPage, page * perPage),
      total: filtered.length,
      page,
      per_page: perPage,
      pages: Math.max(1, Math.ceil(filtered.length / perPage)),
    };
  }
  if (path === '/audit/logs') {
    const action = q.action ? String(q.action) : '';
    const search = q.search ? String(q.search).toLowerCase() : '';
    const filtered = auditLogs.filter((l) => (
      (!action || l.action.includes(action))
      && (!q.site_id || l.site_id === q.site_id)
      && (
        !search
        || l.action.includes(search)
        || l.resource_name.toLowerCase().includes(search)
        || l.actor_name.toLowerCase().includes(search)
      )
    ));
    const page = Number(q.page || 1);
    const perPage = Number(q.per_page || 50);
    return {
      items: filtered.slice((page - 1) * perPage, page * perPage),
      total: filtered.length,
      page,
      per_page: perPage,
      pages: Math.max(1, Math.ceil(filtered.length / perPage)),
    };
  }
  if (path === '/audit/stats') return auditRollup;

  // ── Notifications ───────────────────────────────────────────────────────
  if (path === '/notifications/in-app') {
    const includeDismissed = String(q.include_dismissed) === 'true';
    const unreadOnly = String(q.unread_only) === 'true';
    const rows = inAppNotifications
      .filter((n) => (includeDismissed ? n.dismissed : !n.dismissed))
      .filter((n) => (unreadOnly ? !n.read : true));
    const limit = Number(q.limit || 20);
    const offset = Number(q.offset || 0);
    return {
      items: rows.slice(offset, offset + limit),
      total: rows.length,
      limit,
      offset,
      unread_count: inAppNotifications.filter((n) => !n.read && !n.dismissed).length,
    };
  }
  if (path === '/notifications/in-app/unread-count' || path === '/notifications/unread-count') {
    const unread = inAppNotifications.filter((n) => !n.read && !n.dismissed);
    return {
      total: unread.length,
      by_severity: unread.reduce<Record<string, number>>((acc, n) => {
        acc[n.severity] = (acc[n.severity] ?? 0) + 1;
        return acc;
      }, {}),
      by_category: unread.reduce<Record<string, number>>((acc, n) => {
        acc[n.category] = (acc[n.category] ?? 0) + 1;
        return acc;
      }, {}),
    };
  }
  if (path === '/notifications/providers') {
    return notificationProviders.filter((p) => (
      (!q.channel || p.channel === q.channel)
      && (String(q.enabled_only) !== 'true' || p.is_enabled)
    ));
  }
  if (path === '/notifications/providers/types') return notificationProviderTypes;

  // ── System log stream ───────────────────────────────────────────────────
  if (path === '/logs/health') return logsHealth;
  if (path === '/logs/stats') {
    const hours = Math.min(Number(q.hours) || 24, demoLogHourly.length);
    const buckets = demoLogHourly.slice(-hours);
    const total = buckets.reduce((sum, b) => sum + b.count, 0);
    const share = (fraction: number) => Math.round(total * fraction);
    return {
      total,
      by_level: {
        debug: share(0.246), info: share(0.583), warning: share(0.11),
        error: share(0.053), critical: share(0.0025), success: share(0.0055),
      },
      by_source: {
        device: share(0.309), api: share(0.291), auth: share(0.128),
        system: share(0.101), user: share(0.087), database: share(0.084),
      },
      by_hour: buckets,
      error_rate: 5.3,
      avg_duration_ms: 214,
    };
  }
  if (path === '/logs' || path === '/logs/') {
    const level = q.level ? String(q.level) : '';
    const source = q.source ? String(q.source) : '';
    const search = q.search ? String(q.search).toLowerCase() : '';
    const filtered = demoSystemLogs.filter((l) => (
      (!level || l.level === level)
      && (!source || l.source === source)
      && (!q.site_id || l.site_id === q.site_id)
      && (!search || l.message.toLowerCase().includes(search))
    ));
    const page = Number(q.page || 1);
    const perPage = Number(q.per_page || 50);
    return {
      items: filtered.slice((page - 1) * perPage, page * perPage),
      total: filtered.length,
      page,
      per_page: perPage,
      pages: Math.max(1, Math.ceil(filtered.length / perPage)),
    };
  }

  // ── Health trend (Enterprise > Health) ──────────────────────────────────
  if (path === '/enterprise/health/history') {
    const ranges: Record<string, number> = { '7d': 7, '30d': 30, '90d': 90 };
    return demoHealthHistory.slice(-(ranges[String(q.range || '7d')] ?? 7));
  }

  if (path === '/auth/me') return demoUser;
  if (path === '/health' || path.startsWith('/health/')) return health();
  // AboutSettingsTab and the System tab both read platform.app_version from
  // here. Without it About fell through to its own fallback, which is how the
  // demo reported 26.06.1 while serving an entirely current bundle.
  if (path === '/enterprise/health/infrastructure') {
    return {
      platform: {
        app_version: DEMO_VERSION,
        environment: 'demo',
        python_version: '3.14.4',
        uptime_seconds: 1_284_000,
      },
      database: { status: 'healthy', latency_ms: 3 },
      cache: { status: 'healthy', latency_ms: 1 },
      queue: { status: 'healthy', depth: 0 },
    };
  }
  if (path === '/system/info') return { app: 'FreeSDN', version: DEMO_VERSION, environment: 'demo', demo: true };
  if (path === '/system/frontend-versions') return { react: '19', vite: '8', demo: 'true' };

  if (path === '/organizations' || path === '/organizations/') return paginated(organizations);
  if (/^\/organizations\/[^/]+\/dashboard$/.test(path)) {
    const org = findById(organizations, path.split('/')[2]) as AnyRecord | null;
    if (!org) return null;
    return {
      ...org,
      contact_email: null,
      contact_phone: null,
      settings: { plan: 'enterprise' },
      site_count: sites.length,
      user_count: 12,
      controller_count: controllers.length,
      device_count: devices.length,
      online_device_count: devices.filter((d) => d.status === 'online').length,
      recent_sites: sites.slice(0, 3).map((s) => ({
        id: s.id, name: s.name, slug: s.slug, description: null, address: s.address || null,
        city: null, country: null, timezone: s.timezone, is_active: s.is_active,
        organization_id: s.organization_id, controller_count: s.controller_count,
        device_count: s.device_count, online_device_count: Math.max(1, s.device_count - 2),
        created_at: s.created_at, updated_at: s.updated_at,
      })),
    };
  }
  if (path.startsWith('/organizations/')) return findById(organizations, path.split('/')[2]);

  if (path === '/sites' || path === '/sites/') return paginated(sites, Number(q.page || 1), Number(q.per_page || 100));
  if (/^\/sites\/[^/]+\/health$/.test(path)) return { status: 'healthy', score: 94, open_alerts: 1, devices_online: 24, devices_total: 26 };
  if (/^\/sites\/[^/]+\/devices$/.test(path)) {
    const siteId = path.split('/')[2];
    return paginated(devices.filter((d) => d.site_id === siteId));
  }
  if (path.startsWith('/sites/')) return findById(sites, path.split('/')[2]);

  if (path === '/controllers' || path === '/controllers/') return paginated(controllers);
  if (/^\/controllers\/[^/]+\/capabilities$/.test(path)) {
    const controller = findById(controllers, path.split('/')[2]) as AnyRecord | null;
    return {
      controller_id: controller?.id,
      adapter_id: controller?.vendor,
      adapter_name: String(controller?.vendor || 'demo'),
      vendor: controller?.vendor,
      capabilities: ['read', 'stage_write', 'health', 'inventory'],
      by_device_type: { switch: ['ports', 'vlans', 'poe'], camera: ['snapshot'], firewall: ['rules', 'vpn'] },
      supports_bulk_operations: true,
    };
  }
  if (/^\/controllers\/[^/]+\/storage$/.test(path)) return {
    controller_id: demoIds.truenas,
    name: 'TrueNAS Backup Pool',
    host: 'truenas.demo.local',
    transport: 'ws-json-rpc',
    system: { version: '25.10', hostname: 'truenas-demo', product: 'TrueNAS SCALE', serial: 'DEMO-TRUENAS', physmem: 137_438_953_472, uptime_seconds: 18_800_000, timezone: 'America/New_York' },
    health: { status: 'warning', pool_count: 2, alert_count: 1, critical_alert_count: 0 },
    alerts: [{ level: 'WARNING', klass: 'PoolCapacity', message: 'tank-backup is above warning threshold', at_ms: Date.now(), one_shot: false }],
    services: [{ service: 'nfs', state: 'RUNNING', enabled: true }, { service: 'ssh', state: 'RUNNING', enabled: true }],
    data_protection: { snapshot_tasks: 8, replication: 2, cloudsync: 1 },
    pools: [{ name: 'tank-backup', status: 'ONLINE', healthy: true, size: 96_000_000_000_000, allocated: 78_000_000_000_000, free: 18_000_000_000_000, fragmentation: '12%', usage_percent: 82, is_decrypted: true, redundancy: { type: 'RAIDZ3', vdevs: 2, width: 8 }, scrub: null }],
    disks: [],
    datasets: [],
    snapshot_count: 420,
  };
  if (/^\/controllers\/[^/]+\/metadata$/.test(path)) {
    const controller = findById(controllers, path.split('/')[2]) as AnyRecord | null;
    const owned = devices.filter((d) => d.controller_id === controller?.id);
    return {
      controller_id: controller?.id,
      controller_name: controller?.name,
      controller_type: controller?.controller_type,
      status: controller?.status,
      runtime_status: { cpu_util: 42, mem_util: 58, disk_util: 65, uptime: 18_800_000, version: '5.15.20.16', model: String(controller?.vendor || 'demo'), device_count: controller?.device_count, site_count: 1, client_count: 128 },
      device_counts: { total: owned.length, online: Math.max(0, owned.length - 1), offline: Math.min(1, owned.length), switches: owned.filter((d) => d.device_type === 'switch').length, access_points: owned.filter((d) => d.device_type === 'access_point').length, gateways: owned.filter((d) => d.device_type === 'firewall').length },
      client_count: 128,
      poe_budget: { total_budget_watts: 384, total_consumed_watts: 184, total_remaining_watts: 200, switches_with_poe: 2 },
      firmware: { total_devices: owned.length, up_to_date: owned.length, needs_upgrade: 0, devices: owned.map((d) => ({ mac: d.mac_address, name: d.name, current: d.firmware_version || '1.0.0', latest: d.firmware_version || '1.0.0', needs_upgrade: false })) },
      sync: { last_sync: controller?.last_sync_at, last_sync_duration_seconds: 12.5, last_error: null, error_history: [] },
      site_mappings: {},
      devices: owned.map((d) => ({ id: d.id, name: d.name, type: d.device_type, status: d.status, mac: d.mac_address, ip: d.ip_address, model: d.model, firmware_version: d.firmware_version, cpu_usage: d.cpu_usage, memory_usage: d.memory_usage, uptime: d.uptime, poe_budget_watts: null, poe_consumed_watts: null, radios: null, clients: null })),
    };
  }
  if (path.startsWith('/controllers/')) return findById(controllers, path.split('/')[2]);

  if (path === '/devices/stats/summary') return { total: devices.length, online: dashboardSummary.devices_online, offline: 0, warning: dashboardSummary.devices_warning, by_type: { switch: 1, access_point: 2, firewall: 1, camera: 1, phone: 1, hypervisor: 1, storage: 1 } };
  if (/^\/devices\/[^/]+\/ports/.test(path)) return switchPorts(path.split('/')[2]);
  if (/^\/devices\/[^/]+\/capabilities$/.test(path)) return { device_id: path.split('/')[2], capabilities: ['reboot', 'locate', 'poe', 'status'], actions: [] };
  if (path === '/devices' || path === '/devices/') return paginated(devices);
  if (/^\/devices\/[^/]+$/.test(path)) {
    const raw = findById(devices, path.split('/')[2]) as AnyRecord | null;
    if (!raw) return null;
    return {
      ...raw,
      manufacturer: raw.vendor ?? null,
      is_active: true,
      is_managed: true,
      uptime_seconds: raw.uptime ?? null,
      cpu_usage_percent: raw.cpu_usage ?? null,
      memory_usage_percent: raw.memory_usage ?? null,
      port_count: raw.total_ports ?? 0,
      active_port_count: raw.ports_up ?? 0,
      client_count: raw.connected_clients ?? 0,
      discovery_method: 'agent',
      connection_type: 'wired',
      created_at: iso(6000),
      updated_at: iso(5),
      metadata: {},
      capabilities: {},
    };
  }
  if (path.startsWith('/devices/')) return findById(devices, path.split('/')[2]);

  if (path === '/analytics/dashboard/summary') return dashboardSummary;
  if (path === '/analytics/dashboard/enterprise') return enterpriseAnalytics;
  if (path === '/analytics/alerts') return alerts.filter((a) => !q.status || a.status === q.status);
  if (path === '/analytics/sites/comparison') return {
    sites: sites.map((site) => ({
      site_id: site.id,
      name: site.name,
      slug: site.slug,
      devices: { total: site.device_count, online: Math.max(1, site.device_count - 2), online_pct: 94, switches: 4, access_points: 6, cameras: 3, firewalls: 1, phones: 8 },
      phones: { total: 8, sip_registered: 7, managed: 8 },
      alerts: { open: alerts.filter((a) => a.site_id === site.id && a.status === 'active').length, critical_open: 0, last_24h: 3, last_7d: 9 },
      controllers: { total: site.controller_count, connected: site.controller_count },
      firmware: { tracked: site.device_count, compliant: site.device_count - 1, compliance_pct: 96 },
    })),
    summary: { total_sites: sites.length, total_devices: devices.length, total_online_devices: dashboardSummary.devices_online, total_phones: 22, total_alerts_open: 2, total_critical_open: 0, total_controllers: controllers.length, generated_at: new Date().toISOString() },
  };
  if (path.startsWith('/analytics/')) return emptyList();

  if (path === '/cameras' || path === '/cameras/') return paginated(cameras);
  if (path === '/cameras/streams/stats') return { active_streams: 0, target_fps: 0, frame_interval_ms: 0, per_nvr: {}, overloaded_nvrs: [], snapshot_cache_channels: cameras.length };
  if (path === '/cameras/events/unacknowledged/count') return { count: 1 };
  if (path.startsWith('/cameras/events')) return paginated(alerts.filter((a) => a.alert_type.startsWith('camera')));
  if (path.startsWith('/cameras/groups') || path.startsWith('/cameras/views')) return [];
  if (/^\/cameras\/[^/]+\/snapshot$/.test(path) || /^\/cameras\/[^/]+\/playback-frame$/.test(path)) {
    const imagePath = getDemoCameraSnapshotPath(path.split('/')[2]);
    if (typeof fetch === 'function') {
      const image = await fetch(imagePath);
      if (image.ok) return image.blob();
    }
    return new Blob([], { type: 'image/jpeg' });
  }
  if (/^\/cameras\/[^/]+\/stream-token$/.test(path)) return { token: 'demo-stream-token' };
  if (/^\/cameras\/[^/]+/.test(path)) return findById(cameras, path.split('/')[2]);

  if (path === '/modules' || path === '/modules/') return modulesEnvelope();
  if (path === '/modules/states') return { states: modules.map((m) => ({ module_id: m.id, state: 'running', started_orgs: [demoIds.org] })) };
  if (path.includes('/modules/org/') && path.endsWith('/navigation')) return { items: moduleNavItems };
  if (path.includes('/modules/org/')) return { modules: modules.map((m) => ({ module_id: m.id, is_enabled: true, enabled_at: new Date().toISOString(), settings: {}, manifest: m })) };

  if (path === '/notifications/in-app') return { ...paginated(alerts.map((a) => ({ id: a.id, title: a.title, body: a.message, category: a.alert_type, severity: a.severity, action_url: null, read: a.status !== 'active', created_at: a.triggered_at }))), unread_count: 2 };
  if (path === '/notifications/unread-count') return { total: 2 };
  if (path.startsWith('/notifications')) return emptyList();

  if (path === '/network/summary') return networkSummary();
  if (path === '/network/topology') return networkTopology();
  if (path.startsWith('/network/vlans')) return paginated([{ id: 'vlan-10', vlan_id: 10, name: 'Corporate', site_id: demoIds.hq }, { id: 'vlan-20', vlan_id: 20, name: 'Voice', site_id: demoIds.hq }, { id: 'vlan-40', vlan_id: 40, name: 'Cameras', site_id: demoIds.hq }]);
  if (path.startsWith('/network/clients')) return paginated([{ id: 'client-1', hostname: 'finance-laptop', mac_address: '02:00:00:10:20:01', ip_address: '10.10.10.44', connection_type: 'wireless', site_id: demoIds.hq }]);
  if (path.startsWith('/network/wifi')) return paginated([
    { id: 'ssid-corp', ssid: 'Acme-Corp', name: 'Acme-Corp', security: 'wpa2_personal', vlan_id: 10, site_id: demoIds.hq, hidden: false, enabled: true, band: 'both', client_isolation: false, band_steering: true, fast_roaming: false, rate_limit_enabled: false, rate_limit_up: undefined, rate_limit_down: undefined, guest_network: false, wlan_group_name: undefined, external_id: undefined, controller_id: demoIds.omada, schedule_enabled: false, mac_filter_enabled: false, portal_enabled: false },
    { id: 'ssid-guest', ssid: 'Acme-Guest', name: 'Acme-Guest', security: 'open', vlan_id: 30, site_id: demoIds.hq, hidden: false, enabled: true, band: '5ghz', client_isolation: true, band_steering: false, fast_roaming: false, rate_limit_enabled: true, rate_limit_up: 5000, rate_limit_down: 10000, guest_network: true, wlan_group_name: 'Guest Networks', external_id: undefined, controller_id: demoIds.omada, schedule_enabled: false, mac_filter_enabled: false, portal_enabled: true },
  ]);
  if (path === '/switches/profiles' || path === '/switches/profiles/') return [];
  if (/^\/switches\/[^/]+\/ports$/.test(path)) return switchPorts(path.split('/')[2]);
  if (/^\/switches\/[^/]+\/vlans$/.test(path)) return [{ id: 'vlan-10', vlan_id: 10, name: 'Corporate', tagged: false }, { id: 'vlan-20', vlan_id: 20, name: 'Voice', tagged: true }];
  if (path.startsWith('/switches')) return paginated(devices.filter((d) => d.device_type === 'switch').map((d) => ({
    ...d,
    poe_ports: Math.floor((d.total_ports ?? 0) * 0.3),
    sfp_ports: (d.total_ports ?? 0) >= 24 ? 2 : 0,
    ports_disabled: 0,
    vlans_configured: 4,
    connected_clients: 0,
    update_available: false,
  })));
  if (path.startsWith('/access-points')) return paginated(devices.filter((d) => d.device_type === 'access_point'));
  if (path === '/poe/devices' || path === '/poe/devices/') return [{ id: 'dev-sw-core', name: 'HQ-Core-SW-01', device_id: 'dev-sw-core', power_used: 184, power_budget: 384, active_poe_ports: 8, total_poe_ports: 28, disabled_poe_ports: 1, fault_poe_ports: 0, near_budget: false }];
  if (path === '/poe/ports' || path === '/poe/ports/') return [];
  if (path === '/poe/schedules' || path === '/poe/schedules/') return [];
  if (path.startsWith('/poe')) return { budget: 384, used: 184, available: 200, ports: switchPorts('dev-sw-core') };

  if (path === '/hypervisor/fleet/dashboard') return hypervisorFleetDashboard();
  if (path === '/hypervisor/fleet/task-statistics') return { ok: 14, running: 1, warning: 1, error: 0 };
  if (/^\/hypervisor\/controllers\/[^/]+\/dashboard$/.test(path)) return hypervisorDashboard;
  if (/^\/hypervisor\/controllers\/[^/]+\/nodes$/.test(path)) return hypervisorNodes;
  if (/^\/hypervisor\/controllers\/[^/]+\/nodes\/[^/]+$/.test(path)) return hypervisorNodes[0];
  if (/^\/hypervisor\/controllers\/[^/]+\/vms$/.test(path)) return hypervisorGuests;
  if (/^\/hypervisor\/controllers\/[^/]+\/nodes\/[^/]+\/vms$/.test(path)) return hypervisorGuests.filter((guest) => guest.vm_type === 'qemu');
  if (/^\/hypervisor\/controllers\/[^/]+\/nodes\/[^/]+\/containers$/.test(path)) return hypervisorGuests.filter((guest) => guest.vm_type === 'lxc');
  if (/^\/hypervisor\/controllers\/[^/]+\/nodes\/[^/]+\/storage$/.test(path)) return hypervisorStorage;
  if (/^\/hypervisor\/controllers\/[^/]+\/nodes\/[^/]+\/tasks$/.test(path)) return [{ upid: 'UPID:pve-node-01:demo', node: 'pve-node-01', type: 'vzdump', status: 'OK', user: 'root@pam', start_time: Date.now() / 1000 - 120, end_time: Date.now() / 1000 - 60, is_running: false }];
  if (/^\/hypervisor\/controllers\/[^/]+\/nodes\/[^/]+\/rrd$/.test(path)) return [{ time: Date.now() / 1000, cpu: 0.36, mem: 97_600_000_000, netin: 12_400, netout: 8_800 }];
  if (path.startsWith('/hypervisor/nodes')) return hypervisorNodes;
  if (path.startsWith('/hypervisor/vms')) return paginated(hypervisorGuests);
  if (path.startsWith('/hypervisor')) return emptyList();

  const phoneDetailMatch = path.match(/^\/voip\/phones\/([^/]+)$/);
  if (phoneDetailMatch) {
    const p = devices.find((d) => d.id === phoneDetailMatch[1] && d.device_type === 'phone');
    if (p) return { ...p, lifecycle_state: 'managed', provision_status: 'provisioned', sip_registered: true, extension: '101' };
  }
  if (path.startsWith('/voip/phones')) return paginated(devices.filter((d) => d.device_type === 'phone'));
  if (path.startsWith('/voip/extensions')) return paginated([{ id: 'ext-101', extension: '101', name: 'Reception', status: 'registered' }, { id: 'ext-204', extension: '204', name: 'Support Queue', status: 'registered' }]);
  if (path.startsWith('/voip')) return emptyList();

  if (path.startsWith('/backups/stats')) return { total_backups: 14, completed_backups: 13, failed_backups: 1, total_size_bytes: 1_842_000_000, latest_at: new Date().toISOString() };
  if (path.startsWith('/backups/storage-locations/types/supported')) return { types: ['local', 's3', 'sftp'] };
  if (path === '/backups/schedules' || path === '/backups/schedules/') return [];
  if (path.startsWith('/backups')) return paginated([{ id: 'backup-1', name: 'HQ nightly config snapshot', status: 'success', created_at: new Date().toISOString(), size_bytes: 842_000 }]);

  if (path === '/enterprise/health/devices') {
    const filtered = devices
      .filter((d) => !q.site_id || d.site_id === q.site_id)
      .filter((d) => !q.device_type || d.device_type === q.device_type);
    const rows = filtered.map((d, idx) => {
      const base = d.status === 'online' ? 94 - idx : 72;
      return {
        device_id: d.id,
        device_name: d.name,
        device_type: d.device_type,
        ip_address: d.ip_address || null,
        site_name: d.site_name || null,
        site_id: d.site_id || null,
        health_score: base,
        health_status: base >= 90 ? 'healthy' : base >= 70 ? 'warning' : 'degraded',
        reachability_score: 96,
        latency_score: 91,
        drift_score: 88,
        error_score: 93,
        utilization_score: 78,
        firmware_score: 95,
        score_history: Array.from({ length: 7 }, (_, i) => ({ t: iso((6 - i) * 1440), s: base - 2 + (i % 3) })),
        updated_at: iso(2),
      };
    });
    const limit = Number(q.limit || 50);
    const offset = Number(q.offset || 0);
    return { devices: rows.slice(offset, offset + limit), total: rows.length };
  }
  if (/^\/enterprise\/health\/site\/[^/]+$/.test(path)) {
    const siteId = path.split('/')[4];
    const siteObj = sites.find((s) => s.id === siteId);
    return {
      site_id: siteId,
      site_name: siteObj?.name || 'Unknown',
      device_count: devices.filter((d) => d.site_id === siteId).length,
      avg_health_score: siteObj?.status === 'healthy' ? 94 : 80,
      health_status: siteObj?.status === 'healthy' ? 'healthy' : 'warning',
      healthy: Math.max(0, (siteObj?.device_count || 0) - 4),
      warning: 2,
      degraded: 1,
      critical: 0,
      uptime_percent: siteObj?.status === 'healthy' ? 99.9 : 99.2,
    };
  }
  if (path === '/enterprise/health/top-issues') return { issues: [
    { device_id: devices[0].id, device_name: devices[0].name, device_type: devices[0].device_type, site_name: sites[0].name, site_id: sites[0].id, health_score: 65, health_status: 'warning', worst_component: 'reachability', worst_component_score: 65 },
  ] };
  if (path === '/enterprise/health/site-ranking') return sites.map((s) => ({ site_id: s.id, site_name: s.name, avg_health_score: s.status === 'healthy' ? 94 : 80, device_count: s.device_count, uptime_percent: s.status === 'healthy' ? 99.9 : 99.2, trend: 'up', trend_delta: 2.3 }));
  if (path === '/enterprise/health/wan') return devices.filter((d) => ['firewall', 'gateway'].includes(d.device_type)).map((d) => ({ device_id: d.id, device_name: d.name, device_type: d.device_type, site_name: sites.find((s) => s.id === d.site_id)?.name || 'Unknown', ip_address: '203.0.113.10', health_score: 88, latency_score: 92, reachability_score: 100, utilization_score: 45 }));
  if (path === '/enterprise/health/modules') return [{ module: 'network', device_count: devices.length, avg_health_score: 92, healthy: 24, warning: 2, degraded: 1, critical: 0 }];
  if (path === '/enterprise/health/history') return [{ snapshot_date: iso(1440), avg_health_score: 91, device_count: devices.length, healthy_count: 24, warning_count: 2, degraded_count: 1, critical_count: 0 }];
  if (path === '/enterprise/health/infrastructure') return { status: 'healthy', uptime_seconds: 18_800_000, components: [{ name: 'Database', status: 'healthy', latency_ms: 4, details: {} }, { name: 'Message Queue', status: 'healthy', latency_ms: 2, details: {} }, { name: 'Storage', status: 'healthy', latency_ms: 8, details: {} }] };
  if (path.startsWith('/enterprise/health')) return {
    organization_id: demoIds.org,
    site_count: sites.length,
    device_count: devices.length,
    avg_health_score: 92,
    health_status: 'healthy',
    sites: sites.map((s) => ({
      site_id: s.id,
      site_name: s.name,
      device_count: s.device_count,
      avg_health_score: s.status === 'healthy' ? 94 : 80,
      health_status: s.status === 'healthy' ? 'healthy' : 'warning',
      healthy: Math.max(0, s.device_count - 4),
      warning: 2,
      degraded: 1,
      critical: 0,
      uptime_percent: s.status === 'healthy' ? 99.9 : 99.2,
    })),
  };
  if (path === '/alert-rules/alerts' || path === '/alert-rules/alerts/') {
    const firing = alerts.filter((a) => a.status === 'active').map((a) => ({
      id: a.id,
      rule_id: `rule-${a.id}`,
      rule_name: a.title,
      title: a.title,
      message: a.message,
      severity: a.severity,
      status: 'firing',
      site_id: a.site_id,
      site_name: sites.find((s) => s.id === a.site_id)?.name || null,
      device_id: null,
      device_name: a.source,
      source: a.source,
      triggered_at: a.triggered_at,
      fired_at: a.triggered_at,
      acknowledged_at: null,
      resolved_at: null,
      last_notified_at: null,
      notifications_sent: 1,
      occurrence_count: 1,
      suppressed: false,
      tags: [],
      details: {},
    }));
    const filtered = firing.filter((a) => !q.site_id || a.site_id === q.site_id);
    return { alerts: filtered.slice(0, Number(q.limit || 10)), total: filtered.length };
  }
  if (path === '/sla/summary') return { active_policies: 3, active_breaches: 1, avg_compliance_percent: 96.4, breaches_last_24h: 2, worst_policy: null };
  if (path === '/sla/policies' || path === '/sla/policies/') return { policies: [], total: 0 };
  if (path === '/sla/breaches' || path === '/sla/breaches/') return { breaches: [], total: 0 };
  if (path.startsWith('/enterprise') || path.startsWith('/sla') || path.startsWith('/alert-rules') || path.startsWith('/topology') || path.startsWith('/correlation')) return emptyList();

  if (path === '/agents/stats') return { total: 1, online: 1, offline: 0, error: 0, pending_approval: 0, by_type: { site: 1 }, by_platform: { linux: 1 } };
  if (path === '/agents/fleet/overview') return { agents_total: 1, agents_online: 1, agents_offline: 0, schedules_total: 2, schedules_enabled: 1, runs_24h: 5, runs_24h_failed: 0, discovered_hosts_total: 12, discovered_hosts_unadopted: 3, last_run_at: iso(10) };
  if (path === '/agents/fleet/runs') return [
    { id: 'run-1', schedule_id: 'sched-1', schedule_name: 'HQ Network Scan', agent_id: 'agent-branch', agent_name: 'Branch scanner', site_id: demoIds.branch, site_name: 'Branch Office', status: 'completed', device_count: 12, duration_seconds: 245, error_message: null, started_at: iso(60), completed_at: iso(40) },
    { id: 'run-2', schedule_id: 'sched-2', schedule_name: 'DC Discovery', agent_id: 'agent-branch', agent_name: 'Branch scanner', site_id: demoIds.dc, site_name: 'Datacenter', status: 'completed', device_count: 8, duration_seconds: 180, error_message: null, started_at: iso(120), completed_at: iso(100) },
  ];
  if (path === '/agents/releases' || path === '/agents/releases/') return [
    { id: 'rel-linux-1.0.5', version: '1.0.5', platform: 'linux', agent_type: 'daemon', download_url: 'https://releases.freesdn.org/agents/1.0.5/freesdn-agent-linux-1.0.5.tar.gz', checksum_sha256: 'linux1234efgh5678ijkl9012mnop3456qrst7890uvwx1234yz', file_size: 38_000_000, release_notes: 'Bug fixes and performance improvements.', min_backend_version: '26.06.0', is_latest: true, is_prerelease: false, published_at: iso(60), download_count: 342 },
    { id: 'rel-win-1.0.5', version: '1.0.5', platform: 'windows', agent_type: 'daemon', download_url: 'https://releases.freesdn.org/agents/1.0.5/freesdn-agent-windows-1.0.5.exe', checksum_sha256: 'win12345efgh5678ijkl9012mnop3456qrst7890uvwx1234yz', file_size: 45_000_000, release_notes: 'Bug fixes and performance improvements.', min_backend_version: '26.06.0', is_latest: true, is_prerelease: false, published_at: iso(60), download_count: 128 },
    { id: 'rel-linux-1.0.4', version: '1.0.4', platform: 'linux', agent_type: 'daemon', download_url: 'https://releases.freesdn.org/agents/1.0.4/freesdn-agent-linux-1.0.4.tar.gz', checksum_sha256: 'prev11234efgh5678ijkl9012mnop3456qrst7890uvwx1234yz', file_size: 37_000_000, release_notes: 'Stability fixes.', min_backend_version: '26.05.0', is_latest: false, is_prerelease: false, published_at: iso(120), download_count: 156 },
  ];
  if (/^\/agents\/site\/[^/]+$/.test(path)) {
    const siteId = path.split('/')[3];
    return [
      { id: 'agent-hq', name: 'HQ Scanner', status: 'online', site_id: demoIds.hq, last_seen: new Date().toISOString() },
      { id: 'agent-branch', name: 'Branch scanner', status: 'online', site_id: demoIds.branch, last_seen: new Date().toISOString() },
    ].filter((a) => a.site_id === siteId);
  }
  if (path === '/agents/schedules' || path === '/agents/schedules/') {
    const allSchedules = [
      { id: 'sched-1', organization_id: demoIds.org, site_id: demoIds.hq, agent_id: 'agent-hq', name: 'HQ Network Scan', scan_type: 'quick', cron: '0 2 * * *', targets: ['10.0.0.0/8'], enabled: true, last_fired_at: iso(120), notification_channels: {}, notify_on_failure: false, notify_on_new_devices: 0, created_at: iso(1440), updated_at: iso(10) },
      { id: 'sched-2', organization_id: demoIds.org, site_id: demoIds.branch, agent_id: 'agent-branch', name: 'Branch Device Discovery', scan_type: 'full', cron: '0 */4 * * *', targets: ['10.20.0.0/16'], enabled: true, last_fired_at: iso(240), notification_channels: {}, notify_on_failure: false, notify_on_new_devices: 2, created_at: iso(2880), updated_at: iso(20) },
    ];
    let filtered = allSchedules;
    if (q.site_id) filtered = filtered.filter((s) => s.site_id === q.site_id);
    if (q.agent_id) filtered = filtered.filter((s) => s.agent_id === q.agent_id);
    return filtered;
  }
  if (/^\/agents\/schedules\/[^/]+\/runs$/.test(path)) {
    const scheduleId = path.split('/')[3];
    return [
      { id: 'run-1', schedule_id: scheduleId, agent_id: 'agent-hq', status: 'completed', device_count: 12, duration_seconds: 245, error_message: null, started_at: iso(60), completed_at: iso(40) },
      { id: 'run-2', schedule_id: scheduleId, agent_id: 'agent-hq', status: 'completed', device_count: 8, duration_seconds: 180, error_message: null, started_at: iso(120), completed_at: iso(100) },
    ];
  }
  if (/^\/agents\/[^/]+\/tasks$/.test(path)) {
    const agentId = path.split('/')[2];
    return [
      { id: 'task-1', agent_id: agentId, task_type: 'scan_network', task_data: { interactive: true, scan_type: 'quick', targets: [] }, priority: 1, status: 'completed', progress: 100, result: { total: 12, devices: [] }, error_message: null, scheduled_at: null, started_at: iso(60), completed_at: iso(40), max_retries: 3, retry_count: 0, created_at: iso(120), updated_at: iso(40) },
      { id: 'task-2', agent_id: agentId, task_type: 'scan_network', task_data: { interactive: true, scan_type: 'full', targets: ['10.20.0.0/16'] }, priority: 1, status: 'running', progress: 45, result: undefined, error_message: null, scheduled_at: null, started_at: iso(20), completed_at: null, max_retries: 3, retry_count: 0, created_at: iso(100), updated_at: iso(2) },
    ];
  }
  if (/^\/agents\/[^/]+\/runs$/.test(path)) return [
    { id: 'run-1', schedule_id: 'sched-1', schedule_name: 'HQ Network Scan', agent_id: path.split('/')[2], agent_name: 'Branch scanner', site_id: demoIds.branch, site_name: 'Branch Office', status: 'completed', device_count: 12, duration_seconds: 245, error_message: null, started_at: iso(60), completed_at: iso(40) },
  ];
  if (/^\/agents\/[^/]+\/schedules$/.test(path)) return [
    { id: 'sched-1', name: 'HQ Network Scan', scan_type: 'network', cron: '0 2 * * *', targets: ['10.0.0.0/8'], enabled: true, last_fired_at: iso(120), is_pinned: true },
    { id: 'sched-2', name: 'Device Discovery', scan_type: 'devices', cron: '0 */4 * * *', targets: ['10.20.0.0/16'], enabled: true, last_fired_at: iso(240), is_pinned: false },
  ];
  if (/^\/agents\/[^/]+\/discoveries$/.test(path)) return [
    { id: 'disc-1', ip_address: '10.30.12.5', mac_address: '02:00:00:aa:bb:cc', hostname: 'branch-printer-01', vendor: 'xerox', device_type: 'printer', is_adopted: false, adopted_device_id: null, first_seen: iso(1440), last_seen: iso(60) },
    { id: 'disc-2', ip_address: '10.30.20.10', mac_address: '02:00:00:dd:ee:ff', hostname: 'branch-laptop', vendor: 'dell', device_type: 'workstation', is_adopted: true, adopted_device_id: 'dev-unifi-ap', first_seen: iso(2880), last_seen: iso(30) },
  ];
  if (/^\/agents\/[^/]+\/topology-edges$/.test(path)) return [
    { id: 'edge-1', protocol: 'LLDP', local_interface: 'eth0', neighbor_chassis_id: '02:00:00:00:10:01', neighbor_port_id: 'ge-0/0/1', neighbor_system_name: 'HQ-Core-SW-01', vlan_id: 10, first_seen: iso(7200), last_seen: iso(120) },
  ];
  if (/^\/agents\/[^/]+$/.test(path) && !['stats', 'releases', 'downloads', 'fleet', 'schedules'].includes(path.split('/')[2])) {
    const agentId = path.split('/')[2];
    return { id: agentId, name: 'Branch scanner', status: 'online', site_id: demoIds.branch, site_name: 'Branch Office', last_seen: new Date().toISOString(), agent_type: 'daemon', version: '1.0.5', is_approved: true, last_heartbeat: iso(2), description: 'Demo agent at the branch office', capabilities: { scan_types: ['network', 'devices'] }, notification_channels: {}, offline_threshold_seconds: 180, created_at: iso(10080), updated_at: iso(2) };
  }
  if (path.startsWith('/agents')) return paginated([{ id: 'agent-branch', name: 'Branch scanner', status: 'online', site_id: demoIds.branch, last_seen: new Date().toISOString() }]);
  if (path === '/plugins' || path === '/plugins/') return installedPlugins;
  if (path === '/marketplace/plugins' || path === '/marketplace/plugins/') return { plugins: marketplacePlugins, total: marketplacePlugins.length, page: 1, per_page: 24, pages: 1 };
  if (/^\/marketplace\/plugins\/[^/]+\/reviews$/.test(path)) return { reviews: [
    { id: 'review-1', rating: 5, title: 'Excellent automation tool', body: 'Works perfectly with FreeSDN. Highly recommended!', created_at: iso(1440) },
    { id: 'review-2', rating: 4, title: 'Good, but needs docs', body: 'Does what it says, but could use more documentation.', created_at: iso(2880) },
  ] };
  if (/^\/marketplace\/plugins\/[^/]+\/versions$/.test(path)) return { versions: [
    { version: '1.0.0', changelog: 'Initial release: full n8n integration, webhook triggers, action nodes for FreeSDN events.', min_core_version: '26.0.0', released_at: iso(7200) },
    { version: '0.9.0', changelog: 'Beta release for community testing.', min_core_version: '25.0.0', released_at: iso(10080) },
  ] };
  if (/^\/marketplace\/plugins\/[^/]+$/.test(path)) return { plugin_id: 'plugin-n8n', slug: 'n8n-bridge', name: 'n8n Bridge', short_description: 'Connect FreeSDN events to n8n workflows.', description: 'The n8n Bridge plugin enables seamless integration between FreeSDN and the n8n automation platform: trigger n8n workflows from FreeSDN events, query network data from workflows, and build complex automations. Event-triggered workflows, bidirectional sync, pre-built nodes, webhook support, OAuth2.', author_name: 'FreeSDN', author_url: 'https://freesdn.org', category: 'automation', tags: ['automation', 'webhooks', 'n8n', 'integration'], latest_version: '1.0.0', min_core_version: '26.0.0', icon_url: null, banner_url: null, screenshots: [], download_url: 'https://marketplace.freesdn.org/plugins/n8n-bridge/1.0.0/package.tar.gz', checksum_sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', package_size: 245000, download_count: 1280, rating: 4.7, rating_count: 18, is_verified: true, is_featured: true };
  if (path.startsWith('/marketplace')) return { plugins: marketplacePlugins, total: marketplacePlugins.length, page: 1, per_page: 24, pages: 1 };
  if (/^\/vpn\/sites\/[^/]+\/config$/.test(path)) return null;

  if (path === '/fabric/catalog') {
    const operations = [
      { id: 'network.device.reboot', title: 'Reboot Device', description: 'Restart a network device.', input_schema: { type: 'object', properties: { device_id: { type: 'string' } } }, produces: [], accepts: [], permission: 'device.reboot', write: true, feature: 'device_action_reboot', tier: 'native', provider_id: 'network' },
      { id: 'storage.backup.snapshot', title: 'Create Snapshot', description: 'Back up to TrueNAS.', input_schema: { type: 'object', properties: { pool_id: { type: 'string' } } }, produces: [], accepts: [], permission: 'backup.write', write: true, feature: 'backup_snapshot', tier: 'native', provider_id: 'storage' },
      { id: 'cameras.snapshot.capture', title: 'Capture Snapshot', description: 'Get the latest frame from a camera.', input_schema: { type: 'object', properties: { camera_id: { type: 'string' } } }, produces: ['image/jpeg'], accepts: [], permission: null, write: false, feature: null, tier: 'native', provider_id: 'cameras' },
      { id: 'notifications.send', title: 'Send Notification', description: 'Dispatch an in-app notification.', input_schema: { type: 'object', properties: { title: { type: 'string' }, body: { type: 'string' } } }, produces: [], accepts: [], permission: null, write: false, feature: null, tier: 'native', provider_id: 'notifications' },
    ];
    const events = [
      { event_type: 'camera.motion.detected', title: 'Camera Motion Detected', description: 'Motion event from a camera.', payload_schema: { type: 'object', properties: { camera_id: { type: 'string' } } }, produces: ['image/jpeg'], tier: 'native', provider_id: 'cameras' },
      { event_type: 'device.offline', title: 'Device Went Offline', description: 'Device lost connection.', payload_schema: { type: 'object', properties: { device_id: { type: 'string' } } }, produces: [], tier: 'native', provider_id: 'network' },
      { event_type: 'storage.alert.capacity', title: 'Storage Capacity Warning', description: 'Pool usage exceeded threshold.', payload_schema: { type: 'object', properties: { pool_id: { type: 'string' }, usage_percent: { type: 'number' } } }, produces: [], tier: 'native', provider_id: 'storage' },
    ];
    return { operations, events, ai_tools: [], counts: { operations: operations.length, events: events.length, ai_tools: 0, native_operations: operations.length, plugin_operations: 0 } };
  }
  if (path.startsWith('/fabric')) return emptyList();

  if (path === '/collector/status') return { services: { snmp_trap: { running: true, port: 162 }, syslog: { running: true, port: 514 }, netflow: { running: false, port: 2055 } } };
  if (path === '/collector/config') return { snmp_enabled: true, snmp_port: 162, snmp_community: 'public', syslog_enabled: true, syslog_port: 514, netflow_enabled: false, netflow_port: 2055, log_retention_days: 90, flow_retention_days: 30, allowed_source_ips: ['10.0.0.0/8', '192.168.0.0/16'] };
  if (path === '/collector/logs/stats') return { total: 1847, hours: 24, by_severity: [{ severity: 'critical', count: 12 }, { severity: 'error', count: 48 }, { severity: 'warning', count: 310 }, { severity: 'info', count: 1477 }], by_source_type: [{ source_type: 'snmp_trap', count: 1124 }, { source_type: 'syslog', count: 723 }], top_sources: [{ source_ip: '10.10.0.2', count: 412 }, { source_ip: '10.20.0.11', count: 284 }, { source_ip: '10.10.0.1', count: 156 }] };
  if (path === '/collector/logs' || path === '/collector/logs/') {
    const logs = [
      { id: 'log-1', source_type: 'snmp_trap', source_ip: '10.10.0.2', device_id: 'dev-sw-core', severity: 'warning', facility: null, hostname: 'hq-core-sw-01', app_name: null, message: 'linkDown: ifIndex 8 (Port 8)', enterprise_oid: '1.3.6.1.2.1.1.3.0', trap_type: 'linkDown', varbinds: {}, timestamp: iso(5) },
      { id: 'log-2', source_type: 'syslog', source_ip: '10.20.0.11', device_id: 'dev-pve-01', severity: 'info', facility: 'local0', hostname: 'pve-node-01', app_name: 'kernel', message: 'nf_conntrack: table full, dropping packet', enterprise_oid: null, trap_type: null, varbinds: null, timestamp: iso(8) },
      { id: 'log-3', source_type: 'snmp_trap', source_ip: '10.10.0.1', device_id: 'dev-fw-hq', severity: 'critical', facility: null, hostname: 'hq-fw-01', app_name: null, message: 'cpuLoad exceeds threshold', enterprise_oid: '1.3.6.1.4.1.25461.2.1.3.1.0', trap_type: 'cpuLoad', varbinds: {}, timestamp: iso(12) },
    ];
    return { logs, total: 1847, page: Number(q.page || 1), size: Number(q.size || 50), pages: 37 };
  }

  if (path === '/logs/health') return { total_events_24h: 3847, total_events_7d: 28591, error_count_24h: 142, warning_count_24h: 267, critical_count_24h: 2, success_rate: 96.3, failed_logins_24h: 3, active_ip_blocks: 1, unresolved_anomalies: 0, open_incidents: 1, event_trend: 12, error_trend: -8, needs_attention: [{ type: 'incident', id: 'inc-001', title: 'TrueNAS pool capacity approaching limit', severity: 'warning', timestamp: iso(2) }], avg_response_ms: 247, p95_response_ms: 1840, daily_histogram: Array.from({ length: 7 }, (_, i) => ({ date: new Date(Date.now() - (6 - i) * 86_400_000).toISOString().slice(0, 10), total: 3500, errors: 140, warnings: 260 })) };
  if (path === '/logs/stats') {
    const hours = Number(q.hours) || 24;
    return { total: hours === 24 ? 3847 : 18050, by_level: { debug: 1200, info: 1840, warning: 267, error: 120, critical: 20, success: 400 }, by_source: { api: 1200, auth: 340, device: 1100, database: 420, system: 200, user: 587 }, by_hour: Array.from({ length: hours }, (_, i) => ({ hour: new Date(Date.now() - (hours - 1 - i) * 3_600_000).toISOString().slice(0, 13) + ':00', count: 240, errors: 12 })), error_rate: 3.1, avg_duration_ms: 247 };
  }
  if (path === '/logs' || path === '/logs/') return paginated(Array.from({ length: 24 }, (_, i) => ({
    id: `log-${i + 1}`, timestamp: iso(i * 10), level: ['debug', 'info', 'warning', 'error', 'critical'][i % 5], source: ['api', 'auth', 'device', 'database', 'system', 'user'][i % 6], message: ['API request completed', 'User login successful', 'Device sync started', 'Config saved', 'Health check passed'][i % 5], details: undefined, user_email: i % 2 === 0 ? 'demo@freesdn.local' : undefined, ip_address: i % 2 === 0 ? `192.168.1.${100 + i}` : undefined, duration_ms: 120, site_id: [demoIds.hq, demoIds.branch, demoIds.dc][i % 3], site_name: ['HQ Campus', 'Branch Office', 'Datacenter'][i % 3],
  })), Number(q.page || 1), Number(q.per_page || 50));

  if (path.startsWith('/security') || path.startsWith('/audit') || path.startsWith('/logs') || path.startsWith('/events')) return emptyList();

  return emptyList();
}

export const demoAxiosAdapter: AxiosAdapter = async (config) => {
  const method = (config.method || 'get').toLowerCase();
  const path = toPath(config);

  await new Promise((resolve) => setTimeout(resolve, 120));

  if (method === 'post' && path === '/auth/login') {
    return response(config, { user: demoUser, force_password_change: false });
  }
  if (method === 'post' && (path === '/auth/refresh' || path === '/auth/logout')) {
    return response(config, { success: true, demo: true });
  }

  if (!['get', 'head', 'options'].includes(method)) {
    return demoWriteResponse(config);
  }

  return response(config, await routeGet(path, config));
};

export function installDemoApi(instance: AxiosInstance) {
  instance.defaults.adapter = demoAxiosAdapter;
}

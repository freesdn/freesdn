// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import type {
  AxiosAdapter,
  AxiosInstance,
  AxiosResponse,
  InternalAxiosRequestConfig,
} from 'axios';
import { demoWriteMessage } from './mode';
import {
  alerts,
  cameras,
  controllers,
  dashboardSummary,
  demoIds,
  demoUser,
  devices,
  enterpriseAnalytics,
  getDemoCameraSnapshotPath,
  moduleNavItems,
  modules,
  organizations,
  sites,
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

async function routeGet(path: string, config: InternalAxiosRequestConfig) {
  const q = params(config);

  if (path === '/auth/me') return demoUser;
  if (path === '/health' || path.startsWith('/health/')) return health();
  if (path === '/system/info') return { app: 'FreeSDN', version: '26.06.1-demo', environment: 'demo', demo: true };
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
      runtime_status: { cpu_util: 42, mem_util: 58, disk_util: 65, uptime: 18_800_000, version: '26.06.1', model: String(controller?.vendor || 'demo'), device_count: controller?.device_count, site_count: 1, client_count: 128 },
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

  if (path === '/devices/stats/summary') return { total: devices.length, online: dashboardSummary.online_devices, offline: 0, warning: dashboardSummary.warning_devices, by_type: { switch: 1, access_point: 2, firewall: 1, camera: 1, phone: 1, hypervisor: 1, storage: 1 } };
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
    summary: { total_sites: sites.length, total_devices: devices.length, total_online_devices: dashboardSummary.online_devices, total_phones: 22, total_alerts_open: 2, total_critical_open: 0, total_controllers: controllers.length, generated_at: new Date().toISOString() },
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

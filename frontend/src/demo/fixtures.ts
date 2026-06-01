// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
const now = new Date('2026-06-07T14:30:00Z');
const iso = (minutesAgo = 0) => new Date(now.getTime() - minutesAgo * 60_000).toISOString();

export const demoIds = {
  org: '11111111-1111-4111-8111-111111111111',
  hq: '22222222-2222-4222-8222-222222222222',
  branch: '33333333-3333-4333-8333-333333333333',
  dc: '44444444-4444-4444-8444-444444444444',
  omada: '55555555-5555-4555-8555-555555555555',
  opnsense: '66666666-6666-4666-8666-666666666666',
  proxmox: '77777777-7777-4777-8777-777777777777',
  hikvision: '88888888-8888-4888-8888-888888888888',
  freepbx: '99999999-9999-4999-8999-999999999999',
  truenas: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
  unifi: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
};

export const demoUser = {
  id: '10000000-0000-4000-8000-000000000001',
  email: 'demo@freesdn.local',
  username: 'demo-admin',
  first_name: 'Demo',
  last_name: 'Admin',
  full_name: 'Demo Admin',
  role: 'super_admin',
  organization_id: demoIds.org,
  is_active: true,
  is_superuser: true,
  is_org_admin: true,
  mfa_enabled: false,
  permissions: ['*'],
  roles: ['super_admin'],
};

export const organizations = [{
  id: demoIds.org,
  name: 'Acme Corp / Demo Org',
  slug: 'acme-demo',
  description: 'Sample organization for the read-only FreeSDN demo',
  is_active: true,
  created_at: iso(60 * 24 * 30),
  updated_at: iso(30),
}];

export const sites = [
  {
    id: demoIds.hq,
    name: 'HQ Campus',
    slug: 'hq-campus',
    site_type: 'campus',
    address: '100 Market Street, Austin, TX',
    timezone: 'America/Chicago',
    organization_id: demoIds.org,
    is_active: true,
    device_count: 42,
    controller_count: 4,
    subnets: [{ cidr: '10.10.0.0/16' }, { cidr: '10.10.40.0/24' }],
    status: 'healthy',
    created_at: iso(60 * 24 * 20),
    updated_at: iso(12),
  },
  {
    id: demoIds.branch,
    name: 'Branch Office',
    slug: 'branch-office',
    site_type: 'branch',
    address: '45 Hudson Ave, Denver, CO',
    timezone: 'America/Denver',
    organization_id: demoIds.org,
    is_active: true,
    device_count: 19,
    controller_count: 2,
    subnets: [{ cidr: '10.30.0.0/16' }],
    status: 'warning',
    created_at: iso(60 * 24 * 16),
    updated_at: iso(18),
  },
  {
    id: demoIds.dc,
    name: 'Datacenter',
    slug: 'datacenter',
    site_type: 'datacenter',
    address: '1 Technology Way, Ashburn, VA',
    timezone: 'America/New_York',
    organization_id: demoIds.org,
    is_active: true,
    device_count: 31,
    controller_count: 3,
    subnets: [{ cidr: '10.20.0.0/16' }],
    status: 'healthy',
    created_at: iso(60 * 24 * 14),
    updated_at: iso(8),
  },
];

export const controllers = [
  { id: demoIds.omada, name: 'Omada OC300 - HQ', controller_type: 'omada', vendor: 'omada', host: 'omada-hq.demo.local', status: 'online', site_id: demoIds.hq, site_name: 'HQ Campus', device_count: 28, last_sync_at: iso(4), created_at: iso(9000), updated_at: iso(4) },
  { id: demoIds.opnsense, name: 'OPNsense HA Pair', controller_type: 'opnsense', vendor: 'opnsense', host: 'fw-hq.demo.local', status: 'online', site_id: demoIds.hq, site_name: 'HQ Campus', device_count: 2, last_sync_at: iso(6), created_at: iso(8500), updated_at: iso(6) },
  { id: demoIds.proxmox, name: 'PVE Cluster A', controller_type: 'proxmox', vendor: 'proxmox', host: 'pve-a.demo.local', status: 'online', site_id: demoIds.dc, site_name: 'Datacenter', device_count: 9, last_sync_at: iso(3), created_at: iso(8200), updated_at: iso(3) },
  { id: demoIds.hikvision, name: 'Hikvision NVR HQ', controller_type: 'hikvision', vendor: 'hikvision', host: 'nvr-hq.demo.local', status: 'online', site_id: demoIds.hq, site_name: 'HQ Campus', device_count: 8, last_sync_at: iso(7), created_at: iso(7500), updated_at: iso(7) },
  { id: demoIds.freepbx, name: 'FreePBX Voice', controller_type: 'freepbx', vendor: 'freepbx', host: 'pbx.demo.local', status: 'online', site_id: demoIds.hq, site_name: 'HQ Campus', device_count: 22, last_sync_at: iso(5), created_at: iso(7000), updated_at: iso(5) },
  { id: demoIds.truenas, name: 'TrueNAS Backup Pool', controller_type: 'truenas', vendor: 'truenas', host: 'truenas.demo.local', status: 'warning', site_id: demoIds.dc, site_name: 'Datacenter', device_count: 1, last_sync_at: iso(10), created_at: iso(6800), updated_at: iso(10) },
  { id: demoIds.unifi, name: 'UniFi Branch', controller_type: 'unifi', vendor: 'unifi', host: 'unifi-branch.demo.local', status: 'online', site_id: demoIds.branch, site_name: 'Branch Office', device_count: 12, last_sync_at: iso(9), created_at: iso(6500), updated_at: iso(9) },
];

export const devices = [
  { id: 'dev-sw-core', name: 'HQ-Core-SW-01', hostname: 'hq-core-sw-01', device_type: 'switch', vendor: 'tp-link', model: 'SG3428XMP', ip_address: '10.10.0.2', mac_address: '02:00:00:00:10:01', status: 'online', site_id: demoIds.hq, site_name: 'HQ Campus', controller_id: demoIds.omada, ports_up: 21, ports_down: 3, total_ports: 28, poe_used: 184, poe_budget: 384, firmware_version: '5.15.8', uptime: 16_240_000, cpu_usage: 18, memory_usage: 44, last_seen: iso(2) },
  { id: 'dev-ap-lobby', name: 'HQ-Lobby-AP-01', hostname: 'hq-lobby-ap-01', device_type: 'access_point', vendor: 'tp-link', model: 'EAP670', ip_address: '10.10.12.11', mac_address: '02:00:00:00:10:02', status: 'online', site_id: demoIds.hq, site_name: 'HQ Campus', controller_id: demoIds.omada, connected_clients: 37, firmware_version: '1.0.13', uptime: 6_820_000, cpu_usage: 22, memory_usage: 48, last_seen: iso(1) },
  { id: 'dev-fw-hq', name: 'HQ-FW-01', hostname: 'hq-fw-01', device_type: 'firewall', vendor: 'opnsense', model: 'DEC850', ip_address: '10.10.0.1', mac_address: '02:00:00:00:10:03', status: 'online', site_id: demoIds.hq, site_name: 'HQ Campus', controller_id: demoIds.opnsense, firmware_version: '24.7.8', uptime: 12_450_000, cpu_usage: 11, memory_usage: 39, last_seen: iso(2) },
  { id: 'dev-pve-01', name: 'PVE-Node-01', hostname: 'pve-node-01', device_type: 'hypervisor', vendor: 'proxmox', model: 'R740xd', ip_address: '10.20.0.11', mac_address: '02:00:00:00:20:01', status: 'online', site_id: demoIds.dc, site_name: 'Datacenter', controller_id: demoIds.proxmox, firmware_version: '8.3', uptime: 24_880_000, cpu_usage: 36, memory_usage: 71, last_seen: iso(4) },
  { id: 'dev-truenas-01', name: 'TrueNAS-Backup-01', hostname: 'truenas-backup-01', device_type: 'storage', vendor: 'truenas', model: 'SCALE', ip_address: '10.20.0.30', mac_address: '02:00:00:00:20:30', status: 'warning', site_id: demoIds.dc, site_name: 'Datacenter', controller_id: demoIds.truenas, firmware_version: '25.10', uptime: 18_800_000, cpu_usage: 14, memory_usage: 62, last_seen: iso(8) },
  { id: 'dev-phone-101', name: 'Reception Phone 101', hostname: 'gxp-101', device_type: 'phone', vendor: 'grandstream', model: 'GXP2170', ip_address: '10.10.30.101', mac_address: '02:00:00:00:30:65', status: 'online', site_id: demoIds.hq, site_name: 'HQ Campus', controller_id: demoIds.freepbx, firmware_version: '1.0.11.88', uptime: 1_840_000, cpu_usage: 8, memory_usage: 31, last_seen: iso(3) },
  { id: 'cam-front-door', name: 'Front Door Camera', hostname: 'cam-front-door', device_type: 'camera', vendor: 'hikvision', model: 'DS-2CD2387G2', ip_address: '10.10.40.21', mac_address: '02:00:00:00:40:21', status: 'online', site_id: demoIds.hq, site_name: 'HQ Campus', controller_id: demoIds.hikvision, firmware_version: '5.7.13', uptime: 4_210_000, cpu_usage: 17, memory_usage: 38, last_seen: iso(2) },
  { id: 'dev-unifi-ap', name: 'Branch-U6-Pro-01', hostname: 'branch-u6-pro-01', device_type: 'access_point', vendor: 'unifi', model: 'U6-Pro', ip_address: '10.30.12.8', mac_address: '02:00:00:00:30:08', status: 'online', site_id: demoIds.branch, site_name: 'Branch Office', controller_id: demoIds.unifi, connected_clients: 21, firmware_version: '6.6.55', uptime: 2_490_000, cpu_usage: 27, memory_usage: 53, last_seen: iso(2) },
];

export const cameras = [
  { id: 'cam-front-door', name: 'Front Door Camera', status: 'online', ip_address: '10.10.40.21', vendor: 'hikvision', model: 'DS-2CD2387G2', site_id: demoIds.hq, site_name: 'HQ Campus', nvr_id: demoIds.hikvision, channel_id: 1, location: 'HQ entrance', camera_type: 'fixed', stream_status: 'demo_unavailable', snapshot_url: '/demo/camera-front-door.jpg', last_snapshot_at: iso(5), created_at: iso(6000), updated_at: iso(5) },
  { id: 'cam-warehouse', name: 'Warehouse Aisle Camera', status: 'online', ip_address: '10.20.40.18', vendor: 'onvif', model: 'Generic Profile S', site_id: demoIds.dc, site_name: 'Datacenter', nvr_id: demoIds.hikvision, channel_id: 2, location: 'Datacenter cage', camera_type: 'fixed', stream_status: 'demo_unavailable', snapshot_url: '/demo/camera-warehouse.jpg', last_snapshot_at: iso(7), created_at: iso(5900), updated_at: iso(7) },
  { id: 'cam-branch-lobby', name: 'Branch Lobby Protect', status: 'online', ip_address: '10.30.40.7', vendor: 'unifi_protect', model: 'G5 Dome', site_id: demoIds.branch, site_name: 'Branch Office', nvr_id: demoIds.unifi, channel_id: 3, location: 'Branch lobby', camera_type: 'fixed', stream_status: 'demo_unavailable', snapshot_url: '/demo/camera-branch-lobby.jpg', last_snapshot_at: iso(4), created_at: iso(5800), updated_at: iso(4) },
];

export function getDemoCameraSnapshotPath(cameraId: string | undefined) {
  if (cameraId === 'cam-warehouse') return '/demo/camera-warehouse.jpg';
  if (cameraId === 'cam-branch-lobby') return '/demo/camera-branch-lobby.jpg';
  return '/demo/camera-front-door.jpg';
}

export const alerts = [
  { id: 'alert-1', title: 'TrueNAS pool capacity warning', message: 'tank-backup is at 82% usage.', alert_type: 'storage.capacity', severity: 'warning', status: 'active', site_id: demoIds.dc, triggered_at: iso(18), source: 'TrueNAS Backup Pool' },
  { id: 'alert-2', title: 'Branch AP channel utilization high', message: '5 GHz utilization exceeded threshold.', alert_type: 'network.rf', severity: 'warning', status: 'active', site_id: demoIds.branch, triggered_at: iso(42), source: 'Branch-U6-Pro-01' },
  { id: 'alert-3', title: 'Front door motion detected', message: 'Motion event captured by camera.', alert_type: 'camera.motion', severity: 'info', status: 'acknowledged', site_id: demoIds.hq, triggered_at: iso(65), source: 'Front Door Camera' },
];

export const modules = [
  ['network', 'Network Management', 'Network'],
  ['cameras', 'Video Surveillance', 'Cameras'],
  ['voip', 'VoIP & Telephony', 'VoIP'],
  ['firewall', 'Firewall', 'Firewall'],
  ['access_control', 'Access Control', 'Access'],
  ['backup', 'Backup & Restore', 'Backup'],
  ['ai', 'AI Assistant', 'AI'],
  ['collector', 'Observability', 'Observability'],
  ['hypervisor', 'Compute / Hypervisor', 'Hypervisor'],
  ['storage', 'Storage', 'Storage'],
].map(([id, name, category], index) => ({
  id,
  name,
  version: '26.06.1',
  description: `${name} module fixture for the read-only demo.`,
  category,
  icon: id,
  color: 'blue',
  is_core: id === 'network',
  is_beta: id === 'access_control' || id === 'ai',
  is_premium: false,
  coming_soon: id === 'access_control',
  capabilities: [],
  device_types: [],
  dependencies: [],
  permissions: [],
  nav_items: [],
  widgets: [],
  author: 'FreeSDN',
  license: 'AGPL-3.0-only',
  order: index + 1,
}));

export const moduleNavItems = [
  { path: '/network', label: 'Network', icon: 'network', order: 10, module_id: 'network' },
  { path: '/cameras', label: 'Cameras', icon: 'camera', order: 20, module_id: 'cameras' },
  { path: '/voip', label: 'VoIP', icon: 'phone', order: 30, module_id: 'voip' },
  { path: '/firewall', label: 'Firewall', icon: 'shield', order: 40, module_id: 'firewall' },
  { path: '/hypervisor', label: 'Hypervisor', icon: 'server', order: 50, module_id: 'hypervisor' },
  { path: '/storage', label: 'Storage', icon: 'database', order: 60, module_id: 'storage' },
];

export const dashboardSummary = {
  total_devices: devices.length,
  online_devices: devices.filter((d) => d.status === 'online').length,
  offline_devices: 0,
  warning_devices: devices.filter((d) => d.status === 'warning').length,
  total_sites: sites.length,
  total_controllers: controllers.length,
  active_alerts: alerts.filter((a) => a.status === 'active').length,
  critical_alerts: alerts.filter((a) => a.severity === 'critical').length,
  cameras_online: cameras.filter((c) => c.status === 'online').length,
  switches_online: devices.filter((d) => d.device_type === 'switch' && d.status === 'online').length,
  recent_alerts: alerts,
};

export const enterpriseAnalytics = {
  timestamp: iso(),
  generated_at: iso(),
  hours: 24,
  health_score: 92,
  total_sites: sites.length,
  device_counts: {
    total: devices.length,
    online: dashboardSummary.online_devices,
    offline: dashboardSummary.offline_devices,
    warning: dashboardSummary.warning_devices,
  },
  fleet: {
    total: devices.length,
    online: devices.filter((d) => d.status === 'online').length,
    offline: 0,
    degraded: devices.filter((d) => d.status === 'warning').length,
    avg_cpu: 22, avg_memory: 51, avg_temp: 47,
    max_cpu: 71, max_memory: 75, max_temp: 58,
    by_type: {
      switch: { total: 1, online: 1, offline: 0 },
      access_point: { total: 2, online: 2, offline: 0 },
      firewall: { total: 1, online: 1, offline: 0 },
      camera: { total: 1, online: 1, offline: 0 },
      phone: { total: 1, online: 1, offline: 0 },
      hypervisor: { total: 1, online: 1, offline: 0 },
      storage: { total: 1, online: 0, offline: 0 },
    },
    by_manufacturer: [
      { name: 'TP-Link', count: 28 },
      { name: 'Grandstream', count: 22 },
      { name: 'Ubiquiti', count: 12 },
      { name: 'Proxmox', count: 9 },
      { name: 'Hikvision', count: 8 },
      { name: 'OPNsense', count: 2 },
      { name: 'TrueNAS', count: 1 },
    ],
  },
  clients: {
    total: 94, online: 88,
    band_2g: 18, band_5g: 52, band_6g: 12,
    avg_signal_dbm: -58,
    total_tx_bytes: 184_000_000_000, total_rx_bytes: 412_000_000_000,
    signal_distribution: { excellent: 30, good: 34, fair: 16, weak: 6, poor: 2 },
    top_ssids: [
      { ssid: 'Acme-Corp', count: 58 },
      { ssid: 'Acme-Guest', count: 24 },
    ],
  },
  ports: {
    total: 28, up: 24, down: 4,
    poe_ports: 12, total_poe_watts: 184,
    total_tx_bytes: 820_000_000_000, total_rx_bytes: 1_240_000_000_000,
    total_errors: 3,
  },
  sites: sites.map((site) => ({
    site_id: site.id,
    name: site.name,
    health: site.status === 'healthy' ? 96 : 82,
    devices: site.device_count,
    online: Math.max(1, site.device_count - 2),
  })),
  controllers: controllers.map((c) => ({
    id: c.id, name: c.name, status: c.status, type: c.vendor, host: c.host, device_count: c.device_count,
  })),
  audit: {
    total_events: 1284,
    by_level: { info: 1180, notice: 64, warning: 32, error: 8 },
    by_source: { auth: 420, device: 360, config: 280, system: 224 },
  },
  incidents: { open: 1, investigating: 1, resolved: 7, total: 9 },
  security: {
    failed_logins_window: 4,
    active_ip_blocks: 1,
    unresolved_anomalies: 0,
    total_security_events: 36,
  },
  top_devices_cpu: [
    { name: 'PVE-Node-01', cpu: 36 },
    { name: 'Branch-U6-Pro-01', cpu: 27 },
    { name: 'HQ-Lobby-AP-01', cpu: 22 },
    { name: 'HQ-Core-SW-01', cpu: 18 },
    { name: 'Front Door Camera', cpu: 17 },
  ],
  top_devices_memory: [
    { name: 'PVE-Node-01', memory: 71 },
    { name: 'TrueNAS-Backup-01', memory: 62 },
    { name: 'Branch-U6-Pro-01', memory: 53 },
    { name: 'HQ-Lobby-AP-01', memory: 48 },
    { name: 'HQ-Core-SW-01', memory: 44 },
  ],
  totals: dashboardSummary,
  traffic: Array.from({ length: 12 }, (_, i) => ({
    timestamp: iso((11 - i) * 60),
    rx_mbps: 180 + i * 11,
    tx_mbps: 92 + i * 7,
  })),
  manufacturers: [
    { name: 'TP-Link', count: 28 },
    { name: 'Ubiquiti', count: 12 },
    { name: 'Hikvision', count: 8 },
    { name: 'Proxmox', count: 9 },
    { name: 'Grandstream', count: 22 },
  ],
};

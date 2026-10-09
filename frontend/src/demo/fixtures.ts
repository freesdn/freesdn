// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { demoIds, demoUser } from './identity';
export { demoIds, demoUser } from './identity';
export { getDemoCameraSnapshotPath } from './cameraSnapshots';

// One place for the release the demo claims to be. Three fixtures hardcoded
// '26.06.1' independently, so the Modules page kept advertising a June build
// long after the demo had moved on.
export const DEMO_PLATFORM_VERSION = '26.10.0';

const now = new Date('2026-06-07T14:30:00Z');
const iso = (minutesAgo = 0) => new Date(now.getTime() - minutesAgo * 60_000).toISOString();

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
    online_device_count: 38,
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
    online_device_count: 19,
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
    online_device_count: 29,
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

export const cameras = [
  { id: 'cam-front-door', name: 'Front Door Camera', status: 'online', ip_address: '10.10.40.21', vendor: 'hikvision', model: 'DS-2CD2387G2', site_id: demoIds.hq, site_name: 'HQ Campus', nvr_id: demoIds.hikvision, channel_id: 1, location: 'HQ entrance', camera_type: 'fixed', stream_status: 'demo_unavailable', snapshot_url: '/demo/camera-front-door.jpg', last_snapshot_at: iso(5), created_at: iso(6000), updated_at: iso(5) },
  { id: 'cam-warehouse', name: 'Warehouse Aisle Camera', status: 'online', ip_address: '10.20.40.18', vendor: 'onvif', model: 'Generic Profile S', site_id: demoIds.dc, site_name: 'Datacenter', nvr_id: demoIds.hikvision, channel_id: 2, location: 'Datacenter cage', camera_type: 'fixed', stream_status: 'demo_unavailable', snapshot_url: '/demo/camera-warehouse.jpg', last_snapshot_at: iso(7), created_at: iso(5900), updated_at: iso(7) },
  { id: 'cam-branch-lobby', name: 'Branch Lobby Protect', status: 'online', ip_address: '10.30.40.7', vendor: 'unifi_protect', model: 'G5 Dome', site_id: demoIds.branch, site_name: 'Branch Office', nvr_id: demoIds.unifi, channel_id: 3, location: 'Branch lobby', camera_type: 'fixed', stream_status: 'demo_unavailable', snapshot_url: '/demo/camera-branch-lobby.jpg', last_snapshot_at: iso(4), created_at: iso(5800), updated_at: iso(4) },
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
  version: DEMO_PLATFORM_VERSION,
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

// ==== demo fleet: network fleet (devices, switch ports, VLANs, WiFi/SSIDs, clients, topology) ====
// ---------------------------------------------------------------------------
// NETWORK FLEET  ·  61 devices  ·  HQ Campus 42 (38 online) + Branch Office 19
// ---------------------------------------------------------------------------
// Addressing: HQ 10.10.0.0/16, Branch 10.30.0.0/16. Infrastructure lives on the
// management VLAN (99) at x.x.0.0/24; users/voice/cameras/IoT sit on VLANs
// 10/20/30/40/50. Every MAC is locally-administered (02:...) so nothing here can
// collide with real hardware. Serials/firmware are synthetic but vendor-shaped.
//
// Rows use short column names so one device fits on one line; the .map()
// below expands every one to the snake_case field the frontend reads, and
// derives the rest. `seen` is the age of last_seen in minutes, re-anchored
// to the live clock by mockApi so the demo never looks stale.
export const networkDevices = [
  // ── HQ Campus · WAN edge, firewalls, gateways (4) ────────────────────────
  { id: 'dev-fw-hq', n: 'HQ-FW-01', t: 'firewall', v: 'opnsense', m: 'DEC850', sn: 'DEMO-DEC850-0001', fw: '24.7.8', ip: '10.10.0.1', mac: '02:00:00:00:10:03', st: 'online', site: demoIds.hq, ctl: demoIds.opnsense, loc: 'MDF', fl: '1', rm: 'MDF-101', vl: 99, up: 12_450_000, cpu: 11, mem: 39, fan: 'ok', tp: 8, pu: 5, px: 0, pp: 0, sp: 2, pb: 0, pw: 0, cc: 0, upd: false, seen: 2 },
  { id: 'dev-fw-hq-02', n: 'HQ-FW-02', t: 'firewall', v: 'opnsense', m: 'DEC850', sn: 'DEMO-DEC850-0002', fw: '24.7.8', ip: '10.10.0.4', mac: '02:00:00:13:00:02', st: 'online', site: demoIds.hq, ctl: demoIds.opnsense, loc: 'MDF', fl: '1', rm: 'MDF-101', vl: 99, up: 12_408_000, cpu: 6, mem: 37, fan: 'ok', tp: 8, pu: 4, px: 0, pp: 0, sp: 2, pb: 0, pw: 0, cc: 0, upd: false, seen: 2 },
  { id: 'dev-rtr-hq-edge', n: 'HQ-EDGE-RTR-01', t: 'router', v: 'mikrotik', m: 'CCR2004-1G-12S+2XS', sn: 'DEMOHDX0A114', fw: '7.16.2', ip: '10.10.0.5', mac: '02:00:00:13:00:03', st: 'online', site: demoIds.hq, ctl: null, loc: 'MDF', fl: '1', rm: 'MDF-101', vl: 99, up: 9_812_000, cpu: 14, mem: 28, fan: 'ok', tp: 15, pu: 6, px: 0, pp: 0, sp: 14, pb: 0, pw: 0, cc: 0, upd: true, seen: 3 },
  { id: 'dev-gw-hq-annex', n: 'HQ-ANNEX-GW-01', t: 'gateway', v: 'openwrt', m: 'GL-MT6000', sn: 'DEMOGL6000021', fw: '24.10.0', ip: '10.10.0.6', mac: '02:00:00:13:00:04', st: 'online', site: demoIds.hq, ctl: null, loc: 'Annex', fl: '1', rm: 'ANX-010', vl: 99, up: 3_186_000, cpu: 9, mem: 44, fan: 'n/a', tp: 6, pu: 3, px: 0, pp: 0, sp: 1, pb: 0, pw: 0, cc: 0, upd: false, seen: 4 },

  // ── HQ Campus · switches (17) ────────────────────────────────────────────
  { id: 'dev-sw-core', n: 'HQ-Core-SW-01', t: 'switch', v: 'tp-link', m: 'TL-SG3428XMP', sn: 'DEMO2245SG3428X01', fw: '1.20.4', ip: '10.10.0.2', mac: '02:00:00:00:10:01', st: 'online', site: demoIds.hq, ctl: demoIds.omada, loc: 'MDF', fl: '1', rm: 'MDF-101', vl: 99, up: 16_240_000, cpu: 18, mem: 44, fan: 'ok', tp: 28, pu: 19, px: 4, pp: 24, sp: 4, pb: 384, pw: 85, cc: 5, upd: false, seen: 2 },
  { id: 'dev-sw-hq-core-02', n: 'HQ-Core-SW-02', t: 'switch', v: 'tp-link', m: 'TL-SG3428XMP', sn: 'DEMO2245SG3428X02', fw: '1.20.4', ip: '10.10.0.3', mac: '02:00:00:11:00:02', st: 'online', site: demoIds.hq, ctl: demoIds.omada, loc: 'MDF', fl: '1', rm: 'MDF-101', vl: 99, up: 16_236_000, cpu: 15, mem: 41, fan: 'ok', tp: 28, pu: 14, px: 4, pp: 24, sp: 4, pb: 384, pw: 62, cc: 0, upd: false, seen: 2 },
  { id: 'dev-sw-hq-agg-01', n: 'HQ-Agg-SW-01', t: 'switch', v: 'tp-link', m: 'TL-SX3016F', sn: 'DEMO2312SX3016F01', fw: '1.10.2', ip: '10.10.0.7', mac: '02:00:00:11:00:03', st: 'online', site: demoIds.hq, ctl: demoIds.omada, loc: 'MDF', fl: '1', rm: 'MDF-101', vl: 99, up: 14_902_000, cpu: 12, mem: 33, fan: 'ok', tp: 16, pu: 9, px: 0, pp: 0, sp: 16, pb: 0, pw: 0, cc: 0, upd: false, seen: 3 },
  { id: 'dev-sw-hq-agg-02', n: 'HQ-Agg-SW-02', t: 'switch', v: 'tp-link', m: 'TL-SX3016F', sn: 'DEMO2312SX3016F02', fw: '1.10.2', ip: '10.10.0.8', mac: '02:00:00:11:00:04', st: 'online', site: demoIds.hq, ctl: demoIds.omada, loc: 'MDF', fl: '1', rm: 'MDF-101', vl: 99, up: 14_898_000, cpu: 10, mem: 31, fan: 'ok', tp: 16, pu: 7, px: 0, pp: 0, sp: 16, pb: 0, pw: 0, cc: 0, upd: false, seen: 3 },
  { id: 'dev-sw-hq-idf1-01', n: 'HQ-IDF1-SW-01', t: 'switch', v: 'tp-link', m: 'TL-SG3428XMP', sn: 'DEMO2245SG3428X03', fw: '1.20.4', ip: '10.10.0.11', mac: '02:00:00:11:00:05', st: 'online', site: demoIds.hq, ctl: demoIds.omada, loc: 'IDF 1', fl: '1', rm: 'IDF-118', vl: 99, up: 11_704_000, cpu: 21, mem: 47, fan: 'ok', tp: 28, pu: 12, px: 4, pp: 24, sp: 4, pb: 384, pw: 33, cc: 7, upd: false, seen: 1 },
  { id: 'dev-sw-hq-idf1-02', n: 'HQ-IDF1-SW-02', t: 'switch', v: 'tp-link', m: 'TL-SG2428P', sn: 'DEMO2311SG2428P01', fw: '1.0.9', ip: '10.10.0.12', mac: '02:00:00:11:00:06', st: 'online', site: demoIds.hq, ctl: demoIds.omada, loc: 'IDF 1', fl: '1', rm: 'IDF-118', vl: 99, up: 11_698_000, cpu: 13, mem: 38, fan: 'ok', tp: 28, pu: 9, px: 2, pp: 24, sp: 4, pb: 250, pw: 41, cc: 0, upd: true, seen: 2 },
  { id: 'dev-sw-hq-idf2-01', n: 'HQ-IDF2-SW-01', t: 'switch', v: 'tp-link', m: 'TL-SG3428XMP', sn: 'DEMO2245SG3428X04', fw: '1.20.4', ip: '10.10.0.13', mac: '02:00:00:11:00:07', st: 'online', site: demoIds.hq, ctl: demoIds.omada, loc: 'IDF 2', fl: '2', rm: 'IDF-214', vl: 99, up: 10_412_000, cpu: 19, mem: 45, fan: 'ok', tp: 28, pu: 11, px: 2, pp: 24, sp: 4, pb: 384, pw: 74, cc: 2, upd: false, seen: 1 },
  { id: 'dev-sw-hq-idf2-02', n: 'HQ-IDF2-SW-02', t: 'switch', v: 'tp-link', m: 'TL-SG3210XHP-M2', sn: 'DEMO2402SG3210X01', fw: '1.1.3', ip: '10.10.0.14', mac: '02:00:00:11:00:08', st: 'degraded', site: demoIds.hq, ctl: demoIds.omada, loc: 'IDF 2', fl: '2', rm: 'IDF-214', vl: 99, up: 486_000, cpu: 68, mem: 81, fan: 'degraded', tp: 10, pu: 9, px: 0, pp: 8, sp: 2, pb: 240, pw: 205, cc: 0, upd: true, seen: 3 },
  { id: 'dev-sw-hq-idf3-01', n: 'HQ-IDF3-SW-01', t: 'switch', v: 'tp-link', m: 'TL-SG3452', sn: 'DEMO2208SG345201', fw: '3.2.1', ip: '10.10.0.15', mac: '02:00:00:11:00:09', st: 'online', site: demoIds.hq, ctl: demoIds.omada, loc: 'IDF 3', fl: '3', rm: 'IDF-312', vl: 99, up: 13_106_000, cpu: 16, mem: 40, fan: 'ok', tp: 52, pu: 18, px: 4, pp: 0, sp: 4, pb: 0, pw: 0, cc: 2, upd: false, seen: 2 },
  { id: 'dev-sw-hq-idf3-02', n: 'HQ-IDF3-SW-02', t: 'switch', v: 'tp-link', m: 'TL-SG2428P', sn: 'DEMO2311SG2428P02', fw: '1.0.9', ip: '10.10.0.18', mac: '02:00:00:11:00:0a', st: 'offline', site: demoIds.hq, ctl: demoIds.omada, loc: 'IDF 3', fl: '3', rm: 'IDF-312', vl: 99, up: 0, cpu: 0, mem: 0, fan: 'unknown', tp: 28, pu: 0, px: 0, pp: 24, sp: 4, pb: 250, pw: 0, cc: 0, upd: true, seen: 226 },
  { id: 'dev-sw-hq-idf4-01', n: 'HQ-IDF4-SW-01', t: 'switch', v: 'tp-link', m: 'TL-SG3428XMP', sn: 'DEMO2245SG3428X05', fw: '1.20.4', ip: '10.10.0.19', mac: '02:00:00:11:00:0b', st: 'online', site: demoIds.hq, ctl: demoIds.omada, loc: 'IDF 4', fl: '4', rm: 'IDF-406', vl: 99, up: 9_204_000, cpu: 17, mem: 42, fan: 'ok', tp: 28, pu: 10, px: 2, pp: 24, sp: 4, pb: 384, pw: 58, cc: 0, upd: false, seen: 2 },
  { id: 'dev-sw-hq-idf4-02', n: 'HQ-IDF4-SW-02', t: 'switch', v: 'tp-link', m: 'TL-SG2428P', sn: 'DEMO2311SG2428P03', fw: '1.0.9', ip: '10.10.0.20', mac: '02:00:00:11:00:0c', st: 'online', site: demoIds.hq, ctl: demoIds.omada, loc: 'IDF 4', fl: '4', rm: 'IDF-406', vl: 99, up: 9_198_000, cpu: 11, mem: 36, fan: 'ok', tp: 28, pu: 6, px: 2, pp: 24, sp: 4, pb: 250, pw: 24, cc: 0, upd: true, seen: 3 },
  { id: 'dev-sw-hq-secops-01', n: 'HQ-SecOps-SW-01', t: 'switch', v: 'tp-link', m: 'TL-SG3210XHP-M2', sn: 'DEMO2402SG3210X02', fw: '1.1.3', ip: '10.10.0.21', mac: '02:00:00:11:00:0d', st: 'online', site: demoIds.hq, ctl: demoIds.omada, loc: 'Security office', fl: '1', rm: 'Security 104', vl: 99, up: 8_112_000, cpu: 14, mem: 39, fan: 'ok', tp: 10, pu: 6, px: 0, pp: 8, sp: 2, pb: 240, pw: 63, cc: 0, upd: false, seen: 2 },
  { id: 'dev-sw-hq-voice-01', n: 'HQ-Voice-SW-01', t: 'switch', v: 'tp-link', m: 'TL-SG3428XMP', sn: 'DEMO2245SG3428X06', fw: '1.20.4', ip: '10.10.0.22', mac: '02:00:00:11:00:0e', st: 'online', site: demoIds.hq, ctl: demoIds.omada, loc: 'IDF 1', fl: '1', rm: 'IDF-118', vl: 99, up: 10_884_000, cpu: 12, mem: 35, fan: 'ok', tp: 28, pu: 16, px: 2, pp: 24, sp: 4, pb: 384, pw: 68, cc: 0, upd: false, seen: 1 },
  { id: 'dev-sw-hq-guest-01', n: 'HQ-Guest-SW-01', t: 'switch', v: 'tp-link', m: 'TL-SG3210', sn: 'DEMO2109SG321001', fw: '3.0.6', ip: '10.10.0.23', mac: '02:00:00:11:00:0f', st: 'online', site: demoIds.hq, ctl: demoIds.omada, loc: 'Reception', fl: '1', rm: 'LOB-100', vl: 99, up: 7_326_000, cpu: 8, mem: 29, fan: 'n/a', tp: 10, pu: 3, px: 0, pp: 0, sp: 2, pb: 0, pw: 0, cc: 0, upd: false, seen: 4 },
  { id: 'dev-sw-hq-wh-01', n: 'HQ-Warehouse-SW-01', t: 'switch', v: 'mikrotik', m: 'CRS328-24P-4S+RM', sn: 'DEMOHDX0C331', fw: '7.16.2', ip: '10.10.0.16', mac: '02:00:00:11:00:10', st: 'online', site: demoIds.hq, ctl: null, loc: 'Warehouse', fl: '1', rm: 'WH-001', vl: 99, up: 6_940_000, cpu: 22, mem: 34, fan: 'ok', tp: 28, pu: 8, px: 2, pp: 24, sp: 4, pb: 500, pw: 47, cc: 1, upd: false, seen: 3 },
  { id: 'dev-sw-hq-lab-01', n: 'HQ-Lab-SW-01', t: 'switch', v: 'mikrotik', m: 'CRS354-48G-4S+2Q+RM', sn: 'DEMOHDX0C354', fw: '7.16.2', ip: '10.10.0.17', mac: '02:00:00:11:00:11', st: 'online', site: demoIds.hq, ctl: null, loc: 'Engineering lab', fl: '2', rm: 'LAB-220', vl: 99, up: 5_218_000, cpu: 26, mem: 37, fan: 'ok', tp: 54, pu: 14, px: 4, pp: 0, sp: 6, pb: 0, pw: 0, cc: 1, upd: false, seen: 2 },

  // ── HQ Campus · access points (19) ───────────────────────────────────────
  { id: 'dev-ap-lobby', n: 'HQ-Lobby-AP-01', t: 'access_point', v: 'tp-link', m: 'EAP670', sn: 'DEMO2301EAP670A1', fw: '1.0.13', ip: '10.10.0.31', mac: '02:00:00:00:10:02', st: 'online', site: demoIds.hq, ctl: demoIds.omada, loc: 'Lobby', fl: '1', rm: 'LOB-100', vl: 99, up: 6_820_000, cpu: 22, mem: 48, fan: 'n/a', tp: 1, pu: 1, px: 0, pp: 0, sp: 0, pb: 0, pw: 0, cc: 4, upd: false, seen: 1 },
  { id: 'dev-ap-hq-02', n: 'HQ-Floor1-AP-01', t: 'access_point', v: 'tp-link', m: 'EAP670', sn: 'DEMO2301EAP670A2', fw: '1.0.13', ip: '10.10.0.32', mac: '02:00:00:12:00:02', st: 'online', site: demoIds.hq, ctl: demoIds.omada, loc: 'Floor 1 west', fl: '1', rm: '1W-120', vl: 99, up: 6_818_000, cpu: 19, mem: 45, fan: 'n/a', tp: 1, pu: 1, px: 0, pp: 0, sp: 0, pb: 0, pw: 0, cc: 3, upd: false, seen: 1 },
  { id: 'dev-ap-hq-03', n: 'HQ-Floor1-AP-02', t: 'access_point', v: 'tp-link', m: 'EAP670', sn: 'DEMO2301EAP670A3', fw: '1.0.13', ip: '10.10.0.33', mac: '02:00:00:12:00:03', st: 'online', site: demoIds.hq, ctl: demoIds.omada, loc: 'Floor 1 east', fl: '1', rm: '1E-142', vl: 99, up: 6_812_000, cpu: 17, mem: 43, fan: 'n/a', tp: 1, pu: 1, px: 0, pp: 0, sp: 0, pb: 0, pw: 0, cc: 2, upd: false, seen: 2 },
  { id: 'dev-ap-hq-04', n: 'HQ-Floor1-AP-03', t: 'access_point', v: 'tp-link', m: 'EAP650', sn: 'DEMO2304EAP650B1', fw: '1.0.9', ip: '10.10.0.34', mac: '02:00:00:12:00:04', st: 'online', site: demoIds.hq, ctl: demoIds.omada, loc: 'Floor 1 north', fl: '1', rm: '1N-166', vl: 99, up: 6_806_000, cpu: 15, mem: 41, fan: 'n/a', tp: 1, pu: 1, px: 0, pp: 0, sp: 0, pb: 0, pw: 0, cc: 2, upd: true, seen: 2 },
  { id: 'dev-ap-hq-05', n: 'HQ-Floor2-AP-01', t: 'access_point', v: 'tp-link', m: 'EAP670', sn: 'DEMO2301EAP670A4', fw: '1.0.13', ip: '10.10.0.35', mac: '02:00:00:12:00:05', st: 'online', site: demoIds.hq, ctl: demoIds.omada, loc: 'Floor 2 west', fl: '2', rm: '2W-210', vl: 99, up: 6_442_000, cpu: 24, mem: 49, fan: 'n/a', tp: 1, pu: 1, px: 0, pp: 0, sp: 0, pb: 0, pw: 0, cc: 3, upd: false, seen: 1 },
  { id: 'dev-ap-hq-06', n: 'HQ-Floor2-AP-02', t: 'access_point', v: 'tp-link', m: 'EAP670', sn: 'DEMO2301EAP670A5', fw: '1.0.13', ip: '10.10.0.36', mac: '02:00:00:12:00:06', st: 'online', site: demoIds.hq, ctl: demoIds.omada, loc: 'Floor 2 east', fl: '2', rm: '2E-238', vl: 99, up: 6_438_000, cpu: 20, mem: 46, fan: 'n/a', tp: 1, pu: 1, px: 0, pp: 0, sp: 0, pb: 0, pw: 0, cc: 2, upd: false, seen: 2 },
  { id: 'dev-ap-hq-07', n: 'HQ-Floor2-AP-03', t: 'access_point', v: 'tp-link', m: 'EAP650', sn: 'DEMO2304EAP650B2', fw: '1.0.9', ip: '10.10.0.37', mac: '02:00:00:12:00:07', st: 'degraded', site: demoIds.hq, ctl: demoIds.omada, loc: 'Floor 2 north', fl: '2', rm: '2N-262', vl: 99, up: 212_000, cpu: 61, mem: 77, fan: 'n/a', tp: 1, pu: 1, px: 0, pp: 0, sp: 0, pb: 0, pw: 0, cc: 1, upd: true, seen: 3 },
  { id: 'dev-ap-hq-08', n: 'HQ-Floor3-AP-01', t: 'access_point', v: 'tp-link', m: 'EAP690E HD', sn: 'DEMO2404EAP690C1', fw: '1.1.4', ip: '10.10.0.38', mac: '02:00:00:12:00:08', st: 'online', site: demoIds.hq, ctl: demoIds.omada, loc: 'Floor 3 west', fl: '3', rm: '3W-306', vl: 99, up: 4_106_000, cpu: 26, mem: 52, fan: 'n/a', tp: 1, pu: 1, px: 0, pp: 0, sp: 0, pb: 0, pw: 0, cc: 2, upd: false, seen: 1 },
  { id: 'dev-ap-hq-09', n: 'HQ-Floor3-AP-02', t: 'access_point', v: 'tp-link', m: 'EAP690E HD', sn: 'DEMO2404EAP690C2', fw: '1.1.4', ip: '10.10.0.39', mac: '02:00:00:12:00:09', st: 'online', site: demoIds.hq, ctl: demoIds.omada, loc: 'Floor 3 east', fl: '3', rm: '3E-334', vl: 99, up: 4_102_000, cpu: 21, mem: 48, fan: 'n/a', tp: 1, pu: 1, px: 0, pp: 0, sp: 0, pb: 0, pw: 0, cc: 1, upd: false, seen: 2 },
  { id: 'dev-ap-hq-10', n: 'HQ-Conf-AP-01', t: 'access_point', v: 'tp-link', m: 'EAP660 HD', sn: 'DEMO2212EAP660D1', fw: '1.2.7', ip: '10.10.0.40', mac: '02:00:00:12:00:0a', st: 'online', site: demoIds.hq, ctl: demoIds.omada, loc: 'Boardroom', fl: '1', rm: 'CONF-A', vl: 99, up: 8_904_000, cpu: 18, mem: 44, fan: 'n/a', tp: 1, pu: 1, px: 0, pp: 0, sp: 0, pb: 0, pw: 0, cc: 2, upd: false, seen: 1 },
  { id: 'dev-ap-hq-11', n: 'HQ-Conf-AP-02', t: 'access_point', v: 'tp-link', m: 'EAP660 HD', sn: 'DEMO2212EAP660D2', fw: '1.2.7', ip: '10.10.0.41', mac: '02:00:00:12:00:0b', st: 'online', site: demoIds.hq, ctl: demoIds.omada, loc: 'Conference B', fl: '1', rm: 'CONF-B', vl: 99, up: 8_898_000, cpu: 14, mem: 40, fan: 'n/a', tp: 1, pu: 1, px: 0, pp: 0, sp: 0, pb: 0, pw: 0, cc: 1, upd: false, seen: 2 },
  { id: 'dev-ap-hq-12', n: 'HQ-Cafeteria-AP-01', t: 'access_point', v: 'tp-link', m: 'EAP620 HD', sn: 'DEMO2205EAP620E1', fw: '1.1.8', ip: '10.10.0.42', mac: '02:00:00:12:00:0c', st: 'online', site: demoIds.hq, ctl: demoIds.omada, loc: 'Cafeteria', fl: '1', rm: 'CAF-150', vl: 99, up: 9_512_000, cpu: 23, mem: 47, fan: 'n/a', tp: 1, pu: 1, px: 0, pp: 0, sp: 0, pb: 0, pw: 0, cc: 2, upd: false, seen: 2 },
  { id: 'dev-ap-hq-13', n: 'HQ-Warehouse-AP-01', t: 'access_point', v: 'tp-link', m: 'EAP610-Outdoor', sn: 'DEMO2306EAP610F1', fw: '1.0.7', ip: '10.10.0.43', mac: '02:00:00:12:00:0d', st: 'online', site: demoIds.hq, ctl: demoIds.omada, loc: 'Warehouse bay 2', fl: '1', rm: 'WH-002', vl: 99, up: 5_640_000, cpu: 16, mem: 39, fan: 'n/a', tp: 1, pu: 1, px: 0, pp: 0, sp: 0, pb: 0, pw: 0, cc: 1, upd: false, seen: 3 },
  { id: 'dev-ap-hq-14', n: 'HQ-Loading-AP-01', t: 'access_point', v: 'tp-link', m: 'EAP610-Outdoor', sn: 'DEMO2306EAP610F2', fw: '1.0.7', ip: '10.10.0.44', mac: '02:00:00:12:00:0e', st: 'offline', site: demoIds.hq, ctl: demoIds.omada, loc: 'Loading dock', fl: '1', rm: 'WH-010', vl: 99, up: 0, cpu: 0, mem: 0, fan: 'n/a', tp: 1, pu: 0, px: 0, pp: 0, sp: 0, pb: 0, pw: 0, cc: 0, upd: false, seen: 94 },
  { id: 'dev-ap-hq-15', n: 'HQ-Exec-AP-01', t: 'access_point', v: 'tp-link', m: 'EAP783', sn: 'DEMO2502EAP783G1', fw: '1.0.4', ip: '10.10.0.45', mac: '02:00:00:12:00:0f', st: 'online', site: demoIds.hq, ctl: demoIds.omada, loc: 'Executive suite', fl: '4', rm: '4E-410', vl: 99, up: 1_842_000, cpu: 12, mem: 38, fan: 'n/a', tp: 1, pu: 1, px: 0, pp: 0, sp: 0, pb: 0, pw: 0, cc: 1, upd: false, seen: 1 },
  { id: 'dev-ap-hq-16', n: 'HQ-Exec-AP-02', t: 'access_point', v: 'tp-link', m: 'EAP772', sn: 'DEMO2502EAP772G2', fw: '1.0.4', ip: '10.10.0.46', mac: '02:00:00:12:00:10', st: 'online', site: demoIds.hq, ctl: demoIds.omada, loc: 'Executive suite', fl: '4', rm: '4W-424', vl: 99, up: 1_838_000, cpu: 10, mem: 36, fan: 'n/a', tp: 1, pu: 1, px: 0, pp: 0, sp: 0, pb: 0, pw: 0, cc: 1, upd: false, seen: 2 },
  { id: 'dev-ap-hq-17', n: 'HQ-Training-AP-01', t: 'access_point', v: 'tp-link', m: 'EAP670', sn: 'DEMO2301EAP670A6', fw: '1.0.13', ip: '10.10.0.47', mac: '02:00:00:12:00:11', st: 'online', site: demoIds.hq, ctl: demoIds.omada, loc: 'Training room', fl: '2', rm: 'TRN-240', vl: 99, up: 7_204_000, cpu: 13, mem: 40, fan: 'n/a', tp: 1, pu: 1, px: 0, pp: 0, sp: 0, pb: 0, pw: 0, cc: 1, upd: false, seen: 3 },
  { id: 'dev-ap-hq-18', n: 'HQ-Hall-AP-01', t: 'access_point', v: 'tp-link', m: 'EAP615-Wall', sn: 'DEMO2209EAP615H1', fw: '1.2.2', ip: '10.10.0.48', mac: '02:00:00:12:00:12', st: 'online', site: demoIds.hq, ctl: demoIds.omada, loc: 'Main corridor', fl: '1', rm: '1C-130', vl: 99, up: 10_206_000, cpu: 9, mem: 34, fan: 'n/a', tp: 4, pu: 2, px: 0, pp: 1, sp: 0, pb: 13, pw: 4, cc: 1, upd: false, seen: 2 },
  { id: 'dev-ap-hq-19', n: 'HQ-Annex-AP-01', t: 'access_point', v: 'openwrt', m: 'Linksys E8450', sn: 'DEMOE8450A0071', fw: '24.10.0', ip: '10.10.0.49', mac: '02:00:00:12:00:13', st: 'online', site: demoIds.hq, ctl: null, loc: 'Annex', fl: '1', rm: 'ANX-012', vl: 99, up: 3_180_000, cpu: 11, mem: 51, fan: 'n/a', tp: 5, pu: 1, px: 0, pp: 0, sp: 0, pb: 0, pw: 0, cc: 0, upd: false, seen: 4 },

  // ── HQ Campus · the two non-network endpoints already in the fixture (2) ──
  { id: 'cam-front-door', n: 'Front Door Camera', t: 'camera', v: 'hikvision', m: 'DS-2CD2387G2', sn: 'DEMO2387G20114', fw: '5.7.13', ip: '10.10.40.21', mac: '02:00:00:00:40:21', st: 'online', site: demoIds.hq, ctl: demoIds.hikvision, loc: 'Main entrance', fl: '1', rm: 'LOB-100', vl: 40, up: 4_210_000, cpu: 17, mem: 38, fan: 'n/a', tp: 1, pu: 1, px: 0, pp: 0, sp: 0, pb: 0, pw: 0, cc: 0, upd: false, seen: 2 },
  { id: 'dev-phone-101', n: 'Reception Phone 101', t: 'phone', v: 'grandstream', m: 'GXP2170', sn: 'DEMOGXP2170101', fw: '1.0.11.88', ip: '10.10.30.101', mac: '02:00:00:00:30:65', st: 'online', site: demoIds.hq, ctl: demoIds.freepbx, loc: 'Reception', fl: '1', rm: 'LOB-100', vl: 30, up: 1_840_000, cpu: 8, mem: 31, fan: 'n/a', tp: 2, pu: 1, px: 0, pp: 0, sp: 0, pb: 0, pw: 0, cc: 0, upd: false, seen: 3 },

  // ── Branch Office · WAN edge and gateways (3) ────────────────────────────
  { id: 'dev-unifi-gw-branch', n: 'BR-GW-01', t: 'gateway', v: 'unifi', m: 'UDM-SE', sn: 'DEMO7C2E0A31', fw: '4.0.21', ip: '10.30.0.1', mac: '02:00:00:33:00:01', st: 'online', site: demoIds.branch, ctl: demoIds.unifi, loc: 'Comms room', fl: '1', rm: 'CR-01', vl: 99, up: 7_412_000, cpu: 24, mem: 56, fan: 'ok', tp: 11, pu: 6, px: 0, pp: 2, sp: 2, pb: 30, pw: 0, cc: 0, upd: false, seen: 2 },
  { id: 'dev-rtr-br-edge', n: 'BR-EDGE-RTR-01', t: 'router', v: 'mikrotik', m: 'RB5009UG+S+IN', sn: 'DEMOHDX0B509', fw: '7.16.2', ip: '10.30.0.7', mac: '02:00:00:33:00:02', st: 'online', site: demoIds.branch, ctl: null, loc: 'Comms room', fl: '1', rm: 'CR-01', vl: 99, up: 8_920_000, cpu: 17, mem: 31, fan: 'n/a', tp: 9, pu: 4, px: 0, pp: 0, sp: 1, pb: 0, pw: 0, cc: 0, upd: false, seen: 3 },
  { id: 'dev-gw-br-lte', n: 'BR-LTE-GW-01', t: 'gateway', v: 'openwrt', m: 'GL-X3000', sn: 'DEMOGLX30000042', fw: '24.10.0', ip: '10.30.0.9', mac: '02:00:00:33:00:03', st: 'online', site: demoIds.branch, ctl: null, loc: 'Comms room', fl: '1', rm: 'CR-01', vl: 99, up: 2_614_000, cpu: 7, mem: 42, fan: 'n/a', tp: 4, pu: 2, px: 0, pp: 0, sp: 0, pb: 0, pw: 0, cc: 0, upd: false, seen: 5 },

  // ── Branch Office · switches (8) ─────────────────────────────────────────
  { id: 'dev-sw-br-01', n: 'BR-Core-SW-01', t: 'switch', v: 'unifi', m: 'USW-Pro-24-PoE', sn: 'DEMO7C2E1B01', fw: '7.1.26', ip: '10.30.0.2', mac: '02:00:00:31:00:01', st: 'online', site: demoIds.branch, ctl: demoIds.unifi, loc: 'Comms room', fl: '1', rm: 'CR-01', vl: 99, up: 7_408_000, cpu: 16, mem: 43, fan: 'ok', tp: 26, pu: 14, px: 4, pp: 24, sp: 2, pb: 400, pw: 51, cc: 3, upd: false, seen: 1 },
  { id: 'dev-sw-br-02', n: 'BR-IDF1-SW-01', t: 'switch', v: 'unifi', m: 'USW-Pro-24-PoE', sn: 'DEMO7C2E1B02', fw: '7.1.26', ip: '10.30.0.3', mac: '02:00:00:31:00:02', st: 'online', site: demoIds.branch, ctl: demoIds.unifi, loc: 'IDF 1', fl: '1', rm: 'IDF-12', vl: 99, up: 7_402_000, cpu: 13, mem: 40, fan: 'ok', tp: 26, pu: 9, px: 2, pp: 24, sp: 2, pb: 400, pw: 38, cc: 2, upd: false, seen: 2 },
  { id: 'dev-sw-br-03', n: 'BR-IDF2-SW-01', t: 'switch', v: 'unifi', m: 'USW-24-PoE', sn: 'DEMO7C2E1B03', fw: '7.1.26', ip: '10.30.0.4', mac: '02:00:00:31:00:03', st: 'online', site: demoIds.branch, ctl: demoIds.unifi, loc: 'IDF 2', fl: '2', rm: 'IDF-24', vl: 99, up: 6_988_000, cpu: 11, mem: 37, fan: 'ok', tp: 26, pu: 7, px: 2, pp: 16, sp: 2, pb: 95, pw: 29, cc: 0, upd: true, seen: 2 },
  { id: 'dev-sw-br-04', n: 'BR-Agg-SW-01', t: 'switch', v: 'unifi', m: 'USW-Aggregation', sn: 'DEMO7C2E1B04', fw: '7.1.26', ip: '10.30.0.5', mac: '02:00:00:31:00:04', st: 'online', site: demoIds.branch, ctl: demoIds.unifi, loc: 'Comms room', fl: '1', rm: 'CR-01', vl: 99, up: 7_396_000, cpu: 8, mem: 28, fan: 'ok', tp: 8, pu: 4, px: 0, pp: 0, sp: 8, pb: 0, pw: 0, cc: 0, upd: false, seen: 3 },
  { id: 'dev-sw-br-05', n: 'BR-Reception-SW-01', t: 'switch', v: 'unifi', m: 'USW-Lite-16-PoE', sn: 'DEMO7C2E1B05', fw: '7.1.26', ip: '10.30.0.6', mac: '02:00:00:31:00:05', st: 'online', site: demoIds.branch, ctl: demoIds.unifi, loc: 'Reception', fl: '1', rm: 'REC-01', vl: 99, up: 6_204_000, cpu: 9, mem: 32, fan: 'n/a', tp: 16, pu: 6, px: 2, pp: 8, sp: 0, pb: 45, pw: 17, cc: 1, upd: false, seen: 2 },
  { id: 'dev-sw-br-06', n: 'BR-Conf-SW-01', t: 'switch', v: 'unifi', m: 'USW-Flex-Mini', sn: 'DEMO7C2E1B06', fw: '2.3.4', ip: '10.30.0.10', mac: '02:00:00:31:00:06', st: 'online', site: demoIds.branch, ctl: demoIds.unifi, loc: 'Conference room', fl: '1', rm: 'CONF-1', vl: 99, up: 4_882_000, cpu: 6, mem: 24, fan: 'n/a', tp: 5, pu: 2, px: 0, pp: 0, sp: 0, pb: 0, pw: 0, cc: 0, upd: false, seen: 4 },
  { id: 'dev-sw-br-07', n: 'BR-Lab-SW-01', t: 'switch', v: 'mikrotik', m: 'CRS326-24G-2S+RM', sn: 'DEMOHDX0B326', fw: '7.16.2', ip: '10.30.0.8', mac: '02:00:00:31:00:07', st: 'online', site: demoIds.branch, ctl: null, loc: 'Test lab', fl: '1', rm: 'LAB-04', vl: 99, up: 3_442_000, cpu: 19, mem: 30, fan: 'ok', tp: 26, pu: 5, px: 2, pp: 0, sp: 2, pb: 0, pw: 0, cc: 0, upd: false, seen: 3 },
  { id: 'dev-sw-br-08', n: 'BR-Yard-SW-01', t: 'switch', v: 'mikrotik', m: 'CRS328-24P-4S+RM', sn: 'DEMOHDX0B328', fw: '7.16.2', ip: '10.30.0.11', mac: '02:00:00:31:00:08', st: 'online', site: demoIds.branch, ctl: null, loc: 'Yard cabinet', fl: '1', rm: 'YD-01', vl: 99, up: 2_986_000, cpu: 15, mem: 29, fan: 'ok', tp: 28, pu: 4, px: 2, pp: 24, sp: 4, pb: 500, pw: 22, cc: 0, upd: false, seen: 4 },

  // ── Branch Office · access points (8) ────────────────────────────────────
  { id: 'dev-unifi-ap', n: 'Branch-U6-Pro-01', t: 'access_point', v: 'unifi', m: 'U6-Pro', sn: 'DEMO7C2E2C01', fw: '6.6.55', ip: '10.30.0.21', mac: '02:00:00:00:30:08', st: 'online', site: demoIds.branch, ctl: demoIds.unifi, loc: 'Open plan north', fl: '1', rm: 'OP-11', vl: 99, up: 2_490_000, cpu: 27, mem: 53, fan: 'n/a', tp: 1, pu: 1, px: 0, pp: 0, sp: 0, pb: 0, pw: 0, cc: 3, upd: false, seen: 2 },
  { id: 'dev-ap-br-02', n: 'Branch-U6-Pro-02', t: 'access_point', v: 'unifi', m: 'U6-Pro', sn: 'DEMO7C2E2C02', fw: '6.6.55', ip: '10.30.0.22', mac: '02:00:00:32:00:02', st: 'online', site: demoIds.branch, ctl: demoIds.unifi, loc: 'Open plan south', fl: '1', rm: 'OP-18', vl: 99, up: 2_486_000, cpu: 21, mem: 49, fan: 'n/a', tp: 1, pu: 1, px: 0, pp: 0, sp: 0, pb: 0, pw: 0, cc: 2, upd: false, seen: 2 },
  { id: 'dev-ap-br-03', n: 'Branch-U6-Enterprise-01', t: 'access_point', v: 'unifi', m: 'U6-Enterprise', sn: 'DEMO7C2E2C03', fw: '6.6.65', ip: '10.30.0.23', mac: '02:00:00:32:00:03', st: 'online', site: demoIds.branch, ctl: demoIds.unifi, loc: 'Conference room', fl: '1', rm: 'CONF-1', vl: 99, up: 2_112_000, cpu: 24, mem: 51, fan: 'n/a', tp: 1, pu: 1, px: 0, pp: 0, sp: 0, pb: 0, pw: 0, cc: 2, upd: false, seen: 1 },
  { id: 'dev-ap-br-04', n: 'Branch-U7-Pro-01', t: 'access_point', v: 'unifi', m: 'U7-Pro', sn: 'DEMO7C2E2C04', fw: '7.0.35', ip: '10.30.0.24', mac: '02:00:00:32:00:04', st: 'online', site: demoIds.branch, ctl: demoIds.unifi, loc: 'Floor 2 open plan', fl: '2', rm: 'OP-21', vl: 99, up: 1_204_000, cpu: 18, mem: 47, fan: 'n/a', tp: 1, pu: 1, px: 0, pp: 0, sp: 0, pb: 0, pw: 0, cc: 2, upd: false, seen: 2 },
  { id: 'dev-ap-br-05', n: 'Branch-U6-Mesh-01', t: 'access_point', v: 'unifi', m: 'U6-Mesh', sn: 'DEMO7C2E2C05', fw: '6.6.55', ip: '10.30.0.25', mac: '02:00:00:32:00:05', st: 'online', site: demoIds.branch, ctl: demoIds.unifi, loc: 'Yard canopy', fl: '1', rm: 'YD-02', vl: 99, up: 1_886_000, cpu: 15, mem: 42, fan: 'n/a', tp: 1, pu: 1, px: 0, pp: 0, sp: 0, pb: 0, pw: 0, cc: 1, upd: false, seen: 3 },
  { id: 'dev-ap-br-06', n: 'Branch-U6-LR-01', t: 'access_point', v: 'unifi', m: 'U6-LR', sn: 'DEMO7C2E2C06', fw: '6.6.55', ip: '10.30.0.26', mac: '02:00:00:32:00:06', st: 'online', site: demoIds.branch, ctl: demoIds.unifi, loc: 'Warehouse', fl: '1', rm: 'WH-01', vl: 99, up: 3_006_000, cpu: 13, mem: 40, fan: 'n/a', tp: 1, pu: 1, px: 0, pp: 0, sp: 0, pb: 0, pw: 0, cc: 1, upd: false, seen: 3 },
  { id: 'dev-ap-br-07', n: 'Branch-U6-IW-01', t: 'access_point', v: 'unifi', m: 'U6-IW', sn: 'DEMO7C2E2C07', fw: '6.6.55', ip: '10.30.0.27', mac: '02:00:00:32:00:07', st: 'online', site: demoIds.branch, ctl: demoIds.unifi, loc: 'Reception wall', fl: '1', rm: 'REC-01', vl: 99, up: 2_744_000, cpu: 10, mem: 37, fan: 'n/a', tp: 5, pu: 2, px: 0, pp: 1, sp: 0, pb: 13, pw: 4, cc: 1, upd: false, seen: 2 },
  { id: 'dev-ap-br-08', n: 'Branch-Yard-AP-01', t: 'access_point', v: 'openwrt', m: 'Netgear WAX206', sn: 'DEMOWAX206A0019', fw: '24.10.0', ip: '10.30.0.28', mac: '02:00:00:32:00:08', st: 'online', site: demoIds.branch, ctl: null, loc: 'Yard cabinet', fl: '1', rm: 'YD-01', vl: 99, up: 962_000, cpu: 8, mem: 46, fan: 'n/a', tp: 5, pu: 1, px: 0, pp: 0, sp: 0, pb: 0, pw: 0, cc: 0, upd: false, seen: 5 },

  // ── Datacenter · top-of-rack and edge (8) ────────────────────────────────
  // The DC hosts the Proxmox cluster and the TrueNAS pool, so its floor devices
  // are a redundant ToR pair per rack plus the edge. Without these the site card
  // reported zero devices and scored "unknown", which is what a site with no
  // telemetry looks like -- not what a datacenter looks like.
  { id: 'dev-fw-dc-01', n: 'DC-FW-01', t: 'firewall', v: 'opnsense', m: 'DEC3852', sn: 'DEMO-DEC3852-0001', fw: '24.7.8', ip: '10.50.0.1', mac: '02:00:00:50:00:01', st: 'online', site: demoIds.dc, ctl: demoIds.opnsense, loc: 'Cage 4', fl: '1', rm: 'ASH-C4', vl: 99, up: 21_400_000, cpu: 17, mem: 42, fan: 'ok', tp: 10, pu: 8, px: 0, pp: 0, sp: 6, pb: 0, pw: 0, cc: 0, upd: false, seen: 1 },
  { id: 'dev-rtr-dc-01', n: 'DC-EDGE-RTR-01', t: 'router', v: 'mikrotik', m: 'CCR2216-1G-12XS-2XQ', sn: 'DEMOHDX0C201', fw: '7.16.2', ip: '10.50.0.2', mac: '02:00:00:50:00:02', st: 'online', site: demoIds.dc, ctl: null, loc: 'Cage 4', fl: '1', rm: 'ASH-C4', vl: 99, up: 21_396_000, cpu: 22, mem: 35, fan: 'ok', tp: 16, pu: 11, px: 0, pp: 0, sp: 14, pb: 0, pw: 0, cc: 0, upd: false, seen: 1 },
  { id: 'dev-sw-dc-r1-tor-a', n: 'DC-R1-TOR-A', t: 'switch', v: 'mikrotik', m: 'CRS518-16XS-2XQ', sn: 'DEMOHDX0C310', fw: '7.16.2', ip: '10.50.0.11', mac: '02:00:00:50:01:0a', st: 'online', site: demoIds.dc, ctl: null, loc: 'Rack 1', fl: '1', rm: 'ASH-C4', vl: 99, up: 20_880_000, cpu: 13, mem: 29, fan: 'ok', tp: 18, pu: 12, px: 2, pp: 0, sp: 18, pb: 0, pw: 0, cc: 0, upd: false, seen: 2 },
  { id: 'dev-sw-dc-r1-tor-b', n: 'DC-R1-TOR-B', t: 'switch', v: 'mikrotik', m: 'CRS518-16XS-2XQ', sn: 'DEMOHDX0C311', fw: '7.16.2', ip: '10.50.0.12', mac: '02:00:00:50:01:0b', st: 'online', site: demoIds.dc, ctl: null, loc: 'Rack 1', fl: '1', rm: 'ASH-C4', vl: 99, up: 20_874_000, cpu: 11, mem: 28, fan: 'ok', tp: 18, pu: 12, px: 2, pp: 0, sp: 18, pb: 0, pw: 0, cc: 0, upd: false, seen: 2 },
  { id: 'dev-sw-dc-r2-tor-a', n: 'DC-R2-TOR-A', t: 'switch', v: 'mikrotik', m: 'CRS518-16XS-2XQ', sn: 'DEMOHDX0C312', fw: '7.16.2', ip: '10.50.0.13', mac: '02:00:00:50:02:0a', st: 'online', site: demoIds.dc, ctl: null, loc: 'Rack 2', fl: '1', rm: 'ASH-C4', vl: 99, up: 18_312_000, cpu: 14, mem: 31, fan: 'ok', tp: 18, pu: 10, px: 2, pp: 0, sp: 18, pb: 0, pw: 0, cc: 0, upd: false, seen: 2 },
  { id: 'dev-sw-dc-r2-tor-b', n: 'DC-R2-TOR-B', t: 'switch', v: 'mikrotik', m: 'CRS518-16XS-2XQ', sn: 'DEMOHDX0C313', fw: '7.16.2', ip: '10.50.0.14', mac: '02:00:00:50:02:0b', st: 'degraded', site: demoIds.dc, ctl: null, loc: 'Rack 2', fl: '1', rm: 'ASH-C4', vl: 99, up: 612_000, cpu: 58, mem: 74, fan: 'degraded', tp: 18, pu: 9, px: 2, pp: 0, sp: 18, pb: 0, pw: 0, cc: 0, upd: true, seen: 3 },
  { id: 'dev-sw-dc-mgmt-01', n: 'DC-MGMT-SW-01', t: 'switch', v: 'tp-link', m: 'TL-SG3428', sn: 'DEMO2245SG342801', fw: '1.20.4', ip: '10.50.0.15', mac: '02:00:00:50:03:01', st: 'online', site: demoIds.dc, ctl: demoIds.omada, loc: 'Rack 1', fl: '1', rm: 'ASH-C4', vl: 99, up: 20_868_000, cpu: 8, mem: 24, fan: 'ok', tp: 28, pu: 16, px: 4, pp: 0, sp: 4, pb: 0, pw: 0, cc: 0, upd: false, seen: 2 },
  { id: 'dev-sw-dc-oob-01', n: 'DC-OOB-SW-01', t: 'switch', v: 'tp-link', m: 'TL-SG3210', sn: 'DEMO2245SG321001', fw: '1.20.4', ip: '10.50.0.16', mac: '02:00:00:50:03:02', st: 'online', site: demoIds.dc, ctl: demoIds.omada, loc: 'Rack 2', fl: '1', rm: 'ASH-C4', vl: 99, up: 18_306_000, cpu: 6, mem: 21, fan: 'ok', tp: 10, pu: 7, px: 2, pp: 0, sp: 2, pb: 0, pw: 0, cc: 0, upd: false, seen: 3 },
].map((d) => ({
  id: d.id,
  name: d.n,
  hostname: d.n.toLowerCase().replace(/\s+/g, '-'),
  device_type: d.t,
  vendor: d.v,
  manufacturer: d.v,
  model: d.m,
  hardware_version: d.m,
  serial_number: d.sn,
  firmware_version: d.fw,
  ip_address: d.ip,
  mac_address: d.mac,
  external_id: d.mac,
  status: d.st,
  site_id: d.site,
  site_name: d.site === demoIds.hq ? 'HQ Campus' : 'Branch Office',
  controller_id: d.ctl,
  location: d.loc,
  floor: d.fl,
  room: d.rm,
  vlan_id: d.vl,
  connection_type: 'wired',
  uptime: d.up,
  uptime_seconds: d.up,
  cpu_usage: d.cpu,
  cpu_usage_percent: d.cpu,
  memory_usage: d.mem,
  memory_usage_percent: d.mem,
  fan_status: d.fan,
  temperature: d.st === 'offline' ? 0 : d.st === 'degraded' ? 71 : 38 + (d.cpu % 14),
  total_ports: d.tp,
  port_count: d.tp,
  ports_up: d.pu,
  active_port_count: d.pu,
  ports_disabled: d.px,
  ports_down: d.tp - d.pu - d.px,
  poe_ports: d.pp,
  sfp_ports: d.sp,
  poe_budget: d.pb,
  poe_used: d.pw,
  connected_clients: d.cc,
  client_count: d.cc,
  vlans_configured: ['switch', 'access_point'].includes(d.t) ? (d.site === demoIds.hq ? 6 : 5) : 1,
  mesh_enabled: /Mesh|Outdoor/.test(d.m),
  led_enabled: d.st === 'offline' ? null : d.ctl ? true : null,
  update_available: d.upd,
  topology_layer: ['firewall', 'router', 'gateway'].includes(d.t) ? 'core'
    : d.t !== 'switch' ? 'edge'
      : /Core|Agg/.test(d.n) ? 'distribution' : 'access',
  is_active: true,
  is_managed: true,
  notes: null,
  discovery_method: d.ctl ? 'controller' : 'agent',
  seen_minutes: d.seen,
  last_seen: iso(d.seen),
  created_at: iso(60 * 24 * 18),
  updated_at: iso(d.seen),
  metadata: {},
  capabilities: {},
}));


// `devices` IS the fleet. Three lists used to disagree here -- an 8-row
// `devices`, this 61-row fleet, and sites asserting 92 between them -- so the
// dashboard claimed one number while the device list showed another. Everything
// downstream now derives from this one alias.
export const devices = networkDevices;
// ── AP radios ─────────────────────────────────────────────────────────────
// `channel_width` is the Omada width CODE the AP page decodes (0=20, 1=40,
// 3=80, 5=160, 7=320 MHz), not a MHz value. Per-radio `clients` sum to each
// AP's `connected_clients`.
export const apRadios = [
  { d: 'dev-ap-lobby', b: '2g', ch: 1, cw: 1, txp: 17, mode: 'auto', c: 1 },
  { d: 'dev-ap-lobby', b: '5g', ch: 36, cw: 3, txp: 20, mode: 'auto', c: 3 },
  { d: 'dev-ap-hq-02', b: '2g', ch: 6, cw: 1, txp: 17, mode: 'auto', c: 1 },
  { d: 'dev-ap-hq-02', b: '5g', ch: 44, cw: 3, txp: 20, mode: 'auto', c: 2 },
  { d: 'dev-ap-hq-03', b: '2g', ch: 11, cw: 1, txp: 17, mode: 'auto', c: 0 },
  { d: 'dev-ap-hq-03', b: '5g', ch: 149, cw: 3, txp: 20, mode: 'auto', c: 2 },
  { d: 'dev-ap-hq-04', b: '2g', ch: 1, cw: 1, txp: 16, mode: 'auto', c: 1 },
  { d: 'dev-ap-hq-04', b: '5g', ch: 157, cw: 3, txp: 19, mode: 'auto', c: 1 },
  { d: 'dev-ap-hq-05', b: '2g', ch: 6, cw: 1, txp: 17, mode: 'auto', c: 1 },
  { d: 'dev-ap-hq-05', b: '5g', ch: 40, cw: 3, txp: 20, mode: 'auto', c: 2 },
  { d: 'dev-ap-hq-06', b: '2g', ch: 11, cw: 1, txp: 17, mode: 'auto', c: 0 },
  { d: 'dev-ap-hq-06', b: '5g', ch: 48, cw: 3, txp: 20, mode: 'auto', c: 2 },
  { d: 'dev-ap-hq-07', b: '2g', ch: 1, cw: 1, txp: 17, mode: 'auto', c: 0 },
  { d: 'dev-ap-hq-07', b: '5g', ch: 153, cw: 3, txp: 20, mode: 'auto', c: 1 },
  { d: 'dev-ap-hq-08', b: '2g', ch: 6, cw: 1, txp: 17, mode: 'auto', c: 0 },
  { d: 'dev-ap-hq-08', b: '5g', ch: 36, cw: 3, txp: 20, mode: 'auto', c: 1 },
  { d: 'dev-ap-hq-08', b: '6g', ch: 37, cw: 5, txp: 18, mode: 'auto', c: 1 },
  { d: 'dev-ap-hq-09', b: '2g', ch: 11, cw: 1, txp: 17, mode: 'auto', c: 0 },
  { d: 'dev-ap-hq-09', b: '5g', ch: 44, cw: 3, txp: 20, mode: 'auto', c: 1 },
  { d: 'dev-ap-hq-09', b: '6g', ch: 53, cw: 5, txp: 18, mode: 'auto', c: 0 },
  { d: 'dev-ap-hq-10', b: '2g', ch: 1, cw: 1, txp: 17, mode: 'auto', c: 0 },
  { d: 'dev-ap-hq-10', b: '5g', ch: 149, cw: 3, txp: 21, mode: 'high', c: 2 },
  { d: 'dev-ap-hq-11', b: '2g', ch: 6, cw: 1, txp: 17, mode: 'auto', c: 0 },
  { d: 'dev-ap-hq-11', b: '5g', ch: 161, cw: 3, txp: 21, mode: 'high', c: 1 },
  { d: 'dev-ap-hq-12', b: '2g', ch: 11, cw: 1, txp: 17, mode: 'auto', c: 1 },
  { d: 'dev-ap-hq-12', b: '5g', ch: 36, cw: 3, txp: 20, mode: 'auto', c: 1 },
  { d: 'dev-ap-hq-13', b: '2g', ch: 1, cw: 0, txp: 20, mode: 'high', c: 1 },
  { d: 'dev-ap-hq-13', b: '5g', ch: 157, cw: 3, txp: 23, mode: 'high', c: 0 },
  { d: 'dev-ap-hq-14', b: '2g', ch: 6, cw: 0, txp: 20, mode: 'high', c: 0 },
  { d: 'dev-ap-hq-14', b: '5g', ch: 161, cw: 3, txp: 23, mode: 'high', c: 0 },
  { d: 'dev-ap-hq-15', b: '2g', ch: 1, cw: 1, txp: 17, mode: 'auto', c: 0 },
  { d: 'dev-ap-hq-15', b: '5g', ch: 40, cw: 3, txp: 21, mode: 'auto', c: 1 },
  { d: 'dev-ap-hq-15', b: '6g', ch: 69, cw: 7, txp: 18, mode: 'auto', c: 0 },
  { d: 'dev-ap-hq-16', b: '2g', ch: 6, cw: 1, txp: 17, mode: 'auto', c: 0 },
  { d: 'dev-ap-hq-16', b: '5g', ch: 48, cw: 3, txp: 21, mode: 'auto', c: 0 },
  { d: 'dev-ap-hq-16', b: '6g', ch: 85, cw: 5, txp: 18, mode: 'auto', c: 1 },
  { d: 'dev-ap-hq-17', b: '2g', ch: 11, cw: 1, txp: 17, mode: 'auto', c: 0 },
  { d: 'dev-ap-hq-17', b: '5g', ch: 52, cw: 3, txp: 20, mode: 'auto', c: 1 },
  { d: 'dev-ap-hq-18', b: '2g', ch: 1, cw: 1, txp: 14, mode: 'auto', c: 0 },
  { d: 'dev-ap-hq-18', b: '5g', ch: 44, cw: 3, txp: 17, mode: 'auto', c: 1 },
  { d: 'dev-ap-hq-19', b: '2g', ch: 11, cw: 1, txp: 20, mode: 'custom', c: 0 },
  { d: 'dev-ap-hq-19', b: '5g', ch: 36, cw: 3, txp: 23, mode: 'custom', c: 0 },
  { d: 'dev-unifi-ap', b: '2g', ch: 6, cw: 1, txp: 18, mode: 'auto', c: 1 },
  { d: 'dev-unifi-ap', b: '5g', ch: 44, cw: 3, txp: 22, mode: 'auto', c: 2 },
  { d: 'dev-ap-br-02', b: '2g', ch: 11, cw: 1, txp: 18, mode: 'auto', c: 0 },
  { d: 'dev-ap-br-02', b: '5g', ch: 157, cw: 3, txp: 22, mode: 'auto', c: 2 },
  { d: 'dev-ap-br-03', b: '2g', ch: 1, cw: 1, txp: 18, mode: 'auto', c: 0 },
  { d: 'dev-ap-br-03', b: '5g', ch: 36, cw: 3, txp: 23, mode: 'auto', c: 2 },
  { d: 'dev-ap-br-03', b: '6g', ch: 37, cw: 5, txp: 20, mode: 'auto', c: 0 },
  { d: 'dev-ap-br-04', b: '2g', ch: 6, cw: 1, txp: 18, mode: 'auto', c: 0 },
  { d: 'dev-ap-br-04', b: '5g', ch: 149, cw: 3, txp: 23, mode: 'auto', c: 2 },
  { d: 'dev-ap-br-04', b: '6g', ch: 53, cw: 5, txp: 20, mode: 'auto', c: 0 },
  { d: 'dev-ap-br-05', b: '2g', ch: 11, cw: 0, txp: 20, mode: 'high', c: 0 },
  { d: 'dev-ap-br-05', b: '5g', ch: 48, cw: 3, txp: 22, mode: 'high', c: 1 },
  { d: 'dev-ap-br-06', b: '2g', ch: 1, cw: 1, txp: 20, mode: 'high', c: 1 },
  { d: 'dev-ap-br-06', b: '5g', ch: 40, cw: 3, txp: 23, mode: 'high', c: 0 },
  { d: 'dev-ap-br-07', b: '2g', ch: 6, cw: 1, txp: 16, mode: 'auto', c: 0 },
  { d: 'dev-ap-br-07', b: '5g', ch: 161, cw: 3, txp: 20, mode: 'auto', c: 1 },
  { d: 'dev-ap-br-08', b: '2g', ch: 11, cw: 1, txp: 20, mode: 'custom', c: 0 },
  { d: 'dev-ap-br-08', b: '5g', ch: 36, cw: 3, txp: 23, mode: 'custom', c: 0 },
].map((r) => ({
  device_id: r.d,
  band: r.b,
  channel: r.ch,
  channel_width: r.cw,
  tx_power: r.txp,
  tx_power_mode: r.mode,
  clients: r.c,
}));

// ── VLANs · both sites ────────────────────────────────────────────────────
export const networkVlans = [
  { id: 'vlan-hq-10', vlan_id: 10, name: 'Corporate', description: 'Staff workstations and laptops', purpose: 'data', site_id: demoIds.hq, dhcp_enabled: true, dhcp_start: '10.10.10.50', dhcp_end: '10.10.10.250', gateway: '10.10.10.1', subnet_mask: '255.255.255.0', cidr: '10.10.10.0/24', subnet: '10.10.10.0' },
  { id: 'vlan-hq-20', vlan_id: 20, name: 'Guest', description: 'Captive-portal guest access, internet only', purpose: 'guest', site_id: demoIds.hq, dhcp_enabled: true, dhcp_start: '10.10.20.50', dhcp_end: '10.10.20.250', gateway: '10.10.20.1', subnet_mask: '255.255.255.0', cidr: '10.10.20.0/24', subnet: '10.10.20.0' },
  { id: 'vlan-hq-30', vlan_id: 30, name: 'Voice', description: 'SIP handsets, LLDP-MED auto-assigned', purpose: 'voice', site_id: demoIds.hq, dhcp_enabled: true, dhcp_start: '10.10.30.100', dhcp_end: '10.10.30.240', gateway: '10.10.30.1', subnet_mask: '255.255.255.0', cidr: '10.10.30.0/24', subnet: '10.10.30.0' },
  { id: 'vlan-hq-40', vlan_id: 40, name: 'Cameras', description: 'Surveillance, no route to Corporate', purpose: 'camera', site_id: demoIds.hq, dhcp_enabled: true, dhcp_start: '10.10.40.20', dhcp_end: '10.10.40.120', gateway: '10.10.40.1', subnet_mask: '255.255.255.0', cidr: '10.10.40.0/24', subnet: '10.10.40.0' },
  { id: 'vlan-hq-50', vlan_id: 50, name: 'IoT / Building', description: 'Badge readers, HVAC and sensors', purpose: 'iot', site_id: demoIds.hq, dhcp_enabled: true, dhcp_start: '10.10.50.30', dhcp_end: '10.10.50.200', gateway: '10.10.50.1', subnet_mask: '255.255.255.0', cidr: '10.10.50.0/24', subnet: '10.10.50.0' },
  { id: 'vlan-hq-99', vlan_id: 99, name: 'Management', description: 'Switch, AP and gateway management plane', purpose: 'management', site_id: demoIds.hq, dhcp_enabled: false, dhcp_start: undefined, dhcp_end: undefined, gateway: '10.10.0.1', subnet_mask: '255.255.255.0', cidr: '10.10.0.0/24', subnet: '10.10.0.0' },
  { id: 'vlan-br-10', vlan_id: 10, name: 'Corporate', description: 'Branch staff workstations and laptops', purpose: 'data', site_id: demoIds.branch, dhcp_enabled: true, dhcp_start: '10.30.10.50', dhcp_end: '10.30.10.240', gateway: '10.30.10.1', subnet_mask: '255.255.255.0', cidr: '10.30.10.0/24', subnet: '10.30.10.0' },
  { id: 'vlan-br-20', vlan_id: 20, name: 'Guest', description: 'Branch guest wifi, internet only', purpose: 'guest', site_id: demoIds.branch, dhcp_enabled: true, dhcp_start: '10.30.20.50', dhcp_end: '10.30.20.240', gateway: '10.30.20.1', subnet_mask: '255.255.255.0', cidr: '10.30.20.0/24', subnet: '10.30.20.0' },
  { id: 'vlan-br-30', vlan_id: 30, name: 'Voice', description: 'Branch SIP handsets', purpose: 'voice', site_id: demoIds.branch, dhcp_enabled: true, dhcp_start: '10.30.30.100', dhcp_end: '10.30.30.200', gateway: '10.30.30.1', subnet_mask: '255.255.255.0', cidr: '10.30.30.0/24', subnet: '10.30.30.0' },
  { id: 'vlan-br-40', vlan_id: 40, name: 'Cameras', description: 'Branch surveillance segment', purpose: 'camera', site_id: demoIds.branch, dhcp_enabled: true, dhcp_start: '10.30.40.20', dhcp_end: '10.30.40.100', gateway: '10.30.40.1', subnet_mask: '255.255.255.0', cidr: '10.30.40.0/24', subnet: '10.30.40.0' },
  { id: 'vlan-br-99', vlan_id: 99, name: 'Management', description: 'Branch management plane', purpose: 'management', site_id: demoIds.branch, dhcp_enabled: false, dhcp_start: undefined, dhcp_end: undefined, gateway: '10.30.0.1', subnet_mask: '255.255.255.0', cidr: '10.30.0.0/24', subnet: '10.30.0.0' },
];

// ── WiFi networks / SSIDs ─────────────────────────────────────────────────
// No PSK is stored anywhere in the demo: the read model has no password field
// and the fixture deliberately does not invent one.
export const wifiNetworks = [
  { id: 'ssid-hq-corp', ssid: 'Acme-Corp', name: 'Acme-Corp', security: 'wpa2_wpa3_personal', vlan_id: 10, site_id: demoIds.hq, controller_id: demoIds.omada, hidden: false, enabled: true, band: 'both', client_isolation: false, band_steering: true, fast_roaming: true, rate_limit_enabled: false, rate_limit_up: undefined, rate_limit_down: undefined, guest_network: false, wlan_group_name: 'HQ Default', wlan_group_id: 'wg-hq-default', external_id: 'omada-wlan-1', schedule_enabled: false, mac_filter_enabled: false, portal_enabled: false },
  { id: 'ssid-hq-guest', ssid: 'Acme-Guest', name: 'Acme-Guest', security: 'open', vlan_id: 20, site_id: demoIds.hq, controller_id: demoIds.omada, hidden: false, enabled: true, band: '5ghz', client_isolation: true, band_steering: false, fast_roaming: false, rate_limit_enabled: true, rate_limit_up: 5000, rate_limit_down: 20000, guest_network: true, wlan_group_name: 'HQ Guest', wlan_group_id: 'wg-hq-guest', external_id: 'omada-wlan-2', schedule_enabled: true, mac_filter_enabled: false, portal_enabled: true },
  { id: 'ssid-hq-voice', ssid: 'Acme-Voice', name: 'Acme-Voice', security: 'wpa2_personal', vlan_id: 30, site_id: demoIds.hq, controller_id: demoIds.omada, hidden: true, enabled: true, band: '5ghz', client_isolation: false, band_steering: false, fast_roaming: true, rate_limit_enabled: false, rate_limit_up: undefined, rate_limit_down: undefined, guest_network: false, wlan_group_name: 'HQ Default', wlan_group_id: 'wg-hq-default', external_id: 'omada-wlan-3', schedule_enabled: false, mac_filter_enabled: false, portal_enabled: false },
  { id: 'ssid-hq-iot', ssid: 'Acme-IoT', name: 'Acme-IoT', security: 'wpa2_personal', vlan_id: 50, site_id: demoIds.hq, controller_id: demoIds.omada, hidden: true, enabled: true, band: '2.4ghz', client_isolation: true, band_steering: false, fast_roaming: false, rate_limit_enabled: true, rate_limit_up: 2000, rate_limit_down: 4000, guest_network: false, wlan_group_name: 'HQ IoT', wlan_group_id: 'wg-hq-iot', external_id: 'omada-wlan-4', schedule_enabled: false, mac_filter_enabled: true, portal_enabled: false },
  { id: 'ssid-hq-corp-6e', ssid: 'Acme-Corp-6E', name: 'Acme-Corp-6E', security: 'wpa3_personal', vlan_id: 10, site_id: demoIds.hq, controller_id: demoIds.omada, hidden: false, enabled: true, band: '6ghz', client_isolation: false, band_steering: false, fast_roaming: true, rate_limit_enabled: false, rate_limit_up: undefined, rate_limit_down: undefined, guest_network: false, wlan_group_name: 'HQ Default', wlan_group_id: 'wg-hq-default', external_id: 'omada-wlan-5', schedule_enabled: false, mac_filter_enabled: false, portal_enabled: false },
  { id: 'ssid-br-corp', ssid: 'Acme-Corp', name: 'Acme-Corp', security: 'wpa2_wpa3_personal', vlan_id: 10, site_id: demoIds.branch, controller_id: demoIds.unifi, hidden: false, enabled: true, band: 'both', client_isolation: false, band_steering: true, fast_roaming: true, rate_limit_enabled: false, rate_limit_up: undefined, rate_limit_down: undefined, guest_network: false, wlan_group_name: 'Branch Default', wlan_group_id: 'wg-br-default', external_id: 'unifi-wlan-1', schedule_enabled: false, mac_filter_enabled: false, portal_enabled: false },
  { id: 'ssid-br-guest', ssid: 'Acme-Guest', name: 'Acme-Guest', security: 'open', vlan_id: 20, site_id: demoIds.branch, controller_id: demoIds.unifi, hidden: false, enabled: true, band: '5ghz', client_isolation: true, band_steering: false, fast_roaming: false, rate_limit_enabled: true, rate_limit_up: 5000, rate_limit_down: 10000, guest_network: true, wlan_group_name: 'Branch Guest', wlan_group_id: 'wg-br-guest', external_id: 'unifi-wlan-2', schedule_enabled: true, mac_filter_enabled: false, portal_enabled: true },
  { id: 'ssid-br-voice', ssid: 'Acme-Voice', name: 'Acme-Voice', security: 'wpa2_personal', vlan_id: 30, site_id: demoIds.branch, controller_id: demoIds.unifi, hidden: true, enabled: false, band: '5ghz', client_isolation: false, band_steering: false, fast_roaming: true, rate_limit_enabled: false, rate_limit_up: undefined, rate_limit_down: undefined, guest_network: false, wlan_group_name: 'Branch Default', wlan_group_id: 'wg-br-default', external_id: 'unifi-wlan-3', schedule_enabled: false, mac_filter_enabled: false, portal_enabled: false },
];

// ── Switch ports · hand-authored panel for the HQ core switch ─────────────
// `w` is PoE draw in watts (0 = capable but not delivering). Port counts here
// match ports_up / ports_down / ports_disabled on the parent device, and the
// summed watts match its poe_used. Every other switch gets an equivalent panel
// derived from its device row by `fleetPortSpec` in mockApi.
export const switchPortFixtures = [
  // HQ-Core-SW-01 · TL-SG3428XMP · 24x GbE PoE+ + 4x 10G SFP+ · 85 W of 384 W
  { sw: 'dev-sw-core', i: 1, name: 'Omada OC300 Controller', kind: 'ethernet', mode: 'access', vlan: 99, tagged: [] as number[], on: true, poe: true, w: 5.4, link: 'up', speed: 1000, rxErr: 0, txErr: 0, peer: null as string | null, peerPort: null as string | null },
  { sw: 'dev-sw-core', i: 2, name: 'HQ-Lobby-AP-01', kind: 'ethernet', mode: 'trunk', vlan: 99, tagged: [10, 20, 30, 50], on: true, poe: true, w: 12.8, link: 'up', speed: 1000, rxErr: 0, txErr: 0, peer: 'HQ-Lobby-AP-01', peerPort: 'eth0' },
  { sw: 'dev-sw-core', i: 3, name: 'HQ-Conf-AP-01', kind: 'ethernet', mode: 'trunk', vlan: 99, tagged: [10, 20, 30, 50], on: true, poe: true, w: 11.9, link: 'up', speed: 1000, rxErr: 0, txErr: 0, peer: 'HQ-Conf-AP-01', peerPort: 'eth0' },
  { sw: 'dev-sw-core', i: 4, name: 'HQ-Conf-AP-02', kind: 'ethernet', mode: 'trunk', vlan: 99, tagged: [10, 20, 30, 50], on: true, poe: true, w: 11.4, link: 'up', speed: 1000, rxErr: 0, txErr: 0, peer: 'HQ-Conf-AP-02', peerPort: 'eth0' },
  { sw: 'dev-sw-core', i: 5, name: 'HQ-Cafeteria-AP-01', kind: 'ethernet', mode: 'trunk', vlan: 99, tagged: [10, 20, 30], on: true, poe: true, w: 9.8, link: 'up', speed: 1000, rxErr: 0, txErr: 0, peer: 'HQ-Cafeteria-AP-01', peerPort: 'eth0' },
  { sw: 'dev-sw-core', i: 6, name: 'HQ-Training-AP-01', kind: 'ethernet', mode: 'trunk', vlan: 99, tagged: [10, 20, 30, 50], on: true, poe: true, w: 10.6, link: 'up', speed: 1000, rxErr: 0, txErr: 0, peer: 'HQ-Training-AP-01', peerPort: 'eth0' },
  { sw: 'dev-sw-core', i: 7, name: 'HQ-Hall-AP-01', kind: 'ethernet', mode: 'trunk', vlan: 99, tagged: [10, 20, 30], on: true, poe: true, w: 7.2, link: 'up', speed: 1000, rxErr: 0, txErr: 0, peer: 'HQ-Hall-AP-01', peerPort: 'eth0' },
  { sw: 'dev-sw-core', i: 8, name: 'Reception Phone 101', kind: 'ethernet', mode: 'access', vlan: 30, tagged: [], on: true, poe: true, w: 4.1, link: 'up', speed: 1000, rxErr: 0, txErr: 0, peer: 'Reception Phone 101', peerPort: 'LAN' },
  { sw: 'dev-sw-core', i: 9, name: 'Front Door Camera', kind: 'ethernet', mode: 'access', vlan: 40, tagged: [], on: true, poe: true, w: 8.3, link: 'up', speed: 100, rxErr: 3, txErr: 0, peer: 'Front Door Camera', peerPort: 'eth0' },
  { sw: 'dev-sw-core', i: 10, name: 'Badge Reader - Main Entry', kind: 'ethernet', mode: 'access', vlan: 50, tagged: [], on: true, poe: true, w: 3.2, link: 'up', speed: 100, rxErr: 0, txErr: 0, peer: null, peerPort: null },
  { sw: 'dev-sw-core', i: 11, name: 'MDF Console Server', kind: 'ethernet', mode: 'access', vlan: 99, tagged: [], on: true, poe: true, w: 0, link: 'up', speed: 1000, rxErr: 0, txErr: 0, peer: null, peerPort: null },
  { sw: 'dev-sw-core', i: 12, name: 'Reception Printer', kind: 'ethernet', mode: 'access', vlan: 10, tagged: [], on: true, poe: true, w: 0, link: 'up', speed: 1000, rxErr: 0, txErr: 0, peer: null, peerPort: null },
  { sw: 'dev-sw-core', i: 13, name: 'Boardroom Display', kind: 'ethernet', mode: 'access', vlan: 10, tagged: [], on: true, poe: true, w: 0, link: 'up', speed: 1000, rxErr: 0, txErr: 0, peer: null, peerPort: null },
  { sw: 'dev-sw-core', i: 14, name: 'Front Desk Workstation', kind: 'ethernet', mode: 'access', vlan: 10, tagged: [], on: true, poe: true, w: 0, link: 'up', speed: 1000, rxErr: 0, txErr: 0, peer: null, peerPort: null },
  { sw: 'dev-sw-core', i: 15, name: 'Guest Kiosk', kind: 'ethernet', mode: 'access', vlan: 20, tagged: [], on: true, poe: true, w: 0, link: 'up', speed: 100, rxErr: 0, txErr: 0, peer: null, peerPort: null },
  { sw: 'dev-sw-core', i: 16, name: 'Patch MDF-16', kind: 'ethernet', mode: 'access', vlan: 10, tagged: [], on: true, poe: true, w: 0, link: 'down', speed: 0, rxErr: 0, txErr: 0, peer: null, peerPort: null },
  { sw: 'dev-sw-core', i: 17, name: 'Patch MDF-17', kind: 'ethernet', mode: 'access', vlan: 10, tagged: [], on: true, poe: true, w: 0, link: 'down', speed: 0, rxErr: 0, txErr: 0, peer: null, peerPort: null },
  { sw: 'dev-sw-core', i: 18, name: 'Patch MDF-18 (decommissioned)', kind: 'ethernet', mode: 'access', vlan: 1, tagged: [], on: false, poe: true, w: 0, link: 'down', speed: 0, rxErr: 0, txErr: 0, peer: null, peerPort: null },
  { sw: 'dev-sw-core', i: 19, name: 'Patch MDF-19', kind: 'ethernet', mode: 'access', vlan: 10, tagged: [], on: true, poe: true, w: 0, link: 'down', speed: 0, rxErr: 0, txErr: 0, peer: null, peerPort: null },
  { sw: 'dev-sw-core', i: 20, name: 'Patch MDF-20', kind: 'ethernet', mode: 'access', vlan: 10, tagged: [], on: true, poe: true, w: 0, link: 'down', speed: 0, rxErr: 0, txErr: 0, peer: null, peerPort: null },
  { sw: 'dev-sw-core', i: 21, name: 'HQ-ANNEX-GW-01', kind: 'ethernet', mode: 'trunk', vlan: 99, tagged: [10, 20, 50], on: true, poe: true, w: 0, link: 'up', speed: 1000, rxErr: 0, txErr: 1, peer: 'HQ-ANNEX-GW-01', peerPort: 'lan1' },
  { sw: 'dev-sw-core', i: 22, name: 'Spare', kind: 'ethernet', mode: 'access', vlan: 1, tagged: [], on: false, poe: true, w: 0, link: 'down', speed: 0, rxErr: 0, txErr: 0, peer: null, peerPort: null },
  { sw: 'dev-sw-core', i: 23, name: 'Spare', kind: 'ethernet', mode: 'access', vlan: 1, tagged: [], on: false, poe: true, w: 0, link: 'down', speed: 0, rxErr: 0, txErr: 0, peer: null, peerPort: null },
  { sw: 'dev-sw-core', i: 24, name: 'Spare', kind: 'ethernet', mode: 'access', vlan: 1, tagged: [], on: false, poe: true, w: 0, link: 'down', speed: 0, rxErr: 0, txErr: 0, peer: null, peerPort: null },
  { sw: 'dev-sw-core', i: 25, name: 'Uplink to HQ-FW-01', kind: 'sfp', mode: 'trunk', vlan: 99, tagged: [10, 20, 30, 40, 50], on: true, poe: false, w: 0, link: 'up', speed: 10000, rxErr: 0, txErr: 0, peer: 'HQ-FW-01', peerPort: 'igb1' },
  { sw: 'dev-sw-core', i: 26, name: 'LAG1 to HQ-Core-SW-02', kind: 'sfp', mode: 'trunk', vlan: 99, tagged: [10, 20, 30, 40, 50], on: true, poe: false, w: 0, link: 'up', speed: 10000, rxErr: 0, txErr: 0, peer: 'HQ-Core-SW-02', peerPort: 'Te1/0/26' },
  { sw: 'dev-sw-core', i: 27, name: 'Uplink to HQ-Agg-SW-01', kind: 'sfp', mode: 'trunk', vlan: 99, tagged: [10, 20, 30, 40, 50], on: true, poe: false, w: 0, link: 'up', speed: 10000, rxErr: 0, txErr: 0, peer: 'HQ-Agg-SW-01', peerPort: 'Te1/0/1' },
  { sw: 'dev-sw-core', i: 28, name: 'Spare 10G', kind: 'sfp', mode: 'trunk', vlan: 99, tagged: [], on: true, poe: false, w: 0, link: 'down', speed: 0, rxErr: 0, txErr: 0, peer: null, peerPort: null },
];

// ── Link aggregation groups ───────────────────────────────────────────────
export const switchLags = [
  { id: 'lag-hq-core-01', device_id: 'dev-sw-core', name: 'LAG1 · Core stack', lag_id: 1, mode: 'lacp', member_ports: [26], lacp_mode: 'active', lacp_timeout: 'fast', status: 'up', active_ports: 1, aggregate_speed: 10000 },
  { id: 'lag-hq-core-02', device_id: 'dev-sw-hq-core-02', name: 'LAG1 · Core stack', lag_id: 1, mode: 'lacp', member_ports: [26], lacp_mode: 'active', lacp_timeout: 'fast', status: 'up', active_ports: 1, aggregate_speed: 10000 },
  { id: 'lag-br-core-01', device_id: 'dev-sw-br-01', name: 'LAG1 · Uplink to aggregation', lag_id: 1, mode: 'lacp', member_ports: [25, 26], lacp_mode: 'active', lacp_timeout: 'slow', status: 'up', active_ports: 2, aggregate_speed: 20000 },
];

// ── Network clients ───────────────────────────────────────────────────────
// `dev` is the switch or AP the client is attached to, so every client resolves
// to a real device in `networkDevices`. Per-AP wireless counts here match each
// AP's `connected_clients`; per-switch wired counts match `connected_clients`
// on the switch. `m` is the age of last_seen in minutes.
export const networkClients = [
  // HQ · wireless
  { id: 'cl-hq-w01', host: 'reception-ipad', mac: '02:00:0c:10:00:01', ip: '10.10.10.201', type: 'wireless', dev: 'dev-ap-lobby', ssid: 'Acme-Corp', sig: -46, rx: 2_140_000_000, tx: 486_000_000, status: 'online', blocked: false, site: demoIds.hq, m: 1 },
  { id: 'cl-hq-w02', host: 'lobby-kiosk', mac: '02:00:0c:10:00:02', ip: '10.10.20.101', type: 'wireless', dev: 'dev-ap-lobby', ssid: 'Acme-Guest', sig: -52, rx: 918_000_000, tx: 121_000_000, status: 'online', blocked: false, site: demoIds.hq, m: 2 },
  { id: 'cl-hq-w03', host: 'jm-macbook', mac: '02:00:0c:10:00:03', ip: '10.10.10.202', type: 'wireless', dev: 'dev-ap-lobby', ssid: 'Acme-Corp', sig: -58, rx: 6_420_000_000, tx: 1_180_000_000, status: 'online', blocked: false, site: demoIds.hq, m: 1 },
  { id: 'cl-hq-w04', host: 'lobby-tablet-01', mac: '02:00:0c:10:00:04', ip: '10.10.50.34', type: 'wireless', dev: 'dev-ap-lobby', ssid: 'Acme-IoT', sig: -55, rx: 74_000_000, tx: 18_400_000, status: 'online', blocked: false, site: demoIds.hq, m: 3 },
  { id: 'cl-hq-w05', host: 'eng-lt-114', mac: '02:00:0c:10:00:05', ip: '10.10.10.203', type: 'wireless', dev: 'dev-ap-hq-02', ssid: 'Acme-Corp', sig: -49, rx: 12_840_000_000, tx: 3_260_000_000, status: 'online', blocked: false, site: demoIds.hq, m: 1 },
  { id: 'cl-hq-w06', host: 'eng-lt-118', mac: '02:00:0c:10:00:06', ip: '10.10.10.204', type: 'wireless', dev: 'dev-ap-hq-02', ssid: 'Acme-Corp', sig: -55, rx: 8_120_000_000, tx: 2_040_000_000, status: 'online', blocked: false, site: demoIds.hq, m: 2 },
  { id: 'cl-hq-w07', host: 'sales-lt-072', mac: '02:00:0c:10:00:07', ip: '10.10.10.205', type: 'wireless', dev: 'dev-ap-hq-02', ssid: 'Acme-Corp', sig: -61, rx: 3_480_000_000, tx: 742_000_000, status: 'online', blocked: false, site: demoIds.hq, m: 2 },
  { id: 'cl-hq-w08', host: 'eng-lt-131', mac: '02:00:0c:10:00:08', ip: '10.10.10.206', type: 'wireless', dev: 'dev-ap-hq-03', ssid: 'Acme-Corp', sig: -53, rx: 9_640_000_000, tx: 2_410_000_000, status: 'online', blocked: false, site: demoIds.hq, m: 1 },
  { id: 'cl-hq-w09', host: 'qa-tablet-04', mac: '02:00:0c:10:00:09', ip: '10.10.10.207', type: 'wireless', dev: 'dev-ap-hq-03', ssid: 'Acme-Corp', sig: -64, rx: 1_260_000_000, tx: 284_000_000, status: 'online', blocked: false, site: demoIds.hq, m: 4 },
  { id: 'cl-hq-w10', host: 'sales-lt-081', mac: '02:00:0c:10:00:0a', ip: '10.10.10.208', type: 'wireless', dev: 'dev-ap-hq-04', ssid: 'Acme-Corp', sig: -57, rx: 4_920_000_000, tx: 1_040_000_000, status: 'online', blocked: false, site: demoIds.hq, m: 2 },
  { id: 'cl-hq-w11', host: 'sales-lt-084', mac: '02:00:0c:10:00:0b', ip: '10.10.10.209', type: 'wireless', dev: 'dev-ap-hq-04', ssid: 'Acme-Corp', sig: -70, rx: 2_180_000_000, tx: 512_000_000, status: 'online', blocked: false, site: demoIds.hq, m: 3 },
  { id: 'cl-hq-w12', host: 'fin-lt-014', mac: '02:00:0c:10:00:0c', ip: '10.10.10.210', type: 'wireless', dev: 'dev-ap-hq-05', ssid: 'Acme-Corp', sig: -48, rx: 7_460_000_000, tx: 1_860_000_000, status: 'online', blocked: false, site: demoIds.hq, m: 1 },
  { id: 'cl-hq-w13', host: 'fin-lt-021', mac: '02:00:0c:10:00:0d', ip: '10.10.10.211', type: 'wireless', dev: 'dev-ap-hq-05', ssid: 'Acme-Corp', sig: -59, rx: 5_120_000_000, tx: 1_320_000_000, status: 'online', blocked: false, site: demoIds.hq, m: 2 },
  { id: 'cl-hq-w14', host: 'hr-lt-006', mac: '02:00:0c:10:00:0e', ip: '10.10.10.212', type: 'wireless', dev: 'dev-ap-hq-05', ssid: 'Acme-Corp', sig: -63, rx: 2_940_000_000, tx: 684_000_000, status: 'online', blocked: false, site: demoIds.hq, m: 3 },
  { id: 'cl-hq-w15', host: 'ops-lt-045', mac: '02:00:0c:10:00:0f', ip: '10.10.10.213', type: 'wireless', dev: 'dev-ap-hq-06', ssid: 'Acme-Corp', sig: -51, rx: 6_840_000_000, tx: 1_720_000_000, status: 'online', blocked: false, site: demoIds.hq, m: 1 },
  { id: 'cl-hq-w16', host: 'ops-lt-049', mac: '02:00:0c:10:00:10', ip: '10.10.10.214', type: 'wireless', dev: 'dev-ap-hq-06', ssid: 'Acme-Corp', sig: -67, rx: 3_120_000_000, tx: 802_000_000, status: 'online', blocked: false, site: demoIds.hq, m: 4 },
  { id: 'cl-hq-w17', host: 'mktg-lt-033', mac: '02:00:0c:10:00:11', ip: '10.10.10.215', type: 'wireless', dev: 'dev-ap-hq-07', ssid: 'Acme-Corp', sig: -74, rx: 1_480_000_000, tx: 364_000_000, status: 'online', blocked: false, site: demoIds.hq, m: 5 },
  { id: 'cl-hq-w18', host: 'exec-lt-002', mac: '02:00:0c:10:00:12', ip: '10.10.10.216', type: 'wireless', dev: 'dev-ap-hq-08', ssid: 'Acme-Corp', sig: -44, rx: 10_260_000_000, tx: 2_680_000_000, status: 'online', blocked: false, site: demoIds.hq, m: 1 },
  { id: 'cl-hq-w19', host: 'exec-ipad-01', mac: '02:00:0c:10:00:13', ip: '10.10.10.217', type: 'wireless', dev: 'dev-ap-hq-08', ssid: 'Acme-Corp-6E', sig: -50, rx: 3_840_000_000, tx: 726_000_000, status: 'online', blocked: false, site: demoIds.hq, m: 2 },
  { id: 'cl-hq-w20', host: 'legal-lt-011', mac: '02:00:0c:10:00:14', ip: '10.10.10.218', type: 'wireless', dev: 'dev-ap-hq-09', ssid: 'Acme-Corp', sig: -56, rx: 4_180_000_000, tx: 962_000_000, status: 'online', blocked: false, site: demoIds.hq, m: 2 },
  { id: 'cl-hq-w21', host: 'boardroom-cast', mac: '02:00:0c:10:00:15', ip: '10.10.10.219', type: 'wireless', dev: 'dev-ap-hq-10', ssid: 'Acme-Corp', sig: -47, rx: 18_400_000_000, tx: 640_000_000, status: 'online', blocked: false, site: demoIds.hq, m: 1 },
  { id: 'cl-hq-w22', host: 'guest-lt-201', mac: '02:00:0c:10:00:16', ip: '10.10.20.103', type: 'wireless', dev: 'dev-ap-hq-10', ssid: 'Acme-Guest', sig: -62, rx: 2_260_000_000, tx: 418_000_000, status: 'online', blocked: false, site: demoIds.hq, m: 3 },
  { id: 'cl-hq-w23', host: 'conf-b-cast', mac: '02:00:0c:10:00:17', ip: '10.10.10.220', type: 'wireless', dev: 'dev-ap-hq-11', ssid: 'Acme-Corp', sig: -53, rx: 9_120_000_000, tx: 384_000_000, status: 'online', blocked: false, site: demoIds.hq, m: 2 },
  { id: 'cl-hq-w24', host: 'cafe-tablet-01', mac: '02:00:0c:10:00:18', ip: '10.10.50.31', type: 'wireless', dev: 'dev-ap-hq-12', ssid: 'Acme-IoT', sig: -58, rx: 62_000_000, tx: 14_800_000, status: 'online', blocked: false, site: demoIds.hq, m: 6 },
  { id: 'cl-hq-w25', host: 'staff-phone-14', mac: '02:00:0c:10:00:19', ip: '10.10.10.221', type: 'wireless', dev: 'dev-ap-hq-12', ssid: 'Acme-Corp', sig: -69, rx: 1_820_000_000, tx: 462_000_000, status: 'online', blocked: false, site: demoIds.hq, m: 3 },
  { id: 'cl-hq-w26', host: 'wh-scanner-07', mac: '02:00:0c:10:00:1a', ip: '10.10.50.32', type: 'wireless', dev: 'dev-ap-hq-13', ssid: 'Acme-IoT', sig: -72, rx: 41_000_000, tx: 9_600_000, status: 'online', blocked: false, site: demoIds.hq, m: 5 },
  { id: 'cl-hq-w27', host: 'exec-lt-004', mac: '02:00:0c:10:00:1b', ip: '10.10.10.222', type: 'wireless', dev: 'dev-ap-hq-15', ssid: 'Acme-Corp', sig: -45, rx: 7_840_000_000, tx: 1_940_000_000, status: 'online', blocked: false, site: demoIds.hq, m: 1 },
  { id: 'cl-hq-w28', host: 'exec-lt-006', mac: '02:00:0c:10:00:1c', ip: '10.10.10.223', type: 'wireless', dev: 'dev-ap-hq-16', ssid: 'Acme-Corp-6E', sig: -49, rx: 11_620_000_000, tx: 2_840_000_000, status: 'online', blocked: false, site: demoIds.hq, m: 1 },
  { id: 'cl-hq-w29', host: 'training-cart-01', mac: '02:00:0c:10:00:1d', ip: '10.10.10.224', type: 'wireless', dev: 'dev-ap-hq-17', ssid: 'Acme-Corp', sig: -60, rx: 3_040_000_000, tx: 618_000_000, status: 'online', blocked: false, site: demoIds.hq, m: 4 },
  { id: 'cl-hq-w30', host: 'lobby-signage-02', mac: '02:00:0c:10:00:1e', ip: '10.10.10.225', type: 'wireless', dev: 'dev-ap-hq-18', ssid: 'Acme-Corp', sig: -65, rx: 5_260_000_000, tx: 142_000_000, status: 'online', blocked: false, site: demoIds.hq, m: 2 },
  { id: 'cl-hq-w31', host: 'guest-lt-207', mac: '02:00:0c:10:00:1f', ip: '10.10.20.104', type: 'wireless', dev: 'dev-ap-lobby', ssid: 'Acme-Guest', sig: -78, rx: 184_000_000, tx: 38_000_000, status: 'offline', blocked: true, site: demoIds.hq, m: 182 },
  { id: 'cl-hq-w32', host: null, mac: '02:00:0c:10:00:20', ip: null, type: 'wireless', dev: 'dev-ap-hq-12', ssid: 'Acme-Guest', sig: -81, rx: 4_200_000, tx: 1_100_000, status: 'offline', blocked: true, site: demoIds.hq, m: 418 },
  // HQ · wired
  { id: 'cl-hq-e01', host: 'mdf-console-01', mac: '02:00:0c:10:01:01', ip: '10.10.0.60', type: 'wired', dev: 'dev-sw-core', ssid: null, sig: null, rx: 640_000_000, tx: 218_000_000, status: 'online', blocked: false, site: demoIds.hq, m: 2 },
  { id: 'cl-hq-e02', host: 'reception-printer', mac: '02:00:0c:10:01:02', ip: '10.10.10.70', type: 'wired', dev: 'dev-sw-core', ssid: null, sig: null, rx: 1_240_000_000, tx: 86_000_000, status: 'online', blocked: false, site: demoIds.hq, m: 3 },
  { id: 'cl-hq-e03', host: 'boardroom-display', mac: '02:00:0c:10:01:03', ip: '10.10.10.71', type: 'wired', dev: 'dev-sw-core', ssid: null, sig: null, rx: 24_800_000_000, tx: 412_000_000, status: 'online', blocked: false, site: demoIds.hq, m: 1 },
  { id: 'cl-hq-e04', host: 'frontdesk-ws-01', mac: '02:00:0c:10:01:04', ip: '10.10.10.72', type: 'wired', dev: 'dev-sw-core', ssid: null, sig: null, rx: 9_420_000_000, tx: 2_180_000_000, status: 'online', blocked: false, site: demoIds.hq, m: 1 },
  { id: 'cl-hq-e05', host: 'guest-kiosk-01', mac: '02:00:0c:10:01:05', ip: '10.10.20.60', type: 'wired', dev: 'dev-sw-core', ssid: null, sig: null, rx: 862_000_000, tx: 104_000_000, status: 'online', blocked: false, site: demoIds.hq, m: 4 },
  { id: 'cl-hq-e06', host: 'eng-ws-221', mac: '02:00:0c:10:01:06', ip: '10.10.10.101', type: 'wired', dev: 'dev-sw-hq-idf1-01', ssid: null, sig: null, rx: 42_600_000_000, tx: 12_400_000_000, status: 'online', blocked: false, site: demoIds.hq, m: 1 },
  { id: 'cl-hq-e07', host: 'eng-ws-224', mac: '02:00:0c:10:01:07', ip: '10.10.10.102', type: 'wired', dev: 'dev-sw-hq-idf1-01', ssid: null, sig: null, rx: 38_100_000_000, tx: 10_800_000_000, status: 'online', blocked: false, site: demoIds.hq, m: 1 },
  { id: 'cl-hq-e08', host: 'cad-ws-004', mac: '02:00:0c:10:01:08', ip: '10.10.10.103', type: 'wired', dev: 'dev-sw-hq-idf1-01', ssid: null, sig: null, rx: 61_400_000_000, tx: 18_600_000_000, status: 'online', blocked: false, site: demoIds.hq, m: 2 },
  { id: 'cl-hq-e09', host: 'cad-ws-006', mac: '02:00:0c:10:01:09', ip: '10.10.10.104', type: 'wired', dev: 'dev-sw-hq-idf1-01', ssid: null, sig: null, rx: 57_200_000_000, tx: 16_900_000_000, status: 'online', blocked: false, site: demoIds.hq, m: 2 },
  { id: 'cl-hq-e10', host: 'build-agent-01', mac: '02:00:0c:10:01:0a', ip: '10.10.10.105', type: 'wired', dev: 'dev-sw-hq-idf1-01', ssid: null, sig: null, rx: 128_400_000_000, tx: 84_200_000_000, status: 'online', blocked: false, site: demoIds.hq, m: 1 },
  { id: 'cl-hq-e11', host: 'build-agent-02', mac: '02:00:0c:10:01:0b', ip: '10.10.10.106', type: 'wired', dev: 'dev-sw-hq-idf1-01', ssid: null, sig: null, rx: 119_800_000_000, tx: 78_600_000_000, status: 'online', blocked: false, site: demoIds.hq, m: 1 },
  { id: 'cl-hq-e12', host: 'lab-nuc-03', mac: '02:00:0c:10:01:0c', ip: '10.10.10.107', type: 'wired', dev: 'dev-sw-hq-idf1-01', ssid: null, sig: null, rx: 14_200_000_000, tx: 6_400_000_000, status: 'online', blocked: false, site: demoIds.hq, m: 3 },
  { id: 'cl-hq-e13', host: 'acct-ws-051', mac: '02:00:0c:10:01:0d', ip: '10.10.10.121', type: 'wired', dev: 'dev-sw-hq-idf2-01', ssid: null, sig: null, rx: 21_600_000_000, tx: 5_240_000_000, status: 'online', blocked: false, site: demoIds.hq, m: 2 },
  { id: 'cl-hq-e14', host: 'acct-ws-054', mac: '02:00:0c:10:01:0e', ip: '10.10.10.122', type: 'wired', dev: 'dev-sw-hq-idf2-01', ssid: null, sig: null, rx: 19_400_000_000, tx: 4_880_000_000, status: 'online', blocked: false, site: demoIds.hq, m: 2 },
  { id: 'cl-hq-e15', host: 'support-ws-012', mac: '02:00:0c:10:01:0f', ip: '10.10.10.141', type: 'wired', dev: 'dev-sw-hq-idf3-01', ssid: null, sig: null, rx: 16_800_000_000, tx: 4_120_000_000, status: 'online', blocked: false, site: demoIds.hq, m: 1 },
  { id: 'cl-hq-e16', host: 'support-ws-015', mac: '02:00:0c:10:01:10', ip: '10.10.10.142', type: 'wired', dev: 'dev-sw-hq-idf3-01', ssid: null, sig: null, rx: 15_200_000_000, tx: 3_960_000_000, status: 'online', blocked: false, site: demoIds.hq, m: 3 },
  { id: 'cl-hq-e17', host: 'wh-label-printer', mac: '02:00:0c:10:01:11', ip: '10.10.10.161', type: 'wired', dev: 'dev-sw-hq-wh-01', ssid: null, sig: null, rx: 486_000_000, tx: 42_000_000, status: 'online', blocked: false, site: demoIds.hq, m: 6 },
  { id: 'cl-hq-e18', host: 'lab-bench-ws-01', mac: '02:00:0c:10:01:12', ip: '10.10.10.171', type: 'wired', dev: 'dev-sw-hq-lab-01', ssid: null, sig: null, rx: 33_400_000_000, tx: 11_200_000_000, status: 'online', blocked: false, site: demoIds.hq, m: 4 },
  { id: 'cl-hq-e19', host: 'idf3-ups-mgmt', mac: '02:00:0c:10:01:13', ip: '10.10.0.81', type: 'wired', dev: 'dev-sw-hq-idf3-02', ssid: null, sig: null, rx: 62_000_000, tx: 18_000_000, status: 'offline', blocked: false, site: demoIds.hq, m: 226 },
  // Branch · wireless
  { id: 'cl-br-w01', host: 'br-lt-301', mac: '02:00:0c:30:00:01', ip: '10.30.10.201', type: 'wireless', dev: 'dev-unifi-ap', ssid: 'Acme-Corp', sig: -47, rx: 8_240_000_000, tx: 2_120_000_000, status: 'online', blocked: false, site: demoIds.branch, m: 1 },
  { id: 'cl-br-w02', host: 'br-lt-304', mac: '02:00:0c:30:00:02', ip: '10.30.10.202', type: 'wireless', dev: 'dev-unifi-ap', ssid: 'Acme-Corp', sig: -55, rx: 6_120_000_000, tx: 1_640_000_000, status: 'online', blocked: false, site: demoIds.branch, m: 2 },
  { id: 'cl-br-w03', host: 'br-ipad-02', mac: '02:00:0c:30:00:03', ip: '10.30.10.203', type: 'wireless', dev: 'dev-unifi-ap', ssid: 'Acme-Corp', sig: -62, rx: 2_480_000_000, tx: 542_000_000, status: 'online', blocked: false, site: demoIds.branch, m: 3 },
  { id: 'cl-br-w04', host: 'br-lt-307', mac: '02:00:0c:30:00:04', ip: '10.30.10.204', type: 'wireless', dev: 'dev-ap-br-02', ssid: 'Acme-Corp', sig: -51, rx: 7_320_000_000, tx: 1_880_000_000, status: 'online', blocked: false, site: demoIds.branch, m: 1 },
  { id: 'cl-br-w05', host: 'br-guest-401', mac: '02:00:0c:30:00:05', ip: '10.30.20.51', type: 'wireless', dev: 'dev-ap-br-02', ssid: 'Acme-Guest', sig: -68, rx: 1_140_000_000, tx: 246_000_000, status: 'online', blocked: false, site: demoIds.branch, m: 4 },
  { id: 'cl-br-w06', host: 'br-lt-310', mac: '02:00:0c:30:00:06', ip: '10.30.10.205', type: 'wireless', dev: 'dev-ap-br-03', ssid: 'Acme-Corp', sig: -49, rx: 9_460_000_000, tx: 2_340_000_000, status: 'online', blocked: false, site: demoIds.branch, m: 1 },
  { id: 'cl-br-w07', host: 'br-tablet-05', mac: '02:00:0c:30:00:07', ip: '10.30.10.206', type: 'wireless', dev: 'dev-ap-br-03', ssid: 'Acme-Corp', sig: -64, rx: 1_680_000_000, tx: 384_000_000, status: 'online', blocked: false, site: demoIds.branch, m: 3 },
  { id: 'cl-br-w08', host: 'br-lt-313', mac: '02:00:0c:30:00:08', ip: '10.30.10.207', type: 'wireless', dev: 'dev-ap-br-04', ssid: 'Acme-Corp', sig: -53, rx: 5_840_000_000, tx: 1_420_000_000, status: 'online', blocked: false, site: demoIds.branch, m: 2 },
  { id: 'cl-br-w09', host: 'br-ws-tablet-09', mac: '02:00:0c:30:00:09', ip: '10.30.10.208', type: 'wireless', dev: 'dev-ap-br-04', ssid: 'Acme-Corp', sig: -64, rx: 2_040_000_000, tx: 486_000_000, status: 'online', blocked: false, site: demoIds.branch, m: 4 },
  { id: 'cl-br-w10', host: 'yard-scanner-02', mac: '02:00:0c:30:00:0a', ip: '10.30.10.209', type: 'wireless', dev: 'dev-ap-br-05', ssid: 'Acme-Corp', sig: -71, rx: 108_000_000, tx: 24_000_000, status: 'online', blocked: false, site: demoIds.branch, m: 5 },
  { id: 'cl-br-w11', host: 'br-lt-316', mac: '02:00:0c:30:00:0b', ip: '10.30.10.210', type: 'wireless', dev: 'dev-ap-br-06', ssid: 'Acme-Corp', sig: -66, rx: 3_260_000_000, tx: 742_000_000, status: 'online', blocked: false, site: demoIds.branch, m: 2 },
  { id: 'cl-br-w12', host: 'br-lt-319', mac: '02:00:0c:30:00:0c', ip: '10.30.10.211', type: 'wireless', dev: 'dev-ap-br-07', ssid: 'Acme-Corp', sig: -50, rx: 6_940_000_000, tx: 1_760_000_000, status: 'online', blocked: false, site: demoIds.branch, m: 1 },
  // Branch · wired
  { id: 'cl-br-e01', host: 'br-reception-ws', mac: '02:00:0c:30:01:01', ip: '10.30.10.51', type: 'wired', dev: 'dev-sw-br-01', ssid: null, sig: null, rx: 12_400_000_000, tx: 3_180_000_000, status: 'online', blocked: false, site: demoIds.branch, m: 1 },
  { id: 'cl-br-e02', host: 'br-manager-ws', mac: '02:00:0c:30:01:02', ip: '10.30.10.52', type: 'wired', dev: 'dev-sw-br-01', ssid: null, sig: null, rx: 18_600_000_000, tx: 4_920_000_000, status: 'online', blocked: false, site: demoIds.branch, m: 1 },
  { id: 'cl-br-e03', host: 'br-printer-01', mac: '02:00:0c:30:01:03', ip: '10.30.10.53', type: 'wired', dev: 'dev-sw-br-01', ssid: null, sig: null, rx: 742_000_000, tx: 61_000_000, status: 'online', blocked: false, site: demoIds.branch, m: 5 },
  { id: 'cl-br-e04', host: 'br-ws-402', mac: '02:00:0c:30:01:04', ip: '10.30.10.61', type: 'wired', dev: 'dev-sw-br-02', ssid: null, sig: null, rx: 14_800_000_000, tx: 3_640_000_000, status: 'online', blocked: false, site: demoIds.branch, m: 2 },
  { id: 'cl-br-e05', host: 'br-ws-405', mac: '02:00:0c:30:01:05', ip: '10.30.10.62', type: 'wired', dev: 'dev-sw-br-02', ssid: null, sig: null, rx: 13_200_000_000, tx: 3_280_000_000, status: 'online', blocked: false, site: demoIds.branch, m: 2 },
  { id: 'cl-br-e06', host: 'br-conf-display', mac: '02:00:0c:30:01:06', ip: '10.30.10.71', type: 'wired', dev: 'dev-sw-br-05', ssid: null, sig: null, rx: 8_640_000_000, tx: 184_000_000, status: 'online', blocked: false, site: demoIds.branch, m: 3 },
];

// ── Physical topology · one row per cable ─────────────────────────────────
// Every id below exists in `networkDevices`; mockApi derives edge status from
// the two endpoints, so a link into an offline device renders as down.
export const topologyLinks = [
  { s: 'dev-rtr-hq-edge', t: 'dev-fw-hq', sp: 'sfp-sfpplus1', tp: 'igb0', spd: '10G' },
  { s: 'dev-rtr-hq-edge', t: 'dev-fw-hq-02', sp: 'sfp-sfpplus2', tp: 'igb0', spd: '10G' },
  { s: 'dev-fw-hq', t: 'dev-sw-core', sp: 'igb1', tp: 'Te1/0/25', spd: '10G' },
  { s: 'dev-fw-hq-02', t: 'dev-sw-hq-core-02', sp: 'igb1', tp: 'Te1/0/25', spd: '10G' },
  { s: 'dev-sw-core', t: 'dev-sw-hq-core-02', sp: 'Te1/0/26', tp: 'Te1/0/26', spd: '10G' },
  { s: 'dev-sw-core', t: 'dev-sw-hq-agg-01', sp: 'Te1/0/27', tp: 'Te1/0/1', spd: '10G' },
  { s: 'dev-sw-hq-core-02', t: 'dev-sw-hq-agg-02', sp: 'Te1/0/27', tp: 'Te1/0/1', spd: '10G' },
  { s: 'dev-sw-hq-agg-01', t: 'dev-sw-hq-agg-02', sp: 'Te1/0/7', tp: 'Te1/0/7', spd: '10G' },
  { s: 'dev-sw-hq-agg-01', t: 'dev-sw-hq-idf1-01', sp: 'Te1/0/2', tp: 'Te1/0/25', spd: '10G' },
  { s: 'dev-sw-hq-agg-01', t: 'dev-sw-hq-idf2-01', sp: 'Te1/0/3', tp: 'Te1/0/25', spd: '10G' },
  { s: 'dev-sw-hq-agg-01', t: 'dev-sw-hq-idf3-01', sp: 'Te1/0/4', tp: 'Te1/0/49', spd: '10G' },
  { s: 'dev-sw-hq-agg-01', t: 'dev-sw-hq-wh-01', sp: 'Te1/0/5', tp: 'sfp-sfpplus1', spd: '10G' },
  { s: 'dev-sw-hq-agg-01', t: 'dev-sw-hq-lab-01', sp: 'Te1/0/6', tp: 'sfp-sfpplus1', spd: '10G' },
  { s: 'dev-sw-hq-agg-02', t: 'dev-sw-hq-idf4-01', sp: 'Te1/0/2', tp: 'Te1/0/25', spd: '10G' },
  { s: 'dev-sw-hq-agg-02', t: 'dev-sw-hq-secops-01', sp: 'Te1/0/3', tp: 'Te1/0/9', spd: '10G' },
  { s: 'dev-sw-hq-agg-02', t: 'dev-sw-hq-voice-01', sp: 'Te1/0/4', tp: 'Te1/0/25', spd: '10G' },
  { s: 'dev-sw-hq-agg-02', t: 'dev-sw-hq-idf3-02', sp: 'Te1/0/5', tp: 'Te1/0/25', spd: '10G' },
  { s: 'dev-sw-hq-idf1-01', t: 'dev-sw-hq-idf1-02', sp: 'Te1/0/26', tp: 'SFP1', spd: '10G' },
  { s: 'dev-sw-hq-idf2-01', t: 'dev-sw-hq-idf2-02', sp: 'Te1/0/26', tp: 'Te1/0/9', spd: '10G' },
  { s: 'dev-sw-hq-idf4-01', t: 'dev-sw-hq-idf4-02', sp: 'Te1/0/26', tp: 'SFP1', spd: '10G' },
  { s: 'dev-sw-hq-core-02', t: 'dev-sw-hq-guest-01', sp: 'Gi1/0/24', tp: 'Gi1/0/9', spd: '1G' },
  { s: 'dev-sw-core', t: 'dev-gw-hq-annex', sp: 'Gi1/0/21', tp: 'lan1', spd: '1G' },
  { s: 'dev-gw-hq-annex', t: 'dev-ap-hq-19', sp: 'lan2', tp: 'eth0', spd: '1G' },
  { s: 'dev-sw-core', t: 'dev-ap-lobby', sp: 'Gi1/0/2', tp: 'eth0', spd: '1G' },
  { s: 'dev-sw-core', t: 'dev-ap-hq-10', sp: 'Gi1/0/3', tp: 'eth0', spd: '1G' },
  { s: 'dev-sw-core', t: 'dev-ap-hq-11', sp: 'Gi1/0/4', tp: 'eth0', spd: '1G' },
  { s: 'dev-sw-core', t: 'dev-ap-hq-12', sp: 'Gi1/0/5', tp: 'eth0', spd: '1G' },
  { s: 'dev-sw-core', t: 'dev-ap-hq-17', sp: 'Gi1/0/6', tp: 'eth0', spd: '1G' },
  { s: 'dev-sw-core', t: 'dev-ap-hq-18', sp: 'Gi1/0/7', tp: 'eth0', spd: '1G' },
  { s: 'dev-sw-core', t: 'dev-phone-101', sp: 'Gi1/0/8', tp: 'LAN', spd: '1G' },
  { s: 'dev-sw-core', t: 'cam-front-door', sp: 'Gi1/0/9', tp: 'eth0', spd: '100M' },
  { s: 'dev-sw-hq-idf1-01', t: 'dev-ap-hq-02', sp: 'Gi1/0/1', tp: 'eth0', spd: '1G' },
  { s: 'dev-sw-hq-idf1-01', t: 'dev-ap-hq-03', sp: 'Gi1/0/2', tp: 'eth0', spd: '1G' },
  { s: 'dev-sw-hq-idf1-01', t: 'dev-ap-hq-04', sp: 'Gi1/0/3', tp: 'eth0', spd: '1G' },
  { s: 'dev-sw-hq-idf2-01', t: 'dev-ap-hq-05', sp: 'Gi1/0/1', tp: 'eth0', spd: '1G' },
  { s: 'dev-sw-hq-idf2-01', t: 'dev-ap-hq-06', sp: 'Gi1/0/2', tp: 'eth0', spd: '1G' },
  { s: 'dev-sw-hq-idf2-02', t: 'dev-ap-hq-07', sp: 'Gi1/0/1', tp: 'eth0', spd: '1G' },
  { s: 'dev-sw-hq-idf3-01', t: 'dev-ap-hq-08', sp: 'Gi1/0/1', tp: 'eth0', spd: '1G' },
  { s: 'dev-sw-hq-idf3-01', t: 'dev-ap-hq-09', sp: 'Gi1/0/2', tp: 'eth0', spd: '1G' },
  { s: 'dev-sw-hq-idf4-01', t: 'dev-ap-hq-15', sp: 'Gi1/0/1', tp: 'eth0', spd: '2.5G' },
  { s: 'dev-sw-hq-idf4-01', t: 'dev-ap-hq-16', sp: 'Gi1/0/2', tp: 'eth0', spd: '2.5G' },
  { s: 'dev-sw-hq-wh-01', t: 'dev-ap-hq-13', sp: 'ether5', tp: 'eth0', spd: '1G' },
  { s: 'dev-sw-hq-wh-01', t: 'dev-ap-hq-14', sp: 'ether6', tp: 'eth0', spd: '1G' },
  { s: 'dev-rtr-br-edge', t: 'dev-unifi-gw-branch', sp: 'sfp-sfpplus1', tp: 'Port 9', spd: '10G' },
  { s: 'dev-unifi-gw-branch', t: 'dev-sw-br-01', sp: 'Port 10', tp: 'Port 25', spd: '10G' },
  { s: 'dev-gw-br-lte', t: 'dev-sw-br-01', sp: 'lan1', tp: 'Port 19', spd: '1G' },
  { s: 'dev-sw-br-01', t: 'dev-sw-br-04', sp: 'Port 26', tp: 'Port 1', spd: '10G' },
  { s: 'dev-sw-br-04', t: 'dev-sw-br-02', sp: 'Port 2', tp: 'Port 25', spd: '10G' },
  { s: 'dev-sw-br-04', t: 'dev-sw-br-03', sp: 'Port 3', tp: 'Port 25', spd: '10G' },
  { s: 'dev-sw-br-04', t: 'dev-sw-br-08', sp: 'Port 4', tp: 'sfp-sfpplus1', spd: '10G' },
  { s: 'dev-sw-br-01', t: 'dev-sw-br-05', sp: 'Port 17', tp: 'Port 6', spd: '1G' },
  { s: 'dev-sw-br-01', t: 'dev-sw-br-06', sp: 'Port 18', tp: 'Port 1', spd: '1G' },
  { s: 'dev-sw-br-01', t: 'dev-sw-br-07', sp: 'Port 20', tp: 'ether1', spd: '1G' },
  { s: 'dev-sw-br-01', t: 'dev-unifi-ap', sp: 'Port 1', tp: 'eth0', spd: '1G' },
  { s: 'dev-sw-br-01', t: 'dev-ap-br-02', sp: 'Port 2', tp: 'eth0', spd: '1G' },
  { s: 'dev-sw-br-01', t: 'dev-ap-br-03', sp: 'Port 3', tp: 'eth0', spd: '2.5G' },
  { s: 'dev-sw-br-01', t: 'dev-ap-br-04', sp: 'Port 4', tp: 'eth0', spd: '2.5G' },
  { s: 'dev-sw-br-02', t: 'dev-ap-br-06', sp: 'Port 1', tp: 'eth0', spd: '1G' },
  { s: 'dev-sw-br-05', t: 'dev-ap-br-07', sp: 'Port 1', tp: 'eth0', spd: '1G' },
  { s: 'dev-sw-br-08', t: 'dev-ap-br-05', sp: 'ether1', tp: 'eth0', spd: '1G' },
  { s: 'dev-sw-br-08', t: 'dev-ap-br-08', sp: 'ether2', tp: 'eth0', spd: '1G' },
].map((l) => ({
  source_id: l.s,
  target_id: l.t,
  source_port: l.sp,
  target_port: l.tp,
  speed: l.spd,
}));

// ==== demo fleet: Pending/staged changes (the approval queue) + the Firewall module (gateways, rules, NAT, aliases, IDS/event feed) ====
// ── Firewall + staged-write demo fixtures ───────────────────────────────
//
// The staging chokepoint is what makes FreeSDN different from a vendor
// controller: every device mutation lands in ``adapter_pending_changes``
// and only reaches the device behind an explicit per-request apply. The
// demo has to SHOW that, so these rows carry real diffs, real vendor
// payload keys, real failure text and a history with range.

// Gateway-connection ids (``firewall.gateway_connections``). The OPNsense
// gateway deliberately re-uses the controller id from ``demoIds`` so the
// same box appears both in the controller picker on /gateway/pending and
// as a gateway at /firewall/gateways/:id, exactly as it does in a real
// install where the polymorphic resolver accepts either id shape.
const firewallDemoIds = {
  gwOpnsense: demoIds.opnsense,
  gwPfsense: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
  gwMikrotik: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
};

// ``created_by`` is a user id (AuditMixin), not a display name -- the UI
// never renders it, so the operator's name lives in ``notes`` where the
// Pending Changes table actually shows it.
const firewallDemoActors = {
  priya: '10000000-0000-4000-8000-000000000002', // Priya Raman, network engineer
  marcus: '10000000-0000-4000-8000-000000000003', // Marcus Hale, security admin
  dana: '10000000-0000-4000-8000-000000000004', // Dana Okafor, site operator
};

/**
 * The approval queue.
 *
 * Story: NET-2214 rolls VLAN 60 "IoT" across two vendors -- OPNsense at HQ
 * (L2 + gateway, Kea scope, deny rule, alias widening) and UniFi at Branch
 * (same VLAN 60, 10.30.60.0/24) -- while fences it off and OPS
 * rotates the guest PSK and cuts PoE on a decommissioned camera port.
 *
 * Every field matches ``PendingChangeResponse`` in the generated OpenAPI
 * types; secrets are already masked with the backend's ``***`` sentinel
 * (app/core/redaction.py), which is what a staged payload really looks
 * like once it comes back out of the API.
 */
export const pendingChanges = [
  // ── OPNsense @ HQ, the cross-vendor VLAN push ───────────────────────
  {
    id: 'e0000001-0000-4000-8000-000000000001',
    organization_id: demoIds.org,
    controller_id: firewallDemoIds.gwOpnsense,
    site_id: demoIds.hq,
    omada_site_id: null,
    feature: 'opnsense.interfaces.vlan',
    operation: 'create',
    target_id: null,
    payload: {
      if: 'igc0',
      tag: 60,
      pcp: 0,
      vlanif: 'igc0_vlan60',
      descr: 'IOT_HQ',
      proto: 'staticv4',
      ipaddr: '10.10.60.1',
      subnet: 24,
    },
    status: 'pending',
    applied_at: null,
    applied_response: null,
    failure_reason: null,
    notes: 'Priya Raman - NET-2214 step 1/4: VLAN 60 trunk + gateway on the HQ edge',
    created_by: firewallDemoActors.priya,
    created_at: iso(96),
  },
  {
    id: 'e0000001-0000-4000-8000-000000000002',
    organization_id: demoIds.org,
    controller_id: firewallDemoIds.gwOpnsense,
    site_id: demoIds.hq,
    omada_site_id: null,
    feature: 'opnsense.dhcp.kea_subnet',
    operation: 'create',
    target_id: null,
    payload: {
      subnet: '10.10.60.0/24',
      interface: 'igc0_vlan60',
      pools: ['10.10.60.50-10.10.60.240'],
      option_data: {
        routers: '10.10.60.1',
        domain_name_servers: '10.10.0.1',
        domain_name: 'iot.demo.local',
      },
      valid_lifetime: 7200,
      description: 'IoT HQ',
    },
    status: 'pending',
    applied_at: null,
    applied_response: null,
    failure_reason: null,
    notes: 'Priya Raman - NET-2214 step 2/4: Kea scope for 10.10.60.0/24',
    created_by: firewallDemoActors.priya,
    created_at: iso(94),
  },
  {
    id: 'e0000001-0000-4000-8000-000000000003',
    organization_id: demoIds.org,
    controller_id: firewallDemoIds.gwOpnsense,
    site_id: demoIds.hq,
    omada_site_id: null,
    feature: 'opnsense.firewall.rule',
    operation: 'create',
    target_id: null,
    payload: {
      interface: 'igc0_vlan60',
      action: 'block',
      direction: 'in',
      ipprotocol: 'inet',
      protocol: 'any',
      source_net: '10.10.60.0/24',
      destination_net: 'RFC1918_ALL_SITES',
      quick: true,
      log: true,
      sequence: 20,
      description: 'IoT: no lateral movement into corporate, voice or camera nets',
    },
    status: 'pending',
    applied_at: null,
    applied_response: null,
    failure_reason: null,
    notes: 'Marcus Hale - deny IoT to internal, Internet egress only',
    created_by: firewallDemoActors.marcus,
    created_at: iso(88),
  },
  {
    id: 'e0000001-0000-4000-8000-000000000004',
    organization_id: demoIds.org,
    controller_id: firewallDemoIds.gwOpnsense,
    site_id: demoIds.hq,
    omada_site_id: null,
    feature: 'opnsense.firewall.alias',
    operation: 'update',
    target_id: '9a2f4b18-3c7d-4e51-8b06-c1d9f4a27e30',
    payload: {
      name: 'RFC1918_ALL_SITES',
      type: 'network',
      content: ['10.10.0.0/16', '10.20.0.0/16', '10.30.0.0/16', '172.16.0.0/12', '192.168.0.0/16'],
      description: 'Internal networks, all sites',
      counters: false,
      enabled: '1',
    },
    status: 'pending',
    applied_at: null,
    applied_response: null,
    failure_reason: null,
    notes: 'Marcus Hale - add Branch + DC ranges so the IoT deny is complete',
    created_by: firewallDemoActors.marcus,
    created_at: iso(86),
  },

  // ── UniFi @ Branch, same VLAN, different vendor ─────────────────────
  {
    id: 'e0000002-0000-4000-8000-000000000005',
    organization_id: demoIds.org,
    controller_id: demoIds.unifi,
    site_id: demoIds.branch,
    omada_site_id: 'default',
    feature: 'unifi.networks.create_vlan',
    operation: 'create',
    target_id: null,
    payload: {
      name: 'IoT-Branch',
      purpose: 'corporate',
      // v10 rejects a vlan networkconf without this; the adapter fills it
      // in and the staged payload records what will actually be sent.
      networkgroup: 'LAN',
      vlan_enabled: true,
      vlan: 60,
      ip_subnet: '10.30.60.1/24',
      dhcpd_enabled: true,
      dhcpd_start: '10.30.60.50',
      dhcpd_stop: '10.30.60.240',
      dhcpd_dns_enabled: true,
      dhcpd_dns_1: '10.30.0.1',
      dhcpguard_enabled: true,
      igmp_snooping: false,
    },
    status: 'pending',
    applied_at: null,
    applied_response: null,
    failure_reason: null,
    notes: 'Priya Raman - NET-2214 step 3/4: same VLAN 60 on the Branch UniFi',
    created_by: firewallDemoActors.priya,
    created_at: iso(74),
  },
  {
    id: 'e0000002-0000-4000-8000-000000000006',
    organization_id: demoIds.org,
    controller_id: demoIds.unifi,
    site_id: demoIds.branch,
    omada_site_id: 'default',
    feature: 'unifi.devices.set_port_poe',
    operation: 'update',
    target_id: '02:00:00:00:30:02',
    payload: {
      device_mac: '02:00:00:00:30:02',
      device_name: 'Branch-USW-24-PoE-01',
      port_idx: 14,
      poe_mode: 'off',
      previous_poe_mode: 'auto',
      port_name: 'Lobby cam (decommissioned)',
      reason: 'Camera swapped to the new dome on port 16, patch stays in place',
    },
    status: 'pending',
    applied_at: null,
    applied_response: null,
    failure_reason: null,
    notes: 'Dana Okafor - OPS-903: cut PoE on port 14 after the camera swap',
    created_by: firewallDemoActors.dana,
    created_at: iso(61),
  },
  {
    id: 'e0000002-0000-4000-8000-000000000007',
    organization_id: demoIds.org,
    controller_id: demoIds.unifi,
    site_id: demoIds.branch,
    omada_site_id: 'default',
    feature: 'unifi.wlans.password',
    operation: 'update',
    target_id: '66c1f0a24b7e3f0012ab34cd',
    payload: {
      wlan_id: '66c1f0a24b7e3f0012ab34cd',
      name: 'Acme-Guest',
      security: 'wpapsk',
      wpa_mode: 'wpa2',
      // Staged payloads are read back through redact_secrets(), so the
      // passphrase is already masked before it reaches this drawer.
      x_passphrase: '***',
      rotation_window: '2026-Q3',
    },
    status: 'pending',
    applied_at: null,
    applied_response: null,
    failure_reason: null,
    notes: 'Dana Okafor - OPS-911: quarterly guest PSK rotation, secret redacted in staging',
    created_by: firewallDemoActors.dana,
    created_at: iso(58),
  },
  {
    id: 'e0000002-0000-4000-8000-000000000008',
    organization_id: demoIds.org,
    controller_id: demoIds.unifi,
    site_id: demoIds.branch,
    omada_site_id: 'default',
    feature: 'unifi.networks.delete',
    operation: 'delete',
    target_id: '66b0d3e51f2a4c0011fe22ab',
    payload: {
      network_id: '66b0d3e51f2a4c0011fe22ab',
      name: 'Legacy-Guest-VLAN-90',
      vlan: 90,
      ip_subnet: '10.30.90.1/24',
      clients_attached: 0,
      last_client_seen: '2026-05-19T18:44:00Z',
    },
    status: 'pending',
    applied_at: null,
    applied_response: null,
    failure_reason: null,
    notes: 'Priya Raman - NET-2240: retire the old guest VLAN once IoT is live',
    created_by: firewallDemoActors.priya,
    created_at: iso(22),
  },

  // ── Omada @ HQ, one per aggregated feature domain ───────────────────
  // These are the rows /gateway/pending merges: the five per-domain list
  // endpoints filter on feature prefix (wifi. / profile. / firewall. /
  // vpn. / firmware.), so one of each keeps that page honest and full.
  {
    id: 'e0000003-0000-4000-8000-000000000009',
    organization_id: demoIds.org,
    controller_id: demoIds.omada,
    site_id: demoIds.hq,
    omada_site_id: 'Default',
    feature: 'wifi.ssid.advanced',
    operation: 'update',
    target_id: '6a5f2d1c9b8e470a',
    payload: {
      ssid: 'Acme-Corp',
      wlan_group: 'HQ-Default',
      band_steering: true,
      multicast_to_unicast: true,
      airtime_fairness: true,
      mac_filter_enabled: false,
      rate_limit_profile: 'Corp-50M',
    },
    status: 'pending',
    applied_at: null,
    applied_response: null,
    failure_reason: null,
    notes: 'Priya Raman - NET-2233: band steering on for the HQ corporate SSID',
    created_by: firewallDemoActors.priya,
    created_at: iso(120),
  },
  {
    id: 'e0000003-0000-4000-8000-000000000010',
    organization_id: demoIds.org,
    controller_id: demoIds.omada,
    site_id: demoIds.hq,
    omada_site_id: 'Default',
    feature: 'vpn.ipsec.policy',
    operation: 'create',
    target_id: null,
    payload: {
      name: 'HQ-to-Branch-P2-IoT-exclude',
      ike_policy: 'HQ-to-Branch',
      local_networks: ['10.10.0.0/16'],
      remote_networks: ['10.30.0.0/16'],
      exclude_networks: ['10.10.60.0/24', '10.30.60.0/24'],
      pfs: 'dh14',
      encryption: 'aes256',
      integrity: 'sha256',
      lifetime_seconds: 3600,
    },
    status: 'pending',
    applied_at: null,
    applied_response: null,
    failure_reason: null,
    notes: 'Priya Raman - NET-2214: keep IoT out of the site-to-site selectors',
    created_by: firewallDemoActors.priya,
    created_at: iso(112),
  },
  {
    id: 'e0000003-0000-4000-8000-000000000011',
    organization_id: demoIds.org,
    controller_id: demoIds.omada,
    site_id: demoIds.hq,
    omada_site_id: 'Default',
    feature: 'profile.rate_limit',
    operation: 'create',
    target_id: null,
    payload: {
      name: 'IoT-2M',
      download_limit_kbps: 2048,
      upload_limit_kbps: 1024,
      applies_to: 'IoT-HQ',
      enabled: true,
    },
    status: 'pending',
    applied_at: null,
    applied_response: null,
    failure_reason: null,
    notes: 'Priya Raman - NET-2214 step 4/4: rate-limit profile for IoT clients',
    created_by: firewallDemoActors.priya,
    created_at: iso(70),
  },
  {
    id: 'e0000003-0000-4000-8000-000000000012',
    organization_id: demoIds.org,
    controller_id: demoIds.omada,
    site_id: demoIds.hq,
    omada_site_id: 'Default',
    feature: 'firewall.urlfilter.rule',
    operation: 'create',
    target_id: null,
    payload: {
      name: 'Block IoT vendor telemetry',
      policy: 'deny',
      source_type: 'network',
      source: 'IoT-HQ',
      urls: ['*.iot-telemetry.example', '*.device-analytics.example'],
      schedule: 'Always',
      log: true,
      enabled: true,
    },
    status: 'pending',
    applied_at: null,
    applied_response: null,
    failure_reason: null,
    notes: 'Marcus Hale - IoT telemetry stays inside the segment',
    created_by: firewallDemoActors.marcus,
    created_at: iso(64),
  },
  {
    id: 'e0000003-0000-4000-8000-000000000013',
    organization_id: demoIds.org,
    controller_id: demoIds.omada,
    site_id: demoIds.hq,
    omada_site_id: 'Default',
    feature: 'firmware.upgrade',
    operation: 'create',
    target_id: '02:00:00:00:10:02',
    payload: {
      device_mac: '02:00:00:00:10:02',
      device_name: 'HQ-Lobby-AP-01',
      model: 'EAP670',
      current_version: '1.0.13',
      target_version: '1.0.15',
      apply_window: '2026-06-08T07:00:00Z',
      reboot_required: true,
    },
    status: 'pending',
    applied_at: null,
    applied_response: null,
    failure_reason: null,
    notes: 'Dana Okafor - CHG-0447: EAP670 firmware, applies in the Sunday window',
    created_by: firewallDemoActors.dana,
    created_at: iso(38),
  },

  // ── MikroTik @ Datacenter ───────────────────────────────────────────
  {
    id: 'e0000004-0000-4000-8000-000000000014',
    organization_id: demoIds.org,
    controller_id: firewallDemoIds.gwMikrotik,
    site_id: demoIds.dc,
    omada_site_id: null,
    feature: 'mikrotik.firewall.filter_rule',
    operation: 'create',
    target_id: null,
    payload: {
      chain: 'forward',
      action: 'drop',
      'src-address': '10.20.90.0/24',
      'dst-address': '10.20.0.0/16',
      protocol: 'tcp',
      'dst-port': '445,3389',
      'place-before': '3',
      log: true,
      'log-prefix': 'LAB-BLOCK',
      comment: 'Lab segment must not reach prod over SMB or RDP',
    },
    status: 'pending',
    applied_at: null,
    applied_response: null,
    failure_reason: null,
    notes: 'Marcus Hale - fence the lab VLAN off from production',
    created_by: firewallDemoActors.marcus,
    created_at: iso(46),
  },

  // ── pfSense @ Branch, the catastrophic one (typed APPLY) ────────────
  {
    id: 'e0000005-0000-4000-8000-000000000015',
    organization_id: demoIds.org,
    controller_id: firewallDemoIds.gwPfsense,
    site_id: demoIds.branch,
    omada_site_id: null,
    feature: 'pfsense.system.firmware_update',
    operation: 'create',
    target_id: null,
    payload: {
      current_version: '2.7.2-RELEASE',
      target_version: '2.8.0-RELEASE',
      reboot_required: true,
      config_backup_taken: true,
      maintenance_window: '2026-06-08T06:00:00Z',
      estimated_downtime_minutes: 12,
    },
    status: 'pending',
    applied_at: null,
    applied_response: null,
    failure_reason: null,
    notes: 'Dana Okafor - CHG-0442: Branch edge patch, needs typed APPLY at the window',
    created_by: firewallDemoActors.dana,
    created_at: iso(30),
  },

  // ── History: applied ────────────────────────────────────────────────
  {
    id: 'e0000006-0000-4000-8000-000000000016',
    organization_id: demoIds.org,
    controller_id: demoIds.omada,
    site_id: demoIds.hq,
    omada_site_id: 'Default',
    feature: 'switch.poe_budget',
    operation: 'update',
    target_id: '02:00:00:00:10:01',
    payload: {
      device_mac: '02:00:00:00:10:01',
      device_name: 'HQ-Core-SW-01',
      poe_budget_watts: 384,
      reserved_watts: 40,
      priority_ports: [1, 2, 3, 4],
    },
    status: 'applied',
    applied_at: iso(1002),
    applied_response: { errorCode: 0, msg: 'Success.' },
    failure_reason: null,
    notes: 'Priya Raman - NET-2180: raise the PoE reserve before the AP refresh',
    created_by: firewallDemoActors.priya,
    created_at: iso(1020),
  },
  {
    id: 'e0000006-0000-4000-8000-000000000017',
    organization_id: demoIds.org,
    controller_id: demoIds.omada,
    site_id: demoIds.hq,
    omada_site_id: 'Default',
    feature: 'firewall.port_forward',
    operation: 'create',
    target_id: null,
    payload: {
      name: 'Guest portal callback',
      protocol: 'tcp',
      wan_port: 8443,
      lan_ip: '10.10.20.15',
      lan_port: 8443,
      interface: 'WAN',
      enabled: true,
    },
    status: 'applied',
    applied_at: iso(874),
    applied_response: { errorCode: 0, msg: 'Success.', result: { id: '7fd41a02b6c94e18' } },
    failure_reason: null,
    notes: 'Marcus Hale - publish the captive portal callback',
    created_by: firewallDemoActors.marcus,
    created_at: iso(880),
  },
  {
    id: 'e0000006-0000-4000-8000-000000000018',
    organization_id: demoIds.org,
    controller_id: firewallDemoIds.gwOpnsense,
    site_id: demoIds.hq,
    omada_site_id: null,
    feature: 'opnsense.nat.port_forward',
    operation: 'create',
    target_id: 'b74e1c09-5d2a-4f83-9a11-6e0c73d8ff42',
    payload: {
      interface: 'wan',
      protocol: 'tcp',
      destination_port: '443',
      target: '10.10.20.15',
      local_port: '443',
      natreflection: 'disable',
      log: true,
      description: 'DMZ web front end',
    },
    status: 'applied',
    applied_at: iso(2870),
    applied_response: {
      status: 'ok',
      uuid: 'b74e1c09-5d2a-4f83-9a11-6e0c73d8ff42',
      result: 'saved',
      reload: { status: 'ok', service: 'filter' },
    },
    failure_reason: null,
    notes: 'Marcus Hale - publish the DMZ web front end',
    created_by: firewallDemoActors.marcus,
    created_at: iso(2890),
  },
  {
    id: 'e0000006-0000-4000-8000-000000000019',
    organization_id: demoIds.org,
    controller_id: demoIds.unifi,
    site_id: demoIds.branch,
    omada_site_id: 'default',
    feature: 'unifi.wlans.enable',
    operation: 'update',
    target_id: '66c1f0a24b7e3f0012ab34ce',
    payload: { wlan_id: '66c1f0a24b7e3f0012ab34ce', name: 'Acme-IoT', enabled: true },
    status: 'applied',
    applied_at: iso(430),
    applied_response: { meta: { rc: 'ok' }, data: [] },
    failure_reason: null,
    notes: 'Priya Raman - NET-2214: bring the Branch IoT SSID up before the cutover',
    created_by: firewallDemoActors.priya,
    created_at: iso(440),
  },

  // ── History: failed (the device said no, nothing changed) ───────────
  {
    id: 'e0000007-0000-4000-8000-000000000020',
    organization_id: demoIds.org,
    controller_id: firewallDemoIds.gwMikrotik,
    site_id: demoIds.dc,
    omada_site_id: null,
    feature: 'mikrotik.firewall.nat_rule',
    operation: 'create',
    target_id: null,
    payload: {
      chain: 'srcnat',
      action: 'masquerade',
      'out-interface': 'ether1-wan',
      'src-address': '10.20.90.0/24',
      comment: 'Lab egress',
    },
    status: 'failed',
    applied_at: iso(370),
    applied_response: {
      error: 400,
      message: 'Bad Request',
      detail: 'input does not match any value of interface',
    },
    failure_reason:
      'RouterOS rejected the write: out-interface "ether1-wan" does not exist (interfaces are ether1, ether2, sfp-sfpplus1). Nothing was changed on the device.',
    notes: 'Dana Okafor - OPS-880: lab egress NAT, interface name was wrong',
    created_by: firewallDemoActors.dana,
    created_at: iso(380),
  },
  {
    id: 'e0000007-0000-4000-8000-000000000021',
    organization_id: demoIds.org,
    controller_id: demoIds.omada,
    site_id: demoIds.hq,
    omada_site_id: 'Default',
    feature: 'profile.ppsk',
    operation: 'create',
    target_id: null,
    payload: {
      name: 'Contractors-PPSK',
      ssid: 'Acme-Corp',
      vlan_id: 70,
      key_count: 25,
      expires_at: '2026-09-01T00:00:00Z',
      passphrases: '***',
    },
    status: 'failed',
    applied_at: iso(514),
    applied_response: { errorCode: -33005, msg: 'The VLAN does not exist in this site.' },
    failure_reason:
      'Omada rejected the write: VLAN 70 is not defined on site "Default". Create the VLAN first, then re-stage.',
    notes: 'Dana Okafor - OPS-874: contractor PPSK pool for the Q3 fit-out',
    created_by: firewallDemoActors.dana,
    created_at: iso(520),
  },

  // ── History: discarded in review ────────────────────────────────────
  {
    id: 'e0000008-0000-4000-8000-000000000022',
    organization_id: demoIds.org,
    controller_id: demoIds.omada,
    site_id: demoIds.hq,
    omada_site_id: 'Default',
    feature: 'firewall.urlfilter.rule',
    operation: 'create',
    target_id: null,
    payload: {
      name: 'Block all social',
      policy: 'deny',
      source_type: 'network',
      source: 'Corporate-HQ',
      urls: ['*'],
      schedule: 'Always',
      enabled: true,
    },
    status: 'discarded',
    applied_at: null,
    applied_response: null,
    failure_reason: null,
    notes: 'Marcus Hale - rejected in review: a bare wildcard would also block the vendor support portal',
    created_by: firewallDemoActors.marcus,
    created_at: iso(1660),
  },

  // ── History: stranded, outcome on the device is unknown ─────────────
  {
    id: 'e0000009-0000-4000-8000-000000000023',
    organization_id: demoIds.org,
    controller_id: firewallDemoIds.gwPfsense,
    site_id: demoIds.branch,
    omada_site_id: null,
    feature: 'pfsense.services.restart',
    operation: 'update',
    target_id: 'unbound',
    payload: { service: 'unbound', reason: 'DNS overrides added for the IoT segment' },
    status: 'reconciliation_required',
    applied_at: iso(180),
    applied_response: null,
    failure_reason:
      'The apply worker was lost after the device write and before the terminal commit, so the outcome is unknown. Check Unbound on the Branch edge, then discard with force once verified.',
    notes: 'Dana Okafor - OPS-905: restart Unbound after the DNS override push',
    created_by: firewallDemoActors.dana,
    created_at: iso(186),
  },
];

/**
 * Feature-prefix map for the per-domain ``/changes`` endpoints.
 *
 * Each backend list route filters ``feature_prefix=`` before returning, so
 * the demo has to do the same or one change would show up in five places
 * at once on the aggregated Pending Changes page.
 */
export const pendingChangeDomainPrefixes: Record<string, string[]> = {
  vpn: ['vpn.'],
  firmware: ['firmware.'],
  profiles: ['profile.'],
  firewall: ['firewall.'],
  wifi: ['wifi.'],
  'switch-advanced': ['switch.'],
  routing: ['routing.'],
  hotspot: ['hotspot.'],
  bulk: ['bulk.', 'site.'],
  system: ['system.', 'site.', 'monitoring.'],
  storage: ['storage.'],
};

/** Shared filter for every ``/changes`` route, newest first. */
export const filterPendingChanges = (
  rows: typeof pendingChanges,
  opts: {
    controllerId?: string;
    siteId?: string;
    featurePrefixes?: string[];
    status?: string;
  },
) =>
  rows
    .filter((c) => !opts.controllerId || c.controller_id === opts.controllerId)
    .filter((c) => !opts.siteId || c.site_id === opts.siteId)
    .filter(
      (c) =>
        !opts.featurePrefixes ||
        opts.featurePrefixes.length === 0 ||
        opts.featurePrefixes.some((p) => c.feature.startsWith(p)),
    )
    .filter((c) => !opts.status || opts.status === 'all' || c.status === opts.status)
    .sort((a, b) => b.created_at.localeCompare(a.created_at));

// ── Gateway connections (firewall.gateway_connections) ──────────────────

export const firewallGateways = [
  {
    id: firewallDemoIds.gwOpnsense,
    org_id: demoIds.org,
    site_id: demoIds.hq,
    device_id: 'dev-fw-hq',
    name: 'HQ Edge (OPNsense CARP pair)',
    description: 'Primary HQ perimeter firewall, CARP master with dual WAN',
    vendor: 'opnsense',
    host: '10.10.0.1',
    port: 443,
    verify_ssl: true,
    has_credentials: true,
    sync_enabled: true,
    sync_interval_seconds: 300,
    sync_status: 'success',
    last_sync_at: iso(6),
    last_sync_error: null,
    is_online: true,
    last_seen_at: iso(2),
    detected_version: '24.7.8_1',
    detected_hostname: 'hq-fw-01.demo.local',
    detected_model: 'Deciso DEC850',
    capabilities: [
      'firewall.rules',
      'firewall.aliases',
      'nat.port_forward',
      'nat.source',
      'dhcp.kea',
      'dns.unbound',
      'vpn.wireguard',
      'vpn.ipsec',
      'vpn.openvpn',
      'ids.suricata',
      'shaper',
      'routing.static',
      'ha.carp',
    ],
    settings: { api_flavour: 'core', apply_mode: 'staged', carp_role: 'master' },
    created_at: iso(60 * 24 * 20),
    updated_at: iso(6),
  },
  {
    id: firewallDemoIds.gwPfsense,
    org_id: demoIds.org,
    site_id: demoIds.branch,
    device_id: null,
    name: 'Branch Edge (pfSense)',
    description: 'Branch office edge firewall and IPsec spoke',
    vendor: 'pfsense',
    host: '10.30.0.1',
    port: 443,
    verify_ssl: true,
    has_credentials: true,
    sync_enabled: true,
    sync_interval_seconds: 600,
    sync_status: 'success',
    last_sync_at: iso(11),
    last_sync_error: null,
    is_online: true,
    last_seen_at: iso(3),
    detected_version: '2.7.2-RELEASE',
    detected_hostname: 'branch-fw-01.demo.local',
    detected_model: 'Netgate 4100',
    capabilities: [
      'firewall.rules',
      'firewall.aliases',
      'nat.port_forward',
      'nat.outbound',
      'dhcp.server',
      'dns.resolver',
      'vpn.ipsec',
      'vpn.openvpn',
      'ids.suricata',
      'routing.static',
    ],
    settings: { api_flavour: 'rest-v2', apply_mode: 'staged' },
    created_at: iso(60 * 24 * 16),
    updated_at: iso(11),
  },
  {
    id: firewallDemoIds.gwMikrotik,
    org_id: demoIds.org,
    site_id: demoIds.dc,
    device_id: null,
    name: 'DC Edge (MikroTik CCR)',
    description: 'Datacenter border router, BGP to two transit providers',
    vendor: 'mikrotik',
    host: '10.20.0.1',
    port: 443,
    verify_ssl: false,
    has_credentials: true,
    sync_enabled: true,
    sync_interval_seconds: 300,
    sync_status: 'failed',
    last_sync_at: iso(27),
    last_sync_error:
      'REST login rejected (401): the stored API user is disabled on the router. Re-enable it or rotate the credential, then sync again.',
    is_online: true,
    last_seen_at: iso(9),
    detected_version: 'RouterOS 7.16.2',
    detected_hostname: 'dc-edge-ccr',
    detected_model: 'CCR2004-1G-12S+2XS',
    capabilities: [
      'firewall.filter',
      'firewall.nat',
      'ip.address',
      'ip.pool',
      'dhcp.server',
      'dns.static',
      'queues.simple',
      'routing.static',
      'routing.bgp',
      'vpn.l2tp',
    ],
    settings: { api_flavour: 'rest', apply_mode: 'staged' },
    created_at: iso(60 * 24 * 13),
    updated_at: iso(27),
  },
];

export const firewallGatewaySummary = {
  total_gateways: 3,
  online: 3,
  offline: 0,
  sync_success: 2,
  sync_failed: 1,
  sync_idle: 0,
  sync_never: 0,
  by_vendor: { opnsense: 1, pfsense: 1, mikrotik: 1 },
};

/**
 * Per-gateway live reads, keyed by gateway id then by the URL tail after
 * ``/firewall/gateways/{id}/``. Every consumer on GatewayDetailPage does
 * ``data?.<envelope> ?? []``, so an absent key degrades to an honest empty
 * table rather than a crash -- MikroTik has no Suricata, so it has no
 * ``ids/*`` keys at all.
 */
export const gatewayLiveData: Record<string, Record<string, unknown>> = {
  [firewallDemoIds.gwOpnsense]: {
    status: {
      hostname: 'hq-fw-01.demo.local',
      version: '24.7.8_1',
      uptime: '18 days 04:12:38',
      carp_status: 'MASTER',
      carp_peer_status: 'BACKUP',
      wan_ip: '203.0.113.10',
      gateway_group: 'WAN_FAILOVER',
      states: { current: 18442, limit: 396000 },
      mbuf: { current: 26112, max: 1000000 },
      last_config_change: '2026-06-06T09:14:02Z',
      pending_changes: 4,
    },
    'device-summary': {
      summary: {
        cpu_usage_pct: 11,
        memory_usage_pct: 39,
        disk_usage_pct: 34,
        uptime_text: '18d 4h 12m',
        version: '24.7.8_1',
        wan_ip: '203.0.113.10',
        wan_delay_ms: 9.4,
        wan_loss_pct: 0,
        services_running: 14,
        services_stopped: 2,
        vpn_tunnels_up: 3,
        vpn_tunnels_total: 4,
      },
    },
    firmware: {
      firmware: {
        product: 'OPNsense',
        current_version: '24.7.8_1',
        latest_version: '24.7.9',
        update_available: true,
        needs_update: true,
        release_type: 'business',
        last_check: iso(120),
        packages_pending: 6,
      },
    },
    health: {
      gateways: [
        {
          name: 'WAN_DHCP',
          interface: 'igc0',
          address: '203.0.113.1',
          monitor_ip: '203.0.113.1',
          status: 'none',
          status_text: 'Online',
          delay_ms: 9.4,
          stddev_ms: 1.2,
          loss_pct: 0,
          default_gateway: true,
        },
        {
          name: 'WAN2_LTE',
          interface: 'igc1',
          address: '198.51.100.1',
          monitor_ip: '198.51.100.1',
          status: 'none',
          status_text: 'Online',
          delay_ms: 41.8,
          stddev_ms: 6.7,
          loss_pct: 0.4,
          default_gateway: false,
        },
      ],
    },
    'firewall-rules': {
      rules: [
        {
          uuid: '2b7c1f40-9d3a-4a11-b0e4-51c8a1d7e001',
          sequence: 1,
          action: 'block',
          direction: 'in',
          interface_name: 'wan',
          protocol: 'any',
          source_net: 'BOGON_NETS',
          destination_net: 'any',
          description: 'Drop bogon and reserved source networks',
          enabled: '1',
          log: true,
        },
        {
          uuid: '2b7c1f40-9d3a-4a11-b0e4-51c8a1d7e002',
          sequence: 2,
          action: 'pass',
          direction: 'in',
          interface_name: 'wan',
          protocol: 'udp',
          source_net: 'any',
          destination_net: '203.0.113.10',
          destination_port: '51820',
          description: 'WireGuard remote access',
          enabled: '1',
          log: false,
        },
        {
          uuid: '2b7c1f40-9d3a-4a11-b0e4-51c8a1d7e003',
          sequence: 10,
          action: 'pass',
          direction: 'in',
          interface_name: 'corporate',
          protocol: 'any',
          source_net: '10.10.10.0/24',
          destination_net: 'any',
          gateway: 'WAN_FAILOVER',
          description: 'Corporate to Internet',
          enabled: '1',
          log: false,
        },
        {
          uuid: '2b7c1f40-9d3a-4a11-b0e4-51c8a1d7e004',
          sequence: 11,
          action: 'pass',
          direction: 'in',
          interface_name: 'voice',
          protocol: 'udp',
          source_net: '10.10.30.0/24',
          destination_net: '10.10.0.20',
          destination_port: '5060-5061',
          description: 'Handsets to the PBX',
          enabled: '1',
          log: false,
        },
        {
          uuid: '2b7c1f40-9d3a-4a11-b0e4-51c8a1d7e005',
          sequence: 12,
          action: 'pass',
          direction: 'in',
          interface_name: 'cameras',
          protocol: 'tcp',
          source_net: '10.10.40.0/24',
          destination_net: '10.10.40.10',
          destination_port: '8000',
          description: 'Cameras to the NVR only',
          enabled: '1',
          log: false,
        },
        {
          uuid: '2b7c1f40-9d3a-4a11-b0e4-51c8a1d7e006',
          sequence: 13,
          action: 'block',
          direction: 'in',
          interface_name: 'cameras',
          protocol: 'any',
          source_net: '10.10.40.0/24',
          destination_net: 'any',
          description: 'Cameras never reach the Internet',
          enabled: '1',
          log: true,
        },
        {
          uuid: '2b7c1f40-9d3a-4a11-b0e4-51c8a1d7e007',
          sequence: 20,
          action: 'reject',
          direction: 'in',
          interface_name: 'corporate',
          protocol: 'tcp',
          source_net: 'any',
          destination_net: 'RFC1918_ALL_SITES',
          destination_port: '445',
          description: 'No SMB across VLAN boundaries',
          enabled: '1',
          log: true,
        },
        {
          uuid: '2b7c1f40-9d3a-4a11-b0e4-51c8a1d7e008',
          sequence: 99,
          action: 'block',
          direction: 'in',
          interface_name: 'any',
          protocol: 'any',
          source_net: 'any',
          destination_net: 'any',
          description: 'Default deny, logged',
          enabled: '1',
          log: true,
        },
      ],
    },
    'nat-rules': {
      rules: [
        {
          uuid: '4f81ba32-6c0d-4e77-91a2-8db3c5f9a101',
          type: 'srcnat',
          interface: 'wan',
          protocol: 'any',
          source: '10.10.0.0/16',
          destination: 'any',
          target: '203.0.113.10',
          description: 'HQ outbound NAT to the primary WAN',
        },
        {
          uuid: '4f81ba32-6c0d-4e77-91a2-8db3c5f9a102',
          type: 'srcnat',
          interface: 'wan2',
          protocol: 'any',
          source: '10.10.0.0/16',
          destination: 'any',
          target: '198.51.100.24',
          description: 'HQ outbound NAT over the LTE failover',
        },
        {
          uuid: '4f81ba32-6c0d-4e77-91a2-8db3c5f9a103',
          type: 'srcnat',
          interface: 'ipsec',
          protocol: 'any',
          source: '10.10.99.0/24',
          destination: '10.30.0.0/16',
          target: '10.10.99.1',
          description: 'Management hides behind one address over the tunnel',
        },
      ],
    },
    'port-forwards': {
      port_forwards: [
        {
          uuid: 'b74e1c09-5d2a-4f83-9a11-6e0c73d8ff42',
          interface: 'wan',
          protocol: 'tcp',
          source: 'any',
          dst_port: '443',
          target_ip: '10.10.20.15',
          target_port: '443',
          description: 'DMZ web front end',
          enabled: true,
        },
        {
          uuid: 'b74e1c09-5d2a-4f83-9a11-6e0c73d8ff43',
          interface: 'wan',
          protocol: 'tcp',
          source: 'VPN_VENDOR_NETS',
          dst_port: '3389',
          target_ip: '10.10.20.40',
          target_port: '3389',
          description: 'Vendor jump host, source restricted',
          enabled: false,
        },
        {
          uuid: 'b74e1c09-5d2a-4f83-9a11-6e0c73d8ff44',
          interface: 'wan',
          protocol: 'tcp',
          source: 'any',
          dst_port: '25',
          target_ip: '10.10.20.22',
          target_port: '25',
          description: 'Inbound SMTP relay',
          enabled: true,
        },
        {
          uuid: 'b74e1c09-5d2a-4f83-9a11-6e0c73d8ff45',
          interface: 'wan',
          protocol: 'udp',
          source: 'any',
          dst_port: '51820',
          target_ip: '10.10.0.1',
          target_port: '51820',
          description: 'WireGuard listener',
          enabled: true,
        },
      ],
    },
    aliases: {
      aliases: [
        {
          uuid: '9a2f4b18-3c7d-4e51-8b06-c1d9f4a27e30',
          name: 'RFC1918_ALL_SITES',
          alias_type: 'network',
          content: ['10.10.0.0/16', '10.20.0.0/16', '172.16.0.0/12', '192.168.0.0/16'],
          description: 'Internal networks, all sites (Branch pending)',
          enabled: '1',
        },
        {
          uuid: '9a2f4b18-3c7d-4e51-8b06-c1d9f4a27e31',
          name: 'BOGON_NETS',
          alias_type: 'network',
          content: ['0.0.0.0/8', '127.0.0.0/8', '169.254.0.0/16', '224.0.0.0/4'],
          description: 'Never valid as a WAN source',
          enabled: '1',
        },
        {
          uuid: '9a2f4b18-3c7d-4e51-8b06-c1d9f4a27e32',
          name: 'MGMT_JUMP_HOSTS',
          alias_type: 'host',
          content: ['10.10.99.5', '10.10.99.6'],
          description: 'Only these may reach device management',
          enabled: '1',
        },
        {
          uuid: '9a2f4b18-3c7d-4e51-8b06-c1d9f4a27e33',
          name: 'CAMERA_NVR',
          alias_type: 'host',
          content: ['10.10.40.10'],
          description: 'Hikvision NVR at HQ',
          enabled: '1',
        },
        {
          uuid: '9a2f4b18-3c7d-4e51-8b06-c1d9f4a27e34',
          name: 'VOIP_PORTS',
          alias_type: 'port',
          content: ['5060', '5061', '10000:20000'],
          description: 'SIP signalling and RTP media',
          enabled: '1',
        },
        {
          uuid: '9a2f4b18-3c7d-4e51-8b06-c1d9f4a27e35',
          name: 'VPN_VENDOR_NETS',
          alias_type: 'network',
          content: ['10.99.44.0/24'],
          description: 'Support vendor tunnel, review quarterly',
          enabled: '0',
        },
      ],
    },
    interfaces: {
      interfaces: [
        {
          name: 'WAN',
          identifier: 'wan',
          device: 'igc0',
          status: 'up',
          ipv4_address: '203.0.113.10',
          ipv4_subnet: 24,
          link_type: '1000baseT full-duplex',
          mac_address: '02:00:00:00:10:03',
          mtu: 1500,
        },
        {
          name: 'WAN2_LTE',
          identifier: 'wan2',
          device: 'igc1',
          status: 'up',
          ipv4_address: '198.51.100.24',
          ipv4_subnet: 24,
          link_type: '1000baseT full-duplex',
          mac_address: '02:00:00:00:10:04',
          mtu: 1500,
        },
        {
          name: 'LAN_INFRA',
          identifier: 'lan',
          device: 'igc2',
          status: 'up',
          ipv4_address: '10.10.0.1',
          ipv4_subnet: 24,
          link_type: '10Gbase-SR',
          mac_address: '02:00:00:00:10:05',
          mtu: 9000,
        },
        {
          name: 'CORPORATE',
          identifier: 'corporate',
          device: 'igc2_vlan10',
          parent_interface: 'igc2',
          vlan_id: 10,
          status: 'up',
          ipv4_address: '10.10.10.1',
          ipv4_subnet: 24,
          mtu: 1500,
        },
        {
          name: 'VOICE',
          identifier: 'voice',
          device: 'igc2_vlan30',
          parent_interface: 'igc2',
          vlan_id: 30,
          status: 'up',
          ipv4_address: '10.10.30.1',
          ipv4_subnet: 24,
          mtu: 1500,
        },
        {
          name: 'CAMERAS',
          identifier: 'cameras',
          device: 'igc2_vlan40',
          parent_interface: 'igc2',
          vlan_id: 40,
          status: 'up',
          ipv4_address: '10.10.40.1',
          ipv4_subnet: 24,
          mtu: 1500,
        },
        {
          name: 'DMZ',
          identifier: 'dmz',
          device: 'igc3',
          status: 'up',
          ipv4_address: '10.10.20.1',
          ipv4_subnet: 24,
          link_type: '1000baseT full-duplex',
          mac_address: '02:00:00:00:10:06',
          mtu: 1500,
        },
      ],
    },
    'ids/status': {
      status: {
        running: true,
        ips_mode: true,
        engine: 'Suricata 7.0.6',
        rules_loaded: 41208,
        rules_updated: '2026-06-07T03:12:00Z',
        drops_24h: 214,
      },
    },
    'ids/settings': {
      enabled: true,
      ips_mode: true,
      pattern_matcher: 'hyperscan',
      interfaces: ['wan', 'dmz', 'cameras'],
      promisc: false,
      syslog: true,
      update_cron: '0 3 * * *',
      home_net: ['10.10.0.0/16'],
    },
    'ids/rulesets': [
      {
        name: 'emerging-threats/emerging-exploit.rules',
        description: 'Emerging Threats, exploit attempts',
        enabled: true,
      },
      {
        name: 'emerging-threats/emerging-scan.rules',
        description: 'Emerging Threats, reconnaissance and scanning',
        enabled: true,
      },
      {
        name: 'emerging-threats/emerging-policy.rules',
        description: 'Emerging Threats, policy violations',
        enabled: true,
      },
      {
        name: 'abuse.ch/sslblacklist.rules',
        description: 'abuse.ch SSL blacklist',
        enabled: false,
      },
    ],
    'ids/alerts': {
      alerts: [
        {
          timestamp: iso(7),
          severity: 'high',
          src_ip: '198.51.100.77',
          src_port: 51344,
          dst_ip: '203.0.113.10',
          dst_port: 443,
          proto: 'TCP',
          interface: 'igc0',
          alert: {
            signature: 'ET WEB_SERVER Possible SQL Injection Attempt in URI',
            signature_id: 2006446,
            category: 'web-application-attack',
            action: 'blocked',
          },
        },
        {
          timestamp: iso(23),
          severity: 'medium',
          src_ip: '198.51.100.41',
          src_port: 40122,
          dst_ip: '203.0.113.10',
          dst_port: 22,
          proto: 'TCP',
          interface: 'igc0',
          alert: {
            signature: 'ET SCAN Potential SSH Scan',
            signature_id: 2001219,
            category: 'attempted-recon',
            action: 'allowed',
          },
        },
        {
          timestamp: iso(38),
          severity: 'high',
          src_ip: '198.51.100.203',
          src_port: 33110,
          dst_ip: '10.10.20.15',
          dst_port: 8080,
          proto: 'TCP',
          interface: 'igc3',
          alert: {
            signature: 'ET EXPLOIT Apache log4j RCE Attempt (JNDI LDAP)',
            signature_id: 2034647,
            category: 'attempted-admin',
            action: 'blocked',
          },
        },
        {
          timestamp: iso(64),
          severity: 'low',
          src_ip: '10.10.40.21',
          src_port: 49220,
          dst_ip: '198.51.100.9',
          dst_port: 80,
          proto: 'TCP',
          interface: 'igc2_vlan40',
          alert: {
            signature: 'ET POLICY IoT Device Firmware Check-in over cleartext HTTP',
            signature_id: 2027863,
            category: 'policy-violation',
            action: 'blocked',
          },
        },
        {
          timestamp: iso(96),
          severity: 'medium',
          src_ip: '198.51.100.150',
          src_port: 60011,
          dst_ip: '203.0.113.10',
          dst_port: 3389,
          proto: 'TCP',
          interface: 'igc0',
          alert: {
            signature: 'ET SCAN NMAP -sS window 1024',
            signature_id: 2009582,
            category: 'attempted-recon',
            action: 'blocked',
          },
        },
        {
          timestamp: iso(142),
          severity: 'low',
          src_ip: '10.10.10.88',
          src_port: 51120,
          dst_ip: '198.51.100.60',
          dst_port: 6881,
          proto: 'UDP',
          interface: 'igc2_vlan10',
          alert: {
            signature: 'ET P2P BitTorrent DHT ping request',
            signature_id: 2008581,
            category: 'policy-violation',
            action: 'allowed',
          },
        },
        {
          timestamp: iso(201),
          severity: 'high',
          src_ip: '198.51.100.14',
          src_port: 44300,
          dst_ip: '203.0.113.10',
          dst_port: 443,
          proto: 'TCP',
          interface: 'igc0',
          alert: {
            signature: 'ET MALWARE Suspicious User-Agent (empty)',
            signature_id: 2013028,
            category: 'trojan-activity',
            action: 'blocked',
          },
        },
        {
          timestamp: iso(268),
          severity: 'medium',
          src_ip: '198.51.100.98',
          src_port: 12400,
          dst_ip: '203.0.113.10',
          dst_port: 53,
          proto: 'UDP',
          interface: 'igc0',
          alert: {
            signature: 'ET DNS Query for a Suspicious Dynamic DNS Domain',
            signature_id: 2012811,
            category: 'bad-unknown',
            action: 'allowed',
          },
        },
      ],
    },
    services: {
      services: [
        { name: 'unbound', description: 'Unbound DNS resolver', status: 'running' },
        { name: 'kea-dhcp4', description: 'Kea DHCPv4 server', status: 'running' },
        { name: 'suricata', description: 'Suricata IDS/IPS', status: 'running' },
        { name: 'wireguard', description: 'WireGuard VPN', status: 'running' },
        { name: 'strongswan', description: 'IPsec (strongSwan)', status: 'running' },
        { name: 'openvpn', description: 'OpenVPN remote access', status: 'running' },
        { name: 'ntpd', description: 'NTP server', status: 'running' },
        { name: 'haproxy', description: 'HAProxy load balancer', status: 'stopped' },
        { name: 'squid', description: 'Web proxy', status: 'stopped' },
      ],
    },
    dhcp: {
      leases: [
        {
          address: '10.10.10.44',
          mac: '02:00:00:10:20:01',
          hostname: 'finance-laptop',
          state: 'active',
          expires: iso(-210),
          interface: 'corporate',
        },
        {
          address: '10.10.10.61',
          mac: '02:00:00:10:20:02',
          hostname: 'design-imac',
          state: 'active',
          expires: iso(-96),
          interface: 'corporate',
        },
        {
          address: '10.10.30.101',
          mac: '02:00:00:00:30:65',
          hostname: 'gxp-101',
          state: 'static',
          expires: null,
          interface: 'voice',
        },
        {
          address: '10.10.40.21',
          mac: '02:00:00:00:40:21',
          hostname: 'cam-front-door',
          state: 'static',
          expires: null,
          interface: 'cameras',
        },
        {
          address: '10.10.20.15',
          mac: '02:00:00:00:20:15',
          hostname: 'dmz-web-01',
          state: 'static',
          expires: null,
          interface: 'dmz',
        },
      ],
    },
    'routes/static': {
      routes: [
        {
          uuid: 'c9d0e1f2-1a2b-4c3d-8e4f-5a6b7c8d9e01',
          network: '10.20.0.0/16',
          gateway: 'WG_DC_TUNNEL',
          description: 'Datacenter over WireGuard',
          disabled: '0',
        },
        {
          uuid: 'c9d0e1f2-1a2b-4c3d-8e4f-5a6b7c8d9e02',
          network: '10.30.0.0/16',
          gateway: 'IPSEC_BRANCH',
          description: 'Branch office over IPsec',
          disabled: '0',
        },
        {
          uuid: 'c9d0e1f2-1a2b-4c3d-8e4f-5a6b7c8d9e03',
          network: '10.99.44.0/24',
          gateway: 'IPSEC_VENDOR',
          description: 'Vendor support tunnel, disabled between engagements',
          disabled: '1',
        },
      ],
    },
    arp: {
      arp_entries: [
        { ip: '10.10.0.2', mac: '02:00:00:00:10:01', intf: 'igc2', hostname: 'hq-core-sw-01', type: 'ethernet' },
        { ip: '10.10.12.11', mac: '02:00:00:00:10:02', intf: 'igc2', hostname: 'hq-lobby-ap-01', type: 'ethernet' },
        { ip: '10.10.20.15', mac: '02:00:00:00:20:15', intf: 'igc3', hostname: 'dmz-web-01', type: 'ethernet' },
        { ip: '10.10.40.21', mac: '02:00:00:00:40:21', intf: 'igc2_vlan40', hostname: 'cam-front-door', type: 'ethernet' },
        { ip: '203.0.113.1', mac: '02:00:00:00:99:01', intf: 'igc0', hostname: null, type: 'ethernet' },
      ],
    },
    'logs/firewall': {
      logs: [
        { timestamp: iso(1), process_name: 'filterlog', line: 'block in on igc0: 198.51.100.77.51344 > 203.0.113.10.443: tcp flags [S] (rule 99, default deny)' },
        { timestamp: iso(2), process_name: 'filterlog', line: 'pass in on igc2_vlan10: 10.10.10.44.53122 > 203.0.113.53.443: tcp flags [S] (rule 10)' },
        { timestamp: iso(4), process_name: 'filterlog', line: 'block in on igc2_vlan40: 10.10.40.21.49220 > 198.51.100.9.80: tcp flags [S] (rule 13, cameras offline)' },
        { timestamp: iso(6), process_name: 'filterlog', line: 'reject in on igc2_vlan10: 10.10.10.61.51999 > 10.10.20.40.445: tcp flags [S] (rule 20, no cross-VLAN SMB)' },
        { timestamp: iso(9), process_name: 'filterlog', line: 'pass in on igc2_vlan30: 10.10.30.101.5060 > 10.10.0.20.5060: udp (rule 11)' },
        { timestamp: iso(13), process_name: 'filterlog', line: 'block in on igc0: 198.51.100.150.60011 > 203.0.113.10.3389: tcp flags [S] (rule 99, default deny)' },
        { timestamp: iso(18), process_name: 'filterlog', line: 'pass in on igc0: 198.51.100.201.44121 > 203.0.113.10.51820: udp (rule 2, wireguard)' },
        { timestamp: iso(24), process_name: 'filterlog', line: 'block in on igc0: 169.254.14.9.1024 > 203.0.113.10.80: tcp flags [S] (rule 1, bogon source)' },
      ],
    },
    'sync-logs': [
      {
        id: 'sync-opn-1',
        gateway_id: firewallDemoIds.gwOpnsense,
        started_at: iso(6),
        finished_at: iso(6),
        duration_ms: 2140,
        status: 'success',
        items_synced: 186,
        items_failed: 0,
        details: { rules: 8, aliases: 6, interfaces: 7, leases: 5, ids_alerts: 8 },
      },
      {
        id: 'sync-opn-2',
        gateway_id: firewallDemoIds.gwOpnsense,
        started_at: iso(306),
        finished_at: iso(306),
        duration_ms: 1980,
        status: 'success',
        items_synced: 184,
        items_failed: 0,
        details: { rules: 8, aliases: 6, interfaces: 7 },
      },
      {
        id: 'sync-opn-3',
        gateway_id: firewallDemoIds.gwOpnsense,
        started_at: iso(606),
        finished_at: iso(606),
        duration_ms: 8402,
        status: 'partial',
        error: 'Suricata alert log read timed out after 8s, other collections synced',
        items_synced: 178,
        items_failed: 1,
        details: { rules: 8, aliases: 6, ids_alerts: 0 },
      },
    ],
  },

  [firewallDemoIds.gwPfsense]: {
    status: {
      hostname: 'branch-fw-01.demo.local',
      version: '2.7.2-RELEASE',
      uptime: '46 days 11:02:07',
      wan_ip: '198.51.100.20',
      states: { current: 4127, limit: 198000 },
      last_config_change: '2026-06-05T16:41:19Z',
      pending_changes: 2,
    },
    'device-summary': {
      summary: {
        cpu_usage_pct: 7,
        memory_usage_pct: 28,
        disk_usage_pct: 19,
        uptime_text: '46d 11h 2m',
        version: '2.7.2-RELEASE',
        wan_ip: '198.51.100.20',
        wan_delay_ms: 16.2,
        wan_loss_pct: 0,
        services_running: 9,
        services_stopped: 1,
        vpn_tunnels_up: 1,
        vpn_tunnels_total: 1,
      },
    },
    firmware: {
      firmware: {
        product: 'pfSense CE',
        current_version: '2.7.2-RELEASE',
        latest_version: '2.8.0-RELEASE',
        update_available: true,
        needs_update: true,
        last_check: iso(60),
      },
    },
    health: {
      gateways: [
        {
          name: 'WANGW',
          interface: 'igb0',
          address: '198.51.100.1',
          monitor_ip: '198.51.100.1',
          status: 'none',
          status_text: 'Online',
          delay_ms: 16.2,
          stddev_ms: 2.9,
          loss_pct: 0,
          default_gateway: true,
        },
      ],
    },
    'firewall-rules': {
      rules: [
        {
          uuid: 'pf-rule-0001',
          sequence: 1,
          action: 'pass',
          direction: 'in',
          interface_name: 'lan',
          protocol: 'any',
          source_net: '10.30.10.0/24',
          destination_net: 'any',
          description: 'Branch users to Internet and HQ',
          enabled: '1',
          log: false,
        },
        {
          uuid: 'pf-rule-0002',
          sequence: 2,
          action: 'pass',
          direction: 'in',
          interface_name: 'lan',
          protocol: 'any',
          source_net: '10.30.10.0/24',
          destination_net: '10.10.0.0/16',
          description: 'Branch to HQ over IPsec',
          enabled: '1',
          log: false,
        },
        {
          uuid: 'pf-rule-0003',
          sequence: 10,
          action: 'block',
          direction: 'in',
          interface_name: 'guest',
          protocol: 'any',
          source_net: '10.30.50.0/24',
          destination_net: 'PRIVATE_NETS',
          description: 'Guest cannot reach anything internal',
          enabled: '1',
          log: true,
        },
        {
          uuid: 'pf-rule-0004',
          sequence: 99,
          action: 'block',
          direction: 'in',
          interface_name: 'any',
          protocol: 'any',
          source_net: 'any',
          destination_net: 'any',
          description: 'Default deny, logged',
          enabled: '1',
          log: true,
        },
      ],
    },
    'nat-rules': {
      rules: [
        {
          uuid: 'pf-nat-0001',
          type: 'srcnat',
          interface: 'wan',
          protocol: 'any',
          source: '10.30.0.0/16',
          destination: 'any',
          target: '198.51.100.20',
          description: 'Branch outbound NAT',
        },
      ],
    },
    'port-forwards': {
      port_forwards: [
        {
          uuid: 'pf-fwd-0001',
          interface: 'wan',
          protocol: 'udp',
          source: 'any',
          dst_port: '1194',
          target_ip: '10.30.0.1',
          target_port: '1194',
          description: 'OpenVPN remote access',
          enabled: true,
        },
      ],
    },
    aliases: {
      aliases: [
        {
          uuid: 'pf-alias-0001',
          name: 'PRIVATE_NETS',
          alias_type: 'network',
          content: ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'],
          description: 'All RFC1918 space',
          enabled: '1',
        },
        {
          uuid: 'pf-alias-0002',
          name: 'BRANCH_PRINTERS',
          alias_type: 'host',
          content: ['10.30.10.240', '10.30.10.241'],
          description: 'Branch MFPs',
          enabled: '1',
        },
        {
          uuid: 'pf-alias-0003',
          name: 'HQ_SERVICES',
          alias_type: 'network',
          content: ['10.10.0.0/24', '10.10.20.0/24'],
          description: 'HQ infrastructure and DMZ',
          enabled: '1',
        },
      ],
    },
    interfaces: {
      interfaces: [
        {
          name: 'WAN',
          identifier: 'wan',
          device: 'igb0',
          status: 'up',
          ipv4_address: '198.51.100.20',
          ipv4_subnet: 24,
          mac_address: '02:00:00:00:30:01',
          mtu: 1500,
        },
        {
          name: 'LAN',
          identifier: 'lan',
          device: 'igb1',
          status: 'up',
          ipv4_address: '10.30.0.1',
          ipv4_subnet: 24,
          mac_address: '02:00:00:00:30:03',
          mtu: 1500,
        },
        {
          name: 'USERS',
          identifier: 'users',
          device: 'igb1_vlan10',
          parent_interface: 'igb1',
          vlan_id: 10,
          status: 'up',
          ipv4_address: '10.30.10.1',
          ipv4_subnet: 24,
          mtu: 1500,
        },
        {
          name: 'GUEST',
          identifier: 'guest',
          device: 'igb1_vlan50',
          parent_interface: 'igb1',
          vlan_id: 50,
          status: 'up',
          ipv4_address: '10.30.50.1',
          ipv4_subnet: 24,
          mtu: 1500,
        },
      ],
    },
    'ids/status': {
      status: {
        running: true,
        ips_mode: false,
        engine: 'Suricata 7.0.6',
        rules_loaded: 28940,
        rules_updated: '2026-06-07T03:20:00Z',
        drops_24h: 0,
      },
    },
    'ids/settings': {
      enabled: true,
      ips_mode: false,
      pattern_matcher: 'ac',
      interfaces: ['wan'],
      promisc: false,
      syslog: true,
      update_cron: '20 3 * * *',
      home_net: ['10.30.0.0/16'],
    },
    'ids/alerts': {
      alerts: [
        {
          timestamp: iso(52),
          severity: 'medium',
          src_ip: '198.51.100.66',
          src_port: 39221,
          dst_ip: '198.51.100.20',
          dst_port: 1194,
          proto: 'UDP',
          interface: 'igb0',
          alert: {
            signature: 'ET SCAN Potential OpenVPN Enumeration',
            signature_id: 2027759,
            category: 'attempted-recon',
            action: 'allowed',
          },
        },
        {
          timestamp: iso(180),
          severity: 'low',
          src_ip: '10.30.50.31',
          src_port: 55010,
          dst_ip: '198.51.100.9',
          dst_port: 123,
          proto: 'UDP',
          interface: 'igb1_vlan50',
          alert: {
            signature: 'ET POLICY External NTP Server Use',
            signature_id: 2014169,
            category: 'policy-violation',
            action: 'allowed',
          },
        },
        {
          timestamp: iso(410),
          severity: 'medium',
          src_ip: '198.51.100.180',
          src_port: 41002,
          dst_ip: '198.51.100.20',
          dst_port: 443,
          proto: 'TCP',
          interface: 'igb0',
          alert: {
            signature: 'ET WEB_SERVER Possible Path Traversal Attempt',
            signature_id: 2016184,
            category: 'web-application-attack',
            action: 'allowed',
          },
        },
      ],
    },
    services: {
      services: [
        { name: 'unbound', description: 'DNS Resolver', status: 'running' },
        { name: 'dhcpd', description: 'DHCP Service', status: 'running' },
        { name: 'suricata', description: 'Suricata IDS', status: 'running' },
        { name: 'openvpn', description: 'OpenVPN server', status: 'running' },
        { name: 'strongswan', description: 'IPsec to HQ', status: 'running' },
        { name: 'ntpd', description: 'NTP clock sync', status: 'stopped' },
      ],
    },
    'sync-logs': [
      {
        id: 'sync-pf-1',
        gateway_id: firewallDemoIds.gwPfsense,
        started_at: iso(11),
        finished_at: iso(11),
        duration_ms: 1620,
        status: 'success',
        items_synced: 74,
        items_failed: 0,
        details: { rules: 4, aliases: 3, interfaces: 4 },
      },
      {
        id: 'sync-pf-2',
        gateway_id: firewallDemoIds.gwPfsense,
        started_at: iso(611),
        finished_at: iso(611),
        duration_ms: 1704,
        status: 'success',
        items_synced: 74,
        items_failed: 0,
        details: { rules: 4, aliases: 3, interfaces: 4 },
      },
    ],
  },

  [firewallDemoIds.gwMikrotik]: {
    status: {
      identity: 'dc-edge-ccr',
      version: '7.16.2',
      board_name: 'CCR2004-1G-12S+2XS',
      uptime: '9w2d05:14:22',
      cpu_load: 6,
      free_memory: 3_120_000_000,
      total_memory: 4_294_967_296,
      bgp_sessions_established: 2,
    },
    'device-summary': {
      summary: {
        cpu_usage_pct: 6,
        memory_usage_pct: 27,
        disk_usage_pct: 12,
        uptime_text: '65d 5h 14m',
        version: '7.16.2',
        wan_ip: '203.0.113.66',
        wan_delay_ms: 1.8,
        wan_loss_pct: 0,
        services_running: 6,
        services_stopped: 3,
        vpn_tunnels_up: 1,
        vpn_tunnels_total: 2,
      },
    },
    firmware: {
      firmware: {
        product: 'RouterOS',
        current_version: '7.16.2',
        latest_version: '7.17',
        update_available: true,
        needs_update: true,
        channel: 'stable',
        last_check: iso(240),
      },
    },
    'firewall-rules': {
      rules: [
        {
          id: '*1',
          sequence: 0,
          chain: 'forward',
          action: 'accept',
          protocol: 'any',
          source_net: '10.20.0.0/16',
          destination_net: 'any',
          description: 'Datacenter egress',
          enabled: '1',
          log: false,
        },
        {
          id: '*2',
          sequence: 1,
          chain: 'input',
          action: 'drop',
          protocol: 'tcp',
          source_net: '!10.20.99.0/24',
          destination_net: 'any',
          destination_port: '8728,8291,443',
          description: 'Management only from the DC jump network',
          enabled: '1',
          log: true,
        },
        {
          id: '*3',
          sequence: 2,
          chain: 'forward',
          action: 'drop',
          protocol: 'any',
          source_net: 'any',
          destination_net: 'any',
          description: 'Default drop',
          enabled: '1',
          log: true,
        },
      ],
    },
    'nat-rules': {
      rules: [
        {
          id: '*5',
          type: 'srcnat',
          chain: 'srcnat',
          protocol: 'any',
          src_address: '10.20.0.0/16',
          dst_address: 'any',
          to_addresses: '203.0.113.66',
          interface: 'sfp-sfpplus1',
          comment: 'Datacenter outbound NAT',
        },
      ],
    },
    interfaces: {
      interfaces: [
        {
          name: 'sfp-sfpplus1',
          status: 'up',
          ipv4_address: '203.0.113.66',
          ipv4_subnet: 30,
          link_type: '10G-SR',
          mac_address: '02:00:00:00:20:02',
          mtu: 1500,
        },
        {
          name: 'sfp-sfpplus2',
          status: 'up',
          ipv4_address: '198.51.100.66',
          ipv4_subnet: 30,
          link_type: '10G-SR',
          mac_address: '02:00:00:00:20:03',
          mtu: 1500,
        },
        {
          name: 'ether1',
          status: 'up',
          ipv4_address: '10.20.0.1',
          ipv4_subnet: 24,
          link_type: '1G-baseT',
          mac_address: '02:00:00:00:20:04',
          mtu: 1500,
        },
        {
          name: 'ether2',
          status: 'down',
          link_type: '1G-baseT',
          mac_address: '02:00:00:00:20:05',
          mtu: 1500,
        },
      ],
    },
    services: {
      services: [
        { name: 'api-ssl', description: 'REST/API over TLS', status: 'running' },
        { name: 'winbox', description: 'Winbox management', status: 'running' },
        { name: 'ssh', description: 'SSH', status: 'running' },
        { name: 'bgp', description: 'BGP routing', status: 'running' },
        { name: 'telnet', description: 'Telnet', status: 'stopped' },
        { name: 'ftp', description: 'FTP', status: 'stopped' },
      ],
    },
    'sync-logs': [
      {
        id: 'sync-mt-1',
        gateway_id: firewallDemoIds.gwMikrotik,
        started_at: iso(27),
        finished_at: iso(27),
        duration_ms: 640,
        status: 'failed',
        error: 'REST login rejected (401): the stored API user is disabled on the router',
        items_synced: 0,
        items_failed: 1,
        details: {},
      },
      {
        id: 'sync-mt-2',
        gateway_id: firewallDemoIds.gwMikrotik,
        started_at: iso(327),
        finished_at: iso(327),
        duration_ms: 1180,
        status: 'success',
        items_synced: 41,
        items_failed: 0,
        details: { rules: 3, nat: 1, interfaces: 4 },
      },
    ],
  },
};

// ── Firewall module, normalized local-DB records (/firewall/*) ──────────

export const firewallRules = [
  { id: 'fwr-0001', site_id: demoIds.hq, device_id: 'dev-fw-hq', name: 'Corporate to Internet', rule_order: 10, source_address: '10.10.10.0/24', source_port: null, dest_address: 'any', dest_port: null, source_zone: 'corporate', dest_zone: 'wan', protocol: 'any', action: 'allow', is_enabled: true, hit_count: 4_812_904, log_enabled: false, description: 'General user egress', created_at: iso(60 * 24 * 18), updated_at: iso(60 * 24 * 4) },
  { id: 'fwr-0002', site_id: demoIds.hq, device_id: 'dev-fw-hq', name: 'Handsets to PBX', rule_order: 11, source_address: '10.10.30.0/24', source_port: null, dest_address: '10.10.0.20', dest_port: '5060-5061', source_zone: 'voice', dest_zone: 'lan', protocol: 'udp', action: 'allow', is_enabled: true, hit_count: 1_204_338, log_enabled: false, description: 'SIP signalling to FreePBX', created_at: iso(60 * 24 * 18), updated_at: iso(60 * 24 * 9) },
  { id: 'fwr-0003', site_id: demoIds.hq, device_id: 'dev-fw-hq', name: 'Cameras to NVR only', rule_order: 12, source_address: '10.10.40.0/24', source_port: null, dest_address: '10.10.40.10', dest_port: '8000', source_zone: 'cameras', dest_zone: 'cameras', protocol: 'tcp', action: 'allow', is_enabled: true, hit_count: 883_401, log_enabled: false, description: 'Hikvision streams stay on the camera VLAN', created_at: iso(60 * 24 * 17), updated_at: iso(60 * 24 * 6) },
  { id: 'fwr-0004', site_id: demoIds.hq, device_id: 'dev-fw-hq', name: 'Cameras never reach Internet', rule_order: 13, source_address: '10.10.40.0/24', source_port: null, dest_address: 'any', dest_port: null, source_zone: 'cameras', dest_zone: 'wan', protocol: 'any', action: 'deny', is_enabled: true, hit_count: 24_119, log_enabled: true, description: 'Blocks vendor cloud check-in', created_at: iso(60 * 24 * 17), updated_at: iso(60 * 24 * 6) },
  { id: 'fwr-0005', site_id: demoIds.hq, device_id: 'dev-fw-hq', name: 'Management from jump hosts', rule_order: 14, source_address: '10.10.99.0/24', source_port: null, dest_address: '10.10.0.0/16', dest_port: '22,443', source_zone: 'mgmt', dest_zone: 'lan', protocol: 'tcp', action: 'allow', is_enabled: true, hit_count: 61_204, log_enabled: true, description: 'Only the two jump hosts administer devices', created_at: iso(60 * 24 * 16), updated_at: iso(60 * 24 * 2) },
  { id: 'fwr-0006', site_id: demoIds.hq, device_id: 'dev-fw-hq', name: 'No SMB across VLANs', rule_order: 20, source_address: 'any', source_port: null, dest_address: '10.10.0.0/16', dest_port: '445', source_zone: 'any', dest_zone: 'lan', protocol: 'tcp', action: 'reject', is_enabled: true, hit_count: 3_842, log_enabled: true, description: 'Lateral-movement control', created_at: iso(60 * 24 * 15), updated_at: iso(60 * 24 * 5) },
  { id: 'fwr-0007', site_id: demoIds.hq, device_id: 'dev-fw-hq', name: 'Guest to Internet only', rule_order: 30, source_address: '10.10.80.0/24', source_port: null, dest_address: 'any', dest_port: null, source_zone: 'guest', dest_zone: 'wan', protocol: 'any', action: 'allow', is_enabled: true, hit_count: 522_110, log_enabled: false, description: 'Paired with the RFC1918 deny below', created_at: iso(60 * 24 * 15), updated_at: iso(60 * 24 * 5) },
  { id: 'fwr-0008', site_id: demoIds.hq, device_id: 'dev-fw-hq', name: 'Default deny (logged)', rule_order: 99, source_address: 'any', source_port: null, dest_address: 'any', dest_port: null, source_zone: 'any', dest_zone: 'any', protocol: 'any', action: 'deny', is_enabled: true, hit_count: 918_640, log_enabled: true, description: 'Catch-all at the bottom of the chain', created_at: iso(60 * 24 * 20), updated_at: iso(60 * 24 * 20) },
  { id: 'fwr-0009', site_id: demoIds.branch, device_id: 'dev-fw-branch', name: 'Branch users to HQ', rule_order: 10, source_address: '10.30.10.0/24', source_port: null, dest_address: '10.10.0.0/16', dest_port: null, source_zone: 'users', dest_zone: 'ipsec', protocol: 'any', action: 'allow', is_enabled: true, hit_count: 1_640_922, log_enabled: false, description: 'Over the site-to-site tunnel', created_at: iso(60 * 24 * 14), updated_at: iso(60 * 24 * 3) },
  { id: 'fwr-0010', site_id: demoIds.branch, device_id: 'dev-fw-branch', name: 'Guest cannot reach internal', rule_order: 11, source_address: '10.30.50.0/24', source_port: null, dest_address: '10.0.0.0/8', dest_port: null, source_zone: 'guest', dest_zone: 'any', protocol: 'any', action: 'deny', is_enabled: true, hit_count: 12_744, log_enabled: true, description: 'Guest VLAN isolation', created_at: iso(60 * 24 * 14), updated_at: iso(60 * 24 * 3) },
  { id: 'fwr-0011', site_id: demoIds.dc, device_id: 'dev-fw-dc', name: 'Lab to production (staged deny)', rule_order: 12, source_address: '10.20.90.0/24', source_port: null, dest_address: '10.20.0.0/16', dest_port: '445,3389', source_zone: 'lab', dest_zone: 'prod', protocol: 'tcp', action: 'deny', is_enabled: false, hit_count: 0, log_enabled: true, description: 'Awaiting approval as a staged MikroTik change', created_at: iso(46), updated_at: iso(46) },
];

export const firewallNatRules = [
  { id: 'nat-0001', site_id: demoIds.hq, device_id: 'dev-fw-hq', name: 'HQ outbound', nat_type: 'masquerade', original_address: '10.10.0.0/16', original_port: null, translated_address: '203.0.113.10', translated_port: null, protocol: 'any', interface: 'wan', is_enabled: true, description: 'Primary WAN egress', created_at: iso(60 * 24 * 20) },
  { id: 'nat-0002', site_id: demoIds.hq, device_id: 'dev-fw-hq', name: 'DMZ web front end', nat_type: 'dnat', original_address: '203.0.113.10', original_port: '443', translated_address: '10.10.20.15', translated_port: '443', protocol: 'tcp', interface: 'wan', is_enabled: true, description: 'Published HTTPS service', created_at: iso(2890) },
  { id: 'nat-0003', site_id: demoIds.hq, device_id: 'dev-fw-hq', name: 'Inbound SMTP relay', nat_type: 'dnat', original_address: '203.0.113.10', original_port: '25', translated_address: '10.10.20.22', translated_port: '25', protocol: 'tcp', interface: 'wan', is_enabled: true, description: 'Mail gateway', created_at: iso(60 * 24 * 12) },
  { id: 'nat-0004', site_id: demoIds.hq, device_id: 'dev-fw-hq', name: 'Vendor RDP jump', nat_type: 'dnat', original_address: '203.0.113.10', original_port: '3389', translated_address: '10.10.20.40', translated_port: '3389', protocol: 'tcp', interface: 'wan', is_enabled: false, description: 'Enabled only during a support engagement', created_at: iso(60 * 24 * 8) },
  { id: 'nat-0005', site_id: demoIds.branch, device_id: 'dev-fw-branch', name: 'Branch outbound', nat_type: 'masquerade', original_address: '10.30.0.0/16', original_port: null, translated_address: '198.51.100.20', translated_port: null, protocol: 'any', interface: 'wan', is_enabled: true, description: 'Branch WAN egress', created_at: iso(60 * 24 * 16) },
  { id: 'nat-0006', site_id: demoIds.dc, device_id: 'dev-fw-dc', name: 'Datacenter outbound', nat_type: 'snat', original_address: '10.20.0.0/16', original_port: null, translated_address: '203.0.113.66', translated_port: null, protocol: 'any', interface: 'sfp-sfpplus1', is_enabled: true, description: 'Transit A egress', created_at: iso(60 * 24 * 13) },
];

export const firewallVpnTunnels = [
  { id: 'vpn-0001', site_id: demoIds.hq, device_id: 'dev-fw-hq', name: 'HQ to Branch', vpn_type: 'ipsec', status: 'up', local_address: '203.0.113.10', local_subnets: ['10.10.0.0/16'], remote_address: '198.51.100.20', remote_subnets: ['10.30.0.0/16'], auth_type: 'psk', bytes_in: 482_119_884_012, bytes_out: 311_774_002_918, last_connected: iso(4320), is_enabled: true, description: 'Site-to-site, IKEv2 / AES-256 / SHA-256', created_at: iso(60 * 24 * 16) },
  { id: 'vpn-0002', site_id: demoIds.hq, device_id: 'dev-fw-hq', name: 'HQ to Datacenter', vpn_type: 'wireguard', status: 'up', local_address: '203.0.113.10', local_subnets: ['10.10.0.0/16'], remote_address: '203.0.113.66', remote_subnets: ['10.20.0.0/16'], auth_type: 'pubkey', bytes_in: 1_902_441_006_733, bytes_out: 1_144_820_119_004, last_connected: iso(11_520), is_enabled: true, description: 'Backup replication and hypervisor management', created_at: iso(60 * 24 * 13) },
  { id: 'vpn-0003', site_id: demoIds.hq, device_id: 'dev-fw-hq', name: 'Remote access (OpenVPN)', vpn_type: 'openvpn', status: 'up', local_address: '203.0.113.10', local_subnets: ['10.10.0.0/16'], remote_subnets: ['10.10.200.0/24'], auth_type: 'cert+mfa', bytes_in: 40_118_776_221, bytes_out: 88_902_114_558, last_connected: iso(12), is_enabled: true, description: '9 of 40 seats connected', created_at: iso(60 * 24 * 19) },
  { id: 'vpn-0004', site_id: demoIds.hq, device_id: 'dev-fw-hq', name: 'Vendor support tunnel', vpn_type: 'ipsec', status: 'down', local_address: '203.0.113.10', local_subnets: ['10.10.99.0/24'], remote_address: '198.51.100.44', remote_subnets: ['10.99.44.0/24'], auth_type: 'psk', bytes_in: 0, bytes_out: 0, last_connected: iso(60 * 24 * 7), is_enabled: false, description: 'Brought up only for an approved engagement', created_at: iso(60 * 24 * 11) },
];

export const firewallVpnStats = { total: 4, up: 3, down: 1, error: 0, connecting: 0 };

export const firewallIdsAlerts = [
  { id: 'ids-0001', site_id: demoIds.hq, device_id: 'dev-fw-hq', signature_id: '2034647', signature_name: 'ET EXPLOIT Apache log4j RCE Attempt (JNDI LDAP)', category: 'attempted-admin', severity: 'critical', source_ip: '198.51.100.203', dest_ip: '10.10.20.15', source_port: 33110, dest_port: 8080, protocol: 'tcp', action_taken: 'blocked', timestamp: iso(38), is_acknowledged: false },
  { id: 'ids-0002', site_id: demoIds.hq, device_id: 'dev-fw-hq', signature_id: '2006446', signature_name: 'ET WEB_SERVER Possible SQL Injection Attempt in URI', category: 'web-application-attack', severity: 'high', source_ip: '198.51.100.77', dest_ip: '203.0.113.10', source_port: 51344, dest_port: 443, protocol: 'tcp', action_taken: 'blocked', timestamp: iso(7), is_acknowledged: false },
  { id: 'ids-0003', site_id: demoIds.hq, device_id: 'dev-fw-hq', signature_id: '2013028', signature_name: 'ET MALWARE Suspicious User-Agent (empty)', category: 'trojan-activity', severity: 'high', source_ip: '198.51.100.14', dest_ip: '203.0.113.10', source_port: 44300, dest_port: 443, protocol: 'tcp', action_taken: 'blocked', timestamp: iso(201), is_acknowledged: false },
  { id: 'ids-0004', site_id: demoIds.hq, device_id: 'dev-fw-hq', signature_id: '2001219', signature_name: 'ET SCAN Potential SSH Scan', category: 'attempted-recon', severity: 'medium', source_ip: '198.51.100.41', dest_ip: '203.0.113.10', source_port: 40122, dest_port: 22, protocol: 'tcp', action_taken: 'alerted', timestamp: iso(23), is_acknowledged: false },
  { id: 'ids-0005', site_id: demoIds.hq, device_id: 'dev-fw-hq', signature_id: '2009582', signature_name: 'ET SCAN NMAP -sS window 1024', category: 'attempted-recon', severity: 'medium', source_ip: '198.51.100.150', dest_ip: '203.0.113.10', source_port: 60011, dest_port: 3389, protocol: 'tcp', action_taken: 'blocked', timestamp: iso(96), is_acknowledged: true, acknowledged_by: 'Marcus Hale', acknowledged_at: iso(90) },
  { id: 'ids-0006', site_id: demoIds.hq, device_id: 'dev-fw-hq', signature_id: '2012811', signature_name: 'ET DNS Query for a Suspicious Dynamic DNS Domain', category: 'bad-unknown', severity: 'medium', source_ip: '198.51.100.98', dest_ip: '203.0.113.10', source_port: 12400, dest_port: 53, protocol: 'udp', action_taken: 'alerted', timestamp: iso(268), is_acknowledged: false },
  { id: 'ids-0007', site_id: demoIds.branch, device_id: 'dev-fw-branch', signature_id: '2027759', signature_name: 'ET SCAN Potential OpenVPN Enumeration', category: 'attempted-recon', severity: 'medium', source_ip: '198.51.100.66', dest_ip: '198.51.100.20', source_port: 39221, dest_port: 1194, protocol: 'udp', action_taken: 'alerted', timestamp: iso(52), is_acknowledged: false },
  { id: 'ids-0008', site_id: demoIds.hq, device_id: 'dev-fw-hq', signature_id: '2027863', signature_name: 'ET POLICY IoT Device Firmware Check-in over cleartext HTTP', category: 'policy-violation', severity: 'low', source_ip: '10.10.40.21', dest_ip: '198.51.100.9', source_port: 49220, dest_port: 80, protocol: 'tcp', action_taken: 'blocked', timestamp: iso(64), is_acknowledged: true, acknowledged_by: 'Priya Raman', acknowledged_at: iso(60) },
  { id: 'ids-0009', site_id: demoIds.hq, device_id: 'dev-fw-hq', signature_id: '2008581', signature_name: 'ET P2P BitTorrent DHT ping request', category: 'policy-violation', severity: 'low', source_ip: '10.10.10.88', dest_ip: '198.51.100.60', source_port: 51120, dest_port: 6881, protocol: 'udp', action_taken: 'alerted', timestamp: iso(142), is_acknowledged: false },
  { id: 'ids-0010', site_id: demoIds.branch, device_id: 'dev-fw-branch', signature_id: '2014169', signature_name: 'ET POLICY External NTP Server Use', category: 'policy-violation', severity: 'low', source_ip: '10.30.50.31', dest_ip: '198.51.100.9', source_port: 55010, dest_port: 123, protocol: 'udp', action_taken: 'alerted', timestamp: iso(180), is_acknowledged: true, acknowledged_by: 'Dana Okafor', acknowledged_at: iso(170) },
];

export const firewallIdsAlertStats = {
  total: 10,
  critical: 1,
  high: 2,
  medium: 4,
  low: 3,
  unacknowledged: 7,
  acknowledged: 3,
  by_category: {
    'attempted-admin': 1,
    'web-application-attack': 1,
    'trojan-activity': 1,
    'attempted-recon': 3,
    'bad-unknown': 1,
    'policy-violation': 3,
  },
};

export const firewallLogs = [
  { id: 'fwl-0001', site_id: demoIds.hq, device_id: 'dev-fw-hq', rule_id: 'fwr-0008', timestamp: iso(1), source_ip: '198.51.100.77', source_port: 51344, dest_ip: '203.0.113.10', dest_port: 443, source_zone: 'wan', dest_zone: 'self', protocol: 'tcp', action: 'deny', bytes_sent: 0, bytes_received: 60, application: 'https' },
  { id: 'fwl-0002', site_id: demoIds.hq, device_id: 'dev-fw-hq', rule_id: 'fwr-0001', timestamp: iso(2), source_ip: '10.10.10.44', source_port: 53122, dest_ip: '203.0.113.53', dest_port: 443, source_zone: 'corporate', dest_zone: 'wan', protocol: 'tcp', action: 'allow', bytes_sent: 184_220, bytes_received: 1_842_004, application: 'https' },
  { id: 'fwl-0003', site_id: demoIds.hq, device_id: 'dev-fw-hq', rule_id: 'fwr-0004', timestamp: iso(4), source_ip: '10.10.40.21', source_port: 49220, dest_ip: '198.51.100.9', dest_port: 80, source_zone: 'cameras', dest_zone: 'wan', protocol: 'tcp', action: 'deny', bytes_sent: 0, bytes_received: 60, application: 'http' },
  { id: 'fwl-0004', site_id: demoIds.hq, device_id: 'dev-fw-hq', rule_id: 'fwr-0006', timestamp: iso(6), source_ip: '10.10.10.61', source_port: 51999, dest_ip: '10.10.20.40', dest_port: 445, source_zone: 'corporate', dest_zone: 'dmz', protocol: 'tcp', action: 'reject', bytes_sent: 0, bytes_received: 60, application: 'smb' },
  { id: 'fwl-0005', site_id: demoIds.hq, device_id: 'dev-fw-hq', rule_id: 'fwr-0002', timestamp: iso(9), source_ip: '10.10.30.101', source_port: 5060, dest_ip: '10.10.0.20', dest_port: 5060, source_zone: 'voice', dest_zone: 'lan', protocol: 'udp', action: 'allow', bytes_sent: 12_880, bytes_received: 14_202, application: 'sip' },
  { id: 'fwl-0006', site_id: demoIds.hq, device_id: 'dev-fw-hq', rule_id: 'fwr-0008', timestamp: iso(13), source_ip: '198.51.100.150', source_port: 60011, dest_ip: '203.0.113.10', dest_port: 3389, source_zone: 'wan', dest_zone: 'self', protocol: 'tcp', action: 'deny', bytes_sent: 0, bytes_received: 60, application: 'rdp' },
  { id: 'fwl-0007', site_id: demoIds.hq, device_id: 'dev-fw-hq', rule_id: 'fwr-0003', timestamp: iso(16), source_ip: '10.10.40.22', source_port: 47110, dest_ip: '10.10.40.10', dest_port: 8000, source_zone: 'cameras', dest_zone: 'cameras', protocol: 'tcp', action: 'allow', bytes_sent: 902_118, bytes_received: 4_118, application: 'hikvision-isapi' },
  { id: 'fwl-0008', site_id: demoIds.hq, device_id: 'dev-fw-hq', rule_id: 'fwr-0005', timestamp: iso(21), source_ip: '10.10.99.5', source_port: 55210, dest_ip: '10.10.0.2', dest_port: 22, source_zone: 'mgmt', dest_zone: 'lan', protocol: 'tcp', action: 'allow', bytes_sent: 44_112, bytes_received: 88_204, application: 'ssh' },
  { id: 'fwl-0009', site_id: demoIds.hq, device_id: 'dev-fw-hq', rule_id: 'fwr-0008', timestamp: iso(24), source_ip: '169.254.14.9', source_port: 1024, dest_ip: '203.0.113.10', dest_port: 80, source_zone: 'wan', dest_zone: 'self', protocol: 'tcp', action: 'deny', bytes_sent: 0, bytes_received: 60, application: 'http' },
  { id: 'fwl-0010', site_id: demoIds.hq, device_id: 'dev-fw-hq', rule_id: 'fwr-0007', timestamp: iso(29), source_ip: '10.10.80.31', source_port: 52001, dest_ip: '198.51.100.30', dest_port: 443, source_zone: 'guest', dest_zone: 'wan', protocol: 'tcp', action: 'allow', bytes_sent: 220_411, bytes_received: 3_918_224, application: 'https' },
  { id: 'fwl-0011', site_id: demoIds.branch, device_id: 'dev-fw-branch', rule_id: 'fwr-0009', timestamp: iso(31), source_ip: '10.30.10.55', source_port: 50122, dest_ip: '10.10.20.22', dest_port: 993, source_zone: 'users', dest_zone: 'ipsec', protocol: 'tcp', action: 'allow', bytes_sent: 61_002, bytes_received: 402_118, application: 'imaps' },
  { id: 'fwl-0012', site_id: demoIds.branch, device_id: 'dev-fw-branch', rule_id: 'fwr-0010', timestamp: iso(35), source_ip: '10.30.50.31', source_port: 55010, dest_ip: '10.30.10.240', dest_port: 9100, source_zone: 'guest', dest_zone: 'users', protocol: 'tcp', action: 'deny', bytes_sent: 0, bytes_received: 60, application: 'jetdirect' },
  { id: 'fwl-0013', site_id: demoIds.hq, device_id: 'dev-fw-hq', rule_id: 'fwr-0001', timestamp: iso(41), source_ip: '10.10.10.19', source_port: 49881, dest_ip: '198.51.100.14', dest_port: 443, source_zone: 'corporate', dest_zone: 'wan', protocol: 'tcp', action: 'allow', bytes_sent: 88_112, bytes_received: 1_140_882, application: 'https' },
  { id: 'fwl-0014', site_id: demoIds.dc, device_id: 'dev-fw-dc', rule_id: null, timestamp: iso(47), source_ip: '10.20.90.14', source_port: 44120, dest_ip: '10.20.0.30', dest_port: 445, source_zone: 'lab', dest_zone: 'prod', protocol: 'tcp', action: 'allow', bytes_sent: 1_204_118, bytes_received: 88_402, application: 'smb' },
  { id: 'fwl-0015', site_id: demoIds.hq, device_id: 'dev-fw-hq', rule_id: 'fwr-0008', timestamp: iso(58), source_ip: '198.51.100.203', source_port: 33110, dest_ip: '10.10.20.15', dest_port: 8080, source_zone: 'wan', dest_zone: 'dmz', protocol: 'tcp', action: 'deny', bytes_sent: 0, bytes_received: 512, application: 'http-alt' },
  { id: 'fwl-0016', site_id: demoIds.dc, device_id: 'dev-fw-dc', rule_id: null, timestamp: iso(66), source_ip: '10.20.0.11', source_port: 39112, dest_ip: '10.20.0.30', dest_port: 3260, source_zone: 'prod', dest_zone: 'storage', protocol: 'tcp', action: 'allow', bytes_sent: 8_204_118_002, bytes_received: 14_882_004_119, application: 'iscsi' },
];

// ==== demo fleet: cameras and VoIP ====

// ═══════════════════════════════════════════════════════════════════════════
// Cameras + VoIP demo estate
// ═══════════════════════════════════════════════════════════════════════════
// The NVR ids reuse the camera/VoIP controller ids already in `demoIds` so the
// three original cameras keep pointing at a real recorder; the Datacenter NVR
// and the branch PBX are new.
export const demoMediaIds = {
  nvrHq: demoIds.hikvision,
  nvrBranch: demoIds.unifi,
  nvrDc: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
  pbxHq: demoIds.freepbx,
  pbxBranch: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
};

export const demoNvrs = [
  {
    id: demoMediaIds.nvrHq,
    name: 'HQ Hikvision NVR',
    description: 'Primary recorder for the HQ camera VLAN (10.10.40.0/24)',
    ip_address: '10.10.40.10',
    port: 80,
    mac_address: '02:00:00:00:40:10',
    vendor: 'hikvision',
    model: 'DS-7716NI-K4/16P',
    firmware_version: 'V4.62.005 build 230412',
    serial_number: 'DEMO-NVR-HQ-7716-0001',
    device_type: 'hikvision',
    channel_count: 16,
    storage_total_gb: 32000,
    storage_used_gb: 24580,
    status: 'online',
    last_seen: iso(1),
    last_synced_at: iso(7),
    site_id: demoIds.hq,
    stream_encryption_key: true,
    settings: { retention_days: 30, overwrite: true, timezone: 'America/Chicago' },
    created_at: iso(60 * 24 * 19),
    updated_at: iso(7),
  },
  {
    id: demoMediaIds.nvrBranch,
    name: 'Branch UniFi Protect',
    description: 'UNVR-Pro serving the branch office cameras',
    ip_address: '10.30.40.4',
    port: 443,
    mac_address: '02:00:00:00:41:04',
    vendor: 'unifi_protect',
    model: 'UNVR-Pro',
    firmware_version: '4.1.13',
    serial_number: 'DEMO-NVR-BR-UNVR-0002',
    device_type: 'unifi_protect',
    channel_count: 8,
    storage_total_gb: 16000,
    storage_used_gb: 9420,
    status: 'online',
    last_seen: iso(2),
    last_synced_at: iso(9),
    site_id: demoIds.branch,
    stream_encryption_key: false,
    settings: { retention_days: 21, overwrite: true, timezone: 'America/Denver' },
    created_at: iso(60 * 24 * 15),
    updated_at: iso(9),
  },
  {
    id: demoMediaIds.nvrDc,
    name: 'Datacenter Hikvision NVR',
    description: 'Cage and mantrap recorder at the colocation site',
    ip_address: '10.20.40.10',
    port: 80,
    mac_address: '02:00:00:00:42:10',
    vendor: 'hikvision',
    model: 'DS-7608NI-K2/8P',
    firmware_version: 'V4.61.025 build 220315',
    serial_number: 'DEMO-NVR-DC-7608-0003',
    device_type: 'hikvision',
    channel_count: 8,
    storage_total_gb: 8000,
    storage_used_gb: 6120,
    status: 'online',
    last_seen: iso(3),
    last_synced_at: iso(14),
    site_id: demoIds.dc,
    stream_encryption_key: true,
    settings: { retention_days: 45, overwrite: true, timezone: 'America/New_York' },
    created_at: iso(60 * 24 * 13),
    updated_at: iso(14),
  },
];

// `cameras` (above) is left untouched so dashboardSummary keeps working;
// `demoCameras` is the full estate the camera module serves - the same three
// ids, enriched, plus eighteen more. Field names follow CameraResponse in
// backend/app/modules/cameras/schemas.py (device_type is the ADAPTER id,
// camera_type is the CameraType enum).
export const demoCameras = [
  { id: 'cam-front-door', name: 'Front Door Camera', desc: 'Main visitor entrance, faces the plaza', st: 'online', rec: true, ip: '10.10.40.21', mac: '02:00:00:00:40:21', vendor: 'hikvision', model: 'DS-2CD2387G2-LU', fw: 'V5.7.13 build 230427', sn: 'DEMO-CAM-HQ-0021', ptz: false, audio: true, two: false, ir: true, w: 3840, h: 2160, loc: 'HQ entrance', floor: 'Ground', ch: 1, nvr: 'hq', seen: 1, snap: 'front-door', note: null },
  { id: 'cam-hq-lobby-ptz', name: 'HQ Lobby PTZ', desc: 'Pan/tilt over the reception floor', st: 'online', rec: true, ip: '10.10.40.22', mac: '02:00:00:00:40:22', vendor: 'hikvision', model: 'DS-2DE4A425IW-DE', fw: 'V5.7.13 build 230427', sn: 'DEMO-CAM-HQ-0022', ptz: true, audio: true, two: true, ir: true, w: 2560, h: 1440, loc: 'HQ lobby', floor: 'Ground', ch: 2, nvr: 'hq', seen: 1, snap: 'front-door', note: null },
  { id: 'cam-hq-reception', name: 'Reception Desk', desc: 'Overhead view of the reception counter', st: 'online', rec: true, ip: '10.10.40.23', mac: '02:00:00:00:40:23', vendor: 'hikvision', model: 'DS-2CD2143G2-I', fw: 'V5.7.13 build 230427', sn: 'DEMO-CAM-HQ-0023', ptz: false, audio: false, two: false, ir: true, w: 2688, h: 1520, loc: 'HQ reception', floor: 'Ground', ch: 3, nvr: 'hq', seen: 2, snap: 'front-door', note: null },
  { id: 'cam-hq-parking-north', name: 'Parking North', desc: 'ColorVu overlooking the north visitor bays', st: 'online', rec: true, ip: '10.10.40.24', mac: '02:00:00:00:40:24', vendor: 'hikvision', model: 'DS-2CD2T87G2P-LSU/SL', fw: 'V5.7.13 build 230427', sn: 'DEMO-CAM-HQ-0024', ptz: false, audio: true, two: true, ir: false, w: 3840, h: 2160, loc: 'North car park', floor: 'Exterior', ch: 4, nvr: 'hq', seen: 1, snap: 'warehouse', note: null },
  { id: 'cam-hq-parking-south', name: 'Parking South', desc: 'Offline for a scheduled lens clean and remount', st: 'offline', rec: false, ip: '10.10.40.25', mac: '02:00:00:00:40:25', vendor: 'hikvision', model: 'DS-2CD2T87G2P-LSU/SL', fw: 'V5.7.13 build 230427', sn: 'DEMO-CAM-HQ-0025', ptz: false, audio: true, two: true, ir: false, w: 3840, h: 2160, loc: 'South car park', floor: 'Exterior', ch: 5, nvr: 'hq', seen: 212, snap: 'warehouse', note: 'Lens clean and remount, back in service today' },
  { id: 'cam-hq-loading-dock', name: 'Loading Dock', desc: 'Covers both roller doors and the dock apron', st: 'online', rec: true, ip: '10.10.40.26', mac: '02:00:00:00:40:26', vendor: 'hikvision', model: 'DS-2CD2T47G2-L', fw: 'V5.7.13 build 230427', sn: 'DEMO-CAM-HQ-0026', ptz: false, audio: false, two: false, ir: false, w: 2688, h: 1520, loc: 'Loading dock', floor: 'Exterior', ch: 6, nvr: 'hq', seen: 2, snap: 'warehouse', note: null },
  { id: 'cam-hq-server-room', name: 'Server Room', desc: 'Rack row A, audio armed for tamper alerts', st: 'online', rec: true, ip: '10.10.40.27', mac: '02:00:00:00:40:27', vendor: 'hikvision', model: 'DS-2CD2146G2-ISU', fw: 'V5.7.13 build 230427', sn: 'DEMO-CAM-HQ-0027', ptz: false, audio: true, two: false, ir: true, w: 2560, h: 1440, loc: 'HQ server room', floor: 'Ground', ch: 7, nvr: 'hq', seen: 1, snap: 'front-door', note: null },
  { id: 'cam-hq-corridor-l2', name: 'Level 2 Corridor', desc: 'Corridor between the east and west wings', st: 'online', rec: true, ip: '10.10.40.28', mac: '02:00:00:00:40:28', vendor: 'hikvision', model: 'DS-2CD2143G2-I', fw: 'V5.7.13 build 230427', sn: 'DEMO-CAM-HQ-0028', ptz: false, audio: false, two: false, ir: true, w: 2688, h: 1520, loc: 'Level 2 corridor', floor: 'Level 2', ch: 8, nvr: 'hq', seen: 2, snap: 'front-door', note: null },
  { id: 'cam-hq-cafeteria', name: 'Cafeteria', desc: 'Staff cafeteria, recorded on motion only', st: 'online', rec: false, ip: '10.10.40.29', mac: '02:00:00:00:40:29', vendor: 'hikvision', model: 'DS-2CD2143G2-I', fw: 'V5.7.13 build 230427', sn: 'DEMO-CAM-HQ-0029', ptz: false, audio: false, two: false, ir: true, w: 2688, h: 1520, loc: 'Cafeteria', floor: 'Level 2', ch: 9, nvr: 'hq', seen: 3, snap: 'front-door', note: null },
  { id: 'cam-hq-rear-exit', name: 'Rear Fire Exit', desc: 'Door-forced monitoring on the rear stairwell exit', st: 'online', rec: true, ip: '10.10.40.30', mac: '02:00:00:00:40:30', vendor: 'hikvision', model: 'DS-2CD2387G2-LU', fw: 'V5.7.13 build 230427', sn: 'DEMO-CAM-HQ-0030', ptz: false, audio: true, two: false, ir: true, w: 3840, h: 2160, loc: 'Rear fire exit', floor: 'Ground', ch: 10, nvr: 'hq', seen: 1, snap: 'front-door', note: null },
  { id: 'cam-hq-roof-ptz', name: 'Roof Perimeter PTZ', desc: 'Roof-mounted PTZ running the perimeter patrol tour', st: 'online', rec: true, ip: '10.10.40.31', mac: '02:00:00:00:40:31', vendor: 'hikvision', model: 'DS-2DE5A432IW-AE', fw: 'V5.7.13 build 230427', sn: 'DEMO-CAM-HQ-0031', ptz: true, audio: false, two: false, ir: true, w: 2560, h: 1440, loc: 'HQ roof', floor: 'Roof', ch: 11, nvr: 'hq', seen: 2, snap: 'warehouse', note: null },
  { id: 'cam-branch-lobby', name: 'Branch Lobby Protect', desc: 'Adopted by the branch UNVR-Pro', st: 'online', rec: true, ip: '10.30.40.7', mac: '02:00:00:00:41:07', vendor: 'unifi_protect', model: 'G5 Dome', fw: '4.75.62', sn: 'DEMO-CAM-BR-0007', ptz: false, audio: true, two: true, ir: true, w: 2688, h: 1512, loc: 'Branch lobby', floor: 'Ground', ch: 1, nvr: 'br', seen: 1, snap: 'branch-lobby', note: null },
  { id: 'cam-branch-entry', name: 'Branch Front Entry', desc: 'Street-facing bullet over the front door', st: 'online', rec: true, ip: '10.30.40.8', mac: '02:00:00:00:41:08', vendor: 'unifi_protect', model: 'G5 Bullet', fw: '4.75.62', sn: 'DEMO-CAM-BR-0008', ptz: false, audio: true, two: false, ir: true, w: 2688, h: 1512, loc: 'Branch front entry', floor: 'Ground', ch: 2, nvr: 'br', seen: 1, snap: 'branch-lobby', note: null },
  { id: 'cam-branch-stockroom', name: 'Branch Stockroom', desc: 'Shelving aisle and the stock cage door', st: 'online', rec: true, ip: '10.30.40.9', mac: '02:00:00:00:41:09', vendor: 'unifi_protect', model: 'G4 Instant', fw: '4.71.30', sn: 'DEMO-CAM-BR-0009', ptz: false, audio: true, two: true, ir: true, w: 1920, h: 1080, loc: 'Branch stockroom', floor: 'Ground', ch: 3, nvr: 'br', seen: 2, snap: 'warehouse', note: null },
  { id: 'cam-branch-lot', name: 'Branch Staff Lot', desc: '4K view of the staff parking lot and gate', st: 'online', rec: true, ip: '10.30.40.10', mac: '02:00:00:00:41:10', vendor: 'unifi_protect', model: 'G5 Pro', fw: '4.75.62', sn: 'DEMO-CAM-BR-0010', ptz: false, audio: true, two: false, ir: true, w: 3840, h: 2160, loc: 'Branch staff lot', floor: 'Exterior', ch: 4, nvr: 'br', seen: 1, snap: 'warehouse', note: null },
  { id: 'cam-branch-back-door', name: 'Branch Back Door', desc: 'Powered down while the dock canopy is rebuilt', st: 'offline', rec: false, ip: '10.30.40.11', mac: '02:00:00:00:41:11', vendor: 'unifi_protect', model: 'G5 Turret Ultra', fw: '4.75.62', sn: 'DEMO-CAM-BR-0011', ptz: false, audio: true, two: false, ir: true, w: 2688, h: 1512, loc: 'Branch back door', floor: 'Exterior', ch: 5, nvr: 'br', seen: 1480, snap: 'branch-lobby', note: 'Dock canopy rebuild, back in service Tuesday' },
  { id: 'cam-warehouse', name: 'Warehouse Aisle Camera', desc: 'ONVIF Profile S camera on the cage aisle', st: 'online', rec: true, ip: '10.20.40.18', mac: '02:00:00:00:42:18', vendor: 'onvif', model: 'Generic Profile S', fw: '2.4.1', sn: 'DEMO-CAM-DC-0018', ptz: false, audio: false, two: false, ir: true, w: 1920, h: 1080, loc: 'Datacenter cage', floor: 'Ground', ch: 1, nvr: 'dc', seen: 2, snap: 'warehouse', note: null },
  { id: 'cam-dc-cage-a', name: 'Cage A Aisle', desc: 'Front of cage A, rack rows 1-6', st: 'online', rec: true, ip: '10.20.40.19', mac: '02:00:00:00:42:19', vendor: 'hikvision', model: 'DS-2CD2143G2-I', fw: 'V5.5.164 build 220630', sn: 'DEMO-CAM-DC-0019', ptz: false, audio: false, two: false, ir: true, w: 2688, h: 1520, loc: 'Cage A', floor: 'Ground', ch: 2, nvr: 'dc', seen: 2, snap: 'warehouse', note: null },
  { id: 'cam-dc-cage-b', name: 'Cage B Aisle', desc: 'Front of cage B, rack rows 7-12', st: 'online', rec: true, ip: '10.20.40.20', mac: '02:00:00:00:42:20', vendor: 'hikvision', model: 'DS-2CD2143G2-I', fw: 'V5.5.164 build 220630', sn: 'DEMO-CAM-DC-0020', ptz: false, audio: false, two: false, ir: true, w: 2688, h: 1520, loc: 'Cage B', floor: 'Ground', ch: 3, nvr: 'dc', seen: 3, snap: 'warehouse', note: null },
  { id: 'cam-dc-mantrap', name: 'Mantrap Entry', desc: 'Badge-in mantrap, two-factor entry to the suite', st: 'online', rec: true, ip: '10.20.40.21', mac: '02:00:00:00:42:21', vendor: 'hikvision', model: 'DS-2CD2387G2-LU', fw: 'V5.7.13 build 230427', sn: 'DEMO-CAM-DC-0021', ptz: false, audio: true, two: false, ir: true, w: 3840, h: 2160, loc: 'Suite mantrap', floor: 'Ground', ch: 4, nvr: 'dc', seen: 1, snap: 'front-door', note: null },
  { id: 'cam-dc-generator-yard', name: 'Generator Yard', desc: 'Fenced generator and fuel bund compound', st: 'online', rec: true, ip: '10.20.40.22', mac: '02:00:00:00:42:22', vendor: 'hikvision', model: 'DS-2CD2T87G2P-LSU/SL', fw: 'V5.7.13 build 230427', sn: 'DEMO-CAM-DC-0022', ptz: false, audio: true, two: true, ir: false, w: 3840, h: 2160, loc: 'Generator yard', floor: 'Exterior', ch: 5, nvr: 'dc', seen: 2, snap: 'warehouse', note: null },
].map((c, index) => {
  const nvrId = c.nvr === 'hq' ? demoMediaIds.nvrHq : c.nvr === 'br' ? demoMediaIds.nvrBranch : demoMediaIds.nvrDc;
  const nvrName = c.nvr === 'hq' ? 'HQ Hikvision NVR' : c.nvr === 'br' ? 'Branch UniFi Protect' : 'Datacenter Hikvision NVR';
  const nvrIp = c.nvr === 'hq' ? '10.10.40.10' : c.nvr === 'br' ? '10.30.40.4' : '10.20.40.10';
  const siteId = c.nvr === 'hq' ? demoIds.hq : c.nvr === 'br' ? demoIds.branch : demoIds.dc;
  const siteName = c.nvr === 'hq' ? 'HQ Campus' : c.nvr === 'br' ? 'Branch Office' : 'Datacenter';
  const protect = c.vendor === 'unifi_protect';
  const slug = c.id.replace(/^cam-(branch-|dc-|hq-)?/, '');
  return {
    id: c.id,
    name: c.name,
    description: c.desc,
    camera_type: c.ptz ? 'ptz_camera' : 'ip_camera',
    ip_address: c.ip,
    port: protect ? 443 : 80,
    mac_address: c.mac,
    vendor: c.vendor,
    model: c.model,
    firmware_version: c.fw,
    serial_number: c.sn,
    channel_id: c.ch,
    // device_type is the adapter id on the cameras table, not the literal "camera".
    device_type: c.vendor,
    has_ptz: c.ptz,
    has_audio: c.audio,
    has_two_way_audio: c.two,
    has_ir: c.ir,
    status: c.st,
    last_seen: iso(c.seen),
    is_recording: c.rec,
    motion_detection_enabled: true,
    nvr_id: nvrId,
    nvr: { id: nvrId, name: nvrName },
    site_id: siteId,
    site_name: siteName,
    location: c.loc,
    floor: c.floor,
    // No credentials embedded: the API masks them anyway, the demo has none.
    rtsp_main_stream: protect ? `rtsps://${nvrIp}:7441/demo-${slug}-main` : `rtsp://${nvrIp}:554/Streaming/Channels/${c.ch}01`,
    rtsp_sub_stream: protect ? `rtsps://${nvrIp}:7441/demo-${slug}-sub` : `rtsp://${nvrIp}:554/Streaming/Channels/${c.ch}02`,
    stream_encryption_key: !protect,
    settings: {
      day_night: /T87G2P|T47G2-L/.test(c.model) ? 'colorvu' : 'auto',
      wdr: c.w >= 2688,
      maintenance_note: c.note,
    },
    // Carried over from the original three-camera fixture (not CameraResponse
    // fields, but the demo's snapshot plumbing reads them).
    resolution_width: c.w,
    resolution_height: c.h,
    stream_status: 'demo_unavailable',
    snapshot_url: `/demo/camera-${c.snap}.jpg`,
    last_snapshot_at: iso(c.seen + 3),
    created_at: iso(6000 - index * 20),
    updated_at: iso(c.seen + 3),
  };
});

/** Camera id -> one of the three demo snapshot JPGs shipped in public/demo. */
export const demoCameraSnapshots = demoCameras.map((c) => ({ id: c.id, path: c.snapshot_url }));

// ── Camera events (motion / line crossing / intrusion / face / tamper) ──────
export const demoCameraEvents = [
  { id: 'cev-0001', camera_id: 'cam-front-door', event_type: 'motion', timestamp: iso(3), description: 'Person entering the main doors', snapshot_url: '/demo/camera-front-door.jpg', is_acknowledged: false, metadata_json: { target_type: 'human', confidence: 0.94, region: 'Doorway' } },
  { id: 'cev-0002', camera_id: 'cam-branch-lot', event_type: 'linedetection', timestamp: iso(6), description: 'Vehicle crossed the gate line inbound', snapshot_url: '/demo/camera-warehouse.jpg', is_acknowledged: false, metadata_json: { target_type: 'vehicle', confidence: 0.91, region: 'Gate line' } },
  { id: 'cev-0003', camera_id: 'cam-hq-parking-north', event_type: 'motion', timestamp: iso(9), description: 'Vehicle parked in visitor bay 4', snapshot_url: '/demo/camera-warehouse.jpg', is_acknowledged: false, metadata_json: { target_type: 'vehicle', confidence: 0.88, region: 'Visitor bays' } },
  { id: 'cev-0004', camera_id: 'cam-dc-mantrap', event_type: 'motion', timestamp: iso(12), description: 'Badge-in at the suite mantrap', snapshot_url: '/demo/camera-front-door.jpg', is_acknowledged: true, metadata_json: { target_type: 'human', confidence: 0.96, region: 'Mantrap' } },
  { id: 'cev-0005', camera_id: 'cam-hq-loading-dock', event_type: 'linedetection', timestamp: iso(17), description: 'Delivery van crossed the dock apron line', snapshot_url: '/demo/camera-warehouse.jpg', is_acknowledged: true, metadata_json: { target_type: 'vehicle', confidence: 0.86, region: 'Apron line' } },
  { id: 'cev-0006', camera_id: 'cam-branch-entry', event_type: 'motion', timestamp: iso(21), description: 'Two people entered the branch', snapshot_url: '/demo/camera-branch-lobby.jpg', is_acknowledged: false, metadata_json: { target_type: 'human', confidence: 0.93, region: 'Entry mat' } },
  { id: 'cev-0007', camera_id: 'cam-hq-rear-exit', event_type: 'fielddetection', timestamp: iso(26), description: 'Loitering in the rear stairwell zone', snapshot_url: '/demo/camera-front-door.jpg', is_acknowledged: false, metadata_json: { target_type: 'human', confidence: 0.79, region: 'Stairwell' } },
  { id: 'cev-0008', camera_id: 'cam-dc-generator-yard', event_type: 'fielddetection', timestamp: iso(33), description: 'Intrusion zone breached near the fuel bund', snapshot_url: '/demo/camera-warehouse.jpg', is_acknowledged: true, metadata_json: { target_type: 'human', confidence: 0.82, region: 'Fuel bund' } },
  { id: 'cev-0009', camera_id: 'cam-hq-lobby-ptz', event_type: 'facedetection', timestamp: iso(38), description: 'Face captured at the reception counter', snapshot_url: '/demo/camera-front-door.jpg', is_acknowledged: true, metadata_json: { target_type: 'human', confidence: 0.9, region: 'Counter' } },
  { id: 'cev-0010', camera_id: 'cam-branch-stockroom', event_type: 'motion', timestamp: iso(44), description: 'Stock cage door opened', snapshot_url: '/demo/camera-warehouse.jpg', is_acknowledged: true, metadata_json: { target_type: 'human', confidence: 0.87, region: 'Cage door' } },
  { id: 'cev-0011', camera_id: 'cam-hq-roof-ptz', event_type: 'motion', timestamp: iso(51), description: 'Movement on the west roof walkway', snapshot_url: '/demo/camera-warehouse.jpg', is_acknowledged: true, metadata_json: { target_type: null, confidence: 0.64, region: 'Walkway' } },
  { id: 'cev-0012', camera_id: 'cam-hq-parking-south', event_type: 'videoloss', timestamp: iso(56), description: 'Video loss, camera powered down for maintenance', snapshot_url: '/demo/camera-warehouse.jpg', is_acknowledged: true, metadata_json: { target_type: null, confidence: 1, region: 'Channel 5' } },
  { id: 'cev-0013', camera_id: 'cam-warehouse', event_type: 'motion', timestamp: iso(62), description: 'Technician walking the cage aisle', snapshot_url: '/demo/camera-warehouse.jpg', is_acknowledged: true, metadata_json: { target_type: 'human', confidence: 0.85, region: 'Aisle' } },
  { id: 'cev-0014', camera_id: 'cam-front-door', event_type: 'motion', timestamp: iso(70), description: 'Courier drop at the main doors', snapshot_url: '/demo/camera-front-door.jpg', is_acknowledged: true, metadata_json: { target_type: 'human', confidence: 0.92, region: 'Doorway' } },
  { id: 'cev-0015', camera_id: 'cam-hq-server-room', event_type: 'shelteralarm', timestamp: iso(78), description: 'Camera housing tamper detected, cleared by facilities', snapshot_url: '/demo/camera-front-door.jpg', is_acknowledged: true, metadata_json: { target_type: null, confidence: 0.71, region: 'Housing' } },
  { id: 'cev-0016', camera_id: 'cam-branch-lot', event_type: 'motion', timestamp: iso(86), description: 'Vehicle left the staff lot', snapshot_url: '/demo/camera-warehouse.jpg', is_acknowledged: true, metadata_json: { target_type: 'vehicle', confidence: 0.89, region: 'Exit lane' } },
  { id: 'cev-0017', camera_id: 'cam-dc-cage-a', event_type: 'motion', timestamp: iso(95), description: 'Rack door opened in row 3', snapshot_url: '/demo/camera-warehouse.jpg', is_acknowledged: true, metadata_json: { target_type: 'human', confidence: 0.83, region: 'Row 3' } },
  { id: 'cev-0018', camera_id: 'cam-hq-corridor-l2', event_type: 'motion', timestamp: iso(104), description: 'Corridor traffic between wings', snapshot_url: '/demo/camera-front-door.jpg', is_acknowledged: true, metadata_json: { target_type: 'human', confidence: 0.8, region: 'Corridor' } },
  { id: 'cev-0019', camera_id: 'cam-hq-cafeteria', event_type: 'motion', timestamp: iso(118), description: 'Motion recording triggered in the cafeteria', snapshot_url: '/demo/camera-front-door.jpg', is_acknowledged: true, metadata_json: { target_type: 'human', confidence: 0.77, region: 'Servery' } },
  { id: 'cev-0020', camera_id: 'cam-branch-entry', event_type: 'linedetection', timestamp: iso(131), description: 'Person crossed the entry threshold line', snapshot_url: '/demo/camera-branch-lobby.jpg', is_acknowledged: true, metadata_json: { target_type: 'human', confidence: 0.9, region: 'Threshold' } },
  { id: 'cev-0021', camera_id: 'cam-dc-mantrap', event_type: 'facedetection', timestamp: iso(146), description: 'Face captured at the inner mantrap door', snapshot_url: '/demo/camera-front-door.jpg', is_acknowledged: true, metadata_json: { target_type: 'human', confidence: 0.95, region: 'Inner door' } },
  { id: 'cev-0022', camera_id: 'cam-hq-parking-north', event_type: 'linedetection', timestamp: iso(163), description: 'Vehicle crossed the barrier line outbound', snapshot_url: '/demo/camera-warehouse.jpg', is_acknowledged: true, metadata_json: { target_type: 'vehicle', confidence: 0.87, region: 'Barrier' } },
  { id: 'cev-0023', camera_id: 'cam-hq-loading-dock', event_type: 'motion', timestamp: iso(181), description: 'Pallet jack movement on the dock', snapshot_url: '/demo/camera-warehouse.jpg', is_acknowledged: true, metadata_json: { target_type: null, confidence: 0.68, region: 'Dock apron' } },
  { id: 'cev-0024', camera_id: 'cam-dc-cage-b', event_type: 'motion', timestamp: iso(204), description: 'Aisle motion, scheduled hands-and-eyes visit', snapshot_url: '/demo/camera-warehouse.jpg', is_acknowledged: true, metadata_json: { target_type: 'human', confidence: 0.81, region: 'Row 9' } },
  { id: 'cev-0025', camera_id: 'cam-branch-lobby', event_type: 'motion', timestamp: iso(228), description: 'Customer waiting in the lobby', snapshot_url: '/demo/camera-branch-lobby.jpg', is_acknowledged: true, metadata_json: { target_type: 'human', confidence: 0.88, region: 'Seating' } },
  { id: 'cev-0026', camera_id: 'cam-hq-rear-exit', event_type: 'motion', timestamp: iso(255), description: 'Fire exit opened from inside', snapshot_url: '/demo/camera-front-door.jpg', is_acknowledged: true, metadata_json: { target_type: 'human', confidence: 0.9, region: 'Door' } },
  { id: 'cev-0027', camera_id: 'cam-dc-generator-yard', event_type: 'motion', timestamp: iso(288), description: 'Generator weekly test, engineer on site', snapshot_url: '/demo/camera-warehouse.jpg', is_acknowledged: true, metadata_json: { target_type: 'human', confidence: 0.84, region: 'Genset A' } },
  { id: 'cev-0028', camera_id: 'cam-hq-roof-ptz', event_type: 'fielddetection', timestamp: iso(322), description: 'Perimeter zone entered during the patrol tour', snapshot_url: '/demo/camera-warehouse.jpg', is_acknowledged: true, metadata_json: { target_type: null, confidence: 0.62, region: 'North edge' } },
  { id: 'cev-0029', camera_id: 'cam-branch-stockroom', event_type: 'motion', timestamp: iso(360), description: 'Stock count in progress', snapshot_url: '/demo/camera-warehouse.jpg', is_acknowledged: true, metadata_json: { target_type: 'human', confidence: 0.86, region: 'Aisle 2' } },
  { id: 'cev-0030', camera_id: 'cam-front-door', event_type: 'motion', timestamp: iso(402), description: 'Opening rounds, first badge of the day', snapshot_url: '/demo/camera-front-door.jpg', is_acknowledged: true, metadata_json: { target_type: 'human', confidence: 0.93, region: 'Doorway' } },
  { id: 'cev-0031', camera_id: 'cam-branch-back-door', event_type: 'videoloss', timestamp: iso(1480), description: 'Video loss, camera isolated for the canopy rebuild', snapshot_url: '/demo/camera-branch-lobby.jpg', is_acknowledged: true, metadata_json: { target_type: null, confidence: 1, region: 'Channel 5' } },
  { id: 'cev-0032', camera_id: 'cam-hq-server-room', event_type: 'motion', timestamp: iso(1650), description: 'After-hours access to rack row A', snapshot_url: '/demo/camera-front-door.jpg', is_acknowledged: true, metadata_json: { target_type: 'human', confidence: 0.91, region: 'Row A' } },
];

// ── Camera groups and saved wall views ─────────────────────────────────────
export const demoCameraGroups = [
  { id: 'cgrp-perimeter', name: 'Perimeter', description: 'Every outward-facing camera across the three sites', color: '#f97316', icon: 'shield', sort_order: 1, created_at: iso(20160), is_default: false, camera_ids: ['cam-hq-parking-north', 'cam-hq-parking-south', 'cam-hq-roof-ptz', 'cam-branch-lot', 'cam-dc-generator-yard'] },
  { id: 'cgrp-entrances', name: 'Entrances', description: 'Doors, mantraps and reception views', color: '#3b82f6', icon: 'door-open', sort_order: 2, created_at: iso(20160), is_default: true, camera_ids: ['cam-front-door', 'cam-hq-rear-exit', 'cam-hq-reception', 'cam-branch-entry', 'cam-branch-lobby', 'cam-dc-mantrap'] },
  { id: 'cgrp-datacenter', name: 'Datacenter Cages', description: 'Colocation suite, cages A and B', color: '#8b5cf6', icon: 'server', sort_order: 3, created_at: iso(20160), is_default: false, camera_ids: ['cam-warehouse', 'cam-dc-cage-a', 'cam-dc-cage-b', 'cam-dc-mantrap'] },
  { id: 'cgrp-logistics', name: 'Logistics', description: 'Dock, stockroom and goods handling', color: '#22c55e', icon: 'package', sort_order: 4, created_at: iso(20160), is_default: false, camera_ids: ['cam-hq-loading-dock', 'cam-branch-stockroom', 'cam-warehouse'] },
];

export const demoCameraViews = [
  { id: 'cview-lobby-wall', name: 'Front of house', description: 'Reception and entry cameras for the security desk', layout: '2x2', camera_ids: ['cam-front-door', 'cam-hq-reception', 'cam-hq-lobby-ptz', 'cam-branch-lobby'], filters: {}, sort_order: 1, created_at: iso(18000), is_default: true, is_shared: true, is_owner: true },
  { id: 'cview-perimeter-wall', name: 'Perimeter watch', description: 'Outdoor cameras across all sites', layout: '3x3', camera_ids: ['cam-hq-parking-north', 'cam-hq-roof-ptz', 'cam-hq-loading-dock', 'cam-branch-lot', 'cam-dc-generator-yard'], filters: {}, sort_order: 2, created_at: iso(18000), is_default: false, is_shared: true, is_owner: true },
  { id: 'cview-dc-wall', name: 'Datacenter suite', description: 'Cage aisles and the mantrap', layout: '2x2', camera_ids: ['cam-dc-mantrap', 'cam-dc-cage-a', 'cam-dc-cage-b', 'cam-warehouse'], filters: {}, sort_order: 3, created_at: iso(18000), is_default: false, is_shared: false, is_owner: true },
];

// ── Evidence archives (legal hold) ─────────────────────────────────────────
// The sha256 values are content digests of demo clips, not secrets.
export const demoEvidenceArchives = [
  { id: 'evd-2026-0007', camera_id: 'cam-hq-loading-dock', camera_name: 'Loading Dock', start_time: iso(200), end_time: iso(185), watermarked: true, status: 'ready', file_size: 486_320_128, sha256: '9f2c1d4a7be0356148c9a0d2f7be34519a0c6d8e2b4713f5a6c8d90e1f2a3b4c', note: 'Damaged pallet claim, held for the carrier', error: null, created_at: iso(180), completed_at: iso(176) },
  { id: 'evd-2026-0008', camera_id: 'cam-dc-mantrap', camera_name: 'Mantrap Entry', start_time: iso(160), end_time: iso(150), watermarked: true, status: 'ready', file_size: 312_115_200, sha256: '3a7f90bd25c1e846f0b2d3491a7c5e68d04b1f92c7a3e5061d8b4f2907ce31da', note: 'Access review, badge audit window', error: null, created_at: iso(148), completed_at: iso(145) },
  { id: 'evd-2026-0009', camera_id: 'cam-branch-lot', camera_name: 'Branch Staff Lot', start_time: iso(95), end_time: iso(80), watermarked: true, status: 'ready', file_size: 704_643_072, sha256: 'c81b56ef3d90a24718f60b3c5d2e79a4106fb8de2c47903a51e6b8d0f9247c3b', note: 'Parking incident report 26-0141', error: null, created_at: iso(78), completed_at: iso(71) },
  { id: 'evd-2026-0010', camera_id: 'cam-front-door', camera_name: 'Front Door Camera', start_time: iso(40), end_time: iso(25), watermarked: true, status: 'archiving', file_size: null, sha256: null, note: 'Reception dispute, requested by facilities', error: null, created_at: iso(12), completed_at: null },
];

// ── Daily camera uptime reports ────────────────────────────────────────────
export const demoCameraReports = Array.from({ length: 14 }, (_, i) => {
  const dayIndex = 13 - i;
  const offline = dayIndex < 2 ? 2 : dayIndex < 5 ? 1 : 0;
  return {
    id: `crep-${String(14 - i).padStart(4, '0')}`,
    report_type: 'daily_uptime',
    period_start: iso((dayIndex + 1) * 1440),
    period_end: iso(dayIndex * 1440),
    generated_at: iso(dayIndex * 1440),
    data: {
      total_cameras: 21,
      online_cameras: 21 - offline,
      total_events: 96 - dayIndex * 3 + (dayIndex % 4) * 7,
      uptime_pct: offline === 0 ? 99.97 : offline === 1 ? 99.4 : 98.6,
      total_snapshots: 21 * 288,
      online_snapshots: (21 - offline) * 288,
    },
  };
});

// ── NVR storage, system info and network (one row per NVR) ─────────────────
export const demoNvrStorage = [
  {
    nvr_id: demoMediaIds.nvrHq, total_gb: 32000, used_gb: 24580, free_gb: 7420, percent_used: 77, disk_count: 4, healthy_count: 4, unhealthy_count: 0,
    disks: [
      { id: 1, name: 'HDD1', capacity_mb: 8_000_000, free_mb: 1_855_000, status: 'OK', hdd_type: 'SATA', property: 'RW', model: 'WD Purple WD82PURZ', serial_number: 'DEMO-HDD-HQ-1', firmware: '80.00A80', capacity_bytes: 8_000_000_000_000, smart_status: 'OK', temperature_c: 38, power_on_hours: 14_820, smart_self_test_percent: 100 },
      { id: 2, name: 'HDD2', capacity_mb: 8_000_000, free_mb: 1_855_000, status: 'OK', hdd_type: 'SATA', property: 'RW', model: 'WD Purple WD82PURZ', serial_number: 'DEMO-HDD-HQ-2', firmware: '80.00A80', capacity_bytes: 8_000_000_000_000, smart_status: 'OK', temperature_c: 39, power_on_hours: 14_820, smart_self_test_percent: 100 },
      { id: 3, name: 'HDD3', capacity_mb: 8_000_000, free_mb: 1_855_000, status: 'OK', hdd_type: 'SATA', property: 'RW', model: 'WD Purple WD82PURZ', serial_number: 'DEMO-HDD-HQ-3', firmware: '80.00A80', capacity_bytes: 8_000_000_000_000, smart_status: 'OK', temperature_c: 40, power_on_hours: 9_140, smart_self_test_percent: 100 },
      { id: 4, name: 'HDD4', capacity_mb: 8_000_000, free_mb: 1_855_000, status: 'OK', hdd_type: 'SATA', property: 'RW', model: 'WD Purple WD82PURZ', serial_number: 'DEMO-HDD-HQ-4', firmware: '80.00A80', capacity_bytes: 8_000_000_000_000, smart_status: 'OK', temperature_c: 37, power_on_hours: 9_140, smart_self_test_percent: 100 },
    ],
  },
  {
    nvr_id: demoMediaIds.nvrBranch, total_gb: 16000, used_gb: 9420, free_gb: 6580, percent_used: 59, disk_count: 2, healthy_count: 2, unhealthy_count: 0,
    disks: [
      { id: 1, name: 'Bay 1', capacity_mb: 8_000_000, free_mb: 3_290_000, status: 'OK', hdd_type: 'SATA', property: 'RW', model: 'Seagate SkyHawk ST8000VX', serial_number: 'DEMO-HDD-BR-1', firmware: 'SC61', capacity_bytes: 8_000_000_000_000, smart_status: 'OK', temperature_c: 35, power_on_hours: 7_610, smart_self_test_percent: 100 },
      { id: 2, name: 'Bay 2', capacity_mb: 8_000_000, free_mb: 3_290_000, status: 'OK', hdd_type: 'SATA', property: 'RW', model: 'Seagate SkyHawk ST8000VX', serial_number: 'DEMO-HDD-BR-2', firmware: 'SC61', capacity_bytes: 8_000_000_000_000, smart_status: 'OK', temperature_c: 36, power_on_hours: 7_610, smart_self_test_percent: 100 },
    ],
  },
  {
    nvr_id: demoMediaIds.nvrDc, total_gb: 8000, used_gb: 6120, free_gb: 1880, percent_used: 77, disk_count: 2, healthy_count: 1, unhealthy_count: 1,
    disks: [
      { id: 1, name: 'HDD1', capacity_mb: 4_000_000, free_mb: 940_000, status: 'OK', hdd_type: 'SATA', property: 'RW', model: 'WD Purple WD43PURZ', serial_number: 'DEMO-HDD-DC-1', firmware: '80.00A80', capacity_bytes: 4_000_000_000_000, smart_status: 'OK', temperature_c: 41, power_on_hours: 22_400, smart_self_test_percent: 100 },
      { id: 2, name: 'HDD2', capacity_mb: 4_000_000, free_mb: 940_000, status: 'Warning', hdd_type: 'SATA', property: 'RW', model: 'WD Purple WD43PURZ', serial_number: 'DEMO-HDD-DC-2', firmware: '80.00A80', capacity_bytes: 4_000_000_000_000, smart_status: 'Warning', temperature_c: 46, power_on_hours: 38_910, smart_self_test_percent: 100 },
    ],
  },
];

export const demoNvrSystemInfo = [
  { nvr_id: demoMediaIds.nvrHq, device: { deviceName: 'HQ Hikvision NVR', deviceType: 'NVR', model: 'DS-7716NI-K4/16P', serialNumber: 'DEMO-NVR-HQ-7716-0001', macAddress: '02:00:00:00:40:10', firmwareVersion: 'V4.62.005', firmwareDate: 'build 230412', hardwareVersion: '0x1400', encoderVersion: 'V5.0 build 230208' }, system_status: { cpu_usage: 34, memory_usage: 52, device_up_time: 3_142_800, channel_count: 16 }, time: { device_time: iso(0), time_mode: 'NTP', time_zone: 'CST+6:00:00DST', ntp_server: '10.10.0.1', ntp_port: 123 } },
  { nvr_id: demoMediaIds.nvrBranch, device: { deviceName: 'Branch UniFi Protect', deviceType: 'NVR', model: 'UNVR-Pro', serialNumber: 'DEMO-NVR-BR-UNVR-0002', macAddress: '02:00:00:00:41:04', firmwareVersion: '4.1.13', firmwareDate: 'build 260412', hardwareVersion: 'UNVRPRO-1', encoderVersion: 'protect 6.0.44' }, system_status: { cpu_usage: 21, memory_usage: 44, device_up_time: 1_986_400, channel_count: 8 }, time: { device_time: iso(0), time_mode: 'NTP', time_zone: 'MST+7:00:00DST', ntp_server: '10.30.0.1', ntp_port: 123 } },
  { nvr_id: demoMediaIds.nvrDc, device: { deviceName: 'Datacenter Hikvision NVR', deviceType: 'NVR', model: 'DS-7608NI-K2/8P', serialNumber: 'DEMO-NVR-DC-7608-0003', macAddress: '02:00:00:00:42:10', firmwareVersion: 'V4.61.025', firmwareDate: 'build 220315', hardwareVersion: '0x1300', encoderVersion: 'V5.0 build 211220' }, system_status: { cpu_usage: 28, memory_usage: 47, device_up_time: 5_508_000, channel_count: 8 }, time: { device_time: iso(0), time_mode: 'NTP', time_zone: 'EST+5:00:00DST', ntp_server: '10.20.0.1', ntp_port: 123 } },
];

export const demoNvrNetwork = [
  { nvr_id: demoMediaIds.nvrHq, time: { device_time: iso(0), time_mode: 'NTP', time_zone: 'CST+6:00:00DST', ntp_server: '10.10.0.1', ntp_port: 123 }, interfaces: [{ id: '1', ip_address: '10.10.40.10', subnet_mask: '255.255.255.0', gateway: '10.10.40.1', primary_dns: '10.10.0.1', secondary_dns: '10.10.0.2', mac_address: '02:00:00:00:40:10', mtu: 1500, speed: '1000M', duplex: 'full', addressing_type: 'static', auto_negotiate: true, ipv6_address: '' }] },
  { nvr_id: demoMediaIds.nvrBranch, time: { device_time: iso(0), time_mode: 'NTP', time_zone: 'MST+7:00:00DST', ntp_server: '10.30.0.1', ntp_port: 123 }, interfaces: [{ id: '1', ip_address: '10.30.40.4', subnet_mask: '255.255.255.0', gateway: '10.30.40.1', primary_dns: '10.30.0.1', secondary_dns: '10.10.0.1', mac_address: '02:00:00:00:41:04', mtu: 1500, speed: '1000M', duplex: 'full', addressing_type: 'static', auto_negotiate: true, ipv6_address: '' }] },
  { nvr_id: demoMediaIds.nvrDc, time: { device_time: iso(0), time_mode: 'NTP', time_zone: 'EST+5:00:00DST', ntp_server: '10.20.0.1', ntp_port: 123 }, interfaces: [{ id: '1', ip_address: '10.20.40.10', subnet_mask: '255.255.255.0', gateway: '10.20.40.1', primary_dns: '10.20.0.1', secondary_dns: '10.10.0.1', mac_address: '02:00:00:00:42:10', mtu: 1500, speed: '1000M', duplex: 'full', addressing_type: 'static', auto_negotiate: true, ipv6_address: '' }] },
];

export const demoNvrHolidays = [
  { id: 1, enabled: true, name: 'New Year', mode: 'date', start_month: 1, start_day: 1, end_month: 1, end_day: 1 },
  { id: 2, enabled: true, name: 'Independence Day', mode: 'date', start_month: 7, start_day: 4, end_month: 7, end_day: 4 },
  { id: 3, enabled: true, name: 'Thanksgiving', mode: 'date', start_month: 11, start_day: 26, end_month: 11, end_day: 27 },
  { id: 4, enabled: true, name: 'Winter shutdown', mode: 'date', start_month: 12, start_day: 24, end_month: 12, end_day: 26 },
  { id: 5, enabled: false, name: 'Reserved', mode: 'date', start_month: 1, start_day: 1, end_month: 1, end_day: 1 },
];

// ── Recording templates and per-camera access grants ───────────────────────
export const demoRecordingTemplates = [
  { id: 'rtpl-continuous', name: 'Continuous 24/7', description: 'Always recording, used on entrances and the datacenter cages', is_builtin: true, schedule: { type: 'continuous', days: ['mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun'], start: '00:00', end: '23:59' } },
  { id: 'rtpl-business-hours', name: 'Business hours motion', description: 'Motion-only 07:00-19:00 on weekdays', is_builtin: false, schedule: { type: 'motion', days: ['mon', 'tue', 'wed', 'thu', 'fri'], start: '07:00', end: '19:00' } },
  { id: 'rtpl-after-hours', name: 'After hours alarm', description: 'Event recording overnight and at weekends', is_builtin: false, schedule: { type: 'event', days: ['mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun'], start: '19:00', end: '07:00' } },
];

export const demoCameraAccessGrants = [
  { id: 'cag-0001', user_id: '10000000-0000-4000-8000-000000000002', camera_id: null, group_id: 'cgrp-entrances', access_level: 'viewer', can_live: true, can_playback: true, can_ptz: false, can_export: false, can_configure: false, expires_at: null, created_at: iso(4320), user_email: 'front-desk@freesdn.local', user_name: 'Front Desk (shared)' },
  { id: 'cag-0002', user_id: '10000000-0000-4000-8000-000000000003', camera_id: null, group_id: 'cgrp-perimeter', access_level: 'operator', can_live: true, can_playback: true, can_ptz: true, can_export: true, can_configure: false, expires_at: null, created_at: iso(8640), user_email: 'security@freesdn.local', user_name: 'Security Operations' },
  { id: 'cag-0003', user_id: '10000000-0000-4000-8000-000000000004', camera_id: 'cam-dc-mantrap', group_id: null, access_level: 'viewer', can_live: true, can_playback: true, can_ptz: false, can_export: true, can_configure: false, expires_at: iso(-20160), created_at: iso(1440), user_email: 'auditor@freesdn.local', user_name: 'External Auditor (time limited)' },
];

// ── Live camera health (CameraHealthResponse: bitrate/fps/codec live HERE,
//    not on the camera record - see backend schemas.py CameraHealthResponse) ──
export const demoCameraHealth = demoCameras.map((c) => {
  const online = c.status === 'online';
  return {
    camera_id: c.id,
    is_online: online,
    bitrate_kbps: online ? Math.round((c.resolution_width * c.resolution_height) / 1_400_000) * 1024 : null,
    frame_rate: online ? (c.vendor === 'unifi_protect' ? 30 : c.camera_type === 'ptz_camera' ? 25 : 20) : null,
    codec: c.vendor === 'hikvision' ? 'H.265' : 'H.264',
    resolution_width: online ? c.resolution_width : null,
    resolution_height: online ? c.resolution_height : null,
    captured_at: iso(2),
  };
});

// ═══════════════════════════════════════════════════════════════════════════
// VoIP: two FreePBX systems, 38 extensions, 40 endpoints
// ═══════════════════════════════════════════════════════════════════════════
// Shapes follow backend/app/modules/voip/schemas.py (PBXResponse,
// PhoneResponse) and api.py `_flatten_ext` for extensions.
export const demoPbxSystems = [
  { id: demoMediaIds.pbxHq, site_id: demoIds.hq, name: 'FreePBX Voice', description: 'Primary PBX at HQ, voice VLAN 10.10.30.0/24', pbx_type: 'freepbx', ip_address: '10.10.30.10', api_port: 443, sip_port: 5060, is_active: true, last_seen: iso(2), extension_count: 26, settings: { asterisk_version: '20.9.2', freepbx_version: '17.0.19.20', transport: 'tls', ami_enabled: true, needs_reload: false }, created_at: iso(20160), updated_at: iso(5) },
  { id: demoMediaIds.pbxBranch, site_id: demoIds.branch, name: 'Branch FreePBX', description: 'Branch office PBX with its own SIP trunk', pbx_type: 'freepbx', ip_address: '10.30.30.10', api_port: 443, sip_port: 5060, is_active: true, last_seen: iso(4), extension_count: 12, settings: { asterisk_version: '20.9.2', freepbx_version: '17.0.19.20', transport: 'tls', ami_enabled: true, needs_reload: true }, created_at: iso(19000), updated_at: iso(11) },
];

export const demoVoipExtensions = [
  { n: '101', display: 'Reception', pbx: 'hq', vm: true },
  { n: '102', display: 'Dana Whitfield', pbx: 'hq', vm: true },
  { n: '103', display: 'Marcus Ellery', pbx: 'hq', vm: true },
  { n: '104', display: 'Priya Nandakumar', pbx: 'hq', vm: true },
  { n: '105', display: 'Tomas Brenner', pbx: 'hq', vm: true },
  { n: '106', display: 'Alicia Fong', pbx: 'hq', vm: true },
  { n: '107', display: 'Grant Okafor', pbx: 'hq', vm: true },
  { n: '108', display: 'Renee Castille', pbx: 'hq', vm: true },
  { n: '109', display: 'Ibrahim Salah', pbx: 'hq', vm: true },
  { n: '110', display: 'Joanna Pike', pbx: 'hq', vm: true },
  { n: '111', display: 'Derek Halloran', pbx: 'hq', vm: true },
  { n: '112', display: 'Naomi Estrada', pbx: 'hq', vm: true },
  { n: '113', display: 'Victor Lindqvist', pbx: 'hq', vm: true },
  { n: '114', display: 'Sasha Merrell', pbx: 'hq', vm: true },
  { n: '115', display: 'Conference Room A', pbx: 'hq', vm: false },
  { n: '116', display: 'Conference Room B', pbx: 'hq', vm: false },
  { n: '117', display: 'Break Room', pbx: 'hq', vm: false },
  { n: '118', display: 'Warehouse Floor', pbx: 'hq', vm: false },
  { n: '119', display: 'Shipping Desk', pbx: 'hq', vm: true },
  { n: '120', display: 'Owen Marsh', pbx: 'hq', vm: true },
  { n: '121', display: 'Leah Duarte', pbx: 'hq', vm: true },
  { n: '122', display: 'Kai Sorensen', pbx: 'hq', vm: true },
  { n: '123', display: 'Freya Bennington', pbx: 'hq', vm: true },
  { n: '124', display: 'Security Desk', pbx: 'hq', vm: true },
  { n: '125', display: 'Lobby Paging', pbx: 'hq', vm: false },
  { n: '126', display: 'Fax Line', pbx: 'hq', vm: false },
  { n: '201', display: 'Branch Reception', pbx: 'branch', vm: true },
  { n: '202', display: 'Hana Lindgren', pbx: 'branch', vm: true },
  { n: '203', display: 'Paulo Restrepo', pbx: 'branch', vm: true },
  { n: '204', display: 'Mei-Ling Zhou', pbx: 'branch', vm: true },
  { n: '205', display: 'Curtis Yardley', pbx: 'branch', vm: true },
  { n: '206', display: 'Angela Boateng', pbx: 'branch', vm: true },
  { n: '207', display: 'Devin Kaur', pbx: 'branch', vm: true },
  { n: '208', display: 'Stockroom', pbx: 'branch', vm: false },
  { n: '209', display: 'Branch Conference', pbx: 'branch', vm: false },
  { n: '210', display: 'Branch Break Room', pbx: 'branch', vm: false },
  { n: '211', display: 'Loading Bay', pbx: 'branch', vm: false },
  { n: '212', display: 'Branch Fax Line', pbx: 'branch', vm: false },
].map((e) => ({
  id: `ext-${e.n}`,
  pbx_id: e.pbx === 'hq' ? demoMediaIds.pbxHq : demoMediaIds.pbxBranch,
  extension_number: e.n,
  display_name: e.display,
  caller_id_name: e.display,
  caller_id_number: e.n,
  voicemail_enabled: e.vm,
  // The API masks a stored PIN as "****" and sends null when none is set.
  voicemail_pin: e.vm ? '****' : null,
  is_active: true,
  created_at: iso(20160),
  updated_at: iso(2880),
  settings: { tech: 'PJSIP', ringtimer: 20, mohclass: 'default', dnd: 'no' },
}));

export const demoVoipPhones = [
  { n: 101, name: 'Reception Phone 101', model: 'GXP2170', fw: '1.0.11.74', site: 'hq', loc: 'HQ reception', status: 'online', life: 'managed', seen: 3 },
  { n: 102, name: 'Office Manager 102', model: 'GRP2614', fw: '1.0.11.88', site: 'hq', loc: 'HQ level 2 office', status: 'online', life: 'managed', seen: 2 },
  { n: 103, name: 'Sales 103', model: 'GRP2614', fw: '1.0.11.88', site: 'hq', loc: 'HQ sales floor', status: 'in_call', life: 'managed', seen: 1 },
  { n: 104, name: 'Sales 104', model: 'GRP2614', fw: '1.0.11.88', site: 'hq', loc: 'HQ sales floor', status: 'online', life: 'managed', seen: 2 },
  { n: 105, name: 'Sales 105', model: 'GRP2612P', fw: '1.0.11.88', site: 'hq', loc: 'HQ sales floor', status: 'online', life: 'managed', seen: 4 },
  { n: 106, name: 'Support 106', model: 'GRP2613', fw: '1.0.11.88', site: 'hq', loc: 'HQ support pod', status: 'online', life: 'managed', seen: 1 },
  { n: 107, name: 'Support 107', model: 'GRP2613', fw: '1.0.11.88', site: 'hq', loc: 'HQ support pod', status: 'ringing', life: 'managed', seen: 1 },
  { n: 108, name: 'Support 108', model: 'GRP2613', fw: '1.0.11.88', site: 'hq', loc: 'HQ support pod', status: 'online', life: 'managed', seen: 2 },
  { n: 109, name: 'Support 109', model: 'GRP2612P', fw: '1.0.9.42', site: 'hq', loc: 'HQ support pod', status: 'offline', life: 'managed', seen: 640 },
  { n: 110, name: 'Accounts 110', model: 'GRP2612P', fw: '1.0.11.88', site: 'hq', loc: 'HQ accounts', status: 'online', life: 'managed', seen: 3 },
  { n: 111, name: 'Accounts 111', model: 'GRP2612P', fw: '1.0.11.88', site: 'hq', loc: 'HQ accounts', status: 'online', life: 'managed', seen: 5 },
  { n: 112, name: 'HR 112', model: 'GRP2614', fw: '1.0.11.88', site: 'hq', loc: 'HQ level 2 office', status: 'online', life: 'managed', seen: 6 },
  { n: 113, name: 'IT 113', model: 'GRP2615', fw: '1.0.11.88', site: 'hq', loc: 'HQ IT room', status: 'online', life: 'managed', seen: 1 },
  { n: 114, name: 'IT 114', model: 'GRP2614', fw: '1.0.11.74', site: 'hq', loc: 'HQ IT room', status: 'online', life: 'firmware_updating', seen: 1 },
  { n: 115, name: 'Conference Room A', model: 'GAC2570', fw: '1.0.3.9', site: 'hq', loc: 'HQ conference A', status: 'online', life: 'managed', seen: 8 },
  { n: 116, name: 'Conference Room B', model: 'GAC2570', fw: '1.0.3.9', site: 'hq', loc: 'HQ conference B', status: 'online', life: 'managed', seen: 12 },
  { n: 117, name: 'Break Room Phone', model: 'GXP1625', fw: '1.0.7.10', site: 'hq', loc: 'HQ break room', status: 'online', life: 'managed', seen: 15 },
  { n: 118, name: 'Warehouse Handset', model: 'WP822', fw: '1.0.9.5', site: 'hq', loc: 'HQ warehouse floor', status: 'online', life: 'managed', seen: 2 },
  { n: 119, name: 'Shipping Desk', model: 'GXP1625', fw: '1.0.7.10', site: 'hq', loc: 'HQ shipping desk', status: 'online', life: 'managed', seen: 4 },
  { n: 120, name: 'Operations 120', model: 'GRP2612P', fw: '1.0.11.88', site: 'hq', loc: 'HQ operations', status: 'in_call', life: 'managed', seen: 1 },
  { n: 121, name: 'Operations 121', model: 'GRP2612P', fw: '1.0.11.88', site: 'hq', loc: 'HQ operations', status: 'online', life: 'managed', seen: 3 },
  { n: 122, name: 'Marketing 122', model: 'GRP2613', fw: '1.0.11.88', site: 'hq', loc: 'HQ marketing', status: 'online', life: 'managed', seen: 7 },
  { n: 123, name: 'Marketing 123', model: 'GRP2613', fw: '1.0.11.88', site: 'hq', loc: 'HQ marketing', status: 'online', life: 'managed', seen: 9 },
  { n: 124, name: 'Security Desk', model: 'GXP1625', fw: '1.0.7.10', site: 'hq', loc: 'HQ security desk', status: 'online', life: 'managed', seen: 1 },
  { n: 125, name: 'Lobby Paging Speaker', model: 'GSC3510', fw: '1.0.7.10', site: 'hq', loc: 'HQ lobby ceiling', status: 'online', life: 'managed', seen: 6 },
  { n: 126, name: 'Fax ATA', model: 'HT802', fw: '1.0.53.5', site: 'hq', loc: 'HQ mail room', status: 'online', life: 'managed', seen: 11 },
  { n: 201, name: 'Branch Reception', model: 'GXP2170', fw: '1.0.11.74', site: 'branch', loc: 'Branch reception', status: 'online', life: 'managed', seen: 2 },
  { n: 202, name: 'Branch Manager 202', model: 'GRP2614', fw: '1.0.11.88', site: 'branch', loc: 'Branch manager office', status: 'online', life: 'managed', seen: 3 },
  { n: 203, name: 'Branch Sales 203', model: 'GRP2613', fw: '1.0.11.88', site: 'branch', loc: 'Branch sales desk', status: 'online', life: 'managed', seen: 1 },
  { n: 204, name: 'Branch Sales 204', model: 'GRP2613', fw: '1.0.11.88', site: 'branch', loc: 'Branch sales desk', status: 'online', life: 'managed', seen: 4 },
  { n: 205, name: 'Branch Service 205', model: 'GRP2612P', fw: '1.0.11.88', site: 'branch', loc: 'Branch service bay', status: 'in_call', life: 'managed', seen: 1 },
  { n: 206, name: 'Branch Service 206', model: 'GRP2612P', fw: '1.0.11.88', site: 'branch', loc: 'Branch service bay', status: 'online', life: 'managed', seen: 5 },
  { n: 207, name: 'Branch Service 207', model: 'GRP2612P', fw: '1.0.11.88', site: 'branch', loc: 'Branch service bay', status: 'offline', life: 'maintenance', seen: 2880 },
  { n: 208, name: 'Stockroom Handset', model: 'WP822', fw: '1.0.9.5', site: 'branch', loc: 'Branch stockroom', status: 'online', life: 'managed', seen: 6 },
  { n: 209, name: 'Branch Conference', model: 'GAC2570', fw: '1.0.3.9', site: 'branch', loc: 'Branch conference room', status: 'online', life: 'managed', seen: 22 },
  { n: 210, name: 'Branch Break Room', model: 'GXP1625', fw: '1.0.7.10', site: 'branch', loc: 'Branch break room', status: 'online', life: 'managed', seen: 18 },
  { n: 211, name: 'Loading Bay Speaker', model: 'GSC3510', fw: '1.0.7.10', site: 'branch', loc: 'Branch loading bay', status: 'online', life: 'managed', seen: 9 },
  { n: 212, name: 'Branch Fax ATA', model: 'HT802', fw: '1.0.53.5', site: 'branch', loc: 'Branch back office', status: 'online', life: 'managed', seen: 14 },
  { n: 180, name: 'Unclaimed handset 10.10.30.180', model: 'T33G', fw: '124.86.0.50', site: 'hq', loc: 'HQ level 2 office', status: 'online', life: 'discovered', seen: 26 },
  { n: 181, name: 'Unclaimed handset 10.30.30.181', model: 'VVX 250', fw: '6.4.6.2731', site: 'branch', loc: 'Branch back office', status: 'online', life: 'discovered', seen: 31 },
].map((p, index) => {
  // Everything below is derived so the roster stays internally consistent:
  // the extension number is the host octet, and the MAC low byte is that
  // same number in hex (which is where the existing dev-phone-101 MAC came from).
  const hq = p.site === 'hq';
  const discovered = p.life === 'discovered';
  const ext = discovered ? null : String(p.n);
  const vendor = p.model === 'T33G' ? 'yealink' : p.model.startsWith('VVX') ? 'poly' : 'grandstream';
  const target = [
    ['GXP2170', '1.0.11.88'], ['GRP2612P', '1.0.11.88'], ['GRP2613', '1.0.11.88'],
    ['GRP2614', '1.0.11.88'], ['GRP2615', '1.0.11.88'], ['GAC2570', '1.0.3.9'],
    ['GXP1625', '1.0.7.10'], ['GSC3510', '1.0.7.10'], ['WP822', '1.0.9.5'], ['HT802', '1.0.53.5'],
  ].find(([m]) => m === p.model)?.[1] ?? null;
  const ip = hq ? `10.10.30.${p.n}` : `10.30.30.${p.n}`;
  const mac = `02:00:00:00:${hq ? '30' : '31'}:${p.n.toString(16)}`;
  const offline = p.status === 'offline';
  const provision = discovered
    ? 'pending'
    : p.life === 'firmware_updating'
      ? 'pushed'
      : offline && p.fw !== target
        ? 'stale'
        : 'applied';
  return {
    id: p.n === 101 ? 'dev-phone-101' : `ph-${hq ? 'hq' : 'br'}-${p.n}`,
    site_id: hq ? demoIds.hq : demoIds.branch,
    pbx_id: discovered ? null : hq ? demoMediaIds.pbxHq : demoMediaIds.pbxBranch,
    extension_id: ext ? `ext-${ext}` : null,
    config_template_id: discovered ? null : hq ? 'vtpl-hq-desk' : 'vtpl-branch-desk',
    controller_id: null,
    name: p.name,
    description: ext ? `${p.model} bound to extension ${ext}` : `${p.model} seen on the voice VLAN, not yet onboarded`,
    ip_address: ip,
    mac_address: mac,
    vendor,
    model: p.model,
    firmware_version: p.fw,
    serial_number: `DEMO-${vendor.toUpperCase()}-${mac.replace(/:/g, '').slice(-6).toUpperCase()}`,
    status: p.status,
    last_seen: iso(p.seen),
    lifecycle_state: p.life,
    discovery_method: discovered ? 'subnet_scan' : 'pbx_sync',
    discovered_at: iso(20160),
    onboarded_at: discovered ? null : iso(19800),
    provision_status: provision,
    last_provisioned_at: provision === 'pending' ? null : iso(1440 + index * 3),
    config_checksum: provision === 'applied' ? `sha256:${mac.replace(/:/g, '')}0demo` : null,
    firmware_target: target,
    uptime_seconds: offline ? 0 : 240_000 + index * 9_400,
    sip_registered: !offline && !discovered,
    sip_server: discovered ? null : hq ? '10.10.30.10' : '10.30.30.10',
    last_reboot: offline ? iso(p.seen) : iso(4320 + index * 11),
    cpu_usage: offline ? 0 : 6 + (index % 7),
    memory_usage: offline ? 0 : 28 + (index % 11),
    subnet: hq ? '10.10.30.0/24' : '10.30.30.0/24',
    vlan_id: 30,
    lldp_switch_port: p.model.startsWith('WP') ? 'wifi' : `Gi1/0/${6 + (index % 40)}`,
    location: p.loc,
    tags: discovered ? ['unclaimed'] : hq ? ['hq', 'desk'] : ['branch', 'desk'],
    // No credentials in the demo: settings deliberately carries no web_password,
    // which is also what gates PhoneDetailPage's live-status poll.
    settings: { transport: 'tls', srtp: true, codec_priority: ['OPUS', 'G722', 'PCMU'], provisioning: 'https', vlan_id: 30 },
    created_at: iso(20160),
    updated_at: iso(p.seen),
    // Joined by the service layer on the list/detail path.
    extension: ext,
    extension_display: ext ? `${ext} - ${p.name}` : null,
    pbx_system_id: discovered ? null : hq ? demoMediaIds.pbxHq : demoMediaIds.pbxBranch,
    pbx_system_name: discovered ? null : hq ? 'FreePBX Voice' : 'Branch FreePBX',
    sip_user: ext,
  };
});

/** Extension id -> the phones bound to it, in the `_flatten_ext` bound_phones shape. */
export const demoBoundPhones = demoVoipPhones
  .filter((p) => p.extension_id !== null)
  .map((p) => ({
    extension_id: p.extension_id,
    id: p.id,
    name: p.name,
    ip_address: p.ip_address,
    mac_address: p.mac_address,
    vendor: p.vendor,
    model: p.model,
    firmware_version: p.firmware_version,
    status: p.status,
    sip_registered: p.sip_registered,
    lifecycle_state: p.lifecycle_state,
  }));

// ── Ring groups (voip.ring_groups columns) ─────────────────────────────────
export const demoRingGroups = [
  { id: 'rg-600', pbx_id: demoMediaIds.pbxHq, name: 'Sales Team', description: 'Rings every sales desk at HQ', group_number: '600', ring_strategy: 'ringall', ring_time: 20, members: ['103', '104', '105'], is_active: true, settings: { destination_if_no_answer: 'Voicemail 101' }, created_at: iso(20160), updated_at: iso(2880) },
  { id: 'rg-601', pbx_id: demoMediaIds.pbxHq, name: 'Support Desk', description: 'Hunt group for tier 1 support', group_number: '601', ring_strategy: 'hunt', ring_time: 25, members: ['106', '107', '108', '109'], is_active: true, settings: { destination_if_no_answer: 'Queue 700' }, created_at: iso(20160), updated_at: iso(2880) },
  { id: 'rg-602', pbx_id: demoMediaIds.pbxHq, name: 'All Staff', description: 'Everyone at HQ, used for emergencies only', group_number: '602', ring_strategy: 'ringall', ring_time: 30, members: ['101', '102', '103', '104', '105', '106', '107', '108', '110', '111', '112', '113', '114'], is_active: true, settings: { destination_if_no_answer: 'Hangup' }, created_at: iso(20160), updated_at: iso(4320) },
  { id: 'rg-603', pbx_id: demoMediaIds.pbxHq, name: 'Warehouse', description: 'Warehouse floor and shipping desk', group_number: '603', ring_strategy: 'memoryhunt', ring_time: 20, members: ['118', '119'], is_active: true, settings: { destination_if_no_answer: 'Reception 101' }, created_at: iso(19000), updated_at: iso(4320) },
  { id: 'rg-610', pbx_id: demoMediaIds.pbxBranch, name: 'Branch Front', description: 'Reception and the branch manager', group_number: '610', ring_strategy: 'ringall', ring_time: 20, members: ['201', '202'], is_active: true, settings: { destination_if_no_answer: 'Voicemail 201' }, created_at: iso(19000), updated_at: iso(2880) },
  { id: 'rg-611', pbx_id: demoMediaIds.pbxBranch, name: 'Branch Service', description: 'Service bay hunt group', group_number: '611', ring_strategy: 'hunt', ring_time: 25, members: ['205', '206', '207'], is_active: true, settings: { destination_if_no_answer: 'Queue 710' }, created_at: iso(19000), updated_at: iso(2880) },
];

// ── Adapter-backed PBX sub-resources ───────────────────────────────────────
// QueueResponse/TrunkResponse field names, plus the aliases VoIPPage's own
// local CallQueue/SIPTrunk interfaces read (see notes: FE/BE name drift).
export const demoCallQueues = [
  { pbx_id: demoMediaIds.pbxHq, id: 700, queue_number: '700', name: '700', display_name: 'Support Queue', strategy: 'ringall', members: [{ interface: 'PJSIP/106', name: 'Alicia Fong', paused: false }, { interface: 'PJSIP/107', name: 'Grant Okafor', paused: false }, { interface: 'PJSIP/108', name: 'Renee Castille', paused: false }, { interface: 'PJSIP/109', name: 'Ibrahim Salah', paused: true }], member_count: 4, callers_waiting: 2, calls_waiting: 2, current_callers: 2, available_agents: 3, calls_taken: 148, holdtime: 42, talk_time: 268, completed: 141, abandoned: 7, service_level: 88, settings: { timeout: 300, wrapuptime: 15 } },
  { pbx_id: demoMediaIds.pbxHq, id: 701, queue_number: '701', name: '701', display_name: 'Sales Queue', strategy: 'leastrecent', members: [{ interface: 'PJSIP/103', name: 'Marcus Ellery', paused: false }, { interface: 'PJSIP/104', name: 'Priya Nandakumar', paused: false }, { interface: 'PJSIP/105', name: 'Tomas Brenner', paused: false }], member_count: 3, callers_waiting: 0, calls_waiting: 0, current_callers: 0, available_agents: 3, calls_taken: 96, holdtime: 21, talk_time: 412, completed: 93, abandoned: 3, service_level: 94, settings: { timeout: 240, wrapuptime: 20 } },
  { pbx_id: demoMediaIds.pbxBranch, id: 710, queue_number: '710', name: '710', display_name: 'Branch Service Queue', strategy: 'fewestcalls', members: [{ interface: 'PJSIP/205', name: 'Curtis Yardley', paused: false }, { interface: 'PJSIP/206', name: 'Angela Boateng', paused: false }, { interface: 'PJSIP/207', name: 'Devin Kaur', paused: true }], member_count: 3, callers_waiting: 1, calls_waiting: 1, current_callers: 1, available_agents: 2, calls_taken: 54, holdtime: 63, talk_time: 305, completed: 49, abandoned: 5, service_level: 81, settings: { timeout: 300, wrapuptime: 15 } },
];

export const demoSipTrunks = [
  { pbx_id: demoMediaIds.pbxHq, id: 1, trunk_id: '1', name: 'Primary SIP Trunk', trunk_type: 'pjsip', technology: 'PJSIP', host: 'sip.northline.example', port: 5061, username: 'demo-hq-trunk', status: 'registered', is_registered: true, channels_used: 4, active_channels: 4, max_channels: 20, provider: 'Northline Telecom', settings: { transport: 'tls', codecs: 'opus,g722,ulaw', context: 'from-trunk', outcid: '+15550100', dtmfmode: 'rfc4733', media_encryption: 'sdes', qualify_frequency: 60 } },
  { pbx_id: demoMediaIds.pbxHq, id: 2, trunk_id: '2', name: 'Backup SIP Trunk', trunk_type: 'pjsip', technology: 'PJSIP', host: 'sip.cedarline.example', port: 5061, username: 'demo-hq-backup', status: 'registered', is_registered: true, channels_used: 0, active_channels: 0, max_channels: 10, provider: 'Cedarline Voice', settings: { transport: 'tls', codecs: 'g722,ulaw', context: 'from-trunk', outcid: '+15550100', dtmfmode: 'rfc4733', media_encryption: 'sdes', qualify_frequency: 60 } },
  { pbx_id: demoMediaIds.pbxBranch, id: 3, trunk_id: '1', name: 'Branch SIP Trunk', trunk_type: 'pjsip', technology: 'PJSIP', host: 'sip.northline.example', port: 5061, username: 'demo-br-trunk', status: 'registered', is_registered: true, channels_used: 1, active_channels: 1, max_channels: 8, provider: 'Northline Telecom', settings: { transport: 'tls', codecs: 'opus,g722,ulaw', context: 'from-trunk', outcid: '+15550110', dtmfmode: 'rfc4733', media_encryption: 'sdes', qualify_frequency: 60 } },
];

export const demoIvrs = [
  { pbx_id: demoMediaIds.pbxHq, ivr_id: '1', name: 'Main Menu', description: 'Daytime auto attendant on the main line', announcement: 'welcome-main', direct_dial: true, timeout: 10, entries: [{ digit: '1', destination: 'Sales Queue (701)' }, { digit: '2', destination: 'Support Queue (700)' }, { digit: '3', destination: 'Accounts (110)' }, { digit: '0', destination: 'Reception (101)' }], settings: { invalid_retries: 3, timeout_destination: 'Reception (101)' } },
  { pbx_id: demoMediaIds.pbxHq, ivr_id: '2', name: 'After Hours', description: 'Out of hours message and voicemail drop', announcement: 'after-hours', direct_dial: false, timeout: 8, entries: [{ digit: '1', destination: 'Voicemail 101' }, { digit: '9', destination: 'Emergency ring group (602)' }], settings: { invalid_retries: 2, timeout_destination: 'Voicemail 101' } },
];

export const demoDids = [
  { pbx: 'hq', did: '+15550100', dest: 'IVR: Main Menu', desc: 'Main published number', fax: 'off', delay: '0' },
  { pbx: 'hq', did: '+15550101', dest: 'Queue: Sales Queue (701)', desc: 'Sales direct line', fax: 'off', delay: '0' },
  { pbx: 'hq', did: '+15550102', dest: 'Queue: Support Queue (700)', desc: 'Support direct line', fax: 'off', delay: '0' },
  { pbx: 'hq', did: '+15550103', dest: 'Extension: 110', desc: 'Accounts direct dial', fax: 'off', delay: '0' },
  { pbx: 'hq', did: '+15550104', dest: 'Extension: 126', desc: 'Inbound fax', fax: 'on', delay: '2' },
  { pbx: 'branch', did: '+15550110', dest: 'Ring group: Branch Front (610)', desc: 'Branch published number', fax: 'off', delay: '0' },
].map((d) => ({
  pbx_id: d.pbx === 'hq' ? demoMediaIds.pbxHq : demoMediaIds.pbxBranch,
  cidnum: '',
  extension: d.did,
  destination: d.dest,
  description: d.desc,
  fanswer: d.fax,
  delay_answer: d.delay,
  privacyman: 'off',
  alertinfo: '',
  ringing: 'default',
  mohclass: 'default',
  grppre: '',
  pricid: '',
  pmmaxretries: '',
  pmminlength: '',
  reversal: '',
  rvolume: '',
  indication_zone: 'us',
}));

export const demoActiveCalls = [
  { pbx_id: demoMediaIds.pbxHq, channel: 'PJSIP/103-000012ab', caller_id_name: 'Marcus Ellery', caller_id_num: '103', connected_line_name: 'Northline Supply', connected_line_num: '+15550163', state: 'Up', application: 'Dial', duration: 412, bridge_id: 'bridge-000012ab', context: 'from-internal', extension: '+15550163' },
  { pbx_id: demoMediaIds.pbxHq, channel: 'PJSIP/120-000012c4', caller_id_name: 'Owen Marsh', caller_id_num: '120', connected_line_name: 'Harborline Freight', connected_line_num: '+15550172', state: 'Up', application: 'Dial', duration: 96, bridge_id: 'bridge-000012c4', context: 'from-internal', extension: '+15550172' },
  { pbx_id: demoMediaIds.pbxHq, channel: 'PJSIP/anonymous-000012d0', caller_id_name: '', caller_id_num: '+15550188', connected_line_name: 'Support Queue', connected_line_num: '700', state: 'Ring', application: 'Queue', duration: 38, bridge_id: '', context: 'from-trunk', extension: '700' },
  { pbx_id: demoMediaIds.pbxBranch, channel: 'PJSIP/205-00000771', caller_id_name: 'Curtis Yardley', caller_id_num: '205', connected_line_name: '', connected_line_num: '+15550174', state: 'Up', application: 'Dial', duration: 187, bridge_id: 'bridge-00000771', context: 'from-internal', extension: '+15550174' },
];

// ── Call detail records (voip.call_logs columns + the pbx_system_* the
//    list endpoint joins on). External numbers use the reserved fictional
//    555-01xx block. ─────────────────────────────────────────────────────────
export const demoCallLogs = [
  { n: 1, from: '+15550188', fname: '', to: '700', tname: 'Support Queue', dir: 'inbound', st: 'answered', dur: 214, ring: 12, mins: 4, pbx: 'hq', rec: true },
  { n: 2, from: '103', fname: 'Marcus Ellery', to: '+15550163', tname: 'Northline Supply', dir: 'outbound', st: 'answered', dur: 412, ring: 6, mins: 7, pbx: 'hq', rec: false },
  { n: 3, from: '+15550151', fname: '', to: '601', tname: 'Support Desk', dir: 'inbound', st: 'answered', dur: 168, ring: 9, mins: 14, pbx: 'hq', rec: true },
  { n: 4, from: '120', fname: 'Owen Marsh', to: '108', tname: 'Renee Castille', dir: 'internal', st: 'answered', dur: 96, ring: 4, mins: 18, pbx: 'hq', rec: false },
  { n: 5, from: '+15550174', fname: '', to: '610', tname: 'Branch Front', dir: 'inbound', st: 'answered', dur: 187, ring: 11, mins: 22, pbx: 'branch', rec: false },
  { n: 6, from: '+15550129', fname: '', to: '+15550100', tname: 'Main Menu', dir: 'inbound', st: 'missed', dur: 0, ring: 30, mins: 27, pbx: 'hq', rec: false },
  { n: 7, from: '104', fname: 'Priya Nandakumar', to: '+15550117', tname: '', dir: 'outbound', st: 'answered', dur: 305, ring: 8, mins: 33, pbx: 'hq', rec: false },
  { n: 8, from: '+15550193', fname: 'Cedarline Voice', to: '701', tname: 'Sales Queue', dir: 'inbound', st: 'answered', dur: 141, ring: 7, mins: 38, pbx: 'hq', rec: true },
  { n: 9, from: '106', fname: 'Alicia Fong', to: '+15550122', tname: '', dir: 'outbound', st: 'no_answer', dur: 0, ring: 26, mins: 44, pbx: 'hq', rec: false },
  { n: 10, from: '+15550135', fname: '', to: '700', tname: 'Support Queue', dir: 'inbound', st: 'answered', dur: 268, ring: 18, mins: 51, pbx: 'hq', rec: true },
  { n: 11, from: '205', fname: 'Curtis Yardley', to: '+15550174', tname: '', dir: 'outbound', st: 'answered', dur: 187, ring: 5, mins: 57, pbx: 'branch', rec: false },
  { n: 12, from: '101', fname: 'Reception', to: '113', tname: 'Victor Lindqvist', dir: 'internal', st: 'answered', dur: 58, ring: 3, mins: 63, pbx: 'hq', rec: false },
  { n: 13, from: '+15550166', fname: '', to: '+15550102', tname: 'Support direct', dir: 'inbound', st: 'voicemail', dur: 44, ring: 25, mins: 70, pbx: 'hq', rec: false },
  { n: 14, from: '202', fname: 'Hana Lindgren', to: '102', tname: 'Dana Whitfield', dir: 'internal', st: 'answered', dur: 231, ring: 4, mins: 76, pbx: 'branch', rec: false },
  { n: 15, from: '+15550148', fname: '', to: '710', tname: 'Branch Service Queue', dir: 'inbound', st: 'answered', dur: 322, ring: 21, mins: 83, pbx: 'branch', rec: true },
  { n: 16, from: '110', fname: 'Joanna Pike', to: '+15550190', tname: '', dir: 'outbound', st: 'busy', dur: 0, ring: 9, mins: 91, pbx: 'hq', rec: false },
  { n: 17, from: '+15550107', fname: '', to: '600', tname: 'Sales Team', dir: 'inbound', st: 'answered', dur: 176, ring: 13, mins: 98, pbx: 'hq', rec: false },
  { n: 18, from: '107', fname: 'Grant Okafor', to: '+15550158', tname: '', dir: 'outbound', st: 'answered', dur: 512, ring: 7, mins: 106, pbx: 'hq', rec: true },
  { n: 19, from: '+15550181', fname: '', to: '+15550100', tname: 'Main Menu', dir: 'inbound', st: 'answered', dur: 89, ring: 6, mins: 115, pbx: 'hq', rec: false },
  { n: 20, from: '119', fname: 'Shipping Desk', to: '118', tname: 'Warehouse Floor', dir: 'internal', st: 'answered', dur: 41, ring: 3, mins: 123, pbx: 'hq', rec: false },
  { n: 21, from: '+15550143', fname: '', to: '700', tname: 'Support Queue', dir: 'inbound', st: 'missed', dur: 0, ring: 45, mins: 132, pbx: 'hq', rec: false },
  { n: 22, from: '203', fname: 'Paulo Restrepo', to: '+15550111', tname: '', dir: 'outbound', st: 'answered', dur: 264, ring: 8, mins: 141, pbx: 'branch', rec: false },
  { n: 23, from: '+15550172', fname: 'Harborline Freight', to: '603', tname: 'Warehouse', dir: 'inbound', st: 'answered', dur: 133, ring: 10, mins: 151, pbx: 'hq', rec: false },
  { n: 24, from: '112', fname: 'Naomi Estrada', to: '+15550126', tname: '', dir: 'outbound', st: 'answered', dur: 398, ring: 12, mins: 162, pbx: 'hq', rec: false },
  { n: 25, from: '+15550159', fname: '', to: '+15550101', tname: 'Sales direct', dir: 'inbound', st: 'answered', dur: 205, ring: 9, mins: 174, pbx: 'hq', rec: true },
  { n: 26, from: '206', fname: 'Angela Boateng', to: '205', tname: 'Curtis Yardley', dir: 'internal', st: 'answered', dur: 77, ring: 4, mins: 186, pbx: 'branch', rec: false },
  { n: 27, from: '+15550138', fname: '', to: '601', tname: 'Support Desk', dir: 'inbound', st: 'voicemail', dur: 51, ring: 28, mins: 199, pbx: 'hq', rec: false },
  { n: 28, from: '105', fname: 'Tomas Brenner', to: '+15550164', tname: '', dir: 'outbound', st: 'answered', dur: 611, ring: 11, mins: 213, pbx: 'hq', rec: true },
  { n: 29, from: '+15550115', fname: '', to: '+15550110', tname: 'Branch main', dir: 'inbound', st: 'answered', dur: 154, ring: 8, mins: 228, pbx: 'branch', rec: false },
  { n: 30, from: '124', fname: 'Security Desk', to: '602', tname: 'All Staff', dir: 'internal', st: 'answered', dur: 34, ring: 5, mins: 244, pbx: 'hq', rec: false },
  { n: 31, from: '+15550196', fname: '', to: '700', tname: 'Support Queue', dir: 'inbound', st: 'answered', dur: 287, ring: 16, mins: 261, pbx: 'hq', rec: true },
  { n: 32, from: '111', fname: 'Derek Halloran', to: '+15550183', tname: '', dir: 'outbound', st: 'failed', dur: 0, ring: 0, mins: 279, pbx: 'hq', rec: false },
  { n: 33, from: '+15550124', fname: '', to: '701', tname: 'Sales Queue', dir: 'inbound', st: 'answered', dur: 192, ring: 14, mins: 298, pbx: 'hq', rec: false },
  { n: 34, from: '208', fname: 'Stockroom', to: '202', tname: 'Hana Lindgren', dir: 'internal', st: 'answered', dur: 63, ring: 6, mins: 318, pbx: 'branch', rec: false },
  { n: 35, from: '+15550177', fname: '', to: '+15550104', tname: 'Inbound fax', dir: 'inbound', st: 'answered', dur: 78, ring: 2, mins: 339, pbx: 'hq', rec: false },
  { n: 36, from: '122', fname: 'Kai Sorensen', to: '+15550131', tname: '', dir: 'outbound', st: 'answered', dur: 226, ring: 9, mins: 361, pbx: 'hq', rec: false },
  { n: 37, from: '+15550169', fname: '', to: '600', tname: 'Sales Team', dir: 'inbound', st: 'missed', dur: 0, ring: 32, mins: 384, pbx: 'hq', rec: false },
  { n: 38, from: '204', fname: 'Mei-Ling Zhou', to: '+15550152', tname: '', dir: 'outbound', st: 'answered', dur: 343, ring: 7, mins: 408, pbx: 'branch', rec: false },
  { n: 39, from: '+15550105', fname: 'Westgate Property', to: '+15550100', tname: 'Main Menu', dir: 'inbound', st: 'answered', dur: 121, ring: 5, mins: 433, pbx: 'hq', rec: false },
  { n: 40, from: '113', fname: 'Victor Lindqvist', to: '114', tname: 'Sasha Merrell', dir: 'internal', st: 'answered', dur: 512, ring: 3, mins: 459, pbx: 'hq', rec: false },
  { n: 41, from: '+15550142', fname: '', to: '700', tname: 'Support Queue', dir: 'inbound', st: 'answered', dur: 176, ring: 19, mins: 1490, pbx: 'hq', rec: true },
  { n: 42, from: '108', fname: 'Renee Castille', to: '+15550137', tname: '', dir: 'outbound', st: 'answered', dur: 254, ring: 8, mins: 1585, pbx: 'hq', rec: false },
  { n: 43, from: '+15550118', fname: '', to: '610', tname: 'Branch Front', dir: 'inbound', st: 'voicemail', dur: 39, ring: 27, mins: 1712, pbx: 'branch', rec: false },
  { n: 44, from: '121', fname: 'Leah Duarte', to: '+15550149', tname: '', dir: 'outbound', st: 'answered', dur: 401, ring: 10, mins: 1840, pbx: 'hq', rec: false },
  { n: 45, from: '+15550186', fname: '', to: '601', tname: 'Support Desk', dir: 'inbound', st: 'answered', dur: 298, ring: 15, mins: 2965, pbx: 'hq', rec: true },
  { n: 46, from: '123', fname: 'Freya Bennington', to: '+15550178', tname: '', dir: 'outbound', st: 'answered', dur: 187, ring: 6, mins: 3120, pbx: 'hq', rec: false },
].map((c) => ({
  id: `cdr-${String(c.n).padStart(5, '0')}`,
  pbx_id: c.pbx === 'hq' ? demoMediaIds.pbxHq : demoMediaIds.pbxBranch,
  unique_id: `1780${String(1000000 + c.n * 137)}.${c.n}`,
  caller_number: c.from,
  caller_name: c.fname || null,
  callee_number: c.to,
  callee_name: c.tname || null,
  direction: c.dir,
  status: c.st,
  start_time: iso(c.mins),
  answer_time: c.dur > 0 ? iso(c.mins - c.ring / 60) : null,
  end_time: iso(c.mins - (c.dur + c.ring) / 60),
  duration_seconds: c.dur,
  ring_duration_seconds: c.ring,
  recording_path: c.rec ? `monitor/2026/06/07/demo-cdr-${String(c.n).padStart(5, '0')}.wav` : null,
  metadata_json: { channel: c.dir === 'inbound' ? 'from-trunk' : 'from-internal' },
  pbx_system_id: c.pbx === 'hq' ? demoMediaIds.pbxHq : demoMediaIds.pbxBranch,
  pbx_system_name: c.pbx === 'hq' ? 'FreePBX Voice' : 'Branch FreePBX',
}));

// service.get_call_stats returns exactly these three keys.
export const demoCallStats = {
  total_calls: demoCallLogs.length,
  total_duration: demoCallLogs.reduce((sum, c) => sum + c.duration_seconds, 0),
  avg_duration: demoCallLogs.reduce((sum, c) => sum + c.duration_seconds, 0) / demoCallLogs.length,
};

// ── Voicemail (voip.voicemail_messages columns) ────────────────────────────
export const demoVoicemails = [
  { n: 1, ext: '101', from: '+15550166', fname: '', dur: 44, mins: 70, read: false, urgent: false, txt: 'Calling about the delivery slot for Thursday, please call me back.' },
  { n: 2, ext: '106', from: '+15550138', fname: '', dur: 51, mins: 199, read: false, urgent: true, txt: 'Our card reader is offline again, this is the second time this week.' },
  { n: 3, ext: '110', from: '+15550190', fname: 'Northline Telecom', dur: 38, mins: 260, read: false, urgent: false, txt: 'Invoice query on the March statement, extension 4 when you call back.' },
  { n: 4, ext: '201', from: '+15550118', fname: '', dur: 39, mins: 1712, read: false, urgent: false, txt: 'Checking whether the branch is open on the holiday Monday.' },
  { n: 5, ext: '103', from: '+15550163', fname: 'Northline Supply', dur: 62, mins: 1880, read: false, urgent: false, txt: 'Quote accepted, send the order confirmation when you can.' },
  { n: 6, ext: '113', from: '114', fname: 'Sasha Merrell', dur: 27, mins: 2100, read: false, urgent: false, txt: 'Firmware push for the level 2 handsets is queued for tonight.' },
  { n: 7, ext: '101', from: '+15550129', fname: '', dur: 33, mins: 2960, read: true, urgent: false, txt: 'Wrong number, sorry.' },
  { n: 8, ext: '107', from: '+15550143', fname: '', dur: 71, mins: 3180, read: true, urgent: false, txt: 'Follow up on ticket 4412, the replacement handset arrived.' },
  { n: 9, ext: '104', from: '+15550117', fname: '', dur: 48, mins: 3600, read: true, urgent: false, txt: 'Please resend the pricing sheet, the attachment did not open.' },
  { n: 10, ext: '202', from: '+15550174', fname: '', dur: 55, mins: 4320, read: true, urgent: false, txt: 'Confirming the service appointment for next Tuesday morning.' },
  { n: 11, ext: '119', from: '+15550172', fname: 'Harborline Freight', dur: 29, mins: 4880, read: true, urgent: false, txt: 'Driver will be twenty minutes late to the dock.' },
  { n: 12, ext: '112', from: '+15550126', fname: '', dur: 84, mins: 5760, read: true, urgent: false, txt: 'Returning your call about the onboarding paperwork.' },
  { n: 13, ext: '205', from: '+15550148', fname: '', dur: 41, mins: 7200, read: true, urgent: true, txt: 'Vehicle is still under warranty, need a callback today please.' },
  { n: 14, ext: '108', from: '+15550135', fname: '', dur: 36, mins: 8640, read: true, urgent: false, txt: 'All sorted now, no callback needed. Thanks for the help.' },
].map((v) => ({
  id: `vm-${String(v.n).padStart(4, '0')}`,
  pbx_id: v.ext.startsWith('2') ? demoMediaIds.pbxBranch : demoMediaIds.pbxHq,
  extension_id: `ext-${v.ext}`,
  extension_number: v.ext,
  caller_id: v.from,
  caller_name: v.fname || null,
  duration: v.dur,
  message_date: iso(v.mins),
  is_read: v.read,
  is_urgent: v.urgent,
  transcription: v.txt,
  file_path: `/var/spool/asterisk/voicemail/default/${v.ext}/INBOX/msg${String(v.n).padStart(4, '0')}.wav`,
  folder: v.read ? 'Old' : 'INBOX',
}));

export const demoVoicemailStats = {
  total: demoVoicemails.length,
  unread: demoVoicemails.filter((v) => !v.is_read).length,
  urgent: demoVoicemails.filter((v) => v.is_urgent).length,
};

export const demoVoicemailBoxes = demoVoipExtensions
  .filter((e) => e.voicemail_enabled)
  .map((e) => ({
    pbx_id: e.pbx_id,
    mailbox: e.extension_number,
    context: 'default',
    name: e.display_name,
    email: `${e.extension_number}@freesdn.local`,
    new_messages: demoVoicemails.filter((v) => v.extension_number === e.extension_number && !v.is_read).length,
    old_messages: demoVoicemails.filter((v) => v.extension_number === e.extension_number && v.is_read).length,
    settings: { attach: 'yes', delete: 'no', tz: 'central' },
  }));

// ── Provisioning templates, discovery scans, firmware tracks ───────────────
// ConfigTemplateResponse: `phone_count` (singular) and a LIST line_key_settings.
export const demoVoipTemplates = [
  { id: 'vtpl-hq-desk', site_id: demoIds.hq, name: 'HQ desk phone', description: 'Grandstream GRP/GXP desk phones on the HQ voice VLAN', vendor: 'grandstream', model_pattern: 'GRP26*|GXP*', is_default: true, sip_settings: { registrar: '10.10.30.10', transport: 'TLS', srtp: 'enabled', register_expiration: 3600 }, network_settings: { vlan_id: 30, lldp: true, dhcp: true, ntp: '10.10.0.1' }, provisioning_settings: { protocol: 'https', check_interval_minutes: 720, config_server: 'provision.demo.local' }, feature_settings: { call_waiting: true, dnd_key: true, voicemail_key: true }, line_key_settings: [{ key: 1, type: 'account', value: '' }, { key: 2, type: 'blf', value: '101' }, { key: 3, type: 'blf', value: '113' }], raw_overrides: { P271: '1' }, firmware_version: '1.0.11.88', phone_count: 24, phones_count: 24, created_at: iso(20160), updated_at: iso(2880) },
  { id: 'vtpl-branch-desk', site_id: demoIds.branch, name: 'Branch desk phone', description: 'Branch office handsets registering to the branch PBX', vendor: 'grandstream', model_pattern: 'GRP26*|GXP*', is_default: false, sip_settings: { registrar: '10.30.30.10', transport: 'TLS', srtp: 'enabled', register_expiration: 3600 }, network_settings: { vlan_id: 30, lldp: true, dhcp: true, ntp: '10.30.0.1' }, provisioning_settings: { protocol: 'https', check_interval_minutes: 720, config_server: 'provision.demo.local' }, feature_settings: { call_waiting: true, dnd_key: true, voicemail_key: true }, line_key_settings: [{ key: 1, type: 'account', value: '' }, { key: 2, type: 'blf', value: '201' }], raw_overrides: {}, firmware_version: '1.0.11.88', phone_count: 12, phones_count: 12, created_at: iso(19000), updated_at: iso(4320) },
  { id: 'vtpl-common-area', site_id: demoIds.hq, name: 'Common area and paging', description: 'Break rooms, paging speakers and ATAs, no voicemail key', vendor: 'grandstream', model_pattern: 'GSC*|HT8*|GXP16*', is_default: false, sip_settings: { registrar: '10.10.30.10', transport: 'TLS', srtp: 'enabled', register_expiration: 3600 }, network_settings: { vlan_id: 30, lldp: true, dhcp: true, ntp: '10.10.0.1' }, provisioning_settings: { protocol: 'https', check_interval_minutes: 1440, config_server: 'provision.demo.local' }, feature_settings: { call_waiting: false, dnd_key: false, voicemail_key: false, auto_answer: true }, line_key_settings: [{ key: 1, type: 'account', value: '' }], raw_overrides: {}, firmware_version: '1.0.7.10', phone_count: 4, phones_count: 4, created_at: iso(18000), updated_at: iso(5760) },
];

export const demoVoipDiscoveryScans = [
  { id: 'vscan-0004', site_id: demoIds.hq, scan_type: 'subnet', subnet: '10.10.30.0/24', status: 'completed', started_at: iso(28), completed_at: iso(24), devices_found: 27, new_devices: 1, updated_devices: 26, duration_seconds: 214.6, results: [], error_message: null },
  { id: 'vscan-0003', site_id: demoIds.branch, scan_type: 'subnet', subnet: '10.30.30.0/24', status: 'completed', started_at: iso(1470), completed_at: iso(1466), devices_found: 13, new_devices: 1, updated_devices: 12, duration_seconds: 188.2, results: [], error_message: null },
  { id: 'vscan-0002', site_id: demoIds.hq, scan_type: 'pbx_sync', subnet: null, status: 'completed', started_at: iso(2900), completed_at: iso(2898), devices_found: 26, new_devices: 0, updated_devices: 26, duration_seconds: 96.4, results: [], error_message: null },
  { id: 'vscan-0001', site_id: demoIds.branch, scan_type: 'subnet', subnet: '10.30.30.0/24', status: 'failed', started_at: iso(5800), completed_at: iso(5796), devices_found: 0, new_devices: 0, updated_devices: 0, duration_seconds: 240, results: [], error_message: 'WAN tunnel to the branch was down for the whole scan window' },
];

export const demoVoipFirmwareTracks = [
  { id: 'vfw-grp2614', site_id: demoIds.hq, vendor: 'grandstream', model: 'GRP2614', version: '1.0.11.88', release_date: iso(10080), changelog: 'Security fixes plus BLF stability on TLS transports.', download_url: 'https://firmware.demo.local/grandstream/grp2614/1.0.11.88', file_checksum: null, file_size_bytes: 43_000_000, is_stable: true, is_recommended: true, created_at: iso(10080) },
  { id: 'vfw-grp2613', site_id: demoIds.hq, vendor: 'grandstream', model: 'GRP2613', version: '1.0.11.88', release_date: iso(10080), changelog: 'Security fixes plus BLF stability on TLS transports.', download_url: 'https://firmware.demo.local/grandstream/grp2613/1.0.11.88', file_checksum: null, file_size_bytes: 42_500_000, is_stable: true, is_recommended: true, created_at: iso(10080) },
  { id: 'vfw-gxp2170', site_id: demoIds.hq, vendor: 'grandstream', model: 'GXP2170', version: '1.0.11.88', release_date: iso(20160), changelog: 'Final maintenance release for the GXP21xx line.', download_url: 'https://firmware.demo.local/grandstream/gxp2170/1.0.11.88', file_checksum: null, file_size_bytes: 38_900_000, is_stable: true, is_recommended: true, created_at: iso(20160) },
  { id: 'vfw-gac2570', site_id: demoIds.hq, vendor: 'grandstream', model: 'GAC2570', version: '1.0.3.9', release_date: iso(14400), changelog: 'Conference bridge echo cancellation improvements.', download_url: 'https://firmware.demo.local/grandstream/gac2570/1.0.3.9', file_checksum: null, file_size_bytes: 61_200_000, is_stable: true, is_recommended: true, created_at: iso(14400) },
  { id: 'vfw-ht802', site_id: demoIds.hq, vendor: 'grandstream', model: 'HT802', version: '1.0.53.5', release_date: iso(21600), changelog: 'T.38 fax reliability fixes.', download_url: 'https://firmware.demo.local/grandstream/ht802/1.0.53.5', file_checksum: null, file_size_bytes: 9_800_000, is_stable: true, is_recommended: true, created_at: iso(21600) },
];

// ── Aggregates ─────────────────────────────────────────────────────────────
export const demoPhoneStats = {
  total: demoVoipPhones.length,
  online: demoVoipPhones.filter((p) => p.status === 'online').length,
  offline: demoVoipPhones.filter((p) => p.status === 'offline').length,
  in_call: demoVoipPhones.filter((p) => p.status === 'in_call').length,
};

export const demoVoipFleetDashboard = {
  total_phones: demoVoipPhones.length,
  online: demoPhoneStats.online,
  offline: demoPhoneStats.offline,
  in_call: demoPhoneStats.in_call,
  by_lifecycle: demoVoipPhones.reduce<Record<string, number>>((acc, p) => {
    acc[p.lifecycle_state] = (acc[p.lifecycle_state] ?? 0) + 1;
    return acc;
  }, {}),
  by_vendor: demoVoipPhones.reduce<Record<string, number>>((acc, p) => {
    acc[p.vendor] = (acc[p.vendor] ?? 0) + 1;
    return acc;
  }, {}),
  by_model: demoVoipPhones.reduce<Record<string, number>>((acc, p) => {
    acc[p.model] = (acc[p.model] ?? 0) + 1;
    return acc;
  }, {}),
  by_firmware: demoVoipPhones.reduce<Record<string, number>>((acc, p) => {
    acc[p.firmware_version] = (acc[p.firmware_version] ?? 0) + 1;
    return acc;
  }, {}),
  firmware_compliant: demoVoipPhones.filter((p) => p.firmware_target === null || p.firmware_version === p.firmware_target).length,
  firmware_non_compliant: demoVoipPhones.filter((p) => p.firmware_target !== null && p.firmware_version !== p.firmware_target).length,
  recently_discovered: demoVoipPhones.filter((p) => p.lifecycle_state === 'discovered').length,
  pending_provision: demoVoipPhones.filter((p) => p.provision_status === 'pending' || p.provision_status === 'stale').length,
  sip_registered: demoVoipPhones.filter((p) => p.sip_registered).length,
  sip_unregistered: demoVoipPhones.filter((p) => !p.sip_registered).length,
};

// ==== demo fleet: hypervisor, storage, backup ====
// ===========================================================================
// HYPERVISOR — Proxmox VE cluster "PVE Cluster A" (Datacenter, 10.20.0.0/16)
// ===========================================================================

export const demoHypervisorNodes = [
  {
    id: 'pve-node-01',
    node: 'pve-node-01',
    status: 'online',
    ip_address: '10.20.0.11',
    cpu_count: 32,
    cpu_usage: 0.36,
    cpu_percent: 36,
    memory_total: 137_438_953_472,
    memory_used: 97_710_505_984,
    memory_percent: 71.1,
    storage_total: 2_400_000_000_000,
    storage_used: 1_298_000_000_000,
    storage_percent: 54.1,
    uptime: 24_883_200,
    pve_version: '8.3.2',
    kernel_version: '6.8.12-8-pve',
    cpu_model: 'Intel(R) Xeon(R) Silver 4314 CPU @ 2.40GHz',
    subscription_level: 'community',
  },
  {
    id: 'pve-node-02',
    node: 'pve-node-02',
    status: 'online',
    ip_address: '10.20.0.12',
    cpu_count: 32,
    cpu_usage: 0.61,
    cpu_percent: 61,
    memory_total: 137_438_953_472,
    memory_used: 118_111_600_640,
    memory_percent: 85.9,
    storage_total: 2_400_000_000_000,
    storage_used: 1_563_000_000_000,
    storage_percent: 65.1,
    uptime: 15_724_800,
    pve_version: '8.3.2',
    kernel_version: '6.8.12-8-pve',
    cpu_model: 'Intel(R) Xeon(R) Silver 4314 CPU @ 2.40GHz',
    subscription_level: 'community',
  },
  {
    id: 'pve-node-03',
    node: 'pve-node-03',
    status: 'online',
    ip_address: '10.20.0.13',
    cpu_count: 24,
    cpu_usage: 0.22,
    cpu_percent: 22,
    memory_total: 103_079_215_104,
    memory_used: 73_014_444_032,
    memory_percent: 70.8,
    storage_total: 2_400_000_000_000,
    storage_used: 976_000_000_000,
    storage_percent: 40.7,
    uptime: 4_233_600,
    pve_version: '8.3.2',
    kernel_version: '6.8.12-8-pve',
    cpu_model: 'Intel(R) Xeon(R) Silver 4310 CPU @ 2.10GHz',
    subscription_level: 'none',
  },
];

/** VMs + LXC containers, templates included (the page filters `template`). */
export const demoHypervisorGuests = [
  { id: 'pve-qemu-101', vmid: 101, name: 'dc-auth-01', node: 'pve-node-01', vm_type: 'qemu', status: 'running', cpu_cores: 4, cpu_usage: 0.14, cpu_percent: 14, memory_mb: 8192, memory_used_mb: 4915, memory_percent: 60, disk_gb: 120, disk_used_gb: 48.6, disk_percent: 40.5, ip_address: '10.20.10.21', net_in: 184_320_000_000, net_out: 96_470_000_000, uptime: 3_542_400, tags: ['identity', 'prod'], template: false, ha_state: 'started', lock: null, os_type: 'l26' },
  { id: 'pve-qemu-102', vmid: 102, name: 'dc-auth-02', node: 'pve-node-02', vm_type: 'qemu', status: 'running', cpu_cores: 4, cpu_usage: 0.11, cpu_percent: 11, memory_mb: 8192, memory_used_mb: 4587, memory_percent: 56, disk_gb: 120, disk_used_gb: 46.2, disk_percent: 38.5, ip_address: '10.20.10.22', net_in: 171_900_000_000, net_out: 88_140_000_000, uptime: 3_542_400, tags: ['identity', 'prod'], template: false, ha_state: 'started', lock: null, os_type: 'l26' },
  { id: 'pve-qemu-110', vmid: 110, name: 'dc-db-01', node: 'pve-node-01', vm_type: 'qemu', status: 'running', cpu_cores: 8, cpu_usage: 0.47, cpu_percent: 47, memory_mb: 32768, memory_used_mb: 26214, memory_percent: 80, disk_gb: 512, disk_used_gb: 337.4, disk_percent: 65.9, ip_address: '10.20.10.30', net_in: 1_284_000_000_000, net_out: 942_000_000_000, uptime: 5_270_400, tags: ['database', 'prod'], template: false, ha_state: 'started', lock: null, os_type: 'l26' },
  { id: 'pve-qemu-111', vmid: 111, name: 'dc-db-02', node: 'pve-node-03', vm_type: 'qemu', status: 'running', cpu_cores: 8, cpu_usage: 0.19, cpu_percent: 19, memory_mb: 32768, memory_used_mb: 24576, memory_percent: 75, disk_gb: 512, disk_used_gb: 331.8, disk_percent: 64.8, ip_address: '10.20.10.31', net_in: 918_000_000_000, net_out: 604_000_000_000, uptime: 2_505_600, tags: ['database', 'replica'], template: false, ha_state: 'started', lock: null, os_type: 'l26' },
  { id: 'pve-qemu-120', vmid: 120, name: 'dc-app-01', node: 'pve-node-02', vm_type: 'qemu', status: 'running', cpu_cores: 4, cpu_usage: 0.38, cpu_percent: 38, memory_mb: 16384, memory_used_mb: 11469, memory_percent: 70, disk_gb: 200, disk_used_gb: 118.4, disk_percent: 59.2, ip_address: '10.20.10.40', net_in: 612_000_000_000, net_out: 488_000_000_000, uptime: 1_814_400, tags: ['app', 'prod'], template: false, ha_state: null, lock: null, os_type: 'l26' },
  { id: 'pve-qemu-121', vmid: 121, name: 'dc-app-02', node: 'pve-node-03', vm_type: 'qemu', status: 'running', cpu_cores: 4, cpu_usage: 0.29, cpu_percent: 29, memory_mb: 16384, memory_used_mb: 10240, memory_percent: 62.5, disk_gb: 200, disk_used_gb: 112.6, disk_percent: 56.3, ip_address: '10.20.10.41', net_in: 574_000_000_000, net_out: 451_000_000_000, uptime: 1_814_400, tags: ['app', 'prod'], template: false, ha_state: null, lock: null, os_type: 'l26' },
  { id: 'pve-qemu-130', vmid: 130, name: 'dc-nvr-archive', node: 'pve-node-02', vm_type: 'qemu', status: 'running', cpu_cores: 4, cpu_usage: 0.52, cpu_percent: 52, memory_mb: 16384, memory_used_mb: 12288, memory_percent: 75, disk_gb: 4096, disk_used_gb: 3102.7, disk_percent: 75.7, ip_address: '10.20.10.50', net_in: 8_940_000_000_000, net_out: 412_000_000_000, uptime: 7_776_000, tags: ['cameras', 'archive'], template: false, ha_state: null, lock: null, os_type: 'l26' },
  { id: 'pve-qemu-160', vmid: 160, name: 'dc-mail-relay', node: 'pve-node-01', vm_type: 'qemu', status: 'running', cpu_cores: 2, cpu_usage: 0.08, cpu_percent: 8, memory_mb: 4096, memory_used_mb: 2253, memory_percent: 55, disk_gb: 64, disk_used_gb: 22.8, disk_percent: 35.6, ip_address: '10.20.10.65', net_in: 62_400_000_000, net_out: 58_100_000_000, uptime: 4_320_000, tags: ['mail'], template: false, ha_state: null, lock: 'backup', os_type: 'l26' },
  { id: 'pve-qemu-170', vmid: 170, name: 'dc-app-canary', node: 'pve-node-02', vm_type: 'qemu', status: 'running', cpu_cores: 4, cpu_usage: 0.24, cpu_percent: 24, memory_mb: 16384, memory_used_mb: 8192, memory_percent: 50, disk_gb: 200, disk_used_gb: 96.4, disk_percent: 48.2, ip_address: '10.20.10.42', net_in: 41_800_000_000, net_out: 33_600_000_000, uptime: 259_200, tags: ['app', 'canary'], template: false, ha_state: null, lock: 'migrate', os_type: 'l26' },
  { id: 'pve-qemu-140', vmid: 140, name: 'hq-print-01', node: 'pve-node-01', vm_type: 'qemu', status: 'stopped', cpu_cores: 2, cpu_usage: 0, cpu_percent: 0, memory_mb: 8192, memory_used_mb: 0, memory_percent: 0, disk_gb: 80, disk_used_gb: 34.2, disk_percent: 42.8, ip_address: null, net_in: 0, net_out: 0, uptime: 0, tags: ['print'], template: false, ha_state: null, lock: null, os_type: 'win11' },
  { id: 'pve-qemu-150', vmid: 150, name: 'lab-win2022', node: 'pve-node-03', vm_type: 'qemu', status: 'stopped', cpu_cores: 4, cpu_usage: 0, cpu_percent: 0, memory_mb: 16384, memory_used_mb: 0, memory_percent: 0, disk_gb: 250, disk_used_gb: 148.6, disk_percent: 59.4, ip_address: null, net_in: 0, net_out: 0, uptime: 0, tags: ['lab'], template: false, ha_state: null, lock: null, os_type: 'win11' },
  { id: 'pve-qemu-198', vmid: 198, name: 'tmpl-ubuntu2404-cloud', node: 'pve-node-02', vm_type: 'qemu', status: 'stopped', cpu_cores: 2, cpu_usage: 0, cpu_percent: 0, memory_mb: 2048, memory_used_mb: 0, memory_percent: 0, disk_gb: 32, disk_used_gb: 2.4, disk_percent: 7.5, ip_address: null, net_in: 0, net_out: 0, uptime: 0, tags: ['template'], template: true, ha_state: null, lock: null, os_type: 'l26' },
  { id: 'pve-qemu-199', vmid: 199, name: 'tmpl-debian12-cloud', node: 'pve-node-01', vm_type: 'qemu', status: 'stopped', cpu_cores: 2, cpu_usage: 0, cpu_percent: 0, memory_mb: 2048, memory_used_mb: 0, memory_percent: 0, disk_gb: 32, disk_used_gb: 2.1, disk_percent: 6.6, ip_address: null, net_in: 0, net_out: 0, uptime: 0, tags: ['template'], template: true, ha_state: null, lock: null, os_type: 'l26' },
  { id: 'pve-lxc-310', vmid: 310, name: 'ct-grafana', node: 'pve-node-01', vm_type: 'lxc', status: 'running', cpu_cores: 2, cpu_usage: 0.09, cpu_percent: 9, memory_mb: 4096, memory_used_mb: 1802, memory_percent: 44, disk_gb: 32, disk_used_gb: 11.2, disk_percent: 35, ip_address: '10.20.10.55', net_in: 28_400_000_000, net_out: 21_900_000_000, uptime: 4_060_800, tags: ['observability'], template: false, ha_state: null, lock: null, os_type: 'debian' },
  { id: 'pve-lxc-311', vmid: 311, name: 'ct-prometheus', node: 'pve-node-01', vm_type: 'lxc', status: 'running', cpu_cores: 4, cpu_usage: 0.31, cpu_percent: 31, memory_mb: 8192, memory_used_mb: 6062, memory_percent: 74, disk_gb: 256, disk_used_gb: 168.4, disk_percent: 65.8, ip_address: '10.20.10.56', net_in: 341_000_000_000, net_out: 74_200_000_000, uptime: 4_060_800, tags: ['observability'], template: false, ha_state: null, lock: null, os_type: 'debian' },
  { id: 'pve-lxc-320', vmid: 320, name: 'ct-nginx-edge', node: 'pve-node-02', vm_type: 'lxc', status: 'running', cpu_cores: 2, cpu_usage: 0.16, cpu_percent: 16, memory_mb: 2048, memory_used_mb: 843, memory_percent: 41, disk_gb: 16, disk_used_gb: 4.8, disk_percent: 30, ip_address: '10.20.10.70', net_in: 496_000_000_000, net_out: 731_000_000_000, uptime: 1_209_600, tags: ['edge'], template: false, ha_state: null, lock: null, os_type: 'debian' },
  { id: 'pve-lxc-321', vmid: 321, name: 'ct-syslog', node: 'pve-node-03', vm_type: 'lxc', status: 'running', cpu_cores: 2, cpu_usage: 0.12, cpu_percent: 12, memory_mb: 4096, memory_used_mb: 2662, memory_percent: 65, disk_gb: 128, disk_used_gb: 78.4, disk_percent: 61.3, ip_address: '10.20.10.71', net_in: 214_000_000_000, net_out: 9_800_000_000, uptime: 2_073_600, tags: ['observability'], template: false, ha_state: null, lock: null, os_type: 'ubuntu' },
  { id: 'pve-lxc-330', vmid: 330, name: 'ct-docs', node: 'pve-node-03', vm_type: 'lxc', status: 'stopped', cpu_cores: 1, cpu_usage: 0, cpu_percent: 0, memory_mb: 1024, memory_used_mb: 0, memory_percent: 0, disk_gb: 8, disk_used_gb: 2.1, disk_percent: 26.3, ip_address: null, net_in: 0, net_out: 0, uptime: 0, tags: ['docs'], template: false, ha_state: null, lock: null, os_type: 'alpine' },
  { id: 'pve-lxc-399', vmid: 399, name: 'tmpl-debian12-ct', node: 'pve-node-01', vm_type: 'lxc', status: 'stopped', cpu_cores: 1, cpu_usage: 0, cpu_percent: 0, memory_mb: 512, memory_used_mb: 0, memory_percent: 0, disk_gb: 8, disk_used_gb: 0.4, disk_percent: 5, ip_address: null, net_in: 0, net_out: 0, uptime: 0, tags: ['template'], template: true, ha_state: null, lock: null, os_type: 'debian' },
];

export const demoHypervisorClusterDashboard = {
  cluster_name: 'pve-dc-a',
  quorate: true,
  total_nodes: 3,
  online_nodes: 3,
  total_vms: 11,
  running_vms: 9,
  total_containers: 5,
  running_containers: 4,
  total_cpu_cores: 88,
  cpu_usage_percent: 41,
  total_memory_bytes: 377_957_122_048,
  used_memory_bytes: 288_836_550_656,
  memory_usage_percent: 76,
  total_storage_bytes: 191_200_000_000_000,
  used_storage_bytes: 128_797_000_000_000,
  storage_usage_percent: 67,
  ha_active: true,
};

export const demoHypervisorFleetDashboard = {
  total_clusters: 1,
  online_clusters: 1,
  ...demoHypervisorClusterDashboard,
  clusters: [
    {
      controller_id: demoIds.proxmox,
      controller_name: 'PVE Cluster A',
      ...demoHypervisorClusterDashboard,
      status: 'online',
      error: '',
    },
  ],
};

export const demoHypervisorTaskStats = { ok: 214, running: 2, warning: 3, error: 1, total: 220 };

export const demoHypervisorClusterStatus = {
  name: 'pve-dc-a',
  quorate: true,
  node_count: 3,
  version: 7,
  nodes: demoHypervisorNodes.map((n) => ({
    node: n.node,
    status: 'online',
    ip: n.ip_address,
    level: n.subscription_level === 'none' ? '' : 'c',
  })),
};

export const demoHypervisorClusterConfigNodes = demoHypervisorNodes.map((n, i) => ({
  node: n.node,
  nodeid: i + 1,
  ring0_addr: n.ip_address,
  quorum_votes: 1,
  pve_addr: n.ip_address,
}));

export const demoHypervisorClusterResources = demoHypervisorGuests.map((g) => ({
  id: `${g.vm_type}/${g.vmid}`,
  type: g.vm_type,
  node: g.node,
  status: g.status,
  name: g.name,
  vmid: g.vmid,
  maxcpu: g.cpu_cores,
  cpu: g.cpu_usage,
  maxmem: g.memory_mb * 1_048_576,
  mem: g.memory_used_mb * 1_048_576,
  maxdisk: g.disk_gb * 1_073_741_824,
  disk: Math.round(g.disk_used_gb * 1_073_741_824),
  uptime: g.uptime,
  template: g.template,
}));

/** Proxmox storages. Shared entries repeat per node, exactly as PVE reports them. */
export const demoHypervisorStorages = [
  ...['pve-node-01', 'pve-node-02', 'pve-node-03'].flatMap((node) => [
    { storage: 'ceph-vm', node, storage_type: 'rbd', content: 'images,rootdir', total: 48_000_000_000_000, used: 20_000_000_000_000, available: 28_000_000_000_000, used_percent: 41.7, active: true, shared: true, enabled: true },
    { storage: 'pbs-dc', node, storage_type: 'pbs', content: 'backup', total: 40_000_000_000_000, used: 26_240_000_000_000, available: 13_760_000_000_000, used_percent: 65.6, active: true, shared: true, enabled: true },
    { storage: 'truenas-nfs', node, storage_type: 'nfs', content: 'backup,iso,vztmpl', total: 96_000_000_000_000, used: 78_720_000_000_000, available: 17_280_000_000_000, used_percent: 82, active: true, shared: true, enabled: true },
  ]),
  { storage: 'local-zfs', node: 'pve-node-01', storage_type: 'zfspool', content: 'images,rootdir', total: 2_000_000_000_000, used: 1_180_000_000_000, available: 820_000_000_000, used_percent: 59, active: true, shared: false, enabled: true },
  { storage: 'local-zfs', node: 'pve-node-02', storage_type: 'zfspool', content: 'images,rootdir', total: 2_000_000_000_000, used: 1_422_000_000_000, available: 578_000_000_000, used_percent: 71.1, active: true, shared: false, enabled: true },
  { storage: 'local-zfs', node: 'pve-node-03', storage_type: 'zfspool', content: 'images,rootdir', total: 2_000_000_000_000, used: 880_000_000_000, available: 1_120_000_000_000, used_percent: 44, active: true, shared: false, enabled: true },
  { storage: 'local', node: 'pve-node-01', storage_type: 'dir', content: 'iso,vztmpl,backup,snippets', total: 400_000_000_000, used: 118_000_000_000, available: 282_000_000_000, used_percent: 29.5, active: true, shared: false, enabled: true },
  { storage: 'local', node: 'pve-node-02', storage_type: 'dir', content: 'iso,vztmpl,backup,snippets', total: 400_000_000_000, used: 141_000_000_000, available: 259_000_000_000, used_percent: 35.3, active: true, shared: false, enabled: true },
  { storage: 'local', node: 'pve-node-03', storage_type: 'dir', content: 'iso,vztmpl,backup,snippets', total: 400_000_000_000, used: 96_000_000_000, available: 304_000_000_000, used_percent: 24, active: true, shared: false, enabled: true },
];

/** Volumes browsable from the Storage tab. `ctime` is epoch SECONDS. */
export const demoHypervisorStorageContent = [
  { storage: 'local', volid: 'local:iso/debian-12.5.0-amd64-netinst.iso', content: 'iso', format: 'iso', size: 658_505_728, ctime: 1_764_547_200, vmid: null, notes: null },
  { storage: 'local', volid: 'local:iso/ubuntu-24.04.1-live-server-amd64.iso', content: 'iso', format: 'iso', size: 2_782_588_928, ctime: 1_767_225_600, vmid: null, notes: null },
  { storage: 'local', volid: 'local:iso/virtio-win-0.1.262.iso', content: 'iso', format: 'iso', size: 707_035_136, ctime: 1_762_819_200, vmid: null, notes: null },
  { storage: 'local', volid: 'local:vztmpl/debian-12-standard_12.7-1_amd64.tar.zst', content: 'vztmpl', format: 'tzst', size: 130_023_424, ctime: 1_765_411_200, vmid: null, notes: null },
  { storage: 'local', volid: 'local:vztmpl/ubuntu-24.04-standard_24.04-2_amd64.tar.zst', content: 'vztmpl', format: 'tzst', size: 141_557_760, ctime: 1_765_411_200, vmid: null, notes: null },
  { storage: 'local', volid: 'local:snippets/cloud-init-baseline.yaml', content: 'snippets', format: 'snippet', size: 2_148, ctime: 1_768_262_400, vmid: null, notes: null },
  { storage: 'ceph-vm', volid: 'ceph-vm:vm-101-disk-0', content: 'images', format: 'raw', size: 128_849_018_880, ctime: 1_759_276_800, vmid: 101, notes: null },
  { storage: 'ceph-vm', volid: 'ceph-vm:vm-110-disk-0', content: 'images', format: 'raw', size: 549_755_813_888, ctime: 1_759_276_800, vmid: 110, notes: null },
  { storage: 'ceph-vm', volid: 'ceph-vm:vm-130-disk-0', content: 'images', format: 'raw', size: 4_398_046_511_104, ctime: 1_756_684_800, vmid: 130, notes: null },
  { storage: 'ceph-vm', volid: 'ceph-vm:vm-120-disk-0', content: 'images', format: 'raw', size: 214_748_364_800, ctime: 1_762_128_000, vmid: 120, notes: null },
  { storage: 'pbs-dc', volid: 'pbs-dc:backup/vm/110/2026-06-07T02:11:03Z', content: 'backup', format: 'pbs-vm', size: 214_748_364_800, ctime: 1_780_798_263, vmid: 110, notes: 'nightly-critical' },
  { storage: 'pbs-dc', volid: 'pbs-dc:backup/vm/101/2026-06-07T02:04:18Z', content: 'backup', format: 'pbs-vm', size: 34_359_738_368, ctime: 1_780_797_858, vmid: 101, notes: 'nightly-critical' },
  { storage: 'pbs-dc', volid: 'pbs-dc:backup/vm/111/2026-06-07T02:26:41Z', content: 'backup', format: 'pbs-vm', size: 209_715_200_000, ctime: 1_780_799_201, vmid: 111, notes: 'nightly-critical' },
  { storage: 'pbs-dc', volid: 'pbs-dc:backup/ct/310/2026-06-07T02:31:05Z', content: 'backup', format: 'pbs-ct', size: 8_589_934_592, ctime: 1_780_799_465, vmid: 310, notes: 'nightly-critical' },
  { storage: 'truenas-nfs', volid: 'truenas-nfs:backup/vzdump-qemu-130-2026_06_01-03_38_12.vma.zst', content: 'backup', format: 'vma.zst', size: 2_267_742_732_288, ctime: 1_780_281_492, vmid: 130, notes: 'weekly-all' },
  { storage: 'truenas-nfs', volid: 'truenas-nfs:backup/vzdump-qemu-120-2026_06_01-04_51_09.vma.zst', content: 'backup', format: 'vma.zst', size: 78_390_722_560, ctime: 1_780_285_869, vmid: 120, notes: 'weekly-all' },
  { storage: 'truenas-nfs', volid: 'truenas-nfs:backup/vzdump-lxc-311-2026_06_01-05_02_44.tar.zst', content: 'backup', format: 'tar.zst', size: 91_268_055_040, ctime: 1_780_286_564, vmid: 311, notes: 'weekly-all' },
  { storage: 'local-zfs', volid: 'local-zfs:vm-140-disk-0', content: 'images', format: 'raw', size: 85_899_345_920, ctime: 1_754_006_400, vmid: 140, notes: null },
  { storage: 'local-zfs', volid: 'local-zfs:vm-150-disk-0', content: 'images', format: 'raw', size: 268_435_456_000, ctime: 1_757_030_400, vmid: 150, notes: null },
];

/** Tasks per node. `started_at`/`ended_at` are ISO strings (HypervisorTask). */
export const demoHypervisorTasks = [
  { upid: 'UPID:pve-node-01:0004A1C2:0F3D4E5F:6860B1C2:vzdump:110:root@pam:', node: 'pve-node-01', type: 'vzdump', status: 'running', user: 'root@pam', started_at: iso(11), ended_at: null, is_running: true },
  { upid: 'UPID:pve-node-02:0004B7D1:0F3E1A22:6860B0F4:qmigrate:170:root@pam:', node: 'pve-node-02', type: 'qmigrate', status: 'running', user: 'root@pam', started_at: iso(6), ended_at: null, is_running: true },
  { upid: 'UPID:pve-node-01:00049E10:0F3B22C7:68608E30:vzdump:101:root@pam:', node: 'pve-node-01', type: 'vzdump', status: 'OK', user: 'root@pam', started_at: iso(748), ended_at: iso(741), is_running: false },
  { upid: 'UPID:pve-node-01:00049F22:0F3B4411:686090A1:vzdump:310:root@pam:', node: 'pve-node-01', type: 'vzdump', status: 'OK', user: 'root@pam', started_at: iso(739), ended_at: iso(736), is_running: false },
  { upid: 'UPID:pve-node-01:0004A0B4:0F3C1180:6860A2FF:zfs-scrub:local-zfs:root@pam:', node: 'pve-node-01', type: 'zfs-scrub', status: 'OK', user: 'root@pam', started_at: iso(2880), ended_at: iso(2764), is_running: false },
  { upid: 'UPID:pve-node-01:0004A2D9:0F3D6612:6860B3A0:aptupdate::root@pam:', node: 'pve-node-01', type: 'aptupdate', status: 'OK', user: 'root@pam', started_at: iso(184), ended_at: iso(183), is_running: false },
  { upid: 'UPID:pve-node-01:0004A311:0F3D7A55:6860B412:qmstart:160:demo@pve:', node: 'pve-node-01', type: 'qmstart', status: 'OK', user: 'demo@pve', started_at: iso(96), ended_at: iso(95), is_running: false },
  { upid: 'UPID:pve-node-01:0004A3C0:0F3D8090:6860B480:vzdump:150:root@pam:', node: 'pve-node-01', type: 'vzdump', status: "command 'vzdump 150 --storage local --mode snapshot' failed: exit code 2", user: 'root@pam', started_at: iso(1462), ended_at: iso(1449), is_running: false },
  { upid: 'UPID:pve-node-02:0004B801:0F3E2200:6860B120:vzdump:120:root@pam:', node: 'pve-node-02', type: 'vzdump', status: 'OK', user: 'root@pam', started_at: iso(730), ended_at: iso(704), is_running: false },
  { upid: 'UPID:pve-node-02:0004B8F3:0F3E3311:6860B190:vzdump:130:root@pam:', node: 'pve-node-02', type: 'vzdump', status: 'OK', user: 'root@pam', started_at: iso(700), ended_at: iso(566), is_running: false },
  { upid: 'UPID:pve-node-02:0004B9A2:0F3E4402:6860B200:qmreboot:120:demo@pve:', node: 'pve-node-02', type: 'qmreboot', status: 'OK', user: 'demo@pve', started_at: iso(412), ended_at: iso(411), is_running: false },
  { upid: 'UPID:pve-node-02:0004BA10:0F3E5510:6860B260:cephcreateosd:osd.17:root@pam:', node: 'pve-node-02', type: 'cephcreateosd', status: 'OK', user: 'root@pam', started_at: iso(11520), ended_at: iso(11511), is_running: false },
  { upid: 'UPID:pve-node-03:0004C102:0F3F1100:6860B080:vzdump:111:root@pam:', node: 'pve-node-03', type: 'vzdump', status: 'OK', user: 'root@pam', started_at: iso(724), ended_at: iso(698), is_running: false },
  { upid: 'UPID:pve-node-03:0004C1B7:0F3F2211:6860B0E0:vzdump:321:root@pam:', node: 'pve-node-03', type: 'vzdump', status: 'OK', user: 'root@pam', started_at: iso(695), ended_at: iso(689), is_running: false },
  { upid: 'UPID:pve-node-03:0004C244:0F3F3322:6860B140:pull_file::root@pam:', node: 'pve-node-03', type: 'pull_file', status: 'OK', user: 'root@pam', started_at: iso(240), ended_at: iso(240), is_running: false },
  { upid: 'UPID:pve-node-03:0004C300:0F3F4433:6860B1A0:replication:111-0:root@pam:', node: 'pve-node-03', type: 'replication', status: 'OK', user: 'root@pam', started_at: iso(12), ended_at: iso(11), is_running: false },
];

export const demoHypervisorTaskLog = [
  { n: 1, t: 'INFO: starting new backup job: vzdump 110 --storage pbs-dc --mode snapshot --compress zstd' },
  { n: 2, t: 'INFO: Starting Backup of VM 110 (qemu)' },
  { n: 3, t: 'INFO: Backup started at 2026-06-07 02:11:03' },
  { n: 4, t: 'INFO: status = running' },
  { n: 5, t: 'INFO: creating vzdump archive on pbs-dc' },
  { n: 6, t: 'INFO: issuing guest-agent "fs-freeze" command' },
  { n: 7, t: 'INFO: issuing guest-agent "fs-thaw" command' },
  { n: 8, t: 'INFO: started backup task' },
  { n: 9, t: 'INFO: scsi0: dirty-bitmap status: created new' },
  { n: 10, t: 'INFO:  12% (41.4 GiB of 337.4 GiB) in 3m 4s, read: 231.0 MiB/s, write: 214.7 MiB/s' },
  { n: 11, t: 'INFO:  24% (81.9 GiB of 337.4 GiB) in 6m 1s, read: 236.2 MiB/s, write: 220.1 MiB/s' },
];

export const demoHypervisorBackupJobs = [
  { id: 'backup-nightly-critical', schedule: '02:00', storage: 'pbs-dc', vmid: '101,102,110,111,310,311', mode: 'snapshot', compress: 'zstd', enabled: true, mailto: 'ops@demo.local', node: null },
  { id: 'backup-weekly-all', schedule: 'sun 03:30', storage: 'truenas-nfs', vmid: 'all', mode: 'snapshot', compress: 'zstd', enabled: true, mailto: 'ops@demo.local', node: null },
  { id: 'backup-lab-monthly', schedule: 'sat 05:00', storage: 'local', vmid: '150', mode: 'stop', compress: 'lzo', enabled: false, mailto: '', node: 'pve-node-03' },
];

/** Fields the Backup Age tab actually reads: last_backup_time / age_hours / is_stale. */
export const demoHypervisorBackupAgeReport = {
  controller_id: demoIds.proxmox,
  threshold_hours: 24,
  total_vms: 16,
  backed_up: 12,
  stale: 3,
  never_backed_up: 1,
  generated_at: iso(2),
  vms: [
    { vmid: 101, name: 'dc-auth-01', node: 'pve-node-01', vm_type: 'qemu', last_backup_time: iso(746), age_hours: 12.4, is_stale: false, size: 34_359_738_368 },
    { vmid: 102, name: 'dc-auth-02', node: 'pve-node-02', vm_type: 'qemu', last_backup_time: iso(742), age_hours: 12.4, is_stale: false, size: 33_285_996_544 },
    { vmid: 110, name: 'dc-db-01', node: 'pve-node-01', vm_type: 'qemu', last_backup_time: iso(11), age_hours: 0.2, is_stale: false, size: 214_748_364_800 },
    { vmid: 111, name: 'dc-db-02', node: 'pve-node-03', vm_type: 'qemu', last_backup_time: iso(698), age_hours: 11.6, is_stale: false, size: 209_715_200_000 },
    { vmid: 120, name: 'dc-app-01', node: 'pve-node-02', vm_type: 'qemu', last_backup_time: iso(704), age_hours: 11.7, is_stale: false, size: 78_390_722_560 },
    { vmid: 121, name: 'dc-app-02', node: 'pve-node-03', vm_type: 'qemu', last_backup_time: iso(709), age_hours: 11.8, is_stale: false, size: 74_490_609_664 },
    { vmid: 130, name: 'dc-nvr-archive', node: 'pve-node-02', vm_type: 'qemu', last_backup_time: iso(566), age_hours: 9.4, is_stale: false, size: 2_267_742_732_288 },
    { vmid: 140, name: 'hq-print-01', node: 'pve-node-01', vm_type: 'qemu', last_backup_time: iso(4322), age_hours: 72, is_stale: true, size: 21_474_836_480 },
    { vmid: 150, name: 'lab-win2022', node: 'pve-node-03', vm_type: 'qemu', last_backup_time: iso(11522), age_hours: 192, is_stale: true, size: 96_207_142_912 },
    { vmid: 160, name: 'dc-mail-relay', node: 'pve-node-01', vm_type: 'qemu', last_backup_time: iso(738), age_hours: 12.3, is_stale: false, size: 14_495_514_624 },
    { vmid: 170, name: 'dc-app-canary', node: 'pve-node-02', vm_type: 'qemu', last_backup_time: null, age_hours: null, is_stale: true, size: 0 },
    { vmid: 310, name: 'ct-grafana', node: 'pve-node-01', vm_type: 'lxc', last_backup_time: iso(736), age_hours: 12.3, is_stale: false, size: 8_589_934_592 },
    { vmid: 311, name: 'ct-prometheus', node: 'pve-node-01', vm_type: 'lxc', last_backup_time: iso(733), age_hours: 12.2, is_stale: false, size: 91_268_055_040 },
    { vmid: 320, name: 'ct-nginx-edge', node: 'pve-node-02', vm_type: 'lxc', last_backup_time: iso(720), age_hours: 12, is_stale: false, size: 3_221_225_472 },
    { vmid: 321, name: 'ct-syslog', node: 'pve-node-03', vm_type: 'lxc', last_backup_time: iso(689), age_hours: 11.5, is_stale: false, size: 47_244_640_256 },
    { vmid: 330, name: 'ct-docs', node: 'pve-node-03', vm_type: 'lxc', last_backup_time: iso(2882), age_hours: 48, is_stale: true, size: 1_073_741_824 },
  ],
};

/** PBS prune preview rows — `ctime` epoch SECONDS, `mark` keep|remove. */
export const demoHypervisorPrunePreview = [
  { vmid: 110, type: 'vm', ctime: 1_780_798_263, size: 214_748_364_800, mark: 'keep' },
  { vmid: 110, type: 'vm', ctime: 1_780_711_863, size: 213_674_622_976, mark: 'keep' },
  { vmid: 110, type: 'vm', ctime: 1_780_625_463, size: 212_600_881_152, mark: 'keep' },
  { vmid: 110, type: 'vm', ctime: 1_780_539_063, size: 211_527_139_328, mark: 'keep' },
  { vmid: 110, type: 'vm', ctime: 1_780_452_663, size: 210_453_397_504, mark: 'remove' },
  { vmid: 110, type: 'vm', ctime: 1_780_366_263, size: 209_379_655_680, mark: 'remove' },
  { vmid: 101, type: 'vm', ctime: 1_780_797_858, size: 34_359_738_368, mark: 'keep' },
  { vmid: 101, type: 'vm', ctime: 1_780_711_458, size: 34_091_302_912, mark: 'keep' },
  { vmid: 101, type: 'vm', ctime: 1_780_452_258, size: 33_554_432_000, mark: 'remove' },
  { vmid: 310, type: 'ct', ctime: 1_780_799_465, size: 8_589_934_592, mark: 'keep' },
  { vmid: 310, type: 'ct', ctime: 1_780_713_065, size: 8_522_825_728, mark: 'keep' },
  { vmid: 310, type: 'ct', ctime: 1_780_453_865, size: 8_455_716_864, mark: 'remove' },
];

/** Guest snapshots, keyed by `vmid` (extra key; HypervisorSnapshot ignores it). */
export const demoHypervisorSnapshots = [
  { vmid: 110, name: 'pre-pg16-upgrade', description: 'Taken before the PostgreSQL 16 in-place upgrade', created_at: iso(4325), vmstate: true, parent: null },
  { vmid: 110, name: 'nightly-consistent', description: 'Automatic pre-backup snapshot', created_at: iso(11), vmstate: false, parent: 'pre-pg16-upgrade' },
  { vmid: 110, name: 'current', description: 'You are here', created_at: null, vmstate: false, parent: 'nightly-consistent' },
  { vmid: 101, name: 'before-oidc-rollout', description: 'Rollback point for the OIDC provider change', created_at: iso(2885), vmstate: true, parent: null },
  { vmid: 101, name: 'current', description: 'You are here', created_at: null, vmstate: false, parent: 'before-oidc-rollout' },
  { vmid: 120, name: 'v4.2-release', description: 'App release 4.2 baseline', created_at: iso(10082), vmstate: false, parent: null },
  { vmid: 120, name: 'v4.3-rc1', description: 'Release candidate 1', created_at: iso(1445), vmstate: false, parent: 'v4.2-release' },
  { vmid: 120, name: 'current', description: 'You are here', created_at: null, vmstate: false, parent: 'v4.3-rc1' },
  { vmid: 150, name: 'clean-install', description: 'Fresh Windows install, drivers only', created_at: iso(43_205), vmstate: false, parent: null },
  { vmid: 150, name: 'current', description: 'You are here', created_at: null, vmstate: false, parent: 'clean-install' },
  { vmid: 310, name: 'pre-plugin-update', description: 'Before the dashboard plugin bump', created_at: iso(7205), vmstate: false, parent: null },
  { vmid: 310, name: 'current', description: 'You are here', created_at: null, vmstate: false, parent: 'pre-plugin-update' },
];

export const demoHypervisorHaResources = [
  { sid: 'vm:101', state: 'started', group: 'dc-critical', max_relocate: 1, max_restart: 1, comment: 'Primary identity node', request_state: 'started', status: 'started', node: 'pve-node-01', crm_state: 'started' },
  { sid: 'vm:102', state: 'started', group: 'dc-critical', max_relocate: 1, max_restart: 1, comment: 'Secondary identity node', request_state: 'started', status: 'started', node: 'pve-node-02', crm_state: 'started' },
  { sid: 'vm:110', state: 'started', group: 'dc-critical', max_relocate: 2, max_restart: 1, comment: 'Primary database', request_state: 'started', status: 'started', node: 'pve-node-01', crm_state: 'started' },
  { sid: 'vm:111', state: 'started', group: 'dc-critical', max_relocate: 2, max_restart: 1, comment: 'Streaming replica', request_state: 'started', status: 'started', node: 'pve-node-03', crm_state: 'started' },
  { sid: 'ct:320', state: 'started', group: 'dc-edge', max_relocate: 1, max_restart: 2, comment: 'Edge reverse proxy', request_state: 'started', status: 'started', node: 'pve-node-02', crm_state: 'started' },
];

export const demoHypervisorHaGroups = [
  { group: 'dc-critical', nodes: 'pve-node-01:2,pve-node-02:1,pve-node-03:1', nofailback: false, restricted: false, comment: 'Identity and database tier — prefers node 01' },
  { group: 'dc-edge', nodes: 'pve-node-02:1,pve-node-03:1', nofailback: true, restricted: true, comment: 'Edge tier — pinned to the two uplink-attached nodes' },
];

export const demoHypervisorFirewallRules = [
  { pos: 0, type: 'in', action: 'ACCEPT', enable: true, source: '10.10.0.0/16', dest: null, sport: null, dport: '8006', proto: 'tcp', macro: null, iface: null, log: 'nolog', comment: 'PVE web UI from the HQ management VLAN' },
  { pos: 1, type: 'in', action: 'ACCEPT', enable: true, source: '10.20.0.0/24', dest: null, sport: null, dport: '5405:5412', proto: 'udp', macro: null, iface: null, log: 'nolog', comment: 'Corosync cluster traffic' },
  { pos: 2, type: 'in', action: 'ACCEPT', enable: true, source: '10.20.0.0/24', dest: null, sport: null, dport: '3300,6789,6800:7300', proto: 'tcp', macro: null, iface: null, log: 'nolog', comment: 'Ceph mon + OSD' },
  { pos: 3, type: 'in', action: 'ACCEPT', enable: true, source: '10.10.40.0/24', dest: null, sport: null, dport: null, proto: null, macro: 'SSH', iface: null, log: 'info', comment: 'SSH from the jump hosts only' },
  { pos: 4, type: 'in', action: 'DROP', enable: true, source: null, dest: null, sport: null, dport: '8006', proto: 'tcp', macro: null, iface: null, log: 'warning', comment: 'Deny web UI from everywhere else' },
  { pos: 5, type: 'out', action: 'ACCEPT', enable: true, source: null, dest: '10.20.0.30', sport: null, dport: '2049', proto: 'tcp', macro: null, iface: null, log: 'nolog', comment: 'NFS to the TrueNAS backup target' },
  { pos: 6, type: 'in', action: 'REJECT', enable: false, source: '10.30.0.0/16', dest: null, sport: null, dport: '22', proto: 'tcp', macro: null, iface: null, log: 'info', comment: 'Staged: block branch SSH (disabled pending change window)' },
];

export const demoHypervisorPools = [
  { poolid: 'production', comment: 'Customer-facing production workloads', members: demoHypervisorGuests.filter((g) => g.tags.includes('prod')).map((g) => ({ vmid: g.vmid, node: g.node, type: g.vm_type })) },
  { poolid: 'infrastructure', comment: 'Observability, mail relay and edge services', members: demoHypervisorGuests.filter((g) => g.tags.includes('observability') || g.tags.includes('edge') || g.tags.includes('mail')).map((g) => ({ vmid: g.vmid, node: g.node, type: g.vm_type })) },
  { poolid: 'lab', comment: 'Non-production lab and template staging', members: demoHypervisorGuests.filter((g) => g.tags.includes('lab') || g.tags.includes('template')).map((g) => ({ vmid: g.vmid, node: g.node, type: g.vm_type })) },
];

export const demoHypervisorNodeServices = ['pve-node-01', 'pve-node-02', 'pve-node-03'].flatMap((node) => [
  { node, service: 'pveproxy', name: 'pveproxy', desc: 'PVE API Proxy Server', state: 'running' },
  { node, service: 'pvedaemon', name: 'pvedaemon', desc: 'PVE API Daemon', state: 'running' },
  { node, service: 'pve-cluster', name: 'pve-cluster', desc: 'Cluster Filesystem', state: 'running' },
  { node, service: 'pvestatd', name: 'pvestatd', desc: 'PVE Status Daemon', state: 'running' },
  { node, service: 'corosync', name: 'corosync', desc: 'Corosync Cluster Engine', state: 'running' },
  { node, service: 'ceph-mon', name: 'ceph-mon', desc: 'Ceph Monitor', state: 'running' },
  { node, service: 'ceph-osd', name: 'ceph-osd', desc: 'Ceph Object Storage Daemon', state: 'running' },
  { node, service: 'pve-firewall', name: 'pve-firewall', desc: 'PVE Firewall', state: 'running' },
  { node, service: 'chrony', name: 'chrony', desc: 'NTP client/server', state: 'running' },
  { node, service: 'sshd', name: 'sshd', desc: 'OpenSSH Server', state: 'running' },
  { node, service: 'postfix', name: 'postfix', desc: 'Mail Transport Agent', state: node === 'pve-node-03' ? 'stopped' : 'running' },
]);

export const demoHypervisorNodeDisks = ['pve-node-01', 'pve-node-02', 'pve-node-03'].flatMap((node, n) => [
  { node, devpath: '/dev/nvme0n1', model: 'MZ1LB960HAJQ-00007', serial: `DEMO-BOOT-${n + 1}A`, size: 960_197_124_096, vendor: 'Samsung', wearout: 96 - n * 3, rpm: null, disk_type: 'nvme', gpt: true, health: 'PASSED' },
  { node, devpath: '/dev/nvme1n1', model: 'MZ1LB960HAJQ-00007', serial: `DEMO-BOOT-${n + 1}B`, size: 960_197_124_096, vendor: 'Samsung', wearout: 95 - n * 3, rpm: null, disk_type: 'nvme', gpt: true, health: 'PASSED' },
  ...Array.from({ length: 8 }, (_, i) => ({
    node,
    devpath: `/dev/sd${'bcdefghi'[i]}`,
    model: 'PM1643a MZILT7T6HALA',
    serial: `DEMO-OSD-${n + 1}${i + 1}`,
    size: 7_681_501_126_656,
    vendor: 'Samsung',
    wearout: 99 - i,
    rpm: null,
    disk_type: 'ssd',
    gpt: true,
    health: n === 2 && i === 6 ? 'UNKNOWN' : 'PASSED',
  })),
]);

export const demoHypervisorDiskSmart = {
  health: 'PASSED',
  type: 'ata',
  attributes: [
    { id: 5, name: 'Reallocated_Sector_Ct', value: 100, worst: 100, threshold: 10, raw: '0', flags: 'PO--CK' },
    { id: 9, name: 'Power_On_Hours', value: 92, worst: 92, threshold: 0, raw: '24318', flags: '-O--CK' },
    { id: 12, name: 'Power_Cycle_Count', value: 100, worst: 100, threshold: 0, raw: '41', flags: '-O--CK' },
    { id: 177, name: 'Wear_Leveling_Count', value: 97, worst: 97, threshold: 5, raw: '38', flags: 'PO--C-' },
    { id: 179, name: 'Used_Rsvd_Blk_Cnt_Tot', value: 100, worst: 100, threshold: 10, raw: '0', flags: 'PO--C-' },
    { id: 194, name: 'Temperature_Celsius', value: 62, worst: 55, threshold: 0, raw: '38', flags: '-O---K' },
    { id: 197, name: 'Current_Pending_Sector', value: 100, worst: 100, threshold: 0, raw: '0', flags: '-O--C-' },
    { id: 199, name: 'UDMA_CRC_Error_Count', value: 100, worst: 100, threshold: 0, raw: '0', flags: '-OSRCK' },
    { id: 241, name: 'Total_LBAs_Written', value: 99, worst: 99, threshold: 0, raw: '184213004288', flags: '-O--CK' },
  ],
};

export const demoHypervisorNodeNetwork = ['pve-node-01', 'pve-node-02', 'pve-node-03'].flatMap((node, n) => [
  { node, iface: 'vmbr0', type: 'bridge', active: true, address: `10.20.0.${11 + n}`, netmask: '24', gateway: '10.20.0.1', cidr: `10.20.0.${11 + n}/24`, bridge_ports: 'bond0', bond_slaves: null, method: 'static', autostart: true },
  { node, iface: 'vmbr1', type: 'bridge', active: true, address: null, netmask: null, gateway: null, cidr: null, bridge_ports: 'eno3 eno4', bond_slaves: null, method: 'manual', autostart: true },
  { node, iface: 'bond0', type: 'bond', active: true, address: null, netmask: null, gateway: null, cidr: null, bridge_ports: null, bond_slaves: 'eno1 eno2', method: 'manual', autostart: true },
  { node, iface: 'eno1', type: 'eth', active: true, address: null, netmask: null, gateway: null, cidr: null, bridge_ports: null, bond_slaves: null, method: 'manual', autostart: false },
  { node, iface: 'eno2', type: 'eth', active: true, address: null, netmask: null, gateway: null, cidr: null, bridge_ports: null, bond_slaves: null, method: 'manual', autostart: false },
  { node, iface: 'ens1f0', type: 'eth', active: true, address: `10.20.99.${11 + n}`, netmask: '24', gateway: null, cidr: `10.20.99.${11 + n}/24`, bridge_ports: null, bond_slaves: null, method: 'static', autostart: true },
]);

export const demoHypervisorNodeSensors = demoHypervisorNodes.map((n) => ({
  node: n.node,
  cpu_temp: n.node === 'pve-node-02' ? 71 : 54,
  cpu_temps: [
    { name: 'Package id 0', value: n.node === 'pve-node-02' ? 71 : 54, unit: '°C' },
    { name: 'Package id 1', value: n.node === 'pve-node-02' ? 68 : 51, unit: '°C' },
  ],
  loadavg: n.node === 'pve-node-02' ? [11.42, 10.87, 9.94] : n.node === 'pve-node-01' ? [6.18, 5.72, 5.41] : [2.94, 3.11, 3.02],
  cpuinfo: { cpus: n.cpu_count, sockets: 2, mhz: n.cpu_count === 32 ? '2400.000' : '2100.000', model: n.cpu_model },
  pveversion: `pve-manager/${n.pve_version}/demo`,
  kversion: `Linux ${n.kernel_version}`,
}));

export const demoHypervisorSubscriptions = [
  { node: 'pve-node-01', status: 'active', level: 'c', serverid: 'DEMOSERVERID0001', productname: 'Proxmox VE Community Subscription 2 CPUs/year', regdate: '2026-01-14 00:00:00', nextduedate: '2027-01-14', url: 'https://www.proxmox.com/proxmox-ve/pricing' },
  { node: 'pve-node-02', status: 'active', level: 'c', serverid: 'DEMOSERVERID0002', productname: 'Proxmox VE Community Subscription 2 CPUs/year', regdate: '2026-01-14 00:00:00', nextduedate: '2027-01-14', url: 'https://www.proxmox.com/proxmox-ve/pricing' },
  { node: 'pve-node-03', status: 'notfound', level: '', serverid: 'DEMOSERVERID0003', productname: null, regdate: null, nextduedate: null, url: 'https://www.proxmox.com/proxmox-ve/pricing' },
];

export const demoHypervisorAptUpdates = [
  { node: 'pve-node-01', Package: 'pve-manager', Title: 'Proxmox Virtual Environment Management Tools', OldVersion: '8.3.2', Version: '8.3.5', Origin: 'Proxmox', Priority: 'optional', CurrentState: 'installed' },
  { node: 'pve-node-01', Package: 'libpve-storage-perl', Title: 'Proxmox VE storage management library', OldVersion: '8.3.3', Version: '8.3.4', Origin: 'Proxmox', Priority: 'optional', CurrentState: 'installed' },
  { node: 'pve-node-01', Package: 'openssl', Title: 'Secure Sockets Layer toolkit', OldVersion: '3.0.15-1~deb12u1', Version: '3.0.16-1~deb12u1', Origin: 'Debian', Priority: 'important', CurrentState: 'installed' },
  { node: 'pve-node-02', Package: 'pve-manager', Title: 'Proxmox Virtual Environment Management Tools', OldVersion: '8.3.2', Version: '8.3.5', Origin: 'Proxmox', Priority: 'optional', CurrentState: 'installed' },
  { node: 'pve-node-02', Package: 'ceph-common', Title: 'Common utilities to mount and interact with a Ceph storage cluster', OldVersion: '18.2.4-pve3', Version: '18.2.5-pve1', Origin: 'Proxmox', Priority: 'optional', CurrentState: 'installed' },
  { node: 'pve-node-03', Package: 'pve-manager', Title: 'Proxmox Virtual Environment Management Tools', OldVersion: '8.3.2', Version: '8.3.5', Origin: 'Proxmox', Priority: 'optional', CurrentState: 'installed' },
];

export const demoHypervisorCertificates = ['pve-node-01', 'pve-node-02', 'pve-node-03'].flatMap((node) => [
  {
    node,
    filename: 'pve-ssl.pem',
    subject: `/OU=PVE Cluster Node/O=Proxmox Virtual Environment/CN=${node}.demo.local`,
    issuer: '/CN=Proxmox Virtual Environment/OU=pve-dc-a/O=PVE Cluster Manager CA',
    fingerprint: '3F:A1:7C:22:9B:04:E8:5D:16:C3:70:AA:2E:91:48:B7:0D:6F:35:C9:82:14:7A:E0:5B:38:D1:64:9C:20:F5:AB',
    notbefore: 1_764_547_200,
    notafter: 1_827_705_600,
    'public-key-type': 'rsa',
    'public-key-bits': 2048,
    san: [node, `${node}.demo.local`],
  },
  {
    node,
    filename: 'pveproxy-ssl.pem',
    subject: `/CN=${node}.demo.local`,
    issuer: '/C=US/O=Demo Internal CA/CN=Demo Internal Issuing CA R2',
    fingerprint: 'C8:14:6E:B0:57:2D:39:F1:88:AE:41:05:73:9C:D2:6B:1F:40:88:E3:57:C2:9A:11:64:7D:0E:B3:52:88:A0:1C',
    notbefore: 1_772_150_400,
    notafter: 1_803_686_400,
    'public-key-type': 'ecdsa',
    'public-key-bits': 384,
    san: [node, `${node}.demo.local`, '10.20.0.11'],
  },
]);

export const demoHypervisorSdnZones = [
  { zone: 'dczone', type: 'vlan', nodes: 'pve-node-01,pve-node-02,pve-node-03', mtu: 1500, bridge: 'vmbr0', state: 'available', pending: {} },
  { zone: 'labzone', type: 'simple', nodes: 'pve-node-03', mtu: 1500, bridge: 'vmbr1', state: 'available', pending: {} },
];

export const demoHypervisorSdnVnets = [
  { vnet: 'vprod', zone: 'dczone', tag: 10, alias: 'Production servers', vlanaware: false, state: 'available' },
  { vnet: 'vstore', zone: 'dczone', tag: 20, alias: 'Storage / backup traffic', vlanaware: false, state: 'available' },
  { vnet: 'vcam', zone: 'dczone', tag: 40, alias: 'Camera archive ingest', vlanaware: false, state: 'available' },
  { vnet: 'vlab', zone: 'labzone', tag: null, alias: 'Isolated lab network', vlanaware: true, state: 'pending' },
];

export const demoHypervisorSdnControllers = [
  { controller: 'evpn-rr', type: 'evpn', node: 'pve-node-01', state: 'available' },
];

export const demoHypervisorClusterLog = [
  { time: Math.floor(Date.now() / 1000) - 360, node: 'pve-node-02', severity: 'info', pri: 6, tag: 'qmigrate', user: 'root@pam', msg: 'starting migration of VM 170 to node pve-node-03', pid: 309_233, uid: 0 },
  { time: Math.floor(Date.now() / 1000) - 660, node: 'pve-node-01', severity: 'info', pri: 6, tag: 'vzdump', user: 'root@pam', msg: 'INFO: Starting Backup of VM 110 (qemu)', pid: 301_442, uid: 0 },
  { time: Math.floor(Date.now() / 1000) - 5_400, node: 'pve-node-03', severity: 'warning', pri: 4, tag: 'pvestatd', user: 'root@pam', msg: 'storage "pbs-dc" is not online (response took 8.4s)', pid: 2_119, uid: 0 },
  { time: Math.floor(Date.now() / 1000) - 11_400, node: 'pve-node-02', severity: 'warning', pri: 4, tag: 'kernel', user: '', msg: 'CPU package temperature above threshold, cpu clock throttled', pid: 0, uid: 0 },
  { time: Math.floor(Date.now() / 1000) - 87_000, node: 'pve-node-03', severity: 'err', pri: 3, tag: 'vzdump', user: 'root@pam', msg: "ERROR: Backup of VM 150 failed - command 'vzdump 150 --storage local' failed: exit code 2", pid: 388_017, uid: 0 },
  { time: Math.floor(Date.now() / 1000) - 90_600, node: 'pve-node-01', severity: 'info', pri: 6, tag: 'pveproxy', user: 'demo@pve', msg: 'successful auth for user demo@pve', pid: 2_988, uid: 0 },
  { time: Math.floor(Date.now() / 1000) - 172_800, node: 'pve-node-01', severity: 'info', pri: 6, tag: 'zfs', user: 'root@pam', msg: 'scrub repaired 0B in 01:56:12 with 0 errors on local-zfs', pid: 4_401, uid: 0 },
  { time: Math.floor(Date.now() / 1000) - 259_200, node: 'pve-node-02', severity: 'notice', pri: 5, tag: 'ceph-mon', user: '', msg: 'osdmap e2214: 24 total, 24 up, 24 in', pid: 3_150, uid: 0 },
];

export const demoHypervisorReplicationJobs = [
  { id: '110-0', type: 'local', source: 'pve-node-01', target: 'pve-node-03', guest: 110, schedule: '*/15', rate: 120, disable: false, comment: 'Database replica seed', last_sync: Math.floor(Date.now() / 1000) - 720, last_try: Math.floor(Date.now() / 1000) - 720, next_sync: Math.floor(Date.now() / 1000) + 180, duration: 41.6, fail_count: 0, error: null },
  { id: '120-0', type: 'local', source: 'pve-node-02', target: 'pve-node-03', guest: 120, schedule: '*/30', rate: null, disable: false, comment: 'App tier warm standby', last_sync: Math.floor(Date.now() / 1000) - 1_380, last_try: Math.floor(Date.now() / 1000) - 1_380, next_sync: Math.floor(Date.now() / 1000) + 420, duration: 18.2, fail_count: 0, error: null },
  { id: '130-0', type: 'local', source: 'pve-node-02', target: 'pve-node-01', guest: 130, schedule: '00:30', rate: 80, disable: false, comment: 'Camera archive nightly', last_sync: Math.floor(Date.now() / 1000) - 46_800, last_try: Math.floor(Date.now() / 1000) - 3_600, next_sync: Math.floor(Date.now() / 1000) + 39_600, duration: 1_884.4, fail_count: 2, error: 'target node pve-node-01 has 820 GB free, snapshot needs 1.1 TB' },
  { id: '150-0', type: 'local', source: 'pve-node-03', target: 'pve-node-02', guest: 150, schedule: 'sat 04:00', rate: null, disable: true, comment: 'Lab VM — paused while the lab is rebuilt', last_sync: Math.floor(Date.now() / 1000) - 1_209_600, last_try: Math.floor(Date.now() / 1000) - 1_209_600, next_sync: null, duration: 612.9, fail_count: 0, error: null },
];

export const demoHypervisorReplicationLog = [
  { n: 1, t: '2026-06-07 14:18:02 110-0: start replication job' },
  { n: 2, t: '2026-06-07 14:18:02 110-0: guest => VM 110, running => 1' },
  { n: 3, t: '2026-06-07 14:18:02 110-0: volumes => ceph-vm:vm-110-disk-0' },
  { n: 4, t: '2026-06-07 14:18:04 110-0: create snapshot "__replicate_110-0_1780798684__"' },
  { n: 5, t: '2026-06-07 14:18:05 110-0: using secure transmission, rate limit: 120 MByte/s' },
  { n: 6, t: '2026-06-07 14:18:42 110-0: 4.18 GB sent in 37 seconds, 113 MB/s' },
  { n: 7, t: '2026-06-07 14:18:44 110-0: end replication job' },
];

export const demoHypervisorCephStatus = {
  health: 'HEALTH_OK',
  num_osds: 24,
  num_osds_up: 24,
  num_osds_in: 24,
  num_pgs: 1_025,
  num_pools: 3,
  total_bytes: 144_000_000_000_000,
  used_bytes: 60_000_000_000_000,
  avail_bytes: 84_000_000_000_000,
  used_percent: 41.7,
};

export const demoHypervisorCephDetail = {
  osds: Array.from({ length: 24 }, (_, i) => ({
    id: i,
    name: `osd.${i}`,
    host: `pve-node-0${Math.floor(i / 8) + 1}`,
    up: true,
    in: true,
    total_bytes: 6_000_000_000_000,
    used_bytes: 2_360_000_000_000 + (i % 5) * 84_000_000_000,
    avail_bytes: 3_640_000_000_000 - (i % 5) * 84_000_000_000,
    crush_weight: 5.45799,
  })),
  pools: [
    { pool: 1, pool_name: 'ceph-vm', size: 3, pg_num: 512, crush_rule: 'replicated_rule', bytes_used: 57_600_000_000_000, percent_used: 0.4, stored: 19_200_000_000_000 },
    { pool: 2, pool_name: 'cephfs_data', size: 3, pg_num: 256, crush_rule: 'replicated_rule', bytes_used: 2_100_000_000_000, percent_used: 0.0146, stored: 700_000_000_000 },
    { pool: 3, pool_name: 'cephfs_metadata', size: 3, pg_num: 32, crush_rule: 'replicated_rule', bytes_used: 300_000_000_000, percent_used: 0.0021, stored: 100_000_000_000 },
  ],
  monitors: [
    { name: 'pve-node-01', addr: '10.20.0.11:6789/0', rank: 0 },
    { name: 'pve-node-02', addr: '10.20.0.12:6789/0', rank: 1 },
    { name: 'pve-node-03', addr: '10.20.0.13:6789/0', rank: 2 },
  ],
  mds: [{ name: 'pve-node-01', state: 'active', rank: 0 }],
  crush_rules: [{ rule_id: 0, rule_name: 'replicated_rule', type: 1, min_size: 1, max_size: 10 }],
};

/** 48 five-minute RRD points. `time` is epoch SECONDS, `cpu` a 0-1 fraction. */
export const demoHypervisorNodeRrd = Array.from({ length: 48 }, (_, i) => {
  const wave = Math.sin(i / 5.5);
  return {
    time: Math.floor(Date.now() / 1000) - (47 - i) * 300,
    cpu: Number((0.34 + wave * 0.11).toFixed(4)),
    maxcpu: 32,
    mem: Math.round(93_000_000_000 + wave * 6_400_000_000),
    maxmem: 137_438_953_472,
    netin: Math.round(184_000_000 + wave * 62_000_000),
    netout: Math.round(96_000_000 + wave * 31_000_000),
    diskread: Math.round(42_000_000 + wave * 18_000_000),
    diskwrite: Math.round(88_000_000 + wave * 34_000_000),
    iowait: Number((0.018 + wave * 0.009).toFixed(4)),
  };
});

export const demoHypervisorGuestRrd = Array.from({ length: 48 }, (_, i) => {
  const wave = Math.sin(i / 4.2);
  return {
    time: Math.floor(Date.now() / 1000) - (47 - i) * 300,
    cpu: Number((0.44 + wave * 0.14).toFixed(4)),
    maxcpu: 8,
    mem: Math.round(27_000_000_000 + wave * 2_100_000_000),
    maxmem: 34_359_738_368,
    netin: Math.round(64_000_000 + wave * 22_000_000),
    netout: Math.round(48_000_000 + wave * 16_000_000),
    diskread: Math.round(31_000_000 + wave * 12_000_000),
    diskwrite: Math.round(74_000_000 + wave * 26_000_000),
    iowait: Number((0.024 + wave * 0.011).toFixed(4)),
  };
});

export const demoHypervisorGuestAgent = {
  hostname: 'dc-db-01',
  os_type: 'linux',
  os_version: 'Debian GNU/Linux 12 (bookworm)',
  interfaces: [
    { name: 'lo', mac_address: '00:00:00:00:00:00', ip_addresses: ['127.0.0.1', '::1'] },
    { name: 'ens18', mac_address: '02:00:00:20:10:30', ip_addresses: ['10.20.10.30'] },
  ],
};

// ===========================================================================
// STORAGE — TrueNAS SCALE appliance (Datacenter, 10.20.0.30)
// ===========================================================================

export const demoStoragePools = [
  {
    name: 'tank',
    status: 'ONLINE',
    healthy: true,
    size: 64_000_000_000_000,
    allocated: 38_400_000_000_000,
    free: 25_600_000_000_000,
    fragmentation: '9%',
    usage_percent: 60,
    is_decrypted: true,
    redundancy: { type: 'RAIDZ2', vdevs: 2, width: 6 },
    scrub: { function: 'SCRUB', state: 'FINISHED', errors: 0, percentage: 100, finished_at_ms: Date.now() - 6 * 86_400_000 },
  },
  {
    name: 'tank-backup',
    status: 'ONLINE',
    healthy: true,
    size: 96_000_000_000_000,
    allocated: 78_720_000_000_000,
    free: 17_280_000_000_000,
    fragmentation: '14%',
    usage_percent: 82,
    is_decrypted: true,
    redundancy: { type: 'RAIDZ3', vdevs: 2, width: 8 },
    scrub: { function: 'SCRUB', state: 'FINISHED', errors: 0, percentage: 100, finished_at_ms: Date.now() - 13 * 86_400_000 },
  },
  {
    name: 'flash-vm',
    status: 'ONLINE',
    healthy: true,
    size: 12_800_000_000_000,
    allocated: 6_912_000_000_000,
    free: 5_888_000_000_000,
    fragmentation: '3%',
    usage_percent: 54,
    is_decrypted: true,
    redundancy: { type: 'MIRROR', vdevs: 4, width: 2 },
    scrub: { function: 'SCRUB', state: 'SCANNING', errors: 0, percentage: 46.2, finished_at_ms: null },
  },
];

export const demoStorageDisks = [
  // tank — 2 RAIDZ2 vdevs of 6 x 8 TB
  ...Array.from({ length: 12 }, (_, i) => ({
    name: `sd${'abcdefghijkl'[i]}`,
    type: 'HDD',
    model: 'WDC WUH721818ALE6L4',
    serial: `DEMO-TANK-${String(i + 1).padStart(2, '0')}`,
    size: 8_001_563_222_016,
    pool: 'tank',
    vdev_type: `raidz2-${Math.floor(i / 6)}`,
    zfs_status: 'ONLINE',
    read_errors: 0,
    write_errors: 0,
    checksum_errors: i === 9 ? 2 : 0,
    temperature_c: 34 + (i % 5),
    transfermode: 'SATA/600',
  })),
  // tank-backup — 2 RAIDZ3 vdevs of 8 x 10 TB
  ...Array.from({ length: 16 }, (_, i) => ({
    name: i < 14 ? `sd${'mnopqrstuvwxyz'[i]}` : `sda${'ab'[i - 14]}`,
    type: 'HDD',
    model: 'ST10000NM017B',
    serial: `DEMO-BKUP-${String(i + 1).padStart(2, '0')}`,
    size: 10_000_831_348_736,
    pool: 'tank-backup',
    vdev_type: `raidz3-${Math.floor(i / 8)}`,
    zfs_status: 'ONLINE',
    read_errors: 0,
    write_errors: 0,
    checksum_errors: 0,
    temperature_c: i === 10 ? 58 : 36 + (i % 6),
    transfermode: 'SAS/12Gb',
  })),
  // flash-vm — 4 mirrors of 2 x 3.2 TB NVMe
  ...Array.from({ length: 8 }, (_, i) => ({
    name: `nvme${i}n1`,
    type: 'SSD',
    model: 'KCM61VUL3T20',
    serial: `DEMO-FLASH-${String(i + 1).padStart(2, '0')}`,
    size: 3_200_631_791_616,
    pool: 'flash-vm',
    vdev_type: `mirror-${Math.floor(i / 2)}`,
    zfs_status: 'ONLINE',
    read_errors: 0,
    write_errors: 0,
    checksum_errors: 0,
    temperature_c: 41 + (i % 4),
    transfermode: 'NVMe',
  })),
  // hot spare + unassigned boot mirror
  { name: 'sdac', type: 'HDD', model: 'WDC WUH721818ALE6L4', serial: 'DEMO-SPARE-01', size: 8_001_563_222_016, pool: 'tank', vdev_type: 'spare', zfs_status: 'AVAIL', read_errors: 0, write_errors: 0, checksum_errors: 0, temperature_c: 31, transfermode: 'SATA/600' },
  { name: 'sdad', type: 'SSD', model: 'MTFDDAV240TDU', serial: 'DEMO-BOOT-01', size: 240_057_409_536, pool: null, vdev_type: null, zfs_status: null, read_errors: null, write_errors: null, checksum_errors: null, temperature_c: 29, transfermode: 'SATA/600' },
  { name: 'sdae', type: 'SSD', model: 'MTFDDAV240TDU', serial: 'DEMO-BOOT-02', size: 240_057_409_536, pool: null, vdev_type: null, zfs_status: null, read_errors: null, write_errors: null, checksum_errors: null, temperature_c: 30, transfermode: 'SATA/600' },
];

export const demoStorageDatasets = [
  { id: 'tank/vm-images', name: 'vm-images', pool: 'tank', type: 'FILESYSTEM', mountpoint: '/mnt/tank/vm-images', encrypted: false, locked: false, used_bytes: 14_800_000_000_000, available_bytes: 25_600_000_000_000, quota_bytes: 0 },
  { id: 'tank/media', name: 'media', pool: 'tank', type: 'FILESYSTEM', mountpoint: '/mnt/tank/media', encrypted: false, locked: false, used_bytes: 9_200_000_000_000, available_bytes: 25_600_000_000_000, quota_bytes: 12_000_000_000_000 },
  { id: 'tank/projects', name: 'projects', pool: 'tank', type: 'FILESYSTEM', mountpoint: '/mnt/tank/projects', encrypted: true, locked: false, used_bytes: 7_400_000_000_000, available_bytes: 25_600_000_000_000, quota_bytes: 0 },
  { id: 'tank/archive', name: 'archive', pool: 'tank', type: 'FILESYSTEM', mountpoint: '/mnt/tank/archive', encrypted: true, locked: true, used_bytes: 3_260_000_000_000, available_bytes: 25_600_000_000_000, quota_bytes: 0 },
  { id: 'tank/home', name: 'home', pool: 'tank', type: 'FILESYSTEM', mountpoint: '/mnt/tank/home', encrypted: false, locked: false, used_bytes: 3_100_000_000_000, available_bytes: 25_600_000_000_000, quota_bytes: 4_000_000_000_000 },
  { id: 'tank/iso', name: 'iso', pool: 'tank', type: 'FILESYSTEM', mountpoint: '/mnt/tank/iso', encrypted: false, locked: false, used_bytes: 640_000_000_000, available_bytes: 25_600_000_000_000, quota_bytes: 0 },
  { id: 'tank-backup/pve-vzdump', name: 'pve-vzdump', pool: 'tank-backup', type: 'FILESYSTEM', mountpoint: '/mnt/tank-backup/pve-vzdump', encrypted: false, locked: false, used_bytes: 41_200_000_000_000, available_bytes: 17_280_000_000_000, quota_bytes: 0 },
  { id: 'tank-backup/nvr-footage', name: 'nvr-footage', pool: 'tank-backup', type: 'FILESYSTEM', mountpoint: '/mnt/tank-backup/nvr-footage', encrypted: false, locked: false, used_bytes: 28_600_000_000_000, available_bytes: 17_280_000_000_000, quota_bytes: 32_000_000_000_000 },
  { id: 'tank-backup/offsite-stage', name: 'offsite-stage', pool: 'tank-backup', type: 'FILESYSTEM', mountpoint: '/mnt/tank-backup/offsite-stage', encrypted: true, locked: false, used_bytes: 7_800_000_000_000, available_bytes: 17_280_000_000_000, quota_bytes: 0 },
  { id: 'tank-backup/freesdn-config', name: 'freesdn-config', pool: 'tank-backup', type: 'FILESYSTEM', mountpoint: '/mnt/tank-backup/freesdn-config', encrypted: true, locked: false, used_bytes: 1_120_000_000_000, available_bytes: 17_280_000_000_000, quota_bytes: 0 },
  { id: 'flash-vm/pve-rbd-cache', name: 'pve-rbd-cache', pool: 'flash-vm', type: 'VOLUME', mountpoint: null, encrypted: false, locked: false, used_bytes: 4_200_000_000_000, available_bytes: 5_888_000_000_000, quota_bytes: 0 },
  { id: 'flash-vm/db-volumes', name: 'db-volumes', pool: 'flash-vm', type: 'VOLUME', mountpoint: null, encrypted: false, locked: false, used_bytes: 2_712_000_000_000, available_bytes: 5_888_000_000_000, quota_bytes: 0 },
];

/** 24 most recent of 1,284 — the page shows the "showing N of M" banner. */
export const demoStorageSnapshots = [
  'tank/vm-images',
  'tank/projects',
  'tank/home',
  'tank-backup/pve-vzdump',
  'tank-backup/nvr-footage',
  'tank-backup/freesdn-config',
].flatMap((dataset, d) =>
  Array.from({ length: 4 }, (_, i) => {
    const minutesAgo = 240 + i * 1440 + d * 17;
    const stamp = new Date(new Date('2026-06-07T14:30:00Z').getTime() - minutesAgo * 60_000)
      .toISOString()
      .slice(0, 16)
      .replace('T', '_')
      .replace(':', '-');
    return {
      id: `${dataset}@auto-${stamp}`,
      name: `auto-${stamp}`,
      dataset,
      created_at: iso(minutesAgo),
      used_bytes: [18_400_000_000, 4_120_000_000, 962_000_000, 74_800_000_000, 141_000_000_000, 8_400_000_000][d] - i * 310_000_000,
    };
  }),
);

export const demoStorageInventory = {
  controller_id: demoIds.truenas,
  name: 'TrueNAS Backup Pool',
  host: 'truenas.demo.local',
  transport: 'ws',
  system: {
    version: 'TrueNAS-SCALE-25.10.0',
    hostname: 'truenas-backup-01',
    product: 'TRUENAS-R50B',
    serial: 'DEMO-TN-0001',
    physmem: 137_438_953_472,
    uptime_seconds: 18_800_000,
    timezone: 'America/New_York',
  },
  health: { status: 'warning', pool_count: 3, alert_count: 3, critical_alert_count: 0 },
  alerts: [
    { level: 'WARNING', klass: 'ZpoolCapacityWarning', message: 'Pool tank-backup is 82% full. Consider pruning old vzdump archives or adding a vdev.', at_ms: Date.now() - 18 * 60_000, one_shot: false },
    { level: 'WARNING', klass: 'SMARTTemperature', message: 'Device DEMO-BKUP-11 is reporting 58 C, above the 55 C warning threshold.', at_ms: Date.now() - 96 * 60_000, one_shot: false },
    { level: 'INFO', klass: 'ScrubStarted', message: 'Scrub of pool flash-vm started and is 46% complete.', at_ms: Date.now() - 214 * 60_000, one_shot: true },
  ],
  services: [
    { service: 'cifs', state: 'RUNNING', enabled: true },
    { service: 'nfs', state: 'RUNNING', enabled: true },
    { service: 'iscsitarget', state: 'RUNNING', enabled: true },
    { service: 'ssh', state: 'RUNNING', enabled: true },
    { service: 'snmp', state: 'STOPPED', enabled: false },
  ],
  data_protection: { snapshot_tasks: 9, replication: 3, cloudsync: 1 },
  pools: demoStoragePools,
  disks: demoStorageDisks,
  datasets: demoStorageDatasets,
  snapshot_count: 1_284,
  snapshots: demoStorageSnapshots,
};

// ===========================================================================
// BACKUP — FreeSDN config backups, schedules, destinations, restore points
// ===========================================================================

export const demoStorageLocations = [
  { id: 'c0000000-0000-4000-8000-000000000001', name: 'Appliance volume', description: 'Local NVMe volume on the FreeSDN controller. Fast, but not off-box.', storage_type: 'local', is_active: true, is_default: true, last_test_at: iso(180), last_test_status: 'success', last_test_message: 'Wrote and removed a 4 MiB probe file in 41 ms.', created_at: iso(60 * 24 * 26), updated_at: iso(180) },
  { id: 'c0000000-0000-4000-8000-000000000002', name: 'TrueNAS offsite-stage', description: 'SMB share on tank-backup/offsite-stage, replicated nightly to the DR site.', storage_type: 'sftp', is_active: true, is_default: false, last_test_at: iso(184), last_test_status: 'success', last_test_message: 'Connected and listed the remote path in 118 ms.', created_at: iso(60 * 24 * 24), updated_at: iso(184) },
  { id: 'c0000000-0000-4000-8000-000000000003', name: 'Object storage (S3 compatible)', description: 'Versioned bucket with a 180 day lifecycle rule for weekly vault backups.', storage_type: 's3', is_active: true, is_default: false, last_test_at: iso(190), last_test_status: 'success', last_test_message: 'PutObject / GetObject / DeleteObject round trip in 612 ms.', created_at: iso(60 * 24 * 21), updated_at: iso(190) },
  { id: 'c0000000-0000-4000-8000-000000000004', name: 'DR site SFTP', description: 'Standby controller at the branch office. Currently failing its connection test.', storage_type: 'sftp', is_active: true, is_default: false, last_test_at: iso(2885), last_test_status: 'failed', last_test_message: 'Host key for the DR host changed since it was enrolled. Re-verify the fingerprint before re-enabling uploads.', created_at: iso(60 * 24 * 18), updated_at: iso(2885) },
  { id: 'c0000000-0000-4000-8000-000000000005', name: 'Legacy NAS (retired)', description: 'Kept for read-only restores of pre-migration archives.', storage_type: 'nfs', is_active: false, is_default: false, last_test_at: iso(60 * 24 * 40), last_test_status: 'success', last_test_message: 'Mount succeeded.', created_at: iso(60 * 24 * 40), updated_at: iso(60 * 24 * 12) },
];

export const demoBackupStorageTypes = {
  types: [
    { id: 'local', name: 'Local filesystem', description: 'A directory on the FreeSDN controller itself. Fastest, but shares the fate of the appliance.', icon: 'hard-drive', fields: [{ name: 'path', type: 'string', label: 'Directory path', required: false, default: '/var/lib/freesdn/backups', placeholder: '/var/lib/freesdn/backups' }] },
    { id: 's3', name: 'S3 compatible object storage', description: 'Any S3 API endpoint: AWS S3, MinIO, Ceph RGW, Backblaze B2.', icon: 'cloud', fields: [{ name: 'bucket', type: 'string', label: 'Bucket', required: true, placeholder: 'freesdn-backups' }, { name: 'region', type: 'string', label: 'Region', required: false, placeholder: 'us-east-1' }, { name: 'endpoint_url', type: 'string', label: 'Endpoint URL', required: false, placeholder: 'https://s3.example.internal' }, { name: 'access_key', type: 'string', label: 'Access key ID', required: true }, { name: 'secret_key', type: 'password', label: 'Secret access key', required: true }, { name: 'path_prefix', type: 'string', label: 'Path prefix', required: false, placeholder: 'controllers/hq' }] },
    { id: 'sftp', name: 'SFTP', description: 'Upload over SSH to any reachable host. Password or private key.', icon: 'server', fields: [{ name: 'host', type: 'string', label: 'Host', required: true }, { name: 'port', type: 'number', label: 'Port', required: false, default: 22 }, { name: 'username', type: 'string', label: 'Username', required: true }, { name: 'password', type: 'password', label: 'Password', required: false }, { name: 'private_key_path', type: 'string', label: 'Private key path', required: false }, { name: 'remote_path', type: 'string', label: 'Remote path', required: false, placeholder: '/srv/backups/freesdn' }] },
    { id: 'ftp', name: 'FTP / FTPS', description: 'Legacy FTP target. Use FTPS unless the network is fully trusted.', icon: 'folder-sync', fields: [{ name: 'host', type: 'string', label: 'Host', required: true }, { name: 'port', type: 'number', label: 'Port', required: false, default: 21 }, { name: 'username', type: 'string', label: 'Username', required: true }, { name: 'password', type: 'password', label: 'Password', required: true }, { name: 'use_tls', type: 'boolean', label: 'Require TLS (FTPS)', required: false, default: true }] },
    { id: 'nfs', name: 'NFS export', description: 'Mounted NFS export, typically from a TrueNAS or other NAS appliance.', icon: 'database', fields: [{ name: 'host', type: 'string', label: 'Server', required: true }, { name: 'remote_path', type: 'string', label: 'Export path', required: true, placeholder: '/mnt/tank-backup/freesdn-config' }] },
    { id: 'webdav', name: 'WebDAV', description: 'Nextcloud, ownCloud, or any WebDAV endpoint.', icon: 'cloud', fields: [{ name: 'url', type: 'string', label: 'WebDAV URL', required: true }, { name: 'username', type: 'string', label: 'Username', required: true }, { name: 'password', type: 'password', label: 'Password', required: true }, { name: 'path', type: 'string', label: 'Remote folder', required: false }] },
  ],
};

export const demoBackupSchedules = [
  { id: 'b5000000-0000-4000-8000-000000000001', name: 'Nightly config snapshot', description: 'Secret-free .fsdn snapshot of every site, kept for 30 days on the appliance volume.', cron_expression: '0 2 * * *', timezone: 'America/Chicago', backup_type: 'full', site_id: null, storage_type: 'local', storage_location_id: 'c0000000-0000-4000-8000-000000000001', is_encrypted: true, retention_days: 30, max_backups: 30, is_enabled: true, last_run_at: iso(750), next_run_at: iso(-690), created_at: iso(60 * 24 * 26), device_ids: [], include_devices: true, include_vlans: true, include_ssids: true, include_users: true, include_automation: true },
  { id: 'b5000000-0000-4000-8000-000000000002', name: 'Weekly offsite vault', description: 'Passphrase-sealed .fsdnvault including credentials, pushed to object storage.', cron_expression: '0 3 * * 0', timezone: 'America/Chicago', backup_type: 'full', site_id: null, storage_type: 's3', storage_location_id: 'c0000000-0000-4000-8000-000000000003', is_encrypted: true, retention_days: 180, max_backups: 26, is_enabled: true, last_run_at: iso(4290), next_run_at: iso(-5790), created_at: iso(60 * 24 * 24), device_ids: [], include_devices: true, include_vlans: true, include_ssids: true, include_users: true, include_automation: true },
  { id: 'b5000000-0000-4000-8000-000000000003', name: 'HQ switch + AP configs', description: 'Device-config only, every six hours, for fast single-device rollback.', cron_expression: '0 */6 * * *', timezone: 'America/Chicago', backup_type: 'device_config', site_id: demoIds.hq, storage_type: 'local', storage_location_id: 'c0000000-0000-4000-8000-000000000001', is_encrypted: false, retention_days: 14, max_backups: 56, is_enabled: true, last_run_at: iso(150), next_run_at: iso(-210), created_at: iso(60 * 24 * 20), device_ids: ['dev-sw-core', 'dev-ap-lobby'], include_devices: true, include_vlans: true, include_ssids: true, include_users: false, include_automation: false },
  { id: 'b5000000-0000-4000-8000-000000000004', name: 'Branch device configs', description: 'Paused while the branch is being re-cabled — resume after the cutover.', cron_expression: '0 4 * * *', timezone: 'America/Denver', backup_type: 'site_config', site_id: demoIds.branch, storage_type: 'sftp', storage_location_id: 'c0000000-0000-4000-8000-000000000004', is_encrypted: true, retention_days: 30, max_backups: 30, is_enabled: false, last_run_at: iso(2870), next_run_at: null, created_at: iso(60 * 24 * 18), device_ids: [], include_devices: true, include_vlans: true, include_ssids: true, include_users: false, include_automation: false },
];

export const demoBackups = [
  { id: 'b0000000-0000-4000-8000-000000000001', name: 'Nightly config snapshot 2026-06-07', description: 'Scheduled .fsdn snapshot, all sites', backup_type: 'full', status: 'completed', progress: 100, started_at: iso(750), completed_at: iso(748), storage_type: 'local', storage_location_id: 'c0000000-0000-4000-8000-000000000001', storage_path: 'freesdn/2026/06/nightly-2026-06-07.fsdn', file_size: 231_735_296, site_id: null, device_ids: [], include_devices: true, include_vlans: true, include_ssids: true, include_users: true, include_automation: true, is_encrypted: true, retention_days: 30, expires_at: iso(-43_200), error_message: null, created_at: iso(750), created_by_id: null, schedule_id: 'b5000000-0000-4000-8000-000000000001' },
  { id: 'b0000000-0000-4000-8000-000000000002', name: 'Nightly config snapshot 2026-06-06', description: 'Scheduled .fsdn snapshot, all sites', backup_type: 'full', status: 'completed', progress: 100, started_at: iso(2190), completed_at: iso(2188), storage_type: 'local', storage_location_id: 'c0000000-0000-4000-8000-000000000001', storage_path: 'freesdn/2026/06/nightly-2026-06-06.fsdn', file_size: 229_638_144, site_id: null, device_ids: [], include_devices: true, include_vlans: true, include_ssids: true, include_users: true, include_automation: true, is_encrypted: true, retention_days: 30, expires_at: iso(-41_760), error_message: null, created_at: iso(2190), created_by_id: null, schedule_id: 'b5000000-0000-4000-8000-000000000001' },
  { id: 'b0000000-0000-4000-8000-000000000003', name: 'Nightly config snapshot 2026-06-05', description: 'Scheduled .fsdn snapshot, all sites', backup_type: 'full', status: 'completed', progress: 100, started_at: iso(3630), completed_at: iso(3627), storage_type: 'local', storage_location_id: 'c0000000-0000-4000-8000-000000000001', storage_path: 'freesdn/2026/06/nightly-2026-06-05.fsdn', file_size: 227_540_992, site_id: null, device_ids: [], include_devices: true, include_vlans: true, include_ssids: true, include_users: true, include_automation: true, is_encrypted: true, retention_days: 30, expires_at: iso(-40_320), error_message: null, created_at: iso(3630), created_by_id: null, schedule_id: 'b5000000-0000-4000-8000-000000000001' },
  { id: 'b0000000-0000-4000-8000-000000000004', name: 'Nightly config snapshot 2026-06-04', description: 'Scheduled .fsdn snapshot, all sites', backup_type: 'full', status: 'completed', progress: 100, started_at: iso(5070), completed_at: iso(5068), storage_type: 'local', storage_location_id: 'c0000000-0000-4000-8000-000000000001', storage_path: 'freesdn/2026/06/nightly-2026-06-04.fsdn', file_size: 224_395_264, site_id: null, device_ids: [], include_devices: true, include_vlans: true, include_ssids: true, include_users: true, include_automation: true, is_encrypted: true, retention_days: 30, expires_at: iso(-38_880), error_message: null, created_at: iso(5070), created_by_id: null, schedule_id: 'b5000000-0000-4000-8000-000000000001' },
  { id: 'b0000000-0000-4000-8000-000000000005', name: 'Nightly config snapshot 2026-06-03', description: 'Scheduled .fsdn snapshot, all sites', backup_type: 'full', status: 'completed', progress: 100, started_at: iso(6510), completed_at: iso(6507), storage_type: 'local', storage_location_id: 'c0000000-0000-4000-8000-000000000001', storage_path: 'freesdn/2026/06/nightly-2026-06-03.fsdn', file_size: 222_298_112, site_id: null, device_ids: [], include_devices: true, include_vlans: true, include_ssids: true, include_users: true, include_automation: true, is_encrypted: true, retention_days: 30, expires_at: iso(-37_440), error_message: null, created_at: iso(6510), created_by_id: null, schedule_id: 'b5000000-0000-4000-8000-000000000001' },
  { id: 'b0000000-0000-4000-8000-000000000006', name: 'Nightly config snapshot 2026-06-02', description: 'Scheduled .fsdn snapshot, all sites', backup_type: 'full', status: 'completed', progress: 100, started_at: iso(7950), completed_at: iso(7948), storage_type: 'local', storage_location_id: 'c0000000-0000-4000-8000-000000000001', storage_path: 'freesdn/2026/06/nightly-2026-06-02.fsdn', file_size: 219_152_384, site_id: null, device_ids: [], include_devices: true, include_vlans: true, include_ssids: true, include_users: true, include_automation: true, is_encrypted: true, retention_days: 30, expires_at: iso(-36_000), error_message: null, created_at: iso(7950), created_by_id: null, schedule_id: 'b5000000-0000-4000-8000-000000000001' },
  { id: 'b0000000-0000-4000-8000-000000000007', name: 'Weekly offsite vault 2026-06-07', description: 'Passphrase-sealed .fsdnvault including credential material', backup_type: 'full', status: 'completed', progress: 100, started_at: iso(4290), completed_at: iso(4272), storage_type: 's3', storage_location_id: 'c0000000-0000-4000-8000-000000000003', storage_path: 's3://freesdn-backups/controllers/hq/vault-2026-06-07.fsdnvault', file_size: 1_186_988_032, site_id: null, device_ids: [], include_devices: true, include_vlans: true, include_ssids: true, include_users: true, include_automation: true, is_encrypted: true, retention_days: 180, expires_at: iso(-255_000), error_message: null, created_at: iso(4290), created_by_id: null, schedule_id: 'b5000000-0000-4000-8000-000000000002' },
  { id: 'b0000000-0000-4000-8000-000000000008', name: 'Weekly offsite vault 2026-05-31', description: 'Passphrase-sealed .fsdnvault including credential material', backup_type: 'full', status: 'completed', progress: 100, started_at: iso(14_370), completed_at: iso(14_351), storage_type: 's3', storage_location_id: 'c0000000-0000-4000-8000-000000000003', storage_path: 's3://freesdn-backups/controllers/hq/vault-2026-05-31.fsdnvault', file_size: 1_172_307_968, site_id: null, device_ids: [], include_devices: true, include_vlans: true, include_ssids: true, include_users: true, include_automation: true, is_encrypted: true, retention_days: 180, expires_at: iso(-244_920), error_message: null, created_at: iso(14_370), created_by_id: null, schedule_id: 'b5000000-0000-4000-8000-000000000002' },
  { id: 'b0000000-0000-4000-8000-000000000009', name: 'Weekly offsite vault 2026-05-24', description: 'Passphrase-sealed .fsdnvault including credential material', backup_type: 'full', status: 'failed', progress: 42, started_at: iso(24_450), completed_at: iso(24_446), storage_type: 'sftp', storage_location_id: 'c0000000-0000-4000-8000-000000000004', storage_path: null, file_size: null, site_id: null, device_ids: [], include_devices: true, include_vlans: true, include_ssids: true, include_users: true, include_automation: true, is_encrypted: true, retention_days: 180, expires_at: null, error_message: 'Upload aborted: the DR host presented a different SSH host key than the one recorded when the destination was enrolled. Re-verify the fingerprint in Storage Locations, then re-run this backup.', created_at: iso(24_450), created_by_id: null, schedule_id: 'b5000000-0000-4000-8000-000000000002' },
  { id: 'b0000000-0000-4000-8000-000000000010', name: 'HQ device configs 12:00', description: 'Six-hourly device-config capture for HQ Campus', backup_type: 'device_config', status: 'completed', progress: 100, started_at: iso(150), completed_at: iso(150), storage_type: 'local', storage_location_id: 'c0000000-0000-4000-8000-000000000001', storage_path: 'freesdn/2026/06/hq-devices-1200.fsdn', file_size: 3_842_048, site_id: demoIds.hq, device_ids: ['dev-sw-core', 'dev-ap-lobby', 'dev-fw-hq'], include_devices: true, include_vlans: true, include_ssids: true, include_users: false, include_automation: false, is_encrypted: false, retention_days: 14, expires_at: iso(-20_010), error_message: null, created_at: iso(150), created_by_id: null, schedule_id: 'b5000000-0000-4000-8000-000000000003' },
  { id: 'b0000000-0000-4000-8000-000000000011', name: 'HQ device configs 06:00', description: 'Six-hourly device-config capture for HQ Campus', backup_type: 'device_config', status: 'completed', progress: 100, started_at: iso(510), completed_at: iso(510), storage_type: 'local', storage_location_id: 'c0000000-0000-4000-8000-000000000001', storage_path: 'freesdn/2026/06/hq-devices-0600.fsdn', file_size: 3_838_976, site_id: demoIds.hq, device_ids: ['dev-sw-core', 'dev-ap-lobby', 'dev-fw-hq'], include_devices: true, include_vlans: true, include_ssids: true, include_users: false, include_automation: false, is_encrypted: false, retention_days: 14, expires_at: iso(-19_650), error_message: null, created_at: iso(510), created_by_id: null, schedule_id: 'b5000000-0000-4000-8000-000000000003' },
  { id: 'b0000000-0000-4000-8000-000000000012', name: 'Pre-VLAN-40-rollout snapshot', description: 'Manual safety copy taken before pushing the camera VLAN to the branch', backup_type: 'site_config', status: 'completed', progress: 100, started_at: iso(1_710), completed_at: iso(1_709), storage_type: 'local', storage_location_id: 'c0000000-0000-4000-8000-000000000001', storage_path: 'freesdn/2026/06/pre-vlan40.fsdn', file_size: 42_614_784, site_id: demoIds.branch, device_ids: [], include_devices: true, include_vlans: true, include_ssids: true, include_users: false, include_automation: false, is_encrypted: false, retention_days: 90, expires_at: iso(-127_890), error_message: null, created_at: iso(1_710), created_by_id: demoUser.id, schedule_id: null },
  { id: 'b0000000-0000-4000-8000-000000000013', name: 'Datacenter site config', description: 'Manual export before the Proxmox 8.3.5 maintenance window', backup_type: 'site_config', status: 'completed', progress: 100, started_at: iso(2_940), completed_at: iso(2_938), storage_type: 'local', storage_location_id: 'c0000000-0000-4000-8000-000000000001', storage_path: 'freesdn/2026/06/dc-site-config.fsdn', file_size: 61_857_792, site_id: demoIds.dc, device_ids: [], include_devices: true, include_vlans: true, include_ssids: false, include_users: false, include_automation: true, is_encrypted: false, retention_days: 90, expires_at: iso(-126_660), error_message: null, created_at: iso(2_940), created_by_id: demoUser.id, schedule_id: null },
  { id: 'b0000000-0000-4000-8000-000000000014', name: 'Pre-restore rollback slot', description: 'Captured automatically before restoring "Pre-VLAN-40-rollout snapshot"', backup_type: 'rollback_slot', status: 'completed', progress: 100, started_at: iso(1_640), completed_at: iso(1_639), storage_type: 'local', storage_location_id: 'c0000000-0000-4000-8000-000000000001', storage_path: 'freesdn/2026/06/rollback-2026-06-06.fsdn', file_size: 44_040_192, site_id: demoIds.branch, device_ids: [], include_devices: true, include_vlans: true, include_ssids: true, include_users: true, include_automation: true, is_encrypted: true, retention_days: 30, expires_at: iso(-41_560), error_message: null, created_at: iso(1_640), created_by_id: null, schedule_id: null, rollback_for_restore_job_id: 'd0000000-0000-4000-8000-000000000001' },
  { id: 'b0000000-0000-4000-8000-000000000015', name: 'Ad-hoc export before adapter upgrade', description: 'Taken by the on-call engineer before bumping the Omada adapter', backup_type: 'full', status: 'completed', progress: 100, started_at: iso(9_390), completed_at: iso(9_387), storage_type: 'local', storage_location_id: 'c0000000-0000-4000-8000-000000000001', storage_path: 'freesdn/2026/06/pre-adapter-upgrade.fsdn', file_size: 216_006_656, site_id: null, device_ids: [], include_devices: true, include_vlans: true, include_ssids: true, include_users: true, include_automation: true, is_encrypted: false, retention_days: 30, expires_at: iso(-33_810), error_message: null, created_at: iso(9_390), created_by_id: demoUser.id, schedule_id: null },
  { id: 'b0000000-0000-4000-8000-000000000016', name: 'Branch site config 2026-05-30', description: 'Last successful run of the now-paused branch schedule', backup_type: 'site_config', status: 'completed', progress: 100, started_at: iso(2_870), completed_at: iso(2_868), storage_type: 'sftp', storage_location_id: 'c0000000-0000-4000-8000-000000000004', storage_path: '/srv/backups/freesdn/branch-2026-05-30.fsdn', file_size: 38_797_312, site_id: demoIds.branch, device_ids: [], include_devices: true, include_vlans: true, include_ssids: true, include_users: false, include_automation: false, is_encrypted: true, retention_days: 30, expires_at: iso(-40_330), error_message: null, created_at: iso(2_870), created_by_id: null, schedule_id: 'b5000000-0000-4000-8000-000000000004' },
  { id: 'b0000000-0000-4000-8000-000000000017', name: 'Nightly config snapshot 2026-06-08', description: 'Scheduled .fsdn snapshot, all sites', backup_type: 'full', status: 'in_progress', progress: 62, started_at: iso(3), completed_at: null, storage_type: 'local', storage_location_id: 'c0000000-0000-4000-8000-000000000001', storage_path: null, file_size: null, site_id: null, device_ids: [], include_devices: true, include_vlans: true, include_ssids: true, include_users: true, include_automation: true, is_encrypted: true, retention_days: 30, expires_at: null, error_message: null, created_at: iso(3), created_by_id: demoUser.id, schedule_id: 'b5000000-0000-4000-8000-000000000001' },
  { id: 'b0000000-0000-4000-8000-000000000018', name: 'Queued: HQ device configs 18:00', description: 'Waiting on the running nightly job to release the export lock', backup_type: 'device_config', status: 'pending', progress: 0, started_at: null, completed_at: null, storage_type: 'local', storage_location_id: 'c0000000-0000-4000-8000-000000000001', storage_path: null, file_size: null, site_id: demoIds.hq, device_ids: ['dev-sw-core', 'dev-ap-lobby', 'dev-fw-hq'], include_devices: true, include_vlans: true, include_ssids: true, include_users: false, include_automation: false, is_encrypted: false, retention_days: 14, expires_at: null, error_message: null, created_at: iso(1), created_by_id: null, schedule_id: 'b5000000-0000-4000-8000-000000000003' },
];

export const demoBackupStats = {
  total_backups: demoBackups.length,
  completed_backups: demoBackups.filter((b) => b.status === 'completed').length,
  failed_backups: demoBackups.filter((b) => b.status === 'failed').length,
  in_progress: demoBackups.filter((b) => b.status === 'in_progress').length,
  total_size_bytes: demoBackups.reduce((sum, b) => sum + (b.file_size || 0), 0),
  total_size_gb: Number((demoBackups.reduce((sum, b) => sum + (b.file_size || 0), 0) / 1_073_741_824).toFixed(2)),
  recent_backups: demoBackups.slice(0, 5),
  schedules_enabled: demoBackupSchedules.filter((s) => s.is_enabled).length,
  schedules_disabled: demoBackupSchedules.filter((s) => !s.is_enabled).length,
  latest_at: iso(3),
};

export const demoBackupManifest = {
  format_version: '2.1',
  source_version: DEMO_PLATFORM_VERSION,
  organization_id: demoIds.org,
  contributors: [
    { id: 'core.organizations', schema_version: '2.0', counts: { organizations: 1, sites: 3 }, restorable: true, incompatibility_reason: null },
    { id: 'core.users', schema_version: '2.0', counts: { users: 12, roles: 5, site_grants: 9 }, restorable: true, incompatibility_reason: null },
    { id: 'network.inventory', schema_version: '2.1', counts: { devices: 92, controllers: 7, vlans: 4 }, restorable: true, incompatibility_reason: null },
    { id: 'network.wifi', schema_version: '2.0', counts: { ssids: 3, radius_profiles: 1 }, restorable: true, incompatibility_reason: null },
    { id: 'firewall.rules', schema_version: '2.0', counts: { rules: 148, aliases: 31, nat: 22 }, restorable: true, incompatibility_reason: null },
    { id: 'cameras.inventory', schema_version: '2.0', counts: { cameras: 3, nvrs: 2, views: 4 }, restorable: true, incompatibility_reason: null },
    { id: 'voip.extensions', schema_version: '2.0', counts: { extensions: 22, trunks: 2 }, restorable: true, incompatibility_reason: null },
    { id: 'hypervisor.clusters', schema_version: '2.0', counts: { clusters: 1, backup_jobs: 3 }, restorable: true, incompatibility_reason: null },
    { id: 'storage.appliances', schema_version: '2.0', counts: { appliances: 1, snapshot_tasks: 9 }, restorable: true, incompatibility_reason: null },
    { id: 'automation.workflows', schema_version: '1.4', counts: { workflows: 6, triggers: 11 }, restorable: false, incompatibility_reason: 'Written by FreeSDN 25.12 with workflow schema 1.4. This build reads 2.0 and later; export the workflows separately after restoring.' },
  ],
};

export const demoRestoreJobs = [
  { id: 'd0000000-0000-4000-8000-000000000001', backup_id: 'b0000000-0000-4000-8000-000000000012', status: 'completed', progress: 100, started_at: iso(1_638), completed_at: iso(1_632), error_message: null, dry_run: false, dry_run_report: null, created_at: iso(1_640) },
  { id: 'd0000000-0000-4000-8000-000000000002', backup_id: 'b0000000-0000-4000-8000-000000000007', status: 'completed', progress: 100, started_at: iso(11_520), completed_at: iso(11_502), error_message: null, dry_run: true, dry_run_report: { devices: { would_create: 0, would_update: 92, would_skip: 0 }, vlans: { would_create: 1, would_update: 3, would_skip: 0 }, ssids: { would_create: 0, would_update: 3, would_skip: 0 }, users: { would_create: 0, would_update: 12, would_skip: 0 }, automation_rules: { would_create: 0, would_update: 6, would_skip: 0 }, warnings: ['Controller "UniFi Branch" is offline; its device rows will be updated in FreeSDN but not pushed until it reconnects.'] }, created_at: iso(11_522) },
];

/** Staged device writes awaiting review in the Pending Changes drawer. */
export const demoStagedChanges = [
  { id: 'e0000000-0000-4000-8000-000000000001', organization_id: demoIds.org, site_id: demoIds.dc, controller_id: demoIds.truenas, omada_site_id: null, feature: 'storage.snapshot.create', operation: 'create', payload: { dataset: 'tank/projects', name: 'pre-migration-2026-06-07', recursive: true }, target_id: 'tank/projects', status: 'pending', created_at: iso(34), created_by: demoUser.email, applied_at: null, applied_response: null, failure_reason: null, notes: 'Requested before the projects share is re-tiered onto flash-vm.' },
  { id: 'e0000000-0000-4000-8000-000000000002', organization_id: demoIds.org, site_id: demoIds.dc, controller_id: demoIds.truenas, omada_site_id: null, feature: 'storage.pool.scrub', operation: 'create', payload: { pool: 'tank-backup' }, target_id: 'tank-backup', status: 'pending', created_at: iso(21), created_by: demoUser.email, applied_at: null, applied_response: null, failure_reason: null, notes: 'Manual scrub ahead of the quarterly integrity report.' },
  { id: 'e0000000-0000-4000-8000-000000000003', organization_id: demoIds.org, site_id: demoIds.dc, controller_id: demoIds.proxmox, omada_site_id: null, feature: 'proxmox.backup.prune', operation: 'create', payload: { node: 'pve-node-01', storage: 'pbs-dc', keep_last: 3, keep_daily: 7, keep_weekly: 4, keep_monthly: 3 }, target_id: 'pve-node-01:pbs-dc', status: 'pending', created_at: iso(47), created_by: demoUser.email, applied_at: null, applied_response: null, failure_reason: null, notes: 'Reclaims 3 of 12 archives on pbs-dc. Review the preview before applying.' },
  { id: 'e0000000-0000-4000-8000-000000000004', organization_id: demoIds.org, site_id: demoIds.dc, controller_id: demoIds.proxmox, omada_site_id: null, feature: 'proxmox.backup.restore', operation: 'create', payload: { node: 'pve-node-03', vm_type: 'qemu', archive: 'pbs-dc:backup/vm/150/2026-05-31T05:02:11Z', vmid: 150, storage: 'local-zfs', start: false, unique: false }, target_id: '150', status: 'discarded', created_at: iso(1_465), created_by: demoUser.email, applied_at: null, applied_response: null, failure_reason: null, notes: 'Discarded — the lab VM was rebuilt from the template instead.' },
];

// ==== demo fleet: Dashboard, alerts, analytics, security audit, notifications (the first screens a visitor sees) ====
// ═══════════════════════════════════════════════════════════════════════════
//  Dashboard · alerts · analytics · security audit
//  ------------------------------------------------------------------------
//  These fixtures feed the first screens a visitor sees. Every roll-up that
//  CAN be derived from `devices` / `sites` / `controllers` above IS derived,
//  so the landing dashboard cannot drift out of sync with the fleet the way
//  the old hand-copied counts did ("0/8 Online" with seven devices up).
// ═══════════════════════════════════════════════════════════════════════════

// The `iso()` helper at the top of this file is pinned to a HARD-CODED `now`
// (`new Date('2026-06-07T14:30:00Z')`). Anything stamped with it renders as
// "3 months ago" on a live demo -- a "firing" alert dated last quarter reads
// as a dead product. These fixtures therefore carry their own clock, which
// moves. If `now` above is ever changed to `new Date()`, `iso` and `demoIso`
// become the same function and this pair can be deleted.
export const demoNow = new Date();
export const demoIso = (minutesAgo = 0) =>
  new Date(demoNow.getTime() - minutesAgo * 60_000).toISOString();

// `devices` is a heterogeneous array literal -- a switch carries `ports_up`,
// an access point carries `connected_clients` -- so TypeScript infers its
// element type as a UNION and rejects reading a field only some members have.
// Normalising once through an index-signature cast is what lets the roll-ups
// below be DERIVED instead of hand-copied.
export const demoDeviceMetrics = devices.map((entry) => {
  const d = entry as unknown as Record<string, unknown>;
  return {
    id: String(d.id ?? ''),
    name: String(d.name ?? ''),
    type: String(d.device_type ?? 'unknown'),
    status: String(d.status ?? 'unknown'),
    vendor: String(d.vendor ?? 'unknown'),
    site_id: String(d.site_id ?? ''),
    cpu: Number(d.cpu_usage ?? 0),
    memory: Number(d.memory_usage ?? 0),
  };
});

/** Adapter ids are lowercase slugs; the fleet charts want vendor names. */
export const demoVendorLabels: Record<string, string> = {
  'tp-link': 'TP-Link',
  omada: 'TP-Link Omada',
  unifi: 'Ubiquiti',
  unifi_protect: 'Ubiquiti Protect',
  ubiquiti: 'Ubiquiti',
  opnsense: 'OPNsense',
  pfsense: 'pfSense',
  mikrotik: 'MikroTik',
  proxmox: 'Proxmox',
  hikvision: 'Hikvision',
  freepbx: 'FreePBX',
  grandstream: 'Grandstream',
  openwrt: 'OpenWrt',
  truenas: 'TrueNAS',
  onvif: 'ONVIF',
};

export const demoAvg = (values: number[]) =>
  values.length === 0 ? 0 : Math.round(values.reduce((sum, v) => sum + v, 0) / values.length);

export const demoOnlineDevices = demoDeviceMetrics.filter((d) => d.status === 'online');
export const demoOfflineDevices = demoDeviceMetrics.filter((d) => d.status === 'offline');
export const demoDegradedDevices = demoDeviceMetrics.filter(
  (d) => d.status === 'warning' || d.status === 'degraded',
);

export const demoFleetByType = demoDeviceMetrics.reduce<
  Record<string, { total: number; online: number; offline: number }>
>((acc, d) => {
  if (!acc[d.type]) acc[d.type] = { total: 0, online: 0, offline: 0 };
  acc[d.type].total += 1;
  if (d.status === 'online') acc[d.type].online += 1;
  else acc[d.type].offline += 1;
  return acc;
}, {});

export const demoFleetByManufacturer = Object.entries(
  demoDeviceMetrics.reduce<Record<string, number>>((acc, d) => {
    const label = demoVendorLabels[d.vendor] ?? d.vendor;
    acc[label] = (acc[label] ?? 0) + 1;
    return acc;
  }, {}),
)
  .map(([name, count]) => ({ name, count }))
  .sort((a, b) => b.count - a.count);

/** Client population the wireless roll-ups and the client curve share. */
export const demoClientTotals = {
  total: 512,
  online: 486,
  band_2g: 78,
  band_5g: 312,
  band_6g: 96,
};

// ─── Time-series shape ─────────────────────────────────────────────────────
// A demo chart with three points reads as a broken product. Everything below
// is generated from one business-day curve so traffic, client count, latency
// and log volume all peak at the same hours -- deterministic, never random,
// so the curve is identical on every render and every build.

/** Hourly weights, index = UTC hour, 1.0 = the daily peak. */
export const demoDayCurve = [
  0.16, 0.13, 0.11, 0.10, 0.11, 0.15, 0.26, 0.44,
  0.71, 0.89, 0.96, 0.99, 0.83, 0.94, 1.00, 0.97,
  0.90, 0.74, 0.58, 0.47, 0.39, 0.31, 0.24, 0.19,
];

/** Fixed wobble so the curves read as telemetry, not as a formula. */
export const demoJitter = [1.0, 1.04, 0.97, 1.02, 0.95, 1.06, 0.99, 1.03, 0.96, 1.01, 1.05, 0.98];

export const demoCurveAt = (at: Date, index: number) =>
  demoDayCurve[at.getUTCHours()] * demoJitter[index % demoJitter.length];

/** 48 half-hour buckets covering the last 24h. Peak ≈ 940/316 Mbps. */
export const demoTrafficSeries = Array.from({ length: 48 }, (_, i) => {
  const at = new Date(demoNow.getTime() - (47 - i) * 30 * 60_000);
  const w = demoCurveAt(at, i);
  return {
    timestamp: at.toISOString(),
    rx_mbps: Math.round(940 * w),
    tx_mbps: Math.round(316 * w),
    clients: Math.min(
      demoClientTotals.total,
      Math.round(96 + 416 * demoDayCurve[at.getUTCHours()] * demoJitter[(i + 4) % demoJitter.length]),
    ),
  };
});

/**
 * Latency in the same 48 buckets. The last three carry the spike that tripped
 * the firing `network.wan.latency` alert, so the chart explains the alert
 * instead of contradicting it.
 */
export const demoLatencySeries = Array.from({ length: 48 }, (_, i) => {
  const at = new Date(demoNow.getTime() - (47 - i) * 30 * 60_000);
  const w = demoCurveAt(at, i);
  const spiking = i >= 45;
  return {
    timestamp: at.toISOString(),
    // The spike lands on 168 ms, the figure the firing WAN alert quotes.
    latency_ms: spiking ? 152 + (i - 45) * 8 : Math.round(9 + 21 * w),
    jitter_ms: Math.round((2 + 5 * w) * 10) / 10,
    packet_loss_percent: spiking ? 0.9 : Math.round((0.04 + 0.1 * w) * 100) / 100,
  };
});

/** Mbps over one 30-minute bucket, in bytes. */
export const demoBytesPerHalfHourMbit = 225_000_000;
export const demoRxBytes24h = demoTrafficSeries.reduce(
  (sum, p) => sum + p.rx_mbps * demoBytesPerHalfHourMbit,
  0,
);
export const demoTxBytes24h = demoTrafficSeries.reduce(
  (sum, p) => sum + p.tx_mbps * demoBytesPerHalfHourMbit,
  0,
);

/** 168 hourly log buckets (7 days); the stats handler slices the tail. */
export const demoLogHourly = Array.from({ length: 168 }, (_, i) => {
  const at = new Date(demoNow.getTime() - (167 - i) * 3_600_000);
  const count = Math.round(58 + 372 * demoCurveAt(at, i));
  return {
    hour: `${at.toISOString().slice(0, 13)}:00`,
    count,
    errors: Math.max(1, Math.round(count * 0.05 * demoJitter[(i + 3) % demoJitter.length])),
  };
});

/** 14 daily buckets for the Logs health histogram. */
export const demoLogDaily = Array.from({ length: 14 }, (_, i) => {
  const at = new Date(demoNow.getTime() - (13 - i) * 86_400_000);
  const weekday = at.getUTCDay();
  const weight = weekday === 0 || weekday === 6 ? 0.42 : 1;
  const total = Math.round(6_100 * weight * demoJitter[i % demoJitter.length]);
  return {
    date: at.toISOString().slice(0, 10),
    total,
    errors: Math.round(total * 0.053),
    warnings: Math.round(total * 0.11),
  };
});

/** 90 daily health snapshots: a slow climb with the outage week visible. */
export const demoHealthHistory = Array.from({ length: 90 }, (_, i) => {
  const at = new Date(demoNow.getTime() - (89 - i) * 86_400_000);
  const daysAgo = 89 - i;
  const trend = 84 + (i / 89) * 9;
  const wobble = (demoJitter[i % demoJitter.length] - 1) * 60;
  const outage = daysAgo === 5 || daysAgo === 4 ? -12 : 0;
  const score = Math.max(58, Math.min(99, Math.round(trend + wobble + outage)));
  const total = demoDeviceMetrics.length;
  const critical = score < 70 ? 3 : 0;
  const degraded = score < 85 ? 2 : 1;
  const warning = score < 92 ? 4 : 2;
  return {
    snapshot_date: at.toISOString().slice(0, 10),
    avg_health_score: score,
    device_count: total,
    healthy_count: Math.max(0, total - critical - degraded - warning),
    warning_count: warning,
    degraded_count: degraded,
    critical_count: critical,
  };
});

// ─── Alerts ────────────────────────────────────────────────────────────────
// A realistic console: three firing (one critical), four acknowledged (one of
// them suppressed), five resolved. `status: 'active'` is what the demo's
// /analytics/alerts filter and the dashboard's `status=active` query read;
// the alert-rules projection below maps it to the engine's 'firing'.

export const alerts = [
  {
    id: 'b4f2a1e0-1c73-4a58-9d21-000000000001',
    rule_id: '2c9d5b71-8e40-4f16-b3a7-000000000001',
    title: 'Access point unreachable',
    message:
      'HQ-Floor2-AP-03 missed 6 consecutive reachability polls. Last successful poll was 34 minutes ago.',
    alert_type: 'network.device.offline',
    severity: 'critical',
    status: 'active',
    site_id: demoIds.hq,
    device_id: null as string | null,
    source: 'HQ-Floor2-AP-03',
    metric_name: 'device.reachability.consecutive_failures',
    metric_value: { value: 6, threshold: 5, unit: 'polls' },
    details: { ip_address: '10.10.12.43', last_seen: demoIso(34), switch_port: 'HQ-IDF2-SW-02 · Port 14', poe_state: 'delivering' },
    tags: ['wireless', 'hq'],
    occurrence_count: 3,
    notifications_sent: 2,
    suppressed: false,
    suppressed_until: null as string | null,
    suppression_reason: null as string | null,
    triggered_at: demoIso(34),
    last_occurrence_at: demoIso(4),
    last_notified_at: demoIso(30),
    acknowledged_at: null as string | null,
    acknowledged_by: null as string | null,
    resolved_at: null as string | null,
    resolved_by: null as string | null,
    updated_at: demoIso(4),
  },
  {
    id: 'b4f2a1e0-1c73-4a58-9d21-000000000002',
    rule_id: '2c9d5b71-8e40-4f16-b3a7-000000000002',
    title: 'WAN latency above SLA on the Branch uplink',
    message:
      'Five-minute average round-trip time on the Branch Office WAN is 168 ms against a 60 ms objective.',
    alert_type: 'network.wan.latency',
    severity: 'warning',
    status: 'active',
    site_id: demoIds.branch,
    device_id: null,
    source: 'Branch Office WAN',
    metric_name: 'wan.latency.rtt_ms',
    metric_value: { value: 168, threshold: 60, unit: 'ms' },
    details: { probe_target: 'site-probe.freesdn.local', samples: 60, jitter_ms: 22, packet_loss_percent: 0.9 },
    tags: ['wan', 'branch', 'sla'],
    occurrence_count: 5,
    notifications_sent: 1,
    suppressed: false,
    suppressed_until: null,
    suppression_reason: null,
    triggered_at: demoIso(12),
    last_occurrence_at: demoIso(2),
    last_notified_at: demoIso(11),
    acknowledged_at: null,
    acknowledged_by: null,
    resolved_at: null,
    resolved_by: null,
    updated_at: demoIso(2),
  },
  {
    id: 'b4f2a1e0-1c73-4a58-9d21-000000000003',
    title: 'Backup pool nearing capacity',
    rule_id: '2c9d5b71-8e40-4f16-b3a7-000000000003',
    message:
      'tank-backup is 88% full (11.3 TB free of 96 TB). At the current retention rate free space runs out in about 9 days.',
    alert_type: 'storage.pool.capacity',
    severity: 'warning',
    status: 'active',
    site_id: demoIds.dc,
    device_id: null,
    source: 'TrueNAS-Backup-01',
    metric_name: 'storage.pool.usage_percent',
    metric_value: { value: 88, threshold: 85, unit: '%' },
    details: { pool: 'tank-backup', free_bytes: 11_300_000_000_000, size_bytes: 96_000_000_000_000, snapshots: 420 },
    tags: ['storage', 'capacity'],
    occurrence_count: 1,
    notifications_sent: 1,
    suppressed: false,
    suppressed_until: null,
    suppression_reason: null,
    triggered_at: demoIso(96),
    last_occurrence_at: demoIso(96),
    last_notified_at: demoIso(95),
    acknowledged_at: null,
    acknowledged_by: null,
    resolved_at: null,
    resolved_by: null,
    updated_at: demoIso(6),
  },
  {
    id: 'b4f2a1e0-1c73-4a58-9d21-000000000004',
    rule_id: '2c9d5b71-8e40-4f16-b3a7-000000000004',
    title: 'Nightly configuration backup failed',
    message:
      'The Branch Office device-config backup failed after 3 retries: the SFTP target refused the connection.',
    alert_type: 'backup.job.failed',
    severity: 'warning',
    status: 'acknowledged',
    site_id: demoIds.branch,
    device_id: null,
    source: 'Branch nightly config backup',
    metric_name: 'backup.job.result',
    metric_value: { value: 'failed', attempts: 3 },
    details: { job: 'branch-config-nightly', target: 'sftp://backup.freesdn.local/branch', error: 'connection refused', devices_covered: 19 },
    tags: ['backup', 'branch'],
    occurrence_count: 1,
    notifications_sent: 2,
    suppressed: false,
    suppressed_until: null,
    suppression_reason: null,
    triggered_at: demoIso(218),
    last_occurrence_at: demoIso(218),
    last_notified_at: demoIso(216),
    acknowledged_at: demoIso(176),
    acknowledged_by: 'Demo Admin',
    resolved_at: null,
    resolved_by: null,
    updated_at: demoIso(176),
  },
  {
    id: 'b4f2a1e0-1c73-4a58-9d21-000000000005',
    rule_id: '2c9d5b71-8e40-4f16-b3a7-000000000005',
    title: '5 GHz channel utilization high',
    message:
      'HQ-Floor2-AP-11 held 78% channel utilization on 5 GHz for 15 minutes against a 70% threshold.',
    alert_type: 'network.rf.utilization',
    severity: 'warning',
    status: 'acknowledged',
    site_id: demoIds.hq,
    device_id: null,
    source: 'HQ-Floor2-AP-11',
    metric_name: 'wifi.radio.channel_utilization_percent',
    metric_value: { value: 78, threshold: 70, unit: '%', band: '5ghz' },
    details: { radio: '5ghz', channel: 44, width_mhz: 80, clients: 41, retries_percent: 12 },
    tags: ['wireless', 'rf', 'hq'],
    occurrence_count: 4,
    notifications_sent: 1,
    suppressed: true,
    suppressed_until: demoIso(-120),
    suppression_reason: 'Suppressed for 2h while the all-hands is running in the Floor 2 auditorium.',
    triggered_at: demoIso(305),
    last_occurrence_at: demoIso(64),
    last_notified_at: demoIso(300),
    acknowledged_at: demoIso(291),
    acknowledged_by: 'Riley Nakamura',
    resolved_at: null,
    resolved_by: null,
    updated_at: demoIso(64),
  },
  {
    id: 'b4f2a1e0-1c73-4a58-9d21-000000000006',
    rule_id: '2c9d5b71-8e40-4f16-b3a7-000000000006',
    title: 'Motion detected at the front door',
    message: 'Front Door Camera recorded a 12 s motion event in the entrance zone.',
    alert_type: 'camera.motion.detected',
    severity: 'info',
    status: 'acknowledged',
    site_id: demoIds.hq,
    device_id: 'cam-front-door',
    source: 'Front Door Camera',
    metric_name: 'camera.motion.duration_seconds',
    metric_value: { value: 12, unit: 's', zone: 'entrance' },
    details: { camera_id: 'cam-front-door', zone: 'entrance', duration_seconds: 12, clip_available: true },
    tags: ['cameras', 'hq'],
    occurrence_count: 1,
    notifications_sent: 1,
    suppressed: false,
    suppressed_until: null,
    suppression_reason: null,
    triggered_at: demoIso(61),
    last_occurrence_at: demoIso(61),
    last_notified_at: demoIso(61),
    acknowledged_at: demoIso(58),
    acknowledged_by: 'Priya Raman',
    resolved_at: null,
    resolved_by: null,
    updated_at: demoIso(58),
  },
  {
    id: 'b4f2a1e0-1c73-4a58-9d21-000000000007',
    rule_id: '2c9d5b71-8e40-4f16-b3a7-000000000009',
    title: 'Extension 204 lost SIP registration',
    message: 'Support Queue (extension 204) has been unregistered from the PBX for 9 minutes.',
    alert_type: 'voip.registration.lost',
    severity: 'warning',
    status: 'acknowledged',
    site_id: demoIds.hq,
    device_id: null,
    source: 'FreePBX Voice',
    metric_name: 'voip.extension.registered',
    metric_value: { value: 0, threshold: 1, extension: '204' },
    details: { extension: '204', display_name: 'Support Queue', transport: 'TLS', last_registered_at: demoIso(411) },
    tags: ['voip', 'hq'],
    occurrence_count: 2,
    notifications_sent: 1,
    suppressed: false,
    suppressed_until: null,
    suppression_reason: null,
    triggered_at: demoIso(402),
    last_occurrence_at: demoIso(402),
    last_notified_at: demoIso(400),
    acknowledged_at: demoIso(388),
    acknowledged_by: 'Riley Nakamura',
    resolved_at: null,
    resolved_by: null,
    updated_at: demoIso(388),
  },
  {
    id: 'b4f2a1e0-1c73-4a58-9d21-000000000008',
    rule_id: '2c9d5b71-8e40-4f16-b3a7-000000000007',
    title: 'PoE budget exhausted on HQ-Core-SW-01',
    message: 'PoE draw reached 372 W of a 384 W budget; port 22 was denied power until load dropped.',
    alert_type: 'power.poe.budget',
    severity: 'critical',
    status: 'resolved',
    site_id: demoIds.hq,
    device_id: 'dev-sw-core',
    source: 'HQ-Core-SW-01',
    metric_name: 'switch.poe.utilization_percent',
    metric_value: { value: 97, threshold: 95, unit: '%' },
    details: { budget_watts: 384, peak_watts: 372, denied_ports: ['22'], resolution: 'Port 14 camera moved to HQ-IDF2-SW-02.' },
    tags: ['power', 'switching', 'hq'],
    occurrence_count: 2,
    notifications_sent: 3,
    suppressed: false,
    suppressed_until: null,
    suppression_reason: null,
    triggered_at: demoIso(186),
    last_occurrence_at: demoIso(160),
    last_notified_at: demoIso(160),
    acknowledged_at: demoIso(178),
    acknowledged_by: 'Riley Nakamura',
    resolved_at: demoIso(154),
    resolved_by: 'Riley Nakamura',
    updated_at: demoIso(154),
  },
  {
    id: 'b4f2a1e0-1c73-4a58-9d21-000000000009',
    rule_id: '2c9d5b71-8e40-4f16-b3a7-000000000008',
    title: 'Uplink flapping on HQ-IDF2-SW-02',
    message: 'Port 25 (uplink to HQ-Core-SW-01) changed link state 7 times in 10 minutes.',
    alert_type: 'network.uplink.flap',
    severity: 'warning',
    status: 'resolved',
    site_id: demoIds.hq,
    device_id: null,
    source: 'HQ-IDF2-SW-02',
    metric_name: 'port.link.state_changes',
    metric_value: { value: 7, threshold: 6, window_seconds: 600 },
    details: { port: '25', peer: 'HQ-Core-SW-01 · Port 27', media: 'DAC', resolution: 'Reseated the DAC; link stable since.' },
    tags: ['switching', 'hq'],
    occurrence_count: 1,
    notifications_sent: 1,
    suppressed: false,
    suppressed_until: null,
    suppression_reason: null,
    triggered_at: demoIso(372),
    last_occurrence_at: demoIso(372),
    last_notified_at: demoIso(371),
    acknowledged_at: demoIso(360),
    acknowledged_by: 'Demo Admin',
    resolved_at: demoIso(341),
    resolved_by: 'Demo Admin',
    updated_at: demoIso(341),
  },
  {
    id: 'b4f2a1e0-1c73-4a58-9d21-000000000010',
    rule_id: '2c9d5b71-8e40-4f16-b3a7-000000000012',
    title: 'Firmware update available for 6 access points',
    message: 'EAP670 firmware 1.0.15 is published; 6 HQ access points are still on 1.0.13.',
    alert_type: 'firmware.update.available',
    severity: 'info',
    status: 'resolved',
    site_id: demoIds.hq,
    device_id: null,
    source: 'Omada OC300 - HQ',
    metric_name: 'device.firmware.behind_count',
    metric_value: { value: 6, threshold: 1 },
    details: { model: 'EAP670', current: '1.0.13', available: '1.0.15', devices: 6, resolution: 'Staged and applied in the Tuesday 02:00 window.' },
    tags: ['firmware', 'hq'],
    occurrence_count: 1,
    notifications_sent: 1,
    suppressed: false,
    suppressed_until: null,
    suppression_reason: null,
    triggered_at: demoIso(640),
    last_occurrence_at: demoIso(640),
    last_notified_at: demoIso(639),
    acknowledged_at: demoIso(628),
    acknowledged_by: 'Demo Admin',
    resolved_at: demoIso(602),
    resolved_by: 'FreeSDN Automation',
    updated_at: demoIso(602),
  },
  {
    id: 'b4f2a1e0-1c73-4a58-9d21-000000000011',
    rule_id: '2c9d5b71-8e40-4f16-b3a7-000000000010',
    title: 'PVE-Node-01 memory pressure',
    message: 'Memory use held above 88% for 20 minutes against an 85% threshold.',
    alert_type: 'hypervisor.node.memory',
    severity: 'warning',
    status: 'resolved',
    site_id: demoIds.dc,
    device_id: 'dev-pve-01',
    source: 'PVE-Node-01',
    metric_name: 'hypervisor.node.memory_percent',
    metric_value: { value: 88, threshold: 85, unit: '%' },
    details: { node: 'pve-node-01', ballooning: true, resolution: 'nms-worker-01 reduced from 12 GB to 8 GB.' },
    tags: ['hypervisor', 'datacenter'],
    occurrence_count: 3,
    notifications_sent: 1,
    suppressed: false,
    suppressed_until: null,
    suppression_reason: null,
    triggered_at: demoIso(545),
    last_occurrence_at: demoIso(520),
    last_notified_at: demoIso(544),
    acknowledged_at: demoIso(530),
    acknowledged_by: 'Priya Raman',
    resolved_at: demoIso(498),
    resolved_by: 'Priya Raman',
    updated_at: demoIso(498),
  },
  {
    id: 'b4f2a1e0-1c73-4a58-9d21-000000000012',
    rule_id: '2c9d5b71-8e40-4f16-b3a7-000000000001',
    title: 'Access point unreachable',
    message: 'Branch-U6-Pro-04 dropped off after a PoE injector reset and re-registered 36 minutes later.',
    alert_type: 'network.device.offline',
    severity: 'critical',
    status: 'resolved',
    site_id: demoIds.branch,
    device_id: null,
    source: 'Branch-U6-Pro-04',
    metric_name: 'device.reachability.consecutive_failures',
    metric_value: { value: 9, threshold: 5, unit: 'polls' },
    details: { ip_address: '10.30.12.11', downtime_seconds: 2_160, resolution: 'Injector replaced; device stable.' },
    tags: ['wireless', 'branch'],
    occurrence_count: 1,
    notifications_sent: 2,
    suppressed: false,
    suppressed_until: null,
    suppression_reason: null,
    triggered_at: demoIso(848),
    last_occurrence_at: demoIso(848),
    last_notified_at: demoIso(846),
    acknowledged_at: demoIso(840),
    acknowledged_by: 'Riley Nakamura',
    resolved_at: demoIso(812),
    resolved_by: 'Riley Nakamura',
    updated_at: demoIso(812),
  },
];

export const demoFiringAlerts = alerts.filter((a) => a.status === 'active');

/**
 * The alert-rules engine's own shape (`AlertInstance` in lib/api/types.ts).
 * Projected from `alerts` so the unified /alerts console, the dashboard
 * widget and the analytics roll-up can never disagree about what is firing.
 */
export const alertInstances = alerts.map((a) => ({
  id: a.id,
  organization_id: demoIds.org,
  rule_id: a.rule_id,
  site_id: a.site_id,
  device_id: a.device_id,
  severity: a.severity,
  title: a.title,
  message: a.message,
  details: a.details,
  status: a.status === 'active' ? 'firing' : a.status,
  fired_at: a.triggered_at,
  acknowledged_at: a.acknowledged_at,
  acknowledged_by: a.acknowledged_by,
  resolved_at: a.resolved_at,
  resolved_by: a.resolved_by,
  fingerprint: `${a.alert_type}:${a.source.toLowerCase().replace(/\s+/g, '-')}`,
  occurrence_count: a.occurrence_count,
  last_occurrence_at: a.last_occurrence_at,
  suppressed: a.suppressed,
  suppressed_until: a.suppressed_until,
  suppression_reason: a.suppression_reason,
  notifications_sent: a.notifications_sent,
  last_notified_at: a.last_notified_at,
  tags: a.tags,
  metadata: {},
  source: a.source,
  created_at: a.triggered_at,
  updated_at: a.updated_at,
}));

// ─── Alert rules that plausibly produced those alerts ──────────────────────

export const demoRuleChannels = {
  emailInApp: { email: { enabled: true, recipients: ['netops@freesdn.local'] }, in_app: { enabled: true } },
  emailSlackInApp: {
    email: { enabled: true, recipients: ['netops@freesdn.local'] },
    slack: { enabled: true, channel: '#netops-alerts' },
    in_app: { enabled: true },
  },
  inAppOnly: { in_app: { enabled: true } },
};

export const alertRules = [
  ['000000000001', 'Device offline', 'Fires when a managed device misses five consecutive reachability polls.', 'threshold', 'critical', 'organization', { metric: 'device.reachability.consecutive_failures', operator: '>=', value: 5 }, 'active', 23, 34, demoRuleChannels.emailSlackInApp, ['availability'], true],
  ['000000000002', 'WAN latency above SLA', 'Round-trip time on a site uplink over the 60 ms service objective.', 'threshold', 'warning', 'site', { metric: 'wan.latency.rtt_ms', operator: '>', value: 60 }, 'active', 14, 12, demoRuleChannels.emailInApp, ['wan', 'sla'], false],
  ['000000000003', 'Storage pool capacity', 'Any pool crossing 85% used, so retention can be trimmed before writes fail.', 'threshold', 'warning', 'organization', { metric: 'storage.pool.usage_percent', operator: '>=', value: 85 }, 'active', 6, 96, demoRuleChannels.emailInApp, ['storage'], false],
  ['000000000004', 'Backup job failure', 'Any backup job that finishes in a failed state.', 'pattern', 'warning', 'organization', { event_type: 'backup.job.failed', min_count: 1, time_window_seconds: 3600 }, 'active', 4, 218, demoRuleChannels.emailSlackInApp, ['backup'], false],
  ['000000000005', 'Wi-Fi channel utilization', 'A radio holding above 70% channel utilization for 15 minutes.', 'threshold', 'warning', 'site', { metric: 'wifi.radio.channel_utilization_percent', operator: '>', value: 70 }, 'active', 31, 305, demoRuleChannels.inAppOnly, ['wireless', 'rf'], false],
  ['000000000006', 'Camera motion (entrance zones)', 'Motion in a zone tagged as an entrance, outside business hours.', 'pattern', 'info', 'device_group', { event_type: 'camera.motion.detected', min_count: 1, time_window_seconds: 60 }, 'active', 148, 61, demoRuleChannels.inAppOnly, ['cameras', 'physical-security'], false],
  ['000000000007', 'PoE budget headroom', 'A switch drawing 95% or more of its PoE budget.', 'threshold', 'critical', 'organization', { metric: 'switch.poe.utilization_percent', operator: '>=', value: 95 }, 'active', 5, 186, demoRuleChannels.emailSlackInApp, ['power', 'switching'], false],
  ['000000000008', 'Uplink flap detection', 'Six or more link-state changes on one port inside ten minutes.', 'pattern', 'warning', 'organization', { event_type: 'port.link.state_changed', min_count: 6, time_window_seconds: 600 }, 'active', 9, 372, demoRuleChannels.emailInApp, ['switching'], false],
  ['000000000009', 'SIP registration lost', 'An extension that drops its registration and does not come back inside 5 minutes.', 'pattern', 'warning', 'site', { event_type: 'voip.extension.unregistered', min_count: 1, time_window_seconds: 300 }, 'active', 11, 402, demoRuleChannels.emailInApp, ['voip'], false],
  ['000000000010', 'Hypervisor memory pressure', 'A node above 85% memory for more than fifteen minutes.', 'threshold', 'warning', 'organization', { metric: 'hypervisor.node.memory_percent', operator: '>', value: 85 }, 'active', 7, 545, demoRuleChannels.emailInApp, ['hypervisor'], false],
  ['000000000011', 'Anomalous WAN throughput', 'Z-scores WAN receive throughput against its own 14-day baseline.', 'anomaly', 'warning', 'site', { metric: 'wan.throughput.rx_mbps', std_dev_threshold: 3 }, 'disabled', 2, 4_320, demoRuleChannels.inAppOnly, ['wan', 'anomaly'], false],
  ['000000000012', 'Firmware drift', 'Managed devices behind the release their controller advertises.', 'threshold', 'info', 'organization', { metric: 'device.firmware.behind_count', operator: '>=', value: 1 }, 'active', 18, 640, demoRuleChannels.inAppOnly, ['firmware', 'compliance'], true],
].map((row) => {
  const [suffix, name, description, ruleType, severity, scope, conditions, status, fireCount, lastFiredMinutes, channels, tags, isSystem] = row as [
    string, string, string, string, string, string, Record<string, unknown>, string, number, number, Record<string, unknown>, string[], boolean,
  ];
  return {
    id: `2c9d5b71-8e40-4f16-b3a7-${suffix}`,
    organization_id: demoIds.org,
    name,
    description,
    rule_type: ruleType,
    status,
    severity,
    conditions,
    scope,
    scope_ids: scope === 'site' ? [demoIds.hq, demoIds.branch] : null,
    device_types: null,
    check_interval_seconds: 180,
    for_duration_seconds: ruleType === 'threshold' ? 300 : 0,
    cooldown_seconds: 900,
    auto_resolve: true,
    auto_resolve_after_seconds: 3600,
    notification_channels: channels,
    notify_on_resolve: true,
    dedupe_window_seconds: 3600,
    tags,
    metadata: {},
    last_evaluated_at: demoIso(2),
    last_fired_at: demoIso(lastFiredMinutes),
    fire_count: fireCount,
    is_system: isSystem,
    created_at: demoIso(60 * 24 * 45),
    updated_at: demoIso(60 * 24 * 3),
  };
});

export const alertRuleStats = {
  total_rules: alertRules.length,
  active_rules: alertRules.filter((r) => r.status === 'active').length,
  disabled_rules: alertRules.filter((r) => r.status !== 'active').length,
  total_alerts: 148,
  firing_alerts: demoFiringAlerts.length,
  acknowledged_alerts: alerts.filter((a) => a.status === 'acknowledged').length,
  alerts_last_24h: alerts.filter((a) => a.status !== 'resolved').length + 5,
  critical_firing: demoFiringAlerts.filter((a) => a.severity === 'critical').length,
};

// ─── Correlation incidents ─────────────────────────────────────────────────

export const incidents = [
  {
    id: 'e07a4c39-52b6-4d81-a4f0-000000000001',
    organization_id: demoIds.org,
    rule_id: 'c58f0d92-7a34-4e61-8bd5-000000000001',
    site_id: demoIds.branch,
    title: 'Branch Office WAN degradation',
    description: 'Latency, jitter and loss on the Branch uplink crossed threshold together inside a 10-minute window.',
    severity: 'critical',
    status: 'open',
    opened_at: demoIso(18),
    acknowledged_at: null as string | null,
    resolved_at: null as string | null,
    closed_at: null as string | null,
    assigned_to: null as string | null,
    event_count: 7,
    affected_devices: ['dev-unifi-ap'],
    root_cause: null as string | null,
    resolution_notes: null as string | null,
    tags: ['wan', 'branch'],
    context: { probe_target: 'site-probe.freesdn.local', peak_rtt_ms: 168, loss_percent: 0.9 },
    created_at: demoIso(18),
    updated_at: demoIso(3),
  },
  {
    id: 'e07a4c39-52b6-4d81-a4f0-000000000002',
    organization_id: demoIds.org,
    rule_id: 'c58f0d92-7a34-4e61-8bd5-000000000002',
    site_id: null,
    title: 'Repeated authentication failures from a single source',
    description: '14 failed sign-ins for three different accounts from 198.51.100.42 in six minutes.',
    severity: 'high',
    status: 'open',
    opened_at: demoIso(52),
    acknowledged_at: null,
    resolved_at: null,
    closed_at: null,
    assigned_to: null,
    event_count: 14,
    affected_devices: [],
    root_cause: null,
    resolution_notes: null,
    tags: ['security', 'authentication'],
    context: { source_ip: '198.51.100.42', accounts: 3, blocked: true, block_expires_at: demoIso(-58) },
    created_at: demoIso(52),
    updated_at: demoIso(50),
  },
  {
    id: 'e07a4c39-52b6-4d81-a4f0-000000000003',
    organization_id: demoIds.org,
    rule_id: 'c58f0d92-7a34-4e61-8bd5-000000000003',
    site_id: demoIds.hq,
    title: 'HQ Floor 2 wireless degradation',
    description: 'One access point offline and two neighbours over 70% channel utilization on the same floor.',
    severity: 'warning',
    status: 'investigating',
    opened_at: demoIso(182),
    acknowledged_at: demoIso(170),
    resolved_at: null,
    closed_at: null,
    assigned_to: 'Riley Nakamura',
    event_count: 9,
    affected_devices: ['dev-ap-lobby'],
    root_cause: null,
    resolution_notes: null,
    tags: ['wireless', 'hq'],
    context: { floor: 2, access_points: 3, clients_affected: 62 },
    created_at: demoIso(182),
    updated_at: demoIso(64),
  },
  {
    id: 'e07a4c39-52b6-4d81-a4f0-000000000004',
    organization_id: demoIds.org,
    rule_id: 'c58f0d92-7a34-4e61-8bd5-000000000004',
    site_id: demoIds.hq,
    title: 'PoE brownout on the HQ core switch',
    description: 'PoE budget and a downstream camera dropout correlated within 90 seconds.',
    severity: 'critical',
    status: 'resolved',
    opened_at: demoIso(186),
    acknowledged_at: demoIso(178),
    resolved_at: demoIso(154),
    closed_at: demoIso(150),
    assigned_to: 'Riley Nakamura',
    event_count: 5,
    affected_devices: ['dev-sw-core', 'cam-front-door'],
    root_cause: 'A camera added to Port 14 pushed the switch past its 384 W budget.',
    resolution_notes: 'Camera moved to HQ-IDF2-SW-02; budget headroom back to 48%.',
    tags: ['power', 'hq'],
    context: { budget_watts: 384, peak_watts: 372 },
    created_at: demoIso(186),
    updated_at: demoIso(150),
  },
  {
    id: 'e07a4c39-52b6-4d81-a4f0-000000000005',
    organization_id: demoIds.org,
    rule_id: 'c58f0d92-7a34-4e61-8bd5-000000000005',
    site_id: demoIds.dc,
    title: 'Backup window overran into business hours',
    description: 'Replication and the nightly snapshot task overlapped and finished 96 minutes late.',
    severity: 'warning',
    status: 'resolved',
    opened_at: demoIso(1_180),
    acknowledged_at: demoIso(1_160),
    resolved_at: demoIso(1_048),
    closed_at: demoIso(1_040),
    assigned_to: 'Priya Raman',
    event_count: 4,
    affected_devices: ['dev-truenas-01'],
    root_cause: 'Snapshot retention pass ran while replication still held the dataset lock.',
    resolution_notes: 'Retention moved to 03:30; the two tasks no longer overlap.',
    tags: ['storage', 'backup'],
    context: { overrun_minutes: 96 },
    created_at: demoIso(1_180),
    updated_at: demoIso(1_040),
  },
  {
    id: 'e07a4c39-52b6-4d81-a4f0-000000000006',
    organization_id: demoIds.org,
    rule_id: 'c58f0d92-7a34-4e61-8bd5-000000000003',
    site_id: demoIds.branch,
    title: 'Branch access point flapped after an injector reset',
    description: 'Offline and re-registration events for the same device inside 40 minutes.',
    severity: 'warning',
    status: 'closed',
    opened_at: demoIso(848),
    acknowledged_at: demoIso(840),
    resolved_at: demoIso(812),
    closed_at: demoIso(800),
    assigned_to: 'Riley Nakamura',
    event_count: 3,
    affected_devices: [],
    root_cause: 'Failing passive PoE injector.',
    resolution_notes: 'Injector replaced from the branch spares kit.',
    tags: ['wireless', 'branch'],
    context: { downtime_seconds: 2_160 },
    created_at: demoIso(848),
    updated_at: demoIso(800),
  },
];

export const correlationRules = [
  ['000000000001', 'WAN degradation', 'Latency, jitter and loss events for the same site inside ten minutes.', 'critical', 'site', 600, [{ event_type: 'network.wan.latency', min_count: 1 }, { event_type: 'network.wan.loss', min_count: 1 }], 31, 18],
  ['000000000002', 'Credential stuffing', 'Five or more failed sign-ins from one source address in five minutes.', 'high', 'organization', 300, [{ event_type: 'auth.login.failed', min_count: 5, category: 'security' }], 12, 52],
  ['000000000003', 'Wireless area degradation', 'An offline access point plus high utilization on its neighbours.', 'warning', 'site', 900, [{ event_type: 'network.device.offline', min_count: 1 }, { event_type: 'network.rf.utilization', min_count: 2 }], 24, 182],
  ['000000000004', 'PoE brownout', 'A PoE budget alert followed by a downstream device dropout.', 'critical', 'site', 120, [{ event_type: 'power.poe.budget', min_count: 1 }, { event_type: 'network.device.offline', min_count: 1 }], 5, 186],
  ['000000000005', 'Backup window overrun', 'Backup and replication tasks overlapping on the same pool.', 'warning', 'organization', 3_600, [{ event_type: 'backup.job.started', min_count: 2 }], 8, 1_180],
  ['000000000006', 'Configuration drift burst', 'Three or more devices drifting from their template in one hour.', 'warning', 'organization', 3_600, [{ event_type: 'config.drift.detected', min_count: 3 }], 3, 4_260],
].map((row) => {
  const [suffix, name, description, severity, scope, windowSeconds, patterns, fireCount, lastFiredMinutes] = row as [
    string, string, string, string, string, number, Array<Record<string, unknown>>, number, number,
  ];
  return {
    id: `c58f0d92-7a34-4e61-8bd5-${suffix}`,
    organization_id: demoIds.org,
    name,
    description,
    status: suffix === '000000000006' ? 'disabled' : 'active',
    event_patterns: patterns,
    time_window_seconds: windowSeconds,
    scope,
    conditions: null,
    severity,
    auto_resolve_seconds: 7_200,
    notification_channels: { in_app: { enabled: true } },
    fire_count: fireCount,
    last_fired_at: demoIso(lastFiredMinutes),
    created_at: demoIso(60 * 24 * 60),
    updated_at: demoIso(60 * 24 * 5),
  };
});

export const correlationStats = {
  total_rules: correlationRules.length,
  active_rules: correlationRules.filter((r) => r.status === 'active').length,
  open_incidents: incidents.filter((i) => i.status === 'open' || i.status === 'investigating').length,
  incidents_last_24h: 5,
  events_correlated_last_24h: 214,
  top_firing_rules: correlationRules
    .slice()
    .sort((a, b) => b.fire_count - a.fire_count)
    .slice(0, 5)
    .map((r) => ({ id: r.id, name: r.name, fire_count: r.fire_count, last_fired_at: r.last_fired_at })),
};

export const incidentEvents: Record<string, Array<Record<string, unknown>>> = {
  'e07a4c39-52b6-4d81-a4f0-000000000001': [
    { id: 'f1a00001-0000-4000-8000-000000000001', event_id: 'evt-wan-0001', matched_pattern: 'network.wan.latency', added_at: demoIso(18), event_type: 'network.wan.latency', event_category: 'network', event_timestamp: demoIso(18), event_payload: { rtt_ms: 132, site: 'Branch Office' } },
    { id: 'f1a00001-0000-4000-8000-000000000002', event_id: 'evt-wan-0002', matched_pattern: 'network.wan.loss', added_at: demoIso(15), event_type: 'network.wan.loss', event_category: 'network', event_timestamp: demoIso(15), event_payload: { loss_percent: 0.8 } },
    { id: 'f1a00001-0000-4000-8000-000000000003', event_id: 'evt-wan-0003', matched_pattern: 'network.wan.latency', added_at: demoIso(12), event_type: 'network.wan.latency', event_category: 'network', event_timestamp: demoIso(12), event_payload: { rtt_ms: 168, site: 'Branch Office' } },
  ],
  'e07a4c39-52b6-4d81-a4f0-000000000002': [
    { id: 'f1a00002-0000-4000-8000-000000000001', event_id: 'evt-auth-0011', matched_pattern: 'auth.login.failed', added_at: demoIso(52), event_type: 'auth.login.failed', event_category: 'security', event_timestamp: demoIso(52), event_payload: { source_ip: '198.51.100.42', account: 'priya@freesdn.local' } },
    { id: 'f1a00002-0000-4000-8000-000000000002', event_id: 'evt-auth-0012', matched_pattern: 'auth.login.failed', added_at: demoIso(51), event_type: 'auth.login.failed', event_category: 'security', event_timestamp: demoIso(51), event_payload: { source_ip: '198.51.100.42', account: 'riley@freesdn.local' } },
    { id: 'f1a00002-0000-4000-8000-000000000003', event_id: 'evt-auth-0013', matched_pattern: 'auth.ip.blocked', added_at: demoIso(46), event_type: 'auth.ip.blocked', event_category: 'security', event_timestamp: demoIso(46), event_payload: { source_ip: '198.51.100.42', duration_minutes: 60 } },
  ],
};

// ─── Security audit ────────────────────────────────────────────────────────
// One array serves three endpoints with three historical shapes:
//   /security/events        → severity + outcome  (SecurityAuditPage)
//   /audit/security-events  → risk_score + success (SecurityPage)
//   /audit/security         → the same, for the unified /alerts console
// Addresses are RFC 5737 documentation space or the demo's own RFC 1918
// ranges. Nothing here is a credential or a token.

export const securityEvents = [
  ['000000000001', 4, 'login_success', 'low', 'success', true, 3, demoUser.email, '10.10.20.31', 'session', 'authenticate', { method: 'password', mfa: false, user_agent: 'Firefox 141 / Linux' }],
  ['000000000002', 9, 'permission_denied', 'medium', 'blocked', false, 55, 'priya@freesdn.local', '10.10.20.58', 'firewall_rule', 'delete', { path: '/api/v1/firewall/rules/3f2a', required_role: 'org_admin', held_role: 'operator' }],
  ['000000000003', 22, 'api_access', 'low', 'success', true, 8, 'automation@freesdn.local', '10.20.10.44', 'api_key', 'read', { scope: 'devices:read', calls: 42, key_label: 'nms-worker' }],
  ['000000000004', 46, 'account_locked', 'high', 'blocked', false, 78, 'riley@freesdn.local', '198.51.100.42', 'user', 'lock', { reason: 'five failed attempts in six minutes', unlock_after_minutes: 30 }],
  ['000000000005', 49, 'brute_force_attempt', 'critical', 'blocked', false, 88, 'riley@freesdn.local', '198.51.100.42', 'session', 'authenticate', { attempts: 14, accounts_targeted: 3, blocked: true }],
  ['000000000006', 51, 'login_failed', 'medium', 'failure', false, 45, 'priya@freesdn.local', '198.51.100.42', 'session', 'authenticate', { method: 'password', failure: 'invalid_credentials' }],
  ['000000000007', 52, 'login_failed', 'medium', 'failure', false, 45, 'demo@freesdn.local', '198.51.100.42', 'session', 'authenticate', { method: 'password', failure: 'invalid_credentials' }],
  ['000000000008', 88, 'mfa_enabled', 'low', 'success', true, 2, 'priya@freesdn.local', '10.10.20.58', 'user', 'update', { factor: 'totp' }],
  ['000000000009', 141, 'data_export', 'medium', 'success', true, 38, demoUser.email, '10.10.20.31', 'audit_log', 'export', { format: 'csv', rows: 4_812, range_hours: 24 }],
  ['000000000010', 198, 'permission_change', 'high', 'success', true, 64, demoUser.email, '10.10.20.31', 'user', 'update', { target: 'riley@freesdn.local', from_role: 'operator', to_role: 'network_admin' }],
  ['000000000011', 244, 'login_success', 'low', 'success', true, 3, 'riley@freesdn.local', '10.30.20.14', 'session', 'authenticate', { method: 'oidc', provider: 'demo-idp', mfa: true }],
  ['000000000012', 312, 'suspicious_activity', 'high', 'blocked', false, 71, 'automation@freesdn.local', '203.0.113.77', 'api_key', 'read', { reason: 'API key used from an address outside its allow-list', allowed: '10.0.0.0/8' }],
  ['000000000013', 480, 'password_change', 'low', 'success', true, 6, 'priya@freesdn.local', '10.10.20.58', 'user', 'update', { self_service: true }],
  ['000000000014', 626, 'user_created', 'medium', 'success', true, 22, demoUser.email, '10.10.20.31', 'user', 'create', { new_user: 'contractor-audit@freesdn.local', role: 'viewer', expires_in_days: 14 }],
  ['000000000015', 918, 'logout', 'low', 'success', true, 1, 'riley@freesdn.local', '10.30.20.14', 'session', 'terminate', { reason: 'user_initiated' }],
  ['000000000016', 1_204, 'account_unlocked', 'medium', 'success', true, 18, demoUser.email, '10.10.20.31', 'user', 'update', { target: 'riley@freesdn.local' }],
].map((row) => {
  const [suffix, minutesAgo, eventType, severity, outcome, success, riskScore, userEmail, ip, resourceType, action, details] = row as [
    string, number, string, string, string, boolean, number, string, string, string, string, Record<string, unknown>,
  ];
  return {
    id: `5a8e2d64-b119-4c73-8e95-${suffix}`,
    timestamp: demoIso(minutesAgo),
    event_type: eventType,
    severity,
    outcome,
    success,
    risk_score: riskScore,
    user_id: demoUser.id,
    user_email: userEmail,
    source_ip: ip,
    ip_address: ip,
    resource_type: resourceType,
    action,
    details,
  };
});

export const securitySummary = {
  total_events: 428,
  failed_logins: 17,
  suspicious_activities: 4,
  blocked_requests: 9,
  unique_source_ips: 23,
  events_by_severity: { low: 331, medium: 68, high: 23, critical: 6 },
  events_by_type: {
    login_success: 214,
    api_access: 96,
    login_failed: 17,
    permission_denied: 11,
    data_export: 4,
    brute_force_attempt: 2,
  },
  period: '24h',
  generated_at: demoIso(),
};

export const securityAnomalies = [
  {
    anomaly_type: 'Credential stuffing from a single source',
    description:
      '14 failed sign-ins across 3 accounts from 198.51.100.42 in six minutes. The address is blocked for another 8 minutes.',
    severity: 'critical',
    detected_at: demoIso(49),
    source_ip: '198.51.100.42',
    event_count: 14,
  },
  {
    anomaly_type: 'API key used outside its allow-list',
    description:
      'The nms-worker key authenticated from 203.0.113.77, outside the 10.0.0.0/8 allow-list recorded on the key. The request was refused.',
    severity: 'high',
    detected_at: demoIso(312),
    source_ip: '203.0.113.77',
    event_count: 1,
  },
];

export const securityEventTypes = [
  { event_type: 'login_success', label: 'Successful sign-in', category: 'authentication', default_severity: 'low' },
  { event_type: 'login_failed', label: 'Failed sign-in', category: 'authentication', default_severity: 'medium' },
  { event_type: 'logout', label: 'Sign-out', category: 'authentication', default_severity: 'low' },
  { event_type: 'brute_force_attempt', label: 'Brute-force attempt', category: 'authentication', default_severity: 'critical' },
  { event_type: 'account_locked', label: 'Account locked', category: 'authentication', default_severity: 'high' },
  { event_type: 'account_unlocked', label: 'Account unlocked', category: 'authentication', default_severity: 'medium' },
  { event_type: 'mfa_enabled', label: 'MFA enabled', category: 'authentication', default_severity: 'low' },
  { event_type: 'password_change', label: 'Password changed', category: 'authentication', default_severity: 'low' },
  { event_type: 'permission_denied', label: 'Permission denied', category: 'authorization', default_severity: 'medium' },
  { event_type: 'permission_change', label: 'Role or permission changed', category: 'authorization', default_severity: 'high' },
  { event_type: 'user_created', label: 'User created', category: 'administration', default_severity: 'medium' },
  { event_type: 'api_access', label: 'API key access', category: 'api', default_severity: 'low' },
  { event_type: 'data_export', label: 'Data export', category: 'data', default_severity: 'medium' },
  { event_type: 'suspicious_activity', label: 'Suspicious activity', category: 'detection', default_severity: 'high' },
];

// ─── Audit trail ───────────────────────────────────────────────────────────
// Who did what, including the staged-change approvals that are the product's
// central safety mechanism: nothing reaches a device without one.

export const auditLogs = [
  ['0000000001', 6, 'Demo Admin', demoUser.email, '10.10.20.31', 'staged_change.apply', 'staged_change', 'VLAN 60 "Guest-IoT" → Omada OC300 - HQ', 'success', { staged_change_id: 'chg-4821', approved_by: 'Riley Nakamura', devices: 4, force: false }],
  ['0000000002', 11, 'Riley Nakamura', 'riley@freesdn.local', '10.10.20.58', 'staged_change.approve', 'staged_change', 'VLAN 60 "Guest-IoT" → Omada OC300 - HQ', 'success', { staged_change_id: 'chg-4821', diff_lines: 12 }],
  ['0000000003', 24, 'Demo Admin', demoUser.email, '10.10.20.31', 'vlan.create', 'vlan', 'VLAN 60 · Guest-IoT', 'success', { vlan_id: 60, site: 'HQ Campus', subnet: '10.10.60.0/24', staged: true }],
  ['0000000004', 38, 'Riley Nakamura', 'riley@freesdn.local', '10.10.20.58', 'device.config.update', 'device', 'HQ-IDF2-SW-02', 'success', { port: '14', changes: { poe_enabled: [false, true], description: ['', 'Floor 2 AP'] } }],
  ['0000000005', 52, 'FreeSDN Automation', 'automation@freesdn.local', '10.20.10.44', 'alert.acknowledge', 'alert', 'Nightly configuration backup failed', 'success', { alert_id: 'b4f2a1e0-1c73-4a58-9d21-000000000004', rule: 'Backup job failure' }],
  ['0000000006', 61, 'Priya Raman', 'priya@freesdn.local', '10.10.20.58', 'staged_change.reject', 'staged_change', 'Firewall rule "Allow-RDP-Any" → OPNsense HA Pair', 'success', { staged_change_id: 'chg-4817', reason: 'Any/any RDP from WAN; needs a source restriction.' }],
  ['0000000007', 88, 'Demo Admin', demoUser.email, '10.10.20.31', 'user.login', 'session', 'demo@freesdn.local', 'success', { method: 'password', mfa: false }],
  ['0000000008', 96, 'Riley Nakamura', 'riley@freesdn.local', '10.10.20.58', 'wifi.update', 'wifi_network', 'Acme-Guest', 'success', { changes: { rate_limit_down: [5_000, 10_000] }, staged: true }],
  ['0000000009', 134, 'Priya Raman', 'priya@freesdn.local', '10.10.20.58', 'credential.update', 'credential', 'Omada controller (HQ)', 'success', { rotated: true, vault_ref: 'cred-omada-hq' }],
  ['0000000010', 152, 'Riley Nakamura', 'riley@freesdn.local', '10.10.20.58', 'staged_change.apply', 'staged_change', 'PoE port 14 disable → HQ-Core-SW-01', 'success', { staged_change_id: 'chg-4809', force: true, reason: 'PoE budget exhausted' }],
  ['0000000011', 188, 'FreeSDN Automation', 'automation@freesdn.local', '10.20.10.44', 'backup.create', 'backup', 'HQ nightly config snapshot', 'success', { devices: 42, size_bytes: 842_000, duration_seconds: 74 }],
  ['0000000012', 219, 'FreeSDN Automation', 'automation@freesdn.local', '10.20.10.44', 'backup.create', 'backup', 'Branch nightly config snapshot', 'failure', { devices: 19, error: 'sftp: connection refused', retries: 3 }],
  ['0000000013', 264, 'Demo Admin', demoUser.email, '10.10.20.31', 'firewall_rule.update', 'firewall_rule', 'Allow-Guest-DNS', 'success', { changes: { destination_port: ['53', '53,853'] }, staged: true }],
  ['0000000014', 318, 'Priya Raman', 'priya@freesdn.local', '10.10.20.58', 'user.logout', 'session', 'priya@freesdn.local', 'success', { reason: 'user_initiated' }],
  ['0000000015', 402, 'Demo Admin', demoUser.email, '10.10.20.31', 'user.update', 'user', 'riley@freesdn.local', 'success', { changes: { role: ['operator', 'network_admin'] } }],
  ['0000000016', 478, 'Riley Nakamura', 'riley@freesdn.local', '10.30.20.14', 'device.reboot', 'device', 'Branch-U6-Pro-04', 'success', { staged_change_id: 'chg-4788', confirmed: true }],
  ['0000000017', 604, 'FreeSDN Automation', 'automation@freesdn.local', '10.20.10.44', 'firmware.apply', 'device', '6 × EAP670 (HQ Campus)', 'success', { from: '1.0.13', to: '1.0.15', window: 'Tue 02:00-04:00' }],
  ['0000000018', 742, 'Demo Admin', demoUser.email, '10.10.20.31', 'site.update', 'site', 'Branch Office', 'success', { changes: { timezone: ['America/Chicago', 'America/Denver'] } }],
  ['0000000019', 906, 'Priya Raman', 'priya@freesdn.local', '10.10.20.58', 'credential.delete', 'credential', 'Legacy pfSense (decommissioned)', 'success', { reason: 'appliance retired' }],
  ['0000000020', 1_284, 'Demo Admin', demoUser.email, '10.10.20.31', 'alert_rule.create', 'alert_rule', 'Storage pool capacity', 'success', { severity: 'warning', threshold: 85 }],
].map((row) => {
  const [suffix, minutesAgo, actorName, actorEmail, ip, action, resourceType, resourceName, status, changes] = row as [
    string, number, string, string, string, string, string, string, string, Record<string, unknown>,
  ];
  return {
    id: `9d6b3f18-4e27-4a90-bc63-${suffix}`,
    timestamp: demoIso(minutesAgo),
    actor_type: actorEmail === 'automation@freesdn.local' ? 'service' : 'user',
    actor_id: demoUser.id,
    actor_name: actorName,
    actor_email: actorEmail,
    ip_address: ip,
    action,
    resource_type: resourceType,
    resource_id: `${resourceType}-${suffix.slice(-4)}`,
    resource_name: resourceName,
    changes,
    status,
    organization_id: demoIds.org,
    site_id: resourceName.includes('Branch') ? demoIds.branch : demoIds.hq,
  };
});

export const auditRollup = {
  total_events: 4_812,
  by_level: { info: 4_218, notice: 402, warning: 154, error: 34, critical: 4 },
  by_source: { device: 1_642, auth: 1_180, config: 786, automation: 604, api: 412, system: 188 },
};

// ─── System log stream (/logs) ─────────────────────────────────────────────

export const demoLogTemplates = [
  ['info', 'api', 'GET /api/v1/devices/ completed', 46],
  ['info', 'device', 'Controller sync finished for Omada OC300 - HQ', 12_480],
  ['debug', 'device', 'SNMP walk 1.3.6.1.2.1.2.2 completed on HQ-Core-SW-01', 318],
  ['warning', 'device', 'Adapter retry 1/3 after read timeout on Branch Office WAN probe', 8_000],
  ['info', 'auth', 'Session refreshed for demo@freesdn.local', 22],
  ['info', 'system', 'Celery queue "metrics" drained, depth 0', 4],
  ['error', 'device', 'HQ-Floor2-AP-03 unreachable after 6 consecutive polls', 8_000],
  ['info', 'config', 'Staged change chg-4821 applied to 4 devices', 2_940],
  ['debug', 'database', 'Connection pool checkout took 3 ms (pool 8/20)', 3],
  ['info', 'user', 'Dashboard layout saved for demo@freesdn.local', 18],
  ['warning', 'system', 'Metric ingest lagging by 42 s; backlog 1 380 samples', 120],
  ['critical', 'device', 'PoE budget exhausted on HQ-Core-SW-01; port 22 denied power', 60],
  ['info', 'api', 'POST /api/v1/alert-rules/evaluate completed', 1_240],
  ['info', 'device', 'Discovery scan found 3 new hosts at Branch Office', 245_000],
  ['error', 'api', 'Upstream controller returned 502 for GET /api/v2/sites', 8_100],
  ['info', 'auth', 'OIDC token exchange succeeded for riley@freesdn.local', 210],
];

export const demoSystemLogs = Array.from({ length: 72 }, (_, i) => {
  const [level, source, message, duration] = demoLogTemplates[i % demoLogTemplates.length] as [
    string, string, string, number,
  ];
  const site = [demoIds.hq, demoIds.branch, demoIds.dc][i % 3];
  const siteName = ['HQ Campus', 'Branch Office', 'Datacenter'][i % 3];
  const actorEmail = ['demo@freesdn.local', 'riley@freesdn.local', 'automation@freesdn.local'][i % 3];
  return {
    id: `logent-${String(i + 1).padStart(4, '0')}`,
    timestamp: demoIso(3 + i * 7),
    level,
    source,
    message,
    details: { request_id: `req-${(918_400 + i * 17).toString(16)}` },
    user_email: source === 'auth' || source === 'user' ? actorEmail : undefined,
    ip_address: source === 'auth' || source === 'user' ? '10.10.20.31' : undefined,
    request_id: `req-${(918_400 + i * 17).toString(16)}`,
    duration_ms: duration,
    site_id: site,
    site_name: siteName,
  };
});

// ─── Notifications ─────────────────────────────────────────────────────────
// The bell reads `body` / `read` (BE names), not `message` / `is_read`.

export const inAppNotifications = [
  // [id suffix, title, body, category, severity, action_url, read, dismissed, minutesAgo]
  ['0000000001', 'Access point unreachable', 'HQ-Floor2-AP-03 has missed 6 reachability polls. Investigate before the Floor 2 stand-up.', 'alerts', 'critical', '/alerts', false, false, 34],
  ['0000000002', 'WAN latency above SLA', 'Branch Office uplink RTT is 168 ms against a 60 ms objective.', 'alerts', 'warning', '/alerts', false, false, 12],
  ['0000000003', 'Backup pool nearing capacity', 'tank-backup is 88% full; about 9 days of retention left.', 'storage', 'warning', '/storage', false, false, 96],
  ['0000000004', 'Staged change applied', 'VLAN 60 "Guest-IoT" reached 4 devices on Omada OC300 - HQ.', 'changes', 'info', '/pending-changes', true, false, 6],
  ['0000000005', 'Staged change needs review', 'Firewall rule "Allow-RDP-Any" was rejected and is waiting on a source restriction.', 'changes', 'warning', '/pending-changes', true, false, 61],
  ['0000000006', 'Nightly backup failed', 'The Branch Office config backup failed after 3 retries.', 'backup', 'warning', '/backups', true, false, 218],
  // Dismissed rows are what the bell's Archive tab shows; with none the tab
  // rendered permanently empty.
  ['0000000007', 'Address blocked', '198.51.100.42 was blocked for 60 minutes after 14 failed sign-ins.', 'security', 'high', '/security', true, true, 49],
  ['0000000008', 'Firmware applied', '6 access points moved from 1.0.13 to 1.0.15 in the Tuesday window.', 'firmware', 'info', '/firmware', true, true, 602],
].map((row) => {
  const [suffix, title, body, category, severity, actionUrl, read, dismissed, minutesAgo] = row as [
    string, string, string, string, string, string, boolean, boolean, number,
  ];
  return {
    id: `31c8e7a5-6d02-4b44-9f18-${suffix}`,
    user_id: demoUser.id,
    title,
    body,
    category,
    severity,
    action_url: actionUrl,
    read,
    read_at: read ? demoIso(minutesAgo - 2) : null,
    dismissed,
    dismissed_at: dismissed ? demoIso(minutesAgo - 4) : null,
    entity_type: null,
    entity_id: null,
    expires_at: null,
    created_at: demoIso(minutesAgo),
  };
});

export const notificationProviders = [
  {
    id: 'a2b6c04f-3d51-4e78-9a10-000000000001',
    name: 'Ops mailbox (SMTP)',
    provider_type: 'smtp',
    channel: 'email',
    is_enabled: true,
    is_default: true,
    is_verified: true,
    last_verified_at: demoIso(180),
    last_error: undefined,
    rate_limit_per_hour: 120,
    rate_limit_per_day: 600,
    config_summary: { host: 'smtp.freesdn.local', port: 587, starttls: true, from_address: 'freesdn@freesdn.local' },
    created_at: demoIso(60 * 24 * 40),
    updated_at: demoIso(180),
  },
  {
    id: 'a2b6c04f-3d51-4e78-9a10-000000000002',
    name: '#netops-alerts',
    provider_type: 'slack',
    channel: 'slack',
    is_enabled: true,
    is_default: false,
    is_verified: true,
    last_verified_at: demoIso(240),
    last_error: undefined,
    rate_limit_per_hour: 200,
    rate_limit_per_day: 1_000,
    config_summary: { workspace: 'freesdn-demo', channel: '#netops-alerts', webhook: 'stored in the credential vault' },
    created_at: demoIso(60 * 24 * 32),
    updated_at: demoIso(240),
  },
  {
    id: 'a2b6c04f-3d51-4e78-9a10-000000000003',
    name: 'Automation webhook',
    provider_type: 'webhook',
    channel: 'webhook',
    is_enabled: true,
    is_default: false,
    is_verified: false,
    last_verified_at: demoIso(1_440),
    last_error: 'Last verification returned 503 from the automation host.',
    rate_limit_per_hour: 600,
    rate_limit_per_day: 5_000,
    config_summary: { url: 'https://automation.freesdn.local/hooks/freesdn', method: 'POST', signed: true },
    created_at: demoIso(60 * 24 * 21),
    updated_at: demoIso(1_440),
  },
  {
    id: 'a2b6c04f-3d51-4e78-9a10-000000000004',
    name: 'In-app bell',
    provider_type: 'in_app',
    channel: 'in_app',
    is_enabled: true,
    is_default: true,
    is_verified: true,
    last_verified_at: demoIso(30),
    last_error: undefined,
    rate_limit_per_hour: 1_000,
    rate_limit_per_day: 10_000,
    config_summary: { retention_days: 30 },
    created_at: demoIso(60 * 24 * 45),
    updated_at: demoIso(30),
  },
];

export const notificationProviderTypes = [
  { type: 'smtp', name: 'SMTP e-mail', channel: 'email', config_schema: { type: 'object', properties: { host: { type: 'string' }, port: { type: 'integer' }, from_address: { type: 'string' } }, required: ['host', 'port', 'from_address'] } },
  { type: 'slack', name: 'Slack', channel: 'slack', config_schema: { type: 'object', properties: { webhook_url: { type: 'string' }, channel: { type: 'string' } }, required: ['webhook_url'] } },
  { type: 'teams', name: 'Microsoft Teams', channel: 'teams', config_schema: { type: 'object', properties: { webhook_url: { type: 'string' } }, required: ['webhook_url'] } },
  { type: 'webhook', name: 'Generic webhook', channel: 'webhook', config_schema: { type: 'object', properties: { url: { type: 'string' }, method: { type: 'string' } }, required: ['url'] } },
  { type: 'twilio', name: 'Twilio SMS', channel: 'sms', config_schema: { type: 'object', properties: { account_sid: { type: 'string' }, from_number: { type: 'string' } }, required: ['account_sid', 'from_number'] } },
  { type: 'in_app', name: 'In-app notification', channel: 'in_app', config_schema: { type: 'object', properties: { retention_days: { type: 'integer' } } } },
];

// ─── Metric catalogue (/analytics/metrics/definitions) ─────────────────────

export const metricDefinitions = [
  ['0000000001', 'wan.latency.rtt_ms', 'WAN round-trip time', 'network', 'gauge', 'ms', 60, 150],
  ['0000000002', 'wan.throughput.rx_mbps', 'WAN receive throughput', 'network', 'gauge', 'Mbps', 800, 940],
  ['0000000003', 'wifi.radio.channel_utilization_percent', 'Wi-Fi channel utilization', 'wireless', 'gauge', '%', 70, 85],
  ['0000000004', 'switch.poe.utilization_percent', 'PoE budget utilization', 'power', 'gauge', '%', 85, 95],
  ['0000000005', 'storage.pool.usage_percent', 'Storage pool usage', 'storage', 'gauge', '%', 85, 92],
  ['0000000006', 'hypervisor.node.memory_percent', 'Hypervisor node memory', 'compute', 'gauge', '%', 85, 93],
  ['0000000007', 'device.reachability.consecutive_failures', 'Consecutive reachability failures', 'availability', 'counter', 'polls', 3, 5],
  ['0000000008', 'client.signal.dbm', 'Client signal strength', 'wireless', 'gauge', 'dBm', -70, -78],
].map((row) => {
  const [suffix, name, displayName, category, metricType, unit, warn, crit] = row as [
    string, string, string, string, string, string, number, number,
  ];
  return {
    id: `6b1d4e83-0f92-4a17-8c56-${suffix}`,
    name,
    display_name: displayName,
    description: `${displayName} collected by the observability module.`,
    category,
    metric_type: metricType,
    unit,
    labels: ['site_id', 'device_id'],
    default_aggregation: 'avg',
    warning_threshold: { operator: '>', value: warn },
    critical_threshold: { operator: '>', value: crit },
    is_active: true,
    is_system: true,
  };
});

// ─── Dashboard summary ─────────────────────────────────────────────────────
// Field names MUST match the backend DashboardSummaryResponse
// (app/schemas/analytics.py): devices_online / devices_offline /
// devices_warning. They were online_devices / offline_devices /
// warning_devices here, which no consumer reads, so the demo dashboard
// rendered "0/8 Online" with seven of eight devices up. The counts are
// derived from `devices` so that class of drift cannot come back; the
// contract test in src/demo/__tests__ pins it.

export const dashboardSummary = {
  total_devices: demoDeviceMetrics.length,
  devices_online: demoOnlineDevices.length,
  devices_offline: demoOfflineDevices.length,
  devices_warning: demoDegradedDevices.length,
  total_sites: sites.length,
  total_clients: demoClientTotals.total,
  active_alerts: demoFiringAlerts.length,
  critical_alerts: demoFiringAlerts.filter((a) => a.severity === 'critical').length,
  total_rx_bytes_24h: demoRxBytes24h,
  total_tx_bytes_24h: demoTxBytes24h,
  health_score_avg: 93,
  metrics_summary: {
    api_calls: 128_400,
    events_processed: 41_920,
    automation_executions: 386,
  },
  top_issues: demoFiringAlerts.map((a) => ({
    id: a.id,
    severity: a.severity,
    title: a.title,
    triggered_at: a.triggered_at,
  })),
  recent_alerts: alerts
    .slice()
    .sort((a, b) => new Date(b.triggered_at).getTime() - new Date(a.triggered_at).getTime())
    .slice(0, 8)
    .map((a) => ({
      id: a.id,
      severity: a.severity,
      status: a.status,
      title: a.title,
      triggered_at: a.triggered_at,
    })),
  timestamp: demoIso(),
  // Extra keys the demo's own mock handlers read (/devices/stats/summary).
  total_controllers: controllers.length,
  cameras_online: cameras.filter((c) => c.status === 'online').length,
  switches_online: demoOnlineDevices.filter((d) => d.type === 'switch').length,
};

// ─── Enterprise analytics ──────────────────────────────────────────────────
// Drives /analytics (five tabs) and eleven dashboard widgets. Shapes come
// from `EnterpriseAnalytics` in lib/api/types.ts -- note `sites[].id` (not
// site_id) and `clients.top_ssids[].clients` (not count); the old fixture
// used the wrong key on both and the Top SSIDs widget rendered "NaN clients".

export const enterpriseAnalytics = {
  timestamp: demoIso(),
  generated_at: demoIso(),
  hours: 24,
  health_score: 93,
  total_sites: sites.length,
  fleet: {
    total: demoDeviceMetrics.length,
    online: demoOnlineDevices.length,
    offline: demoOfflineDevices.length,
    degraded: demoDegradedDevices.length,
    avg_cpu: demoAvg(demoDeviceMetrics.filter((d) => d.cpu > 0).map((d) => d.cpu)),
    avg_memory: demoAvg(demoDeviceMetrics.filter((d) => d.memory > 0).map((d) => d.memory)),
    avg_temp: 47,
    max_cpu: demoDeviceMetrics.reduce((max, d) => Math.max(max, d.cpu), 0),
    max_memory: demoDeviceMetrics.reduce((max, d) => Math.max(max, d.memory), 0),
    max_temp: 61,
    by_type: demoFleetByType,
    by_manufacturer: demoFleetByManufacturer,
  },
  clients: {
    total: demoClientTotals.total,
    online: demoClientTotals.online,
    band_2g: demoClientTotals.band_2g,
    band_5g: demoClientTotals.band_5g,
    band_6g: demoClientTotals.band_6g,
    avg_signal_dbm: -56,
    total_tx_bytes: Math.round(demoTxBytes24h * 0.58),
    total_rx_bytes: Math.round(demoRxBytes24h * 0.61),
    signal_distribution: { excellent: 168, good: 194, fair: 84, weak: 32, poor: 8 },
    top_ssids: [
      { ssid: 'Acme-Corp', clients: 268 },
      { ssid: 'Acme-Guest', clients: 122 },
      { ssid: 'Acme-IoT', clients: 74 },
      { ssid: 'Acme-Voice', clients: 22 },
    ],
  },
  ports: {
    total: 180,
    up: 152,
    down: 28,
    poe_ports: 96,
    total_poe_watts: 1_284,
    total_tx_bytes: demoTxBytes24h,
    total_rx_bytes: demoRxBytes24h,
    total_errors: 41,
  },
  sites: sites.map((site) => ({
    id: site.id,
    site_id: site.id,
    name: site.name,
    devices: site.device_count,
    online: site.online_device_count,
    offline: Math.max(0, site.device_count - site.online_device_count),
    health: site.status === 'healthy' ? 96 : 82,
  })),
  controllers: controllers.map((c) => ({
    id: c.id,
    name: c.name,
    type: c.vendor,
    status: c.status,
    host: c.host,
    sync_enabled: true,
    device_count: c.device_count,
  })),
  security: {
    failed_logins_window: securitySummary.failed_logins,
    active_ip_blocks: 1,
    unresolved_anomalies: securityAnomalies.length,
    total_security_events: securitySummary.total_events,
  },
  audit: auditRollup,
  incidents: {
    open: incidents.filter((i) => i.status === 'open').length,
    investigating: incidents.filter((i) => i.status === 'investigating').length,
    resolved: 14,
    total: 17,
  },
  top_devices_cpu: demoDeviceMetrics
    .filter((d) => d.cpu > 0)
    .slice()
    .sort((a, b) => b.cpu - a.cpu)
    .slice(0, 8)
    .map((d) => ({ id: d.id, name: d.name, type: d.type, cpu: d.cpu, status: d.status })),
  top_devices_memory: demoDeviceMetrics
    .filter((d) => d.memory > 0)
    .slice()
    .sort((a, b) => b.memory - a.memory)
    .slice(0, 8)
    .map((d) => ({ id: d.id, name: d.name, type: d.type, memory: d.memory, status: d.status })),
  // Time series. Not read by DashboardPage yet -- see the note in the
  // handoff: buildTrafficChartData() still collapses 24h into one point.
  traffic: demoTrafficSeries,
  latency: demoLatencySeries,
  clients_timeline: demoTrafficSeries.map((p) => ({ timestamp: p.timestamp, clients: p.clients })),
  network: {
    latency_ms: demoLatencySeries[demoLatencySeries.length - 1].latency_ms,
    latency_history: demoLatencySeries.map((p) => p.latency_ms),
    packet_loss_percent: demoLatencySeries[demoLatencySeries.length - 1].packet_loss_percent,
    packet_loss_history: demoLatencySeries.map((p) => p.packet_loss_percent),
    throughput_history: demoTrafficSeries.map((p) => ({ download: p.rx_mbps, upload: p.tx_mbps })),
    uptime_percent: 99.87,
  },
};

// ─── Logs health / stats roll-ups ──────────────────────────────────────────

export const logsHealth = {
  total_events_24h: demoLogHourly.slice(-24).reduce((sum, b) => sum + b.count, 0),
  total_events_7d: demoLogHourly.reduce((sum, b) => sum + b.count, 0),
  error_count_24h: demoLogHourly.slice(-24).reduce((sum, b) => sum + b.errors, 0),
  warning_count_24h: 528,
  critical_count_24h: 12,
  success_rate: 96.9,
  failed_logins_24h: securitySummary.failed_logins,
  active_ip_blocks: 1,
  unresolved_anomalies: securityAnomalies.length,
  open_incidents: correlationStats.open_incidents,
  event_trend: 8,
  error_trend: -14,
  needs_attention: demoFiringAlerts.map((a) => ({
    type: 'alert',
    id: a.id,
    title: a.title,
    severity: a.severity,
    timestamp: a.triggered_at,
  })),
  avg_response_ms: 214,
  p95_response_ms: 1_640,
  daily_histogram: demoLogDaily,
};

// ---------------------------------------------------------------------------
// ONE FLEET, ONE SET OF NUMBERS
// ---------------------------------------------------------------------------
// The demo previously carried three device lists that disagreed: an 8-row
// `devices`, a 61-row fleet, and sites asserting 92 between them. A visitor saw
// a dashboard claiming one number and a device list showing another, which
// reads as a broken product rather than a new one.
//
// Every count is DERIVED from that one list rather than asserted alongside it,
// so the three can no longer drift apart.

for (const site of sites) {
  const own = devices.filter((d) => d.site_id === site.id);
  site.device_count = own.length;
  site.online_device_count = own.filter((d) => d.status === 'online').length;
}

dashboardSummary.total_devices = devices.length;
dashboardSummary.devices_online = devices.filter((d) => d.status === 'online').length;
dashboardSummary.devices_offline = devices.filter((d) => d.status === 'offline').length;
dashboardSummary.devices_warning = devices.filter((d) => d.status === 'degraded').length;
dashboardSummary.total_sites = sites.length;

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { api } from './client';

export interface TestConnectionResult {
  success: boolean;
  message: string;
  controller_id?: string;
  status?: string;
  error?: string;
  details?: {
    latency_ms?: number;
    controller_version?: string;
    controller_name?: string;
    site_count?: number;
    device_count?: number;
    api_version?: string;
  };
}

export interface ControllerMetadata {
  controller_id: string;
  controller_name: string;
  controller_type: string;
  status: string;
  runtime_status: {
    cpu_util?: number;
    mem_util?: number;
    disk_util?: number;
    uptime?: number;
    version?: string;
    model?: string;
    device_count?: number;
    site_count?: number;
    client_count?: number;
  };
  device_counts: {
    total: number;
    online: number;
    offline: number;
    switches: number;
    access_points: number;
    gateways: number;
  };
  client_count: number;
  poe_budget: {
    total_budget_watts: number;
    total_consumed_watts: number;
    total_remaining_watts: number;
    switches_with_poe: number;
  };
  firmware: {
    total_devices: number;
    up_to_date: number;
    needs_upgrade: number;
    devices: Array<{
      mac: string;
      name: string;
      current: string | null;
      latest: string | null;
      needs_upgrade: boolean;
    }>;
  };
  sync: {
    last_sync: string | null;
    last_sync_duration_seconds: number | null;
    last_error: string | null;
    error_history: Array<{ timestamp: string; error: string }>;
  };
  site_mappings: Record<string, string>;
  devices: Array<{
    id: string;
    name: string;
    type: string;
    status: string;
    mac: string;
    ip: string | null;
    model: string | null;
    firmware_version: string | null;
    cpu_usage: number | null;
    memory_usage: number | null;
    uptime: number | null;
    poe_budget_watts: number | null;
    poe_consumed_watts: number | null;
    radios: Array<{
      band: string;
      channel: number;
      channel_width: string;
      tx_power: number;
      clients: number;
    }> | null;
    clients: number | null;
  }>;
}

/** Returned by ``GET /controllers/{id}/capabilities``. Sourced from
 *  the adapter's ``AdapterManifest``; flat ``capabilities`` is the
 *  set the UI checks against, ``by_device_type`` lets a page scope
 *  by device type (e.g. show "WIDS/WIPS" only when ``access_point``
 *  advertises it). */
export interface ControllerCapabilities {
  controller_id: string;
  adapter_id: string;
  adapter_name?: string;
  vendor?: string;
  version?: string;
  supported_versions?: string[];
  capabilities: string[];
  by_device_type: Record<string, string[]>;
  auth_methods?: string[];
  supports_bulk_operations?: boolean;
}

/** Live read-only storage inventory for a TrueNAS appliance.
 *  Returned by ``GET /controllers/{id}/storage`` (proxied to the
 *  TrueNAS WS JSON-RPC API). */
export interface StoragePoolRedundancy {
  type: string; // RAIDZ1/2/3, MIRROR, STRIPE, UNKNOWN
  vdevs: number;
  width: number;
}

export interface StoragePoolScrub {
  function: string | null;
  state: string | null; // FINISHED / SCANNING / …
  errors: number | null;
  percentage: number | null;
  finished_at_ms: number | null;
}

export interface StoragePool {
  name: string;
  status: string;
  healthy: boolean;
  size: number;
  allocated: number;
  free: number;
  fragmentation: string;
  usage_percent: number;
  is_decrypted: boolean;
  redundancy: StoragePoolRedundancy;
  scrub: StoragePoolScrub | null;
}

export interface StorageDisk {
  name: string;
  type: string;
  model: string;
  serial: string;
  size: number;
  pool: string | null;
  vdev_type: string | null;
  zfs_status: string | null;
  read_errors: number | null;
  write_errors: number | null;
  checksum_errors: number | null;
  temperature_c: number | null;
  transfermode: string;
}

export interface StorageAlert {
  level: string; // INFO/NOTICE/WARNING/ERROR/CRITICAL/ALERT
  klass: string;
  message: string;
  at_ms: number | null;
  one_shot: boolean;
}

export interface StorageService {
  service: string; // cifs/nfs/iscsitarget/ssh/…
  state: string; // RUNNING / STOPPED
  enabled: boolean;
}

export interface StorageDataset {
  id: string;
  name: string;
  pool: string;
  type: string;
  mountpoint: string | null;
  encrypted: boolean;
  locked: boolean;
  used_bytes: number;
  available_bytes: number;
  quota_bytes: number;
}

export interface StorageInventory {
  controller_id: string;
  name: string;
  host: string;
  transport: string | null;
  system: {
    version: string;
    hostname: string;
    product: string;
    serial: string;
    physmem: number;
    uptime_seconds: number;
    timezone: string;
  };
  health: {
    status: 'ok' | 'warning' | 'error';
    pool_count: number;
    alert_count: number;
    critical_alert_count: number;
  };
  alerts: StorageAlert[];
  services: StorageService[];
  data_protection: { snapshot_tasks: number; replication: number; cloudsync: number };
  pools: StoragePool[];
  disks: StorageDisk[];
  datasets: StorageDataset[];
  snapshot_count: number;
}

export const controllersApi = {
  getAll: (siteId?: string, perPage?: number, controllerType?: string) =>
    api.get('/controllers/', {
      params: { site_id: siteId, per_page: perPage, controller_type: controllerType },
    }),
  getById: (id: string) => api.get(`/controllers/${id}`),
  getMetadata: (id: string) => api.get<ControllerMetadata>(`/controllers/${id}/metadata`),
  /** Adapter-advertised capabilities. UI uses these to hide tabs / buttons
   *  for features the underlying adapter doesn't support. */
  getCapabilities: (id: string) =>
    api.get<ControllerCapabilities>(`/controllers/${id}/capabilities`),
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  create: (data: Record<string, any>) => api.post('/controllers/', data),
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  update: (id: string, data: Record<string, any>) => api.patch(`/controllers/${id}`, data),
  delete: (id: string) => api.delete(`/controllers/${id}`),
  sync: (id: string) => api.post(`/controllers/${id}/sync`),
  /** Test connection for an existing (saved) controller */
  test: (id: string) => api.post<TestConnectionResult>(`/controllers/${id}/test`),
  /** Live read-only TrueNAS storage inventory (system + pools + disks + datasets). */
  getStorage: (id: string) => api.get<StorageInventory>(`/controllers/${id}/storage`),
  /** Test connection before creating a controller (pre-creation probe) */
  testConnection: (data: Record<string, unknown>) =>
    api.post<TestConnectionResult>('/controllers/test-connection', data),
  // Site mapping endpoints
  getRemoteSites: (id: string) => api.get(`/controllers/${id}/remote-sites`),
  updateSiteMappings: (id: string, mappings: Record<string, string>) =>
    api.put(`/controllers/${id}/site-mappings`, { site_mappings: mappings }),
  probeRemoteSites: (data: Record<string, unknown>) => api.post('/controllers/probe-remote-sites', data),
  // WiFi management
  getChannelUtilization: (id: string) => api.get(`/controllers/${id}/wifi/channel-utilization`),
  getRogueAps: (id: string) => api.get(`/controllers/${id}/wifi/rogue-aps`),
  getRadioSettings: (id: string) => api.get(`/controllers/${id}/wifi/radio-settings`),
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  updateRadioSettings: (id: string, data: Record<string, any>) =>
    api.put(`/controllers/${id}/wifi/radio-settings`, data),
};

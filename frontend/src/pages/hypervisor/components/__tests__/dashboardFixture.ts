// SPDX-License-Identifier: AGPL-3.0-only
import type { HypervisorDashboard } from '@/lib/api';

export function dashboard(overrides: Partial<HypervisorDashboard> = {}): HypervisorDashboard {
  const now = Date.now();
  const metric = () => ({ status: 'available' as const, expected_nodes: 1, observed_nodes: 1, reasons: [] });
  return {
    controller_id: 'controller', cluster_name: 'lab', quorate: true,
    total_nodes: 1, online_nodes: 1, total_vms: 2, running_vms: 1,
    total_containers: 1, running_containers: 0,
    total_cpu_cores: 4, used_cpu_cores: 1, cpu_usage_percent: 25,
    total_memory_bytes: 1000, used_memory_bytes: 500, memory_usage_percent: 50,
    total_storage_bytes: 2000, used_storage_bytes: 1000, storage_usage_percent: 50,
    metric_coverage: { cpu: metric(), memory: metric(), node_filesystem: metric() },
    coverage: 'complete_visible', inventory_scope: 'credential_visible', storage_scope: 'node_filesystems',
    provider_sample_time_known: false, collection_started_at: new Date(now - 2000).toISOString(),
    observed_at: new Date(now - 1000).toISOString(), served_at: new Date(now).toISOString(),
    observation_age_seconds: 2, stale_after_seconds: 90, ha_active: null, ha_services_visible: 0,
    nodes: [{ node: 'n1', status: 'online' }], ...overrides,
  };
}

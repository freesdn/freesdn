// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import type { FleetDashboard, HypervisorDashboard } from '@/lib/api/types';
import { demoHypervisorGuests, demoHypervisorHaResources, demoHypervisorNodes, demoIds } from './fixtures';

// These are sample observations, never hardware measurements. Generate their
// timestamps per request so a demo refresh does not return an expired snapshot.
export function getDemoHypervisorDashboard(): HypervisorDashboard {
  const now = new Date().toISOString();
  const totalCpu = demoHypervisorNodes.reduce((sum, n) => sum + n.cpu_count, 0);
  const usedCpu = demoHypervisorNodes.reduce((sum, n) => sum + n.cpu_count * n.cpu_usage, 0);
  const totalMemory = demoHypervisorNodes.reduce((sum, n) => sum + n.memory_total, 0);
  const usedMemory = demoHypervisorNodes.reduce((sum, n) => sum + n.memory_used, 0);
  const totalStorage = demoHypervisorNodes.reduce((sum, n) => sum + n.storage_total, 0);
  const usedStorage = demoHypervisorNodes.reduce((sum, n) => sum + n.storage_used, 0);
  const guests = (kind: string, running = false) => demoHypervisorGuests.filter(
    g => g.vm_type === kind && (!running || g.status === 'running'),
  ).length;
  const metric = () => ({ status: 'available' as const, expected_nodes: demoHypervisorNodes.length,
    observed_nodes: demoHypervisorNodes.length, reasons: [] });
  return {
    controller_id: demoIds.proxmox, cluster_name: 'pve-dc-a', quorate: true,
    total_nodes: demoHypervisorNodes.length,
    online_nodes: demoHypervisorNodes.filter(n => n.status === 'online').length,
    total_vms: guests('qemu'), running_vms: guests('qemu', true),
    total_containers: guests('lxc'), running_containers: guests('lxc', true),
    total_cpu_cores: totalCpu, used_cpu_cores: usedCpu, cpu_usage_percent: usedCpu / totalCpu * 100,
    total_memory_bytes: totalMemory, used_memory_bytes: usedMemory, memory_usage_percent: usedMemory / totalMemory * 100,
    total_storage_bytes: totalStorage, used_storage_bytes: usedStorage, storage_usage_percent: usedStorage / totalStorage * 100,
    metric_coverage: { cpu: metric(), memory: metric(), node_filesystem: metric() },
    coverage: 'complete_visible', inventory_scope: 'credential_visible', storage_scope: 'node_filesystems',
    provider_sample_time_known: false, collection_started_at: now, observed_at: now, served_at: now,
    observation_age_seconds: 0, stale_after_seconds: 90,
    ha_active: null, ha_services_visible: demoHypervisorHaResources.length,
    nodes: demoHypervisorNodes.map(n => ({ node: n.node, status: n.status === 'online' ? 'online' : 'offline' })),
  };
}

export function getDemoHypervisorFleetDashboard(): FleetDashboard {
  const cluster = getDemoHypervisorDashboard();
  return {
    ...cluster, total_clusters: 1, online_clusters: 1, failed_clusters: 0,
    aggregation_scope: 'controller_registrations', deduplicated: false,
    clusters: [{ ...cluster, controller_name: 'PVE Cluster A', status: 'online', error: '' }],
  };
}

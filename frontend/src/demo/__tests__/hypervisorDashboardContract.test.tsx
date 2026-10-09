// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import axios from 'axios';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import type { FleetDashboard, HypervisorDashboard } from '@/lib/api/types';
import { renderWithProviders } from '@/test-utils';
import { DashboardTab, FleetTab } from '@/pages/hypervisor/components/DashboardPanels';
import { observationFreshness } from '@/pages/hypervisor/components/dashboardObservationState';
import { demoIds } from '../identity';
import { demoAxiosAdapter } from '../mockApi';

const client = axios.create({ adapter: demoAxiosAdapter });
const dashboard = async () => (await client.get<HypervisorDashboard>(`/hypervisor/controllers/${demoIds.proxmox}/dashboard`)).data;
afterEach(() => vi.useRealTimers());

describe('demo hypervisor responses satisfy the real dashboard contract', () => {
  it('identifies the registered controller and renders the cluster instead of a load error', async () => {
    const data = await dashboard();
    expect(data.controller_id).toBe(demoIds.proxmox);
    renderWithProviders(<DashboardTab controllerId={demoIds.proxmox} dashLoading={false} dashError={false} dash={data} refetchDash={vi.fn()} />);
    expect(screen.getByText('pve-dc-a')).toBeInTheDocument();
    expect(screen.queryByText('Failed to load dashboard')).not.toBeInTheDocument();
    expect(screen.getByText('Visible HA services')).toBeInTheDocument();
  });

  it('supplies a current observation with complete sample metric coverage', async () => {
    const data = await dashboard();
    expect(observationFreshness(data, Date.now()).state).toBe('current');
    expect(data.coverage).toBe('complete_visible');
    for (const metric of Object.values(data.metric_coverage)) {
      expect(metric).toMatchObject({ status: 'available', expected_nodes: 3, observed_nodes: 3 });
    }
    expect(data.provider_sample_time_known).toBe(false);
  });

  it('refreshes an expired snapshot without changing the prior response', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(new Date('2026-09-25T12:00:00Z'));
    const old = await dashboard();
    vi.setSystemTime(new Date('2026-09-25T12:02:00Z'));
    const fresh = await dashboard();
    expect(observationFreshness(old, Date.now()).state).toBe('stale');
    expect(observationFreshness(fresh, Date.now()).state).toBe('current');
    expect(fresh.observed_at).not.toBe(old.observed_at);
  });

  it('reports node filesystems and visible HA services without claiming storage-pool or HA health', async () => {
    const data = await dashboard();
    expect(data.storage_scope).toBe('node_filesystems');
    expect(data.total_storage_bytes).toBe(7_200_000_000_000);
    expect(data.used_storage_bytes).toBe(3_837_000_000_000);
    expect(data.ha_active).toBeNull();
    expect(data.ha_services_visible).toBe(5);
  });

  it('renders fleet observations with the same controller and explicit registration scope', async () => {
    const data = (await client.get<FleetDashboard>('/hypervisor/fleet/dashboard')).data;
    expect(data.aggregation_scope).toBe('controller_registrations');
    expect(data.deduplicated).toBe(false);
    expect(data.failed_clusters).toBe(0);
    expect(data.clusters[0].controller_id).toBe(demoIds.proxmox);
    renderWithProviders(<FleetTab fleetLoading={false} fleetError={false} fleet={data} refetchFleet={vi.fn()} />);
    expect(screen.getByText('PVE Cluster A')).toBeInTheDocument();
    expect(screen.queryByText('Failed to load dashboard')).not.toBeInTheDocument();
  });
});

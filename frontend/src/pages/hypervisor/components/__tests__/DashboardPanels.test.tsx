// SPDX-License-Identifier: AGPL-3.0-only
import { afterEach, describe, expect, it, vi } from 'vitest';
import { act, screen } from '@testing-library/react';
import { renderWithProviders } from '@/test-utils';
import type { FleetDashboard } from '@/lib/api';
import { DashboardTab, FleetTab } from '../DashboardPanels';
import { dashboard } from './dashboardFixture';

afterEach(() => vi.useRealTimers());
const base = { controllerId: 'controller', dashLoading: false, dashError: false, refetchDash: vi.fn() };

describe('cluster and fleet dashboard presentation', () => {
  it('shows observed zero as zero and labels node filesystem capacity', () => {
    renderWithProviders(<DashboardTab {...base} dash={dashboard({ cpu_usage_percent: 0 })} />);
    expect(screen.getByText('0.0%')).toBeInTheDocument();
    expect(screen.getAllByText('Node filesystem usage').length).toBeGreaterThan(0);
    expect(screen.getByText('Visible HA services')).toBeInTheDocument();
    expect(screen.queryByText('Active')).not.toBeInTheDocument();
  });
  it('does not render a partial metric as a subset percentage', () => {
    const data = dashboard({ coverage: 'partial', cpu_usage_percent: null, total_cpu_cores: null });
    data.metric_coverage.cpu = { status: 'partial', expected_nodes: 2, observed_nodes: 1, reasons: ['missing_statistics'] };
    renderWithProviders(<DashboardTab {...base} dash={data} />);
    expect(screen.queryByText('25.0%')).not.toBeInTheDocument();
    expect(screen.getAllByText('Unknown').length).toBeGreaterThan(0);
    expect(screen.getByText(/1 of 2 known nodes/)).toBeInTheDocument();
  });
  it('does not expose cached counters when refresh has failed', () => {
    renderWithProviders(<DashboardTab {...base} dashError dash={dashboard()} />);
    expect(screen.queryByText('25.0%')).not.toBeInTheDocument();
    expect(screen.queryByText('lab')).not.toBeInTheDocument();
  });
  it('rejects a different controller response', () => {
    renderWithProviders(<DashboardTab {...base} dash={dashboard({ controller_id: 'foreign' })} />);
    expect(screen.queryByText('lab')).not.toBeInTheDocument();
  });
  it('hides data when it ages beyond the freshness limit', () => {
    vi.useFakeTimers();
    renderWithProviders(<DashboardTab {...base} dash={dashboard()} />);
    expect(screen.getByText('25.0%')).toBeInTheDocument();
    act(() => vi.advanceTimersByTime(90000));
    expect(screen.queryByText('25.0%')).not.toBeInTheDocument();
    expect(screen.getByText(/Current values are hidden/)).toBeInTheDocument();
  });
  it('keeps failed controllers visible without presenting complete fleet totals', () => {
    const data = dashboard({ coverage: 'partial', total_nodes: null, online_nodes: null, cpu_usage_percent: null, total_cpu_cores: null });
    data.metric_coverage.cpu = { status: 'partial', expected_nodes: 1, observed_nodes: 1, reasons: [] };
    const fleet: FleetDashboard = { ...data, total_clusters: 2, online_clusters: 1, failed_clusters: 1, aggregation_scope: 'controller_registrations', deduplicated: false,
      clusters: [ { ...dashboard(), controller_name: 'Working registration', status: 'online', error: '' },
        { ...dashboard({ controller_id: 'failed', coverage: 'unavailable', observed_at: null }), controller_name: 'Failed registration', status: 'error', error: 'Failed to observe cluster' } ] };
    renderWithProviders(<FleetTab fleetLoading={false} fleetError={false} fleet={fleet} refetchFleet={vi.fn()} />);
    expect(screen.getByText(/1 of 2 controllers observed; 1 failed/)).toBeInTheDocument();
    expect(screen.getByText('Failed registration')).toBeInTheDocument();
    expect(screen.getByText('Failed to observe cluster')).toBeInTheDocument();
    expect(screen.getAllByText('25.0%')).toHaveLength(1);
  });
});

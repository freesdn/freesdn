// SPDX-License-Identifier: AGPL-3.0-only
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { act, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { renderWithProviders } from '@/test-utils';
import { hypervisorApi } from '@/lib/api';
import { KioskMode } from '../KioskMode';
import { dashboard } from './dashboardFixture';

vi.mock('@/lib/api', () => ({ hypervisorApi: { getDashboard: vi.fn() } }));
type Response = Awaited<ReturnType<typeof hypervisorApi.getDashboard>>;
const respond = (data = dashboard()) => vi.mocked(hypervisorApi.getDashboard).mockResolvedValue({ data } as Response);
beforeEach(() => { vi.resetAllMocks(); respond(); });

describe('kiosk observations', () => {
  it('shows no healthy zero gauges before the first observation', () => {
    vi.mocked(hypervisorApi.getDashboard).mockImplementation(() => new Promise(() => {}));
    renderWithProviders(<KioskMode controllerId="controller" onExit={vi.fn()} />);
    expect(screen.getByText('Waiting for a dashboard observation')).toBeInTheDocument();
    expect(screen.queryAllByTestId(/kiosk-gauge/)).toHaveLength(0);
  });
  it('uses nodes from the same successful observation', async () => {
    renderWithProviders(<KioskMode controllerId="controller" onExit={vi.fn()} />);
    await screen.findByTestId('kiosk-gauge-cpu');
    expect(screen.getByText('n1')).toBeInTheDocument();
    expect(hypervisorApi.getDashboard).toHaveBeenCalledExactlyOnceWith('controller');
  });
  it('hides previous counters after a refresh failure and withholds raw diagnostics', async () => {
    const { queryClient } = renderWithProviders(<KioskMode controllerId="controller" onExit={vi.fn()} />);
    await screen.findByTestId('kiosk-gauge-cpu');
    vi.mocked(hypervisorApi.getDashboard).mockRejectedValue(new Error('private upstream credentials'));
    await act(() => queryClient.invalidateQueries({ queryKey: ['hypervisor', 'kiosk', 'dashboard', 'controller'] }));
    await waitFor(() => expect(screen.queryAllByTestId(/kiosk-gauge/)).toHaveLength(0));
    expect(screen.queryByText('n1')).not.toBeInTheDocument();
    expect(screen.queryByText(/private upstream/)).not.toBeInTheDocument();
  });
  it('does not display values belonging to another controller', async () => {
    respond(dashboard({ controller_id: 'foreign' }));
    renderWithProviders(<KioskMode controllerId="controller" onExit={vi.fn()} />);
    await screen.findByRole('alert');
    expect(screen.queryAllByTestId(/kiosk-gauge/)).toHaveLength(0);
  });
  it('drops the previous controller immediately while another request is pending', async () => {
    const { rerender } = renderWithProviders(<KioskMode controllerId="controller" onExit={vi.fn()} />);
    await screen.findByTestId('kiosk-gauge-cpu');
    vi.mocked(hypervisorApi.getDashboard).mockImplementation(() => new Promise(() => {}));
    rerender(<KioskMode controllerId="next" onExit={vi.fn()} />);
    expect(screen.queryAllByTestId(/kiosk-gauge/)).toHaveLength(0);
    expect(screen.queryByText('n1')).not.toBeInTheDocument();
  });
  it('does not draw a gauge for missing metrics but preserves observed zero', async () => {
    const data = dashboard({ cpu_usage_percent: null, memory_usage_percent: 0 });
    data.metric_coverage.cpu = { status: 'unavailable', expected_nodes: 1, observed_nodes: 0, reasons: ['missing_statistics'] };
    respond(data);
    renderWithProviders(<KioskMode controllerId="controller" onExit={vi.fn()} />);
    await screen.findByTestId('kiosk-gauge-memory');
    expect(screen.queryByTestId('kiosk-gauge-cpu')).not.toBeInTheDocument();
    expect(screen.getByText('0%')).toBeInTheDocument();
  });
  it('keeps exit available even when disconnected', async () => {
    const onExit = vi.fn();
    vi.mocked(hypervisorApi.getDashboard).mockRejectedValue(new Error('offline'));
    renderWithProviders(<KioskMode controllerId="controller" onExit={onExit} />);
    await userEvent.click(screen.getByRole('button', { name: 'Exit kiosk mode' }));
    expect(onExit).toHaveBeenCalledOnce();
  });
});

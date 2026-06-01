// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import { renderWithProviders } from '@/test-utils/render';
import { FleetActivityPanel } from '../FleetActivityPanel';

// Mock the API module the component imports
vi.mock('@/lib/api/agents', () => ({
  agentFleetApi: {
    runs: vi.fn(),
  },
}));

import { agentFleetApi } from '@/lib/api/agents';

describe('FleetActivityPanel', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders the empty state when there are no runs', async () => {
    (agentFleetApi.runs as any).mockResolvedValue({ data: [] });
    renderWithProviders(<FleetActivityPanel />);

    await waitFor(() => {
      expect(
        screen.getByText(/No scheduled runs yet/i),
      ).toBeInTheDocument();
    });
  });

  it('renders run rows with site + schedule labels', async () => {
    (agentFleetApi.runs as any).mockResolvedValue({
      data: [
        {
          id: 'r1',
          schedule_id: 's1',
          schedule_name: 'nightly-quick',
          agent_id: 'a1',
          agent_name: 'lab-agent',
          site_id: 'site-1',
          site_name: 'Test Lab',
          status: 'completed',
          device_count: 21,
          duration_seconds: 11.0,
          error_message: null,
          started_at: new Date(Date.now() - 60 * 1000).toISOString(),
          completed_at: new Date().toISOString(),
        },
      ],
    });
    renderWithProviders(<FleetActivityPanel />);

    expect(await screen.findByText('Test Lab')).toBeInTheDocument();
    expect(screen.getByText('nightly-quick')).toBeInTheDocument();
    expect(screen.getByText('lab-agent')).toBeInTheDocument();
    expect(screen.getByText('21')).toBeInTheDocument(); // device count
  });

  it('shows the failed icon + error message for failed runs', async () => {
    (agentFleetApi.runs as any).mockResolvedValue({
      data: [
        {
          id: 'r1',
          schedule_id: 's1',
          schedule_name: 'broken',
          agent_id: null,
          agent_name: null,
          site_id: 'site-1',
          site_name: 'Lab',
          status: 'failed',
          device_count: 0,
          duration_seconds: 0.5,
          error_message: 'scapy permission denied',
          started_at: new Date().toISOString(),
          completed_at: null,
        },
      ],
    });
    renderWithProviders(<FleetActivityPanel />);

    await waitFor(() => {
      expect(
        screen.getByText('scapy permission denied'),
      ).toBeInTheDocument();
    });
  });

  it('shows error state when the fetch fails', async () => {
    (agentFleetApi.runs as any).mockRejectedValue(new Error('500'));
    renderWithProviders(<FleetActivityPanel />);
    await waitFor(() => {
      expect(
        screen.getByText(/Could not load fleet activity/i),
      ).toBeInTheDocument();
    });
  });
});

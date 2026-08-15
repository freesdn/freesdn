// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { renderWithProviders } from '@/test-utils/render';
import { RunScanDialog } from '../RunScanDialog';

vi.mock('@/lib/api/agents', () => ({
  agentsApi: {
    runScan: vi.fn(),
    getScanStatus: vi.fn(),
  },
}));

import { agentsApi } from '@/lib/api/agents';

const AGENT_ID = 'agent-uuid-1';
const TASK_ID = 'task-uuid-1';

function baseTask(overrides: Record<string, unknown> = {}) {
  return {
    id: TASK_ID,
    agent_id: AGENT_ID,
    task_type: 'scan_network',
    task_data: { scan_type: 'quick' },
    priority: 3,
    status: 'running',
    progress: 0,
    result: null,
    error_message: null,
    scheduled_at: null,
    started_at: new Date().toISOString(),
    completed_at: null,
    max_retries: 3,
    retry_count: 0,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    ...overrides,
  };
}

describe('RunScanDialog', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders disabled trigger when agent is offline', () => {
    renderWithProviders(
      <RunScanDialog
        agentId={AGENT_ID}
        agentName="laptop_agent"
        agentStatus="offline"
        supportedScanTypes={['quick', 'full']}
      />,
    );
    const trigger = screen.getByRole('button', { name: /Run scan now/i });
    expect(trigger).toBeDisabled();
  });

  it('opens the dialog and shows scan_type options from capabilities', async () => {
    const user = userEvent.setup();
    renderWithProviders(
      <RunScanDialog
        agentId={AGENT_ID}
        agentName="laptop_agent"
        agentStatus="online"
        supportedScanTypes={['quick', 'full', 'voip']}
      />,
    );

    await user.click(screen.getByRole('button', { name: /Run scan now/i }));
    expect(
      await screen.findByText(/Run scan on laptop_agent/i),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/Filtered by this agent's advertised capabilities/i),
    ).toBeInTheDocument();
  });

  it('dispatches a scan and shows the progress card', async () => {
    const user = userEvent.setup();
    (agentsApi.runScan as any).mockResolvedValue({
      data: {
        task_id: TASK_ID,
        agent_id: AGENT_ID,
        scan_type: 'quick',
        status: 'running',
        dispatched_at: new Date().toISOString(),
        message: 'ok',
      },
    });
    (agentsApi.getScanStatus as any).mockResolvedValue({
      data: baseTask({ progress: 35, result: { scanner: 'arp', devices_found: 4 } }),
    });

    renderWithProviders(
      <RunScanDialog
        agentId={AGENT_ID}
        agentName="laptop_agent"
        agentStatus="online"
        supportedScanTypes={['quick']}
      />,
    );

    await user.click(screen.getByRole('button', { name: /Run scan now/i }));
    await user.click(screen.getByRole('button', { name: /Start scan/i }));

    await waitFor(() =>
      expect(agentsApi.runScan).toHaveBeenCalledWith(AGENT_ID, {
        scan_type: 'quick',
        targets: undefined,
        timeout_seconds: 300,
      }),
    );

    // Progress card appears with the live data from getScanStatus
    expect(await screen.findByText(/Scanning…/i)).toBeInTheDocument();
    await waitFor(() => {
      expect(screen.getByText(/Current scanner/i)).toBeInTheDocument();
      expect(screen.getByText('arp')).toBeInTheDocument();
    });
  });

  it('renders success state when task reaches completed', async () => {
    const user = userEvent.setup();
    (agentsApi.runScan as any).mockResolvedValue({
      data: {
        task_id: TASK_ID,
        agent_id: AGENT_ID,
        scan_type: 'quick',
        status: 'running',
        dispatched_at: new Date().toISOString(),
        message: 'ok',
      },
    });
    (agentsApi.getScanStatus as any).mockResolvedValue({
      data: baseTask({
        status: 'completed',
        progress: 100,
        completed_at: new Date().toISOString(),
        result: { devices: [{ ip_address: '10.0.0.1' }], total: 1 },
      }),
    });

    const onComplete = vi.fn();
    renderWithProviders(
      <RunScanDialog
        agentId={AGENT_ID}
        agentName="laptop_agent"
        agentStatus="online"
        supportedScanTypes={['quick']}
        onScanComplete={onComplete}
      />,
    );

    await user.click(screen.getByRole('button', { name: /Run scan now/i }));
    await user.click(screen.getByRole('button', { name: /Start scan/i }));

    expect(await screen.findByText(/Scan complete/i)).toBeInTheDocument();
    await waitFor(() => expect(onComplete).toHaveBeenCalledTimes(1));
    // Run-another button surfaces on terminal state
    expect(screen.getByRole('button', { name: /Run another/i })).toBeInTheDocument();
  });

  it('shows failure detail when task fails', async () => {
    const user = userEvent.setup();
    (agentsApi.runScan as any).mockResolvedValue({
      data: {
        task_id: TASK_ID,
        agent_id: AGENT_ID,
        scan_type: 'quick',
        status: 'running',
        dispatched_at: new Date().toISOString(),
        message: 'ok',
      },
    });
    (agentsApi.getScanStatus as any).mockResolvedValue({
      data: baseTask({
        status: 'failed',
        progress: 25,
        completed_at: new Date().toISOString(),
        error_message: 'scapy not available',
      }),
    });

    renderWithProviders(
      <RunScanDialog
        agentId={AGENT_ID}
        agentName="laptop_agent"
        agentStatus="online"
        supportedScanTypes={['quick']}
      />,
    );

    await user.click(screen.getByRole('button', { name: /Run scan now/i }));
    await user.click(screen.getByRole('button', { name: /Start scan/i }));

    expect(await screen.findByText(/Scan failed/i)).toBeInTheDocument();
    expect(screen.getByText('scapy not available')).toBeInTheDocument();
  });
});

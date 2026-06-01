// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { renderWithProviders } from '@/test-utils/render';
import { AdHocScansPanel } from '../AdHocScansPanel';

vi.mock('@/lib/api/agents', () => ({
  agentsApi: {
    listAdHocScans: vi.fn(),
    cancelTask: vi.fn(),
  },
}));

import { agentsApi } from '@/lib/api/agents';

const AGENT_ID = 'agent-1';

function makeTask(overrides: Record<string, unknown> = {}) {
  return {
    id: `task-${Math.random()}`,
    agent_id: AGENT_ID,
    task_type: 'scan_network',
    task_data: { scan_type: 'quick', interactive: true, targets: [] },
    priority: 3,
    status: 'running',
    progress: 25,
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

describe('AdHocScansPanel', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders empty-state when no interactive tasks exist', async () => {
    (agentsApi.listAdHocScans as any).mockResolvedValue({ data: [] });
    renderWithProviders(<AdHocScansPanel agentId={AGENT_ID} />);
    expect(
      await screen.findByText(/No ad-hoc scans yet/i),
    ).toBeInTheDocument();
  });

  it('filters out scheduled tasks (interactive=false / unset)', async () => {
    (agentsApi.listAdHocScans as any).mockResolvedValue({
      data: [
        makeTask({
          id: 'scheduled-1',
          task_data: { scan_type: 'quick' }, // no interactive flag
        }),
      ],
    });
    renderWithProviders(<AdHocScansPanel agentId={AGENT_ID} />);
    expect(
      await screen.findByText(/No ad-hoc scans yet/i),
    ).toBeInTheDocument();
  });

  it('renders running task with progress bar and Cancel button', async () => {
    (agentsApi.listAdHocScans as any).mockResolvedValue({
      data: [
        makeTask({
          id: 'task-running',
          status: 'running',
          progress: 60,
          task_data: {
            scan_type: 'quick',
            interactive: true,
            targets: ['10.0.0.0/24'],
          },
        }),
      ],
    });
    renderWithProviders(<AdHocScansPanel agentId={AGENT_ID} />);

    expect(await screen.findByText('quick')).toBeInTheDocument();
    expect(screen.getByText('10.0.0.0/24')).toBeInTheDocument();
    expect(
      screen.getByRole('button', { name: /Cancel/i }),
    ).toBeInTheDocument();
  });

  it('completed tasks show total devices, no cancel button', async () => {
    (agentsApi.listAdHocScans as any).mockResolvedValue({
      data: [
        makeTask({
          id: 'task-done',
          status: 'completed',
          progress: 100,
          completed_at: new Date().toISOString(),
          result: { total: 12, devices: [] },
          task_data: { scan_type: 'full', interactive: true, targets: [] },
        }),
      ],
    });
    renderWithProviders(<AdHocScansPanel agentId={AGENT_ID} />);

    expect(await screen.findByText('full')).toBeInTheDocument();
    expect(screen.getByText('12')).toBeInTheDocument();
    expect(
      screen.queryByRole('button', { name: /Cancel/i }),
    ).not.toBeInTheDocument();
  });

  it('Cancel button calls cancelTask API', async () => {
    const user = userEvent.setup();
    (agentsApi.listAdHocScans as any).mockResolvedValue({
      data: [
        makeTask({
          id: 'task-cancel-me',
          status: 'running',
          progress: 10,
          task_data: { scan_type: 'quick', interactive: true, targets: [] },
        }),
      ],
    });
    (agentsApi.cancelTask as any).mockResolvedValue({ data: {} });

    renderWithProviders(<AdHocScansPanel agentId={AGENT_ID} />);

    const btn = await screen.findByRole('button', { name: /Cancel/i });
    await user.click(btn);

    await waitFor(() =>
      expect(agentsApi.cancelTask).toHaveBeenCalledWith('task-cancel-me'),
    );
  });
});

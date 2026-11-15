// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * A failed enable/disable or delete says what failed and the server's reason.
 * Both mutations had no onError: outside the app's global safety net nothing
 * was shown, and inside it only "Something went wrong".
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { AxiosError, AxiosHeaders, type AxiosResponse } from 'axios';
import { renderWithProviders } from '@/test-utils/render';
import { AgentSchedulesPanel } from '../AgentSchedulesPanel';

vi.mock('@/lib/api/agents', () => ({
  agentSchedulesApi: {
    list: vi.fn(),
    create: vi.fn(),
    update: vi.fn(),
    remove: vi.fn(),
    listRuns: vi.fn(),
  },
}));

import { agentSchedulesApi } from '@/lib/api/agents';

const schedule = {
  id: 'sched-1', organization_id: 'org-1', site_id: 'site-1', agent_id: null,
  name: 'nightly', scan_type: 'quick', cron: '0 2 * * *', targets: ['192.168.1.0/24'],
  interface: null, enabled: true, last_fired_at: null,
  created_at: '2026-11-01T00:00:00Z', updated_at: '2026-11-01T00:00:00Z',
};

function apiError(status: number, message: string): AxiosError {
  const response = {
    status,
    statusText: '',
    headers: {},
    config: { headers: new AxiosHeaders() },
    data: { error: { code: status, message, request_id: 'r1' } },
  } as AxiosResponse;
  return new AxiosError(`Request failed with status code ${status}`, 'ERR_BAD_RESPONSE', response.config, null, response);
}

describe('AgentSchedulesPanel failures', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(agentSchedulesApi.list).mockResolvedValue({ data: [schedule] } as never);
  });

  it('says why disabling a schedule failed', async () => {
    vi.mocked(agentSchedulesApi.update).mockRejectedValue(apiError(409, 'The schedule is running; try again when it finishes'));
    const user = userEvent.setup();
    renderWithProviders(<AgentSchedulesPanel siteId="site-1" />);
    await screen.findByText('nightly');
    await user.click(screen.getByRole('button', { name: 'Disable' }));
    expect(await screen.findByText('Could not disable nightly')).toBeInTheDocument();
    expect(screen.getByText('The schedule is running; try again when it finishes')).toBeInTheDocument();
  });

  it('says why deleting a schedule failed', async () => {
    vi.mocked(agentSchedulesApi.remove).mockRejectedValue(apiError(403, 'You do not have agents.manage on this site'));
    const user = userEvent.setup();
    renderWithProviders(<AgentSchedulesPanel siteId="site-1" />);
    await screen.findByText('nightly');
    await user.click(screen.getByRole('button', { name: 'Delete schedule' }));
    const dialog = await screen.findByRole('alertdialog');
    await user.click(within(dialog).getByRole('button', { name: 'Delete schedule' }));
    expect(await screen.findByText('Could not delete the schedule')).toBeInTheDocument();
    expect(screen.getByText('You do not have agents.manage on this site')).toBeInTheDocument();
    expect(screen.queryByText('Schedule deleted')).not.toBeInTheDocument();
  });
});

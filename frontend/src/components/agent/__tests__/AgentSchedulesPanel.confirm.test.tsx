// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
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

describe('AgentSchedulesPanel delete confirmation', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(agentSchedulesApi.list).mockResolvedValue({ data: [schedule] } as never);
    vi.mocked(agentSchedulesApi.remove).mockResolvedValue({ data: {} } as never);
  });

  it('removes the schedule only after the operator confirms', async () => {
    const user = userEvent.setup();
    renderWithProviders(<AgentSchedulesPanel siteId="site-1" />);
    await screen.findByText('nightly');

    await user.click(screen.getByRole('button', { name: 'Delete schedule' }));
    let dialog = await screen.findByRole('alertdialog');
    expect(within(dialog).getByText('Delete schedule "nightly"?')).toBeInTheDocument();
    await user.click(within(dialog).getByRole('button', { name: 'Cancel' }));
    await waitFor(() => expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument());
    expect(agentSchedulesApi.remove).not.toHaveBeenCalled();

    await user.click(screen.getByRole('button', { name: 'Delete schedule' }));
    dialog = await screen.findByRole('alertdialog');
    await user.click(within(dialog).getByRole('button', { name: 'Delete schedule' }));
    await waitFor(() => expect(agentSchedulesApi.remove).toHaveBeenCalledWith('sched-1'));
  });
});

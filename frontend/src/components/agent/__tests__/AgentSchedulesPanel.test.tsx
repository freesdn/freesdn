// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
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

const SITE_ID = 'site-1';

describe('AgentSchedulesPanel', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders "select a site" when siteId is missing', () => {
    renderWithProviders(<AgentSchedulesPanel siteId={undefined} />);
    expect(
      screen.getByText(/Select a site to manage scan schedules/i),
    ).toBeInTheDocument();
  });

  it('renders the empty state when site has no schedules', async () => {
    (agentSchedulesApi.list as any).mockResolvedValue({ data: [] });
    renderWithProviders(<AgentSchedulesPanel siteId={SITE_ID} />);

    expect(
      await screen.findByText(/No scheduled scans yet/i),
    ).toBeInTheDocument();
  });

  it('renders rows for existing schedules', async () => {
    (agentSchedulesApi.list as any).mockResolvedValue({
      data: [
        {
          id: 'sched-1',
          organization_id: 'org-1',
          site_id: SITE_ID,
          agent_id: null,
          name: 'nightly',
          scan_type: 'quick',
          cron: '0 2 * * *',
          targets: ['192.168.1.0/24'],
          interface: null,
          enabled: true,
          last_fired_at: null,
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString(),
        },
      ],
    });
    renderWithProviders(<AgentSchedulesPanel siteId={SITE_ID} />);

    expect(await screen.findByText('nightly')).toBeInTheDocument();
    expect(screen.getByText('0 2 * * *')).toBeInTheDocument();
    expect(screen.getByText('192.168.1.0/24')).toBeInTheDocument();
  });

  it('opens the new-schedule dialog and creates a schedule', async () => {
    const user = userEvent.setup();
    (agentSchedulesApi.list as any).mockResolvedValue({ data: [] });
    (agentSchedulesApi.create as any).mockResolvedValue({
      data: {
        id: 'new',
        organization_id: 'org-1',
        site_id: SITE_ID,
        agent_id: null,
        name: 'lab',
        scan_type: 'quick',
        cron: '0 */4 * * *',
        targets: ['10.0.0.0/24'],
        interface: null,
        enabled: true,
        last_fired_at: null,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      },
    });

    renderWithProviders(<AgentSchedulesPanel siteId={SITE_ID} />);
    await user.click(await screen.findByRole('button', { name: /new schedule/i }));

    // Dialog opened, fill name + targets, then submit
    const nameInput = await screen.findByPlaceholderText('e.g. nightly-quick');
    await user.type(nameInput, 'lab');

    const targetsInput = screen.getByPlaceholderText('192.168.1.0/24');
    await user.type(targetsInput, '10.0.0.0/24');

    await user.click(screen.getByRole('button', { name: 'Create' }));

    await waitFor(() => {
      expect(agentSchedulesApi.create).toHaveBeenCalledWith(
        SITE_ID,
        expect.objectContaining({
          name: 'lab',
          scan_type: 'quick',
          targets: ['10.0.0.0/24'],
        }),
      );
    });
  });
});

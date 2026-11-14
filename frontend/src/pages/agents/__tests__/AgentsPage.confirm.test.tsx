// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Removing agents asks through the in-app confirmation dialog. It names the
 * agents and says what the removal really does (the key stops working, the
 * heartbeat history and the site's WireGuard configuration go, discoveries
 * stay). A Cancel sends nothing; a confirm sends one delete per agent.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import AgentsPage from '../AgentsPage';
import { agentsApi } from '@/lib/api/agents';
import { useSiteStore } from '@/stores/siteStore';
import { renderWithProviders } from '@/test-utils';

vi.mock('@/lib/api/agents', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api/agents')>('@/lib/api/agents');
  return {
    ...actual,
    agentsApi: {
      ...actual.agentsApi,
      list: vi.fn(),
      stats: vi.fn(),
      approve: vi.fn(),
      update: vi.fn(),
      disconnect: vi.fn(),
      register: vi.fn(),
    },
    agentFleetApi: { ...actual.agentFleetApi, overview: vi.fn() },
  };
});

vi.mock('@/lib/api/sites', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api/sites')>('@/lib/api/sites');
  return { ...actual, sitesApiV2: { ...actual.sitesApiV2, list: vi.fn() } };
});

vi.mock('@/components/agent/FleetActivityPanel', () => ({ FleetActivityPanel: () => null }));

const agents = [
  { id: 'a-1', name: 'branch-east', agent_type: 'site', status: 'online', is_approved: true, is_enabled: true },
  { id: 'a-2', name: 'branch-west', agent_type: 'site', status: 'offline', is_approved: true, is_enabled: true },
  { id: 'a-3', name: 'lab-scanner', agent_type: 'scanner', status: 'offline', is_approved: true, is_enabled: true },
];

beforeEach(async () => {
  vi.clearAllMocks();
  useSiteStore.setState({ selectedSiteId: null });
  const { agentFleetApi } = await import('@/lib/api/agents');
  const { sitesApiV2 } = await import('@/lib/api/sites');
  vi.mocked(agentsApi.list).mockResolvedValue({ data: { items: agents, total: agents.length } } as never);
  vi.mocked(agentsApi.stats).mockResolvedValue({ data: { total: 3, online: 1, offline: 2, pending_approval: 0 } } as never);
  vi.mocked(agentsApi.disconnect).mockResolvedValue({ data: { message: 'Agent deleted successfully' } } as never);
  vi.mocked(agentFleetApi.overview).mockResolvedValue({ data: {} } as never);
  vi.mocked(sitesApiV2.list).mockResolvedValue({ data: { items: [] } } as never);
});

async function selectFirstTwo(user: ReturnType<typeof userEvent.setup>) {
  // The first checkbox is the header's select-all. Query again after each
  // click: selecting a row re-renders the table.
  const rowBoxes = () => screen.getAllByRole('checkbox').slice(1);
  await user.click(rowBoxes()[0]);
  await user.click(rowBoxes()[1]);
  await waitFor(() => expect(rowBoxes().filter((c) => (c as HTMLInputElement).checked)).toHaveLength(2));
}

describe('AgentsPage removal confirmation', () => {
  it('bulk delete names the agents and the consequence, and Cancel deletes nothing', async () => {
    const user = userEvent.setup();
    renderWithProviders(<AgentsPage />, { initialPath: '/agents' });
    expect(await screen.findByText('branch-east')).toBeInTheDocument();
    await selectFirstTwo(user);

    await user.click(screen.getByRole('button', { name: 'Delete' }));

    const dialog = await screen.findByRole('alertdialog');
    expect(within(dialog).getByRole('heading', { name: 'Delete 2 agents?' })).toBeInTheDocument();
    expect(within(dialog).getByText(/key stops working/)).toBeInTheDocument();
    expect(within(dialog).getByText(/WireGuard VPN configuration/)).toBeInTheDocument();
    expect(within(dialog).getByText('This affects 2 items.')).toBeInTheDocument();
    const listed = within(within(dialog).getByRole('list', { name: 'Affected items' })).getAllByRole('listitem');
    expect(listed.map((li) => li.textContent)).toEqual(['branch-east', 'branch-west']);

    await user.click(within(dialog).getByRole('button', { name: 'Cancel' }));
    await waitFor(() => expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument());
    expect(agentsApi.disconnect).not.toHaveBeenCalled();
  });

  it('bulk delete sends one delete per selected agent only after the operator confirms', async () => {
    const user = userEvent.setup();
    renderWithProviders(<AgentsPage />, { initialPath: '/agents' });
    expect(await screen.findByText('branch-east')).toBeInTheDocument();
    await selectFirstTwo(user);

    await user.click(screen.getByRole('button', { name: 'Delete' }));
    const dialog = await screen.findByRole('alertdialog');
    expect(agentsApi.disconnect).not.toHaveBeenCalled();

    await user.click(within(dialog).getByRole('button', { name: 'Delete agents' }));

    await waitFor(() => expect(agentsApi.disconnect).toHaveBeenCalledTimes(2));
    expect(vi.mocked(agentsApi.disconnect).mock.calls.map((c) => c[0]).sort()).toEqual(['a-1', 'a-2']);
  });

  it('single remove from the row menu sends nothing on Cancel and the delete on confirm', async () => {
    const user = userEvent.setup();
    renderWithProviders(<AgentsPage />, { initialPath: '/agents' });
    expect(await screen.findByText('lab-scanner')).toBeInTheDocument();

    const openMenu = async () => {
      await user.click(screen.getByRole('button', { name: 'Actions for lab-scanner' }));
      await user.click(await screen.findByRole('menuitem', { name: 'Disconnect' }));
      return screen.findByRole('alertdialog');
    };

    let dialog = await openMenu();
    expect(within(dialog).getByRole('heading', { name: 'Remove agent "lab-scanner"?' })).toBeInTheDocument();
    expect(within(dialog).getByText(/Discoveries and runs are kept/)).toBeInTheDocument();
    await user.click(within(dialog).getByRole('button', { name: 'Cancel' }));
    await waitFor(() => expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument());
    expect(agentsApi.disconnect).not.toHaveBeenCalled();

    dialog = await openMenu();
    await user.click(within(dialog).getByRole('button', { name: 'Remove agent' }));
    await waitFor(() => expect(agentsApi.disconnect).toHaveBeenCalledTimes(1));
    expect(vi.mocked(agentsApi.disconnect).mock.calls[0][0]).toBe('a-3');
  });
});

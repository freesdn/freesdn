// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Bulk VLAN delete asks through the in-app confirmation dialog, names the
 * VLANs it is about to delete and says the delete reaches the controller. A
 * Cancel sends nothing; a confirm sends one delete per selected VLAN.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import VlansPage from '../VlansPage';
import { networkApi } from '@/lib/api';
import { useSiteStore } from '@/stores/siteStore';
import { renderWithProviders } from '@/test-utils';

vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api');
  return {
    ...actual,
    networkApi: {
      ...actual.networkApi,
      vlans: {
        list: vi.fn(),
        get: vi.fn(),
        create: vi.fn(),
        update: vi.fn(),
        delete: vi.fn(),
      },
      getVlanAlignment: vi.fn(),
      distributeVlan: vi.fn(),
    },
  };
});

const list = vi.mocked(networkApi.vlans.list);
const remove = vi.mocked(networkApi.vlans.delete);

const vlans = [
  { id: 'v-10', vlan_id: 10, name: 'mgmt', dhcp_enabled: false },
  { id: 'v-20', vlan_id: 20, name: 'voice', dhcp_enabled: true },
  { id: 'v-30', vlan_id: 30, name: 'cameras', dhcp_enabled: false },
];

beforeEach(() => {
  vi.clearAllMocks();
  useSiteStore.setState({ selectedSiteId: null });
  list.mockResolvedValue({ data: { items: vlans, total: vlans.length } } as never);
  remove.mockResolvedValue({ data: { success: true } } as never);
});

async function selectFirstTwo(user: ReturnType<typeof userEvent.setup>) {
  expect(await screen.findByText('mgmt')).toBeInTheDocument();
  // The first checkbox is the header's select-all. Query again after each
  // click: selecting a row re-renders the table.
  const rowBoxes = () => screen.getAllByRole('checkbox').slice(1);
  await user.click(rowBoxes()[0]);
  await user.click(rowBoxes()[1]);
  await waitFor(() => expect(rowBoxes().filter((c) => (c as HTMLInputElement).checked)).toHaveLength(2));
}

describe('VlansPage bulk delete confirmation', () => {
  it('names the selected VLANs and the controller consequence, and Cancel deletes nothing', async () => {
    const user = userEvent.setup();
    renderWithProviders(<VlansPage />, { initialPath: '/vlans' });
    await selectFirstTwo(user);

    await user.click(screen.getByRole('button', { name: 'Delete' }));

    const dialog = await screen.findByRole('alertdialog');
    expect(within(dialog).getByRole('heading', { name: 'Delete 2 VLANs?' })).toBeInTheDocument();
    expect(within(dialog).getByText(/deleted from its controller right away, without staging/)).toBeInTheDocument();
    expect(within(dialog).getByText('This affects 2 items.')).toBeInTheDocument();
    const listed = within(within(dialog).getByRole('list', { name: 'Affected items' })).getAllByRole('listitem');
    expect(listed.map((li) => li.textContent)).toEqual(['10 mgmt', '20 voice']);

    await user.click(within(dialog).getByRole('button', { name: 'Cancel' }));
    await waitFor(() => expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument());
    expect(remove).not.toHaveBeenCalled();
  });

  it('sends one delete per selected VLAN only after the operator confirms', async () => {
    const user = userEvent.setup();
    renderWithProviders(<VlansPage />, { initialPath: '/vlans' });
    await selectFirstTwo(user);

    await user.click(screen.getByRole('button', { name: 'Delete' }));
    const dialog = await screen.findByRole('alertdialog');
    expect(remove).not.toHaveBeenCalled();

    await user.click(within(dialog).getByRole('button', { name: 'Delete VLANs' }));

    await waitFor(() => expect(remove).toHaveBeenCalledTimes(2));
    expect(remove.mock.calls.map((c) => c[0]).sort()).toEqual(['v-10', 'v-20']);
  });
});

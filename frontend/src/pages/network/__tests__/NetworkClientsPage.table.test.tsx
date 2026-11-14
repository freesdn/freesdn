// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Clients page: bulk Block asked nothing and blocked every selected client on
 * its controller at once; it now asks through the in-app dialog with the
 * count and the client names. A failed load used to replace the whole page
 * with the bare transport text ("Request failed with status code 502"); the
 * table now shows the server's own reason with a retry, and the counters are
 * not shown claiming zero clients.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { AxiosError, AxiosHeaders, type AxiosResponse } from 'axios';

import NetworkClientsPage from '../NetworkClientsPage';
import { networkApi } from '@/lib/api';
import { useSiteStore } from '@/stores/siteStore';
import { renderWithProviders } from '@/test-utils';

vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api');
  return {
    ...actual,
    networkApi: {
      ...actual.networkApi,
      clients: { list: vi.fn(), block: vi.fn(), unblock: vi.fn() },
    },
  };
});

const list = vi.mocked(networkApi.clients.list);
const block = vi.mocked(networkApi.clients.block);

const clients = [
  { id: 'c1', mac_address: 'aa:bb:cc:00:00:01', display_name: 'Lobby kiosk', hostname: null, ip_address: '10.0.0.11', status: 'online', connection_type: 'wired', rx_bytes: 10, tx_bytes: 20, last_seen: '2026-11-13T00:00:00Z' },
  { id: 'c2', mac_address: 'aa:bb:cc:00:00:02', display_name: 'Front desk', hostname: null, ip_address: '10.0.0.12', status: 'online', connection_type: 'wireless', rx_bytes: 10, tx_bytes: 20, last_seen: '2026-11-13T00:00:00Z' },
  { id: 'c3', mac_address: 'aa:bb:cc:00:00:03', display_name: 'Printer', hostname: null, ip_address: '10.0.0.13', status: 'offline', connection_type: 'wired', rx_bytes: 0, tx_bytes: 0, last_seen: '2026-11-13T00:00:00Z' },
];

beforeEach(() => {
  vi.clearAllMocks();
  useSiteStore.setState({ selectedSiteId: null });
  list.mockResolvedValue({ data: { items: clients, total: clients.length } } as never);
  block.mockResolvedValue({ data: { success: true } } as never);
});

async function selectFirstTwo(user: ReturnType<typeof userEvent.setup>) {
  expect(await screen.findByText('Lobby kiosk')).toBeInTheDocument();
  const rowBoxes = () => screen.getAllByRole('checkbox').slice(1);
  await user.click(rowBoxes()[0]);
  await user.click(rowBoxes()[1]);
  await waitFor(() => expect(rowBoxes().filter((c) => (c as HTMLInputElement).checked)).toHaveLength(2));
}

describe('Clients page', () => {
  it('asks before a bulk block, names the clients, and blocks nothing on Cancel', async () => {
    const user = userEvent.setup();
    renderWithProviders(<NetworkClientsPage />);
    await selectFirstTwo(user);
    await user.click(screen.getByRole('button', { name: /^Block$/ }));

    let dialog = await screen.findByRole('alertdialog');
    expect(within(dialog).getByText('Block 2 clients?')).toBeInTheDocument();
    expect(within(dialog).getByText(/disconnected by its controller right away/)).toBeInTheDocument();
    expect(within(dialog).getByText('Lobby kiosk')).toBeInTheDocument();
    expect(within(dialog).getByText('Front desk')).toBeInTheDocument();
    await user.click(within(dialog).getByRole('button', { name: 'Cancel' }));
    await waitFor(() => expect(screen.queryByRole('alertdialog')).toBeNull());
    expect(block).not.toHaveBeenCalled();

    await user.click(screen.getByRole('button', { name: /^Block$/ }));
    dialog = await screen.findByRole('alertdialog');
    await user.click(within(dialog).getByRole('button', { name: 'Block clients' }));
    await waitFor(() => expect(block).toHaveBeenCalledTimes(2));
    expect(block.mock.calls.map((c) => c[0]).sort()).toEqual(['c1', 'c2']);
  });

  it("shows the server's reason for a failed load, with a retry, and no zero counters", async () => {
    const response = {
      status: 502,
      statusText: 'Bad Gateway',
      headers: {},
      config: { headers: new AxiosHeaders() },
      data: { error: { code: 502, message: 'The controller did not answer', request_id: 'r1' } },
    } as AxiosResponse;
    list.mockRejectedValue(new AxiosError('Request failed with status code 502', 'ERR_BAD_RESPONSE', response.config, null, response));
    renderWithProviders(<NetworkClientsPage />);
    expect(await screen.findByText('The controller did not answer')).toBeInTheDocument();
    expect(screen.queryByText(/Request failed with status code/)).toBeNull();
    expect(screen.queryByText('Total Clients')).toBeNull();
    list.mockResolvedValue({ data: { items: clients, total: clients.length } } as never);
    await userEvent.setup().click(screen.getByRole('button', { name: /try again|retry/i }));
    expect(await screen.findByText('Lobby kiosk')).toBeInTheDocument();
  });
});

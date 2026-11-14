// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * The access-point list is the shared DataTable: one compact, sortable row
 * per access point with figures aligned right, a named actions menu, the
 * server's own reason (not a fixed sentence) when the list fails to load,
 * and the row opens the access point.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { AxiosError, AxiosHeaders, type AxiosResponse } from 'axios';
import AccessPointsPage from '../AccessPointsPage';
import { renderWithProviders } from '@/test-utils';

const api = vi.hoisted(() => ({ list: vi.fn(), detail: vi.fn() }));

vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api');
  return {
    ...actual,
    accessPointsApi: {
      ...actual.accessPointsApi,
      listAccessPoints: api.list,
      getAccessPoint: api.detail,
    },
  };
});

const ap = (id: string, name: string, clients: number, over: Record<string, unknown> = {}) => ({
  id, name, model: 'EAP670', vendor: 'omada', mac_address: `aa:bb:cc:00:00:0${id}`, ip_address: `10.0.0.${id}`,
  site_id: 's1', site_name: 'HQ', controller_id: null, status: 'online', firmware_version: '1.0', clients,
  uptime: 7200, cpu_usage: 1, memory_usage: 2, mesh_enabled: false, led_enabled: true, update_available: false,
  radios: [{ band: '5GHz', channel: 36, channel_width: 80, tx_power: 20, clients }],
  ...over,
});

beforeEach(() => {
  api.list.mockReset().mockResolvedValue({ data: { items: [ap('1', 'Lobby', 12), ap('2', 'Warehouse', 3, { status: 'offline' }), ap('3', 'Dock', 0, { status: 'degraded' })] } });
  api.detail.mockReset().mockImplementation(async () => ({ data: ap('1', 'Lobby', 12) }));
});

const render = () => renderWithProviders(<AccessPointsPage />, { initialPath: '/access-points', routePath: '/access-points/:deviceId?/:tab?' });

describe('AccessPointsPage list', () => {
  it('lists access points as compact rows with clients aligned right', async () => {
    render();
    const table = await screen.findByRole('table');
    expect(within(table).getByText('Lobby')).toBeInTheDocument();
    expect(within(table).getByRole('columnheader', { name: /Clients/ }).className).toMatch(/text-right/);
    const cell = within(table).getByText('12').closest('td') as HTMLElement;
    expect(cell.className).toMatch(/text-right/);
    expect(cell.className).toMatch(/py-2/);
    expect(within(table).getByText('Offline')).toBeInTheDocument();
    // Status reads as a status: green when online, translated otherwise.
    expect(within(table).getByText('Online').className).toMatch(/green/);
    expect(within(table).getByRole('button', { name: 'Actions for Warehouse' })).toBeInTheDocument();
    expect(within(table).getByText('Degraded')).toBeInTheDocument();
  });

  it('sorts by clients', async () => {
    render();
    const table = await screen.findByRole('table');
    const user = userEvent.setup();
    await user.click(within(table).getByRole('button', { name: /Clients/ }));
    const rows = within(table).getAllByRole('row').slice(1);
    expect(rows[0]).toHaveTextContent('Dock');
    expect(rows[1]).toHaveTextContent('Warehouse');
    expect(rows[2]).toHaveTextContent('Lobby');
  });

  it("shows the server's reason and a retry when the list fails", async () => {
    const response = {
      status: 503,
      statusText: '',
      headers: {},
      config: { headers: new AxiosHeaders() },
      data: { error: { code: 503, message: 'Omada controller did not answer', request_id: 'r1' } },
    } as AxiosResponse;
    api.list.mockRejectedValueOnce(new AxiosError('Request failed with status code 503', 'ERR_BAD_RESPONSE', response.config, null, response));
    render();
    expect(await screen.findByText('Omada controller did not answer')).toBeInTheDocument();
    await userEvent.setup().click(screen.getByRole('button', { name: /try again|retry/i }));
    expect(await screen.findByText('Lobby')).toBeInTheDocument();
  });

  it('opens an access point from its row', async () => {
    render();
    const table = await screen.findByRole('table');
    await userEvent.setup().click(within(table).getByText('Lobby'));
    expect(await screen.findByRole('button', { name: /Back/i })).toBeInTheDocument();
  });
});

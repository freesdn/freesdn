// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * The switch Clients tab opts in to the shared table's compact density,
 * right-aligned numbers, row labels for the selection boxes and the load
 * error state. A failed load used to be a separate card with fixed text
 * ("Failed to load clients"); the table now shows the server's reason and a
 * retry, and the zero counters and filter chips are not shown.
 */
import { describe, expect, it, vi } from 'vitest';
import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { AxiosError, AxiosHeaders, type AxiosResponse } from 'axios';

import { SwitchClientsTab } from '../SwitchClientsTab';
import { renderWithProviders } from '@/test-utils';
import type { SwitchClient } from '@/lib/api';

const clients = [
  { mac_address: 'aa:bb:cc:00:00:01', name: 'Desk phone', connection_type: 'wired', vlan_id: 20, switch_port: 4, download: 1000, upload: 2000, uptime: 3600 },
] as unknown as SwitchClient[];

describe('SwitchClientsTab', () => {
  it('renders a compact table with numbers aligned right', async () => {
    renderWithProviders(<SwitchClientsTab clients={clients} isLoading={false} />);
    const table = await screen.findByRole('table');
    const vlanHeader = within(table).getByRole('columnheader', { name: /VLAN/ });
    expect(vlanHeader.className).toMatch(/text-right/);
    const cell = within(table).getByText('20').closest('td') as HTMLElement;
    expect(cell.className).toMatch(/text-right/);
    expect(cell.className).toMatch(/py-2/);
  });

  it("shows the server's reason and a retry instead of zero counters", async () => {
    const response = {
      status: 503,
      statusText: 'Service Unavailable',
      headers: {},
      config: { headers: new AxiosHeaders() },
      data: { error: { code: 503, message: 'Switch is not reachable', request_id: 'r1' } },
    } as AxiosResponse;
    const error = new AxiosError('Request failed with status code 503', 'ERR_BAD_RESPONSE', response.config, null, response);
    const onRetry = vi.fn();
    renderWithProviders(<SwitchClientsTab clients={[]} isLoading={false} error={error} onRetry={onRetry} />);
    expect(await screen.findByText('Switch is not reachable')).toBeInTheDocument();
    expect(screen.queryByText('Total Clients')).toBeNull();
    await userEvent.setup().click(screen.getByRole('button', { name: /try again|retry/i }));
    expect(onRetry).toHaveBeenCalledTimes(1);
  });
});

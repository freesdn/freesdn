// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * The switch port table is the shared DataTable: compact rows, numbers
 * aligned right, every port reachable (the old virtualised table drew only
 * the first rows of a 48-port switch and had no spacer to scroll the rest
 * into view), selection boxes named after the port, the server's reason with
 * a retry when the ports fail to load, and the reason a disabled control is
 * disabled.
 */
import { describe, expect, it, vi } from 'vitest';
import { fireEvent, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { AxiosError, AxiosHeaders, type AxiosResponse } from 'axios';

import { PortsTab, type PortsTabPort, type PortsTabProps } from '../PortsTab';
import { renderWithProviders } from '@/test-utils';

const port = (index: number, over: Partial<PortsTabPort> = {}): PortsTabPort => ({
  id: `p${index}`,
  port_index: index,
  port_name: `Port ${index}`,
  port_type: 'rj45',
  enabled: true,
  link_status: 'up',
  link_speed: 1000,
  vlan_mode: 'access',
  native_vlan: 10,
  tagged_vlans: [],
  poe_enabled: false,
  tx_bytes: 0,
  rx_bytes: 0,
  tx_packets: 0,
  rx_packets: 0,
  tx_errors: 0,
  rx_errors: 0,
  tx_utilization: 0,
  rx_utilization: 0,
  ...over,
});

const mutation = { isPending: false, mutate: vi.fn() };

function renderTab(props: Partial<PortsTabProps> = {}) {
  return renderWithProviders(
    <PortsTab
      ports={[port(1), port(2, { native_vlan: 4094 })]}
      selectedSwitchId="sw-1"
      showPortControls
      showPoeControls
      portDisabledReason={undefined}
      portBounceMutation={mutation}
      poeCycleMutation={mutation}
      portToggleMutation={mutation}
      poeToggleMutation={mutation}
      onPortEdit={vi.fn()}
      onApplyProfile={vi.fn()}
      {...props}
    />,
  );
}

describe('PortsTab table', () => {
  it('renders compact rows with VLAN and speed aligned right', () => {
    renderTab();
    const table = screen.getByRole('table');
    expect(within(table).getByRole('columnheader', { name: /VLAN/ }).className).toMatch(/text-right/);
    const cell = within(table).getByText('4094').closest('td') as HTMLElement;
    expect(cell.className).toMatch(/text-right/);
    expect(cell.className).toMatch(/py-2/);
  });

  it('keeps sent and received traffic in one column, and long names on one line', () => {
    renderTab({ ports: [port(1, { port_name: 'Reception Phone 101 (desk)', tx_bytes: 2048, rx_bytes: 4096 })] });
    const table = screen.getByRole('table');
    expect(within(table).getByRole('columnheader', { name: /Traffic/ })).toBeInTheDocument();
    expect(within(table).queryByRole('columnheader', { name: /TX Sum/ })).toBeNull();
    const cell = within(table).getByText(/↑/).closest('td') as HTMLElement;
    expect(cell).toHaveTextContent(/↓/);
    const name = within(table).getByText('Reception Phone 101 (desk)');
    expect(name.className).toMatch(/\btruncate\b/);
    expect(name).toHaveAttribute('title', 'Reception Phone 101 (desk)');
  });

  it('shows every port of a 48-port switch', () => {
    renderTab({ ports: Array.from({ length: 48 }, (_, i) => port(i + 1)) });
    const table = screen.getByRole('table');
    expect(within(table).getByText('Port 48')).toBeInTheDocument();
    expect(within(table).getAllByRole('row')).toHaveLength(49);
  });

  it('names each selection box after its port and offers the profile for the selection', async () => {
    const onApplyProfile = vi.fn();
    renderTab({ onApplyProfile });
    await userEvent.setup().click(screen.getByRole('checkbox', { name: 'Select Port 2' }));
    fireEvent.click(screen.getByRole('button', { name: /Apply Profile \(1\)/ }));
    expect(onApplyProfile).toHaveBeenCalledWith(['p2']);
  });

  it("shows the server's reason and a retry when the ports fail to load", async () => {
    const response = {
      status: 502,
      statusText: 'Bad Gateway',
      headers: {},
      config: { headers: new AxiosHeaders() },
      data: { error: { code: 502, message: 'Switch did not answer', request_id: 'r1' } },
    } as AxiosResponse;
    const error = new AxiosError('Request failed with status code 502', 'ERR_BAD_RESPONSE', response.config, null, response);
    const onRetry = vi.fn();
    renderTab({ ports: [], error, onRetry });
    expect(await screen.findByText('Switch did not answer')).toBeInTheDocument();
    expect(screen.queryByText('Request failed with status code 502')).toBeNull();
    await userEvent.setup().click(screen.getByRole('button', { name: /try again|retry/i }));
    expect(onRetry).toHaveBeenCalledTimes(1);
  });

  it('gives the disabled control its reason', async () => {
    renderTab({ showPortControls: false, portDisabledReason: 'This switch is read-only' });
    const buttons = screen.getAllByRole('button', { name: 'This switch is read-only' });
    expect(buttons[0]).toBeDisabled();
    const wrapper = buttons[0].parentElement as HTMLElement;
    expect(wrapper).toHaveAttribute('tabindex', '0');
    fireEvent.focus(wrapper);
    expect((await screen.findAllByText('This switch is read-only')).length).toBeGreaterThan(0);
  });
});

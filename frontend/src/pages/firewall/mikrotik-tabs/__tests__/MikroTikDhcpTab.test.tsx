// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * MikroTikDhcpTab, interaction test.
 *
 * Verifies "Make static" now uses the shadcn AlertDialog,
 * NOT `window.confirm`. We render the tab with a single dynamic lease,
 * click the per-row Make-static button, confirm the dialog opens, and
 * verify confirming inside the dialog calls `makeLeaseStatic` with the
 * expected lease shape.
 */
import { describe, it, expect, beforeEach, vi, type Mock } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MikroTikDhcpTab } from '../MikroTikDhcpTab';
import { mikrotikApi } from '@/lib/api';
import { renderWithProviders } from '@/test-utils';

vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api');
  return {
    ...actual,
    mikrotikApi: {
      getDHCPServers: vi.fn(),
      getDHCPLeases: vi.fn(),
      createDHCPServer: vi.fn(),
      updateDHCPServer: vi.fn(),
      deleteDHCPServer: vi.fn(),
      makeLeaseStatic: vi.fn(),
      createStaticLease: vi.fn(),
      updateStaticLease: vi.fn(),
      deleteStaticLease: vi.fn(),
    },
  };
});

const mockServers = mikrotikApi.getDHCPServers as unknown as Mock;
const mockLeases = mikrotikApi.getDHCPLeases as unknown as Mock;
const mockMakeStatic = mikrotikApi.makeLeaseStatic as unknown as Mock;

beforeEach(() => {
  mockServers.mockReset();
  mockLeases.mockReset();
  mockMakeStatic.mockReset();
});

const empty = {
  data: { controller_id: 'c1', items: [], fetched_at: '', limit: 200, offset: 0, total: 0 },
};

describe('MikroTikDhcpTab', () => {
  it('stages a Make-static via the AlertDialog', async () => {
    const user = userEvent.setup();
    mockServers.mockResolvedValue(empty);
    mockLeases.mockResolvedValue({
      data: {
        controller_id: 'c1',
        items: [
          {
            '.id': '*1',
            address: '192.168.88.50',
            'mac-address': 'AA:BB:CC:DD:EE:FF',
            'host-name': 'laptop',
            server: 'dhcp-lan',
            dynamic: 'true',
            status: 'bound',
          },
        ],
        fetched_at: '',
        limit: 200,
        offset: 0,
        total: 1,
      },
    });
    mockMakeStatic.mockResolvedValue({ data: { staged: true } });

    renderWithProviders(
      <MikroTikDhcpTab controllerId="c1" isActive={true} gatewayName="edge-rtr-1" />,
    );
    await waitFor(() => expect(mockLeases).toHaveBeenCalled());

    const makeStaticBtn = await screen.findByRole('button', { name: /Make static/i });
    await user.click(makeStaticBtn);

    // The new shadcn dialog opens, confirm its title is visible.
    expect(await screen.findByText(/Stage static mapping\?/i)).toBeInTheDocument();
    // The IP appears in both the lease row and the dialog body, assert
    // at least one match (not the table row which is shorthand prose).
    expect(screen.getAllByText(/192\.168\.88\.50/).length).toBeGreaterThan(0);

    const confirm = await screen.findByRole('button', { name: /Stage mapping/i });
    await user.click(confirm);

    await waitFor(() =>
      expect(mockMakeStatic).toHaveBeenCalledWith('c1', {
        'mac-address': 'AA:BB:CC:DD:EE:FF',
        address: '192.168.88.50',
        server: 'dhcp-lan',
        'host-name': 'laptop',
        comment: undefined,
      }),
    );
  });
});

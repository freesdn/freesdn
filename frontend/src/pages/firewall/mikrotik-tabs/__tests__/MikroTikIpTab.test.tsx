// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * MikroTikIpTab, interaction test.
 *
 * Verifies the address-create dialog: opening it, filling a valid
 * CIDR + interface, submitting, and asserting the create mutation
 * fired with the right payload. Also asserts an invalid CIDR keeps the
 * submit button disabled.
 */
import { describe, it, expect, beforeEach, vi, type Mock } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MikroTikIpTab } from '../MikroTikIpTab';
import { mikrotikApi } from '@/lib/api';
import { renderWithProviders } from '@/test-utils';

vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api');
  return {
    ...actual,
    mikrotikApi: {
      getIPAddresses: vi.fn(),
      getRoutes: vi.fn(),
      getIPPools: vi.fn(),
      createIPAddress: vi.fn(),
      deleteIPAddress: vi.fn(),
      createRoute: vi.fn(),
      updateRoute: vi.fn(),
      deleteRoute: vi.fn(),
      createIPPool: vi.fn(),
      updateIPPool: vi.fn(),
      deleteIPPool: vi.fn(),
    },
  };
});

const mockAddr = mikrotikApi.getIPAddresses as unknown as Mock;
const mockRoutes = mikrotikApi.getRoutes as unknown as Mock;
const mockPools = mikrotikApi.getIPPools as unknown as Mock;
const mockCreateAddr = mikrotikApi.createIPAddress as unknown as Mock;

beforeEach(() => {
  mockAddr.mockReset();
  mockRoutes.mockReset();
  mockPools.mockReset();
  mockCreateAddr.mockReset();
});

const empty = {
  data: { controller_id: 'c1', items: [], fetched_at: '', limit: 200, offset: 0, total: 0 },
};

describe('MikroTikIpTab', () => {
  it('keeps Stage create disabled on invalid CIDR, enables on valid', async () => {
    const user = userEvent.setup();
    mockAddr.mockResolvedValue(empty);
    mockRoutes.mockResolvedValue(empty);
    mockPools.mockResolvedValue(empty);
    mockCreateAddr.mockResolvedValue({ data: { staged: true } });

    renderWithProviders(
      <MikroTikIpTab controllerId="c1" isActive={true} gatewayName="edge-rtr-1" />,
    );
    await waitFor(() => expect(mockAddr).toHaveBeenCalled());

    // Find the "Add address" header button (multiple "Add address"
    // labels exist if EmptyState is present, pick the header one).
    const addBtns = await screen.findAllByRole('button', { name: /Add address/i });
    await user.click(addBtns[0]);

    const cidr = await screen.findByLabelText(/Address \(CIDR\)/i);
    const iface = await screen.findByLabelText(/^Interface/i);

    // Invalid CIDR
    await user.type(cidr, '192.168.1.1');
    await user.type(iface, 'bridge1');

    const submit = screen.getByRole('button', { name: /Stage create/i });
    expect(submit).toBeDisabled();

    // Make it valid
    await user.type(cidr, '/24');
    expect(submit).toBeEnabled();

    await user.click(submit);

    await waitFor(() =>
      expect(mockCreateAddr).toHaveBeenCalledWith('c1', {
        address: '192.168.1.1/24',
        interface: 'bridge1',
      }),
    );
  });
});

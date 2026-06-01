// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * MikroTikInterfacesTab, interaction test.
 *
 * Verifies the wireless enable/disable toggle uses the new shadcn
 * AlertDialog instead of `window.confirm`: clicking the per-row
 * "Disable" button opens the dialog, confirming inside the dialog
 * fires the toggle mutation.
 */
import { describe, it, expect, beforeEach, vi, type Mock } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MikroTikInterfacesTab } from '../MikroTikInterfacesTab';
import { mikrotikApi } from '@/lib/api';
import { renderWithProviders } from '@/test-utils';

vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api');
  return {
    ...actual,
    mikrotikApi: {
      getEthernet: vi.fn(),
      getBridges: vi.fn(),
      getAllInterfaces: vi.fn(),
      createBridge: vi.fn(),
      updateBridge: vi.fn(),
      deleteBridge: vi.fn(),
      toggleInterface: vi.fn(),
    },
  };
});

const mockEth = mikrotikApi.getEthernet as unknown as Mock;
const mockBr = mikrotikApi.getBridges as unknown as Mock;
const mockAll = mikrotikApi.getAllInterfaces as unknown as Mock;
const mockToggle = mikrotikApi.toggleInterface as unknown as Mock;

beforeEach(() => {
  mockEth.mockReset();
  mockBr.mockReset();
  mockAll.mockReset();
  mockToggle.mockReset();
});

const emptyList = {
  data: { controller_id: 'c1', items: [], fetched_at: '', limit: 200, offset: 0, total: 0 },
};

describe('MikroTikInterfacesTab', () => {
  it('stages a wireless toggle via the AlertDialog', async () => {
    const user = userEvent.setup();
    mockEth.mockResolvedValue(emptyList);
    mockBr.mockResolvedValue(emptyList);
    mockAll.mockResolvedValue({
      data: {
        controller_id: 'c1',
        items: [
          {
            '.id': '*1',
            name: 'wlan1',
            type: 'wlan',
            disabled: 'false',
            running: 'true',
          },
        ],
        fetched_at: '',
        limit: 200,
        offset: 0,
        total: 1,
      },
    });
    mockToggle.mockResolvedValue({ data: { staged: true } });

    renderWithProviders(
      <MikroTikInterfacesTab controllerId="c1" isActive={true} gatewayName="edge-rtr-1" />,
    );
    await waitFor(() => expect(mockAll).toHaveBeenCalled());

    // The wireless row's per-row button reads "Disable" because the
    // interface is currently enabled (disabled='false').
    const disableBtn = await screen.findByRole('button', { name: /Disable/i });
    await user.click(disableBtn);

    // The confirmation dialog opens, confirm it's our new dialog, not
    // a `window.confirm` (which can't be detected via the DOM).
    expect(
      await screen.findByText(/Stage disable for wireless interface/i),
    ).toBeInTheDocument();

    const confirm = await screen.findByRole('button', { name: /^Stage disable$/i });
    await user.click(confirm);

    await waitFor(() =>
      expect(mockToggle).toHaveBeenCalledWith('c1', '*1', false),
    );
  });

  it('drops the global error banner, per-card ErrorState only', async () => {
    mockEth.mockRejectedValue(new Error('boom'));
    mockBr.mockResolvedValue(emptyList);
    mockAll.mockResolvedValue(emptyList);

    renderWithProviders(
      <MikroTikInterfacesTab controllerId="c1" isActive={true} gatewayName="edge-rtr-1" />,
    );
    await waitFor(() => expect(mockEth).toHaveBeenCalled());
    // The old global banner copy is gone.
    expect(
      screen.queryByText(/One or more RouterOS interface queries failed/i),
    ).not.toBeInTheDocument();
  });
});

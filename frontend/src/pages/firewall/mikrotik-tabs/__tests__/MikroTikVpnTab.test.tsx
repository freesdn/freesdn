// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * MikroTikVpnTab, smoke test.
 *
 * The VPN tab is read-mostly: it loads L2TP + PPTP singleton rows and
 * renders an edit dialog for each. The smoke test verifies both panes
 * render, the deprecated PPTP badge is visible, and the SSTP "settings
 * deferred" panel is present.
 */
import { describe, it, expect, beforeEach, vi, type Mock } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MikroTikVpnTab } from '../MikroTikVpnTab';
import { mikrotikApi } from '@/lib/api';
import { renderWithProviders } from '@/test-utils';

vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api');
  return {
    ...actual,
    mikrotikApi: {
      getL2TPServer: vi.fn(),
      getPPTPServer: vi.fn(),
      updateL2TPServer: vi.fn(),
      updatePPTPServer: vi.fn(),
    },
  };
});

const mockL2TP = mikrotikApi.getL2TPServer as unknown as Mock;
const mockPPTP = mikrotikApi.getPPTPServer as unknown as Mock;

beforeEach(() => {
  mockL2TP.mockReset();
  mockPPTP.mockReset();
});

describe('MikroTikVpnTab smoke', () => {
  it('renders all three sub-panes', async () => {
    mockL2TP.mockResolvedValue({
      data: {
        controller_id: 'c1',
        item: { enabled: 'true', 'default-profile': 'default-encryption', authentication: 'mschap2' },
        fetched_at: '',
      },
    });
    mockPPTP.mockResolvedValue({
      data: {
        controller_id: 'c1',
        item: { enabled: 'false', authentication: 'mschap2' },
        fetched_at: '',
      },
    });

    renderWithProviders(<MikroTikVpnTab controllerId="c1" isActive={true} />);
    await waitFor(() => expect(mockL2TP).toHaveBeenCalledWith('c1'));
    expect(await screen.findByText(/L2TP server/i)).toBeInTheDocument();
    expect(screen.getByText(/PPTP server/i)).toBeInTheDocument();
    expect(screen.getByText(/SSTP server/i)).toBeInTheDocument();
    // Deprecated badge appears next to PPTP heading.
    expect(screen.getByText(/Deprecated/i)).toBeInTheDocument();
  });

  it('shows empty state if L2TP server data is missing', async () => {
    mockL2TP.mockResolvedValue({
      data: { controller_id: 'c1', item: undefined, fetched_at: '' },
    });
    mockPPTP.mockResolvedValue({
      data: { controller_id: 'c1', item: undefined, fetched_at: '' },
    });

    renderWithProviders(<MikroTikVpnTab controllerId="c1" isActive={true} />);
    await waitFor(() => expect(mockL2TP).toHaveBeenCalled());
    expect(
      await screen.findByText(/L2TP server not available/i),
    ).toBeInTheDocument();
  });

  it('does not fetch when isActive=false', async () => {
    renderWithProviders(<MikroTikVpnTab controllerId="c1" isActive={false} />);
    expect(mockL2TP).not.toHaveBeenCalled();
    expect(mockPPTP).not.toHaveBeenCalled();
  });

  // ── CRIT-1: IPsec secret must never seed from a read response ───
  it('CRIT-1: ipsec-secret input is empty even when API returns a secret', async () => {
    const user = userEvent.setup();
    // Simulate a regressed backend that includes the secret in the GET
    // response. The frontend must NOT surface it into the password
    // input, the field is write-only.
    mockL2TP.mockResolvedValue({
      data: {
        controller_id: 'c1',
        item: {
          enabled: 'true',
          'default-profile': 'default-encryption',
          authentication: 'mschap2',
          'use-ipsec': 'true',
          'ipsec-secret': 'SUPER_SECRET_DO_NOT_LEAK',
        },
        fetched_at: '',
      },
    });
    mockPPTP.mockResolvedValue({
      data: { controller_id: 'c1', item: undefined, fetched_at: '' },
    });

    renderWithProviders(<MikroTikVpnTab controllerId="c1" isActive={true} />);
    await waitFor(() => expect(mockL2TP).toHaveBeenCalled());

    // Open the L2TP edit dialog.
    const editBtns = await screen.findAllByRole('button', { name: /Edit settings/i });
    await user.click(editBtns[0]);

    // The IPsec checkbox is on, so the password input should be visible.
    const ipsecInput = (await screen.findByLabelText(
      /IPsec shared secret/i,
    )) as HTMLInputElement;
    // CRIT-1 invariant: the input is empty and write-only.
    expect(ipsecInput.value).toBe('');
    expect(ipsecInput.type).toBe('password');
    // The DOM must not contain the secret anywhere as a `value`
    // attribute (defensive, guards future regressions where someone
    // adds a hidden mirror input).
    expect(document.querySelector('[value="SUPER_SECRET_DO_NOT_LEAK"]')).toBeNull();
  });
});

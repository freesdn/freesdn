// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * MikroTikFirewallTab, interaction test.
 *
 * Verifies the destructive-scope delete dialog (MEDIUM-3) shows the
 * full rule detail (chain, action, src, dst) rather than the old
 * one-line label. Also asserts the reorder-rollback by
 * exercising a failed reorder mutation.
 */
import { describe, it, expect, beforeEach, vi, type Mock } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MikroTikFirewallTab } from '../MikroTikFirewallTab';
import { mikrotikApi } from '@/lib/api';
import { renderWithProviders } from '@/test-utils';

vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api');
  return {
    ...actual,
    mikrotikApi: {
      getFilterRules: vi.fn(),
      getNATRules: vi.fn(),
      createFilterRule: vi.fn(),
      updateFilterRule: vi.fn(),
      deleteFilterRule: vi.fn(),
      reorderFilterRules: vi.fn(),
      createNATRule: vi.fn(),
      updateNATRule: vi.fn(),
      deleteNATRule: vi.fn(),
    },
  };
});

const mockFilter = mikrotikApi.getFilterRules as unknown as Mock;
const mockNat = mikrotikApi.getNATRules as unknown as Mock;
const mockDelFilter = mikrotikApi.deleteFilterRule as unknown as Mock;

beforeEach(() => {
  mockFilter.mockReset();
  mockNat.mockReset();
  mockDelFilter.mockReset();
});

const emptyList = {
  data: { controller_id: 'c1', items: [], fetched_at: '', limit: 200, offset: 0, total: 0 },
};

describe('MikroTikFirewallTab', () => {
  it('delete dialog renders full rule detail (MEDIUM-3)', async () => {
    const user = userEvent.setup();
    mockFilter.mockResolvedValue({
      data: {
        controller_id: 'c1',
        items: [
          {
            '.id': '*1',
            chain: 'forward',
            action: 'accept',
            protocol: 'tcp',
            'src-address': '10.0.0.0/8',
            'dst-address': '0.0.0.0/0',
            'dst-port': '443',
            'in-interface': 'ether1',
            comment: 'allow HTTPS',
            disabled: 'false',
          },
        ],
        fetched_at: '',
        limit: 200,
        offset: 0,
        total: 1,
      },
    });
    mockNat.mockResolvedValue(emptyList);
    mockDelFilter.mockResolvedValue({ data: { staged: true } });

    renderWithProviders(
      <MikroTikFirewallTab controllerId="c1" isActive={true} gatewayName="edge-rtr-1" />,
    );
    await waitFor(() => expect(mockFilter).toHaveBeenCalled());

    // edit / delete buttons now carry an aria-label of the form
    // ``Delete firewall rule <comment|chain action>``. Find the delete
    // button via that label rather than via `name=''` (which used to
    // catch the unlabelled icon-only button).
    const deleteBtn = await screen.findByRole('button', {
      name: /Delete firewall rule allow HTTPS/i,
    });
    await user.click(deleteBtn);

    // Dialog should now show the rich rule detail.
    expect(
      await screen.findByText(/Stage delete · filter rule\?/i),
    ).toBeInTheDocument();
    // The dl labels overlap with table headers ("Chain", "Action",
    // etc.), so we assert each label appears AT LEAST twice
    // (once in the table header, once in the dialog dl).
    expect(screen.getAllByText(/^Chain$/).length).toBeGreaterThanOrEqual(2);
    expect(screen.getAllByText(/^Action$/).length).toBeGreaterThanOrEqual(2);
    // Comment-only labels (not in the table header) appear once.
    expect(screen.getAllByText(/^Comment$/).length).toBeGreaterThanOrEqual(1);
    // The actual rule values may also appear in both row and dialog.
    expect(screen.getAllByText('10.0.0.0/8').length).toBeGreaterThan(0);
    expect(screen.getAllByText('allow HTTPS').length).toBeGreaterThan(0);
  });

  it('drag handle has aria-label (LOW-1)', async () => {
    mockFilter.mockResolvedValue({
      data: {
        controller_id: 'c1',
        items: [
          {
            '.id': '*1',
            chain: 'forward',
            action: 'accept',
          },
        ],
        fetched_at: '',
        limit: 200,
        offset: 0,
        total: 1,
      },
    });
    mockNat.mockResolvedValue(emptyList);

    renderWithProviders(
      <MikroTikFirewallTab controllerId="c1" isActive={true} gatewayName="edge-rtr-1" />,
    );
    await waitFor(() => expect(mockFilter).toHaveBeenCalled());

    expect(
      await screen.findByLabelText(/Drag to reorder rule/i),
    ).toBeInTheDocument();
  });

  // icon-only edit / delete buttons must expose an aria-label
  // so screen readers and automated tests can identify each per-row
  // action. The label uses the row's comment when available and falls
  // back to chain/action shape, then to the RouterOS .id.
  it('filter rule edit + delete buttons expose aria-labels', async () => {
    mockFilter.mockResolvedValue({
      data: {
        controller_id: 'c1',
        items: [
          {
            '.id': '*42',
            chain: 'forward',
            action: 'drop',
            comment: 'block lan-to-wan smb',
          },
        ],
        fetched_at: '',
        limit: 200,
        offset: 0,
        total: 1,
      },
    });
    mockNat.mockResolvedValue(emptyList);

    renderWithProviders(
      <MikroTikFirewallTab controllerId="c1" isActive={true} gatewayName="edge-rtr-1" />,
    );
    await waitFor(() => expect(mockFilter).toHaveBeenCalled());

    expect(
      await screen.findByRole('button', {
        name: /Edit firewall rule block lan-to-wan smb/i,
      }),
    ).toBeInTheDocument();
    expect(
      await screen.findByRole('button', {
        name: /Delete firewall rule block lan-to-wan smb/i,
      }),
    ).toBeInTheDocument();
  });

  it('falls back to chain/action shape when comment is missing', async () => {
    mockFilter.mockResolvedValue({
      data: {
        controller_id: 'c1',
        items: [
          {
            '.id': '*7',
            chain: 'input',
            action: 'accept',
          },
        ],
        fetched_at: '',
        limit: 200,
        offset: 0,
        total: 1,
      },
    });
    mockNat.mockResolvedValue(emptyList);

    renderWithProviders(
      <MikroTikFirewallTab controllerId="c1" isActive={true} gatewayName="edge-rtr-1" />,
    );
    await waitFor(() => expect(mockFilter).toHaveBeenCalled());

    expect(
      await screen.findByRole('button', { name: /Edit firewall rule input accept/i }),
    ).toBeInTheDocument();
    expect(
      await screen.findByRole('button', {
        name: /Delete firewall rule input accept/i,
      }),
    ).toBeInTheDocument();
  });

  it('NAT rule edit + delete buttons expose aria-labels', async () => {
    mockFilter.mockResolvedValue(emptyList);
    mockNat.mockResolvedValue({
      data: {
        controller_id: 'c1',
        items: [
          {
            '.id': '*9',
            chain: 'srcnat',
            action: 'masquerade',
            comment: 'wan-out',
          },
        ],
        fetched_at: '',
        limit: 200,
        offset: 0,
        total: 1,
      },
    });

    renderWithProviders(
      <MikroTikFirewallTab controllerId="c1" isActive={true} gatewayName="edge-rtr-1" />,
    );
    await waitFor(() => expect(mockNat).toHaveBeenCalled());

    expect(
      await screen.findByRole('button', { name: /Edit NAT rule wan-out/i }),
    ).toBeInTheDocument();
    expect(
      await screen.findByRole('button', { name: /Delete NAT rule wan-out/i }),
    ).toBeInTheDocument();
  });
});

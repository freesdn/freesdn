// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * MikroTikSnmpTab, smoke test.
 *
 * SECURITY-CRITICAL: SNMPv3 passwords are write-only. The smoke test
 * verifies:
 *   - All three surfaces render (settings card / trap-targets table /
 *     SNMPv3 users table).
 *   - The SNMPv3 users table NEVER renders a column labelled "password".
 *   - A SNMPv3 user row renders auth-protocol + encryption-protocol
 *     metadata only, never password material.
 *   - isActive=false short-circuits the fetches.
 */
import { describe, it, expect, beforeEach, vi, type Mock } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import { MikroTikSnmpTab } from '../MikroTikSnmpTab';
import { mikrotikApi } from '@/lib/api';
import { renderWithProviders } from '@/test-utils';

vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api');
  return {
    ...actual,
    mikrotikApi: {
      getSnmpTrapTargets: vi.fn(),
      getSnmpV3Users: vi.fn(),
      addSnmpTrapTarget: vi.fn(),
      updateSnmpTrapTarget: vi.fn(),
      removeSnmpTrapTarget: vi.fn(),
      addSnmpV3User: vi.fn(),
      updateSnmpV3User: vi.fn(),
      deleteSnmpV3User: vi.fn(),
      updateSnmpSettings: vi.fn(),
    },
  };
});

const mockTraps = mikrotikApi.getSnmpTrapTargets as unknown as Mock;
const mockV3Users = mikrotikApi.getSnmpV3Users as unknown as Mock;

beforeEach(() => {
  mockTraps.mockReset();
  mockV3Users.mockReset();
});

// Trap targets still come through the {items} envelope (unchanged).
const emptyList = {
  data: {
    controller_id: 'c1',
    items: [],
    fetched_at: '',
    limit: 200,
    offset: 0,
    total: 0,
  },
};

// SNMPv3 users now return a BARE array (no envelope).
const emptyV3Users = { data: [] };

describe('MikroTikSnmpTab smoke', () => {
  it('renders all three surfaces with empty data', async () => {
    mockTraps.mockResolvedValue(emptyList);
    mockV3Users.mockResolvedValue(emptyV3Users);

    renderWithProviders(<MikroTikSnmpTab controllerId="c1" isActive={true} />);
    await waitFor(() => expect(mockTraps).toHaveBeenCalledWith('c1'));
    // "SNMP server" appears in both card title + description blurb.
    expect((await screen.findAllByText(/SNMP server/i)).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/Trap targets/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/SNMPv3 users/i).length).toBeGreaterThan(0);
  });

  it('renders a SNMPv3 user row WITHOUT any password column', async () => {
    mockTraps.mockResolvedValue(emptyList);
    mockV3Users.mockResolvedValue({
      data: [
        {
          '.id': '*1',
          name: 'monitor',
          'auth-protocol': 'SHA1',
          'encryption-protocol': 'AES',
          addresses: '10.0.0.0/24',
        },
      ],
    });

    renderWithProviders(<MikroTikSnmpTab controllerId="c1" isActive={true} />);
    await waitFor(() => expect(mockV3Users).toHaveBeenCalled());
    expect(await screen.findByText('monitor')).toBeInTheDocument();
    expect(screen.getByText('SHA1')).toBeInTheDocument();
    expect(screen.getByText('AES')).toBeInTheDocument();
    // CRITICAL: no column header in either table mentions "password" /
    // "secret" / "auth password" / "priv password". We scope to
    // <th> (column headers), the password fields exist in the modal
    // dialog form but those are write-only inputs, not visible columns.
    const headerCells = screen.getAllByRole('columnheader');
    for (const h of headerCells) {
      expect(h.textContent ?? '').not.toMatch(/password/i);
      expect(h.textContent ?? '').not.toMatch(/secret/i);
    }
    // And no row cell contains a password-shaped value either.
    const rowCells = screen.getAllByRole('cell');
    for (const c of rowCells) {
      expect(c.textContent ?? '').not.toMatch(/password/i);
      expect(c.textContent ?? '').not.toMatch(/secret/i);
    }
  });

  it('renders a trap target row with version badge', async () => {
    mockTraps.mockResolvedValue({
      data: {
        controller_id: 'c1',
        items: [
          {
            '.id': '*1',
            address: '10.0.0.100',
            port: '162',
            version: '2',
            community: 'public',
          },
        ],
        fetched_at: '',
        limit: 200,
        offset: 0,
        total: 1,
      },
    });
    mockV3Users.mockResolvedValue(emptyV3Users);

    renderWithProviders(<MikroTikSnmpTab controllerId="c1" isActive={true} />);
    await waitFor(() => expect(mockTraps).toHaveBeenCalled());
    expect(await screen.findByText('10.0.0.100')).toBeInTheDocument();
    expect(screen.getByText('v2')).toBeInTheDocument();
    expect(screen.getByText('public')).toBeInTheDocument();
  });

  it('does not fetch when isActive=false', async () => {
    renderWithProviders(<MikroTikSnmpTab controllerId="c1" isActive={false} />);
    expect(mockTraps).not.toHaveBeenCalled();
    expect(mockV3Users).not.toHaveBeenCalled();
  });
});

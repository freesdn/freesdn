// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * MikroTikHotspotTab, smoke test.
 *
 * Three sub-tables (servers / user profiles / active sessions). The
 * smoke test verifies all three render, and that the disconnect
 * button on active rows is disabled (ships read-only).
 */
import { describe, it, expect, beforeEach, vi, type Mock } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import { MikroTikHotspotTab } from '../MikroTikHotspotTab';
import { mikrotikApi } from '@/lib/api';
import { renderWithProviders } from '@/test-utils';

vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api');
  return {
    ...actual,
    mikrotikApi: {
      getHotspotServers: vi.fn(),
      getHotspotUserProfiles: vi.fn(),
      getHotspotActive: vi.fn(),
      createHotspotServer: vi.fn(),
      updateHotspotServer: vi.fn(),
      deleteHotspotServer: vi.fn(),
      createHotspotUserProfile: vi.fn(),
      updateHotspotUserProfile: vi.fn(),
      deleteHotspotUserProfile: vi.fn(),
    },
  };
});

const mockServers = mikrotikApi.getHotspotServers as unknown as Mock;
const mockProfiles = mikrotikApi.getHotspotUserProfiles as unknown as Mock;
const mockActive = mikrotikApi.getHotspotActive as unknown as Mock;

beforeEach(() => {
  mockServers.mockReset();
  mockProfiles.mockReset();
  mockActive.mockReset();
});

const emptyList = {
  data: { controller_id: 'c1', items: [], fetched_at: '', limit: 200, offset: 0, total: 0 },
};

describe('MikroTikHotspotTab smoke', () => {
  it('renders all three sub-tables with empty data', async () => {
    mockServers.mockResolvedValue(emptyList);
    mockProfiles.mockResolvedValue(emptyList);
    mockActive.mockResolvedValue(emptyList);

    renderWithProviders(<MikroTikHotspotTab controllerId="c1" isActive={true} />);
    await waitFor(() => expect(mockServers).toHaveBeenCalled());
    // Card titles + empty-state titles both contain the same phrases.
    expect(
      (await screen.findAllByText(/Hotspot servers/i)).length,
    ).toBeGreaterThan(0);
    expect(screen.getAllByText(/User profiles/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/Active users/i).length).toBeGreaterThan(0);
  });

  it('renders an active session row with a disabled Disconnect button', async () => {
    mockServers.mockResolvedValue(emptyList);
    mockProfiles.mockResolvedValue(emptyList);
    mockActive.mockResolvedValue({
      data: {
        controller_id: 'c1',
        items: [
          {
            '.id': '*1',
            user: 'guest1',
            address: '192.168.10.5',
            'mac-address': 'AA:BB:CC:DD:EE:FF',
            uptime: '5m12s',
            server: 'guest-hs',
          },
        ],
        fetched_at: '',
        limit: 200,
        offset: 0,
        total: 1,
      },
    });

    renderWithProviders(<MikroTikHotspotTab controllerId="c1" isActive={true} />);
    await waitFor(() => expect(mockActive).toHaveBeenCalled());
    expect(await screen.findByText('guest1')).toBeInTheDocument();
    const disconnect = screen.getByRole('button', { name: /Disconnect/i });
    expect(disconnect).toBeDisabled();
  });

  it('does not fetch when isActive=false', async () => {
    renderWithProviders(<MikroTikHotspotTab controllerId="c1" isActive={false} />);
    expect(mockServers).not.toHaveBeenCalled();
    expect(mockProfiles).not.toHaveBeenCalled();
    expect(mockActive).not.toHaveBeenCalled();
  });
});

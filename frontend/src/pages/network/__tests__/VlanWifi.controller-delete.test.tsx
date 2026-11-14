// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * A VLAN or WiFi delete the controller did not confirm is reported. The
 * backend pushes the delete to the controller first and answers
 * ``controller_synced: false`` with a warning when it did not confirm; the
 * pages ignored that and closed the dialog as if all went well. Both the
 * current answer (record removed anyway) and the documented one (record kept,
 * ``success: false``) are covered.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import VlansPage from '../VlansPage';
import WifiNetworksPage from '../WifiNetworksPage';
import { networkApi } from '@/lib/api';
import { useSiteStore } from '@/stores/siteStore';
import { renderWithProviders } from '@/test-utils';

vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api');
  return {
    ...actual,
    networkApi: {
      ...actual.networkApi,
      vlans: { list: vi.fn(), get: vi.fn(), create: vi.fn(), update: vi.fn(), delete: vi.fn() },
      wifi: { list: vi.fn(), get: vi.fn(), create: vi.fn(), update: vi.fn(), delete: vi.fn(), toggle: vi.fn() },
      getVlanAlignment: vi.fn(),
      distributeVlan: vi.fn(),
    },
  };
});

const WARNING = 'Omada answered -33004: the VLAN is in use by a port profile';

beforeEach(() => {
  vi.clearAllMocks();
  useSiteStore.setState({ selectedSiteId: null });
  vi.mocked(networkApi.vlans.list).mockResolvedValue({ data: { items: [{ id: 'v-20', vlan_id: 20, name: 'voice', dhcp_enabled: true }], total: 1 } } as never);
  vi.mocked(networkApi.wifi.list).mockResolvedValue({ data: { items: [{ id: 'w-1', ssid: 'Guest', security: 'wpa2', enabled: true, band: 'both', hidden: false }], total: 1 } } as never);
});

async function deleteVlan(user: ReturnType<typeof userEvent.setup>) {
  await user.click(await screen.findByRole('button', { name: 'Actions for VLAN 20 voice' }));
  await user.click(await screen.findByRole('menuitem', { name: /Delete/ }));
  const dialog = await screen.findByRole('alertdialog');
  await user.click(within(dialog).getByRole('button', { name: 'Delete' }));
}

async function deleteWifi(user: ReturnType<typeof userEvent.setup>) {
  await user.click(await screen.findByRole('button', { name: 'Actions for Guest' }));
  await user.click(await screen.findByRole('menuitem', { name: /Delete/ }));
  const dialog = await screen.findByRole('alertdialog');
  await user.click(within(dialog).getByRole('button', { name: /Delete/ }));
}

describe('VLAN delete the controller did not confirm', () => {
  it('says the VLAN may still exist on the controller (current answer)', async () => {
    vi.mocked(networkApi.vlans.delete).mockResolvedValue({ data: { success: true, controller_synced: false, controller_warning: WARNING } } as never);
    const user = userEvent.setup();
    renderWithProviders(<VlansPage />, { initialPath: '/vlans' });
    await deleteVlan(user);
    expect(await screen.findByText('The controller did not confirm the deletion')).toBeInTheDocument();
    expect(screen.getByText(new RegExp(`VLAN 20 voice was removed from FreeSDN.*may still exist there.*${WARNING}`))).toBeInTheDocument();
    expect(networkApi.vlans.delete).toHaveBeenCalledWith('v-20');
  });

  it('says FreeSDN kept the VLAN (documented answer)', async () => {
    vi.mocked(networkApi.vlans.delete).mockResolvedValue({ data: { success: false, controller_synced: false, controller_warning: WARNING } } as never);
    const user = userEvent.setup();
    renderWithProviders(<VlansPage />, { initialPath: '/vlans' });
    await deleteVlan(user);
    expect(await screen.findByText(new RegExp(`FreeSDN kept VLAN 20 voice.*${WARNING}`))).toBeInTheDocument();
  });

  it('says nothing extra when the controller confirmed', async () => {
    vi.mocked(networkApi.vlans.delete).mockResolvedValue({ data: { success: true, controller_synced: true, controller_warning: null } } as never);
    const user = userEvent.setup();
    renderWithProviders(<VlansPage />, { initialPath: '/vlans' });
    await deleteVlan(user);
    await waitFor(() => expect(networkApi.vlans.delete).toHaveBeenCalled());
    await waitFor(() => expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument());
    expect(screen.queryByText('The controller did not confirm the deletion')).not.toBeInTheDocument();
  });
});

describe('WiFi delete the controller did not confirm', () => {
  it('says the SSID may still be broadcasting (current answer)', async () => {
    vi.mocked(networkApi.wifi.delete).mockResolvedValue({ data: { success: true, controller_synced: false, controller_warning: WARNING } } as never);
    const user = userEvent.setup();
    renderWithProviders(<WifiNetworksPage />, { initialPath: '/wifi' });
    await deleteWifi(user);
    expect(await screen.findByText(new RegExp(`Guest was removed from FreeSDN.*SSID may still be broadcasting.*${WARNING}`))).toBeInTheDocument();
    expect(networkApi.wifi.delete).toHaveBeenCalledWith('w-1');
  });

  it('says FreeSDN kept the network (documented answer)', async () => {
    vi.mocked(networkApi.wifi.delete).mockResolvedValue({ data: { success: false, controller_synced: false, controller_warning: WARNING } } as never);
    const user = userEvent.setup();
    renderWithProviders(<WifiNetworksPage />, { initialPath: '/wifi' });
    await deleteWifi(user);
    expect(await screen.findByText(new RegExp(`FreeSDN kept Guest.*${WARNING}`))).toBeInTheDocument();
  });
});

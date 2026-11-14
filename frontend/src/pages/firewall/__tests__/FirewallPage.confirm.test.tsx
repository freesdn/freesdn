// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Deleting a gateway connection asks through the in-app confirmation dialog,
 * which names the gateway and says the gateway itself is left untouched. A
 * Cancel sends nothing; a confirm sends exactly one delete. API responses are
 * doubles; nothing reaches a device.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import FirewallPage from '../FirewallPage';
import { gatewayApi } from '@/lib/api';
import { useSiteStore } from '@/stores/siteStore';
import { renderWithProviders } from '@/test-utils';

vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api');
  return {
    ...actual,
    gatewayApi: {
      getAll: vi.fn(),
      getSummary: vi.fn().mockResolvedValue({ data: null }),
      create: vi.fn(),
      update: vi.fn(),
      delete: vi.fn(),
      triggerSync: vi.fn(),
      testConnection: vi.fn(),
      testExisting: vi.fn(),
    },
    firewallApi: {
      getRules: vi.fn().mockResolvedValue({ data: [] }),
      getNATRules: vi.fn().mockResolvedValue({ data: [] }),
      getVPNTunnels: vi.fn().mockResolvedValue({ data: [] }),
      getVPNStats: vi.fn().mockResolvedValue({ data: {} }),
      getAlerts: vi.fn().mockResolvedValue({ data: [] }),
      getAlertStats: vi.fn().mockResolvedValue({ data: {} }),
      getLogs: vi.fn().mockResolvedValue({ data: [] }),
    },
    sitesApiV2: { list: vi.fn().mockResolvedValue({ data: { items: [] } }) },
  };
});

const getAll = vi.mocked(gatewayApi.getAll);
const remove = vi.mocked(gatewayApi.delete);

const gateway = {
  id: 'gw-edge',
  org_id: 'org-1',
  name: 'Edge firewall',
  vendor: 'opnsense',
  host: 'edge.example.test',
  port: 443,
  verify_ssl: true,
  has_credentials: true,
  sync_enabled: true,
  sync_interval_seconds: 900,
  sync_status: 'success',
  is_online: true,
  capabilities: [],
  settings: {},
  created_at: '2026-11-01T00:00:00Z',
  updated_at: '2026-11-01T00:00:00Z',
};

beforeEach(() => {
  vi.clearAllMocks();
  useSiteStore.setState({ selectedSiteId: null });
  getAll.mockResolvedValue({ data: [gateway] } as never);
  remove.mockResolvedValue({ data: null } as never);
});

async function openDeleteConfirm(user: ReturnType<typeof userEvent.setup>) {
  renderWithProviders(<FirewallPage />, { initialPath: '/firewall/gateways' });
  const cell = (await screen.findAllByText('Edge firewall')).find((el) => el.closest('tr'));
  const row = cell!.closest('tr') as HTMLElement;
  const trigger = within(row)
    .getAllByRole('button')
    .find((b) => b.getAttribute('aria-haspopup') === 'menu');
  await user.click(trigger!);
  await user.click(await screen.findByRole('menuitem', { name: 'Delete' }));
  return screen.findByRole('alertdialog');
}

describe('FirewallPage gateway delete confirmation', () => {
  it('names the gateway, says the device is untouched, and Cancel sends nothing', async () => {
    const user = userEvent.setup();
    const dialog = await openDeleteConfirm(user);

    expect(within(dialog).getByRole('heading', { name: 'Delete gateway "Edge firewall"?' })).toBeInTheDocument();
    expect(within(dialog).getByText(/Nothing is changed on the gateway itself\./)).toBeInTheDocument();

    await user.click(within(dialog).getByRole('button', { name: 'Cancel' }));
    await waitFor(() => expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument());
    expect(remove).not.toHaveBeenCalled();
  });

  it('deletes the gateway connection once the operator confirms', async () => {
    const user = userEvent.setup();
    const dialog = await openDeleteConfirm(user);
    expect(remove).not.toHaveBeenCalled();

    await user.click(within(dialog).getByRole('button', { name: 'Delete gateway' }));

    await waitFor(() => expect(remove).toHaveBeenCalledTimes(1));
    expect(remove).toHaveBeenCalledWith('gw-edge');
  });
});

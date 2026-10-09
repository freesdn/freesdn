// SPDX-License-Identifier: AGPL-3.0-only
/** Real page and tabs; vendor identity and API inventory are explicit fixtures. */
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, screen, waitFor, within } from '@testing-library/react';
import GatewayDetailPage from '../GatewayDetailPage';
import { renderWithProviders } from '@/test-utils';

const state = vi.hoisted(() => ({ vendor: 'opnsense', inventory: vi.fn(), create: vi.fn(), revert: vi.fn(), remove: vi.fn(), download: vi.fn(), toast: vi.fn() }));
const ID = '12345678-1234-4123-8123-123456789abc';
const row = { filename: 'config-owned.xml', timestamp: '2026-09-25T10:00:00Z', size_bytes: 2048, description: 'Owned fixture' };
const notice = /Creating a saved backup is not supported by this adapter/;

vi.mock('@/hooks/use-toast', () => ({ useToast: () => ({ toast: state.toast }) }));
vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api');
  const getById = vi.fn(async (id: string) => ({ data: {
    id, name: 'Owned gateway', vendor: state.vendor, host: 'gateway.example.test', port: 443,
    is_online: true, capabilities: [], settings: {},
  } }));
  const empty = vi.fn().mockResolvedValue({ data: {} });
  return { ...actual, gatewayApi: new Proxy({ getById, getBackups: state.inventory,
    createBackup: state.create, revertBackup: state.revert, deleteBackup: state.remove, downloadConfig: state.download,
  }, { get: (target, name) => name in target ? target[name as keyof typeof target] : empty }),
  sitesApiV2: { list: vi.fn().mockResolvedValue({ data: { items: [] } }) } };
});

beforeEach(() => {
  state.vendor = 'opnsense';
  for (const fn of [state.inventory, state.create, state.revert, state.remove, state.download, state.toast]) fn.mockReset();
  state.inventory.mockResolvedValue({ data: { gateway_id: ID, vendor: state.vendor, backups: [row], count: 1 } });
  state.revert.mockResolvedValue({ data: { success: true } });
  state.remove.mockResolvedValue({ data: { success: true } });
});

async function show() {
  const view = renderWithProviders(<GatewayDetailPage />, {
    initialPath: `/firewall/gateways/${ID}/backups`, routePath: '/firewall/gateways/:id/:tab',
  });
  await screen.findByText('Owned gateway');
  await waitFor(() => expect(view.queryClient.getQueryState(['gateways', ID, 'backups'])?.fetchStatus).toBe('idle'));
  return view;
}

describe('unsupported generic gateway backup creation', () => {
  it.each(['opnsense', 'pfsense'].flatMap((vendor) => ['history', 'empty', 'unavailable'].map((inventory) => ({ vendor, inventory }))))(
    'does not offer creation for $vendor with $inventory inventory', async ({ vendor, inventory }) => {
      state.vendor = vendor;
      if (inventory === 'unavailable') state.inventory.mockRejectedValue(new Error('owned-unavailable'));
      else state.inventory.mockResolvedValue({ data: { gateway_id: ID, vendor, backups: inventory === 'empty' ? [] : [row], count: inventory === 'empty' ? 0 : 1 } });
      await show();
      expect(screen.queryByRole('button', { name: /Create Backup/i })).not.toBeInTheDocument();
      expect(screen.getByText(notice)).toBeInTheDocument();
      expect(screen.getByRole('button', { name: 'Export configuration' })).toBeEnabled();
      expect(state.create).not.toHaveBeenCalled();
      expect(state.download).not.toHaveBeenCalled();
      expect(state.revert).not.toHaveBeenCalled();
      expect(state.remove).not.toHaveBeenCalled();
      expect(state.toast).not.toHaveBeenCalled();
    },
  );

  it.each(['revert', 'delete'] as const)('keeps %s confirmation available for a valid OPNsense history row', async (action) => {
    await show();
    const cell = await screen.findByText(row.filename);
    const buttons = within(cell.closest('tr')!).getAllByRole('button');
    fireEvent.click(buttons[action === 'revert' ? 0 : 1]);
    await waitFor(() => expect(screen.queryByRole('alertdialog') ?? screen.queryByRole('dialog')).toBeInTheDocument());
    expect(state.create).not.toHaveBeenCalled();
    expect(state.revert).not.toHaveBeenCalled();
    expect(state.remove).not.toHaveBeenCalled();
    expect(state.download).not.toHaveBeenCalled();
  });
});

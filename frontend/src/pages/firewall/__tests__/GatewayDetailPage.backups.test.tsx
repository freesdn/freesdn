// SPDX-License-Identifier: AGPL-3.0-only
/** Actual page, table, query state and confirmations; API transport is controlled. */
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { act, fireEvent, screen, waitFor, within } from '@testing-library/react';
import GatewayDetailPage from '../GatewayDetailPage';
import { renderWithProviders } from '@/test-utils';

const state = vi.hoisted(() => ({ inventory: vi.fn(), create: vi.fn(), revert: vi.fn(), remove: vi.fn(), download: vi.fn(), toast: vi.fn() }));
const ID = '12345678-1234-4123-8123-123456789abc';
const row = { filename: 'config-owned.xml', timestamp: '2026-09-25T10:00:00Z', size_bytes: 2048, description: 'Owned fixture' };
const complete = { gateway_id: ID, vendor: 'opnsense', backups: [row], count: 1 };
const unavailable = /Backup history is unavailable/;
const key = ['gateways', ID, 'backups'];

vi.mock('@/hooks/use-toast', () => ({ useToast: () => ({ toast: state.toast }) }));
vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api');
  const getById = vi.fn(async (id: string) => ({ data: {
    id, name: 'Owned gateway', vendor: 'opnsense', host: 'gateway.example.test',
    port: 443, is_online: true, capabilities: [], settings: {},
  } }));
  const empty = vi.fn().mockResolvedValue({ data: {} });
  return { ...actual, gatewayApi: new Proxy({ getById, getBackups: state.inventory,
    createBackup: state.create, revertBackup: state.revert, deleteBackup: state.remove, downloadConfig: state.download,
  }, { get: (target, name) => name in target ? target[name as keyof typeof target] : empty }),
  sitesApiV2: { list: vi.fn().mockResolvedValue({ data: { items: [] } }) } };
});

beforeEach(() => {
  for (const fn of Object.values(state)) fn.mockReset();
  state.inventory.mockResolvedValue({ data: complete });
  state.revert.mockResolvedValue({ data: { success: true } });
  state.remove.mockResolvedValue({ data: { success: true } });
});

async function show() {
  const view = renderWithProviders(<GatewayDetailPage />, {
    initialPath: `/firewall/gateways/${ID}/backups`, routePath: '/firewall/gateways/:id/:tab',
  });
  await screen.findByText('Owned gateway');
  await waitFor(() => expect(view.queryClient.getQueryState(key)?.fetchStatus).toBe('idle'));
  return view;
}

function noWrites() {
  expect(state.create).not.toHaveBeenCalled();
  expect(state.revert).not.toHaveBeenCalled();
  expect(state.remove).not.toHaveBeenCalled();
}

function dialog() {
  return screen.queryByRole('alertdialog') ?? screen.queryByRole('dialog');
}

async function openAction(action: 'revert' | 'delete') {
  const cell = await screen.findByText(row.filename);
  const buttons = within(cell.closest('tr')!).getAllByRole('button');
  fireEvent.click(buttons[action === 'revert' ? 0 : 1]);
  await waitFor(() => expect(dialog()).toBeInTheDocument());
}

describe('gateway backup inventory availability', () => {
  const invalid: [unknown, unknown][] = [
    ['missing body', undefined], ['null body', null], ['empty body', {}],
    ['missing rows', { ...complete, backups: undefined }],
    ['null rows', { ...complete, backups: null }],
    ['wrong gateway', { ...complete, gateway_id: 'other-gateway' }],
    ['missing gateway', { ...complete, gateway_id: undefined }],
    ['missing vendor', { ...complete, vendor: undefined }],
    ['wrong vendor type', { ...complete, vendor: 123 }],
    ['count mismatch', { ...complete, count: 0 }],
    ['count string', { ...complete, count: '1' }],
    ['missing count', { ...complete, count: undefined }],
    ['duplicate names', { ...complete, count: 2, backups: [row, row] }],
    ...[
      ['filename missing', { filename: undefined }], ['filename traversal', { filename: '../config.xml' }],
      ['filename dot', { filename: '.' }], ['filename newline', { filename: 'config.xml\n' }],
      ['filename too long', { filename: 'a'.repeat(256) }],
      ['timestamp missing', { timestamp: undefined }], ['timestamp number', { timestamp: 1 }],
      ['size missing', { size_bytes: undefined }], ['size negative', { size_bytes: -1 }],
      ['size string', { size_bytes: '2048' }], ['size boolean', { size_bytes: true }],
      ['size fractional', { size_bytes: 1.5 }],
      ['description missing', { description: undefined }], ['description object', { description: {} }],
    ].map(([name, change]): [unknown, unknown] => [name, { ...complete, backups: [{ ...row, ...(change as object) }] }]),
  ];
  it.each(invalid)('does not represent %s as available history', async (_name, data) => {
    state.inventory.mockResolvedValue({ data });
    await show();
    expect(await screen.findByText(unavailable)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Revert' })).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Export configuration' })).toBeEnabled();
    noWrites();
  });

  it('shows unavailable for a failed read without reflecting server diagnostics', async () => {
    state.inventory.mockRejectedValue(new Error('private-inventory-diagnostic'));
    await show();
    expect(await screen.findByText(unavailable)).toBeInTheDocument();
    expect(screen.queryByText(/private-inventory-diagnostic/)).not.toBeInTheDocument();
    noWrites();
  });

  it('keeps a valid empty history distinct from an unavailable read', async () => {
    state.inventory.mockResolvedValue({ data: { ...complete, backups: [], count: 0 } });
    await show();
    expect(screen.queryByText(unavailable)).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Revert' })).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Export configuration' })).toBeEnabled();
    noWrites();
  });

  it.each([0, 2048])('displays the normalized size of %s bytes', async (size) => {
    state.inventory.mockResolvedValue({ data: { ...complete, backups: [{ ...row, size_bytes: size }] } });
    await show();
    expect(await screen.findByText(`${size.toLocaleString()} B`)).toBeInTheDocument();
    noWrites();
  });

  it('retries only the inventory read and recovers to valid rows', async () => {
    state.inventory.mockRejectedValueOnce(new Error('unavailable'));
    await show();
    fireEvent.click(await screen.findByRole('button', { name: 'Retry backup history' }));
    expect(await screen.findByText(row.filename)).toBeInTheDocument();
    expect(state.inventory).toHaveBeenCalledTimes(2);
    expect(screen.queryByText(unavailable)).not.toBeInTheDocument();
    expect(state.download).not.toHaveBeenCalled();
    noWrites();
  });

  it('hides cached rows during refresh and after a failed refresh', async () => {
    const view = await show();
    await screen.findByText(row.filename);
    let fail!: (reason: Error) => void;
    state.inventory.mockReturnValue(new Promise((_resolve, reject) => { fail = reject; }));
    let request!: Promise<void>;
    await act(async () => { request = view.queryClient.refetchQueries({ queryKey: key, exact: true }); });
    await waitFor(() => expect(screen.queryByText(row.filename)).not.toBeInTheDocument());
    expect(screen.queryByRole('button', { name: 'Revert' })).not.toBeInTheDocument();
    await act(async () => { fail(new Error('private-refresh-error')); await request; });
    expect(await screen.findByText(unavailable)).toBeInTheDocument();
    expect(screen.queryByText(row.filename)).not.toBeInTheDocument();
    noWrites();
  });

  it.each(['revert', 'delete'] as const)('cancels pending %s when a refresh begins and does not reopen it', async (action) => {
    const view = await show();
    await openAction(action);
    let resolve!: (value: unknown) => void;
    state.inventory.mockReturnValue(new Promise((done) => { resolve = done; }));
    let request!: Promise<void>;
    await act(async () => { request = view.queryClient.refetchQueries({ queryKey: key, exact: true }); });
    await waitFor(() => expect(dialog()).not.toBeInTheDocument());
    await act(async () => { resolve({ data: complete }); await request; });
    await screen.findByText(row.filename);
    expect(dialog()).not.toBeInTheDocument();
    noWrites();
  });

  it.each(['revert', 'delete'] as const)('cancels pending %s when inventory is replaced without a fetch', async (action) => {
    const view = await show();
    await openAction(action);
    await act(async () => { view.queryClient.setQueryData(key, { data: {
      ...complete, backups: [{ ...row, size_bytes: 4096 }],
    } }); });
    await waitFor(() => expect(dialog()).not.toBeInTheDocument());
    noWrites();
  });

  it.each(['revert', 'delete'] as const)('requires confirmation before dispatching a current %s', async (action) => {
    await show();
    await openAction(action);
    noWrites();
    fireEvent.click(within(dialog()!).getByRole('button', { name: action === 'revert' ? 'Revert' : 'Delete' }));
    await waitFor(() => expect(action === 'revert' ? state.revert : state.remove).toHaveBeenCalledWith(ID, row.filename));
    expect(action === 'revert' ? state.remove : state.revert).not.toHaveBeenCalled();
    expect(state.create).not.toHaveBeenCalled();
  });
});

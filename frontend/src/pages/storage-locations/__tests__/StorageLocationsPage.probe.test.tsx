// SPDX-License-Identifier: AGPL-3.0-only
/** Actual page, Axios chain and auth store; controlled network responses only. */
import type { AxiosResponse, InternalAxiosRequestConfig } from 'axios';
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { api } from '@/lib/api/client';
import type { StorageLocation } from '@/lib/api/types';
import { useAuthStore, type User } from '@/stores/authStore';
import StorageLocationsPage from '../StorageLocationsPage';

const notification = vi.hoisted(() => ({ toast: vi.fn() }));
vi.mock('@/hooks/use-toast', () => ({ useToast: () => ({ toast: notification.toast }) }));
const actor = '11111111-1111-4111-8111-111111111111';
const organization = '22222222-2222-4222-8222-222222222222';
const first = '33333333-3333-4333-8333-333333333333';
const second = '44444444-4444-4444-8444-444444444444';
const marker = 'owned-probe-result-marker';
const initialAuth = useAuthStore.getState();
const originalAdapter = api.defaults.adapter;
const clients: QueryClient[] = [];
const requests: InternalAxiosRequestConfig[] = [];
const releases: (() => void)[] = [];
let wait: ((config: InternalAxiosRequestConfig) => Promise<void>) | undefined;
let success = true;
function user(): User {
  return { id: actor, organization_id: organization, role: 'org_admin', is_active: true,
    is_superuser: false, is_org_admin: true, mfa_enabled: false, permissions: [], roles: ['org_admin'],
    username: 'owned', email: 'owned@example.invalid', first_name: 'Owned', last_name: 'Operator', full_name: 'Owned Operator' };
}
function row(id: string): StorageLocation {
  return { id, name: 'Owned location ' + id, description: null, storage_type: 'sftp', is_active: true,
    is_default: false, last_test_at: null, last_test_status: null, last_test_message: null,
    created_at: '2026-09-01T00:00:00Z', updated_at: null };
}
const isProbe = (config: InternalAxiosRequestConfig) => config.method === 'post' && config.url?.endsWith('/test');
const probes = () => requests.filter(isProbe);
beforeEach(() => {
  requests.length = 0; success = true; wait = undefined; notification.toast.mockReset();
  useAuthStore.setState({ user: user(), isAuthenticated: true, _isHydrated: true, _isAuthInitialized: true,
    isLoading: false, mfaPending: false, mfaToken: null, error: null });
  document.cookie = 'freesdn_csrf=owned-probe-page-csrf; path=/';
  api.defaults.adapter = async config => {
    requests.push(config); await wait?.(config);
    let data: unknown;
    if (isProbe(config)) data = { success, message: marker, latency_ms: 1, details: { marker } };
    else if (config.url === '/backups/storage-locations') data = [row(first), row(second)];
    else if (config.url === '/backups/storage-locations/types/supported') data = { types: [] };
    else throw new Error('Unexpected controlled page request');
    return { config, data, status: 200, statusText: 'OK', headers: {} } satisfies AxiosResponse;
  };
});
afterEach(async () => {
  releases.splice(0).forEach(release => release()); await act(async () => { await Promise.resolve(); });
  cleanup(); clients.splice(0).forEach(client => client.clear()); api.defaults.adapter = originalAdapter;
  useAuthStore.setState(initialAuth); vi.restoreAllMocks();
  document.cookie = 'freesdn_csrf=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/';
});
function mount() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  clients.push(client);
  return { client, ...render(<QueryClientProvider client={client}><MemoryRouter><StorageLocationsPage /></MemoryRouter></QueryClientProvider>) };
}
async function action(id = first) {
  const title = await screen.findByRole('heading', { name: 'Owned location ' + id });
  const card = title.closest('.bg-card'); expect(card).not.toBeNull();
  const trigger = card!.querySelector('button[aria-haspopup="menu"]'); expect(trigger).not.toBeNull();
  fireEvent.pointerDown(trigger!, { button: 0, ctrlKey: false, pointerType: 'mouse' });
  const menu = await screen.findByRole('menu');
  return within(menu).getByRole('menuitem', { name: 'Test Connection' });
}
async function start() { fireEvent.click(await action()); }
const result = () => screen.findByRole('dialog', { name: 'Connection Test Passed' });
function hold() {
  let release!: () => void; const pending = new Promise<void>(resolve => { release = resolve; });
  releases.push(release); const entered = vi.fn();
  wait = async config => { if (isProbe(config)) { entered(); await pending; } };
  return { entered, release };
}

it.each(['unchanged', 'user', 'organization', 'logout', 'role', 'inactive', 'cycle'] as const)(
  'retained probe result follows current page identity: %s', async transition => {
    mount(); await start(); await result(); expect(probes()).toHaveLength(1);
    await act(async () => {
      if (transition === 'user') useAuthStore.setState({ user: { ...user(), id: second } });
      if (transition === 'organization') useAuthStore.setState({ user: { ...user(), organization_id: second } });
      if (transition === 'logout') useAuthStore.setState({ user: null, isAuthenticated: false });
      if (transition === 'role') useAuthStore.setState({ user: { ...user(), role: 'viewer', is_org_admin: false } });
      if (transition === 'inactive') useAuthStore.setState({ user: { ...user(), is_active: false } });
      if (transition === 'cycle') { useAuthStore.setState({ user: { ...user(), id: second } }); useAuthStore.setState({ user: user() }); }
      if (transition === 'unchanged') useAuthStore.setState({ user: user() });
    });
    if (transition === 'unchanged') expect(await result()).toBeInTheDocument();
    else await waitFor(() => expect(screen.queryByRole('dialog', { name: 'Connection Test Passed' })).not.toBeInTheDocument());
    expect(probes()).toHaveLength(1);
  },
);

it('preserves an ordinary completed negative result', async () => {
  success = false; mount(); await start();
  const dialog = await screen.findByRole('dialog', { name: 'Connection Test Failed' });
  expect(within(dialog).getByText(marker)).toBeInTheDocument(); expect(probes()).toHaveLength(1);
});

it('unmount aborts the owned pending probe signal without claiming remote rollback', async () => {
  const gate = hold(); const view = mount(); await start(); await waitFor(() => expect(gate.entered).toHaveBeenCalledOnce());
  const request = probes()[0]; expect(request.signal?.aborted).toBe(false);
  try { view.unmount(); expect(request.signal?.aborted).toBe(true); }
  finally { await act(async () => { gate.release(); }); }
});

it('disables all probe actions while another location probe is pending', async () => {
  const gate = hold(); mount(); await start(); await waitFor(() => expect(gate.entered).toHaveBeenCalledOnce());
  try { expect(await action(second)).toHaveAttribute('aria-disabled', 'true'); }
  finally { await act(async () => { gate.release(); }); }
});

it('does not retain completed probe details in the mutation cache', async () => {
  const { client } = mount(); await start(); const dialog = await result();
  fireEvent.click(within(dialog).getByRole('button', { name: 'Close' }));
  expect(JSON.stringify(client.getMutationCache().getAll().map(mutation => mutation.state))).not.toContain(marker);
});

it('does not offer a probe action to a current viewer', async () => {
  useAuthStore.setState({ user: { ...user(), role: 'viewer', is_org_admin: false, roles: ['viewer'] } });
  mount(); expect(await action()).toHaveAttribute('aria-disabled', 'true'); expect(probes()).toHaveLength(0);
});

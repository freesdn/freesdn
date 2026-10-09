// SPDX-License-Identifier: AGPL-3.0-only
/** Real store actions, shared QueryClient and route guard; HTTP responses are controlled. */
import { AxiosError, type AxiosResponse, type InternalAxiosRequestConfig } from 'axios';
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { ProtectedRoute } from '@/components/auth/ProtectedRoute';
import { api } from '@/lib/api/client';
import type { StorageLocation } from '@/lib/api/types';
import { queryClient } from '@/lib/queryClient';
import { useAuthStore, type User } from '@/stores/authStore';
import StorageLocationsPage from '../StorageLocationsPage';

const notification = vi.hoisted(() => ({ toast: vi.fn() }));
vi.mock('@/hooks/use-toast', () => ({ useToast: () => ({ toast: notification.toast }) }));
const actor = '11111111-1111-4111-8111-111111111111';
const organization = '22222222-2222-4222-8222-222222222222';
const location = '33333333-3333-4333-8333-333333333333';
const other = '44444444-4444-4444-8444-444444444444';
const oldName = 'Owned previous-context storage';
const newName = 'Owned current-context storage';
const probeMarker = 'owned-auth-integration-probe';
const errorMarker = 'owned-auth-integration-old-delete-error';
const listURL = '/backups/storage-locations';
const originalAdapter = api.defaults.adapter;
const initialAuth = useAuthStore.getState();
const requests: InternalAxiosRequestConfig[] = [];
const releases: (() => void)[] = [];
let serverUser: User;
let pause: ((config: InternalAxiosRequestConfig) => Promise<void>) | undefined;
let deleteError = false;
function user(): User {
  return { id: actor, organization_id: organization, role: 'org_admin', is_active: true,
    is_superuser: false, is_org_admin: true, mfa_enabled: false, permissions: ['backups:read'], roles: ['org_admin'],
    username: 'owned', email: 'owned@example.invalid', first_name: 'Owned', last_name: 'Operator', full_name: 'Owned Operator' };
}
function row(current: User): StorageLocation {
  const same = current.id === actor && current.organization_id === organization;
  return { id: same ? location : other, name: same ? oldName : newName, description: null,
    storage_type: 'sftp', is_active: true, is_default: false, last_test_at: null, last_test_status: null,
    last_test_message: null, created_at: '2026-09-01T00:00:00Z', updated_at: null };
}
const list = (config: InternalAxiosRequestConfig) => config.method === 'get' && config.url === listURL;
const probe = (config: InternalAxiosRequestConfig) => config.method === 'post' && config.url?.endsWith('/test');
const deletion = (config: InternalAxiosRequestConfig) => config.method === 'delete';
function gate(match: (config: InternalAxiosRequestConfig) => boolean | undefined) {
  let release!: () => void;
  const pending = new Promise<void>(resolve => { release = resolve; });
  releases.push(release);
  const entered = vi.fn();
  pause = async config => { if (match(config)) { entered(config); await pending; } };
  return { release, entered };
}
beforeEach(() => {
  queryClient.clear(); requests.length = 0; pause = undefined; deleteError = false; notification.toast.mockReset();
  serverUser = user();
  useAuthStore.setState({ user: user(), isAuthenticated: true, _isHydrated: true, _isAuthInitialized: true,
    isLoading: false, mfaPending: false, mfaToken: null, error: null });
  document.cookie = 'freesdn_csrf=owned-auth-integration-csrf; path=/';
  api.defaults.adapter = async config => {
    requests.push(config);
    const atEntry = { ...serverUser };
    await pause?.(config);
    let data: unknown;
    if (config.url === '/auth/logout' || config.url === '/auth/refresh') data = {};
    else if (config.url === '/auth/me') data = atEntry;
    else if (list(config)) data = [row(atEntry)];
    else if (config.url === listURL + '/types/supported') data = { types: [] };
    else if (probe(config)) data = { success: true, message: probeMarker, latency_ms: 1, details: {} };
    else if (deletion(config)) {
      if (deleteError) {
        const response = { config, status: 400, statusText: 'Bad Request', data: { detail: errorMarker }, headers: {} };
        throw new AxiosError('Controlled old-context failure', 'ERR_BAD_REQUEST', config, undefined, response);
      }
      data = {};
    } else throw new Error('Unexpected controlled integration request: ' + config.method + ' ' + config.url);
    return { config, data, status: 200, statusText: 'OK', headers: {} } satisfies AxiosResponse;
  };
});
afterEach(async () => {
  releases.splice(0).forEach(release => release()); await act(async () => { await Promise.resolve(); });
  cleanup(); queryClient.clear(); api.defaults.adapter = originalAdapter;
  useAuthStore.setState(initialAuth); useAuthStore.persist.clearStorage(); vi.restoreAllMocks();
  document.cookie = 'freesdn_csrf=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/';
});
function mount() {
  return render(<QueryClientProvider client={queryClient}>
    <MemoryRouter initialEntries={['/storage-locations']}><Routes>
      <Route path="/storage-locations" element={<ProtectedRoute requiredPermissions={['backups:read']}><StorageLocationsPage /></ProtectedRoute>} />
      <Route path="/login" element={<h1>Owned login destination</h1>} />
      <Route path="/unauthorized" element={<h1>Owned unauthorized destination</h1>} />
    </Routes></MemoryRouter>
  </QueryClientProvider>);
}
async function action(name: string) {
  const title = await screen.findByRole('heading', { name: oldName });
  const trigger = title.closest('.bg-card')?.querySelector('button[aria-haspopup="menu"]');
  expect(trigger).toBeTruthy();
  fireEvent.pointerDown(trigger!, { button: 0, ctrlKey: false, pointerType: 'mouse' });
  fireEvent.click(within(await screen.findByRole('menu')).getByRole('menuitem', { name }));
}
async function refresh(transition: 'same' | 'user' | 'organization') {
  serverUser = { ...user(), ...(transition === 'user' ? { id: other } : {}),
    ...(transition === 'organization' ? { organization_id: other } : {}) };
  await act(async () => {
    expect(await useAuthStore.getState().refreshSession()).toBe(true);
    await useAuthStore.getState().fetchCurrentUser();
  });
  expect(requests.filter(config => config.url === '/auth/refresh')).toHaveLength(1);
  expect(requests.filter(config => config.url === '/auth/me')).toHaveLength(1);
  expect(useAuthStore.getState().user?.id).toBe(serverUser.id);
  expect(useAuthStore.getState().user?.organization_id).toBe(serverUser.organization_id);
}

it.each(['pending-probe', 'retained-probe', 'pending-list'] as const)(
  'real logout clears singleton cache and protected route: %s', async kind => {
    const held = kind === 'retained-probe' ? undefined : gate(kind === 'pending-list' ? list : probe);
    mount();
    if (kind !== 'pending-list') await action('Test Connection');
    if (held) await waitFor(() => expect(held.entered).toHaveBeenCalledOnce());
    else expect(await screen.findByRole('dialog', { name: 'Connection Test Passed' })).toBeInTheDocument();
    await act(async () => { await useAuthStore.getState().logout(); });
    expect(await screen.findByRole('heading', { name: 'Owned login destination' })).toBeInTheDocument();
    expect(requests.filter(config => config.url === '/auth/logout')).toHaveLength(1);
    if (kind === 'pending-probe') expect(requests.find(probe)?.signal?.aborted).toBe(true);
    await act(async () => { held?.release(); });
    expect(screen.queryByText(probeMarker)).not.toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: oldName })).not.toBeInTheDocument();
    expect(queryClient.getQueryCache().getAll()).toHaveLength(0);
    expect(queryClient.getMutationCache().getAll()).toHaveLength(0);
  },
);

it.each(['same', 'user', 'organization'] as const)(
  'loaded list follows actual refresh and current-user action: %s', async transition => {
    mount(); expect(await screen.findByRole('heading', { name: oldName })).toBeInTheDocument();
    await refresh(transition);
    if (transition === 'same') expect(screen.getByRole('heading', { name: oldName })).toBeInTheDocument();
    else {
      await waitFor(() => expect(screen.queryByRole('heading', { name: oldName })).not.toBeInTheDocument());
      expect(await screen.findByRole('heading', { name: newName })).toBeInTheDocument();
    }
  },
);

it.each(['same', 'user', 'organization'] as const)(
  'queued old list cannot populate refreshed identity: %s', async transition => {
    const held = gate(list); mount(); await waitFor(() => expect(held.entered).toHaveBeenCalledOnce());
    await refresh(transition);
    await act(async () => { held.release(); });
    const expected = transition === 'same' ? oldName : newName;
    expect(await screen.findByRole('heading', { name: expected })).toBeInTheDocument();
    if (transition !== 'same') expect(screen.queryByRole('heading', { name: oldName })).not.toBeInTheDocument();
  },
);

it.each([
  ['user', 'success'], ['organization', 'success'], ['user', 'error'], ['organization', 'error'],
] as const)('late delete completion does not notify a new identity: %s %s', async (transition, outcome) => {
  deleteError = outcome === 'error'; const held = gate(deletion); mount(); await action('Delete');
  const dialog = await screen.findByRole('dialog', { name: 'Delete Storage Location' });
  fireEvent.click(within(dialog).getByRole('button', { name: 'Delete' }));
  await waitFor(() => expect(held.entered).toHaveBeenCalledOnce());
  await refresh(transition); notification.toast.mockClear();
  let unsubscribe = () => {};
  const settled = new Promise<void>(resolve => {
    unsubscribe = queryClient.getMutationCache().subscribe(event => {
      if (event.type === 'updated' && ['success', 'error'].includes(event.mutation.state.status)) resolve();
    });
  });
  try { await act(async () => { held.release(); await settled; }); }
  finally { unsubscribe(); }
  // Observe real late callback behavior; a sent delete may already have committed.
  expect(requests.filter(deletion)).toHaveLength(1);
  expect(notification.toast).not.toHaveBeenCalled();
  expect(screen.queryByRole('dialog', { name: 'Delete Storage Location' })).not.toBeInTheDocument();
});

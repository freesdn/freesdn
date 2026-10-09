// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/** Real page, Axios and Zustand; only network responses and browser saves are controlled. */
import type { AxiosResponse, InternalAxiosRequestConfig } from 'axios';
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { afterEach, beforeEach, expect, vi } from 'vitest';
import { api } from '@/lib/api/client';
import { useAuthStore, type User } from '@/stores/authStore';
import BackupsPage from '../BackupsPage';

export const actorId = '11111111-1111-4111-8111-111111111111';
export const organizationId = '22222222-2222-4222-8222-222222222222';
export const backupId = '33333333-3333-4333-8333-333333333333';
export const otherId = '44444444-4444-4444-8444-444444444444';
export const accountPassword = 'Owned current account password';
export const archivePassphrase = 'Owned queued archive passphrase';
export const proof = 'synthetic-page-proof';
export const mfaCode = '123456';
export const principals = ['super_admin', 'org_admin', 'site_admin', 'viewer', 'inactive_super', 'missing'] as const;

export function identity(principal: string): User | null {
  if (principal === 'missing') return null;
  const role = principal === 'inactive_super' ? 'super_admin' : principal;
  return { id: actorId, username: 'owned-actor', email: 'owned@example.invalid',
    first_name: 'Owned', last_name: 'Actor', full_name: 'Owned Actor', organization_id: organizationId,
    role, is_active: principal !== 'inactive_super', is_superuser: role === 'super_admin',
    is_org_admin: ['org_admin', 'super_admin'].includes(role), mfa_enabled: false,
    permissions: [], roles: [role] };
}
export function row(secrets: boolean, id = backupId, integrity: 'recorded' | 'legacy_unverified' | 'invalid' = 'recorded') {
  return { id, name: 'Owned archive ' + id, backup_type: 'full', status: 'completed', progress: 100,
    storage_type: 'local', file_size: 3, created_at: '2026-09-01T00:00:00Z',
    is_encrypted: true, include_secrets: secrets, artifact_integrity: integrity };
}
export function installPageFixture() {
  const originalAuth = useAuthStore.getState(); const oldAdapter = api.defaults.adapter;
  const originalCreate = Object.getOwnPropertyDescriptor(URL, 'createObjectURL');
  const originalRevoke = Object.getOwnPropertyDescriptor(URL, 'revokeObjectURL');
  const clients: QueryClient[] = []; const interceptorIds: number[] = []; const releases: (() => void)[] = [];
  const state = {
    backups: [row(false)], requests: [] as InternalAxiosRequestConfig[],
    created: vi.fn(() => 'blob:owned-archive'), revoked: vi.fn(), clicked: vi.fn(),
    method: 'local' as 'local' | 'ldap' | 'oidc', mfaRequired: false,
    adapterWait: undefined as ((config: InternalAxiosRequestConfig) => Promise<void>) | undefined,
    customAnswer: undefined as ((config: InternalAxiosRequestConfig) => AxiosResponse | undefined) | undefined,
  };
  const reply = (config: InternalAxiosRequestConfig, data: unknown, status = 200, integrity = 'verified'): AxiosResponse => ({
    config, data, status, statusText: 'OK', headers: { 'x-freesdn-artifact-integrity': integrity },
  });
  const answer = (config: InternalAxiosRequestConfig) => {
    const custom = state.customAnswer?.(config); if (custom) return custom;
    const path = config.url!;
    if (path.startsWith('/backups?')) return reply(config, { items: state.backups, total: state.backups.length });
    if (path.startsWith('/backups/stats?')) return reply(config, { total_backups: state.backups.length, completed_backups: state.backups.length });
    if (path === '/sites') return reply(config, { items: [] });
    if (path.startsWith('/backups/schedules?') || path === '/backups/storage-locations' || path.includes('/storage-locations/types/')) return reply(config, []);
    if (path.startsWith('/auth/vault-export/requirements?')) return reply(config, { method: state.method, mfa_required: state.mfaRequired, oidc_redirect_uri: null });
    if (path === '/auth/vault-export/identity/ldap') return reply(config, { identity_token: 'synthetic-page-identity', expires_at: Math.floor(Date.now() / 1000) + 100 });
    if (path.startsWith('/auth/vault-export/authorize/')) return reply(config, { proof });
    if (path.endsWith('/vault-observation')) return reply(config, { operation: 'download_legacy', proof: 'synthetic-page-observed', artifact_integrity: 'legacy_unverified', observed_identity: { version: 1, bytes: 3, sha256: 'a'.repeat(64) }, authentication_expires_at: Math.floor(Date.now() / 1000) + 100 });
    if (path.endsWith('/download') || path.endsWith('/vault-download')) return reply(config, new Blob(['abc']), 200, path.endsWith('/vault-download') ? 'legacy_unverified' : 'verified');
    if ((path === '/backups/' || path === '/backups') && config.method === 'post') return reply(config, { id: backupId, include_secrets: true, status: 'completed' }, 201);
    throw new Error('Unexpected owned page request');
  };
  beforeEach(() => {
    vi.resetAllMocks(); state.backups = [row(false)]; state.requests.length = 0;
    state.method = 'local'; state.mfaRequired = false; state.adapterWait = undefined; state.customAnswer = undefined;
    state.created.mockReturnValue('blob:owned-archive');
    Object.defineProperty(URL, 'createObjectURL', { value: state.created, configurable: true, writable: true });
    Object.defineProperty(URL, 'revokeObjectURL', { value: state.revoked, configurable: true, writable: true });
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(state.clicked);
    useAuthStore.setState({ user: identity('super_admin'), isAuthenticated: true, _isHydrated: true,
      _isAuthInitialized: true, isLoading: false, mfaPending: false, mfaToken: null, error: null });
    document.cookie = 'freesdn_csrf=synthetic-page-csrf; path=/';
    api.defaults.adapter = async config => {
      state.requests.push(config); await state.adapterWait?.(config); return answer(config);
    };
  });
  afterEach(async () => {
    cleanup(); await Promise.resolve(); releases.splice(0).forEach(release => release());
    interceptorIds.splice(0).forEach(id => api.interceptors.request.eject(id));
    clients.splice(0).forEach(client => client.clear()); api.defaults.adapter = oldAdapter;
    useAuthStore.setState(originalAuth); vi.restoreAllMocks();
    document.cookie = 'freesdn_csrf=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/';
    for (const [name, descriptor] of [['createObjectURL', originalCreate], ['revokeObjectURL', originalRevoke]] as const) {
      if (descriptor) Object.defineProperty(URL, name, descriptor); else Reflect.deleteProperty(URL, name);
    }
  });
  return { state, reply,
    mount(principal = 'super_admin') {
      const user = identity(principal); useAuthStore.setState({ user, isAuthenticated: user !== null });
      const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
      clients.push(client);
      const view = render(<QueryClientProvider client={client}><MemoryRouter initialEntries={['/backups']}>
        <Routes><Route path="/backups/:tab?" element={<BackupsPage />} /></Routes>
      </MemoryRouter></QueryClientProvider>);
      return { client, ...view };
    },
    gate(predicate: (config: InternalAxiosRequestConfig) => boolean, boundary: 'before-dispatch' | 'after-dispatch') {
      let release!: () => void; const pending = new Promise<void>(resolve => { release = resolve; });
      releases.push(release); const reached = vi.fn();
      const wait = async (config: InternalAxiosRequestConfig) => { if (predicate(config)) { reached(); await pending; } };
      if (boundary === 'before-dispatch') interceptorIds.push(api.interceptors.request.use(async config => { await wait(config); return config; }));
      else state.adapterWait = wait;
      return { release, reached };
    },
  };
}
export const isDownload = (config: InternalAxiosRequestConfig) => /\/(download|vault-download)$/.test(config.url ?? '');
export const isCreate = (config: InternalAxiosRequestConfig) => config.method === 'post' && config.url === '/backups/';
export async function selectArchive(id = backupId) {
  fireEvent.click(await screen.findByRole('checkbox', { name: 'Select Owned archive ' + id }));
}
export async function openRowMenu(id = backupId) {
  // Current list trigger is icon-only. Open it through its actual menu behavior;
  // the lack of an accessible label remains a separate source concern.
  const checkbox = await screen.findByRole('checkbox', { name: 'Select Owned archive ' + id });
  const card = checkbox.closest('.bg-card'); expect(card).not.toBeNull();
  const trigger = card!.querySelector('button[aria-haspopup="menu"]'); expect(trigger).not.toBeNull();
  fireEvent.pointerDown(trigger!, { button: 0, ctrlKey: false, pointerType: 'mouse' });
  return screen.findByRole('menu');
}
export async function openDownload(id = backupId) {
  const menu = await openRowMenu(id); fireEvent.click(within(menu).getByRole('menuitem', { name: /^Download$/ }));
}
export async function submitCreate() {
  fireEvent.click(await screen.findByRole('button', { name: 'New Backup' }));
  const dialog = await screen.findByRole('dialog', { name: 'Create New Backup' });
  fireEvent.change(within(dialog).getByLabelText('Backup Name'), { target: { value: 'Owned queued vault' } });
  fireEvent.click(within(dialog).getByRole('switch', { name: /Full (backup|vault)/ }));
  fireEvent.change(within(dialog).getByLabelText('Backup passphrase'), { target: { value: archivePassphrase } });
  fireEvent.click(within(dialog).getByRole('button', { name: 'Create Backup' }));
  await screen.findByRole('dialog', { name: 'Confirm vault export' });
}
export async function readRequirements(legacy = false) {
  const dialog = await screen.findByRole('dialog', { name: 'Confirm vault export' });
  if (legacy) fireEvent.click(within(dialog).getByRole('checkbox', { name: 'I understand the legacy archive limitation.' }));
  fireEvent.click(within(dialog).getByRole('button', { name: 'Check confirmation requirements' }));
  await within(dialog).findByLabelText('Current account password'); return dialog;
}
export async function confirm(operation: 'create' | 'download', legacy = false, mfa = false) {
  const dialog = await readRequirements(legacy);
  fireEvent.change(within(dialog).getByLabelText('Current account password'), { target: { value: accountPassword } });
  if (mfa) fireEvent.change(within(dialog).getByLabelText('Authenticator or remaining recovery code'), { target: { value: mfaCode } });
  fireEvent.click(within(dialog).getByRole('button', { name: operation === 'create' ? 'Confirm and create vault' : 'Confirm and download vault' }));
}
export function assertNoSecretCache(client: QueryClient) {
  const retained = JSON.stringify({ queries: client.getQueryCache().getAll().map(query => ({ key: query.queryKey, state: query.state })),
    mutations: client.getMutationCache().getAll().map(mutation => mutation.state) });
  for (const secret of [accountPassword, archivePassphrase, proof, 'synthetic-page-observed', 'synthetic-page-identity']) expect(retained).not.toContain(secret);
  expect(client.getMutationCache().getAll()).toHaveLength(0);
}
export async function completedDownload(state: ReturnType<typeof installPageFixture>['state']) {
  await waitFor(() => expect(state.revoked).toHaveBeenCalledWith('blob:owned-archive'));
  expect(state.created).toHaveBeenCalledOnce(); expect(state.clicked).toHaveBeenCalledOnce();
}

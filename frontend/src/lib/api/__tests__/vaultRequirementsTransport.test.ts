// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/** Actual Axios transport with controlled adapters; no server/browser proof. */
import axios, { AxiosError, type InternalAxiosRequestConfig } from 'axios';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { useAuthStore } from '@/stores/authStore';
import { api } from '../client';
import { beginVaultExport, type VaultBrowserIntent } from '../vaultExportTransport';
vi.mock('@/demo/mode', () => ({ isDemoMode: false }));
vi.mock('@/stores/authStore', async () => {
  const { createStore } = await import('zustand/vanilla');
  return { useAuthStore: createStore(() => ({ user: null, isAuthenticated: false, _isHydrated: true,
    _isAuthInitialized: true, isLoading: false, mfaPending: false })) };
});
const actor = '11111111-1111-4111-8111-111111111111';
const org = '22222222-2222-4222-8222-222222222222';
const backup = '33333333-3333-4333-8333-333333333333';
const scopes: ReturnType<typeof beginVaultExport>[] = [];
let previous: typeof api.defaults.adapter;
const requests: InternalAxiosRequestConfig[] = [];
function action(kind: 'create' | 'download_recorded' | 'observe_legacy' = 'create') {
  const intent: VaultBrowserIntent = kind === 'create' ? { kind, backup: { name: 'Owned', include_secrets: true, passphrase: 'synthetic-passphrase' } }
    : kind === 'download_recorded' ? { kind, backup_id: backup } : { kind, backup_id: backup, legacy_acknowledged: true };
  const scope = beginVaultExport(intent); scopes.push(scope); return scope;
}
function answer(data: unknown) {
  api.defaults.adapter = async config => { requests.push(config); return { config, data, headers: {}, status: 200, statusText: 'OK' }; };
}
beforeEach(() => {
  previous = api.defaults.adapter; requests.length = 0;
  useAuthStore.setState({ isAuthenticated: true, _isHydrated: true, _isAuthInitialized: true, isLoading: false, mfaPending: false,
    user: { id: actor, organization_id: org, role: 'super_admin', is_active: true, is_superuser: true, is_org_admin: true, mfa_enabled: false, permissions: ['*'], roles: ['super_admin'] } as never });
});
afterEach(() => { scopes.splice(0).forEach(scope => scope.dispose()); api.defaults.adapter = previous; vi.restoreAllMocks(); });
describe('current factor requirements transport', () => {
  it.each(['create', 'download_recorded', 'observe_legacy'] as const)('reads %s requirements once without sending the secret intent or granting a proof', async kind => {
    answer({ method: 'local', mfa_required: true, oidc_redirect_uri: null }); const scope = action(kind);
    expect(await scope.requirements()).toEqual({ method: 'local', mfa_required: true, oidc_redirect_uri: null });
    expect(requests).toHaveLength(1); expect(requests[0].url).toBe('/auth/vault-export/requirements?action=' + (kind === 'create' ? 'create' : 'download'));
    expect(requests[0].data).toBeUndefined(); expect(requests[0].headers.get('X-FreeSDN-Vault-Actor')).toBe(actor);
    expect(requests[0].headers.get('X-FreeSDN-Vault-Organization')).toBe(org); expect(requests[0].headers.has('X-FreeSDN-Vault-Proof')).toBe(false);
    await expect(scope.requirements()).rejects.toMatchObject({ outcome: 'not-issued' });
    await expect(kind === 'create' ? scope.create() : scope.download()).rejects.toMatchObject({ outcome: 'not-issued' }); expect(requests).toHaveLength(1);
  });
  it.each(['local', 'ldap', 'oidc'] as const)('accepts bounded %s hints without consulting stale user-store MFA', async method => {
    const value = { method, mfa_required: true, oidc_redirect_uri: method === 'oidc' ? 'https://owned.example/vault-export-callback.html' : null };
    answer(value); expect(await action().requirements()).toEqual(value);
  });
  it.each(['missing', 'method', 'boolean', 'extra', 'local-callback', 'http', 'userinfo', 'query', 'fragment', 'callback-bound'])('refuses malformed hint %s and closes the scope', async fault => {
    const value: Record<string, unknown> = { method: 'oidc', mfa_required: true, oidc_redirect_uri: 'https://owned.example/vault-export-callback.html' };
    if (fault === 'missing') delete value.mfa_required; if (fault === 'method') value.method = 'saml'; if (fault === 'boolean') value.mfa_required = 'true';
    if (fault === 'extra') value.proof = 'private-proof'; if (fault === 'local-callback') value.method = 'local';
    if (fault === 'http') value.oidc_redirect_uri = 'http://owned.example/cb'; if (fault === 'userinfo') value.oidc_redirect_uri = 'https://u:p@owned.example/cb';
    if (fault === 'query') value.oidc_redirect_uri += '?state=x'; if (fault === 'fragment') value.oidc_redirect_uri += '#x';
    if (fault === 'callback-bound') value.oidc_redirect_uri = 'x'.repeat(2049);
    answer(value); const scope = action(); await expect(scope.requirements()).rejects.toMatchObject({ outcome: 'unconfirmed' });
    await expect(scope.authorizeLocal('password')).rejects.toMatchObject({ outcome: 'not-issued' }); expect(requests).toHaveLength(1);
  });
  it('does not refresh or replay a failed requirements read', async () => {
    const refresh = vi.spyOn(axios, 'post').mockResolvedValue({});
    api.defaults.adapter = async config => { requests.push(config); throw new AxiosError('private', 'ERR_BAD_REQUEST', config, undefined,
      { config, data: { private: 'hidden' }, status: 401, statusText: 'Unauthorized', headers: {} }); };
    const scope = action(); await expect(scope.requirements()).rejects.toMatchObject({ outcome: 'unconfirmed', status: 401 });
    expect(requests).toHaveLength(1); expect(refresh).not.toHaveBeenCalled();
  });
  it('withholds a hint arriving after an account change', async () => {
    let finish!: () => void; const gate = new Promise<void>(yes => { finish = yes; });
    api.defaults.adapter = async config => { requests.push(config); await gate; return { config, status: 200, statusText: 'OK', headers: {}, data: { method: 'local', mfa_required: false, oidc_redirect_uri: null } }; };
    const pending = action().requirements(); const check = expect(pending).rejects.toMatchObject({ outcome: 'unconfirmed' });
    await vi.waitFor(() => expect(requests).toHaveLength(1)); useAuthStore.setState({ user: null, isAuthenticated: false }); finish(); await check;
  });
});

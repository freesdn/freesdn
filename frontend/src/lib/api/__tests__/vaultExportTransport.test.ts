// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/** Real Axios/Zustand with controlled adapters; no live browser/IdP/SQL proof. */
import axios, { AxiosError, type AxiosResponse, type InternalAxiosRequestConfig } from 'axios';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { useAuthStore, type User } from '@/stores/authStore';
import { api } from '../client';
import { beginVaultExport, VaultTransportError, type VaultBrowserIntent } from '../vaultExportTransport';

const mode = vi.hoisted(() => ({ demo: false }));
vi.mock('@/demo/mode', () => ({ get isDemoMode() { return mode.demo; } }));
vi.mock('@/stores/authStore', async () => {
  const { createStore } = await import('zustand/vanilla');
  return { useAuthStore: createStore(() => ({ user: null, isAuthenticated: false, _isHydrated: true,
    _isAuthInitialized: true, isLoading: false, mfaPending: false })) };
});
const actor = '11111111-1111-4111-8111-111111111111';
const org = '22222222-2222-4222-8222-222222222222';
const backupId = '33333333-3333-4333-8333-333333333333';
const other = '44444444-4444-4444-8444-444444444444';
const original = (): VaultBrowserIntent => ({ kind: 'create', backup: { name: 'Owned vault', include_secrets: true,
  passphrase: 'synthetic-passphrase-only', device_ids: [backupId] } });
const artifact = { version: 1 as const, bytes: 3, sha256: 'a'.repeat(64) };
const expiry = () => Math.floor(Date.now() / 1000) + 100;
const actions: ReturnType<typeof beginVaultExport>[] = [];
let oldAdapter: typeof api.defaults.adapter;
const observed: InternalAxiosRequestConfig[] = [];
function user(): User {
  return { id: actor, organization_id: org, role: 'super_admin', is_active: true, is_superuser: true,
    is_org_admin: true, mfa_enabled: true, permissions: ['*'], roles: ['super_admin'], email: 'owned@example.invalid',
    username: 'owned', first_name: 'Owned', last_name: 'Operator', full_name: 'Owned Operator' };
}
function scope(value: VaultBrowserIntent = original()) { const v = beginVaultExport(value); actions.push(v); return v; }
function response(config: InternalAxiosRequestConfig, data: unknown, status = 200, integrity = 'verified'): AxiosResponse {
  return { config, data, status, statusText: 'OK', headers: { 'x-freesdn-artifact-integrity': integrity } };
}
function answer(config: InternalAxiosRequestConfig): AxiosResponse {
  observed.push(config);
  const url = config.url!;
  if (url.endsWith('/oidc/start')) return response(config, { authorize_url: 'https://idp.example.invalid/auth?state=synthetic-state', state: 'synthetic-state', expires_at: expiry() });
  if (url.endsWith('/ldap') || url.endsWith('/oidc/complete')) return response(config, { identity_token: 'synthetic-identity', expires_at: expiry() });
  if (url.includes('/authorize/')) return response(config, { proof: 'synthetic-proof' });
  if (url.endsWith('/vault-observation')) return response(config, { operation: 'download_legacy', proof: 'synthetic-legacy-proof', artifact_integrity: 'legacy_unverified', observed_identity: artifact, authentication_expires_at: expiry() });
  if (url.endsWith('/download') || url.endsWith('/vault-download')) return response(config, new Blob(['abc']), 200, url.endsWith('/vault-download') ? 'legacy_unverified' : 'verified');
  return response(config, { id: backupId, include_secrets: true, status: 'completed', name: 'Owned vault' }, 201);
}
function change(which: string) {
  const u = user();
  if (which === 'logout') useAuthStore.setState({ user: null, isAuthenticated: false });
  else if (which === 'loading') useAuthStore.setState({ isLoading: true });
  else if (which === 'mfa-pending') useAuthStore.setState({ mfaPending: true });
  else if (which === 'user' || which === 'cycle') useAuthStore.setState({ user: { ...u, id: other } });
  else if (which === 'organization') useAuthStore.setState({ user: { ...u, organization_id: other } });
  else if (which === 'role') useAuthStore.setState({ user: { ...u, role: 'viewer' } });
  else if (which === 'inactive') useAuthStore.setState({ user: { ...u, is_active: false } });
  else if (which === 'mfa-state') useAuthStore.setState({ user: { ...u, mfa_enabled: false } });
  if (which === 'cycle') useAuthStore.setState({ user: u });
}
beforeEach(() => {
  oldAdapter = api.defaults.adapter; observed.length = 0; mode.demo = false;
  api.defaults.adapter = async config => answer(config);
  useAuthStore.setState({ user: user(), isAuthenticated: true, _isHydrated: true, _isAuthInitialized: true,
    isLoading: false, mfaPending: false });
  document.cookie = 'freesdn_csrf=synthetic-csrf; path=/';
});
afterEach(() => {
  actions.splice(0).forEach(a => a.dispose()); api.defaults.adapter = oldAdapter;
  vi.restoreAllMocks(); vi.useRealTimers(); mode.demo = false;
  document.cookie = 'freesdn_csrf=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/';
});

describe('vault workflow transport', () => {
  it.each(['local', 'ldap', 'oidc'])('completes %s factors before one creation and retains original intent', async factor => {
    const input = original(); const expected = JSON.stringify(input); const a = scope(input);
    if (input.kind === 'create') { input.backup.name = 'later edit'; input.backup.device_ids!.push(other); }
    if (factor === 'local') await a.authorizeLocal('synthetic-password', '123456');
    if (factor === 'ldap') { await a.confirmLdap('synthetic-password'); await a.authorizeExternal('123456'); }
    if (factor === 'oidc') {
      expect(await a.beginOidc()).toMatchObject({ state: 'synthetic-state' });
      await a.completeOidc('synthetic-state', 'synthetic-code'); await a.authorizeExternal('123456');
    }
    const result = await a.create(); expect(result).toEqual({ id: backupId, status: 'completed' });
    expect(observed.length).toBe(factor === 'local' ? 2 : factor === 'ldap' ? 3 : 4);
    for (const request of observed.slice(0, -1)) expect(JSON.parse(request.data).intent).toEqual(JSON.parse(expected));
    expect(JSON.parse(observed[observed.length - 1].data)).toEqual(JSON.parse(expected).backup);
    for (const request of observed) {
      expect(request.headers.get('X-FreeSDN-Vault-Actor')).toBe(actor);
      expect(request.headers.get('X-FreeSDN-Vault-Organization')).toBe(org);
      expect(request.headers.get('X-CSRF-Token')).toBe('synthetic-csrf');
      expect(request.withCredentials).toBe(true); expect(request.timeout).toBe(130000);
      expect(request.url).not.toContain('synthetic-');
    }
    expect(observed[observed.length - 1].headers.get('X-FreeSDN-Vault-Proof')).toBe('synthetic-proof');
    const count = observed.length;
    await expect(a.create()).rejects.toMatchObject({ outcome: 'not-issued' });
    expect(observed).toHaveLength(count);
  });

  it.each(['recorded', 'legacy'])('downloads %s bytes only through its explicit bound sequence', async kind => {
    const a = scope(kind === 'recorded' ? { kind: 'download_recorded', backup_id: backupId }
      : { kind: 'observe_legacy', backup_id: backupId, legacy_acknowledged: true });
    await expect(a.download()).rejects.toMatchObject({ outcome: 'not-issued' });
    await a.authorizeLocal('synthetic-password');
    if (kind === 'legacy') {
      await expect(a.download()).rejects.toMatchObject({ outcome: 'not-issued' });
      const observation = await a.observeLegacy();
      expect(observation).toMatchObject({ artifact_integrity: 'legacy_unverified', observed_identity: artifact });
      expect(observation).not.toHaveProperty('proof'); observation.observed_identity.bytes = 99;
    }
    const result = await a.download();
    expect(await result.blob.text()).toBe('abc');
    expect(result.artifact_integrity).toBe(kind === 'legacy' ? 'legacy_unverified' : 'verified');
    expect(observed[observed.length - 1].headers.get('X-FreeSDN-Vault-Proof')).toBe(kind === 'legacy' ? 'synthetic-legacy-proof' : 'synthetic-proof');
    if (kind === 'legacy') expect(JSON.parse(observed[observed.length - 1].data)).toEqual({ legacy_acknowledged: true, observed_identity: artifact });
    const count = observed.length;
    await expect(a.download()).rejects.toMatchObject({ outcome: 'not-issued' }); expect(observed).toHaveLength(count);
  });

  it.each(['user', 'organization', 'role', 'inactive', 'logout', 'loading', 'mfa-pending', 'mfa-state', 'cycle'])(
    'refuses a queued request after %s', async which => {
      const a = scope(); change(which);
      await expect(a.authorizeLocal('synthetic-password')).rejects.toMatchObject({ outcome: 'not-issued' });
      expect(observed).toHaveLength(0);
    });
  it.each(['user', 'organization', 'role', 'inactive', 'logout', 'loading', 'mfa-pending', 'mfa-state', 'cycle'])(
    'withholds a late factor response after %s without claiming rollback', async which => {
      let finish!: () => void; const gate = new Promise<void>(resolve => { finish = resolve; });
      const adapter = vi.fn(async (config: InternalAxiosRequestConfig) => { await gate; return answer(config); }); api.defaults.adapter = adapter;
      const a = scope(); const pending = a.authorizeLocal('synthetic-password');
      const check = expect(pending).rejects.toMatchObject({ outcome: 'unconfirmed' });
      await vi.waitFor(() => expect(adapter).toHaveBeenCalledTimes(1)); change(which); finish(); await check;
      await expect(a.create()).rejects.toMatchObject({ outcome: 'not-issued' }); expect(observed).toHaveLength(1);
    });

  it('rechecks after an asynchronous request interceptor without dispatching', async () => {
    let finish!: () => void; const gate = new Promise<void>(resolve => { finish = resolve; }); const waiting = vi.fn();
    const id = api.interceptors.request.use(async config => { waiting(); await gate; return config; });
    try {
      const a = scope(); const pending = a.authorizeLocal('synthetic-password');
      const check = expect(pending).rejects.toMatchObject({ outcome: 'not-issued' });
      await vi.waitFor(() => expect(waiting).toHaveBeenCalledTimes(1)); change('cycle'); finish(); await check;
      expect(observed).toHaveLength(0);
    } finally { finish(); api.interceptors.request.eject(id); }
  });

  it.each([401, 403, 409, 429, 500, 503])('sanitizes status %s and permits no implicit replay', async status => {
    const refresh = vi.spyOn(axios, 'post').mockResolvedValue({ data: {} });
    const adapter = vi.fn(async (config: InternalAxiosRequestConfig) => {
      throw new AxiosError('synthetic-password', 'ERR_BAD_REQUEST', config, undefined,
        response(config, { detail: 'synthetic-passphrase-only', proof: 'synthetic-proof' }, status));
    }); api.defaults.adapter = adapter;
    const a = scope(); const error = await a.authorizeLocal('synthetic-password').catch(e => e);
    expect(error).toBeInstanceOf(VaultTransportError); expect(error).toMatchObject({ outcome: 'unconfirmed', status });
    for (const key of ['config', 'response', 'request', 'cause']) expect(error).not.toHaveProperty(key);
    expect(String(error)).not.toContain('synthetic'); expect(JSON.stringify(error)).not.toContain('synthetic');
    await expect(a.authorizeLocal('synthetic-password')).rejects.toMatchObject({ outcome: 'not-issued' });
    expect(adapter).toHaveBeenCalledTimes(1); expect(refresh).not.toHaveBeenCalled();
  });

  it.each([{}, { proof: '' }, { proof: 'x\r\nHeader: bad' }, { proof: 'x', extra: 'private' }, { proof: 'x'.repeat(8193) }])(
    'refuses malformed proof response %# without retaining input', async data => {
      api.defaults.adapter = async config => response(config, data);
      const a = scope(); const error = await a.authorizeLocal('synthetic-password').catch(e => e);
      expect(error).toBeInstanceOf(VaultTransportError); expect(error).toMatchObject({ outcome: 'unconfirmed' });
      await expect(a.create()).rejects.toMatchObject({ outcome: 'not-issued' });
    });

  it.each(['url-http', 'url-userinfo', 'url-fragment', 'different-state', 'duplicate-state', 'expired'])(
    'refuses unsafe OIDC response %s', async fault => {
      api.defaults.adapter = async config => {
        const data = { authorize_url: 'https://idp.example.invalid/auth?state=synthetic-state', state: 'synthetic-state', expires_at: expiry() };
        if (fault === 'url-http') data.authorize_url = data.authorize_url.replace('https:', 'http:');
        if (fault === 'url-userinfo') data.authorize_url = data.authorize_url.replace('https://', 'https://user:pass@');
        if (fault === 'url-fragment') data.authorize_url += '#private';
        if (fault === 'different-state') data.state = 'different';
        if (fault === 'duplicate-state') data.authorize_url += '&state=synthetic-state';
        if (fault === 'expired') data.expires_at = Math.floor(Date.now() / 1000) - 1;
        return response(config, data);
      };
      await expect(scope().beginOidc()).rejects.toMatchObject({ outcome: 'unconfirmed' });
    });
  it('refuses mismatched callback state and requires external MFA after valid callback', async () => {
    const a = scope(); await a.beginOidc();
    await expect(a.completeOidc('other-state', 'code')).rejects.toMatchObject({ outcome: 'not-issued' }); expect(observed).toHaveLength(1);
    await a.completeOidc('synthetic-state', 'code');
    await expect(a.create()).rejects.toMatchObject({ outcome: 'not-issued' }); expect(observed).toHaveLength(2);
    await a.authorizeExternal('123456'); await a.create(); expect(observed).toHaveLength(4);
  });
  it.each(['oidc', 'identity', 'legacy'])('refuses expired %s intermediate state', async which => {
    const a = scope(which === 'legacy' ? { kind: 'observe_legacy', backup_id: backupId, legacy_acknowledged: true } : original());
    if (which === 'oidc') await a.beginOidc();
    if (which === 'identity') await a.confirmLdap('synthetic-password');
    if (which === 'legacy') { await a.authorizeLocal('synthetic-password'); await a.observeLegacy(); }
    const count = observed.length; const future = Date.now() + 200000; vi.spyOn(Date, 'now').mockReturnValue(future);
    await expect(which === 'oidc' ? a.completeOidc('synthetic-state', 'code') : which === 'identity' ? a.authorizeExternal() : a.download())
      .rejects.toMatchObject({ outcome: 'not-issued' }); expect(observed).toHaveLength(count);
  });
  it.each(['oidc', 'identity', 'legacy'])('rechecks %s expiry after a queued interceptor', async which => {
    const a = scope(which === 'legacy' ? { kind: 'observe_legacy', backup_id: backupId, legacy_acknowledged: true } : original());
    if (which === 'oidc') await a.beginOidc();
    if (which === 'identity') await a.confirmLdap('synthetic-password');
    if (which === 'legacy') { await a.authorizeLocal('synthetic-password'); await a.observeLegacy(); }
    const count = observed.length;
    let finish!: () => void; const gate = new Promise<void>(resolve => { finish = resolve; }); const waiting = vi.fn();
    const id = api.interceptors.request.use(async config => { waiting(); await gate; return config; });
    try {
      const pending = which === 'oidc' ? a.completeOidc('synthetic-state', 'code') : which === 'identity' ? a.authorizeExternal() : a.download();
      const check = expect(pending).rejects.toMatchObject({ outcome: 'not-issued' });
      await vi.waitFor(() => expect(waiting).toHaveBeenCalledTimes(1));
      const future = Date.now() + 200000; vi.spyOn(Date, 'now').mockReturnValue(future); finish(); await check;
      expect(observed).toHaveLength(count);
    } finally { finish(); api.interceptors.request.eject(id); }
  });
  it.each(['oidc', 'identity', 'legacy'])('withholds a late %s response after expiry', async which => {
    const a = scope(which === 'legacy' ? { kind: 'observe_legacy', backup_id: backupId, legacy_acknowledged: true } : original());
    if (which === 'oidc') await a.beginOidc();
    if (which === 'identity') await a.confirmLdap('synthetic-password');
    if (which === 'legacy') { await a.authorizeLocal('synthetic-password'); await a.observeLegacy(); }
    let finish!: () => void; const gate = new Promise<void>(resolve => { finish = resolve; });
    const adapter = vi.fn(async (config: InternalAxiosRequestConfig) => { await gate; return answer(config); }); api.defaults.adapter = adapter;
    const pending = which === 'oidc' ? a.completeOidc('synthetic-state', 'code') : which === 'identity' ? a.authorizeExternal() : a.download();
    const check = expect(pending).rejects.toMatchObject({ outcome: 'unconfirmed' });
    await vi.waitFor(() => expect(adapter).toHaveBeenCalledTimes(1));
    const future = Date.now() + 200000; vi.spyOn(Date, 'now').mockReturnValue(future); finish(); await check;
    expect(adapter).toHaveBeenCalledTimes(1);
  });
  it('a backward wall-clock change cannot extend the monotonic external deadline', async () => {
    const a = scope(); await a.confirmLdap('synthetic-password'); const count = observed.length;
    const wall = Date.now() - 200000; const elapsed = performance.now() + 200000;
    vi.spyOn(Date, 'now').mockReturnValue(wall); vi.spyOn(performance, 'now').mockReturnValue(elapsed);
    await expect(a.authorizeExternal()).rejects.toMatchObject({ outcome: 'not-issued' }); expect(observed).toHaveLength(count);
  });
  it.each(['recorded', 'legacy'])('withholds late %s download bytes after an account change', async kind => {
    const a = scope(kind === 'recorded' ? { kind: 'download_recorded', backup_id: backupId }
      : { kind: 'observe_legacy', backup_id: backupId, legacy_acknowledged: true });
    await a.authorizeLocal('synthetic-password'); if (kind === 'legacy') await a.observeLegacy();
    let finish!: () => void; const gate = new Promise<void>(resolve => { finish = resolve; });
    const adapter = vi.fn(async (config: InternalAxiosRequestConfig) => { await gate; return answer(config); }); api.defaults.adapter = adapter;
    const pending = a.download(); const check = expect(pending).rejects.toMatchObject({ outcome: 'unconfirmed' });
    await vi.waitFor(() => expect(adapter).toHaveBeenCalledTimes(1)); change('cycle'); finish(); await check;
    expect(adapter).toHaveBeenCalledTimes(1);
  });
  it.each(['empty', 'oversize', 'not-blob', 'wrong-integrity', 'legacy-size'])(
    'refuses invalid binary response %s', async fault => {
      const a = scope(fault === 'legacy-size' ? { kind: 'observe_legacy', backup_id: backupId, legacy_acknowledged: true }
        : { kind: 'download_recorded', backup_id: backupId });
      await a.authorizeLocal('synthetic-password'); if (fault === 'legacy-size') await a.observeLegacy();
      api.defaults.adapter = async config => {
        const payload = new Blob([fault === 'empty' ? '' : 'abc']);
        if (fault === 'oversize') Object.defineProperty(payload, 'size', { value: 200 * 1024 * 1024 + 1 });
        if (fault === 'legacy-size') Object.defineProperty(payload, 'size', { value: 4 });
        return response(config, fault === 'not-blob' ? { private: 'synthetic' } : payload, 200,
          fault === 'wrong-integrity' || fault === 'legacy-size' ? 'legacy_unverified' : 'verified');
      };
      await expect(a.download()).rejects.toMatchObject({ outcome: 'unconfirmed' });
    });
  it('aborts a bounded JSON response on progress overflow before revealing its proof', async () => {
    api.defaults.adapter = async config => {
      config.onDownloadProgress?.({ loaded: 131073, bytes: 131073, lengthComputable: false });
      return response(config, { proof: 'synthetic-proof' });
    };
    const a = scope(); await expect(a.authorizeLocal('synthetic-password')).rejects.toMatchObject({ outcome: 'unconfirmed' });
    await expect(a.create()).rejects.toMatchObject({ outcome: 'not-issued' });
  });
  it.each(['false-superuser', 'null-org', 'noncanonical-org', 'demo', 'uninitialized'])(
    'refuses initial context %s', fault => {
      if (fault === 'false-superuser') useAuthStore.setState({ user: { ...user(), is_superuser: false } });
      if (fault === 'null-org') useAuthStore.setState({ user: { ...user(), organization_id: null } });
      if (fault === 'noncanonical-org') useAuthStore.setState({ user: { ...user(), organization_id: '../bad' } });
      if (fault === 'demo') mode.demo = true;
      if (fault === 'uninitialized') useAuthStore.setState({ _isAuthInitialized: false });
      expect(() => scope()).toThrow(VaultTransportError); expect(observed).toHaveLength(0);
    });
  it.each(['unknown', 'unacknowledged', 'invalid-id', 'no-secrets', 'short-passphrase', 'nonfinite-retention', 'lone-surrogate'])(
    'refuses invalid intent %s before requests', fault => {
      let value: unknown = original();
      if (fault === 'unknown') value = { ...original(), extra: true };
      if (fault === 'unacknowledged') value = { kind: 'observe_legacy', backup_id: backupId, legacy_acknowledged: false };
      if (fault === 'invalid-id') value = { kind: 'download_recorded', backup_id: '../other' };
      if (['no-secrets', 'short-passphrase', 'nonfinite-retention', 'lone-surrogate'].includes(fault)) {
        const base = original(); if (base.kind !== 'create') throw new Error('fixture');
        value = { ...base, backup: { ...base.backup,
          ...(fault === 'no-secrets' ? { include_secrets: false } : {}),
          ...(fault === 'short-passphrase' ? { passphrase: 'short' } : {}),
          ...(fault === 'nonfinite-retention' ? { retention_days: Infinity } : {}),
          ...(fault === 'lone-surrogate' ? { name: '\ud800' } : {}) } };
      }
      expect(() => scope(value as VaultBrowserIntent)).toThrow(VaultTransportError); expect(observed).toHaveLength(0);
    });
  it('refuses concurrent work and disposes an in-flight request without claiming rollback', async () => {
    let finish!: () => void; const gate = new Promise<void>(resolve => { finish = resolve; });
    const adapter = vi.fn(async (config: InternalAxiosRequestConfig) => { await gate; return answer(config); }); api.defaults.adapter = adapter;
    const a = scope(); const pending = a.authorizeLocal('synthetic-password'); const check = expect(pending).rejects.toMatchObject({ outcome: 'unconfirmed' });
    await vi.waitFor(() => expect(adapter).toHaveBeenCalledTimes(1));
    await expect(a.authorizeLocal('synthetic-password')).rejects.toMatchObject({ outcome: 'not-issued' }); a.dispose(); finish(); await check;
    expect(adapter).toHaveBeenCalledTimes(1);
  });
  it('bounds live scopes and releases admission exactly once on disposal', () => {
    for (let i = 0; i < 8; i++) scope(); expect(() => scope()).toThrow(VaultTransportError);
    actions[0].dispose(); actions[0].dispose(); expect(() => scope()).not.toThrow(); expect(() => scope()).toThrow(VaultTransportError);
  });
});

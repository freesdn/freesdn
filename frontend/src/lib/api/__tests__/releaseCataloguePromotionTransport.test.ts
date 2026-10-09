// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/** Real Axios/auth-store boundaries with a controlled adapter; no browser/server proof. */
import axios, { AxiosError, type AxiosResponse, type InternalAxiosRequestConfig } from 'axios';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { useAuthStore, type User } from '@/stores/authStore';
import { api } from '../client';
import { beginReleaseOperationAction, ReleaseTransportError, type ReleaseCatalogueFilters } from '../releaseOperationTransport';

vi.mock('@/demo/mode', () => ({ isDemoMode: false }));
vi.mock('@/stores/authStore', async () => {
  const { createStore } = await import('zustand/vanilla');
  return { useAuthStore: createStore(() => ({ user: null, isAuthenticated: false, _isHydrated: true,
    _isAuthInitialized: true, isLoading: false, mfaPending: false, hasPermission: () => true })) };
});
const actor = '11111111-1111-4111-8111-111111111111';
const organization = '22222222-2222-4222-8222-222222222222';
const release = '44444444-4444-4444-8444-444444444444';
const scopes: ReturnType<typeof beginReleaseOperationAction>[] = [];
let originalAdapter: typeof api.defaults.adapter;
function user(): User {
  return { id: actor, organization_id: organization, role: 'admin', is_active: true, is_superuser: false,
    is_org_admin: true, mfa_enabled: false, permissions: ['agent:admin'], roles: ['admin'], email: 'owned@example.invalid',
    username: 'owned', first_name: 'Owned', last_name: 'Operator', full_name: 'Owned Operator' };
}
function action() { const value = beginReleaseOperationAction(); scopes.push(value); return value; }
function success(config: InternalAxiosRequestConfig, data: unknown = '{"unvalidated":"observation"}'): AxiosResponse {
  return { config, data, headers: {}, status: 200, statusText: 'OK' };
}
function change(which: string) {
  const old = user();
  useAuthStore.setState({ user: which === 'organization' ? { ...old, organization_id: release } : { ...old, id: release } });
  if (which === 'cycle') useAuthStore.setState({ user: old });
}
function request(scope: ReturnType<typeof action>, route: string, signal?: AbortSignal) {
  return route === 'catalogue' ? scope.catalogue({}, signal) : scope.promote(release, signal);
}
beforeEach(() => {
  originalAdapter = api.defaults.adapter;
  useAuthStore.setState({ user: user(), isAuthenticated: true, _isHydrated: true, _isAuthInitialized: true,
    isLoading: false, mfaPending: false, hasPermission: () => true });
  document.cookie = 'freesdn_csrf=owned-csrf-test; path=/';
});
afterEach(() => {
  scopes.splice(0).forEach(value => value.dispose()); api.defaults.adapter = originalAdapter;
  vi.restoreAllMocks(); document.cookie = 'freesdn_csrf=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/';
});

describe.each(['catalogue', 'promotion'])('captured %s transport', route => {
  it.each(['user', 'organization', 'cycle'])('refuses queued work after %s change', async which => {
    const adapter = vi.fn(async (config: InternalAxiosRequestConfig) => success(config)); api.defaults.adapter = adapter;
    const scope = action(); change(which);
    await expect(request(scope, route)).rejects.toMatchObject({ outcome: 'not-issued' });
    expect(adapter).not.toHaveBeenCalled();
  });
  it.each(['user', 'organization', 'cycle'])('refuses late disclosure after %s change without assuming rollback', async which => {
    let finish!: () => void; const gate = new Promise<void>(resolve => { finish = resolve; });
    const adapter = vi.fn(async (config: InternalAxiosRequestConfig) => { await gate; return success(config); });
    api.defaults.adapter = adapter; const pending = request(action(), route);
    const observed = expect(pending).rejects.toMatchObject({ outcome: 'unconfirmed' });
    await vi.waitFor(() => expect(adapter).toHaveBeenCalledTimes(1)); change(which); finish(); await observed;
    expect(adapter).toHaveBeenCalledTimes(1);
  });
  it('rechecks after an actual asynchronous request-interceptor wait', async () => {
    let finish!: () => void; const gate = new Promise<void>(resolve => { finish = resolve; }); const waiting = vi.fn();
    const interceptor = api.interceptors.request.use(async config => { waiting(); await gate; return config; });
    const adapter = vi.fn(async (config: InternalAxiosRequestConfig) => success(config)); api.defaults.adapter = adapter;
    try {
      const pending = request(action(), route); const observed = expect(pending).rejects.toMatchObject({ outcome: 'not-issued' });
      await vi.waitFor(() => expect(waiting).toHaveBeenCalledTimes(1)); change('cycle'); finish(); await observed;
      expect(adapter).not.toHaveBeenCalled();
    } finally { finish(); api.interceptors.request.eject(interceptor); }
  });
  it.each([401, 409, 503])('never refreshes or replays after HTTP %s', async status => {
    const adapter = vi.fn(async (config: InternalAxiosRequestConfig) => { throw new AxiosError('private-error', 'ERR_BAD_REQUEST', config,
      undefined, { ...success(config), status }); }); api.defaults.adapter = adapter;
    const refresh = vi.spyOn(axios, 'post').mockResolvedValue({ data: {} }); const scope = action();
    const error = await request(scope, route).catch(value => value);
    expect(error).toBeInstanceOf(ReleaseTransportError); expect(error).toMatchObject({ outcome: 'unconfirmed', status });
    expect(error).not.toHaveProperty('config'); expect(error).not.toHaveProperty('response');
    expect(adapter).toHaveBeenCalledTimes(1); expect(refresh).not.toHaveBeenCalled();
    if (route === 'promotion') {
      await expect(scope.promote(release)).rejects.toMatchObject({ outcome: 'not-issued' });
      expect(adapter).toHaveBeenCalledTimes(1);
    }
  });
  it('refuses a cancelled request before dispatch', async () => {
    const adapter = vi.fn(async (config: InternalAxiosRequestConfig) => success(config)); api.defaults.adapter = adapter;
    const controller = new AbortController(); controller.abort();
    await expect(request(action(), route, controller.signal)).rejects.toMatchObject({ outcome: 'not-issued' });
    expect(adapter).not.toHaveBeenCalled();
  });
});

it('captures exact filters before waiting and sends paired context without converting raw JSON', async () => {
  let finish!: () => void; const gate = new Promise<void>(resolve => { finish = resolve; }); const seen: InternalAxiosRequestConfig[] = [];
  const interceptor = api.interceptors.request.use(async config => { await gate; return config; });
  const body = '[{"id":"historical-not-authority"}]';
  api.defaults.adapter = async config => { seen.push(config); return success(config, body); };
  try {
    const filters = { platform: 'Linux', agent_type: 'daemon' }; const pending = action().catalogue(filters);
    filters.platform = 'windows'; finish(); expect(await pending).toBe(body);
    expect(seen).toHaveLength(1); expect(seen[0].url).toBe('/agents/releases?platform=Linux&agent_type=daemon');
    expect(seen[0].method).toBe('get'); expect(seen[0].data).toBeUndefined();
    expect(seen[0].headers.get('X-FreeSDN-Release-Actor')).toBe(actor);
    expect(seen[0].headers.get('X-FreeSDN-Release-Organization')).toBe(organization);
  } finally { finish(); api.interceptors.request.eject(interceptor); }
});
it('sends one explicit bodyless promotion with CSRF and permits only later read-only catalogue inspection', async () => {
  const seen: InternalAxiosRequestConfig[] = []; api.defaults.adapter = async config => { seen.push(config); return success(config); };
  const scope = action(); await scope.promote(release);
  expect(seen).toHaveLength(1); expect(seen[0].url).toBe(`/agents/releases/${release}/promote`);
  expect(seen[0].method).toBe('patch'); expect(seen[0].data).toBeUndefined();
  expect(seen[0].headers.get('X-CSRF-Token')).toBe('owned-csrf-test');
  expect(seen[0].headers.get('X-FreeSDN-Release-Actor')).toBe(actor);
  expect(seen[0].headers.get('X-FreeSDN-Release-Organization')).toBe(organization);
  await expect(scope.promote(release)).rejects.toMatchObject({ outcome: 'not-issued' });
  expect(seen).toHaveLength(1); await scope.catalogue(); expect(seen).toHaveLength(2);
});
it.each(['../escape', '00000000-0000-0000-0000-000000000000', 'not-a-uuid'])('refuses invalid promotion identity %s before transport', bad => {
  const adapter = vi.fn(); api.defaults.adapter = adapter;
  expect(() => action().promote(bad)).toThrow(ReleaseTransportError); expect(adapter).not.toHaveBeenCalled();
});
it.each([{ platform: '' }, { platform: 'x'.repeat(51) }, { organization_id: release }, { platform: 'linux&extra=true' }])(
  'refuses malformed or authority-bearing catalogue filters %j before transport', bad => {
    const adapter = vi.fn(); api.defaults.adapter = adapter;
    expect(() => action().catalogue(bad as ReleaseCatalogueFilters)).toThrow(ReleaseTransportError);
    expect(adapter).not.toHaveBeenCalled();
  },
);

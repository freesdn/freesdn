// SPDX-License-Identifier: AGPL-3.0-only
/** Actual Axios interception and Zustand updates; controlled adapter, not live browser/SQL. */
import axios, { AxiosError, type AxiosResponse, type InternalAxiosRequestConfig } from 'axios';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { useAuthStore, type User } from '@/stores/authStore';
import { api } from '../client';
import { storageLocationsApi } from '../system';

vi.mock('@/demo/mode', () => ({ isDemoMode: false }));
vi.mock('@/lib/queryClient', () => ({ queryClient: { clear: vi.fn() } }));
vi.mock('@/stores/authStore', async () => {
  const { createStore } = await import('zustand/vanilla');
  return { useAuthStore: createStore(() => ({ user: null, isAuthenticated: false, _isHydrated: true,
    _isAuthInitialized: true, isLoading: false, mfaPending: false })) };
});
const actor = '11111111-1111-4111-8111-111111111111';
const org = '22222222-2222-4222-8222-222222222222';
const location = '33333333-3333-4333-8333-333333333333';
const other = '44444444-4444-4444-8444-444444444444';
const path = `/backups/storage-locations/${location}/test`;
let oldAdapter: typeof api.defaults.adapter;
const interceptors: number[] = [];
function user(): User {
  return { id: actor, organization_id: org, role: 'org_admin', is_active: true, is_superuser: false,
    is_org_admin: true, mfa_enabled: false, permissions: ['*'], roles: ['org_admin'], email: 'owned@example.invalid',
    username: 'owned', first_name: 'Owned', last_name: 'Operator', full_name: 'Owned Operator' };
}
function gate() { let release!: () => void; const promise = new Promise<void>(resolve => { release = resolve; }); return { promise, release }; }
function answer(config: InternalAxiosRequestConfig): AxiosResponse {
  return { config, data: { success: true, message: 'Owned synthetic peer observation', details: {}, latency_ms: 1 },
    headers: {}, status: 200, statusText: 'OK' };
}
function refusal(config: InternalAxiosRequestConfig): Promise<never> {
  return Promise.reject(new AxiosError('Owned refusal after possible I/O', 'ERR_BAD_REQUEST', config, undefined,
    { config, data: { detail: 'Storage probe authorization changed' }, headers: {}, status: 401, statusText: 'Unauthorized' }));
}
function change(which: string) {
  const u = user();
  if (which === 'logout') useAuthStore.setState({ user: null, isAuthenticated: false });
  else if (which === 'loading') useAuthStore.setState({ isLoading: true });
  else if (which === 'mfa-pending') useAuthStore.setState({ mfaPending: true });
  else if (which === 'user' || which === 'cycle') useAuthStore.setState({ user: { ...u, id: other } });
  else if (which === 'organization') useAuthStore.setState({ user: { ...u, organization_id: other } });
  else if (which === 'role') useAuthStore.setState({ user: { ...u, role: 'viewer', is_org_admin: false } });
  else if (which === 'inactive') useAuthStore.setState({ user: { ...u, is_active: false } });
  if (which === 'cycle') useAuthStore.setState({ user: u });
}
const settle = <T>(promise: Promise<T>) => promise.then(value => ({ accepted: true, value, error: undefined }),
  (error: unknown) => ({ accepted: false, value: undefined, error }));
beforeEach(() => {
  oldAdapter = api.defaults.adapter;
  useAuthStore.setState({ user: user(), isAuthenticated: true, _isHydrated: true, _isAuthInitialized: true,
    isLoading: false, mfaPending: false });
});
afterEach(() => {
  for (const n of interceptors.splice(0)) api.interceptors.request.eject(n);
  api.defaults.adapter = oldAdapter; vi.restoreAllMocks();
});

it('does not refresh or replay an uncertain storage probe after 401', async () => {
  let calls = 0;
  api.defaults.adapter = async config => { calls += 1; return calls === 1 ? refusal(config) : answer(config); };
  const refresh = vi.spyOn(axios, 'post').mockResolvedValue({ data: {} });
  const result = await settle(storageLocationsApi.test(location));
  const observed = { accepted: result.accepted, calls, refreshCalls: refresh.mock.calls.length };
  expect(observed).toEqual({ accepted: false, calls: 1, refreshCalls: 0 });
});

it('does not join an existing ordinary refresh queue', async () => {
  const waiting = gate(), release = gate(); let ordinaryCalls = 0, probeCalls = 0;
  const refresh = vi.spyOn(axios, 'post').mockImplementation(async () => { waiting.release(); await release.promise; return { data: {} }; });
  api.defaults.adapter = async config => {
    if (config.url === '/ordinary') { ordinaryCalls += 1; return ordinaryCalls === 1 ? refusal(config) : answer(config); }
    probeCalls += 1; return probeCalls === 1 ? refusal(config) : answer(config);
  };
  const ordinary = settle(api.get('/ordinary'));
  let result: Awaited<ReturnType<typeof settle<AxiosResponse>>> | undefined;
  try {
    await waiting.promise;
    const probe = settle(storageLocationsApi.test(location));
    await vi.waitFor(() => expect(probeCalls).toBe(1));
    release.release(); result = await probe;
  } finally { release.release(); expect((await ordinary).accepted).toBe(true); }
  expect({ accepted: result?.accepted, probeCalls, ordinaryCalls, refreshCalls: refresh.mock.calls.length })
    .toEqual({ accepted: false, probeCalls: 1, ordinaryCalls: 2, refreshCalls: 1 });
});

it('preserves an ordinary request refresh control', async () => {
  let calls = 0;
  api.defaults.adapter = async config => { calls += 1; return calls === 1 ? refusal(config) : answer(config); };
  const refresh = vi.spyOn(axios, 'post').mockResolvedValue({ data: {} });
  expect((await settle(api.get('/ordinary'))).accepted).toBe(true);
  expect(calls).toBe(2); expect(refresh).toHaveBeenCalledTimes(1);
});

it('preserves one unchanged successful probe request', async () => {
  const requests: InternalAxiosRequestConfig[] = [];
  api.defaults.adapter = async config => { requests.push(config); return answer(config); };
  const refresh = vi.spyOn(axios, 'post').mockResolvedValue({ data: {} });
  const result = await storageLocationsApi.test(location);
  expect(result.data.success).toBe(true); expect(requests).toHaveLength(1);
  expect(requests[0]).toMatchObject({ method: 'post', url: path, withCredentials: true });
  expect(refresh).not.toHaveBeenCalled();
});

for (const boundary of ['queued', 'response'] as const) {
  it.each(['logout', 'user', 'organization', 'role', 'inactive', 'loading', 'mfa-pending', 'cycle'])(
    `refuses changed context at ${boundary} for %s`, async transition => {
      const entered = gate(), release = gate(); let calls = 0;
      if (boundary === 'queued') {
        interceptors.push(api.interceptors.request.use(async config => {
          if (config.url === path) { entered.release(); await release.promise; }
          return config;
        }));
      }
      api.defaults.adapter = async config => {
        calls += 1;
        if (boundary === 'response') { entered.release(); await release.promise; }
        return answer(config);
      };
      const pending = settle(storageLocationsApi.test(location));
      let result: Awaited<typeof pending> | undefined;
      try { await entered.promise; change(transition); }
      finally { release.release(); result = await pending; }
      const observed = { accepted: result.accepted, calls };
      expect(observed).toEqual({ accepted: false, calls: boundary === 'queued' ? 0 : 1 });
    });
}

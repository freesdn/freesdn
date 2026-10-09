// SPDX-License-Identifier: AGPL-3.0-only
/** Controlled adapter/lifetime cases; fake timer tests do not qualify server clocks. */
import axios, { AxiosError, type InternalAxiosRequestConfig } from 'axios';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { useAuthStore, type User } from '@/stores/authStore';
import { api } from '../client';
import { beginStorageProbe, StorageProbeError } from '../storageProbeTransport';

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
const actions: ReturnType<typeof beginStorageProbe>[] = [];
const calls: InternalAxiosRequestConfig[] = [];
let original: typeof api.defaults.adapter;
function user(): User {
  return { id: actor, organization_id: org, role: 'org_admin', is_active: true, is_superuser: false,
    is_org_admin: true, mfa_enabled: false, permissions: ['*'], roles: ['org_admin'], email: 'owned@example.invalid',
    username: 'owned', first_name: 'Owned', last_name: 'Operator', full_name: 'Owned Operator' };
}
function begin(id = location) { const a = beginStorageProbe(id); actions.push(a); return a; }
function answer(config: InternalAxiosRequestConfig) {
  return { config, data: { success: true, message: 'Owned observation', details: {}, latency_ms: 1 },
    status: 200, statusText: 'OK', headers: {} };
}
function gate() { let release!: () => void; const promise = new Promise<void>(resolve => { release = resolve; }); return { promise, release }; }
function settle<T>(p: Promise<T>) { return p.then(value => ({ value, error: undefined }), (error: unknown) => ({ value: undefined, error })); }
beforeEach(() => {
  original = api.defaults.adapter; calls.length = 0;
  api.defaults.adapter = async config => { calls.push(config); return answer(config); };
  useAuthStore.setState({ user: user(), isAuthenticated: true, _isHydrated: true, _isAuthInitialized: true,
    isLoading: false, mfaPending: false });
  document.cookie = 'freesdn_csrf=synthetic-probe-csrf; path=/';
});
afterEach(() => {
  actions.splice(0).forEach(a => a.dispose()); api.defaults.adapter = original;
  vi.restoreAllMocks(); vi.useRealTimers();
  document.cookie = 'freesdn_csrf=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/';
});

it.each(['admin', 'org_admin', 'super_admin'])('preserves the ordinary %s role and copied context headers', async role => {
  useAuthStore.setState({ user: { ...user(), role, roles: [role], is_superuser: role === 'super_admin' } });
  const action = begin();
  expect((await action.run()).data.success).toBe(true); action.assertCurrent();
  expect(calls).toHaveLength(1);
  const request = calls[0];
  expect(request).toMatchObject({ method: 'post', url: `/backups/storage-locations/${location}/test`, withCredentials: true, timeout: 180000 });
  expect(request.headers.get('X-FreeSDN-Storage-Probe-Actor')).toBe(actor);
  expect(request.headers.get('X-FreeSDN-Storage-Probe-Organization')).toBe(org);
  expect(request.headers.get('X-CSRF-Token')).toBe('synthetic-probe-csrf');
  expect(request.signal?.aborted).toBe(false);
});

it.each(['', '../foreign', '00000000-0000-0000-0000-000000000000', 'not-a-uuid', '33333333-3333-4333-8333-333333333333/extra'])('refuses invalid location %s before adapter dispatch', id => {
  expect(() => begin(id)).toThrow(StorageProbeError); expect(calls).toHaveLength(0);
});

it.each(['no-user', 'logged-out', 'unhydrated', 'uninitialized', 'loading', 'mfa-pending', 'inactive', 'viewer', 'no-organization', 'no-admin-flag'])('refuses inadmissible initial context %s', state => {
  if (state === 'no-user') useAuthStore.setState({ user: null });
  if (state === 'logged-out') useAuthStore.setState({ isAuthenticated: false });
  if (state === 'unhydrated') useAuthStore.setState({ _isHydrated: false });
  if (state === 'uninitialized') useAuthStore.setState({ _isAuthInitialized: false });
  if (state === 'loading') useAuthStore.setState({ isLoading: true });
  if (state === 'mfa-pending') useAuthStore.setState({ mfaPending: true });
  if (state === 'inactive') useAuthStore.setState({ user: { ...user(), is_active: false } });
  if (state === 'viewer') useAuthStore.setState({ user: { ...user(), role: 'viewer' } });
  if (state === 'no-organization') useAuthStore.setState({ user: { ...user(), organization_id: null } });
  if (state === 'no-admin-flag') useAuthStore.setState({ user: { ...user(), is_org_admin: false } });
  expect(() => begin()).toThrow(StorageProbeError); expect(calls).toHaveLength(0);
});

it.each(['permissions', 'roles'] as const)('detects an in-place %s edit even without a store notification', field => {
  const a = begin(); const current = useAuthStore.getState().user!;
  current[field].push('changed');
  expect(() => a.assertCurrent()).toThrow(StorageProbeError);
  expect(calls).toHaveLength(0);
});

it.each(['success', 'failure'])('one action cannot repeat after %s', async outcome => {
  api.defaults.adapter = async config => {
    calls.push(config);
    if (outcome === 'failure') throw new Error('Owned peer response loss');
    return answer(config);
  };
  const a = begin(); const first = await settle(a.run());
  if (outcome === 'success') expect(first.value?.data.success).toBe(true);
  else expect(first.error).toMatchObject({ outcome: 'unconfirmed' });
  await expect(a.run()).rejects.toMatchObject({ outcome: 'not-issued' }); expect(calls).toHaveLength(1);
});

it('refuses a simultaneous second call while the first adapter is owned', async () => {
  const entered = gate(), release = gate();
  api.defaults.adapter = async config => { calls.push(config); entered.release(); await release.promise; return answer(config); };
  const a = begin(); const first = settle(a.run());
  try { await entered.promise; await expect(a.run()).rejects.toMatchObject({ outcome: 'not-issued' }); }
  finally { release.release(); expect((await first).value?.data.success).toBe(true); }
  expect(calls).toHaveLength(1);
});

it('refuses a pre-aborted signal without issuing a request', async () => {
  const control = new AbortController(); control.abort();
  await expect(begin().run(control.signal)).rejects.toMatchObject({ outcome: 'not-issued' });
  expect(calls).toHaveLength(0);
});

it.each(['signal', 'dispose'])('marks an issued request unconfirmed after %s', async cancel => {
  const entered = gate(), release = gate(), signal = new AbortController();
  api.defaults.adapter = async config => { calls.push(config); entered.release(); await release.promise; return answer(config); };
  const a = begin(); const pending = settle(a.run(signal.signal));
  try { await entered.promise; if (cancel === 'signal') signal.abort(); else a.dispose(); }
  finally { release.release(); }
  expect((await pending).error).toMatchObject({ outcome: 'unconfirmed' });
  expect(calls).toHaveLength(1); expect(calls[0].signal?.aborted).toBe(true);
});

it.each(['before', 'during'])('refuses fake-timer expiry %s dispatch without reviving the action', async when => {
  vi.useFakeTimers(); const entered = gate(), release = gate();
  api.defaults.adapter = async config => { calls.push(config); entered.release(); await release.promise; return answer(config); };
  const a = begin();
  if (when === 'before') {
    await vi.advanceTimersByTimeAsync(180000);
    await expect(a.run()).rejects.toMatchObject({ outcome: 'not-issued' }); expect(calls).toHaveLength(0);
  } else {
    const pending = settle(a.run());
    try { await entered.promise; await vi.advanceTimersByTimeAsync(180000); }
    finally { release.release(); }
    expect((await pending).error).toMatchObject({ outcome: 'unconfirmed' }); expect(calls).toHaveLength(1);
  }
  expect(() => a.assertCurrent()).toThrow(StorageProbeError);
});

it('keeps bounded live actions and releases admission idempotently', () => {
  for (let i = 0; i < 8; i += 1) begin();
  expect(() => begin()).toThrow(StorageProbeError);
  actions[0].dispose(); actions[0].dispose();
  expect(() => begin()).not.toThrow(); expect(calls).toHaveLength(0);
});

it.each([401, 500])('preserves numeric status %s without retaining Axios request or response content', async status => {
  const secret = 'owned-private-response-marker';
  api.defaults.adapter = async config => {
    calls.push(config);
    throw new AxiosError(secret, 'ERR_BAD_RESPONSE', config, undefined,
      { config, data: { sensitive: secret }, headers: {}, status, statusText: secret });
  };
  const refresh = vi.spyOn(axios, 'post').mockResolvedValue({ data: {} });
  const result = await settle(begin().run());
  expect(result.error).toBeInstanceOf(StorageProbeError);
  expect(result.error).toMatchObject({ outcome: 'unconfirmed', status });
  expect(String(result.error) + JSON.stringify(result.error)).not.toContain(secret);
  expect(result.error).not.toHaveProperty('response'); expect(result.error).not.toHaveProperty('config');
  expect(calls).toHaveLength(1); expect(refresh).not.toHaveBeenCalled();
});

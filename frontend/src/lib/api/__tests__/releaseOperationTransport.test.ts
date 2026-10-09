// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/** Planned real Axios/Zustand transport checks, no live server or browser proof. */
import axios, { AxiosError, type AxiosResponse, type InternalAxiosRequestConfig } from 'axios';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { useAuthStore, type User } from '@/stores/authStore';
import { api } from '../client';
import { beginReleaseOperationAction, ReleaseTransportError } from '../releaseOperationTransport';

const mode = vi.hoisted(() => ({ demo: false }));
vi.mock('@/demo/mode', () => ({ get isDemoMode() { return mode.demo; } }));
vi.mock('@/stores/authStore', async () => {
  const { createStore } = await import('zustand/vanilla');
  return { useAuthStore: createStore(() => ({ user: null, isAuthenticated: false, _isHydrated: true,
    _isAuthInitialized: true, isLoading: false, mfaPending: false, hasPermission: () => true })) };
});
const actor = '11111111-1111-4111-8111-111111111111';
const organization = '22222222-2222-4222-8222-222222222222';
const operation = '33333333-3333-4333-8333-333333333333';
const release = '44444444-4444-4444-8444-444444444444';
const raw = JSON.stringify({ kind: 'publish', operation_id: operation, release_id: release,
  organization_id: organization, storage_kind: 'owned', metadata: { file_size: 3 } });
const actions: ReturnType<typeof beginReleaseOperationAction>[] = [];
let restoreAdapter: typeof api.defaults.adapter;

function user(): User {
  return { id: actor, organization_id: organization, role: 'admin', is_active: true, is_superuser: false,
    is_org_admin: true, mfa_enabled: false, permissions: ['agent:admin'], roles: ['admin'], email: 'owned@example.invalid',
    username: 'owned', first_name: 'Owned', last_name: 'Operator', full_name: 'Owned Operator' };
}
function action() {
  const value = beginReleaseOperationAction();
  actions.push(value);
  return value;
}
function success(config: InternalAxiosRequestConfig, data: unknown = { historical: 'unvalidated-test-observation' }): AxiosResponse {
  return { config, data, headers: {}, status: 200, statusText: 'OK' };
}
function change(which: string) {
  const initial = user();
  if (which === 'logout') useAuthStore.setState({ isAuthenticated: false, user: null });
  else if (which === 'loading') useAuthStore.setState({ isLoading: true });
  else if (which === 'mfa') useAuthStore.setState({ mfaPending: true });
  else if (which === 'user' || which === 'cycle') useAuthStore.setState({ user: { ...initial, id: release } });
  else if (which === 'organization') useAuthStore.setState({ user: { ...initial, organization_id: release } });
  else if (which === 'inactive') useAuthStore.setState({ user: { ...initial, is_active: false } });
  else if (which === 'role') useAuthStore.setState({ user: { ...initial, role: 'viewer' } });
  if (which === 'cycle') useAuthStore.setState({ user: initial });
}

beforeEach(() => {
  restoreAdapter = api.defaults.adapter;
  mode.demo = false;
  useAuthStore.setState({ user: user(), isAuthenticated: true, _isHydrated: true, _isAuthInitialized: true,
    isLoading: false, mfaPending: false, hasPermission: () => true });
  document.cookie = 'freesdn_csrf=owned-csrf-test; path=/';
});
afterEach(() => {
  actions.splice(0).forEach(value => value.dispose());
  api.defaults.adapter = restoreAdapter;
  mode.demo = false;
  vi.restoreAllMocks();
  vi.useRealTimers();
  document.cookie = 'freesdn_csrf=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/';
});

describe('one deliberate release-operation action', () => {
  it.each(['user', 'organization', 'role', 'inactive', 'logout', 'loading', 'mfa', 'cycle'])(
    'does not send queued work after %s context change', async which => {
      const adapter = vi.fn(async (config: InternalAxiosRequestConfig) => success(config));
      api.defaults.adapter = adapter;
      const scope = action();
      change(which);
      await expect(scope.command(operation, 'reserve', raw)).rejects.toMatchObject({ outcome: 'not-issued' });
      expect(adapter).not.toHaveBeenCalled();
    },
  );

  it.each(['user', 'organization', 'role', 'inactive', 'logout', 'loading', 'mfa', 'cycle'])(
    'does not disclose a late result or assume rollback after %s', async which => {
      let finish!: () => void;
      const gate = new Promise<void>(resolve => { finish = resolve; });
      const adapter = vi.fn(async (config: InternalAxiosRequestConfig) => { await gate; return success(config, { committed: true }); });
      api.defaults.adapter = adapter;
      const scope = action();
      const pending = scope.command(operation, 'publish', raw);
      const observed = expect(pending).rejects.toMatchObject({ outcome: 'unconfirmed' });
      await vi.waitFor(() => expect(adapter).toHaveBeenCalledTimes(1));
      change(which);
      finish();
      await observed;
      expect(adapter).toHaveBeenCalledTimes(1);
    },
  );

  it('rechecks context at the actual adapter boundary after an asynchronous interceptor wait', async () => {
    let finish!: () => void;
    const gate = new Promise<void>(resolve => { finish = resolve; });
    const waiting = vi.fn();
    const interceptor = api.interceptors.request.use(async config => { waiting(); await gate; return config; });
    const adapter = vi.fn(async (config: InternalAxiosRequestConfig) => success(config));
    api.defaults.adapter = adapter;
    const scope = action();
    try {
      const pending = scope.command(operation, 'reserve', raw);
      const outcome = expect(pending).rejects.toMatchObject({ outcome: 'not-issued' });
      await vi.waitFor(() => expect(waiting).toHaveBeenCalledTimes(1));
      change('cycle');
      finish();
      await outcome;
      expect(adapter).not.toHaveBeenCalled();
    } finally {
      finish();
      api.interceptors.request.eject(interceptor);
    }
  });

  it.each([200, 401, 409, 503])('permits no second mutation after status %s but allows explicit inspection', async status => {
    const adapter = vi.fn(async (config: InternalAxiosRequestConfig) => {
      if (config.method === 'get' || status === 200) return success(config);
      throw new AxiosError('private-intent-must-not-escape', 'ERR_BAD_REQUEST', config, undefined,
        { ...success(config, { private_value: 'synthetic-sensitive-value' }), status });
    });
    api.defaults.adapter = adapter;
    const refresh = vi.spyOn(axios, 'post').mockResolvedValue({ data: {} });
    const scope = action();
    if (status === 200) await scope.command(operation, 'reserve', raw);
    else {
      const error = await scope.command(operation, 'reserve', raw).catch(value => value);
      expect(error).toBeInstanceOf(ReleaseTransportError);
      expect(error).toMatchObject({ outcome: 'unconfirmed', status });
      expect(error).not.toHaveProperty('config');
      expect(error).not.toHaveProperty('response');
      expect(String(error)).not.toContain('private-intent');
      expect(JSON.stringify(error)).not.toContain('synthetic-sensitive-value');
    }
    await expect(scope.command(operation, 'cancel', raw)).rejects.toMatchObject({ outcome: 'not-issued' });
    expect(adapter).toHaveBeenCalledTimes(1);
    await scope.inspect(operation);
    expect(adapter).toHaveBeenCalledTimes(2);
    expect(refresh).not.toHaveBeenCalled();
  });

  it('sends exact intent, cookie/CSRF policy and actor context without granting target authority', async () => {
    const seen: InternalAxiosRequestConfig[] = [];
    api.defaults.adapter = async config => { seen.push(config); return success(config); };
    const scope = action();
    await scope.command(operation, 'reserve', raw);
    expect(seen).toHaveLength(1);
    expect(seen[0].data).toBe(raw);
    expect(seen[0].withCredentials).toBe(true);
    expect(seen[0].headers.get('X-CSRF-Token')).toBe('owned-csrf-test');
    expect(seen[0].headers.get('X-FreeSDN-Release-Actor')).toBe(actor);
    expect(seen[0].headers.get('X-FreeSDN-Release-Organization')).toBe(organization);
    expect(seen[0].timeout).toBe(130000);
  });

  it('uses intent string before a binary file without a JSON filename or full-file buffering', async () => {
    const seen: InternalAxiosRequestConfig[] = [];
    api.defaults.adapter = async config => { seen.push(config); return success(config); };
    const file = new Blob([new Uint8Array([0, 1, 2])], { type: 'multipart/mixed' });
    const read = vi.spyOn(file, 'arrayBuffer');
    await action().upload(operation, raw, file);
    const body = seen[0].data as FormData;
    expect([...body.keys()]).toEqual(['intent', 'file']);
    expect(body.get('intent')).toBe(raw);
    const part = body.get('file') as File;
    expect(part.name).toBe('payload.bin');
    expect(part.type).toBe('application/octet-stream');
    expect(part.size).toBe(3);
    expect(seen[0].headers.get('Content-Type')).toBe(false);
    expect(read).not.toHaveBeenCalled();
  });

  it.each(['invalid-id', 'oversize-document', 'mismatched-id', 'lone-surrogate', 'wrong-file-size'])(
    'rejects %s before transport', async fault => {
      const adapter = vi.fn(async (config: InternalAxiosRequestConfig) => success(config));
      api.defaults.adapter = adapter;
      const scope = action();
      const operationId = fault === 'invalid-id' ? '../escape' : operation;
      const document = fault === 'oversize-document' ? 'x'.repeat(307201)
        : fault === 'lone-surrogate' ? raw + '\ud800'
        : fault === 'mismatched-id' ? raw.replace(operation, release) : raw;
      expect(() => fault === 'wrong-file-size'
        ? scope.upload(operationId, document, new Blob(['wrong size']))
        : scope.command(operationId, 'reserve', document)).toThrow(ReleaseTransportError);
      expect(adapter).not.toHaveBeenCalled();
    },
  );

  it('keeps raw duplicate fields for the exact server codec instead of silently normalizing them', async () => {
    const duplicate = raw.replace('"kind":"publish"', '"kind":"delete","kind":"publish"');
    const seen: InternalAxiosRequestConfig[] = [];
    api.defaults.adapter = async config => { seen.push(config); return success(config); };
    await action().command(operation, 'reserve', duplicate);
    expect(seen[0].data).toBe(duplicate);
  });

  it.each(['before', 'after'])('distinguishes cancellation %s adapter dispatch without retry', async when => {
    let finish!: () => void;
    const gate = new Promise<void>(resolve => { finish = resolve; });
    const adapter = vi.fn(async (config: InternalAxiosRequestConfig) => { await gate; return success(config); });
    api.defaults.adapter = adapter;
    const scope = action();
    const controller = new AbortController();
    if (when === 'before') controller.abort();
    const pending = scope.command(operation, 'reserve', raw, controller.signal);
    const outcome = expect(pending).rejects.toMatchObject({ outcome: when === 'before' ? 'not-issued' : 'unconfirmed' });
    if (when === 'after') {
      await vi.waitFor(() => expect(adapter).toHaveBeenCalledTimes(1));
      controller.abort();
    }
    finish();
    await outcome;
    expect(adapter).toHaveBeenCalledTimes(when === 'before' ? 0 : 1);
  });

  it('refuses concurrent work on one action while retaining later inspection', async () => {
    let finish!: () => void;
    const gate = new Promise<void>(resolve => { finish = resolve; });
    const adapter = vi.fn(async (config: InternalAxiosRequestConfig) => { await gate; return success(config); });
    api.defaults.adapter = adapter;
    const scope = action();
    const pending = scope.command(operation, 'reserve', raw);
    await vi.waitFor(() => expect(adapter).toHaveBeenCalledTimes(1));
    await expect(scope.inspect(operation)).rejects.toMatchObject({ outcome: 'not-issued' });
    finish();
    await pending;
    await scope.inspect(operation);
    expect(adapter).toHaveBeenCalledTimes(2);
  });

  it('bounds active action objects and releases capacity on disposal or expiry', () => {
    vi.useFakeTimers();
    for (let i = 0; i < 8; i += 1) action();
    expect(() => action()).toThrow(ReleaseTransportError);
    actions[0].dispose();
    action();
    vi.advanceTimersByTime(600000);
    expect(() => actions[1].assertCurrent()).toThrow(ReleaseTransportError);
    expect(() => action()).not.toThrow();
  });

  it('refuses demo transport without falling back to real HTTP', () => {
    const adapter = vi.fn();
    api.defaults.adapter = adapter;
    mode.demo = true;
    expect(() => action()).toThrow(ReleaseTransportError);
    expect(adapter).not.toHaveBeenCalled();
  });
});

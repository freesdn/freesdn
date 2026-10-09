// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/** Real Axios interceptor chain with controlled adapters; not browser/server proof. */
import type { AxiosInstance, AxiosRequestConfig, InternalAxiosRequestConfig } from 'axios';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('@/stores/authStore', () => ({ useAuthStore: { setState: vi.fn() } }));
vi.mock('@/demo/mode', () => ({ isDemoMode: false }));
vi.mock('@/lib/queryClient', () => ({ queryClient: { clear: vi.fn() } }));

let api: AxiosInstance;
let library: typeof import('axios');
let reject401: (config: InternalAxiosRequestConfig) => Promise<never>;
const once = { _freesdnVaultNoReplay: true } as AxiosRequestConfig & { _freesdnVaultNoReplay: true };

beforeEach(async () => {
  vi.resetModules();
  library = await import('axios');
  api = (await import('../client')).api;
  reject401 = config => Promise.reject(new library.AxiosError('synthetic refusal', 'ERR_BAD_REQUEST', config, undefined,
    { config, data: { detail: 'Fresh confirmation refused' }, headers: {}, status: 401, statusText: 'Unauthorized' }));
});
afterEach(() => { vi.restoreAllMocks(); });

describe('purpose-bound vault requests never join refresh or replay', () => {
  it.each([
    ['POST', '/auth/vault-export/authorize/local'],
    ['POST', '/auth/vault-export/identity/ldap'],
    ['POST', '/auth/vault-export/identity/oidc/start'],
    ['POST', '/auth/vault-export/identity/oidc/complete'],
    ['POST', '/auth/vault-export/authorize/external'],
    ['POST', '/backups/'],
    ['GET', '/backups/11111111-1111-4111-8111-111111111111/download'],
    ['POST', '/backups/11111111-1111-4111-8111-111111111111/vault-observation'],
    ['POST', '/backups/11111111-1111-4111-8111-111111111111/vault-download'],
  ])('does not refresh or replay explicit %s %s', async (method, url) => {
    const adapter = vi.fn(reject401);
    api.defaults.adapter = adapter;
    const refresh = vi.spyOn(library.default, 'post').mockResolvedValue({ data: {} });
    await expect(api.request({ ...once, method, url })).rejects.toMatchObject({ response: { status: 401 } });
    expect(adapter).toHaveBeenCalledTimes(1);
    expect(refresh).not.toHaveBeenCalled();
  });

  it.each([undefined, false, 'true', 1, null])('requires exact true; ordinary requests still refresh for %s', async flag => {
    let calls = 0;
    api.defaults.adapter = async config => {
      calls += 1;
      if (calls === 1) return reject401(config);
      return { config, data: { control: true }, headers: {}, status: 200, statusText: 'OK' };
    };
    const refresh = vi.spyOn(library.default, 'post').mockResolvedValue({ data: {} });
    const config = { url: '/ordinary', _freesdnVaultNoReplay: flag } as AxiosRequestConfig & { _freesdnVaultNoReplay: unknown };
    expect((await api.request(config)).data).toEqual({ control: true });
    expect(calls).toBe(2);
    expect(refresh).toHaveBeenCalledTimes(1);
  });

  it.each(['success', 'failure'])('refuses independently while an ordinary refresh waits for %s', async outcome => {
    let finish!: () => void;
    const gate = new Promise<void>(resolve => { finish = resolve; });
    const refreshError = new Error('synthetic refresh refusal');
    const refresh = vi.spyOn(library.default, 'post').mockImplementation(async () => {
      await gate;
      if (outcome === 'failure') throw refreshError;
      return { data: {} };
    });
    let ordinaryCalls = 0;
    let vaultCalls = 0;
    api.defaults.adapter = async config => {
      if (config.url === '/ordinary') {
        ordinaryCalls += 1;
        if (ordinaryCalls === 1) return reject401(config);
        return { config, data: { control: true }, headers: {}, status: 200, statusText: 'OK' };
      }
      vaultCalls += 1;
      return reject401(config);
    };
    const ordinary = api.get('/ordinary').then(value => ({ value, error: null }), error => ({ value: null, error }));
    try {
      await vi.waitFor(() => expect(refresh).toHaveBeenCalledTimes(1));
      let refused = false;
      const vault = api.post('/auth/vault-export/authorize/local', '{}', once).catch(error => {
        refused = true;
        return error.response?.status;
      });
      await vi.waitFor(() => expect(refused).toBe(true));
      expect(await vault).toBe(401);
      expect(vaultCalls).toBe(1);
    } finally {
      finish();
      const observed = await ordinary;
      if (outcome === 'failure') expect(observed.error).toBe(refreshError);
      else expect(observed.value?.data).toEqual({ control: true });
    }
    expect(vaultCalls).toBe(1);
    expect(ordinaryCalls).toBe(outcome === 'failure' ? 1 : 2);
    expect(refresh).toHaveBeenCalledTimes(1);
  });

  it('retains the independent release-operation refusal policy', async () => {
    const adapter = vi.fn(reject401);
    api.defaults.adapter = adapter;
    const refresh = vi.spyOn(library.default, 'post').mockResolvedValue({ data: {} });
    const config = { _freesdnReleaseNoReplay: true } as AxiosRequestConfig & { _freesdnReleaseNoReplay: true };
    await expect(api.post('/agents/release-operations/owned/publish', '{}', config)).rejects.toMatchObject({ response: { status: 401 } });
    expect(adapter).toHaveBeenCalledTimes(1);
    expect(refresh).not.toHaveBeenCalled();
  });
});

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/** Planned actual Axios-chain checks; adapters are controlled, no server proof. */
import type { AxiosInstance, AxiosRequestConfig, InternalAxiosRequestConfig } from 'axios';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('@/stores/authStore', () => ({ useAuthStore: { setState: vi.fn() } }));
vi.mock('@/demo/mode', () => ({ isDemoMode: false }));
let api: AxiosInstance;
let library: typeof import('axios');
let reject401: (config: InternalAxiosRequestConfig) => Promise<never>;

beforeEach(async () => {
  vi.resetModules();
  library = await import('axios');
  api = (await import('../client')).api;
  reject401 = (config) => Promise.reject(new library.AxiosError('synthetic refusal', 'ERR_BAD_REQUEST', config, undefined,
    { config, data: { error: { message: 'Unauthorized' } }, headers: {}, status: 401, statusText: 'Unauthorized' }));
});
afterEach(() => { vi.restoreAllMocks(); });
const once = { _freesdnReleaseNoReplay: true } as AxiosRequestConfig & { _freesdnReleaseNoReplay: true };


describe('explicit release calls never join refresh/replay', () => {
  it.each(['POST', 'GET'])('does not refresh or replay an opted-out %s', async method => {
    const adapter = vi.fn(reject401);
    api.defaults.adapter = adapter;
    const refresh = vi.spyOn(library.default, 'post').mockResolvedValue({ data: {} });
    await expect(api.request({ ...once, url: '/agents/release-operations/owned', method })).rejects.toMatchObject({ response: { status: 401 } });
    expect(adapter).toHaveBeenCalledTimes(1);
    expect(refresh).not.toHaveBeenCalled();
  });

  it('refuses a release request while an ordinary refresh is pending without queuing it', async () => {
    let finish!: () => void;
    const gate = new Promise<void>(resolve => { finish = resolve; });
    const refresh = vi.spyOn(library.default, 'post').mockImplementation(async () => { await gate; return { data: {} }; });
    let ordinaryCalls = 0;
    let releaseCalls = 0;
    api.defaults.adapter = async config => {
      if (config.url === '/ordinary') {
        ordinaryCalls += 1;
        if (ordinaryCalls === 1) return reject401(config);
        return { config, data: { ok: true }, headers: {}, status: 200, statusText: 'OK' };
      }
      releaseCalls += 1;
      return reject401(config);
    };
    const ordinary = api.get('/ordinary');
    try {
      await vi.waitFor(() => expect(refresh).toHaveBeenCalledTimes(1));
      let refused = false;
      const pending = api.post('/agents/release-operations/owned/publish', '{}', once).catch(() => { refused = true; });
      await vi.waitFor(() => expect(refused).toBe(true));
      await pending;
      expect(releaseCalls).toBe(1);
    } finally {
      finish();
      await ordinary;
    }
    expect(releaseCalls).toBe(1);
    expect(ordinaryCalls).toBe(2);
    expect(refresh).toHaveBeenCalledTimes(1);
  });

  it('preserves the existing ordinary-request refresh behavior as a control', async () => {
    let count = 0;
    api.defaults.adapter = async config => {
      count += 1;
      if (count === 1) return reject401(config);
      return { config, data: { control: true }, headers: {}, status: 200, statusText: 'OK' };
    };
    const refresh = vi.spyOn(library.default, 'post').mockResolvedValue({ data: {} });
    expect((await api.get('/ordinary')).data).toEqual({ control: true });
    expect(count).toBe(2);
    expect(refresh).toHaveBeenCalledTimes(1);
  });
});

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import type { InternalAxiosRequestConfig } from 'axios';
import { afterEach, describe, expect, it, vi } from 'vitest';

vi.mock('@/stores/authStore', () => ({ useAuthStore: { setState: vi.fn() } }));
vi.mock('@/demo/mode', () => ({ isDemoMode: true }));

afterEach(() => {
  vi.doUnmock('@/demo/mockApi');
  vi.resetModules();
});

describe('demo requests stay isolated while loading their data', () => {
  it('does not load fixtures at startup and holds concurrent requests until they load', async () => {
    let release!: () => void;
    const ready = new Promise<void>((resolve) => { release = resolve; });
    const load = vi.fn(async () => {
      await ready;
      return { demoAxiosAdapter: vi.fn(async (config: InternalAxiosRequestConfig) => ({
        data: { demo: true }, status: 200, statusText: 'OK', headers: {}, config,
      })) };
    });
    vi.doMock('@/demo/mockApi', load);
    const { api } = await import('@/lib/api/client');
    expect(load).not.toHaveBeenCalled();
    let completed = 0;
    const reads = [api.get('/sites'), api.get('/devices')].map(async (request) => {
      const response = await request;
      completed++;
      return response;
    });
    await vi.waitFor(() => expect(load).toHaveBeenCalledOnce());
    expect(completed).toBe(0);
    release();
    const responses = await Promise.all(reads);
    expect(responses.map((r) => r.data)).toEqual([{ demo: true }, { demo: true }]);
  });

  it('rejects a failed fixture import without calling the normal Axios transport', async () => {
    vi.doMock('@/demo/mockApi', () => { throw new Error('fixture chunk unavailable'); });
    const { default: axios } = await import('axios');
    const original = axios.defaults.adapter;
    const transport = vi.fn();
    axios.defaults.adapter = transport;
    try {
      const { api } = await import('@/lib/api/client');
      await expect(api.get('/devices')).rejects.toBeInstanceOf(Error);
      await expect(api.post('/firewall/gateways', {})).rejects.toBeInstanceOf(Error);
      expect(transport).not.toHaveBeenCalled();
    } finally {
      axios.defaults.adapter = original;
    }
  });

  it('keeps a canceled request canceled when its delayed fixtures finally arrive', async () => {
    let release!: () => void;
    const ready = new Promise<void>((resolve) => { release = resolve; });
    const load = vi.fn(async () => {
      await ready;
      return { demoAxiosAdapter: vi.fn(async (config: InternalAxiosRequestConfig) => ({
        data: { demo: true }, status: 200, statusText: 'OK', headers: {}, config,
      })) };
    });
    vi.doMock('@/demo/mockApi', load);
    const { api } = await import('@/lib/api/client');
    const controller = new AbortController();
    const request = api.get('/sites', { signal: controller.signal });
    const rejection = expect(request).rejects.toMatchObject({ code: 'ERR_CANCELED' });
    await vi.waitFor(() => expect(load).toHaveBeenCalledOnce());
    controller.abort();
    release();
    await rejection;
  });
});

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Reading the live-read freshness fields and the device-busy 503.
 *
 * The bodies are the ones backend/app/services/device_live_read.py builds:
 * ``stamp()`` adds ``as_of``, ``cached`` and ``cache_reason`` to a dict
 * answer, and ``DeviceBusyError`` is an HTTPException(503) with
 * ``Retry-After: 5`` that the global handler wraps in ``{ error: {...} }``.
 * Errors come from a real axios instance with a stub adapter.
 */
import axios, { AxiosError, AxiosHeaders, type AxiosAdapter } from 'axios';
import { describe, expect, it } from 'vitest';
import {
  DEVICE_BUSY_RETRY_LIMIT,
  deviceBusyMessage,
  deviceBusyRetryDelay,
  isDeviceBusyError,
  isDeviceBusyReason,
  liveReadRetryDelay,
  readLiveFreshness,
  retryWhenDeviceBusy,
} from '@/lib/api/liveRead';
import { queryClient } from '@/lib/queryClient';

const BUSY = 'Device busy: gateway full sync since 14:02:10 UTC (35s). Nothing was sent to it; try again in a few seconds.';

async function failWith(status: number, data: unknown, headers: Record<string, string> = {}): Promise<unknown> {
  const adapter: AxiosAdapter = async (config) => {
    throw new AxiosError(`Request failed with status code ${status}`, AxiosError.ERR_BAD_RESPONSE, config, {}, {
      data,
      status,
      statusText: '',
      headers: new AxiosHeaders({ 'content-type': 'application/json', ...headers }),
      config,
      request: {},
    });
  };
  return axios.create({ adapter }).get('/api/v1/firewall/gateways/x/status').catch((err: unknown) => err);
}

const busy503 = (retryAfter = '5') =>
  failWith(503, { error: { code: 503, message: BUSY, request_id: 'r-1' } }, { 'retry-after': retryAfter });

describe('readLiveFreshness', () => {
  it('reads a remembered answer from the body or from the axios response', () => {
    const body = { gateway_id: 'g', status: {}, as_of: '2026-11-13T14:02:10+00:00', cached: true, cache_reason: 'device_busy' };
    const expected = { asOf: body.as_of, cached: true, reason: 'device_busy' };
    expect(readLiveFreshness(body)).toEqual(expected);
    expect(readLiveFreshness({ data: body, status: 200 })).toEqual(expected);
  });

  it('reads a live answer as not cached', () => {
    expect(readLiveFreshness({ as_of: '2026-11-13T14:02:10Z', cached: false, cache_reason: null })).toEqual({
      asOf: '2026-11-13T14:02:10Z',
      cached: false,
      reason: null,
    });
  });

  it('returns null for answers without a usable as_of', () => {
    expect(readLiveFreshness({ gateway_id: 'g' })).toBeNull();
    expect(readLiveFreshness({ data: [{ as_of: 'x' }] })).toBeNull();
    expect(readLiveFreshness({ as_of: 'not a time', cached: true })).toBeNull();
    expect(readLiveFreshness(null)).toBeNull();
    expect(readLiveFreshness([1, 2])).toBeNull();
  });
});

describe('device busy', () => {
  it('recognises the 503 the backend sends for a busy device', async () => {
    const err = await busy503();
    expect(isDeviceBusyError(err)).toBe(true);
    expect(deviceBusyMessage(err)).toBe(BUSY);
    expect(deviceBusyRetryDelay(err)).toBe(5000);
  });

  it('accepts a typed envelope too', async () => {
    const err = await failWith(503, { error: { code: 503, type: 'device_busy', message: 'Busy' } });
    expect(isDeviceBusyError(err)).toBe(true);
  });

  it('does not treat another 503, or a busy sentence on another status, as busy', async () => {
    const revocation = await failWith(503, {
      error: { code: 503, message: 'Token revocation is temporarily unavailable; the operation was not confirmed' },
    });
    expect(isDeviceBusyError(revocation)).toBe(false);
    expect(isDeviceBusyError(await failWith(502, { error: { code: 502, message: BUSY } }))).toBe(false);
    expect(isDeviceBusyError(new Error(BUSY))).toBe(false);
    expect(deviceBusyMessage(revocation)).toBeNull();
  });

  it('keeps the wait between one second and a minute', async () => {
    expect(deviceBusyRetryDelay(await busy503('0'))).toBe(1000);
    expect(deviceBusyRetryDelay(await busy503('600'))).toBe(60_000);
    expect(deviceBusyRetryDelay(await failWith(503, { error: { code: 503, message: BUSY } }))).toBe(5000);
  });

  it('recognises the skipped-sync sentence in last_sync_error', () => {
    expect(isDeviceBusyReason('Device busy: firewall health poll since 10:01:00 UTC (3s)')).toBe(true);
    expect(isDeviceBusyReason('Full sync backed off after 3 failures')).toBe(false);
    expect(isDeviceBusyReason(null)).toBe(false);
  });
});

describe('retrying a busy device', () => {
  it('waits out busy answers up to the limit and keeps the ordinary retry count', async () => {
    const busy = await busy503();
    const ordinary = await failWith(500, { error: { code: 500, message: 'boom' } });
    const retry = retryWhenDeviceBusy(1);
    expect(retry(0, busy)).toBe(true);
    expect(retry(DEVICE_BUSY_RETRY_LIMIT - 1, busy)).toBe(true);
    expect(retry(DEVICE_BUSY_RETRY_LIMIT, busy)).toBe(false);
    expect(retry(0, ordinary)).toBe(true);
    expect(retry(1, ordinary)).toBe(false);
    expect(retryWhenDeviceBusy()(0, ordinary)).toBe(false);
  });

  it('waits Retry-After for a busy device and backs off for anything else', async () => {
    expect(liveReadRetryDelay(3, await busy503('7'))).toBe(7000);
    expect(liveReadRetryDelay(0, new Error('x'))).toBe(1000);
    expect(liveReadRetryDelay(2, new Error('x'))).toBe(4000);
    expect(liveReadRetryDelay(10, new Error('x'))).toBe(30_000);
  });

  it('is the app-wide default, so every page waits out a busy device', async () => {
    const { retry, retryDelay } = queryClient.getDefaultOptions().queries ?? {};
    expect(typeof retry).toBe('function');
    const busy = await busy503();
    const ordinary = new Error('x');
    const asFn = retry as (count: number, error: unknown) => boolean;
    expect(asFn(5, busy)).toBe(true);
    expect(asFn(0, ordinary)).toBe(true);
    expect(asFn(1, ordinary)).toBe(false);
    expect((retryDelay as (count: number, error: unknown) => number)(0, busy)).toBe(5000);
  });
});

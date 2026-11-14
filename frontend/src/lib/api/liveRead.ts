// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Live device reads that wait their turn (backend/app/services/device_live_read.py).
 *
 * A page that reads a device live no longer sends its request alongside a
 * scheduled sync. The backend waits briefly for the device and then either:
 *
 * - reads live and answers with ``as_of`` (now), ``cached: false``;
 * - answers with the last read it remembers: ``as_of`` (when that read was
 *   made), ``cached: true``, ``cache_reason: "device_busy"``;
 * - with nothing remembered, answers **503** with ``Retry-After`` and a
 *   message that starts with "Device busy". Nothing was sent to the device.
 *
 * The same "Device busy: ..." sentence is what a skipped background sync
 * leaves in a gateway's ``last_sync_error``.
 *
 * This module reads those signals for any vendor: the gateway reads have them
 * today and the controller, hypervisor, storage, camera and phone reads are
 * gaining the same three fields. Nothing here knows which route answered.
 */
import { parseApiError } from './errors';

/** What a live read says about how fresh its answer is. */
export interface LiveReadFreshness {
  /** ISO time the answer was read from the device. */
  asOf: string;
  /** True when this is the remembered answer, not a read made just now. */
  cached: boolean;
  /** Why the remembered answer was served (``device_busy``), or null. */
  reason: string | null;
}

type Dict = Record<string, unknown>;

const isDict = (value: unknown): value is Dict =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

/**
 * The freshness fields of a live read, or null when the answer has none.
 *
 * Accepts the response body or the axios response that wraps it, because
 * React Query caches whichever the query function returned.
 */
export function readLiveFreshness(value: unknown): LiveReadFreshness | null {
  if (!isDict(value)) return null;
  let body: Dict = value;
  if (!('as_of' in body) && isDict(body.data) && 'as_of' in body.data) body = body.data;
  const asOf = body.as_of;
  if (typeof asOf !== 'string' || !asOf.trim() || Number.isNaN(Date.parse(asOf))) return null;
  const reason = typeof body.cache_reason === 'string' && body.cache_reason ? body.cache_reason : null;
  return { asOf, cached: body.cached === true, reason };
}

/** True for the "Device busy: ..." sentence the backend writes. */
export function isDeviceBusyReason(text: unknown): boolean {
  return typeof text === 'string' && /^\s*device busy\b/i.test(text);
}

/**
 * True when a read was refused because the device was busy and nothing was
 * remembered yet: an answer to wait out, not a failure.
 */
export function isDeviceBusyError(error: unknown): boolean {
  if (!isDict(error) || !isDict(error.response)) return false;
  const info = parseApiError(error);
  if (info.status !== 503) return false;
  return info.type === 'device_busy' || isDeviceBusyReason(info.message);
}

/** The server's reason for a device-busy answer, or null for any other error. */
export function deviceBusyMessage(error: unknown): string | null {
  return isDeviceBusyError(error) ? parseApiError(error).message : null;
}

/** Wait used when a busy answer carries no ``Retry-After`` (the backend sends 5). */
export const DEVICE_BUSY_DEFAULT_WAIT_MS = 5_000;
const DEVICE_BUSY_MIN_WAIT_MS = 1_000;
const DEVICE_BUSY_MAX_WAIT_MS = 60_000;

/**
 * How many busy answers in a row a query waits out before it shows an error.
 * Each attempt already waits up to ``DEVICE_UI_READ_MAX_WAIT_SECONDS`` (15 s)
 * on the server, then ``Retry-After`` here, so this is about four minutes:
 * long enough for a full firewall sync, short enough not to spin forever.
 */
export const DEVICE_BUSY_RETRY_LIMIT = 12;

/** Milliseconds to wait before asking a busy device again. */
export function deviceBusyRetryDelay(error: unknown): number {
  const seconds = parseApiError(error).retryAfter;
  const ms = seconds === null ? DEVICE_BUSY_DEFAULT_WAIT_MS : seconds * 1000;
  return Math.min(DEVICE_BUSY_MAX_WAIT_MS, Math.max(DEVICE_BUSY_MIN_WAIT_MS, ms));
}

/**
 * A React Query ``retry`` function: wait out device-busy answers, and retry
 * any other failure ``otherRetries`` times (the app default is 1).
 */
export function retryWhenDeviceBusy(otherRetries = 0) {
  return (failureCount: number, error: unknown): boolean =>
    isDeviceBusyError(error)
      ? failureCount < DEVICE_BUSY_RETRY_LIMIT
      : failureCount < otherRetries;
}

/**
 * A React Query ``retryDelay``: the server's ``Retry-After`` for a busy
 * device, React Query's own exponential backoff for anything else.
 */
export function liveReadRetryDelay(failureCount: number, error: unknown): number {
  if (isDeviceBusyError(error)) return deviceBusyRetryDelay(error);
  return Math.min(1000 * 2 ** failureCount, 30_000);
}

/**
 * Spread into a query that reads a device live. ``otherRetries`` keeps the
 * query's previous retry count for ordinary failures (0 for a query that had
 * ``retry: false``).
 */
export function liveReadQueryOptions(otherRetries = 0) {
  return { retry: retryWhenDeviceBusy(otherRetries), retryDelay: liveReadRetryDelay };
}

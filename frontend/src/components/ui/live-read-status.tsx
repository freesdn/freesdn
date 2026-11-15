// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN Design System · live-read freshness
 *
 * A device read that found the device busy is answered with the last read the
 * server remembers (``as_of``, ``cached: true``) or, with nothing remembered,
 * with 503 + ``Retry-After`` (see src/lib/api/liveRead.ts). These components
 * say so quietly, so a busy firewall reads as "as of 14:02", not as an error.
 *
 *   <AsOfIndicator asOf={body.as_of} reason={body.cache_reason} />
 *   <LiveReadStatus queryKey={['gateways', id]} />   // every active read under the key
 *   <LiveReadStatus deviceId={id} />                  // every active read naming the device
 *
 * ``LiveReadStatus`` watches the query cache, so a page adds it once and every
 * panel under the key (the open tab's reads) is covered, whatever the vendor.
 */
import { useCallback, useMemo, useSyncExternalStore } from 'react';
import { useTranslation } from 'react-i18next';
import { useQueryClient, type Query, type QueryKey } from '@tanstack/react-query';
import { Clock, RefreshCw } from 'lucide-react';
import { cn } from '@/lib/utils';
import { deviceBusyMessage, isDeviceBusyError, readLiveFreshness } from '@/lib/api/liveRead';

const PILL =
  'inline-flex max-w-full items-center gap-1.5 rounded-full border border-border bg-muted/40 px-2.5 py-0.5 text-xs text-muted-foreground tabular-nums';

function sameDay(a: Date, b: Date): boolean {
  return a.getFullYear() === b.getFullYear() && a.getMonth() === b.getMonth() && a.getDate() === b.getDate();
}

/** "14:02", or "12 Nov, 14:02" for an answer read on another day. */
export function formatAsOf(asOf: string, now: Date = new Date(), locale?: string): string {
  const when = new Date(asOf);
  if (Number.isNaN(when.getTime())) return asOf;
  const time = when.toLocaleTimeString(locale, { hour: '2-digit', minute: '2-digit' });
  if (sameDay(when, now)) return time;
  return `${when.toLocaleDateString(locale, { day: 'numeric', month: 'short' })}, ${time}`;
}

export interface AsOfIndicatorProps {
  /** ISO time the answer was read from the device. */
  asOf: string;
  /** ``cache_reason`` from the answer (``device_busy``), if any. */
  reason?: string | null;
  className?: string;
}

/** "As of 14:02, device busy": the answer shown is the last one read. */
export function AsOfIndicator({ asOf, reason, className }: AsOfIndicatorProps) {
  const { t, i18n } = useTranslation('common');
  const time = formatAsOf(asOf, new Date(), i18n.language);
  const full = Number.isNaN(new Date(asOf).getTime()) ? asOf : new Date(asOf).toLocaleString(i18n.language);
  const busy = reason === 'device_busy';
  return (
    <span
      className={cn(PILL, className)}
      title={busy ? t('LiveRead.asOfBusyTitle', { when: full }) : t('LiveRead.asOfTitle', { when: full })}
      data-testid="live-read-as-of"
    >
      <Clock className="h-3 w-3 shrink-0" aria-hidden="true" />
      <span className="truncate">{busy ? t('LiveRead.asOfBusy', { time }) : t('LiveRead.asOf', { time })}</span>
    </span>
  );
}

/** "Device busy, retrying": a busy answer being waited out, not an error. */
export function DeviceBusyIndicator({ message, className }: { message?: string | null; className?: string }) {
  const { t } = useTranslation('common');
  return (
    <span className={cn(PILL, className)} title={message ?? undefined} data-testid="live-read-busy">
      <RefreshCw className="h-3 w-3 shrink-0 animate-spin motion-reduce:animate-none" aria-hidden="true" />
      <span className="truncate">{t('LiveRead.busyRetrying')}</span>
    </span>
  );
}

export interface LiveReadSummary {
  /** The oldest remembered answer on show, and how many panels show one. */
  cached: { asOf: string; reason: string | null; count: number } | null;
  /** Reads waiting out a busy device (being retried after ``Retry-After``). */
  waiting: { count: number; message: string | null } | null;
  /** Reads that stayed busy through every retry. */
  stillBusy: { count: number; message: string | null } | null;
}

const EMPTY: LiveReadSummary = { cached: null, waiting: null, stillBusy: null };

/** Summarise the freshness of the given queries (exported for tests). */
export function summariseLiveReads(queries: readonly Query[]): LiveReadSummary {
  let oldest: { asOf: string; reason: string | null } | null = null;
  let cachedCount = 0;
  let waitingCount = 0;
  let waitingMessage: string | null = null;
  let stuckCount = 0;
  let stuckMessage: string | null = null;
  for (const query of queries) {
    const { state } = query;
    const fresh = readLiveFreshness(state.data);
    if (fresh?.cached) {
      cachedCount += 1;
      if (!oldest || Date.parse(fresh.asOf) < Date.parse(oldest.asOf)) {
        oldest = { asOf: fresh.asOf, reason: fresh.reason };
      }
    }
    if (state.fetchStatus !== 'idle' && isDeviceBusyError(state.fetchFailureReason)) {
      waitingCount += 1;
      waitingMessage ??= deviceBusyMessage(state.fetchFailureReason);
    } else if (state.status === 'error' && state.fetchStatus === 'idle' && isDeviceBusyError(state.error)) {
      stuckCount += 1;
      stuckMessage ??= deviceBusyMessage(state.error);
    }
  }
  if (!oldest && !waitingCount && !stuckCount) return EMPTY;
  return {
    cached: oldest ? { ...oldest, count: cachedCount } : null,
    waiting: waitingCount ? { count: waitingCount, message: waitingMessage } : null,
    stillBusy: stuckCount ? { count: stuckCount, message: stuckMessage } : null,
  };
}

/** Which queries a summary covers. */
export interface LiveReadScope {
  /** Prefix of the queries that read the device, e.g. ``['gateways', id]``. */
  queryKey?: QueryKey;
  /**
   * Or: every query whose key mentions this device id anywhere, for a page
   * whose tabs use several key shapes (``['mikrotik-leases', id]``, ...).
   */
  deviceId?: string;
}

function inScope(query: Query, deviceId: string | undefined): boolean {
  return deviceId === undefined || query.queryKey.some((part) => part === deviceId);
}

/**
 * The freshness of every ACTIVE query in scope (a disabled query, such as
 * another tab's, is not counted). Re-renders only when the summary changes.
 */
export function useLiveReadSummary({ queryKey, deviceId }: LiveReadScope): LiveReadSummary {
  const cache = useQueryClient().getQueryCache();
  const keyHash = queryKey === undefined ? null : JSON.stringify(queryKey);
  const snapshot = useCallback(() => {
    const filters = keyHash === null ? { type: 'active' as const } : { queryKey: JSON.parse(keyHash) as QueryKey, type: 'active' as const };
    const queries = cache.findAll(filters).filter((query) => inScope(query, deviceId));
    return JSON.stringify(summariseLiveReads(queries));
  }, [cache, keyHash, deviceId]);
  const subscribe = useCallback((onChange: () => void) => cache.subscribe(onChange), [cache]);
  const raw = useSyncExternalStore(subscribe, snapshot, snapshot);
  return useMemo(() => JSON.parse(raw) as LiveReadSummary, [raw]);
}

export interface LiveReadStatusProps extends LiveReadScope {
  className?: string;
}

/**
 * One quiet line for a page that reads a device live: "Device busy, retrying"
 * while a busy answer is being waited out, "As of 14:02, device busy" while a
 * panel shows the last answer read, and "Device still busy" with a retry once
 * the waiting stopped. Renders nothing when every read is live.
 */
export function LiveReadStatus({ queryKey, deviceId, className }: LiveReadStatusProps) {
  const { t } = useTranslation('common');
  const queryClient = useQueryClient();
  const { cached, waiting, stillBusy } = useLiveReadSummary({ queryKey, deviceId });
  if (!cached && !waiting && !stillBusy) return null;
  const retryBusy = () => {
    void queryClient.refetchQueries({
      queryKey,
      type: 'active',
      predicate: (query) =>
        inScope(query, deviceId) && query.state.status === 'error' && isDeviceBusyError(query.state.error),
    });
  };
  return (
    <div className={cn('flex flex-wrap items-center gap-2', className)} role="status" aria-live="polite">
      {waiting && <DeviceBusyIndicator message={waiting.message} />}
      {cached && <AsOfIndicator asOf={cached.asOf} reason={cached.reason} />}
      {stillBusy && (
        <span className={PILL} title={stillBusy.message ?? undefined} data-testid="live-read-still-busy">
          <span className="truncate">{t('LiveRead.stillBusy')}</span>
          <button
            type="button"
            onClick={retryBusy}
            className="rounded font-medium text-foreground underline-offset-2 hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
          >
            {t('LiveRead.retry')}
          </button>
        </span>
      )}
    </div>
  );
}

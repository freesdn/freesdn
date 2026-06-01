// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
//
// The shared TanStack QueryClient. Lives in its own module (not main.tsx) so
// non-React code, notably the auth store's logout, can import and clear it
// without a circular import on the app entry point. Clearing on logout prevents
// the previous user's cached data (Connections, run payloads, device lists, …)
// from briefly surfacing for the next user on a shared browser.
import { MutationCache, QueryClient } from '@tanstack/react-query';
import { emitMutationError } from './toastBridge';

// every per-tab stage mutation
// invalidates only its own list key. The Pending Changes badge + drawer
// subscribe to a CROSS-CUTTING key (``['pending-changes', vendor, gatewayId]``),
// so without a shared invalidator the badge count stays stale for up to 8s after
// every stage. Rather than touching ~30+ onSuccess sites across 13 tabs, we hook
// the MutationCache globally and invalidate the cross-cutting key whenever a
// mutation returns a payload shaped like a ``PendingChangeResponse`` (has
// ``feature`` + ``operation`` + ``status`` in {pending, applying, applied,
// discarded, failed}). This is the canonical shape every stage / apply / discard
// endpoint returns, vendor-agnostic.
const STAGE_RESPONSE_STATUSES = new Set([
  'pending',
  'applying',
  'applied',
  'discarded',
  'failed',
]);

function looksLikePendingChange(data: unknown): boolean {
  if (typeof data !== 'object' || data === null) return false;
  let d = data as Record<string, unknown>;
  // The mutationFn for every stage call returns an axios Promise, so ``data`` in
  // the MutationCache callback is the AxiosResponse wrapper, the actual
  // PendingChangeResponse body lives on ``.data``. Unwrap one level before
  // shape-checking. Without the unwrap, the check read ``d.feature`` on
  // the AxiosResponse (always undefined), so the invalidator never fired
  // and the Pending Changes badge stayed at zero.
  if (
    typeof d.data === 'object' &&
    d.data !== null &&
    typeof (d.data as Record<string, unknown>).feature === 'string'
  ) {
    d = d.data as Record<string, unknown>;
  }
  return (
    typeof d.feature === 'string' &&
    typeof d.operation === 'string' &&
    typeof d.status === 'string' &&
    STAGE_RESPONSE_STATUSES.has(d.status as string)
  );
}

const mutationCache = new MutationCache({
  onSuccess: (data, _variables, _context, mutation) => {
    if (looksLikePendingChange(data)) {
      mutation.options.meta = mutation.options.meta ?? {};
      // Invalidate every pending-changes query, the cache stores entries by
      // (vendor, gatewayId), but a stage on one of them is cheap enough to nudge
      // all of them since each tab only has one or two visible at a time.
      queryClient.invalidateQueries({ queryKey: ['pending-changes'] });
    }
  },
  // Global error safety net: any mutation that did NOT supply its own onError
  // still surfaces a uniform, localized error toast. Mutations that DO define
  // onError own their messaging, so we skip them here to avoid double toasts.
  // The toast is dispatched through toastBridge so this non-React module stays
  // free of React/i18n/axios imports (and the import cycle that would create).
  onError: (error, _variables, _context, mutation) => {
    if (mutation.options.onError) return;
    emitMutationError(error);
  },
});

export const queryClient = new QueryClient({
  mutationCache,
  defaultOptions: {
    queries: {
      staleTime: 1000 * 60 * 5, // 5 minutes
      retry: 1,
      refetchOnWindowFocus: false,
    },
  },
});

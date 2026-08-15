// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * React hook for adapter capability-based feature gating.
 *
 * The companion to ``useDeviceCapabilities``: this one queries the
 * controller's ADAPTER manifest (Omada / MikroTik / UniFi / …) so
 * the UI can hide gateway-* tabs and buttons for features the
 * underlying vendor / adapter doesn't implement.
 *
 * Backend: ``GET /api/v1/controllers/{id}/capabilities`` returns the
 * manifest's flat ``capabilities`` array plus a per-device-type
 * breakdown. Pages call ``has('wifi.wids_wips')`` to gate a tab.
 *
 * Usage::
 *
 *     const caps = useControllerCapabilities(controllerId);
 *     {caps.has('wifi.wids_wips') && <WidsWipsTab />}
 *
 *     // Per-device-type scoping:
 *     {caps.hasFor('access_point', 'wifi.dfs') && <DfsPanel />}
 */

import { useQuery } from '@tanstack/react-query';

import {
  controllersApi,
  type ControllerCapabilities,
} from '@/lib/api/controllers';

export interface UseControllerCapabilitiesResult {
  /** Raw response from the backend. ``undefined`` while loading. */
  capabilities: ControllerCapabilities | undefined;

  /** True while the query is in flight. */
  isLoading: boolean;

  /** Truthy when the query failed. UI should fall back to "show
   *  everything" rather than hiding by accident. */
  error: Error | null;

  /** Refetch (e.g. after switching controller). */
  refetch: () => void;

  /** ``true`` when the adapter advertises the given capability code.
   *  When ``capabilities`` hasn't loaded yet returns ``true`` so the
   *  UI doesn't flicker tabs hidden during the first paint. Returns
   *  ``true`` on error too, fail-open is safer than fail-closed for
   *  navigation. */
  has: (code: string) => boolean;

  /** Same shape as ``has`` but scoped to a specific device type
   *  (e.g. ``access_point``, ``switch``, ``gateway``). */
  hasFor: (deviceType: string, code: string) => boolean;
}

export function useControllerCapabilities(
  controllerId: string | undefined | null,
): UseControllerCapabilitiesResult {
  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ['controller-capabilities', controllerId],
    queryFn: async () => {
      if (!controllerId) throw new Error('controller id required');
      const response = await controllersApi.getCapabilities(controllerId);
      return response.data;
    },
    enabled: !!controllerId,
    // Capabilities don't change between requests in normal operation
    // (they change only when the adapter is upgraded), so cache for
    // an hour. The user can hard-refresh if they need to bust it.
    staleTime: 60 * 60 * 1000,
    retry: 1,
  });

  // Fail-open: when we don't yet know what the adapter supports,
  // assume it supports everything so the UI doesn't show empty
  // navigation. The page will surface a real "not implemented" /
  // 404 from the backend if the operator clicks through.
  const fallback = !data;

  return {
    capabilities: data,
    isLoading,
    error: error as Error | null,
    refetch,
    has: (code: string) =>
      fallback ? true : (data?.capabilities ?? []).includes(code),
    hasFor: (deviceType: string, code: string) =>
      fallback
        ? true
        : ((data?.by_device_type ?? {})[deviceType] ?? []).includes(code),
  };
}

export default useControllerCapabilities;

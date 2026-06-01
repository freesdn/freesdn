// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN - Site-Filtered Query Hook
 *
 * Wraps React Query's useQuery to automatically inject site_id
 * from the global siteStore into every query key + query function.
 * When the user switches sites in the TopBar, all active queries
 * using this hook automatically re-fetch.
 */
import { useQuery, type UseQueryOptions, type QueryKey } from '@tanstack/react-query';
import { useSiteStore } from '@/stores/siteStore';

/**
 * useQuery wrapper that automatically:
 * 1. Adds selectedSiteId to the query key (triggers re-fetch on site change)
 * 2. Passes siteId to the query function
 * 3. Handles "All Sites" (null) by letting the caller omit site_id
 *
 * @param baseKey  Base query key, e.g. ['devices']
 * @param queryFn  Query function that receives siteId (null = global)
 * @param options  Standard React Query options (minus queryKey / queryFn)
 */
export function useSiteFilteredQuery<TData = unknown>(
  baseKey: QueryKey,
  queryFn: (siteId: string | null) => Promise<TData>,
  options?: Omit<UseQueryOptions<TData>, 'queryKey' | 'queryFn'>
) {
  const selectedSiteId = useSiteStore((s) => s.selectedSiteId);

  return useQuery<TData>({
    queryKey: [
      ...(Array.isArray(baseKey) ? baseKey : [baseKey]),
      { siteId: selectedSiteId },
    ],
    queryFn: () => queryFn(selectedSiteId),
    ...options,
  });
}

/**
 * Helper: converts a siteId into the API params shape.
 * Returns `{ site_id: siteId }` when a site is selected,
 * or `{}` in global mode so the param is simply omitted.
 */
export function siteParams(siteId: string | null): { site_id?: string } {
  return siteId ? { site_id: siteId } : {};
}

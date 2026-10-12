// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { api } from './client';
import type { Site, CreateSiteRequest } from './types';

export const sitesApi = {
  getAll: (params?: { page?: number; per_page?: number; search?: string; is_active?: boolean; organization_id?: string }) =>
    api.get('/sites/', { params }),
  getById: (id: string) => api.get(`/sites/${id}`),
  create: (data: Record<string, unknown>) => api.post('/sites/', data),
  update: (id: string, data: Record<string, unknown>) => api.patch(`/sites/${id}`, data),
  delete: (id: string) => api.delete(`/sites/${id}`),
};

/** Backend /sites caps per_page at 100 (Query le=100). Clamp so callers
 *  asking for more get the max instead of a 422. */
const SITES_MAX_PER_PAGE = 100;

/** Shared query config for every "pick a site" dropdown.
 *
 * Two defects made this shared rather than copied into each dialog:
 *
 * 1. The app QueryClient sets `staleTime: 5 minutes` with
 *    `refetchOnWindowFocus: false` (see lib/queryClient.ts). A site created
 *    while a dialog had already fetched ['sites'] stayed INVISIBLE for five
 *    minutes: reopening the dialog served cache and never revalidated, so a
 *    freshly created site could not be chosen. A picker is opened precisely
 *    when the list has to be current, so it always revalidates.
 *
 * 2. Five dialogs registered DIFFERENT query functions under the IDENTICAL
 *    key ['sites'] -- most with the default per_page (20), one with 100.
 *    React Query caches by key alone, so whichever dialog mounted first
 *    decided the page size for all of them. Above 20 sites the rest silently
 *    truncated. One key, one fetch, one page size.
 *
 * NOTE: staleTime alone is not a refetch TRIGGER. These dialogs stay
 * mounted between opens, so each consumer must also pass `enabled: open`
 * -- re-enabling a stale query is what actually refetches it.
 *
 * The key stays prefixed with 'sites' so existing
 * `invalidateQueries({ queryKey: ['sites'] })` calls still match it.
 */
export const sitePickerQuery = {
  queryKey: ['sites', 'picker', { per_page: SITES_MAX_PER_PAGE }] as const,
  queryFn: async () => (await sitesApi.getAll({ per_page: SITES_MAX_PER_PAGE })).data,
  staleTime: 0,
  refetchOnMount: 'always' as const,
};

export const sitesApiV2 = {
  list: (params?: { page?: number; per_page?: number; page_size?: number; search?: string; site_type?: string }) => {
    // Backend only accepts `per_page` (not `page_size`); accept either here and
    // forward `per_page`, clamped to the backend's le=100 ceiling.
    const { page_size, per_page, ...rest } = params ?? {};
    const requested = per_page ?? page_size;
    const normalized =
      requested != null
        ? { ...rest, per_page: Math.min(requested, SITES_MAX_PER_PAGE) }
        : rest;
    return api.get<{ items: Site[]; total: number; page: number; per_page: number; pages: number }>(
      '/sites', { params: normalized }
    );
  },

  getById: (id: string) =>
    api.get<Site>(`/sites/${id}`),

  create: (data: CreateSiteRequest) =>
    api.post<Site>('/sites', data),

  update: (id: string, data: Partial<CreateSiteRequest>) =>
    api.patch<Site>(`/sites/${id}`, data),

  delete: (id: string, force?: boolean) =>
    api.delete(`/sites/${id}`, { params: { force } }),
};

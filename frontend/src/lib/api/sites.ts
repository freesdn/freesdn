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

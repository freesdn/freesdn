// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN - Site Context Store
 *
 * Global site context that persists across navigation.
 * Controls which site's data is displayed throughout the UI.
 * null selectedSiteId = "All Sites" (global aggregate view).
 */
import { create } from 'zustand';
import { persist } from 'zustand/middleware';

export interface SiteInfo {
  id: string;
  name: string;
  site_type?: string;
  is_active?: boolean;
}

interface SiteState {
  // State
  selectedSiteId: string | null; // null = "All Sites" (global view)
  sites: SiteInfo[];
  isLoading: boolean;

  // Actions
  selectSite: (id: string | null) => void;
  setSites: (sites: SiteInfo[]) => void;
  setLoading: (loading: boolean) => void;

  // Derived helpers
  getCurrentSite: () => SiteInfo | null;
  isGlobalView: () => boolean;
}

/** Site-only pages · redirect to dashboard when switching to global */
export const SITE_ONLY_PATHS = ['/topology', '/discovery'];

/** Global-only pages · hidden in site mode (handled by sidebar visibility) */
export const GLOBAL_ONLY_PATHS = [
  '/sites',
  '/users',
  '/roles',
  '/organizations',
  '/drivers',
  '/notification-providers',
];

export const useSiteStore = create<SiteState>()(
  persist(
    (set, get) => ({
      selectedSiteId: null,
      sites: [],
      isLoading: false,

      selectSite: (id) => {
        set({ selectedSiteId: id });
      },

      setSites: (sites) => {
        const state = get();
        const update: Partial<Pick<SiteState, 'sites' | 'selectedSiteId'>> = { sites };

        // Validate: if selected site no longer exists, reset to global
        if (
          state.selectedSiteId &&
          !sites.find((s) => s.id === state.selectedSiteId)
        ) {
          update.selectedSiteId = null;
        }

        // Auto-select if exactly one site and currently in global
        if (sites.length === 1 && state.selectedSiteId === null) {
          update.selectedSiteId = sites[0].id;
        }

        set(update);
      },

      setLoading: (loading) => set({ isLoading: loading }),

      getCurrentSite: () => {
        const { sites, selectedSiteId } = get();
        return sites.find((s) => s.id === selectedSiteId) ?? null;
      },

      isGlobalView: () => get().selectedSiteId === null,
    }),
    {
      name: 'freesdn-site-context',
      partialize: (state) => ({
        selectedSiteId: state.selectedSiteId,
        // Don't persist sites array · always fetch fresh from API
      }),
    }
  )
);

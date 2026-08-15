// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN · Sidebar UI State
 *
 * Persists which sidebar sections are expanded/collapsed.
 * Default: ALL sections expanded · every nav item visible by default.
 * Users can collapse sections they don't use; preference persists.
 */

import { create } from 'zustand';
import { persist } from 'zustand/middleware';

export type SectionId =
  | 'overview'
  | 'network'
  | 'cameras'
  | 'voip'
  | 'infrastructure'
  | 'operations'
  | 'automation'
  | 'administration';

const DEFAULT_EXPANDED: Record<SectionId, boolean> = {
  overview: true,
  network: true,
  cameras: true,
  voip: true,
  infrastructure: true,
  operations: true,
  automation: true,
  administration: true,
};

/** Recent rail only appears once user has visited at least this many distinct nav routes. */
export const RECENT_VISIBILITY_THRESHOLD = 5;

interface SidebarState {
  sections: Record<SectionId, boolean>;
  toggleSection: (id: SectionId) => void;
  expandSection: (id: SectionId) => void;
  setAllSections: (expanded: boolean) => void;
  /** Recently visited routes · most recent first */
  recentRoutes: string[];
  trackVisit: (path: string, label: string) => void;
}

interface RecentRoute {
  path: string;
  label: string;
}

// Stable empty-array reference for the useRecentRoutes selector. Returning a
// fresh `[]` literal when recentRoutesV2 is undefined makes the Zustand
// getSnapshot return a new reference every call, which React 19's
// useSyncExternalStore treats as an infinite update loop ("The result of
// getSnapshot should be cached"). Returning this shared constant keeps the
// snapshot stable. See useRecentRoutes below.
const EMPTY_RECENT_ROUTES: readonly RecentRoute[] = [];

interface SidebarStateInternal {
  sections: Record<SectionId, boolean>;
  recentRoutesV2: RecentRoute[];
}

export const useSidebarStore = create<SidebarState>()(
  persist(
    (set, get) => ({
      sections: { ...DEFAULT_EXPANDED },
      recentRoutes: [],
      // Initialize the internal V2 field so it is NEVER undefined on first
      // render, otherwise useRecentRoutes' `?? []` fallback returns a fresh
      // array every call and React 19 useSyncExternalStore infinite-loops.
      ...({ recentRoutesV2: [] } as unknown as Partial<SidebarState>),

      toggleSection: (id) =>
        set((state) => ({
          sections: { ...state.sections, [id]: !state.sections[id] },
        })),

      expandSection: (id) =>
        set((state) => ({
          sections: { ...state.sections, [id]: true },
        })),

      setAllSections: (expanded) =>
        set(() => ({
          sections: Object.fromEntries(
            (Object.keys(DEFAULT_EXPANDED) as SectionId[]).map((k) => [k, expanded]),
          ) as Record<SectionId, boolean>,
        })),

      trackVisit: (path, label) => {
        const internal = get() as unknown as SidebarStateInternal;
        const existing = internal.recentRoutesV2 ?? [];
        const filtered = existing.filter((r) => r.path !== path);
        const next = [{ path, label }, ...filtered].slice(0, 10);
        set({
          // expose paths via legacy field for compat with selectors that just want paths
          recentRoutes: next.map((r) => r.path),
          // and store full {path,label} via the internal field (kept by persist)
          ...({ recentRoutesV2: next } as unknown as Partial<SidebarState>),
        });
      },
    }),
    {
      name: 'freesdn-sidebar',
      version: 2,
      partialize: (state) =>
        ({
          sections: state.sections,
          recentRoutesV2:
            (state as unknown as SidebarStateInternal).recentRoutesV2 ?? [],
        }) as Partial<SidebarState>,
    },
  ),
);

/** Helper to read recently visited routes with their labels. */
export function useRecentRoutes(): RecentRoute[] {
  return useSidebarStore((s) => {
    const internal = s as unknown as SidebarStateInternal;
    return internal.recentRoutesV2 ?? (EMPTY_RECENT_ROUTES as RecentRoute[]);
  });
}

// ─────────────────────────────────────────────────────────────────
// Global UI dialogs (command palette, shortcuts cheatsheet)
// Kept separate from persisted sidebar state · these are ephemeral.
// ─────────────────────────────────────────────────────────────────

interface UIPaletteState {
  commandPaletteOpen: boolean;
  shortcutsOpen: boolean;
  setCommandPaletteOpen: (open: boolean) => void;
  toggleCommandPalette: () => void;
  setShortcutsOpen: (open: boolean) => void;
  openShortcuts: () => void;
}

export const useUIPaletteStore = create<UIPaletteState>((set) => ({
  commandPaletteOpen: false,
  shortcutsOpen: false,
  setCommandPaletteOpen: (open) => set({ commandPaletteOpen: open }),
  toggleCommandPalette: () =>
    set((state) => ({ commandPaletteOpen: !state.commandPaletteOpen })),
  setShortcutsOpen: (open) => set({ shortcutsOpen: open }),
  openShortcuts: () => set({ shortcutsOpen: true }),
}));

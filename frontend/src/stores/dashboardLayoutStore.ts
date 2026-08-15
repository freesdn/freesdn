// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Dashboard Layout Store
 * ========================
 *
 * Persists the user's customised home dashboard:
 *  - which widgets are enabled AND their order (the array IS the render order)
 *  - whether the user is in "customize" mode (transient · not persisted)
 *
 * Drag-and-drop reorder calls `reorderWidgets(activeId, overId)` which moves
 * `activeId` to `overId`'s slot via arrayMove semantics.
 */

import { create } from 'zustand';
import { devtools, persist } from 'zustand/middleware';
import { immer } from 'zustand/middleware/immer';

interface DashboardLayoutState {
  /** Ordered widget-ids the user has enabled. Index in the array IS the render position. */
  enabledWidgets: string[];
  /** Customize mode toggles edit affordances on each widget (X button, drag handle, dashed outline). */
  isCustomizing: boolean;

  setEnabledWidgets: (ids: string[]) => void;
  addWidget: (id: string) => void;
  removeWidget: (id: string) => void;
  reorderWidgets: (activeId: string, overId: string) => void;
  resetLayout: (defaults: string[]) => void;
  setCustomizing: (on: boolean) => void;
  toggleCustomizing: () => void;
}

export const useDashboardLayoutStore = create<DashboardLayoutState>()(
  devtools(
    persist(
      immer((set) => ({
        // Empty until first read · DashboardPage seeds defaults from the registry.
        enabledWidgets: [],
        isCustomizing: false,

        setEnabledWidgets: (ids) =>
          set((state) => {
            state.enabledWidgets = ids;
          }),

        addWidget: (id) =>
          set((state) => {
            if (!state.enabledWidgets.includes(id)) {
              state.enabledWidgets.push(id);
            }
          }),

        removeWidget: (id) =>
          set((state) => {
            state.enabledWidgets = state.enabledWidgets.filter((w) => w !== id);
          }),

        reorderWidgets: (activeId, overId) =>
          set((state) => {
            const from = state.enabledWidgets.indexOf(activeId);
            const to = state.enabledWidgets.indexOf(overId);
            if (from === -1 || to === -1 || from === to) return;
            const [moved] = state.enabledWidgets.splice(from, 1);
            state.enabledWidgets.splice(to, 0, moved);
          }),

        resetLayout: (defaults) =>
          set((state) => {
            state.enabledWidgets = [...defaults];
          }),

        setCustomizing: (on) =>
          set((state) => {
            state.isCustomizing = on;
          }),

        toggleCustomizing: () =>
          set((state) => {
            state.isCustomizing = !state.isCustomizing;
          }),
      })),
      {
        name: 'freesdn-dashboard-layout',
        // Don't persist the transient customize-mode flag · it always starts off
        partialize: (state) => ({ enabledWidgets: state.enabledWidgets }),
      },
    ),
    { name: 'dashboard-layout-store' },
  ),
);

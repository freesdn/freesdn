// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN - Module Store
 * 
 * Zustand store for managing module state across the application.
 * Tracks which modules are available, enabled, and their metadata.
 */
import { create } from 'zustand';
import { devtools, persist } from 'zustand/middleware';
import { immer } from 'zustand/middleware/immer';

// ────────────────────────────────────────────────────────────────
// Types
// ────────────────────────────────────────────────────────────────

export interface ModulePermission {
  code: string;
  name: string;
  description: string;
  resource?: string;
  action?: string;
}

export interface ModuleNavItem {
  path: string;
  label: string;
  icon: string;
  order: number;
  parent?: string;
  permission?: string;
  children?: ModuleNavItem[];
  /** Module ID this nav item belongs to (populated by backend navigation API). */
  module_id?: string;
}

export interface ModuleWidget {
  id: string;
  name: string;
  description: string;
  component: string;
  default_size: string;
  supports_refresh?: boolean;
  refresh_interval?: number;
  permission?: string;
}

export interface ModuleManifest {
  id: string;
  name: string;
  version: string;
  description: string;
  category: string;
  icon: string;
  color: string;
  is_core: boolean;
  is_beta: boolean;
  is_premium: boolean;
  /** Preview module that is not production-ready: shown as a non-enableable
   *  "Coming soon" entry and rejected by the enablement API. */
  coming_soon?: boolean;
  min_core_version?: string;
  capabilities: string[];
  device_types: string[];
  dependencies: { module_id: string; min_version: string; optional: boolean }[];
  permissions: ModulePermission[];
  nav_items: ModuleNavItem[];
  widgets: ModuleWidget[];
  author: string;
  license: string;
  docs_url?: string;
}

export interface ModuleState {
  module_id: string;
  state: string;
  error?: string;
  started_orgs: string[];
}

export interface OrgModule {
  module_id: string;
  is_enabled: boolean;
  enabled_at?: string;
  disabled_at?: string;
  settings: Record<string, unknown>;
  manifest?: ModuleManifest;
}

// ────────────────────────────────────────────────────────────────
// Store
// ────────────────────────────────────────────────────────────────

interface ModuleStoreState {
  // Data
  modules: ModuleManifest[];
  moduleStates: ModuleState[];
  enabledModules: string[];
  orgModules: OrgModule[];
  navigationItems: ModuleNavItem[];
  isLoaded: boolean;
  isLoading: boolean;
  error: string | null;

  // Actions
  setModules: (modules: ModuleManifest[]) => void;
  setModuleStates: (states: ModuleState[]) => void;
  setEnabledModules: (moduleIds: string[]) => void;
  setOrgModules: (orgModules: OrgModule[]) => void;
  setNavigationItems: (items: ModuleNavItem[]) => void;
  setLoading: (loading: boolean) => void;
  setError: (error: string | null) => void;
  markLoaded: () => void;

  // Queries
  isModuleEnabled: (moduleId: string) => boolean;
  getModule: (moduleId: string) => ModuleManifest | undefined;
  getEnabledModuleManifests: () => ModuleManifest[];
  getModulesByCategory: () => Record<string, ModuleManifest[]>;
}

export const useModuleStore = create<ModuleStoreState>()(
  devtools(
    persist(
      immer((set, get) => ({
        // Initial state
        modules: [],
        moduleStates: [],
        enabledModules: [],
        orgModules: [],
        navigationItems: [],
        isLoaded: false,
        isLoading: false,
        error: null,

        // ─── Setters ────────────────────────────────────
        setModules: (modules) =>
          set((state) => {
            state.modules = modules;
          }),

        setModuleStates: (states) =>
          set((state) => {
            state.moduleStates = states;
          }),

        setEnabledModules: (moduleIds) =>
          set((state) => {
            state.enabledModules = moduleIds;
          }),

        setOrgModules: (orgModules) =>
          set((state) => {
            state.orgModules = orgModules;
            state.enabledModules = orgModules
              .filter((m) => m.is_enabled)
              .map((m) => m.module_id);
          }),

        setNavigationItems: (items) =>
          set((state) => {
            state.navigationItems = items;
          }),

        setLoading: (loading) =>
          set((state) => {
            state.isLoading = loading;
          }),

        setError: (error) =>
          set((state) => {
            state.error = error;
          }),

        markLoaded: () =>
          set((state) => {
            state.isLoaded = true;
            state.isLoading = false;
          }),

        // ─── Queries ────────────────────────────────────
        isModuleEnabled: (moduleId) => {
          const { enabledModules } = get();
          return enabledModules.includes(moduleId);
        },

        getModule: (moduleId) => {
          const { modules } = get();
          return modules.find((m) => m.id === moduleId);
        },

        getEnabledModuleManifests: () => {
          const { modules, enabledModules } = get();
          return modules.filter((m) => enabledModules.includes(m.id));
        },

        getModulesByCategory: () => {
          const { modules } = get();
          return modules.reduce(
            (acc, module) => {
              const cat = module.category || 'other';
              if (!acc[cat]) acc[cat] = [];
              acc[cat].push(module);
              return acc;
            },
            {} as Record<string, ModuleManifest[]>
          );
        },
      })),
      {
        name: 'freesdn-modules',
        // Do NOT persist enabledModules. A stale value from a prior session or
        // instance can make ModuleGuard show an enabled module as "not enabled"
        // until the live query refetches (the bug seen right after the setup
        // wizard). enabledModules is always loaded fresh from the API each
        // session; ModuleGuard renders children optimistically while the load
        // is in flight, so there is no false-disabled flash.
        partialize: () => ({}),
      }
    ),
    { name: 'module-store' }
  )
);

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN - Setup Wizard Store
 *
 * Persisted to sessionStorage so browser refresh doesn't lose progress.
 * Cleared automatically when setup is completed.
 */
import { create } from 'zustand';
import { persist, createJSONStorage } from 'zustand/middleware';
import type { SetupSummary, ModuleOption, ControllerType } from '@/lib/setup-api';

// Access mode chosen during setup. "manage" = read-write (default);
// "monitor" = read-only (the safe monitor-only mode). When "monitor",
// the Complete step flips adapter read-only on via the system API.
export type AccessMode = 'manage' | 'monitor';

interface SetupState {
  currentStep: number;
  stepsCompleted: number[];

  // IDs that flow between steps (stateless backend)
  adminId: string;
  organizationId: string;
  siteId: string;

  // Data collected during setup
  adminEmail: string;
  adminUsername: string;
  organizationName: string;
  organizationSlug: string;
  enabledModules: string[];
  accessMode: AccessMode;
  controllersAdded: number;
  totalDevices: number;

  // Environment
  environment: string;

  // Cached data
  availableModules: ModuleOption[];
  availableControllerTypes: ControllerType[];

  // Actions
  setCurrentStep: (step: number) => void;
  setEnvironment: (env: string) => void;
  markStepCompleted: (step: number) => void;
  setAdminInfo: (email: string, username: string, id: string) => void;
  setOrganizationInfo: (name: string, slug: string, orgId: string, siteId: string) => void;
  setEnabledModules: (modules: string[]) => void;
  setAccessMode: (mode: AccessMode) => void;
  addController: (devicesFound: number) => void;
  setAvailableModules: (modules: ModuleOption[]) => void;
  setAvailableControllerTypes: (types: ControllerType[]) => void;
  getSummary: () => SetupSummary;
  reset: () => void;
}

const initialState = {
  currentStep: 0,
  stepsCompleted: [] as number[],
  adminId: '',
  organizationId: '',
  siteId: '',
  adminEmail: '',
  adminUsername: '',
  organizationName: '',
  organizationSlug: '',
  enabledModules: [] as string[],
  accessMode: 'manage' as AccessMode,
  controllersAdded: 0,
  totalDevices: 0,
  environment: '',
  availableModules: [] as ModuleOption[],
  availableControllerTypes: [] as ControllerType[],
};

export const useSetupStore = create<SetupState>()(
  persist(
    (set, get) => ({
      ...initialState,

      setCurrentStep: (step) => set({ currentStep: step }),

      setEnvironment: (env) => set({ environment: env }),

      markStepCompleted: (step) => set((state) => ({
        stepsCompleted: state.stepsCompleted.includes(step)
          ? state.stepsCompleted
          : [...state.stepsCompleted, step],
      })),

      setAdminInfo: (email, username, id) => set({
        adminEmail: email,
        adminUsername: username,
        adminId: id,
      }),

      setOrganizationInfo: (name, slug, orgId, siteId) => set({
        organizationName: name,
        organizationSlug: slug,
        organizationId: orgId,
        siteId: siteId,
      }),

      setEnabledModules: (modules) => set({ enabledModules: modules }),

      setAccessMode: (mode) => set({ accessMode: mode }),

      addController: (devicesFound) => set((state) => ({
        controllersAdded: state.controllersAdded + 1,
        totalDevices: state.totalDevices + devicesFound,
      })),

      setAvailableModules: (modules) => set({ availableModules: modules }),

      setAvailableControllerTypes: (types) => set({ availableControllerTypes: types }),

      getSummary: () => {
        const state = get();
        return {
          admin_email: state.adminEmail,
          organization_name: state.organizationName,
          enabled_modules: state.enabledModules,
          controllers_added: state.controllersAdded,
          total_devices: state.totalDevices,
        };
      },

      reset: () => set(initialState),
    }),
    {
      name: 'freesdn-setup',
      storage: createJSONStorage(() => sessionStorage),
      // Only persist data fields, not cached module/controller type lists
      partialize: (state) => ({
        currentStep: state.currentStep,
        stepsCompleted: state.stepsCompleted,
        adminId: state.adminId,
        organizationId: state.organizationId,
        siteId: state.siteId,
        adminEmail: state.adminEmail,
        adminUsername: state.adminUsername,
        organizationName: state.organizationName,
        organizationSlug: state.organizationSlug,
        enabledModules: state.enabledModules,
        accessMode: state.accessMode,
        controllersAdded: state.controllersAdded,
        totalDevices: state.totalDevices,
        environment: state.environment,
      }),
    },
  ),
);

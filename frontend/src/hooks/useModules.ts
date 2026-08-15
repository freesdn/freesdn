// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN - Module Hooks
 * 
 * React hooks for loading and managing module state.
 * Enterprise-grade with proper error handling, cache invalidation,
 * and state synchronization.
 */
import { useEffect, useCallback } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { modulesApi } from '@/lib/api';
import { useModuleStore, type ModuleManifest, type ModuleState, type OrgModule } from '@/stores/moduleStore';
import { useAuthStore } from '@/stores/authStore';

// ────────────────────────────────────────────────────────────────
// Helpers to safely unwrap API responses
// ────────────────────────────────────────────────────────────────

/** Backend wraps lists as { modules: [...], total: N } · unwrap safely. */
function unwrapList<T>(data: unknown, key = 'modules'): T[] {
  if (Array.isArray(data)) return data;
  if (data && typeof data === 'object' && Array.isArray((data as Record<string, unknown>)[key])) return (data as Record<string, unknown>)[key] as T[];
  return [];
}

// ────────────────────────────────────────────────────────────────
// Query keys (centralized for invalidation)
// ────────────────────────────────────────────────────────────────

export const moduleQueryKeys = {
  all: ['modules'] as const,
  states: ['modules', 'states'] as const,
  org: (orgId: string | undefined) => ['modules', 'org', orgId] as const,
  navigation: (orgId: string | undefined) => ['modules', 'navigation', orgId] as const,
};

// ────────────────────────────────────────────────────────────────
// Load all modules + org state on login
// ────────────────────────────────────────────────────────────────

export function useModulesInit() {
  const { user, isAuthenticated } = useAuthStore();
  const {
    setModules,
    setModuleStates,
    setOrgModules,
    setNavigationItems,
    setLoading,
    setError,
    markLoaded,
    isLoaded,
  } = useModuleStore();

  const orgId = user?.organization_id;

  // ─── Fetch all available modules ───────────────────────────
  const modulesQuery = useQuery({
    queryKey: moduleQueryKeys.all,
    queryFn: async () => {
      const res = await modulesApi.getAll();
      return unwrapList<ModuleManifest>(res.data, 'modules');
    },
    enabled: isAuthenticated,
    staleTime: 5 * 60 * 1000,
    retry: 2,
  });

  // ─── Fetch module states ───────────────────────────────────
  const statesQuery = useQuery({
    queryKey: moduleQueryKeys.states,
    queryFn: async () => {
      const res = await modulesApi.getStates();
      return unwrapList<ModuleState>(res.data, 'states');
    },
    enabled: isAuthenticated,
    staleTime: 5 * 60 * 1000,
    retry: 2,
  });

  // ─── Fetch org-specific module enablement (include ALL) ────
  const orgModulesQuery = useQuery({
    queryKey: moduleQueryKeys.org(orgId ?? undefined),
    queryFn: async () => {
      const res = await modulesApi.getOrgModules(orgId!, true);
      return unwrapList<OrgModule>(res.data, 'modules');
    },
    enabled: isAuthenticated && !!orgId,
    // The enabled-module set MUST be fresh after setup/login. Serving a stale
    // (or empty) cache here makes ModuleGuard wrongly show "module not enabled"
    // for modules that ARE enabled — until a manual enable/disable toggle
    // invalidates the query. Always refetch on mount so the guard is correct
    // immediately after the setup wizard completes.
    staleTime: 0,
    refetchOnMount: 'always',
    retry: 2,
  });

  // ─── Fetch navigation items for enabled modules ────────────
  const navQuery = useQuery({
    queryKey: moduleQueryKeys.navigation(orgId ?? undefined),
    queryFn: async () => {
      const res = await modulesApi.getNavigation(orgId!);
      const data = res.data;
      return data?.items ?? unwrapList(data, 'items');
    },
    enabled: isAuthenticated && !!orgId,
    staleTime: 30 * 1000,
    retry: 2,
  });

  // ─── Sync to store ────────────────────────────────────────
  useEffect(() => {
    if (modulesQuery.data) {
      setModules(modulesQuery.data);
    }
  }, [modulesQuery.data, setModules]);

  useEffect(() => {
    if (statesQuery.data) {
      setModuleStates(statesQuery.data);
    }
  }, [statesQuery.data, setModuleStates]);

  useEffect(() => {
    if (orgModulesQuery.data) {
      setOrgModules(orgModulesQuery.data);
    }
  }, [orgModulesQuery.data, setOrgModules]);

  useEffect(() => {
    if (navQuery.data && Array.isArray(navQuery.data)) {
      setNavigationItems(navQuery.data);
    }
  }, [navQuery.data, setNavigationItems]);

  // ─── Loading / loaded state ────────────────────────────────
  useEffect(() => {
    const anyLoading =
      modulesQuery.isLoading || statesQuery.isLoading || orgModulesQuery.isLoading;

    setLoading(anyLoading);

    // Only flip isLoaded once the ORG-ENABLEMENT query has actually resolved
    // (its data is an array — possibly empty), NOT merely when the manifest list
    // is in. orgModulesQuery is gated on orgId, which loads async right after the
    // setup wizard's auto-auth; marking loaded on the manifest alone sets
    // isLoaded=true with an empty enabledModules set, so ModuleGuard wrongly
    // shows "module not enabled" for modules that ARE enabled (the post-setup
    // glitch). While orgId is present but enablement is still unknown, stay
    // not-loaded so ModuleGuard renders children optimistically instead of
    // false-blocking. (When there is genuinely no orgId — a broken auth state —
    // we still mark loaded so the app doesn't hang; module routes then fail open
    // in the UI but stay enforced by the backend.)
    const enablementResolved = !orgId || !!orgModulesQuery.data;
    if (!anyLoading && modulesQuery.data && enablementResolved && !isLoaded) {
      markLoaded();
    }
  }, [
    modulesQuery.isLoading,
    statesQuery.isLoading,
    orgModulesQuery.isLoading,
    modulesQuery.data,
    orgModulesQuery.data,
    orgId,
    isLoaded,
    markLoaded,
    setLoading,
  ]);

  // ─── Error state ──────────────────────────────────────────
  useEffect(() => {
    const err =
      modulesQuery.error?.message ||
      statesQuery.error?.message ||
      orgModulesQuery.error?.message ||
      null;
    setError(err ? String(err) : null);
  }, [modulesQuery.error, statesQuery.error, orgModulesQuery.error, setError]);

  return {
    isLoading: modulesQuery.isLoading || statesQuery.isLoading || orgModulesQuery.isLoading,
    isLoaded,
    error: modulesQuery.error || statesQuery.error || orgModulesQuery.error,
    refetch: () => {
      modulesQuery.refetch();
      statesQuery.refetch();
      orgModulesQuery.refetch();
      navQuery.refetch();
    },
  };
}

// ────────────────────────────────────────────────────────────────
// Toggle module enable/disable with full cache invalidation
// ────────────────────────────────────────────────────────────────

export function useModuleToggle() {
  const { user } = useAuthStore();
  const queryClient = useQueryClient();
  const orgId = user?.organization_id;

  const invalidateAll = useCallback(() => {
    if (!orgId) return;
    // Invalidate all module-related queries to get fresh state
    queryClient.invalidateQueries({ queryKey: moduleQueryKeys.all });
    queryClient.invalidateQueries({ queryKey: moduleQueryKeys.states });
    queryClient.invalidateQueries({ queryKey: moduleQueryKeys.org(orgId) });
    queryClient.invalidateQueries({ queryKey: moduleQueryKeys.navigation(orgId) });
  }, [queryClient, orgId]);

  const enableMutation = useMutation({
    mutationFn: async (moduleId: string) => {
      if (!orgId) throw new Error('No organization context');
      const res = await modulesApi.enableModule(orgId, moduleId);
      return res.data;
    },
    onSuccess: () => invalidateAll(),
    onError: (error) => {
      console.error('Failed to enable module:', error);
    },
  });

  const disableMutation = useMutation({
    mutationFn: async (moduleId: string) => {
      if (!orgId) throw new Error('No organization context');
      const res = await modulesApi.disableModule(orgId, moduleId);
      return res.data;
    },
    onSuccess: () => invalidateAll(),
    onError: (error) => {
      console.error('Failed to disable module:', error);
    },
  });

  const toggleModule = useCallback(
    async (moduleId: string, currentlyEnabled: boolean) => {
      if (currentlyEnabled) {
        return disableMutation.mutateAsync(moduleId);
      } else {
        return enableMutation.mutateAsync(moduleId);
      }
    },
    [enableMutation, disableMutation]
  );

  return {
    toggleModule,
    enableModule: enableMutation.mutateAsync,
    disableModule: disableMutation.mutateAsync,
    isToggling: enableMutation.isPending || disableMutation.isPending,
    toggleError: enableMutation.error || disableMutation.error,
    resetError: () => {
      enableMutation.reset();
      disableMutation.reset();
    },
  };
}

// ────────────────────────────────────────────────────────────────
// Hook to check if a specific module is enabled
// ────────────────────────────────────────────────────────────────

export function useIsModuleEnabled(moduleId: string): boolean {
  const { enabledModules } = useModuleStore();
  return enabledModules.includes(moduleId);
}


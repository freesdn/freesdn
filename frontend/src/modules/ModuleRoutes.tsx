// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN - Module Routes
 * 
 * Renders all module-provided routes with:
 *   - ProtectedRoute wrapper (auth check)
 *   - MainLayout wrapper (sidebar + header)
 *   - ModuleGuard (module enablement check)
 *   - React.Suspense (lazy loading fallback)
 * 
 * Usage in App.tsx:
 *   <ModuleRoutes />
 * 
 * This replaces the static per-module <Route> blocks.
 */
import { Suspense } from 'react';
import { Route } from 'react-router-dom';
import { Loader2 } from 'lucide-react';
import { ProtectedRoute, ModuleGuard } from '@/components/auth';
import { MainLayout } from '@/components/layout';
import { moduleManifests } from '@/modules';

/**
 * Fallback component shown while a lazy-loaded module page is loading.
 */
function ModuleLoadingFallback() {
  return (
    <div className="flex items-center justify-center min-h-[40vh]">
      <div className="flex flex-col items-center gap-3 text-muted-foreground">
        <Loader2 className="h-8 w-8 animate-spin" />
        <p className="text-sm">Loading module…</p>
      </div>
    </div>
  );
}

/**
 * Returns an array of <Route> elements for every registered module.
 * 
 * Must be spread/called inside a <Routes> element:
 *   <Routes>
 *     {renderModuleRoutes()}
 *   </Routes>
 * 
 * React Router requires direct children of <Routes> to be <Route> or
 * <React.Fragment> elements · a wrapper component won't work.
 */
export function renderModuleRoutes() {
  return moduleManifests.flatMap((mod) =>
    mod.routes.map((route) => (
      <Route
        key={`${mod.id}:${route.path}`}
        path={route.path}
        element={
          <ProtectedRoute>
            <MainLayout>
              <ModuleGuard moduleId={mod.id}>
                <Suspense fallback={<ModuleLoadingFallback />}>
                  <route.component />
                </Suspense>
              </ModuleGuard>
            </MainLayout>
          </ProtectedRoute>
        }
      />
    ))
  );
}

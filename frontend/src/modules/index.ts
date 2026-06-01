// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN - Frontend Module Registry
 *
 * Central registry of all frontend module manifests.
 * Provides query methods for routes, navigation items, and widgets.
 */
import type { FrontendModuleManifest, ModuleNavDefinition, ModuleRouteDefinition, NavSection } from './types';

// ────────────────────────────────────────────────────────────
// Import all module manifests
// ────────────────────────────────────────────────────────────
import { networkModule } from './network/manifest';
import { camerasModule } from './cameras/manifest';
import { voipModule } from './voip/manifest';
import { firewallModule } from './firewall/manifest';
import { accessControlModule } from './access-control/manifest';
import { backupModule } from './backup/manifest';
import { aiModule } from './ai/manifest';
import { collectorModule } from './collector/manifest';
import { hypervisorModule } from './hypervisor/manifest';

/**
 * All registered frontend module manifests.
 * Order matters · modules listed first get lower route priority.
 *
 * 9 modules total:
 *   Network · Cameras · VoIP · Firewall · Access Control
 *   Backup · AI · Observability · Hypervisor
 */
export const moduleManifests: FrontendModuleManifest[] = [
  networkModule,
  camerasModule,
  voipModule,
  firewallModule,
  accessControlModule,
  backupModule,
  aiModule,
  collectorModule,
  hypervisorModule,
];

// ────────────────────────────────────────────────────────────
// Query helpers
// ────────────────────────────────────────────────────────────

/** Map of module ID → manifest for O(1) lookups */
const manifestMap = new Map<string, FrontendModuleManifest>(
  moduleManifests.map((m) => [m.id, m])
);

/** Get a module manifest by ID */
export function getModuleManifest(moduleId: string): FrontendModuleManifest | undefined {
  return manifestMap.get(moduleId);
}

/**
 * Get all routes for a list of enabled module IDs.
 * Returns route definitions with their parent module ID attached.
 */
export function getEnabledRoutes(
  enabledModuleIds: string[]
): Array<ModuleRouteDefinition & { moduleId: string }> {
  const enabledSet = new Set(enabledModuleIds);
  return moduleManifests
    .filter((m) => enabledSet.has(m.id))
    .flatMap((m) =>
      m.routes.map((r) => ({ ...r, moduleId: m.id }))
    );
}

/**
 * Get all navigation items for enabled modules, grouped by section.
 * Items are sorted by their `order` field within each section.
 */
export function getEnabledNavItems(
  enabledModuleIds: string[]
): Record<NavSection, ModuleNavDefinition[]> {
  const enabledSet = new Set(enabledModuleIds);
  const result: Record<NavSection, ModuleNavDefinition[]> = {
    network: [],
    configuration: [],
    monitoring: [],
    security: [],
  };

  for (const mod of moduleManifests) {
    if (!enabledSet.has(mod.id)) continue;
    for (const item of mod.navItems) {
      result[item.section].push(item);
    }
  }

  // Sort each section by order
  for (const section of Object.keys(result) as NavSection[]) {
    result[section].sort((a, b) => (a.order ?? 99) - (b.order ?? 99));
  }

  return result;
}

/**
 * Get all route paths for a specific module.
 * Useful for checking if a path belongs to a module.
 */
export function getModuleRoutes(moduleId: string): string[] {
  const manifest = manifestMap.get(moduleId);
  return manifest?.routes.map((r) => r.path) ?? [];
}

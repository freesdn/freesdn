// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN - Settings Extension Tabs
 *
 * Collects all settingsTabs from enabled modules and renders them
 * as additional tab triggers + content panels, sorted by order.
 *
 * Intended to be rendered inside an existing <Tabs> in SettingsPage.
 */

import { Suspense } from 'react';
import { TabsContent, TabsTrigger } from '@/components/ui/tabs';
import { Skeleton } from '@/components/ui/skeleton';
import { moduleManifests } from '@/modules';
import type { ModuleSettingsTab } from '@/modules/types';


interface SettingsExtensionTabsProps {
  /** Set of enabled module IDs (if not provided, all modules are considered enabled) */
  enabledModuleIds?: string[];
  /** Render mode: 'triggers' renders TabsTrigger elements, 'content' renders TabsContent */
  mode: 'triggers' | 'content';
}

/**
 * Collects settingsTabs from all enabled modules.
 *
 * Usage in SettingsPage · call twice, once for triggers and once for content:
 * ```tsx
 * <TabsList>
 *   {/* existing triggers *\/}
 *   <SettingsExtensionTabs mode="triggers" />
 * </TabsList>
 * {/* existing TabsContent *\/}
 * <SettingsExtensionTabs mode="content" />
 * ```
 */
export function SettingsExtensionTabs({
  enabledModuleIds,
  mode,
}: SettingsExtensionTabsProps) {
  const enabledSet = enabledModuleIds ? new Set(enabledModuleIds) : null;

  const tabs: ModuleSettingsTab[] = moduleManifests
    .filter((m) => !enabledSet || enabledSet.has(m.id))
    .flatMap((m) => m.settingsTabs ?? [])
    .sort((a, b) => (a.order ?? 99) - (b.order ?? 99));

  if (tabs.length === 0) return null;

  if (mode === 'triggers') {
    return (
      <>
        {tabs.map((tab) => (
          <TabsTrigger key={tab.id} value={`ext:${tab.id}`} className="gap-2">
            <tab.icon className="h-4 w-4" />
            <span className="hidden sm:inline">{tab.label}</span>
          </TabsTrigger>
        ))}
      </>
    );
  }

  // mode === 'content'
  return (
    <>
      {tabs.map((tab) => (
        <TabsContent key={tab.id} value={`ext:${tab.id}`}>
          <Suspense
            fallback={
              <div className="space-y-3 p-4">
                <Skeleton className="h-6 w-48" />
                <Skeleton className="h-4 w-full" />
                <Skeleton className="h-4 w-3/4" />
              </div>
            }
          >
            <tab.component />
          </Suspense>
        </TabsContent>
      ))}
    </>
  );
}

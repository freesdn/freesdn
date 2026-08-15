// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN · URL-Aware Page Tabs
 *
 * Drop-in tabbed navigation that:
 *  1. Syncs the active tab to the URL  (e.g. /firmware/repository)
 *  2. Falls back to the first tab when the URL has no suffix
 *  3. Uses the shadcn Tabs primitives for a unified look
 *
 * Usage:
 *   <PageTabs
 *     basePath="/firmware"
 *     tabs={[
 *       { value: 'devices',    label: 'Devices',    content: <DevicesTab /> },
 *       { value: 'repository', label: 'Repository', content: <RepoTab /> },
 *     ]}
 *   />
 */

import { useNavigate, useParams } from 'react-router-dom';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import { cn } from '@/lib/utils';

export interface PageTab {
  /** URL slug, appended to basePath  (e.g. "repository" → /firmware/repository) */
  value: string;
  /** Display label in the tab bar (string or ReactNode for icon+text combos) */
  label: React.ReactNode;
  /** Optional neutral count pill */
  count?: number;
  /** Optional custom badge node (overrides `count`); use for status/severity-coloured pills */
  badge?: React.ReactNode;
  /** Content rendered when this tab is active */
  content: React.ReactNode;
  /** When true, the tab is hidden from the tab bar (still resolvable by URL) */
  hidden?: boolean;
}

export interface PageTabsProps {
  /** Base route path WITHOUT trailing slash (e.g. "/firmware") */
  basePath: string;
  /** Tab definitions · first tab is the default */
  tabs: PageTab[];
  /** Extra className on the root wrapper */
  className?: string;
  /** URL param name that carries the tab value.  Defaults to "tab". */
  paramName?: string;
}

export function PageTabs({
  basePath,
  tabs,
  className,
  paramName = 'tab',
}: PageTabsProps) {
  const navigate = useNavigate();
  const params = useParams<Record<string, string>>();

  const visibleTabs = tabs.filter((t) => !t.hidden);
  const firstValue = visibleTabs[0]?.value ?? tabs[0]?.value;

  const activeTab =
    tabs.find((t) => t.value === params[paramName])?.value ?? firstValue;

  const handleChange = (value: string) => {
    // Navigate to basePath/tabValue · first visible tab can omit the suffix
    const target = value === firstValue ? basePath : `${basePath}/${value}`;
    navigate(target, { replace: true });
  };

  if (tabs.length === 0) return null;

  return (
    <Tabs
      value={activeTab}
      onValueChange={handleChange}
      className={cn('w-full', className)}
    >
      <TabsList className="justify-start">
        {visibleTabs.map((tab) => (
          <TabsTrigger key={tab.value} value={tab.value}>
            {tab.label}
            {tab.badge !== undefined ? (
              <span className="ml-1.5 inline-flex items-center">{tab.badge}</span>
            ) : tab.count !== undefined ? (
              <span className="ml-1.5 rounded-full bg-muted px-1.5 py-0.5 text-[10px] font-medium leading-none text-muted-foreground">
                {tab.count}
              </span>
            ) : null}
          </TabsTrigger>
        ))}
      </TabsList>

      {tabs.map((tab) => (
        <TabsContent key={tab.value} value={tab.value}>
          {tab.content}
        </TabsContent>
      ))}
    </Tabs>
  );
}

export default PageTabs;

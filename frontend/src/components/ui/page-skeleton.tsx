// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN Design System · PageSkeleton
 *
 * Single canonical loading skeleton for entire pages. Variants mirror the
 * common page layouts (list, dashboard, detail). Eliminates blank-flash
 * during route load · Apple/UniFi never show a blank page.
 *
 * Usage:
 *   if (isLoading) return <PageSkeleton variant="list" />;
 *   if (isLoading) return <PageSkeleton variant="dashboard" />;
 *   if (isLoading) return <PageSkeleton variant="detail" />;
 *
 * For sub-section loading (just the table, not the page), use Skeleton
 * directly or DataTable's built-in isLoading prop.
 */

import { Skeleton } from './skeleton';
import { cn } from '../../lib/utils';

type Variant = 'list' | 'dashboard' | 'detail' | 'tabbed';

interface PageSkeletonProps {
  variant?: Variant;
  /** Number of stats cards (list/dashboard/detail variants) */
  statsCount?: 2 | 3 | 4 | 6;
  /** Number of table rows (list variant) */
  rows?: number;
  /** Skip the StatsGrid skeleton */
  hideStats?: boolean;
  /** Skip the toolbar skeleton */
  hideToolbar?: boolean;
  className?: string;
}

const statsCols: Record<2 | 3 | 4 | 6, string> = {
  2: 'grid-cols-2',
  3: 'grid-cols-1 sm:grid-cols-3',
  4: 'grid-cols-2 md:grid-cols-4',
  6: 'grid-cols-2 md:grid-cols-3 lg:grid-cols-6',
};

function StatsGridSkeleton({ count }: { count: 2 | 3 | 4 | 6 }) {
  return (
    <div className={cn('grid gap-4', statsCols[count])}>
      {Array.from({ length: count }).map((_, i) => (
        <div key={i} className="rounded-xl border bg-card p-4">
          <div className="flex items-center gap-3">
            <Skeleton className="h-10 w-10 rounded-lg" />
            <div className="space-y-2 flex-1 min-w-0">
              <Skeleton className="h-6 w-12" />
              <Skeleton className="h-3 w-20" />
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}

function HeaderSkeleton({ withActions = true }: { withActions?: boolean }) {
  return (
    <div className="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-4">
      <div className="space-y-2 flex-1 min-w-0">
        <Skeleton className="h-3 w-24" /> {/* site badge */}
        <div className="flex items-center gap-3">
          <Skeleton className="h-7 w-7 rounded" /> {/* icon */}
          <Skeleton className="h-7 w-48" /> {/* title */}
        </div>
        <Skeleton className="h-4 w-72" /> {/* description */}
      </div>
      {withActions && (
        <div className="flex items-center gap-2 flex-shrink-0">
          <Skeleton className="h-9 w-9 rounded-md" />
          <Skeleton className="h-9 w-24 rounded-md" />
          <Skeleton className="h-9 w-32 rounded-md" />
        </div>
      )}
    </div>
  );
}

function ToolbarSkeleton() {
  return (
    <div className="flex flex-wrap items-center gap-3">
      <Skeleton className="h-9 flex-1 min-w-[240px] rounded-md" /> {/* search */}
      <Skeleton className="h-9 w-32 rounded-md" /> {/* filter 1 */}
      <Skeleton className="h-9 w-32 rounded-md" /> {/* filter 2 */}
    </div>
  );
}

function TableSkeleton({ rows = 8 }: { rows?: number }) {
  return (
    <div className="rounded-xl border bg-card overflow-hidden">
      {/* Header row */}
      <div className="flex items-center gap-4 h-12 px-4 border-b border-border/50 bg-muted/30">
        <Skeleton className="h-4 w-4" />
        {Array.from({ length: 5 }).map((_, i) => (
          <Skeleton key={i} className="h-4 flex-1 max-w-[100px]" />
        ))}
      </div>
      {/* Body rows */}
      {Array.from({ length: rows }).map((_, i) => (
        <div
          key={i}
          className="flex items-center gap-4 px-4 py-3 border-b border-border/30 last:border-0"
        >
          <Skeleton className="h-4 w-4" />
          <Skeleton className="h-9 w-9 rounded-lg" />
          <div className="flex-1 space-y-1.5">
            <Skeleton className="h-4 w-[180px]" />
            <Skeleton className="h-3 w-[120px]" />
          </div>
          <Skeleton className="h-6 w-16 rounded-full" />
          <Skeleton className="h-4 w-20" />
          <Skeleton className="h-4 w-24" />
          <Skeleton className="h-8 w-8 rounded-md" />
        </div>
      ))}
      {/* Pagination */}
      <div className="flex items-center justify-between px-4 py-3 border-t border-border/50">
        <Skeleton className="h-4 w-40" />
        <div className="flex items-center gap-2">
          <Skeleton className="h-8 w-16 rounded-md" />
          <Skeleton className="h-8 w-24" />
        </div>
      </div>
    </div>
  );
}

function DashboardWidgetsSkeleton() {
  return (
    <div className="grid gap-6 lg:grid-cols-3">
      {/* Left 2/3 */}
      <div className="lg:col-span-2 space-y-6">
        <Skeleton className="h-[320px] rounded-xl" /> {/* chart */}
        <div className="grid gap-6 md:grid-cols-2">
          <Skeleton className="h-[200px] rounded-xl" />
          <Skeleton className="h-[200px] rounded-xl" />
        </div>
      </div>
      {/* Right 1/3 */}
      <div className="space-y-6">
        <Skeleton className="h-[180px] rounded-xl" />
        <Skeleton className="h-[180px] rounded-xl" />
        <Skeleton className="h-[180px] rounded-xl" />
      </div>
    </div>
  );
}

function DetailContentSkeleton() {
  return (
    <div className="space-y-4">
      {/* Tabs row */}
      <div className="flex gap-2 border-b border-border">
        {Array.from({ length: 5 }).map((_, i) => (
          <Skeleton key={i} className="h-9 w-24 rounded-md" />
        ))}
      </div>
      {/* Two-column detail content */}
      <div className="grid gap-6 lg:grid-cols-3">
        <div className="lg:col-span-2">
          <Skeleton className="h-[400px] rounded-xl" />
        </div>
        <div className="space-y-4">
          <Skeleton className="h-[160px] rounded-xl" />
          <Skeleton className="h-[160px] rounded-xl" />
        </div>
      </div>
    </div>
  );
}

export function PageSkeleton({
  variant = 'list',
  statsCount = 4,
  rows = 8,
  hideStats = false,
  hideToolbar = false,
  className,
}: PageSkeletonProps) {
  return (
    <div className={cn('space-y-6 animate-in fade-in duration-200', className)} aria-busy="true" aria-live="polite">
      <HeaderSkeleton />

      {!hideStats && variant !== 'detail' && <StatsGridSkeleton count={statsCount} />}

      {variant === 'list' && (
        <>
          {!hideToolbar && <ToolbarSkeleton />}
          <TableSkeleton rows={rows} />
        </>
      )}

      {variant === 'dashboard' && <DashboardWidgetsSkeleton />}

      {variant === 'detail' && (
        <>
          {!hideStats && <StatsGridSkeleton count={statsCount} />}
          <DetailContentSkeleton />
        </>
      )}

      {variant === 'tabbed' && (
        <>
          {!hideToolbar && <ToolbarSkeleton />}
          <DetailContentSkeleton />
        </>
      )}
    </div>
  );
}

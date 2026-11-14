// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN - Unified Page Header Component
 * 
 * Provides a consistent header layout across all pages:
 * - Icon + Title on the left
 * - Subtitle/description below the title
 * - Action buttons on the right (supports both simple and complex patterns)
 * 
 * Simple Usage:
 * <PageHeader
 *   icon={Server}
 *   title="Controllers"
 *   subtitle="Manage network controllers and device managers"
 *   actions={<Button>Add Controller</Button>}
 * />
 * 
 * Complex Usage (v1 compatibility):
 * <PageHeader
 *   icon={Server}
 *   title="Controllers"
 *   description="Manage network controllers"
 *   onRefresh={() => refetch()}
 *   refreshing={isLoading}
 *   primaryAction={{ label: 'Add', icon: Plus, onClick: handleAdd }}
 *   secondaryActions={[{ label: 'Export', onClick: handleExport }]}
 * />
 *
 * Button order (left → right):
 *   [Refresh] → [actions slot / secondaryActions] → [primaryAction]
 */

import { ReactNode, useCallback, useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { LucideIcon, MapPin, RefreshCw } from 'lucide-react';
import { cn } from '@/lib/utils';
import { Button } from '@/components/ui/button';
import { useSiteStore } from '@/stores/siteStore';

interface PageHeaderAction {
  /** Label for the button */
  label: string;
  /** Icon component */
  icon?: LucideIcon;
  /** Click handler */
  onClick?: () => void;
  /** Button variant */
  variant?: 'default' | 'outline' | 'ghost' | 'destructive';
  /** Loading state */
  loading?: boolean;
  /** Disabled state */
  disabled?: boolean;
  /** Hide the action */
  hidden?: boolean;
}

export interface PageHeaderProps { // exported for the deprecation shim in components/ui/page-header.tsx
  /** Lucide icon component to display next to the title */
  icon?: LucideIcon;
  /** Main page title */
  title: string;
  /** Optional subtitle text (v2 style) */
  subtitle?: string;
  /** Optional description text (v1 style - alias for subtitle) */
  description?: string;
  /** Simple action buttons (v2 style) */
  actions?: ReactNode;
  /** Primary action button (v1 style) */
  primaryAction?: PageHeaderAction;
  /** Secondary actions (v1 style) */
  secondaryActions?: PageHeaderAction[];
  /**
   * Show refresh button. When the handler returns a promise (as
   * `() => refetch()` does), the button spins and stays disabled until it
   * settles, so a refetch of already-cached data still shows feedback.
   */
  onRefresh?: () => void | Promise<unknown>;
  /** Refresh loading state (OR-ed with the pending promise above) */
  refreshing?: boolean;
  /** Optional small badge rendered next to the title — e.g. a capability
   *  maturity marker (Stable / Beta / Experimental). Additive: no effect when
   *  omitted. */
  titleBadge?: ReactNode;
  /** Breadcrumbs or navigation above the title */
  breadcrumbs?: ReactNode;
  /** Additional CSS classes */
  className?: string;
}

export function PageHeader({
  icon: Icon,
  title,
  subtitle,
  description,
  actions,
  primaryAction,
  secondaryActions = [],
  onRefresh,
  refreshing = false,
  titleBadge,
  breadcrumbs,
  className,
}: PageHeaderProps) {
  const { t } = useTranslation('common');
  // Use description as fallback for subtitle (v1 compatibility)
  const descriptionText = subtitle || description;
  const currentSite = useSiteStore((s) => s.getCurrentSite());

  // Determine if we have complex actions (v1 style)
  const hasComplexActions = onRefresh || secondaryActions.length > 0 || primaryAction;

  // `refreshing` is usually wired to a query's `isLoading`, which is only true
  // on the first load. A refetch of cached data never set it, so the refresh
  // button looked dead on every list page. Track the handler's own promise.
  const [refreshPending, setRefreshPending] = useState(false);
  const mounted = useRef(true);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);
  const handleRefresh = useCallback(() => {
    const result = onRefresh?.();
    if (!result || typeof (result as Promise<unknown>).then !== 'function') return;
    setRefreshPending(true);
    // A minimum spin so a sub-100ms refetch is still visible as feedback.
    const minimum = new Promise((resolve) => setTimeout(resolve, 400));
    Promise.allSettled([result, minimum]).then(() => {
      if (mounted.current) setRefreshPending(false);
    });
  }, [onRefresh]);
  const isRefreshing = refreshing || refreshPending;

  return (
    <div className={cn('flex flex-col sm:flex-row sm:items-start sm:justify-between gap-4', className)}>
      <div className="space-y-1 min-w-0">
        {breadcrumbs && <div className="mb-2">{breadcrumbs}</div>}
        {currentSite && (
          <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
            <MapPin className="h-3 w-3" aria-hidden="true" />
            <span>{currentSite.name}</span>
          </div>
        )}
        <h1 className="text-xl sm:text-2xl font-semibold tracking-tight flex items-center gap-2">
          {Icon && <Icon className="h-5 w-5 sm:h-6 sm:w-6 text-primary flex-shrink-0" aria-hidden="true" />}
          {/* A long title truncates; the full text stays available on hover. */}
          <span className="truncate" title={title}>{title}</span>
          {titleBadge && <span className="flex-shrink-0">{titleBadge}</span>}
        </h1>
        {descriptionText && (
          <p className="text-sm sm:text-base text-muted-foreground">{descriptionText}</p>
        )}
      </div>

      {/* Simple actions (v2 style). Many pages pass their buttons inside a
          single wrapper <div className="flex items-center gap-2">; that inner
          row did not wrap, so on a phone the last buttons were pushed past the
          edge of the screen and clipped (gateway and device detail headers at
          390px). `[&>div]:flex-wrap` lets such a wrapper wrap too. */}
      {actions && !hasComplexActions && (
        <div className="flex items-center gap-2 flex-wrap shrink-0 max-w-full sm:justify-end [&>div]:flex-wrap">
          {actions}
        </div>
      )}

      {/* Complex actions (v1 style) */}
      {hasComplexActions && (
        <div className="flex items-center gap-2 flex-wrap flex-shrink-0 max-w-full sm:justify-end [&>div]:flex-wrap">
          {/* Refresh button · always leftmost */}
          {onRefresh && (
            <Button
              variant="outline"
              size="icon"
              onClick={handleRefresh}
              disabled={isRefreshing}
              aria-busy={isRefreshing}
              title={t('PageHeader.actions.refresh')}
              aria-label={t('PageHeader.actions.refresh')}
            >
              <RefreshCw className={cn("h-4 w-4", isRefreshing && "animate-spin")} />
            </Button>
          )}

          {/* Custom actions slot */}
          {actions}

          {/* Secondary actions */}
          {secondaryActions.filter(a => !a.hidden).map((action, index) => (
            <Button
              key={index}
              variant={action.variant || 'outline'}
              onClick={action.onClick}
              disabled={action.disabled || action.loading}
            >
              {action.icon && (
                <action.icon className={cn("h-4 w-4", action.label && "mr-2", action.loading && "animate-spin")} />
              )}
              {action.label}
            </Button>
          ))}

          {/* Primary action */}
          {primaryAction && !primaryAction.hidden && (
            <Button
              variant={primaryAction.variant || 'default'}
              onClick={primaryAction.onClick}
              disabled={primaryAction.disabled || primaryAction.loading}
            >
              {primaryAction.icon && (
                <primaryAction.icon className={cn("h-4 w-4", primaryAction.label && "mr-2", primaryAction.loading && "animate-spin")} />
              )}
              {primaryAction.label}
            </Button>
          )}
        </div>
      )}
    </div>
  );
}

export default PageHeader;

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

import { ReactNode } from 'react';
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
  /** Show refresh button */
  onRefresh?: () => void;
  /** Refresh loading state */
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

  return (
    <div className={cn('flex flex-col sm:flex-row sm:items-start sm:justify-between gap-4', className)}>
      <div className="space-y-1 min-w-0">
        {breadcrumbs && <div className="mb-2">{breadcrumbs}</div>}
        {currentSite && (
          <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
            <MapPin className="h-3 w-3" />
            <span>{currentSite.name}</span>
          </div>
        )}
        <h1 className="text-xl sm:text-2xl font-semibold tracking-tight flex items-center gap-2">
          {Icon && <Icon className="h-5 w-5 sm:h-6 sm:w-6 text-primary flex-shrink-0" />}
          <span className="truncate">{title}</span>
          {titleBadge && <span className="flex-shrink-0">{titleBadge}</span>}
        </h1>
        {descriptionText && (
          <p className="text-sm sm:text-base text-muted-foreground">{descriptionText}</p>
        )}
      </div>

      {/* Simple actions (v2 style) */}
      {actions && !hasComplexActions && (
        <div className="flex items-center gap-2 flex-wrap shrink-0 sm:justify-end">
          {actions}
        </div>
      )}

      {/* Complex actions (v1 style) */}
      {hasComplexActions && (
        <div className="flex items-center gap-2 flex-wrap flex-shrink-0 sm:justify-end">
          {/* Refresh button · always leftmost */}
          {onRefresh && (
            <Button
              variant="outline"
              size="icon"
              onClick={onRefresh}
              disabled={refreshing}
              title={t('PageHeader.actions.refresh')}
              aria-label={t('PageHeader.actions.refresh')}
            >
              <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
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

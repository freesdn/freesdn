// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN - Empty State Component
 * 
 * Consistent empty state UI for lists, tables, and pages
 */

import { AlertTriangle, LucideIcon, Package, Search, Plus, RefreshCw } from 'lucide-react';
import { getApiErrorMessage } from '@/lib/api/errors';
import { useTranslation } from 'react-i18next';
import { Button } from './button';
import { cn } from '@/lib/utils';

interface EmptyStateProps {
  icon?: LucideIcon;
  title: string;
  description?: string;
  action?: {
    label: string;
    onClick: () => void;
    icon?: LucideIcon;
  };
  secondaryAction?: {
    label: string;
    onClick: () => void;
  };
  className?: string;
  variant?: 'default' | 'compact' | 'card';
  /** `destructive` tints the icon for failures. */
  tone?: 'neutral' | 'destructive';
  /** ARIA role for the container, e.g. `alert` for a failure. */
  role?: string;
}

export function EmptyState({
  icon: Icon = Package,
  title,
  description,
  action,
  secondaryAction,
  className,
  variant = 'default',
  tone = 'neutral',
  role,
}: EmptyStateProps) {
  const ActionIcon = action?.icon || Plus;
  const iconWrap = tone === 'destructive' ? 'bg-destructive/10' : 'bg-muted';
  const iconColor = tone === 'destructive' ? 'text-destructive' : 'text-muted-foreground';

  if (variant === 'compact') {
    return (
      <div className={cn('flex items-center justify-center py-8 text-center', className)} role={role}>
        <div className="space-y-2 max-w-sm">
          <div className={cn('mx-auto flex h-12 w-12 items-center justify-center rounded-full', iconWrap)}>
            <Icon className={cn('h-6 w-6', iconColor)} aria-hidden="true" />
          </div>
          <p className="text-sm font-medium text-foreground">{title}</p>
          {description && (
            <p className="text-xs text-muted-foreground">{description}</p>
          )}
          {action && (
            <Button size="sm" variant="outline" onClick={action.onClick}>
              <ActionIcon className="mr-2 h-4 w-4" />
              {action.label}
            </Button>
          )}
        </div>
      </div>
    );
  }

  if (variant === 'card') {
    return (
      <div className={cn(
        'flex flex-col items-center justify-center rounded-lg border border-dashed p-8 text-center',
        className
      )} role={role}>
        <div className={cn('flex h-14 w-14 items-center justify-center rounded-full', iconWrap)}>
          <Icon className={cn('h-6 w-6', iconColor)} aria-hidden="true" />
        </div>
        <h3 className="mt-4 text-lg font-semibold">{title}</h3>
        {description && (
          <p className="mt-2 text-sm text-muted-foreground max-w-sm">{description}</p>
        )}
        {(action || secondaryAction) && (
          <div className="mt-6 flex items-center gap-2">
            {action && (
              <Button onClick={action.onClick}>
                <ActionIcon className="mr-2 h-4 w-4" />
                {action.label}
              </Button>
            )}
            {secondaryAction && (
              <Button variant="outline" onClick={secondaryAction.onClick}>
                {secondaryAction.label}
              </Button>
            )}
          </div>
        )}
      </div>
    );
  }

  // Default variant
  return (
    <div className={cn('flex flex-col items-center justify-center px-4 py-12 sm:py-16 text-center', className)} role={role}>
      <div className={cn('flex h-16 w-16 sm:h-20 sm:w-20 items-center justify-center rounded-full', iconWrap)}>
        <Icon className={cn('h-8 w-8 sm:h-10 sm:w-10', iconColor)} aria-hidden="true" />
      </div>
      <h3 className="mt-6 text-xl font-semibold">{title}</h3>
      {description && (
        <p className="mt-2 text-muted-foreground max-w-md">{description}</p>
      )}
      {(action || secondaryAction) && (
        <div className="mt-8 flex items-center gap-3">
          {action && (
            <Button onClick={action.onClick}>
              <ActionIcon className="mr-2 h-4 w-4" />
              {action.label}
            </Button>
          )}
          {secondaryAction && (
            <Button variant="outline" onClick={secondaryAction.onClick}>
              {secondaryAction.label}
            </Button>
          )}
        </div>
      )}
    </div>
  );
}

// Pre-built empty states for common scenarios
export function NoResultsState({ 
  searchQuery, 
  onClear 
}: {
  searchQuery?: string;
  onClear?: () => void;
}) {
  const { t } = useTranslation('common');
  return (
    <EmptyState
      icon={Search}
      title={t('EmptyState.noResults.title')}
      description={searchQuery
        ? t('EmptyState.noResults.descriptionWithQuery', { query: searchQuery })
        : t('EmptyState.noResults.description')
      }
      action={onClear ? { label: t('EmptyState.noResults.clear'), onClick: onClear } : undefined}
    />
  );
}

export function NoDataState({
  type = 'items',
  onAdd,
}: {
  type?: string;
  onAdd?: () => void;
}) {
  const { t } = useTranslation('common');
  const singular = type.replace(/s$/, '');
  return (
    <EmptyState
      icon={Package}
      title={t('EmptyState.noData.title', { type })}
      description={t('EmptyState.noData.description', { type: singular })}
      action={onAdd ? { label: t('EmptyState.noData.add', { type: singular }), onClick: onAdd } : undefined}
    />
  );
}

export function ErrorState({
  message,
  error,
  onRetry,
  variant,
  className,
}: {
  /** Text to show. Defaults to the message read from `error`. */
  message?: string;
  /** The thrown value (a query error); its server message is shown. */
  error?: unknown;
  onRetry?: () => void;
  variant?: 'default' | 'compact' | 'card';
  className?: string;
}) {
  const { t } = useTranslation('common');
  const description =
    message ?? (error ? getApiErrorMessage(error, t('EmptyState.error.description')) : t('EmptyState.error.description'));
  return (
    <EmptyState
      icon={AlertTriangle}
      tone="destructive"
      role="alert"
      variant={variant}
      className={className}
      title={t('EmptyState.error.title')}
      description={description}
      // The default action icon is a plus; a retry is not an "add".
      action={onRetry ? { label: t('EmptyState.error.retry'), onClick: onRetry, icon: RefreshCw } : undefined}
    />
  );
}

/**
 * InlineErrorBanner · compact in-page error bar for partial failures.
 * Use when SOME data loaded but a sub-query failed.
 *
 *   {hasError && <InlineErrorBanner>Some metrics failed to load.</InlineErrorBanner>}
 */
export function InlineErrorBanner({
  children,
  onRetry,
  className,
}: {
  children: React.ReactNode;
  onRetry?: () => void;
  className?: string;
}) {
  const { t } = useTranslation('common');
  return (
    <div
      className={cn(
        'flex items-center gap-3 rounded-lg border border-destructive/30 bg-destructive/5 px-4 py-3',
        className,
      )}
      role="alert"
    >
      <AlertTriangle className="h-5 w-5 text-destructive flex-shrink-0" aria-hidden="true" />
      <div className="flex-1 min-w-0 text-sm text-foreground break-words">{children}</div>
      {onRetry && (
        <Button size="sm" variant="ghost" onClick={onRetry} className="shrink-0">
          <RefreshCw className="mr-1.5 h-3.5 w-3.5" aria-hidden="true" />
          {t('EmptyState.inlineError.retry')}
        </Button>
      )}
    </div>
  );
}

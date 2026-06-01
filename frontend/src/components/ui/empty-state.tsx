// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN - Empty State Component
 * 
 * Consistent empty state UI for lists, tables, and pages
 */

import { LucideIcon, Package, Search, FileQuestion, Plus } from 'lucide-react';
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
}

export function EmptyState({
  icon: Icon = Package,
  title,
  description,
  action,
  secondaryAction,
  className,
  variant = 'default',
}: EmptyStateProps) {
  const ActionIcon = action?.icon || Plus;

  if (variant === 'compact') {
    return (
      <div className={cn('flex items-center justify-center py-8 text-center', className)}>
        <div className="space-y-2 max-w-sm">
          <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-full bg-muted">
            <Icon className="h-6 w-6 text-muted-foreground" />
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
      )}>
        <div className="flex h-14 w-14 items-center justify-center rounded-full bg-muted">
          <Icon className="h-6 w-6 text-muted-foreground" />
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
    <div className={cn('flex flex-col items-center justify-center py-16 text-center', className)}>
      <div className="flex h-20 w-20 items-center justify-center rounded-full bg-muted">
        <Icon className="h-10 w-10 text-muted-foreground" />
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
  onRetry,
}: {
  message?: string;
  onRetry?: () => void;
}) {
  const { t } = useTranslation('common');
  return (
    <EmptyState
      icon={FileQuestion}
      title={t('EmptyState.error.title')}
      description={message ?? t('EmptyState.error.description')}
      action={onRetry ? { label: t('EmptyState.error.retry'), onClick: onRetry } : undefined}
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
      <FileQuestion className="h-5 w-5 text-destructive flex-shrink-0" />
      <div className="flex-1 text-sm text-foreground">{children}</div>
      {onRetry && (
        <Button size="sm" variant="ghost" onClick={onRetry}>
          {t('EmptyState.inlineError.retry')}
        </Button>
      )}
    </div>
  );
}

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN Design System - Bulk Actions Bar Component
 * 
 * Consistent bulk actions bar that appears when items are selected.
 * Used across all data pages for enterprise-grade consistency.
 * Includes Django admin-style "select all" functionality.
 */

import { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { motion, AnimatePresence } from 'framer-motion';
import { CheckSquare, X, LucideIcon } from 'lucide-react';
import { cn } from '../../lib/utils';

interface BulkAction {
  label: string;
  icon?: LucideIcon;
  onClick: () => void;
  disabled?: boolean;
  variant?: 'default' | 'outline' | 'destructive';
}

interface BulkActionsBarProps {
  /** Number of selected items */
  selectedCount: number;
  /** Clear selection callback */
  onClear: () => void;
  /** Action buttons (new declarative API) */
  actions?: BulkAction[];
  /** Action buttons (legacy children API) */
  children?: ReactNode;
  /** Item name for pluralization (e.g., "user", "device") */
  itemName?: string;
  /** Additional className */
  className?: string;
  /** Total count of all items (for "select all" feature) */
  totalCount?: number;
  /** Callback to select all items */
  onSelectAll?: () => void;
  /** Whether all items on current page are selected */
  isAllPageSelected?: boolean;
}

export function BulkActionsBar({
  selectedCount,
  onClear,
  actions,
  children,
  itemName = 'item',
  className,
  totalCount,
  onSelectAll,
  isAllPageSelected,
}: BulkActionsBarProps) {
  const { t } = useTranslation('common');
  const pluralizedItem = selectedCount === 1 ? itemName : `${itemName}s`;
  const isAllSelected = totalCount !== undefined && selectedCount === totalCount;
  const showSelectAllLink = isAllPageSelected && totalCount && selectedCount < totalCount && onSelectAll;

  // Don't show if nothing selected
  if (selectedCount === 0) return null;

  return (
    <AnimatePresence>
      <motion.div
        initial={{ opacity: 0, y: 20, scale: 0.95 }}
        animate={{ opacity: 1, y: 0, scale: 1 }}
        exit={{ opacity: 0, y: 20, scale: 0.95 }}
        className={cn(
          'fixed bottom-6 left-1/2 -translate-x-1/2 z-50',
          'flex items-center gap-2 rounded-full',
          'bg-foreground text-background',
          'shadow-2xl ring-1 ring-foreground/10',
          'px-2 py-2',
          // Mobile: stay inside the viewport. The pill scrolls horizontally on
          // narrow widths so action buttons remain reachable instead of being
          // pushed off-screen.
          'max-w-[calc(100vw-1rem)] overflow-x-auto scrollbar-hide',
          className,
        )}
      >
        <div className="flex items-center gap-2 pl-3">
          <CheckSquare className="h-4 w-4" />
          <span className="text-sm font-medium">
            {t('BulkActionsBar.selectedCount', { count: selectedCount, item: pluralizedItem })}
          </span>
          {showSelectAllLink && (
            <>
              <span className="opacity-50">·</span>
              <button
                onClick={onSelectAll}
                className="text-sm font-medium underline-offset-2 hover:underline"
              >
                {t('BulkActionsBar.selectAll', { count: totalCount, item: itemName })}
              </button>
            </>
          )}
          {isAllSelected && totalCount && totalCount > selectedCount && (
            <span className="text-sm opacity-70">{t('BulkActionsBar.all')}</span>
          )}
        </div>

        <div className="mx-1 h-5 w-px bg-background/20" />

        <div className="flex items-center gap-1">
          {actions?.map((action, index) => {
            const Icon = action.icon;
            const isDestructive = action.variant === 'destructive';
            return (
              <button
                key={index}
                onClick={action.onClick}
                disabled={action.disabled}
                className={cn(
                  'inline-flex items-center gap-2 rounded-full px-3 py-1.5 text-sm font-medium',
                  'transition-colors hover:bg-background/10 disabled:opacity-50',
                  isDestructive && 'text-red-400 hover:bg-red-400/10 hover:text-red-300',
                )}
              >
                {Icon && <Icon className="h-4 w-4" />}
                {action.label}
              </button>
            );
          })}
          {children}
          <button
            onClick={onClear}
            className={cn(
              'inline-flex items-center justify-center rounded-full p-1.5',
              'transition-colors hover:bg-background/10',
            )}
            aria-label={t('BulkActionsBar.clearSelection')}
          >
            <X className="h-4 w-4" />
          </button>
        </div>
      </motion.div>
    </AnimatePresence>
  );
}

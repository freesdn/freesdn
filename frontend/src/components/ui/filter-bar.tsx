// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN Design System - Filter Bar Component
 * 
 * Consistent filter bar with collapsible filters.
 * Used across all data pages for enterprise-grade consistency.
 */

import { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { motion } from 'framer-motion';
import { Filter } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from './card';
import { cn } from '../../lib/utils';

interface FilterBarProps {
  /** Filter controls to display */
  children: ReactNode;
  /** Number of columns for grid layout */
  columns?: 1 | 2 | 3 | 4;
  /** Additional className */
  className?: string;
  /** Show/hide the filter icon and title */
  showTitle?: boolean;
  /** Custom title */
  title?: string;
  /** Animation delay (for staggered animations) */
  delay?: number;
}

export function FilterBar({
  children,
  columns = 3,
  className,
  showTitle = true,
  title,
  delay = 0.2,
}: FilterBarProps) {
  const { t } = useTranslation('common');
  const resolvedTitle = title ?? t('filters');
  const gridCols = {
    1: 'grid-cols-1',
    2: 'grid-cols-1 sm:grid-cols-2',
    3: 'grid-cols-1 sm:grid-cols-2 lg:grid-cols-3',
    4: 'grid-cols-1 sm:grid-cols-2 lg:grid-cols-4',
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay }}
    >
      <Card className={className}>
        {showTitle && (
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <Filter className="h-4 w-4" />
              {resolvedTitle}
            </CardTitle>
          </CardHeader>
        )}
        <CardContent className={cn(!showTitle && 'pt-6')}>
          <div className={cn('grid gap-4', gridCols[columns])}>{children}</div>
        </CardContent>
      </Card>
    </motion.div>
  );
}

interface FilterFieldProps {
  /** Field label */
  label: string;
  /** Filter control */
  children: ReactNode;
  /** Additional className */
  className?: string;
}

export function FilterField({ label, children, className }: FilterFieldProps) {
  return (
    <div className={cn('space-y-2', className)}>
      <label className="text-sm font-medium text-muted-foreground">{label}</label>
      {children}
    </div>
  );
}

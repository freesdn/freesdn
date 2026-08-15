// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN Design System - Stats Grid Component
 * 
 * Consistent statistics grid layout with animated cards.
 * Used across all pages for enterprise-grade consistency.
 */

import { motion } from 'framer-motion';
import { LucideIcon } from 'lucide-react';
import { Link } from 'react-router-dom';
import { Card, CardContent } from './card';
import { Skeleton } from './skeleton';
import { cn } from '../../lib/utils';

// ============================================================================
// Types
// ============================================================================

type StatVariant = 'default' | 'primary' | 'success' | 'warning' | 'destructive' | 'info';

interface StatItem {
  /** Stat title/label */
  title: string;
  /** Stat value */
  value: string | number;
  /** Icon to display */
  icon: LucideIcon;
  /** Color variant */
  variant?: StatVariant;
  /** Additional description */
  description?: string;
  /** Trend indicator */
  trend?: {
    value: number;
    direction: 'up' | 'down';
  };
  /** Make the card a router link to this path (Alerts → /alerts/incidents pattern) */
  linkTo?: string;
  /** Make the card a clickable button with this onClick handler */
  onClick?: () => void;
}

interface StatsGridProps {
  /** Array of stat items */
  stats: StatItem[];
  /** Number of columns */
  columns?: 2 | 3 | 4;
  /** Loading state */
  isLoading?: boolean;
  /** Animation delay */
  delay?: number;
  /** Additional className */
  className?: string;
}

// ============================================================================
// Variant Colors
// ============================================================================

const variantColors: Record<StatVariant, string> = {
  default: 'text-muted-foreground bg-muted/50',
  primary: 'text-primary bg-primary/10',
  success: 'text-success bg-success/10',
  warning: 'text-warning bg-warning/10',
  destructive: 'text-destructive bg-destructive/10',
  info: 'text-info bg-info/10',
};

// ============================================================================
// Loading Skeleton
// ============================================================================

function StatsSkeleton({ columns = 4 }: { columns?: number }) {
  const gridCols: Record<number, string> = {
    2: 'grid-cols-2',
    3: 'grid-cols-1 sm:grid-cols-2 lg:grid-cols-3',
    4: 'grid-cols-2 md:grid-cols-4',
  };

  return (
    <div className={cn('grid gap-4', gridCols[columns] || 'grid-cols-4')}>
      {Array.from({ length: columns }).map((_, i) => (
        <Card key={i}>
          <CardContent noOffset className="p-4">
            <div className="flex items-center gap-3">
              <Skeleton className="h-10 w-10 rounded-lg" />
              <div className="space-y-2">
                <Skeleton className="h-6 w-12" />
                <Skeleton className="h-3 w-20" />
              </div>
            </div>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}

// ============================================================================
// Stat Card Component
// ============================================================================

interface StatCardProps extends StatItem {
  index: number;
  delay: number;
}

function StatCard({ title, value, icon: Icon, variant = 'primary', description, trend, linkTo, onClick, index, delay }: StatCardProps) {
  const isClickable = !!(linkTo || onClick);

  // Inner card body · the canonical icon-LEFT + value-stack-RIGHT layout.
  // items-center vertically centers the icon block against the text stack
  // so the card reads as one balanced row regardless of how many lines of
  // description are present. This is the look used by PoE / Network Discovery.
  const body = (
    <Card
      className={cn(
        'overflow-hidden h-full',
        isClickable && 'transition-all hover:shadow-md hover:border-primary/30 cursor-pointer',
      )}
    >
      <CardContent noOffset className="p-4 sm:p-5">
        <div className="flex items-center gap-3 sm:gap-4">
          <div
            className={cn(
              'flex h-10 w-10 sm:h-11 sm:w-11 items-center justify-center rounded-lg flex-shrink-0',
              variantColors[variant],
            )}
          >
            <Icon className="h-5 w-5 sm:h-[1.4rem] sm:w-[1.4rem]" />
          </div>
          <div className="min-w-0 flex-1">
            <div className="flex items-baseline gap-2">
              <p className="text-2xl sm:text-[1.7rem] leading-none font-bold tracking-tight text-foreground truncate">
                {value}
              </p>
              {trend && (
                <span
                  className={cn(
                    'text-xs font-medium',
                    trend.direction === 'up' ? 'text-success' : 'text-destructive',
                  )}
                >
                  {trend.direction === 'up' ? '↑' : '↓'} {Math.abs(trend.value)}%
                </span>
              )}
            </div>
            <p className="text-xs sm:text-sm text-muted-foreground mt-1 truncate">{title}</p>
            {description && (
              <p className="text-[11px] sm:text-xs text-muted-foreground/70 mt-0.5 truncate">
                {description}
              </p>
            )}
          </div>
        </div>
      </CardContent>
    </Card>
  );

  // Wrap in motion + (Link | button | div) based on interactivity.
  const wrapped = linkTo ? (
    <Link to={linkTo} className="block">
      {body}
    </Link>
  ) : onClick ? (
    <button type="button" onClick={onClick} className="block w-full text-left">
      {body}
    </button>
  ) : (
    body
  );

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: delay + index * 0.05 }}
    >
      {wrapped}
    </motion.div>
  );
}

// ============================================================================
// Main Stats Grid Component
// ============================================================================

export function StatsGrid({
  stats,
  columns = 4,
  isLoading = false,
  delay = 0.1,
  className,
}: StatsGridProps) {
  const gridCols = {
    2: 'grid-cols-2',
    3: 'grid-cols-1 sm:grid-cols-2 lg:grid-cols-3',
    4: 'grid-cols-2 md:grid-cols-4',
  };

  if (isLoading) {
    return <StatsSkeleton columns={columns} />;
  }

  return (
    <div className={cn('grid gap-4', gridCols[columns], className)}>
      {stats.map((stat, index) => (
        <StatCard key={stat.title} {...stat} index={index} delay={delay} />
      ))}
    </div>
  );
}

// ============================================================================
// Exports
// ============================================================================

export type { StatItem, StatVariant };
export { StatsSkeleton };

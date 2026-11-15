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
  /**
   * Columns at full width. Match it to the number of cards so none is left
   * alone on a row: five cards want columns={5}. Narrower screens step down
   * (see GRID_COLS); a last card that would sit alone on a two-column row
   * spans the row instead.
   */
  columns?: StatsColumns;
  /** Loading state */
  isLoading?: boolean;
  /** Animation delay */
  delay?: number;
  /** Additional className */
  className?: string;
}

type StatsColumns = 2 | 3 | 4 | 5 | 6;

// ============================================================================
// Responsive columns
// ============================================================================

// Each count steps down at narrower widths without stranding a card: 3 goes
// straight from one column to three (two would leave the third alone), 5 and
// 6 pass through three. Wherever the grid is two columns wide, an odd last
// card spans both so the row is never half empty. Breakpoints are viewport
// widths; the sidebar takes 256px from lg up, which is why five and six
// columns wait for xl.
const GRID_COLS: Record<StatsColumns, string> = {
  2: 'grid-cols-2 [&>*:last-child:nth-child(odd)]:col-span-2',
  3: 'grid-cols-1 sm:grid-cols-3',
  4: 'grid-cols-2 md:grid-cols-4 max-md:[&>*:last-child:nth-child(odd)]:col-span-2',
  5: 'grid-cols-2 sm:grid-cols-3 xl:grid-cols-5 max-sm:[&>*:last-child:nth-child(odd)]:col-span-2',
  6: 'grid-cols-2 sm:grid-cols-3 xl:grid-cols-6',
};

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

function StatsSkeleton({ columns = 4, className }: { columns?: StatsColumns; className?: string }) {
  return (
    <div
      className={cn('grid gap-3 sm:gap-4', GRID_COLS[columns] ?? GRID_COLS[4], className)}
      aria-busy="true"
      data-testid="stats-skeleton"
    >
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

/** Values longer than this (characters) use the smaller value size. */
const LONG_VALUE = 8;

function StatCard({ title, value, icon: Icon, variant = 'primary', description, trend, linkTo, onClick, index, delay }: StatCardProps) {
  const isClickable = !!(linkTo || onClick);
  const valueText = typeof value === 'string' || typeof value === 'number' ? String(value) : '';

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
        {/* Below sm the icon sits above the value: beside it, a half-width
            card left about 86 px for the value and cut "203.0.113.10" or
            "18d 4h 12m" short, with no tooltip to read on a phone. */}
        <div className="flex flex-col items-start gap-2.5 sm:flex-row sm:items-center sm:gap-4" data-testid="stat-card-body">
          <div
            className={cn(
              'flex h-9 w-9 sm:h-11 sm:w-11 items-center justify-center rounded-lg flex-shrink-0',
              variantColors[variant],
            )}
          >
            <Icon className="h-5 w-5 sm:h-[1.4rem] sm:w-[1.4rem]" />
          </div>
          <div className="min-w-0 w-full sm:w-auto sm:flex-1">
            <div className="flex items-baseline gap-2">
              <p
                className={cn(
                  'leading-none font-bold tracking-tight tabular-nums text-foreground truncate',
                  // An address or a "288 / 520" ratio did not fit a quarter-
                  // width card at the full size and was cut to "203.0.113...";
                  // long values step down a size.
                  valueText.length > LONG_VALUE ? 'text-xl sm:text-2xl' : 'text-2xl sm:text-[1.7rem]',
                )}
                title={valueText || undefined}
              >
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
            {/* Two lines before an ellipsis: at 390 px a card is about 170 px
                wide and one line cut "Total Controllers" to "Total Controll...". */}
            <p className="text-xs sm:text-sm text-muted-foreground mt-1 line-clamp-2 break-words" title={typeof title === 'string' ? title : undefined}>{title}</p>
            {description && (
              <p className="text-[11px] sm:text-xs text-muted-foreground/70 mt-0.5 line-clamp-2 break-words" title={typeof description === 'string' ? description : undefined}>
                {description}
              </p>
            )}
          </div>
        </div>
      </CardContent>
    </Card>
  );

  // Wrap in motion + (Link | button | div) based on interactivity.
  // Clickable cards are tab stops; give them the same focus ring as buttons.
  const focusRing =
    'rounded-lg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background';
  const wrapped = linkTo ? (
    <Link to={linkTo} className={cn('block h-full', focusRing)}>
      {body}
    </Link>
  ) : onClick ? (
    <button type="button" onClick={onClick} className={cn('block h-full w-full text-left', focusRing)}>
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
      className="min-w-0"
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
  if (isLoading) {
    return <StatsSkeleton columns={columns} className={className} />;
  }

  return (
    <div className={cn('grid gap-3 sm:gap-4', GRID_COLS[columns] ?? GRID_COLS[4], className)}>
      {stats.map((stat, index) => (
        <StatCard key={stat.title} {...stat} index={index} delay={delay} />
      ))}
    </div>
  );
}

// ============================================================================
// Exports
// ============================================================================

export type { StatItem, StatVariant, StatsColumns };
export { StatsSkeleton };

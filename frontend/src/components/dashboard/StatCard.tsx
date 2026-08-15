// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN - Stat Card Component
 * 
 * Animated stat card with trend indicators and sparklines
 */

import { motion } from 'framer-motion';
import { LucideIcon, TrendingUp, TrendingDown, Minus } from 'lucide-react';
import { cn } from '@/lib/utils';

interface StatCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  icon: LucideIcon;
  trend?: {
    value: number;
    direction: 'up' | 'down' | 'neutral';
    label?: string;
  };
  color?: 'blue' | 'green' | 'purple' | 'amber' | 'red' | 'cyan';
  className?: string;
  onClick?: () => void;
}

const colorVariants = {
  blue: {
    bg: 'bg-info/10',
    icon: 'text-info',
    ring: 'ring-info/20',
  },
  green: {
    bg: 'bg-success/10',
    icon: 'text-success',
    ring: 'ring-success/20',
  },
  purple: {
    bg: 'bg-primary/10',
    icon: 'text-primary',
    ring: 'ring-primary/20',
  },
  amber: {
    bg: 'bg-warning/10',
    icon: 'text-warning',
    ring: 'ring-warning/20',
  },
  red: {
    bg: 'bg-destructive/10',
    icon: 'text-destructive',
    ring: 'ring-destructive/20',
  },
  cyan: {
    bg: 'bg-info/10',
    icon: 'text-info',
    ring: 'ring-info/20',
  },
};

export function StatCard({
  title,
  value,
  subtitle,
  icon: Icon,
  trend,
  color = 'blue',
  className,
  onClick,
}: StatCardProps) {
  const colors = colorVariants[color];
  
  const TrendIcon = trend?.direction === 'up' 
    ? TrendingUp 
    : trend?.direction === 'down' 
    ? TrendingDown 
    : Minus;

  const trendColor = trend?.direction === 'up'
    ? 'text-success'
    : trend?.direction === 'down'
    ? 'text-destructive'
    : 'text-muted-foreground';

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      whileHover={onClick ? { scale: 1.02 } : undefined}
      onClick={onClick}
      className={cn(
        // Tighter padding on phones; restore generous spacing at sm+
        'relative overflow-hidden rounded-xl border bg-card p-4 sm:p-6 shadow-sm transition-all',
        onClick && 'cursor-pointer hover:shadow-md hover:border-primary/20',
        className
      )}
    >
      <div className="relative flex items-start justify-between gap-3">
        <div className="flex-1 min-w-0">
          <p className="text-sm font-medium text-muted-foreground truncate">{title}</p>
          <motion.p
            className="mt-2 text-2xl sm:text-3xl font-bold tracking-tight truncate"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.1 }}
          >
            {value}
          </motion.p>
          
          {(subtitle || trend) && (
            <div className="mt-2 flex items-center gap-2">
              {trend && (
                <span className={cn('flex items-center gap-1 text-xs font-medium', trendColor)}>
                  <TrendIcon className="h-3 w-3" />
                  {Math.abs(trend.value)}%
                </span>
              )}
              {subtitle && (
                <span className="text-xs text-muted-foreground">{subtitle}</span>
              )}
            </div>
          )}
        </div>
        
        <div className={cn(
          'flex h-10 w-10 sm:h-11 sm:w-11 items-center justify-center rounded-xl ring-1 flex-shrink-0',
          colors.bg,
          colors.ring
        )}>
          <Icon className={cn('h-5 w-5', colors.icon)} />
        </div>
      </div>
    </motion.div>
  );
}

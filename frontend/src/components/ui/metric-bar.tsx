// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN Design System · MetricBar + MetricBreakdown
 *
 * Standardized progress / metric bars. Replaces every page-local
 * MiniProgress / inline progress bar implementation.
 *
 *   <MetricBar value={75} />                         // bar + "75%"
 *   <MetricBar value={42} thresholds={[50, 75]} />   // custom thresholds
 *   <MetricBar value={75} variant="thin" />          // thinner
 *   <MetricBar value={75} hideValue />               // bar only
 *   <MetricBar value={75} tone="info" showValue />   // forced tone
 *
 *   <MetricBreakdown items={[
 *     { label: 'Switches', value: 6, total: 22, icon: HardDrive },
 *     { label: 'APs',      value: 6, total: 22, icon: Wifi },
 *   ]} />
 */

import { cn } from '../../lib/utils';
import type { LucideIcon } from 'lucide-react';

type Tone = 'success' | 'warning' | 'destructive' | 'info' | 'primary' | 'neutral';
type Variant = 'thin' | 'standard' | 'thick';

const toneClass: Record<Tone, string> = {
  success:     'bg-success',
  warning:     'bg-warning',
  destructive: 'bg-destructive',
  info:        'bg-info',
  primary:     'bg-primary',
  neutral:     'bg-muted-foreground',
};

const variantClass: Record<Variant, string> = {
  thin:     'h-1',
  standard: 'h-1.5',
  thick:    'h-2.5',
};

interface MetricBarProps {
  /** Numeric value (0-max, clamped) */
  value: number | null | undefined;
  /** Max value, defaults to 100 */
  max?: number;
  /** Bar thickness */
  variant?: Variant;
  /** Show numeric value text on the right */
  showValue?: boolean;
  /** Hide value text entirely (bar only) */
  hideValue?: boolean;
  /** Force a specific tone */
  tone?: Tone;
  /** Auto-tone thresholds · defaults [70, 90]: <70 success, 70-90 warning, >90 destructive */
  thresholds?: [number, number];
  /** Reverse threshold direction (for "higher is better" metrics like uptime/availability) */
  invertThresholds?: boolean;
  /** Format the displayed value (default: "75%") */
  formatValue?: (value: number, max: number) => string;
  /** Min width for the bar itself */
  className?: string;
}

export function MetricBar({
  value,
  max = 100,
  variant = 'standard',
  showValue = true,
  hideValue = false,
  tone,
  thresholds = [70, 90],
  invertThresholds = false,
  formatValue,
  className,
}: MetricBarProps) {
  if (value == null) {
    return <span className="text-xs text-muted-foreground">-</span>;
  }

  const pct = max > 0 ? Math.max(0, Math.min(100, (value / max) * 100)) : 0;

  // Auto-tone: by default higher % = worse (CPU/memory/utilization).
  // invertThresholds=true → higher % = better (uptime/availability).
  const resolvedTone: Tone =
    tone ??
    (invertThresholds
      ? pct >= thresholds[1]
        ? 'success'
        : pct >= thresholds[0]
          ? 'warning'
          : 'destructive'
      : pct > thresholds[1]
        ? 'destructive'
        : pct > thresholds[0]
          ? 'warning'
          : 'success');

  const displayValue = formatValue
    ? formatValue(value, max)
    : max === 100
      ? `${Math.round(pct)}%`
      : `${value}/${max}`;

  return (
    <div className={cn('flex items-center gap-2 min-w-[80px]', className)}>
      <div
        className={cn(
          'flex-1 rounded-full bg-muted overflow-hidden',
          variantClass[variant],
        )}
        role="progressbar"
        aria-valuenow={pct}
        aria-valuemin={0}
        aria-valuemax={100}
      >
        <div
          className={cn(
            'h-full rounded-full transition-all duration-500 ease-out',
            toneClass[resolvedTone],
          )}
          style={{ width: `${pct}%` }}
        />
      </div>
      {!hideValue && showValue && (
        <span className="text-xs font-mono tabular-nums text-muted-foreground w-10 text-right">
          {displayValue}
        </span>
      )}
    </div>
  );
}

// ============================================================================
// MetricBreakdown · list of (icon, label, value, total, bar) rows
// ============================================================================

interface MetricBreakdownItem {
  label: string;
  value: number;
  total?: number;
  icon?: LucideIcon;
  tone?: Tone;
}

interface MetricBreakdownProps {
  items: MetricBreakdownItem[];
  /** Bar thickness */
  variant?: Variant;
  /** Default tone for all bars */
  defaultTone?: Tone;
  /** Show a small bar under each row (default true) */
  showBars?: boolean;
  className?: string;
}

export function MetricBreakdown({
  items,
  variant = 'thin',
  defaultTone = 'primary',
  showBars = true,
  className,
}: MetricBreakdownProps) {
  const maxTotal = Math.max(...items.map((i) => i.total ?? i.value), 1);

  return (
    <div className={cn('space-y-3', className)}>
      {items.map((item, i) => {
        const Icon = item.icon;
        const total = item.total ?? maxTotal;
        const pct = total > 0 ? (item.value / total) * 100 : 0;
        return (
          <div key={i} className="space-y-1">
            <div className="flex items-center justify-between text-sm">
              <span className="flex items-center gap-2 min-w-0">
                {Icon && <Icon className="h-3.5 w-3.5 text-muted-foreground flex-shrink-0" />}
                <span className="truncate">{item.label}</span>
              </span>
              <span className="text-foreground font-medium tabular-nums">
                {item.value}
                {item.total !== undefined && (
                  <span className="text-muted-foreground"> / {item.total}</span>
                )}
              </span>
            </div>
            {showBars && (
              <div
                className={cn(
                  'rounded-full bg-muted overflow-hidden',
                  variantClass[variant],
                )}
              >
                <div
                  className={cn(
                    'h-full rounded-full transition-all duration-500',
                    toneClass[item.tone ?? defaultTone],
                  )}
                  style={{ width: `${pct}%` }}
                />
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN Design System · HealthRing
 *
 * Single canonical donut chart for health/percentage indicators.
 * Replaces every page-local SVG donut implementation.
 *
 * Token-driven colors via thresholds:
 *   default thresholds: [80, 95]
 *     value >= 95 → success (green)
 *     value >= 80 → warning (amber)
 *     value <  80 → destructive (red)
 *
 * Usage:
 *   <HealthRing value={86} size="md" />                       // 86%, auto-color
 *   <HealthRing value={86} size="lg" label="Online" />        // with label
 *   <HealthRing value={42} size="sm" thresholds={[50, 75]} /> // custom thresholds
 *   <HealthRing value={86} size="md" tone="success" />        // force tone
 */

import { cn } from '../../lib/utils';

type Size = 'sm' | 'md' | 'lg' | 'xl';
type Tone = 'success' | 'warning' | 'destructive' | 'info' | 'primary' | 'muted';

const sizes: Record<Size, { px: number; stroke: number; valueText: string; labelText: string }> = {
  sm: { px: 56,  stroke: 4, valueText: 'text-xs',  labelText: 'text-[10px]' },
  md: { px: 80,  stroke: 5, valueText: 'text-sm',  labelText: 'text-xs' },
  lg: { px: 120, stroke: 6, valueText: 'text-2xl font-bold', labelText: 'text-xs' },
  xl: { px: 160, stroke: 8, valueText: 'text-3xl font-bold', labelText: 'text-sm' },
};

// Token-driven stroke colors · these resolve to CSS var values in both themes.
// We use the actual CSS var pattern to bypass Tailwind JIT for SVG stroke.
const toneStroke: Record<Tone, string> = {
  success:     'hsl(var(--success))',
  warning:     'hsl(var(--warning))',
  destructive: 'hsl(var(--destructive))',
  info:        'hsl(var(--info))',
  primary:     'hsl(var(--primary))',
  muted:       'hsl(var(--muted-foreground))',
};

const toneText: Record<Tone, string> = {
  success:     'text-success',
  warning:     'text-warning',
  destructive: 'text-destructive',
  info:        'text-info',
  primary:     'text-primary',
  muted:       'text-muted-foreground',
};

interface HealthRingProps {
  /** Numeric value (0-100 typically). Will be clamped. */
  value: number;
  /** Maximum value, defaults to 100. Useful for `value=8 max=10`. */
  max?: number;
  /** Visual size */
  size?: Size;
  /** Optional small label below the value (e.g., "Online") */
  label?: string;
  /** Hide the inner percentage text */
  hideValue?: boolean;
  /** Force a specific tone instead of computing from thresholds */
  tone?: Tone;
  /** Thresholds for auto-color [warningAbove, successAbove] · defaults [80, 95] */
  thresholds?: [number, number];
  /** Show value as raw number rather than percentage */
  showAsCount?: boolean;
  /** Additional className on the wrapper */
  className?: string;
}

export function HealthRing({
  value,
  max = 100,
  size = 'md',
  label,
  hideValue = false,
  tone,
  thresholds = [80, 95],
  showAsCount = false,
  className,
}: HealthRingProps) {
  const dim = sizes[size];
  const pct = max > 0 ? Math.max(0, Math.min(100, (value / max) * 100)) : 0;

  // Compute tone from thresholds if not explicitly set
  const resolvedTone: Tone =
    tone ?? (pct >= thresholds[1] ? 'success' : pct >= thresholds[0] ? 'warning' : 'destructive');

  const strokeColor = toneStroke[resolvedTone];
  const textClass = toneText[resolvedTone];

  const r = (dim.px - dim.stroke * 2) / 2;
  const c = 2 * Math.PI * r;
  const offset = c - (pct / 100) * c;

  const displayValue = showAsCount ? value : `${Math.round(pct)}%`;

  return (
    <div
      className={cn('relative inline-flex items-center justify-center', className)}
      style={{ width: dim.px, height: dim.px }}
      role="img"
      aria-label={`${label ? label + ': ' : ''}${displayValue}`}
    >
      <svg width={dim.px} height={dim.px} className="-rotate-90">
        {/* Track */}
        <circle
          cx={dim.px / 2}
          cy={dim.px / 2}
          r={r}
          fill="none"
          stroke="hsl(var(--muted))"
          strokeWidth={dim.stroke}
        />
        {/* Progress */}
        <circle
          cx={dim.px / 2}
          cy={dim.px / 2}
          r={r}
          fill="none"
          stroke={strokeColor}
          strokeWidth={dim.stroke}
          strokeDasharray={c}
          strokeDashoffset={offset}
          strokeLinecap="round"
          className="transition-[stroke-dashoffset] duration-700 ease-out"
        />
      </svg>
      {!hideValue && (
        <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
          <span className={cn('tabular-nums', dim.valueText, textClass)}>{displayValue}</span>
          {label && (
            <span className={cn(dim.labelText, 'text-muted-foreground mt-0.5')}>{label}</span>
          )}
        </div>
      )}
    </div>
  );
}

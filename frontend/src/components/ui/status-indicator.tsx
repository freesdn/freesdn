// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { cn } from '../../lib/utils';

// ─────────────────────────────────────────────────────────────────────
// Variants
// ─────────────────────────────────────────────────────────────────────

/** Legacy 6-variant set (kept for back-compat) */
export type StatusType = 'online' | 'offline' | 'warning' | 'updating' | 'disabled' | 'pending';

/** Extended variant set used by newer call-sites (PBXDetailPage, HypervisorPage, etc.) */
export type StatusVariant =
  | StatusType
  | 'success'
  | 'error'
  | 'neutral'
  | 'info'
  | 'syncing'
  | 'connected'
  | 'disconnected'
  | 'unknown'
  | 'critical'
  | 'severity_critical'
  | 'severity_high'
  | 'severity_medium'
  | 'severity_low'
  | 'severity_info';

interface StatusIndicatorProps {
  status: StatusType | StatusVariant;
  size?: 'sm' | 'md' | 'lg';
  pulse?: boolean;
  showLabel?: boolean;
  className?: string;
}

// Map every variant onto a base "tone" · drives both the dot color and badge color.
type Tone = 'success' | 'destructive' | 'warning' | 'info' | 'muted';

const variantToTone: Record<StatusVariant, Tone> = {
  // Legacy 6
  online: 'success',
  offline: 'destructive',
  warning: 'warning',
  updating: 'info',
  disabled: 'muted',
  pending: 'muted',
  // Extended
  success: 'success',
  error: 'destructive',
  neutral: 'muted',
  info: 'info',
  syncing: 'info',
  connected: 'success',
  disconnected: 'destructive',
  unknown: 'muted',
  critical: 'destructive',
  severity_critical: 'destructive',
  severity_high: 'warning',
  severity_medium: 'warning',
  severity_low: 'muted',
  severity_info: 'info',
};

const toneDot: Record<Tone, string> = {
  success: 'bg-success',
  destructive: 'bg-destructive',
  warning: 'bg-warning',
  info: 'bg-info',
  muted: 'bg-muted-foreground',
};

const tonePill: Record<Tone, string> = {
  success: 'bg-success/10 text-success border-success/20',
  destructive: 'bg-destructive/10 text-destructive border-destructive/20',
  warning: 'bg-warning/10 text-warning border-warning/20',
  info: 'bg-info/10 text-info border-info/20',
  muted: 'bg-muted text-muted-foreground border-muted',
};

const statusSizes = {
  sm: 'h-2 w-2',
  md: 'h-2.5 w-2.5',
  lg: 'h-3 w-3',
};

const variantLabel: Record<StatusVariant, string> = {
  online: 'Online',
  offline: 'Offline',
  warning: 'Warning',
  updating: 'Updating',
  disabled: 'Disabled',
  pending: 'Pending',
  success: 'Success',
  error: 'Error',
  neutral: 'Neutral',
  info: 'Info',
  syncing: 'Syncing',
  connected: 'Connected',
  disconnected: 'Disconnected',
  unknown: 'Unknown',
  critical: 'Critical',
  severity_critical: 'Critical',
  severity_high: 'High',
  severity_medium: 'Medium',
  severity_low: 'Low',
  severity_info: 'Info',
};

export function StatusIndicator({
  status,
  size = 'md',
  pulse = true,
  showLabel = false,
  className,
}: StatusIndicatorProps) {
  const tone = variantToTone[status as StatusVariant] ?? 'muted';
  const dot = toneDot[tone];
  return (
    <span className={cn('relative inline-flex items-center gap-1.5', className)}>
      <span className="relative inline-flex">
        <span className={cn('rounded-full', dot, statusSizes[size])} />
        {pulse && (status === 'online' || status === 'connected') && (
          <span
            className={cn(
              'absolute inline-flex h-full w-full rounded-full opacity-75',
              dot,
              'animate-ping',
            )}
            style={{ animationDuration: '2s' }}
          />
        )}
      </span>
      {showLabel && (
        <span className="text-xs font-medium capitalize">
          {variantLabel[status as StatusVariant] ?? String(status)}
        </span>
      )}
    </span>
  );
}

// ─────────────────────────────────────────────────────────────────────
// StatusBadge · pill with optional dot/icon + label
//
// Supports BOTH legacy and extended APIs:
//   Legacy:    <StatusBadge status="online" label="Connected" />
//   Extended:  <StatusBadge variant="success" hideIcon size="sm">Active</StatusBadge>
// ─────────────────────────────────────────────────────────────────────

interface StatusBadgeProps {
  /** Legacy prop · preferred for older code */
  status?: StatusType | StatusVariant;
  /** Extended prop (alias for status) */
  variant?: StatusVariant;
  /** Legacy label override */
  label?: string;
  /** Children override (alias for label) */
  children?: React.ReactNode;
  /** Hide the dot indicator */
  hideIcon?: boolean;
  /** Compact / default size */
  size?: 'sm' | 'md';
  className?: string;
}

export function StatusBadge({
  status,
  variant,
  label,
  children,
  hideIcon = false,
  size = 'md',
  className,
}: StatusBadgeProps) {
  const v: StatusVariant = (variant ?? status ?? 'neutral') as StatusVariant;
  const tone = variantToTone[v] ?? 'muted';
  const labelText = children ?? label ?? variantLabel[v] ?? String(v);

  const sizeClasses =
    size === 'sm'
      ? 'px-2 py-0.5 text-[10px] gap-1'
      : 'px-2.5 py-0.5 text-xs gap-1.5';

  return (
    <span
      className={cn(
        'inline-flex items-center rounded-full border font-medium whitespace-nowrap',
        tonePill[tone],
        sizeClasses,
        className,
      )}
    >
      {!hideIcon && (
        <StatusIndicator
          status={v}
          size="sm"
          pulse={v === 'online' || v === 'connected'}
        />
      )}
      {labelText}
    </span>
  );
}

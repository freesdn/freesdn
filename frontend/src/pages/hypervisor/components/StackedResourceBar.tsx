// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Hypervisor Module - Stacked Resource Bar
 * Shows multi-segment resource usage (e.g. per-VM memory/disk breakdown on a node).
 */
import { formatBytes } from './helpers';

type SegmentTone = 'success' | 'warning' | 'destructive' | 'info' | 'primary' | 'muted';

const toneToCss: Record<SegmentTone, string> = {
  success:     'hsl(var(--success))',
  warning:     'hsl(var(--warning))',
  destructive: 'hsl(var(--destructive))',
  info:        'hsl(var(--info))',
  primary:     'hsl(var(--primary))',
  muted:       'hsl(var(--muted-foreground))',
};

export interface StackedSegment {
  label: string;
  value: number;
  /** Raw CSS color (e.g. '#22c55e', 'hsl(...)' ) · backward-compat path */
  color?: string;
  /** Semantic tone · preferred. Resolves to the matching CSS token. */
  tone?: SegmentTone;
}

interface StackedResourceBarProps {
  segments: StackedSegment[];
  total: number;
  label: string;
  formatValue?: (v: number) => string;
}

export function StackedResourceBar({
  segments,
  total,
  label,
  formatValue = formatBytes,
}: StackedResourceBarProps) {
  const used = segments.reduce((sum, s) => sum + s.value, 0);

  if (total <= 0) return null;

  return (
    <div className="space-y-1">
      <div className="flex justify-between text-xs text-muted-foreground">
        <span>{label}</span>
        <span>
          {formatValue(used)} / {formatValue(total)}
        </span>
      </div>
      <div className="h-3 rounded-full overflow-hidden bg-muted flex">
        {segments.map((seg, i) => {
          const pct = (seg.value / total) * 100;
          if (pct <= 0) return null;
          // Prefer semantic tone; fall back to raw color for back-compat.
          const bg = seg.tone
            ? toneToCss[seg.tone]
            : seg.color ?? toneToCss.primary;
          return (
            <div
              key={i}
              className="h-full transition-all"
              style={{ width: `${pct}%`, backgroundColor: bg }}
              title={`${seg.label}: ${formatValue(seg.value)}`}
            />
          );
        })}
      </div>
      {segments.length > 1 && (
        <div className="flex flex-wrap gap-2 text-xs">
          {segments.map((seg, i) => (
            <span key={i} className="flex items-center gap-1">
              <span
                className="h-2 w-2 rounded-full inline-block"
                style={{ backgroundColor: seg.color }}
              />
              {seg.label}
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

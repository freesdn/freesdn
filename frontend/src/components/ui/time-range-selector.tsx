// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN Design System · TimeRangeSelector
 *
 * Canonical time-range picker used by Dashboard, Analytics, Logs, Health,
 * Network. Predefined ranges (1h/6h/24h/7d/30d) + optional custom.
 *
 * Usage:
 *   const [range, setRange] = useState<TimeRange>('24h');
 *   <TimeRangeSelector value={range} onChange={setRange} />
 *
 *   // In query: const { from, to } = resolveRange(range);
 *
 * Variants:
 *   <TimeRangeSelector variant="chips" />   // pill toggles (default)
 *   <TimeRangeSelector variant="dropdown" /> // shadcn select
 *   <TimeRangeSelector ranges={['1h', '24h', '7d']} />  // custom subset
 */

import { Calendar, Clock } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { cn } from '../../lib/utils';
import { Button } from './button';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from './select';

export type TimeRange = '5m' | '15m' | '1h' | '6h' | '24h' | '7d' | '30d' | '90d' | 'custom';

interface TimeRangeMeta {
  value: TimeRange;
  label: string;
  shortLabel: string;
  /** Duration in milliseconds (custom = 0) */
  durationMs: number;
}

export const TIME_RANGES: Record<TimeRange, TimeRangeMeta> = {
  '5m':     { value: '5m',     label: 'Last 5 minutes',  shortLabel: '5M',  durationMs: 5 * 60 * 1000 },
  '15m':    { value: '15m',    label: 'Last 15 minutes', shortLabel: '15M', durationMs: 15 * 60 * 1000 },
  '1h':     { value: '1h',     label: 'Last hour',       shortLabel: '1H',  durationMs: 60 * 60 * 1000 },
  '6h':     { value: '6h',     label: 'Last 6 hours',    shortLabel: '6H',  durationMs: 6 * 60 * 60 * 1000 },
  '24h':    { value: '24h',    label: 'Last 24 hours',   shortLabel: '24H', durationMs: 24 * 60 * 60 * 1000 },
  '7d':     { value: '7d',     label: 'Last 7 days',     shortLabel: '7D',  durationMs: 7 * 24 * 60 * 60 * 1000 },
  '30d':    { value: '30d',    label: 'Last 30 days',    shortLabel: '30D', durationMs: 30 * 24 * 60 * 60 * 1000 },
  '90d':    { value: '90d',    label: 'Last 90 days',    shortLabel: '90D', durationMs: 90 * 24 * 60 * 60 * 1000 },
  'custom': { value: 'custom', label: 'Custom range',    shortLabel: 'Custom', durationMs: 0 },
};

const DEFAULT_RANGES: TimeRange[] = ['1h', '6h', '24h', '7d', '30d'];

interface TimeRangeSelectorProps {
  value: TimeRange;
  onChange: (value: TimeRange) => void;
  /** Which ranges to show · defaults to common 5 */
  ranges?: TimeRange[];
  /** Layout variant */
  variant?: 'chips' | 'dropdown';
  /** Show clock icon prefix */
  showIcon?: boolean;
  /** Disable interaction */
  disabled?: boolean;
  className?: string;
}

export function TimeRangeSelector({
  value,
  onChange,
  ranges = DEFAULT_RANGES,
  variant = 'chips',
  showIcon = false,
  disabled = false,
  className,
}: TimeRangeSelectorProps) {
  const { t } = useTranslation('common');
  if (variant === 'dropdown') {
    return (
      <Select
        value={value}
        onValueChange={(v) => onChange(v as TimeRange)}
        disabled={disabled}
      >
        <SelectTrigger className={cn('w-full sm:w-[160px]', className)}>
          {showIcon && <Clock className="h-3.5 w-3.5 mr-2 text-muted-foreground" />}
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          {ranges.map((r) => (
            <SelectItem key={r} value={r}>
              {t(`TimeRangeSelector.labels.${r}`)}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
    );
  }

  // Chips variant · pill toggle group
  return (
    <div
      className={cn(
        'inline-flex items-center rounded-md border bg-muted/50 p-0.5',
        className,
      )}
      role="group"
      aria-label={t('TimeRangeSelector.ariaLabel')}
    >
      {showIcon && (
        <Clock className="h-3.5 w-3.5 mx-2 text-muted-foreground flex-shrink-0" />
      )}
      {ranges.map((r) => (
        <Button
          key={r}
          variant={value === r ? 'secondary' : 'ghost'}
          size="sm"
          disabled={disabled}
          onClick={() => onChange(r)}
          className={cn(
            'h-7 px-2.5 text-xs font-medium',
            value === r && 'shadow-sm',
          )}
        >
          {t(`TimeRangeSelector.shortLabels.${r}`)}
        </Button>
      ))}
      {ranges.includes('custom') && (
        <Button
          variant={value === 'custom' ? 'secondary' : 'ghost'}
          size="sm"
          disabled={disabled}
          onClick={() => onChange('custom')}
          className="h-7 px-2.5 text-xs font-medium"
        >
          <Calendar className="h-3 w-3 mr-1" />
          {t('TimeRangeSelector.custom')}
        </Button>
      )}
    </div>
  );
}

/**
 * Resolve a TimeRange to absolute from/to timestamps.
 * For 'custom' returns null · caller must provide custom dates.
 */
export function resolveRange(
  range: TimeRange,
  now: Date = new Date(),
): { from: Date; to: Date } | null {
  if (range === 'custom') return null;
  const meta = TIME_RANGES[range];
  return {
    from: new Date(now.getTime() - meta.durationMs),
    to: now,
  };
}

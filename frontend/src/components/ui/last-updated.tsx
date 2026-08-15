// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN Design System · LastUpdated
 *
 * Standardized "Updated 2m ago" widget for refresh status.
 * Use inside PageHeader actions slot or anywhere a freshness indicator is needed.
 *
 *   <LastUpdated timestamp={dataUpdatedAt} />
 *   <LastUpdated timestamp={lastSync} prefix="Last sync" />
 *   <LastUpdated timestamp={lastSync} hideOnMobile />
 */

import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Clock } from 'lucide-react';
import { cn } from '../../lib/utils';

type TFn = (key: string, opts?: Record<string, unknown>) => string;

function formatRelative(
  ts: number | string | Date | null | undefined,
  t: TFn,
): string {
  if (!ts) return t('relative.never');
  const time = typeof ts === 'number' ? ts : new Date(ts).getTime();
  if (!Number.isFinite(time)) return t('relative.never');
  const diff = Date.now() - time;
  if (diff < 0) return t('relative.justNow');
  const mins = Math.floor(diff / 60_000);
  if (mins < 1) return t('relative.justNow');
  if (mins < 60) return t('relative.minutesAgo', { n: mins });
  const hrs = Math.floor(diff / 3_600_000);
  if (hrs < 24) return t('relative.hoursAgo', { n: hrs });
  const days = Math.floor(diff / 86_400_000);
  if (days < 30) return t('relative.daysAgo', { n: days });
  return new Date(time).toLocaleDateString();
}

interface LastUpdatedProps {
  /** Timestamp · number (epoch ms), ISO string, or Date */
  timestamp: number | string | Date | null | undefined;
  /** Prefix text · defaults to "Updated" */
  prefix?: string;
  /** Show clock icon */
  showIcon?: boolean;
  /** Hide on mobile (sm breakpoint) */
  hideOnMobile?: boolean;
  /** Auto-refresh interval in ms · defaults 30s */
  refreshIntervalMs?: number;
  className?: string;
}

export function LastUpdated({
  timestamp,
  prefix,
  showIcon = false,
  hideOnMobile = false,
  refreshIntervalMs = 30_000,
  className,
}: LastUpdatedProps) {
  const { t } = useTranslation('common');
  const resolvedPrefix = prefix ?? t('updated');
  // Re-render every interval so the relative text stays fresh
  const [, tick] = useState(0);
  useEffect(() => {
    const id = setInterval(() => tick((t) => t + 1), refreshIntervalMs);
    return () => clearInterval(id);
  }, [refreshIntervalMs]);

  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 text-xs text-muted-foreground tabular-nums',
        hideOnMobile && 'hidden sm:inline-flex',
        className,
      )}
      title={timestamp && !Number.isNaN(new Date(timestamp).getTime()) ? new Date(timestamp).toLocaleString() : undefined}
    >
      {showIcon && <Clock className="h-3 w-3" />}
      {resolvedPrefix} {formatRelative(timestamp, t)}
    </span>
  );
}

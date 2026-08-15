// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { useQuery } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Skeleton } from '@/components/ui/skeleton';
import { enterpriseApi, type SiteRanking } from '@/lib/api';
import { cn } from '@/lib/utils';

interface SiteRankingTableProps {
  siteId?: string;
}

function scoreColor(score: number): string {
  if (score >= 90) return 'text-green-600 dark:text-green-400';
  if (score >= 70) return 'text-amber-600 dark:text-amber-400';
  if (score >= 50) return 'text-orange-600 dark:text-orange-400';
  return 'text-red-600 dark:text-red-400';
}

function uptimeColor(pct: number | null | undefined): string {
  if (pct == null) return 'text-muted-foreground';
  if (pct >= 99.5) return 'text-green-600 dark:text-green-400';
  if (pct >= 99) return 'text-amber-600 dark:text-amber-400';
  return 'text-red-600 dark:text-red-400';
}

function TrendIndicator({ trend, delta }: { trend: string; delta: number }) {
  if (trend === 'up') {
    return (
      <span className="inline-flex items-center gap-1 text-green-600 dark:text-green-400 text-xs font-medium">
        <span>&#8593;</span>
        <span>+{delta.toFixed(1)}</span>
      </span>
    );
  }
  if (trend === 'down') {
    return (
      <span className="inline-flex items-center gap-1 text-red-600 dark:text-red-400 text-xs font-medium">
        <span>&#8595;</span>
        <span>{delta.toFixed(1)}</span>
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1 text-muted-foreground text-xs font-medium">
      <span>&#8594;</span>
      <span>0.0</span>
    </span>
  );
}

export function SiteRankingTable({ siteId }: SiteRankingTableProps) {
  const { t } = useTranslation('enterprise');
  // NOTE: backend ``get_site_ranking`` does not accept a ``site_id``
  // filter, the ranking is always org-wide (it's literally a ranking
  // OF sites). Previously we passed ``site_id`` and the backend
  // silently ignored it; the FE looked like it was filtering when it
  // wasn't. We now omit the param entirely and also drop ``siteId``
  // from the queryKey so we don't burn extra refetches when the site
  // selector changes (the rankings don't change).
  const { data: rankings, isLoading, isError } = useQuery<SiteRanking[]>({
    queryKey: ['health', 'site-ranking'],
    queryFn: () => enterpriseApi.getSiteRanking().then((r) => r.data),
    refetchInterval: 60000,
  });
  // Highlight the currently-selected site if there is one.
  const highlightedId = siteId;

  const sorted = (rankings ?? []).slice().sort((a, b) => b.avg_health_score - a.avg_health_score);

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">{t('SiteRankingTable.title')}</CardTitle>
      </CardHeader>
      <CardContent>
        {isError && (
          <div className="rounded-md bg-destructive/10 p-3 text-sm text-destructive">
            {t('SiteRankingTable.error')}
          </div>
        )}

        {isLoading && (
          <div className="space-y-2">
            {Array.from({ length: 5 }).map((_, i) => (
              <Skeleton key={i} className="h-10" />
            ))}
          </div>
        )}

        {!isLoading && !isError && sorted.length === 0 && (
          <p className="text-sm text-muted-foreground text-center py-8">
            {t('SiteRankingTable.empty')}
          </p>
        )}

        {sorted.length > 0 && (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b text-left text-muted-foreground">
                  <th className="pb-2 pr-3 font-medium w-12">#</th>
                  <th className="pb-2 pr-3 font-medium">{t('SiteRankingTable.columns.site')}</th>
                  <th className="pb-2 pr-3 font-medium">{t('SiteRankingTable.columns.healthScore')}</th>
                  <th className="pb-2 pr-3 font-medium">{t('SiteRankingTable.columns.uptimePercent')}</th>
                  <th className="pb-2 pr-3 font-medium">{t('SiteRankingTable.columns.devices')}</th>
                  <th className="pb-2 font-medium">{t('SiteRankingTable.columns.trend')}</th>
                </tr>
              </thead>
              <tbody>
                {sorted.map((site, idx) => (
                  <tr
                    key={site.site_id}
                    className={cn(
                      'border-b last:border-0 hover:bg-muted/50',
                      site.site_id === highlightedId && 'bg-primary/5',
                    )}
                  >
                    <td className="py-2 pr-3 text-muted-foreground font-medium">{idx + 1}</td>
                    <td className="py-2 pr-3 font-medium">{site.site_name}</td>
                    <td className="py-2 pr-3">
                      <span className={cn('font-semibold tabular-nums', scoreColor(site.avg_health_score))}>
                        {Math.round(site.avg_health_score)}
                      </span>
                    </td>
                    <td className="py-2 pr-3">
                      {site.uptime_percent == null ? (
                        <span className="text-muted-foreground text-xs">-</span>
                      ) : (
                        <span className={cn('font-medium tabular-nums', uptimeColor(site.uptime_percent))}>
                          {site.uptime_percent.toFixed(1)}%
                        </span>
                      )}
                    </td>
                    <td className="py-2 pr-3 text-muted-foreground">{site.device_count}</td>
                    <td className="py-2">
                      <TrendIndicator trend={site.trend} delta={site.trend_delta} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

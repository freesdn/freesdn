// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { useQuery } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Skeleton } from '@/components/ui/skeleton';
import { enterpriseApi, type WANDeviceHealth } from '@/lib/api';
import { HealthGauge } from './HealthGauge';
import { cn } from '@/lib/utils';

interface WANHealthPanelProps {
  siteId?: string;
}

function scoreColor(score: number | null): string {
  if (score === null || score === undefined) return 'text-muted-foreground';
  if (score >= 90) return 'text-green-600 dark:text-green-400';
  if (score >= 70) return 'text-amber-600 dark:text-amber-400';
  if (score >= 50) return 'text-orange-600 dark:text-orange-400';
  return 'text-red-600 dark:text-red-400';
}

function MiniScoreBar({ label, score }: { label: string; score: number | null }) {
  if (score === null || score === undefined) {
    return (
      <div className="space-y-0.5">
        <span className="text-[10px] text-muted-foreground">{label}</span>
        <div className="h-1.5 rounded-full bg-muted" />
      </div>
    );
  }
  const color =
    score >= 90 ? 'bg-green-500' :
    score >= 70 ? 'bg-amber-500' :
    score >= 50 ? 'bg-orange-500' :
    'bg-red-500';

  return (
    <div className="space-y-0.5">
      <div className="flex justify-between">
        <span className="text-[10px] text-muted-foreground">{label}</span>
        <span className={cn('text-[10px] font-medium', scoreColor(score))}>{score}</span>
      </div>
      <div className="h-1.5 rounded-full bg-muted overflow-hidden">
        <div className={cn('h-full rounded-full', color)} style={{ width: `${score}%` }} />
      </div>
    </div>
  );
}

export function WANHealthPanel({ siteId }: WANHealthPanelProps) {
  const { t } = useTranslation('enterprise');
  const { data: devices, isLoading, isError } = useQuery<WANDeviceHealth[]>({
    queryKey: ['health', 'wan', { siteId }],
    queryFn: () => enterpriseApi.getWANHealth(siteId ? { site_id: siteId } : undefined).then((r) => r.data),
    refetchInterval: 60000,
  });

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">{t('WANHealthPanel.title')}</CardTitle>
      </CardHeader>
      <CardContent>
        {isError && (
          <div className="rounded-md bg-destructive/10 p-3 text-sm text-destructive">
            {t('WANHealthPanel.error')}
          </div>
        )}

        {isLoading && (
          <div className="space-y-2">
            {Array.from({ length: 3 }).map((_, i) => (
              <Skeleton key={i} className="h-16" />
            ))}
          </div>
        )}

        {!isLoading && !isError && (!devices || devices.length === 0) && (
          <p className="text-sm text-muted-foreground text-center py-8">
            {t('WANHealthPanel.empty')}
          </p>
        )}

        {devices && devices.length > 0 && (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b text-left text-muted-foreground">
                  <th className="pb-2 pr-3 font-medium">{t('WANHealthPanel.columns.device')}</th>
                  <th className="pb-2 pr-3 font-medium">{t('WANHealthPanel.columns.site')}</th>
                  <th className="pb-2 pr-3 font-medium">{t('WANHealthPanel.columns.ip')}</th>
                  <th className="pb-2 pr-3 font-medium">{t('WANHealthPanel.columns.health')}</th>
                  <th className="pb-2 pr-3 font-medium w-32">{t('WANHealthPanel.columns.latency')}</th>
                  <th className="pb-2 font-medium w-32">{t('WANHealthPanel.columns.reachability')}</th>
                </tr>
              </thead>
              <tbody>
                {devices.map((device) => (
                  <tr key={device.device_id} className="border-b last:border-0 hover:bg-muted/50">
                    <td className="py-2 pr-3">
                      <div>
                        <span className="font-medium">{device.device_name}</span>
                        <span className="ml-2 text-xs text-muted-foreground capitalize">{device.device_type}</span>
                      </div>
                    </td>
                    <td className="py-2 pr-3 text-muted-foreground">{device.site_name}</td>
                    <td className="py-2 pr-3 text-muted-foreground font-mono text-xs">{device.ip_address ?? '-'}</td>
                    <td className="py-2 pr-3">
                      <HealthGauge score={Math.round(device.health_score)} size="sm" />
                    </td>
                    <td className="py-2 pr-3">
                      <MiniScoreBar label={t('WANHealthPanel.columns.latency')} score={device.latency_score} />
                    </td>
                    <td className="py-2">
                      <MiniScoreBar label={t('WANHealthPanel.columns.reachability')} score={device.reachability_score} />
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

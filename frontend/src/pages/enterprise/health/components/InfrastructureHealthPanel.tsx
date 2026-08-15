// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { useQuery } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { Database, HardDrive, Cog, CheckCircle2, AlertTriangle, XCircle } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';

import { Skeleton } from '@/components/ui/skeleton';
import { cn } from '@/lib/utils';
import { enterpriseApi } from '@/lib/api';

const COMPONENT_ICONS: Record<string, React.ElementType> = {
  database: Database,
  postgres: Database,
  redis: HardDrive,
  celery: Cog,
  worker: Cog,
};

function statusDot(status: string): string {
  switch (status) {
    case 'healthy':
    case 'ok':
    case 'up':
      return 'bg-green-500';
    case 'warning':
    case 'degraded':
      return 'bg-amber-500';
    default:
      return 'bg-red-500';
  }
}

function statusBadgeClass(status: string): string {
  switch (status) {
    case 'healthy':
    case 'ok':
    case 'up':
      return 'bg-green-500/10 text-green-500 border-green-500/20';
    case 'warning':
    case 'degraded':
      return 'bg-amber-500/10 text-amber-500 border-amber-500/20';
    default:
      return 'bg-red-500/10 text-red-500 border-red-500/20';
  }
}

export function InfrastructureHealthPanel() {
  const { t } = useTranslation('enterprise');
  const { data, isLoading, isError } = useQuery({
    queryKey: ['health', 'infrastructure'],
    queryFn: () => enterpriseApi.getInfrastructureHealth().then((r) => r.data),
    refetchInterval: 30_000,
  });

  const overallStatus = data?.status ?? 'unknown';

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <Database className="h-4 w-4" />
          {t('InfrastructureHealthPanel.title')}
        </CardTitle>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <div className="space-y-3">
            <Skeleton className="h-8" />
            <div className="grid gap-3 sm:grid-cols-3">
              {Array.from({ length: 3 }).map((_, i) => (
                <Skeleton key={i} className="h-24" />
              ))}
            </div>
          </div>
        ) : isError ? (
          <div className="rounded-md bg-destructive/10 p-3 text-sm text-destructive">
            {t('InfrastructureHealthPanel.loadError')}
          </div>
        ) : (
          <div className="space-y-4">
            {/* Overall status banner */}
            <div className={cn('rounded-lg p-3 flex items-center gap-2', statusBadgeClass(overallStatus))}>
              {overallStatus === 'healthy' || overallStatus === 'ok' || overallStatus === 'up' ? (
                <CheckCircle2 className="h-4 w-4" />
              ) : overallStatus === 'warning' || overallStatus === 'degraded' ? (
                <AlertTriangle className="h-4 w-4" />
              ) : (
                <XCircle className="h-4 w-4" />
              )}
              <span className="text-sm font-medium capitalize">
                {t('InfrastructureHealthPanel.systemStatus', { status: overallStatus })}
              </span>
              {data?.uptime_seconds != null && (
                <span className="ml-auto text-xs opacity-75">
                  {t('InfrastructureHealthPanel.uptime', {
                    hours: Math.floor(data.uptime_seconds / 3600),
                    minutes: Math.floor((data.uptime_seconds % 3600) / 60),
                  })}
                </span>
              )}
            </div>

            {/* Component cards */}
            <div className="grid gap-3 sm:grid-cols-3">
              {(data?.components ?? []).map((comp) => {
                const Icon = COMPONENT_ICONS[comp.name.toLowerCase()] ?? Cog;
                return (
                  <div key={comp.name} className="rounded-lg border p-4">
                    <div className="flex items-center gap-2 mb-2">
                      <Icon className="h-4 w-4 text-muted-foreground" />
                      <span className="text-sm font-medium capitalize">{comp.name}</span>
                      <span className={cn('h-2 w-2 rounded-full ml-auto', statusDot(comp.status))} />
                    </div>
                    <div className="text-xs text-muted-foreground capitalize">{comp.status}</div>
                    {comp.latency_ms != null && (
                      <div className="text-xs text-muted-foreground mt-1">
                        {t('InfrastructureHealthPanel.latencyLabel')}{' '}
                        <span className="font-medium text-foreground">
                          {t('InfrastructureHealthPanel.latencyValue', { ms: comp.latency_ms })}
                        </span>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

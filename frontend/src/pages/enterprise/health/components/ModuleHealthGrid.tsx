// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { useQuery } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { Network, Camera, Phone, Shield, Server, Boxes } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Skeleton } from '@/components/ui/skeleton';

import { enterpriseApi } from '@/lib/api';
import { HealthGauge } from './HealthGauge';

interface ModuleHealthGridProps {
  siteId?: string;
}

const MODULE_ICONS: Record<string, React.ElementType> = {
  network: Network,
  cameras: Camera,
  voip: Phone,
  security: Shield,
  firewall: Shield,
  compute: Server,
  hypervisor: Server,
  backup: Boxes,
  access: Shield,
  ai: Boxes,
  observability: Boxes,
};

function DistributionBar({
  healthy,
  warning,
  degraded,
  critical,
  total,
}: {
  healthy: number;
  warning: number;
  degraded: number;
  critical: number;
  total: number;
}) {
  if (total === 0) {
    return <div className="h-2 rounded-full bg-muted" />;
  }
  const pct = (n: number) => `${(n / total) * 100}%`;
  return (
    <div className="flex h-2 rounded-full overflow-hidden bg-muted">
      {healthy > 0 && (
        <div className="bg-green-500" style={{ width: pct(healthy) }} />
      )}
      {warning > 0 && (
        <div className="bg-amber-500" style={{ width: pct(warning) }} />
      )}
      {degraded > 0 && (
        <div className="bg-orange-500" style={{ width: pct(degraded) }} />
      )}
      {critical > 0 && (
        <div className="bg-red-500" style={{ width: pct(critical) }} />
      )}
    </div>
  );
}

export function ModuleHealthGrid({ siteId }: ModuleHealthGridProps) {
  const { t } = useTranslation('enterprise');
  const { data, isLoading, isError } = useQuery({
    queryKey: ['health', 'modules', { siteId }],
    queryFn: () => enterpriseApi.getModuleHealth({ site_id: siteId }).then((r) => r.data),
    refetchInterval: 60_000,
  });

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">{t('ModuleHealthGrid.title')}</CardTitle>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {Array.from({ length: 6 }).map((_, i) => (
              <Skeleton key={i} className="h-32" />
            ))}
          </div>
        ) : isError ? (
          <div className="rounded-md bg-destructive/10 p-3 text-sm text-destructive">
            {t('ModuleHealthGrid.error')}
          </div>
        ) : !data?.length ? (
          <div className="flex items-center justify-center py-8 text-sm text-muted-foreground">
            {t('ModuleHealthGrid.empty')}
          </div>
        ) : (
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {data.map((mod) => {
              const Icon = MODULE_ICONS[mod.module.toLowerCase()] ?? Boxes;
              const total = mod.healthy + mod.warning + mod.degraded + mod.critical;
              return (
                <div key={mod.module} className="rounded-lg border p-4">
                  <div className="flex items-center justify-between mb-3">
                    <div className="flex items-center gap-2">
                      <Icon className="h-4 w-4 text-muted-foreground" />
                      <span className="text-sm font-medium capitalize">{mod.module}</span>
                    </div>
                    <HealthGauge score={Math.round(mod.avg_health_score)} size="sm" />
                  </div>
                  <div className="text-xs text-muted-foreground mb-2">
                    {mod.device_count === 1
                      ? t('ModuleHealthGrid.deviceCount_one', { count: mod.device_count })
                      : t('ModuleHealthGrid.deviceCount_other', { count: mod.device_count })}
                  </div>
                  <DistributionBar
                    healthy={mod.healthy}
                    warning={mod.warning}
                    degraded={mod.degraded}
                    critical={mod.critical}
                    total={total}
                  />
                  <div className="flex justify-between mt-1 text-[10px] text-muted-foreground">
                    <span className="text-green-500">{t('ModuleHealthGrid.counts.healthy', { count: mod.healthy })}</span>
                    <span className="text-amber-500">{t('ModuleHealthGrid.counts.warning', { count: mod.warning })}</span>
                    <span className="text-orange-500">{t('ModuleHealthGrid.counts.degraded', { count: mod.degraded })}</span>
                    <span className="text-red-500">{t('ModuleHealthGrid.counts.critical', { count: mod.critical })}</span>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

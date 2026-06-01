// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { useQuery } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { vpnApi } from '@/lib/api';
import type { VPNDashboard } from '@/lib/api/types';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Skeleton } from '@/components/ui/skeleton';
import {
  Shield,
  Wifi,
  AlertTriangle,
  Activity,
  ArrowDownRight,
  ArrowUpRight,
} from 'lucide-react';

function formatBytes(bytes: number): string {
  if (!bytes || bytes === 0) return '0 B';
  if (!Number.isFinite(bytes)) return '-- B';
  if (bytes < 0) return '-' + formatBytes(-bytes);
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.min(Math.floor(Math.log(bytes) / Math.log(k)), sizes.length - 1);
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
}

function healthColor(pct: number): string {
  if (pct >= 90) return 'text-green-600 dark:text-green-400';
  if (pct >= 70) return 'text-amber-600 dark:text-amber-400';
  return 'text-red-600 dark:text-red-400';
}

function LoadingSkeleton() {
  return (
    <Card>
      <CardHeader className="pb-3">
        <div className="flex items-center gap-2">
          <Skeleton className="h-5 w-5 rounded" />
          <Skeleton className="h-5 w-24" />
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          {Array.from({ length: 4 }).map((_, i) => (
            <div key={i} className="space-y-1.5">
              <Skeleton className="h-3 w-16" />
              <Skeleton className="h-6 w-12" />
            </div>
          ))}
        </div>
        <div className="grid grid-cols-2 gap-3">
          <Skeleton className="h-10 rounded-md" />
          <Skeleton className="h-10 rounded-md" />
        </div>
        <Skeleton className="h-4 w-32" />
      </CardContent>
    </Card>
  );
}

export default function VPNDashboardWidget() {
  const { t } = useTranslation('common');
  const {
    data: dashboard,
    isLoading,
    isError,
    error,
  } = useQuery<VPNDashboard>({
    queryKey: ['vpn', 'dashboard'],
    queryFn: () => vpnApi.getDashboard().then((r) => r.data),
    refetchInterval: 30_000,
    refetchIntervalInBackground: false,
  });

  if (isLoading) {
    return <LoadingSkeleton />;
  }

  if (isError) {
    return (
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-base">
            <Shield className="h-4 w-4 text-muted-foreground" />
            {t('VPNDashboardWidget.title')}
          </CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-destructive">
            {t('VPNDashboardWidget.error.failedToLoad')}
            {error instanceof Error ? `: ${error.message}` : '.'}
          </p>
        </CardContent>
      </Card>
    );
  }

  if (!dashboard) {
    return (
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-base">
            <Shield className="h-4 w-4 text-muted-foreground" />
            {t('VPNDashboardWidget.title')}
          </CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-muted-foreground">
            {t('VPNDashboardWidget.empty.noData')}
          </p>
        </CardContent>
      </Card>
    );
  }

  const {
    active_connections,
    healthy_pct,
    avg_latency_ms,
    total_rx_bytes,
    total_tx_bytes,
    active_tunnels,
    vpn_alerts,
    sites_with_vpn,
    sites_healthy,
  } = dashboard;

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2 text-base">
          <Shield className="h-4 w-4 text-primary" />
          {t('VPNDashboardWidget.title')}
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Top stats row */}
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          {/* Active Connections */}
          <div className="space-y-1">
            <p className="text-xs text-muted-foreground flex items-center gap-1">
              <Wifi className="h-3 w-3" />
              {t('VPNDashboardWidget.stats.connections')}
            </p>
            <p className="text-lg font-semibold text-green-600 dark:text-green-400">
              {active_connections}
            </p>
          </div>

          {/* Healthy % */}
          <div className="space-y-1">
            <p className="text-xs text-muted-foreground flex items-center gap-1">
              <Activity className="h-3 w-3" />
              {t('VPNDashboardWidget.stats.healthy')}
            </p>
            <p className={`text-lg font-semibold ${healthColor(healthy_pct ?? 0)}`}>
              {(healthy_pct ?? 0).toFixed(0)}%
            </p>
          </div>

          {/* Avg Latency */}
          <div className="space-y-1">
            <p className="text-xs text-muted-foreground">{t('VPNDashboardWidget.stats.avgLatency')}</p>
            <p className="text-lg font-semibold">
              {avg_latency_ms !== null ? `${avg_latency_ms.toFixed(0)} ms` : '--'}
            </p>
          </div>

          {/* Active Tunnels */}
          <div className="space-y-1">
            <p className="text-xs text-muted-foreground">{t('VPNDashboardWidget.stats.tunnels')}</p>
            <p className="text-lg font-semibold">{active_tunnels}</p>
          </div>
        </div>

        {/* Bandwidth row */}
        <div className="grid grid-cols-2 gap-3">
          <div className="flex items-center gap-2 rounded-md bg-muted/50 px-3 py-2">
            <ArrowDownRight className="h-4 w-4 text-blue-500" />
            <div>
              <p className="text-[10px] uppercase tracking-wider text-muted-foreground">
                {t('VPNDashboardWidget.bandwidth.rx')}
              </p>
              <p className="text-sm font-medium">{formatBytes(total_rx_bytes)}</p>
            </div>
          </div>
          <div className="flex items-center gap-2 rounded-md bg-muted/50 px-3 py-2">
            <ArrowUpRight className="h-4 w-4 text-violet-500" />
            <div>
              <p className="text-[10px] uppercase tracking-wider text-muted-foreground">
                {t('VPNDashboardWidget.bandwidth.tx')}
              </p>
              <p className="text-sm font-medium">{formatBytes(total_tx_bytes)}</p>
            </div>
          </div>
        </div>

        {/* Bottom row: alerts + sites */}
        <div className="flex items-center justify-between text-sm">
          <div className="flex items-center gap-1.5">
            <AlertTriangle className="h-3.5 w-3.5 text-muted-foreground" />
            <span className="text-muted-foreground">{t('VPNDashboardWidget.alerts')}</span>
            {vpn_alerts > 0 ? (
              <Badge variant="warning">{vpn_alerts}</Badge>
            ) : (
              <Badge variant="success">0</Badge>
            )}
          </div>
          <div className="text-muted-foreground">
            {t('VPNDashboardWidget.sites.prefix')}{' '}
            <span className="font-medium text-foreground">
              {sites_healthy}/{sites_with_vpn}
            </span>{' '}
            {t('VPNDashboardWidget.sites.suffix')}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

export { VPNDashboardWidget };

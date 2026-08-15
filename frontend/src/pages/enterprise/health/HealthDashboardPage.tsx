// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN Enterprise · Health Dashboard
 *
 * Enterprise-grade health monitoring with 5 tabs:
 * Overview, Devices, Alerts & SLA, Infrastructure, Score Info
 */

import { useParams, useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useToast } from '@/hooks/use-toast';
import { useSiteStore } from '@/stores/siteStore';
import {
  Activity,
  Heart,
  AlertTriangle,
  AlertOctagon,
  CheckCircle2,
  GitCompareArrows,
  Clock,
  Cpu,
  Download,
  Signal,
} from 'lucide-react';
import { PageHeader } from '@/components/layout';
import { StatsGrid } from '@/components/ui/stats-grid';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Skeleton } from '@/components/ui/skeleton';
import { enterpriseApi, type SiteHealthSummary } from '@/lib/api';
import {
  HealthGauge,
  HealthStatusBadge,
  ScoreBar,
  HealthTrendChart,
  TopIssuesPanel,
  DeviceHealthTable,
  ActiveAlertsPanel,
  SLAComplianceCard,
  InfrastructureHealthPanel,
  ModuleHealthGrid,
  WANHealthPanel,
  SiteRankingTable,
} from './components';

// ─── Site Card ───────────────────────────────────────────────────────────────

function SiteCard({ site }: { site: SiteHealthSummary }) {
  const { t } = useTranslation('enterprise');
  return (
    <Card className="hover:border-primary/30 transition-colors">
      <CardContent noOffset className="p-5">
        <div className="flex items-start justify-between mb-4">
          <div>
            <h3 className="font-semibold text-foreground">{site.site_name}</h3>
            <p className="text-sm text-muted-foreground">
              {t('HealthDashboardPage.siteCard.deviceCount', { count: site.device_count })}
            </p>
            {site.uptime_percent != null && (
              <p className={`text-xs ${
                site.uptime_percent >= 99.5
                  ? 'text-green-600 dark:text-green-400'
                  : site.uptime_percent >= 99
                    ? 'text-amber-600 dark:text-amber-400'
                    : 'text-red-600 dark:text-red-400'
              }`}>
                &#8593; {t('HealthDashboardPage.siteCard.uptime', { percent: site.uptime_percent.toFixed(1) })}
              </p>
            )}
          </div>
          <HealthGauge score={Math.round(site.avg_health_score)} size="sm" />
        </div>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
          <div className="text-center">
            <div className="text-lg font-semibold text-green-500">{site.healthy}</div>
            <div className="text-[10px] text-muted-foreground">{t('HealthDashboardPage.status.healthy')}</div>
          </div>
          <div className="text-center">
            <div className="text-lg font-semibold text-amber-500">{site.warning}</div>
            <div className="text-[10px] text-muted-foreground">{t('HealthDashboardPage.status.warning')}</div>
          </div>
          <div className="text-center">
            <div className="text-lg font-semibold text-orange-500">{site.degraded}</div>
            <div className="text-[10px] text-muted-foreground">{t('HealthDashboardPage.status.degraded')}</div>
          </div>
          <div className="text-center">
            <div className="text-lg font-semibold text-red-500">{site.critical}</div>
            <div className="text-[10px] text-muted-foreground">{t('HealthDashboardPage.status.critical')}</div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

// ─── Main Page ───────────────────────────────────────────────────────────────

const HEALTH_TABS = ['overview', 'devices', 'alerts', 'infrastructure', 'scores'] as const;

export default function HealthDashboardPage() {
  const { t } = useTranslation('enterprise');
  const navigate = useNavigate();
  const { tab: urlTab } = useParams<{ tab?: string }>();
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const activeTab = HEALTH_TABS.includes(urlTab as any) ? urlTab! : 'overview';
  const setActiveTab = (v: string) =>
    navigate(v === 'overview' ? '/health' : `/health/${v}`, { replace: true });
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const selectedSiteId = useSiteStore((s) => s.selectedSiteId);

  const { data: orgHealth, isLoading, isError } = useQuery({
    queryKey: ['enterprise', 'health', 'org', selectedSiteId],
    queryFn: () =>
      enterpriseApi
        .getOrgHealth(selectedSiteId ? { site_id: selectedSiteId } : undefined)
        .then((r) => r.data),
    refetchInterval: 60000,
  });

  const reconcileMutation = useMutation({
    // scope_id is optional for ``scope=organization`` (backend ignores it
    // and falls back to caller's org). Required for site/device.
    mutationFn: (data: { scope: string; scope_id?: string }) =>
      enterpriseApi.triggerReconcile(data),
    onSuccess: (resp) => {
      // Org gauge keys on ['enterprise','health',...]; the 11 sub-panels key on
      // ['health',...]. Invalidate BOTH so Reconcile All refreshes everything.
      queryClient.invalidateQueries({ queryKey: ['enterprise', 'health'] });
      queryClient.invalidateQueries({ queryKey: ['health'] });
      const total = resp?.data?.total ?? 0;
      toast({
        title: t('HealthDashboardPage.toast.reconcileDispatched.title'),
        description: t('HealthDashboardPage.toast.reconcileDispatched.description', { count: total }),
      });
    },
    onError: (err) => {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const detail = (err as any)?.response?.data?.detail
        || (err instanceof Error ? err.message : t('HealthDashboardPage.toast.unknownError'));
      toast({
        variant: 'destructive',
        title: t('HealthDashboardPage.toast.reconcileFailed.title'),
        description: String(detail),
      });
    },
  });

  const score = orgHealth ? Math.round(orgHealth.avg_health_score) : 0;
  const totalDevices = orgHealth?.device_count ?? 0;
  const totalSites = orgHealth?.site_count ?? 0;

  const healthyCounts = orgHealth?.sites.reduce(
    (acc, s) => ({
      healthy: acc.healthy + s.healthy,
      warning: acc.warning + s.warning,
      degraded: acc.degraded + s.degraded,
      critical: acc.critical + s.critical,
    }),
    { healthy: 0, warning: 0, degraded: 0, critical: 0 },
  ) ?? { healthy: 0, warning: 0, degraded: 0, critical: 0 };

  const stats = [
    {
      title: t('HealthDashboardPage.stats.overallScore'),
      value: isLoading ? '-' : score,
      icon: Heart,
      variant: (score >= 90 ? 'success' : score >= 70 ? 'warning' : 'destructive') as 'success' | 'warning' | 'destructive',
    },
    { title: t('HealthDashboardPage.stats.healthyDevices'), value: healthyCounts.healthy, icon: CheckCircle2, variant: 'success' as const },
    { title: t('HealthDashboardPage.stats.warnings'), value: healthyCounts.warning + healthyCounts.degraded, icon: AlertTriangle, variant: 'warning' as const },
    { title: t('HealthDashboardPage.stats.critical'), value: healthyCounts.critical, icon: AlertOctagon, variant: 'destructive' as const },
  ];

  return (
    <div className="space-y-6">
      <PageHeader
        icon={Activity}
        title={t('HealthDashboardPage.title')}
        description={selectedSiteId
          ? t('HealthDashboardPage.description.site', { devices: totalDevices })
          : t('HealthDashboardPage.description.org', { sites: totalSites, devices: totalDevices })
        }
        onRefresh={() => {
          // Org gauge keys on ['enterprise','health',...]; the 11 sub-panels key
          // on ['health',...]. Invalidate BOTH so Refresh updates everything.
          queryClient.invalidateQueries({ queryKey: ['enterprise', 'health'] });
          queryClient.invalidateQueries({ queryKey: ['health'] });
        }}
      />

      {isError && (
        <div className="rounded-md bg-destructive/10 p-3 text-sm text-destructive">
          {t('HealthDashboardPage.error.loadFailed')}
        </div>
      )}

      <StatsGrid stats={stats} isLoading={isLoading} />

      {/* Org-level gauge + summary */}
      {!isLoading && orgHealth && (
        <Card>
          <CardContent noOffset className="flex flex-col md:flex-row items-center gap-8">
            <HealthGauge score={score} size="lg" />
            <div className="flex-1 space-y-3">
              <div className="flex items-center gap-2">
                <h2 className="text-xl font-semibold">{t('HealthDashboardPage.orgHealth.heading')}</h2>
                <HealthStatusBadge status={orgHealth.health_status} />
              </div>
              <p className="text-sm text-muted-foreground">
                {t('HealthDashboardPage.orgHealth.summary', { sites: totalSites, devices: totalDevices })}
              </p>
              <div className="flex gap-2">
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() =>
                    reconcileMutation.mutate({
                      scope: 'organization',
                      scope_id: orgHealth.organization_id,
                    })
                  }
                  disabled={reconcileMutation.isPending}
                >
                  <GitCompareArrows className="h-4 w-4 mr-2" />
                  {t('HealthDashboardPage.actions.reconcileAll')}
                </Button>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* ─── 5-Tab Layout ──────────────────────────────────────────────────── */}
      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          <TabsTrigger value="overview">{t('HealthDashboardPage.tabs.overview')}</TabsTrigger>
          <TabsTrigger value="devices">{t('HealthDashboardPage.tabs.devices')}</TabsTrigger>
          <TabsTrigger value="alerts">{t('HealthDashboardPage.tabs.alerts')}</TabsTrigger>
          <TabsTrigger value="infrastructure">{t('HealthDashboardPage.tabs.infrastructure')}</TabsTrigger>
          <TabsTrigger value="scores">{t('HealthDashboardPage.tabs.scores')}</TabsTrigger>
        </TabsList>

        {/* ── Tab 1: Overview ──────────────────────────────────────────────── */}
        <TabsContent value="overview" className="mt-4 space-y-6">
          {/* Health trend chart */}
          {orgHealth?.sites && orgHealth.sites.length > 0 && (
            <HealthTrendChart siteId={selectedSiteId ?? undefined} />
          )}

          {/* Two-column: top issues + site grid */}
          <div className="grid gap-6 lg:grid-cols-3">
            <div className="lg:col-span-1">
              <TopIssuesPanel siteId={selectedSiteId ?? undefined} />
            </div>
            <div className="lg:col-span-2">
              {isLoading ? (
                <div className="grid gap-4 md:grid-cols-2">
                  {Array.from({ length: 4 }).map((_, i) => (
                    <Card key={i}>
                      <CardContent noOffset className="p-5">
                        <Skeleton className="h-32" />
                      </CardContent>
                    </Card>
                  ))}
                </div>
              ) : orgHealth?.sites.length ? (
                <div className="grid gap-4 md:grid-cols-2">
                  {orgHealth.sites
                    .sort((a, b) => a.avg_health_score - b.avg_health_score)
                    .map((site) => (
                      <SiteCard key={site.site_id} site={site} />
                    ))}
                </div>
              ) : (
                <Card>
                  <CardContent noOffset className="p-8 text-center text-muted-foreground">
                    <Activity className="h-12 w-12 mx-auto mb-4 opacity-30" />
                    <p>{t('HealthDashboardPage.empty.noData')}</p>
                  </CardContent>
                </Card>
              )}
            </div>
          </div>

          {/* Site ranking table */}
          <SiteRankingTable siteId={selectedSiteId ?? undefined} />
        </TabsContent>

        {/* ── Tab 2: Devices ───────────────────────────────────────────────── */}
        <TabsContent value="devices" className="mt-4">
          <DeviceHealthTable siteId={selectedSiteId ?? undefined} />
        </TabsContent>

        {/* ── Tab 3: Alerts & SLA ──────────────────────────────────────────── */}
        <TabsContent value="alerts" className="mt-4">
          <div className="grid gap-6 lg:grid-cols-2">
            <ActiveAlertsPanel siteId={selectedSiteId ?? undefined} />
            <SLAComplianceCard siteId={selectedSiteId ?? undefined} />
          </div>
        </TabsContent>

        {/* ── Tab 4: Infrastructure ────────────────────────────────────────── */}
        <TabsContent value="infrastructure" className="mt-4 space-y-6">
          <InfrastructureHealthPanel />
          <WANHealthPanel siteId={selectedSiteId ?? undefined} />
          <ModuleHealthGrid siteId={selectedSiteId ?? undefined} />
        </TabsContent>

        {/* ── Tab 5: Score Info ────────────────────────────────────────────── */}
        <TabsContent value="scores" className="mt-4">
          <Card>
            <CardHeader>
              <CardTitle>{t('HealthDashboardPage.scoreInfo.title')}</CardTitle>
              <CardDescription>
                {t('HealthDashboardPage.scoreInfo.description')}
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="grid gap-6 md:grid-cols-2">
                <div className="space-y-4">
                  <h4 className="text-sm font-medium text-foreground">
                    {t('HealthDashboardPage.scoreInfo.weightsHeading')}
                  </h4>
                  {/* Honesty pass: only reachability +
                      config-drift are computed today; latency / utilization /
                      error-rate / firmware are wired in the score formula but
                      sourced from stubs in tasks/reconciliation.py. Marking
                      them "(preview)" so operators don't read a false
                      promise off the dashboard. */}
                  <ScoreBar label={t('HealthDashboardPage.scoreInfo.weights.reachability')} score={30} icon={Signal} />
                  <ScoreBar label={t('HealthDashboardPage.scoreInfo.weights.configDrift')} score={20} icon={GitCompareArrows} />
                  <ScoreBar label={t('HealthDashboardPage.scoreInfo.weights.latency')} score={15} icon={Clock} />
                  <ScoreBar label={t('HealthDashboardPage.scoreInfo.weights.errorRate')} score={15} icon={AlertTriangle} />
                  <ScoreBar label={t('HealthDashboardPage.scoreInfo.weights.utilization')} score={10} icon={Cpu} />
                  <ScoreBar label={t('HealthDashboardPage.scoreInfo.weights.firmware')} score={10} icon={Download} />
                  <p className="text-xs text-muted-foreground pt-2">
                    {t('HealthDashboardPage.scoreInfo.previewNote')}
                  </p>
                </div>
                <div className="space-y-4">
                  <h4 className="text-sm font-medium text-foreground">
                    {t('HealthDashboardPage.scoreInfo.thresholdsHeading')}
                  </h4>
                  <div className="space-y-3">
                    <div className="flex items-center gap-3">
                      <div className="w-3 h-3 rounded-full bg-green-500" />
                      <span className="text-sm">{t('HealthDashboardPage.scoreInfo.thresholds.healthy')}</span>
                    </div>
                    <div className="flex items-center gap-3">
                      <div className="w-3 h-3 rounded-full bg-amber-500" />
                      <span className="text-sm">{t('HealthDashboardPage.scoreInfo.thresholds.warning')}</span>
                    </div>
                    <div className="flex items-center gap-3">
                      <div className="w-3 h-3 rounded-full bg-orange-500" />
                      <span className="text-sm">{t('HealthDashboardPage.scoreInfo.thresholds.degraded')}</span>
                    </div>
                    <div className="flex items-center gap-3">
                      <div className="w-3 h-3 rounded-full bg-red-500" />
                      <span className="text-sm">{t('HealthDashboardPage.scoreInfo.thresholds.critical')}</span>
                    </div>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN - Enterprise Dashboard Page
 *
 * Comprehensive overview with widgets, metrics, and real-time updates.
 * All data is fetched from backend APIs; no hardcoded sample data.
 */

import { useCallback, useEffect, useMemo } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import type { TFunction } from 'i18next';
import {
  DndContext,
  KeyboardSensor,
  PointerSensor,
  closestCenter,
  useSensor,
  useSensors,
  type DragEndEvent,
} from '@dnd-kit/core';
import {
  SortableContext,
  rectSortingStrategy,
  sortableKeyboardCoordinates,
} from '@dnd-kit/sortable';
import {
  MapPin,
  Server,
  Wifi,
  Camera,
  BarChart3,
  LayoutDashboard,
  ArrowRight,
  AlertTriangle,
  Plus,
  RotateCcw,
  Settings2,
  Check,
} from 'lucide-react';
import {
  analyticsApi,
  systemApi,
  camerasApi,
  controllersApi,
  type DashboardSummary,
  type EnterpriseAnalytics,
  type AnalyticsAlert,
  type HealthCheck,
} from '@/lib/api';
import { sitesApiV2 } from '@/lib/api/sites';
import type { Site } from '@/lib/api/types';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Skeleton } from '@/components/ui/skeleton';
import { Button } from '@/components/ui/button';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { PageHeader } from '@/components/layout';
import { cn } from '@/lib/utils';
import { useSiteStore } from '@/stores/siteStore';
import { useDashboardLayoutStore } from '@/stores/dashboardLayoutStore';
import {
  DASHBOARD_WIDGETS,
  DASHBOARD_DEFAULT_ENABLED,
  groupWidgetsByCategory,
} from './widgets';
import { DashboardWidgetCard } from './DashboardWidgetCard';
import {
  TopCpuWidget,
  TopMemoryWidget,
  ManufacturerMixWidget,
  WifiBandsWidget,
  TopSsidsWidget,
  PoeBudgetWidget,
  SecurityPostureWidget,
  AuditActivityWidget,
  IncidentOverviewWidget,
  PortStatusWidget,
  SiteHealthWidget,
} from './extra-widgets';
import { enterpriseApi } from '@/lib/api';
import {
  StatCard,
  GreetingCard,
  ActivityFeed,
  DeviceStatusWidget,
  NetworkHealthWidget,
  QuickActions,
  CameraPreviewWidget,
  AlertsWidget,
  SystemStatusWidget,
  UsageChart,
  type ActivityEvent,
  type Alert,
} from '@/components/dashboard';
import { useAuthStore } from '@/stores/authStore';
import { useToast } from '@/hooks/use-toast';

/**
 * Map AnalyticsAlert records from the API into the Alert shape
 * expected by the AlertsWidget component.
 */
function mapAnalyticsAlerts(apiAlerts: AnalyticsAlert[]): Alert[] {
  return apiAlerts.map((a) => ({
    id: a.id,
    severity: (['critical', 'warning', 'info', 'success'].includes(a.severity)
      ? a.severity
      : 'info') as Alert['severity'],
    title: a.title,
    message: a.message ?? '',
    timestamp: a.triggered_at,
    source: a.alert_type,
    acknowledged: a.status === 'acknowledged' || a.status === 'resolved',
  }));
}

/**
 * Map the `recent_alerts` array returned by DashboardSummary into
 * ActivityEvent records for the activity feed widget.
 */
function mapRecentAlertsToEvents(
  recentAlerts: DashboardSummary['recent_alerts'],
  t: TFunction,
): ActivityEvent[] {
  return recentAlerts.map((a, idx) => ({
    id: a.id ?? String(idx),
    type: 'alert' as const,
    title: a.title,
    description: t('DashboardPage.activity.severityStatus', {
      severity: a.severity,
      status: a.status,
    }),
    timestamp: a.triggered_at,
    severity: (['warning', 'error', 'info', 'success'].includes(a.severity)
      ? a.severity
      : 'info') as ActivityEvent['severity'],
  }));
}

/**
 * Derive service rows for SystemStatusWidget from the HealthCheck response.
 */
function buildServicesFromHealth(health: HealthCheck, t: TFunction) {
  const mapStatus = (s: string): 'healthy' | 'degraded' | 'down' => {
    if (s === 'ok' || s === 'healthy' || s === 'connected') return 'healthy';
    if (s === 'degraded') return 'degraded';
    return 'down';
  };

  // Backend returns ``components.{database,redis,celery}.status``;
  // the legacy code read ``checks.{...}: string`` which always
  // resolved to ``undefined`` → mapStatus("unknown") → "down".
  // Read ``components`` first; fall back to the legacy field only
  // for backward compat with older API versions.
  const dbStatus =
    health.components?.database?.status
    ?? health.checks?.database
    ?? 'unknown';
  const redisStatus =
    health.components?.redis?.status
    ?? health.checks?.redis
    ?? 'unknown';

  return [
    {
      id: 'api',
      name: t('DashboardPage.services.apiServer'),
      status: mapStatus(health.status),
    },
    {
      id: 'database',
      name: t('DashboardPage.services.database'),
      status: mapStatus(dbStatus),
    },
    {
      id: 'redis',
      name: t('DashboardPage.services.redisCache'),
      status: mapStatus(redisStatus),
    },
  ];
}

export default function DashboardPage() {
  const { t } = useTranslation('dashboard');
  const { t: tCommon } = useTranslation('common');
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const selectedSiteId = useSiteStore((s) => s.selectedSiteId);
  const currentSite = useSiteStore((s) => s.getCurrentSite());
  const isGlobal = selectedSiteId === null;
  const user = useAuthStore((s) => s.user);

  // ── Primary dashboard summary (stats cards, recent alerts) ───────
  const {
    data: summary,
    isLoading: summaryLoading,
    isError: summaryError,
    refetch,
  } = useQuery({
    queryKey: ['dashboard-summary', { siteId: selectedSiteId }],
    queryFn: async () => {
      const res = await analyticsApi.getDashboardSummary(selectedSiteId ?? undefined);
      return res.data;
    },
    refetchInterval: 30000,
  });

  // ── Enterprise analytics (fleet, traffic, network health) ────────
  const { data: analytics, isLoading: analyticsLoading, isError: analyticsError } = useQuery({
    queryKey: ['dashboard-enterprise-analytics', { siteId: selectedSiteId }],
    queryFn: async () => {
      const res = await analyticsApi.getEnterpriseAnalytics(24, selectedSiteId ?? undefined);
      return res.data;
    },
    refetchInterval: 60000,
  });

  // ── Active alerts ────────────────────────────────────────────────
  const { data: alertsData, isLoading: alertsLoading, isError: alertsError } = useQuery({
    queryKey: ['dashboard-alerts', { siteId: selectedSiteId }],
    queryFn: async () => {
      const res = await analyticsApi.getAlerts({
        status: 'active',
        limit: 10,
        site_id: selectedSiteId ?? undefined,
      });
      return res.data;
    },
    refetchInterval: 30000,
  });

  // ── System health & info ─────────────────────────────────────────
  const { data: healthData, isError: healthError } = useQuery({
    queryKey: ['system-health'],
    queryFn: async () => {
      const res = await systemApi.getHealth();
      return res.data;
    },
    refetchInterval: 60000,
  });

  const { data: sysInfo, isError: sysInfoError } = useQuery({
    queryKey: ['system-info'],
    queryFn: async () => {
      const res = await systemApi.getInfo();
      return res.data;
    },
    staleTime: 5 * 60000,
  });

  // ── Camera list ──────────────────────────────────────────────────
  const { data: camerasData, isError: camerasError } = useQuery({
    queryKey: ['dashboard-cameras', { siteId: selectedSiteId }],
    queryFn: async () => {
      const res = await camerasApi.getAll({ limit: 4, site_id: selectedSiteId ?? undefined });
      return res.data;
    },
    refetchInterval: 60000,
  });

  // ── Sites list (for global view site health grid) ────────────────
  const { data: allSitesData, isError: sitesError } = useQuery({
    queryKey: ['dashboard-all-sites'],
    queryFn: async () => {
      const res = await sitesApiV2.list({ per_page: 50 });
      return res.data;
    },
    enabled: isGlobal,
    staleTime: 30_000,
    refetchInterval: 60_000,
  });
  const allSites: Site[] = allSitesData?.items ?? [];

  // ── Org health summary (powers Site Health Map widget) ──────────
  const { data: orgHealth, isError: orgHealthError } = useQuery({
    queryKey: ['dashboard-org-health', { siteId: selectedSiteId }],
    queryFn: async () => {
      const res = await enterpriseApi.getOrgHealth(
        selectedSiteId ? { site_id: selectedSiteId } : undefined,
      );
      return res.data;
    },
    refetchInterval: 60_000,
    staleTime: 30_000,
  });

  // ── Derived values ───────────────────────────────────────────────
  const hasQueryError = summaryError || analyticsError || alertsError || healthError || sysInfoError || camerasError || sitesError || orgHealthError;
  const isLoading = summaryLoading;

  // Activity events from recent alerts in summary (memoized, array identity
  // matters for the widgetMap useMemo deps below)
  const events: ActivityEvent[] = useMemo(
    () => (summary?.recent_alerts ? mapRecentAlertsToEvents(summary.recent_alerts, t) : []),
    [summary?.recent_alerts, t],
  );

  // Alerts mapped from API
  const alerts: Alert[] = useMemo(
    () => (alertsData ? mapAnalyticsAlerts(Array.isArray(alertsData) ? alertsData : []) : []),
    [alertsData],
  );

  // Traffic chart data derived from enterprise analytics
  const trafficData = useMemo(() => buildTrafficChartData(analytics, t), [analytics, t]);
  const trafficSeries = useMemo(
    () => [
      { key: 'download', label: t('DashboardPage.traffic.downloadMbps'), color: '#10b981' },
      { key: 'upload', label: t('DashboardPage.traffic.uploadMbps'), color: '#3b82f6' },
    ],
    [t],
  );

  // System services from health check
  const services = useMemo(
    () => (healthData ? buildServicesFromHealth(healthData, t) : []),
    [healthData, t],
  );

  // Camera previews from API
  const cameras = useMemo(() => buildCameraList(camerasData, t), [camerasData, t]);

  // Network health from enterprise analytics
  const networkHealth = useMemo(() => buildNetworkHealth(analytics, t), [analytics, t]);

  // System resources from enterprise analytics
  const resources = useMemo(
    () => (analytics
      ? {
          cpu: Math.round(analytics.fleet?.avg_cpu ?? 0),
          memory: Math.round(analytics.fleet?.avg_memory ?? 0),
          disk: 0, // Disk usage is not available in the analytics API
        }
      : undefined),
    [analytics],
  );

  // ─── Customisable widget layout ─────────────────────────────────────
  const enabledWidgets = useDashboardLayoutStore((s) => s.enabledWidgets);
  const isCustomizing = useDashboardLayoutStore((s) => s.isCustomizing);
  const setEnabledWidgets = useDashboardLayoutStore((s) => s.setEnabledWidgets);
  const addWidget = useDashboardLayoutStore((s) => s.addWidget);
  const removeWidget = useDashboardLayoutStore((s) => s.removeWidget);
  const reorderWidgets = useDashboardLayoutStore((s) => s.reorderWidgets);
  const resetLayout = useDashboardLayoutStore((s) => s.resetLayout);
  const toggleCustomizing = useDashboardLayoutStore((s) => s.toggleCustomizing);

  // dnd-kit sensors · pointer (mouse/touch) + keyboard for a11y
  const sensors = useSensors(
    useSensor(PointerSensor, { activationConstraint: { distance: 6 } }),
    useSensor(KeyboardSensor, { coordinateGetter: sortableKeyboardCoordinates }),
  );

  const handleDragEnd = (event: DragEndEvent) => {
    const { active, over } = event;
    if (!over || active.id === over.id) return;
    reorderWidgets(String(active.id), String(over.id));
  };

  // ── Quick Actions · "Sync All" ──────────────────────────────────
  // Fans the existing per-controller sync endpoint over every controller
  // already loaded in the analytics payload. Mirrors the proven
  // CommandPalette "Sync All Controllers" flow (same i18n keys).
  const handleSyncAll = useCallback(async () => {
    const controllers = (analytics?.controllers ?? []).filter((c) => Boolean(c?.id));

    if (controllers.length === 0) {
      toast({
        title: tCommon('CommandPalette.sync.none.title'),
        description: tCommon('CommandPalette.sync.none.description'),
      });
      navigate('/controllers');
      return;
    }

    const results = await Promise.allSettled(
      controllers.map((c) => controllersApi.sync(c.id)),
    );
    const succeeded = results.filter((r) => r.status === 'fulfilled').length;
    const failed = results.length - succeeded;

    if (failed === 0) {
      toast({
        title: tCommon('CommandPalette.sync.started.title'),
        description: tCommon('CommandPalette.sync.started.description', { count: succeeded }),
      });
    } else if (succeeded === 0) {
      toast({
        title: tCommon('CommandPalette.sync.failed.title'),
        description: tCommon('CommandPalette.sync.failed.description'),
        variant: 'destructive',
      });
    } else {
      toast({
        title: tCommon('CommandPalette.sync.partial.title'),
        description: tCommon('CommandPalette.sync.partial.description', { succeeded, failed }),
        variant: 'destructive',
      });
    }

    // Refresh the dashboard so freshly-synced counts surface.
    queryClient.invalidateQueries({ queryKey: ['dashboard-summary'] });
    queryClient.invalidateQueries({ queryKey: ['dashboard-enterprise-analytics'] });
  }, [analytics?.controllers, navigate, queryClient, toast, tCommon]);

  // Seed defaults the first time the user lands on the dashboard
  useEffect(() => {
    if (enabledWidgets.length === 0) {
      setEnabledWidgets(DASHBOARD_DEFAULT_ENABLED);
    }
  }, [enabledWidgets.length, setEnabledWidgets]);

  // Widget id → render fn (data binding lives in this scope)
  // Each entry is invoked from the registry-driven map below.
  const widgetRenderers: Record<string, () => React.ReactNode> = useMemo(() => ({
    'traffic': () =>
      analyticsLoading ? (
        <Skeleton className="h-[280px] w-full rounded-lg" />
      ) : trafficData.length > 0 ? (
        <UsageChart data={trafficData} series={trafficSeries} height={280} />
      ) : (
        <div className="flex flex-col items-center justify-center h-[280px] text-muted-foreground">
          <BarChart3 className="h-12 w-12 opacity-30" />
          <p className="mt-4 text-sm">{t('DashboardPage.traffic.noData')}</p>
        </div>
      ),
    'device-status': () =>
      isLoading ? (
        <Skeleton className="h-[120px] w-full rounded-lg" />
      ) : (
        <DeviceStatusWidget
          data={{
            online: summary?.devices_online ?? 0,
            offline: summary?.devices_offline ?? 0,
            warning: summary?.devices_warning ?? 0,
            unknown: 0,
          }}
        />
      ),
    'network-health': () =>
      analyticsLoading ? (
        <Skeleton className="h-[200px] w-full rounded-lg" />
      ) : (
        <NetworkHealthWidget
          latency={networkHealth.latency}
          throughput={networkHealth.throughput}
          packetLoss={networkHealth.packetLoss}
          uptime={networkHealth.uptime}
        />
      ),
    'camera-preview': () => (
      <CameraPreviewWidget
        cameras={cameras}
        onViewCamera={(id) => navigate(`/cameras/${id}`)}
        onViewAll={() => navigate('/cameras')}
      />
    ),
    'quick-actions': () => (
      <QuickActions
        onAddDevice={() => navigate('/devices/new')}
        onDiscovery={() => navigate('/discovery')}
        onSync={handleSyncAll}
        onBackup={() => navigate('/backups')}
      />
    ),
    'alerts': () =>
      alertsLoading ? (
        <Skeleton className="h-[120px] w-full rounded-lg" />
      ) : (
        <AlertsWidget alerts={alerts} onViewAll={() => navigate('/alerts')} />
      ),
    'activity': () =>
      summaryLoading ? (
        <Skeleton className="h-[200px] w-full rounded-lg" />
      ) : (
        <ActivityFeed events={events} maxHeight={320} />
      ),
    'system-status': () =>
      !healthData ? (
        <Skeleton className="h-[200px] w-full rounded-lg" />
      ) : (
        <SystemStatusWidget services={services} resources={resources} version={sysInfo?.app_version} />
      ),
    // ── New rich widgets driven off the existing analytics payload ────
    'top-cpu': () => <TopCpuWidget analytics={analytics} />,
    'top-memory': () => <TopMemoryWidget analytics={analytics} />,
    'manufacturer-mix': () => <ManufacturerMixWidget analytics={analytics} />,
    'wifi-bands': () => <WifiBandsWidget analytics={analytics} />,
    'top-ssids': () => <TopSsidsWidget analytics={analytics} />,
    'poe-budget': () => <PoeBudgetWidget analytics={analytics} />,
    'security-posture': () => <SecurityPostureWidget analytics={analytics} />,
    'audit-activity': () => <AuditActivityWidget analytics={analytics} />,
    'incidents': () => <IncidentOverviewWidget analytics={analytics} />,
    'port-status': () => <PortStatusWidget analytics={analytics} />,
    'site-health': () => <SiteHealthWidget sites={orgHealth?.sites} />,
  }), [
    analyticsLoading, isLoading, alertsLoading, summaryLoading,
    trafficData, trafficSeries, summary, networkHealth, cameras,
    alerts, events, healthData, services, resources, sysInfo,
    analytics, orgHealth, navigate, t, handleSyncAll,
  ]);

  // User's `enabledWidgets` array IS the render order (post-dnd reorder).
  // Filter through the registry to drop any stale ids and pick up metadata.
  const visibleWidgets = enabledWidgets
    .map((id) => DASHBOARD_WIDGETS.find((w) => w.id === id))
    .filter((w): w is (typeof DASHBOARD_WIDGETS)[number] => Boolean(w));
  const hiddenWidgets = DASHBOARD_WIDGETS.filter(
    (w) => !enabledWidgets.includes(w.id),
  );
  const colSpanClass: Record<number, string> = {
    1: 'lg:col-span-1',
    2: 'lg:col-span-2 md:col-span-2',
    3: 'lg:col-span-3 md:col-span-2',
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <PageHeader
        icon={LayoutDashboard}
        title={t('DashboardPage.title')}
        subtitle={
          isGlobal
            ? t('DashboardPage.subtitle.global')
            : t('DashboardPage.subtitle.site', {
                site: currentSite?.name ?? t('DashboardPage.subtitle.defaultSite'),
                count: summary?.devices_online ?? 0,
              })
        }
        onRefresh={() => refetch()}
        refreshing={isLoading}
        actions={
          isCustomizing ? (
            <>
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={hiddenWidgets.length === 0}
                  >
                    <Plus className="h-4 w-4 mr-2" />
                    {t('DashboardPage.actions.addWidget')}
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end" className="w-80 max-h-[480px] overflow-y-auto">
                  {hiddenWidgets.length === 0 ? (
                    <div className="px-2 py-4 text-center text-xs text-muted-foreground">
                      {t('DashboardPage.customize.allWidgetsAdded')}
                    </div>
                  ) : (
                    Object.entries(groupWidgetsByCategory(hiddenWidgets)).map(([cat, items]) => {
                      if (items.length === 0) return null;
                      return (
                        <div key={cat}>
                          <DropdownMenuLabel className="text-[10px] uppercase tracking-wide text-muted-foreground">
                            {cat}
                          </DropdownMenuLabel>
                          {items.map((w) => {
                            const Icon = w.icon;
                            return (
                              <DropdownMenuItem
                                key={w.id}
                                onClick={() => addWidget(w.id)}
                                className="flex items-start gap-3 py-2.5"
                              >
                                <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-md bg-primary/10 text-primary">
                                  <Icon className="h-4 w-4" />
                                </div>
                                <div className="min-w-0 flex-1">
                                  <div className="text-sm font-medium">{w.label}</div>
                                  <div className="text-xs text-muted-foreground line-clamp-2">
                                    {w.description}
                                  </div>
                                </div>
                              </DropdownMenuItem>
                            );
                          })}
                          <DropdownMenuSeparator />
                        </div>
                      );
                    })
                  )}
                </DropdownMenuContent>
              </DropdownMenu>
              <Button
                variant="ghost"
                size="sm"
                onClick={() => resetLayout(DASHBOARD_DEFAULT_ENABLED)}
                title={t('DashboardPage.actions.resetTooltip')}
              >
                <RotateCcw className="h-4 w-4 mr-2" />
                {t('DashboardPage.actions.reset')}
              </Button>
              <Button
                variant="default"
                size="sm"
                onClick={toggleCustomizing}
              >
                <Check className="h-4 w-4 mr-2" />
                {t('DashboardPage.actions.done')}
              </Button>
            </>
          ) : (
            <Button
              variant="outline"
              size="sm"
              onClick={toggleCustomizing}
              title={t('DashboardPage.actions.customizeTooltip')}
            >
              <Settings2 className="h-4 w-4 mr-2" />
              {t('DashboardPage.actions.customize')}
            </Button>
          )
        }
      />

      {hasQueryError && (
        <Card className="border-destructive">
          <CardContent noOffset className="p-4 flex items-center gap-3">
            <AlertTriangle className="h-5 w-5 text-destructive" />
            <span className="text-sm">{t('DashboardPage.error.partialLoad')}</span>
          </CardContent>
        </Card>
      )}

      {/* Stats Grid · greeting card always first, then mode-specific stats.
            Site mode = 4 cards (Greeting + 3 stats), Global = 5 (Greeting + 4 stats). */}
      <div
        className={cn(
          'grid gap-4 sm:grid-cols-2 lg:grid-cols-4',
          isGlobal && 'xl:grid-cols-5',
        )}
      >
        {/* Greeting always visible · doesn't wait on data, gives the page identity */}
        <GreetingCard name={user?.first_name} />

        {isLoading ? (
          Array.from({ length: 4 }).map((_, i) => (
            <Skeleton key={i} className="h-32 rounded-xl" />
          ))
        ) : (
          <>
            {isGlobal && (
              <StatCard
                title={t('DashboardPage.stats.sites.title')}
                value={summary?.total_sites ?? 0}
                subtitle={t('DashboardPage.stats.sites.subtitle')}
                icon={MapPin}
                color="blue"
                onClick={() => navigate('/sites')}
              />
            )}
            <StatCard
              title={t('DashboardPage.stats.controllers.title')}
              value={analytics?.controllers?.length ?? 0}
              subtitle={t('DashboardPage.stats.controllers.subtitle')}
              icon={Server}
              color="purple"
              onClick={() => navigate('/controllers')}
            />
            <StatCard
              title={t('DashboardPage.stats.devices.title')}
              value={`${summary?.devices_online ?? 0}/${summary?.total_devices ?? 0}`}
              subtitle={t('DashboardPage.stats.devices.subtitle')}
              icon={Wifi}
              color="green"
              onClick={() => navigate('/devices')}
            />
            <StatCard
              title={t('DashboardPage.stats.cameras.title')}
              value={cameras.length}
              subtitle={t('DashboardPage.stats.cameras.subtitle', {
                count: cameras.filter((c) => c.status === 'recording').length,
              })}
              icon={Camera}
              color="cyan"
              onClick={() => navigate('/cameras')}
            />
          </>
        )}
      </div>

      {/* Global: Site Health Grid */}
      {isGlobal && allSites.length > 0 && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-base font-medium flex items-center gap-2">
              <MapPin className="h-4 w-4 text-muted-foreground" />
              {t('DashboardPage.siteHealth.title')}
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
              {allSites.map((site) => {
                const onlineRatio = site.device_count > 0 ? site.online_device_count / site.device_count : 0;
                const status =
                  site.device_count === 0
                    ? 'unknown'
                    : onlineRatio >= 1
                      ? 'healthy'
                      : onlineRatio >= 0.5
                        ? 'degraded'
                        : 'critical';
                const dotColor =
                  status === 'healthy'
                    ? 'bg-green-500'
                    : status === 'degraded'
                      ? 'bg-yellow-500'
                      : status === 'critical'
                        ? 'bg-red-500'
                        : 'bg-muted-foreground';

                return (
                  <button
                    key={site.id}
                    onClick={() => {
                      useSiteStore.getState().selectSite(site.id);
                    }}
                    className="text-left p-4 rounded-lg border border-border hover:border-primary/30 hover:bg-muted/30 transition-all group"
                  >
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center gap-2">
                        <span className={cn('w-2.5 h-2.5 rounded-full', dotColor)} />
                        <span className="text-sm font-semibold truncate">
                          {site.name}
                        </span>
                      </div>
                      <ArrowRight className="h-3.5 w-3.5 text-muted-foreground opacity-0 group-hover:opacity-100 transition-opacity" />
                    </div>
                    <div className="space-y-1 text-[12px] text-muted-foreground">
                      <div>
                        {t('DashboardPage.siteHealth.devicesOnline', {
                          online: site.online_device_count,
                          total: site.device_count,
                        })}
                      </div>
                      <div>
                        {site.controller_count === 1
                          ? t('DashboardPage.siteHealth.controllerCount', {
                              count: site.controller_count,
                            })
                          : t('DashboardPage.siteHealth.controllerCount_plural', {
                              count: site.controller_count,
                            })}
                      </div>
                    </div>
                  </button>
                );
              })}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Customisable widget grid · registry-driven, drag-and-drop in customize mode */}
      {visibleWidgets.length > 0 ? (
        <DndContext sensors={sensors} collisionDetection={closestCenter} onDragEnd={handleDragEnd}>
          <SortableContext
            items={visibleWidgets.map((w) => w.id)}
            strategy={rectSortingStrategy}
          >
            <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
              {visibleWidgets.map((w) => {
                const renderer = widgetRenderers[w.id];
                if (!renderer) return null;
                return (
                  <DashboardWidgetCard
                    key={w.id}
                    id={w.id}
                    title={w.label}
                    icon={w.icon}
                    colSpanClass={colSpanClass[w.colSpan]}
                    editing={isCustomizing}
                    onRemove={removeWidget}
                  >
                    {renderer()}
                  </DashboardWidgetCard>
                );
              })}
            </div>
          </SortableContext>
        </DndContext>
      ) : (
        <Card>
          <CardContent noOffset className="flex flex-col items-center justify-center py-16 text-center">
            <LayoutDashboard className="h-12 w-12 text-muted-foreground/40 mb-4" />
            <h3 className="text-lg font-semibold">{t('DashboardPage.empty.title')}</h3>
            <p className="text-sm text-muted-foreground mt-1 mb-6 max-w-sm">
              {t('DashboardPage.empty.description')}
            </p>
            <Button onClick={() => resetLayout(DASHBOARD_DEFAULT_ENABLED)}>
              <RotateCcw className="h-4 w-4 mr-2" />
              {t('DashboardPage.empty.restoreButton')}
            </Button>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

// ── Helper: build traffic chart data from enterprise analytics ──────

function buildTrafficChartData(
  analytics: EnterpriseAnalytics | undefined,
  t: TFunction,
): { timestamp: string; download: number; upload: number }[] {
  if (!analytics) return [];

  // The enterprise analytics provides aggregate TX/RX bytes.
  // Without per-hour data points we cannot render a time-series.
  // Return an empty array so the chart shows the "no data" state
  // rather than fabricated numbers.  When the analytics API starts
  // returning `data_points` in the future, this function can be
  // extended to map them.
  const totalTx = analytics.ports?.total_tx_bytes ?? 0;
  const totalRx = analytics.ports?.total_rx_bytes ?? 0;

  // If there is at least some data, show a single summary point so the
  // chart area is not entirely empty.
  if (totalTx === 0 && totalRx === 0) return [];

  // Show a single aggregated data point so the user sees real numbers.
  return [
    {
      timestamp: t('DashboardPage.traffic.last24h'),
      download: Math.round((totalRx / (1024 * 1024)) * 100) / 100,
      upload: Math.round((totalTx / (1024 * 1024)) * 100) / 100,
    },
  ];
}

// ── Helper: build network health from enterprise analytics ──────────

function buildNetworkHealth(analytics: EnterpriseAnalytics | undefined, t: TFunction) {
  if (!analytics) {
    return {
      latency: { value: 0, history: [] as number[] },
      throughput: { download: 0, upload: 0, history: [] as { download: number; upload: number }[] },
      packetLoss: { value: 0, history: [] as number[] },
      uptime: { value: 0, label: t('DashboardPage.networkHealth.notAvailable') },
    };
  }

  const txBytes = analytics.ports?.total_tx_bytes ?? 0;
  const rxBytes = analytics.ports?.total_rx_bytes ?? 0;
  const hours = analytics.hours || 24;

  // Convert aggregate bytes to average Mbps over the period
  const avgDownloadMbps = (rxBytes * 8) / (hours * 3600) / 1_000_000;
  const avgUploadMbps = (txBytes * 8) / (hours * 3600) / 1_000_000;

  // Health score as a proxy for uptime
  const healthScore = analytics.health_score ?? 0;

  return {
    latency: { value: 0, history: [] as number[] },
    throughput: {
      download: Math.round(avgDownloadMbps * 100) / 100,
      upload: Math.round(avgUploadMbps * 100) / 100,
      history: [] as { download: number; upload: number }[],
    },
    packetLoss: {
      value: analytics.ports?.total_errors
        ? Math.round(
            (analytics.ports.total_errors /
              Math.max(1, (analytics.ports.total_tx_bytes + analytics.ports.total_rx_bytes))) *
              10000,
          ) / 100
        : 0,
      history: [] as number[],
    },
    uptime: {
      value: healthScore,
      label: t('DashboardPage.networkHealth.windowLabel', { hours }),
    },
  };
}

// ── Helper: build camera preview list ───────────────────────────────

function buildCameraList(
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  camerasData: any,
  t: TFunction,
): { id: string; name: string; status: 'online' | 'offline' | 'recording' | 'error'; location?: string }[] {
  if (!camerasData) return [];

  // camerasApi.getAll may return { items: [...] } or a plain array
  const items = Array.isArray(camerasData)
    ? camerasData
    : Array.isArray(camerasData.items)
      ? camerasData.items
      : [];

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  return items.map((cam: any) => {
    let status: 'online' | 'offline' | 'recording' | 'error' = 'offline';
    const rawStatus = (cam.status ?? '').toLowerCase();
    if (rawStatus === 'recording') status = 'recording';
    else if (rawStatus === 'online' || rawStatus === 'connected') status = 'online';
    else if (rawStatus === 'error') status = 'error';

    return {
      id: cam.id,
      name: cam.name ?? cam.camera_name ?? t('DashboardPage.camera.unknown'),
      status,
      location: cam.location ?? cam.site_name,
    };
  });
}

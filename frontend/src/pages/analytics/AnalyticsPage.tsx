// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Enterprise Analytics Dashboard
 *
 * Real-time fleet, security, client and traffic insights powered by the
 * unified `/analytics/dashboard/enterprise` endpoint. Honours the global
 * site filter (useSiteStore) and a 1D / 1W / 1M time range.
 *
 * Tabs (URL-deep-linked via PageTabs at /analytics/:tab):
 *   overview  · fleet health, resource pressure, distribution, top devices
 *   insights  · security posture, audit trail, incidents
 *   wifi      · bands, signal quality, SSIDs, Wi-Fi health radar
 *   clients   · connectivity mix, signal, traffic
 *   traffic   · port utilisation, PoE, per-site breakdown
 */

import { useState, useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { useQuery } from '@tanstack/react-query';
import { useSiteStore } from '@/stores/siteStore';
import {
  BarChart3,
  Activity,
  Wifi,
  Users,
  AlertTriangle,
  TrendingUp,
  ArrowUpRight,
  ArrowDownRight,
  Globe,
  CheckCircle,
  Server,
  Zap,
  Signal,
  Shield,
  ShieldAlert,
  Eye,
  Lock,
  Thermometer,
  Cable,
  Cpu,
  MemoryStick,
} from 'lucide-react';
import {
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
  RadarChart,
  Radar,
  PolarGrid,
  PolarAngleAxis,
  PolarRadiusAxis,
} from 'recharts';
import { format } from 'date-fns';

import { PageHeader, PageTabs, type PageTab } from '@/components/layout';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { StatsGrid, type StatItem } from '@/components/ui/stats-grid';
import { EmptyState, ErrorState } from '@/components/ui/empty-state';
import { Skeleton } from '@/components/ui/skeleton';
import { DataTable, type DataTableColumn } from '@/components/ui/data-table';
import { cn } from '@/lib/utils';
import { analyticsApi, type EnterpriseAnalytics } from '@/lib/api';

// ─── Constants ───────────────────────────────────────────────────────────────

interface TimeRange {
  value: string;
  label: string;
  hours: number;
}

const TIME_RANGES: TimeRange[] = [
  { value: '1D', label: '24h', hours: 24 },
  { value: '1W', label: '7d', hours: 168 },
  { value: '1M', label: '30d', hours: 720 },
];

const COLORS = {
  primary: '#3b82f6',
  secondary: '#6366f1',
  accent: '#8b5cf6',
  warning: '#f59e0b',
  danger: '#ef4444',
  success: '#22c55e',
  info: '#06b6d4',
  muted: '#6b7280',
};

const CHART_COLORS = [
  '#3b82f6',
  '#6366f1',
  '#8b5cf6',
  '#ec4899',
  '#f59e0b',
  '#22c55e',
  '#06b6d4',
  '#f97316',
  '#14b8a6',
  '#a855f7',
];

const tooltipStyle = {
  backgroundColor: 'hsl(var(--card))',
  border: '1px solid hsl(var(--border))',
  borderRadius: '8px',
  fontSize: '12px',
};

// ─── Helpers ─────────────────────────────────────────────────────────────────

function formatBytes(bytes: number, decimals = 1): string {
  if (!bytes || bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  const i = Math.floor(Math.log(Math.abs(bytes)) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(decimals)) + ' ' + sizes[i];
}

function getHealthColor(score: number): string {
  if (score >= 80) return COLORS.success;
  if (score >= 60) return COLORS.warning;
  return COLORS.danger;
}

function getHealthVariant(score: number): 'success' | 'warning' | 'destructive' {
  if (score >= 80) return 'success';
  if (score >= 60) return 'warning';
  return 'destructive';
}

function getResourceVariant(pct: number): 'success' | 'warning' | 'destructive' | 'default' {
  if (pct >= 85) return 'destructive';
  if (pct >= 70) return 'warning';
  if (pct > 0) return 'success';
  return 'default';
}

// ─── Reusable visual primitives ──────────────────────────────────────────────

function HealthGauge({
  score,
  label,
  size = 'md',
}: {
  score: number;
  label?: string;
  size?: 'sm' | 'md' | 'lg';
}) {
  const sizes = {
    sm: { width: 80, fontSize: 'text-lg' },
    md: { width: 120, fontSize: 'text-3xl' },
    lg: { width: 160, fontSize: 'text-4xl' },
  };
  const { width, fontSize } = sizes[size];
  const strokeWidth = size === 'sm' ? 6 : size === 'md' ? 8 : 10;
  const radius = (width - strokeWidth) / 2;
  const circumference = radius * 2 * Math.PI;
  const offset = circumference - (score / 100) * circumference;
  const color = getHealthColor(score);

  return (
    <div className="flex flex-col items-center">
      <div className="relative" style={{ width, height: width }}>
        <svg className="transform -rotate-90" width={width} height={width}>
          <circle
            cx={width / 2}
            cy={width / 2}
            r={radius}
            stroke="currentColor"
            strokeWidth={strokeWidth}
            fill="none"
            className="text-muted/30"
          />
          <circle
            cx={width / 2}
            cy={width / 2}
            r={radius}
            stroke={color}
            strokeWidth={strokeWidth}
            fill="none"
            strokeDasharray={circumference}
            strokeDashoffset={offset}
            strokeLinecap="round"
            className="transition-all duration-500"
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className={cn(fontSize, 'font-bold text-foreground tabular-nums')}>{score}</span>
        </div>
      </div>
      {label && <span className="text-sm text-muted-foreground mt-2">{label}</span>}
    </div>
  );
}

function MiniPie({
  data,
  total,
  label,
}: {
  data: Array<{ name: string; value: number; color: string }>;
  total: number;
  label: string;
}) {
  const { t } = useTranslation('analytics');
  const hasData = total > 0 && data.length > 0;
  return (
    <div className="flex items-center gap-4">
      <div className="relative h-24 w-24 shrink-0">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={hasData ? data : [{ name: 'empty', value: 1, color: COLORS.muted }]}
              cx="50%"
              cy="50%"
              innerRadius={28}
              outerRadius={42}
              dataKey="value"
              isAnimationActive={false}
            >
              {(hasData ? data : [{ color: COLORS.muted }]).map((e, i) => (
                <Cell key={i} fill={e.color} />
              ))}
            </Pie>
          </PieChart>
        </ResponsiveContainer>
        <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
          <span className="text-xl font-bold tabular-nums text-foreground">{total}</span>
          <span className="text-[9px] uppercase tracking-wide text-muted-foreground">{label}</span>
        </div>
      </div>
      <div className="flex-1 space-y-1.5 text-xs min-w-0">
        {hasData ? (
          data.map((item) => (
            <div key={item.name} className="flex items-center justify-between gap-2">
              <span className="flex items-center gap-1.5 min-w-0">
                <span className="h-2 w-2 rounded-full shrink-0" style={{ backgroundColor: item.color }} />
                <span className="text-muted-foreground truncate">{item.name}</span>
              </span>
              <span className="font-medium tabular-nums shrink-0">{item.value}</span>
            </div>
          ))
        ) : (
          <span className="text-muted-foreground">{t('AnalyticsPage.common.noData')}</span>
        )}
      </div>
    </div>
  );
}

/** Time range segmented selector · drop-in replacement for the prior bg-muted pill row. */
function TimeRangeSelector({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  return (
    <div className="inline-flex items-center rounded-lg border bg-card p-0.5">
      {TIME_RANGES.map((r) => (
        <button
          key={r.value}
          type="button"
          onClick={() => onChange(r.value)}
          className={cn(
            'h-7 px-3 text-xs font-medium rounded-md transition-colors',
            value === r.value
              ? 'bg-primary text-primary-foreground shadow-sm'
              : 'text-muted-foreground hover:text-foreground hover:bg-muted',
          )}
        >
          {r.label}
        </button>
      ))}
    </div>
  );
}

/** Standardised chart card with title, optional description and empty-state fallback. */
function ChartCard({
  title,
  description,
  children,
  isEmpty,
  emptyText,
  className,
  action,
}: {
  title: string;
  description?: string;
  children: React.ReactNode;
  isEmpty?: boolean;
  emptyText?: string;
  className?: string;
  action?: React.ReactNode;
}) {
  const { t } = useTranslation('analytics');
  const resolvedEmptyText = emptyText ?? t('AnalyticsPage.common.noDataAvailable');
  return (
    <Card className={className}>
      <CardHeader className="pb-3">
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0">
            <CardTitle className="text-base">{title}</CardTitle>
            {description && <CardDescription className="text-xs mt-0.5">{description}</CardDescription>}
          </div>
          {action && <div className="shrink-0">{action}</div>}
        </div>
      </CardHeader>
      <CardContent>
        {isEmpty ? (
          <EmptyState variant="compact" icon={BarChart3} title={resolvedEmptyText} />
        ) : (
          children
        )}
      </CardContent>
    </Card>
  );
}

// ─── OVERVIEW TAB ────────────────────────────────────────────────────────────

function OverviewTab({ d }: { d: EnterpriseAnalytics }) {
  const { t } = useTranslation('analytics');
  const fleet = d.fleet;

  const typeData = useMemo(
    () =>
      Object.entries(fleet.by_type)
        .map(([type, counts]) => ({ type: type.replace(/_/g, ' '), ...counts }))
        .sort((a, b) => b.total - a.total),
    [fleet.by_type],
  );

  const mfrData = useMemo(
    () =>
      fleet.by_manufacturer.map((m, i) => ({
        name: m.name,
        value: m.count,
        color: CHART_COLORS[i % CHART_COLORS.length],
      })),
    [fleet.by_manufacturer],
  );

  const siteData = useMemo(
    () => d.sites.map((s) => ({ name: s.name, health: s.health, devices: s.devices, online: s.online })),
    [d.sites],
  );

  const headlineStats: StatItem[] = [
    {
      title: t('AnalyticsPage.overview.stats.healthScore'),
      value: d.health_score,
      icon: Activity,
      variant: getHealthVariant(d.health_score),
      description:
        d.health_score >= 80
          ? t('AnalyticsPage.overview.healthStatus.healthy')
          : d.health_score >= 60
            ? t('AnalyticsPage.overview.healthStatus.degraded')
            : t('AnalyticsPage.overview.healthStatus.critical'),
    },
    {
      title: t('AnalyticsPage.overview.stats.devices'),
      value: fleet.total,
      icon: Server,
      variant: 'primary',
      description: t('AnalyticsPage.overview.stats.devicesDesc', {
        online: fleet.online,
        offline: fleet.offline,
      }),
    },
    {
      title: t('AnalyticsPage.overview.stats.networkClients'),
      value: d.clients.total,
      icon: Users,
      variant: 'info',
      description: t('AnalyticsPage.overview.stats.networkClientsDesc', { online: d.clients.online }),
    },
    {
      title: t('AnalyticsPage.overview.stats.activeAlerts'),
      value: d.incidents.open + d.incidents.investigating,
      icon: AlertTriangle,
      variant: d.incidents.open > 0 ? 'warning' : 'success',
      description: t('AnalyticsPage.overview.stats.activeAlertsDesc', { total: d.incidents.total }),
    },
  ];

  const resourceStats: StatItem[] = [
    {
      title: t('AnalyticsPage.overview.stats.avgCpu'),
      value: `${fleet.avg_cpu}%`,
      icon: Cpu,
      variant: getResourceVariant(fleet.avg_cpu),
      description: fleet.max_cpu != null ? t('AnalyticsPage.overview.peak', { value: fleet.max_cpu }) : '-',
    },
    {
      title: t('AnalyticsPage.overview.stats.avgMemory'),
      value: `${fleet.avg_memory}%`,
      icon: MemoryStick,
      variant: getResourceVariant(fleet.avg_memory),
      description: fleet.max_memory != null ? t('AnalyticsPage.overview.peak', { value: fleet.max_memory }) : '-',
    },
    {
      title: t('AnalyticsPage.overview.stats.avgTemperature'),
      value: fleet.avg_temp != null ? `${fleet.avg_temp}°C` : '-',
      icon: Thermometer,
      variant: fleet.avg_temp != null ? getResourceVariant(fleet.avg_temp) : 'default',
      description:
        fleet.max_temp != null
          ? t('AnalyticsPage.overview.peakTemp', { value: fleet.max_temp })
          : t('AnalyticsPage.overview.noTelemetry'),
    },
    {
      title: t('AnalyticsPage.overview.stats.portHealth'),
      value: `${d.ports.up}/${d.ports.total}`,
      icon: Cable,
      variant: d.ports.down > 0 ? 'warning' : 'success',
      description: t('AnalyticsPage.overview.stats.portHealthDesc', {
        down: d.ports.down,
        errors: d.ports.total_errors,
      }),
    },
  ];

  return (
    <div className="space-y-6">
      <StatsGrid columns={4} stats={headlineStats} />
      <StatsGrid columns={4} stats={resourceStats} />

      {/* Hero health gauge + sites summary */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <Card>
          <CardContent noOffset className="flex flex-col items-center justify-center py-8">
            <HealthGauge score={d.health_score} label={t('AnalyticsPage.overview.organizationHealth')} size="lg" />
            <p className="text-xs text-muted-foreground mt-3">
              {t('AnalyticsPage.overview.acrossSitesDevices', {
                siteCount: d.total_sites,
                sites:
                  d.total_sites === 1
                    ? t('AnalyticsPage.overview.unit.site')
                    : t('AnalyticsPage.overview.unit.sites'),
                deviceCount: fleet.total,
                devices:
                  fleet.total === 1
                    ? t('AnalyticsPage.overview.unit.device')
                    : t('AnalyticsPage.overview.unit.devices'),
              })}
            </p>
          </CardContent>
        </Card>

        <ChartCard
          title={t('AnalyticsPage.overview.siteHealth.title')}
          description={t('AnalyticsPage.overview.siteHealth.description')}
          isEmpty={siteData.length === 0}
          emptyText={t('AnalyticsPage.overview.siteHealth.empty')}
          className="lg:col-span-2"
        >
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={siteData}>
                <CartesianGrid strokeDasharray="3 3" className="stroke-border" vertical={false} />
                <XAxis dataKey="name" tick={{ fontSize: 11 }} tickLine={false} axisLine={false} />
                <YAxis
                  domain={[0, 100]}
                  tick={{ fontSize: 11 }}
                  tickLine={false}
                  axisLine={false}
                  tickFormatter={(v) => `${v}%`}
                />
                <Tooltip contentStyle={tooltipStyle} formatter={(v) => [`${Number(v)}%`, t('AnalyticsPage.overview.siteHealth.tooltip')]} />
                <Bar dataKey="health" name={t('AnalyticsPage.overview.siteHealth.barName')} radius={[4, 4, 0, 0]}>
                  {siteData.map((s, i) => (
                    <Cell key={i} fill={getHealthColor(s.health)} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </ChartCard>
      </div>

      {/* Distribution row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <ChartCard
          title={t('AnalyticsPage.overview.devicesByType.title')}
          description={t('AnalyticsPage.overview.devicesByType.description')}
          isEmpty={typeData.length === 0}
          emptyText={t('AnalyticsPage.overview.devicesByType.empty')}
        >
          <div className="h-72">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={typeData} layout="vertical" margin={{ left: 80 }}>
                <CartesianGrid strokeDasharray="3 3" className="stroke-border" horizontal={false} />
                <XAxis type="number" tick={{ fontSize: 10 }} tickLine={false} axisLine={false} />
                <YAxis
                  dataKey="type"
                  type="category"
                  tick={{ fontSize: 11 }}
                  tickLine={false}
                  axisLine={false}
                  width={75}
                />
                <Tooltip contentStyle={tooltipStyle} />
                <Bar dataKey="online" name={t('AnalyticsPage.overview.online')} stackId="a" fill={COLORS.success} />
                <Bar dataKey="offline" name={t('AnalyticsPage.overview.offline')} stackId="a" fill={COLORS.danger} radius={[0, 4, 4, 0]} />
                <Legend wrapperStyle={{ fontSize: 11 }} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </ChartCard>

        <ChartCard
          title={t('AnalyticsPage.overview.devicesByManufacturer.title')}
          description={t('AnalyticsPage.overview.devicesByManufacturer.description')}
          isEmpty={mfrData.length === 0}
          emptyText={t('AnalyticsPage.overview.devicesByManufacturer.empty')}
        >
          <MiniPie data={mfrData} total={fleet.total} label={t('AnalyticsPage.overview.devicesLabel')} />
        </ChartCard>
      </div>

      {/* Controllers + Top devices */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <ChartCard
          title={t('AnalyticsPage.overview.controllers.title')}
          description={t('AnalyticsPage.overview.controllers.description', { count: d.controllers.length })}
          isEmpty={d.controllers.length === 0}
          emptyText={t('AnalyticsPage.overview.controllers.empty')}
        >
          <div className="space-y-2">
            {d.controllers.map((c) => {
              const dotColor =
                c.status === 'connected' || c.status === 'online'
                  ? 'bg-green-500'
                  : c.status === 'error'
                    ? 'bg-red-500'
                    : 'bg-yellow-500';
              return (
                <div
                  key={c.id}
                  className="flex items-center justify-between gap-3 p-3 rounded-lg border bg-muted/30 hover:bg-muted/50 transition-colors"
                >
                  <div className="flex items-center gap-3 min-w-0">
                    <span className={cn('h-2.5 w-2.5 rounded-full shrink-0', dotColor)} />
                    <div className="min-w-0">
                      <p className="text-sm font-medium truncate">{c.name}</p>
                      <p className="text-xs text-muted-foreground truncate font-mono">
                        {c.type} · {c.host}
                      </p>
                    </div>
                  </div>
                  <div className="text-right shrink-0">
                    <span className="text-sm font-semibold tabular-nums">{c.device_count}</span>
                    <span className="text-xs text-muted-foreground ml-1">{t('AnalyticsPage.overview.devicesLabel')}</span>
                  </div>
                </div>
              );
            })}
          </div>
        </ChartCard>

        <ChartCard
          title={t('AnalyticsPage.overview.topCpu.title')}
          description={t('AnalyticsPage.overview.topCpu.description')}
          isEmpty={d.top_devices_cpu.length === 0}
          emptyText={t('AnalyticsPage.overview.topCpu.empty')}
        >
          <div className="h-72">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={d.top_devices_cpu} layout="vertical" margin={{ left: 100 }}>
                <CartesianGrid strokeDasharray="3 3" className="stroke-border" horizontal={false} />
                <XAxis
                  type="number"
                  domain={[0, 100]}
                  tick={{ fontSize: 10 }}
                  tickLine={false}
                  axisLine={false}
                  tickFormatter={(v) => `${v}%`}
                />
                <YAxis
                  dataKey="name"
                  type="category"
                  tick={{ fontSize: 10 }}
                  tickLine={false}
                  axisLine={false}
                  width={95}
                />
                <Tooltip contentStyle={tooltipStyle} formatter={(v) => [`${Number(v)}%`, t('AnalyticsPage.overview.cpuLabel')]} />
                <Bar dataKey="cpu" name={t('AnalyticsPage.overview.cpuBarName')} radius={[0, 4, 4, 0]}>
                  {d.top_devices_cpu.map((dev, i) => (
                    <Cell
                      key={i}
                      fill={dev.cpu > 80 ? COLORS.danger : dev.cpu > 60 ? COLORS.warning : COLORS.primary}
                    />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </ChartCard>
      </div>

      {/* Top memory */}
      <ChartCard
        title={t('AnalyticsPage.overview.topMemory.title')}
        description={t('AnalyticsPage.overview.topMemory.description')}
        isEmpty={d.top_devices_memory.length === 0}
        emptyText={t('AnalyticsPage.overview.topMemory.empty')}
      >
        <div className="h-72">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={d.top_devices_memory} layout="vertical" margin={{ left: 100 }}>
              <CartesianGrid strokeDasharray="3 3" className="stroke-border" horizontal={false} />
              <XAxis
                type="number"
                domain={[0, 100]}
                tick={{ fontSize: 10 }}
                tickLine={false}
                axisLine={false}
                tickFormatter={(v) => `${v}%`}
              />
              <YAxis
                dataKey="name"
                type="category"
                tick={{ fontSize: 10 }}
                tickLine={false}
                axisLine={false}
                width={95}
              />
              <Tooltip contentStyle={tooltipStyle} formatter={(v) => [`${Number(v)}%`, t('AnalyticsPage.overview.memoryLabel')]} />
              <Bar dataKey="memory" name={t('AnalyticsPage.overview.memoryBarName')} radius={[0, 4, 4, 0]}>
                {d.top_devices_memory.map((dev, i) => (
                  <Cell
                    key={i}
                    fill={dev.memory > 80 ? COLORS.danger : dev.memory > 60 ? COLORS.warning : COLORS.secondary}
                  />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </ChartCard>
    </div>
  );
}

// ─── INSIGHTS TAB ────────────────────────────────────────────────────────────

function InsightsTab({ d }: { d: EnterpriseAnalytics }) {
  const { t } = useTranslation('analytics');
  const totalTraffic =
    d.clients.total_tx_bytes +
    d.clients.total_rx_bytes +
    d.ports.total_tx_bytes +
    d.ports.total_rx_bytes;

  const auditLevelData = useMemo(
    () =>
      Object.entries(d.audit.by_level).map(([level, count], i) => ({
        name: level,
        value: count,
        color: CHART_COLORS[i % CHART_COLORS.length],
      })),
    [d.audit.by_level],
  );

  const auditSourceData = useMemo(
    () =>
      Object.entries(d.audit.by_source)
        .map(([source, count]) => ({ source, count }))
        .sort((a, b) => b.count - a.count),
    [d.audit.by_source],
  );

  const incidentData = useMemo(() => {
    const items: Array<{ name: string; value: number; color: string }> = [];
    if (d.incidents.open)
      items.push({ name: t('AnalyticsPage.insights.incidentStatus.open'), value: d.incidents.open, color: COLORS.danger });
    if (d.incidents.investigating)
      items.push({ name: t('AnalyticsPage.insights.incidentStatus.investigating'), value: d.incidents.investigating, color: COLORS.warning });
    if (d.incidents.resolved)
      items.push({ name: t('AnalyticsPage.insights.incidentStatus.resolved'), value: d.incidents.resolved, color: COLORS.success });
    const other = d.incidents.total - d.incidents.open - d.incidents.investigating - d.incidents.resolved;
    if (other > 0) items.push({ name: t('AnalyticsPage.insights.incidentStatus.other'), value: other, color: COLORS.muted });
    return items;
  }, [d.incidents, t]);

  const headlineStats: StatItem[] = [
    {
      title: t('AnalyticsPage.insights.stats.healthScore'),
      value: d.health_score,
      icon: Activity,
      variant: getHealthVariant(d.health_score),
    },
    {
      title: t('AnalyticsPage.insights.stats.totalTraffic'),
      value: formatBytes(totalTraffic),
      icon: TrendingUp,
      variant: 'info',
      description: t('AnalyticsPage.insights.stats.totalTrafficDesc', {
        tx: formatBytes(d.ports.total_tx_bytes),
        rx: formatBytes(d.ports.total_rx_bytes),
      }),
    },
    {
      title: t('AnalyticsPage.insights.stats.devicesOnline'),
      value: d.fleet.online,
      icon: Server,
      variant: 'success',
      description: t('AnalyticsPage.insights.stats.devicesOnlineDesc', {
        degraded: d.fleet.degraded,
        offline: d.fleet.offline,
      }),
    },
    {
      title: t('AnalyticsPage.insights.stats.avgClientSignal'),
      value: d.clients.avg_signal_dbm != null ? `${d.clients.avg_signal_dbm} dBm` : '-',
      icon: Signal,
      variant:
        d.clients.avg_signal_dbm == null
          ? 'default'
          : d.clients.avg_signal_dbm > -55
            ? 'success'
            : d.clients.avg_signal_dbm > -70
              ? 'warning'
              : 'destructive',
    },
  ];

  const securityStats: StatItem[] = [
    {
      title: t('AnalyticsPage.insights.security.failedLogins'),
      value: d.security.failed_logins_window,
      icon: Lock,
      variant: d.security.failed_logins_window > 10 ? 'destructive' : 'success',
      description: t('AnalyticsPage.insights.security.lastHours', { hours: d.hours }),
    },
    {
      title: t('AnalyticsPage.insights.security.activeIpBlocks'),
      value: d.security.active_ip_blocks,
      icon: ShieldAlert,
      variant: d.security.active_ip_blocks > 0 ? 'warning' : 'success',
    },
    {
      title: t('AnalyticsPage.insights.security.unresolvedAnomalies'),
      value: d.security.unresolved_anomalies,
      icon: Eye,
      variant: d.security.unresolved_anomalies > 0 ? 'destructive' : 'success',
    },
    {
      title: t('AnalyticsPage.insights.security.securityEvents'),
      value: d.security.total_security_events,
      icon: Shield,
      variant: 'info',
      description: t('AnalyticsPage.insights.security.lastHours', { hours: d.hours }),
    },
  ];

  return (
    <div className="space-y-6">
      <StatsGrid columns={4} stats={headlineStats} />

      <div>
        <h3 className="text-sm font-semibold text-muted-foreground uppercase tracking-wider mb-3">
          {t('AnalyticsPage.insights.securityPosture')}
        </h3>
        <StatsGrid columns={4} stats={securityStats} />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <ChartCard
          title={t('AnalyticsPage.insights.auditByLevel.title')}
          description={t('AnalyticsPage.insights.auditByLevel.description', { count: d.audit.total_events })}
          isEmpty={auditLevelData.length === 0}
          emptyText={t('AnalyticsPage.insights.auditByLevel.empty')}
        >
          <MiniPie data={auditLevelData} total={d.audit.total_events} label={t('AnalyticsPage.insights.eventsLabel')} />
        </ChartCard>

        <ChartCard
          title={t('AnalyticsPage.insights.auditBySource.title')}
          description={t('AnalyticsPage.insights.auditBySource.description')}
          isEmpty={auditSourceData.length === 0}
          emptyText={t('AnalyticsPage.insights.auditBySource.empty')}
          className="lg:col-span-2"
        >
          <div className="h-56">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={auditSourceData} layout="vertical" margin={{ left: 80 }}>
                <CartesianGrid strokeDasharray="3 3" className="stroke-border" horizontal={false} />
                <XAxis type="number" tick={{ fontSize: 10 }} tickLine={false} axisLine={false} />
                <YAxis
                  dataKey="source"
                  type="category"
                  tick={{ fontSize: 10 }}
                  tickLine={false}
                  axisLine={false}
                  width={75}
                />
                <Tooltip contentStyle={tooltipStyle} />
                <Bar dataKey="count" name={t('AnalyticsPage.insights.eventsLabel')} fill={COLORS.primary} radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </ChartCard>
      </div>

      <ChartCard
        title={t('AnalyticsPage.insights.incidents.title')}
        description={t('AnalyticsPage.insights.incidents.description', {
          total: d.incidents.total,
          open: d.incidents.open,
        })}
        isEmpty={d.incidents.total === 0}
        emptyText={t('AnalyticsPage.insights.incidents.empty')}
      >
        <MiniPie data={incidentData} total={d.incidents.total} label={t('AnalyticsPage.insights.totalLabel')} />
      </ChartCard>
    </div>
  );
}

// ─── WI-FI TAB ───────────────────────────────────────────────────────────────

function WifiTab({ d }: { d: EnterpriseAnalytics }) {
  const { t } = useTranslation('analytics');
  const c = d.clients;
  const wireless = c.band_2g + c.band_5g + c.band_6g;

  const bandData = useMemo(() => {
    const items: Array<{ name: string; value: number; color: string }> = [];
    if (c.band_2g) items.push({ name: '2.4 GHz', value: c.band_2g, color: COLORS.warning });
    if (c.band_5g) items.push({ name: '5 GHz', value: c.band_5g, color: COLORS.primary });
    if (c.band_6g) items.push({ name: '6 GHz', value: c.band_6g, color: COLORS.accent });
    const wired = c.total - wireless;
    if (wired > 0) items.push({ name: t('AnalyticsPage.common.wired'), value: wired, color: COLORS.muted });
    return items;
  }, [c, wireless, t]);

  const signalData = useMemo(() => {
    const order = ['excellent', 'good', 'fair', 'weak', 'poor'];
    const labels: Record<string, string> = {
      excellent: '> -45 dBm',
      good: '-45 ~ -55',
      fair: '-55 ~ -65',
      weak: '-65 ~ -75',
      poor: '< -75 dBm',
    };
    const colors: Record<string, string> = {
      excellent: COLORS.success,
      good: COLORS.primary,
      fair: COLORS.info,
      weak: COLORS.warning,
      poor: COLORS.danger,
    };
    return order.map((q) => ({
      quality: labels[q] || q,
      count: c.signal_distribution[q] || 0,
      fill: colors[q] || COLORS.muted,
    }));
  }, [c.signal_distribution]);

  const ssidData = useMemo(
    () => (c.top_ssids || []).map((s, i) => ({ ...s, fill: CHART_COLORS[i % CHART_COLORS.length] })),
    [c.top_ssids],
  );

  const wifiRadar = useMemo(() => {
    const sigScore = c.avg_signal_dbm != null ? Math.max(0, Math.min(100, (c.avg_signal_dbm + 90) * 2)) : 50;
    const excellentGood =
      (c.signal_distribution['excellent'] || 0) + (c.signal_distribution['good'] || 0);
    const qualityScore = wireless > 0 ? Math.round((excellentGood / wireless) * 100) : 50;
    const bandDiversityScore =
      wireless > 0 ? Math.round(((c.band_5g + c.band_6g) / wireless) * 100) : 50;
    const onlineScore = c.total > 0 ? Math.round((c.online / c.total) * 100) : 100;
    return [
      { subject: t('AnalyticsPage.wifi.radar.signalStrength'), A: Math.round(sigScore) },
      { subject: t('AnalyticsPage.wifi.radar.signalQuality'), A: qualityScore },
      { subject: t('AnalyticsPage.wifi.radar.bandDiversity'), A: bandDiversityScore },
      { subject: t('AnalyticsPage.wifi.radar.connectivity'), A: onlineScore },
    ];
  }, [c, wireless, t]);

  const stats: StatItem[] = [
    {
      title: t('AnalyticsPage.wifi.stats.wirelessClients'),
      value: wireless,
      icon: Wifi,
      variant: 'primary',
      description: t('AnalyticsPage.wifi.stats.ofTotal', { total: c.total }),
    },
    {
      title: t('AnalyticsPage.wifi.stats.avgSignal'),
      value: c.avg_signal_dbm != null ? `${c.avg_signal_dbm} dBm` : '-',
      icon: Signal,
      variant:
        c.avg_signal_dbm == null
          ? 'default'
          : c.avg_signal_dbm > -55
            ? 'success'
            : c.avg_signal_dbm > -70
              ? 'warning'
              : 'destructive',
    },
    {
      title: t('AnalyticsPage.wifi.stats.clientUpload'),
      value: formatBytes(c.total_tx_bytes),
      icon: ArrowUpRight,
      variant: 'info',
    },
    {
      title: t('AnalyticsPage.wifi.stats.clientDownload'),
      value: formatBytes(c.total_rx_bytes),
      icon: ArrowDownRight,
      variant: 'info',
    },
  ];

  return (
    <div className="space-y-6">
      <StatsGrid columns={4} stats={stats} />

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <ChartCard
          title={t('AnalyticsPage.wifi.bandDistribution.title')}
          description={t('AnalyticsPage.wifi.bandDistribution.description')}
          isEmpty={c.total === 0}
        >
          <MiniPie data={bandData} total={c.total} label={t('AnalyticsPage.common.clients')} />
        </ChartCard>

        <ChartCard
          title={t('AnalyticsPage.wifi.signalQuality.title')}
          description={t('AnalyticsPage.wifi.signalQuality.description')}
          isEmpty={!signalData.some((s) => s.count > 0)}
          emptyText={t('AnalyticsPage.wifi.signalQuality.empty')}
        >
          <div className="h-52">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={signalData}>
                <CartesianGrid strokeDasharray="3 3" className="stroke-border" vertical={false} />
                <XAxis dataKey="quality" tick={{ fontSize: 10 }} tickLine={false} axisLine={false} />
                <YAxis tick={{ fontSize: 10 }} tickLine={false} axisLine={false} />
                <Tooltip contentStyle={tooltipStyle} />
                <Bar dataKey="count" name={t('AnalyticsPage.common.clients')} radius={[4, 4, 0, 0]}>
                  {signalData.map((e, i) => (
                    <Cell key={i} fill={e.fill} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </ChartCard>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <ChartCard
          title={t('AnalyticsPage.wifi.topSsids.title')}
          description={t('AnalyticsPage.wifi.topSsids.description')}
          isEmpty={ssidData.length === 0}
          emptyText={t('AnalyticsPage.wifi.topSsids.empty')}
        >
          <div className="h-52">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={ssidData}>
                <CartesianGrid strokeDasharray="3 3" className="stroke-border" vertical={false} />
                <XAxis dataKey="ssid" tick={{ fontSize: 10 }} tickLine={false} axisLine={false} />
                <YAxis tick={{ fontSize: 10 }} tickLine={false} axisLine={false} />
                <Tooltip contentStyle={tooltipStyle} />
                <Bar dataKey="clients" name={t('AnalyticsPage.common.clients')} radius={[4, 4, 0, 0]}>
                  {ssidData.map((e, i) => (
                    <Cell key={i} fill={e.fill} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </ChartCard>

        <ChartCard
          title={t('AnalyticsPage.wifi.healthProfile.title')}
          description={t('AnalyticsPage.wifi.healthProfile.description')}
        >
          <div className="h-52">
            <ResponsiveContainer width="100%" height="100%">
              <RadarChart data={wifiRadar}>
                <PolarGrid stroke="hsl(var(--border))" />
                <PolarAngleAxis dataKey="subject" tick={{ fontSize: 10 }} />
                <PolarRadiusAxis angle={90} domain={[0, 100]} tick={false} axisLine={false} />
                <Radar
                  name={t('AnalyticsPage.wifi.healthProfile.radarName')}
                  dataKey="A"
                  stroke={COLORS.primary}
                  fill={COLORS.primary}
                  fillOpacity={0.3}
                />
              </RadarChart>
            </ResponsiveContainer>
          </div>
        </ChartCard>
      </div>
    </div>
  );
}

// ─── CLIENTS TAB ─────────────────────────────────────────────────────────────

function ClientsTab({ d }: { d: EnterpriseAnalytics }) {
  const { t } = useTranslation('analytics');
  const c = d.clients;
  const wireless = c.band_2g + c.band_5g + c.band_6g;
  const wired = Math.max(0, c.total - wireless);

  const connData = useMemo(
    () => [
      { name: t('AnalyticsPage.common.wireless'), value: wireless, color: COLORS.secondary },
      { name: t('AnalyticsPage.common.wired'), value: wired, color: COLORS.primary },
    ],
    [wireless, wired, t],
  );

  const bandData = useMemo(() => {
    const items: Array<{ name: string; value: number; color: string }> = [];
    if (c.band_2g) items.push({ name: '2.4 GHz', value: c.band_2g, color: COLORS.warning });
    if (c.band_5g) items.push({ name: '5 GHz', value: c.band_5g, color: COLORS.primary });
    if (c.band_6g) items.push({ name: '6 GHz', value: c.band_6g, color: COLORS.accent });
    return items;
  }, [c]);

  const ssidPieData = useMemo(
    () =>
      (c.top_ssids || []).map((s, i) => ({
        name: s.ssid,
        value: s.clients,
        color: CHART_COLORS[i % CHART_COLORS.length],
      })),
    [c.top_ssids],
  );

  const signalData = useMemo(() => {
    const order = ['excellent', 'good', 'fair', 'weak', 'poor'];
    const labels: Record<string, string> = {
      excellent: `${t('AnalyticsPage.clients.signalRating.excellent')} (> -45)`,
      good: `${t('AnalyticsPage.clients.signalRating.good')} (-45~-55)`,
      fair: `${t('AnalyticsPage.clients.signalRating.fair')} (-55~-65)`,
      weak: `${t('AnalyticsPage.clients.signalRating.weak')} (-65~-75)`,
      poor: `${t('AnalyticsPage.clients.signalRating.poor')} (< -75)`,
    };
    const colors: Record<string, string> = {
      excellent: COLORS.success,
      good: COLORS.primary,
      fair: COLORS.info,
      weak: COLORS.warning,
      poor: COLORS.danger,
    };
    return order
      .filter((q) => (c.signal_distribution[q] || 0) > 0)
      .map((q) => ({ quality: labels[q], count: c.signal_distribution[q], fill: colors[q] }));
  }, [c.signal_distribution, t]);

  const stats: StatItem[] = [
    { title: t('AnalyticsPage.clients.stats.totalClients'), value: c.total, icon: Users, variant: 'primary' },
    {
      title: t('AnalyticsPage.clients.stats.online'),
      value: c.online,
      icon: CheckCircle,
      variant: 'success',
      description:
        c.total > 0
          ? t('AnalyticsPage.clients.stats.reachable', { pct: Math.round((c.online / c.total) * 100) })
          : '-',
    },
    { title: t('AnalyticsPage.common.wired'), value: wired, icon: Cable, variant: 'info' },
    { title: t('AnalyticsPage.common.wireless'), value: wireless, icon: Wifi, variant: 'info' },
  ];

  const signalRating =
    c.avg_signal_dbm == null
      ? t('AnalyticsPage.common.noData')
      : c.avg_signal_dbm > -55
        ? t('AnalyticsPage.clients.signalRating.excellent')
        : c.avg_signal_dbm > -70
          ? t('AnalyticsPage.clients.signalRating.fair')
          : t('AnalyticsPage.clients.signalRating.poor');

  return (
    <div className="space-y-6">
      <StatsGrid columns={4} stats={stats} />

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <ChartCard title={t('AnalyticsPage.clients.connectionType.title')} description={t('AnalyticsPage.clients.connectionType.description')}>
          <MiniPie data={connData} total={c.total} label={t('AnalyticsPage.common.clients')} />
        </ChartCard>
        <ChartCard
          title={t('AnalyticsPage.clients.bandDistribution.title')}
          description={t('AnalyticsPage.clients.bandDistribution.description')}
          isEmpty={bandData.length === 0}
          emptyText={t('AnalyticsPage.clients.bandDistribution.empty')}
        >
          <MiniPie data={bandData} total={wireless} label={t('AnalyticsPage.common.wireless')} />
        </ChartCard>
        <ChartCard
          title={t('AnalyticsPage.clients.ssidDistribution.title')}
          description={t('AnalyticsPage.clients.ssidDistribution.description')}
          isEmpty={ssidPieData.length === 0}
          emptyText={t('AnalyticsPage.clients.ssidDistribution.empty')}
        >
          <MiniPie data={ssidPieData} total={wireless} label={t('AnalyticsPage.common.wireless')} />
        </ChartCard>
      </div>

      <ChartCard
        title={t('AnalyticsPage.clients.signalQuality.title')}
        description={t('AnalyticsPage.clients.signalQuality.description')}
        isEmpty={signalData.length === 0}
        emptyText={t('AnalyticsPage.clients.signalQuality.empty')}
      >
        <div className="h-56">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={signalData} layout="vertical" margin={{ left: 140 }}>
              <CartesianGrid strokeDasharray="3 3" className="stroke-border" horizontal={false} />
              <XAxis type="number" tick={{ fontSize: 10 }} tickLine={false} axisLine={false} />
              <YAxis
                dataKey="quality"
                type="category"
                tick={{ fontSize: 11 }}
                tickLine={false}
                axisLine={false}
                width={135}
              />
              <Tooltip contentStyle={tooltipStyle} />
              <Bar dataKey="count" name={t('AnalyticsPage.common.clients')} radius={[0, 4, 4, 0]}>
                {signalData.map((e, i) => (
                  <Cell key={i} fill={e.fill} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </ChartCard>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <ChartCard title={t('AnalyticsPage.clients.clientTraffic.title')} description={t('AnalyticsPage.clients.clientTraffic.totalDesc', { total: formatBytes(c.total_tx_bytes + c.total_rx_bytes) })}>
          <div className="space-y-3">
            <div className="flex items-center justify-between rounded-lg border bg-muted/30 px-4 py-3">
              <span className="flex items-center gap-2 text-sm text-muted-foreground">
                <ArrowUpRight className="h-4 w-4" /> {t('AnalyticsPage.clients.clientTraffic.uploadTx')}
              </span>
              <span className="text-base font-bold tabular-nums">{formatBytes(c.total_tx_bytes)}</span>
            </div>
            <div className="flex items-center justify-between rounded-lg border bg-muted/30 px-4 py-3">
              <span className="flex items-center gap-2 text-sm text-muted-foreground">
                <ArrowDownRight className="h-4 w-4" /> {t('AnalyticsPage.clients.clientTraffic.downloadRx')}
              </span>
              <span className="text-base font-bold tabular-nums">{formatBytes(c.total_rx_bytes)}</span>
            </div>
            <div className="flex items-center justify-between rounded-lg border-2 border-primary/40 bg-primary/5 px-4 py-3">
              <span className="text-sm font-semibold">{t('AnalyticsPage.common.total')}</span>
              <span className="text-lg font-bold tabular-nums text-primary">
                {formatBytes(c.total_tx_bytes + c.total_rx_bytes)}
              </span>
            </div>
          </div>
        </ChartCard>

        <ChartCard
          title={t('AnalyticsPage.clients.avgSignalStrength.title')}
          description={t('AnalyticsPage.clients.avgSignalStrength.description')}
          isEmpty={c.avg_signal_dbm == null}
          emptyText={t('AnalyticsPage.clients.avgSignalStrength.empty')}
        >
          <div className="flex flex-col items-center py-4">
            <Signal
              className={cn(
                'h-16 w-16 mb-3',
                c.avg_signal_dbm != null && c.avg_signal_dbm > -55
                  ? 'text-success'
                  : c.avg_signal_dbm != null && c.avg_signal_dbm > -70
                    ? 'text-warning'
                    : 'text-destructive',
              )}
            />
            <span className="text-4xl font-bold tabular-nums">{c.avg_signal_dbm}</span>
            <span className="text-sm text-muted-foreground mt-1">{t('AnalyticsPage.clients.avgSignalStrength.dbmAverage')}</span>
            <Badge
              variant={
                c.avg_signal_dbm != null && c.avg_signal_dbm > -55
                  ? 'default'
                  : c.avg_signal_dbm != null && c.avg_signal_dbm > -70
                    ? 'secondary'
                    : 'destructive'
              }
              className="mt-2"
            >
              {signalRating}
            </Badge>
          </div>
        </ChartCard>
      </div>
    </div>
  );
}

// ─── TRAFFIC TAB ─────────────────────────────────────────────────────────────

interface SiteRow {
  id: string;
  name: string;
  devices: number;
  online: number;
  offline: number;
  health: number;
}

function TrafficTab({ d }: { d: EnterpriseAnalytics }) {
  const { t } = useTranslation('analytics');
  const p = d.ports;

  const portStatusData = useMemo(() => {
    const items: Array<{ name: string; value: number; color: string }> = [];
    if (p.up) items.push({ name: t('AnalyticsPage.traffic.portStatusLabel.up'), value: p.up, color: COLORS.success });
    if (p.down) items.push({ name: t('AnalyticsPage.traffic.portStatusLabel.down'), value: p.down, color: COLORS.danger });
    const other = p.total - p.up - p.down;
    if (other > 0) items.push({ name: t('AnalyticsPage.traffic.portStatusLabel.other'), value: other, color: COLORS.muted });
    return items;
  }, [p, t]);

  const trafficCompare = useMemo(
    () => [
      { name: t('AnalyticsPage.traffic.trafficCompare.portTx'), bytes: p.total_tx_bytes },
      { name: t('AnalyticsPage.traffic.trafficCompare.portRx'), bytes: p.total_rx_bytes },
      { name: t('AnalyticsPage.traffic.trafficCompare.clientTx'), bytes: d.clients.total_tx_bytes },
      { name: t('AnalyticsPage.traffic.trafficCompare.clientRx'), bytes: d.clients.total_rx_bytes },
    ],
    [p, d.clients, t],
  );

  const stats: StatItem[] = [
    {
      title: t('AnalyticsPage.traffic.stats.totalPorts'),
      value: p.total,
      icon: Cable,
      variant: 'primary',
      description: t('AnalyticsPage.traffic.stats.totalPortsDesc', { up: p.up, down: p.down }),
    },
    {
      title: t('AnalyticsPage.traffic.stats.portUpload'),
      value: formatBytes(p.total_tx_bytes),
      icon: ArrowUpRight,
      variant: 'info',
    },
    {
      title: t('AnalyticsPage.traffic.stats.portDownload'),
      value: formatBytes(p.total_rx_bytes),
      icon: ArrowDownRight,
      variant: 'info',
    },
    {
      title: t('AnalyticsPage.traffic.stats.poePower'),
      value: `${p.total_poe_watts} W`,
      icon: Zap,
      variant: p.total_poe_watts > 0 ? 'warning' : 'default',
      description: t('AnalyticsPage.traffic.stats.poePortsCount', { count: p.poe_ports }),
    },
  ];

  // DataTable for site overview
  const siteColumns: DataTableColumn<SiteRow>[] = [
    {
      id: 'name',
      header: t('AnalyticsPage.traffic.siteColumns.site'),
      cell: (s) => (
        <div className="flex items-center gap-2">
          <Globe className="h-4 w-4 text-muted-foreground shrink-0" />
          <span className="font-medium">{s.name}</span>
        </div>
      ),
    },
    {
      id: 'devices',
      header: t('AnalyticsPage.traffic.siteColumns.devices'),
      cell: (s) => <span className="tabular-nums">{s.devices}</span>,
    },
    {
      id: 'online',
      header: t('AnalyticsPage.traffic.siteColumns.online'),
      cell: (s) => (
        <span className="text-success font-medium tabular-nums">{s.online}</span>
      ),
    },
    {
      id: 'offline',
      header: t('AnalyticsPage.traffic.siteColumns.offline'),
      cell: (s) => (
        <span className={cn('tabular-nums', s.offline > 0 ? 'text-destructive font-medium' : 'text-muted-foreground')}>
          {s.offline}
        </span>
      ),
    },
    {
      id: 'health',
      header: t('AnalyticsPage.traffic.siteColumns.health'),
      cell: (s) => (
        <Badge
          variant={s.health >= 80 ? 'default' : s.health >= 60 ? 'secondary' : 'destructive'}
          className="font-mono tabular-nums"
        >
          {s.health}%
        </Badge>
      ),
    },
  ];

  return (
    <div className="space-y-6">
      <StatsGrid columns={4} stats={stats} />

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <ChartCard
          title={t('AnalyticsPage.traffic.portStatus.title')}
          description={t('AnalyticsPage.traffic.portStatus.description', { count: p.total })}
          isEmpty={p.total === 0}
          emptyText={t('AnalyticsPage.traffic.portStatus.empty')}
        >
          <MiniPie data={portStatusData} total={p.total} label={t('AnalyticsPage.traffic.portsLabel')} />
        </ChartCard>

        <ChartCard
          title={t('AnalyticsPage.traffic.trafficBreakdown.title')}
          description={t('AnalyticsPage.traffic.trafficBreakdown.description')}
          isEmpty={trafficCompare.every((tc) => tc.bytes === 0)}
          emptyText={t('AnalyticsPage.traffic.trafficBreakdown.empty')}
        >
          <div className="h-56">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={trafficCompare}>
                <CartesianGrid strokeDasharray="3 3" className="stroke-border" vertical={false} />
                <XAxis dataKey="name" tick={{ fontSize: 10 }} tickLine={false} axisLine={false} />
                <YAxis
                  tick={{ fontSize: 10 }}
                  tickLine={false}
                  axisLine={false}
                  tickFormatter={(v) => formatBytes(v, 0)}
                />
                <Tooltip
                  contentStyle={tooltipStyle}
                  formatter={(v) => [formatBytes(Number(v)), t('AnalyticsPage.traffic.bytesLabel')]}
                />
                <Bar dataKey="bytes" name={t('AnalyticsPage.traffic.trafficLabel')} radius={[4, 4, 0, 0]}>
                  {trafficCompare.map((_, i) => (
                    <Cell key={i} fill={CHART_COLORS[i % CHART_COLORS.length]} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </ChartCard>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <ChartCard
          title={t('AnalyticsPage.traffic.poeBudget.title')}
          description={t('AnalyticsPage.traffic.poeBudget.description', { count: p.poe_ports })}
        >
          <div className="flex flex-col items-center py-4">
            <Zap
              className={cn(
                'h-16 w-16 mb-3',
                p.total_poe_watts > 0 ? 'text-warning' : 'text-muted-foreground/30',
              )}
            />
            <span className="text-4xl font-bold tabular-nums">{p.total_poe_watts}</span>
            <span className="text-sm text-muted-foreground mt-1">{t('AnalyticsPage.traffic.poeBudget.wattsConsumed')}</span>
          </div>
        </ChartCard>

        <ChartCard
          title={t('AnalyticsPage.traffic.portErrors.title')}
          description={p.total_errors > 0 ? t('AnalyticsPage.traffic.portErrors.recentDetected') : t('AnalyticsPage.traffic.portErrors.healthy')}
        >
          <div className="flex flex-col items-center py-4">
            {p.total_errors > 0 ? (
              <>
                <AlertTriangle className="h-16 w-16 mb-3 text-destructive/70" />
                <span className="text-4xl font-bold text-destructive tabular-nums">{p.total_errors}</span>
                <span className="text-sm text-muted-foreground mt-1">{t('AnalyticsPage.traffic.portErrors.totalErrors')}</span>
              </>
            ) : (
              <>
                <CheckCircle className="h-16 w-16 mb-3 text-success/40" />
                <span className="text-sm text-muted-foreground">{t('AnalyticsPage.traffic.portErrors.noErrorsDetected')}</span>
              </>
            )}
          </div>
        </ChartCard>
      </div>

      {/* Site overview · DataTable in embedded mode so it lives inside our outer Card */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base">{t('AnalyticsPage.traffic.siteOverview.title')}</CardTitle>
          <CardDescription className="text-xs">
            {t('AnalyticsPage.traffic.siteOverview.description')}
          </CardDescription>
        </CardHeader>
        <CardContent noOffset className="pt-0">
          <DataTable
            data={d.sites as SiteRow[]}
            columns={siteColumns}
            isLoading={false}
            searchable={false}
            embedded
            itemName={t('AnalyticsPage.traffic.siteOverview.itemName')}
            getRowId={(row) => row.id}
          />
        </CardContent>
      </Card>
    </div>
  );
}

// ─── Skeleton ─────────────────────────────────────────────────────────────────

function AnalyticsSkeleton() {
  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {Array.from({ length: 4 }).map((_, i) => (
          <Skeleton key={i} className="h-24 rounded-xl" />
        ))}
      </div>
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {Array.from({ length: 4 }).map((_, i) => (
          <Skeleton key={i} className="h-24 rounded-xl" />
        ))}
      </div>
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <Skeleton className="h-72 rounded-xl" />
        <Skeleton className="h-72 rounded-xl lg:col-span-2" />
      </div>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Skeleton className="h-72 rounded-xl" />
        <Skeleton className="h-72 rounded-xl" />
      </div>
    </div>
  );
}

// ─── MAIN PAGE ───────────────────────────────────────────────────────────────

export default function AnalyticsPage() {
  const { t } = useTranslation('analytics');
  const [timeRange, setTimeRange] = useState('1D');
  const selectedSiteId = useSiteStore((s) => s.selectedSiteId);
  const hours = TIME_RANGES.find((r) => r.value === timeRange)?.hours ?? 24;

  const { data, isLoading, isError, refetch, isFetching } = useQuery({
    queryKey: ['enterprise-analytics', hours, { siteId: selectedSiteId }],
    queryFn: async () => {
      // Pass siteId so the global site filter actually scopes the response
      const r = await analyticsApi.getEnterpriseAnalytics(hours, selectedSiteId || undefined);
      return r.data as EnterpriseAnalytics;
    },
    refetchInterval: 60000,
    staleTime: 30000,
  });

  const subtitle = data
    ? t('AnalyticsPage.subtitle.updated', {
        timestamp: format(new Date(data.timestamp), 'MMM d, HH:mm'),
        window: TIME_RANGES.find((r) => r.value === timeRange)?.label,
      })
    : t('AnalyticsPage.subtitle.default');

  // Tabs are URL-deep-linked via the `/analytics/:tab` route registered in App.tsx
  const tabs: PageTab[] = [
    {
      value: 'overview',
      label: (
        <span className="inline-flex items-center gap-1.5">
          <BarChart3 className="h-3.5 w-3.5" /> {t('AnalyticsPage.tabs.overview')}
        </span>
      ),
      content: data ? <OverviewTab d={data} /> : <AnalyticsSkeleton />,
    },
    {
      value: 'insights',
      label: (
        <span className="inline-flex items-center gap-1.5">
          <TrendingUp className="h-3.5 w-3.5" /> {t('AnalyticsPage.tabs.insights')}
        </span>
      ),
      content: data ? <InsightsTab d={data} /> : <AnalyticsSkeleton />,
    },
    {
      value: 'wifi',
      label: (
        <span className="inline-flex items-center gap-1.5">
          <Wifi className="h-3.5 w-3.5" /> {t('AnalyticsPage.tabs.wifi')}
        </span>
      ),
      content: data ? <WifiTab d={data} /> : <AnalyticsSkeleton />,
    },
    {
      value: 'clients',
      label: (
        <span className="inline-flex items-center gap-1.5">
          <Users className="h-3.5 w-3.5" /> {t('AnalyticsPage.tabs.clients')}
        </span>
      ),
      content: data ? <ClientsTab d={data} /> : <AnalyticsSkeleton />,
    },
    {
      value: 'traffic',
      label: (
        <span className="inline-flex items-center gap-1.5">
          <Activity className="h-3.5 w-3.5" /> {t('AnalyticsPage.tabs.traffic')}
        </span>
      ),
      content: data ? <TrafficTab d={data} /> : <AnalyticsSkeleton />,
    },
  ];

  return (
    <div className="space-y-6">
      <PageHeader
        icon={BarChart3}
        title={t('AnalyticsPage.title')}
        description={subtitle}
        onRefresh={() => refetch()}
        refreshing={isFetching}
        actions={<TimeRangeSelector value={timeRange} onChange={setTimeRange} />}
      />

      {isError && (
        <ErrorState message={t('AnalyticsPage.errors.loadFailed')} onRetry={() => refetch()} />
      )}

      {!isError && isLoading && !data && <AnalyticsSkeleton />}

      {!isError && (data || !isLoading) && (
        <PageTabs basePath="/analytics" tabs={tabs} />
      )}
    </div>
  );
}

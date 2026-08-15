// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Enterprise Logs & Audit Trail
 *
 * THE unified chronological stream for everything that happened in the system.
 * Two focused tabs:
 *   1. Overview  - Bird-eye system health (KPIs, charts, needs-attention with nav links)
 *   2. All Logs  - Unified audit+security log stream (search, filters, live, export)
 *
 * Other domains own their own pages:
 *   /security   - Security events, audit logs, failed logins, IP blocks, anomalies
 *   /incidents  - Incident lifecycle, correlation rules
 *   /alerts     - Alert triage & acknowledge
 */
import React, { useState, useMemo, useCallback, useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { useQuery } from '@tanstack/react-query';
import { useSiteStore } from '@/stores/siteStore';
import { useNavigate, useParams, useSearchParams } from 'react-router-dom';
import { PageHeader } from '@/components/layout';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import {
  ScrollText, Download, RefreshCw, AlertTriangle, AlertCircle,
  Info, CheckCircle, Bug, Clock, Server, User, Globe, Database,
  Shield, Activity, TrendingUp, ChevronDown, ChevronRight,
  Copy, Pause, Play, X, Eye, ShieldAlert, Flame, Lock,
  HeartPulse, Gauge, ArrowUpRight, ArrowDownRight,
  LayoutDashboard, List, Ban, Skull, Zap, Radio,
  Fingerprint, ExternalLink, CheckCircle2,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { SearchBar } from '@/components/ui/search-bar';
import { useToast } from '@/hooks/use-toast';
import { api } from '@/lib/api';
import { format, formatDistanceToNow, parseISO, isValid } from 'date-fns';

// ----------------------------------------------------------------
// Constants & Types
// ----------------------------------------------------------------

const LOG_LEVELS = {
  debug:    { labelKey: 'levels.debug',    color: 'bg-muted-foreground', textColor: 'text-muted-foreground', icon: Bug,          bgLight: 'bg-muted' },
  info:     { labelKey: 'levels.info',     color: 'bg-primary',          textColor: 'text-primary',          icon: Info,         bgLight: 'bg-primary/10' },
  warning:  { labelKey: 'levels.warning',  color: 'bg-amber-500',        textColor: 'text-amber-500',        icon: AlertTriangle, bgLight: 'bg-amber-500/10' },
  error:    { labelKey: 'levels.error',    color: 'bg-destructive',      textColor: 'text-destructive',      icon: AlertCircle,  bgLight: 'bg-destructive/10' },
  critical: { labelKey: 'levels.critical', color: 'bg-red-700',          textColor: 'text-red-700',          icon: Skull,        bgLight: 'bg-red-700/10' },
  success:  { labelKey: 'levels.success',  color: 'bg-green-500',        textColor: 'text-green-500',        icon: CheckCircle,  bgLight: 'bg-green-500/10' },
} as const;

const LOG_SOURCES = {
  api:       { labelKey: 'sources.api',       icon: Globe,    color: 'text-blue-500' },
  auth:      { labelKey: 'sources.auth',      icon: Shield,   color: 'text-purple-500' },
  device:    { labelKey: 'sources.device',    icon: Server,   color: 'text-cyan-500' },
  database:  { labelKey: 'sources.database',  icon: Database, color: 'text-amber-500' },
  system:    { labelKey: 'sources.system',    icon: Activity, color: 'text-green-500' },
  user:      { labelKey: 'sources.user',      icon: User,     color: 'text-indigo-500' },
  network:   { labelKey: 'sources.network',   icon: Globe,    color: 'text-teal-500' },
  scheduler: { labelKey: 'sources.scheduler', icon: Clock,    color: 'text-orange-500' },
} as const;

const TIME_RANGES = [
  { value: '1h',  labelKey: 'timeRanges.1h',  hours: 1 },
  { value: '6h',  labelKey: 'timeRanges.6h',  hours: 6 },
  { value: '24h', labelKey: 'timeRanges.24h', hours: 24 },
  { value: '7d',  labelKey: 'timeRanges.7d',  hours: 168 },
  { value: '30d', labelKey: 'timeRanges.30d', hours: 720 },
];

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'text-red-500 bg-red-500/10 border-red-500/30',
  high:     'text-orange-500 bg-orange-500/10 border-orange-500/30',
  medium:   'text-amber-500 bg-amber-500/10 border-amber-500/30',
  low:      'text-blue-500 bg-blue-500/10 border-blue-500/30',
  error:    'text-red-500 bg-red-500/10 border-red-500/30',
  info:     'text-muted-foreground bg-muted border-border',
};

// ----------------------------------------------------------------
// Interfaces
// ----------------------------------------------------------------

interface LogEntry {
  id: string;
  timestamp: string;
  level: string;
  source: string;
  message: string;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  details?: Record<string, any>;
  user_id?: string;
  user_email?: string;
  ip_address?: string;
  request_id?: string;
  duration_ms?: number;
  site_id?: string;
  site_name?: string;
  device_id?: string;
  device_name?: string;
  stack_trace?: string;
}

interface LogListResponse {
  items: LogEntry[];
  total: number;
  page: number;
  per_page: number;
  pages: number;
}

interface HourlyCount { hour: string; count: number; errors: number }

interface LogStatsResponse {
  total: number;
  by_level: Record<string, number>;
  by_source: Record<string, number>;
  by_hour: HourlyCount[];
  error_rate: number;
  avg_duration_ms: number | null;
}

interface SystemHealth {
  total_events_24h: number;
  total_events_7d: number;
  error_count_24h: number;
  warning_count_24h: number;
  critical_count_24h: number;
  success_rate: number;
  failed_logins_24h: number;
  active_ip_blocks: number;
  unresolved_anomalies: number;
  open_incidents: number;
  event_trend: number;
  error_trend: number;
  needs_attention: { type: string; id: string; title: string; severity: string; timestamp: string }[];
  avg_response_ms: number | null;
  p95_response_ms: number | null;
  daily_histogram: { date: string; total: number; errors: number; warnings: number }[];
}

// ----------------------------------------------------------------
// API functions
// ----------------------------------------------------------------

async function fetchLogs(params: {
  page?: number; per_page?: number; level?: string; source?: string;
  search?: string; start_date?: string; site_id?: string;
}): Promise<LogListResponse> {
  const sp = new URLSearchParams();
  if (params.page)       sp.set('page', params.page.toString());
  if (params.per_page)   sp.set('per_page', params.per_page.toString());
  if (params.level)      sp.set('level', params.level);
  if (params.source)     sp.set('source', params.source);
  if (params.search)     sp.set('search', params.search);
  if (params.start_date) sp.set('start_date', params.start_date);
  if (params.site_id)    sp.set('site_id', params.site_id);
  return (await api.get(`/logs?${sp.toString()}`)).data;
}

async function fetchStats(hours: number, siteId?: string): Promise<LogStatsResponse> {
  const sp = new URLSearchParams();
  sp.set('hours', hours.toString());
  if (siteId) sp.set('site_id', siteId);
  return (await api.get(`/logs/stats?${sp.toString()}`)).data;
}

async function fetchHealth(): Promise<SystemHealth> {
  return (await api.get('/logs/health')).data;
}

// ----------------------------------------------------------------
// Shared sub-components
// ----------------------------------------------------------------

function MetricCard({
  title, value, icon: Icon, color = 'primary', subtitle, trend, className, onClick,
}: {
  title: string; value: string | number; icon: React.ElementType;
  color?: 'primary' | 'success' | 'warning' | 'error' | 'muted';
  subtitle?: string; trend?: number; className?: string; onClick?: () => void;
}) {
  const { t } = useTranslation('logs');
  const palette: Record<string, string> = {
    primary: 'bg-primary/10 text-primary',
    success: 'bg-green-500/10 text-green-500',
    warning: 'bg-amber-500/10 text-amber-500',
    error:   'bg-red-500/10 text-red-500',
    muted:   'bg-muted text-muted-foreground',
  };
  return (
    <Card className={cn('border-border/50', onClick && 'cursor-pointer hover:border-primary/40 transition-colors', className)} onClick={onClick}>
      <CardContent noOffset className="p-4">
        <div className="flex items-center justify-between">
          <div className="min-w-0">
            <p className="text-[11px] font-medium text-muted-foreground uppercase tracking-wider truncate">{title}</p>
            <p className="text-2xl font-bold mt-0.5">{typeof value === 'number' ? value.toLocaleString() : value}</p>
            {subtitle && <p className="text-xs text-muted-foreground mt-0.5">{subtitle}</p>}
            {trend !== undefined && trend !== 0 && (
              <div className={cn('flex items-center gap-1 text-xs mt-0.5',
                trend > 0 ? 'text-red-500' : 'text-green-500'
              )}>
                {trend > 0 ? <ArrowUpRight className="h-3 w-3" /> : <ArrowDownRight className="h-3 w-3" />}
                {t('LogsPage.metric.trendVsPrior', { pct: Math.abs(trend) })}
              </div>
            )}
          </div>
          <div className={cn('p-2.5 rounded-xl flex-shrink-0', palette[color])}>
            <Icon className="h-5 w-5" />
          </div>
        </div>
        {onClick && (
          <div className="flex items-center gap-1 text-[10px] text-muted-foreground mt-2 pt-2 border-t border-border/30">
            <ExternalLink className="h-3 w-3" /> {t('LogsPage.metric.viewDetails')}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function LevelBadge({ level }: { level: string }) {
  const { t } = useTranslation('logs');
  const config = LOG_LEVELS[level as keyof typeof LOG_LEVELS];
  if (!config) return <Badge variant="outline" className="text-[10px]">{level}</Badge>;
  const LIcon = config.icon;
  return (
    <Badge variant="outline" className={cn('gap-1 text-[10px] font-medium border-transparent', config.textColor, config.bgLight)}>
      <LIcon className="h-3 w-3" />
      {t(`LogsPage.${config.labelKey}`)}
    </Badge>
  );
}

function SourceBadge({ source }: { source: string }) {
  const { t } = useTranslation('logs');
  const config = LOG_SOURCES[source as keyof typeof LOG_SOURCES];
  if (!config) return <Badge variant="outline" className="text-[10px]">{source}</Badge>;
  const SIcon = config.icon;
  return (
    <Badge variant="outline" className={cn('gap-1 text-[10px] font-medium bg-transparent', config.color)}>
      <SIcon className="h-3 w-3" />
      {t(`LogsPage.${config.labelKey}`)}
    </Badge>
  );
}

function SeverityBadge({ severity }: { severity: string }) {
  const cls = SEVERITY_COLORS[severity] || SEVERITY_COLORS.info;
  return (
    <Badge variant="outline" className={cn('text-[10px] font-semibold uppercase', cls)}>
      {severity}
    </Badge>
  );
}

/** 7-day bar chart with errors overlay */
function DailyChart({ data, height = 100 }: { data: { date: string; total: number; errors: number; warnings?: number }[]; height?: number }) {
  const { t } = useTranslation('logs');
  if (!data?.length) return <div className="text-sm text-muted-foreground text-center py-4">{t('LogsPage.charts.noData')}</div>;
  const maxCount = Math.max(...data.map(d => d.total), 1);
  return (
    <div className="flex items-end gap-1.5" style={{ height }}>
      {data.map((item, i) => {
        const barH = (item.total / maxCount) * height;
        const errH = (item.errors / maxCount) * height;
        const warnH = ((item.warnings || 0) / maxCount) * height;
        const dayLabel = (item.date ?? '').slice(5);
        return (
          <div key={i} className="flex-1 flex flex-col items-center group relative">
            <div className="absolute -top-7 left-1/2 -translate-x-1/2 bg-popover border border-border rounded px-2 py-0.5 text-xs font-mono opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none whitespace-nowrap z-10">
              {t('LogsPage.charts.eventsErrors', { events: item.total, errors: item.errors })}
            </div>
            <div className="w-full flex flex-col-reverse relative" style={{ height }}>
              <div className="w-full bg-primary/20 rounded-t transition-all group-hover:bg-primary/40" style={{ height: barH }} />
              {errH > 0 && (
                <div className="w-full bg-red-500/50 absolute bottom-0 rounded-t" style={{ height: errH }} />
              )}
              {warnH > 0 && (
                <div className="w-full bg-amber-500/30 absolute rounded-t" style={{ height: warnH, bottom: errH }} />
              )}
            </div>
            <span className="text-[9px] text-muted-foreground mt-1 opacity-60 group-hover:opacity-100">{dayLabel}</span>
          </div>
        );
      })}
    </div>
  );
}

/** Hourly bar chart */
function HourlyChart({ data, height = 60 }: { data: HourlyCount[]; height?: number }) {
  const { t } = useTranslation('logs');
  if (!data?.length) return <div className="text-sm text-muted-foreground text-center py-4">{t('LogsPage.charts.noData')}</div>;
  const maxCount = Math.max(...data.map(d => d.count), 1);
  return (
    <div className="flex items-end gap-0.5" style={{ height }}>
      {data.map((item, i) => {
        const barH = (item.count / maxCount) * height;
        const errH = (item.errors / maxCount) * height;
        return (
          <div key={i} className="flex-1 group relative">
            <div className="absolute -top-6 left-1/2 -translate-x-1/2 bg-popover border border-border rounded px-1.5 py-0.5 text-[10px] font-mono opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none whitespace-nowrap z-10">
              {item.count}
            </div>
            <div className="w-full flex flex-col-reverse" style={{ height }}>
              <div className="w-full bg-primary/30 rounded-t transition-all group-hover:bg-primary/50" style={{ height: barH }} />
              {errH > 0 && <div className="w-full bg-red-500/50 absolute bottom-0 rounded-t" style={{ height: errH }} />}
            </div>
          </div>
        );
      })}
    </div>
  );
}

/** Level distribution horizontal bars */
function LevelDistribution({ data }: { data: Record<string, number> }) {
  const { t } = useTranslation('logs');
  const safeData = data ?? {};
  const total = Object.values(safeData).reduce((a, b) => a + b, 0) || 1;
  const ordered = ['critical', 'error', 'warning', 'info', 'success', 'debug'];
  return (
    <div className="space-y-1.5">
      {ordered.filter(k => (safeData[k] || 0) > 0).map(key => {
        const config = LOG_LEVELS[key as keyof typeof LOG_LEVELS];
        if (!config) return null;
        const count = safeData[key] || 0;
        const pct = (count / total) * 100;
        return (
          <div key={key} className="flex items-center gap-2">
            <span className={cn('text-[10px] font-medium w-14 text-right', config.textColor)}>{t(`LogsPage.${config.labelKey}`)}</span>
            <div className="flex-1 h-2.5 rounded-full bg-muted overflow-hidden">
              <div className={cn('h-full rounded-full transition-all', config.color)} style={{ width: pct+'%' }} />
            </div>
            <span className="text-[10px] text-muted-foreground w-10 text-right font-mono">{count}</span>
          </div>
        );
      })}
    </div>
  );
}

// ================================================================
// Tab 1 · Overview (Bird-Eye Health Dashboard)
// ================================================================

function OverviewTab() {
  const { t } = useTranslation('logs');
  const navigate = useNavigate();
  // Overview is intrinsically org-scoped: several metrics (FailedLoginRecord,
  // SecurityEventRecord) have no site_id column to filter on, so /logs/health
  // returns org-wide data regardless of the selected site. Keep the global site
  // control out of this queryKey so it doesn't imply per-site filtering it
  // can't do (mirrors the security-events / collector approach).
  const { data: health, isLoading, isError } = useQuery({
    queryKey: ['logs-health'],
    queryFn: fetchHealth,
    refetchInterval: 30000,
  });

  if (isError) {
    return (
      <div className="rounded-md bg-destructive/10 p-3 text-sm text-destructive">
        {t('LogsPage.overview.loadError')}
      </div>
    );
  }

  if (isLoading || !health) {
    return (
      <div className="flex items-center justify-center py-20 text-muted-foreground">
        <RefreshCw className="h-6 w-6 animate-spin mr-2" /> {t('LogsPage.overview.loading')}
      </div>
    );
  }

  const attentionItems = health.needs_attention || [];

  // Route helpers for attention items
  const navForType = (type: string) => {
    switch (type) {
      case 'security': return '/alerts';
      case 'incident': return '/incidents';
      case 'anomaly':  return '/security';
      default:         return undefined;
    }
  };

  return (
    <div className="space-y-6">
      {/* System Pulse · top KPIs */}
      <div className="grid grid-cols-2 lg:grid-cols-5 gap-3">
        <MetricCard title={t('LogsPage.overview.kpi.events24h')} value={health.total_events_24h} icon={Activity}
          trend={health.event_trend} subtitle={t('LogsPage.overview.kpi.inSevenDays', { count: (health.total_events_7d ?? 0).toLocaleString() })} />
        <MetricCard title={t('LogsPage.overview.kpi.errors')} value={health.error_count_24h} icon={AlertCircle}
          color="error" trend={health.error_trend} />
        <MetricCard title={t('LogsPage.overview.kpi.warnings')} value={health.warning_count_24h} icon={AlertTriangle} color="warning" />
        <MetricCard title={t('LogsPage.overview.kpi.critical')} value={health.critical_count_24h} icon={Skull}
          color={health.critical_count_24h > 0 ? 'error' : 'muted'} />
        <MetricCard title={t('LogsPage.overview.kpi.successRate')} value={health.success_rate+'%'} icon={Gauge}
          color={health.success_rate >= 99 ? 'success' : health.success_rate >= 95 ? 'warning' : 'error'} />
      </div>

      {/* Quick-nav cards · link to dedicated pages */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <MetricCard title={t('LogsPage.overview.kpi.openIncidents')} value={health.open_incidents} icon={Flame}
          color={health.open_incidents > 0 ? 'error' : 'success'}
          onClick={() => navigate('/incidents')} />
        <MetricCard title={t('LogsPage.overview.kpi.failedLogins24h')} value={health.failed_logins_24h} icon={Lock}
          color={health.failed_logins_24h > 10 ? 'error' : health.failed_logins_24h > 0 ? 'warning' : 'success'}
          onClick={() => navigate('/security')} />
        <MetricCard title={t('LogsPage.overview.kpi.ipBlocksActive')} value={health.active_ip_blocks} icon={Ban}
          color={health.active_ip_blocks > 0 ? 'warning' : 'muted'}
          onClick={() => navigate('/security')} />
        <MetricCard title={t('LogsPage.overview.kpi.avgResponse')} value={health.avg_response_ms ? Math.round(health.avg_response_ms)+'ms' : t('LogsPage.common.na')} icon={Zap}
          color="primary" subtitle={health.p95_response_ms ? t('LogsPage.overview.kpi.p95Subtitle', { ms: Math.round(health.p95_response_ms) }) : undefined} />
      </div>

      {/* 7-Day Trend + Needs Attention */}
      <div className="grid lg:grid-cols-5 gap-4">
        <Card className="border-border/50 lg:col-span-3">
          <CardHeader className="pb-2">
            <div className="flex items-center justify-between">
              <div>
                <CardTitle className="text-base flex items-center gap-2"><HeartPulse className="h-4 w-4 text-primary" /> {t('LogsPage.overview.activity.title')}</CardTitle>
                <CardDescription>{t('LogsPage.overview.activity.description')}</CardDescription>
              </div>
              <div className="flex items-center gap-3 text-xs">
                <span className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded bg-primary/30" /> {t('LogsPage.overview.activity.legendTotal')}</span>
                <span className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded bg-red-500/50" /> {t('LogsPage.overview.activity.legendErrors')}</span>
                <span className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded bg-amber-500/30" /> {t('LogsPage.overview.activity.legendWarnings')}</span>
              </div>
            </div>
          </CardHeader>
          <CardContent>
            <DailyChart data={health.daily_histogram} height={120} />
          </CardContent>
        </Card>

        <Card className="border-border/50 lg:col-span-2">
          <CardHeader className="pb-2">
            <CardTitle className="text-base flex items-center gap-2">
              <Eye className="h-4 w-4 text-amber-500" />
              {t('LogsPage.overview.attention.title')}
              {attentionItems.length > 0 && (
                <Badge className="bg-red-500/10 text-red-500 border-red-500/30 ml-auto" variant="outline">{attentionItems.length}</Badge>
              )}
            </CardTitle>
            <CardDescription>{t('LogsPage.overview.attention.description')}</CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            {attentionItems.length === 0 ? (
              <div className="p-6 text-center text-muted-foreground text-sm">
                <CheckCircle2 className="h-8 w-8 mx-auto mb-2 text-green-500 opacity-50" />
                {t('LogsPage.overview.attention.allClear')}
              </div>
            ) : (
              <div className="max-h-[280px] overflow-y-auto divide-y divide-border/50">
                {attentionItems.map((item, i) => {
                  const typeIcons: Record<string, React.ElementType> = {
                    security: ShieldAlert, error: AlertCircle, anomaly: Fingerprint, incident: Flame,
                  };
                  const TIcon = typeIcons[item.type] || AlertTriangle;
                  const sevColor = SEVERITY_COLORS[item.severity] || '';
                  const dest = navForType(item.type);
                  return (
                    <div key={i}
                      className={cn('flex items-start gap-3 px-4 py-2.5 hover:bg-muted/30 transition-colors', dest && 'cursor-pointer')}
                      onClick={dest ? () => navigate(dest) : undefined}
                    >
                      <div className={cn('p-1.5 rounded-lg mt-0.5', sevColor)}>
                        <TIcon className="h-3.5 w-3.5" />
                      </div>
                      <div className="min-w-0 flex-1">
                        <p className="text-sm font-medium truncate">{item.title}</p>
                        <p className="text-[11px] text-muted-foreground mt-0.5">
                          {t(`LogsPage.attentionTypes.${item.type}`, { defaultValue: item.type })} {item.timestamp && isValid(parseISO(item.timestamp)) ? formatDistanceToNow(parseISO(item.timestamp), { addSuffix: true }) : ''}
                        </p>
                      </div>
                      <SeverityBadge severity={item.severity} />
                      {dest && <ExternalLink className="h-3.5 w-3.5 text-muted-foreground/50 mt-1 flex-shrink-0" />}
                    </div>
                  );
                })}
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Summary row · performance + system pulse + quick links */}
      <div className="grid md:grid-cols-3 gap-4">
        <Card className="border-border/50">
          <CardHeader className="pb-2">
            <CardTitle className="text-base flex items-center gap-2"><Zap className="h-4 w-4 text-primary" /> {t('LogsPage.overview.performance.title')}</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-sm text-muted-foreground">{t('LogsPage.overview.performance.avgResponse')}</span>
                <span className={cn('text-sm font-medium font-mono', health.avg_response_ms && health.avg_response_ms > 500 ? 'text-amber-500' : 'text-green-500')}>
                  {health.avg_response_ms ? Math.round(health.avg_response_ms)+'ms' : t('LogsPage.common.na')}
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-muted-foreground">{t('LogsPage.overview.performance.p95Response')}</span>
                <span className={cn('text-sm font-medium font-mono', health.p95_response_ms && health.p95_response_ms > 1000 ? 'text-red-500' : 'text-green-500')}>
                  {health.p95_response_ms ? Math.round(health.p95_response_ms)+'ms' : t('LogsPage.common.na')}
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-muted-foreground">{t('LogsPage.overview.performance.successRate')}</span>
                <span className={cn('text-sm font-medium', health.success_rate >= 99 ? 'text-green-500' : health.success_rate >= 95 ? 'text-amber-500' : 'text-red-500')}>
                  {health.success_rate}%
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-muted-foreground">{t('LogsPage.overview.performance.errorRate')}</span>
                <span className="text-sm font-medium text-muted-foreground">
                  {health.total_events_24h > 0 ? ((health.error_count_24h / health.total_events_24h) * 100).toFixed(1) : '0.0'}%
                </span>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="border-border/50">
          <CardHeader className="pb-2">
            <CardTitle className="text-base flex items-center gap-2"><Radio className="h-4 w-4 text-primary" /> {t('LogsPage.overview.pulse.title')}</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-sm text-muted-foreground">{t('LogsPage.overview.pulse.events24h')}</span>
                <span className="text-sm font-medium">{(health.total_events_24h ?? 0).toLocaleString()}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-muted-foreground">{t('LogsPage.overview.pulse.events7d')}</span>
                <span className="text-sm font-medium">{(health.total_events_7d ?? 0).toLocaleString()}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-muted-foreground">{t('LogsPage.overview.pulse.unresolvedAnomalies')}</span>
                <span className={cn('text-sm font-medium', health.unresolved_anomalies > 0 ? 'text-amber-500' : 'text-green-500')}>{health.unresolved_anomalies}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-muted-foreground">{t('LogsPage.overview.pulse.activeIpBlocks')}</span>
                <span className="text-sm font-medium">{health.active_ip_blocks}</span>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="border-border/50">
          <CardHeader className="pb-2">
            <CardTitle className="text-base flex items-center gap-2"><ExternalLink className="h-4 w-4 text-primary" /> {t('LogsPage.overview.quickLinks.title')}</CardTitle>
            <CardDescription>{t('LogsPage.overview.quickLinks.description')}</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {[
                { label: t('LogsPage.overview.quickLinks.securityOps'), icon: Shield, path: '/security', count: health.failed_logins_24h + health.active_ip_blocks + health.unresolved_anomalies },
                { label: t('LogsPage.overview.quickLinks.incidentMgmt'), icon: Flame, path: '/incidents', count: health.open_incidents },
                { label: t('LogsPage.overview.quickLinks.alertTriage'), icon: AlertTriangle, path: '/alerts' },
                { label: t('LogsPage.overview.quickLinks.analyticsDashboard'), icon: Activity, path: '/analytics' },
              ].map(link => (
                <button key={link.path}
                  onClick={() => navigate(link.path)}
                  className="w-full flex items-center gap-3 px-3 py-2 rounded-lg hover:bg-muted/50 transition-colors text-left group"
                >
                  <link.icon className="h-4 w-4 text-muted-foreground group-hover:text-primary transition-colors" />
                  <span className="text-sm flex-1">{link.label}</span>
                  {link.count !== undefined && link.count > 0 && (
                    <Badge variant="outline" className="text-[10px] bg-red-500/10 text-red-500 border-red-500/30">{link.count}</Badge>
                  )}
                  <ChevronRight className="h-3.5 w-3.5 text-muted-foreground/40 group-hover:text-muted-foreground transition-colors" />
                </button>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

// ================================================================
// LogEntryRow · expandable log row
// ================================================================

function LogEntryRow({ entry }: { entry: LogEntry }) {
  const { t } = useTranslation('logs');
  const [expanded, setExpanded] = useState(false);

  return (
    <div className={cn('border-b border-border/30 transition-colors', expanded ? 'bg-muted/20' : 'hover:bg-muted/10')}>
      <button
        className="w-full flex items-center gap-3 px-4 py-2 text-left"
        onClick={() => setExpanded(!expanded)}
      >
        {expanded ? <ChevronDown className="h-3.5 w-3.5 text-muted-foreground flex-shrink-0" /> : <ChevronRight className="h-3.5 w-3.5 text-muted-foreground flex-shrink-0" />}
        <span className="text-[11px] text-muted-foreground font-mono w-[140px] flex-shrink-0">
          {entry.timestamp && isValid(parseISO(entry.timestamp)) ? format(parseISO(entry.timestamp), 'MMM dd HH:mm:ss') : ''}
        </span>
        <LevelBadge level={entry.level} />
        <SourceBadge source={entry.source} />
        <span className="text-sm truncate flex-1 min-w-0">{entry.message}</span>
        {entry.duration_ms && (
          <span className="text-[10px] text-muted-foreground font-mono flex-shrink-0">{Math.round(entry.duration_ms)}ms</span>
        )}
      </button>
      {expanded && (
        <div className="px-4 pb-3 pl-11 space-y-2">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-xs">
            {entry.user_email && (
              <div><span className="text-muted-foreground">{t('LogsPage.entry.user')}</span> <span className="font-medium">{entry.user_email}</span></div>
            )}
            {entry.ip_address && (
              <div><span className="text-muted-foreground">{t('LogsPage.entry.ip')}</span> <span className="font-mono">{entry.ip_address}</span></div>
            )}
            {entry.request_id && (
              <div className="flex items-center gap-1">
                <span className="text-muted-foreground">{t('LogsPage.entry.request')}</span>
                <span className="font-mono text-[10px] truncate max-w-[120px]">{entry.request_id}</span>
                <button onClick={(e) => { e.stopPropagation(); navigator.clipboard.writeText(entry.request_id!); }}
                  className="text-muted-foreground hover:text-foreground"><Copy className="h-3 w-3" /></button>
              </div>
            )}
            {entry.device_name && (
              <div><span className="text-muted-foreground">{t('LogsPage.entry.device')}</span> <span className="font-medium">{entry.device_name}</span></div>
            )}
            {entry.site_name && (
              <div><span className="text-muted-foreground">{t('LogsPage.entry.site')}</span> <span className="font-medium">{entry.site_name}</span></div>
            )}
          </div>
          {entry.details && Object.keys(entry.details).length > 0 && (
            <div className="bg-muted/50 rounded-lg p-3 font-mono text-[11px] max-h-[200px] overflow-auto">
              <pre className="whitespace-pre-wrap">{JSON.stringify(entry.details, null, 2)}</pre>
            </div>
          )}
          {entry.stack_trace && (
            <div className="bg-red-500/5 border border-red-500/20 rounded-lg p-3 font-mono text-[11px] text-red-500 max-h-[150px] overflow-auto">
              <pre className="whitespace-pre-wrap">{entry.stack_trace}</pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ================================================================
// Tab 2 · All Logs (Unified Stream)
// ================================================================

function AllLogsTab({ initialLevel, initialSource, initialSearch }: {
  initialLevel?: string | null;
  initialSource?: string | null;
  initialSearch?: string | null;
}) {
  const { t } = useTranslation(['logs', 'common']);
  const { toast } = useToast();
  const selectedSiteId = useSiteStore((s) => s.selectedSiteId);
  const [search, setSearch] = useState(initialSearch || '');
  const [levelFilter, setLevelFilter] = useState<string | null>(initialLevel || null);
  const [sourceFilter, setSourceFilter] = useState<string | null>(initialSource || null);
  const [timeRange, setTimeRange] = useState('24h');
  const [page, setPage] = useState(1);
  const [liveMode, setLiveMode] = useState(false);
  const [exporting, setExporting] = useState<string | null>(null);

  const hours = TIME_RANGES.find(t => t.value === timeRange)?.hours || 24;
  const startDate = useMemo(() => {
    const d = new Date();
    d.setHours(d.getHours() - hours);
    return d.toISOString();
  }, [hours]);

  const { data: logs, isLoading: logsLoading, isError: logsError } = useQuery({
    queryKey: ['logs-list', page, levelFilter, sourceFilter, search, startDate, { siteId: selectedSiteId }],
    queryFn: () => fetchLogs({
      page, per_page: 50,
      level: levelFilter || undefined,
      source: sourceFilter || undefined,
      search: search || undefined,
      start_date: startDate,
      site_id: selectedSiteId || undefined,
    }),
    refetchInterval: liveMode ? 5000 : false,
  });

  const { data: stats } = useQuery({
    queryKey: ['logs-stats', hours, { siteId: selectedSiteId }],
    queryFn: () => fetchStats(hours, selectedSiteId || undefined),
    refetchInterval: liveMode ? 10000 : false,
  });

  // Reset to page 1 whenever the level filter or search query changes.
  useEffect(() => {
    setPage(1);
  }, [levelFilter, search]);

  const handleExport = useCallback(async (fmt: string) => {
    // Mirror the same filter shape the log list sends, so the export
    // honours the active level/source/search/time-range selections.
    const sp = new URLSearchParams();
    if (levelFilter)  sp.set('level', levelFilter);
    if (sourceFilter) sp.set('source', sourceFilter);
    if (search)       sp.set('search', search);
    if (startDate)    sp.set('start_date', startDate);
    if (selectedSiteId) sp.set('site_id', selectedSiteId);

    setExporting(fmt);
    try {
      const resp = await api.get('/logs/export/'+fmt+'?'+sp.toString(), { responseType: 'blob' });
      const url = URL.createObjectURL(resp.data);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'freesdn_logs.'+fmt;
      a.click();
      URL.revokeObjectURL(url);
      toast({ title: t('common:success') });
    } catch (err) {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const detail = (err as any)?.response?.data?.detail;
      toast({
        title: t('common:error'),
        description: detail || t('LogsPage.allLogs.loadError'),
        variant: 'destructive',
      });
    } finally {
      setExporting(null);
    }
  }, [levelFilter, sourceFilter, search, startDate, selectedSiteId, toast, t]);

  return (
    <div className="space-y-4">
      {logsError && (
        <div className="rounded-md bg-destructive/10 p-3 text-sm text-destructive">
          {t('LogsPage.allLogs.loadError')}
        </div>
      )}

      {/* Stats row */}
      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
          <MetricCard title={t('LogsPage.allLogs.stats.totalEvents')} value={stats.total} icon={Activity} />
          <MetricCard title={t('LogsPage.allLogs.stats.errors')} value={(stats.by_level?.error || 0) + (stats.by_level?.critical || 0)}
            icon={AlertCircle} color="error" />
          <MetricCard title={t('LogsPage.allLogs.stats.warnings')} value={stats.by_level?.warning || 0}
            icon={AlertTriangle} color="warning" />
          <MetricCard title={t('LogsPage.allLogs.stats.errorRate')} value={stats.error_rate+'%'}
            icon={TrendingUp} color={stats.error_rate > 5 ? 'error' : stats.error_rate > 1 ? 'warning' : 'success'} />
          <MetricCard title={t('LogsPage.allLogs.stats.avgResponse')} value={stats.avg_duration_ms ? Math.round(stats.avg_duration_ms)+'ms' : t('LogsPage.common.na')}
            icon={Zap} color="primary" />
        </div>
      )}

      {/* Charts row */}
      {stats && (
        <div className="grid md:grid-cols-3 gap-4">
          <Card className="border-border/50 md:col-span-2">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm">{t('LogsPage.allLogs.charts.hourlyActivity')}</CardTitle>
            </CardHeader>
            <CardContent>
              <HourlyChart data={stats.by_hour} height={60} />
            </CardContent>
          </Card>
          <Card className="border-border/50">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm">{t('LogsPage.allLogs.charts.levelDistribution')}</CardTitle>
            </CardHeader>
            <CardContent>
              <LevelDistribution data={stats.by_level} />
            </CardContent>
          </Card>
        </div>
      )}

      {/* Toolbar */}
      <div className="flex flex-wrap items-center gap-2">
        <div className="flex-1 min-w-[200px] max-w-sm">
          <SearchBar value={search} onChange={setSearch} placeholder={t('LogsPage.allLogs.searchPlaceholder')} />
        </div>

        {/* Level filter */}
        <div className="flex gap-1">
          {Object.entries(LOG_LEVELS).map(([key, cfg]) => (
            <button key={key}
              onClick={() => setLevelFilter(levelFilter === key ? null : key)}
              className={cn(
                'px-2 py-1 rounded text-[10px] font-medium transition-colors border',
                levelFilter === key
                  ? cn(cfg.bgLight, cfg.textColor, 'border-current')
                  : 'border-transparent text-muted-foreground hover:bg-muted'
              )}
            >
              {t(`LogsPage.${cfg.labelKey}`)}
            </button>
          ))}
        </div>

        {/* Source filter */}
        <select
          value={sourceFilter || ''}
          onChange={(e) => { setSourceFilter(e.target.value || null); setPage(1); }}
          className="h-8 px-2 rounded border border-border bg-background text-xs"
        >
          <option value="">{t('LogsPage.allLogs.allSources')}</option>
          {Object.entries(LOG_SOURCES).map(([key, cfg]) => (
            <option key={key} value={key}>{t(`LogsPage.${cfg.labelKey}`)}</option>
          ))}
        </select>

        {/* Time range */}
        <select
          value={timeRange}
          onChange={(e) => { setTimeRange(e.target.value); setPage(1); }}
          className="h-8 px-2 rounded border border-border bg-background text-xs"
        >
          {TIME_RANGES.map(tr => (
            <option key={tr.value} value={tr.value}>{t(`LogsPage.${tr.labelKey}`)}</option>
          ))}
        </select>

        {/* Live mode */}
        <Button variant={liveMode ? 'default' : 'outline'} size="sm" className="h-8 gap-1 text-xs"
          onClick={() => setLiveMode(!liveMode)}
        >
          {liveMode ? <><Pause className="h-3 w-3" /> {t('LogsPage.allLogs.live')}</> : <><Play className="h-3 w-3" /> {t('LogsPage.allLogs.live')}</>}
        </Button>

        {/* Export */}
        <div className="flex gap-1">
          <Button variant="outline" size="sm" className="h-8 gap-1 text-xs" disabled={exporting !== null}
            onClick={() => handleExport('json')}>
            {exporting === 'json' ? <RefreshCw className="h-3 w-3 animate-spin" /> : <Download className="h-3 w-3" />} {t('LogsPage.allLogs.exportJson')}
          </Button>
          <Button variant="outline" size="sm" className="h-8 gap-1 text-xs" disabled={exporting !== null}
            onClick={() => handleExport('csv')}>
            {exporting === 'csv' ? <RefreshCw className="h-3 w-3 animate-spin" /> : <Download className="h-3 w-3" />} {t('LogsPage.allLogs.exportCsv')}
          </Button>
        </div>
      </div>

      {/* Active filters */}
      {(levelFilter || sourceFilter || search) && (
        <div className="flex items-center gap-2 text-xs">
          <span className="text-muted-foreground">{t('LogsPage.allLogs.filters.label')}</span>
          {levelFilter && (
            <Badge variant="outline" className="gap-1 text-[10px]">
              {t('LogsPage.allLogs.filters.level', { value: levelFilter })} <X className="h-3 w-3 cursor-pointer" onClick={() => setLevelFilter(null)} />
            </Badge>
          )}
          {sourceFilter && (
            <Badge variant="outline" className="gap-1 text-[10px]">
              {t('LogsPage.allLogs.filters.source', { value: sourceFilter })} <X className="h-3 w-3 cursor-pointer" onClick={() => setSourceFilter(null)} />
            </Badge>
          )}
          {search && (
            <Badge variant="outline" className="gap-1 text-[10px]">
              {t('LogsPage.allLogs.filters.search', { value: search })} <X className="h-3 w-3 cursor-pointer" onClick={() => setSearch('')} />
            </Badge>
          )}
          <button className="text-muted-foreground hover:text-foreground text-[10px] underline"
            onClick={() => { setLevelFilter(null); setSourceFilter(null); setSearch(''); setPage(1); }}>
            {t('LogsPage.allLogs.filters.clearAll')}
          </button>
        </div>
      )}

      {/* Log list */}
      <Card className="border-border/50 overflow-hidden">
        {logsLoading ? (
          <div className="flex items-center justify-center py-12 text-muted-foreground">
            <RefreshCw className="h-5 w-5 animate-spin mr-2" /> {t('LogsPage.allLogs.loading')}
          </div>
        ) : !logs?.items?.length ? (
          <div className="flex flex-col items-center justify-center py-16 text-muted-foreground">
            <ScrollText className="h-10 w-10 mb-3 opacity-30" />
            <p className="text-sm">{t('LogsPage.allLogs.empty.title')}</p>
            <p className="text-xs mt-1">{t('LogsPage.allLogs.empty.description')}</p>
          </div>
        ) : (
          <>
            <div className="max-h-[600px] overflow-y-auto">
              {logs.items.map(entry => (
                <LogEntryRow key={entry.id} entry={entry} />
              ))}
            </div>
            {/* Pagination */}
            {logs.pages > 1 && (
              <div className="flex items-center justify-between px-4 py-3 border-t border-border/50 bg-muted/20">
                <span className="text-xs text-muted-foreground">
                  {t('LogsPage.allLogs.pagination.showing', { from: ((page-1)*50)+1, to: Math.min(page*50, logs.total), total: logs.total.toLocaleString() })}
                </span>
                <div className="flex items-center gap-1">
                  <Button variant="outline" size="sm" className="h-7 text-xs" disabled={page <= 1}
                    onClick={() => setPage(page - 1)}>{t('LogsPage.allLogs.pagination.previous')}</Button>
                  <span className="text-xs text-muted-foreground px-2">{t('LogsPage.allLogs.pagination.pageOf', { page, pages: logs.pages })}</span>
                  <Button variant="outline" size="sm" className="h-7 text-xs" disabled={page >= logs.pages}
                    onClick={() => setPage(page + 1)}>{t('LogsPage.allLogs.pagination.next')}</Button>
                </div>
              </div>
            )}
          </>
        )}
      </Card>
    </div>
  );
}

// ================================================================
// Main LogsPage Component
// ================================================================

const LOG_TABS = ['overview', 'all-logs'] as const;

export default function LogsPage() {
  const { t } = useTranslation('logs');
  const navigate = useNavigate();
  const { tab: urlTab } = useParams<{ tab?: string }>();
  const [searchParams] = useSearchParams();

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const activeTab = LOG_TABS.includes(urlTab as any) ? urlTab! : 'overview';
  const setActiveTab = (v: string) =>
    navigate(v === 'overview' ? '/logs' : `/logs/${v}`, { replace: true });

  // Deep-link query params for the All Logs tab
  const qLevel  = searchParams.get('level');
  const qSource = searchParams.get('source');
  const qSearch = searchParams.get('search');

  return (
    <div className="space-y-6">
      <PageHeader
        title={t('LogsPage.header.title')}
        subtitle={t('LogsPage.header.subtitle')}
        icon={ScrollText}
      />

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          <TabsTrigger value="overview" className="gap-1.5">
            <LayoutDashboard className="h-4 w-4" />
            {t('LogsPage.tabs.overview')}
          </TabsTrigger>
          <TabsTrigger value="all-logs" className="gap-1.5">
            <List className="h-4 w-4" />
            {t('LogsPage.tabs.allLogs')}
          </TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="mt-4">
          <OverviewTab />
        </TabsContent>

        <TabsContent value="all-logs" className="mt-4">
          <AllLogsTab
            initialLevel={qLevel}
            initialSource={qSource}
            initialSearch={qSearch}
          />
        </TabsContent>
      </Tabs>
    </div>
  );
}

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN - Controller Detail Page
 *
 * Enterprise-grade controller view with tabs for overview, devices,
 * firmware, sync history, and connection settings.
 */

import { useState } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  ArrowLeft,
  Server,
  Clock,
  RefreshCw,
  AlertCircle,
  CheckCircle,
  XCircle,
  ExternalLink,
  Copy,
  TestTube,
  Loader2,
  Zap,
  Cpu,
  HardDrive,
  MemoryStick,
  Wifi,
  Router,
  Plug,
  ChevronDown,
  ChevronRight,
  Trash2,
  Activity,
  Shield,
  Network,
  ToggleLeft,
  ToggleRight,
  Search,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { PageHeader } from '@/components/layout';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Skeleton } from '@/components/ui/skeleton';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { useTranslation } from 'react-i18next';
import { controllersApi, type TestConnectionResult, type ControllerMetadata } from '@/lib/api';
import { cn, formatRelativeTime, formatUptime, formatWatts } from '@/lib/utils';
import { EmptyState } from '@/components/ui/empty-state';
import { useToast } from '@/hooks/use-toast';

// ─── Constants ────────────────────────────────────────────

const TYPE_LABELS: Record<string, string> = {
  omada: 'TP-Link Omada',
  unifi: 'Ubiquiti UniFi',
  meraki: 'Cisco Meraki',
  opnsense: 'OPNsense',
  proxmox: 'Proxmox VE',
  truenas: 'TrueNAS',
  hikvision: 'HikVision',
  axis: 'Axis',
  generic_onvif: 'ONVIF',
  generic_snmp: 'SNMP',
};

const STATUS_CONFIG: Record<string, { icon: typeof CheckCircle; labelKey: string; className: string }> = {
  connected: { icon: CheckCircle, labelKey: 'status.connected', className: 'bg-emerald-500/10 text-emerald-500' },
  disconnected: { icon: XCircle, labelKey: 'status.disconnected', className: 'bg-muted-foreground/10 text-muted-foreground' },
  error: { icon: AlertCircle, labelKey: 'status.error', className: 'bg-red-500/10 text-red-500' },
  syncing: { icon: RefreshCw, labelKey: 'status.syncing', className: 'bg-blue-500/10 text-blue-500' },
  unknown: { icon: Clock, labelKey: 'status.unknown', className: 'bg-amber-500/10 text-amber-500' },
};

// ─── Helper components ────────────────────────────────────

function InfoRow({ label, value, copyable = false }: { label: string; value: React.ReactNode; copyable?: boolean }) {
  const handleCopy = () => {
    if (typeof value === 'string') navigator.clipboard.writeText(value);
  };
  return (
    <div className="flex items-start justify-between py-1.5">
      <span className="text-sm text-muted-foreground">{label}</span>
      <div className="flex items-center gap-2">
        <span className="text-sm font-medium text-right max-w-[280px] truncate">{value}</span>
        {copyable && typeof value === 'string' && (
          <Button variant="ghost" size="icon" className="h-6 w-6" onClick={handleCopy}>
            <Copy className="h-3 w-3" />
          </Button>
        )}
      </div>
    </div>
  );
}

function UtilBar({ label, icon: Icon, value, color }: {
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  value: number | null | undefined;
  color: string;
}) {
  const { t } = useTranslation('controllers');
  const pct = value != null ? Math.min(100, Math.max(0, value)) : null;
  return (
    <div className="space-y-1">
      <div className="flex items-center justify-between text-xs">
        <span className="flex items-center gap-1 text-muted-foreground">
          <Icon className="h-3 w-3" /> {label}
        </span>
        <span className="font-medium">{pct != null ? `${pct.toFixed(0)}%` : t('ControllerDetailPage.common.notAvailable')}</span>
      </div>
      <div className="h-1.5 rounded-full bg-muted overflow-hidden">
        {pct != null && (
          <div className={cn('h-full rounded-full transition-all', color)} style={{ width: `${pct}%` }} />
        )}
      </div>
    </div>
  );
}

// ─── Main Component ───────────────────────────────────────

interface Controller {
  id: string;
  name: string;
  description: string | null;
  controller_type: string;
  host: string;
  port: number;
  status: 'connected' | 'disconnected' | 'error' | 'syncing' | 'unknown';
  last_sync: string | null;
  last_error: string | null;
  is_active: boolean;
  use_ssl: boolean;
  verify_ssl: boolean;
  sync_enabled: boolean;
  sync_interval_seconds: number;
  connection_mode?: string;
  site_id: string;
  device_count?: number;
  created_at: string;
  updated_at: string;
}

export default function ControllerDetailPage() {
  const { t } = useTranslation('controllers');
  const { id, tab } = useParams<{ id: string; tab: string }>();
  const navigate = useNavigate();
  const activeTab = tab && ['overview', 'devices', 'firmware', 'settings'].includes(tab) ? tab : 'overview';
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const [testResult, setTestResult] = useState<TestConnectionResult | null>(null);
  const [showErrorHistory, setShowErrorHistory] = useState(false);

  // Reset transient state when navigating between controllers
  const controllerId = id;
  useState(() => { setTestResult(null); setShowErrorHistory(false); });

  // Fetch controller
  const { data: controllerRes, isLoading, isError } = useQuery({
    queryKey: ['controller', controllerId],
    queryFn: () => controllersApi.getById(controllerId!),
    enabled: !!controllerId,
  });
  const controller = controllerRes?.data as Controller | undefined;

  // Fetch metadata
  const { data: meta, isLoading: metaLoading, isError: metaError } = useQuery({
    queryKey: ['controller-metadata', controllerId],
    queryFn: async () => {
      const response = await controllersApi.getMetadata(controllerId!);
      return response.data as ControllerMetadata;
    },
    enabled: !!controllerId,
    staleTime: 30000,
  });

  // Mutations
  const syncMutation = useMutation({
    mutationFn: (cId: string) => controllersApi.sync(cId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['controller', controllerId] });
      queryClient.invalidateQueries({ queryKey: ['controller-metadata', controllerId] });
    },
    onError: () => {
      toast({ title: t('ControllerDetailPage.toast.syncFailed.title'), description: t('ControllerDetailPage.toast.syncFailed.description'), variant: 'destructive' });
    },
  });

  const testMutation = useMutation({
    mutationFn: async (cId: string) => {
      const response = await controllersApi.test(cId);
      return response.data;
    },
    onSuccess: (data) => setTestResult(data),
    onError: (err: Error) => {
      const axiosErr = err as unknown as import('axios').AxiosError<{ detail?: string }>;
      setTestResult({
        success: false,
        message: t('ControllerDetailPage.test.failedMessage'),
        error: axiosErr.response?.data?.detail || err.message,
      });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (cId: string) => controllersApi.delete(cId),
    onSuccess: () => navigate('/controllers'),
    onError: () => {
      toast({ title: t('ControllerDetailPage.toast.deleteFailed.title'), description: t('ControllerDetailPage.toast.deleteFailed.description'), variant: 'destructive' });
    },
  });

  // ─── Loading / Error states ─────────────────────────────

  if (isLoading) {
    return (
      <div className="p-6 space-y-6">
        <Skeleton className="h-8 w-48" />
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-24" />)}
        </div>
        <Skeleton className="h-[400px]" />
      </div>
    );
  }

  if (isError || !controller) {
    return (
      <div className="p-6 flex flex-col items-center justify-center h-[60vh] space-y-4">
        <AlertCircle className="h-12 w-12 text-destructive" />
        <h2 className="text-lg font-semibold">{t('ControllerDetailPage.error.notFound')}</h2>
        <Button variant="outline" onClick={() => navigate('/controllers')}>
          <ArrowLeft className="mr-2 h-4 w-4" /> {t('ControllerDetailPage.error.backToControllers')}
        </Button>
      </div>
    );
  }

  const statusConfig = STATUS_CONFIG[controller.status] || STATUS_CONFIG.unknown;
  const StatusIcon = statusConfig.icon;
  const controllerUrl = `http${controller.use_ssl ? 's' : ''}://${controller.host}:${controller.port}`;
  const runtime = meta?.runtime_status || {};
  const dc = meta?.device_counts;
  const poe = meta?.poe_budget;
  const fw = meta?.firmware;
  const sync = meta?.sync;

  return (
    <div className="space-y-6">
      {/* Header */}
      <PageHeader
        icon={Server}
        title={controller.name}
        description={`${TYPE_LABELS[controller.controller_type] || controller.controller_type} · ${controller.host}:${controller.port}${runtime.version ? ` · v${runtime.version}` : ''}`}
        breadcrumbs={
          <Link to="/controllers" className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground">
            <ArrowLeft className="h-3.5 w-3.5" />
            {t('ControllerDetailPage.error.backToControllers')}
          </Link>
        }
        actions={
          <>
            <Badge className={cn('gap-1', statusConfig.className)}>
              <StatusIcon className={cn('h-3 w-3', controller.status === 'syncing' && 'animate-spin')} />
              {t(`ControllerDetailPage.${statusConfig.labelKey}`)}
            </Badge>
            <Button
              variant="outline"
              onClick={() => { syncMutation.mutate(controller.id); }}
              disabled={syncMutation.isPending}
            >
              {syncMutation.isPending ? (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              ) : (
                <RefreshCw className="mr-2 h-4 w-4" />
              )}
              {t('ControllerDetailPage.actions.syncNow')}
            </Button>
            <Button
              variant="outline"
              onClick={() => { setTestResult(null); testMutation.mutate(controller.id); }}
              disabled={testMutation.isPending}
            >
              {testMutation.isPending ? (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              ) : (
                <TestTube className="mr-2 h-4 w-4" />
              )}
              {t('ControllerDetailPage.actions.testConnection')}
            </Button>
            <Button variant="outline" size="icon" asChild>
              <a href={controllerUrl} target="_blank" rel="noopener noreferrer">
                <ExternalLink className="h-4 w-4" />
              </a>
            </Button>
          </>
        }
      />

      {/* Test Result Banner */}
      {testResult && (
        <div className={cn(
          'rounded-lg border p-4 text-sm',
          testResult.success ? 'bg-emerald-500/10 border-emerald-500/20' : 'bg-destructive/10 border-destructive/20',
        )}>
          <div className="flex items-center gap-2 font-medium">
            {testResult.success ? (
              <>
                <CheckCircle className="h-4 w-4 text-emerald-500" />
                <span className="text-emerald-700 dark:text-emerald-400">{t('ControllerDetailPage.test.successful')}</span>
              </>
            ) : (
              <>
                <AlertCircle className="h-4 w-4 text-destructive" />
                <span className="text-destructive">{t('ControllerDetailPage.test.failed')}</span>
              </>
            )}
            {testResult.success && testResult.details && (
              <div className="ml-4 flex gap-4 text-xs text-muted-foreground">
                {testResult.details.latency_ms != null && (
                  <span className="flex items-center gap-1"><Zap className="h-3 w-3" /> {testResult.details.latency_ms}ms</span>
                )}
                {testResult.details.controller_version && (
                  <span>{t('ControllerDetailPage.test.version', { version: testResult.details.controller_version })}</span>
                )}
              </div>
            )}
          </div>
          {!testResult.success && testResult.error && (
            <p className="mt-1 text-xs text-destructive/80">{testResult.error}</p>
          )}
        </div>
      )}

      {/* Stat Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <Card>
          <CardHeader className="pb-2">
            <CardDescription className="flex items-center gap-2"><Activity className="h-4 w-4" /> {t('ControllerDetailPage.stats.devices')}</CardDescription>
          </CardHeader>
          <CardContent>
            {metaLoading ? <Skeleton className="h-8 w-20" /> : (
              <div className="flex items-baseline gap-2">
                <span className="text-2xl font-bold">{dc?.total ?? controller.device_count ?? 0}</span>
                {dc && (
                  <span className="text-sm text-muted-foreground">
                    <span className="text-emerald-500">{dc.online}</span> / <span className={dc.offline > 0 ? 'text-red-500' : ''}>{dc.offline}</span>
                  </span>
                )}
              </div>
            )}
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardDescription className="flex items-center gap-2"><Network className="h-4 w-4" /> {t('ControllerDetailPage.stats.clients')}</CardDescription>
          </CardHeader>
          <CardContent>
            {metaLoading ? <Skeleton className="h-8 w-20" /> : (
              <span className="text-2xl font-bold">{meta?.client_count ?? 0}</span>
            )}
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardDescription className="flex items-center gap-2"><Plug className="h-4 w-4" /> {t('ControllerDetailPage.stats.poePower')}</CardDescription>
          </CardHeader>
          <CardContent>
            {metaLoading ? <Skeleton className="h-8 w-20" /> : poe && poe.switches_with_poe > 0 ? (
              <div>
                <span className="text-2xl font-bold">{formatWatts(poe.total_consumed_watts)}</span>
                <span className="text-sm text-muted-foreground ml-1">{t('ControllerDetailPage.stats.ofBudget', { budget: formatWatts(poe.total_budget_watts) })}</span>
              </div>
            ) : (
              <span className="text-2xl font-bold text-muted-foreground">{t('ControllerDetailPage.common.notAvailable')}</span>
            )}
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardDescription className="flex items-center gap-2"><Shield className="h-4 w-4" /> {t('ControllerDetailPage.stats.firmware')}</CardDescription>
          </CardHeader>
          <CardContent>
            {metaLoading ? <Skeleton className="h-8 w-20" /> : fw ? (
              <div className="flex items-baseline gap-2">
                <span className="text-2xl font-bold">{fw.up_to_date}/{fw.total_devices}</span>
                <span className="text-sm text-muted-foreground">{t('ControllerDetailPage.stats.upToDate')}</span>
              </div>
            ) : (
              <span className="text-2xl font-bold text-muted-foreground">{t('ControllerDetailPage.common.notAvailable')}</span>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Tabs */}
      <Tabs value={activeTab} onValueChange={(v) => navigate(`/controllers/${id}/${v}`, { replace: true })} className="space-y-4">
        <TabsList>
          <TabsTrigger value="overview">{t('ControllerDetailPage.tabs.overview')}</TabsTrigger>
          <TabsTrigger value="devices">{t('ControllerDetailPage.tabs.devices')}</TabsTrigger>
          <TabsTrigger value="firmware">{t('ControllerDetailPage.tabs.firmware')}</TabsTrigger>
          <TabsTrigger value="settings">{t('ControllerDetailPage.tabs.settings')}</TabsTrigger>
        </TabsList>

        {/* ── Overview Tab ── */}
        <TabsContent value="overview" className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Controller Health */}
            <Card>
              <CardHeader>
                <CardTitle className="text-base">{t('ControllerDetailPage.health.title')}</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                {(runtime.cpu_util != null || runtime.mem_util != null) ? (
                  <>
                    <UtilBar label={t('ControllerDetailPage.health.cpu')} icon={Cpu} value={runtime.cpu_util}
                      color={runtime.cpu_util && runtime.cpu_util > 80 ? 'bg-red-500' : 'bg-emerald-500'} />
                    <UtilBar label={t('ControllerDetailPage.health.memory')} icon={MemoryStick} value={runtime.mem_util}
                      color={runtime.mem_util && runtime.mem_util > 80 ? 'bg-red-500' : 'bg-blue-500'} />
                    {runtime.disk_util != null && (
                      <UtilBar label={t('ControllerDetailPage.health.disk')} icon={HardDrive} value={runtime.disk_util}
                        color={runtime.disk_util > 90 ? 'bg-red-500' : 'bg-amber-500'} />
                    )}
                    {runtime.uptime != null && (
                      <div className="flex items-center justify-between text-sm pt-2 border-t">
                        <span className="text-muted-foreground flex items-center gap-1"><Clock className="h-3.5 w-3.5" /> {t('ControllerDetailPage.health.uptime')}</span>
                        <span className="font-medium">{formatUptime(runtime.uptime)}</span>
                      </div>
                    )}
                  </>
                ) : (
                  <p className="text-sm text-muted-foreground">{t('ControllerDetailPage.health.unavailable')}</p>
                )}
              </CardContent>
            </Card>

            {/* Device Breakdown */}
            <Card>
              <CardHeader>
                <CardTitle className="text-base">{t('ControllerDetailPage.breakdown.title')}</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                {metaLoading ? <Skeleton className="h-20 w-full" /> : metaError ? (
                  <div className="text-center py-8 text-destructive">
                    <AlertCircle className="h-8 w-8 mx-auto mb-2 opacity-60" />
                    <p>{t('ControllerDetailPage.devices.loadError')}</p>
                  </div>
                ) : dc ? (
                  <>
                    <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3">
                      <div className="rounded-lg border p-3 text-center">
                        <div className="text-2xl font-bold">{dc.total}</div>
                        <div className="text-xs text-muted-foreground">{t('ControllerDetailPage.breakdown.total')}</div>
                      </div>
                      <div className="rounded-lg border p-3 text-center">
                        <div className="text-2xl font-bold text-emerald-500">{dc.online}</div>
                        <div className="text-xs text-muted-foreground">{t('ControllerDetailPage.breakdown.online')}</div>
                      </div>
                      <div className="rounded-lg border p-3 text-center">
                        <div className={cn('text-2xl font-bold', dc.offline > 0 ? 'text-red-500' : 'text-muted-foreground')}>{dc.offline}</div>
                        <div className="text-xs text-muted-foreground">{t('ControllerDetailPage.breakdown.offline')}</div>
                      </div>
                    </div>
                    <div className="flex flex-wrap gap-2">
                      {dc.switches > 0 && <Badge variant="outline" className="gap-1.5"><Router className="h-3 w-3" /> {t('ControllerDetailPage.breakdown.switches', { count: dc.switches })}</Badge>}
                      {dc.access_points > 0 && <Badge variant="outline" className="gap-1.5"><Wifi className="h-3 w-3" /> {t('ControllerDetailPage.breakdown.accessPoints', { count: dc.access_points })}</Badge>}
                      {dc.gateways > 0 && <Badge variant="outline" className="gap-1.5"><Server className="h-3 w-3" /> {t('ControllerDetailPage.breakdown.gateways', { count: dc.gateways })}</Badge>}
                      {meta?.client_count != null && meta.client_count > 0 && (
                        <Badge variant="secondary" className="gap-1.5">{t('ControllerDetailPage.breakdown.clients', { count: meta.client_count })}</Badge>
                      )}
                    </div>
                  </>
                ) : null}
              </CardContent>
            </Card>

            {/* PoE Budget */}
            {poe && poe.switches_with_poe > 0 && (
              <Card>
                <CardHeader>
                  <CardTitle className="text-base flex items-center gap-2"><Plug className="h-4 w-4" /> {t('ControllerDetailPage.poe.title')}</CardTitle>
                </CardHeader>
                <CardContent className="space-y-3">
                  <div className="flex justify-between text-sm">
                    <span className="text-muted-foreground">{t('ControllerDetailPage.poe.consumedBudget')}</span>
                    <span className="font-medium">{formatWatts(poe.total_consumed_watts)} / {formatWatts(poe.total_budget_watts)}</span>
                  </div>
                  <div className="h-3 rounded-full bg-muted overflow-hidden">
                    <div
                      className={cn(
                        'h-full rounded-full transition-all',
                        poe.total_budget_watts > 0 && (poe.total_consumed_watts / poe.total_budget_watts) > 0.85
                          ? 'bg-red-500' : 'bg-emerald-500'
                      )}
                      style={{ width: `${poe.total_budget_watts > 0 ? Math.min(100, (poe.total_consumed_watts / poe.total_budget_watts) * 100) : 0}%` }}
                    />
                  </div>
                  <div className="text-sm text-muted-foreground">
                    {poe.switches_with_poe === 1
                      ? t('ControllerDetailPage.poe.remainingOne', { watts: formatWatts(poe.total_remaining_watts) })
                      : t('ControllerDetailPage.poe.remainingOther', { watts: formatWatts(poe.total_remaining_watts), count: poe.switches_with_poe })}
                  </div>
                </CardContent>
              </Card>
            )}

            {/* Sync Status */}
            <Card>
              <CardHeader>
                <CardTitle className="text-base">{t('ControllerDetailPage.sync.title')}</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                <InfoRow label={t('ControllerDetailPage.sync.autoSync')} value={
                  <span className="flex items-center gap-1">
                    {controller.sync_enabled
                      ? <><ToggleRight className="h-4 w-4 text-emerald-500" /> {t('ControllerDetailPage.sync.enabled')}</>
                      : <><ToggleLeft className="h-4 w-4 text-muted-foreground" /> {t('ControllerDetailPage.sync.disabled')}</>}
                  </span>
                } />
                <InfoRow label={t('ControllerDetailPage.sync.interval')} value={`${controller.sync_interval_seconds}s`} />
                <InfoRow label={t('ControllerDetailPage.sync.lastSync')} value={
                  <span title={controller.last_sync ? new Date(controller.last_sync).toLocaleString() : undefined}>
                    {formatRelativeTime(controller.last_sync)}
                  </span>
                } />
                {sync?.last_sync_duration_seconds != null && (
                  <InfoRow label={t('ControllerDetailPage.sync.duration')} value={`${sync.last_sync_duration_seconds.toFixed(1)}s`} />
                )}
                {controller.last_error && (
                  <div className="mt-2 rounded-md bg-destructive/10 p-2.5 text-xs text-destructive">
                    {controller.last_error}
                  </div>
                )}
                {sync && sync.error_history.length > 0 && (
                  <div className="mt-2">
                    <button
                      className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground transition-colors"
                      onClick={() => setShowErrorHistory(!showErrorHistory)}
                    >
                      {showErrorHistory ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />}
                      {t('ControllerDetailPage.sync.errorHistory', { count: sync.error_history.length })}
                    </button>
                    {showErrorHistory && (
                      <div className="mt-1 space-y-1 max-h-48 overflow-y-auto">
                        {sync.error_history.map((e: { timestamp: string; error: string }, i: number) => (
                          <div key={i} className="text-xs py-1 border-t">
                            <span className="text-muted-foreground">{formatRelativeTime(e.timestamp)}: </span>
                            <span className="text-destructive/80">{e.error}</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* ── Devices Tab ── */}
        <TabsContent value="devices" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-base">{t('ControllerDetailPage.devices.title', { count: meta?.devices.length ?? 0 })}</CardTitle>
              <CardDescription>{t('ControllerDetailPage.devices.description')}</CardDescription>
            </CardHeader>
            <CardContent>
              {metaLoading ? (
                <div className="space-y-2">{Array.from({ length: 5 }).map((_, i) => <Skeleton key={i} className="h-12" />)}</div>
              ) : metaError ? (
                <div className="text-center py-8 text-destructive">
                  <AlertCircle className="h-8 w-8 mx-auto mb-2 opacity-60" />
                  <p>{t('ControllerDetailPage.devices.loadError')}</p>
                </div>
              ) : meta && meta.devices.length > 0 ? (
                <div className="overflow-x-auto rounded-lg border">
                  <div className="min-w-[800px] divide-y">
                  {/* Header */}
                  <div className="grid grid-cols-12 gap-2 px-4 py-2 text-xs font-medium text-muted-foreground bg-muted/50">
                    <div className="col-span-3">{t('ControllerDetailPage.devices.columns.device')}</div>
                    <div className="col-span-1">{t('ControllerDetailPage.devices.columns.type')}</div>
                    <div className="col-span-2">{t('ControllerDetailPage.devices.columns.model')}</div>
                    <div className="col-span-2">{t('ControllerDetailPage.devices.columns.ipAddress')}</div>
                    <div className="col-span-1">{t('ControllerDetailPage.devices.columns.cpu')}</div>
                    <div className="col-span-1">{t('ControllerDetailPage.devices.columns.memory')}</div>
                    <div className="col-span-1">{t('ControllerDetailPage.devices.columns.uptime')}</div>
                    <div className="col-span-1 text-right">{t('ControllerDetailPage.devices.columns.status')}</div>
                  </div>
                  {meta.devices.map(d => (
                    <div
                      key={d.id}
                      className="grid grid-cols-12 gap-2 px-4 py-2.5 text-sm items-center hover:bg-muted/30 cursor-pointer transition-colors"
                      onClick={() => navigate(`/devices/${d.id}`)}
                    >
                      <div className="col-span-3 flex items-center gap-2 min-w-0">
                        {d.type === 'switch' && <Router className="h-4 w-4 text-muted-foreground shrink-0" />}
                        {d.type === 'access_point' && <Wifi className="h-4 w-4 text-muted-foreground shrink-0" />}
                        {(d.type === 'router' || d.type === 'gateway') && <Server className="h-4 w-4 text-muted-foreground shrink-0" />}
                        <div className="min-w-0">
                          <div className="font-medium truncate">{d.name}</div>
                          <div className="text-xs text-muted-foreground font-mono">{d.mac}</div>
                        </div>
                      </div>
                      <div className="col-span-1">
                        <Badge variant="outline" className="text-xs capitalize">{d.type?.replace('_', ' ')}</Badge>
                      </div>
                      <div className="col-span-2 text-xs text-muted-foreground truncate">{d.model}</div>
                      <div className="col-span-2 text-xs font-mono">{d.ip || '-'}</div>
                      <div className="col-span-1 text-xs">{d.cpu_usage != null ? `${d.cpu_usage}%` : '-'}</div>
                      <div className="col-span-1 text-xs">{d.memory_usage != null ? `${d.memory_usage}%` : '-'}</div>
                      <div className="col-span-1 text-xs">{d.uptime ? formatUptime(d.uptime) : '-'}</div>
                      <div className="col-span-1 flex justify-end">
                        <div className={cn(
                          'flex items-center gap-1.5 text-xs',
                          d.status === 'online' ? 'text-emerald-500' : 'text-red-500',
                        )}>
                          <div className={cn('h-2 w-2 rounded-full', d.status === 'online' ? 'bg-emerald-500' : 'bg-red-500')} />
                          {d.status === 'online' ? t('ControllerDetailPage.devices.online') : t('ControllerDetailPage.devices.offline')}
                        </div>
                      </div>
                    </div>
                  ))}
                  </div>
                </div>
              ) : (
                <EmptyState
                  icon={Search}
                  title={t('ControllerDetailPage.devices.empty.title')}
                  description={t('ControllerDetailPage.devices.empty.description')}
                  action={{
                    label: t('ControllerDetailPage.devices.empty.action'),
                    onClick: () => syncMutation.mutate(controller.id),
                    icon: RefreshCw,
                  }}
                />
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* ── Firmware Tab ── */}
        <TabsContent value="firmware" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-base">{t('ControllerDetailPage.firmware.title')}</CardTitle>
              <CardDescription>{t('ControllerDetailPage.firmware.description')}</CardDescription>
            </CardHeader>
            <CardContent>
              {metaLoading ? (
                <div className="space-y-2">{Array.from({ length: 5 }).map((_, i) => <Skeleton key={i} className="h-10" />)}</div>
              ) : metaError ? (
                <div className="text-center py-8 text-destructive">
                  <AlertCircle className="h-8 w-8 mx-auto mb-2 opacity-60" />
                  <p>{t('ControllerDetailPage.devices.loadError')}</p>
                </div>
              ) : fw && fw.devices.length > 0 ? (
                <>
                  <div className="flex gap-4 mb-4">
                    <Badge variant="outline" className="text-emerald-500 border-emerald-500/30 gap-1">
                      <CheckCircle className="h-3 w-3" /> {t('ControllerDetailPage.firmware.upToDateCount', { count: fw.up_to_date })}
                    </Badge>
                    {fw.needs_upgrade > 0 && (
                      <Badge variant="outline" className="text-amber-500 border-amber-500/30 gap-1">
                        <AlertCircle className="h-3 w-3" /> {fw.needs_upgrade === 1
                          ? t('ControllerDetailPage.firmware.needsUpgradeOne', { count: fw.needs_upgrade })
                          : t('ControllerDetailPage.firmware.needsUpgradeOther', { count: fw.needs_upgrade })}
                      </Badge>
                    )}
                  </div>
                  <div className="overflow-x-auto rounded-lg border">
                    <div className="min-w-[700px] divide-y">
                    <div className="grid grid-cols-12 gap-2 px-4 py-2 text-xs font-medium text-muted-foreground bg-muted/50">
                      <div className="col-span-4">{t('ControllerDetailPage.firmware.columns.device')}</div>
                      <div className="col-span-4">{t('ControllerDetailPage.firmware.columns.currentVersion')}</div>
                      <div className="col-span-3">{t('ControllerDetailPage.firmware.columns.latestVersion')}</div>
                      <div className="col-span-1 text-right">{t('ControllerDetailPage.firmware.columns.status')}</div>
                    </div>
                    {fw.devices.map(d => (
                      <div key={d.mac} className="grid grid-cols-12 gap-2 px-4 py-2.5 text-sm items-center">
                        <div className="col-span-4">
                          <div className="font-medium">{d.name}</div>
                          <div className="text-xs text-muted-foreground font-mono">{d.mac}</div>
                        </div>
                        <div className="col-span-4 text-xs font-mono text-muted-foreground">{d.current || '-'}</div>
                        <div className="col-span-3 text-xs font-mono">{d.latest || <span className="text-muted-foreground">-</span>}</div>
                        <div className="col-span-1 flex justify-end">
                          {d.needs_upgrade ? (
                            <Badge variant="outline" className="text-xs text-amber-500 border-amber-500/30">{t('ControllerDetailPage.firmware.badge.upgrade')}</Badge>
                          ) : (
                            <Badge variant="outline" className="text-xs text-emerald-500 border-emerald-500/30">{t('ControllerDetailPage.firmware.badge.current')}</Badge>
                          )}
                        </div>
                      </div>
                    ))}
                    </div>
                  </div>
                </>
              ) : (
                <p className="text-sm text-muted-foreground text-center py-8">{t('ControllerDetailPage.firmware.empty')}</p>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* ── Settings Tab ── */}
        <TabsContent value="settings" className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <Card>
              <CardHeader>
                <CardTitle className="text-base">{t('ControllerDetailPage.connection.title')}</CardTitle>
              </CardHeader>
              <CardContent className="space-y-1">
                <InfoRow label={t('ControllerDetailPage.connection.host')} value={controller.host} copyable />
                <InfoRow label={t('ControllerDetailPage.connection.port')} value={String(controller.port)} />
                <InfoRow label={t('ControllerDetailPage.connection.ssl')} value={controller.use_ssl ? t('ControllerDetailPage.common.enabled') : t('ControllerDetailPage.common.disabled')} />
                <InfoRow label={t('ControllerDetailPage.connection.verifyCertificate')} value={controller.verify_ssl ? t('ControllerDetailPage.common.yes') : t('ControllerDetailPage.common.no')} />
                <InfoRow label={t('ControllerDetailPage.connection.connectionMode')} value={controller.connection_mode || 'local'} />
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="text-base">{t('ControllerDetailPage.metadata.title')}</CardTitle>
              </CardHeader>
              <CardContent className="space-y-1">
                <InfoRow label={t('ControllerDetailPage.metadata.controllerId')} value={controller.id} copyable />
                <InfoRow label={t('ControllerDetailPage.metadata.type')} value={TYPE_LABELS[controller.controller_type] || controller.controller_type} />
                <InfoRow label={t('ControllerDetailPage.metadata.active')} value={controller.is_active ? t('ControllerDetailPage.common.yes') : t('ControllerDetailPage.common.no')} />
                <InfoRow label={t('ControllerDetailPage.metadata.created')} value={controller.created_at ? new Date(controller.created_at).toLocaleString() : '—'} />
                <InfoRow label={t('ControllerDetailPage.metadata.updated')} value={controller.updated_at ? new Date(controller.updated_at).toLocaleString() : '—'} />
              </CardContent>
            </Card>

            {meta?.site_mappings && Object.keys(meta.site_mappings).length > 0 && (
              <Card>
                <CardHeader>
                  <CardTitle className="text-base">{t('ControllerDetailPage.siteMappings.title')}</CardTitle>
                  <CardDescription>{t('ControllerDetailPage.siteMappings.description')}</CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-1">
                    {Object.entries(meta.site_mappings).map(([k, v]) => (
                      <InfoRow key={k} label={k} value={v as string} copyable />
                    ))}
                  </div>
                </CardContent>
              </Card>
            )}

            <Card className="border-destructive/20">
              <CardHeader>
                <CardTitle className="text-base text-destructive">{t('ControllerDetailPage.dangerZone.title')}</CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-sm text-muted-foreground mb-4">
                  {t('ControllerDetailPage.dangerZone.description')}
                </p>
                <Button
                  variant="destructive"
                  onClick={() => {
                    if (window.confirm(t('ControllerDetailPage.dangerZone.confirm', { name: controller.name, count: dc?.total ?? 0 }))) {
                      deleteMutation.mutate(controller.id);
                    }
                  }}
                  disabled={deleteMutation.isPending}
                >
                  {deleteMutation.isPending ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Trash2 className="mr-2 h-4 w-4" />}
                  {t('ControllerDetailPage.dangerZone.delete')}
                </Button>
              </CardContent>
            </Card>
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
}

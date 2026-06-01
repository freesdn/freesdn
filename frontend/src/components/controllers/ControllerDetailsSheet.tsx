// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN - Controller Details Sheet
 *
 * Enterprise-grade slide-out panel showing detailed controller information
 * with device breakdown, PoE budget, firmware status, and controller health.
 */

import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Server,
  Clock,
  RefreshCw,
  Settings,
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
} from 'lucide-react';
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from '@/components/ui/sheet';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Separator } from '@/components/ui/separator';
import { Skeleton } from '@/components/ui/skeleton';
import { useTranslation } from 'react-i18next';
import { controllersApi, type TestConnectionResult, type ControllerMetadata } from '@/lib/api';
import { cn, formatRelativeTime, formatUptime, formatWatts } from '@/lib/utils';

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
  site_id: string;
  device_count?: number;
  created_at: string;
  updated_at: string;
}

interface ControllerDetailsSheetProps {
  controller: Controller | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onEdit?: () => void;
  onSync?: () => void;
}

const TYPE_LABELS: Record<string, string> = {
  omada: 'TP-Link Omada',
  unifi: 'Ubiquiti UniFi',
  meraki: 'Cisco Meraki',
  opnsense: 'OPNsense',
  hikvision: 'HikVision',
  axis: 'Axis',
  generic_onvif: 'ONVIF',
  generic_snmp: 'SNMP',
};

const STATUS_CONFIG = {
  connected: {
    icon: CheckCircle,
    labelKey: 'status.connected',
    className: 'bg-emerald-500/10 text-emerald-500',
  },
  disconnected: {
    icon: XCircle,
    labelKey: 'status.disconnected',
    className: 'bg-muted-foreground/10 text-muted-foreground',
  },
  error: {
    icon: AlertCircle,
    labelKey: 'status.error',
    className: 'bg-red-500/10 text-red-500',
  },
  syncing: {
    icon: RefreshCw,
    labelKey: 'status.syncing',
    className: 'bg-blue-500/10 text-blue-500',
  },
  unknown: {
    icon: Clock,
    labelKey: 'status.unknown',
    className: 'bg-amber-500/10 text-amber-500',
  },
};

function InfoRow({ label, value, copyable = false }: { label: string; value: React.ReactNode; copyable?: boolean }) {
  const handleCopy = () => {
    if (typeof value === 'string') {
      navigator.clipboard.writeText(value);
    }
  };

  return (
    <div className="flex items-start justify-between py-1.5">
      <span className="text-sm text-muted-foreground">{label}</span>
      <div className="flex items-center gap-2">
        <span className="text-sm font-medium text-right">{value}</span>
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
  const { t } = useTranslation('common');
  const pct = value != null ? Math.min(100, Math.max(0, value)) : null;
  return (
    <div className="space-y-1">
      <div className="flex items-center justify-between text-xs">
        <span className="flex items-center gap-1 text-muted-foreground">
          <Icon className="h-3 w-3" /> {label}
        </span>
        <span className="font-medium">{pct != null ? `${pct.toFixed(0)}%` : t('ControllerDetailsSheet.common.notAvailable')}</span>
      </div>
      <div className="h-1.5 rounded-full bg-muted overflow-hidden">
        {pct != null && (
          <div
            className={cn('h-full rounded-full transition-all', color)}
            style={{ width: `${pct}%` }}
          />
        )}
      </div>
    </div>
  );
}

export function ControllerDetailsSheet({
  controller,
  open,
  onOpenChange,
  onEdit,
  onSync,
}: ControllerDetailsSheetProps) {
  const { t } = useTranslation('common');
  const queryClient = useQueryClient();
  const [testResult, setTestResult] = useState<TestConnectionResult | null>(null);
  const [showErrorHistory, setShowErrorHistory] = useState(false);
  const [showDeviceList, setShowDeviceList] = useState(false);

  // Fetch enriched metadata
  const { data: meta, isLoading: metaLoading } = useQuery({
    queryKey: ['controller-metadata', controller?.id],
    queryFn: async () => {
      if (!controller) return null;
      const response = await controllersApi.getMetadata(controller.id);
      return response.data as ControllerMetadata;
    },
    enabled: !!controller && open,
    staleTime: 30000,
  });

  // Test connection mutation
  const testMutation = useMutation({
    mutationFn: async (id: string) => {
      const response = await controllersApi.test(id);
      return response.data;
    },
    onSuccess: (data) => {
      setTestResult(data);
      queryClient.invalidateQueries({ queryKey: ['controllers'] });
    },
    onError: (err: Error) => {
      const axiosErr = err as unknown as import('axios').AxiosError<{ detail?: string }>;
      setTestResult({
        success: false,
        message: t('ControllerDetailsSheet.test.failedMessage'),
        error: axiosErr.response?.data?.detail || err.message,
      });
    },
  });

  if (!controller) return null;

  const statusConfig = STATUS_CONFIG[controller.status] || STATUS_CONFIG.unknown;
  const StatusIcon = statusConfig.icon;
  const controllerUrl = `http${controller.use_ssl ? 's' : ''}://${controller.host}:${controller.port}`;
  const runtime = meta?.runtime_status || {};
  const dc = meta?.device_counts;
  const poe = meta?.poe_budget;
  const fw = meta?.firmware;
  const sync = meta?.sync;

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent className="w-[90vw] sm:w-[560px] sm:max-w-[560px] overflow-y-auto">
        <SheetHeader>
          <div className="flex items-start justify-between">
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10">
                <Server className="h-5 w-5 text-primary" />
              </div>
              <div>
                <SheetTitle className="text-left">{controller.name}</SheetTitle>
                <SheetDescription className="text-left">
                  {TYPE_LABELS[controller.controller_type] || controller.controller_type}
                  {runtime.version && <span className="ml-2 font-mono text-xs">v{runtime.version}</span>}
                </SheetDescription>
              </div>
            </div>
            <Badge className={cn('gap-1', statusConfig.className)}>
              <StatusIcon className={cn('h-3 w-3', controller.status === 'syncing' && 'animate-spin')} />
              {t(`ControllerDetailsSheet.${statusConfig.labelKey}`)}
            </Badge>
          </div>
        </SheetHeader>

        <div className="mt-6 space-y-5">
          {/* Quick Actions */}
          <div className="flex gap-2">
            <Button variant="outline" className="flex-1" onClick={onSync}>
              <RefreshCw className="mr-2 h-4 w-4" />
              {t('ControllerDetailsSheet.actions.syncNow')}
            </Button>
            <Button
              variant="outline"
              className="flex-1"
              onClick={() => { setTestResult(null); testMutation.mutate(controller.id); }}
              disabled={testMutation.isPending}
            >
              {testMutation.isPending ? (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              ) : (
                <TestTube className="mr-2 h-4 w-4" />
              )}
              {t('ControllerDetailsSheet.actions.test')}
            </Button>
            <Button variant="outline" className="flex-1" onClick={onEdit}>
              <Settings className="mr-2 h-4 w-4" />
              {t('ControllerDetailsSheet.actions.edit')}
            </Button>
            <Button variant="outline" size="icon" asChild>
              <a href={controllerUrl} target="_blank" rel="noopener noreferrer">
                <ExternalLink className="h-4 w-4" />
              </a>
            </Button>
          </div>

          {/* Test Result */}
          {testResult && (
            <div className={cn(
              'rounded-lg border p-3 text-sm space-y-2',
              testResult.success
                ? 'bg-emerald-500/10 border-emerald-500/20'
                : 'bg-destructive/10 border-destructive/20',
            )}>
              <div className="flex items-center gap-2 font-medium">
                {testResult.success ? (
                  <>
                    <CheckCircle className="h-4 w-4 text-emerald-500" />
                    <span className="text-emerald-700 dark:text-emerald-400">{t('ControllerDetailsSheet.test.successful')}</span>
                  </>
                ) : (
                  <>
                    <AlertCircle className="h-4 w-4 text-destructive" />
                    <span className="text-destructive">{t('ControllerDetailsSheet.test.failed')}</span>
                  </>
                )}
              </div>
              {testResult.success && testResult.details && (
                <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs text-muted-foreground">
                  {testResult.details.latency_ms != null && (
                    <>
                      <span className="flex items-center gap-1"><Zap className="h-3 w-3" /> {t('ControllerDetailsSheet.test.latency')}</span>
                      <span className="font-medium text-foreground">{testResult.details.latency_ms}ms</span>
                    </>
                  )}
                  {testResult.details.controller_version && (
                    <>
                      <span>{t('ControllerDetailsSheet.test.version')}</span>
                      <span className="font-medium text-foreground">{testResult.details.controller_version}</span>
                    </>
                  )}
                </div>
              )}
              {!testResult.success && testResult.error && (
                <p className="text-xs text-destructive/80 whitespace-pre-line">{testResult.error}</p>
              )}
            </div>
          )}

          <Separator />

          {/* Controller Health */}
          {(runtime.cpu_util != null || runtime.mem_util != null) && (
            <div>
              <h4 className="text-sm font-semibold mb-3">{t('ControllerDetailsSheet.health.title')}</h4>
              <div className="rounded-lg border p-3 space-y-3">
                <UtilBar
                  label={t('ControllerDetailsSheet.health.cpu')}
                  icon={Cpu}
                  value={runtime.cpu_util}
                  color={runtime.cpu_util && runtime.cpu_util > 80 ? 'bg-red-500' : 'bg-emerald-500'}
                />
                <UtilBar
                  label={t('ControllerDetailsSheet.health.memory')}
                  icon={MemoryStick}
                  value={runtime.mem_util}
                  color={runtime.mem_util && runtime.mem_util > 80 ? 'bg-red-500' : 'bg-blue-500'}
                />
                {runtime.disk_util != null && (
                  <UtilBar
                    label={t('ControllerDetailsSheet.health.disk')}
                    icon={HardDrive}
                    value={runtime.disk_util}
                    color={runtime.disk_util && runtime.disk_util > 90 ? 'bg-red-500' : 'bg-amber-500'}
                  />
                )}
                {runtime.uptime != null && (
                  <div className="flex items-center justify-between text-xs pt-1 border-t">
                    <span className="text-muted-foreground flex items-center gap-1">
                      <Clock className="h-3 w-3" /> {t('ControllerDetailsSheet.health.uptime')}
                    </span>
                    <span className="font-medium">{formatUptime(runtime.uptime)}</span>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Device Breakdown */}
          <div>
            <h4 className="text-sm font-semibold mb-3">{t('ControllerDetailsSheet.devices.title')}</h4>
            {metaLoading ? (
              <Skeleton className="h-20 w-full" />
            ) : dc ? (
              <div className="space-y-3">
                {/* Main counts */}
                <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2">
                  <div className="rounded-lg border p-2.5 text-center">
                    <div className="text-xl font-bold">{dc.total}</div>
                    <div className="text-xs text-muted-foreground">{t('ControllerDetailsSheet.devices.total')}</div>
                  </div>
                  <div className="rounded-lg border p-2.5 text-center">
                    <div className="text-xl font-bold text-emerald-500">{dc.online}</div>
                    <div className="text-xs text-muted-foreground">{t('ControllerDetailsSheet.devices.online')}</div>
                  </div>
                  <div className="rounded-lg border p-2.5 text-center">
                    <div className={cn('text-xl font-bold', dc.offline > 0 ? 'text-red-500' : 'text-muted-foreground')}>
                      {dc.offline}
                    </div>
                    <div className="text-xs text-muted-foreground">{t('ControllerDetailsSheet.devices.offline')}</div>
                  </div>
                </div>
                {/* Type breakdown + clients */}
                <div className="flex flex-wrap gap-2">
                  {dc.switches > 0 && (
                    <Badge variant="outline" className="gap-1.5">
                      <Router className="h-3 w-3" /> {t('ControllerDetailsSheet.devices.switchesCount', { count: dc.switches })}
                    </Badge>
                  )}
                  {dc.access_points > 0 && (
                    <Badge variant="outline" className="gap-1.5">
                      <Wifi className="h-3 w-3" /> {t('ControllerDetailsSheet.devices.apsCount', { count: dc.access_points })}
                    </Badge>
                  )}
                  {dc.gateways > 0 && (
                    <Badge variant="outline" className="gap-1.5">
                      <Server className="h-3 w-3" /> {t('ControllerDetailsSheet.devices.gatewaysCount', { count: dc.gateways })}
                    </Badge>
                  )}
                  {meta?.client_count != null && meta.client_count > 0 && (
                    <Badge variant="secondary" className="gap-1.5">
                      {t('ControllerDetailsSheet.devices.clientsCount', { count: meta.client_count })}
                    </Badge>
                  )}
                </div>
              </div>
            ) : (
              <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2">
                <div className="rounded-lg border p-2.5 text-center">
                  <div className="text-xl font-bold">{controller.device_count || 0}</div>
                  <div className="text-xs text-muted-foreground">{t('ControllerDetailsSheet.devices.total')}</div>
                </div>
              </div>
            )}
          </div>

          {/* PoE Budget */}
          {poe && poe.switches_with_poe > 0 && (
            <div>
              <h4 className="text-sm font-semibold mb-3 flex items-center gap-2">
                <Plug className="h-4 w-4" /> {t('ControllerDetailsSheet.poe.title')}
              </h4>
              <div className="rounded-lg border p-3 space-y-2">
                <div className="flex justify-between text-sm">
                  <span className="text-muted-foreground">{t('ControllerDetailsSheet.poe.consumedBudget')}</span>
                  <span className="font-medium">
                    {formatWatts(poe.total_consumed_watts)} / {formatWatts(poe.total_budget_watts)}
                  </span>
                </div>
                <div className="h-2 rounded-full bg-muted overflow-hidden">
                  <div
                    className={cn(
                      'h-full rounded-full transition-all',
                      poe.total_budget_watts > 0 && (poe.total_consumed_watts / poe.total_budget_watts) > 0.85
                        ? 'bg-red-500'
                        : 'bg-emerald-500'
                    )}
                    style={{
                      width: `${poe.total_budget_watts > 0 ? Math.min(100, (poe.total_consumed_watts / poe.total_budget_watts) * 100) : 0}%`,
                    }}
                  />
                </div>
                <div className="text-xs text-muted-foreground">
                  {t('ControllerDetailsSheet.poe.remaining', {
                    watts: formatWatts(poe.total_remaining_watts),
                    count: poe.switches_with_poe,
                  })}
                </div>
              </div>
            </div>
          )}

          {/* Firmware Status */}
          {fw && fw.total_devices > 0 && (
            <div>
              <h4 className="text-sm font-semibold mb-3">{t('ControllerDetailsSheet.firmware.title')}</h4>
              <div className="rounded-lg border p-3">
                <div className="flex items-center justify-between">
                  <span className="text-sm text-muted-foreground">{t('ControllerDetailsSheet.firmware.compliance')}</span>
                  <span className="text-sm font-medium">
                    {t('ControllerDetailsSheet.firmware.upToDate', { current: fw.up_to_date, total: fw.total_devices })}
                  </span>
                </div>
                {fw.needs_upgrade > 0 && (
                  <div className="mt-2 space-y-1">
                    {fw.devices.filter(d => d.needs_upgrade).map(d => (
                      <div key={d.mac} className="flex items-center justify-between text-xs py-1 border-t">
                        <span className="text-muted-foreground">{d.name}</span>
                        <div className="flex items-center gap-2">
                          <span className="font-mono">{d.current}</span>
                          <span className="text-muted-foreground">&rarr;</span>
                          <Badge variant="outline" className="text-xs h-5 text-amber-500 border-amber-500/30">
                            {d.latest}
                          </Badge>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}

          <Separator />

          {/* Connection Info */}
          <div>
            <h4 className="text-sm font-semibold mb-3">{t('ControllerDetailsSheet.connection.title')}</h4>
            <div className="space-y-1 rounded-lg border p-3">
              <InfoRow label={t('ControllerDetailsSheet.connection.host')} value={controller.host} copyable />
              <InfoRow label={t('ControllerDetailsSheet.connection.port')} value={controller.port.toString()} />
              <InfoRow label={t('ControllerDetailsSheet.connection.ssl')} value={controller.use_ssl ? t('ControllerDetailsSheet.common.enabled') : t('ControllerDetailsSheet.common.disabled')} />
              <InfoRow label={t('ControllerDetailsSheet.connection.verifyCertificate')} value={controller.verify_ssl ? t('ControllerDetailsSheet.common.yes') : t('ControllerDetailsSheet.common.no')} />
            </div>
          </div>

          {/* Sync Status */}
          <div>
            <h4 className="text-sm font-semibold mb-3">{t('ControllerDetailsSheet.sync.title')}</h4>
            <div className="space-y-1 rounded-lg border p-3">
              <InfoRow label={t('ControllerDetailsSheet.sync.autoSync')} value={controller.sync_enabled ? t('ControllerDetailsSheet.common.enabled') : t('ControllerDetailsSheet.common.disabled')} />
              <InfoRow label={t('ControllerDetailsSheet.sync.interval')} value={`${controller.sync_interval_seconds}s`} />
              <InfoRow
                label={t('ControllerDetailsSheet.sync.lastSync')}
                value={
                  <span title={controller.last_sync ? new Date(controller.last_sync).toLocaleString() : undefined}>
                    {formatRelativeTime(controller.last_sync)}
                  </span>
                }
              />
              {sync?.last_sync_duration_seconds != null && (
                <InfoRow label={t('ControllerDetailsSheet.sync.duration')} value={`${sync.last_sync_duration_seconds.toFixed(1)}s`} />
              )}
              {controller.last_error && (
                <div className="mt-2 rounded-md bg-destructive/10 p-2 text-xs text-destructive">
                  {controller.last_error}
                </div>
              )}
              {/* Error History */}
              {sync && sync.error_history.length > 0 && (
                <div className="mt-2">
                  <button
                    className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground transition-colors"
                    onClick={() => setShowErrorHistory(!showErrorHistory)}
                  >
                    {showErrorHistory ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />}
                    {t('ControllerDetailsSheet.sync.errorHistory', { count: sync.error_history.length })}
                  </button>
                  {showErrorHistory && (
                    <div className="mt-1 space-y-1 max-h-40 overflow-y-auto">
                      {sync.error_history.map((e, i) => (
                        <div key={i} className="text-xs py-1 border-t">
                          <span className="text-muted-foreground">{formatRelativeTime(e.timestamp)}: </span>
                          <span className="text-destructive/80">{e.error}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>

          {/* Quick Device List */}
          {meta && meta.devices.length > 0 && (
            <div>
              <button
                className="flex items-center gap-2 text-sm font-semibold hover:text-primary transition-colors"
                onClick={() => setShowDeviceList(!showDeviceList)}
              >
                {showDeviceList ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
                {t('ControllerDetailsSheet.devices.managedDevices', { count: meta.devices.length })}
              </button>
              {showDeviceList && (
                <div className="mt-2 rounded-lg border divide-y max-h-64 overflow-y-auto">
                  {meta.devices.map(d => (
                    <div key={d.id} className="flex items-center justify-between px-3 py-2 text-xs">
                      <div className="flex items-center gap-2 min-w-0">
                        {d.type === 'switch' && <Router className="h-3.5 w-3.5 text-muted-foreground shrink-0" />}
                        {d.type === 'access_point' && <Wifi className="h-3.5 w-3.5 text-muted-foreground shrink-0" />}
                        {(d.type === 'router' || d.type === 'gateway') && <Server className="h-3.5 w-3.5 text-muted-foreground shrink-0" />}
                        <div className="min-w-0">
                          <div className="font-medium truncate">{d.name}</div>
                          <div className="text-muted-foreground">{d.ip || d.mac}</div>
                        </div>
                      </div>
                      <div className="flex items-center gap-2 shrink-0">
                        {d.firmware_version && (
                          <span className="text-muted-foreground font-mono">{d.firmware_version}</span>
                        )}
                        <div className={cn(
                          'h-2 w-2 rounded-full',
                          d.status === 'online' ? 'bg-emerald-500' : 'bg-red-500'
                        )} />
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Metadata */}
          <div>
            <h4 className="text-sm font-semibold mb-3">{t('ControllerDetailsSheet.details.title')}</h4>
            <div className="space-y-1 rounded-lg border p-3">
              <InfoRow label={t('ControllerDetailsSheet.details.controllerId')} value={controller.id} copyable />
              <InfoRow label={t('ControllerDetailsSheet.details.active')} value={controller.is_active ? t('ControllerDetailsSheet.common.yes') : t('ControllerDetailsSheet.common.no')} />
              <InfoRow
                label={t('ControllerDetailsSheet.details.created')}
                value={controller.created_at ? new Date(controller.created_at).toLocaleString() : '—'}
              />
              <InfoRow
                label={t('ControllerDetailsSheet.details.updated')}
                value={controller.updated_at ? new Date(controller.updated_at).toLocaleString() : '—'}
              />
            </div>
          </div>
        </div>
      </SheetContent>
    </Sheet>
  );
}

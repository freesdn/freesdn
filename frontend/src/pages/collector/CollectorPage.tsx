// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN - Collector Overview Page
 *
 * Service status cards for SNMP trap, Syslog, and NetFlow receivers.
 * Live event stream (last 50 logs), stats charts, and configuration panel.
 */

import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { isValid } from 'date-fns';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Radio,
  RefreshCw,
  Settings,
  Wifi,
  WifiOff,
  Activity,
  ScrollText,
  BarChart3,
  AlertTriangle,
} from 'lucide-react';

import { api } from '@/lib/api';
import { PageHeader } from '@/components/layout';
import { useToast } from '@/hooks/use-toast';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Switch } from '@/components/ui/switch';
import { Label } from '@/components/ui/label';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { Skeleton } from '@/components/ui/skeleton';
import { EmptyState } from '@/components/ui/empty-state';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';


// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

interface ServiceStatus {
  running: boolean;
  port: number | null;
}

interface CollectorStatus {
  services: {
    snmp_trap: ServiceStatus;
    syslog: ServiceStatus;
    netflow: ServiceStatus;
  };
}

interface CollectorConfig {
  snmp_enabled: boolean;
  snmp_port: number;
  snmp_community: string;
  syslog_enabled: boolean;
  syslog_port: number;
  netflow_enabled: boolean;
  netflow_port: number;
  log_retention_days: number;
  flow_retention_days: number;
  allowed_source_ips: string[];
}

interface LogEntry {
  id: string;
  source_type: string;
  source_ip: string;
  severity: string | null;
  hostname: string | null;
  app_name: string | null;
  message: string;
  enterprise_oid: string | null;
  trap_type: string | null;
  timestamp: string;
}

interface LogStats {
  total: number;
  hours: number;
  by_severity: { severity: string; count: number }[];
  by_source_type: { source_type: string; count: number }[];
  top_sources: { source_ip: string; count: number }[];
}


// ─────────────────────────────────────────────────────────────────────────────
// Severity badge helper
// ─────────────────────────────────────────────────────────────────────────────

const SEVERITY_COLORS: Record<string, string> = {
  emergency: 'bg-red-600 text-white',
  alert: 'bg-red-500 text-white',
  critical: 'bg-red-400 text-white',
  error: 'bg-orange-500 text-white',
  warning: 'bg-yellow-500 text-black',
  notice: 'bg-blue-500 text-white',
  info: 'bg-blue-400 text-white',
  debug: 'bg-gray-400 text-white',
};

function SeverityBadge({ severity }: { severity: string | null }) {
  if (!severity) return <Badge variant="outline">-</Badge>;
  const cls = SEVERITY_COLORS[severity.toLowerCase()] ?? 'bg-gray-300 text-black';
  return <span className={`inline-flex items-center rounded px-1.5 py-0.5 text-xs font-medium ${cls}`}>{severity}</span>;
}


// ─────────────────────────────────────────────────────────────────────────────
// Service status card
// ─────────────────────────────────────────────────────────────────────────────

function ServiceCard({
  title,
  icon: Icon,
  serviceKey: _serviceKey,
  status,
  config,
  portField,
  enabledField,
  onToggle,
  saving,
}: {
  title: string;
  icon: React.ElementType;
  serviceKey: keyof CollectorStatus['services'];
  status: ServiceStatus | undefined;
  config: CollectorConfig | undefined;
  portField: keyof CollectorConfig;
  enabledField: keyof CollectorConfig;
  onToggle: (field: keyof CollectorConfig, value: boolean) => void;
  saving: boolean;
}) {
  const { t } = useTranslation('collector');
  const isRunning = status?.running ?? false;
  const isEnabled = config ? Boolean(config[enabledField]) : false;
  const port = status?.port ?? (config ? Number(config[portField]) : null);

  return (
    <Card>
      <CardHeader className="pb-2">
        <div className="flex items-center justify-between">
          <CardTitle className="flex items-center gap-2 text-sm font-medium">
            <Icon className="h-4 w-4 text-primary" />
            {title}
          </CardTitle>
          <Switch
            checked={isEnabled}
            onCheckedChange={(v) => onToggle(enabledField, v)}
            disabled={saving}
          />
        </div>
      </CardHeader>
      <CardContent className="space-y-2">
        <div className="flex items-center gap-2">
          {isRunning ? (
            <Wifi className="h-4 w-4 text-green-500" />
          ) : (
            <WifiOff className="h-4 w-4 text-muted-foreground" />
          )}
          <span className={`text-sm font-medium ${isRunning ? 'text-green-600' : 'text-muted-foreground'}`}>
            {isRunning ? t('CollectorPage.status.running') : t('CollectorPage.status.stopped')}
          </span>
          {port && (
            <Badge variant="outline" className="ml-auto text-xs">
              :{port}/UDP
            </Badge>
          )}
        </div>
      </CardContent>
    </Card>
  );
}


// ─────────────────────────────────────────────────────────────────────────────
// Main page
// ─────────────────────────────────────────────────────────────────────────────

export default function CollectorPage() {
  const { t } = useTranslation('collector');
  const { t: tCommon } = useTranslation('common');
  // Reuse the existing IP-allowlist strings from the settings namespace,
  // semantically identical to the collector's allowed_source_ips control.
  const { t: tSettings } = useTranslation('settings');
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const [showConfig, setShowConfig] = useState(false);
  const [configDraft, setConfigDraft] = useState<Partial<CollectorConfig>>({});

  const { data: statusData, isLoading: statusLoading, isError: statusError } = useQuery<CollectorStatus>({
    // Collector is org-scoped (no per-site dimension), site selector must not refetch.
    queryKey: ['collector-status'],
    queryFn: () => api.get('/collector/status').then((r) => r.data),
    refetchInterval: 10_000,
  });

  const { data: config, isLoading: configLoading, isError: configError } = useQuery<CollectorConfig>({
    queryKey: ['collector-config'],
    queryFn: () => api.get('/collector/config').then((r) => r.data),
  });

  const { data: recentLogs, refetch: refetchLogs, isLoading: logsInitialLoading, isFetching: logsLoading, isError: logsError } = useQuery<{
    logs: LogEntry[];
    total: number;
  }>({
    queryKey: ['collector-recent-logs'],
    queryFn: () =>
      api
        .get('/collector/logs', { params: { size: 50, page: 1 } })
        .then((r) => r.data),
    refetchInterval: 5_000,
  });

  const { data: statsData, isLoading: statsLoading, isError: statsError } = useQuery<LogStats>({
    queryKey: ['collector-stats'],
    queryFn: () =>
      api.get('/collector/logs/stats', { params: { hours: 24 } }).then((r) => r.data),
    refetchInterval: 30_000,
  });

  const updateConfig = useMutation({
    mutationFn: (data: Partial<CollectorConfig>) =>
      api.put('/collector/config', data).then((r) => r.data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['collector-config'] });
      queryClient.invalidateQueries({ queryKey: ['collector-status'] });
      toast({ title: tCommon('success') });
    },
    onError: (err: Error) => {
      toast({ title: t('CollectorPage.toast.operationFailed'), description: err.message, variant: 'destructive' });
    },
  });

  const handleToggle = (field: keyof CollectorConfig, value: boolean) => {
    updateConfig.mutate({ [field]: value });
  };

  const handleSaveConfig = () => {
    if (Object.keys(configDraft).length > 0) {
      updateConfig.mutate(configDraft, {
        onSuccess: () => {
          setConfigDraft({});
          setShowConfig(false);
        },
      });
    }
  };

  // Parse a textarea of one-CIDR-per-line (or comma-separated) into a clean list.
  const handleAllowedIpsChange = (raw: string) => {
    const list = raw
      .split(/[\n,]/)
      .map((s) => s.trim())
      .filter(Boolean);
    setConfigDraft((d) => ({ ...d, allowed_source_ips: list }));
  };

  const hasQueryError = statusError || configError || logsError || statsError;
  const services = statusData?.services;
  const servicesLoading = statusLoading || configLoading;

  return (
    <div className="space-y-6">
      {/* Header */}
      <PageHeader
        icon={Radio}
        title={t('CollectorPage.header.title')}
        subtitle={t('CollectorPage.header.subtitle')}
        actions={
          <>
            <Button
              variant="outline"
              size="sm"
              onClick={() => refetchLogs()}
              disabled={logsLoading}
            >
              <RefreshCw className={`mr-2 h-4 w-4 ${logsLoading ? 'animate-spin' : ''}`} />
              {t('CollectorPage.actions.refresh')}
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => setShowConfig(!showConfig)}
            >
              <Settings className="mr-2 h-4 w-4" />
              {t('CollectorPage.actions.configure')}
            </Button>
          </>
        }
      />

      {hasQueryError && (
        <Card className="border-destructive">
          <CardContent noOffset className="p-4 flex items-center gap-3">
            <AlertTriangle className="h-5 w-5 text-destructive" />
            <span className="text-sm">{t('CollectorPage.errors.partialLoad')}</span>
          </CardContent>
        </Card>
      )}

      {/* Service status cards */}
      {servicesLoading ? (
        <div className="grid gap-4 md:grid-cols-3">
          {Array.from({ length: 3 }).map((_, i) => (
            <Card key={i}>
              <CardHeader className="pb-2">
                <div className="flex items-center justify-between">
                  <Skeleton className="h-4 w-40" />
                  <Skeleton className="h-5 w-9 rounded-full" />
                </div>
              </CardHeader>
              <CardContent className="space-y-2">
                <Skeleton className="h-4 w-24" />
              </CardContent>
            </Card>
          ))}
        </div>
      ) : (
        <div className="grid gap-4 md:grid-cols-3">
          <ServiceCard
            title={t('CollectorPage.services.snmpTrap')}
            icon={Activity}
            serviceKey="snmp_trap"
            status={services?.snmp_trap}
            config={config}
            portField="snmp_port"
            enabledField="snmp_enabled"
            onToggle={handleToggle}
            saving={updateConfig.isPending}
          />
          <ServiceCard
            title={t('CollectorPage.services.syslog')}
            icon={ScrollText}
            serviceKey="syslog"
            status={services?.syslog}
            config={config}
            portField="syslog_port"
            enabledField="syslog_enabled"
            onToggle={handleToggle}
            saving={updateConfig.isPending}
          />
          <ServiceCard
            title={t('CollectorPage.services.netflow')}
            icon={BarChart3}
            serviceKey="netflow"
            status={services?.netflow}
            config={config}
            portField="netflow_port"
            enabledField="netflow_enabled"
            onToggle={handleToggle}
            saving={updateConfig.isPending}
          />
        </div>
      )}

      {/* Config panel */}
      {showConfig && config && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">{t('CollectorPage.config.title')}</CardTitle>
            <CardDescription>{t('CollectorPage.config.description')}</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid gap-4 md:grid-cols-3">
              <div className="space-y-3">
                <p className="text-sm font-medium">{t('CollectorPage.config.snmpTrap')}</p>
                <div className="space-y-1">
                  <Label className="text-xs">{t('CollectorPage.config.port')}</Label>
                  <Input
                    type="number"
                    defaultValue={config.snmp_port}
                    onChange={(e) =>
                      setConfigDraft((d) => ({ ...d, snmp_port: Number(e.target.value) }))
                    }
                  />
                </div>
                <div className="space-y-1">
                  <Label className="text-xs">{t('CollectorPage.config.community')}</Label>
                  <Input
                    defaultValue={config.snmp_community}
                    onChange={(e) =>
                      setConfigDraft((d) => ({ ...d, snmp_community: e.target.value }))
                    }
                  />
                </div>
              </div>
              <div className="space-y-3">
                <p className="text-sm font-medium">{t('CollectorPage.config.syslog')}</p>
                <div className="space-y-1">
                  <Label className="text-xs">{t('CollectorPage.config.port')}</Label>
                  <Input
                    type="number"
                    defaultValue={config.syslog_port}
                    onChange={(e) =>
                      setConfigDraft((d) => ({ ...d, syslog_port: Number(e.target.value) }))
                    }
                  />
                </div>
              </div>
              <div className="space-y-3">
                <p className="text-sm font-medium">{t('CollectorPage.config.netflow')}</p>
                <div className="space-y-1">
                  <Label className="text-xs">{t('CollectorPage.config.port')}</Label>
                  <Input
                    type="number"
                    defaultValue={config.netflow_port}
                    onChange={(e) =>
                      setConfigDraft((d) => ({ ...d, netflow_port: Number(e.target.value) }))
                    }
                  />
                </div>
              </div>
            </div>
            <div className="mt-4 grid gap-4 md:grid-cols-2">
              <div className="space-y-1">
                <Label className="text-xs">{t('CollectorPage.config.logRetention')}</Label>
                <Input
                  type="number"
                  defaultValue={config.log_retention_days}
                  onChange={(e) =>
                    setConfigDraft((d) => ({ ...d, log_retention_days: Number(e.target.value) }))
                  }
                />
              </div>
              <div className="space-y-1">
                <Label className="text-xs">{t('CollectorPage.config.flowRetention')}</Label>
                <Input
                  type="number"
                  defaultValue={config.flow_retention_days}
                  onChange={(e) =>
                    setConfigDraft((d) => ({ ...d, flow_retention_days: Number(e.target.value) }))
                  }
                />
              </div>
            </div>
            <div className="mt-4 space-y-1">
              <Label className="text-xs">
                {tSettings('SettingsPage.security.access.ipWhitelistLabel')}
              </Label>
              <Textarea
                rows={4}
                className="font-mono text-xs"
                placeholder={tSettings('SettingsPage.security.access.ipWhitelistPlaceholder')}
                defaultValue={(config.allowed_source_ips ?? []).join('\n')}
                onChange={(e) => handleAllowedIpsChange(e.target.value)}
              />
              <p className="text-xs text-muted-foreground">
                {tSettings('SettingsPage.security.access.ipWhitelistHelp')}
              </p>
            </div>
            <div className="mt-4 flex gap-2">
              <Button size="sm" onClick={handleSaveConfig} disabled={updateConfig.isPending}>
                {t('CollectorPage.actions.saveConfiguration')}
              </Button>
              <Button size="sm" variant="ghost" onClick={() => setShowConfig(false)}>
                {t('CollectorPage.actions.close')}
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Stats row */}
      {statsLoading && !statsData ? (
        <div className="grid gap-4 md:grid-cols-3">
          {Array.from({ length: 3 }).map((_, i) => (
            <Card key={i}>
              <CardHeader className="pb-2">
                <Skeleton className="h-4 w-28" />
              </CardHeader>
              <CardContent className="space-y-2">
                <Skeleton className="h-8 w-20" />
                <Skeleton className="h-3 w-full" />
                <Skeleton className="h-3 w-3/4" />
              </CardContent>
            </Card>
          ))}
        </div>
      ) : statsData ? (
        <div className="grid gap-4 md:grid-cols-3">
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium text-muted-foreground">
                {t('CollectorPage.stats.events24h')}
              </CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-2xl font-bold">{(statsData.total ?? 0).toLocaleString()}</p>
              <div className="mt-2 space-y-1">
                {(statsData.by_source_type ?? []).map((s) => (
                  <div key={s.source_type} className="flex justify-between text-xs text-muted-foreground">
                    <span>{s.source_type}</span>
                    <span>{s.count.toLocaleString()}</span>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium text-muted-foreground">
                {t('CollectorPage.stats.bySeverity24h')}
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-1">
              {(statsData.by_severity ?? []).slice(0, 6).map((s) => (
                <div key={s.severity} className="flex items-center justify-between">
                  <SeverityBadge severity={s.severity} />
                  <span className="text-sm">{s.count.toLocaleString()}</span>
                </div>
              ))}
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium text-muted-foreground">
                {t('CollectorPage.stats.topSources24h')}
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-1">
              {(statsData.top_sources ?? []).slice(0, 5).map((s) => (
                <div key={s.source_ip} className="flex justify-between text-xs">
                  <span className="font-mono">{s.source_ip}</span>
                  <span className="text-muted-foreground">{s.count.toLocaleString()}</span>
                </div>
              ))}
            </CardContent>
          </Card>
        </div>
      ) : null}

      {/* Live event stream */}
      <Card>
        <CardHeader className="pb-2">
          <div className="flex items-center justify-between">
            <CardTitle className="text-base">{t('CollectorPage.stream.title')}</CardTitle>
            <Badge variant="secondary" className="text-xs">
              {t('CollectorPage.stream.autoRefresh')}
            </Badge>
          </div>
        </CardHeader>
        <CardContent className="p-0">
          {logsInitialLoading ? (
            <div className="space-y-2 p-4">
              {Array.from({ length: 8 }).map((_, i) => (
                <div key={i} className="flex items-center gap-4">
                  <Skeleton className="h-4 w-28" />
                  <Skeleton className="h-4 w-16" />
                  <Skeleton className="h-4 w-20" />
                  <Skeleton className="h-4 w-28" />
                  <Skeleton className="h-4 flex-1" />
                </div>
              ))}
            </div>
          ) : recentLogs && (recentLogs.logs ?? []).length > 0 ? (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-36">{t('CollectorPage.table.time')}</TableHead>
                  <TableHead className="w-24">{t('CollectorPage.table.type')}</TableHead>
                  <TableHead className="w-28">{t('CollectorPage.table.severity')}</TableHead>
                  <TableHead className="w-32">{t('CollectorPage.table.sourceIp')}</TableHead>
                  <TableHead>{t('CollectorPage.table.message')}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(recentLogs.logs ?? []).map((log) => (
                  <TableRow key={log.id}>
                    <TableCell className="text-xs text-muted-foreground font-mono">
                      {log.timestamp && isValid(new Date(log.timestamp))
                        ? new Date(log.timestamp).toLocaleTimeString()
                        : '—'}
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline" className="text-xs">
                        {log.source_type === 'snmp_trap' ? 'SNMP' : 'Syslog'}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <SeverityBadge severity={log.severity} />
                    </TableCell>
                    <TableCell className="text-xs font-mono">{log.source_ip}</TableCell>
                    <TableCell className="max-w-0 truncate text-sm text-muted-foreground">
                      {log.hostname && (
                        <span className="mr-2 font-medium text-foreground">{log.hostname}</span>
                      )}
                      {log.message}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          ) : (
            <EmptyState
              icon={ScrollText}
              title={t('CollectorPage.empty.title')}
              description={t('CollectorPage.empty.description')}
              variant="card"
            />
          )}
        </CardContent>
      </Card>
    </div>
  );
}

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * GatewayMonitoringTab · temperature, disk, traffic, PF state, health-check,
 * Monit, Telegraf, NetFlow / sFlow.
 *
 * Extracted from GatewayDetailPage as part of the monolith breakup. Owns its
 * own data queries (temperature/disk/traffic/pfInfo/healthCheck/monit/telegraf/netflow)
 * since they are only consumed by this tab and only run when the tab is active.
 */
/* eslint-disable @typescript-eslint/no-explicit-any */
import { useQuery } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { Activity, HardDrive, RefreshCw, Shield } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { StatsGrid, type StatItem } from '@/components/ui/stats-grid';
import { gatewayApi } from '@/lib/api';

export interface GatewayMonitoringTabProps {
  gatewayId: string;
  isActive: boolean;
}

export function GatewayMonitoringTab({ gatewayId, isActive }: GatewayMonitoringTabProps) {
  const { t } = useTranslation('firewall');

  const { data: temperatureData } = useQuery({
    queryKey: ['gateways', gatewayId, 'temperature'],
    queryFn: () => gatewayApi.getTemperature(gatewayId),
    enabled: !!gatewayId && isActive,
    refetchInterval: 30_000,
  });

  const { data: diskUsageData } = useQuery({
    queryKey: ['gateways', gatewayId, 'disk-usage'],
    queryFn: () => gatewayApi.getDiskUsage(gatewayId),
    enabled: !!gatewayId && isActive,
    refetchInterval: 60_000,
  });

  const { data: trafficData } = useQuery({
    queryKey: ['gateways', gatewayId, 'traffic'],
    queryFn: () => gatewayApi.getTrafficStats(gatewayId),
    enabled: !!gatewayId && isActive,
    refetchInterval: 15_000,
  });

  const { data: pfInfoData } = useQuery({
    queryKey: ['gateways', gatewayId, 'pf-info'],
    queryFn: () => gatewayApi.getPFInfo(gatewayId),
    enabled: !!gatewayId && isActive,
  });

  const { data: telegrafData, isLoading: telegrafLoading } = useQuery({
    queryKey: ['gateways', gatewayId, 'telegraf'],
    queryFn: () => gatewayApi.getTelegrafStatus(gatewayId),
    enabled: !!gatewayId && isActive,
  });

  const { data: monitData, isLoading: monitLoading } = useQuery({
    queryKey: ['gateways', gatewayId, 'monit'],
    queryFn: () => gatewayApi.getMonitStatus(gatewayId),
    enabled: !!gatewayId && isActive,
  });

  const { data: netflowData, isLoading: netflowLoading } = useQuery({
    queryKey: ['gateways', gatewayId, 'netflow'],
    queryFn: () => gatewayApi.getNetFlowStatus(gatewayId),
    enabled: !!gatewayId && isActive,
  });

  const { data: healthCheckData } = useQuery({
    queryKey: ['gateways', gatewayId, 'health-check'],
    queryFn: () => gatewayApi.getHealthCheck(gatewayId),
    enabled: !!gatewayId && isActive,
    refetchInterval: 60_000,
  });

  // Build the monitoring stats dynamically from whichever queries returned data.
  const monitoringStats: StatItem[] = [];
  if (temperatureData?.data?.temperature) {
    const temp = temperatureData.data.temperature.current || temperatureData.data.temperature.value || 0;
    monitoringStats.push({
      title: t('GatewayMonitoringTab.stats.temperature'),
      value: `${temp || '-'}°C`,
      icon: Activity,
      variant: (temperatureData.data.temperature.current || 0) > 75 ? 'destructive' : 'primary',
    });
  }
  if (diskUsageData?.data?.disk_usage) {
    monitoringStats.push({
      title: t('GatewayMonitoringTab.stats.diskUsage'),
      value: diskUsageData.data.disk_usage.used_percent ? `${diskUsageData.data.disk_usage.used_percent}%` : '-',
      icon: HardDrive,
      variant: 'primary',
      description: diskUsageData.data.disk_usage.total ? `${diskUsageData.data.disk_usage.total}` : undefined,
    });
  }
  if (healthCheckData?.data) {
    monitoringStats.push({
      title: t('GatewayMonitoringTab.stats.health'),
      value: healthCheckData.data.healthy ? t('GatewayMonitoringTab.stats.healthy') : t('GatewayMonitoringTab.stats.degraded'),
      icon: Activity,
      variant: healthCheckData.data.healthy ? 'success' : 'destructive',
    });
  }
  if (pfInfoData?.data?.pf_info) {
    monitoringStats.push({
      title: t('GatewayMonitoringTab.stats.pfStates'),
      value: pfInfoData.data.pf_info.states || pfInfoData.data.pf_info.entries || '-',
      icon: Shield,
      variant: 'primary',
    });
  }

  return (
    <>
      {monitoringStats.length > 0 && (
        <StatsGrid columns={4} stats={monitoringStats} />
      )}

      {trafficData?.data?.traffic && (
        <Card className="border-border/50">
          <CardHeader className="pb-4"><CardTitle>{t('GatewayMonitoringTab.traffic.title')}</CardTitle></CardHeader>
          <CardContent>
            <div className="space-y-4">
              {Object.entries(trafficData.data.traffic).map(([iface, stats]: [string, any]) => {
                const records = Array.isArray(stats?.records) ? stats.records : Array.isArray(stats) ? stats : [];
                return (
                  <div key={iface} className="border rounded-lg overflow-hidden">
                    <div className="bg-muted/50 px-4 py-2 flex items-center justify-between">
                      <p className="font-medium text-sm uppercase">{iface}</p>
                      {stats?.status && <Badge variant="outline" className="text-xs">{stats.status}</Badge>}
                    </div>
                    {records.length > 0 ? (
                      <div className="overflow-x-auto">
                        <table className="w-full text-sm">
                          <thead>
                            <tr className="border-b text-left text-muted-foreground">
                              <th className="px-4 py-2 font-medium">{t('GatewayMonitoringTab.traffic.address')}</th>
                              <th className="px-4 py-2 font-medium text-right">{t('GatewayMonitoringTab.traffic.rateIn')}</th>
                              <th className="px-4 py-2 font-medium text-right">{t('GatewayMonitoringTab.traffic.rateOut')}</th>
                              <th className="px-4 py-2 font-medium text-right">{t('GatewayMonitoringTab.traffic.cumulative')}</th>
                            </tr>
                          </thead>
                          <tbody>
                            {records.map((rec: any, idx: number) => (
                              <tr key={idx} className="border-b last:border-0">
                                <td className="px-4 py-2 font-mono text-xs">{rec.rname || rec.address || '-'}</td>
                                <td className="px-4 py-2 text-right font-mono text-xs text-green-600">{rec.rate_in || rec.rate_bits_in || '-'}</td>
                                <td className="px-4 py-2 text-right font-mono text-xs text-blue-600">{rec.rate_out || rec.rate_bits_out || '-'}</td>
                                <td className="px-4 py-2 text-right font-mono text-xs">{rec.cumulative || '-'}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    ) : (
                      <p className="px-4 py-3 text-sm text-muted-foreground">{t('GatewayMonitoringTab.traffic.noData')}</p>
                    )}
                  </div>
                );
              })}
            </div>
          </CardContent>
        </Card>
      )}

      {healthCheckData?.data?.health && (() => {
        const health = healthCheckData.data.health;
        const gatewayItems = health?.gateways?.items || (Array.isArray(health?.gateways) ? health.gateways : []);
        return (
          <>
            {/* Top-level health fields */}
            <Card className="border-border/50">
              <CardHeader className="pb-4"><CardTitle>{t('GatewayMonitoringTab.healthCheck.title')}</CardTitle></CardHeader>
              <CardContent>
                <dl className="space-y-2 text-sm">
                  {Object.entries(health).filter(([k]) => k !== 'gateways').map(([k, v]) => (
                    <div key={k} className="flex justify-between">
                      <dt className="text-muted-foreground capitalize">{k.replace(/_/g, ' ')}</dt>
                      <dd className="font-medium">{typeof v === 'object' ? JSON.stringify(v) : String(v)}</dd>
                    </div>
                  ))}
                </dl>
              </CardContent>
            </Card>

            {/* Gateways rendered as cards */}
            {gatewayItems.length > 0 && (
              <Card className="border-border/50">
                <CardHeader className="pb-4"><CardTitle>{t('GatewayMonitoringTab.gatewayHealth.title')}</CardTitle></CardHeader>
                <CardContent>
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                    {gatewayItems.map((g: any, i: number) => {
                      const isOnline = g.status === 'none' || g.status_translated === 'Online' || g.status === 'online';
                      return (
                        <div key={i} className="p-3 rounded-lg border space-y-1.5">
                          <div className="flex items-center justify-between">
                            <span className="font-medium text-sm">{g.name || t('GatewayMonitoringTab.gatewayHealth.gatewayN', { n: i + 1 })}</span>
                            <Badge variant={isOnline ? 'default' : 'destructive'}>
                              {g.status_translated || g.status || t('GatewayMonitoringTab.common.unknown')}
                            </Badge>
                          </div>
                          {g.address && g.address !== '~' && <p className="text-xs text-muted-foreground">{t('GatewayMonitoringTab.gatewayHealth.ip')}: <span className="font-mono">{g.address}</span></p>}
                          {g.monitor && g.monitor !== '~' && <p className="text-xs text-muted-foreground">{t('GatewayMonitoringTab.gatewayHealth.monitor')}: <span className="font-mono">{g.monitor}</span></p>}
                          <div className="flex gap-3 text-xs">
                            {g.delay && g.delay !== '~' && <span className="text-muted-foreground">{t('GatewayMonitoringTab.gatewayHealth.latency')}: <span className="font-mono">{g.delay}</span></span>}
                            {g.loss && g.loss !== '~' && <span className="text-muted-foreground">{t('GatewayMonitoringTab.gatewayHealth.loss')}: <span className="font-mono">{g.loss}</span></span>}
                            {g.stddev && g.stddev !== '~' && <span className="text-muted-foreground">{t('GatewayMonitoringTab.gatewayHealth.stddev')}: <span className="font-mono">{g.stddev}</span></span>}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </CardContent>
              </Card>
            )}
          </>
        );
      })()}

      {/* ─── Monit Service Monitor ──────────────────────────── */}
      <Card className="border-border/50">
        <CardHeader className="pb-4">
          <CardTitle>{t('GatewayMonitoringTab.monit.title')}</CardTitle>
          <CardDescription>{t('GatewayMonitoringTab.monit.description')}</CardDescription>
        </CardHeader>
        {monitLoading ? (
          <CardContent><div className="flex items-center gap-2 text-muted-foreground"><RefreshCw className="h-4 w-4 animate-spin" /> {t('GatewayMonitoringTab.monit.loading')}</div></CardContent>
        ) : (() => {
          const m = monitData?.data || {};
          const svc = m.service || {};
          const services = m.services || [];
          const tests = m.tests || [];
          const alerts = m.alerts || [];
          return (
            <CardContent noOffset className="space-y-4">
              <dl className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                <div>
                  <dt className="text-muted-foreground">{t('GatewayMonitoringTab.monit.service')}</dt>
                  <dd><Badge variant={svc.status === 'running' ? 'default' : 'secondary'}>{svc.status || t('GatewayMonitoringTab.common.unknown')}</Badge></dd>
                </div>
                <div>
                  <dt className="text-muted-foreground">{t('GatewayMonitoringTab.monit.monitoredServices')}</dt>
                  <dd className="font-medium">{services.length}</dd>
                </div>
                <div>
                  <dt className="text-muted-foreground">{t('GatewayMonitoringTab.monit.tests')}</dt>
                  <dd className="font-medium">{tests.length}</dd>
                </div>
                <div>
                  <dt className="text-muted-foreground">{t('GatewayMonitoringTab.monit.alertRules')}</dt>
                  <dd className="font-medium">{alerts.length}</dd>
                </div>
              </dl>
              {services.length > 0 && (
                <div>
                  <h4 className="text-sm font-medium mb-2">{t('GatewayMonitoringTab.monit.monitoredServices')}</h4>
                  <div className="overflow-auto max-h-[200px] rounded border">
                    <table className="w-full text-xs">
                      <thead className="bg-muted sticky top-0"><tr><th className="px-3 py-2 text-left">{t('GatewayMonitoringTab.monit.table.name')}</th><th className="px-3 py-2 text-left">{t('GatewayMonitoringTab.monit.table.type')}</th><th className="px-3 py-2 text-left">{t('GatewayMonitoringTab.monit.table.address')}</th><th className="px-3 py-2 text-left">{t('GatewayMonitoringTab.monit.table.enabled')}</th></tr></thead>
                      <tbody>
                        {services.map((s: any, i: number) => (
                          <tr key={i} className="border-t"><td className="px-3 py-1.5 font-medium">{s.name}</td><td className="px-3 py-1.5">{s.type}</td><td className="px-3 py-1.5 font-mono">{s.address || s.path || '-'}</td><td className="px-3 py-1.5"><Badge variant={String(s.enabled) === '1' ? 'default' : 'secondary'}>{String(s.enabled) === '1' ? t('GatewayMonitoringTab.common.yes') : t('GatewayMonitoringTab.common.no')}</Badge></td></tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </CardContent>
          );
        })()}
      </Card>

      {/* ─── Telegraf ───────────────────────────────────────── */}
      <Card className="border-border/50">
        <CardHeader className="pb-4">
          <CardTitle>{t('GatewayMonitoringTab.telegraf.title')}</CardTitle>
          <CardDescription>{t('GatewayMonitoringTab.telegraf.description')}</CardDescription>
        </CardHeader>
        {telegrafLoading ? (
          <CardContent><div className="flex items-center gap-2 text-muted-foreground"><RefreshCw className="h-4 w-4 animate-spin" /> {t('GatewayMonitoringTab.telegraf.loading')}</div></CardContent>
        ) : (() => {
          const tg = telegrafData?.data || {};
          const settings = tg.settings || {};
          const svc = tg.service || {};
          const tEnabled = settings.enabled === '1' || settings.enabled === true;
          return (
            <CardContent noOffset>
              <dl className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                <div>
                  <dt className="text-muted-foreground">{t('GatewayMonitoringTab.telegraf.enabled')}</dt>
                  <dd><Badge variant={tEnabled ? 'default' : 'secondary'}>{tEnabled ? t('GatewayMonitoringTab.common.yes') : t('GatewayMonitoringTab.common.no')}</Badge></dd>
                </div>
                <div>
                  <dt className="text-muted-foreground">{t('GatewayMonitoringTab.telegraf.service')}</dt>
                  <dd><Badge variant={svc.status === 'running' ? 'default' : 'secondary'}>{svc.status || t('GatewayMonitoringTab.common.unknown')}</Badge></dd>
                </div>
                {settings.graphite_server && (
                  <div>
                    <dt className="text-muted-foreground">{t('GatewayMonitoringTab.telegraf.graphiteServer')}</dt>
                    <dd className="font-mono text-xs">{settings.graphite_server}</dd>
                  </div>
                )}
                {settings.influx_url && (
                  <div>
                    <dt className="text-muted-foreground">{t('GatewayMonitoringTab.telegraf.influxUrl')}</dt>
                    <dd className="font-mono text-xs">{settings.influx_url}</dd>
                  </div>
                )}
                {settings.influx_database && (
                  <div>
                    <dt className="text-muted-foreground">{t('GatewayMonitoringTab.telegraf.influxDatabase')}</dt>
                    <dd className="font-mono text-xs">{settings.influx_database}</dd>
                  </div>
                )}
              </dl>
            </CardContent>
          );
        })()}
      </Card>

      {/* ─── NetFlow / sFlow ─────────────────────────────────── */}
      <Card className="border-border/50">
        <CardHeader className="pb-4">
          <CardTitle>{t('GatewayMonitoringTab.netflow.title')}</CardTitle>
          <CardDescription>{t('GatewayMonitoringTab.netflow.description')}</CardDescription>
        </CardHeader>
        {netflowLoading ? (
          <CardContent><div className="flex items-center gap-2 text-muted-foreground"><RefreshCw className="h-4 w-4 animate-spin" /> {t('GatewayMonitoringTab.netflow.loading')}</div></CardContent>
        ) : (() => {
          const nf = netflowData?.data || {};
          const settings = nf.settings || {};
          const svc = nf.service || {};
          const nfEnabled = settings.capture_enabled === '1' || settings.capture_enabled === true;
          return (
            <CardContent noOffset>
              <dl className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                <div>
                  <dt className="text-muted-foreground">{t('GatewayMonitoringTab.netflow.capture')}</dt>
                  <dd><Badge variant={nfEnabled ? 'default' : 'secondary'}>{nfEnabled ? t('GatewayMonitoringTab.common.enabled') : t('GatewayMonitoringTab.common.disabled')}</Badge></dd>
                </div>
                <div>
                  <dt className="text-muted-foreground">{t('GatewayMonitoringTab.netflow.service')}</dt>
                  <dd><Badge variant={svc.status === 'running' ? 'default' : 'secondary'}>{svc.status || t('GatewayMonitoringTab.common.unknown')}</Badge></dd>
                </div>
                {settings.interfaces && (
                  <div>
                    <dt className="text-muted-foreground">{t('GatewayMonitoringTab.netflow.interfaces')}</dt>
                    <dd className="font-mono text-xs">{settings.interfaces}</dd>
                  </div>
                )}
                {settings.collect_version && (
                  <div>
                    <dt className="text-muted-foreground">{t('GatewayMonitoringTab.netflow.version')}</dt>
                    <dd className="font-medium">v{settings.collect_version}</dd>
                  </div>
                )}
                {settings.collect_port && (
                  <div>
                    <dt className="text-muted-foreground">{t('GatewayMonitoringTab.netflow.listenPort')}</dt>
                    <dd className="font-mono text-xs">{settings.collect_port}</dd>
                  </div>
                )}
              </dl>
            </CardContent>
          );
        })()}
      </Card>
    </>
  );
}

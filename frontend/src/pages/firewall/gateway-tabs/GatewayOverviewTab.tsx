// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * GatewayOverviewTab · device summary stat cards, gateway/firmware info,
 * WAN gateway health, and a raw live-status fallback panel.
 *
 * Extracted from GatewayDetailPage as part of the monolith breakup. Pure
 * presentation · receives live read state and retry callbacks via props.
 */
/* eslint-disable @typescript-eslint/no-explicit-any */
import { useTranslation } from 'react-i18next';
import { Activity, Clock, Cpu, Globe, HardDrive, Lock, Settings } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { StatsGrid, type StatItem } from '@/components/ui/stats-grid';
import type { GatewayConnection } from '@/lib/api';
import { GatewayLiveReadNotice } from './GatewayLiveReadNotice';

export interface GatewayOverviewTabProps {
  gw: GatewayConnection;
  vendorLabel: string;
  deviceSummary: Record<string, any>;
  firmware: Record<string, any>;
  firmwareLoading?: boolean;
  firmwareError?: boolean;
  onRetryFirmware?: () => void;
  healthLoading?: boolean;
  healthError?: boolean;
  onRetryHealth?: () => void;
  gwHealth: any[];
  liveStatus: any;
}

export function GatewayOverviewTab({
  gw,
  vendorLabel,
  deviceSummary,
  firmware,
  firmwareLoading = false, firmwareError = false, onRetryFirmware,
  healthLoading = false, healthError = false, onRetryHealth,
  gwHealth,
  liveStatus,
}: GatewayOverviewTabProps) {
  const { t } = useTranslation('firewall');
  const unknown = t('GatewayOverviewTab.common.unknown');
  const availability = [firmware.update_available, firmware.needs_update, firmware.upgrade_available];
  const update = availability.some(value => value === true) ? true : availability.some(value => value === false) ? false : null;
  const firmwareRows = firmwareLoading || firmwareError ? [] : [
    [t('GatewayOverviewTab.firmware.firmware'), firmware.current_version || firmware.product_version || firmware.version || unknown],
    [t('GatewayOverviewTab.firmware.latestVersion'), firmware.latest_version || firmware.new_version || unknown],
    [t('GatewayOverviewTab.firmware.updateAvailable'), update === null ? unknown : update ? t('GatewayOverviewTab.firmware.updateYes', { version: firmware.latest_version || firmware.new_version || '?' }) : t('GatewayOverviewTab.common.no')],
  ];
  const healthState = (status: string) => {
    const known = ['online', 'offline', 'none', 'pending', 'loss', 'delay'];
    return t(`GatewayOverviewTab.wanHealth.states.${known.includes(status) ? status : 'unknown'}`);
  };
  const sample = (value: unknown, unit: string) => typeof value === 'number' && Number.isFinite(value) && value >= 0 ? `${value.toFixed(1)}${unit}` : unknown;


  // Build the device summary stat items dynamically · only include cards
  // for fields that the gateway actually reports.
  const summaryStats: StatItem[] = [];
  const cpu = deviceSummary.cpu_usage_pct ?? deviceSummary.cpu_usage;
  if (cpu != null) {
    summaryStats.push({
      title: t('GatewayOverviewTab.stats.cpuUsage'),
      value: `${cpu}%`,
      icon: Cpu,
      variant: cpu > 80 ? 'destructive' : 'primary',
    });
  }
  const mem = deviceSummary.memory_usage_pct ?? deviceSummary.memory_usage;
  if (mem != null) {
    summaryStats.push({
      title: t('GatewayOverviewTab.stats.memory'),
      value: `${mem}%`,
      icon: Activity,
      variant: mem > 85 ? 'destructive' : 'primary',
    });
  }
  const disk = deviceSummary.disk_usage_pct ?? deviceSummary.disk_usage;
  if (disk != null) {
    summaryStats.push({
      title: t('GatewayOverviewTab.stats.disk'),
      value: `${disk}%`,
      icon: HardDrive,
      variant: disk > 90 ? 'destructive' : 'primary',
    });
  }
  const uptime = deviceSummary.uptime_text || deviceSummary.uptime;
  if (uptime != null && uptime !== '') {
    summaryStats.push({
      title: t('GatewayOverviewTab.stats.uptime'),
      value: uptime,
      icon: Clock,
      variant: 'primary',
    });
  }
  if (deviceSummary.version) {
    summaryStats.push({
      title: t('GatewayOverviewTab.stats.version'),
      value: deviceSummary.version,
      icon: Settings,
      variant: 'primary',
    });
  }
  if (deviceSummary.wan_ip) {
    summaryStats.push({
      title: t('GatewayOverviewTab.stats.wanIp'),
      value: deviceSummary.wan_ip,
      icon: Globe,
      variant: 'primary',
      description: t('GatewayOverviewTab.stats.wanIpDescription', {
        latency: typeof deviceSummary.wan_delay_ms === 'number' && Number.isFinite(deviceSummary.wan_delay_ms) && deviceSummary.wan_delay_ms >= 0
          ? t('GatewayOverviewTab.stats.latencyValue', { value: deviceSummary.wan_delay_ms })
          : t('GatewayOverviewTab.common.unknown'),
        loss: typeof deviceSummary.wan_loss_pct === 'number' && Number.isFinite(deviceSummary.wan_loss_pct) && deviceSummary.wan_loss_pct >= 0 && deviceSummary.wan_loss_pct <= 100
          ? t('GatewayOverviewTab.stats.lossValue', { value: deviceSummary.wan_loss_pct })
          : t('GatewayOverviewTab.common.unknown'),
      }),
    });
  }
  const knownCount = (value: unknown): value is number => typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
  if (knownCount(deviceSummary.services_running) && knownCount(deviceSummary.services_stopped)) {
    summaryStats.push({
      title: t('GatewayOverviewTab.stats.services'),
      value: t('GatewayOverviewTab.stats.servicesRunning', { count: deviceSummary.services_running }),
      icon: Activity,
      variant: 'primary',
      description: t('GatewayOverviewTab.stats.servicesStopped', { count: deviceSummary.services_stopped }),
    });
  }
  if (knownCount(deviceSummary.vpn_tunnels_up) && knownCount(deviceSummary.vpn_tunnels_total) && deviceSummary.vpn_tunnels_up <= deviceSummary.vpn_tunnels_total) {
    summaryStats.push({
      title: t('GatewayOverviewTab.stats.vpnTunnels'),
      value: `${deviceSummary.vpn_tunnels_up} / ${deviceSummary.vpn_tunnels_total}`,
      icon: Lock,
      variant: 'primary',
    });
  }

  return (
    <>
      {/* Device Summary Cards */}
      {summaryStats.length > 0 && (
        <StatsGrid columns={4} stats={summaryStats} />
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Gateway Info */}
        <Card className="border-border/50">
          <CardHeader className="pb-4">
            <CardTitle>{t('GatewayOverviewTab.gatewayInfo.title')}</CardTitle>
          </CardHeader>
          <CardContent>
            <dl className="space-y-3 text-sm">
              {[
                [t('GatewayOverviewTab.gatewayInfo.name'), gw.name],
                [t('GatewayOverviewTab.gatewayInfo.vendor'), vendorLabel],
                [t('GatewayOverviewTab.gatewayInfo.host'), `${gw.host}:${gw.port}`],
                [t('GatewayOverviewTab.gatewayInfo.sslVerify'), gw.verify_ssl ? t('GatewayOverviewTab.common.yes') : t('GatewayOverviewTab.common.no')],
                [t('GatewayOverviewTab.gatewayInfo.hostname'), gw.detected_hostname || '-'],
                [t('GatewayOverviewTab.gatewayInfo.version'), firmwareLoading || firmwareError ? unknown : firmware.current_version || firmware.product_version || firmware.version || unknown],
                [t('GatewayOverviewTab.gatewayInfo.model'), gw.detected_model || '-'],
                [t('GatewayOverviewTab.gatewayInfo.credentials'), gw.has_credentials ? t('GatewayOverviewTab.gatewayInfo.configured') : t('GatewayOverviewTab.gatewayInfo.missing')],
                [t('GatewayOverviewTab.gatewayInfo.created'), new Date(gw.created_at).toLocaleString()],
                [t('GatewayOverviewTab.gatewayInfo.updated'), new Date(gw.updated_at).toLocaleString()],
              ].map(([label, val]) => (
                <div key={label} className="flex justify-between">
                  <dt className="text-muted-foreground">{label}</dt>
                  <dd className="font-medium text-right">{val}</dd>
                </div>
              ))}
            </dl>
          </CardContent>
        </Card>

        {/* Firmware & Sync */}
        <Card className="border-border/50">
          <CardHeader className="pb-4">
            <CardTitle>{t('GatewayOverviewTab.firmware.title')}</CardTitle>
          </CardHeader>
          {(firmwareLoading || firmwareError) && <GatewayLiveReadNotice loading={firmwareLoading} onRetry={onRetryFirmware} />}
          <CardContent>
            <dl className="space-y-3 text-sm">
              {[
                ...firmwareRows,
                [t('GatewayOverviewTab.firmware.autoSync'), gw.sync_enabled ? t('GatewayOverviewTab.common.enabled') : t('GatewayOverviewTab.common.disabled')],
                [t('GatewayOverviewTab.firmware.interval'), `${gw.sync_interval_seconds}s`],
                [t('GatewayOverviewTab.firmware.syncStatus'), gw.sync_status],
                [t('GatewayOverviewTab.firmware.lastSync'), gw.last_sync_at ? new Date(gw.last_sync_at).toLocaleString() : t('GatewayOverviewTab.firmware.never')],
                [t('GatewayOverviewTab.firmware.lastError'), gw.last_sync_error || '-'],
                [t('GatewayOverviewTab.firmware.lastSeen'), gw.last_seen_at ? new Date(gw.last_seen_at).toLocaleString() : '-'],
              ].map(([label, val]) => (
                <div key={label} className="flex justify-between">
                  <dt className="text-muted-foreground">{label}</dt>
                  <dd className="font-medium text-right max-w-[60%] truncate">{val}</dd>
                </div>
              ))}
            </dl>
            {gw.capabilities && gw.capabilities.length > 0 && (
              <div className="mt-4 pt-4 border-t">
                <p className="text-sm text-muted-foreground mb-2">{t('GatewayOverviewTab.firmware.capabilities')}</p>
                <div className="flex flex-wrap gap-1">
                  {gw.capabilities.map((cap) => (
                    <Badge key={cap} variant="secondary" className="text-xs">{cap}</Badge>
                  ))}
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* WAN Gateway Health */}
      {
        <Card className="border-border/50">
          <CardHeader className="pb-4">
            <CardTitle>{t('GatewayOverviewTab.wanHealth.title')}</CardTitle>
          </CardHeader>
          {healthLoading || healthError ? <GatewayLiveReadNotice loading={healthLoading} onRetry={onRetryHealth} /> : <CardContent>
            {gwHealth.length === 0 && <p className="text-sm text-muted-foreground">{t('GatewayOverviewTab.wanHealth.empty')}</p>}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
              {gwHealth.map((g: any, i: number) => {
                const variant = g.status === 'online' ? 'default' : g.status === 'offline' ? 'destructive' : g.status === 'loss' || g.status === 'delay' ? 'warning' : 'muted';
                return (
                  <div key={i} className="p-3 rounded-lg border space-y-1.5">
                    <div className="flex items-center justify-between">
                      <span className="font-medium text-sm">{g.name || g.interface || t('GatewayOverviewTab.wanHealth.gatewayFallback', { index: i + 1 })}</span>
                      <Badge variant={variant}>
                        {healthState(g.status)}
                      </Badge>
                    </div>
                    {g.address && <p className="text-xs text-muted-foreground">{t('GatewayOverviewTab.wanHealth.ip')} <span className="font-mono">{g.address}</span></p>}
                    {g.monitor_ip && <p className="text-xs text-muted-foreground">{t('GatewayOverviewTab.wanHealth.monitor')} <span className="font-mono">{g.monitor_ip}</span></p>}
                    <div className="flex gap-3 text-xs">
                      <span className="text-muted-foreground">{t('GatewayOverviewTab.wanHealth.latency')} <span className="font-mono">{sample(g.delay_ms, ' ms')}</span></span>
                      <span className="text-muted-foreground">{t('GatewayOverviewTab.wanHealth.loss')} <span className="font-mono">{sample(g.loss_pct, '%')}</span></span>
                      <span className="text-muted-foreground">{t('GatewayOverviewTab.wanHealth.jitter')} <span className="font-mono">{sample(g.stddev_ms, ' ms')}</span></span>
                    </div>
                    {g.default_gateway && <Badge variant="outline" className="text-xs mt-1">{t('GatewayOverviewTab.wanHealth.default')}</Badge>}
                  </div>
                );
              })}
            </div>
          </CardContent>}
        </Card>
      }

      {/* Raw status (fallback) */}
      {liveStatus && (
        <Card className="border-border/50">
          <CardHeader className="pb-4">
            <CardTitle>{t('GatewayOverviewTab.liveStatus.title')}</CardTitle>
            <CardDescription>{t('GatewayOverviewTab.liveStatus.description')}</CardDescription>
          </CardHeader>
          <CardContent>
            <pre className="text-xs bg-muted p-4 rounded-lg overflow-auto max-h-[300px]">
              {JSON.stringify(liveStatus, null, 2)}
            </pre>
          </CardContent>
        </Card>
      )}
    </>
  );
}

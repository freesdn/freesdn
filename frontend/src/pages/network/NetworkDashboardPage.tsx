// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN - Network Dashboard Page
 * 
 * Overview dashboard for network management with summary stats,
 * quick actions, and topology visualization placeholder.
 */

import { useQuery } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { useSiteStore } from '@/stores/siteStore';
import { Link } from 'react-router-dom';
import {
  Network,
  Wifi,
  Users,
  HardDrive,
  Router,
  Cable,
  ArrowRight,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Server,
  Layers,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Progress } from '@/components/ui/progress';
import { StatsGrid } from '@/components/ui/stats-grid';
import { networkApi, NetworkSummary, NetworkTopology } from '@/lib/api';
import { cn } from '@/lib/utils';
import { PageHeader } from '@/components/layout';

// Quick navigation card
interface QuickNavCardProps {
  title: string;
  description: string;
  icon: typeof Network;
  iconColor: string;
  bgColor: string;
  href: string;
  count?: number;
}

function QuickNavCard({ title, description, icon: Icon, iconColor, bgColor, href, count }: QuickNavCardProps) {
  return (
    <Link to={href}>
      <Card className="hover:shadow-md transition-shadow cursor-pointer group">
        <CardContent noOffset>
          <div className="flex items-start justify-between">
            <div className={cn('p-3 rounded-lg', bgColor)}>
              <Icon className={cn('h-6 w-6', iconColor)} />
            </div>
            {count !== undefined && (
              <span className="text-2xl font-bold">{count}</span>
            )}
          </div>
          <div className="mt-4">
            <h3 className="font-semibold group-hover:text-primary transition-colors flex items-center gap-2">
              {title}
              <ArrowRight className="h-4 w-4 opacity-0 -translate-x-2 group-hover:opacity-100 group-hover:translate-x-0 transition-all" />
            </h3>
            <p className="text-sm text-muted-foreground mt-1">{description}</p>
          </div>
        </CardContent>
      </Card>
    </Link>
  );
}

// Device type breakdown
function DeviceBreakdown({ devices }: { devices: Record<string, number> }) {
  const { t } = useTranslation('network');
  const total = Object.values(devices).reduce((sum, count) => sum + count, 0);

  const deviceConfig: Record<string, { icon: typeof Server; color: string; label: string }> = {
    switch: { icon: HardDrive, color: 'bg-blue-500', label: t('NetworkDashboardPage.deviceTypes.switch') },
    access_point: { icon: Wifi, color: 'bg-purple-500', label: t('NetworkDashboardPage.deviceTypes.accessPoint') },
    gateway: { icon: Router, color: 'bg-emerald-500', label: t('NetworkDashboardPage.deviceTypes.gateway') },
    router: { icon: Router, color: 'bg-amber-500', label: t('NetworkDashboardPage.deviceTypes.router') },
    other: { icon: Server, color: 'bg-slate-500', label: t('NetworkDashboardPage.deviceTypes.other') },
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm font-medium">{t('NetworkDashboardPage.deviceBreakdown.title')}</CardTitle>
        <CardDescription>{t('NetworkDashboardPage.deviceBreakdown.description')}</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {Object.entries(devices).map(([type, count]) => {
          const config = deviceConfig[type] || deviceConfig.other;
          const percentage = total > 0 ? (count / total) * 100 : 0;
          
          return (
            <div key={type} className="space-y-2">
              <div className="flex items-center justify-between text-sm">
                <div className="flex items-center gap-2">
                  <config.icon className="h-4 w-4 text-muted-foreground" />
                  <span>{config.label}</span>
                </div>
                <span className="font-medium">{count}</span>
              </div>
              <Progress value={percentage} className="h-2" />
            </div>
          );
        })}
        {Object.keys(devices).length === 0 && (
          <p className="text-sm text-muted-foreground text-center py-4">
            {t('NetworkDashboardPage.deviceBreakdown.empty')}
          </p>
        )}
      </CardContent>
    </Card>
  );
}

// Client connection breakdown
function ClientBreakdown({ clients }: { clients: NetworkSummary['clients'] }) {
  const { t } = useTranslation('network');
  const wirelessPercent = clients.total > 0
    ? Math.round((clients.wireless / clients.total) * 100) 
    : 0;
  const wiredPercent = clients.total > 0 
    ? Math.round((clients.wired / clients.total) * 100) 
    : 0;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm font-medium">{t('NetworkDashboardPage.clientBreakdown.title')}</CardTitle>
        <CardDescription>{t('NetworkDashboardPage.clientBreakdown.description')}</CardDescription>
      </CardHeader>
      <CardContent>
        <div className="space-y-6">
          <div className="flex items-center justify-center gap-8">
            <div className="text-center">
              <div className="flex h-16 w-16 items-center justify-center rounded-full bg-purple-100 dark:bg-purple-900/30">
                <Wifi className="h-8 w-8 text-purple-500" />
              </div>
              <p className="mt-2 text-2xl font-bold">{clients.wireless}</p>
              <p className="text-xs text-muted-foreground">{t('NetworkDashboardPage.clientBreakdown.wireless')}</p>
            </div>
            <div className="text-center">
              <div className="flex h-16 w-16 items-center justify-center rounded-full bg-blue-100 dark:bg-blue-900/30">
                <Cable className="h-8 w-8 text-blue-500" />
              </div>
              <p className="mt-2 text-2xl font-bold">{clients.wired}</p>
              <p className="text-xs text-muted-foreground">{t('NetworkDashboardPage.clientBreakdown.wired')}</p>
            </div>
          </div>
          
          <div className="space-y-2">
            <div className="flex h-3 overflow-hidden rounded-full bg-muted">
              <div 
                className="bg-purple-500 transition-all" 
                style={{ width: `${wirelessPercent}%` }} 
              />
              <div 
                className="bg-blue-500 transition-all" 
                style={{ width: `${wiredPercent}%` }} 
              />
            </div>
            <div className="flex justify-between text-xs text-muted-foreground">
              <span>{t('NetworkDashboardPage.clientBreakdown.percentWireless', { percent: wirelessPercent })}</span>
              <span>{t('NetworkDashboardPage.clientBreakdown.percentWired', { percent: wiredPercent })}</span>
            </div>
          </div>

          {clients.blocked > 0 && (
            <div className="flex items-center justify-between rounded-lg border border-red-200 bg-red-50 p-3 dark:border-red-900 dark:bg-red-900/20">
              <span className="text-sm text-red-600 dark:text-red-400">{t('NetworkDashboardPage.clientBreakdown.blockedClients')}</span>
              <span className="font-bold text-red-600 dark:text-red-400">{clients.blocked}</span>
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
}

// Network health indicator
function NetworkHealth({ summary }: { summary: NetworkSummary }) {
  const { t } = useTranslation('network');
  const totalDevices = summary.devices.total;
  const onlineDevices = summary.devices.online;
  const healthPercent = totalDevices > 0 ? Math.round((onlineDevices / totalDevices) * 100) : 0;

  const getHealthStatus = (percent: number) => {
    if (percent >= 90) return { status: t('NetworkDashboardPage.health.excellent'), color: 'text-emerald-500', bgColor: 'bg-emerald-500' };
    if (percent >= 70) return { status: t('NetworkDashboardPage.health.good'), color: 'text-green-500', bgColor: 'bg-green-500' };
    if (percent >= 50) return { status: t('NetworkDashboardPage.health.fair'), color: 'text-amber-500', bgColor: 'bg-amber-500' };
    return { status: t('NetworkDashboardPage.health.critical'), color: 'text-red-500', bgColor: 'bg-red-500' };
  };

  const health = getHealthStatus(healthPercent);

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm font-medium">{t('NetworkDashboardPage.health.title')}</CardTitle>
        <CardDescription>{t('NetworkDashboardPage.health.description')}</CardDescription>
      </CardHeader>
      <CardContent>
        <div className="flex items-center justify-center">
          <div className="relative h-32 w-32">
            <svg className="h-full w-full -rotate-90" viewBox="0 0 100 100">
              <circle
                className="stroke-border"
                strokeWidth="10"
                fill="none"
                r="40"
                cx="50"
                cy="50"
              />
              <circle
                className={cn('transition-all duration-500', health.bgColor.replace('bg-', 'stroke-'))}
                strokeWidth="10"
                strokeLinecap="round"
                fill="none"
                r="40"
                cx="50"
                cy="50"
                strokeDasharray={`${healthPercent * 2.51} 251`}
              />
            </svg>
            <div className="absolute inset-0 flex flex-col items-center justify-center">
              <span className={cn('text-3xl font-bold', health.color)}>{healthPercent}%</span>
              <span className="text-xs text-muted-foreground">{health.status}</span>
            </div>
          </div>
        </div>
        
        <div className="mt-4 grid grid-cols-2 gap-4 text-center">
          <div className="rounded-lg bg-emerald-50 p-2 dark:bg-emerald-900/20">
            <CheckCircle className="mx-auto h-5 w-5 text-emerald-500" />
            <p className="mt-1 text-lg font-bold text-emerald-600 dark:text-emerald-400">{onlineDevices}</p>
            <p className="text-xs text-muted-foreground">{t('NetworkDashboardPage.health.online')}</p>
          </div>
          <div className="rounded-lg bg-red-50 p-2 dark:bg-red-900/20">
            <XCircle className="mx-auto h-5 w-5 text-red-500" />
            <p className="mt-1 text-lg font-bold text-red-600 dark:text-red-400">{summary.devices.offline}</p>
            <p className="text-xs text-muted-foreground">{t('NetworkDashboardPage.health.offline')}</p>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

// Topology placeholder
function TopologyPreview({ topology }: { topology?: NetworkTopology }) {
  const { t } = useTranslation('network');
  const nodeCount = topology?.nodes?.length || 0;
  const linkCount = topology?.links?.length || 0;

  return (
    <Card className="col-span-2">
      <CardHeader>
        <div className="flex items-center justify-between">
          <div>
            <CardTitle className="text-sm font-medium">{t('NetworkDashboardPage.topology.title')}</CardTitle>
            <CardDescription>{t('NetworkDashboardPage.topology.description')}</CardDescription>
          </div>
          <Button variant="outline" size="sm" asChild>
            <Link to="/topology">
              {t('NetworkDashboardPage.topology.viewFullMap')}
              <ArrowRight className="ml-2 h-4 w-4" />
            </Link>
          </Button>
        </div>
      </CardHeader>
      <CardContent>
        <div className="flex h-48 items-center justify-center rounded-lg border-2 border-dashed bg-muted">
          <div className="text-center">
            <Network className="mx-auto h-12 w-12 text-muted-foreground" />
            <p className="mt-4 text-sm text-muted-foreground">
              {nodeCount > 0 ? (
                <>
                  <span className="font-medium text-foreground">{t('NetworkDashboardPage.topology.devicesCount', { count: nodeCount })}</span>{' '}
                  {t('NetworkDashboardPage.topology.connectedVia')}{' '}
                  <span className="font-medium text-foreground">{t('NetworkDashboardPage.topology.linksCount', { count: linkCount })}</span>
                </>
              ) : (
                t('NetworkDashboardPage.topology.noData')
              )}
            </p>
            <Button variant="link" size="sm" className="mt-2" asChild>
              <Link to="/topology">
                {t('NetworkDashboardPage.topology.openViewer')}
              </Link>
            </Button>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

// Main component
export default function NetworkDashboardPage() {
  const { t } = useTranslation('network');
  // Site context
  const selectedSiteId = useSiteStore((s) => s.selectedSiteId);

  // Fetch network summary
  const { data: summaryData, isLoading: summaryLoading, isError: isSummaryError, refetch: refetchSummary } = useQuery({
    queryKey: ['network-summary', { siteId: selectedSiteId }],
    queryFn: () => networkApi.summary.get(selectedSiteId ?? undefined),
  });

  // Fetch topology
  const { data: topologyData, isLoading: topologyLoading, isError: isTopologyError } = useQuery({
    queryKey: ['network-topology', { siteId: selectedSiteId }],
    queryFn: () => networkApi.topology.get(selectedSiteId ?? undefined),
  });

  const summary: NetworkSummary = summaryData?.data || {
    devices: { total: 0, online: 0, offline: 0, by_type: {} },
    clients: { total: 0, online: 0, wired: 0, wireless: 0, blocked: 0 },
    total_vlans: 0,
    total_wifi_networks: 0,
  };

  const topology = topologyData?.data;

  const isLoading = summaryLoading || topologyLoading;
  const hasQueryError = isSummaryError || isTopologyError;

  return (
    <div className="space-y-6">
      {/* Header */}
      <PageHeader
        icon={Network}
        title={t('NetworkDashboardPage.header.title')}
        subtitle={t('NetworkDashboardPage.header.subtitle')}
        onRefresh={() => refetchSummary()}
        refreshing={isLoading}
      />

      {hasQueryError && (
        <Card className="border-destructive">
          <CardContent noOffset className="p-4 flex items-center gap-3">
            <AlertTriangle className="h-5 w-5 text-destructive" />
            <span className="text-sm">{t('NetworkDashboardPage.errors.partialLoad')}</span>
          </CardContent>
        </Card>
      )}

      {/* Quick Stats */}
      <StatsGrid
        columns={4}
        isLoading={summaryLoading}
        stats={[
          {
            title: t('NetworkDashboardPage.stats.totalDevices'),
            value: summary.devices.total,
            icon: Server,
            variant: 'primary',
            description: t('NetworkDashboardPage.stats.onlineCount', { count: summary.devices.online }),
          },
          {
            title: t('NetworkDashboardPage.stats.networkClients'),
            value: summary.clients.total,
            icon: Users,
            variant: 'primary',
            description: t('NetworkDashboardPage.stats.activeCount', { count: summary.clients.online }),
          },
          {
            title: t('NetworkDashboardPage.stats.vlans'),
            value: summary.total_vlans,
            icon: Layers,
            variant: 'success',
            description: t('NetworkDashboardPage.stats.networkSegments'),
          },
          {
            title: t('NetworkDashboardPage.stats.wifiNetworks'),
            value: summary.total_wifi_networks,
            icon: Wifi,
            variant: 'warning',
            description: t('NetworkDashboardPage.stats.ssidsConfigured'),
          },
        ]}
      />

      {/* Quick Navigation */}
      <div>
        <h2 className="text-lg font-semibold mb-4">{t('NetworkDashboardPage.quickAccess.heading')}</h2>
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <QuickNavCard
            title={t('NetworkDashboardPage.quickAccess.vlans.title')}
            description={t('NetworkDashboardPage.quickAccess.vlans.description')}
            icon={Layers}
            iconColor="text-blue-600"
            bgColor="bg-blue-100 dark:bg-blue-900/30"
            href="/network/vlans"
            count={summary.total_vlans}
          />
          <QuickNavCard
            title={t('NetworkDashboardPage.quickAccess.wifi.title')}
            description={t('NetworkDashboardPage.quickAccess.wifi.description')}
            icon={Wifi}
            iconColor="text-purple-600"
            bgColor="bg-purple-100 dark:bg-purple-900/30"
            href="/network/wifi"
            count={summary.total_wifi_networks}
          />
          <QuickNavCard
            title={t('NetworkDashboardPage.quickAccess.clients.title')}
            description={t('NetworkDashboardPage.quickAccess.clients.description')}
            icon={Users}
            iconColor="text-emerald-600"
            bgColor="bg-emerald-100 dark:bg-emerald-900/30"
            href="/network/clients"
            count={summary.clients.total}
          />
          <QuickNavCard
            title={t('NetworkDashboardPage.quickAccess.ports.title')}
            description={t('NetworkDashboardPage.quickAccess.ports.description')}
            icon={Cable}
            iconColor="text-amber-600"
            bgColor="bg-amber-100 dark:bg-amber-900/30"
            href="/switches"
          />
        </div>
      </div>

      {/* Detailed Stats */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        <NetworkHealth summary={summary} />
        <DeviceBreakdown devices={summary.devices.by_type} />
        <ClientBreakdown clients={summary.clients} />
      </div>

      {/* Topology Preview */}
      <TopologyPreview topology={topology} />
    </div>
  );
}

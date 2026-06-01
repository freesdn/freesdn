// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN · VoIP Fleet Dashboard
 *
 * GDMS-style fleet overview with:
 *  - Status & lifecycle metric cards
 *  - Vendor / firmware distribution charts
 *  - Recent discoveries & pending actions
 *  - Quick-action buttons (scan, provision, bulk ops)
 */

import { useQuery } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { useSiteStore } from '@/stores/siteStore';
import {
  Phone, Wifi, WifiOff, Radar, Upload, CheckCircle, Wrench,
  XCircle, Download, BarChart3, Cpu, Shield,
  Activity, Server, HardDrive, Plus, Search, AlertTriangle,
} from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { StatsGrid } from '@/components/ui/stats-grid';
import { Progress } from '@/components/ui/progress';
import { voipApi } from '@/lib/api';
import { cn } from '@/lib/utils';
import { PageHeader } from '@/components/layout';
import type { FleetDashboard } from './types';

export default function FleetDashboardPage() {
  const { t } = useTranslation('voip');
  const navigate = useNavigate();
  const selectedSiteId = useSiteStore((s) => s.selectedSiteId);

  const { data: dashRes, isLoading, isError, refetch } = useQuery({
    queryKey: ['voip-fleet-dashboard', { siteId: selectedSiteId }],
    queryFn: () => voipApi.getFleetDashboard(selectedSiteId ?? undefined),
    refetchInterval: 30_000,
    staleTime: 15_000,
  });

  const dash: FleetDashboard | null = dashRes?.data ?? null;

  const totalPhones = dash?.total_phones ?? 0;
  const online = dash?.online ?? 0;
  const offline = dash?.offline ?? 0;
  const sipReg = dash?.sip_registered ?? 0;
  const sipUnreg = dash?.sip_unregistered ?? 0;
  const discovered = dash?.recently_discovered ?? 0;
  const pendProv = dash?.pending_provision ?? 0;

  const managed = dash?.by_lifecycle?.managed ?? 0;
  const maint = dash?.by_lifecycle?.maintenance ?? 0;
  const disco = dash?.by_lifecycle?.discovered ?? 0;
  const onboarding = dash?.by_lifecycle?.onboarding ?? 0;
  const decomm = dash?.by_lifecycle?.decommissioned ?? 0;

  const topVendors = Object.entries(dash?.by_vendor ?? {}).sort((a, b) => b[1] - a[1]).slice(0, 6);
  const topModels = Object.entries(dash?.by_model ?? {}).sort((a, b) => b[1] - a[1]).slice(0, 8);
  const topFW = Object.entries(dash?.by_firmware ?? {}).sort((a, b) => b[1] - a[1]).slice(0, 8);

  return (
    <div className="space-y-6">
      <PageHeader
        icon={BarChart3}
        title={t('FleetDashboardPage.header.title')}
        subtitle={t('FleetDashboardPage.header.subtitle')}
        onRefresh={() => refetch()}
        refreshing={isLoading}
        primaryAction={{
          label: t('FleetDashboardPage.actions.discoverDevices'),
          icon: Radar,
          onClick: () => navigate('/voip/discovery'),
        }}
        secondaryActions={[
          { label: t('FleetDashboardPage.actions.addPhone'), icon: Plus, onClick: () => navigate('/voip/phones?action=add') },
          { label: t('FleetDashboardPage.actions.viewAllPhones'), icon: Phone, onClick: () => navigate('/voip/phones') },
        ]}
      />

      {isError && (
        <Card className="border-destructive">
          <CardContent noOffset className="p-4 flex items-center gap-3">
            <AlertTriangle className="h-5 w-5 text-destructive" />
            <span className="text-sm">{t('FleetDashboardPage.error.partialLoad')}</span>
          </CardContent>
        </Card>
      )}

      {/* Top metrics row */}
      <StatsGrid
        columns={4}
        stats={[
          { title: t('FleetDashboardPage.stats.totalPhones'), value: totalPhones, icon: Phone, variant: 'primary' },
          { title: t('FleetDashboardPage.stats.online'), value: online, icon: CheckCircle, variant: 'success' },
          { title: t('FleetDashboardPage.stats.offline'), value: offline, icon: XCircle, variant: 'destructive' },
          { title: t('FleetDashboardPage.stats.sipRegistered'), value: sipReg, icon: Wifi, variant: 'success' },
          { title: t('FleetDashboardPage.stats.recentlyDiscovered'), value: discovered, icon: Radar, variant: 'info', description: t('FleetDashboardPage.stats.last24h') },
          { title: t('FleetDashboardPage.stats.pendingProvision'), value: pendProv, icon: Upload, variant: 'warning' },
        ]}
      />

      {/* Lifecycle breakdown + Quick Actions */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Lifecycle */}
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Activity className="h-5 w-5 text-primary" />
              {t('FleetDashboardPage.lifecycle.title')}
            </CardTitle>
            <CardDescription>{t('FleetDashboardPage.lifecycle.description')}</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <LifecycleBar label={t('FleetDashboardPage.lifecycle.discovered')} value={disco} total={totalPhones} color="bg-blue-500" icon={Radar} />
              <LifecycleBar label={t('FleetDashboardPage.lifecycle.onboarding')} value={onboarding} total={totalPhones} color="bg-cyan-500" icon={Upload} />
              <LifecycleBar label={t('FleetDashboardPage.lifecycle.managed')} value={managed} total={totalPhones} color="bg-emerald-500" icon={CheckCircle} />
              <LifecycleBar label={t('FleetDashboardPage.lifecycle.maintenance')} value={maint} total={totalPhones} color="bg-amber-500" icon={Wrench} />
              <LifecycleBar label={t('FleetDashboardPage.lifecycle.decommissioned')} value={decomm} total={totalPhones} color="bg-muted-foreground" icon={XCircle} />
            </div>
          </CardContent>
        </Card>

        {/* Quick Actions */}
        <Card>
          <CardHeader>
            <CardTitle>{t('FleetDashboardPage.quickActions.title')}</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <Button className="w-full justify-start gap-2" variant="outline"
              onClick={() => navigate('/voip/discovery')}>
              <Radar className="h-4 w-4" /> {t('FleetDashboardPage.quickActions.runDiscoveryScan')}
            </Button>
            <Button className="w-full justify-start gap-2" variant="outline"
              onClick={() => navigate('/voip/phones?lifecycle=discovered')}>
              <Search className="h-4 w-4" /> {t('FleetDashboardPage.quickActions.reviewDiscovered', { count: disco })}
            </Button>
            <Button className="w-full justify-start gap-2" variant="outline"
              onClick={() => navigate('/voip/templates')}>
              <HardDrive className="h-4 w-4" /> {t('FleetDashboardPage.quickActions.configTemplates')}
            </Button>
            <Button className="w-full justify-start gap-2" variant="outline"
              onClick={() => navigate('/voip/firmware')}>
              <Download className="h-4 w-4" /> {t('FleetDashboardPage.quickActions.firmwareCompliance')}
            </Button>
            <Button className="w-full justify-start gap-2" variant="outline"
              onClick={() => navigate('/voip/pbx')}>
              <Server className="h-4 w-4" /> {t('FleetDashboardPage.quickActions.pbxSystems')}
            </Button>
          </CardContent>
        </Card>
      </div>

      {/* Vendor distribution + Model distribution + Firmware */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <DistributionCard title={t('FleetDashboardPage.distribution.vendor')} icon={Shield} entries={topVendors} total={totalPhones} />
        <DistributionCard title={t('FleetDashboardPage.distribution.model')} icon={Cpu} entries={topModels} total={totalPhones} />
        <DistributionCard title={t('FleetDashboardPage.distribution.firmware')} icon={HardDrive} entries={topFW} total={totalPhones} />
      </div>

      {/* SIP Registration overview */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Wifi className="h-5 w-5 text-primary" />
            {t('FleetDashboardPage.sip.title')}
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-center gap-6">
            <div className="flex-1">
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm font-medium text-emerald-500 flex items-center gap-1">
                  <Wifi className="h-4 w-4" /> {t('FleetDashboardPage.sip.registered')}
                </span>
                <span className="text-sm font-bold">{sipReg}</span>
              </div>
              <Progress value={totalPhones > 0 ? (sipReg / totalPhones) * 100 : 0}
                className="h-3 bg-muted" />
            </div>
            <div className="flex-1">
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm font-medium text-red-500 flex items-center gap-1">
                  <WifiOff className="h-4 w-4" /> {t('FleetDashboardPage.sip.unregistered')}
                </span>
                <span className="text-sm font-bold">{sipUnreg}</span>
              </div>
              <Progress value={totalPhones > 0 ? (sipUnreg / totalPhones) * 100 : 0}
                className="h-3 bg-muted" />
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}


// ── Sub-components ──────────────────────────────────────────────────────────

function LifecycleBar({ label, value, total, color, icon: Icon }: {
  label: string; value: number; total: number; color: string; icon: typeof CheckCircle;
}) {
  const pct = total > 0 ? (value / total) * 100 : 0;
  return (
    <div className="flex items-center gap-3">
      <Icon className="h-4 w-4 text-muted-foreground shrink-0" />
      <span className="w-28 text-sm font-medium truncate">{label}</span>
      <div className="flex-1 bg-muted rounded-full h-5 overflow-hidden">
        <div className={cn('h-full rounded-full transition-all', color)}
          style={{ width: `${Math.max(pct, 1)}%` }} />
      </div>
      <span className="w-12 text-xs text-right text-muted-foreground font-mono">{value}</span>
      <span className="w-14 text-xs text-right text-muted-foreground">{pct.toFixed(0)}%</span>
    </div>
  );
}

function DistributionCard({ title, icon: Icon, entries, total }: {
  title: string; icon: typeof Shield; entries: [string, number][]; total: number;
}) {
  const { t } = useTranslation('voip');
  const COLORS = [
    'bg-blue-500', 'bg-emerald-500', 'bg-amber-500', 'bg-purple-500',
    'bg-red-500', 'bg-cyan-500', 'bg-pink-500', 'bg-orange-500',
  ];

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2 text-base">
          <Icon className="h-4 w-4 text-primary" />
          {title}
        </CardTitle>
      </CardHeader>
      <CardContent>
        {entries.length === 0 ? (
          <p className="text-sm text-muted-foreground text-center py-4">{t('FleetDashboardPage.distribution.noData')}</p>
        ) : (
          <div className="space-y-2">
            {entries.map(([name, count], idx) => {
              const pct = total > 0 ? (count / total) * 100 : 0;
              return (
                <div key={name} className="flex items-center gap-2">
                  <div className={cn('h-2.5 w-2.5 rounded-full shrink-0', COLORS[idx % COLORS.length])} />
                  <span className="flex-1 text-sm truncate capitalize">{name || t('FleetDashboardPage.distribution.unknown')}</span>
                  <span className="text-xs text-muted-foreground font-mono">{count}</span>
                  <span className="text-xs text-muted-foreground w-10 text-right">{pct.toFixed(0)}%</span>
                </div>
              );
            })}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

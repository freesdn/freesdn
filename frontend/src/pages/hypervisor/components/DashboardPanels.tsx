// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { useTranslation } from 'react-i18next';
import { Activity, Box, Cpu, Globe, HardDrive, MemoryStick, Monitor, Network, Server } from 'lucide-react';
import { StatsGrid } from '@/components/ui/stats-grid';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { EmptyState, ErrorState } from '@/components/ui/empty-state';
import { Skeleton } from '@/components/ui/skeleton';
import { MetricBar } from '@/components/ui/metric-bar';
import type { FleetDashboard, HypervisorDashboard } from '@/lib/api';
import { DashboardObservation } from './DashboardObservation';
import { useObservationFreshness } from './dashboardObservationState';
import { formatBytes } from './helpers';

function Loading() {
  return <div className="grid grid-cols-2 md:grid-cols-4 gap-4">{Array.from({ length: 8 }, (_, i) => <Skeleton key={i} className="h-24" />)}</div>;
}

export function DashboardMetrics({ data }: { data: HypervisorDashboard | FleetDashboard }) {
  const { t } = useTranslation('hypervisor');
  const unknown = t('HypervisorPage.stats.unknown');
  const number = (value: number | null | undefined) => value != null && Number.isFinite(value) ? String(value) : unknown;
  const ratio = (used: number | null, total: number | null) => `${number(used)} / ${number(total)}`;
  const specs = [
    { key: 'cpu' as const, value: data.cpu_usage_percent, capacity: data.total_cpu_cores, icon: Cpu },
    { key: 'memory' as const, value: data.memory_usage_percent, capacity: data.total_memory_bytes, icon: MemoryStick },
    { key: 'node_filesystem' as const, value: data.storage_usage_percent, capacity: data.total_storage_bytes, icon: HardDrive },
  ];
  const valid = (item: typeof specs[number]) => data.metric_coverage?.[item.key]?.status === 'available' && item.value != null && Number.isFinite(item.value) && item.value >= 0 && item.value <= 100;
  const stats = [
    { title: t('HypervisorPage.stats.nodes'), value: ratio(data.online_nodes, data.total_nodes), icon: Server },
    { title: t('HypervisorPage.stats.vms'), value: ratio(data.running_vms, data.total_vms), icon: Monitor },
    { title: t('HypervisorPage.stats.containers'), value: ratio(data.running_containers, data.total_containers), icon: Box },
    ...specs.map(item => ({ title: t(`DashboardObservation.metrics.${item.key}`), value: valid(item) ? `${item.value}%` : unknown, icon: item.icon,
      description: valid(item) && item.capacity != null ? item.key === 'cpu' ? t('HypervisorPage.stats.coresCount', { count: item.capacity }) : formatBytes(item.capacity) : t('DashboardObservation.incompleteMetric'),
      variant: !valid(item) ? 'warning' as const : item.value! > 85 ? 'destructive' as const : 'default' as const,
    })),
  ];
  return <>
    <StatsGrid stats={stats} columns={3} />
    <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">{specs.map(item => <Card key={item.key}>
      <CardContent noOffset>
        <div className="flex items-center justify-between mb-2"><span>{t(`DashboardObservation.metrics.${item.key}`)}</span><strong>{valid(item) ? `${item.value!.toFixed(1)}%` : unknown}</strong></div>
        {valid(item) && <MetricBar value={item.value!} variant="thick" hideValue />}
      </CardContent>
    </Card>)}</div>
  </>;
}

export function DashboardTab({ dashLoading, dashError, dash, refetchDash, controllerId }: {
  dashLoading: boolean; dashError: boolean; dash: HypervisorDashboard | undefined; refetchDash: () => void; controllerId: string;
}) {
  const { t } = useTranslation('hypervisor');
  const freshness = useObservationFreshness(dash);
  if (dashLoading) return <Loading />;
  if (dashError || !dash || dash.controller_id !== controllerId) return <ErrorState message={t('HypervisorPage.dashboard.loadError')} onRetry={refetchDash} />;
  return <div className="space-y-6">
    <DashboardObservation data={dash} />
    {freshness.state === 'current' ? <>
      <DashboardMetrics data={dash} />
      <StatsGrid columns={2} className="grid-cols-1 sm:grid-cols-2" stats={[
        { title: t('HypervisorPage.stats.cluster'), value: dash.cluster_name || t('HypervisorPage.stats.unknown'), icon: Network,
          description: dash.quorate == null ? t('HypervisorPage.stats.unknown') : dash.quorate ? t('HypervisorPage.stats.quorate') : t('HypervisorPage.stats.noQuorum'),
          variant: dash.quorate == null ? 'warning' : dash.quorate ? 'success' : 'destructive' },
        { title: t('DashboardObservation.haServices'), value: dash.ha_services_visible == null ? t('HypervisorPage.stats.unknown') : String(dash.ha_services_visible), icon: Activity },
      ]} />
      <p className="text-sm text-muted-foreground">{t('DashboardObservation.haBoundary')}</p>
    </> : <ErrorState message={t('DashboardObservation.refreshRequired')} onRetry={refetchDash} />}
  </div>;
}

function FleetMember({ cluster }: { cluster: FleetDashboard['clusters'][number] }) {
  const { t } = useTranslation('hypervisor');
  const freshness = useObservationFreshness(cluster);
  return <Card>
    <CardHeader><CardTitle>{cluster.controller_name}</CardTitle>
      <p className="text-sm text-muted-foreground">{cluster.cluster_name || t('HypervisorPage.stats.unknown')} · {t(cluster.status === 'online' ? 'DashboardObservation.readSucceeded' : 'DashboardObservation.readFailed')}</p>
    </CardHeader>
    <CardContent className="space-y-4">
      {cluster.status === 'online' ? <>
        <DashboardObservation data={cluster} />
        {freshness.state === 'current' && <DashboardMetrics data={cluster} />}
      </> : <p className="text-destructive">{cluster.error || t('DashboardObservation.readFailed')}</p>}
    </CardContent>
  </Card>;
}

export function FleetTab({ fleetLoading, fleetError, fleet, refetchFleet, taskStats }: {
  fleetLoading: boolean; fleetError: boolean; fleet: FleetDashboard | undefined; refetchFleet: () => void;
  taskStats?: { ok?: number; running?: number; warning?: number; error?: number };
}) {
  const { t } = useTranslation('hypervisor');
  const freshness = useObservationFreshness(fleet);
  if (fleetLoading) return <Loading />;
  if (fleetError || !fleet) return <ErrorState message={t('HypervisorPage.fleet.loadError')} onRetry={refetchFleet} />;
  if (fleet.total_clusters === 0) return <EmptyState icon={Globe} title={t('HypervisorPage.fleet.emptyTitle')} description={t('HypervisorPage.fleet.emptyDescription')} />;
  return <div className="space-y-6">
    <DashboardObservation data={fleet} fleet />
    <p>{t('DashboardObservation.controllerCoverage', { observed: fleet.online_clusters, total: fleet.total_clusters, failed: fleet.failed_clusters })}</p>
    {freshness.state === 'current' && <DashboardMetrics data={fleet} />}
    {taskStats && Object.values(taskStats).some(value => typeof value === 'number') && <Card>
      <CardHeader><CardTitle>{t('HypervisorPage.fleet.taskStatistics')}</CardTitle></CardHeader>
      <CardContent><p className="text-xs text-muted-foreground mb-4">{t('DashboardObservation.separateTasks')}</p>
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">{(['ok', 'running', 'warning', 'error'] as const).map(key => <div key={key}>
          <p>{t(`HypervisorPage.taskStatus.${key === 'ok' ? 'completed' : key}`)}</p>
          <strong>{typeof taskStats[key] === 'number' && Number.isFinite(taskStats[key]) ? taskStats[key] : t('HypervisorPage.stats.unknown')}</strong>
        </div>)}</div>
      </CardContent>
    </Card>}
    {fleet.clusters.map(cluster => <FleetMember key={cluster.controller_id} cluster={cluster} />)}
  </div>;
}

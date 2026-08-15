// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN Hypervisor Module · Main Page
 * =======================================
 *
 * Proxmox VE cluster management with tabs:
 *   Dashboard · Nodes · Virtual Machines · Containers · Storage
 *   Tasks · Backup · Firewall · HA · Pools
 *
 * Requires a Proxmox controller to be registered first.
 * Controller is selected via a dropdown when multiple exist.
 */
/* eslint-disable @typescript-eslint/no-explicit-any */

import { Fragment, useState, useMemo, useEffect, useCallback } from 'react';
import { useParams } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Server,
  Cpu,
  Monitor,
  Box,
  HardDrive,
  Activity,
  Play,
  Square,
  RotateCcw,
  Power,
  Pause,
  Camera,
  RefreshCw,
  CheckCircle,
  XCircle,
  MemoryStick,
  Network,
  ChevronDown,
  ChevronRight,
  ListTodo,
  Shield,
  Copy,
  ArrowRightLeft,
  Expand,
  Terminal,
  Trash2,
  Archive,
  Layers,
  MoreHorizontal,
  FileText,
  StopCircle,
  Undo2,
  PowerOff,
  Plus,
  Globe,
  Loader2,
  AlertTriangle,
  Upload,
  Thermometer,
  BarChart3,
  LayoutDashboard,
  Clock,
  Maximize2,
  Search,
  Filter,
} from 'lucide-react';

import { PageHeader, PageTabs } from '@/components/layout';
import { StatsGrid } from '@/components/ui/stats-grid';
import { StatusBadge } from '@/components/ui/status-indicator';
import { MetricBar } from '@/components/ui/metric-bar';
import { EmptyState, ErrorState } from '@/components/ui/empty-state';
import { PageSkeleton } from '@/components/ui/page-skeleton';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { Skeleton } from '@/components/ui/skeleton';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { DestructiveConfirmDialog } from '@/components/ui/destructive-confirm-dialog';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Checkbox } from '@/components/ui/checkbox';
import { useToast } from '@/hooks/use-toast';
import { useSiteStore } from '@/stores/siteStore';
import { controllersApi, hypervisorApi } from '@/lib/api';
// Tab components are lazy-loaded so the 182KB Hypervisor monolith
// doesn't pull all 14 tabs into the initial bundle. Each tab fetches
// its own chunk when ``activeTab`` switches to it; un-clicked tabs
// stay un-downloaded.
//
// Components that are NOT lazy:
//   - KioskMode (mounted in the alternate top-level render path
//     before tabs exist)
//   - GuestDetailDrawer (always-mounted overlay, rendered on every
//     guest row click)
//   - StackedResourceBar (visualization util used in dashboard cards
//     that always render)
//   - Dialog components in ./components/dialogs/* (must be ready
//     synchronously when an action button fires)
import { lazy, Suspense } from 'react';
const MonitoringTab = lazy(() =>
  import('./components/MonitoringTab').then((m) => ({ default: m.MonitoringTab }))
);
import { KioskMode } from './components/KioskMode';
const BackupAgeTab = lazy(() =>
  import('./components/BackupAgeTab').then((m) => ({ default: m.BackupAgeTab }))
);
const TemplatesTab = lazy(() =>
  import('./components/TemplatesTab').then((m) => ({ default: m.TemplatesTab }))
);
const UpdatesTab = lazy(() =>
  import('./components/UpdatesTab').then((m) => ({ default: m.UpdatesTab }))
);
const CertificatesTab = lazy(() =>
  import('./components/CertificatesTab').then((m) => ({ default: m.CertificatesTab }))
);
const SubscriptionsTab = lazy(() =>
  import('./components/SubscriptionsTab').then((m) => ({ default: m.SubscriptionsTab }))
);
const SdnTab = lazy(() =>
  import('./components/SdnTab').then((m) => ({ default: m.SdnTab }))
);
const ReplicationTab = lazy(() =>
  import('./components/ReplicationTab').then((m) => ({ default: m.ReplicationTab }))
);
const ClusterLogTab = lazy(() =>
  import('./components/ClusterLogTab').then((m) => ({ default: m.ClusterLogTab }))
);
const CephTab = lazy(() =>
  import('./components/CephTab').then((m) => ({ default: m.CephTab }))
);
const PBSTab = lazy(() =>
  import('./components/PBSTab').then((m) => ({ default: m.PBSTab }))
);
import { GuestDetailDrawer } from './components/GuestDetailDrawer';
import { StackedResourceBar } from './components/StackedResourceBar';
import { EditConfigDialog } from './components/dialogs/EditConfigDialog';
import { BulkActionBar } from './components/dialogs/BulkActionBar';
import { BackupJobDialog } from './components/dialogs/BackupJobDialog';
import { UploadDialog } from './components/dialogs/UploadDialog';
import { AddHypervisorDialog } from './components/dialogs/AddHypervisorDialog';
import { formatBytes, formatUptime, formatTimestamp } from './components/helpers';
import { statusBadge } from './components/StatusBadge';
import { vmKey } from './components/types';
import type { BulkTarget } from './components/types';
import type {
  HypervisorDashboard,
  HypervisorNode,
  HypervisorVM,
  HypervisorStorage,
  HypervisorTask,
  HypervisorBackupJob,
  HypervisorFirewallRule,
  HypervisorSnapshot,
  HypervisorHAResource,
  HypervisorHAGroup,
  HypervisorResourcePool,
  FleetDashboard,
  FleetClusterSummary,
} from '@/lib/api';

// ============================================================================
// EXTRACTED TAB COMPONENTS
// ============================================================================

interface FleetTabProps {
  fleetLoading: boolean;
  fleetError: boolean;
  fleet: FleetDashboard | undefined;
  refetchFleet: () => void;
  taskStats?: { ok?: number; running?: number; warning?: number; error?: number };
}

const FleetTab = ({ fleetLoading, fleetError, fleet, refetchFleet, taskStats }: FleetTabProps) => {
  const { t } = useTranslation('hypervisor');
  if (fleetLoading) {
    return (
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {Array.from({ length: 8 }).map((_, i) => (
          <Skeleton key={i} className="h-24" />
        ))}
      </div>
    );
  }

  if (fleetError || !fleet) {
    return <ErrorState message={t('HypervisorPage.fleet.loadError')} onRetry={() => refetchFleet()} />;
  }

  if (fleet.total_clusters === 0) {
    return <EmptyState icon={Globe} title={t('HypervisorPage.fleet.emptyTitle')} description={t('HypervisorPage.fleet.emptyDescription')} />;
  }

  const fleetStats = [
    { title: t('HypervisorPage.stats.clusters'), value: `${fleet.online_clusters} / ${fleet.total_clusters}`, icon: Globe, variant: fleet.online_clusters === fleet.total_clusters ? 'success' as const : 'warning' as const },
    { title: t('HypervisorPage.stats.nodes'), value: `${fleet.online_nodes} / ${fleet.total_nodes}`, icon: Server, variant: 'primary' as const },
    { title: t('HypervisorPage.stats.vms'), value: `${fleet.running_vms} / ${fleet.total_vms}`, icon: Monitor, variant: 'info' as const },
    { title: t('HypervisorPage.stats.containers'), value: `${fleet.running_containers} / ${fleet.total_containers}`, icon: Box, variant: 'info' as const },
    { title: t('HypervisorPage.stats.cpu'), value: `${fleet.cpu_usage_percent}%`, icon: Cpu, variant: fleet.cpu_usage_percent > 80 ? 'destructive' as const : 'default' as const, description: t('HypervisorPage.stats.coresCount', { count: fleet.total_cpu_cores }) },
    { title: t('HypervisorPage.stats.memory'), value: `${fleet.memory_usage_percent}%`, icon: MemoryStick, variant: fleet.memory_usage_percent > 80 ? 'warning' as const : 'default' as const, description: formatBytes(fleet.total_memory_bytes) },
    { title: t('HypervisorPage.stats.storage'), value: `${fleet.storage_usage_percent}%`, icon: HardDrive, variant: fleet.storage_usage_percent > 85 ? 'destructive' as const : 'default' as const, description: formatBytes(fleet.total_storage_bytes) },
  ];

  return (
    <div className="space-y-6">
      <StatsGrid stats={fleetStats} columns={4} />

      {/* Task Statistics Card */}
      {taskStats && (taskStats.ok || taskStats.running || taskStats.warning || taskStats.error) ? (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-base flex items-center gap-2">
              <BarChart3 className="h-5 w-5 text-muted-foreground" />
              {t('HypervisorPage.fleet.taskStatistics')}
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-center">
              <div>
                <p className="text-2xl font-bold text-success">{taskStats.ok || 0}</p>
                <p className="text-xs text-muted-foreground">{t('HypervisorPage.taskStatus.completed')}</p>
              </div>
              <div>
                <p className="text-2xl font-bold text-info">{taskStats.running || 0}</p>
                <p className="text-xs text-muted-foreground">{t('HypervisorPage.taskStatus.running')}</p>
              </div>
              <div>
                <p className="text-2xl font-bold text-warning">{taskStats.warning || 0}</p>
                <p className="text-xs text-muted-foreground">{t('HypervisorPage.taskStatus.warning')}</p>
              </div>
              <div>
                <p className="text-2xl font-bold text-destructive">{taskStats.error || 0}</p>
                <p className="text-xs text-muted-foreground">{t('HypervisorPage.taskStatus.error')}</p>
              </div>
            </div>
          </CardContent>
        </Card>
      ) : null}

      <div className="grid gap-4">
        {fleet.clusters.map((cluster: FleetClusterSummary) => (
          <Card key={cluster.controller_id}>
            <CardHeader className="pb-2">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  {cluster.status === 'online' ? (
                    <CheckCircle className="h-5 w-5 text-success" />
                  ) : (
                    <AlertTriangle className="h-5 w-5 text-destructive" />
                  )}
                  <div>
                    <CardTitle className="text-base">{cluster.controller_name}</CardTitle>
                    <p className="text-xs text-muted-foreground">
                      {cluster.cluster_name || 'pve'} · {t('HypervisorPage.fleet.nodeCount', { count: cluster.total_nodes })}
                      {cluster.quorate ? '' : t('HypervisorPage.fleet.noQuorumSuffix')}
                    </p>
                  </div>
                </div>
                <StatusBadge variant={cluster.status === 'online' ? 'online' : 'offline'} size="sm">
                  {cluster.status}
                </StatusBadge>
              </div>
            </CardHeader>
            {cluster.status === 'online' ? (
              <CardContent>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
                  <div>
                    <p className="text-xs text-muted-foreground">{t('HypervisorPage.stats.nodes')}</p>
                    <p className="text-sm font-medium">{cluster.online_nodes}/{cluster.total_nodes}</p>
                  </div>
                  <div>
                    <p className="text-xs text-muted-foreground">{t('HypervisorPage.fleet.vmsCts')}</p>
                    <p className="text-sm font-medium">{cluster.running_vms}/{cluster.total_vms} VMs, {cluster.running_containers}/{cluster.total_containers} CTs</p>
                  </div>
                  <div>
                    <p className="text-xs text-muted-foreground">{t('HypervisorPage.stats.cpu')}</p>
                    <div className="flex items-center gap-2">
                      <Progress value={cluster.cpu_usage_percent} className="h-1.5 flex-1" />
                      <span className="text-xs font-medium">{cluster.cpu_usage_percent}%</span>
                    </div>
                  </div>
                  <div>
                    <p className="text-xs text-muted-foreground">{t('HypervisorPage.stats.memory')}</p>
                    <div className="flex items-center gap-2">
                      <Progress value={cluster.memory_usage_percent} className="h-1.5 flex-1" />
                      <span className="text-xs font-medium">{cluster.memory_usage_percent}%</span>
                    </div>
                  </div>
                </div>
              </CardContent>
            ) : cluster.error ? (
              <CardContent noOffset>
                <p className="text-xs text-destructive">{cluster.error}</p>
              </CardContent>
            ) : null}
          </Card>
        ))}
      </div>
    </div>
  );
};

interface DashboardTabProps {
  dashLoading: boolean;
  dashError: boolean;
  dash: HypervisorDashboard | undefined;
  refetchDash: () => void;
}

const DashboardTab = ({ dashLoading, dashError, dash, refetchDash }: DashboardTabProps) => {
  const { t } = useTranslation('hypervisor');
  if (dashLoading) {
    return (
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {Array.from({ length: 8 }).map((_, i) => (
          <Skeleton key={i} className="h-24" />
        ))}
      </div>
    );
  }

  if (dashError || !dash) {
    return <ErrorState message={t('HypervisorPage.dashboard.loadError')} onRetry={() => refetchDash()} />;
  }

  const stats = [
    { title: t('HypervisorPage.stats.nodes'), value: `${dash.online_nodes} / ${dash.total_nodes}`, icon: Server, variant: dash.online_nodes === dash.total_nodes ? 'success' as const : 'warning' as const },
    { title: t('HypervisorPage.stats.vms'), value: `${dash.running_vms} / ${dash.total_vms}`, icon: Monitor, variant: 'primary' as const },
    { title: t('HypervisorPage.stats.containers'), value: `${dash.running_containers} / ${dash.total_containers}`, icon: Box, variant: 'info' as const },
    { title: t('HypervisorPage.stats.cpu'), value: `${dash.cpu_usage_percent}%`, icon: Cpu, variant: dash.cpu_usage_percent > 80 ? 'destructive' as const : 'default' as const, description: t('HypervisorPage.stats.coresCount', { count: dash.total_cpu_cores }) },
    { title: t('HypervisorPage.stats.memory'), value: `${dash.memory_usage_percent}%`, icon: MemoryStick, variant: dash.memory_usage_percent > 80 ? 'warning' as const : 'default' as const, description: formatBytes(dash.total_memory_bytes) },
    { title: t('HypervisorPage.stats.storage'), value: `${dash.storage_usage_percent}%`, icon: HardDrive, variant: dash.storage_usage_percent > 85 ? 'destructive' as const : 'default' as const, description: formatBytes(dash.total_storage_bytes) },
    { title: t('HypervisorPage.stats.cluster'), value: dash.cluster_name || 'pve', icon: Network, variant: dash.quorate ? 'success' as const : 'destructive' as const, description: dash.quorate ? t('HypervisorPage.stats.quorate') : t('HypervisorPage.stats.noQuorum') },
    { title: t('HypervisorPage.stats.ha'), value: dash.ha_active ? t('HypervisorPage.stats.active') : t('HypervisorPage.stats.inactive'), icon: Activity, variant: dash.ha_active ? 'success' as const : 'default' as const },
  ];

  return (
    <div className="space-y-6">
      <StatsGrid stats={stats} columns={4} />
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        {[
          { label: t('HypervisorPage.dashboard.cpuUsage'), value: dash.cpu_usage_percent },
          { label: t('HypervisorPage.dashboard.memoryUsage'), value: dash.memory_usage_percent },
          { label: t('HypervisorPage.dashboard.storageUsage'), value: dash.storage_usage_percent },
        ].map((bar) => (
          <Card key={bar.label}>
            <CardContent noOffset>
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm font-medium">{bar.label}</span>
                <span className="text-sm font-bold">{bar.value.toFixed(1)}%</span>
              </div>
              <MetricBar value={bar.value} variant="thick" hideValue />
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
};

interface NodesTabProps {
  nodesLoading: boolean;
  nodesError: boolean;
  nodes: HypervisorNode[];
  refetchNodes: () => void;
  expandedNode: string | null;
  setExpandedNode: (node: string | null) => void;
  nodeDetailTab: 'overview' | 'services' | 'disks' | 'network' | 'vms' | 'containers' | 'sensors';
  setNodeDetailTab: (tab: 'overview' | 'services' | 'disks' | 'network' | 'vms' | 'containers' | 'sensors') => void;
  nodeServicesLoading: boolean;
  nodeServices: any[];
  nodeDisksLoading: boolean;
  nodeDisks: any[];
  nodeNetworkLoading: boolean;
  nodeNetworkIfaces: any[];
  nodeVMsLoading: boolean;
  nodeCTsLoading: boolean;
  controllerId: string;
  nodeVMs: any[];
  nodeContainers: any[];
  nodeSensorsLoading: boolean;
  nodeSensors: any[];
  nodeRebootMutation: { mutate: (node: string) => void };
  nodeShutdownMutation: { mutate: (node: string) => void };
  /** All VMs + containers for stacked resource bars */
  allGuests: HypervisorVM[];
  /** Page-wide destructive-confirm helper. Threaded from
   *  HypervisorPage so node reboot/shutdown use the typed-confirm
   *  dialog instead of bare ``window.confirm()``. */
  requestConfirm: (args: {
    title: string;
    description: string;
    confirmationText: string;
    confirmLabel: string;
    onConfirm: () => void;
  }) => void;
}

const NodesTab = ({
  nodesLoading, nodesError, nodes, refetchNodes,
  expandedNode, setExpandedNode, nodeDetailTab, setNodeDetailTab,
  nodeServicesLoading, nodeServices, nodeDisksLoading, nodeDisks,
  nodeNetworkLoading, nodeNetworkIfaces, nodeVMsLoading, nodeCTsLoading, nodeVMs, nodeContainers,
  nodeSensorsLoading, nodeSensors,
  nodeRebootMutation, nodeShutdownMutation, allGuests, requestConfirm,
  controllerId,
}: NodesTabProps) => {
  const { t } = useTranslation('hypervisor');
  const [expandedDisk, setExpandedDisk] = useState<string | null>(null);

  const { data: smartResp, isLoading: smartLoading } = useQuery({
    queryKey: ['hypervisor', 'disk-smart', controllerId, expandedNode, expandedDisk],
    queryFn: () => hypervisorApi.getDiskSmart(controllerId, expandedNode!, expandedDisk!),
    enabled: !!controllerId && !!expandedNode && !!expandedDisk && nodeDetailTab === 'disks',
  });
  const smartData: any = smartResp?.data || {};
  const smartAttrs: any[] = smartData?.attributes || smartData?.attrs || [];

  if (nodesLoading) return <Skeleton className="h-64" />;
  if (nodesError) return <ErrorState message={t('HypervisorPage.nodes.loadError')} onRetry={() => refetchNodes()} />;
  if (nodes.length === 0) return <EmptyState icon={Server} title={t('HypervisorPage.nodes.emptyTitle')} />;

  return (
    <div className="grid gap-4">
      {nodes.map((node) => {
        const isExpanded = expandedNode === node.node;
        const nodeGuests = allGuests.filter((g) => g.node === node.node);
        const runningGuests = nodeGuests.filter((g) => g.status === 'running');
        const nodeQemu = nodeGuests.filter((g) => g.vm_type === 'qemu');
        const nodeLxc = nodeGuests.filter((g) => g.vm_type === 'lxc');
        const runningQemu = nodeQemu.filter((g) => g.status === 'running').length;
        const runningLxc = nodeLxc.filter((g) => g.status === 'running').length;

        return (
          <Card key={node.node} className={isExpanded ? 'ring-1 ring-primary/30' : ''}>
            <CardHeader className="pb-2">
              <div className="flex items-center justify-between">
                <div
                  className="flex items-center gap-3 cursor-pointer flex-1 min-w-0"
                  onClick={() => {
                    setExpandedNode(isExpanded ? null : node.node);
                    setNodeDetailTab('overview');
                  }}
                >
                  <ChevronDown className={`h-4 w-4 text-muted-foreground transition-transform shrink-0 ${isExpanded ? '' : '-rotate-90'}`} />
                  <Server className="h-5 w-5 text-muted-foreground shrink-0" />
                  <div className="min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <CardTitle className="text-base">{node.node}</CardTitle>
                      {node.subscription_level && (
                        <Badge variant="outline" className="text-[10px] shrink-0">
                          {node.subscription_level}
                        </Badge>
                      )}
                    </div>
                    <p className="text-xs text-muted-foreground truncate">
                      {node.cpu_model || t('HypervisorPage.nodes.unknownCpu')}
                    </p>
                  </div>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  {/* Workload summary badges */}
                  <div className="hidden sm:flex items-center gap-1.5">
                    <Badge variant="secondary" className="text-[10px] gap-1 font-normal">
                      <Monitor className="h-3 w-3" /> {runningQemu}/{nodeQemu.length}
                    </Badge>
                    <Badge variant="secondary" className="text-[10px] gap-1 font-normal">
                      <Box className="h-3 w-3" /> {runningLxc}/{nodeLxc.length}
                    </Badge>
                  </div>
                  {statusBadge(node.status)}
                  <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                      <Button variant="ghost" size="sm" className="h-7 w-7 p-0">
                        <MoreHorizontal className="h-4 w-4" />
                      </Button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent align="end">
                      <DropdownMenuItem
                        onClick={() => requestConfirm({
                          title: t('HypervisorPage.nodes.rebootConfirm.title', { node: node.node }),
                          description: t('HypervisorPage.nodes.rebootConfirm.description', { node: node.node }),
                          confirmationText: node.node,
                          confirmLabel: t('HypervisorPage.nodes.rebootConfirm.confirmLabel'),
                          onConfirm: () => nodeRebootMutation.mutate(node.node),
                        })}
                        disabled={node.status !== 'online'}
                      >
                        <RotateCcw className="mr-2 h-3.5 w-3.5 text-info" /> {t('HypervisorPage.nodes.reboot')}
                      </DropdownMenuItem>
                      <DropdownMenuItem
                        onClick={() => requestConfirm({
                          title: t('HypervisorPage.nodes.shutdownConfirm.title', { node: node.node }),
                          description: t('HypervisorPage.nodes.shutdownConfirm.description', { node: node.node }),
                          confirmationText: node.node,
                          confirmLabel: t('HypervisorPage.nodes.shutdownConfirm.confirmLabel'),
                          onConfirm: () => nodeShutdownMutation.mutate(node.node),
                        })}
                        disabled={node.status !== 'online'}
                        className="text-destructive"
                      >
                        <PowerOff className="mr-2 h-3.5 w-3.5" /> {t('HypervisorPage.nodes.shutdown')}
                      </DropdownMenuItem>
                    </DropdownMenuContent>
                  </DropdownMenu>
                </div>
              </div>
            </CardHeader>
            <CardContent className="space-y-4">
              {/* Resource bars · always visible */}
              <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
                <div>
                  <p className="text-xs text-muted-foreground mb-1">{t('HypervisorPage.nodes.cpuCores', { count: node.cpu_count })}</p>
                  <Progress value={node.cpu_percent} className="h-2" />
                  <p className="text-xs font-medium mt-1">{node.cpu_percent}%</p>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground mb-1">{t('HypervisorPage.stats.memory')}</p>
                  <Progress value={node.memory_percent} className="h-2" />
                  <p className="text-xs font-medium mt-1">
                    {formatBytes(node.memory_used)} / {formatBytes(node.memory_total)}
                  </p>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground mb-1">{t('HypervisorPage.stats.storage')}</p>
                  <Progress value={node.storage_percent} className="h-2" />
                  <p className="text-xs font-medium mt-1">
                    {formatBytes(node.storage_used)} / {formatBytes(node.storage_total)}
                  </p>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground mb-1">{t('HypervisorPage.nodes.uptime')}</p>
                  <p className="text-sm font-medium">{formatUptime(node.uptime)}</p>
                </div>
                {/* Workload counts · mobile only (shown inline on desktop via header badges) */}
                <div className="sm:hidden">
                  <p className="text-xs text-muted-foreground mb-1">{t('HypervisorPage.nodes.guests')}</p>
                  <p className="text-sm font-medium">{runningQemu}/{nodeQemu.length} VM · {runningLxc}/{nodeLxc.length} CT</p>
                </div>
                {/* Desktop: PVE version + kernel in collapsed row */}
                <div className="hidden md:block">
                  <p className="text-xs text-muted-foreground mb-1">{t('HypervisorPage.nodes.version')}</p>
                  <p className="text-xs font-medium truncate" title={node.pve_version}>{node.pve_version || '-'}</p>
                </div>
              </div>

              {/* Stacked resource bars per node */}
              {runningGuests.length > 0 && (
                <div>
                  <StackedResourceBar
                    segments={runningGuests.map((g) => ({
                      label: g.name || `${g.vmid}`,
                      value: g.memory_used_mb * 1024 * 1024,
                      tone: g.vm_type === 'qemu' ? ('info' as const) : ('primary' as const),
                    }))}
                    total={node.memory_total}
                    label={t('HypervisorPage.nodes.memoryByGuest', { count: runningGuests.length })}
                  />
                </div>
              )}

              {isExpanded && (
                <div className="border-t pt-4">
                  <div className="flex gap-1 mb-3 overflow-x-auto pb-1">
                    {([
                      { key: 'overview', label: t('HypervisorPage.nodeDetail.overview'), icon: LayoutDashboard },
                      { key: 'vms', label: `VMs (${nodeQemu.length})`, icon: Monitor },
                      { key: 'containers', label: `${t('HypervisorPage.tabs.containers')} (${nodeLxc.length})`, icon: Box },
                      { key: 'services', label: t('HypervisorPage.nodeDetail.services'), icon: Activity },
                      { key: 'disks', label: t('HypervisorPage.nodeDetail.disks'), icon: HardDrive },
                      { key: 'network', label: t('HypervisorPage.nodeDetail.network'), icon: Network },
                      { key: 'sensors', label: t('HypervisorPage.nodeDetail.sensors'), icon: Thermometer },
                    ] as const).map(({ key, label, icon: Icon }) => (
                      <Button
                        key={key}
                        variant={nodeDetailTab === key ? 'default' : 'ghost'}
                        size="sm"
                        className="h-7 text-xs shrink-0"
                        onClick={() => setNodeDetailTab(key)}
                      >
                        <Icon className="h-3 w-3 mr-1" />
                        {label}
                      </Button>
                    ))}
                  </div>

                  {/* ── Overview tab ─────────────────────────────────── */}
                  {nodeDetailTab === 'overview' && (
                    <div className="space-y-4">
                      {/* System info row */}
                      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
                        <div className="rounded-lg border p-3 space-y-1">
                          <p className="text-[10px] uppercase tracking-wider text-muted-foreground font-medium">{t('HypervisorPage.nodeDetail.processor')}</p>
                          <p className="text-sm font-medium">{node.cpu_model || t('HypervisorPage.common.unknown')}</p>
                          <p className="text-xs text-muted-foreground">{t('HypervisorPage.nodeDetail.coresUsed', { count: node.cpu_count, percent: node.cpu_percent })}</p>
                        </div>
                        <div className="rounded-lg border p-3 space-y-1">
                          <p className="text-[10px] uppercase tracking-wider text-muted-foreground font-medium">{t('HypervisorPage.stats.memory')}</p>
                          <p className="text-sm font-medium">{formatBytes(node.memory_total)}</p>
                          <p className="text-xs text-muted-foreground">{t('HypervisorPage.nodeDetail.usedPercent', { value: formatBytes(node.memory_used), percent: node.memory_percent })}</p>
                        </div>
                        <div className="rounded-lg border p-3 space-y-1">
                          <p className="text-[10px] uppercase tracking-wider text-muted-foreground font-medium">{t('HypervisorPage.nodeDetail.rootFilesystem')}</p>
                          <p className="text-sm font-medium">{formatBytes(node.storage_total)}</p>
                          <p className="text-xs text-muted-foreground">{t('HypervisorPage.nodeDetail.usedPercent', { value: formatBytes(node.storage_used), percent: node.storage_percent })}</p>
                        </div>
                      </div>

                      {/* Workload summary */}
                      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                        <div className="rounded-lg border p-3 text-center">
                          <Monitor className="h-4 w-4 mx-auto text-info mb-1" />
                          <p className="text-2xl font-bold">{runningQemu}</p>
                          <p className="text-[10px] text-muted-foreground">{t('HypervisorPage.nodeDetail.vmsRunning', { total: nodeQemu.length, running: runningQemu })}</p>
                        </div>
                        <div className="rounded-lg border p-3 text-center">
                          <Box className="h-4 w-4 mx-auto text-primary mb-1" />
                          <p className="text-2xl font-bold">{runningLxc}</p>
                          <p className="text-[10px] text-muted-foreground">{t('HypervisorPage.nodeDetail.ctsRunning', { total: nodeLxc.length, running: runningLxc })}</p>
                        </div>
                        <div className="rounded-lg border p-3 text-center">
                          <Clock className="h-4 w-4 mx-auto text-success mb-1" />
                          <p className="text-2xl font-bold">{formatUptime(node.uptime)}</p>
                          <p className="text-[10px] text-muted-foreground">{t('HypervisorPage.nodes.uptime')}</p>
                        </div>
                        <div className="rounded-lg border p-3 text-center">
                          <Cpu className="h-4 w-4 mx-auto text-warning mb-1" />
                          <p className="text-sm font-bold truncate" title={node.pve_version}>{node.pve_version || '-'}</p>
                          <p className="text-[10px] text-muted-foreground">{t('HypervisorPage.nodeDetail.pveVersion')}</p>
                        </div>
                      </div>

                      {/* Kernel + load average from sensors if available */}
                      {nodeSensors.length > 0 && (
                        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                          {nodeSensors.filter((s: any) => ['Load Average (1m)', 'Load Average (5m)', 'Load Average (15m)', 'Kernel'].includes(s.name)).map((s: any) => (
                            <div key={s.name} className="rounded-lg border p-3">
                              <p className="text-[10px] uppercase tracking-wider text-muted-foreground font-medium">{s.name}</p>
                              <p className="text-sm font-medium truncate" title={String(s.value)}>{s.value}{s.unit ? ` ${s.unit}` : ''}</p>
                            </div>
                          ))}
                        </div>
                      )}

                      {/* Top guests by resource */}
                      {runningGuests.length > 0 && (
                        <div>
                          <p className="text-xs font-medium text-muted-foreground mb-2 uppercase tracking-wider">{t('HypervisorPage.nodeDetail.topGuestsByMemory')}</p>
                          <div className="overflow-x-auto">
                          <Table>
                            <TableHeader>
                              <TableRow>
                                <TableHead>{t('HypervisorPage.tableHeaders.name')}</TableHead>
                                <TableHead>{t('HypervisorPage.tableHeaders.type')}</TableHead>
                                <TableHead>{t('HypervisorPage.tableHeaders.status')}</TableHead>
                                <TableHead>{t('HypervisorPage.stats.cpu')}</TableHead>
                                <TableHead>{t('HypervisorPage.stats.memory')}</TableHead>
                              </TableRow>
                            </TableHeader>
                            <TableBody>
                              {[...runningGuests]
                                .sort((a, b) => b.memory_used_mb - a.memory_used_mb)
                                .slice(0, 8)
                                .map((g) => (
                                  <TableRow key={`${g.vm_type}-${g.vmid}`}>
                                    <TableCell className="font-medium text-sm">
                                      <span className="font-mono text-xs text-muted-foreground mr-1.5">{g.vmid}</span>
                                      {g.name || '-'}
                                    </TableCell>
                                    <TableCell>
                                      <Badge variant="outline" className="text-[10px]">{g.vm_type === 'lxc' ? 'CT' : 'VM'}</Badge>
                                    </TableCell>
                                    <TableCell>{statusBadge(g.status)}</TableCell>
                                    <TableCell className="text-xs">{g.cpu_cores} vCPU</TableCell>
                                    <TableCell className="text-xs">{formatBytes(g.memory_used_mb * 1024 * 1024)} / {formatBytes(g.memory_mb * 1024 * 1024)}</TableCell>
                                  </TableRow>
                                ))}
                            </TableBody>
                          </Table>
                          </div>
                        </div>
                      )}
                    </div>
                  )}

                  {nodeDetailTab === 'services' && (
                    nodeServicesLoading ? <Skeleton className="h-32" /> : nodeServices.length === 0 ? (
                      <p className="text-sm text-muted-foreground">{t('HypervisorPage.nodeDetail.noServices')}</p>
                    ) : (
                      <div className="overflow-x-auto">
                      <Table>
                        <TableHeader>
                          <TableRow>
                            <TableHead>{t('HypervisorPage.nodeDetail.service')}</TableHead>
                            <TableHead>{t('HypervisorPage.nodeDetail.state')}</TableHead>
                            <TableHead>{t('HypervisorPage.tableHeaders.description')}</TableHead>
                          </TableRow>
                        </TableHeader>
                        <TableBody>
                          {nodeServices.map((svc: any) => (
                            <TableRow key={svc.service || svc.name}>
                              <TableCell className="font-mono text-xs">{svc.service || svc.name}</TableCell>
                              <TableCell>
                                <Badge variant={svc.state === 'running' ? 'default' : 'secondary'} className="text-xs">
                                  {svc.state || t('HypervisorPage.common.unknownLower')}
                                </Badge>
                              </TableCell>
                              <TableCell className="text-xs text-muted-foreground">{svc.desc || svc.description || '-'}</TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                      </div>
                    )
                  )}

                  {nodeDetailTab === 'disks' && (
                    nodeDisksLoading ? <Skeleton className="h-32" /> : nodeDisks.length === 0 ? (
                      <p className="text-sm text-muted-foreground">{t('HypervisorPage.nodeDetail.noDisks')}</p>
                    ) : (
                      <div className="overflow-x-auto">
                      <Table>
                        <TableHeader>
                          <TableRow>
                            <TableHead className="w-[30px]" />
                            <TableHead>{t('HypervisorPage.nodeDetail.device')}</TableHead>
                            <TableHead>{t('HypervisorPage.tableHeaders.type')}</TableHead>
                            <TableHead>{t('HypervisorPage.tableHeaders.size')}</TableHead>
                            <TableHead>{t('HypervisorPage.nodeDetail.model')}</TableHead>
                            <TableHead>{t('HypervisorPage.nodeDetail.serial')}</TableHead>
                            <TableHead>{t('HypervisorPage.nodeDetail.health')}</TableHead>
                          </TableRow>
                        </TableHeader>
                        <TableBody>
                          {nodeDisks.map((disk: any) => {
                            const devpath = disk.devpath || disk.name || '';
                            const isExpDisk = expandedDisk === devpath;
                            return (
                              <Fragment key={devpath}>
                                <TableRow
                                  className="cursor-pointer"
                                  onClick={() => setExpandedDisk(isExpDisk ? null : devpath)}
                                >
                                  <TableCell className="px-1">
                                    {isExpDisk
                                      ? <ChevronDown className="h-3.5 w-3.5 text-muted-foreground" />
                                      : <ChevronRight className="h-3.5 w-3.5 text-muted-foreground" />}
                                  </TableCell>
                                  <TableCell className="font-mono text-xs">{devpath}</TableCell>
                                  <TableCell className="text-xs">{disk.type || '-'}</TableCell>
                                  <TableCell className="text-xs">{disk.size ? formatBytes(disk.size) : '-'}</TableCell>
                                  <TableCell className="text-xs text-muted-foreground">{disk.model || '-'}</TableCell>
                                  <TableCell className="font-mono text-xs text-muted-foreground">{disk.serial || '-'}</TableCell>
                                  <TableCell>
                                    <Badge variant={disk.health === 'PASSED' ? 'default' : disk.health === 'UNKNOWN' ? 'secondary' : 'destructive'} className="text-xs">
                                      {disk.health || 'N/A'}
                                    </Badge>
                                  </TableCell>
                                </TableRow>
                                {isExpDisk && (
                                  <TableRow>
                                    <TableCell colSpan={7} className="bg-muted/30 px-4 py-3">
                                      {smartLoading ? (
                                        <Skeleton className="h-24" />
                                      ) : smartAttrs.length === 0 ? (
                                        <p className="text-xs text-muted-foreground">{t('HypervisorPage.nodeDetail.noSmart')}</p>
                                      ) : (
                                        <div>
                                          <p className="text-xs font-medium mb-2">{t('HypervisorPage.nodeDetail.smartAttributes')}</p>
                                          <Table>
                                            <TableHeader>
                                              <TableRow>
                                                <TableHead className="text-xs">ID</TableHead>
                                                <TableHead className="text-xs">{t('HypervisorPage.nodeDetail.attribute')}</TableHead>
                                                <TableHead className="text-xs">{t('HypervisorPage.nodeDetail.value')}</TableHead>
                                                <TableHead className="text-xs">{t('HypervisorPage.nodeDetail.worst')}</TableHead>
                                                <TableHead className="text-xs">{t('HypervisorPage.nodeDetail.threshold')}</TableHead>
                                                <TableHead className="text-xs">{t('HypervisorPage.nodeDetail.raw')}</TableHead>
                                                <TableHead className="text-xs">{t('HypervisorPage.tableHeaders.status')}</TableHead>
                                              </TableRow>
                                            </TableHeader>
                                            <TableBody>
                                              {smartAttrs.map((attr: any, idx: number) => {
                                                const val = attr.value ?? attr.normalized;
                                                const worst = attr.worst ?? '-';
                                                const thresh = attr.threshold ?? '-';
                                                const raw = attr.raw ?? attr.raw_value ?? '-';
                                                const status = typeof thresh === 'number' && typeof val === 'number'
                                                  ? (val <= thresh ? 'FAIL' : val <= thresh + 10 ? 'WARN' : 'PASS')
                                                  : attr.status || 'PASS';
                                                return (
                                                  <TableRow key={attr.id ?? idx}>
                                                    <TableCell className="font-mono text-[10px]">{attr.id ?? idx}</TableCell>
                                                    <TableCell className="text-[10px]">{attr.name || attr.attribute || '-'}</TableCell>
                                                    <TableCell className="font-mono text-[10px]">{val ?? '-'}</TableCell>
                                                    <TableCell className="font-mono text-[10px]">{worst}</TableCell>
                                                    <TableCell className="font-mono text-[10px]">{thresh}</TableCell>
                                                    <TableCell className="font-mono text-[10px]">{raw}</TableCell>
                                                    <TableCell>
                                                      <Badge
                                                        variant={status === 'PASS' ? 'default' : status === 'WARN' ? 'secondary' : 'destructive'}
                                                        className="text-[10px]"
                                                      >
                                                        {status}
                                                      </Badge>
                                                    </TableCell>
                                                  </TableRow>
                                                );
                                              })}
                                            </TableBody>
                                          </Table>
                                        </div>
                                      )}
                                    </TableCell>
                                  </TableRow>
                                )}
                              </Fragment>
                            );
                          })}
                        </TableBody>
                      </Table>
                      </div>
                    )
                  )}

                  {nodeDetailTab === 'network' && (
                    nodeNetworkLoading ? <Skeleton className="h-32" /> : nodeNetworkIfaces.length === 0 ? (
                      <p className="text-sm text-muted-foreground">{t('HypervisorPage.nodeDetail.noInterfaces')}</p>
                    ) : (
                      <div className="overflow-x-auto">
                      <Table>
                        <TableHeader>
                          <TableRow>
                            <TableHead>{t('HypervisorPage.nodeDetail.interface')}</TableHead>
                            <TableHead>{t('HypervisorPage.tableHeaders.type')}</TableHead>
                            <TableHead>{t('HypervisorPage.nodeDetail.address')}</TableHead>
                            <TableHead>{t('HypervisorPage.nodeDetail.gateway')}</TableHead>
                            <TableHead>{t('HypervisorPage.nodeDetail.bridgePorts')}</TableHead>
                            <TableHead>{t('HypervisorPage.nodeDetail.active')}</TableHead>
                          </TableRow>
                        </TableHeader>
                        <TableBody>
                          {nodeNetworkIfaces.map((iface: any) => (
                            <TableRow key={iface.iface || iface.name}>
                              <TableCell className="font-mono text-xs">{iface.iface || iface.name}</TableCell>
                              <TableCell className="text-xs">{iface.type || '-'}</TableCell>
                              <TableCell className="font-mono text-xs">
                                {iface.address ? `${iface.address}/${iface.netmask || iface.cidr || ''}` : iface.cidr || '-'}
                              </TableCell>
                              <TableCell className="font-mono text-xs">{iface.gateway || '-'}</TableCell>
                              <TableCell className="text-xs text-muted-foreground">
                                {iface.bridge_ports || iface.slaves || '-'}
                              </TableCell>
                              <TableCell>
                                <Badge variant={iface.active ? 'default' : 'secondary'} className="text-xs">
                                  {iface.active ? 'up' : 'down'}
                                </Badge>
                              </TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                      </div>
                    )
                  )}

                  {(nodeDetailTab === 'vms' || nodeDetailTab === 'containers') && (() => {
                    const isVMs = nodeDetailTab === 'vms';
                    const list = isVMs ? nodeVMs : nodeContainers;
                    const loading = isVMs ? nodeVMsLoading : nodeCTsLoading;
                    const typeLabel = isVMs ? t('HypervisorPage.common.virtualMachines') : t('HypervisorPage.common.containers');
                    const emptyIcon = isVMs ? Monitor : Box;
                    return loading ? <Skeleton className="h-32" /> : list.length === 0 ? (
                      <EmptyState icon={emptyIcon} title={t('HypervisorPage.nodeDetail.noGuestsOnNode', { type: typeLabel })} />
                    ) : (
                      <div className="overflow-x-auto">
                      <Table>
                        <TableHeader>
                          <TableRow>
                            <TableHead>VMID</TableHead>
                            <TableHead>{t('HypervisorPage.tableHeaders.name')}</TableHead>
                            <TableHead>{t('HypervisorPage.tableHeaders.status')}</TableHead>
                            <TableHead>{t('HypervisorPage.stats.cpu')}</TableHead>
                            <TableHead>{t('HypervisorPage.stats.memory')}</TableHead>
                            <TableHead>{t('HypervisorPage.tableHeaders.disk')}</TableHead>
                            <TableHead>{t('HypervisorPage.nodes.uptime')}</TableHead>
                          </TableRow>
                        </TableHeader>
                        <TableBody>
                          {list.map((vm: any) => (
                            <TableRow key={vm.vmid}>
                              <TableCell className="font-mono text-xs">{vm.vmid}</TableCell>
                              <TableCell className="font-medium text-sm">{vm.name || '-'}</TableCell>
                              <TableCell>{statusBadge(vm.status)}</TableCell>
                              <TableCell className="text-xs">{vm.cpus || vm.maxcpu || '-'} vCPU</TableCell>
                              <TableCell className="text-xs">
                                {vm.maxmem ? formatBytes(vm.maxmem) : '-'}
                              </TableCell>
                              <TableCell className="text-xs">
                                {vm.maxdisk ? formatBytes(vm.maxdisk) : '-'}
                              </TableCell>
                              <TableCell className="text-xs">
                                {vm.uptime ? formatUptime(vm.uptime) : '-'}
                              </TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                      </div>
                    );
                  })()}

                  {nodeDetailTab === 'sensors' && (
                    nodeSensorsLoading ? <Skeleton className="h-32" /> : nodeSensors.length === 0 ? (
                      <p className="text-sm text-muted-foreground">{t('HypervisorPage.nodeDetail.noSensors')}</p>
                    ) : (
                      <div className="space-y-3">
                        <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-3">
                          {nodeSensors.map((sensor: any, idx: number) => {
                            const name = sensor.name || sensor.label || t('HypervisorPage.nodeDetail.sensorIndex', { index: idx + 1 });
                            const value = sensor.value ?? sensor.current;
                            const unit = sensor.unit || '';
                            const isTemp = name.toLowerCase().includes('temp') || unit === '\u00b0C' || unit === 'C';
                            const numVal = typeof value === 'number' ? value : parseFloat(value);
                            const isHigh = isTemp && !isNaN(numVal) && numVal > 80;
                            const isWarn = isTemp && !isNaN(numVal) && numVal > 65;
                            return (
                              <div key={`${name}-${idx}`} className="border rounded-md p-2">
                                <p className="text-[10px] text-muted-foreground truncate" title={name}>
                                  {name}
                                </p>
                                <p className={`text-sm font-medium ${isHigh ? 'text-destructive' : isWarn ? 'text-warning' : ''}`}>
                                  {value != null ? `${value}${unit ? ` ${unit}` : ''}` : '-'}
                                </p>
                              </div>
                            );
                          })}
                        </div>
                      </div>
                    )
                  )}
                </div>
              )}
            </CardContent>
          </Card>
        );
      })}
    </div>
  );
};

interface VMTableProps {
  items: HypervisorVM[];
  loading: boolean;
  error: boolean;
  refetch: () => void;
  label: string;
  selectedVMs: Set<string>;
  setSelectedVMs: React.Dispatch<React.SetStateAction<Set<string>>>;
  toggleVMSelect: (key: string) => void;
  onVMAction: (params: { node: string; vmType: string; vmid: number; action: string }) => void;
  onDeleteVM: (params: { node: string; vmType: string; vmid: number }) => void;
  onSnapshot: (vm: HypervisorVM) => void;
  onSnapList: (vm: HypervisorVM) => void;
  onClone: (vm: HypervisorVM) => void;
  onMigrate: (vm: HypervisorVM) => void;
  onResize: (vm: HypervisorVM) => void;
  onBackup: (vm: HypervisorVM) => void;
  onEditConfig: (vm: HypervisorVM) => void;
  onConsole: (vm: HypervisorVM) => void;
  onRowClick?: (vm: HypervisorVM) => void;
  /** Page-wide destructive-confirm helper.
   *  Replaces bare ``window.confirm()`` for shutdown / reboot /
   *  suspend / force-stop. Threaded from HypervisorPage. */
  requestConfirm: (args: {
    title: string;
    description: string;
    confirmationText: string;
    confirmLabel: string;
    onConfirm: () => void;
  }) => void;
}

const VMTable = ({
  items, loading, error, refetch, label,
  selectedVMs, setSelectedVMs, toggleVMSelect,
  onVMAction, onDeleteVM, onSnapshot, onSnapList,
  onClone, onMigrate, onResize, onBackup, onEditConfig, onConsole,
  onRowClick, requestConfirm,
}: VMTableProps) => {
  const { t } = useTranslation('hypervisor');
  // Row-scoped target for the typed-confirm delete dialog. A bare
  // confirm() is bypassed by one click / accidental Enter; the
  // dialog requires the operator to re-type
  // the VM name before the destructive button enables.
  const [deleteTarget, setDeleteTarget] = useState<typeof items[number] | null>(null);

  if (loading) return <Skeleton className="h-64" />;
  if (error) return <ErrorState message={t('HypervisorPage.vmTable.loadError', { label })} onRetry={refetch} />;
  if (items.length === 0) return <EmptyState icon={Monitor} title={t('HypervisorPage.vmTable.emptyTitle', { label })} />;

  return (
    <div className="overflow-x-auto">
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead className="w-[40px]">
            <Checkbox
              checked={items.length > 0 && items.every((vm) => selectedVMs.has(vmKey(vm)))}
              onCheckedChange={() => {
                const allSelected = items.every((vm) => selectedVMs.has(vmKey(vm)));
                setSelectedVMs((prev) => {
                  const next = new Set(prev);
                  items.forEach((vm) => {
                    const k = vmKey(vm);
                    if (allSelected) next.delete(k); else next.add(k);
                  });
                  return next;
                });
              }}
            />
          </TableHead>
          <TableHead>VMID</TableHead>
          <TableHead>{t('HypervisorPage.tableHeaders.name')}</TableHead>
          <TableHead>{t('HypervisorPage.tableHeaders.node')}</TableHead>
          <TableHead>{t('HypervisorPage.tableHeaders.status')}</TableHead>
          <TableHead>{t('HypervisorPage.stats.cpu')}</TableHead>
          <TableHead>{t('HypervisorPage.stats.memory')}</TableHead>
          <TableHead>{t('HypervisorPage.tableHeaders.disk')}</TableHead>
          <TableHead>{t('HypervisorPage.nodes.uptime')}</TableHead>
          <TableHead>{t('HypervisorPage.tableHeaders.tags')}</TableHead>
          <TableHead className="w-[100px]">{t('HypervisorPage.tableHeaders.actions')}</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {items.map((vm) => (
          <TableRow
            key={`${vm.node}-${vm.vmid}`}
            className={onRowClick ? 'cursor-pointer' : ''}
            onClick={(e) => {
              // Don't trigger row click when clicking checkbox or dropdown
              const target = e.target as HTMLElement;
              if (target.closest('button') || target.closest('[role="checkbox"]') || target.closest('[data-radix-collection-item]')) return;
              onRowClick?.(vm);
            }}
          >
            <TableCell>
              <Checkbox
                checked={selectedVMs.has(vmKey(vm))}
                onCheckedChange={() => toggleVMSelect(vmKey(vm))}
              />
            </TableCell>
            <TableCell className="font-mono text-xs">{vm.vmid}</TableCell>
            <TableCell className="font-medium">{vm.name}</TableCell>
            <TableCell className="text-muted-foreground text-xs">{vm.node}</TableCell>
            <TableCell>{statusBadge(vm.status)}</TableCell>
            <TableCell>
              <div className="flex items-center gap-2">
                <Progress value={vm.cpu_percent} className="h-1.5 w-16" />
                <span className="text-xs tabular-nums">{vm.cpu_percent}%</span>
              </div>
            </TableCell>
            <TableCell>
              <div className="flex items-center gap-2">
                <Progress value={vm.memory_percent} className="h-1.5 w-16" />
                <span className="text-xs tabular-nums">
                  {vm.memory_used_mb}/{vm.memory_mb} MB
                </span>
              </div>
            </TableCell>
            <TableCell className="text-xs tabular-nums">
              {vm.disk_gb > 0 ? `${vm.disk_gb.toFixed(1)} GB` : '-'}
            </TableCell>
            <TableCell className="text-xs">{formatUptime(vm.uptime)}</TableCell>
            <TableCell>
              {vm.tags.length > 0 && (
                <div className="flex gap-1 flex-wrap">
                  {vm.tags.slice(0, 3).map((tag) => (
                    <Badge key={tag} variant="outline" className="text-[10px] px-1">
                      {tag}
                    </Badge>
                  ))}
                </div>
              )}
            </TableCell>
            <TableCell>
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button variant="ghost" size="sm" className="h-7 px-2">
                    <ChevronDown className="h-3.5 w-3.5" />
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end">
                  {vm.status === 'stopped' && (
                    <DropdownMenuItem onClick={() => onVMAction({ node: vm.node, vmType: vm.vm_type, vmid: vm.vmid, action: 'start' })}>
                      <Play className="mr-2 h-3.5 w-3.5 text-success" /> {t('HypervisorPage.vmActions.start')}
                    </DropdownMenuItem>
                  )}
                  {vm.status === 'running' && (
                    <>
                      <DropdownMenuItem onClick={() => requestConfirm({
                        title: t('HypervisorPage.vmConfirm.shutdown.title', { vmid: vm.vmid }),
                        description: t('HypervisorPage.vmConfirm.shutdown.description', { name: vm.name, kind: vm.vm_type === 'lxc' ? 'CT' : 'VM', vmid: vm.vmid, node: vm.node }),
                        confirmationText: vm.name,
                        confirmLabel: t('HypervisorPage.vmActions.shutdown'),
                        onConfirm: () => onVMAction({ node: vm.node, vmType: vm.vm_type, vmid: vm.vmid, action: 'shutdown' }),
                      })}>
                        <Power className="mr-2 h-3.5 w-3.5 text-warning" /> {t('HypervisorPage.vmActions.shutdown')}
                      </DropdownMenuItem>
                      <DropdownMenuItem onClick={() => requestConfirm({
                        title: t('HypervisorPage.vmConfirm.reboot.title', { vmid: vm.vmid }),
                        description: t('HypervisorPage.vmConfirm.reboot.description', { name: vm.name, kind: vm.vm_type === 'lxc' ? 'CT' : 'VM', vmid: vm.vmid, node: vm.node }),
                        confirmationText: vm.name,
                        confirmLabel: t('HypervisorPage.vmActions.reboot'),
                        onConfirm: () => onVMAction({ node: vm.node, vmType: vm.vm_type, vmid: vm.vmid, action: 'reboot' }),
                      })}>
                        <RotateCcw className="mr-2 h-3.5 w-3.5 text-info" /> {t('HypervisorPage.vmActions.reboot')}
                      </DropdownMenuItem>
                      <DropdownMenuItem onClick={() => requestConfirm({
                        title: t('HypervisorPage.vmConfirm.suspend.title', { vmid: vm.vmid }),
                        description: t('HypervisorPage.vmConfirm.suspend.description', { name: vm.name, kind: vm.vm_type === 'lxc' ? 'CT' : 'VM', vmid: vm.vmid, node: vm.node }),
                        confirmationText: vm.name,
                        confirmLabel: t('HypervisorPage.vmActions.suspend'),
                        onConfirm: () => onVMAction({ node: vm.node, vmType: vm.vm_type, vmid: vm.vmid, action: 'suspend' }),
                      })}>
                        <Pause className="mr-2 h-3.5 w-3.5 text-warning" /> {t('HypervisorPage.vmActions.suspend')}
                      </DropdownMenuItem>
                      <DropdownMenuItem onClick={() => requestConfirm({
                        title: t('HypervisorPage.vmConfirm.forceStop.title', { vmid: vm.vmid }),
                        description: t('HypervisorPage.vmConfirm.forceStop.description', { name: vm.name, kind: vm.vm_type === 'lxc' ? 'CT' : 'VM', vmid: vm.vmid, node: vm.node }),
                        confirmationText: vm.name,
                        confirmLabel: t('HypervisorPage.vmActions.forceStop'),
                        onConfirm: () => onVMAction({ node: vm.node, vmType: vm.vm_type, vmid: vm.vmid, action: 'stop' }),
                      })} className="text-destructive">
                        <Square className="mr-2 h-3.5 w-3.5" /> {t('HypervisorPage.vmActions.forceStopMenu')}
                      </DropdownMenuItem>
                    </>
                  )}
                  {vm.status === 'paused' && (
                    <DropdownMenuItem onClick={() => onVMAction({ node: vm.node, vmType: vm.vm_type, vmid: vm.vmid, action: 'resume' })}>
                      <Play className="mr-2 h-3.5 w-3.5 text-success" /> {t('HypervisorPage.vmActions.resume')}
                    </DropdownMenuItem>
                  )}

                  <DropdownMenuSeparator />

                  <DropdownMenuItem onClick={() => onSnapshot(vm)}>
                    <Camera className="mr-2 h-3.5 w-3.5" /> {t('HypervisorPage.vmActions.createSnapshot')}
                  </DropdownMenuItem>
                  <DropdownMenuItem onClick={() => onSnapList(vm)}>
                    <FileText className="mr-2 h-3.5 w-3.5" /> {t('HypervisorPage.vmActions.snapshots')}
                  </DropdownMenuItem>

                  <DropdownMenuSeparator />

                  <DropdownMenuItem onClick={() => onClone(vm)}>
                    <Copy className="mr-2 h-3.5 w-3.5" /> {t('HypervisorPage.vmActions.clone')}
                  </DropdownMenuItem>
                  <DropdownMenuItem onClick={() => onMigrate(vm)}>
                    <ArrowRightLeft className="mr-2 h-3.5 w-3.5" /> {t('HypervisorPage.vmActions.migrate')}
                  </DropdownMenuItem>
                  <DropdownMenuItem onClick={() => onResize(vm)}>
                    <Expand className="mr-2 h-3.5 w-3.5" /> {t('HypervisorPage.vmActions.resizeDisk')}
                  </DropdownMenuItem>

                  <DropdownMenuSeparator />

                  <DropdownMenuItem onClick={() => onBackup(vm)}>
                    <Archive className="mr-2 h-3.5 w-3.5" /> {t('HypervisorPage.vmActions.backupNow')}
                  </DropdownMenuItem>

                  <DropdownMenuItem onClick={() => onEditConfig(vm)}>
                    <Cpu className="mr-2 h-3.5 w-3.5" /> {t('HypervisorPage.vmActions.editConfig')}
                  </DropdownMenuItem>

                  <DropdownMenuItem onClick={() => onConsole(vm)}>
                    <Terminal className="mr-2 h-3.5 w-3.5" /> {t('HypervisorPage.vmActions.console')}
                  </DropdownMenuItem>

                  <DropdownMenuSeparator />

                  <DropdownMenuItem
                    className="text-destructive"
                    disabled={vm.status === 'running'}
                    onClick={() => setDeleteTarget(vm)}
                  >
                    <Trash2 className="mr-2 h-3.5 w-3.5" /> {t('HypervisorPage.vmActions.delete')}
                  </DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
    <DestructiveConfirmDialog
      open={deleteTarget !== null}
      onOpenChange={(o) => !o && setDeleteTarget(null)}
      title={t('HypervisorPage.vmTable.deleteConfirm.title', { kind: deleteTarget?.vm_type === 'lxc' ? 'CT' : 'VM', vmid: deleteTarget?.vmid ?? '' })}
      description={t('HypervisorPage.vmTable.deleteConfirm.description', {
        kind: deleteTarget?.vm_type === 'lxc' ? t('HypervisorPage.common.containerLower') : 'VM',
        vmid: deleteTarget?.vmid,
        name: deleteTarget?.name,
        node: deleteTarget?.node,
      })}
      confirmationText={deleteTarget?.name ?? ''}
      confirmLabel={t('HypervisorPage.vmTable.deleteConfirm.confirmLabel', { kind: deleteTarget?.vm_type === 'lxc' ? 'CT' : 'VM' })}
      onConfirm={() => {
        if (!deleteTarget) return;
        onDeleteVM({
          node: deleteTarget.node,
          vmType: deleteTarget.vm_type,
          vmid: deleteTarget.vmid,
        });
        setDeleteTarget(null);
      }}
    />
    </div>
  );
};

interface StorageTabProps {
  nodes: HypervisorNode[];
  activeStorageNode: string;
  setStorageNode: (node: string) => void;
  storageLoading: boolean;
  storageError: boolean;
  storagePools: HypervisorStorage[];
  refetchStorage: () => void;
  setUploadDialog: (value: { node: string; storage: string } | null) => void;
  controllerId: string;
  setRestoreDialog: (value: { archive: string; node: string; vmType: string; storage: string } | null) => void;
}

const buildContentTypes = (t: (key: string) => string) => [
  { value: '', label: t('HypervisorPage.storage.contentTypes.all') },
  { value: 'iso', label: 'ISO' },
  { value: 'vztmpl', label: t('HypervisorPage.storage.contentTypes.templates') },
  { value: 'backup', label: t('HypervisorPage.storage.contentTypes.backups') },
  { value: 'images', label: t('HypervisorPage.storage.contentTypes.diskImages') },
  { value: 'snippets', label: t('HypervisorPage.storage.contentTypes.snippets') },
];

const StorageTab = ({
  nodes, activeStorageNode, setStorageNode,
  storageLoading, storageError, storagePools, refetchStorage, setUploadDialog,
  controllerId, setRestoreDialog,
}: StorageTabProps) => {
  const { t } = useTranslation('hypervisor');
  const CONTENT_TYPES = useMemo(() => buildContentTypes(t), [t]);
  const [expandedStorage, setExpandedStorage] = useState<string | null>(null);
  const [contentFilter, setContentFilter] = useState('');
  const [vmidFilter, setVmidFilter] = useState('');

  const contentFilters = {
    ...(contentFilter ? { content: contentFilter } : {}),
    ...(vmidFilter ? { vmid: parseInt(vmidFilter) } : {}),
  };
  const hasFilters = contentFilter || vmidFilter;

  const { data: contentResp, isLoading: contentLoading } = useQuery({
    queryKey: ['hypervisor', 'storage-content', controllerId, activeStorageNode, expandedStorage, contentFilter, vmidFilter],
    queryFn: () => hypervisorApi.getStorageContent(
      controllerId, activeStorageNode, expandedStorage!,
      Object.keys(contentFilters).length > 0 ? contentFilters : undefined
    ),
    enabled: !!controllerId && !!activeStorageNode && !!expandedStorage,
  });
  const storageContent: any[] = contentResp?.data || [];

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          {nodes.length > 1 && (
            <>
              <Label className="text-sm">{t('HypervisorPage.common.nodeLabel')}</Label>
              <Select value={activeStorageNode} onValueChange={setStorageNode}>
                <SelectTrigger className="w-[200px]">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {nodes.map((n) => (
                    <SelectItem key={n.node} value={n.node}>{n.node}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </>
          )}
        </div>
        {activeStorageNode && (
          <Button
            variant="outline"
            size="sm"
            onClick={() => setUploadDialog({ node: activeStorageNode, storage: storagePools[0]?.storage || 'local' })}
          >
            <Upload className="h-3.5 w-3.5 mr-1" /> {t('HypervisorPage.storage.uploadIso')}
          </Button>
        )}
      </div>

      {storageLoading ? <Skeleton className="h-64" /> :
       storageError ? <ErrorState message={t('HypervisorPage.storage.loadError')} onRetry={() => refetchStorage()} /> :
       storagePools.length === 0 ? <EmptyState icon={HardDrive} title={t('HypervisorPage.storage.emptyTitle')} /> : (
        <div className="grid gap-4 grid-cols-1 md:grid-cols-2 lg:grid-cols-3">
          {storagePools.map((pool) => {
            const isExpanded = expandedStorage === pool.storage;
            return (
              <Card key={`${pool.node}-${pool.storage}`} className={isExpanded ? 'col-span-full' : ''}>
                <CardHeader className="pb-2">
                  <div
                    className="flex items-center justify-between cursor-pointer"
                    onClick={() => {
                      setExpandedStorage(isExpanded ? null : pool.storage);
                      setContentFilter('');
                      setVmidFilter('');
                    }}
                  >
                    <div className="flex items-center gap-2">
                      {isExpanded
                        ? <ChevronDown className="h-4 w-4 text-muted-foreground" />
                        : <ChevronRight className="h-4 w-4 text-muted-foreground" />}
                      <HardDrive className="h-4 w-4 text-muted-foreground" />
                      <CardTitle className="text-sm">{pool.storage}</CardTitle>
                    </div>
                    <Badge variant={pool.active ? 'default' : 'secondary'} className="text-[10px]">
                      {pool.storage_type}
                    </Badge>
                  </div>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2">
                    <div className="flex justify-between text-xs">
                      <span className="text-muted-foreground">
                        {formatBytes(pool.used)} / {formatBytes(pool.total)}
                      </span>
                      <span className="font-medium">{pool.used_percent}%</span>
                    </div>
                    <MetricBar
                      value={pool.used_percent}
                      variant="thick"
                      hideValue
                      thresholds={[75, 90]}
                    />
                    <div className="flex gap-2 text-[10px] text-muted-foreground">
                      <span>{t('HypervisorPage.storage.nodeColon', { node: pool.node })}</span>
                      {pool.shared && <Badge variant="outline" className="text-[10px] px-1">{t('HypervisorPage.storage.shared')}</Badge>}
                      <span>{t('HypervisorPage.storage.contentColon', { content: pool.content })}</span>
                    </div>

                    {/* Expanded content browser */}
                    {isExpanded && (
                      <div className="border-t pt-3 mt-3 space-y-3">
                        <div className="flex items-center gap-3 flex-wrap">
                          <div className="flex items-center gap-1.5">
                            <Filter className="h-3.5 w-3.5 text-muted-foreground" />
                            <Label className="text-xs">{t('HypervisorPage.storage.contentLabel')}</Label>
                            <Select value={contentFilter} onValueChange={setContentFilter}>
                              <SelectTrigger className="w-[120px] h-7 text-xs">
                                <SelectValue placeholder={t('HypervisorPage.storage.contentTypes.all')} />
                              </SelectTrigger>
                              <SelectContent>
                                {CONTENT_TYPES.map((ct) => (
                                  <SelectItem key={ct.value} value={ct.value}>{ct.label}</SelectItem>
                                ))}
                              </SelectContent>
                            </Select>
                          </div>
                          <div className="flex items-center gap-1.5">
                            <Search className="h-3.5 w-3.5 text-muted-foreground" />
                            <Input
                              placeholder="VMID"
                              value={vmidFilter}
                              onChange={(e) => setVmidFilter(e.target.value.replace(/\D/g, ''))}
                              className="w-[80px] h-7 text-xs"
                            />
                          </div>
                        </div>

                        {contentLoading ? (
                          <Skeleton className="h-24" />
                        ) : storageContent.length === 0 ? (
                          <p className="text-xs text-muted-foreground text-center py-4">
                            {hasFilters ? t('HypervisorPage.storage.noContentMatch') : t('HypervisorPage.storage.empty')}
                          </p>
                        ) : (
                          <div className="overflow-x-auto">
                          <Table>
                            <TableHeader>
                              <TableRow>
                                <TableHead className="text-xs">{t('HypervisorPage.tableHeaders.name')}</TableHead>
                                <TableHead className="text-xs">{t('HypervisorPage.storage.format')}</TableHead>
                                <TableHead className="text-xs">{t('HypervisorPage.tableHeaders.size')}</TableHead>
                                <TableHead className="text-xs">VMID</TableHead>
                                <TableHead className="text-xs">{t('HypervisorPage.storage.content')}</TableHead>
                                <TableHead className="text-xs w-[60px]" />
                              </TableRow>
                            </TableHeader>
                            <TableBody>
                              {storageContent.map((item: any) => (
                                <TableRow key={item.volid || item.name}>
                                  <TableCell className="font-mono text-[10px] max-w-[300px] truncate" title={item.volid || item.name}>
                                    {item.volid || item.name}
                                  </TableCell>
                                  <TableCell className="text-[10px]">{item.format || '-'}</TableCell>
                                  <TableCell className="text-[10px]">{item.size ? formatBytes(item.size) : '-'}</TableCell>
                                  <TableCell className="font-mono text-[10px]">{item.vmid || '-'}</TableCell>
                                  <TableCell>
                                    <Badge variant="outline" className="text-[10px]">{item.content || '-'}</Badge>
                                  </TableCell>
                                  <TableCell>
                                    {(item.content === 'backup' || (item.volid && String(item.volid).includes('vzdump'))) && (
                                      <Button
                                        variant="ghost"
                                        size="sm"
                                        className="h-6 px-2 text-[10px]"
                                        onClick={() => setRestoreDialog({
                                          archive: item.volid || item.name,
                                          node: activeStorageNode,
                                          vmType: String(item.volid || '').includes('lxc') ? 'lxc' : 'qemu',
                                          storage: pool.storage,
                                        })}
                                      >
                                        <Undo2 className="h-3 w-3 mr-0.5" /> {t('HypervisorPage.storage.restore')}
                                      </Button>
                                    )}
                                  </TableCell>
                                </TableRow>
                              ))}
                            </TableBody>
                          </Table>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}
    </div>
  );
};

interface TasksTabProps {
  nodes: HypervisorNode[];
  activeTasksNode: string;
  setTasksNode: (node: string) => void;
  tasksLoading: boolean;
  tasksError: boolean;
  tasks: HypervisorTask[];
  refetchTasks: () => void;
  setTaskLogDialog: (value: { node: string; upid: string } | null) => void;
  onStopTask: (params: { node: string; upid: string }) => void;
  requestConfirm: (args: {
    title: string; description: string; confirmationText: string;
    confirmLabel: string; onConfirm: () => void;
  }) => void;
}

const TasksTab = ({
  nodes, activeTasksNode, setTasksNode,
  tasksLoading, tasksError, tasks, refetchTasks,
  setTaskLogDialog, onStopTask, requestConfirm,
}: TasksTabProps) => {
  const { t } = useTranslation('hypervisor');
  return (
    <div className="space-y-4">
      {nodes.length > 1 && (
        <div className="flex items-center gap-2">
          <Label className="text-sm">{t('HypervisorPage.common.nodeLabel')}</Label>
          <Select value={activeTasksNode} onValueChange={setTasksNode}>
            <SelectTrigger className="w-[200px]">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {nodes.map((n) => (
                <SelectItem key={n.node} value={n.node}>{n.node}</SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Button variant="outline" size="sm" onClick={() => refetchTasks()}>
            <RefreshCw className="h-3.5 w-3.5 mr-1" /> {t('HypervisorPage.actions.refresh')}
          </Button>
        </div>
      )}

      {tasksLoading ? <Skeleton className="h-64" /> :
       tasksError ? <ErrorState message={t('HypervisorPage.tasks.loadError')} onRetry={() => refetchTasks()} /> :
       tasks.length === 0 ? <EmptyState icon={ListTodo} title={t('HypervisorPage.tasks.emptyTitle')} /> : (
        <div className="overflow-x-auto">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>{t('HypervisorPage.tableHeaders.type')}</TableHead>
              <TableHead>{t('HypervisorPage.tableHeaders.status')}</TableHead>
              <TableHead>{t('HypervisorPage.tasks.user')}</TableHead>
              <TableHead>{t('HypervisorPage.tasks.started')}</TableHead>
              <TableHead>{t('HypervisorPage.tasks.ended')}</TableHead>
              <TableHead className="w-[100px]">{t('HypervisorPage.tableHeaders.actions')}</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {tasks.map((task) => (
              <TableRow key={task.upid}>
                <TableCell className="font-medium text-sm">{task.type}</TableCell>
                <TableCell>
                  <Badge
                    variant={
                      task.is_running ? 'default' :
                      task.status === 'OK' ? 'secondary' :
                      'destructive'
                    }
                    className="gap-1"
                  >
                    {task.is_running ? <Activity className="h-3 w-3 animate-pulse" /> :
                     task.status === 'OK' ? <CheckCircle className="h-3 w-3" /> :
                     <XCircle className="h-3 w-3" />}
                    {task.is_running ? t('HypervisorPage.taskStatus.running') : task.status}
                  </Badge>
                </TableCell>
                <TableCell className="text-xs text-muted-foreground">{task.user}</TableCell>
                <TableCell className="text-xs">{formatTimestamp(task.started_at)}</TableCell>
                <TableCell className="text-xs">{formatTimestamp(task.ended_at)}</TableCell>
                <TableCell>
                  <div className="flex gap-1">
                    <Button
                      variant="ghost"
                      size="sm"
                      className="h-7 px-2"
                      onClick={() => setTaskLogDialog({ node: task.node, upid: task.upid })}
                    >
                      <FileText className="h-3.5 w-3.5" />
                    </Button>
                    {task.is_running && (
                      <Button
                        variant="ghost"
                        size="sm"
                        className="h-7 px-2 text-destructive"
                        onClick={() => requestConfirm({
                          title: t('HypervisorPage.tasks.stopConfirm.title'),
                          description: t('HypervisorPage.tasks.stopConfirm.description', { type: task.type || t('HypervisorPage.tasks.taskWord'), upid: task.upid?.slice(0, 60) }),
                          confirmationText: 'stop',
                          confirmLabel: t('HypervisorPage.tasks.stopConfirm.confirmLabel'),
                          onConfirm: () => onStopTask({ node: task.node, upid: task.upid }),
                        })}
                      >
                        <StopCircle className="h-3.5 w-3.5" />
                      </Button>
                    )}
                  </div>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
        </div>
      )}
    </div>
  );
};

interface BackupTabProps {
  backupLoading: boolean;
  backupError: boolean;
  backupJobs: HypervisorBackupJob[];
  refetchBackup: () => void;
  setEditBackupJob: (job: HypervisorBackupJob | null) => void;
  setBackupJobDialog: (open: boolean) => void;
  deleteBackupJobMutation: { mutate: (jobId: string) => void; isPending: boolean };
  requestConfirm: (args: {
    title: string; description: string; confirmationText: string;
    confirmLabel: string; onConfirm: () => void;
  }) => void;
}

const BackupTab = ({
  backupLoading, backupError, backupJobs, refetchBackup,
  setEditBackupJob, setBackupJobDialog, deleteBackupJobMutation, requestConfirm,
}: BackupTabProps) => {
  const { t } = useTranslation('hypervisor');
  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-medium">{t('HypervisorPage.backup.heading')}</h3>
        <Button size="sm" onClick={() => { setEditBackupJob(null); setBackupJobDialog(true); }}>
          <Plus className="h-3.5 w-3.5 mr-1" /> {t('HypervisorPage.backup.createJob')}
        </Button>
      </div>

      {backupLoading ? <Skeleton className="h-64" /> :
       backupError ? <ErrorState message={t('HypervisorPage.backup.loadError')} onRetry={() => refetchBackup()} /> :
       backupJobs.length === 0 ? <EmptyState icon={Archive} title={t('HypervisorPage.backup.emptyTitle')} description={t('HypervisorPage.backup.emptyDescription')} /> : (
        <div className="overflow-x-auto">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>ID</TableHead>
              <TableHead>{t('HypervisorPage.backup.schedule')}</TableHead>
              <TableHead>{t('HypervisorPage.tableHeaders.storage')}</TableHead>
              <TableHead>VMs</TableHead>
              <TableHead>{t('HypervisorPage.backup.mode')}</TableHead>
              <TableHead>{t('HypervisorPage.backup.compress')}</TableHead>
              <TableHead>{t('HypervisorPage.tableHeaders.node')}</TableHead>
              <TableHead>{t('HypervisorPage.backup.enabled')}</TableHead>
              <TableHead className="w-[100px]">{t('HypervisorPage.tableHeaders.actions')}</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {backupJobs.map((job) => (
              <TableRow key={job.id}>
                <TableCell className="font-mono text-xs">{job.id}</TableCell>
                <TableCell className="text-sm">{job.schedule}</TableCell>
                <TableCell className="text-sm">{job.storage}</TableCell>
                <TableCell className="text-xs text-muted-foreground">{job.vmid || t('HypervisorPage.common.all')}</TableCell>
                <TableCell>
                  <Badge variant="outline" className="text-[10px]">{job.mode}</Badge>
                </TableCell>
                <TableCell className="text-xs">{job.compress}</TableCell>
                <TableCell className="text-xs text-muted-foreground">{job.node || t('HypervisorPage.common.all')}</TableCell>
                <TableCell>
                  <Badge variant={job.enabled ? 'default' : 'secondary'}>
                    {job.enabled ? t('HypervisorPage.common.yes') : t('HypervisorPage.common.no')}
                  </Badge>
                </TableCell>
                <TableCell>
                  <div className="flex gap-1">
                    <Button
                      variant="ghost" size="sm" className="h-7 px-2"
                      title={t('HypervisorPage.actions.edit')}
                      onClick={() => { setEditBackupJob(job); setBackupJobDialog(true); }}
                    >
                      <FileText className="h-3.5 w-3.5" />
                    </Button>
                    <Button
                      variant="ghost" size="sm" className="h-7 px-2 text-destructive"
                      title={t('HypervisorPage.actions.delete')}
                      onClick={() => requestConfirm({
                        title: t('HypervisorPage.backup.deleteConfirm.title'),
                        description: t('HypervisorPage.backup.deleteConfirm.description', { id: job.id }),
                        confirmationText: job.id,
                        confirmLabel: t('HypervisorPage.backup.deleteConfirm.confirmLabel'),
                        onConfirm: () => deleteBackupJobMutation.mutate(job.id),
                      })}
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </Button>
                  </div>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
        </div>
      )}
    </div>
  );
};

interface FirewallTabProps {
  fwLoading: boolean;
  fwError: boolean;
  firewallRules: HypervisorFirewallRule[];
  refetchFW: () => void;
  nodes: HypervisorNode[];
  setFwCreateDialog: (value: { node: string } | null) => void;
  setFwAction: (value: string) => void;
  setFwType: (value: string) => void;
  setFwSource: (value: string) => void;
  setFwDest: (value: string) => void;
  setFwDport: (value: string) => void;
  setFwProto: (value: string) => void;
  setFwComment: (value: string) => void;
  deleteFwRuleMutation: { mutate: (params: { node: string; pos: number }) => void; isPending: boolean };
  requestConfirm: (args: {
    title: string; description: string; confirmationText: string;
    confirmLabel: string; onConfirm: () => void;
  }) => void;
}

const FirewallTab = ({
  fwLoading, fwError, firewallRules, refetchFW, nodes,
  setFwCreateDialog, setFwAction, setFwType, setFwSource, setFwDest, setFwDport, setFwProto, setFwComment,
  deleteFwRuleMutation, requestConfirm,
}: FirewallTabProps) => {
  const { t } = useTranslation('hypervisor');
  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-medium">{t('HypervisorPage.firewall.heading')}</h3>
        {nodes.length > 0 && (
          <Button
            variant="outline"
            size="sm"
            onClick={() => {
              setFwCreateDialog({ node: nodes[0].node });
              setFwAction('ACCEPT');
              setFwType('in');
              setFwSource('');
              setFwDest('');
              setFwDport('');
              setFwProto('tcp');
              setFwComment('');
            }}
          >
            <Shield className="h-3.5 w-3.5 mr-1" /> {t('HypervisorPage.firewall.addRule')}
          </Button>
        )}
      </div>

      {fwLoading ? <Skeleton className="h-64" /> :
       fwError ? <ErrorState message={t('HypervisorPage.firewall.loadError')} onRetry={() => refetchFW()} /> :
       firewallRules.length === 0 ? <EmptyState icon={Shield} title={t('HypervisorPage.firewall.emptyTitle')} description={t('HypervisorPage.firewall.emptyDescription')} /> : (
        <div className="overflow-x-auto">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>#</TableHead>
              <TableHead>{t('HypervisorPage.tableHeaders.type')}</TableHead>
              <TableHead>{t('HypervisorPage.firewall.action')}</TableHead>
              <TableHead>{t('HypervisorPage.firewall.protocol')}</TableHead>
              <TableHead>{t('HypervisorPage.firewall.source')}</TableHead>
              <TableHead>{t('HypervisorPage.firewall.dest')}</TableHead>
              <TableHead>{t('HypervisorPage.firewall.dport')}</TableHead>
              <TableHead>{t('HypervisorPage.backup.enabled')}</TableHead>
              <TableHead>{t('HypervisorPage.firewall.comment')}</TableHead>
              <TableHead className="w-[60px]" />
            </TableRow>
          </TableHeader>
          <TableBody>
            {firewallRules.map((rule) => (
              <TableRow key={rule.pos}>
                <TableCell className="font-mono text-xs">{rule.pos}</TableCell>
                <TableCell>
                  <Badge variant="outline" className="text-[10px]">{rule.type}</Badge>
                </TableCell>
                <TableCell>
                  <Badge
                    variant={rule.action === 'ACCEPT' ? 'default' : rule.action === 'DROP' ? 'destructive' : 'secondary'}
                  >
                    {rule.action}
                  </Badge>
                </TableCell>
                <TableCell className="text-xs">{rule.proto || '-'}</TableCell>
                <TableCell className="text-xs font-mono">{rule.source || '-'}</TableCell>
                <TableCell className="text-xs font-mono">{rule.dest || '-'}</TableCell>
                <TableCell className="text-xs font-mono">{rule.dport || '-'}</TableCell>
                <TableCell>
                  <Badge variant={rule.enable ? 'default' : 'secondary'} className="text-[10px]">
                    {rule.enable ? t('HypervisorPage.common.yes') : t('HypervisorPage.common.no')}
                  </Badge>
                </TableCell>
                <TableCell className="text-xs text-muted-foreground max-w-[200px] truncate">
                  {rule.comment || '-'}
                </TableCell>
                <TableCell>
                  <Button
                    variant="ghost"
                    size="sm"
                    className="h-7 w-7 p-0 text-destructive"
                    disabled={deleteFwRuleMutation.isPending}
                    onClick={() => {
                      if (nodes.length === 0) return;
                      const pos = rule.pos;
                      const action = rule.action || t('HypervisorPage.firewall.ruleWord');
                      requestConfirm({
                        title: t('HypervisorPage.firewall.deleteConfirm.title', { pos }),
                        description: t('HypervisorPage.firewall.deleteConfirm.description', { pos, action, type: rule.type || t('HypervisorPage.common.unknownLower') }),
                        confirmationText: String(pos),
                        confirmLabel: t('HypervisorPage.firewall.deleteConfirm.confirmLabel'),
                        onConfirm: () => deleteFwRuleMutation.mutate({ node: nodes[0].node, pos }),
                      });
                    }}
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                  </Button>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
        </div>
      )}
    </div>
  );
};

interface HATabProps {
  haResLoading: boolean;
  haResError: boolean;
  haResources: HypervisorHAResource[];
  refetchHARes: () => void;
  haGroups: HypervisorHAGroup[];
  setHaResDialog: (open: boolean) => void;
  setHaResSid: (value: string) => void;
  setHaResGroup: (value: string) => void;
  setHaGrpDialog: (open: boolean) => void;
  setHaGrpName: (value: string) => void;
  setHaGrpNodes: (value: string) => void;
  setHaGrpComment: (value: string) => void;
  setHaGrpNofailback: (value: boolean) => void;
  setHaGrpRestricted: (value: boolean) => void;
  deleteHAResourceMutation: { mutate: (sid: string) => void; isPending: boolean };
  deleteHAGroupMutation: { mutate: (group: string) => void; isPending: boolean };
  requestConfirm: (args: {
    title: string; description: string; confirmationText: string;
    confirmLabel: string; onConfirm: () => void;
  }) => void;
}

const HATab = ({
  haResLoading, haResError, haResources, refetchHARes, haGroups,
  setHaResDialog, setHaResSid, setHaResGroup,
  setHaGrpDialog, setHaGrpName, setHaGrpNodes, setHaGrpComment, setHaGrpNofailback, setHaGrpRestricted,
  deleteHAResourceMutation, deleteHAGroupMutation, requestConfirm,
}: HATabProps) => {
  const { t } = useTranslation('hypervisor');
  if (haResLoading) return <Skeleton className="h-64" />;
  if (haResError) return <ErrorState message={t('HypervisorPage.ha.loadError')} onRetry={() => refetchHARes()} />;

  return (
    <div className="space-y-6">
      <div>
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-sm font-medium">{t('HypervisorPage.ha.resourcesHeading')}</h3>
          <Button size="sm" variant="outline" onClick={() => { setHaResDialog(true); setHaResSid(''); setHaResGroup(''); }}>
            <Plus className="h-3.5 w-3.5 mr-1" /> {t('HypervisorPage.ha.addResource')}
          </Button>
        </div>
        {haResources.length === 0 ? (
          <EmptyState icon={Activity} title={t('HypervisorPage.ha.resourcesEmptyTitle')} description={t('HypervisorPage.ha.resourcesEmptyDescription')} />
        ) : (
          <div className="overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>SID</TableHead>
                <TableHead>{t('HypervisorPage.ha.state')}</TableHead>
                <TableHead>{t('HypervisorPage.tableHeaders.node')}</TableHead>
                <TableHead>{t('HypervisorPage.ha.group')}</TableHead>
                <TableHead>{t('HypervisorPage.ha.request')}</TableHead>
                <TableHead>{t('HypervisorPage.ha.maxRelocate')}</TableHead>
                <TableHead>{t('HypervisorPage.ha.maxRestart')}</TableHead>
                <TableHead>{t('HypervisorPage.tableHeaders.status')}</TableHead>
                <TableHead className="w-[60px]" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {haResources.map((res) => (
                <TableRow key={res.sid}>
                  <TableCell className="font-mono text-xs">{res.sid}</TableCell>
                  <TableCell>
                    <Badge variant={res.state === 'started' ? 'default' : 'secondary'}>{res.state}</Badge>
                  </TableCell>
                  <TableCell className="text-xs">{res.node || '-'}</TableCell>
                  <TableCell className="text-xs">{res.group || '-'}</TableCell>
                  <TableCell className="text-xs">{res.request_state || '-'}</TableCell>
                  <TableCell className="text-xs text-center">{res.max_relocate}</TableCell>
                  <TableCell className="text-xs text-center">{res.max_restart}</TableCell>
                  <TableCell className="text-xs text-muted-foreground">{res.status || res.crm_state || '-'}</TableCell>
                  <TableCell>
                    <Button
                      variant="ghost"
                      size="sm"
                      className="h-7 w-7 p-0 text-destructive"
                      onClick={() => requestConfirm({
                        title: t('HypervisorPage.ha.removeResourceConfirm.title'),
                        description: t('HypervisorPage.ha.removeResourceConfirm.description', { sid: res.sid }),
                        confirmationText: res.sid,
                        confirmLabel: t('HypervisorPage.ha.removeResourceConfirm.confirmLabel'),
                        onConfirm: () => deleteHAResourceMutation.mutate(res.sid),
                      })}
                      disabled={deleteHAResourceMutation.isPending}
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
          </div>
        )}
      </div>

      <div>
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-sm font-medium">{t('HypervisorPage.ha.groupsHeading')}</h3>
          <Button size="sm" variant="outline" onClick={() => { setHaGrpDialog(true); setHaGrpName(''); setHaGrpNodes(''); setHaGrpComment(''); setHaGrpNofailback(false); setHaGrpRestricted(false); }}>
            <Plus className="h-3.5 w-3.5 mr-1" /> {t('HypervisorPage.ha.addGroup')}
          </Button>
        </div>
        {haGroups.length === 0 ? (
          <p className="text-sm text-muted-foreground">{t('HypervisorPage.ha.noGroups')}</p>
        ) : (
          <div className="overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{t('HypervisorPage.ha.group')}</TableHead>
                <TableHead>{t('HypervisorPage.ha.nodes')}</TableHead>
                <TableHead>{t('HypervisorPage.ha.noFailback')}</TableHead>
                <TableHead>{t('HypervisorPage.ha.restricted')}</TableHead>
                <TableHead>{t('HypervisorPage.firewall.comment')}</TableHead>
                <TableHead className="w-[60px]" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {haGroups.map((grp) => (
                <TableRow key={grp.group}>
                  <TableCell className="font-medium text-sm">{grp.group}</TableCell>
                  <TableCell className="text-xs font-mono">{grp.nodes}</TableCell>
                  <TableCell className="text-xs">{grp.nofailback ? t('HypervisorPage.common.yes') : t('HypervisorPage.common.no')}</TableCell>
                  <TableCell className="text-xs">{grp.restricted ? t('HypervisorPage.common.yes') : t('HypervisorPage.common.no')}</TableCell>
                  <TableCell className="text-xs text-muted-foreground">{grp.comment || '-'}</TableCell>
                  <TableCell>
                    <Button
                      variant="ghost"
                      size="sm"
                      className="h-7 w-7 p-0 text-destructive"
                      onClick={() => requestConfirm({
                        title: t('HypervisorPage.ha.deleteGroupConfirm.title', { group: grp.group }),
                        description: t('HypervisorPage.ha.deleteGroupConfirm.description', { group: grp.group }),
                        confirmationText: grp.group,
                        confirmLabel: t('HypervisorPage.ha.deleteGroupConfirm.confirmLabel'),
                        onConfirm: () => deleteHAGroupMutation.mutate(grp.group),
                      })}
                      disabled={deleteHAGroupMutation.isPending}
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
          </div>
        )}
      </div>
    </div>
  );
};

interface PoolsTabProps {
  poolsLoading: boolean;
  poolsError: boolean;
  pools: HypervisorResourcePool[];
  refetchPools: () => void;
}

const PoolsTab = ({ poolsLoading, poolsError, pools, refetchPools }: PoolsTabProps) => {
  const { t } = useTranslation('hypervisor');
  if (poolsLoading) return <Skeleton className="h-64" />;
  if (poolsError) return <ErrorState message={t('HypervisorPage.pools.loadError')} onRetry={() => refetchPools()} />;
  if (pools.length === 0) return <EmptyState icon={Layers} title={t('HypervisorPage.pools.emptyTitle')} description={t('HypervisorPage.pools.emptyDescription')} />;

  return (
    <div className="grid gap-4 grid-cols-1 md:grid-cols-2 lg:grid-cols-3">
      {pools.map((pool) => (
        <Card key={pool.poolid}>
          <CardHeader className="pb-2">
            <div className="flex items-center gap-2">
              <Layers className="h-4 w-4 text-muted-foreground" />
              <CardTitle className="text-sm">{pool.poolid}</CardTitle>
            </div>
          </CardHeader>
          <CardContent>
            <p className="text-xs text-muted-foreground mb-2">{pool.comment || t('HypervisorPage.pools.noDescription')}</p>
            <Badge variant="outline" className="text-[10px]">
              {t('HypervisorPage.pools.membersCount', { count: pool.members?.length || 0 })}
            </Badge>
          </CardContent>
        </Card>
      ))}
    </div>
  );
};

// ============================================================================
// MAIN COMPONENT
// ============================================================================

export function HypervisorPage() {
  const { t } = useTranslation('hypervisor');
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const selectedSiteId = useSiteStore((s) => s.selectedSiteId);
  const params = useParams<Record<string, string>>();

  // Page-wide destructive-confirm state. One dialog mount + one
  // state at the page
  // top + a ``requestConfirm()`` helper that each handler invokes
  // instead of native ``window.confirm()``. Replaces the per-row
  // ``confirm()`` traps for node power, task stop, backup-job
  // delete, firewall-rule delete, HA resource/group delete,
  // snapshot rollback/delete. VMTable's per-row VM-power confirms
  // receive ``requestConfirm`` as a prop.
  const [confirmState, setConfirmState] = useState<{
    title: string;
    description: string;
    confirmationText: string;
    confirmLabel: string;
    onConfirm: () => void;
  } | null>(null);

  const requestConfirm = useCallback((args: {
    title: string;
    description: string;
    confirmationText: string;
    confirmLabel: string;
    onConfirm: () => void;
  }) => {
    setConfirmState({
      ...args,
      onConfirm: () => {
        args.onConfirm();
        setConfirmState(null);
      },
    });
  }, []);

  // ── Controller selection ──────────────────────────────────────────────
  const { data: controllersResp, isLoading: controllersLoading } = useQuery({
    queryKey: ['controllers', 'proxmox', selectedSiteId],
    queryFn: () => controllersApi.getAll(selectedSiteId || undefined),
  });

  const proxmoxControllers = useMemo(() => {
    const resp = controllersResp?.data;
    const all = resp?.items || resp || [];
    return (Array.isArray(all) ? all : []).filter(
      (c: any) => c.controller_type === 'proxmox' || c.controller_type === 'pve'
    );
  }, [controllersResp]);

  const [selectedCtrlId, setSelectedCtrlId] = useState<string>('');
  const [showAddDialog, setShowAddDialog] = useState(false);
  const controllerId = selectedCtrlId || proxmoxControllers[0]?.id || '';

  // First tab is 'fleet' when multiple controllers, else 'dashboard'
  const defaultTab = proxmoxControllers.length > 1 ? 'fleet' : 'dashboard';
  const activeTab = params['tab'] || defaultTab;

  // ── Dashboard ─────────────────────────────────────────────────────────
  const {
    data: dashboardResp,
    isLoading: dashLoading,
    isError: dashError,
    refetch: refetchDash,
  } = useQuery({
    queryKey: ['hypervisor', 'dashboard', controllerId],
    queryFn: () => hypervisorApi.getDashboard(controllerId),
    enabled: !!controllerId && (activeTab === 'dashboard' || activeTab === 'fleet'),
    refetchInterval: 30_000,
  });
  const dash: HypervisorDashboard | undefined = dashboardResp?.data;

  // ── Nodes ──────────────────────────────────────────────────────────────
  const {
    data: nodesResp,
    isLoading: nodesLoading,
    isError: nodesError,
    refetch: refetchNodes,
  } = useQuery({
    queryKey: ['hypervisor', 'nodes', controllerId],
    queryFn: () => hypervisorApi.getNodes(controllerId),
    enabled: !!controllerId,
    refetchInterval: 30_000,
  });
  const nodes: HypervisorNode[] = nodesResp?.data || [];

  // ── VMs ────────────────────────────────────────────────────────────────
  const {
    data: vmsResp,
    isLoading: vmsLoading,
    isError: vmsError,
    refetch: refetchVMs,
  } = useQuery({
    queryKey: ['hypervisor', 'vms', controllerId],
    queryFn: () => hypervisorApi.getAllVMs(controllerId, 'qemu'),
    enabled: !!controllerId,
    refetchInterval: 15_000,
  });
  const vms: HypervisorVM[] = (vmsResp?.data || []).filter((v) => !v.template);

  // ── Containers ─────────────────────────────────────────────────────────
  const {
    data: ctsResp,
    isLoading: ctsLoading,
    isError: ctsError,
    refetch: refetchCTs,
  } = useQuery({
    queryKey: ['hypervisor', 'containers', controllerId],
    queryFn: () => hypervisorApi.getAllVMs(controllerId, 'lxc'),
    enabled: !!controllerId,
    refetchInterval: 15_000,
  });
  const containers: HypervisorVM[] = (ctsResp?.data || []).filter((v) => !v.template);

  // ── Storage (per-node selector) ────────────────────────────────────────
  const [storageNode, setStorageNode] = useState<string>('');
  const activeStorageNode = storageNode || nodes[0]?.node || '';
  const {
    data: storageResp,
    isLoading: storageLoading,
    isError: storageError,
    refetch: refetchStorage,
  } = useQuery({
    queryKey: ['hypervisor', 'storage', controllerId, activeStorageNode],
    queryFn: () => hypervisorApi.getStorage(controllerId, activeStorageNode),
    enabled: !!controllerId && !!activeStorageNode && activeTab === 'storage',
  });
  const storagePools: HypervisorStorage[] = storageResp?.data || [];

  // ── Tasks (first node) ────────────────────────────────────────────────
  const [tasksNode, setTasksNode] = useState<string>('');
  const activeTasksNode = tasksNode || nodes[0]?.node || '';
  const {
    data: tasksResp,
    isLoading: tasksLoading,
    isError: tasksError,
    refetch: refetchTasks,
  } = useQuery({
    queryKey: ['hypervisor', 'tasks', controllerId, activeTasksNode],
    queryFn: () => hypervisorApi.getTasks(controllerId, activeTasksNode, 50),
    enabled: !!controllerId && !!activeTasksNode && activeTab === 'tasks',
    refetchInterval: 10_000,
  });
  const tasks: HypervisorTask[] = tasksResp?.data || [];

  // ── Backup Jobs ───────────────────────────────────────────────────────
  const {
    data: backupResp,
    isLoading: backupLoading,
    isError: backupError,
    refetch: refetchBackup,
  } = useQuery({
    queryKey: ['hypervisor', 'backup', controllerId],
    queryFn: () => hypervisorApi.getBackupJobs(controllerId),
    enabled: !!controllerId && activeTab === 'backup',
  });
  const backupJobs: HypervisorBackupJob[] = backupResp?.data || [];

  // ── Firewall Rules (cluster-level) ────────────────────────────────────
  const {
    data: fwResp,
    isLoading: fwLoading,
    isError: fwError,
    refetch: refetchFW,
  } = useQuery({
    queryKey: ['hypervisor', 'firewall', controllerId],
    queryFn: () => hypervisorApi.getClusterFirewallRules(controllerId),
    enabled: !!controllerId && activeTab === 'firewall',
  });
  const firewallRules: HypervisorFirewallRule[] = fwResp?.data || [];

  // ── HA Resources ──────────────────────────────────────────────────────
  const {
    data: haResResp,
    isLoading: haResLoading,
    isError: haResError,
    refetch: refetchHARes,
  } = useQuery({
    queryKey: ['hypervisor', 'ha', 'resources', controllerId],
    queryFn: () => hypervisorApi.getHAResources(controllerId),
    enabled: !!controllerId && activeTab === 'ha',
  });
  const haResources: HypervisorHAResource[] = haResResp?.data || [];

  // ── HA Groups ─────────────────────────────────────────────────────────
  const { data: haGrpResp } = useQuery({
    queryKey: ['hypervisor', 'ha', 'groups', controllerId],
    queryFn: () => hypervisorApi.getHAGroups(controllerId),
    enabled: !!controllerId && activeTab === 'ha',
  });
  const haGroups: HypervisorHAGroup[] = haGrpResp?.data || [];

  // ── Resource Pools ────────────────────────────────────────────────────
  const {
    data: poolsResp,
    isLoading: poolsLoading,
    isError: poolsError,
    refetch: refetchPools,
  } = useQuery({
    queryKey: ['hypervisor', 'pools', controllerId],
    queryFn: () => hypervisorApi.getPools(controllerId),
    enabled: !!controllerId && activeTab === 'pools',
  });
  const pools: HypervisorResourcePool[] = poolsResp?.data || [];

  // ── Fleet Dashboard (multi-cluster) ──────────────────────────────────
  const {
    data: fleetResp,
    isLoading: fleetLoading,
    isError: fleetError,
    refetch: refetchFleet,
  } = useQuery({
    queryKey: ['hypervisor', 'fleet', selectedSiteId],
    queryFn: () => hypervisorApi.getFleetDashboard(selectedSiteId || undefined),
    enabled: proxmoxControllers.length > 0 && (activeTab === 'fleet' || activeTab === 'dashboard'),
    refetchInterval: 60_000,
  });
  const fleet: FleetDashboard | undefined = fleetResp?.data;

  // ── Create VM/CT dialog state ──────────────────────────────────────────
  const [createDialog, setCreateDialog] = useState<'vm' | 'ct' | null>(null);
  const [createName, setCreateName] = useState('');
  const [createNode, setCreateNode] = useState('');
  const [createCores, setCreateCores] = useState(2);
  const [createMemory, setCreateMemory] = useState(2048);
  const [createDiskSize, setCreateDiskSize] = useState('32G');
  const [createStorage, setCreateStorage] = useState('local-lvm');
  const [createOsTemplate, setCreateOsTemplate] = useState('');
  const [createIso, setCreateIso] = useState('');
  const [createStartAfter, setCreateStartAfter] = useState(false);

  const createVMMutation = useMutation({
    mutationFn: () =>
      hypervisorApi.createVM(controllerId, {
        name: createName,
        node: createNode || nodes[0]?.node || '',
        cores: createCores,
        memory: createMemory,
        disk_size: createDiskSize,
        storage: createStorage,
        iso: createIso || undefined,
        start_after_create: createStartAfter,
      }),
    onSuccess: (resp) => {
      toast({ title: t('HypervisorPage.toast.vmCreationStarted'), description: `VMID: ${resp.data?.vmid}` });
      setCreateDialog(null);
      setCreateName('');
      queryClient.invalidateQueries({ queryKey: ['hypervisor'] });
    },
    onError: (err: any) => {
      toast({ title: t('HypervisorPage.toast.vmCreationFailed'), description: err?.response?.data?.detail || err.message, variant: 'destructive' });
    },
  });

  const createCTMutation = useMutation({
    mutationFn: () =>
      hypervisorApi.createContainer(controllerId, {
        hostname: createName,
        node: createNode || nodes[0]?.node || '',
        ostemplate: createOsTemplate,
        cores: createCores,
        memory: createMemory,
        rootfs_size: createDiskSize.replace(/G$/i, ''),
        storage: createStorage,
        start_after_create: createStartAfter,
      }),
    onSuccess: (resp) => {
      toast({ title: t('HypervisorPage.toast.containerCreationStarted'), description: `VMID: ${resp.data?.vmid}` });
      setCreateDialog(null);
      setCreateName('');
      queryClient.invalidateQueries({ queryKey: ['hypervisor'] });
    },
    onError: (err: any) => {
      toast({ title: t('HypervisorPage.toast.containerCreationFailed'), description: err?.response?.data?.detail || err.message, variant: 'destructive' });
    },
  });

  // ── Delete VM/CT mutation ──────────────────────────────────────────────
  const deleteVMMutation = useMutation({
    mutationFn: (params: { node: string; vmType: string; vmid: number }) =>
      hypervisorApi.deleteVM(controllerId, params.node, params.vmType, params.vmid),
    onSuccess: (_d, p) => {
      toast({ title: t('HypervisorPage.toast.deletionStarted'), description: `${p.vmType === 'lxc' ? 'CT' : 'VM'} ${p.vmid}` });
      queryClient.invalidateQueries({ queryKey: ['hypervisor'] });
    },
    onError: (err: any) => {
      toast({ title: t('HypervisorPage.toast.deleteFailed'), description: err?.response?.data?.detail || err.message, variant: 'destructive' });
    },
  });

  // ── HA create/delete mutations ─────────────────────────────────────────
  const createHAResourceMutation = useMutation({
    mutationFn: (params: { sid: string; group?: string }) =>
      hypervisorApi.createHAResource(controllerId, params),
    onSuccess: () => {
      toast({ title: t('HypervisorPage.toast.haResourceCreated') });
      queryClient.invalidateQueries({ queryKey: ['hypervisor', 'ha'] });
    },
    onError: (err: any) => {
      toast({ title: t('HypervisorPage.toast.haResourceCreationFailed'), description: err?.response?.data?.detail || err.message, variant: 'destructive' });
    },
  });

  const deleteHAResourceMutation = useMutation({
    mutationFn: (sid: string) => hypervisorApi.deleteHAResource(controllerId, sid),
    onSuccess: () => {
      toast({ title: t('HypervisorPage.toast.haResourceRemoved') });
      queryClient.invalidateQueries({ queryKey: ['hypervisor', 'ha'] });
    },
    onError: (err: any) => {
      toast({ title: t('HypervisorPage.toast.haResourceRemoveFailed'), description: err?.response?.data?.detail || err.message, variant: 'destructive' });
    },
  });

  // ── HA group create/delete mutations ──────────────────────────────────
  const [haResDialog, setHaResDialog] = useState(false);
  const [haResSid, setHaResSid] = useState('');
  const [haResGroup, setHaResGroup] = useState('');

  const [haGrpDialog, setHaGrpDialog] = useState(false);
  const [haGrpName, setHaGrpName] = useState('');
  const [haGrpNodes, setHaGrpNodes] = useState('');
  const [haGrpNofailback, setHaGrpNofailback] = useState(false);
  const [haGrpRestricted, setHaGrpRestricted] = useState(false);
  const [haGrpComment, setHaGrpComment] = useState('');

  const createHAGroupMutation = useMutation({
    mutationFn: () =>
      hypervisorApi.createHAGroup(controllerId, {
        group: haGrpName,
        nodes: haGrpNodes,
        nofailback: haGrpNofailback,
        restricted: haGrpRestricted,
        comment: haGrpComment || undefined,
      }),
    onSuccess: () => {
      toast({ title: t('HypervisorPage.toast.haGroupCreated') });
      setHaGrpDialog(false);
      setHaGrpName('');
      setHaGrpNodes('');
      setHaGrpComment('');
      queryClient.invalidateQueries({ queryKey: ['hypervisor', 'ha'] });
    },
    onError: (err: any) => {
      toast({ title: t('HypervisorPage.toast.haGroupCreationFailed'), description: err?.response?.data?.detail || err.message, variant: 'destructive' });
    },
  });

  const deleteHAGroupMutation = useMutation({
    mutationFn: (group: string) => hypervisorApi.deleteHAGroup(controllerId, group),
    onSuccess: () => {
      toast({ title: t('HypervisorPage.toast.haGroupDeleted') });
      queryClient.invalidateQueries({ queryKey: ['hypervisor', 'ha'] });
    },
    onError: (err: any) => {
      toast({ title: t('HypervisorPage.toast.haGroupDeleteFailed'), description: err?.response?.data?.detail || err.message, variant: 'destructive' });
    },
  });

  // ── VM Action mutation ─────────────────────────────────────────────────
  const vmActionMutation = useMutation({
    mutationFn: (params: { node: string; vmType: string; vmid: number; action: string }) =>
      hypervisorApi.vmAction(controllerId, params.node, params.vmType, params.vmid, params.action),
    onSuccess: (_data, params) => {
      toast({ title: t('HypervisorPage.toast.actionSent', { action: params.action }), description: t('HypervisorPage.toast.vmOnNode', { vmid: params.vmid, node: params.node }) });
      queryClient.invalidateQueries({ queryKey: ['hypervisor'] });
    },
    onError: (err: any) => {
      toast({ title: t('HypervisorPage.toast.actionFailed'), description: err?.response?.data?.detail || err.message, variant: 'destructive' });
    },
  });

  // ── Node power mutations ──────────────────────────────────────────────
  const nodeShutdownMutation = useMutation({
    mutationFn: (node: string) => hypervisorApi.shutdownNode(controllerId, node),
    onSuccess: (_d, node) => {
      toast({ title: t('HypervisorPage.toast.shutdownInitiated'), description: node });
      queryClient.invalidateQueries({ queryKey: ['hypervisor', 'nodes'] });
    },
    onError: (err: any) => {
      toast({ title: t('HypervisorPage.toast.shutdownFailed'), description: err?.response?.data?.detail || err.message, variant: 'destructive' });
    },
  });

  const nodeRebootMutation = useMutation({
    mutationFn: (node: string) => hypervisorApi.rebootNode(controllerId, node),
    onSuccess: (_d, node) => {

      toast({ title: t('HypervisorPage.toast.rebootInitiated'), description: node });
      queryClient.invalidateQueries({ queryKey: ['hypervisor', 'nodes'] });
    },
    onError: (err: any) => {
      toast({ title: t('HypervisorPage.toast.rebootFailed'), description: err?.response?.data?.detail || err.message, variant: 'destructive' });
    },
  });

  // ── Clone mutation ────────────────────────────────────────────────────
  const [cloneDialog, setCloneDialog] = useState<{ node: string; vmType: string; vmid: number; name: string } | null>(null);
  const [cloneNewId, setCloneNewId] = useState('');
  const [cloneName, setCloneName] = useState('');
  const [cloneFull, setCloneFull] = useState(true);

  const cloneMutation = useMutation({
    mutationFn: () => {
      if (!cloneDialog) throw new Error('No VM');
      return hypervisorApi.cloneVM(controllerId, cloneDialog.node, cloneDialog.vmType, cloneDialog.vmid, {
        newid: parseInt(cloneNewId),
        name: cloneName || undefined,
        full: cloneFull,
      });
    },
    onSuccess: () => {
      toast({ title: t('HypervisorPage.toast.cloneStarted') });
      setCloneDialog(null);
      queryClient.invalidateQueries({ queryKey: ['hypervisor'] });
    },
    onError: (err: any) => {
      toast({ title: t('HypervisorPage.toast.cloneFailed'), description: err?.response?.data?.detail || err.message, variant: 'destructive' });
    },
  });

  // ── Migrate mutation ──────────────────────────────────────────────────
  const [migrateDialog, setMigrateDialog] = useState<{ node: string; vmType: string; vmid: number } | null>(null);
  const [migrateTarget, setMigrateTarget] = useState('');
  const [migrateOnline, setMigrateOnline] = useState(true);

  const migrateMutation = useMutation({
    mutationFn: () => {
      if (!migrateDialog) throw new Error('No VM');
      return hypervisorApi.migrateVM(controllerId, migrateDialog.node, migrateDialog.vmType, migrateDialog.vmid, {
        target: migrateTarget,
        online: migrateOnline,
      });
    },
    onSuccess: () => {
      toast({ title: t('HypervisorPage.toast.migrationStarted') });
      setMigrateDialog(null);
      queryClient.invalidateQueries({ queryKey: ['hypervisor'] });
    },
    onError: (err: any) => {
      toast({ title: t('HypervisorPage.toast.migrationFailed'), description: err?.response?.data?.detail || err.message, variant: 'destructive' });
    },
  });

  // ── Resize mutation ───────────────────────────────────────────────────
  const [resizeDialog, setResizeDialog] = useState<{ node: string; vmType: string; vmid: number } | null>(null);
  const [resizeDisk, setResizeDisk] = useState('scsi0');
  const [resizeAmount, setResizeAmount] = useState('+10G');

  const resizeMutation = useMutation({
    mutationFn: () => {
      if (!resizeDialog) throw new Error('No VM');
      return hypervisorApi.resizeDisk(controllerId, resizeDialog.node, resizeDialog.vmType, resizeDialog.vmid, {
        disk: resizeDisk,
        size: resizeAmount,
      });
    },
    onSuccess: () => {
      toast({ title: t('HypervisorPage.toast.diskResized') });
      setResizeDialog(null);
      queryClient.invalidateQueries({ queryKey: ['hypervisor', 'vms'] });
      queryClient.invalidateQueries({ queryKey: ['hypervisor', 'containers'] });
    },
    onError: (err: any) => {
      toast({ title: t('HypervisorPage.toast.resizeFailed'), description: err?.response?.data?.detail || err.message, variant: 'destructive' });
    },
  });

  // ── Snapshot dialog ────────────────────────────────────────────────────
  const [snapDialog, setSnapDialog] = useState<{ open: boolean; node: string; vmType: string; vmid: number } | null>(null);
  const [snapName, setSnapName] = useState('');
  const [snapDesc, setSnapDesc] = useState('');

  const createSnapshotMutation = useMutation({
    mutationFn: () => {
      if (!snapDialog) throw new Error('No VM selected');
      return hypervisorApi.createSnapshot(
        controllerId, snapDialog.node, snapDialog.vmType, snapDialog.vmid,
        { snapname: snapName, description: snapDesc }
      );
    },
    onSuccess: () => {
      toast({ title: t('HypervisorPage.toast.snapshotCreated') });
      setSnapDialog(null);
      setSnapName('');
      setSnapDesc('');
      queryClient.invalidateQueries({ queryKey: ['hypervisor', 'snapshots'] });
    },
    onError: (err: any) => {
      toast({ title: t('HypervisorPage.toast.snapshotFailed'), description: err?.response?.data?.detail || err.message, variant: 'destructive' });
    },
  });

  // ── Snapshot list dialog ──────────────────────────────────────────────
  const [snapListDialog, setSnapListDialog] = useState<{ node: string; vmType: string; vmid: number } | null>(null);

  const { data: snapListResp, isLoading: snapListLoading } = useQuery({
    queryKey: ['hypervisor', 'snapshots', controllerId, snapListDialog?.node, snapListDialog?.vmType, snapListDialog?.vmid],
    queryFn: () =>
      hypervisorApi.getSnapshots(controllerId, snapListDialog!.node, snapListDialog!.vmType, snapListDialog!.vmid),
    enabled: !!snapListDialog,
  });
  const snapshots: HypervisorSnapshot[] = snapListResp?.data || [];

  const rollbackSnapshotMutation = useMutation({
    mutationFn: (params: { node: string; vmType: string; vmid: number; snapname: string }) =>
      hypervisorApi.rollbackSnapshot(controllerId, params.node, params.vmType, params.vmid, params.snapname),
    onSuccess: (_d, p) => {
      toast({ title: t('HypervisorPage.toast.rollbackStarted'), description: t('HypervisorPage.toast.snapshotLabel', { name: p.snapname }) });
      queryClient.invalidateQueries({ queryKey: ['hypervisor'] });
    },
    onError: (err: any) => {
      toast({ title: t('HypervisorPage.toast.rollbackFailed'), description: err?.response?.data?.detail || err.message, variant: 'destructive' });
    },
  });

  const deleteSnapshotMutation = useMutation({
    mutationFn: (params: { node: string; vmType: string; vmid: number; snapname: string }) =>
      hypervisorApi.deleteSnapshot(controllerId, params.node, params.vmType, params.vmid, params.snapname),
    onSuccess: (_d, p) => {
      toast({ title: t('HypervisorPage.toast.snapshotDeleted'), description: p.snapname });
      queryClient.invalidateQueries({ queryKey: ['hypervisor', 'snapshots'] });
    },
    onError: (err: any) => {
      toast({ title: t('HypervisorPage.toast.deleteFailed'), description: err?.response?.data?.detail || err.message, variant: 'destructive' });
    },
  });

  // ── Firewall rule create ──────────────────────────────────────────────
  const [fwCreateDialog, setFwCreateDialog] = useState<{ node: string } | null>(null);
  const [fwAction, setFwAction] = useState<string>('ACCEPT');
  const [fwType, setFwType] = useState<string>('in');
  const [fwSource, setFwSource] = useState('');
  const [fwDest, setFwDest] = useState('');
  const [fwDport, setFwDport] = useState('');
  const [fwProto, setFwProto] = useState('tcp');
  const [fwComment, setFwComment] = useState('');

  const createFwRuleMutation = useMutation({
    mutationFn: () => {
      if (!fwCreateDialog) throw new Error('No node');
      return hypervisorApi.createNodeFirewallRule(controllerId, fwCreateDialog.node, {
        action: fwAction,
        type: fwType,
        source: fwSource || undefined,
        dest: fwDest || undefined,
        dport: fwDport || undefined,
        proto: fwProto || undefined,
        comment: fwComment || undefined,
      });
    },
    onSuccess: () => {
      toast({ title: t('HypervisorPage.toast.firewallRuleCreated') });
      setFwCreateDialog(null);
      queryClient.invalidateQueries({ queryKey: ['hypervisor', 'firewall'] });
    },
    onError: (err: any) => {
      toast({ title: t('HypervisorPage.toast.createFailed'), description: err?.response?.data?.detail || err.message, variant: 'destructive' });
    },
  });

  // ── Task log dialog ───────────────────────────────────────────────────
  const [taskLogDialog, setTaskLogDialog] = useState<{ node: string; upid: string } | null>(null);

  const { data: taskLogResp, isLoading: taskLogLoading } = useQuery({
    queryKey: ['hypervisor', 'tasklog', controllerId, taskLogDialog?.node, taskLogDialog?.upid],
    queryFn: () => hypervisorApi.getTaskLog(controllerId, taskLogDialog!.node, taskLogDialog!.upid, 0, 200),
    enabled: !!taskLogDialog,
    refetchInterval: 5_000,
  });
  const taskLogEntries = taskLogResp?.data || [];

  const stopTaskMutation = useMutation({
    mutationFn: (params: { node: string; upid: string }) =>
      hypervisorApi.stopTask(controllerId, params.node, params.upid),
    onSuccess: () => {
      toast({ title: t('HypervisorPage.toast.taskStopRequested') });
      queryClient.invalidateQueries({ queryKey: ['hypervisor', 'tasks'] });
    },
    onError: (err: any) => {
      toast({ title: t('HypervisorPage.toast.stopFailed'), description: err?.response?.data?.detail || err.message, variant: 'destructive' });
    },
  });

  // ── Backup run mutation ───────────────────────────────────────────────
  const [backupDialog, setBackupDialog] = useState<{ node: string; vmType: string; vmid: number } | null>(null);
  const [backupStorage, setBackupStorage] = useState('local');
  const [backupMode, setBackupMode] = useState('snapshot');
  const [backupCompress, setBackupCompress] = useState('zstd');

  const runBackupMutation = useMutation({
    mutationFn: () => {
      if (!backupDialog) throw new Error('No VM');
      return hypervisorApi.runBackup(controllerId, backupDialog.node, backupDialog.vmType, backupDialog.vmid, {
        storage: backupStorage,
        mode: backupMode,
        compress: backupCompress,
      });
    },
    onSuccess: () => {
      toast({ title: t('HypervisorPage.toast.backupStarted') });
      setBackupDialog(null);
      queryClient.invalidateQueries({ queryKey: ['hypervisor', 'tasks'] });
    },
    onError: (err: any) => {
      toast({ title: t('HypervisorPage.toast.backupFailed'), description: err?.response?.data?.detail || err.message, variant: 'destructive' });
    },
  });

  // ── Bulk selection state ───────────────────────────────────────────────
  const [selectedVMs, setSelectedVMs] = useState<Set<string>>(new Set());

  // Clear selection when switching controllers
  useEffect(() => {
    setSelectedVMs(new Set());
  }, [controllerId]);

  const toggleVMSelect = (key: string) => {
    setSelectedVMs((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key); else next.add(key);
      return next;
    });
  };
  const clearSelection = () => setSelectedVMs(new Set());

  const selectedTargets: BulkTarget[] = Array.from(selectedVMs).map((k) => {
    const [node, vm_type, vmidStr] = k.split(':');
    return { node, vm_type, vmid: parseInt(vmidStr) };
  });

  // ── Edit config dialog state ─────────────────────────────────────────
  const [editConfigVM, setEditConfigVM] = useState<HypervisorVM | null>(null);

  // ── Kiosk mode state ──────────────────────────────────────────────────
  const [kioskMode, setKioskMode] = useState(false);

  // ── Backup job dialog state ──────────────────────────────────────────
  const [backupJobDialog, setBackupJobDialog] = useState(false);
  const [editBackupJob, setEditBackupJob] = useState<HypervisorBackupJob | null>(null);

  const deleteBackupJobMutation = useMutation({
    mutationFn: (jobId: string) => hypervisorApi.deleteBackupJob(controllerId, jobId),
    onSuccess: () => {
      toast({ title: t('HypervisorPage.toast.backupJobDeleted') });
      queryClient.invalidateQueries({ queryKey: ['hypervisor', 'backup'] });
    },
    onError: (err: any) => {
      toast({ title: t('HypervisorPage.toast.deleteFailed'), description: err?.response?.data?.detail || err.message, variant: 'destructive' });
    },
  });

  // ── Firewall delete mutation ─────────────────────────────────────────
  const deleteFwRuleMutation = useMutation({
    mutationFn: (params: { node: string; pos: number }) =>
      hypervisorApi.deleteNodeFirewallRule(controllerId, params.node, params.pos),
    onSuccess: () => {
      toast({ title: t('HypervisorPage.toast.firewallRuleDeleted') });
      queryClient.invalidateQueries({ queryKey: ['hypervisor', 'firewall'] });
    },
    onError: (err: any) => {
      toast({ title: t('HypervisorPage.toast.deleteFailed'), description: err?.response?.data?.detail || err.message, variant: 'destructive' });
    },
  });

  // ── Upload dialog state ──────────────────────────────────────────────
  const [uploadDialog, setUploadDialog] = useState<{ node: string; storage: string } | null>(null);

  // ── Restore from Backup dialog ──────────────────────────────────────
  const [restoreDialog, setRestoreDialog] = useState<{ archive: string; node: string; vmType: string; storage: string } | null>(null);
  const [restoreVmid, setRestoreVmid] = useState('');
  const [restoreTargetStorage, setRestoreTargetStorage] = useState('');
  const [restoreTargetNode, setRestoreTargetNode] = useState('');
  const [restoreStartAfter, setRestoreStartAfter] = useState(false);
  const [restoreUniqueMac, setRestoreUniqueMac] = useState(true);

  const restoreBackupMutation = useMutation({
    mutationFn: () => {
      if (!restoreDialog || !restoreVmid) throw new Error('Missing required fields');
      return hypervisorApi.restoreBackup(controllerId, {
        archive: restoreDialog.archive,
        vmid: parseInt(restoreVmid),
        node: restoreTargetNode || restoreDialog.node,
        vm_type: restoreDialog.vmType || 'qemu',
        storage: restoreTargetStorage || undefined,
        start_after_restore: restoreStartAfter,
        unique_mac: restoreUniqueMac,
      });
    },
    onSuccess: () => {
      toast({ title: t('HypervisorPage.toast.restoreStarted') });
      setRestoreDialog(null);
      setRestoreVmid('');
      queryClient.invalidateQueries({ queryKey: ['hypervisor', 'tasks'] });
    },
    onError: (err: any) => {
      toast({ title: t('HypervisorPage.toast.restoreFailed'), description: err?.response?.data?.detail || err.message, variant: 'destructive' });
    },
  });

  // ── Guest detail drawer state ───────────────────────────────────────
  const [detailVM, setDetailVM] = useState<HypervisorVM | null>(null);

  // ── Fleet Task Statistics ───────────────────────────────────────────
  const { data: taskStatsResp } = useQuery({
    queryKey: ['hypervisor', 'task-stats', selectedSiteId],
    queryFn: () => hypervisorApi.getFleetTaskStatistics(selectedSiteId || undefined),
    enabled: proxmoxControllers.length > 0 && (activeTab === 'fleet' || activeTab === 'dashboard'),
    refetchInterval: 30_000,
  });
  const taskStats: any = taskStatsResp?.data || {};

  // ── Node detail state (must be before any early return · Rules of Hooks) ──
  const [expandedNode, setExpandedNode] = useState<string | null>(null);
  const [nodeDetailTab, setNodeDetailTab] = useState<'overview' | 'services' | 'disks' | 'network' | 'vms' | 'containers' | 'sensors'>('overview');

  // Lazy-loaded node detail queries (only fetch when expanded AND tab is active)
  const { data: nodeServicesResp, isLoading: nodeServicesLoading } = useQuery({
    queryKey: ['hypervisor', 'node-services', controllerId, expandedNode],
    queryFn: () => hypervisorApi.getNodeServices(controllerId, expandedNode!),
    enabled: !!controllerId && !!expandedNode && nodeDetailTab === 'services',
  });
  const nodeServices = nodeServicesResp?.data || [];

  const { data: nodeDisksResp, isLoading: nodeDisksLoading } = useQuery({
    queryKey: ['hypervisor', 'node-disks', controllerId, expandedNode],
    queryFn: () => hypervisorApi.getNodeDisks(controllerId, expandedNode!),
    enabled: !!controllerId && !!expandedNode && nodeDetailTab === 'disks',
  });
  const nodeDisks = nodeDisksResp?.data || [];

  const { data: nodeNetworkResp, isLoading: nodeNetworkLoading } = useQuery({
    queryKey: ['hypervisor', 'node-network', controllerId, expandedNode],
    queryFn: () => hypervisorApi.getNodeNetwork(controllerId, expandedNode!),
    enabled: !!controllerId && !!expandedNode && nodeDetailTab === 'network',
  });
  const nodeNetworkIfaces = nodeNetworkResp?.data || [];

  const nodeGuestTabActive = nodeDetailTab === 'vms' || nodeDetailTab === 'containers' || nodeDetailTab === 'overview';
  const { data: nodeVMsResp, isLoading: nodeVMsLoading } = useQuery({
    queryKey: ['hypervisor', 'node-vms', controllerId, expandedNode],
    queryFn: () => hypervisorApi.getNodeVMs(controllerId, expandedNode!),
    enabled: !!controllerId && !!expandedNode && nodeGuestTabActive,
  });
  const nodeVMs = nodeVMsResp?.data || [];

  const { data: nodeCTsResp, isLoading: nodeCTsLoading } = useQuery({
    queryKey: ['hypervisor', 'node-containers', controllerId, expandedNode],
    queryFn: () => hypervisorApi.getNodeContainers(controllerId, expandedNode!),
    enabled: !!controllerId && !!expandedNode && nodeGuestTabActive,
  });
  const nodeContainers = nodeCTsResp?.data || [];

  const { data: nodeSensorsResp, isLoading: nodeSensorsLoading } = useQuery({
    queryKey: ['hypervisor', 'node-sensors', controllerId, expandedNode],
    queryFn: () => hypervisorApi.getNodeSensors(controllerId, expandedNode!),
    enabled: !!controllerId && !!expandedNode && (nodeDetailTab === 'sensors' || nodeDetailTab === 'overview'),
    refetchInterval: 30_000,
  });
  const nodeSensorsRaw = nodeSensorsResp?.data as any;
  const nodeSensors = useMemo(() => {
    if (!nodeSensorsRaw) return [];
    // API returns {cpu_temp, cpu_temps[], pveversion, loadavg[], cpuinfo{}, kversion}
    const items: any[] = [];
    if (nodeSensorsRaw.cpu_temp != null) {
      items.push({ name: 'CPU Temperature', value: nodeSensorsRaw.cpu_temp, unit: '°C' });
    }
    if (Array.isArray(nodeSensorsRaw.cpu_temps)) {
      for (const t of nodeSensorsRaw.cpu_temps) {
        if (t && t.name) items.push(t);
      }
    }
    if (Array.isArray(nodeSensorsRaw.loadavg) && nodeSensorsRaw.loadavg.length >= 3) {
      items.push({ name: 'Load Average (1m)', value: nodeSensorsRaw.loadavg[0], unit: '' });
      items.push({ name: 'Load Average (5m)', value: nodeSensorsRaw.loadavg[1], unit: '' });
      items.push({ name: 'Load Average (15m)', value: nodeSensorsRaw.loadavg[2], unit: '' });
    }
    if (nodeSensorsRaw.cpuinfo) {
      const ci = nodeSensorsRaw.cpuinfo;
      if (ci.cpus) items.push({ name: 'CPU Cores', value: ci.cpus, unit: '' });
      if (ci.sockets) items.push({ name: 'CPU Sockets', value: ci.sockets, unit: '' });
      if (ci.mhz) items.push({ name: 'CPU Frequency', value: ci.mhz, unit: 'MHz' });
      if (ci.model) items.push({ name: 'CPU Model', value: ci.model, unit: '' });
    }
    if (nodeSensorsRaw.pveversion) {
      items.push({ name: 'PVE Version', value: nodeSensorsRaw.pveversion, unit: '' });
    }
    if (nodeSensorsRaw.kversion) {
      items.push({ name: 'Kernel', value: nodeSensorsRaw.kversion, unit: '' });
    }
    return items;
  }, [nodeSensorsRaw]);

  // ── VM action callbacks (for extracted VMTable) ────────────────────────
  const handleVMAction = useCallback((params: { node: string; vmType: string; vmid: number; action: string }) => {
    vmActionMutation.mutate(params);
  }, [vmActionMutation]);

  const handleDeleteVM = useCallback((params: { node: string; vmType: string; vmid: number }) => {
    deleteVMMutation.mutate(params);
  }, [deleteVMMutation]);

  const handleSnapshot = useCallback((vm: HypervisorVM) => {
    setSnapDialog({ open: true, node: vm.node, vmType: vm.vm_type, vmid: vm.vmid });
    setSnapName(`snap-${Date.now()}`);
    setSnapDesc('');
  }, []);

  const handleSnapList = useCallback((vm: HypervisorVM) => {
    setSnapListDialog({ node: vm.node, vmType: vm.vm_type, vmid: vm.vmid });
  }, []);

  const handleClone = useCallback((vm: HypervisorVM) => {
    setCloneDialog({ node: vm.node, vmType: vm.vm_type, vmid: vm.vmid, name: vm.name });
    setCloneNewId('');
    setCloneName(`${vm.name}-clone`);
    setCloneFull(true);
  }, []);

  const handleMigrate = useCallback((vm: HypervisorVM) => {
    setMigrateDialog({ node: vm.node, vmType: vm.vm_type, vmid: vm.vmid });
    setMigrateTarget('');
    setMigrateOnline(vm.status === 'running');
  }, []);

  const handleResize = useCallback((vm: HypervisorVM) => {
    setResizeDialog({ node: vm.node, vmType: vm.vm_type, vmid: vm.vmid });
    setResizeDisk('scsi0');
    setResizeAmount('+10G');
  }, []);

  const handleBackup = useCallback((vm: HypervisorVM) => {
    setBackupDialog({ node: vm.node, vmType: vm.vm_type, vmid: vm.vmid });
    setBackupStorage('local');
    setBackupMode('snapshot');
    setBackupCompress('zstd');
  }, []);

  const handleEditConfig = useCallback((vm: HypervisorVM) => {
    setEditConfigVM(vm);
  }, []);

  const handleConsole = useCallback((vm: HypervisorVM) => {
    hypervisorApi.getConsoleProxy(controllerId, vm.node, vm.vm_type, vm.vmid, 'vnc')
      .then((resp) => {
        const proxy = resp.data;
        if (proxy?.ticket) {
          const ctrl = proxmoxControllers.find((c: any) => c.id === controllerId);
          const host = ctrl?.host || window.location.hostname;
          const url = `https://${host}:${proxy.port}/vnc_auto.html?token=${encodeURIComponent(proxy.ticket)}`;
          window.open(url, '_blank', 'noopener,noreferrer');
          toast({ title: t('HypervisorPage.toast.consoleOpened') });
        }
      })
      .catch(() => toast({ title: t('HypervisorPage.toast.consoleFailed'), variant: 'destructive' }));
  }, [controllerId, proxmoxControllers, toast, t]);

  const handleStopTask = useCallback((params: { node: string; upid: string }) => {
    stopTaskMutation.mutate(params);
  }, [stopTaskMutation]);

  // ── Skeleton on first load · never show a blank page ──────────────────
  if (controllersLoading && proxmoxControllers.length === 0) {
    return <PageSkeleton variant="dashboard" statsCount={4} />;
  }

  // ── No controller state ────────────────────────────────────────────────
  if (!controllersLoading && proxmoxControllers.length === 0) {
    return (
      <div className="space-y-6">
        <PageHeader icon={Server} title={t('HypervisorPage.header.title')} subtitle={t('HypervisorPage.header.subtitle')} />
        <EmptyState
          icon={Server}
          title={t('HypervisorPage.noController.title')}
          description={t('HypervisorPage.noController.description')}
          action={{ label: t('HypervisorPage.actions.addHypervisor'), onClick: () => setShowAddDialog(true), icon: Plus }}
        />
        <AddHypervisorDialog open={showAddDialog} onOpenChange={setShowAddDialog} />
      </div>
    );
  }

  // ── Controller selector ────────────────────────────────────────────────
  const controllerSelector = proxmoxControllers.length > 1 ? (
    <Select value={controllerId} onValueChange={setSelectedCtrlId}>
      <SelectTrigger className="w-full sm:w-[240px]">
        <SelectValue placeholder={t('HypervisorPage.selectCluster')} />
      </SelectTrigger>
      <SelectContent>
        {proxmoxControllers.map((c: any) => (
          <SelectItem key={c.id} value={c.id}>
            {c.name || c.host}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  ) : null;

  // Extracted tab components (FleetTab, DashboardTab, NodesTab, VMTable,
  // StorageTab, TasksTab, BackupTab, FirewallTab, HATab, PoolsTab) are
  // defined outside HypervisorPage above.

  // ════════════════════════════════════════════════════════════════════════
  // RENDER
  // ════════════════════════════════════════════════════════════════════════

  return (
    <div className="space-y-6">
      {kioskMode && (
        <KioskMode
          controllerId={controllerId}
          nodes={nodes}
          onExit={() => setKioskMode(false)}
        />
      )}
      <PageHeader
        icon={Server}
        title={t('HypervisorPage.header.title')}
        subtitle={t('HypervisorPage.header.subtitle')}
        actions={
          <div className="flex items-center gap-2 flex-wrap">
            {controllerSelector}
            {controllerId && (
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button size="sm">
                    <Plus className="h-4 w-4 mr-1" />
                    {t('HypervisorPage.actions.create')}
                    <ChevronDown className="h-3 w-3 ml-1" />
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end">
                  <DropdownMenuItem onClick={() => { setCreateDialog('vm'); setCreateNode(nodes[0]?.node || ''); }}>
                    <Monitor className="mr-2 h-3.5 w-3.5" /> {t('HypervisorPage.actions.newVm')}
                  </DropdownMenuItem>
                  <DropdownMenuItem onClick={() => { setCreateDialog('ct'); setCreateNode(nodes[0]?.node || ''); }}>
                    <Box className="mr-2 h-3.5 w-3.5" /> {t('HypervisorPage.actions.newContainer')}
                  </DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>
            )}
            {controllerId && (
              <Button
                variant="outline"
                size="sm"
                onClick={() => setKioskMode(true)}
                title={t('HypervisorPage.actions.kioskTooltip')}
              >
                <Maximize2 className="h-4 w-4 mr-1" />
                {t('HypervisorPage.actions.kiosk')}
              </Button>
            )}
            <Button
              variant="outline"
              size="sm"
              onClick={() => setShowAddDialog(true)}
            >
              <Server className="h-4 w-4 mr-1" />
              {t('HypervisorPage.actions.addHypervisor')}
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => {
                refetchDash();
                refetchNodes();
                refetchVMs();
                refetchCTs();
                refetchStorage();
                refetchTasks();
                refetchBackup();
                refetchFW();
              }}
            >
              <RefreshCw className="h-4 w-4 mr-1" />
              {t('HypervisorPage.actions.refresh')}
            </Button>
          </div>
        }
      />

      <AddHypervisorDialog open={showAddDialog} onOpenChange={setShowAddDialog} />

      {controllersLoading ? (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {Array.from({ length: 8 }).map((_, i) => (
            <Skeleton key={i} className="h-24" />
          ))}
        </div>
      ) : (
        // Single Suspense boundary at the PageTabs level: each lazy
        // tab triggers its own bundle fetch when the operator switches
        // to it, but only one fallback Skeleton renders at a time
        // since only one tab is mounted.
        <Suspense fallback={<PageSkeleton />}>
        <PageTabs
          basePath="/hypervisor"
          tabs={[
            ...(proxmoxControllers.length > 1 ? [{
              value: 'fleet',
              label: t('HypervisorPage.tabs.fleet'),
              content: <FleetTab fleetLoading={fleetLoading} fleetError={fleetError} fleet={fleet} refetchFleet={refetchFleet} taskStats={taskStats} />,
            }] : []),
            {
              value: 'dashboard',
              label: t('HypervisorPage.tabs.dashboard'),
              content: <DashboardTab dashLoading={dashLoading} dashError={dashError} dash={dash} refetchDash={refetchDash} />,
            },
            {
              value: 'nodes',
              label: t('HypervisorPage.tabs.nodes'),
              count: nodes.length,
              content: (
                <NodesTab
                  nodesLoading={nodesLoading} nodesError={nodesError} nodes={nodes} refetchNodes={refetchNodes}
                  expandedNode={expandedNode} setExpandedNode={setExpandedNode}
                  nodeDetailTab={nodeDetailTab} setNodeDetailTab={setNodeDetailTab}
                  nodeServicesLoading={nodeServicesLoading} nodeServices={nodeServices}
                  nodeDisksLoading={nodeDisksLoading} nodeDisks={nodeDisks}
                  nodeNetworkLoading={nodeNetworkLoading} nodeNetworkIfaces={nodeNetworkIfaces}
                  nodeVMsLoading={nodeVMsLoading} nodeCTsLoading={nodeCTsLoading} nodeVMs={nodeVMs} nodeContainers={nodeContainers}
                  nodeSensorsLoading={nodeSensorsLoading} nodeSensors={nodeSensors}
                  nodeRebootMutation={nodeRebootMutation} nodeShutdownMutation={nodeShutdownMutation}
                  allGuests={[...vms, ...containers]}
                  controllerId={controllerId}
                  requestConfirm={requestConfirm}
                />
              ),
            },
            {
              value: 'vms',
              label: t('HypervisorPage.tabs.vms'),
              count: vms.length,
              content: (
                <VMTable
                  items={vms}
                  loading={vmsLoading}
                  error={vmsError}
                  refetch={refetchVMs}
                  label={t('HypervisorPage.common.virtualMachines')}
                  selectedVMs={selectedVMs}
                  setSelectedVMs={setSelectedVMs}
                  toggleVMSelect={toggleVMSelect}
                  onVMAction={handleVMAction}
                  onDeleteVM={handleDeleteVM}
                  onSnapshot={handleSnapshot}
                  onSnapList={handleSnapList}
                  onClone={handleClone}
                  onMigrate={handleMigrate}
                  onResize={handleResize}
                  onBackup={handleBackup}
                  onEditConfig={handleEditConfig}
                  onConsole={handleConsole}
                  onRowClick={setDetailVM}
                  requestConfirm={requestConfirm}
                />
              ),
            },
            {
              value: 'containers',
              label: t('HypervisorPage.tabs.containers'),
              count: containers.length,
              content: (
                <VMTable
                  items={containers}
                  loading={ctsLoading}
                  error={ctsError}
                  refetch={refetchCTs}
                  label={t('HypervisorPage.common.containers')}
                  selectedVMs={selectedVMs}
                  setSelectedVMs={setSelectedVMs}
                  toggleVMSelect={toggleVMSelect}
                  onVMAction={handleVMAction}
                  onDeleteVM={handleDeleteVM}
                  onSnapshot={handleSnapshot}
                  onSnapList={handleSnapList}
                  onClone={handleClone}
                  onMigrate={handleMigrate}
                  onResize={handleResize}
                  onBackup={handleBackup}
                  onEditConfig={handleEditConfig}
                  onConsole={handleConsole}
                  onRowClick={setDetailVM}
                  requestConfirm={requestConfirm}
                />
              ),
            },
            {
              value: 'storage',
              label: t('HypervisorPage.tabs.storage'),
              count: storagePools.length,
              content: (
                <StorageTab
                  nodes={nodes} activeStorageNode={activeStorageNode} setStorageNode={setStorageNode}
                  storageLoading={storageLoading} storageError={storageError} storagePools={storagePools}
                  refetchStorage={refetchStorage} setUploadDialog={setUploadDialog}
                  controllerId={controllerId} setRestoreDialog={setRestoreDialog}
                />
              ),
            },
            {
              value: 'tasks',
              label: t('HypervisorPage.tabs.tasks'),
              count: tasks.filter((task) => task.is_running).length || undefined,
              content: (
                <TasksTab
                  nodes={nodes} activeTasksNode={activeTasksNode} setTasksNode={setTasksNode}
                  tasksLoading={tasksLoading} tasksError={tasksError} tasks={tasks}
                  refetchTasks={refetchTasks} setTaskLogDialog={setTaskLogDialog}
                  onStopTask={handleStopTask}
                  requestConfirm={requestConfirm}
                />
              ),
            },
            {
              value: 'backup',
              label: t('HypervisorPage.tabs.backup'),
              count: backupJobs.length,
              content: (
                <BackupTab
                  backupLoading={backupLoading} backupError={backupError} backupJobs={backupJobs}
                  refetchBackup={refetchBackup} setEditBackupJob={setEditBackupJob}
                  setBackupJobDialog={setBackupJobDialog} deleteBackupJobMutation={deleteBackupJobMutation}
                  requestConfirm={requestConfirm}
                />
              ),
            },
            {
              value: 'firewall',
              label: t('HypervisorPage.tabs.firewall'),
              count: firewallRules.length,
              content: (
                <FirewallTab
                  fwLoading={fwLoading} fwError={fwError} firewallRules={firewallRules} refetchFW={refetchFW}
                  nodes={nodes} setFwCreateDialog={setFwCreateDialog}
                  setFwAction={setFwAction} setFwType={setFwType} setFwSource={setFwSource}
                  setFwDest={setFwDest} setFwDport={setFwDport} setFwProto={setFwProto} setFwComment={setFwComment}
                  deleteFwRuleMutation={deleteFwRuleMutation}
                  requestConfirm={requestConfirm}
                />
              ),
            },
            {
              value: 'ha',
              label: t('HypervisorPage.tabs.ha'),
              count: haResources.length || undefined,
              content: (
                <HATab
                  haResLoading={haResLoading} haResError={haResError} haResources={haResources} refetchHARes={refetchHARes}
                  haGroups={haGroups}
                  setHaResDialog={setHaResDialog} setHaResSid={setHaResSid} setHaResGroup={setHaResGroup}
                  setHaGrpDialog={setHaGrpDialog} setHaGrpName={setHaGrpName} setHaGrpNodes={setHaGrpNodes}
                  setHaGrpComment={setHaGrpComment} setHaGrpNofailback={setHaGrpNofailback} setHaGrpRestricted={setHaGrpRestricted}
                  deleteHAResourceMutation={deleteHAResourceMutation} deleteHAGroupMutation={deleteHAGroupMutation}
                  requestConfirm={requestConfirm}
                />
              ),
            },
            {
              value: 'pools',
              label: t('HypervisorPage.tabs.pools'),
              count: pools.length || undefined,
              content: <PoolsTab poolsLoading={poolsLoading} poolsError={poolsError} pools={pools} refetchPools={refetchPools} />,
            },
            {
              value: 'templates',
              label: t('HypervisorPage.tabs.templates'),
              content: activeTab === 'templates' ? (
                <TemplatesTab
                  controllerId={controllerId}
                  nodes={nodes}
                  queryClient={queryClient}
                />
              ) : null,
            },
            {
              value: 'monitoring',
              label: t('HypervisorPage.tabs.monitoring'),
              content: activeTab === 'monitoring' ? (
                <MonitoringTab
                  controllerId={controllerId}
                  nodes={nodes}
                  queryClient={queryClient}
                />
              ) : null,
            },
            {
              value: 'updates',
              label: t('HypervisorPage.tabs.updates'),
              content: activeTab === 'updates' ? (
                <UpdatesTab
                  controllerId={controllerId}
                  nodes={nodes}
                />
              ) : null,
            },
            {
              value: 'certificates',
              label: t('HypervisorPage.tabs.certificates'),
              content: activeTab === 'certificates' ? (
                <CertificatesTab
                  controllerId={controllerId}
                  nodes={nodes}
                />
              ) : null,
            },
            {
              value: 'subscriptions',
              label: t('HypervisorPage.tabs.subscriptions'),
              content: activeTab === 'subscriptions' ? (
                <SubscriptionsTab
                  controllerId={controllerId}
                  nodes={nodes}
                />
              ) : null,
            },
            {
              value: 'sdn',
              label: t('HypervisorPage.tabs.sdn'),
              content: activeTab === 'sdn' ? (
                <SdnTab
                  controllerId={controllerId}
                />
              ) : null,
            },
            {
              value: 'replication',
              label: t('HypervisorPage.tabs.replication'),
              content: activeTab === 'replication' ? (
                <ReplicationTab
                  controllerId={controllerId}
                />
              ) : null,
            },
            {
              value: 'cluster-log',
              label: t('HypervisorPage.tabs.clusterLog'),
              content: activeTab === 'cluster-log' ? (
                <ClusterLogTab
                  controllerId={controllerId}
                />
              ) : null,
            },
            {
              value: 'ceph',
              label: t('HypervisorPage.tabs.ceph'),
              content: activeTab === 'ceph' ? (
                <CephTab
                  controllerId={controllerId}
                  nodes={nodes}
                />
              ) : null,
            },
            {
              value: 'backup-age',
              label: t('HypervisorPage.tabs.backupAge'),
              content: activeTab === 'backup-age' ? (
                <BackupAgeTab controllerId={controllerId} nodes={nodes} />
              ) : null,
            },
            {
              value: 'pbs',
              label: t('HypervisorPage.tabs.pbs'),
              content: activeTab === 'pbs' ? (
                <PBSTab controllerId={controllerId} nodes={nodes} />
              ) : null,
            },
          ]}
        />
        </Suspense>
      )}

      {/* ── Snapshot creation dialog ──────────────────────────────────────── */}
      <Dialog open={!!snapDialog?.open} onOpenChange={(open) => { if (!open) setSnapDialog(null); }}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>{t('HypervisorPage.snapshotDialog.title')}</DialogTitle>
            <DialogDescription>
              {t('HypervisorPage.snapshotDialog.description', { vmid: snapDialog?.vmid, node: snapDialog?.node })}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div>
              <Label htmlFor="snap-name">{t('HypervisorPage.snapshotDialog.nameLabel')}</Label>
              <Input
                id="snap-name"
                value={snapName}
                onChange={(e) => setSnapName(e.target.value.replace(/[^a-zA-Z0-9_-]/g, ''))}
                placeholder="my-snapshot"
                maxLength={40}
              />
            </div>
            <div>
              <Label htmlFor="snap-desc">{t('HypervisorPage.snapshotDialog.descLabel')}</Label>
              <Input
                id="snap-desc"
                value={snapDesc}
                onChange={(e) => setSnapDesc(e.target.value)}
                placeholder={t('HypervisorPage.snapshotDialog.descPlaceholder')}
                maxLength={255}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setSnapDialog(null)}>{t('HypervisorPage.actions.cancel')}</Button>
            <Button
              onClick={() => createSnapshotMutation.mutate()}
              disabled={!snapName || createSnapshotMutation.isPending}
            >
              {createSnapshotMutation.isPending ? t('HypervisorPage.actions.creating') : t('HypervisorPage.snapshotDialog.title')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* ── Snapshot list dialog ──────────────────────────────────────────── */}
      <Dialog open={!!snapListDialog} onOpenChange={(open) => { if (!open) setSnapListDialog(null); }}>
        <DialogContent className="sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>{t('HypervisorPage.snapshotListDialog.title', { vmid: snapListDialog?.vmid })}</DialogTitle>
            <DialogDescription>
              {t('HypervisorPage.snapshotListDialog.description', { vmid: snapListDialog?.vmid, node: snapListDialog?.node })}
            </DialogDescription>
          </DialogHeader>
          {snapListLoading ? <Skeleton className="h-32" /> :
           snapshots.length === 0 ? <p className="text-sm text-muted-foreground py-4">{t('HypervisorPage.snapshotListDialog.empty')}</p> : (
            <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t('HypervisorPage.tableHeaders.name')}</TableHead>
                  <TableHead>{t('HypervisorPage.tableHeaders.description')}</TableHead>
                  <TableHead>{t('HypervisorPage.snapshotListDialog.created')}</TableHead>
                  <TableHead>RAM</TableHead>
                  <TableHead className="w-[100px]">{t('HypervisorPage.tableHeaders.actions')}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {snapshots.filter((s) => s.name !== 'current').map((snap) => (
                  <TableRow key={snap.name}>
                    <TableCell className="font-mono text-xs">{snap.name}</TableCell>
                    <TableCell className="text-xs text-muted-foreground max-w-[150px] truncate">
                      {snap.description || '-'}
                    </TableCell>
                    <TableCell className="text-xs">{formatTimestamp(snap.created_at)}</TableCell>
                    <TableCell className="text-xs">{snap.vmstate ? t('HypervisorPage.common.yes') : t('HypervisorPage.common.no')}</TableCell>
                    <TableCell>
                      <div className="flex gap-1">
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-7 px-2"
                          title={t('HypervisorPage.vmActions.rollback')}
                          onClick={() => {
                            if (!snapListDialog) return;
                            const sd = snapListDialog;
                            requestConfirm({
                              title: t('HypervisorPage.snapshotListDialog.rollbackConfirm.title', { name: snap.name }),
                              description: t('HypervisorPage.snapshotListDialog.rollbackConfirm.description', { kind: sd.vmType === 'lxc' ? 'CT' : 'VM', vmid: sd.vmid, node: sd.node, name: snap.name }),
                              confirmationText: snap.name,
                              confirmLabel: t('HypervisorPage.vmActions.rollback'),
                              onConfirm: () => rollbackSnapshotMutation.mutate({
                                node: sd.node, vmType: sd.vmType,
                                vmid: sd.vmid, snapname: snap.name,
                              }),
                            });
                          }}
                        >
                          <Undo2 className="h-3.5 w-3.5 text-info" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-7 px-2"
                          title={t('HypervisorPage.actions.delete')}
                          onClick={() => {
                            if (!snapListDialog) return;
                            const sd = snapListDialog;
                            requestConfirm({
                              title: t('HypervisorPage.snapshotListDialog.deleteConfirm.title', { name: snap.name }),
                              description: t('HypervisorPage.snapshotListDialog.deleteConfirm.description', { name: snap.name, kind: sd.vmType === 'lxc' ? 'CT' : 'VM', vmid: sd.vmid, node: sd.node }),
                              confirmationText: snap.name,
                              confirmLabel: t('HypervisorPage.snapshotListDialog.deleteConfirm.confirmLabel'),
                              onConfirm: () => deleteSnapshotMutation.mutate({
                                node: sd.node, vmType: sd.vmType,
                                vmid: sd.vmid, snapname: snap.name,
                              }),
                            });
                          }}
                        >
                          <Trash2 className="h-3.5 w-3.5 text-destructive" />
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
            </div>
          )}
        </DialogContent>
      </Dialog>

      {/* ── Clone dialog ─────────────────────────────────────────────────── */}
      <Dialog open={!!cloneDialog} onOpenChange={(open) => { if (!open) setCloneDialog(null); }}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>{t('HypervisorPage.cloneDialog.title', { vmid: cloneDialog?.vmid })}</DialogTitle>
            <DialogDescription>
              {t('HypervisorPage.cloneDialog.description', { name: cloneDialog?.name, node: cloneDialog?.node })}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div>
              <Label>{t('HypervisorPage.cloneDialog.newVmid')}</Label>
              <Input
                type="number"
                value={cloneNewId}
                onChange={(e) => setCloneNewId(e.target.value)}
                placeholder={t('HypervisorPage.cloneDialog.vmidPlaceholder')}
                min={100}
              />
            </div>
            <div>
              <Label>{t('HypervisorPage.tableHeaders.name')}</Label>
              <Input value={cloneName} onChange={(e) => setCloneName(e.target.value)} />
            </div>
            <div className="flex items-center gap-2">
              <Checkbox
                id="clone-full"
                checked={cloneFull}
                onCheckedChange={(v) => setCloneFull(!!v)}
              />
              <Label htmlFor="clone-full">{t('HypervisorPage.cloneDialog.fullClone')}</Label>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setCloneDialog(null)}>{t('HypervisorPage.actions.cancel')}</Button>
            <Button
              onClick={() => cloneMutation.mutate()}
              disabled={!cloneNewId || isNaN(parseInt(cloneNewId)) || parseInt(cloneNewId) < 100 || cloneMutation.isPending}
            >
              {cloneMutation.isPending ? t('HypervisorPage.cloneDialog.cloning') : t('HypervisorPage.vmActions.clone')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* ── Migrate dialog ───────────────────────────────────────────────── */}
      <Dialog open={!!migrateDialog} onOpenChange={(open) => { if (!open) setMigrateDialog(null); }}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>{t('HypervisorPage.migrateDialog.title', { vmid: migrateDialog?.vmid })}</DialogTitle>
            <DialogDescription>
              {t('HypervisorPage.migrateDialog.description', { node: migrateDialog?.node })}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div>
              <Label>{t('HypervisorPage.migrateDialog.targetNode')}</Label>
              <Select value={migrateTarget} onValueChange={setMigrateTarget}>
                <SelectTrigger>
                  <SelectValue placeholder={t('HypervisorPage.migrateDialog.selectTargetNode')} />
                </SelectTrigger>
                <SelectContent>
                  {nodes
                    .filter((n) => n.node !== migrateDialog?.node && n.status === 'online')
                    .map((n) => (
                      <SelectItem key={n.node} value={n.node}>{n.node}</SelectItem>
                    ))}
                </SelectContent>
              </Select>
            </div>
            <div className="flex items-center gap-2">
              <Checkbox
                id="migrate-online"
                checked={migrateOnline}
                onCheckedChange={(v) => setMigrateOnline(!!v)}
              />
              <Label htmlFor="migrate-online">{t('HypervisorPage.migrateDialog.onlineMigration')}</Label>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setMigrateDialog(null)}>{t('HypervisorPage.actions.cancel')}</Button>
            <Button
              onClick={() => migrateMutation.mutate()}
              disabled={!migrateTarget || migrateMutation.isPending}
            >
              {migrateMutation.isPending ? t('HypervisorPage.migrateDialog.migrating') : t('HypervisorPage.vmActions.migrate')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* ── Resize dialog ────────────────────────────────────────────────── */}
      <Dialog open={!!resizeDialog} onOpenChange={(open) => { if (!open) setResizeDialog(null); }}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>{t('HypervisorPage.resizeDialog.title', { vmid: resizeDialog?.vmid })}</DialogTitle>
            <DialogDescription>
              {t('HypervisorPage.resizeDialog.description', { node: resizeDialog?.node })}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div>
              <Label>{t('HypervisorPage.tableHeaders.disk')}</Label>
              <Input value={resizeDisk} onChange={(e) => setResizeDisk(e.target.value)} placeholder="scsi0" />
            </div>
            <div>
              <Label>{t('HypervisorPage.tableHeaders.size')}</Label>
              <Input value={resizeAmount} onChange={(e) => setResizeAmount(e.target.value)} placeholder="+10G" />
              <p className="text-xs text-muted-foreground mt-1">{t('HypervisorPage.resizeDialog.sizeHint')}</p>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setResizeDialog(null)}>{t('HypervisorPage.actions.cancel')}</Button>
            <Button
              onClick={() => resizeMutation.mutate()}
              disabled={!resizeDisk || !resizeAmount || resizeMutation.isPending}
            >
              {resizeMutation.isPending ? t('HypervisorPage.resizeDialog.resizing') : t('HypervisorPage.resizeDialog.resize')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* ── Backup dialog ────────────────────────────────────────────────── */}
      <Dialog open={!!backupDialog} onOpenChange={(open) => { if (!open) setBackupDialog(null); }}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>{t('HypervisorPage.backupDialog.title', { vmid: backupDialog?.vmid })}</DialogTitle>
            <DialogDescription>
              {t('HypervisorPage.backupDialog.description', { node: backupDialog?.node })}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div>
              <Label>{t('HypervisorPage.tableHeaders.storage')}</Label>
              <Input value={backupStorage} onChange={(e) => setBackupStorage(e.target.value)} placeholder="local" />
            </div>
            <div>
              <Label>{t('HypervisorPage.backup.mode')}</Label>
              <Select value={backupMode} onValueChange={setBackupMode}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="snapshot">{t('HypervisorPage.backupDialog.modeSnapshot')}</SelectItem>
                  <SelectItem value="suspend">{t('HypervisorPage.backupDialog.modeSuspend')}</SelectItem>
                  <SelectItem value="stop">{t('HypervisorPage.backupDialog.modeStop')}</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div>
              <Label>{t('HypervisorPage.backupDialog.compression')}</Label>
              <Select value={backupCompress} onValueChange={setBackupCompress}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="zstd">ZSTD</SelectItem>
                  <SelectItem value="lzo">LZO</SelectItem>
                  <SelectItem value="gzip">GZIP</SelectItem>
                  <SelectItem value="none">{t('HypervisorPage.backupDialog.compressNone')}</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setBackupDialog(null)}>{t('HypervisorPage.actions.cancel')}</Button>
            <Button
              onClick={() => runBackupMutation.mutate()}
              disabled={!backupStorage || runBackupMutation.isPending}
            >
              {runBackupMutation.isPending ? t('HypervisorPage.backupDialog.starting') : t('HypervisorPage.backupDialog.startBackup')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* ── Firewall rule create dialog ──────────────────────────────────── */}
      <Dialog open={!!fwCreateDialog} onOpenChange={(open) => { if (!open) setFwCreateDialog(null); }}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>{t('HypervisorPage.firewallDialog.title')}</DialogTitle>
            <DialogDescription>
              {t('HypervisorPage.firewallDialog.description', { node: fwCreateDialog?.node })}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <Label>{t('HypervisorPage.firewall.action')}</Label>
                <Select value={fwAction} onValueChange={setFwAction}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="ACCEPT">ACCEPT</SelectItem>
                    <SelectItem value="DROP">DROP</SelectItem>
                    <SelectItem value="REJECT">REJECT</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div>
                <Label>{t('HypervisorPage.firewallDialog.direction')}</Label>
                <Select value={fwType} onValueChange={setFwType}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="in">{t('HypervisorPage.firewallDialog.inbound')}</SelectItem>
                    <SelectItem value="out">{t('HypervisorPage.firewallDialog.outbound')}</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
            <div>
              <Label>{t('HypervisorPage.firewall.protocol')}</Label>
              <Select value={fwProto} onValueChange={setFwProto}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="tcp">TCP</SelectItem>
                  <SelectItem value="udp">UDP</SelectItem>
                  <SelectItem value="icmp">ICMP</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div>
              <Label>{t('HypervisorPage.firewallDialog.sourceOptional')}</Label>
              <Input value={fwSource} onChange={(e) => setFwSource(e.target.value)} placeholder="10.0.0.0/24" />
            </div>
            <div>
              <Label>{t('HypervisorPage.firewallDialog.destOptional')}</Label>
              <Input value={fwDest} onChange={(e) => setFwDest(e.target.value)} placeholder="192.168.1.0/24" />
            </div>
            <div>
              <Label>{t('HypervisorPage.firewallDialog.dportOptional')}</Label>
              <Input value={fwDport} onChange={(e) => setFwDport(e.target.value)} placeholder="80,443" />
            </div>
            <div>
              <Label>{t('HypervisorPage.firewallDialog.commentOptional')}</Label>
              <Input value={fwComment} onChange={(e) => setFwComment(e.target.value)} placeholder={t('HypervisorPage.firewallDialog.commentPlaceholder')} />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setFwCreateDialog(null)}>{t('HypervisorPage.actions.cancel')}</Button>
            <Button
              onClick={() => createFwRuleMutation.mutate()}
              disabled={createFwRuleMutation.isPending}
            >
              {createFwRuleMutation.isPending ? t('HypervisorPage.actions.creating') : t('HypervisorPage.firewall.createRule')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* ── Task log dialog ──────────────────────────────────────────────── */}
      <Dialog open={!!taskLogDialog} onOpenChange={(open) => { if (!open) setTaskLogDialog(null); }}>
        <DialogContent className="sm:max-w-2xl max-h-[80vh]">
          <DialogHeader>
            <DialogTitle>{t('HypervisorPage.taskLogDialog.title')}</DialogTitle>
            <DialogDescription className="font-mono text-[10px] break-all">
              {taskLogDialog?.upid}
            </DialogDescription>
          </DialogHeader>
          <div className="bg-muted rounded-md p-3 overflow-auto max-h-[50vh]">
            {taskLogLoading ? <Skeleton className="h-32" /> :
             taskLogEntries.length === 0 ? <p className="text-xs text-muted-foreground">{t('HypervisorPage.taskLogDialog.empty')}</p> : (
              <pre className="text-xs font-mono whitespace-pre-wrap">
                {taskLogEntries.map((entry: any) => entry.t).join('\n')}
              </pre>
            )}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setTaskLogDialog(null)}>{t('HypervisorPage.actions.close')}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* ── Create VM / Container dialog ────────────────────────────────── */}
      <Dialog open={!!createDialog} onOpenChange={(open) => { if (!open) setCreateDialog(null); }}>
        <DialogContent className="sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>
              {createDialog === 'vm' ? t('HypervisorPage.createDialog.titleVm') : t('HypervisorPage.createDialog.titleCt')}
            </DialogTitle>
            <DialogDescription>
              {createDialog === 'vm'
                ? t('HypervisorPage.createDialog.descriptionVm')
                : t('HypervisorPage.createDialog.descriptionCt')}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 max-h-[60vh] overflow-y-auto pr-1">
            {/* Name */}
            <div>
              <Label>{createDialog === 'ct' ? t('HypervisorPage.createDialog.hostname') : t('HypervisorPage.tableHeaders.name')}</Label>
              <Input
                value={createName}
                onChange={(e) => setCreateName(e.target.value)}
                placeholder={createDialog === 'ct' ? 'my-container' : 'my-vm'}
                maxLength={128}
              />
            </div>

            {/* Target Node */}
            <div>
              <Label>{t('HypervisorPage.migrateDialog.targetNode')}</Label>
              <Select value={createNode || nodes[0]?.node || ''} onValueChange={setCreateNode}>
                <SelectTrigger><SelectValue placeholder={t('HypervisorPage.createDialog.selectNode')} /></SelectTrigger>
                <SelectContent>
                  {nodes.map((n) => (
                    <SelectItem key={n.node} value={n.node}>
                      {n.node} {n.status === 'online' ? '' : `(${n.status})`}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            {/* OS Template (CT only) */}
            {createDialog === 'ct' && (
              <div>
                <Label>{t('HypervisorPage.createDialog.osTemplate')}</Label>
                <Input
                  value={createOsTemplate}
                  onChange={(e) => setCreateOsTemplate(e.target.value)}
                  placeholder="local:vztmpl/debian-12-standard_12.2-1_amd64.tar.zst"
                />
                <p className="text-xs text-muted-foreground mt-1">
                  {t('HypervisorPage.createDialog.osTemplateHint')}
                </p>
              </div>
            )}

            {/* ISO (VM only) */}
            {createDialog === 'vm' && (
              <div>
                <Label>{t('HypervisorPage.createDialog.isoImage')}</Label>
                <Input
                  value={createIso}
                  onChange={(e) => setCreateIso(e.target.value)}
                  placeholder="local:iso/ubuntu-24.04-server.iso"
                />
                <p className="text-xs text-muted-foreground mt-1">
                  {t('HypervisorPage.createDialog.isoHint')}
                </p>
              </div>
            )}

            {/* CPU & Memory */}
            <div className="grid grid-cols-2 gap-4">
              <div>
                <Label>{t('HypervisorPage.createDialog.cpuCores')}</Label>
                <Input
                  type="number"
                  min={1}
                  max={128}
                  value={createCores}
                  onChange={(e) => setCreateCores(parseInt(e.target.value) || 1)}
                />
              </div>
              <div>
                <Label>{t('HypervisorPage.createDialog.memoryMb')}</Label>
                <Input
                  type="number"
                  min={128}
                  step={256}
                  value={createMemory}
                  onChange={(e) => setCreateMemory(parseInt(e.target.value) || 512)}
                />
                <p className="text-xs text-muted-foreground mt-1">
                  {(createMemory / 1024).toFixed(1)} GB
                </p>
              </div>
            </div>

            {/* Disk & Storage */}
            <div className="grid grid-cols-2 gap-4">
              <div>
                <Label>{createDialog === 'ct' ? t('HypervisorPage.createDialog.rootDiskSize') : t('HypervisorPage.createDialog.diskSize')}</Label>
                <Input
                  value={createDiskSize}
                  onChange={(e) => setCreateDiskSize(e.target.value)}
                  placeholder={createDialog === 'ct' ? '8' : '32G'}
                />
                <p className="text-xs text-muted-foreground mt-1">
                  {createDialog === 'ct' ? t('HypervisorPage.createDialog.diskHintCt') : t('HypervisorPage.createDialog.diskHintVm')}
                </p>
              </div>
              <div>
                <Label>{t('HypervisorPage.tableHeaders.storage')}</Label>
                <Input
                  value={createStorage}
                  onChange={(e) => setCreateStorage(e.target.value)}
                  placeholder="local-lvm"
                />
              </div>
            </div>

            {/* Start after create */}
            <label className="flex items-center gap-2 cursor-pointer">
              <Checkbox
                checked={createStartAfter}
                onCheckedChange={(checked) => setCreateStartAfter(!!checked)}
              />
              <span className="text-sm">{t('HypervisorPage.createDialog.startAfterCreation')}</span>
            </label>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setCreateDialog(null)}>{t('HypervisorPage.actions.cancel')}</Button>
            <Button
              onClick={() => {
                if (createDialog === 'vm') {
                  createVMMutation.mutate();
                } else {
                  createCTMutation.mutate();
                }
              }}
              disabled={
                (createDialog === 'vm' ? createVMMutation.isPending : createCTMutation.isPending) ||
                !createName.trim() ||
                (createDialog === 'ct' && !createOsTemplate)
              }
            >
              {(createDialog === 'vm' ? createVMMutation.isPending : createCTMutation.isPending) && (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              )}
              {(createDialog === 'vm' ? createVMMutation.isPending : createCTMutation.isPending)
                ? t('HypervisorPage.actions.creating')
                : createDialog === 'vm' ? t('HypervisorPage.createDialog.createVm') : t('HypervisorPage.createDialog.createCt')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* ── Add HA Resource dialog ──────────────────────────────────────── */}
      <Dialog open={haResDialog} onOpenChange={setHaResDialog}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>{t('HypervisorPage.ha.addResource')}</DialogTitle>
            <DialogDescription>
              {t('HypervisorPage.haResourceDialog.description')}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div>
              <Label>{t('HypervisorPage.haResourceDialog.serviceId')}</Label>
              <Input
                value={haResSid}
                onChange={(e) => setHaResSid(e.target.value)}
                placeholder="vm:100 or ct:200"
              />
              <p className="text-xs text-muted-foreground mt-1">
                {t('HypervisorPage.haResourceDialog.sidHint')}
              </p>
            </div>
            <div>
              <Label>{t('HypervisorPage.haResourceDialog.haGroupOptional')}</Label>
              {haGroups.length > 0 ? (
                <Select
                  value={haResGroup || '__none__'}
                  onValueChange={(v) => setHaResGroup(v === '__none__' ? '' : v)}
                >
                  <SelectTrigger><SelectValue placeholder={t('HypervisorPage.haResourceDialog.noneAnyNode')} /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="__none__">{t('HypervisorPage.haResourceDialog.none')}</SelectItem>
                    {haGroups.map((g) => (
                      <SelectItem key={g.group} value={g.group}>{g.group}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              ) : (
                <Input
                  value={haResGroup}
                  onChange={(e) => setHaResGroup(e.target.value)}
                  placeholder={t('HypervisorPage.haResourceDialog.emptyForNoGroup')}
                />
              )}
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setHaResDialog(false)}>{t('HypervisorPage.actions.cancel')}</Button>
            <Button
              onClick={() => createHAResourceMutation.mutate({ sid: haResSid, group: haResGroup || undefined })}
              disabled={!haResSid || createHAResourceMutation.isPending}
            >
              {createHAResourceMutation.isPending ? t('HypervisorPage.haResourceDialog.adding') : t('HypervisorPage.ha.addResource')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* ── Add HA Group dialog ─────────────────────────────────────────── */}
      <Dialog open={haGrpDialog} onOpenChange={setHaGrpDialog}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>{t('HypervisorPage.haGroupDialog.title')}</DialogTitle>
            <DialogDescription>
              {t('HypervisorPage.haGroupDialog.description')}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div>
              <Label>{t('HypervisorPage.haGroupDialog.groupName')}</Label>
              <Input
                value={haGrpName}
                onChange={(e) => setHaGrpName(e.target.value)}
                placeholder="production-nodes"
              />
            </div>
            <div>
              <Label>{t('HypervisorPage.ha.nodes')}</Label>
              <Input
                value={haGrpNodes}
                onChange={(e) => setHaGrpNodes(e.target.value)}
                placeholder="node1:2,node2:1,node3:1"
              />
              <p className="text-xs text-muted-foreground mt-1">
                {t('HypervisorPage.haGroupDialog.nodesHint')}
              </p>
            </div>
            <label className="flex items-center gap-2 cursor-pointer">
              <Checkbox
                checked={haGrpNofailback}
                onCheckedChange={(c) => setHaGrpNofailback(!!c)}
              />
              <span className="text-sm">{t('HypervisorPage.haGroupDialog.noFailback')}</span>
            </label>
            <label className="flex items-center gap-2 cursor-pointer">
              <Checkbox
                checked={haGrpRestricted}
                onCheckedChange={(c) => setHaGrpRestricted(!!c)}
              />
              <span className="text-sm">{t('HypervisorPage.haGroupDialog.restricted')}</span>
            </label>
            <div>
              <Label>{t('HypervisorPage.firewallDialog.commentOptional')}</Label>
              <Input
                value={haGrpComment}
                onChange={(e) => setHaGrpComment(e.target.value)}
                placeholder={t('HypervisorPage.haGroupDialog.commentPlaceholder')}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setHaGrpDialog(false)}>{t('HypervisorPage.actions.cancel')}</Button>
            <Button
              onClick={() => createHAGroupMutation.mutate()}
              disabled={!haGrpName || !haGrpNodes || createHAGroupMutation.isPending}
            >
              {createHAGroupMutation.isPending ? t('HypervisorPage.actions.creating') : t('HypervisorPage.haGroupDialog.createGroup')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* ── Edit Config Dialog ─────────────────────────────────────────── */}
      <EditConfigDialog
        open={!!editConfigVM}
        onClose={() => setEditConfigVM(null)}
        controllerId={controllerId}
        vm={editConfigVM}
      />

      {/* ── Backup Job Dialog ──────────────────────────────────────────── */}
      <BackupJobDialog
        open={backupJobDialog}
        onClose={() => { setBackupJobDialog(false); setEditBackupJob(null); }}
        controllerId={controllerId}
        nodes={nodes}
        editJob={editBackupJob}
      />

      {/* ── Upload Dialog ──────────────────────────────────────────────── */}
      <UploadDialog
        open={!!uploadDialog}
        onClose={() => setUploadDialog(null)}
        controllerId={controllerId}
        storage={uploadDialog?.storage || ''}
        node={uploadDialog?.node || ''}
      />

      {/* ── Restore from Backup Dialog ─────────────────────────────────── */}
      <Dialog open={!!restoreDialog} onOpenChange={(open) => { if (!open) setRestoreDialog(null); }}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>{t('HypervisorPage.restoreDialog.title')}</DialogTitle>
            <DialogDescription>
              {t('HypervisorPage.restoreDialog.description')}
            </DialogDescription>
          </DialogHeader>
          {restoreDialog && (
            <div className="space-y-4">
              <div>
                <Label className="text-xs text-muted-foreground">{t('HypervisorPage.restoreDialog.archive')}</Label>
                <p className="text-xs font-mono break-all mt-1">{restoreDialog.archive}</p>
              </div>
              <div>
                <Label className="text-xs">{t('HypervisorPage.restoreDialog.vmidRequired')}</Label>
                <Input
                  type="number"
                  value={restoreVmid}
                  onChange={(e) => setRestoreVmid(e.target.value.replace(/\D/g, ''))}
                  placeholder="100"
                  className="h-8"
                />
              </div>
              <div>
                <Label className="text-xs">{t('HypervisorPage.migrateDialog.targetNode')}</Label>
                <Select value={restoreTargetNode || restoreDialog.node} onValueChange={setRestoreTargetNode}>
                  <SelectTrigger className="h-8">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {nodes.map((n) => (
                      <SelectItem key={n.node} value={n.node}>{n.node}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div>
                <Label className="text-xs">{t('HypervisorPage.restoreDialog.targetStorage')}</Label>
                <Select value={restoreTargetStorage || restoreDialog.storage} onValueChange={setRestoreTargetStorage}>
                  <SelectTrigger className="h-8">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {storagePools.map((s) => (
                      <SelectItem key={s.storage} value={s.storage}>{s.storage}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="flex items-center gap-4">
                <label className="flex items-center gap-2 text-sm">
                  <Checkbox
                    checked={restoreStartAfter}
                    onCheckedChange={(v) => setRestoreStartAfter(!!v)}
                  />
                  {t('HypervisorPage.restoreDialog.startAfterRestore')}
                </label>
                <label className="flex items-center gap-2 text-sm">
                  <Checkbox
                    checked={restoreUniqueMac}
                    onCheckedChange={(v) => setRestoreUniqueMac(!!v)}
                  />
                  {t('HypervisorPage.restoreDialog.uniqueMac')}
                </label>
              </div>
            </div>
          )}
          <DialogFooter>
            <Button variant="outline" onClick={() => setRestoreDialog(null)}>
              {t('HypervisorPage.actions.cancel')}
            </Button>
            <Button
              onClick={() => restoreBackupMutation.mutate()}
              disabled={!restoreVmid || restoreBackupMutation.isPending}
            >
              {restoreBackupMutation.isPending && <Loader2 className="h-3.5 w-3.5 mr-1 animate-spin" />}
              {t('HypervisorPage.storage.restore')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* ── Guest Detail Drawer ──────────────────────────────────────── */}
      {detailVM && (
        <GuestDetailDrawer
          vm={detailVM}
          controllerId={controllerId}
          isOpen={!!detailVM}
          onClose={() => setDetailVM(null)}
          onAction={(params) => {
            handleVMAction(params);
          }}
        />
      )}

      {/* ── Bulk Action Bar ────────────────────────────────────────────── */}
      {selectedVMs.size > 0 && (
        <BulkActionBar
          controllerId={controllerId}
          selectedTargets={selectedTargets}
          nodes={nodes}
          onClear={clearSelection}
        />
      )}

      {/* Page-wide destructive-confirm dialog. All
          node/task/backup-job/firewall-rule/HA/snapshot destructive
          actions request the typed confirmation through here.
          VMTable's per-row power confirms thread through the
          ``requestConfirm`` prop. */}
      <DestructiveConfirmDialog
        open={confirmState !== null}
        onOpenChange={(o) => !o && setConfirmState(null)}
        title={confirmState?.title ?? ''}
        description={confirmState?.description ?? ''}
        confirmationText={confirmState?.confirmationText ?? ''}
        confirmLabel={confirmState?.confirmLabel ?? 'Confirm'}
        onConfirm={confirmState?.onConfirm ?? (() => {})}
      />

    </div>
  );
}

export default HypervisorPage;

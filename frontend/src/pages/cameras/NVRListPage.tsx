// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN · NVR Management Page
 *
 * Enterprise NVR fleet dashboard with:
 *  - Card-based NVR overview with health indicators
 *  - Storage capacity visualization per NVR
 *  - Quick actions: sync, view channels, settings
 *  - Inline status monitoring (online/offline/error)
 *  - Linked navigation to NVR detail pages
 */

import { useState, useMemo, useCallback } from 'react';
import { useTranslation } from 'react-i18next';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useSiteStore } from '@/stores/siteStore';
import {
  HardDrive,
  Plus,
  RefreshCw,
  Server,
  Wifi,
  WifiOff,
  AlertTriangle,
  ChevronRight,
  MoreHorizontal,
  Trash2,
  Settings,
  Activity,
  Camera,
  LayoutGrid,
  List,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { Skeleton } from '@/components/ui/skeleton';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { nvrApi } from '@/lib/api';
import { cn } from '@/lib/utils';
import { PageHeader, PageToolbar } from '@/components/layout';
import { StatsGrid } from '@/components/ui/stats-grid';
import { BulkActionsBar } from '@/components/ui/bulk-actions-bar';
import { EmptyState, ErrorState, NoResultsState } from '@/components/ui/empty-state';
import { SearchBar } from '@/components/ui/search-bar';
import { DataTable, type DataTableColumn } from '@/components/ui/data-table';
import { useToast } from '@/hooks/use-toast';
import { Download } from 'lucide-react';
import { AddDeviceDialog } from '@/components/cameras/AddDeviceDialog';
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface NVRDevice {
  id: string;
  name: string;
  description?: string;
  ip_address: string;
  port: number;
  mac_address?: string;
  vendor?: string;
  model?: string;
  firmware_version?: string;
  serial_number?: string;
  device_type: string;
  channel_count: number;
  storage_total_gb?: number;
  storage_used_gb?: number;
  status: 'online' | 'offline' | 'recording' | 'error' | 'unknown';
  last_seen?: string;
  last_synced_at?: string;
  cameras?: { id: string; name: string; status: string }[];
  created_at?: string;
  updated_at?: string;
}

type ViewMode = 'grid' | 'table';

// ---------------------------------------------------------------------------
// Status Badge
// ---------------------------------------------------------------------------

function NVRStatusBadge({ status }: { status: string }) {
  const { t } = useTranslation('cameras');
  const config: Record<string, { label: string; className: string; icon: typeof Wifi }> = {
    online: { label: t('NVRListPage.status.online'), className: 'bg-success/10 text-success border-success/20', icon: Wifi },
    offline: { label: t('NVRListPage.status.offline'), className: 'bg-destructive/10 text-destructive border-destructive/20', icon: WifiOff },
    recording: { label: t('NVRListPage.status.recording'), className: 'bg-info/10 text-info border-info/20', icon: Activity },
    error: { label: t('NVRListPage.status.error'), className: 'bg-warning/10 text-warning border-warning/20', icon: AlertTriangle },
    unknown: { label: t('NVRListPage.status.unknown'), className: 'bg-muted text-muted-foreground border-muted', icon: HardDrive },
  };
  const c = config[status] || config.unknown;
  const Icon = c.icon;
  return (
    <Badge variant="outline" className={cn('text-[11px] gap-1', c.className)}>
      <Icon className="h-3 w-3" />
      {c.label}
    </Badge>
  );
}

// ---------------------------------------------------------------------------
// Storage Bar
// ---------------------------------------------------------------------------

function StorageBar({ totalGb, usedGb }: { totalGb?: number; usedGb?: number }) {
  const { t } = useTranslation('cameras');
  if (!totalGb || totalGb <= 0) return <span className="text-xs text-muted-foreground">{t('NVRListPage.storage.notAvailable')}</span>;
  const used = usedGb || 0;
  const pct = Math.min(Math.round((used / totalGb) * 100), 100);
  const freeGb = totalGb - used;

  const formatTb = (gb: number) => {
    if (gb >= 1024) return `${(gb / 1024).toFixed(1)} TB`;
    return `${Math.round(gb)} GB`;
  };

  return (
    <div className="space-y-1 w-full">
      <div className="flex justify-between text-[11px]">
        <span className="text-muted-foreground">{t('NVRListPage.storage.used', { size: formatTb(used) })}</span>
        <span className="text-muted-foreground">{t('NVRListPage.storage.free', { size: formatTb(freeGb) })}</span>
      </div>
      <Progress
        value={pct}
        className={cn('h-2', pct > 90 ? '[&>div]:bg-destructive' : pct > 75 ? '[&>div]:bg-warning' : '[&>div]:bg-success')}
      />
      <div className="text-[10px] text-muted-foreground text-center">{t('NVRListPage.storage.percentOf', { pct, total: formatTb(totalGb) })}</div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// NVR Card (Grid View)
// ---------------------------------------------------------------------------

function NVRCard({
  nvr,
  onSync,
  onNavigate,
  onDelete,
  isSyncing,
}: {
  nvr: NVRDevice;
  onSync: (id: string) => void;
  onNavigate: (id: string) => void;
  onDelete: (nvr: NVRDevice) => void;
  isSyncing: boolean;
}) {
  const { t } = useTranslation('cameras');
  const cameraCount = nvr.channel_count || nvr.cameras?.length || 0;
  const onlineCameras = nvr.cameras?.filter((c) => c.status === 'online').length ?? 0;

  return (
    <Card
      className="cursor-pointer hover:border-primary/40 transition-colors group"
      onClick={() => onNavigate(nvr.id)}
    >
      <CardContent noOffset className="p-4 space-y-3">
        {/* Header */}
        <div className="flex items-start justify-between">
          <div className="flex items-center gap-2 min-w-0 flex-1">
            <div className={cn(
              'h-9 w-9 rounded-lg flex items-center justify-center shrink-0',
              nvr.status === 'online' ? 'bg-success/10' : 'bg-muted',
            )}>
              <Server className={cn('h-5 w-5', nvr.status === 'online' ? 'text-success' : 'text-muted-foreground')} />
            </div>
            <div className="min-w-0">
              <h3 className="font-semibold text-sm truncate">{nvr.name}</h3>
              <p className="text-xs text-muted-foreground truncate">{nvr.ip_address}:{nvr.port}</p>
            </div>
          </div>
          <DropdownMenu>
            <DropdownMenuTrigger asChild onClick={(e) => e.stopPropagation()}>
              <Button variant="ghost" size="icon" className="h-7 w-7 opacity-0 group-hover:opacity-100 transition-opacity">
                <MoreHorizontal className="h-4 w-4" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuItem onClick={(e) => { e.stopPropagation(); onNavigate(nvr.id); }}>
                <Settings className="h-4 w-4 mr-2" /> {t('NVRListPage.actions.viewDetails')}
              </DropdownMenuItem>
              <DropdownMenuItem onClick={(e) => { e.stopPropagation(); onSync(nvr.id); }} disabled={isSyncing}>
                <RefreshCw className={cn('h-4 w-4 mr-2', isSyncing && 'animate-spin')} /> {t('NVRListPage.actions.syncChannels')}
              </DropdownMenuItem>
              <DropdownMenuSeparator />
              <DropdownMenuItem
                className="text-destructive"
                onClick={(e) => { e.stopPropagation(); onDelete(nvr); }}
              >
                <Trash2 className="h-4 w-4 mr-2" /> {t('NVRListPage.actions.delete')}
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>

        {/* Status + Model */}
        <div className="flex items-center justify-between">
          <NVRStatusBadge status={nvr.status} />
          {nvr.model && (
            <span className="text-[11px] text-muted-foreground truncate max-w-[50%]">{nvr.model}</span>
          )}
        </div>

        {/* Cameras */}
        <div className="flex items-center gap-2 text-xs">
          <Camera className="h-3.5 w-3.5 text-muted-foreground" />
          <span className="text-muted-foreground">
            {cameraCount === 1
              ? t('NVRListPage.card.channel', { count: cameraCount })
              : t('NVRListPage.card.channels', { count: cameraCount })}
            {nvr.cameras && nvr.cameras.length > 0 && (
              <> · <span className="text-success">{t('NVRListPage.card.online', { count: onlineCameras })}</span></>
            )}
          </span>
        </div>

        {/* Storage */}
        <StorageBar totalGb={nvr.storage_total_gb} usedGb={nvr.storage_used_gb} />

        {/* Footer */}
        <div className="flex items-center justify-between text-[10px] text-muted-foreground pt-1 border-t">
          <span>
            {nvr.firmware_version
              ? t('NVRListPage.card.firmware', { version: nvr.firmware_version })
              : nvr.vendor || t('NVRListPage.card.unknownVendor')}
          </span>
          <span className="flex items-center gap-1">
            {nvr.last_synced_at
              ? t('NVRListPage.card.synced', { date: new Date(nvr.last_synced_at).toLocaleDateString() })
              : t('NVRListPage.card.neverSynced')}
            <ChevronRight className="h-3 w-3" />
          </span>
        </div>
      </CardContent>
    </Card>
  );
}

// ---------------------------------------------------------------------------
// Main Page Component
// ---------------------------------------------------------------------------

export default function NVRListPage() {
  const { t } = useTranslation('cameras');
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [searchParams, setSearchParams] = useSearchParams();
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  // Persist view mode to URL search params so it survives navigation/reload.
  const [viewMode, setViewModeState] = useState<ViewMode>(() => {
    const v = searchParams.get('view');
    return v === 'table' || v === 'grid' ? v : 'grid';
  });
  const setViewMode = useCallback((mode: ViewMode) => {
    setViewModeState(mode);
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev);
      if (mode === 'grid') next.delete('view'); else next.set('view', mode);
      return next;
    }, { replace: true });
  }, [setSearchParams]);
  const [syncingId, setSyncingId] = useState<string | null>(null);
  const [addDialogOpen, setAddDialogOpen] = useState(false);
  const [deleteTarget, setDeleteTarget] = useState<NVRDevice | null>(null);

  // Site context
  const selectedSiteId = useSiteStore((s) => s.selectedSiteId);

  // ── Data Queries ──
  const { data: nvrsData, isLoading, isError, refetch } = useQuery({
    queryKey: ['nvrs', { siteId: selectedSiteId }],
    queryFn: async () => (await nvrApi.getAll({ limit: 200, site_id: selectedSiteId || undefined })).data,
    refetchInterval: 30_000,
    staleTime: 10_000,
  });

  const { data: statsData } = useQuery({
    queryKey: ['nvr-stats', { siteId: selectedSiteId }],
    queryFn: async () => (await nvrApi.getStats({ site_id: selectedSiteId || undefined })).data,
    refetchInterval: 30_000,
  });

  const { data: streamStatsData } = useQuery({
    queryKey: ['stream-stats', { siteId: selectedSiteId }],
    queryFn: async () => (await nvrApi.getStreamStats({ site_id: selectedSiteId || undefined })).data,
    refetchInterval: 5_000,
  });

  const stats = statsData || { total: 0, online: 0, offline: 0, error: 0 };
  const streamStats = streamStatsData || { active_streams: 0, target_fps: 0, frame_interval_ms: 0 };

  const { toast } = useToast();

  // ── Mutations ──
  const syncMut = useMutation({
    mutationFn: (id: string) => nvrApi.sync(id),
    onMutate: (id) => setSyncingId(id),
    onSuccess: (res) => {
      const synced = (res.data?.added ?? 0) + (res.data?.updated ?? 0);
      toast({ title: t('NVRListPage.toasts.syncSuccess', { count: synced }) });
    },
    onError: (err) =>
      toast({
        title: t('NVRListPage.toasts.syncFailed'),
        description: (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail,
        variant: 'destructive',
      }),
    onSettled: () => {
      setSyncingId(null);
      queryClient.invalidateQueries({ queryKey: ['nvrs'] });
      queryClient.invalidateQueries({ queryKey: ['nvr-stats'] });
    },
  });

  const deleteMut = useMutation({
    mutationFn: (id: string) => nvrApi.delete(id),
    onSuccess: () => {
      setDeleteTarget(null);
      queryClient.invalidateQueries({ queryKey: ['nvrs'] });
      queryClient.invalidateQueries({ queryKey: ['nvr-stats'] });
      queryClient.invalidateQueries({ queryKey: ['cameras'] });
    },
    onError: (err) =>
      toast({
        title: t('NVRListPage.toasts.deleteFailed'),
        description: (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail,
        variant: 'destructive',
      }),
  });

  const handleAddSuccess = useCallback(() => {
    queryClient.invalidateQueries({ queryKey: ['nvrs'] });
    queryClient.invalidateQueries({ queryKey: ['nvr-stats'] });
    queryClient.invalidateQueries({ queryKey: ['cameras'] });
  }, [queryClient]);

  // ── Filtering ──
  const filteredNVRs = useMemo(() => {
    const nvrs: NVRDevice[] = nvrsData?.items ?? [];
    let list = nvrs;
    if (search) {
      const q = search.toLowerCase();
      list = list.filter((n) =>
        n.name.toLowerCase().includes(q) ||
        n.ip_address.includes(q) ||
        n.model?.toLowerCase().includes(q) ||
        n.serial_number?.toLowerCase().includes(q) ||
        n.mac_address?.toLowerCase().includes(q)
      );
    }
    if (statusFilter !== 'all') {
      list = list.filter((n) => n.status === statusFilter);
    }
    return list;
  }, [nvrsData?.items, search, statusFilter]);

  const [selected, setSelected] = useState<NVRDevice[]>([]);
  const [bulkDeleteOpen, setBulkDeleteOpen] = useState(false);
  const hasActiveFilters = search !== '' || statusFilter !== 'all';

  // ── Export (client-side CSV of the loaded/filtered NVRs) ──
  const handleExport = useCallback(() => {
    if (filteredNVRs.length === 0) return;
    const headers = [
      'name', 'ip_address', 'port', 'status', 'vendor', 'model',
      'firmware_version', 'serial_number', 'channel_count',
      'storage_total_gb', 'storage_used_gb', 'last_synced_at',
    ];
    const escape = (v: unknown) => {
      const s = v == null ? '' : String(v);
      return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
    };
    const rows = filteredNVRs.map((n) =>
      headers.map((h) => escape((n as unknown as Record<string, unknown>)[h])).join(','),
    );
    const csv = [headers.join(','), ...rows].join('\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `nvrs_${new Date().toISOString().slice(0, 10)}.csv`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }, [filteredNVRs]);

  // ── Bulk delete (confirm → Promise.allSettled → summary toast) ──
  const bulkDeleteMut = useMutation({
    mutationFn: async (ids: string[]) => {
      const results = await Promise.allSettled(ids.map((id) => nvrApi.delete(id)));
      const failed = results.filter((r) => r.status === 'rejected').length;
      return { total: ids.length, failed };
    },
    onSuccess: ({ total, failed }) => {
      queryClient.invalidateQueries({ queryKey: ['nvrs'] });
      queryClient.invalidateQueries({ queryKey: ['nvr-stats'] });
      queryClient.invalidateQueries({ queryKey: ['cameras'] });
      setSelected([]);
      setBulkDeleteOpen(false);
      if (failed === 0) {
        toast({ title: t('CamerasPage.toasts.camerasDeleted', { count: total }) });
      } else {
        toast({
          title: t('CamerasPage.toasts.camerasDeletedPartial', { succeeded: total - failed, total, failed }),
          variant: 'destructive',
        });
      }
    },
    onError: (err) =>
      toast({
        title: t('CamerasPage.toasts.deleteCamerasFailed'),
        description: (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail,
        variant: 'destructive',
      }),
  });

  // Loading skeleton
  if (isLoading) {
    return (
      <div className="space-y-6">
        <Skeleton className="h-10 w-48" />
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {[...Array(4)].map((_, i) => <Skeleton key={i} className="h-24" />)}
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-4">
          {[...Array(6)].map((_, i) => <Skeleton key={i} className="h-56" />)}
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title={t('NVRListPage.header.title')}
        description={t('NVRListPage.header.description', { total: stats.total, online: stats.online })}
        icon={Server}
        onRefresh={() => refetch()}
        refreshing={isLoading}
        secondaryActions={[{ label: t('NVRListPage.actions.export'), icon: Download, onClick: handleExport }]}
        primaryAction={{ label: t('NVRListPage.actions.addNvr'), icon: Plus, onClick: () => setAddDialogOpen(true) }}
      />

      <StatsGrid
        columns={4}
        isLoading={isLoading}
        stats={[
          {
            title: t('NVRListPage.stats.totalNvrs'),
            value: stats.total,
            icon: Server,
            variant: 'primary',
            description: t('NVRListPage.stats.configuredRecorders'),
          },
          {
            title: t('NVRListPage.stats.online'),
            value: stats.online,
            icon: Wifi,
            variant: 'success',
            description: stats.total > 0 ? t('NVRListPage.stats.reachable', { pct: Math.round((stats.online / stats.total) * 100) }) : t('NVRListPage.stats.noNvrs'),
          },
          {
            title: t('NVRListPage.stats.offline'),
            value: stats.offline,
            icon: WifiOff,
            variant: 'destructive',
            description: t('NVRListPage.stats.needsAttention'),
          },
          {
            title: t('NVRListPage.stats.activeStreams'),
            value: streamStats.active_streams,
            icon: Activity,
            variant: 'info',
            description: streamStats.active_streams > 0 ? t('NVRListPage.stats.fpsTarget', { fps: streamStats.target_fps }) : t('NVRListPage.stats.noLiveStreams'),
          },
        ]}
      />

      <PageToolbar>
        <SearchBar
          value={search}
          onChange={setSearch}
          placeholder={t('NVRListPage.toolbar.searchPlaceholder')}
          className="w-full sm:w-auto"
        />
        <Select value={statusFilter} onValueChange={setStatusFilter}>
          <SelectTrigger className="w-full sm:w-[160px]">
            <SelectValue placeholder={t('NVRListPage.toolbar.allStatuses')} />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">{t('NVRListPage.toolbar.allStatuses')}</SelectItem>
            <SelectItem value="online">{t('NVRListPage.status.online')}</SelectItem>
            <SelectItem value="offline">{t('NVRListPage.status.offline')}</SelectItem>
            <SelectItem value="recording">{t('NVRListPage.status.recording')}</SelectItem>
            <SelectItem value="error">{t('NVRListPage.status.error')}</SelectItem>
          </SelectContent>
        </Select>
        {hasActiveFilters && (
          <Button
            variant="ghost"
            size="sm"
            onClick={() => {
              setSearch('');
              setStatusFilter('all');
            }}
          >
            {t('NVRListPage.toolbar.clearFilters')}
          </Button>
        )}
        <div className="ml-auto flex items-center border rounded-md">
          <Button
            variant={viewMode === 'grid' ? 'secondary' : 'ghost'}
            size="icon"
            className="h-9 w-9 rounded-r-none"
            onClick={() => setViewMode('grid')}
            aria-label={t('NVRListPage.toolbar.gridView')}
          >
            <LayoutGrid className="h-4 w-4" />
          </Button>
          <Button
            variant={viewMode === 'table' ? 'secondary' : 'ghost'}
            size="icon"
            className="h-9 w-9 rounded-l-none"
            onClick={() => setViewMode('table')}
            aria-label={t('NVRListPage.toolbar.tableView')}
          >
            <List className="h-4 w-4" />
          </Button>
        </div>
      </PageToolbar>

      {isError && (
        <ErrorState message={t('NVRListPage.error.loadFailed')} onRetry={() => refetch()} />
      )}

      {/* Empty State */}
      {!isError && filteredNVRs.length === 0 && (
        search || statusFilter !== 'all' ? (
          <NoResultsState
            searchQuery={search || undefined}
            onClear={() => { setSearch(''); setStatusFilter('all'); }}
          />
        ) : (
          <EmptyState
            icon={Server}
            title={t('NVRListPage.empty.title')}
            description={t('NVRListPage.empty.description')}
            action={{ label: t('NVRListPage.actions.addNvr'), onClick: () => setAddDialogOpen(true), icon: Plus }}
            variant="card"
          />
        )
      )}

      {/* Grid View */}
      {viewMode === 'grid' && filteredNVRs.length > 0 && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
          {filteredNVRs.map((nvr) => (
            <NVRCard
              key={nvr.id}
              nvr={nvr}
              onSync={(id) => syncMut.mutate(id)}
              onNavigate={(id) => navigate(`/cameras/nvrs/${id}`)}
              onDelete={(n) => setDeleteTarget(n)}
              isSyncing={syncingId === nvr.id}
            />
          ))}
        </div>
      )}

      {/* Table View · canonical DataTable */}
      {viewMode === 'table' && filteredNVRs.length > 0 && (
        <DataTable
          data={filteredNVRs}
          columns={[
            {
              id: 'name',
              header: t('NVRListPage.table.nvr'),
              accessorFn: (nvr) => nvr.name?.toLowerCase() ?? '',
              cell: (nvr) => (
                <div className="flex items-center gap-2">
                  <Server className="h-4 w-4 text-muted-foreground shrink-0" />
                  <div>
                    <button
                      onClick={() => navigate(`/cameras/nvrs/${nvr.id}`)}
                      className="font-medium text-sm hover:text-primary hover:underline text-left"
                    >
                      {nvr.name}
                    </button>
                    {nvr.serial_number && (
                      <p className="text-[10px] text-muted-foreground">{t('NVRListPage.table.serialNumber', { serial: nvr.serial_number.slice(-12) })}</p>
                    )}
                  </div>
                </div>
              ),
            },
            { id: 'status', header: t('NVRListPage.table.status'), accessorFn: (nvr) => nvr.status, cell: (nvr) => <NVRStatusBadge status={nvr.status} /> },
            {
              id: 'ip',
              header: t('NVRListPage.table.ipAddress'),
              accessorFn: (nvr) => nvr.ip_address,
              cell: (nvr) => <span className="text-sm font-mono">{nvr.ip_address}:{nvr.port}</span>,
            },
            {
              id: 'model',
              header: t('NVRListPage.table.model'),
              accessorFn: (nvr) => nvr.model?.toLowerCase() ?? '',
              cell: (nvr) => <span className="text-sm text-muted-foreground">{nvr.model || '-'}</span>,
            },
            {
              id: 'channels',
              header: t('NVRListPage.table.channels'),
              accessorFn: (nvr) => nvr.channel_count ?? 0,
              cell: (nvr) => <span className="text-sm">{nvr.channel_count}</span>,
            },
            {
              id: 'storage',
              header: t('NVRListPage.table.storage'),
              // Sort by storage utilization ratio (used / total); no storage sorts last.
              accessorFn: (nvr) =>
                nvr.storage_total_gb && nvr.storage_total_gb > 0
                  ? (nvr.storage_used_gb || 0) / nvr.storage_total_gb
                  : -1,
              cell: (nvr) => {
                const pct = nvr.storage_total_gb && nvr.storage_total_gb > 0
                  ? Math.round(((nvr.storage_used_gb || 0) / nvr.storage_total_gb) * 100)
                  : null;
                if (pct === null) return <span className="text-xs text-muted-foreground">-</span>;
                return (
                  <div className="flex items-center gap-2 min-w-[80px]">
                    <Progress value={pct} className={cn('h-1.5 flex-1', pct > 90 ? '[&>div]:bg-destructive' : pct > 75 ? '[&>div]:bg-warning' : '')} />
                    <span className="text-[10px] text-muted-foreground w-8">{pct}%</span>
                  </div>
                );
              },
            },
            {
              id: 'firmware',
              header: t('NVRListPage.table.firmware'),
              accessorFn: (nvr) => nvr.firmware_version ?? '',
              cell: (nvr) => (
                <span className="text-xs text-muted-foreground">{nvr.firmware_version || '-'}</span>
              ),
            },
            {
              id: 'synced',
              header: t('NVRListPage.table.lastSynced'),
              // Sort by epoch of last sync; never-synced sorts last (0).
              accessorFn: (nvr) => (nvr.last_synced_at ? new Date(nvr.last_synced_at).getTime() : 0),
              cell: (nvr) => (
                <span className="text-xs text-muted-foreground">
                  {nvr.last_synced_at ? new Date(nvr.last_synced_at).toLocaleDateString() : t('NVRListPage.table.never')}
                </span>
              ),
            },
            {
              id: 'actions',
              header: '',
              sortable: false,
              cell: (nvr) => (
                <div className="flex items-center justify-end">
                  <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                      <Button variant="ghost" size="icon" className="h-7 w-7">
                        <MoreHorizontal className="h-4 w-4" />
                      </Button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent align="end">
                      <DropdownMenuItem onClick={() => navigate(`/cameras/nvrs/${nvr.id}`)}>
                        <Settings className="h-4 w-4 mr-2" /> {t('NVRListPage.actions.viewDetails')}
                      </DropdownMenuItem>
                      <DropdownMenuItem onClick={() => syncMut.mutate(nvr.id)}>
                        <RefreshCw className="h-4 w-4 mr-2" /> {t('NVRListPage.actions.syncChannels')}
                      </DropdownMenuItem>
                      <DropdownMenuSeparator />
                      <DropdownMenuItem
                        className="text-destructive focus:text-destructive"
                        onClick={() => setDeleteTarget(nvr)}
                      >
                        <Trash2 className="h-4 w-4 mr-2" /> {t('NVRListPage.actions.delete')}
                      </DropdownMenuItem>
                    </DropdownMenuContent>
                  </DropdownMenu>
                </div>
              ),
            },
          ] satisfies DataTableColumn<NVRDevice>[]}
          isLoading={false}
          selectable
          onSelectionChange={setSelected}
          searchable={false}
          itemName={t('NVRListPage.table.itemName')}
          getRowId={(row) => row.id}
        />
      )}

      <BulkActionsBar
        selectedCount={selected.length}
        itemName={t('NVRListPage.bulk.itemName')}
        onClear={() => setSelected([])}
        actions={[
          {
            label: t('NVRListPage.bulk.syncAll'),
            icon: RefreshCw,
            onClick: () => {
              selected.forEach((n) => syncMut.mutate(n.id));
              setSelected([]);
            },
          },
          {
            label: t('NVRListPage.actions.delete'),
            icon: Trash2,
            variant: 'destructive',
            onClick: () => setBulkDeleteOpen(true),
          },
        ]}
      />

      {/* Add NVR Dialog */}
      <AddDeviceDialog
        open={addDialogOpen}
        onOpenChange={setAddDialogOpen}
        onSuccess={handleAddSuccess}
      />

      {/* Delete Confirmation */}
      <AlertDialog open={!!deleteTarget} onOpenChange={(open) => !open && setDeleteTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t('NVRListPage.deleteDialog.title')}</AlertDialogTitle>
            <AlertDialogDescription>
              {t('NVRListPage.deleteDialog.confirmPrefix')} <strong>{deleteTarget?.name}</strong> ({deleteTarget?.ip_address})?
              {' '}{t('NVRListPage.deleteDialog.confirmSuffix')}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={deleteMut.isPending}>{t('NVRListPage.deleteDialog.cancel')}</AlertDialogCancel>
            <AlertDialogAction
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
              disabled={deleteMut.isPending}
              onClick={() => deleteTarget && deleteMut.mutate(deleteTarget.id)}
            >
              {deleteMut.isPending ? t('NVRListPage.deleteDialog.deleting') : t('NVRListPage.deleteDialog.delete')}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Bulk Delete Confirmation */}
      <AlertDialog open={bulkDeleteOpen} onOpenChange={(open) => !open && setBulkDeleteOpen(false)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t('NVRListPage.deleteDialog.title')}</AlertDialogTitle>
            <AlertDialogDescription>
              {t('NVRListPage.deleteDialog.confirmPrefix')} <strong>{selected.length}</strong> {t('NVRListPage.bulk.itemName')}?
              {' '}{t('NVRListPage.deleteDialog.confirmSuffix')}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={bulkDeleteMut.isPending}>{t('NVRListPage.deleteDialog.cancel')}</AlertDialogCancel>
            <AlertDialogAction
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
              disabled={bulkDeleteMut.isPending}
              onClick={() => bulkDeleteMut.mutate(selected.map((n) => n.id))}
            >
              {bulkDeleteMut.isPending ? t('NVRListPage.deleteDialog.deleting') : t('NVRListPage.deleteDialog.delete')}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}

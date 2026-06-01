// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN · Controllers Management Page
 *
 * Reference implementation for the canonical design language.
 * Uses ONLY system primitives:
 *   <PageHeader>      from @/components/layout
 *   <PageToolbar>     from @/components/layout
 *   <StatsGrid>       from @/components/ui/stats-grid
 *   <StatusBadge>     from @/components/ui/status-indicator
 *   <TypeBadge>       from @/components/ui/type-badge
 *   <DataTable>       from @/components/ui/data-table  (self-wraps in Card)
 *   <BulkActionsBar>  from @/components/ui/bulk-actions-bar  (floating dark pill)
 *   <ErrorState>      from @/components/ui/empty-state
 */

import { useState, useCallback } from 'react';
import { useTranslation } from 'react-i18next';
import { useNavigate } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useSiteStore } from '@/stores/siteStore';
import {
  Plus,
  RefreshCw,
  Settings,
  Trash2,
  Wifi,
  WifiOff,
  Server,
  MoreHorizontal,
  Eye,
  TestTube,
  PowerOff,
  Download,
} from 'lucide-react';
import { DataTable, type DataTableColumn } from '@/components/ui/data-table';
import { Button } from '@/components/ui/button';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from '@/components/ui/tooltip';
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
import { SearchBar } from '@/components/ui/search-bar';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { StatsGrid } from '@/components/ui/stats-grid';
import { StatusBadge, type StatusVariant } from '@/components/ui/status-indicator';
import { TypeBadge } from '@/components/ui/type-badge';
import { BulkActionsBar } from '@/components/ui/bulk-actions-bar';
import { ErrorState } from '@/components/ui/empty-state';
import { PageHeader, PageToolbar } from '@/components/layout';
import { controllersApi } from '@/lib/api';
import { cn, formatRelativeTime } from '@/lib/utils';
import {
  AddControllerModal,
  EditControllerModal,
  DeleteControllerDialog,
} from '@/components/controllers';
import { useToast } from '@/hooks/use-toast';

// ───────────────────────────────────────────────────────────────────
// Types
// ───────────────────────────────────────────────────────────────────

interface Controller {
  id: string;
  name: string;
  description: string | null;
  controller_type: string;
  host: string;
  port: number;
  status: 'connected' | 'disconnected' | 'error' | 'syncing' | 'unreachable' | 'unknown';
  last_sync: string | null;
  last_error: string | null;
  is_active: boolean;
  use_ssl: boolean;
  verify_ssl: boolean;
  sync_enabled: boolean;
  sync_interval_seconds: number;
  site_id: string;
  device_count?: number;
  online_device_count?: number;
  config?: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

// Map controller status → canonical StatusBadge variant.
const CONTROLLER_STATUS_VARIANT: Record<Controller['status'], StatusVariant> = {
  connected: 'connected',
  disconnected: 'disconnected',
  error: 'error',
  syncing: 'syncing',
  unreachable: 'error',
  unknown: 'unknown',
};

// ───────────────────────────────────────────────────────────────────
// Page
// ───────────────────────────────────────────────────────────────────

export default function ControllersPage() {
  const { t } = useTranslation('controllers');
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const { toast } = useToast();

  // Modal/Dialog state
  const [isAddModalOpen, setIsAddModalOpen] = useState(false);
  const [editController, setEditController] = useState<Controller | null>(null);
  const [deleteController, setDeleteController] = useState<Controller | null>(null);
  const [selectedControllers, setSelectedControllers] = useState<Controller[]>([]);
  const [bulkDeleteOpen, setBulkDeleteOpen] = useState(false);
  const [syncingIds, setSyncingIds] = useState<Set<string>>(new Set());
  const [searchQuery, setSearchQuery] = useState('');
  const [typeFilter, setTypeFilter] = useState<string>('all');
  const [statusFilter, setStatusFilter] = useState<string>('all');

  const selectedSiteId = useSiteStore((s) => s.selectedSiteId);

  // ── Fetch ──
  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ['controllers', { siteId: selectedSiteId }],
    queryFn: async () => {
      const response = await controllersApi.getAll(selectedSiteId ?? undefined, 100);
      return response.data;
    },
    refetchInterval: 30000,
  });

  const allControllers: Controller[] = data?.items || [];

  // ── Filter ──
  const controllers = allControllers.filter((controller) => {
    if (searchQuery) {
      const query = searchQuery.toLowerCase();
      const description = controller.description?.toLowerCase() ?? '';
      const matches =
        controller.name.toLowerCase().includes(query) ||
        controller.host.toLowerCase().includes(query) ||
        controller.controller_type.toLowerCase().includes(query) ||
        description.includes(query);
      if (!matches) return false;
    }
    if (typeFilter !== 'all' && controller.controller_type !== typeFilter) return false;
    if (statusFilter !== 'all' && controller.status !== statusFilter) return false;
    return true;
  });

  // ── Stats from full (unfiltered) list ──
  // `total` reflects the server-side count (may exceed the fetched page), the
  // rest are derived from the loaded controllers.
  const stats = {
    total: data?.total ?? allControllers.length,
    connected: allControllers.filter((c) => c.status === 'connected').length,
    disconnected: allControllers.filter(
      (c) => c.status === 'disconnected' || c.status === 'error',
    ).length,
    devices: allControllers.reduce((sum, c) => sum + (c.device_count || 0), 0),
  };

  // ── Mutations ──
  const syncMutation = useMutation({
    mutationFn: async (id: string) => {
      setSyncingIds((prev) => new Set(prev).add(id));
      const response = await controllersApi.sync(id);
      return response.data;
    },
    onSuccess: () => {
      toast({
        title: t('ControllersPage.toast.syncStarted.title'),
        description: t('ControllersPage.toast.syncStarted.description'),
      });
      queryClient.invalidateQueries({ queryKey: ['controllers'] });
    },
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    onError: (err: any) => {
      toast({
        title: t('ControllersPage.toast.syncFailed.title'),
        description: err.response?.data?.detail || t('ControllersPage.toast.syncFailed.description'),
        variant: 'destructive',
      });
    },
    onSettled: (_, __, id) => {
      setSyncingIds((prev) => {
        const next = new Set(prev);
        next.delete(id);
        return next;
      });
    },
  });

  const testMutation = useMutation({
    mutationFn: async (id: string) => {
      const response = await controllersApi.test(id);
      return response.data;
    },
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['controllers'] });
      const details = data.details;
      const latency = details?.latency_ms != null ? `${details.latency_ms}ms` : '';
      const version = details?.controller_version ? ` | v${details.controller_version}` : '';

      if (data.success) {
        toast({
          title: t('ControllersPage.toast.connectionSuccessful.title'),
          description: `${data.message || t('ControllersPage.toast.connectionSuccessful.connected')}${latency ? ` | ${t('ControllersPage.toast.connectionSuccessful.latency', { latency })}` : ''}${version}`,
        });
      } else {
        toast({
          title: t('ControllersPage.toast.connectionFailed.title'),
          description: data.error || data.message || t('ControllersPage.toast.connectionFailed.description'),
          variant: 'destructive',
        });
      }
    },
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    onError: (err: any) => {
      toast({
        title: t('ControllersPage.toast.connectionTestFailed.title'),
        description: err.response?.data?.detail || err.message || t('ControllersPage.toast.connectionTestFailed.description'),
        variant: 'destructive',
      });
    },
  });

  const bulkSyncMutation = useMutation({
    mutationFn: async (ids: string[]) => {
      const results = await Promise.allSettled(
        ids.map((id) => controllersApi.sync(id)),
      );
      return results;
    },
    onSuccess: () => {
      toast({
        title: t('ControllersPage.toast.bulkSyncStarted.title'),
        description: t('ControllersPage.toast.bulkSyncStarted.description', {
          count: selectedControllers.length,
        }),
      });
      queryClient.invalidateQueries({ queryKey: ['controllers'] });
      setSelectedControllers([]);
    },
    onError: () => {
      toast({
        title: t('ControllersPage.toast.bulkSyncFailed.title'),
        description: t('ControllersPage.toast.bulkSyncFailed.description'),
        variant: 'destructive',
      });
    },
  });

  const bulkDeleteMutation = useMutation({
    mutationFn: async (ids: string[]) => {
      const results = await Promise.allSettled(
        ids.map((id) => controllersApi.delete(id)),
      );
      const succeeded = results.filter((r) => r.status === 'fulfilled').length;
      const failed = results.length - succeeded;
      return { succeeded, failed };
    },
    onSuccess: ({ succeeded, failed }) => {
      queryClient.invalidateQueries({ queryKey: ['controllers'] });
      setSelectedControllers([]);
      if (failed > 0) {
        toast({
          title: t('error', { ns: 'common' }),
          description: t('ControllersPage.toast.controllerDeleted.description') +
            ` (${succeeded} OK / ${failed} ✗)`,
          variant: 'destructive',
        });
      } else {
        toast({
          title: t('ControllersPage.toast.controllerDeleted.title'),
          description: t('ControllersPage.toast.controllerDeleted.description') +
            ` (${succeeded})`,
        });
      }
    },
    onError: () => {
      toast({
        title: t('error', { ns: 'common' }),
        description: t('internalServer', { ns: 'errors' }),
        variant: 'destructive',
      });
    },
  });

  // ── Handlers ──
  const handleSync = useCallback(
    (controller: Controller) => syncMutation.mutate(controller.id),
    [syncMutation],
  );
  const handleEdit = useCallback((controller: Controller) => setEditController(controller), []);
  const handleDelete = useCallback((controller: Controller) => setDeleteController(controller), []);
  const handleViewDetails = useCallback(
    (controller: Controller) => navigate(`/controllers/${controller.id}`),
    [navigate],
  );
  const handleBulkSync = useCallback(() => {
    bulkSyncMutation.mutate(selectedControllers.map((c) => c.id));
  }, [selectedControllers, bulkSyncMutation]);
  const handleConfirmBulkDelete = useCallback(() => {
    bulkDeleteMutation.mutate(selectedControllers.map((c) => c.id));
    setBulkDeleteOpen(false);
  }, [selectedControllers, bulkDeleteMutation]);
  const handleExport = useCallback(() => {
    const headers = [
      'name',
      'controller_type',
      'host',
      'port',
      'status',
      'is_active',
      'device_count',
      'online_device_count',
      'last_sync',
    ];
    const escape = (v: unknown) => {
      let s = v == null ? '' : String(v);
      // neutralize spreadsheet formula injection (=,+,-,@,tab,CR).
      if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
      return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
    };
    const rows = controllers.map((c) =>
      [
        c.name,
        c.controller_type,
        c.host,
        c.port,
        c.status,
        c.is_active,
        c.device_count ?? 0,
        c.online_device_count ?? 0,
        c.last_sync ?? '',
      ]
        .map(escape)
        .join(','),
    );
    const csv = [headers.join(','), ...rows].join('\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `controllers-${new Date().toISOString().slice(0, 10)}.csv`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }, [controllers]);
  const handleClearFilters = useCallback(() => {
    setSearchQuery('');
    setTypeFilter('all');
    setStatusFilter('all');
  }, []);

  const hasActiveFilters = searchQuery !== '' || typeFilter !== 'all' || statusFilter !== 'all';

  // ── Table columns ──
  const columns: DataTableColumn<Controller>[] = [
    {
      id: 'name',
      header: t('ControllersPage.columns.controller'),
      accessorKey: 'name',
      cell: (row) => (
        <div className="flex items-center gap-3">
          <div
            className={cn(
              'flex h-9 w-9 items-center justify-center rounded-lg flex-shrink-0',
              row.is_active ? 'bg-primary/10' : 'bg-muted',
            )}
          >
            <Server
              className={cn(
                'h-4 w-4',
                row.is_active ? 'text-primary' : 'text-muted-foreground',
              )}
            />
          </div>
          <div className="flex flex-col min-w-0">
            <button
              onClick={() => handleViewDetails(row)}
              className="font-medium text-foreground hover:text-primary hover:underline text-left truncate"
            >
              {row.name}
            </button>
            <span className="text-xs text-muted-foreground font-mono truncate">
              {row.host}:{row.port}
            </span>
          </div>
        </div>
      ),
    },
    {
      id: 'type',
      header: t('ControllersPage.columns.type'),
      accessorKey: 'controller_type',
      cell: (row) => <TypeBadge type={row.controller_type} />,
    },
    {
      id: 'status',
      header: t('ControllersPage.columns.status'),
      accessorKey: 'status',
      cell: (row) => (
        <div className="flex flex-col gap-1">
          <StatusBadge
            variant={
              syncingIds.has(row.id) ? 'syncing' : CONTROLLER_STATUS_VARIANT[row.status]
            }
          />
          {!row.is_active && (
            <span className="text-xs text-muted-foreground flex items-center gap-1">
              <PowerOff className="h-3 w-3" /> {t('ControllersPage.status.disabled')}
            </span>
          )}
        </div>
      ),
    },
    {
      id: 'devices',
      header: t('ControllersPage.columns.devices'),
      accessorFn: (row) => row.device_count || 0,
      cell: (row) => {
        const total = row.device_count || 0;
        const online = row.online_device_count || 0;
        const offline = total - online;
        return (
          <div className="flex items-center gap-1.5">
            <span className="inline-flex h-7 min-w-[28px] items-center justify-center rounded-md bg-muted px-1.5 text-sm font-medium">
              {total}
            </span>
            {total > 0 && (
              <div className="flex gap-1 text-xs">
                <span className="text-success font-medium">{online}</span>
                <span className="text-muted-foreground">/</span>
                <span
                  className={cn(
                    'font-medium',
                    offline > 0 ? 'text-destructive' : 'text-muted-foreground',
                  )}
                >
                  {offline}
                </span>
              </div>
            )}
          </div>
        );
      },
    },
    {
      id: 'version',
      header: t('ControllersPage.columns.version'),
      cell: (row) => {
        const runtime = (row.config as Record<string, unknown>)?.runtime_status as
          | Record<string, unknown>
          | undefined;
        const version = runtime?.version as string | undefined;
        return (
          <span className="text-sm text-muted-foreground font-mono">{version || '-'}</span>
        );
      },
    },
    {
      id: 'lastSync',
      header: t('ControllersPage.columns.lastSync'),
      accessorKey: 'last_sync',
      cell: (row) => {
        const syncDuration = (row.config as Record<string, unknown>)
          ?.last_sync_duration_seconds as number | undefined;
        const isStale =
          row.last_sync && Date.now() - new Date(row.last_sync).getTime() > 3600000;
        return (
          <div className="flex flex-col">
            <span
              className={cn(
                'text-sm font-medium',
                !row.last_sync
                  ? 'text-muted-foreground'
                  : isStale
                    ? 'text-warning'
                    : 'text-foreground',
              )}
            >
              {formatRelativeTime(row.last_sync)}
            </span>
            {syncDuration != null && (
              <span className="text-xs text-muted-foreground">
                {t('ControllersPage.lastSync.took', {
                  duration:
                    syncDuration < 60
                      ? `${syncDuration.toFixed(0)}s`
                      : `${(syncDuration / 60).toFixed(1)}m`,
                })}
              </span>
            )}
          </div>
        );
      },
    },
    {
      id: 'actions',
      header: '',
      sortable: false,
      cell: (row) => (
        <div className="flex items-center justify-end gap-1">
          <TooltipProvider>
            <Tooltip>
              <TooltipTrigger asChild>
                <Button
                  variant="ghost"
                  size="icon"
                  className="h-8 w-8"
                  onClick={() => handleSync(row)}
                  disabled={syncingIds.has(row.id)}
                  aria-label={t('ControllersPage.actions.syncAria', { name: row.name })}
                >
                  <RefreshCw
                    className={cn('h-4 w-4', syncingIds.has(row.id) && 'animate-spin')}
                  />
                </Button>
              </TooltipTrigger>
              <TooltipContent>{t('ControllersPage.actions.syncNow')}</TooltipContent>
            </Tooltip>
          </TooltipProvider>

          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button
                variant="ghost"
                size="icon"
                className="h-8 w-8"
                aria-label={t('ControllersPage.actions.menuAria', { name: row.name })}
              >
                <MoreHorizontal className="h-4 w-4" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-48">
              <DropdownMenuLabel>{t('ControllersPage.actions.label')}</DropdownMenuLabel>
              <DropdownMenuSeparator />
              <DropdownMenuItem onClick={() => handleViewDetails(row)}>
                <Eye className="mr-2 h-4 w-4" />
                {t('ControllersPage.actions.viewDetails')}
              </DropdownMenuItem>
              <DropdownMenuItem onClick={() => handleEdit(row)}>
                <Settings className="mr-2 h-4 w-4" />
                {t('ControllersPage.actions.editSettings')}
              </DropdownMenuItem>
              <DropdownMenuItem onClick={() => handleSync(row)}>
                <RefreshCw className="mr-2 h-4 w-4" />
                {t('ControllersPage.actions.syncNow')}
              </DropdownMenuItem>
              <DropdownMenuItem onClick={() => testMutation.mutate(row.id)}>
                <TestTube className="mr-2 h-4 w-4" />
                {t('ControllersPage.actions.testConnection')}
              </DropdownMenuItem>
              <DropdownMenuSeparator />
              <DropdownMenuItem
                onClick={() => handleDelete(row)}
                className="text-destructive focus:text-destructive"
              >
                <Trash2 className="mr-2 h-4 w-4" />
                {t('ControllersPage.actions.delete')}
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      ),
    },
  ];

  if (error) {
    return (
      <div className="space-y-6">
        <PageHeader
          icon={Server}
          title={t('ControllersPage.header.title')}
          description={t('ControllersPage.header.description')}
        />
        <ErrorState
          message={error instanceof Error ? error.message : t('ControllersPage.error.loadFailed')}
          onRetry={() => refetch()}
        />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <PageHeader
        icon={Server}
        title={t('ControllersPage.header.title')}
        description={t('ControllersPage.header.description')}
        onRefresh={() => refetch()}
        refreshing={isLoading}
        secondaryActions={[
          { label: t('ControllersPage.actions.export'), icon: Download, onClick: handleExport },
        ]}
        primaryAction={{
          label: t('ControllersPage.actions.addController'),
          icon: Plus,
          onClick: () => setIsAddModalOpen(true),
        }}
      />

      {/* Stats */}
      <StatsGrid
        columns={4}
        isLoading={isLoading}
        stats={[
          {
            title: t('ControllersPage.stats.totalControllers.title'),
            value: stats.total,
            icon: Server,
            variant: 'default',
            description: t('ControllersPage.stats.totalControllers.description'),
          },
          {
            title: t('ControllersPage.stats.connected.title'),
            value: stats.connected,
            icon: Wifi,
            variant: 'success',
            description:
              stats.total > 0
                ? t('ControllersPage.stats.connected.percentOnline', {
                    percent: Math.round((stats.connected / stats.total) * 100),
                  })
                : t('ControllersPage.stats.connected.noControllers'),
          },
          {
            title: t('ControllersPage.stats.disconnected.title'),
            value: stats.disconnected,
            icon: WifiOff,
            variant: 'destructive',
            description: t('ControllersPage.stats.disconnected.description'),
          },
          {
            title: t('ControllersPage.stats.totalDevices.title'),
            value: stats.devices,
            icon: Settings,
            variant: 'default',
            description: t('ControllersPage.stats.totalDevices.description'),
          },
        ]}
      />

      {/* Toolbar */}
      <PageToolbar>
        <SearchBar
          value={searchQuery}
          onChange={setSearchQuery}
          placeholder={t('ControllersPage.filters.searchPlaceholder')}
          className="w-full sm:w-auto"
        />
        <Select value={typeFilter} onValueChange={setTypeFilter}>
          <SelectTrigger className="w-full sm:w-[180px]">
            <SelectValue placeholder={t('ControllersPage.filters.allTypes')} />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">{t('ControllersPage.filters.allTypes')}</SelectItem>
            <SelectItem value="omada">TP-Link Omada</SelectItem>
            <SelectItem value="unifi">Ubiquiti UniFi</SelectItem>
            <SelectItem value="opnsense">OPNsense</SelectItem>
            <SelectItem value="proxmox">Proxmox VE</SelectItem>
            <SelectItem value="truenas">TrueNAS</SelectItem>
            <SelectItem value="hikvision">HikVision</SelectItem>
            <SelectItem value="axis">Axis</SelectItem>
            <SelectItem value="generic_onvif">ONVIF</SelectItem>
          </SelectContent>
        </Select>
        <Select value={statusFilter} onValueChange={setStatusFilter}>
          <SelectTrigger className="w-full sm:w-[160px]">
            <SelectValue placeholder={t('ControllersPage.filters.allStatuses')} />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">{t('ControllersPage.filters.allStatuses')}</SelectItem>
            <SelectItem value="connected">{t('ControllersPage.statusLabels.connected')}</SelectItem>
            <SelectItem value="disconnected">{t('ControllersPage.statusLabels.disconnected')}</SelectItem>
            <SelectItem value="error">{t('ControllersPage.statusLabels.error')}</SelectItem>
            <SelectItem value="syncing">{t('ControllersPage.statusLabels.syncing')}</SelectItem>
            <SelectItem value="unreachable">{t('ControllersPage.statusLabels.unreachable')}</SelectItem>
          </SelectContent>
        </Select>
        {hasActiveFilters && (
          <Button variant="ghost" size="sm" onClick={handleClearFilters}>
            {t('ControllersPage.filters.clearFilters')}
          </Button>
        )}
      </PageToolbar>

      {/* Data Table · self-wraps in Card */}
      <DataTable
        data={controllers}
        columns={columns}
        isLoading={isLoading}
        selectable
        onSelectionChange={setSelectedControllers}
        searchable={false}
        itemName={t('ControllersPage.itemNamePlural')}
        getRowId={(row) => row.id}
      />

      {/* Bulk Actions · floating dark pill */}
      <BulkActionsBar
        selectedCount={selectedControllers.length}
        itemName={t('ControllersPage.itemNameSingular')}
        onClear={() => setSelectedControllers([])}
        actions={[
          {
            label: t('ControllersPage.bulkActions.syncAll'),
            icon: RefreshCw,
            onClick: handleBulkSync,
          },
          {
            label: t('ControllersPage.bulkActions.delete'),
            icon: Trash2,
            variant: 'destructive',
            disabled: bulkDeleteMutation.isPending,
            onClick: () => setBulkDeleteOpen(true),
          },
        ]}
      />

      {/* Modals */}
      <AddControllerModal open={isAddModalOpen} onOpenChange={setIsAddModalOpen} />
      <EditControllerModal
        controller={editController}
        open={!!editController}
        onOpenChange={(open) => !open && setEditController(null)}
      />
      <DeleteControllerDialog
        controller={deleteController}
        open={!!deleteController}
        onOpenChange={(open) => !open && setDeleteController(null)}
        onSuccess={() => {
          toast({
            title: t('ControllersPage.toast.controllerDeleted.title'),
            description: t('ControllersPage.toast.controllerDeleted.description'),
          });
        }}
      />

      {/* Bulk delete confirmation */}
      <AlertDialog open={bulkDeleteOpen} onOpenChange={setBulkDeleteOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t('ControllersPage.bulkActions.delete')}</AlertDialogTitle>
            <AlertDialogDescription>
              {t('ControllersPage.itemNamePlural')}: {selectedControllers.length}
              {t('DeleteControllerDialog.confirmPrompt.after', { ns: 'common' })}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t('cancel', { ns: 'common' })}</AlertDialogCancel>
            <AlertDialogAction
              onClick={handleConfirmBulkDelete}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              {t('delete', { ns: 'common' })}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}

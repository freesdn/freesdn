// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN - Gateway List Page
 *
 * Lists all firewall gateway integrations (OPNsense, pfSense, MikroTik).
 * Provides summary stats, vendor filtering, and quick actions.
 */

import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useSiteStore } from '@/stores/siteStore';
import { useNavigate } from 'react-router-dom';
import {
  Server,
  Plus,
  RefreshCw,
  Wifi,
  WifiOff,
  CheckCircle,
  AlertCircle,
  AlertTriangle,
  MoreHorizontal,
  Trash2,
  Eye,
  Zap,
  Network,
  Clock,
  Circle,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { DataTable, type DataTableColumn } from '@/components/ui/data-table';
import { Badge } from '@/components/ui/badge';
import { StatsGrid } from '@/components/ui/stats-grid';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
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
import { PageHeader } from '@/components/layout';
import { useToast } from '@/hooks/use-toast';
import { gatewayApi, type GatewayConnection, type GatewaySummary } from '@/lib/api';


// ─── Vendor display helpers ────────────────────────────────────────────

const vendorMeta: Record<string, { label: string; color: string }> = {
  opnsense: { label: 'OPNsense', color: 'text-orange-500' },
  pfsense:  { label: 'pfSense',  color: 'text-blue-500' },
  mikrotik: { label: 'MikroTik', color: 'text-sky-500' },
  openwrt:  { label: 'OpenWRT',  color: 'text-green-500' },
};

const syncStatusBadge: Record<string, { labelKey: string; variant: 'default' | 'secondary' | 'destructive' | 'outline' }> = {
  idle:    { labelKey: 'idle',    variant: 'secondary' },
  syncing: { labelKey: 'syncing', variant: 'default' },
  success: { labelKey: 'success', variant: 'default' },
  failed:  { labelKey: 'failed',  variant: 'destructive' },
  never:   { labelKey: 'never',   variant: 'outline' },
};

function VendorBadge({ vendor }: { vendor: string }) {
  const meta = vendorMeta[vendor] ?? { label: vendor, color: 'text-muted-foreground' };
  return (
    <Badge variant="outline" className="gap-1.5 font-medium">
      <Circle className={cn('h-2.5 w-2.5 fill-current', meta.color)} aria-hidden="true" />
      <span className={meta.color}>{meta.label}</span>
    </Badge>
  );
}

function OnlineIndicator({ isOnline }: { isOnline?: boolean }) {
  const { t } = useTranslation('firewall');
  if (isOnline === true) {
    return <span className="flex items-center gap-1.5 text-sm text-green-600 dark:text-green-400"><Wifi className="h-3.5 w-3.5" /> {t('GatewayListPage.status.online')}</span>;
  }
  if (isOnline === false) {
    return <span className="flex items-center gap-1.5 text-sm text-red-500"><WifiOff className="h-3.5 w-3.5" /> {t('GatewayListPage.status.offline')}</span>;
  }
  return <span className="flex items-center gap-1.5 text-sm text-muted-foreground"><AlertCircle className="h-3.5 w-3.5" /> {t('GatewayListPage.status.unknown')}</span>;
}

// ─── Component ─────────────────────────────────────────────────────────

export default function GatewayListPage() {
  const { t } = useTranslation('firewall');
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const [vendorFilter, setVendorFilter] = useState<string>('all');
  const [deleteTarget, setDeleteTarget] = useState<GatewayConnection | null>(null);

  // Site context
  const selectedSiteId = useSiteStore((s) => s.selectedSiteId);

  // ─── Queries ──────────────────────────────────────────────────────

  const { data: summaryData, isError: isSummaryError } = useQuery({
    queryKey: ['gateways', 'summary', { siteId: selectedSiteId }],
    queryFn: () => gatewayApi.getSummary(),
    refetchInterval: 30_000,
  });

  const summary: GatewaySummary = summaryData?.data ?? {
    total_gateways: 0, online: 0, offline: 0,
    sync_idle: 0, sync_success: 0, sync_failed: 0, sync_never: 0,
    by_vendor: {},
  };

  const { data: gatewaysData, isLoading, isError: isGatewaysError } = useQuery({
    queryKey: ['gateways', 'list', vendorFilter, { siteId: selectedSiteId }],
    queryFn: () => gatewayApi.getAll({
      vendor: vendorFilter !== 'all' ? vendorFilter : undefined,
      limit: 100,
      ...(selectedSiteId ? { site_id: selectedSiteId } : {}),
    }),
    refetchInterval: 30_000,
  });

  const gateways: GatewayConnection[] = gatewaysData?.data?.items ?? [];

  const hasQueryError = isSummaryError || isGatewaysError;

  // ─── Mutations ────────────────────────────────────────────────────

  const deleteMutation = useMutation({
    mutationFn: (id: string) => gatewayApi.delete(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['gateways'] });
      toast({ title: t('GatewayListPage.toasts.deleted.title'), description: t('GatewayListPage.toasts.deleted.description') });
      setDeleteTarget(null);
    },
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    onError: (err: any) => {
      toast({ title: t('GatewayListPage.toasts.error'), description: err?.response?.data?.detail || t('GatewayListPage.toasts.deleteFailed'), variant: 'destructive' });
    },
  });

  const syncMutation = useMutation({
    mutationFn: (id: string) => gatewayApi.triggerSync(id, false),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['gateways'] });
      toast({ title: t('GatewayListPage.toasts.syncStarted.title'), description: t('GatewayListPage.toasts.syncStarted.description') });
    },
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    onError: (err: any) => {
      toast({ title: t('GatewayListPage.toasts.syncFailed.title'), description: err?.response?.data?.detail || t('GatewayListPage.toasts.syncFailed.description'), variant: 'destructive' });
    },
  });

  const testMutation = useMutation({
    mutationFn: (id: string) => gatewayApi.testExisting(id),
    onSuccess: (res) => {
      const r = res.data;
      if (r.success) {
        toast({
          title: t('GatewayListPage.toasts.connectionOk.title'),
          description: t('GatewayListPage.toasts.connectionOk.description', {
            hostname: r.hostname || t('GatewayListPage.gatewayFallback'),
            version: r.version || '',
            latency: r.latency_ms,
          }),
        });
      } else {
        toast({ title: t('GatewayListPage.toasts.connectionFailed.title'), description: r.message, variant: 'destructive' });
      }
      queryClient.invalidateQueries({ queryKey: ['gateways'] });
    },
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    onError: (err: any) => {
      toast({ title: t('GatewayListPage.toasts.testFailed.title'), description: err?.response?.data?.detail || t('GatewayListPage.toasts.testFailed.description'), variant: 'destructive' });
    },
  });

  // ─── Table columns ───────────────────────────────────────────────

  const columns: DataTableColumn<GatewayConnection>[] = [
    {
      id: 'name',
      header: t('GatewayListPage.columns.gateway'),
      accessorKey: 'name',
      sortable: true,
      cell: (row) => (
        <button
          className="text-left group"
          onClick={() => navigate(`/firewall/gateways/${row.id}`)}
        >
          <div className="font-medium group-hover:text-primary transition-colors">{row.name}</div>
          <div className="text-xs text-muted-foreground">{row.host}:{row.port}</div>
        </button>
      ),
    },
    {
      id: 'vendor',
      header: t('GatewayListPage.columns.platform'),
      accessorKey: 'vendor',
      sortable: true,
      cell: (row) => <VendorBadge vendor={row.vendor} />,
    },
    {
      id: 'status',
      header: t('GatewayListPage.columns.status'),
      accessorKey: 'is_online',
      cell: (row) => <OnlineIndicator isOnline={row.is_online} />,
    },
    {
      id: 'version',
      header: t('GatewayListPage.columns.version'),
      accessorFn: (row) => row.detected_version ?? '-',
      cell: (row) => (
        <div className="text-sm">
          <div>{row.detected_hostname || '-'}</div>
          <div className="text-xs text-muted-foreground">{row.detected_version || ''}</div>
        </div>
      ),
    },
    {
      id: 'sync',
      header: t('GatewayListPage.columns.sync'),
      accessorKey: 'sync_status',
      cell: (row) => {
        const meta = syncStatusBadge[row.sync_status] ?? syncStatusBadge.never;
        return (
          <div className="space-y-0.5">
            <Badge variant={meta.variant} className="text-xs">{t(`GatewayListPage.syncStatus.${meta.labelKey}`)}</Badge>
            {row.last_sync_at && (
              <div className="text-[11px] text-muted-foreground flex items-center gap-1">
                <Clock className="h-3 w-3" />
                {new Date(row.last_sync_at).toLocaleString()}
              </div>
            )}
          </div>
        );
      },
    },
    {
      id: 'actions',
      header: '',
      cell: (row) => (
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" size="icon" className="h-8 w-8">
              <MoreHorizontal className="h-4 w-4" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end">
            <DropdownMenuItem onClick={() => navigate(`/firewall/gateways/${row.id}`)}>
              <Eye className="h-4 w-4 mr-2" /> {t('GatewayListPage.actions.viewDetails')}
            </DropdownMenuItem>
            <DropdownMenuItem onClick={() => testMutation.mutate(row.id)}>
              <Zap className="h-4 w-4 mr-2" /> {t('GatewayListPage.actions.testConnection')}
            </DropdownMenuItem>
            <DropdownMenuItem onClick={() => syncMutation.mutate(row.id)}>
              <RefreshCw className="h-4 w-4 mr-2" /> {t('GatewayListPage.actions.syncNow')}
            </DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem className="text-destructive" onClick={() => setDeleteTarget(row)}>
              <Trash2 className="h-4 w-4 mr-2" /> {t('GatewayListPage.actions.delete')}
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      ),
    },
  ];

  // ─── Render ───────────────────────────────────────────────────────

  return (
    <div className="space-y-6">
      <PageHeader
        icon={Server}
        title={t('GatewayListPage.header.title')}
        subtitle={t('GatewayListPage.header.subtitle')}
        actions={
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="icon"
              onClick={() => queryClient.invalidateQueries({ queryKey: ['gateways'] })}
            >
              <RefreshCw className="h-4 w-4" />
            </Button>
            <Button onClick={() => navigate('/firewall/gateways/add')}>
              <Plus className="h-4 w-4 mr-2" />
              {t('GatewayListPage.actions.addGateway')}
            </Button>
          </div>
        }
      />

      {hasQueryError && (
        <Card className="border-destructive">
          <CardContent noOffset className="p-4 flex items-center gap-3">
            <AlertTriangle className="h-5 w-5 text-destructive" />
            <span className="text-sm">{t('GatewayListPage.errors.partialLoad')}</span>
          </CardContent>
        </Card>
      )}

      {/* Summary stats */}
      <StatsGrid
        columns={4}
        stats={[
          {
            title: t('GatewayListPage.stats.totalGateways'),
            value: summary.total_gateways,
            icon: Server,
            variant: 'primary',
          },
          {
            title: t('GatewayListPage.stats.online'),
            value: summary.online,
            icon: CheckCircle,
            variant: 'success',
            description: summary.offline > 0 ? t('GatewayListPage.stats.offlineCount', { count: summary.offline }) : t('GatewayListPage.stats.allReachable'),
          },
          {
            title: t('GatewayListPage.stats.syncOk'),
            value: summary.sync_success,
            icon: RefreshCw,
            variant: 'primary',
            description: summary.sync_failed > 0 ? t('GatewayListPage.stats.failedCount', { count: summary.sync_failed }) : undefined,
          },
          {
            title: t('GatewayListPage.stats.platforms'),
            value: Object.keys(summary.by_vendor).length,
            icon: Network,
            variant: 'primary',
            description:
              Object.entries(summary.by_vendor)
                .map(([v, c]) => `${vendorMeta[v]?.label ?? v}: ${c}`)
                .join(', ') || t('GatewayListPage.stats.noGateways'),
          },
        ]}
      />

      {/* Gateway table */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle>{t('GatewayListPage.table.title')}</CardTitle>
              <CardDescription>
                {t('GatewayListPage.table.description')}
              </CardDescription>
            </div>
            <div className="flex items-center gap-2">
              <Select value={vendorFilter} onValueChange={setVendorFilter}>
                <SelectTrigger className="w-[160px]">
                  <SelectValue placeholder={t('GatewayListPage.filter.allPlatforms')} />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">{t('GatewayListPage.filter.allPlatforms')}</SelectItem>
                  <SelectItem value="opnsense">OPNsense</SelectItem>
                  <SelectItem value="pfsense">pfSense</SelectItem>
                  <SelectItem value="mikrotik">MikroTik</SelectItem>
                  <SelectItem value="openwrt">OpenWRT</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
        </CardHeader>
        <DataTable
          data={gateways}
          columns={columns}
          isLoading={isLoading}
          searchable
          searchPlaceholder={t('GatewayListPage.table.searchPlaceholder')}
          embedded
        />
      </Card>

      {/* Delete confirmation */}
      <AlertDialog open={!!deleteTarget} onOpenChange={() => setDeleteTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t('GatewayListPage.dialogs.delete.title')}</AlertDialogTitle>
            <AlertDialogDescription>
              {t('GatewayListPage.dialogs.delete.confirmPrefix')} <strong>{deleteTarget?.name}</strong>{t('GatewayListPage.dialogs.delete.confirmSuffix')}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t('GatewayListPage.dialogs.delete.cancel')}</AlertDialogCancel>
            <AlertDialogAction
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
              onClick={() => deleteTarget && deleteMutation.mutate(deleteTarget.id)}
            >
              {t('GatewayListPage.dialogs.delete.confirm')}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}

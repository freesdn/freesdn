// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN · Network Clients Page
 *
 * Canonical list-page pattern (matches ControllersPage):
 * PageHeader → StatsGrid → PageToolbar → DataTable → BulkActionsBar
 */

import { useState, useCallback } from 'react';
import { useTranslation } from 'react-i18next';
import type { TFunction } from 'i18next';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useSiteStore } from '@/stores/siteStore';
import {
  Monitor,
  Wifi,
  Cable,
  MoreHorizontal,
  Ban,
  CheckCircle,
  Activity,
  Download,
  Upload,
  Users,
} from 'lucide-react';
import { DataTable, type DataTableColumn } from '@/components/ui/data-table';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { SearchBar } from '@/components/ui/search-bar';
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
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from '@/components/ui/sheet';
import { StatsGrid } from '@/components/ui/stats-grid';
import { StatusBadge } from '@/components/ui/status-indicator';
import { BulkActionsBar } from '@/components/ui/bulk-actions-bar';
import { ErrorState } from '@/components/ui/empty-state';
import { PageHeader, PageToolbar } from '@/components/layout';
import { networkApi, type NetworkClient } from '@/lib/api';
import { cn } from '@/lib/utils';
import { useToast } from '@/hooks/use-toast';

// ───────────────────────────────────────────────────────────────────
// Helpers
// ───────────────────────────────────────────────────────────────────

function ClientIcon({ className }: { className?: string }) {
  return <Monitor className={cn('h-4 w-4', className)} />;
}

function ConnectionBadge({ type }: { type: string }) {
  const { t } = useTranslation('network');
  const isWireless = type === 'wireless';
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-medium',
        isWireless
          ? 'bg-info/10 text-info border-info/20'
          : 'bg-primary/10 text-primary border-primary/20',
      )}
    >
      {isWireless ? <Wifi className="h-3 w-3" /> : <Cable className="h-3 w-3" />}
      {isWireless
        ? t('NetworkClientsPage.connection.wireless')
        : t('NetworkClientsPage.connection.wired')}
    </span>
  );
}

function SignalStrength({ strength }: { strength?: number | null }) {
  if (strength === undefined || strength === null) {
    return <span className="text-muted-foreground">-</span>;
  }
  const getLevel = (dbm: number) => {
    if (dbm >= -50) return { tone: 'success', bars: 4 };
    if (dbm >= -60) return { tone: 'success', bars: 3 };
    if (dbm >= -70) return { tone: 'warning', bars: 2 };
    return { tone: 'destructive', bars: 1 };
  };
  const { tone, bars } = getLevel(strength);
  const fillClass =
    tone === 'success' ? 'bg-success' : tone === 'warning' ? 'bg-warning' : 'bg-destructive';
  const textClass =
    tone === 'success' ? 'text-success' : tone === 'warning' ? 'text-warning' : 'text-destructive';
  return (
    <div className="flex items-center gap-2">
      <div className="flex items-end gap-0.5 h-4">
        {[1, 2, 3, 4].map((bar) => (
          <div
            key={bar}
            className={cn('w-1 rounded-sm', bar <= bars ? fillClass : 'bg-muted')}
            style={{ height: `${bar * 25}%` }}
          />
        ))}
      </div>
      <span className={cn('text-xs', textClass)}>{strength} dBm</span>
    </div>
  );
}

function formatBytes(bytes: number): string {
  if (!bytes) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
}

function formatTimeAgo(t: TFunction, timestamp?: string): string {
  if (!timestamp) return t('NetworkClientsPage.timeAgo.never');
  const date = new Date(timestamp);
  const diff = Date.now() - date.getTime();
  const minutes = Math.floor(diff / 60000);
  const hours = Math.floor(diff / 3600000);
  const days = Math.floor(diff / 86400000);
  if (minutes < 1) return t('NetworkClientsPage.timeAgo.justNow');
  if (minutes < 60) return t('NetworkClientsPage.timeAgo.minutes', { value: minutes });
  if (hours < 24) return t('NetworkClientsPage.timeAgo.hours', { value: hours });
  return t('NetworkClientsPage.timeAgo.days', { value: days });
}

// ───────────────────────────────────────────────────────────────────
// Client details sheet
// ───────────────────────────────────────────────────────────────────

function ClientDetailsSheet({
  client,
  open,
  onOpenChange,
}: {
  client?: NetworkClient;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const { t } = useTranslation('network');
  if (!client) return null;
  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent className="sm:max-w-lg">
        <SheetHeader>
          <SheetTitle className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-muted">
              <ClientIcon className="h-6 w-6 text-muted-foreground" />
            </div>
            {client.display_name || client.hostname || client.mac_address}
          </SheetTitle>
          <SheetDescription>{t('NetworkClientsPage.sheet.description')}</SheetDescription>
        </SheetHeader>

        <div className="mt-6 space-y-6">
          <div className="space-y-4">
            <h4 className="text-sm font-medium text-muted-foreground">
              {t('NetworkClientsPage.sheet.connectionInfo')}
            </h4>
            <div className="grid grid-cols-2 gap-4">
              <div>
                <p className="text-xs text-muted-foreground">
                  {t('NetworkClientsPage.fields.status')}
                </p>
                <StatusBadge
                  variant={
                    client.blocked
                      ? 'error'
                      : client.status === 'online'
                        ? 'online'
                        : client.status === 'offline'
                          ? 'offline'
                          : 'unknown'
                  }
                >
                  {client.blocked ? t('NetworkClientsPage.status.blocked') : client.status}
                </StatusBadge>
              </div>
              <div>
                <p className="text-xs text-muted-foreground">
                  {t('NetworkClientsPage.fields.connection')}
                </p>
                <ConnectionBadge type={client.connection_type} />
              </div>
              <div>
                <p className="text-xs text-muted-foreground">
                  {t('NetworkClientsPage.fields.ipAddress')}
                </p>
                <p className="font-mono text-sm">{client.ip_address || '-'}</p>
              </div>
              <div>
                <p className="text-xs text-muted-foreground">
                  {t('NetworkClientsPage.fields.macAddress')}
                </p>
                <p className="font-mono text-sm">{client.mac_address}</p>
              </div>
              {client.ssid && (
                <div>
                  <p className="text-xs text-muted-foreground">
                    {t('NetworkClientsPage.fields.ssid')}
                  </p>
                  <p className="text-sm">{client.ssid}</p>
                </div>
              )}
              {client.signal_strength !== undefined && (
                <div>
                  <p className="text-xs text-muted-foreground">
                    {t('NetworkClientsPage.fields.signal')}
                  </p>
                  <SignalStrength strength={client.signal_strength} />
                </div>
              )}
            </div>
          </div>

          <div className="space-y-4">
            <h4 className="text-sm font-medium text-muted-foreground">
              {t('NetworkClientsPage.sheet.deviceInfo')}
            </h4>
            <div className="grid grid-cols-2 gap-4">
              <div>
                <p className="text-xs text-muted-foreground">
                  {t('NetworkClientsPage.fields.hostname')}
                </p>
                <p className="text-sm">{client.hostname || '-'}</p>
              </div>
              <div>
                <p className="text-xs text-muted-foreground">
                  {t('NetworkClientsPage.fields.firstSeen')}
                </p>
                <p className="text-sm">{formatTimeAgo(t, client.first_seen)}</p>
              </div>
              <div>
                <p className="text-xs text-muted-foreground">
                  {t('NetworkClientsPage.fields.lastSeen')}
                </p>
                <p className="text-sm">{formatTimeAgo(t, client.last_seen)}</p>
              </div>
            </div>
          </div>

          <div className="space-y-4">
            <h4 className="text-sm font-medium text-muted-foreground">
              {t('NetworkClientsPage.sheet.trafficStatistics')}
            </h4>
            <div className="grid grid-cols-2 gap-4">
              <Card>
                <CardContent noOffset>
                  <div className="flex items-center gap-2">
                    <Download className="h-4 w-4 text-success" />
                    <div>
                      <p className="text-xs text-muted-foreground">
                        {t('NetworkClientsPage.traffic.downloaded')}
                      </p>
                      <p className="text-lg font-bold">{formatBytes(client.rx_bytes)}</p>
                    </div>
                  </div>
                </CardContent>
              </Card>
              <Card>
                <CardContent noOffset>
                  <div className="flex items-center gap-2">
                    <Upload className="h-4 w-4 text-info" />
                    <div>
                      <p className="text-xs text-muted-foreground">
                        {t('NetworkClientsPage.traffic.uploaded')}
                      </p>
                      <p className="text-lg font-bold">{formatBytes(client.tx_bytes)}</p>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </div>
          </div>
        </div>
      </SheetContent>
    </Sheet>
  );
}

// ───────────────────────────────────────────────────────────────────
// Page
// ───────────────────────────────────────────────────────────────────

export default function NetworkClientsPage() {
  const { t } = useTranslation('network');
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const selectedSiteId = useSiteStore((s) => s.selectedSiteId);

  const [searchQuery, setSearchQuery] = useState('');
  const [connectionFilter, setConnectionFilter] = useState<string>('all');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [selectedClient, setSelectedClient] = useState<NetworkClient | undefined>();
  const [blockingClient, setBlockingClient] = useState<NetworkClient | undefined>();
  const [selected, setSelected] = useState<NetworkClient[]>([]);

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ['network-clients', { siteId: selectedSiteId }],
    queryFn: () => networkApi.clients.list({ site_id: selectedSiteId ?? undefined, limit: 500 }),
  });

  const allClients: NetworkClient[] = data?.data?.items || [];

  const clients = allClients.filter((c) => {
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      const hay =
        (c.display_name || '').toLowerCase() +
        ' ' +
        (c.hostname || '').toLowerCase() +
        ' ' +
        c.mac_address.toLowerCase() +
        ' ' +
        (c.ip_address || '').toLowerCase();
      if (!hay.includes(q)) return false;
    }
    if (connectionFilter !== 'all' && c.connection_type !== connectionFilter) return false;
    if (statusFilter !== 'all' && c.status !== statusFilter) return false;
    return true;
  });

  const stats = {
    total: allClients.length,
    online: allClients.filter((c) => c.status === 'online').length,
    wireless: allClients.filter((c) => c.connection_type === 'wireless').length,
    wired: allClients.filter((c) => c.connection_type === 'wired').length,
  };

  const blockMutation = useMutation({
    mutationFn: ({ id, block }: { id: string; block: boolean }) =>
      block ? networkApi.clients.block(id) : networkApi.clients.unblock(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['network-clients'] });
      setBlockingClient(undefined);
      toast({ title: t('NetworkClientsPage.toast.clientUpdated') });
    },
    onError: () =>
      toast({ title: t('NetworkClientsPage.toast.actionFailed'), variant: 'destructive' }),
  });

  const handleClearFilters = useCallback(() => {
    setSearchQuery('');
    setConnectionFilter('all');
    setStatusFilter('all');
  }, []);

  const hasActiveFilters =
    searchQuery !== '' || connectionFilter !== 'all' || statusFilter !== 'all';

  // Export (client-side CSV from loaded/filtered rows)
  const handleExport = useCallback(() => {
    const rows = clients;
    if (rows.length === 0) return;
    const headers = [
      'name',
      'hostname',
      'mac_address',
      'ip_address',
      'connection_type',
      'ssid',
      'status',
      'blocked',
      'signal_strength',
      'rx_bytes',
      'tx_bytes',
      'first_seen',
      'last_seen',
    ];
    const esc = (val: unknown) => {
      const s = val === undefined || val === null ? '' : String(val);
      return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
    };
    const csv = [
      headers.join(','),
      ...rows.map((c) =>
        [
          c.display_name || c.hostname || c.mac_address,
          c.hostname ?? '',
          c.mac_address,
          c.ip_address ?? '',
          c.connection_type,
          c.ssid ?? '',
          c.status,
          c.blocked,
          c.signal_strength ?? '',
          c.rx_bytes,
          c.tx_bytes,
          c.first_seen ?? '',
          c.last_seen ?? '',
        ]
          .map(esc)
          .join(','),
      ),
    ].join('\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `network-clients-${new Date().toISOString().slice(0, 10)}.csv`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }, [clients]);

  const columns: DataTableColumn<NetworkClient>[] = [
    {
      id: 'client',
      header: t('NetworkClientsPage.columns.client'),
      cell: (client) => (
        <div className="flex items-center gap-3">
          <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-muted">
            <ClientIcon className="h-5 w-5 text-muted-foreground" />
          </div>
          <div className="min-w-0">
            <button
              onClick={() => setSelectedClient(client)}
              className="font-medium text-foreground hover:text-primary hover:underline text-left truncate"
            >
              {client.display_name || client.hostname || client.mac_address}
            </button>
            {client.ip_address && (
              <div className="text-xs text-muted-foreground truncate">{client.ip_address}</div>
            )}
          </div>
        </div>
      ),
    },
    {
      id: 'status',
      header: t('NetworkClientsPage.columns.status'),
      cell: (client) => (
        <StatusBadge
          variant={
            client.blocked
              ? 'error'
              : client.status === 'online'
                ? 'online'
                : client.status === 'offline'
                  ? 'offline'
                  : 'unknown'
          }
        >
          {client.blocked ? t('NetworkClientsPage.status.blocked') : client.status}
        </StatusBadge>
      ),
    },
    {
      id: 'connection',
      header: t('NetworkClientsPage.columns.connection'),
      cell: (client) => (
        <div className="space-y-1">
          <ConnectionBadge type={client.connection_type} />
          {client.ssid && <div className="text-xs text-muted-foreground">{client.ssid}</div>}
        </div>
      ),
    },
    {
      id: 'ip_address',
      header: t('NetworkClientsPage.columns.ipAddress'),
      cell: (client) => (
        <span className="font-mono text-sm">{client.ip_address || '-'}</span>
      ),
    },
    {
      id: 'mac_address',
      header: t('NetworkClientsPage.columns.macAddress'),
      cell: (client) => (
        <span className="font-mono text-xs text-muted-foreground">{client.mac_address}</span>
      ),
    },
    {
      id: 'signal',
      header: t('NetworkClientsPage.columns.signal'),
      cell: (client) =>
        client.connection_type === 'wireless' ? (
          <SignalStrength strength={client.signal_strength} />
        ) : (
          <span className="text-muted-foreground">-</span>
        ),
    },
    {
      id: 'traffic',
      header: t('NetworkClientsPage.columns.traffic'),
      cell: (client) => (
        <div className="flex items-center gap-3 text-xs">
          <span className="flex items-center gap-1 text-success">
            <Download className="h-3 w-3" />
            {formatBytes(client.rx_bytes)}
          </span>
          <span className="flex items-center gap-1 text-info">
            <Upload className="h-3 w-3" />
            {formatBytes(client.tx_bytes)}
          </span>
        </div>
      ),
    },
    {
      id: 'last_seen',
      header: t('NetworkClientsPage.columns.lastSeen'),
      cell: (client) => (
        <span className="text-sm text-muted-foreground">{formatTimeAgo(t, client.last_seen)}</span>
      ),
    },
    {
      id: 'actions',
      header: '',
      sortable: false,
      cell: (client) => (
        <div className="flex items-center justify-end">
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" size="icon" className="h-8 w-8">
                <MoreHorizontal className="h-4 w-4" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuItem onClick={() => setSelectedClient(client)}>
                <Activity className="mr-2 h-4 w-4" />
                {t('NetworkClientsPage.actions.viewDetails')}
              </DropdownMenuItem>
              <DropdownMenuSeparator />
              <DropdownMenuItem
                onClick={() => setBlockingClient(client)}
                className={client.blocked ? '' : 'text-destructive focus:text-destructive'}
              >
                {client.blocked ? (
                  <>
                    <CheckCircle className="mr-2 h-4 w-4" />
                    {t('NetworkClientsPage.actions.unblock')}
                  </>
                ) : (
                  <>
                    <Ban className="mr-2 h-4 w-4" />
                    {t('NetworkClientsPage.actions.block')}
                  </>
                )}
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
          icon={Users}
          title={t('NetworkClientsPage.header.title')}
          description={t('NetworkClientsPage.header.descriptionShort')}
        />
        <ErrorState
          message={error instanceof Error ? error.message : t('NetworkClientsPage.error.loadFailed')}
          onRetry={() => refetch()}
        />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader
        icon={Users}
        title={t('NetworkClientsPage.header.title')}
        description={t('NetworkClientsPage.header.description')}
        onRefresh={() => refetch()}
        refreshing={isLoading}
        secondaryActions={[
          { label: t('NetworkClientsPage.actions.export'), icon: Download, onClick: handleExport },
        ]}
      />

      <StatsGrid
        columns={4}
        isLoading={isLoading}
        stats={[
          {
            title: t('NetworkClientsPage.stats.totalClients'),
            value: stats.total,
            icon: Users,
            variant: 'default',
            description: t('NetworkClientsPage.stats.onlineCount', { value: stats.online }),
          },
          {
            title: t('NetworkClientsPage.stats.online'),
            value: stats.online,
            icon: CheckCircle,
            variant: 'success',
            description:
              stats.total > 0
                ? t('NetworkClientsPage.stats.connectedPercent', {
                    percent: Math.round((stats.online / stats.total) * 100),
                  })
                : t('NetworkClientsPage.stats.noClients'),
          },
          {
            title: t('NetworkClientsPage.stats.wireless'),
            value: stats.wireless,
            icon: Wifi,
            variant: 'info',
            description: t('NetworkClientsPage.stats.wifiClients'),
          },
          {
            title: t('NetworkClientsPage.stats.wired'),
            value: stats.wired,
            icon: Cable,
            variant: 'primary',
            description: t('NetworkClientsPage.stats.ethernetClients'),
          },
        ]}
      />

      <PageToolbar>
        <SearchBar
          value={searchQuery}
          onChange={setSearchQuery}
          placeholder={t('NetworkClientsPage.toolbar.searchPlaceholder')}
          className="w-full sm:w-auto"
        />
        <Select value={connectionFilter} onValueChange={setConnectionFilter}>
          <SelectTrigger className="w-full sm:w-[160px]">
            <SelectValue placeholder={t('NetworkClientsPage.filters.allConnections')} />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">{t('NetworkClientsPage.filters.allConnections')}</SelectItem>
            <SelectItem value="wireless">
              {t('NetworkClientsPage.connection.wireless')}
            </SelectItem>
            <SelectItem value="wired">{t('NetworkClientsPage.connection.wired')}</SelectItem>
          </SelectContent>
        </Select>
        <Select value={statusFilter} onValueChange={setStatusFilter}>
          <SelectTrigger className="w-full sm:w-[160px]">
            <SelectValue placeholder={t('NetworkClientsPage.filters.allStatuses')} />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">{t('NetworkClientsPage.filters.allStatuses')}</SelectItem>
            <SelectItem value="online">{t('NetworkClientsPage.status.online')}</SelectItem>
            <SelectItem value="offline">{t('NetworkClientsPage.status.offline')}</SelectItem>
          </SelectContent>
        </Select>
        {hasActiveFilters && (
          <Button variant="ghost" size="sm" onClick={handleClearFilters}>
            {t('NetworkClientsPage.toolbar.clearFilters')}
          </Button>
        )}
      </PageToolbar>

      <DataTable
        data={clients}
        columns={columns}
        isLoading={isLoading}
        selectable
        onSelectionChange={setSelected}
        searchable={false}
        itemName={t('NetworkClientsPage.itemName.plural')}
        getRowId={(row) => row.id}
      />

      <BulkActionsBar
        selectedCount={selected.length}
        itemName={t('NetworkClientsPage.itemName.singular')}
        onClear={() => setSelected([])}
        actions={[
          {
            label: t('NetworkClientsPage.actions.block'),
            icon: Ban,
            variant: 'destructive',
            onClick: () => {
              selected.forEach((c) =>
                blockMutation.mutate({ id: c.id, block: true }),
              );
              setSelected([]);
            },
          },
          {
            label: t('NetworkClientsPage.actions.unblock'),
            icon: CheckCircle,
            onClick: () => {
              selected.forEach((c) =>
                blockMutation.mutate({ id: c.id, block: false }),
              );
              setSelected([]);
            },
          },
          // Bulk "Delete" removed: clients API exposes no delete route
          // (only block/unblock). Re-add once a per-client delete endpoint
          // exists. Block/Unblock above are the honest destructive actions.
        ]}
      />

      <ClientDetailsSheet
        client={selectedClient}
        open={!!selectedClient}
        onOpenChange={(open) => !open && setSelectedClient(undefined)}
      />

      <AlertDialog
        open={!!blockingClient}
        onOpenChange={(open) => !open && setBlockingClient(undefined)}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>
              {blockingClient?.blocked
                ? t('NetworkClientsPage.dialog.unblockTitle')
                : t('NetworkClientsPage.dialog.blockTitle')}
            </AlertDialogTitle>
            <AlertDialogDescription>
              {blockingClient?.blocked
                ? t('NetworkClientsPage.dialog.unblockDescription', {
                    name:
                      blockingClient.display_name ||
                      blockingClient.hostname ||
                      blockingClient.mac_address,
                  })
                : t('NetworkClientsPage.dialog.blockDescription', {
                    name:
                      blockingClient?.display_name ||
                      blockingClient?.hostname ||
                      blockingClient?.mac_address,
                  })}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t('NetworkClientsPage.actions.cancel')}</AlertDialogCancel>
            <AlertDialogAction
              onClick={() =>
                blockingClient &&
                blockMutation.mutate({
                  id: blockingClient.id,
                  block: !blockingClient.blocked,
                })
              }
              className={blockingClient?.blocked ? '' : 'bg-destructive hover:bg-destructive/90'}
            >
              {blockMutation.isPending
                ? t('NetworkClientsPage.dialog.processing')
                : blockingClient?.blocked
                  ? t('NetworkClientsPage.actions.unblock')
                  : t('NetworkClientsPage.actions.block')}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}

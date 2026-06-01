// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * SwitchClientsTab · connected clients table for the switch detail view.
 *
 * Extracted from SwitchesPage as part of the monolith breakup. Receives all
 * data via props; owns only its connection-type filter state.
 */
import { useState, useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { Activity, ArrowDownToLine, ArrowUpFromLine, Monitor, Signal, Users, Wifi } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { DataTable, type DataTableColumn } from '@/components/ui/data-table';
import { EmptyState } from '@/components/ui/empty-state';
import { StatsGrid, type StatItem } from '@/components/ui/stats-grid';
import type { SwitchClient } from '@/lib/api';
import { formatActivity, formatBytes, formatTimeAgo, formatUptime } from './_formatters';

export interface SwitchClientsTabProps {
  clients: SwitchClient[];
  isLoading: boolean;
}

export function SwitchClientsTab({ clients, isLoading }: SwitchClientsTabProps) {
  const { t } = useTranslation('switches');
  const [connectionFilter, setConnectionFilter] = useState<'all' | 'wired' | 'wireless'>('all');

  const filteredClients = useMemo(() => {
    if (connectionFilter === 'all') return clients;
    return clients.filter((c) => (c.connection_type || 'wired') === connectionFilter);
  }, [clients, connectionFilter]);

  const wiredCount = useMemo(() => clients.filter((c) => c.connection_type === 'wired').length, [clients]);
  const wirelessCount = useMemo(() => clients.filter((c) => c.connection_type === 'wireless').length, [clients]);
  const totalDownload = useMemo(() => clients.reduce((sum, c) => sum + (c.download || 0), 0), [clients]);
  const totalUpload = useMemo(() => clients.reduce((sum, c) => sum + (c.upload || 0), 0), [clients]);

  const stats = useMemo<StatItem[]>(
    () => [
      { title: t('SwitchClientsTab.stats.totalClients'), value: clients.length, icon: Users, variant: 'primary' as const },
      { title: t('SwitchClientsTab.stats.wired'), value: wiredCount, icon: Monitor, variant: 'info' as const },
      { title: t('SwitchClientsTab.stats.wireless'), value: wirelessCount, icon: Wifi, variant: 'success' as const },
      {
        title: t('SwitchClientsTab.stats.totalTraffic'),
        value: `${formatBytes(totalDownload)} / ${formatBytes(totalUpload)}`,
        icon: Activity,
        variant: 'default' as const,
        description: t('SwitchClientsTab.stats.downloadUpload'),
      },
    ],
    [t, clients.length, wiredCount, wirelessCount, totalDownload, totalUpload],
  );

  const columns = useMemo<DataTableColumn<SwitchClient>[]>(
    () => [
      {
        id: 'name',
        header: t('SwitchClientsTab.columns.client'),
        accessorFn: (row) => row.name || row.hostname || row.mac_address,
        cell: (row) => (
          <div className="flex items-center gap-3 min-w-[180px]">
            <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-muted">
              {row.connection_type === 'wireless' ? (
                <Wifi className="h-4 w-4 text-emerald-500" />
              ) : (
                <Monitor className="h-4 w-4 text-blue-500" />
              )}
            </div>
            <div className="min-w-0">
              <div className="font-medium text-sm truncate">{row.name || row.hostname || t('SwitchClientsTab.unknownDevice')}</div>
              <div className="text-xs text-muted-foreground flex items-center gap-1.5">
                {row.os_type && <span>{row.os_type}</span>}
                {row.os_type && row.device_category && <span className="opacity-40">·</span>}
                {row.device_category && <span className="capitalize">{row.device_category}</span>}
                {!row.os_type && !row.device_category && <span className="font-mono">{row.mac_address}</span>}
              </div>
            </div>
          </div>
        ),
        sortable: true,
      },
      {
        id: 'ip_address',
        header: t('SwitchClientsTab.columns.ipAddress'),
        accessorKey: 'ip_address',
        cell: (row) => <span className="font-mono text-xs">{row.ip_address || '-'}</span>,
        sortable: true,
      },
      {
        id: 'mac_address',
        header: t('SwitchClientsTab.columns.macAddress'),
        accessorKey: 'mac_address',
        cell: (row) => <span className="font-mono text-xs text-muted-foreground">{row.mac_address}</span>,
        sortable: true,
      },
      {
        id: 'connection',
        header: t('SwitchClientsTab.columns.connection'),
        accessorFn: (row) => row.connection_type || 'wired',
        cell: (row) => {
          const isWireless = row.connection_type === 'wireless';
          return (
            <div className="space-y-0.5">
              <Badge
                variant="outline"
                className={`text-xs capitalize ${isWireless ? 'border-emerald-500/30 text-emerald-600' : 'border-blue-500/30 text-blue-600'}`}
              >
                {isWireless ? t('SwitchClientsTab.connectionType.wireless') : t('SwitchClientsTab.connectionType.wired')}
              </Badge>
              {isWireless && row.ssid && (
                <div className="text-xs text-muted-foreground truncate max-w-[120px]" title={row.ssid}>
                  {row.ssid}
                </div>
              )}
              {isWireless && row.band && (
                <div className="text-[10px] text-muted-foreground">
                  {row.band}
                  {row.channel ? ` ch${row.channel}` : ''}
                </div>
              )}
              {!isWireless && row.switch_port != null && (
                <div className="text-xs text-muted-foreground">{t('SwitchClientsTab.port', { port: row.switch_port })}</div>
              )}
            </div>
          );
        },
        sortable: true,
      },
      {
        id: 'vlan_id',
        header: t('SwitchClientsTab.columns.vlan'),
        accessorKey: 'vlan_id',
        cell: (row) => <span className="text-sm">{row.vlan_id ?? '-'}</span>,
        sortable: true,
      },
      {
        id: 'signal',
        header: t('SwitchClientsTab.columns.signal'),
        accessorFn: (row) => row.rssi ?? row.signal ?? -999,
        cell: (row) => {
          if (row.connection_type !== 'wireless') return <span className="text-xs text-muted-foreground">-</span>;
          const rssi = row.rssi ?? row.signal;
          if (rssi == null) return <span className="text-xs text-muted-foreground">-</span>;
          const quality =
            rssi >= -50
              ? 'text-emerald-500'
              : rssi >= -65
                ? 'text-yellow-500'
                : rssi >= -75
                  ? 'text-orange-500'
                  : 'text-red-500';
          return (
            <div className="flex items-center gap-1.5">
              <Signal className={`h-3.5 w-3.5 ${quality}`} />
              <span className={`text-xs font-medium ${quality}`}>{t('SwitchClientsTab.dbm', { value: rssi })}</span>
            </div>
          );
        },
        sortable: true,
      },
      {
        id: 'activity',
        header: t('SwitchClientsTab.columns.activity'),
        accessorFn: (row) => row.activity || 0,
        cell: (row) => <span className="text-xs tabular-nums">{formatActivity(row.activity)}</span>,
        sortable: true,
      },
      {
        id: 'traffic',
        header: t('SwitchClientsTab.columns.traffic'),
        accessorFn: (row) => (row.download || 0) + (row.upload || 0),
        cell: (row) => {
          const dl = row.download || 0;
          const ul = row.upload || 0;
          if (!dl && !ul) return <span className="text-xs text-muted-foreground">-</span>;
          return (
            <div className="text-xs tabular-nums space-y-0.5">
              <div className="flex items-center gap-1 text-blue-500">
                <ArrowDownToLine className="h-3 w-3" />
                {formatBytes(dl)}
              </div>
              <div className="flex items-center gap-1 text-emerald-500">
                <ArrowUpFromLine className="h-3 w-3" />
                {formatBytes(ul)}
              </div>
            </div>
          );
        },
        sortable: true,
      },
      {
        id: 'uptime',
        header: t('SwitchClientsTab.columns.uptime'),
        accessorFn: (row) => row.uptime || 0,
        cell: (row) => <span className="text-xs text-muted-foreground">{formatUptime(row.uptime)}</span>,
        sortable: true,
      },
      {
        id: 'last_seen',
        header: t('SwitchClientsTab.columns.lastSeen'),
        accessorFn: (row) => row.last_seen || '',
        cell: (row) => <span className="text-xs text-muted-foreground">{formatTimeAgo(row.last_seen)}</span>,
        sortable: true,
      },
    ],
    [t],
  );

  return (
    <div className="space-y-4">
      <StatsGrid stats={stats} columns={4} isLoading={isLoading} />

      <div className="flex items-center gap-2">
        {(
          [
            { key: 'all' as const, label: t('SwitchClientsTab.filters.all'), count: clients.length, icon: Users },
            { key: 'wired' as const, label: t('SwitchClientsTab.filters.wired'), count: wiredCount, icon: Monitor },
            { key: 'wireless' as const, label: t('SwitchClientsTab.filters.wireless'), count: wirelessCount, icon: Wifi },
          ]
        ).map(({ key, label, count, icon: Icon }) => (
          <Button
            key={key}
            variant={connectionFilter === key ? 'default' : 'outline'}
            size="sm"
            onClick={() => setConnectionFilter(key)}
            className="gap-1.5"
          >
            <Icon className="h-3.5 w-3.5" />
            {label}
            <Badge variant="secondary" className="ml-0.5 h-5 px-1.5 text-[10px] font-semibold">
              {count}
            </Badge>
          </Button>
        ))}
      </div>

      <DataTable
        data={filteredClients}
        columns={columns}
        isLoading={isLoading}
        searchable
        searchPlaceholder={t('SwitchClientsTab.searchPlaceholder')}
        paginated
        defaultPageSize={25}
        itemName={t('SwitchClientsTab.itemName')}
        getRowId={(row) => row.mac_address}
        emptyState={
          <EmptyState
            icon={Users}
            title={t('SwitchClientsTab.empty.title')}
            description={t('SwitchClientsTab.empty.description')}
            variant="default"
          />
        }
      />
    </div>
  );
}

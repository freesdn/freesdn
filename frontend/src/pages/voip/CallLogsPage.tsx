// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN · Call History / CDR Page
 *
 * Call detail records with date/direction/status filters,
 * stats cards, searchable table.
 */

import { useState, useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { useQuery } from '@tanstack/react-query';
import { useSiteStore } from '@/stores/siteStore';
import {
  PhoneCall, PhoneIncoming, PhoneOutgoing, PhoneMissed,
  Clock, AlertTriangle,
} from 'lucide-react';
import { Card, CardContent } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { DataTable, type DataTableColumn } from '@/components/ui/data-table';
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from '@/components/ui/select';
import { voipApi } from '@/lib/api';
import { PageHeader } from '@/components/layout';
import { CallDirectionBadge, CallStatusBadge, formatDuration } from './components';
import type { CallLog } from './types';

export default function CallLogsPage() {
  const { t } = useTranslation('voip');
  const [filterDirection, setFilterDirection] = useState('all');
  const [filterStatus, setFilterStatus] = useState('all');
  const [search, setSearch] = useState('');

  // Site context
  const selectedSiteId = useSiteStore((s) => s.selectedSiteId);

  // ── Query ──

  const { data: logsRes, isLoading, isError, refetch } = useQuery({
    queryKey: ['voip-call-logs', filterDirection, filterStatus, { siteId: selectedSiteId }],
    queryFn: () => voipApi.getCallLogs({
      limit: 500,
      direction: filterDirection !== 'all' ? filterDirection : undefined,
      call_status: filterStatus !== 'all' ? filterStatus : undefined,
      ...(selectedSiteId ? { site_id: selectedSiteId } : {}),
    }),
    refetchInterval: 30_000,
  });

  const allLogs: CallLog[] = useMemo(() => logsRes?.data?.items ?? logsRes?.data ?? [], [logsRes?.data]);

  const logs = useMemo(() => {
    if (!search) return allLogs;
    const q = search.toLowerCase();
    return allLogs.filter((l) =>
      (l.caller_number || l.caller)?.toLowerCase().includes(q) ||
      (l.callee_number || l.callee)?.toLowerCase().includes(q) ||
      l.caller_name?.toLowerCase().includes(q) ||
      l.callee_name?.toLowerCase().includes(q)
    );
  }, [allLogs, search]);

  // ── Stats ──

  const totalCalls = allLogs.length;
  const inboundCalls = allLogs.filter((l) => l.direction === 'inbound').length;
  const outboundCalls = allLogs.filter((l) => l.direction === 'outbound').length;
  const missedCalls = allLogs.filter((l) => l.status === 'missed' || l.status === 'no_answer').length;
  const avgDuration = totalCalls > 0
    ? Math.round(allLogs.reduce((s, l) => s + (l.duration_seconds ?? l.duration ?? 0), 0) / totalCalls)
    : 0;

  // ── Columns ──

  const columns: DataTableColumn<CallLog>[] = [
    {
      id: 'direction',
      header: t('CallLogsPage.columns.direction'),
      cell: (row) => <CallDirectionBadge direction={row.direction} />,
    },
    {
      id: 'caller',
      header: t('CallLogsPage.columns.caller'),
      cell: (row) => {
        const caller = row.caller_number || row.caller;
        return (
          <div>
            <p className="text-sm font-medium">{row.caller_name || caller || '-'}</p>
            {row.caller_name && caller && (
              <p className="text-xs text-muted-foreground font-mono">{caller}</p>
            )}
          </div>
        );
      },
    },
    {
      id: 'callee',
      header: t('CallLogsPage.columns.destination'),
      cell: (row) => {
        const callee = row.callee_number || row.callee;
        return (
          <div>
            <p className="text-sm font-medium">{row.callee_name || callee || '-'}</p>
            {row.callee_name && callee && (
              <p className="text-xs text-muted-foreground font-mono">{callee}</p>
            )}
          </div>
        );
      },
    },
    {
      id: 'status',
      header: t('CallLogsPage.columns.status'),
      cell: (row) => <CallStatusBadge status={row.status} />,
    },
    {
      id: 'duration',
      header: t('CallLogsPage.columns.duration'),
      cell: (row) => <span className="text-sm font-mono">{formatDuration(row.duration_seconds ?? row.duration ?? 0)}</span>,
    },
    {
      id: 'started_at',
      header: t('CallLogsPage.columns.dateTime'),
      cell: (row) => {
        const ts = row.start_time || row.started_at;
        if (!ts) return <span className="text-muted-foreground">-</span>;
        const d = new Date(ts);
        return (
          <div className="text-xs">
            <p>{d.toLocaleDateString()}</p>
            <p className="text-muted-foreground">{d.toLocaleTimeString()}</p>
          </div>
        );
      },
    },
    {
      id: 'pbx',
      header: t('CallLogsPage.columns.pbx'),
      cell: (row) => <span className="text-xs text-muted-foreground">{row.pbx_system_name || '-'}</span>,
    },
  ];

  return (
    <div className="space-y-6">
      <PageHeader
        icon={PhoneCall}
        title={t('CallLogsPage.title')}
        subtitle={t('CallLogsPage.subtitle', { count: totalCalls })}
        onRefresh={() => refetch()}
        refreshing={isLoading}
      />

      {isError && (
        <Card className="border-destructive">
          <CardContent noOffset className="p-4 flex items-center gap-3">
            <AlertTriangle className="h-5 w-5 text-destructive" />
            <span className="text-sm">{t('CallLogsPage.error.loadFailed')}</span>
          </CardContent>
        </Card>
      )}

      {/* Stats */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-4">
        <Card>
          <CardContent noOffset>
            <div className="flex items-center gap-3">
              <div className="p-2 bg-primary/10 rounded-lg"><PhoneCall className="h-5 w-5 text-primary" /></div>
              <div>
                <p className="text-2xl font-bold">{totalCalls}</p>
                <p className="text-xs text-muted-foreground">{t('CallLogsPage.stats.totalCalls')}</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent noOffset>
            <div className="flex items-center gap-3">
              <div className="p-2 bg-blue-500/10 rounded-lg"><PhoneIncoming className="h-5 w-5 text-blue-500" /></div>
              <div>
                <p className="text-2xl font-bold">{inboundCalls}</p>
                <p className="text-xs text-muted-foreground">{t('CallLogsPage.stats.inbound')}</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent noOffset>
            <div className="flex items-center gap-3">
              <div className="p-2 bg-green-500/10 rounded-lg"><PhoneOutgoing className="h-5 w-5 text-green-500" /></div>
              <div>
                <p className="text-2xl font-bold">{outboundCalls}</p>
                <p className="text-xs text-muted-foreground">{t('CallLogsPage.stats.outbound')}</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent noOffset>
            <div className="flex items-center gap-3">
              <div className="p-2 bg-red-500/10 rounded-lg"><PhoneMissed className="h-5 w-5 text-red-500" /></div>
              <div>
                <p className="text-2xl font-bold">{missedCalls}</p>
                <p className="text-xs text-muted-foreground">{t('CallLogsPage.stats.missed')}</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent noOffset>
            <div className="flex items-center gap-3">
              <div className="p-2 bg-amber-500/10 rounded-lg"><Clock className="h-5 w-5 text-amber-500" /></div>
              <div>
                <p className="text-2xl font-bold">{formatDuration(avgDuration)}</p>
                <p className="text-xs text-muted-foreground">{t('CallLogsPage.stats.avgDuration')}</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3">
        <Input placeholder={t('CallLogsPage.filters.searchPlaceholder')} value={search}
          onChange={(e) => setSearch(e.target.value)} className="w-64" />
        <Select value={filterDirection} onValueChange={setFilterDirection}>
          <SelectTrigger className="w-36"><SelectValue placeholder={t('CallLogsPage.filters.directionPlaceholder')} /></SelectTrigger>
          <SelectContent>
            <SelectItem value="all">{t('CallLogsPage.filters.allDirections')}</SelectItem>
            <SelectItem value="inbound">{t('CallLogsPage.filters.inbound')}</SelectItem>
            <SelectItem value="outbound">{t('CallLogsPage.filters.outbound')}</SelectItem>
            <SelectItem value="internal">{t('CallLogsPage.filters.internal')}</SelectItem>
          </SelectContent>
        </Select>
        <Select value={filterStatus} onValueChange={setFilterStatus}>
          <SelectTrigger className="w-36"><SelectValue placeholder={t('CallLogsPage.filters.statusPlaceholder')} /></SelectTrigger>
          <SelectContent>
            {/* Values MUST match the vocabulary the CDR normalizer stores
                (service._normalize_and_store_cdr): an answered call is stored
                as "completed", and "no_answer"/"busy"/"failed" are the only
                other live values. The dropdown previously sent "answered" and
                "missed", which never matched any row → always-empty results. */}
            <SelectItem value="all">{t('CallLogsPage.filters.allStatus')}</SelectItem>
            <SelectItem value="completed">{t('CallLogsPage.filters.answered')}</SelectItem>
            <SelectItem value="no_answer">{t('CallLogsPage.filters.noAnswer')}</SelectItem>
            <SelectItem value="busy">{t('CallLogsPage.filters.busy')}</SelectItem>
            <SelectItem value="failed">{t('CallLogsPage.filters.failed')}</SelectItem>
          </SelectContent>
        </Select>
      </div>

      {/* Table */}
      <DataTable
        data={logs}
        columns={columns}
        isLoading={isLoading}
        itemName={t('CallLogsPage.itemName')}
        paginated
        defaultPageSize={25}
        emptyState={
          <div className="flex flex-col items-center gap-3 py-12">
            <PhoneCall className="h-12 w-12 text-muted-foreground/30" />
            <p className="text-muted-foreground">{t('CallLogsPage.empty.noRecords')}</p>
          </div>
        }
      />
    </div>
  );
}

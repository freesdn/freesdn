// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { useState, useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { useQuery, keepPreviousData } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { ChevronUp, ChevronDown, ChevronsUpDown } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Skeleton } from '@/components/ui/skeleton';
import { cn } from '@/lib/utils';
import { enterpriseApi, type DeviceHealthListResponse } from '@/lib/api';
import { HealthStatusBadge } from './HealthStatusBadge';
import { DeviceHealthDrawer } from './DeviceHealthDrawer';

interface DeviceHealthTableProps {
  siteId?: string;
}

const PAGE_SIZE = 50;

// Sort fields the backend's sort_column_map understands. Field names
// match the backend ``DeviceHealth`` columns exactly so the sort button
// click resolves to a real ORDER BY on the right column.
type SortField =
  | 'device_name'
  | 'health_score'
  | 'reachability_score'
  | 'latency_score'
  | 'drift_score'
  | 'error_score'
  | 'utilization_score'
  | 'firmware_score';

function scoreCellColor(score: number | null): string {
  if (score === null || score === undefined) return '';
  if (score >= 90) return 'bg-green-500/10 text-green-700 dark:text-green-400';
  if (score >= 70) return 'bg-amber-500/10 text-amber-700 dark:text-amber-400';
  if (score >= 50) return 'bg-orange-500/10 text-orange-700 dark:text-orange-400';
  return 'bg-red-500/10 text-red-700 dark:text-red-400';
}

function ScoreCell({ value }: { value: number | null }) {
  const { t } = useTranslation('enterprise');
  if (value === null || value === undefined) {
    return <span className="text-xs text-muted-foreground">{t('DeviceHealthTable.common.notAvailable')}</span>;
  }
  return (
    <span className={cn('inline-block px-2 py-0.5 rounded text-xs font-medium tabular-nums', scoreCellColor(value))}>
      {value}
    </span>
  );
}

const STATUS_OPTIONS = ['all', 'healthy', 'warning', 'degraded', 'critical'] as const;

export function DeviceHealthTable({ siteId }: DeviceHealthTableProps) {
  const { t } = useTranslation('enterprise');
  const [page, setPage] = useState(0);
  const [sortField, setSortField] = useState<SortField>('health_score');
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('asc');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [typeFilter, setTypeFilter] = useState<string>('all');
  const [selectedDeviceId, setSelectedDeviceId] = useState<string | null>(null);

  const params = useMemo(
    () => ({
      site_id: siteId,
      health_status: statusFilter !== 'all' ? statusFilter : undefined,
      device_type: typeFilter !== 'all' ? typeFilter : undefined,
      sort_by: sortField,
      sort_dir: sortDir,
      limit: PAGE_SIZE,
      offset: page * PAGE_SIZE,
    }),
    [siteId, statusFilter, typeFilter, sortField, sortDir, page],
  );

  const { data, isLoading, isError } = useQuery<DeviceHealthListResponse>({
    queryKey: ['health', 'devices', params],
    queryFn: () => enterpriseApi.listDeviceHealth(params).then((r) => r.data),
    placeholderData: keepPreviousData,
  });

  // Known device types matching backend module_map
  const deviceTypes = [
    'switch', 'router', 'access_point', 'gateway', 'firewall',
    'camera', 'nvr', 'voip_phone', 'pbx', 'hypervisor',
  ];

  const totalPages = data ? Math.ceil(data.total / PAGE_SIZE) : 0;

  function handleSort(field: SortField) {
    if (sortField === field) {
      setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortField(field);
      setSortDir('asc');
    }
    setPage(0);
  }

  function SortIcon({ field }: { field: SortField }) {
    if (sortField !== field) return <ChevronsUpDown className="h-3 w-3 ml-1 opacity-40" />;
    return sortDir === 'asc' ? (
      <ChevronUp className="h-3 w-3 ml-1" />
    ) : (
      <ChevronDown className="h-3 w-3 ml-1" />
    );
  }

  const columns: Array<{ label: string; field: SortField; component?: boolean }> = [
    { label: t('DeviceHealthTable.columns.health'), field: 'health_score' },
    { label: t('DeviceHealthTable.columns.reachability'), field: 'reachability_score', component: true },
    { label: t('DeviceHealthTable.columns.latency'), field: 'latency_score', component: true },
    { label: t('DeviceHealthTable.columns.drift'), field: 'drift_score', component: true },
    { label: t('DeviceHealthTable.columns.errorRate'), field: 'error_score', component: true },
    { label: t('DeviceHealthTable.columns.utilization'), field: 'utilization_score', component: true },
    { label: t('DeviceHealthTable.columns.firmware'), field: 'firmware_score', component: true },
  ];

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">{t('DeviceHealthTable.title')}</CardTitle>
      </CardHeader>
      <CardContent>
        {/* Filters */}
        <div className="flex flex-wrap gap-3 mb-4">
          <select
            className="rounded-md border bg-background px-3 py-1.5 text-sm"
            value={statusFilter}
            onChange={(e) => { setStatusFilter(e.target.value); setPage(0); }}
          >
            {STATUS_OPTIONS.map((s) => (
              <option key={s} value={s}>
                {t(`DeviceHealthTable.statusOptions.${s}`)}
              </option>
            ))}
          </select>
          <select
            className="rounded-md border bg-background px-3 py-1.5 text-sm"
            value={typeFilter}
            onChange={(e) => { setTypeFilter(e.target.value); setPage(0); }}
          >
            <option value="all">{t('DeviceHealthTable.allTypes')}</option>
            {deviceTypes.map((dt) => (
              <option key={dt} value={dt}>{dt}</option>
            ))}
          </select>
        </div>

        {/* Table */}
        {isError ? (
          <div className="rounded-md bg-destructive/10 p-3 text-sm text-destructive">
            {t('DeviceHealthTable.errorLoading')}
          </div>
        ) : isLoading ? (
          <div className="space-y-2">
            {Array.from({ length: 10 }).map((_, i) => (
              <Skeleton key={i} className="h-10" />
            ))}
          </div>
        ) : !data?.devices.length ? (
          <div className="flex flex-col items-center py-12 text-muted-foreground text-sm">
            {t('DeviceHealthTable.empty')}
          </div>
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b text-left text-muted-foreground">
                    <th className="pb-2 pr-3 font-medium">{t('DeviceHealthTable.headers.device')}</th>
                    <th className="pb-2 pr-3 font-medium">{t('DeviceHealthTable.headers.site')}</th>
                    <th className="pb-2 pr-3 font-medium">{t('DeviceHealthTable.headers.type')}</th>
                    {columns.map((col) => (
                      <th key={col.field} className="pb-2 pr-2 font-medium whitespace-nowrap">
                        <button
                          className="inline-flex items-center hover:text-foreground"
                          onClick={() => handleSort(col.field)}
                        >
                          {col.label}
                          <SortIcon field={col.field} />
                        </button>
                      </th>
                    ))}
                    <th className="pb-2 pr-3 font-medium">{t('DeviceHealthTable.headers.status')}</th>
                    <th className="pb-2 font-medium">{t('DeviceHealthTable.headers.updated')}</th>
                  </tr>
                </thead>
                <tbody>
                  {data.devices.map((device) => (
                    <tr
                      key={device.device_id}
                      className="border-b last:border-0 hover:bg-muted/50 cursor-pointer"
                      onClick={() => setSelectedDeviceId(device.device_id)}
                    >
                      <td className="py-2 pr-3">
                        <Link
                          to={`/devices/${device.device_id}`}
                          className="font-medium hover:underline"
                        >
                          {device.device_name}
                        </Link>
                      </td>
                      <td className="py-2 pr-3 text-muted-foreground">
                        {device.site_name ?? '-'}
                      </td>
                      <td className="py-2 pr-3 text-muted-foreground capitalize">
                        {device.device_type}
                      </td>
                      <td className="py-2 pr-2">
                        <span
                          className={cn(
                            'inline-block px-2 py-0.5 rounded text-xs font-bold tabular-nums',
                            scoreCellColor(device.health_score),
                          )}
                        >
                          {device.health_score}
                        </span>
                      </td>
                      <td className="py-2 pr-2"><ScoreCell value={device.reachability_score} /></td>
                      <td className="py-2 pr-2"><ScoreCell value={device.latency_score} /></td>
                      <td className="py-2 pr-2"><ScoreCell value={device.drift_score} /></td>
                      <td className="py-2 pr-2"><ScoreCell value={device.error_score} /></td>
                      <td className="py-2 pr-2"><ScoreCell value={device.utilization_score} /></td>
                      <td className="py-2 pr-2"><ScoreCell value={device.firmware_score} /></td>
                      <td className="py-2 pr-3">
                        <HealthStatusBadge status={device.health_status} />
                      </td>
                      <td className="py-2 text-xs text-muted-foreground whitespace-nowrap">
                        {new Date(device.updated_at).toLocaleString([], {
                          month: 'short',
                          day: 'numeric',
                          hour: '2-digit',
                          minute: '2-digit',
                        })}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Pagination */}
            {totalPages > 1 && (
              <div className="flex items-center justify-between mt-4 pt-4 border-t">
                <span className="text-sm text-muted-foreground">
                  {data.total === 1
                    ? t('DeviceHealthTable.pagination.totalOne', { count: data.total })
                    : t('DeviceHealthTable.pagination.totalOther', { count: data.total })}
                </span>
                <div className="flex items-center gap-2">
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={page === 0}
                    onClick={() => setPage((p) => p - 1)}
                  >
                    {t('DeviceHealthTable.pagination.previous')}
                  </Button>
                  <span className="text-sm text-muted-foreground">
                    {t('DeviceHealthTable.pagination.pageOf', { page: page + 1, total: totalPages })}
                  </span>
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={page + 1 >= totalPages}
                    onClick={() => setPage((p) => p + 1)}
                  >
                    {t('DeviceHealthTable.pagination.next')}
                  </Button>
                </div>
              </div>
            )}
          </>
        )}
      </CardContent>
      <DeviceHealthDrawer
        deviceId={selectedDeviceId}
        deviceName={data?.devices.find((d) => d.device_id === selectedDeviceId)?.device_name}
        siteName={data?.devices.find((d) => d.device_id === selectedDeviceId)?.site_name ?? undefined}
        onClose={() => setSelectedDeviceId(null)}
      />
    </Card>
  );
}

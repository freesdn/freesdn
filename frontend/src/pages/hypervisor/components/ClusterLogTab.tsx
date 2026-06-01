// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Hypervisor Module - Cluster Log Tab
 * Shows cluster log entries with severity badges and auto-refresh.
 */
import { useQuery } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import type { TFunction } from 'i18next';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table';
import { Skeleton } from '@/components/ui/skeleton';
import { EmptyState, ErrorState } from '@/components/ui/empty-state';
import { FileText } from 'lucide-react';
import { hypervisorApi } from '@/lib/api';

interface ClusterLogTabProps {
  controllerId: string;
}

interface ClusterLogEntry {
  time?: string | number;
  node?: string;
  severity?: string;
  pri?: number;
  tag?: string;
  user?: string;
  msg?: string;
  pid?: number;
  uid?: number;
}

function severityBadge(severity: string | undefined, pri: number | undefined, t: TFunction) {
  const s = (severity || '').toLowerCase();
  // Map numeric priority: 0-3 = error, 4 = warning, 5-7 = info
  const p = pri ?? 6;
  if (s === 'err' || s === 'error' || s === 'crit' || s === 'alert' || s === 'emerg' || p <= 3) {
    return <Badge variant="destructive">{severity || t('ClusterLogTab.severity.error')}</Badge>;
  }
  if (s === 'warn' || s === 'warning' || p === 4) {
    return <Badge className="bg-amber-500 text-white">{severity || t('ClusterLogTab.severity.warning')}</Badge>;
  }
  return <Badge className="bg-green-600 text-white">{severity || t('ClusterLogTab.severity.info')}</Badge>;
}

function formatLogTime(val: string | number | undefined): string {
  if (!val) return '--';
  const d = typeof val === 'number' ? new Date(val * 1000) : new Date(val);
  return d.toLocaleString();
}

export function ClusterLogTab({ controllerId }: ClusterLogTabProps) {
  const { t } = useTranslation('hypervisor');
  const { data: logResp, isLoading, isError } = useQuery({
    queryKey: ['hypervisor', 'cluster', 'log', controllerId],
    queryFn: () => hypervisorApi.getClusterLog(controllerId, 200),
    enabled: !!controllerId,
    refetchInterval: 15_000,
  });
  const entries: ClusterLogEntry[] = (logResp?.data as ClusterLogEntry[] | undefined) || [];

  if (isLoading) {
    return <Skeleton className="h-64" />;
  }

  if (isError) {
    return <ErrorState message={t('ClusterLogTab.error.fetch')} />;
  }

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader className="pb-2">
          <div className="flex items-center gap-2">
            <FileText className="h-4 w-4 text-muted-foreground" />
            <CardTitle className="text-sm">{t('ClusterLogTab.title')}</CardTitle>
            <Badge variant="secondary" className="ml-auto">{t('ClusterLogTab.entriesCount', { count: entries.length })}</Badge>
            <span className="text-xs text-muted-foreground">{t('ClusterLogTab.autoRefresh')}</span>
          </div>
        </CardHeader>
        <CardContent className="p-0">
          {entries.length === 0 ? (
            <div className="py-4">
              <EmptyState icon={FileText} title={t('ClusterLogTab.empty.title')} description={t('ClusterLogTab.empty.description')} />
            </div>
          ) : (
            <div className="max-h-[600px] overflow-y-auto overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>{t('ClusterLogTab.columns.time')}</TableHead>
                    <TableHead>{t('ClusterLogTab.columns.node')}</TableHead>
                    <TableHead>{t('ClusterLogTab.columns.severity')}</TableHead>
                    <TableHead>{t('ClusterLogTab.columns.tag')}</TableHead>
                    <TableHead>{t('ClusterLogTab.columns.user')}</TableHead>
                    <TableHead>{t('ClusterLogTab.columns.message')}</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {entries.map((e, i) => (
                    <TableRow key={i}>
                      <TableCell className="text-xs whitespace-nowrap">{formatLogTime(e.time)}</TableCell>
                      <TableCell>
                        <Badge variant="outline">{e.node || '--'}</Badge>
                      </TableCell>
                      <TableCell>{severityBadge(e.severity, e.pri, t)}</TableCell>
                      <TableCell className="text-xs font-mono">{e.tag || '--'}</TableCell>
                      <TableCell className="text-xs">{e.user || '--'}</TableCell>
                      <TableCell className="text-sm max-w-md truncate">{e.msg || '--'}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

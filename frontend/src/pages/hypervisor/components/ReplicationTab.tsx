// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Hypervisor Module - Replication Tab
 * Shows cluster replication jobs with expandable log view.
 */
import React, { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useQuery } from '@tanstack/react-query';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table';
import { Skeleton } from '@/components/ui/skeleton';
import { EmptyState, ErrorState } from '@/components/ui/empty-state';
import { ArrowRightLeft, ChevronDown, ChevronRight } from 'lucide-react';
import { hypervisorApi } from '@/lib/api';
import { formatTimestamp } from './helpers';

interface ReplicationTabProps {
  controllerId: string;
}

interface ReplicationJob {
  id?: string;
  type?: string;
  source?: string;
  target?: string;
  guest?: number;
  schedule?: string;
  rate?: number;
  disable?: boolean;
  comment?: string;
  last_sync?: number | string;
  last_try?: number | string;
  next_sync?: number | string;
  duration?: number;
  fail_count?: number;
  error?: string;
}

interface ReplicationLogEntry {
  t?: string;
  n?: number;
}

function statusBadge(job: ReplicationJob, t: (key: string) => string) {
  if (job.disable) return <Badge variant="secondary">{t('ReplicationTab.status.disabled')}</Badge>;
  if (job.error) return <Badge variant="destructive">{t('ReplicationTab.status.error')}</Badge>;
  if (job.fail_count && job.fail_count > 0) return <Badge className="bg-amber-500 text-white">{t('ReplicationTab.status.degraded')}</Badge>;
  return <Badge className="bg-green-600 text-white">{t('ReplicationTab.status.ok')}</Badge>;
}

function ExpandableLog({ controllerId, replicationId }: { controllerId: string; replicationId: string }) {
  const { t } = useTranslation('hypervisor');
  const { data: logResp, isLoading } = useQuery({
    queryKey: ['hypervisor', 'replication', 'log', controllerId, replicationId],
    queryFn: () => hypervisorApi.getReplicationLog(controllerId, replicationId),
    enabled: !!controllerId && !!replicationId,
  });
  const entries: ReplicationLogEntry[] = (logResp?.data as ReplicationLogEntry[] | undefined) || [];

  if (isLoading) return <Skeleton className="h-16 m-2" />;

  return (
    <div className="bg-muted/50 rounded p-3 m-2 max-h-48 overflow-y-auto">
      {entries.length === 0 ? (
        <p className="text-xs text-muted-foreground">{t('ReplicationTab.log.empty')}</p>
      ) : (
        <pre className="text-xs font-mono whitespace-pre-wrap">
          {entries.map((e, i) => (
            <div key={i}>{e.t || JSON.stringify(e)}</div>
          ))}
        </pre>
      )}
    </div>
  );
}

export function ReplicationTab({ controllerId }: ReplicationTabProps) {
  const { t } = useTranslation('hypervisor');
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const { data: replResp, isLoading, isError } = useQuery({
    queryKey: ['hypervisor', 'replication', controllerId],
    queryFn: () => hypervisorApi.getClusterReplication(controllerId),
    enabled: !!controllerId,
  });
  const jobs: ReplicationJob[] = (replResp?.data as ReplicationJob[] | undefined) || [];

  if (isLoading) {
    return <Skeleton className="h-64" />;
  }

  if (isError) {
    return <ErrorState message={t('ReplicationTab.error.fetch')} />;
  }

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader className="pb-2">
          <div className="flex items-center gap-2">
            <ArrowRightLeft className="h-4 w-4 text-muted-foreground" />
            <CardTitle className="text-sm">{t('ReplicationTab.title')}</CardTitle>
            <Badge variant="secondary" className="ml-auto">{jobs.length === 1 ? t('ReplicationTab.jobCount.one', { count: jobs.length }) : t('ReplicationTab.jobCount.other', { count: jobs.length })}</Badge>
          </div>
        </CardHeader>
        <CardContent className="p-0">
          {jobs.length === 0 ? (
            <div className="py-4">
              <EmptyState icon={ArrowRightLeft} title={t('ReplicationTab.empty.title')} description={t('ReplicationTab.empty.description')} />
            </div>
          ) : (
            <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-8"></TableHead>
                  <TableHead>{t('ReplicationTab.columns.id')}</TableHead>
                  <TableHead>{t('ReplicationTab.columns.type')}</TableHead>
                  <TableHead>{t('ReplicationTab.columns.source')}</TableHead>
                  <TableHead>{t('ReplicationTab.columns.target')}</TableHead>
                  <TableHead>{t('ReplicationTab.columns.guest')}</TableHead>
                  <TableHead>{t('ReplicationTab.columns.schedule')}</TableHead>
                  <TableHead>{t('ReplicationTab.columns.rate')}</TableHead>
                  <TableHead>{t('ReplicationTab.columns.status')}</TableHead>
                  <TableHead>{t('ReplicationTab.columns.lastSync')}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {jobs.map((j) => {
                  const id = j.id || '';
                  const isExpanded = expandedId === id;
                  return (
                    <React.Fragment key={id}>
                      <TableRow
                        className="cursor-pointer hover:bg-muted/50"
                        onClick={() => setExpandedId(isExpanded ? null : id)}
                      >
                        <TableCell>
                          {isExpanded
                            ? <ChevronDown className="h-4 w-4" />
                            : <ChevronRight className="h-4 w-4" />}
                        </TableCell>
                        <TableCell className="font-mono text-xs">{id}</TableCell>
                        <TableCell><Badge variant="outline">{j.type || '--'}</Badge></TableCell>
                        <TableCell className="text-sm">{j.source || '--'}</TableCell>
                        <TableCell className="text-sm">{j.target || '--'}</TableCell>
                        <TableCell className="text-sm">{j.guest ?? '--'}</TableCell>
                        <TableCell className="font-mono text-xs">{j.schedule || '--'}</TableCell>
                        <TableCell className="text-sm">{j.rate != null ? `${j.rate} MB/s` : '--'}</TableCell>
                        <TableCell>{statusBadge(j, t)}</TableCell>
                        <TableCell className="text-sm">{formatTimestamp(j.last_sync as string | number | null | undefined)}</TableCell>
                      </TableRow>
                      {isExpanded && (
                        <TableRow key={`${id}-log`}>
                          <TableCell colSpan={10} className="p-0">
                            <ExpandableLog controllerId={controllerId} replicationId={id} />
                          </TableCell>
                        </TableRow>
                      )}
                    </React.Fragment>
                  );
                })}
              </TableBody>
            </Table>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

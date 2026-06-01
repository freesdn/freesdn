// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Hypervisor Module - Ceph Tab
 * Displays Ceph cluster status, storage usage, OSDs, pools, and monitors.
 */
/* eslint-disable @typescript-eslint/no-explicit-any */
import { useQuery } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { HardDrive, CheckCircle, XCircle, Database, Server } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { Skeleton } from '@/components/ui/skeleton';
import { EmptyState } from '@/components/ui/empty-state';
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table';
import { hypervisorApi } from '@/lib/api';
import { formatBytes } from './helpers';

interface CephTabProps {
  controllerId: string;
  nodes: { node: string; status: string }[];
}

function healthBadge(health: string | undefined, t: (key: string) => string) {
  if (!health) return <Badge variant="secondary">{t('CephTab.status.unknown')}</Badge>;
  if (health === 'HEALTH_OK') {
    return <Badge className="bg-green-600 text-white">{health}</Badge>;
  }
  if (health === 'HEALTH_WARN') {
    return <Badge className="bg-amber-500 text-white">{health}</Badge>;
  }
  return <Badge variant="destructive">{health}</Badge>;
}

export function CephTab({ controllerId, nodes }: CephTabProps) {
  const { t } = useTranslation('hypervisor');
  const queryNode = nodes[0]?.node || '';

  // Ceph status (high-level cluster health + usage)
  const {
    data: statusResp,
    isLoading: statusLoading,
    isError: statusError,
  } = useQuery({
    queryKey: ['hypervisor', 'ceph-status', controllerId, queryNode],
    queryFn: () => hypervisorApi.getCephStatus(controllerId, queryNode),
    enabled: !!controllerId && !!queryNode,
    refetchInterval: 30_000,
  });
  const cephStatus = statusResp?.data;

  // Ceph detail (OSDs, pools, mons, mds, crush_rules)
  const {
    data: detailResp,
    isLoading: detailLoading,
    isError: detailError,
  } = useQuery({
    queryKey: ['hypervisor', 'ceph-detail', controllerId, queryNode],
    queryFn: () => hypervisorApi.getCephDetail(controllerId, queryNode),
    enabled: !!controllerId && !!queryNode,
    refetchInterval: 30_000,
  });  const detail: any = detailResp?.data || {};  const osds: any[] = detail.osds || [];  const pools: any[] = detail.pools || [];  const mons: any[] = detail.mons || detail.mon || [];

  if (nodes.length === 0) {
    return (
      <EmptyState
        icon={HardDrive}
        title={t('CephTab.empty.noNodes.title')}
        description={t('CephTab.empty.noNodes.description')}
      />
    );
  }

  if (statusLoading && detailLoading) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-40" />
        <Skeleton className="h-64" />
      </div>
    );
  }

  if (statusError && detailError) {
    return (
      <EmptyState
        icon={HardDrive}
        title={t('CephTab.empty.notAvailable.title')}
        description={t('CephTab.empty.notAvailable.description')}
      />
    );
  }

  return (
    <div className="space-y-6">
      {/* ── Status Card ───────────────────────────────────────────────── */}
      {statusLoading ? (
        <Skeleton className="h-40" />
      ) : statusError || !cephStatus ? (
        <EmptyState
          icon={HardDrive}
          title={t('CephTab.empty.statusUnavailable.title')}
          description={t('CephTab.empty.statusUnavailable.description')}
        />
      ) : (
        <Card>
          <CardHeader className="pb-2">
            <div className="flex items-center justify-between">
              <CardTitle className="text-base flex items-center gap-2">
                <HardDrive className="h-5 w-5 text-muted-foreground" />
                {t('CephTab.status.clusterStatus')}
              </CardTitle>
              {healthBadge(cephStatus.health, t)}
            </div>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
              <div>
                <p className="text-xs text-muted-foreground">{t('CephTab.status.osds')}</p>
                <p className="text-sm font-medium">
                  {t('CephTab.status.osdSummary', {
                    total: cephStatus.num_osds,
                    up: cephStatus.num_osds_up,
                    in: cephStatus.num_osds_in,
                  })}
                </p>
              </div>
              <div>
                <p className="text-xs text-muted-foreground">{t('CephTab.status.pgs')}</p>
                <p className="text-sm font-medium">{cephStatus.num_pgs}</p>
              </div>
              <div>
                <p className="text-xs text-muted-foreground">{t('CephTab.status.pools')}</p>
                <p className="text-sm font-medium">{cephStatus.num_pools}</p>
              </div>
              <div>
                <p className="text-xs text-muted-foreground">{t('CephTab.status.usage')}</p>
                <p className="text-sm font-medium">{cephStatus.used_percent.toFixed(1)}%</p>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* ── Storage Card ──────────────────────────────────────────────── */}
      {cephStatus && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-base flex items-center gap-2">
              <Database className="h-5 w-5 text-muted-foreground" />
              {t('CephTab.storage.title')}
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-4">
              <div>
                <p className="text-xs text-muted-foreground">{t('CephTab.storage.used')}</p>
                <p className="text-sm font-medium">{formatBytes(cephStatus.used_bytes)}</p>
              </div>
              <div>
                <p className="text-xs text-muted-foreground">{t('CephTab.storage.available')}</p>
                <p className="text-sm font-medium">{formatBytes(cephStatus.avail_bytes)}</p>
              </div>
              <div>
                <p className="text-xs text-muted-foreground">{t('CephTab.storage.total')}</p>
                <p className="text-sm font-medium">{formatBytes(cephStatus.total_bytes)}</p>
              </div>
            </div>
            <div className="space-y-1">
              <div className="flex justify-between text-xs text-muted-foreground">
                <span>{t('CephTab.storage.capacity')}</span>
                <span>
                  {formatBytes(cephStatus.used_bytes)} / {formatBytes(cephStatus.total_bytes)} (
                  {cephStatus.used_percent.toFixed(1)}%)
                </span>
              </div>
              <Progress
                value={cephStatus.used_percent}
                className={`h-2 ${
                  cephStatus.used_percent > 85
                    ? '[&>div]:bg-red-500'
                    : cephStatus.used_percent > 70
                      ? '[&>div]:bg-amber-500'
                      : ''
                }`}
              />
            </div>
          </CardContent>
        </Card>
      )}

      {/* ── OSDs Table ────────────────────────────────────────────────── */}
      {detailLoading ? (
        <Skeleton className="h-48" />
      ) : osds.length > 0 ? (
        <Card>
          <CardHeader className="pb-2">
            <div className="flex items-center gap-2">
              <HardDrive className="h-4 w-4 text-muted-foreground" />
              <CardTitle className="text-sm">{t('CephTab.osds.title')}</CardTitle>
              <Badge variant="secondary" className="ml-auto">{osds.length}</Badge>
            </div>
          </CardHeader>
          <CardContent className="p-0">
            <div className="max-h-[400px] overflow-y-auto overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>{t('CephTab.osds.columns.id')}</TableHead>
                    <TableHead>{t('CephTab.osds.columns.name')}</TableHead>
                    <TableHead>{t('CephTab.osds.columns.status')}</TableHead>
                    <TableHead>{t('CephTab.osds.columns.in')}</TableHead>
                    <TableHead>{t('CephTab.osds.columns.size')}</TableHead>
                    <TableHead>{t('CephTab.osds.columns.used')}</TableHead>
                    <TableHead>{t('CephTab.osds.columns.available')}</TableHead>
                    <TableHead>{t('CephTab.osds.columns.crushWeight')}</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>                  {osds.map((osd: any) => {
                    const osdId = osd.id ?? osd.osd;
                    const totalBytes = osd.total_bytes || osd.kb * 1024 || 0;
                    const usedBytes = osd.used_bytes || osd.kb_used * 1024 || 0;
                    const availBytes = osd.avail_bytes || osd.kb_avail * 1024 || totalBytes - usedBytes;
                    return (
                      <TableRow key={osdId}>
                        <TableCell className="font-mono text-xs">{osdId}</TableCell>
                        <TableCell className="text-sm">
                          {osd.name || osd.host || `osd.${osdId}`}
                        </TableCell>
                        <TableCell>
                          {osd.up ? (
                            <Badge className="bg-green-600 text-white">{t('CephTab.osds.up')}</Badge>
                          ) : (
                            <Badge variant="destructive">{t('CephTab.osds.down')}</Badge>
                          )}
                        </TableCell>
                        <TableCell>
                          {osd.in !== false && osd.in !== 0 ? (
                            <span className="flex items-center gap-1">
                              <CheckCircle className="h-3 w-3 text-green-500" />
                              <span className="text-xs">{t('CephTab.osds.yes')}</span>
                            </span>
                          ) : (
                            <span className="flex items-center gap-1">
                              <XCircle className="h-3 w-3 text-destructive" />
                              <span className="text-xs">{t('CephTab.osds.no')}</span>
                            </span>
                          )}
                        </TableCell>
                        <TableCell className="text-xs">
                          {totalBytes > 0 ? formatBytes(totalBytes) : '-'}
                        </TableCell>
                        <TableCell className="text-xs">
                          {usedBytes > 0 ? formatBytes(usedBytes) : '-'}
                        </TableCell>
                        <TableCell className="text-xs">
                          {availBytes > 0 ? formatBytes(availBytes) : '-'}
                        </TableCell>
                        <TableCell className="text-xs">{osd.crush_weight ?? '-'}</TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            </div>
          </CardContent>
        </Card>
      ) : null}

      {/* ── Pools Table ───────────────────────────────────────────────── */}
      {!detailLoading && pools.length > 0 && (
        <Card>
          <CardHeader className="pb-2">
            <div className="flex items-center gap-2">
              <Database className="h-4 w-4 text-muted-foreground" />
              <CardTitle className="text-sm">{t('CephTab.pools.title')}</CardTitle>
              <Badge variant="secondary" className="ml-auto">{pools.length}</Badge>
            </div>
          </CardHeader>
          <CardContent className="p-0">
            <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t('CephTab.pools.columns.name')}</TableHead>
                  <TableHead>{t('CephTab.pools.columns.size')}</TableHead>
                  <TableHead>{t('CephTab.pools.columns.pgNum')}</TableHead>
                  <TableHead>{t('CephTab.pools.columns.crushRule')}</TableHead>
                  <TableHead>{t('CephTab.pools.columns.usage')}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>                {pools.map((pool: any) => (
                  <TableRow key={pool.pool_name || pool.pool}>
                    <TableCell className="font-medium text-sm">
                      {pool.pool_name || pool.pool}
                    </TableCell>
                    <TableCell className="text-xs">{pool.size || '-'}</TableCell>
                    <TableCell className="text-xs">{pool.pg_num || '-'}</TableCell>
                    <TableCell className="text-xs">{pool.crush_rule ?? '-'}</TableCell>
                    <TableCell className="text-xs">
                      {pool.bytes_used != null
                        ? `${formatBytes(pool.bytes_used)} (${pool.percent_used != null ? (pool.percent_used * 100).toFixed(1) + '%' : '-'})`
                        : '-'}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
            </div>
          </CardContent>
        </Card>
      )}

      {/* ── Monitors Table ────────────────────────────────────────────── */}
      {!detailLoading && mons.length > 0 && (
        <Card>
          <CardHeader className="pb-2">
            <div className="flex items-center gap-2">
              <Server className="h-4 w-4 text-muted-foreground" />
              <CardTitle className="text-sm">{t('CephTab.monitors.title')}</CardTitle>
              <Badge variant="secondary" className="ml-auto">{mons.length}</Badge>
            </div>
          </CardHeader>
          <CardContent className="p-0">
            <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t('CephTab.monitors.columns.name')}</TableHead>
                  <TableHead>{t('CephTab.monitors.columns.address')}</TableHead>
                  <TableHead>{t('CephTab.monitors.columns.rank')}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>                {mons.map((mon: any) => (
                  <TableRow key={mon.name}>
                    <TableCell className="font-medium text-sm">{mon.name}</TableCell>
                    <TableCell className="font-mono text-xs">
                      {mon.addr || mon.public_addr || '-'}
                    </TableCell>
                    <TableCell className="text-xs">{mon.rank ?? '-'}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

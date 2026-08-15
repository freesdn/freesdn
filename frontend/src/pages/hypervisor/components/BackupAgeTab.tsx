// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Hypervisor Module - Backup Age Tab
 * Shows backup age report with configurable threshold alerting
 * and PBS prune functionality.
 */
/* eslint-disable @typescript-eslint/no-explicit-any */
import { useState, useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import type { TFunction } from 'i18next';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { AlertTriangle, CheckCircle, XCircle, ChevronDown, ChevronRight, Scissors, Eye, Loader2, Trash2 } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Skeleton } from '@/components/ui/skeleton';
import { DestructiveConfirmDialog } from '@/components/ui/destructive-confirm-dialog';
import { ErrorState } from '@/components/ui/empty-state';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Label } from '@/components/ui/label';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { useToast } from '@/hooks/use-toast';
import { hypervisorApi } from '@/lib/api';
import { formatBytes } from './helpers';

interface BackupAgeTabProps {
  controllerId: string;
  nodes: { node: string }[];
}

const buildThresholdOptions = (t: TFunction) => [
  { value: '12', label: t('BackupAgeTab.thresholds.12h') },
  { value: '24', label: t('BackupAgeTab.thresholds.24h') },
  { value: '48', label: t('BackupAgeTab.thresholds.48h') },
  { value: '72', label: t('BackupAgeTab.thresholds.72h') },
  { value: '168', label: t('BackupAgeTab.thresholds.7d') },
];

function formatAge(hours: number | null | undefined, t: TFunction): string {
  if (hours == null) return t('BackupAgeTab.age.never');
  if (hours < 1) return `${Math.round(hours * 60)}m`;
  if (hours < 24) return `${hours.toFixed(1)}h`;
  const days = Math.floor(hours / 24);
  const h = Math.round(hours % 24);
  return `${days}d ${h}h`;
}

export function BackupAgeTab({ controllerId, nodes }: BackupAgeTabProps) {
  const { t } = useTranslation('hypervisor');
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const thresholdOptions = buildThresholdOptions(t);
  const [thresholdHours, setThresholdHours] = useState('24');

  const { data: reportResp, isLoading, isError, refetch } = useQuery({
    queryKey: ['hypervisor', 'backup-age', controllerId, thresholdHours],
    queryFn: () => hypervisorApi.getBackupAgeReport(controllerId, parseInt(thresholdHours)),
    enabled: !!controllerId,
    refetchInterval: 60_000,
  });
  const report: any = reportResp?.data || {};
  const vms: any[] = report?.vms || report?.guests || [];

  // Derive summary counts
  const totalVMs = vms.length;
  const neverBacked = vms.filter((v: any) => v.status === 'never' || v.last_backup == null).length;
  const stale = vms.filter((v: any) => v.status === 'stale').length;
  const ok = vms.filter((v: any) => v.status === 'ok').length;

  // Sort by age descending (worst first): never > stale > ok
  const sorted = [...vms].sort((a: any, b: any) => {
    const statusOrder = (s: string) => s === 'never' ? 3 : s === 'stale' ? 2 : 1;
    const orderDiff = statusOrder(b.status) - statusOrder(a.status);
    if (orderDiff !== 0) return orderDiff;
    return (b.age_hours ?? Infinity) - (a.age_hours ?? Infinity);
  });

  // ── Prune section state ─────────────────────────────────────────────
  const [pruneExpanded, setPruneExpanded] = useState(false);
  // Prune is irreversible; the typed-confirm dialog replaces the
  // bare confirm() one-click trap.
  const [pruneConfirmOpen, setPruneConfirmOpen] = useState(false);
  const [pruneNode, setPruneNode] = useState(nodes[0]?.node || '');
  useEffect(() => {
    if (!pruneNode && nodes.length > 0) setPruneNode(nodes[0].node);
  }, [nodes, pruneNode]);
  const [pruneStorage, setPruneStorage] = useState('');
  const [pruneVmid, setPruneVmid] = useState('');
  const [keepLast, setKeepLast] = useState('');
  const [keepHourly, setKeepHourly] = useState('');
  const [keepDaily, setKeepDaily] = useState('');
  const [keepWeekly, setKeepWeekly] = useState('');
  const [keepMonthly, setKeepMonthly] = useState('');
  const [keepYearly, setKeepYearly] = useState('');
  const [prunePreview, setPrunePreview] = useState<any[] | null>(null);

  // Fetch storage pools for the selected prune node
  const { data: storageResp } = useQuery({
    queryKey: ['hypervisor', 'storage', controllerId, pruneNode],
    queryFn: () => hypervisorApi.getStorage(controllerId, pruneNode),
    enabled: !!controllerId && !!pruneNode && pruneExpanded,
  });
  const storagePools: any[] = (storageResp?.data || []).filter(
    (s: any) => s.content?.includes('backup')
  );

  const prunePreviewMutation = useMutation({
    mutationFn: () => {
      if (!pruneNode || !pruneStorage) throw new Error(t('BackupAgeTab.errors.selectNodeStorage'));
      return hypervisorApi.getPrunePreview(
        controllerId, pruneNode, pruneStorage,
        pruneVmid ? parseInt(pruneVmid) : undefined,
      );
    },
    onSuccess: (resp) => {
      const data = resp?.data;
      setPrunePreview(Array.isArray(data) ? data : []);
    },
    onError: (err: any) => {
      toast({ title: t('BackupAgeTab.toast.previewFailed'), description: err?.response?.data?.detail || err.message, variant: 'destructive' });
    },
  });

  const pruneNowMutation = useMutation({
    mutationFn: () => {
      if (!pruneNode || !pruneStorage) throw new Error(t('BackupAgeTab.errors.selectNodeStorage'));
      const toNum = (v: string) => v ? parseInt(v) : undefined;
      return hypervisorApi.pruneBackups(controllerId, pruneNode, pruneStorage, {
        node: pruneNode,
        storage: pruneStorage,
        keep_last: toNum(keepLast),
        keep_hourly: toNum(keepHourly),
        keep_daily: toNum(keepDaily),
        keep_weekly: toNum(keepWeekly),
        keep_monthly: toNum(keepMonthly),
        keep_yearly: toNum(keepYearly),
        vmid: pruneVmid ? parseInt(pruneVmid) : undefined,
      });
    },
    onSuccess: () => {
      toast({ title: t('BackupAgeTab.toast.pruneCompleted') });
      setPrunePreview(null);
      queryClient.invalidateQueries({ queryKey: ['hypervisor', 'backup-age'] });
    },
    onError: (err: any) => {
      toast({ title: t('BackupAgeTab.toast.pruneFailed'), description: err?.response?.data?.detail || err.message, variant: 'destructive' });
    },
  });

  return (
    <div className="space-y-4">
      {isError && (
        <div className="rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-sm text-destructive">
          {t('BackupAgeTab.errors.loadBanner')}
          <button onClick={() => refetch()} className="underline ml-2">{t('BackupAgeTab.actions.retry')}</button>
        </div>
      )}
      {/* Controls */}
      <div className="flex items-center gap-4">
        <div className="flex items-center gap-2">
          <Label className="text-sm">{t('BackupAgeTab.labels.threshold')}</Label>
          <Select value={thresholdHours} onValueChange={setThresholdHours}>
            <SelectTrigger className="w-[140px]">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {thresholdOptions.map((opt) => (
                <SelectItem key={opt.value} value={opt.value}>{opt.label}</SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      </div>

      {isLoading ? (
        <Skeleton className="h-64" />
      ) : isError ? (
        <ErrorState message={t('BackupAgeTab.errors.loadReport')} onRetry={() => refetch()} />
      ) : (
        <>
          {/* Summary Cards */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <Card>
              <CardContent noOffset className="text-center">
                <p className="text-xs text-muted-foreground mb-1">{t('BackupAgeTab.summary.totalVMs')}</p>
                <p className="text-2xl font-bold">{totalVMs}</p>
              </CardContent>
            </Card>
            <Card>
              <CardContent noOffset className="text-center">
                <p className="text-xs text-muted-foreground mb-1">{t('BackupAgeTab.summary.backedUpOk')}</p>
                <p className="text-2xl font-bold text-green-500">{ok}</p>
              </CardContent>
            </Card>
            <Card>
              <CardContent noOffset className="text-center">
                <p className="text-xs text-muted-foreground mb-1">{t('BackupAgeTab.summary.stale')}</p>
                <p className="text-2xl font-bold text-amber-500">{stale}</p>
              </CardContent>
            </Card>
            <Card>
              <CardContent noOffset className="text-center">
                <p className="text-xs text-muted-foreground mb-1">{t('BackupAgeTab.summary.neverBackedUp')}</p>
                <p className="text-2xl font-bold text-red-500">{neverBacked}</p>
              </CardContent>
            </Card>
          </div>

          {/* VM Table */}
          {sorted.length === 0 ? (
            <p className="text-sm text-muted-foreground text-center py-8">{t('BackupAgeTab.empty.noVMs')}</p>
          ) : (
            <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t('BackupAgeTab.table.vmid')}</TableHead>
                  <TableHead>{t('BackupAgeTab.table.name')}</TableHead>
                  <TableHead>{t('BackupAgeTab.table.node')}</TableHead>
                  <TableHead>{t('BackupAgeTab.table.lastBackup')}</TableHead>
                  <TableHead>{t('BackupAgeTab.table.age')}</TableHead>
                  <TableHead>{t('BackupAgeTab.table.status')}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {sorted.map((vm: any) => (
                  <TableRow key={vm.vmid}>
                    <TableCell className="font-mono text-xs">{vm.vmid}</TableCell>
                    <TableCell className="font-medium text-sm">{vm.name || '-'}</TableCell>
                    <TableCell className="text-xs text-muted-foreground">{vm.node || '-'}</TableCell>
                    <TableCell className="text-xs">
                      {vm.last_backup
                        ? new Date(typeof vm.last_backup === 'number' ? vm.last_backup * 1000 : vm.last_backup).toLocaleString()
                        : '-'}
                    </TableCell>
                    <TableCell className="text-xs tabular-nums">{formatAge(vm.age_hours, t)}</TableCell>
                    <TableCell>
                      {vm.status === 'ok' ? (
                        <Badge variant="default" className="gap-1 text-xs">
                          <CheckCircle className="h-3 w-3" /> {t('BackupAgeTab.status.ok')}
                        </Badge>
                      ) : vm.status === 'stale' ? (
                        <Badge variant="secondary" className="gap-1 text-xs bg-amber-500/10 text-amber-500 border-amber-500/20">
                          <AlertTriangle className="h-3 w-3" /> {t('BackupAgeTab.status.stale')}
                        </Badge>
                      ) : (
                        <Badge variant="destructive" className="gap-1 text-xs">
                          <XCircle className="h-3 w-3" /> {t('BackupAgeTab.status.never')}
                        </Badge>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
            </div>
          )}
        </>
      )}

      {/* ── Prune Backups Section ──────────────────────────────────────── */}
      <Card>
        <CardHeader
          className="pb-2 cursor-pointer"
          onClick={() => setPruneExpanded(!pruneExpanded)}
        >
          <CardTitle className="text-sm flex items-center gap-2">
            {pruneExpanded ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
            <Scissors className="h-4 w-4 text-muted-foreground" />
            {t('BackupAgeTab.prune.title')}
          </CardTitle>
        </CardHeader>
        {pruneExpanded && (
          <CardContent className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <Label className="text-xs">{t('BackupAgeTab.prune.node')}</Label>
                <Select value={pruneNode} onValueChange={(v) => { setPruneNode(v); setPruneStorage(''); setPrunePreview(null); }}>
                  <SelectTrigger className="h-8">
                    <SelectValue placeholder={t('BackupAgeTab.prune.selectNode')} />
                  </SelectTrigger>
                  <SelectContent>
                    {nodes.map((n) => (
                      <SelectItem key={n.node} value={n.node}>{n.node}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div>
                <Label className="text-xs">{t('BackupAgeTab.prune.storage')}</Label>
                <Select value={pruneStorage} onValueChange={(v) => { setPruneStorage(v); setPrunePreview(null); }}>
                  <SelectTrigger className="h-8">
                    <SelectValue placeholder={t('BackupAgeTab.prune.selectStorage')} />
                  </SelectTrigger>
                  <SelectContent>
                    {storagePools.map((s: any) => (
                      <SelectItem key={s.storage} value={s.storage}>{s.storage}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
              <div>
                <Label className="text-xs">{t('BackupAgeTab.prune.keepLast')}</Label>
                <Input className="h-8" type="number" min={0} value={keepLast} onChange={(e) => setKeepLast(e.target.value)} placeholder="-" />
              </div>
              <div>
                <Label className="text-xs">{t('BackupAgeTab.prune.keepHourly')}</Label>
                <Input className="h-8" type="number" min={0} value={keepHourly} onChange={(e) => setKeepHourly(e.target.value)} placeholder="-" />
              </div>
              <div>
                <Label className="text-xs">{t('BackupAgeTab.prune.keepDaily')}</Label>
                <Input className="h-8" type="number" min={0} value={keepDaily} onChange={(e) => setKeepDaily(e.target.value)} placeholder="-" />
              </div>
              <div>
                <Label className="text-xs">{t('BackupAgeTab.prune.keepWeekly')}</Label>
                <Input className="h-8" type="number" min={0} value={keepWeekly} onChange={(e) => setKeepWeekly(e.target.value)} placeholder="-" />
              </div>
              <div>
                <Label className="text-xs">{t('BackupAgeTab.prune.keepMonthly')}</Label>
                <Input className="h-8" type="number" min={0} value={keepMonthly} onChange={(e) => setKeepMonthly(e.target.value)} placeholder="-" />
              </div>
              <div>
                <Label className="text-xs">{t('BackupAgeTab.prune.keepYearly')}</Label>
                <Input className="h-8" type="number" min={0} value={keepYearly} onChange={(e) => setKeepYearly(e.target.value)} placeholder="-" />
              </div>
            </div>

            <div>
              <Label className="text-xs">{t('BackupAgeTab.prune.vmidFilter')}</Label>
              <Input
                className="h-8 w-[120px]"
                type="number"
                value={pruneVmid}
                onChange={(e) => setPruneVmid(e.target.value.replace(/\D/g, ''))}
                placeholder={t('BackupAgeTab.prune.allVMs')}
              />
            </div>

            <div className="flex gap-2">
              <Button
                size="sm"
                variant="outline"
                onClick={() => prunePreviewMutation.mutate()}
                disabled={!pruneNode || !pruneStorage || prunePreviewMutation.isPending}
              >
                {prunePreviewMutation.isPending ? (
                  <Loader2 className="h-3.5 w-3.5 mr-1 animate-spin" />
                ) : (
                  <Eye className="h-3.5 w-3.5 mr-1" />
                )}
                {t('BackupAgeTab.actions.preview')}
              </Button>
              <Button
                size="sm"
                variant="destructive"
                onClick={() => setPruneConfirmOpen(true)}
                disabled={!pruneNode || !pruneStorage || pruneNowMutation.isPending || !(keepLast || keepHourly || keepDaily || keepWeekly || keepMonthly || keepYearly)}
              >
                {pruneNowMutation.isPending ? (
                  <Loader2 className="h-3.5 w-3.5 mr-1 animate-spin" />
                ) : (
                  <Trash2 className="h-3.5 w-3.5 mr-1" />
                )}
                {t('BackupAgeTab.actions.pruneNow')}
              </Button>
              <DestructiveConfirmDialog
                open={pruneConfirmOpen}
                onOpenChange={setPruneConfirmOpen}
                title={t('BackupAgeTab.dialog.title')}
                description={t('BackupAgeTab.dialog.description', { storage: pruneStorage, node: pruneNode })}
                confirmationText={pruneStorage || 'PRUNE'}
                confirmLabel={t('BackupAgeTab.dialog.confirmLabel')}
                isPending={pruneNowMutation.isPending}
                onConfirm={() => {
                  pruneNowMutation.mutate();
                  setPruneConfirmOpen(false);
                }}
              />
            </div>

            {/* Prune preview results */}
            {prunePreview !== null && (
              <div className="border rounded-md overflow-hidden">
                {prunePreview.length === 0 ? (
                  <p className="text-sm text-muted-foreground text-center py-4">{t('BackupAgeTab.empty.noBackups')}</p>
                ) : (
                  <div className="overflow-x-auto">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead className="text-xs">{t('BackupAgeTab.previewTable.backup')}</TableHead>
                        <TableHead className="text-xs">{t('BackupAgeTab.previewTable.vmid')}</TableHead>
                        <TableHead className="text-xs">{t('BackupAgeTab.previewTable.size')}</TableHead>
                        <TableHead className="text-xs">{t('BackupAgeTab.previewTable.date')}</TableHead>
                        <TableHead className="text-xs">{t('BackupAgeTab.previewTable.action')}</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {prunePreview.map((item: any, idx: number) => {
                        const willRemove = item.mark === 'remove' || item.type === 'remove' || item.remove;
                        return (
                          <TableRow key={idx} className={willRemove ? 'bg-red-50 dark:bg-red-950/20' : ''}>
                            <TableCell className="font-mono text-[10px] max-w-[300px] truncate" title={item.volid || item.archive || item.filename}>
                              {item.volid || item.archive || item.filename || '-'}
                            </TableCell>
                            <TableCell className="font-mono text-xs">{item.vmid || '-'}</TableCell>
                            <TableCell className="text-xs">{item.size ? formatBytes(item.size) : '-'}</TableCell>
                            <TableCell className="text-xs">
                              {item.ctime
                                ? new Date(typeof item.ctime === 'number' ? item.ctime * 1000 : item.ctime).toLocaleString()
                                : '-'}
                            </TableCell>
                            <TableCell>
                              {willRemove ? (
                                <Badge variant="destructive" className="text-[10px]">{t('BackupAgeTab.previewTable.remove')}</Badge>
                              ) : (
                                <Badge variant="default" className="text-[10px]">{t('BackupAgeTab.previewTable.keep')}</Badge>
                              )}
                            </TableCell>
                          </TableRow>
                        );
                      })}
                    </TableBody>
                  </Table>
                  </div>
                )}
              </div>
            )}
          </CardContent>
        )}
      </Card>
    </div>
  );
}

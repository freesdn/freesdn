// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Hypervisor Module - PBS (Proxmox Backup Server) Tab
 * Shows backup prune preview, prune execution, and restore capabilities
 * for PVE storage that uses PBS as a backend.
 */
/* eslint-disable @typescript-eslint/no-explicit-any */
import { useState, useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Archive,
  Trash2,
  RefreshCw,
  AlertTriangle,
  Shield,
  Loader2,
} from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Skeleton } from '@/components/ui/skeleton';
import { ErrorState } from '@/components/ui/empty-state';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { useToast } from '@/hooks/use-toast';
import { hypervisorApi } from '@/lib/api';
import { formatBytes, formatTimestamp } from './helpers';
import type { HypervisorNode, HypervisorStorage } from '@/lib/api';

interface PBSTabProps {
  controllerId: string;
  nodes: HypervisorNode[];
}

export function PBSTab({ controllerId, nodes }: PBSTabProps) {
  const { t } = useTranslation('hypervisor');
  const queryClient = useQueryClient();
  const { toast } = useToast();

  // State
  const [selectedNode, setSelectedNode] = useState(nodes[0]?.node || '');
  useEffect(() => {
    if (!selectedNode && nodes.length > 0) setSelectedNode(nodes[0].node);
  }, [nodes, selectedNode]);
  const [selectedStorage, setSelectedStorage] = useState('');
  const [vmidFilter, setVmidFilter] = useState('');
  const [pruneDialog, setPruneDialog] = useState(false);
  const [pruneKeepLast, setPruneKeepLast] = useState('3');
  const [pruneKeepDaily, setPruneKeepDaily] = useState('7');
  const [pruneKeepWeekly, setPruneKeepWeekly] = useState('4');
  const [pruneKeepMonthly, setPruneKeepMonthly] = useState('3');

  // Fetch storage pools for the selected node to find PBS-type storages
  const { data: storageResp, isError: storageError, error: storageErr } = useQuery({
    queryKey: ['hypervisor', 'storage', controllerId, selectedNode],
    queryFn: () => hypervisorApi.getStorage(controllerId, selectedNode),
    enabled: !!controllerId && !!selectedNode,
  });
  // Backend errors silently rendered as
  // "no PBS storage found", operator couldn't tell whether they
  // really had no PBS or whether the API was down. The isError
  // banner below surfaces the failure mode explicitly.
  const storagePools: HypervisorStorage[] = (storageResp?.data as any) || [];
  // All backup-capable storages for display
  const backupStorages = storagePools.filter(
    (s: any) => s.content?.includes('backup') || s.storage_type === 'pbs',
  );
  // PBS storages support prune preview; others do not
  const pbsStorages = backupStorages.filter(
    (s: any) => s.storage_type === 'pbs',
  );

  // Auto-select first PBS storage (prefer PBS, fall back to any backup storage)
  const effectiveStorage = selectedStorage || pbsStorages[0]?.storage || backupStorages[0]?.storage || '';
  const effectiveStorageObj = backupStorages.find((s: any) => s.storage === effectiveStorage);
  const isPbs = effectiveStorageObj?.storage_type === 'pbs';

  // Fetch prune preview
  const parsedVmid = vmidFilter ? parseInt(vmidFilter, 10) : undefined;
  const {
    data: pruneResp,
    isLoading: pruneLoading,
    isError: pruneError,
    refetch: refetchPrune,
  } = useQuery({
    queryKey: ['hypervisor', 'prune-preview', controllerId, selectedNode, effectiveStorage, parsedVmid],
    queryFn: () =>
      hypervisorApi.getPrunePreview(
        controllerId,
        selectedNode,
        effectiveStorage,
        parsedVmid && !isNaN(parsedVmid) ? parsedVmid : undefined,
      ),
    enabled: !!controllerId && !!selectedNode && !!effectiveStorage && isPbs,
    retry: false,
    refetchInterval: 60_000,
  });
  const pruneItems: any[] = (pruneResp?.data as any) || [];

  // Counts
  const keepCount = pruneItems.filter((i: any) => i.mark === 'keep' || i['keep']).length;
  const removeCount = pruneItems.filter((i: any) => i.mark === 'remove' || i['remove']).length;

  // Prune mutation
  const pruneMut = useMutation({
    mutationFn: () =>
      hypervisorApi.pruneBackups(controllerId, selectedNode, effectiveStorage, {
        node: selectedNode,
        storage: effectiveStorage,
        keep_last: parseInt(pruneKeepLast) || undefined,
        keep_daily: parseInt(pruneKeepDaily) || undefined,
        keep_weekly: parseInt(pruneKeepWeekly) || undefined,
        keep_monthly: parseInt(pruneKeepMonthly) || undefined,
        vmid: parsedVmid && !isNaN(parsedVmid) ? parsedVmid : undefined,
      }),
    onSuccess: () => {
      toast({ title: t('PBSTab.toast.pruneStarted.title'), description: t('PBSTab.toast.pruneStarted.description') });
      setPruneDialog(false);
      queryClient.invalidateQueries({ queryKey: ['hypervisor', 'prune-preview'] });
      queryClient.invalidateQueries({ queryKey: ['hypervisor', 'storage-content'] });
    },
    onError: (err: any) => {
      toast({ title: t('PBSTab.toast.pruneFailed.title'), description: err?.message || t('PBSTab.toast.pruneFailed.description'), variant: 'destructive' });
    },
  });

  return (
    <div className="space-y-4">
      {storageError && (
        <div className="rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-sm text-destructive">
          {t('PBSTab.storageError.prefix')}{String((storageErr as any)?.response?.data?.detail || (storageErr as any)?.message || t('PBSTab.storageError.unknown'))}.
          {' '}{t('PBSTab.storageError.suffix')}
        </div>
      )}
      {/* Controls */}
      <div className="flex flex-wrap items-center gap-4">
        <div className="flex items-center gap-2">
          <Label className="text-sm whitespace-nowrap">{t('PBSTab.controls.nodeLabel')}</Label>
          <Select value={selectedNode} onValueChange={setSelectedNode}>
            <SelectTrigger className="w-[180px]">
              <SelectValue placeholder={t('PBSTab.controls.nodePlaceholder')} />
            </SelectTrigger>
            <SelectContent>
              {nodes.map((n) => (
                <SelectItem key={n.node} value={n.node}>
                  {n.node}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

        <div className="flex items-center gap-2">
          <Label className="text-sm whitespace-nowrap">{t('PBSTab.controls.storageLabel')}</Label>
          <Select value={effectiveStorage} onValueChange={setSelectedStorage}>
            <SelectTrigger className="w-[180px]">
              <SelectValue placeholder={t('PBSTab.controls.storagePlaceholder')} />
            </SelectTrigger>
            <SelectContent>
              {backupStorages.length === 0 ? (
                <SelectItem value="_none" disabled>
                  {t('PBSTab.controls.noBackupStorage')}
                </SelectItem>
              ) : (
                backupStorages.map((s: any) => (
                  <SelectItem key={s.storage} value={s.storage}>
                    {s.storage} ({s.storage_type})
                  </SelectItem>
                ))
              )}
            </SelectContent>
          </Select>
        </div>

        <div className="flex items-center gap-2">
          <Label className="text-sm whitespace-nowrap">{t('PBSTab.controls.vmidLabel')}</Label>
          <Input
            value={vmidFilter}
            onChange={(e) => setVmidFilter(e.target.value.replace(/\D/g, ''))}
            placeholder={t('PBSTab.controls.vmidPlaceholder')}
            className="w-[100px]"
          />
        </div>

        <Button variant="outline" size="sm" onClick={() => refetchPrune()}>
          <RefreshCw className="h-3.5 w-3.5 mr-1" /> {t('PBSTab.actions.refresh')}
        </Button>

        <Button
          variant="destructive"
          size="sm"
          onClick={() => setPruneDialog(true)}
          disabled={!effectiveStorage || removeCount === 0}
        >
          <Trash2 className="h-3.5 w-3.5 mr-1" /> {t('PBSTab.actions.pruneBackups')}
        </Button>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <Card>
          <CardContent noOffset className="text-center">
            <p className="text-xs text-muted-foreground mb-1">{t('PBSTab.summary.totalBackups')}</p>
            <p className="text-2xl font-bold">{pruneItems.length}</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent noOffset className="text-center">
            <p className="text-xs text-muted-foreground mb-1">{t('PBSTab.summary.keep')}</p>
            <p className="text-2xl font-bold text-green-500">{keepCount}</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent noOffset className="text-center">
            <p className="text-xs text-muted-foreground mb-1">{t('PBSTab.summary.remove')}</p>
            <p className="text-2xl font-bold text-red-500">{removeCount}</p>
          </CardContent>
        </Card>
      </div>

      {/* Prune Preview Table */}
      {!effectiveStorage ? (
        <Card>
          <CardContent noOffset className="py-8 text-center">
            <Archive className="h-10 w-10 mx-auto text-muted-foreground mb-2" />
            <p className="text-sm font-medium mb-1">{t('PBSTab.empty.noStorage.title')}</p>
            <p className="text-xs text-muted-foreground">
              {t('PBSTab.empty.noStorage.description')}
            </p>
          </CardContent>
        </Card>
      ) : !isPbs ? (
        <Card>
          <CardContent noOffset className="py-8 text-center">
            <Archive className="h-10 w-10 mx-auto text-muted-foreground mb-2" />
            <p className="text-sm font-medium mb-1">{t('PBSTab.empty.notPbs.title')}</p>
            <p className="text-xs text-muted-foreground">
              <strong>{effectiveStorage}</strong> ({effectiveStorageObj?.storage_type}) {t('PBSTab.empty.notPbs.description')}
              {pbsStorages.length === 0 && ` ${t('PBSTab.empty.notPbs.noPbsConfigured')}`}
            </p>
          </CardContent>
        </Card>
      ) : pruneLoading ? (
        <Skeleton className="h-64" />
      ) : pruneError ? (
        <ErrorState message={t('PBSTab.pruneError')} onRetry={() => refetchPrune()} />
      ) : pruneItems.length === 0 ? (
        <Card>
          <CardContent noOffset className="py-8 text-center">
            <Archive className="h-10 w-10 mx-auto text-muted-foreground mb-2" />
            <p className="text-sm text-muted-foreground">
              {!effectiveStorage
                ? t('PBSTab.empty.noStorageOnNode')
                : t('PBSTab.empty.noSnapshots')}
            </p>
          </CardContent>
        </Card>
      ) : (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">{t('PBSTab.table.title')}</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t('PBSTab.table.vmid')}</TableHead>
                  <TableHead>{t('PBSTab.table.type')}</TableHead>
                  <TableHead>{t('PBSTab.table.created')}</TableHead>
                  <TableHead>{t('PBSTab.table.size')}</TableHead>
                  <TableHead>{t('PBSTab.table.mark')}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {pruneItems.map((item: any, idx: number) => {
                  const isKeep = item.mark === 'keep' || item['keep'];
                  return (
                    <TableRow key={idx} className={isKeep ? '' : 'bg-red-500/5'}>
                      <TableCell className="font-mono text-xs">{item.vmid ?? '--'}</TableCell>
                      <TableCell className="text-xs">{item.type || item.ctype || '--'}</TableCell>
                      <TableCell className="text-xs">
                        {formatTimestamp(item.ctime)}
                      </TableCell>
                      <TableCell className="text-xs tabular-nums">
                        {item.size ? formatBytes(item.size) : '--'}
                      </TableCell>
                      <TableCell>
                        {isKeep ? (
                          <Badge variant="default" className="gap-1 text-xs">
                            <Shield className="h-3 w-3" /> {t('PBSTab.mark.keep')}
                          </Badge>
                        ) : (
                          <Badge variant="destructive" className="gap-1 text-xs">
                            <Trash2 className="h-3 w-3" /> {t('PBSTab.mark.remove')}
                          </Badge>
                        )}
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Prune Confirmation Dialog */}
      <Dialog open={pruneDialog} onOpenChange={setPruneDialog}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <AlertTriangle className="h-5 w-5 text-amber-500" />
              {t('PBSTab.dialog.title')}
            </DialogTitle>
            <DialogDescription>
              {t('PBSTab.dialog.descriptionPrefix')}{' '}
              <strong>{effectiveStorage}</strong> ({selectedNode}).
              {' '}{t('PBSTab.dialog.descriptionSuffix')}
            </DialogDescription>
          </DialogHeader>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <Label className="text-xs">{t('PBSTab.dialog.keepLast')}</Label>
              <Input
                type="number"
                min={0}
                max={365}
                value={pruneKeepLast}
                onChange={(e) => setPruneKeepLast(e.target.value)}
              />
            </div>
            <div>
              <Label className="text-xs">{t('PBSTab.dialog.keepDaily')}</Label>
              <Input
                type="number"
                min={0}
                max={365}
                value={pruneKeepDaily}
                onChange={(e) => setPruneKeepDaily(e.target.value)}
              />
            </div>
            <div>
              <Label className="text-xs">{t('PBSTab.dialog.keepWeekly')}</Label>
              <Input
                type="number"
                min={0}
                max={365}
                value={pruneKeepWeekly}
                onChange={(e) => setPruneKeepWeekly(e.target.value)}
              />
            </div>
            <div>
              <Label className="text-xs">{t('PBSTab.dialog.keepMonthly')}</Label>
              <Input
                type="number"
                min={0}
                max={365}
                value={pruneKeepMonthly}
                onChange={(e) => setPruneKeepMonthly(e.target.value)}
              />
            </div>
          </div>

          {vmidFilter && (
            <p className="text-xs text-muted-foreground">
              {t('PBSTab.dialog.filteringToVmid')} <strong>{vmidFilter}</strong>
            </p>
          )}

          <DialogFooter>
            <Button variant="outline" onClick={() => setPruneDialog(false)}>
              {t('PBSTab.actions.cancel')}
            </Button>
            <Button
              variant="destructive"
              onClick={() => pruneMut.mutate()}
              disabled={pruneMut.isPending}
            >
              {pruneMut.isPending ? (
                <Loader2 className="h-4 w-4 mr-1 animate-spin" />
              ) : (
                <Trash2 className="h-4 w-4 mr-1" />
              )}
              {t('PBSTab.actions.pruneNow')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

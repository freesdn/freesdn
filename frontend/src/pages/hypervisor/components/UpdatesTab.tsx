// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Hypervisor Module - Updates Tab
 * Shows APT package updates available across all Proxmox nodes.
 */
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useQueries, useMutation, useQueryClient } from '@tanstack/react-query';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table';
import { Skeleton } from '@/components/ui/skeleton';
import { ErrorState } from '@/components/ui/empty-state';
import { RefreshCw, Download, Package } from 'lucide-react';
import { hypervisorApi } from '@/lib/api';
import { useToast } from '@/hooks/use-toast';
import type { HypervisorNode } from '@/lib/api';

interface UpdatesTabProps {
  controllerId: string;
  nodes: HypervisorNode[];
}

interface AptUpdate {
  Package?: string;
  Title?: string;
  OldVersion?: string;
  CurrentState?: string;
  Version?: string;
  Origin?: string;
  Priority?: string;
}

export function UpdatesTab({ controllerId, nodes }: UpdatesTabProps) {
  const { t } = useTranslation('hypervisor');
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [refreshingNode, setRefreshingNode] = useState<string | null>(null);

  // Fetch updates for all nodes in parallel
  const nodeQueryResults = useQueries({
    queries: nodes.map((n) => ({
      queryKey: ['hypervisor', 'apt', 'updates', controllerId, n.node],
      queryFn: () => hypervisorApi.getNodeAptUpdates(controllerId, n.node),
      enabled: !!controllerId,
    })),
  });

  const isLoading = nodeQueryResults.some((q) => q.isLoading);
  const hasError = nodeQueryResults.some((q) => q.isError);

  // Flatten all updates with node info
  const allUpdates: (AptUpdate & { _node: string })[] = [];
  for (let i = 0; i < nodes.length; i++) {
    const items = (nodeQueryResults[i]?.data?.data as AptUpdate[] | undefined) || [];
    for (const item of items) {
      allUpdates.push({ ...item, _node: nodes[i].node });
    }
  }

  const nodesWithUpdates = new Set(allUpdates.map((u) => u._node));

  const refreshMutation = useMutation({
    mutationFn: (node: string) => hypervisorApi.refreshNodeApt(controllerId, node),
    onMutate: (node) => setRefreshingNode(node),
    onSuccess: (_data, node) => {
      toast({ title: t('UpdatesTab.toast.refreshed.title'), description: t('UpdatesTab.toast.refreshed.description', { node }) });
      queryClient.invalidateQueries({ queryKey: ['hypervisor', 'apt', 'updates', controllerId, node] });
    },
    onError: (_err, node) => {
      toast({ title: t('UpdatesTab.toast.refreshFailed.title'), description: t('UpdatesTab.toast.refreshFailed.description', { node }), variant: 'destructive' });
    },
    onSettled: () => setRefreshingNode(null),
  });

  if (isLoading) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-20" />
        <Skeleton className="h-64" />
      </div>
    );
  }

  if (hasError) {
    return <ErrorState message={t('UpdatesTab.error.fetch')} />;
  }

  return (
    <div className="space-y-4">
      {/* Summary */}
      <Card>
        <CardHeader className="pb-2">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Package className="h-4 w-4 text-muted-foreground" />
              <CardTitle className="text-sm">{t('UpdatesTab.summary.title')}</CardTitle>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <div className="flex items-center gap-6">
            <div className="text-center">
              <p className="text-2xl font-bold">{allUpdates.length}</p>
              <p className="text-xs text-muted-foreground">{t('UpdatesTab.summary.updatesAvailable')}</p>
            </div>
            <div className="text-center">
              <p className="text-2xl font-bold">{nodesWithUpdates.size}</p>
              <p className="text-xs text-muted-foreground">{t('UpdatesTab.summary.ofNodes', { total: nodes.length })}</p>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Per-node refresh buttons */}
      <div className="flex items-center gap-2 flex-wrap">
        {nodes.map((n) => (
          <Button
            key={n.node}
            variant="outline"
            size="sm"
            disabled={refreshingNode === n.node || refreshMutation.isPending}
            onClick={() => refreshMutation.mutate(n.node)}
          >
            <RefreshCw className={`h-3 w-3 mr-1 ${refreshingNode === n.node ? 'animate-spin' : ''}`} />
            {t('UpdatesTab.actions.refreshNode', { node: n.node })}
          </Button>
        ))}
      </div>

      {/* Updates table */}
      {allUpdates.length === 0 ? (
        <Card>
          <CardContent noOffset className="py-8 text-center text-sm text-muted-foreground">
            <Download className="h-8 w-8 mx-auto mb-2 opacity-50" />
            {t('UpdatesTab.empty.upToDate')}
          </CardContent>
        </Card>
      ) : (
        <Card>
          <div className="overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{t('UpdatesTab.table.node')}</TableHead>
                <TableHead>{t('UpdatesTab.table.package')}</TableHead>
                <TableHead>{t('UpdatesTab.table.currentVersion')}</TableHead>
                <TableHead>{t('UpdatesTab.table.availableVersion')}</TableHead>
                <TableHead>{t('UpdatesTab.table.origin')}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {allUpdates.map((u, i) => (
                <TableRow key={`${u._node}-${u.Package}-${i}`}>
                  <TableCell>
                    <Badge variant="outline">{u._node}</Badge>
                  </TableCell>
                  <TableCell className="font-mono text-sm">{u.Package || u.Title || '-'}</TableCell>
                  <TableCell className="text-sm text-muted-foreground">{u.OldVersion || u.CurrentState || '-'}</TableCell>
                  <TableCell className="text-sm">{u.Version || '-'}</TableCell>
                  <TableCell className="text-sm text-muted-foreground">{u.Origin || '-'}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
          </div>
        </Card>
      )}
    </div>
  );
}

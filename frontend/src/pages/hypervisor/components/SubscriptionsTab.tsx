// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Hypervisor Module - Subscriptions Tab
 * Shows Proxmox subscription status per node.
 */
import { useQueries } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import type { TFunction } from 'i18next';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table';
import { Skeleton } from '@/components/ui/skeleton';
import { ErrorState } from '@/components/ui/empty-state';
import { Key, CheckCircle, XCircle, MinusCircle } from 'lucide-react';
import { hypervisorApi } from '@/lib/api';
import type { HypervisorNode } from '@/lib/api';

interface SubscriptionsTabProps {
  controllerId: string;
  nodes: HypervisorNode[];
}

interface SubscriptionInfo {
  status?: string;
  level?: string;
  serverid?: string;
  key?: string;
  nextduedate?: string;
  productname?: string;
  regdate?: string;
  url?: string;
}

function statusBadge(status: string | undefined, t: TFunction) {
  const s = (status || '').toLowerCase();
  if (s === 'active') return <Badge className="bg-green-600 text-white">{t('SubscriptionsTab.status.active')}</Badge>;
  if (s === 'expired' || s === 'invalid') return <Badge variant="destructive">{t('SubscriptionsTab.status.expired')}</Badge>;
  if (s === 'new' || s === 'notfound') return <Badge variant="secondary">{t('SubscriptionsTab.status.none')}</Badge>;
  return <Badge variant="secondary">{status || t('SubscriptionsTab.status.unknown')}</Badge>;
}

export function SubscriptionsTab({ controllerId, nodes }: SubscriptionsTabProps) {
  const { t } = useTranslation('hypervisor');
  // Fetch subscription for all nodes
  const nodeQueryResults = useQueries({
    queries: nodes.map((n) => ({
      queryKey: ['hypervisor', 'subscription', controllerId, n.node],
      queryFn: () => hypervisorApi.getNodeSubscription(controllerId, n.node),
      enabled: !!controllerId,
    })),
  });

  const isLoading = nodeQueryResults.some((q) => q.isLoading);
  const hasError = nodeQueryResults.some((q) => q.isError);

  const subscriptions: (SubscriptionInfo & { _node: string })[] = [];
  for (let i = 0; i < nodes.length; i++) {
    const info = (nodeQueryResults[i]?.data?.data as SubscriptionInfo | undefined) || {};
    subscriptions.push({ ...info, _node: nodes[i].node });
  }

  const active = subscriptions.filter((s) => (s.status || '').toLowerCase() === 'active').length;
  const expired = subscriptions.filter((s) => ['expired', 'invalid'].includes((s.status || '').toLowerCase())).length;
  const none = subscriptions.length - active - expired;

  if (isLoading) {
    return (
      <div className="space-y-4">
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          {[1, 2, 3].map((i) => <Skeleton key={i} className="h-20" />)}
        </div>
        <Skeleton className="h-64" />
      </div>
    );
  }

  if (hasError) {
    return <ErrorState message={t('SubscriptionsTab.errors.fetchFailed')} />;
  }

  return (
    <div className="space-y-4">
      {hasError && (
        <div className="rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-sm text-destructive">
          {t('SubscriptionsTab.errors.partialBanner')}
        </div>
      )}
      {/* Summary cards */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <Card>
          <CardContent noOffset className="flex items-center gap-3">
            <CheckCircle className="h-8 w-8 text-green-500" />
            <div>
              <p className="text-2xl font-bold">{active}</p>
              <p className="text-xs text-muted-foreground">{t('SubscriptionsTab.status.active')}</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent noOffset className="flex items-center gap-3">
            <XCircle className="h-8 w-8 text-red-500" />
            <div>
              <p className="text-2xl font-bold">{expired}</p>
              <p className="text-xs text-muted-foreground">{t('SubscriptionsTab.status.expired')}</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent noOffset className="flex items-center gap-3">
            <MinusCircle className="h-8 w-8 text-muted-foreground" />
            <div>
              <p className="text-2xl font-bold">{none}</p>
              <p className="text-xs text-muted-foreground">{t('SubscriptionsTab.status.none')}</p>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Subscriptions table */}
      <Card>
        <CardHeader className="pb-2">
          <div className="flex items-center gap-2">
            <Key className="h-4 w-4 text-muted-foreground" />
            <CardTitle className="text-sm">{t('SubscriptionsTab.table.title')}</CardTitle>
          </div>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{t('SubscriptionsTab.table.node')}</TableHead>
                <TableHead>{t('SubscriptionsTab.table.status')}</TableHead>
                <TableHead>{t('SubscriptionsTab.table.level')}</TableHead>
                <TableHead>{t('SubscriptionsTab.table.product')}</TableHead>
                <TableHead>{t('SubscriptionsTab.table.serverId')}</TableHead>
                <TableHead>{t('SubscriptionsTab.table.key')}</TableHead>
                <TableHead>{t('SubscriptionsTab.table.nextDueDate')}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {subscriptions.map((s) => (
                <TableRow key={s._node}>
                  <TableCell>
                    <Badge variant="outline">{s._node}</Badge>
                  </TableCell>
                  <TableCell>{statusBadge(s.status, t)}</TableCell>
                  <TableCell className="text-sm">{s.level || '--'}</TableCell>
                  <TableCell className="text-sm">{s.productname || '--'}</TableCell>
                  <TableCell className="font-mono text-xs">{s.serverid || '--'}</TableCell>
                  <TableCell className="font-mono text-xs">{s.key ? `${s.key.slice(0, 8)}${'*'.repeat(Math.max(0, (s.key.length || 0) - 12))}${s.key.slice(-4)}` : '--'}</TableCell>
                  <TableCell className="text-sm">{s.nextduedate || '--'}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

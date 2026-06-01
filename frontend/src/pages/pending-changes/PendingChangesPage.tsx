// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Pending Changes, cross-feature staging review.
 *
 * Aggregates staged changes from VPN, firmware, profiles, firewall,
 * and WiFi into one queue. Operators discard or apply (force-apply
 * gated by OMADA_READ_ONLY). The single dashboard for "what writes
 * are queued for the live controllers".
 */

import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Inbox,
  RefreshCw,
  ShieldCheck,
  ShieldOff,
  CheckCircle,
  Trash2,
} from 'lucide-react';
import { PageHeader } from '@/components/layout';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
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
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog';
import { EmptyState, ErrorState } from '@/components/ui/empty-state';
import { Skeleton } from '@/components/ui/skeleton';
import { useToast } from '@/hooks/use-toast';
import { useSiteStore } from '@/stores/siteStore';
import { controllersApi } from '@/lib/api/controllers';
import { gatewayVpnApi } from '@/lib/api/gatewayVpn';
import { gatewayFirmwareApi } from '@/lib/api/gatewayFirmware';
import { gatewayProfilesApi } from '@/lib/api/gatewayProfiles';
import { gatewayFirewallApi } from '@/lib/api/gatewayFirewall';
import { gatewayWifiApi } from '@/lib/api/gatewayWifi';
import { getApiErrorMessage } from '@/lib/api';
import type { PendingChangeResponse } from '@/lib/api/gatewayCommon';
// Canonical "is this op destructive?" classifier (any delete + device
// restart/disable/upgrade + client forget) — shared with the drawer so both
// apply paths pass the apply-time ``confirmed`` flag the backend gate requires.
import { isCatastrophic } from '@/components/gateways/PendingChangesDrawer';

export default function PendingChangesPage() {
  const selectedSiteId = useSiteStore((s) => s.selectedSiteId);
  const [controllerId, setControllerId] = useState<string | null>(null);
  const [siteId, setSiteId] = useState<string | null>(selectedSiteId);
  const [statusFilter, setStatusFilter] = useState<string>('pending');
  const [confirmApply, setConfirmApply] = useState<PendingChangeResponse | null>(
    null,
  );
  const { toast } = useToast();
  const qc = useQueryClient();
  const { t } = useTranslation('pendingChanges');

  const ready = controllerId && siteId;

  const { data: controllersResp } = useQuery({
    queryKey: ['controllers-for-pending', selectedSiteId],
    queryFn: () => controllersApi.getAll(selectedSiteId ?? undefined),
  });
  const controllers =
    (controllersResp?.data as { items?: unknown[] })?.items ?? [];

  // Aggregate from all 5 feature endpoints
  const aggregateQuery = useQuery({
    queryKey: ['pending-changes-all', controllerId, siteId, statusFilter],
    queryFn: async () => {
      const vpnParams = {
        status: statusFilter as 'pending' | 'applied' | 'discarded' | 'failed',
      };
      const otherParams = { status: statusFilter };
      // allSettled (not all): one feature scope returning 403 (e.g. the
      // operator lacks firewall rights) must not blank the whole queue.
      // We merge only the fulfilled scopes and silently drop rejections.
      const settled = await Promise.allSettled([
        gatewayVpnApi.listPendingChanges(controllerId!, siteId!, vpnParams),
        gatewayFirmwareApi.listPendingChanges(controllerId!, siteId!, otherParams),
        gatewayProfilesApi.listPending(controllerId!, siteId!, otherParams),
        gatewayFirewallApi.listPending(controllerId!, siteId!, otherParams),
        gatewayWifiApi.listPending(controllerId!, siteId!, otherParams),
      ]);
      return settled
        .flatMap((r) =>
          r.status === 'fulfilled'
            ? ((r.value.data as PendingChangeResponse[]) ?? [])
            : [],
        )
        .sort(
          (a, b) =>
            new Date(b.created_at).getTime() - new Date(a.created_at).getTime(),
        );
    },
    enabled: !!ready,
    refetchInterval: 15_000,
  });

  const discardMut = useMutation({
    mutationFn: (id: string) => gatewayVpnApi.discardChange(id),
    onSuccess: () => {
      toast({
        title: t('PendingChangesPage.toasts.discarded.title'),
        variant: 'default',
      });
      // Invalidate every per-feature pending-list query as well,
      // operators flipping between this page and a feature page
      // shouldn't see a "pending" badge that's actually been
      // discarded already.
      qc.invalidateQueries({
        predicate: (q) =>
          typeof q.queryKey[0] === 'string' &&
          (q.queryKey[0] === 'pending-changes-all' ||
            q.queryKey[0].includes('-pending')),
      });
    },
    onError: (e) =>
      toast({
        title: t('PendingChangesPage.toasts.discardFailed.title'),
        description: String((e as Error).message ?? e),
        variant: 'destructive',
      }),
  });

  const applyMut = useMutation({
    mutationFn: (change: PendingChangeResponse) =>
      gatewayVpnApi.applyChange(change.id, {
        force: true,
        // Destructive ops need the operator's apply-time sign-off or the vendor
        // pre-flight 409s; the confirm dialog below is that acknowledgment.
        confirmed: isCatastrophic(change),
      }),
    onSuccess: () => {
      toast({
        title: t('PendingChangesPage.toasts.applied.title'),
        description: t('PendingChangesPage.toasts.applied.description'),
      });
      setConfirmApply(null);
      qc.invalidateQueries({
        predicate: (q) =>
          typeof q.queryKey[0] === 'string' &&
          (q.queryKey[0] === 'pending-changes-all' ||
            q.queryKey[0].includes('-pending')),
      });
    },
    onError: (e) => {
      toast({
        title: t('PendingChangesPage.toasts.applyRefused.title'),
        description: getApiErrorMessage(
          e,
          t('PendingChangesPage.toasts.applyRefused.title'),
        ),
        variant: 'destructive',
      });
    },
  });

  const items = aggregateQuery.data ?? [];

  return (
    <div className="space-y-6">
      <PageHeader
        title={t('PendingChangesPage.header.title')}
        description={t('PendingChangesPage.header.description')}
        icon={Inbox}
      />

      <Card>
        <CardHeader>
          <CardTitle className="text-base">
            {t('PendingChangesPage.filter.title')}
          </CardTitle>
        </CardHeader>
        <CardContent className="grid grid-cols-1 gap-3 sm:grid-cols-3">
          <div>
            <label className="mb-1 block text-xs font-medium text-muted-foreground">
              {t('PendingChangesPage.filter.controller')}
            </label>
            <Select
              value={controllerId ?? ''}
              onValueChange={(v) => setControllerId(v || null)}
            >
              <SelectTrigger>
                <SelectValue
                  placeholder={t('PendingChangesPage.filter.chooseController')}
                />
              </SelectTrigger>
              <SelectContent>
                {(controllers as Array<{ id: string; name: string }>).map(
                  (c) => (
                    <SelectItem key={c.id} value={c.id}>
                      {c.name}
                    </SelectItem>
                  ),
                )}
              </SelectContent>
            </Select>
          </div>
          <div>
            <label className="mb-1 block text-xs font-medium text-muted-foreground">
              {t('PendingChangesPage.filter.site')}
            </label>
            <SitePicker siteId={siteId} onChange={setSiteId} />
          </div>
          <div>
            <label className="mb-1 block text-xs font-medium text-muted-foreground">
              {t('PendingChangesPage.filter.status')}
            </label>
            <Select value={statusFilter} onValueChange={setStatusFilter}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="pending">
                  {t('PendingChangesPage.status.pending')}
                </SelectItem>
                <SelectItem value="applied">
                  {t('PendingChangesPage.status.applied')}
                </SelectItem>
                <SelectItem value="discarded">
                  {t('PendingChangesPage.status.discarded')}
                </SelectItem>
                <SelectItem value="failed">
                  {t('PendingChangesPage.status.failed')}
                </SelectItem>
              </SelectContent>
            </Select>
          </div>
        </CardContent>
      </Card>

      {!ready ? (
        <EmptyState
          icon={Inbox}
          title={t('PendingChangesPage.empty.pickControllerSite')}
        />
      ) : (
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0">
            <div>
              <CardTitle className="text-base">
                {items.length === 1
                  ? t('PendingChangesPage.list.countOne', {
                      count: items.length,
                    })
                  : t('PendingChangesPage.list.countOther', {
                      count: items.length,
                    })}
              </CardTitle>
              <CardDescription>
                {t('PendingChangesPage.list.gateNote')}
              </CardDescription>
            </div>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => aggregateQuery.refetch()}
            >
              <RefreshCw className="h-4 w-4" />
            </Button>
          </CardHeader>
          <CardContent>
            {aggregateQuery.isLoading ? (
              <Skeleton className="h-32 w-full" />
            ) : aggregateQuery.isError ? (
              <ErrorState
                message={t('PendingChangesPage.errors.loadFailed')}
                onRetry={() => aggregateQuery.refetch()}
              />
            ) : items.length === 0 ? (
              <EmptyState
                icon={CheckCircle}
                title={
                  statusFilter === 'pending'
                    ? t('PendingChangesPage.empty.inboxZero')
                    : t('PendingChangesPage.empty.noStatusChanges', {
                        status: statusFilter,
                      })
                }
                description={
                  statusFilter === 'pending'
                    ? t('PendingChangesPage.empty.noneWaiting')
                    : ''
                }
              />
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>{t('PendingChangesPage.table.feature')}</TableHead>
                    <TableHead>{t('PendingChangesPage.table.op')}</TableHead>
                    <TableHead>{t('PendingChangesPage.table.target')}</TableHead>
                    <TableHead>{t('PendingChangesPage.table.notes')}</TableHead>
                    <TableHead>{t('PendingChangesPage.table.created')}</TableHead>
                    <TableHead>{t('PendingChangesPage.table.status')}</TableHead>
                    <TableHead className="text-right">
                      {t('PendingChangesPage.table.actions')}
                    </TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {items.map((it) => (
                    <TableRow key={it.id}>
                      <TableCell className="font-mono text-xs">
                        {it.feature}
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline" className="capitalize">
                          {it.operation}
                        </Badge>
                      </TableCell>
                      <TableCell className="max-w-[120px] truncate font-mono text-xs">
                        {it.target_id ?? '-'}
                      </TableCell>
                      <TableCell className="max-w-[200px] truncate text-xs text-muted-foreground">
                        {it.notes ?? ''}
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground">
                        {new Date(it.created_at).toLocaleString()}
                      </TableCell>
                      <TableCell>
                        <Badge
                          variant={
                            it.status === 'failed'
                              ? 'destructive'
                              : it.status === 'applied'
                                ? 'default'
                                : it.status === 'applying'
                                  ? 'outline'
                                  : 'secondary'
                          }
                          title={
                            it.status === 'failed' && it.failure_reason
                              ? t('PendingChangesPage.table.failureTooltip', {
                                  reason: it.failure_reason,
                                })
                              : undefined
                          }
                        >
                          {it.status}
                        </Badge>
                        {it.status === 'failed' && it.failure_reason ? (
                          <div className="mt-1 max-w-[200px] truncate text-xs text-destructive">
                            {it.failure_reason}
                          </div>
                        ) : null}
                      </TableCell>
                      <TableCell className="text-right space-x-1">
                        {it.status === 'pending' && (
                          <>
                            <Button
                              size="sm"
                              variant="ghost"
                              onClick={() => discardMut.mutate(it.id)}
                              disabled={discardMut.isPending}
                              title={t('PendingChangesPage.actions.discardTooltip')}
                            >
                              <Trash2 className="h-4 w-4" />
                            </Button>
                            <Button
                              size="sm"
                              variant="default"
                              onClick={() => setConfirmApply(it)}
                              title={t('PendingChangesPage.actions.applyTooltip')}
                            >
                              <ShieldCheck className="mr-1 h-4 w-4" />
                              {t('PendingChangesPage.actions.apply')}
                            </Button>
                          </>
                        )}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>
      )}

      <AlertDialog
        open={!!confirmApply}
        onOpenChange={(o) => !o && setConfirmApply(null)}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle className="flex items-center gap-2">
              <ShieldOff className="h-5 w-5 text-destructive" />
              {t('PendingChangesPage.confirmApply.title')}
            </AlertDialogTitle>
            <AlertDialogDescription>
              {t('PendingChangesPage.confirmApply.description')}
            </AlertDialogDescription>
          </AlertDialogHeader>
          {confirmApply && (
            <pre className="max-h-48 overflow-auto rounded-md border bg-muted p-3 text-xs">
              {JSON.stringify(confirmApply.payload, null, 2)}
            </pre>
          )}
          <AlertDialogFooter>
            <AlertDialogCancel>
              {t('PendingChangesPage.confirmApply.cancel')}
            </AlertDialogCancel>
            <AlertDialogAction
              onClick={() => confirmApply && applyMut.mutate(confirmApply)}
              disabled={applyMut.isPending}
            >
              {t('PendingChangesPage.confirmApply.apply')}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}

function SitePicker({
  siteId,
  onChange,
}: {
  siteId: string | null;
  onChange: (id: string | null) => void;
}) {
  const sites = useSiteStore((s) => s.sites);
  const { t } = useTranslation('pendingChanges');
  return (
    <Select value={siteId ?? ''} onValueChange={(v) => onChange(v || null)}>
      <SelectTrigger>
        <SelectValue
          placeholder={t('PendingChangesPage.filter.chooseSite')}
        />
      </SelectTrigger>
      <SelectContent>
        {sites.map((s) => (
          <SelectItem key={s.id} value={s.id}>
            {s.name}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
}

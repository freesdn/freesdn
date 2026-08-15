// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN, UniFi Clients tab
 *
 * First UniFi per-domain tab mirroring the MikroTik tab pattern. Stages
 * block / unblock / forget actions against the Pending Changes drawer
 * via ``stageUniFiChange`` (POST /gateway-unifi-clients/{cid}/changes/...).
 */
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Ban, ShieldOff, Trash2, RefreshCw, Loader2 } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { useToast } from '@/hooks/use-toast';
import { api } from '@/lib/api/client';
import { getApiErrorMessage } from '@/lib/api/client';
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

const enc = encodeURIComponent;

interface UniFiClient {
  mac: string;
  hostname?: string;
  name?: string;
  ip?: string;
  blocked?: boolean;
  is_wired?: boolean;
  last_seen?: number;
  oui?: string;
}

interface UniFiClientsResponse {
  controller_id: string;
  site: string;
  items: UniFiClient[];
  fetched_at: string;
}

async function fetchClients(
  controllerId: string,
  site: string,
) {
  // Axios returns ``AxiosResponse``; consumers access ``.data.items``.
  // Returning the full response keeps the same shape MikroTik tabs use.
  return api.get<UniFiClientsResponse>(
    `/gateway-unifi-clients/${enc(controllerId)}/sites/${enc(site)}/clients`,
  );
}

type UniFiOp = 'block' | 'unblock' | 'reconnect' | 'forget';

async function stageClientChange(
  controllerId: string,
  feature: string,
  operation: 'update' | 'delete',
  mac: string,
  site: string,
) {
  return api.post(
    `/gateway-unifi-clients/${enc(controllerId)}/changes/${enc(feature)}`,
    { payload: { site }, target_id: mac },
    { params: { operation } },
  );
}

interface UniFiClientsTabProps {
  controllerId: string;
  site: string;
  isActive: boolean;
}

export function UniFiClientsTab({
  controllerId,
  site,
  isActive,
}: UniFiClientsTabProps) {
  const { t } = useTranslation('firewall');
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const [confirmAction, setConfirmAction] = useState<{
    op: UniFiOp;
    mac: string;
    label: string;
  } | null>(null);
  // Manual MAC entry for staging against clients we can't see (lab
  // controllers with no adopted devices don't surface real clients).
  const [manualMac, setManualMac] = useState('');

  const LIST_KEY = ['unifi', 'clients', controllerId, site] as const;

  const query = useQuery({
    queryKey: LIST_KEY,
    queryFn: () => fetchClients(controllerId, site),
    enabled: isActive && !!controllerId,
    refetchInterval: 30_000,
  });

  const stageMut = useMutation({
    mutationFn: ({
      op,
      mac,
    }: {
      op: UniFiOp;
      mac: string;
    }) => {
      const feature = `unifi.clients.${op}`;
      const operation: 'update' | 'delete' =
        op === 'forget' ? 'delete' : 'update';
      return stageClientChange(controllerId, feature, operation, mac, site);
    },
    onSuccess: (_data, vars) => {
      toast({
        title: t('UniFiClientsTab.toast.staged.title', {
          op: t(`UniFiClientsTab.ops.${vars.op}`),
        }),
        description: vars.mac,
      });
      setConfirmAction(null);
      // The global MutationCache subscriber in main.tsx invalidates
      // the cross-cutting ['pending-changes'] key automatically, so
      // the drawer + badge refresh without per-tab plumbing.
      queryClient.invalidateQueries({ queryKey: LIST_KEY });
    },
    onError: (err: unknown) => {
      toast({
        title: t('UniFiClientsTab.toast.stageFailed.title'),
        description: getApiErrorMessage(err),
        variant: 'destructive',
      });
    },
  });

  const clients = query.data?.data?.items ?? [];

  function openConfirm(op: UniFiOp, mac: string, label?: string) {
    if (!mac) {
      toast({
        title: t('UniFiClientsTab.toast.macRequired.title'),
        description: t('UniFiClientsTab.toast.macRequired.description'),
        variant: 'destructive',
      });
      return;
    }
    setConfirmAction({ op, mac, label: label || mac });
  }

  return (
    <Card>
      <CardHeader className="flex flex-row items-start justify-between">
        <div>
          <CardTitle className="flex items-center gap-2">
            {t('UniFiClientsTab.title')}
            <Badge variant="default">{clients.length}</Badge>
          </CardTitle>
          <p className="text-sm text-muted-foreground mt-1">
            {t('UniFiClientsTab.description.sitePrefix')}{' '}
            <code className="font-mono">{site}</code>{' '}
            {t('UniFiClientsTab.description.rest')}
          </p>
        </div>
        <Button
          variant="outline"
          size="sm"
          onClick={() => query.refetch()}
          disabled={query.isFetching}
        >
          {query.isFetching ? (
            <Loader2 className="h-4 w-4 animate-spin" />
          ) : (
            <RefreshCw className="h-4 w-4" />
          )}
        </Button>
      </CardHeader>

      <CardContent className="space-y-4">
        {/* Manual stage form, needed because a fresh lab controller has
            no adopted devices to surface real clients. */}
        <div className="border border-border rounded-lg p-3 space-y-2">
          <Label htmlFor="unifi-manual-mac" className="text-sm font-medium">
            {t('UniFiClientsTab.stageByMac.label')}
          </Label>
          <div className="flex items-center gap-2">
            <Input
              id="unifi-manual-mac"
              placeholder="aa:bb:cc:dd:ee:ff"
              value={manualMac}
              onChange={(e) => setManualMac(e.target.value)}
              className="flex-1 font-mono text-sm"
            />
            <Button
              size="sm"
              variant="outline"
              onClick={() => openConfirm('block', manualMac, manualMac)}
              disabled={!manualMac.trim()}
              title={t('UniFiClientsTab.actions.stageBlock')}
            >
              <Ban className="h-4 w-4 mr-1" /> {t('UniFiClientsTab.actions.block')}
            </Button>
            <Button
              size="sm"
              variant="outline"
              onClick={() => openConfirm('unblock', manualMac, manualMac)}
              disabled={!manualMac.trim()}
              title={t('UniFiClientsTab.actions.stageUnblock')}
            >
              <ShieldOff className="h-4 w-4 mr-1" /> {t('UniFiClientsTab.actions.unblock')}
            </Button>
            <Button
              size="sm"
              variant="outline"
              onClick={() => openConfirm('forget', manualMac, manualMac)}
              disabled={!manualMac.trim()}
              title={t('UniFiClientsTab.actions.stageForget')}
            >
              <Trash2 className="h-4 w-4 mr-1" /> {t('UniFiClientsTab.actions.forget')}
            </Button>
          </div>
        </div>

        {query.isError && (
          <div className="rounded-md bg-destructive/10 border border-destructive p-3 text-sm text-destructive">
            {t('UniFiClientsTab.error.loadFailed')}{' '}
            {(query.error as Error)?.message ||
              t('UniFiClientsTab.error.unknown')}
          </div>
        )}

        {query.isLoading ? (
          <div className="flex items-center justify-center py-8 text-muted-foreground">
            <Loader2 className="h-4 w-4 animate-spin mr-2" />{' '}
            {t('UniFiClientsTab.loading')}
          </div>
        ) : clients.length === 0 ? (
          <div className="text-center py-8 text-sm text-muted-foreground">
            {t('UniFiClientsTab.empty')}
          </div>
        ) : (
          <ul className="space-y-2">
            {clients.map((c) => {
              const label = c.name || c.hostname || c.mac;
              return (
                <li
                  key={c.mac}
                  className="flex items-center justify-between border border-border rounded-lg p-3"
                >
                  <div className="space-y-1 min-w-0">
                    <div className="text-sm font-medium">{label}</div>
                    <div className="text-xs text-muted-foreground font-mono">
                      {c.mac}
                      {c.ip ? ` · ${c.ip}` : ''}
                      {c.blocked
                        ? ` · ${t('UniFiClientsTab.blocked')}`
                        : ''}
                    </div>
                  </div>
                  <div className="flex items-center gap-1">
                    {c.blocked ? (
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => openConfirm('unblock', c.mac, label)}
                        disabled={stageMut.isPending}
                      >
                        <ShieldOff className="h-4 w-4 mr-1" />{' '}
                        {t('UniFiClientsTab.actions.unblock')}
                      </Button>
                    ) : (
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => openConfirm('block', c.mac, label)}
                        disabled={stageMut.isPending}
                      >
                        <Ban className="h-4 w-4 mr-1" />{' '}
                        {t('UniFiClientsTab.actions.block')}
                      </Button>
                    )}
                    {!c.blocked && (
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => openConfirm('reconnect', c.mac, label)}
                        disabled={stageMut.isPending}
                        title={t('UniFiClientsTab.actions.stageReconnect')}
                      >
                        <RefreshCw className="h-4 w-4 mr-1" />{' '}
                        {t('UniFiClientsTab.actions.reconnect')}
                      </Button>
                    )}
                    <Button
                      size="sm"
                      variant="ghost"
                      onClick={() => openConfirm('forget', c.mac, label)}
                      disabled={stageMut.isPending}
                      className="text-destructive hover:bg-destructive/10"
                    >
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  </div>
                </li>
              );
            })}
          </ul>
        )}
      </CardContent>

      <AlertDialog
        open={!!confirmAction}
        onOpenChange={(open) => !open && setConfirmAction(null)}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>
              {t('UniFiClientsTab.dialog.title', {
                op: confirmAction
                  ? t(`UniFiClientsTab.ops.${confirmAction.op}`)
                  : '',
              })}
            </AlertDialogTitle>
            <AlertDialogDescription>
              {t('UniFiClientsTab.dialog.descriptionPrefix')}{' '}
              <code className="font-mono">
                unifi.clients.{confirmAction?.op}
              </code>{' '}
              {t('UniFiClientsTab.dialog.descriptionAgainst')}{' '}
              <code className="font-mono">{confirmAction?.label}</code>
              {t('UniFiClientsTab.dialog.descriptionSuffix')}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>
              {t('UniFiClientsTab.dialog.cancel')}
            </AlertDialogCancel>
            <AlertDialogAction
              onClick={() => {
                if (confirmAction) {
                  stageMut.mutate({
                    op: confirmAction.op,
                    mac: confirmAction.mac,
                  });
                }
              }}
              disabled={stageMut.isPending}
            >
              {t('UniFiClientsTab.dialog.confirm', {
                op: confirmAction
                  ? t(`UniFiClientsTab.ops.${confirmAction.op}`)
                  : '',
              })}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </Card>
  );
}

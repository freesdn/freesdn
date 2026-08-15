// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN, UniFi VPN tab
 *
 * Stages VPN-network create / update / delete against gateway-unifi-vpn.
 * UniFi models VPNs (site-to-site, client, server, Teleport, WireGuard)
 * as ``networks`` rows with a vpn-flavoured purpose, so the read lists
 * the VPN networks for context. Like the other UniFi domain tabs, writes
 * never touch the controller directly, they land as pending rows that the
 * operator applies via the Pending Changes drawer
 * (POST /gateway-unifi-vpn/{cid}/changes/...).
 */
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Loader2, Lock, Plus, RefreshCw, Trash2 } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { useToast } from '@/hooks/use-toast';
import { api, getApiErrorMessage } from '@/lib/api/client';
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

interface UniFiVpnNetwork {
  _id: string;
  name?: string;
  purpose?: string;
  vpn_type?: string;
  enabled?: boolean;
  // Note: pre-shared keys / private keys intentionally redacted by the
  // backend; not consumed here.
}

interface UniFiVpnResponse {
  controller_id: string;
  site: string;
  items: UniFiVpnNetwork[];
  fetched_at: string;
}

async function fetchVpnNetworks(controllerId: string, site: string) {
  return api.get<UniFiVpnResponse>(
    `/gateway-unifi-vpn/${enc(controllerId)}/sites/${enc(site)}/networks`,
  );
}

async function stageVpnChange(
  controllerId: string,
  feature: string,
  operation: 'create' | 'update' | 'delete',
  payload: Record<string, unknown>,
  targetId?: string,
) {
  return api.post(
    `/gateway-unifi-vpn/${enc(controllerId)}/changes/${enc(feature)}`,
    targetId ? { payload, target_id: targetId } : { payload },
    { params: { operation } },
  );
}

interface CreateForm {
  name: string;
  vpn_type: string;
}

const BLANK: CreateForm = {
  name: '',
  vpn_type: 'site-to-site',
};

type VpnOp =
  | { kind: 'create'; form: CreateForm }
  | { kind: 'delete'; targetId: string; label: string };

interface UniFiVpnTabProps {
  controllerId: string;
  site: string;
  isActive: boolean;
}

export function UniFiVpnTab({ controllerId, site, isActive }: UniFiVpnTabProps) {
  const { t } = useTranslation('firewall');
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const [form, setForm] = useState<CreateForm>(BLANK);
  const [confirm, setConfirm] = useState<VpnOp | null>(null);

  const LIST_KEY = ['unifi', 'vpn', controllerId, site] as const;

  const query = useQuery({
    queryKey: LIST_KEY,
    queryFn: () => fetchVpnNetworks(controllerId, site),
    enabled: isActive && !!controllerId,
    refetchInterval: 60_000,
  });

  const stageMut = useMutation({
    mutationFn: async (op: VpnOp) => {
      if (op.kind === 'create') {
        return stageVpnChange(controllerId, 'unifi.vpn.create', 'create', {
          site,
          name: op.form.name.trim(),
          vpn_type: op.form.vpn_type,
        });
      }
      // delete
      return stageVpnChange(
        controllerId,
        'unifi.vpn.delete',
        'delete',
        { site },
        op.targetId,
      );
    },
    onSuccess: (_data, vars) => {
      toast({
        title:
          vars.kind === 'create'
            ? t('UniFiVpnTab.toast.created.title')
            : t('UniFiVpnTab.toast.deleted.title'),
        description: vars.kind === 'create' ? vars.form.name : vars.label,
      });
      setConfirm(null);
      if (vars.kind === 'create') setForm(BLANK);
      queryClient.invalidateQueries({ queryKey: LIST_KEY });
    },
    onError: (err: unknown) => {
      toast({
        title: t('UniFiVpnTab.toast.stageFailed.title'),
        description: getApiErrorMessage(err),
        variant: 'destructive',
      });
    },
  });

  const networks = query.data?.data?.items ?? [];
  const canStage = form.name.trim().length > 0;

  return (
    <Card>
      <CardHeader className="flex flex-row items-start justify-between">
        <div>
          <CardTitle className="flex items-center gap-2">
            <Lock className="h-4 w-4" /> {t('UniFiVpnTab.title')}
            <Badge variant="default">{networks.length}</Badge>
          </CardTitle>
          <p className="text-sm text-muted-foreground mt-1">
            {t('UniFiVpnTab.siteLabel')}{' '}
            <code className="font-mono">{site}</code> ·{' '}
            {t('UniFiVpnTab.description')}
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
        {/* Stage create form. Payload is minimal (name + type); operators
            refine peer / key details in the drawer payload preview or via
            a follow-up update. */}
        <div className="border border-border rounded-lg p-3 space-y-3">
          <Label className="text-sm font-medium">
            {t('UniFiVpnTab.form.createVpn')}
          </Label>
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1">
              <Label htmlFor="vpn-name" className="text-xs">
                {t('UniFiVpnTab.fields.name')}
              </Label>
              <Input
                id="vpn-name"
                placeholder={t('UniFiVpnTab.fields.namePlaceholder')}
                value={form.name}
                onChange={(e) =>
                  setForm((f) => ({ ...f, name: e.target.value }))
                }
                className="text-sm"
              />
            </div>
            <div className="space-y-1">
              <Label className="text-xs">{t('UniFiVpnTab.fields.vpnType')}</Label>
              <Select
                value={form.vpn_type}
                onValueChange={(v) =>
                  setForm((f) => ({ ...f, vpn_type: v }))
                }
              >
                <SelectTrigger className="text-sm">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="site-to-site">site-to-site</SelectItem>
                  <SelectItem value="vpn-client">vpn-client</SelectItem>
                  <SelectItem value="vpn-server">vpn-server</SelectItem>
                  <SelectItem value="wireguard-client">
                    wireguard-client
                  </SelectItem>
                  <SelectItem value="wireguard-server">
                    wireguard-server
                  </SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
          <div className="flex justify-end pt-2 border-t border-border">
            <Button
              size="sm"
              onClick={() => setConfirm({ kind: 'create', form })}
              disabled={!canStage}
            >
              <Plus className="h-4 w-4 mr-1" />{' '}
              {t('UniFiVpnTab.actions.stageCreate')}
            </Button>
          </div>
        </div>

        {query.isError && (
          <div className="rounded-md bg-destructive/10 border border-destructive p-3 text-sm text-destructive">
            {t('UniFiVpnTab.loadError')}{' '}
            {(query.error as Error)?.message || t('UniFiVpnTab.unknownError')}
          </div>
        )}

        {query.isLoading ? (
          <div className="flex items-center justify-center py-8 text-muted-foreground">
            <Loader2 className="h-4 w-4 animate-spin mr-2" />{' '}
            {t('UniFiVpnTab.loading')}
          </div>
        ) : networks.length === 0 ? (
          <div className="text-center py-8 text-sm text-muted-foreground">
            {t('UniFiVpnTab.empty')}
          </div>
        ) : (
          <ul className="space-y-2">
            {networks.map((n) => {
              const label = n.name || n._id;
              return (
                <li
                  key={n._id}
                  className="flex items-center justify-between border border-border rounded-lg p-3"
                >
                  <div className="space-y-1 min-w-0">
                    <div className="text-sm font-medium">{label}</div>
                    <div className="text-xs text-muted-foreground font-mono">
                      {n._id}
                      {n.vpn_type ? ` · ${n.vpn_type}` : ''}
                      {n.purpose ? ` · ${n.purpose}` : ''}
                      {n.enabled === false
                        ? ` · ${t('UniFiVpnTab.status.disabled')}`
                        : ''}
                    </div>
                  </div>
                  <div className="flex items-center gap-1">
                    <Button
                      size="sm"
                      variant="ghost"
                      onClick={() =>
                        setConfirm({
                          kind: 'delete',
                          targetId: n._id,
                          label,
                        })
                      }
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
        open={!!confirm}
        onOpenChange={(open) => !open && setConfirm(null)}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>
              {confirm?.kind === 'delete'
                ? t('UniFiVpnTab.dialog.deleteTitle')
                : t('UniFiVpnTab.dialog.createTitle')}
            </AlertDialogTitle>
            <AlertDialogDescription>
              {t('UniFiVpnTab.dialog.stagePrefix')}{' '}
              <code className="font-mono">
                unifi.vpn.{confirm?.kind === 'delete' ? 'delete' : 'create'}
              </code>{' '}
              {t('UniFiVpnTab.dialog.against')}{' '}
              <code className="font-mono">
                {confirm?.kind === 'delete' ? confirm.label : confirm?.form.name}
              </code>
              {t('UniFiVpnTab.dialog.suffix')}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>
              {t('UniFiVpnTab.actions.cancel')}
            </AlertDialogCancel>
            <AlertDialogAction
              onClick={() => confirm && stageMut.mutate(confirm)}
              disabled={stageMut.isPending}
            >
              {t('UniFiVpnTab.actions.stage')}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </Card>
  );
}

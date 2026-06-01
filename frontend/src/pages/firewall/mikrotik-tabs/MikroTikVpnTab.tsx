// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * MikroTikVpnTab · RouterOS L2TP / PPTP / SSTP server panes.
 *
 * RouterOS exposes each remote-access VPN as a *singleton* server row
 * (one ``/interface/<proto>-server/server`` per box) plus per-user
 * secrets in the shared ``/ppp/secret`` collection. This tab focuses on
 * the singleton row + a settings dialog; per-user secrets are visible
 * read-only on the L2TP/PPTP server reads but the per-row CRUD is
 * planned for the PPP/PPPoE tab.
 *
 * Three sub-panes:
 * - L2TP server: settings dialog (enable, default profile, IPsec
 *   shared-secret) staging ``mikrotik.vpn.l2tp_server`` updates.
 * - PPTP server: same shape, badged "deprecated", kept for legacy
 *   deployments still on this protocol.
 * - SSTP server: read-only summary of available certs (the SSTP server
 *   row endpoint is not yet exposed; certs come from the
 *   shared certificate listing). Settings push is deferred to a later release.
 */
import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  Lock,
  Loader2,
  Pencil,
  RefreshCw,
  Shield,
  ShieldAlert,
} from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { EmptyState, ErrorState } from '@/components/ui/empty-state';
import { useToast } from '@/hooks/use-toast';
import {
  getApiErrorMessage,
  mikrotikApi,
  type MikroTikL2TPServer,
  type MikroTikPPTPServer,
} from '@/lib/api';

export interface MikroTikVpnTabProps {
  controllerId: string;
  isActive: boolean;
  /** Display name of the controller, surfaced in error toasts. */
  gatewayName?: string;
}

const L2TP_KEY = (cid: string) => ['mikrotik', cid, 'vpn-l2tp'];
const PPTP_KEY = (cid: string) => ['mikrotik', cid, 'vpn-pptp'];

type ServerForm = {
  enabled: boolean;
  defaultProfile: string;
  authentication: string;
  useIpsec: boolean;
  ipsecSecret: string;
};

const BLANK_FORM: ServerForm = {
  enabled: false,
  defaultProfile: '',
  authentication: '',
  useIpsec: false,
  ipsecSecret: '',
};

function asStr(value: unknown): string {
  if (value === undefined || value === null) return '-';
  if (typeof value === 'string') return value || '-';
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  return '-';
}

function asBool(value: unknown): boolean {
  if (typeof value === 'boolean') return value;
  if (typeof value === 'string') return value === 'true' || value === 'yes';
  return false;
}

export function MikroTikVpnTab({ controllerId, isActive, gatewayName }: MikroTikVpnTabProps) {
  const { t } = useTranslation('firewall');
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const ctx = gatewayName ? `${gatewayName}: ` : '';

  const [editing, setEditing] = useState<null | 'l2tp' | 'pptp'>(null);
  const [form, setForm] = useState<ServerForm>(BLANK_FORM);

  const l2tpQuery = useQuery({
    queryKey: L2TP_KEY(controllerId),
    queryFn: () => mikrotikApi.getL2TPServer(controllerId),
    enabled: !!controllerId && isActive,
    refetchInterval: 60_000,
  });

  const pptpQuery = useQuery({
    queryKey: PPTP_KEY(controllerId),
    queryFn: () => mikrotikApi.getPPTPServer(controllerId),
    enabled: !!controllerId && isActive,
    refetchInterval: 60_000,
  });

  const l2tp: MikroTikL2TPServer | undefined = l2tpQuery.data?.data.item;
  const pptp: MikroTikPPTPServer | undefined = pptpQuery.data?.data.item;

  const updateL2TPMut = useMutation({
    mutationFn: (payload: Record<string, unknown>) =>
      mikrotikApi.updateL2TPServer(controllerId, payload),
    onSuccess: () => {
      toast({ title: t('MikroTikVpnTab.toasts.l2tpStaged') });
      setEditing(null);
      queryClient.invalidateQueries({ queryKey: L2TP_KEY(controllerId) });
    },
    onError: (err) =>
      toast({
        title: `${ctx}${t('MikroTikVpnTab.toasts.l2tpStageFailed')}`,
        description: getApiErrorMessage(err),
        variant: 'destructive',
      }),
  });

  const updatePPTPMut = useMutation({
    mutationFn: (payload: Record<string, unknown>) =>
      mikrotikApi.updatePPTPServer(controllerId, payload),
    onSuccess: () => {
      toast({ title: t('MikroTikVpnTab.toasts.pptpStaged') });
      setEditing(null);
      queryClient.invalidateQueries({ queryKey: PPTP_KEY(controllerId) });
    },
    onError: (err) =>
      toast({
        title: `${ctx}${t('MikroTikVpnTab.toasts.pptpStageFailed')}`,
        description: getApiErrorMessage(err),
        variant: 'destructive',
      }),
  });

  // Re-seed the form whenever the user opens a different protocol's
  // dialog (or the underlying data changes while a dialog is open).
  //
  // NOTE `ipsecSecret` is treated as write-only. We never seed
  // it from the read response, even if the backend regresses and starts
  // returning the secret. The operator must explicitly type a new
  // secret to rotate it; an empty submission is a no-op (the
  // `if (form.useIpsec && form.ipsecSecret.trim())` guard in `submit()`
  // already drops the field). This keeps the live secret out of any
  // DOM `value=""` attribute that DevTools could inspect.
  useEffect(() => {
    if (editing === 'l2tp' && l2tp) {
      setForm({
        enabled: asBool(l2tp.enabled),
        defaultProfile:
          typeof l2tp['default-profile'] === 'string'
            ? l2tp['default-profile']
            : '',
        authentication:
          typeof l2tp.authentication === 'string' ? l2tp.authentication : '',
        useIpsec: asBool(l2tp['use-ipsec']),
        // do not seed from server response, write-only field.
        ipsecSecret: '',
      });
    } else if (editing === 'pptp' && pptp) {
      setForm({
        enabled: asBool(pptp.enabled),
        defaultProfile:
          typeof pptp['default-profile'] === 'string'
            ? pptp['default-profile']
            : '',
        authentication:
          typeof pptp.authentication === 'string' ? pptp.authentication : '',
        useIpsec: false,
        ipsecSecret: '',
      });
    }
  }, [editing, l2tp, pptp]);

  function submit() {
    if (editing === 'l2tp') {
      const payload: Record<string, unknown> = {
        enabled: form.enabled ? 'true' : 'false',
      };
      if (form.defaultProfile.trim()) payload['default-profile'] = form.defaultProfile.trim();
      if (form.authentication.trim()) payload.authentication = form.authentication.trim();
      payload['use-ipsec'] = form.useIpsec ? 'yes' : 'no';
      if (form.useIpsec && form.ipsecSecret.trim()) {
        payload['ipsec-secret'] = form.ipsecSecret.trim();
      }
      updateL2TPMut.mutate(payload);
    } else if (editing === 'pptp') {
      const payload: Record<string, unknown> = {
        enabled: form.enabled ? 'true' : 'false',
      };
      if (form.defaultProfile.trim()) payload['default-profile'] = form.defaultProfile.trim();
      if (form.authentication.trim()) payload.authentication = form.authentication.trim();
      updatePPTPMut.mutate(payload);
    }
  }

  if (l2tpQuery.isLoading && pptpQuery.isLoading) {
    return (
      <div className="flex items-center justify-center py-16 text-muted-foreground">
        <Loader2 className="h-5 w-5 animate-spin mr-2" />
        {t('MikroTikVpnTab.loading')}
      </div>
    );
  }

  const anyFetching = l2tpQuery.isFetching || pptpQuery.isFetching;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-end">
        <Button
          variant="outline"
          size="sm"
          disabled={anyFetching}
          onClick={() => {
            l2tpQuery.refetch();
            pptpQuery.refetch();
          }}
        >
          {anyFetching ? (
            <Loader2 className="h-4 w-4 animate-spin mr-1" />
          ) : (
            <RefreshCw className="h-4 w-4 mr-1" />
          )}
          {t('MikroTikVpnTab.actions.refresh')}
        </Button>
      </div>

      {/* L2TP server */}
      <Card className="border-border/50">
        <CardHeader className="pb-4">
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="flex items-center gap-2">
                <Shield className="h-4 w-4" /> {t('MikroTikVpnTab.l2tp.title')}
              </CardTitle>
              <CardDescription>
                {t('MikroTikVpnTab.l2tp.description')}
              </CardDescription>
            </div>
            <Button
              size="sm"
              variant="outline"
              disabled={!l2tp}
              onClick={() => setEditing('l2tp')}
            >
              <Pencil className="h-4 w-4 mr-1" aria-hidden="true" /> {t('MikroTikVpnTab.actions.editSettings')}
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          {l2tpQuery.isError ? (
            <ErrorState
              message={getApiErrorMessage(l2tpQuery.error, t('MikroTikVpnTab.l2tp.loadError'))}
              onRetry={() => l2tpQuery.refetch()}
            />
          ) : !l2tp ? (
            <EmptyState
              variant="compact"
              title={t('MikroTikVpnTab.l2tp.emptyTitle')}
              description={t('MikroTikVpnTab.l2tp.emptyDescription')}
            />
          ) : (
            <dl className="grid grid-cols-2 gap-x-6 gap-y-3 text-sm">
              <dt className="text-muted-foreground">{t('MikroTikVpnTab.fields.enabled')}</dt>
              <dd>
                <Badge variant={asBool(l2tp.enabled) ? 'default' : 'secondary'}>
                  {asBool(l2tp.enabled) ? t('MikroTikVpnTab.common.yes') : t('MikroTikVpnTab.common.no')}
                </Badge>
              </dd>
              <dt className="text-muted-foreground">{t('MikroTikVpnTab.fields.defaultProfile')}</dt>
              <dd className="font-mono text-xs">{asStr(l2tp['default-profile'])}</dd>
              <dt className="text-muted-foreground">{t('MikroTikVpnTab.fields.authentication')}</dt>
              <dd className="font-mono text-xs">{asStr(l2tp.authentication)}</dd>
              <dt className="text-muted-foreground">{t('MikroTikVpnTab.fields.ipsec')}</dt>
              <dd>
                <Badge variant={asBool(l2tp['use-ipsec']) ? 'default' : 'secondary'}>
                  {asBool(l2tp['use-ipsec']) ? t('MikroTikVpnTab.common.enabled') : t('MikroTikVpnTab.common.disabled')}
                </Badge>
              </dd>
              <dt className="text-muted-foreground">{t('MikroTikVpnTab.fields.maxMtu')}</dt>
              <dd className="font-mono text-xs">{asStr(l2tp['max-mtu'])}</dd>
              <dt className="text-muted-foreground">{t('MikroTikVpnTab.fields.keepalive')}</dt>
              <dd className="font-mono text-xs">{asStr(l2tp['keepalive-timeout'])}</dd>
            </dl>
          )}
        </CardContent>
      </Card>

      {/* PPTP server */}
      <Card className="border-border/50">
        <CardHeader className="pb-4">
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="flex items-center gap-2">
                <ShieldAlert className="h-4 w-4" /> {t('MikroTikVpnTab.pptp.title')}
                <Badge variant="destructive" className="ml-2">
                  {t('MikroTikVpnTab.pptp.deprecated')}
                </Badge>
              </CardTitle>
              <CardDescription>
                {t('MikroTikVpnTab.pptp.description')}
              </CardDescription>
            </div>
            <Button
              size="sm"
              variant="outline"
              disabled={!pptp}
              onClick={() => setEditing('pptp')}
            >
              <Pencil className="h-4 w-4 mr-1" aria-hidden="true" /> {t('MikroTikVpnTab.actions.editSettings')}
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          {pptpQuery.isError ? (
            <ErrorState
              message={getApiErrorMessage(pptpQuery.error, t('MikroTikVpnTab.pptp.loadError'))}
              onRetry={() => pptpQuery.refetch()}
            />
          ) : !pptp ? (
            <EmptyState
              variant="compact"
              title={t('MikroTikVpnTab.pptp.emptyTitle')}
              description={t('MikroTikVpnTab.pptp.emptyDescription')}
            />
          ) : (
            <dl className="grid grid-cols-2 gap-x-6 gap-y-3 text-sm">
              <dt className="text-muted-foreground">{t('MikroTikVpnTab.fields.enabled')}</dt>
              <dd>
                <Badge variant={asBool(pptp.enabled) ? 'default' : 'secondary'}>
                  {asBool(pptp.enabled) ? t('MikroTikVpnTab.common.yes') : t('MikroTikVpnTab.common.no')}
                </Badge>
              </dd>
              <dt className="text-muted-foreground">{t('MikroTikVpnTab.fields.defaultProfile')}</dt>
              <dd className="font-mono text-xs">{asStr(pptp['default-profile'])}</dd>
              <dt className="text-muted-foreground">{t('MikroTikVpnTab.fields.authentication')}</dt>
              <dd className="font-mono text-xs">{asStr(pptp.authentication)}</dd>
              <dt className="text-muted-foreground">{t('MikroTikVpnTab.fields.maxMtu')}</dt>
              <dd className="font-mono text-xs">{asStr(pptp['max-mtu'])}</dd>
              <dt className="text-muted-foreground">{t('MikroTikVpnTab.fields.keepalive')}</dt>
              <dd className="font-mono text-xs">{asStr(pptp['keepalive-timeout'])}</dd>
            </dl>
          )}
        </CardContent>
      </Card>

      {/* SSTP server, read-only */}
      <Card className="border-border/50">
        <CardHeader className="pb-4">
          <CardTitle className="flex items-center gap-2">
            <Lock className="h-4 w-4" /> {t('MikroTikVpnTab.sstp.title')}
          </CardTitle>
          <CardDescription>
            {t('MikroTikVpnTab.sstp.description')}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <EmptyState
            variant="compact"
            title={t('MikroTikVpnTab.sstp.emptyTitle')}
            description={t('MikroTikVpnTab.sstp.emptyDescription')}
          />
        </CardContent>
      </Card>

      {/* Settings dialog */}
      <Dialog
        open={editing !== null}
        onOpenChange={(open) => {
          if (!open) setEditing(null);
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>
              {editing === 'l2tp'
                ? t('MikroTikVpnTab.dialog.titleL2tp')
                : t('MikroTikVpnTab.dialog.titlePptp')}
            </DialogTitle>
            <DialogDescription>
              {editing === 'l2tp'
                ? t('MikroTikVpnTab.dialog.descriptionL2tp')
                : t('MikroTikVpnTab.dialog.descriptionPptp')}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            <label className="flex items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={form.enabled}
                onChange={(e) => setForm((f) => ({ ...f, enabled: e.target.checked }))}
              />
              {t('MikroTikVpnTab.dialog.enableServer')}
            </label>
            <div className="space-y-2">
              <Label htmlFor="mtk-vpn-profile">{t('MikroTikVpnTab.fields.defaultProfile')}</Label>
              <Input
                id="mtk-vpn-profile"
                value={form.defaultProfile}
                onChange={(e) =>
                  setForm((f) => ({ ...f, defaultProfile: e.target.value }))
                }
                placeholder="default-encryption"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="mtk-vpn-auth">{t('MikroTikVpnTab.fields.authentication')}</Label>
              <Input
                id="mtk-vpn-auth"
                value={form.authentication}
                onChange={(e) =>
                  setForm((f) => ({ ...f, authentication: e.target.value }))
                }
                placeholder="mschap2,mschap1"
              />
            </div>
            {editing === 'l2tp' && (
              <>
                <label className="flex items-center gap-2 text-sm">
                  <input
                    type="checkbox"
                    checked={form.useIpsec}
                    onChange={(e) =>
                      setForm((f) => ({ ...f, useIpsec: e.target.checked }))
                    }
                  />
                  {t('MikroTikVpnTab.dialog.useIpsec')}
                </label>
                {form.useIpsec && (
                  <div className="space-y-2">
                    <Label htmlFor="mtk-vpn-ipsec">{t('MikroTikVpnTab.dialog.ipsecSecretLabel')}</Label>
                    <Input
                      id="mtk-vpn-ipsec"
                      type="password"
                      value={form.ipsecSecret}
                      onChange={(e) =>
                        setForm((f) => ({ ...f, ipsecSecret: e.target.value }))
                      }
                      placeholder={t('MikroTikVpnTab.dialog.ipsecSecretPlaceholder')}
                      autoComplete="new-password"
                    />
                    <p className="text-xs text-muted-foreground">
                      {t('MikroTikVpnTab.dialog.ipsecSecretHelp')}
                    </p>
                  </div>
                )}
              </>
            )}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setEditing(null)}>
              {t('MikroTikVpnTab.actions.cancel')}
            </Button>
            <Button
              onClick={submit}
              disabled={updateL2TPMut.isPending || updatePPTPMut.isPending}
            >
              {(updateL2TPMut.isPending || updatePPTPMut.isPending) && (
                <Loader2 className="h-4 w-4 animate-spin mr-1" />
              )}
              {t('MikroTikVpnTab.actions.stageUpdate')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

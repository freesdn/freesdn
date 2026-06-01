// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN, UniFi WLANs tab
 *
 * Stages PSK rotation + enable/disable on UniFi WLAN configs via
 * gateway-unifi-wlans. PSK input is type=password so the value never
 * surfaces in the DOM tree once typed; the stage payload is redacted
 * by the backend before it lands in the drawer's payload preview.
 */
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { KeyRound, Loader2, Power, RefreshCw, Wifi } from 'lucide-react';
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

interface UniFiWlan {
  _id: string;
  name?: string;
  enabled?: boolean;
  security?: string;
  is_guest?: boolean;
  hide_ssid?: boolean;
  // Note: x_passphrase / wpa_passphrase intentionally redacted by
  // backend; not consumed here.
}

interface UniFiWlansResponse {
  controller_id: string;
  site: string;
  items: UniFiWlan[];
  fetched_at: string;
}

async function fetchWlans(controllerId: string, site: string) {
  return api.get<UniFiWlansResponse>(
    `/gateway-unifi-wlans/${enc(controllerId)}/sites/${enc(site)}/wlans`,
  );
}

async function stageWlanChange(
  controllerId: string,
  feature: string,
  wlanId: string,
  payload: Record<string, unknown>,
) {
  return api.post(
    `/gateway-unifi-wlans/${enc(controllerId)}/changes/${enc(feature)}`,
    { payload, target_id: wlanId },
    { params: { operation: 'update' } },
  );
}

type WlanOp =
  | { kind: 'password'; wlanId: string; label: string; psk: string }
  | { kind: 'enable'; wlanId: string; label: string; enabled: boolean };

interface UniFiWlansTabProps {
  controllerId: string;
  site: string;
  isActive: boolean;
}

export function UniFiWlansTab({
  controllerId,
  site,
  isActive,
}: UniFiWlansTabProps) {
  const queryClient = useQueryClient();
  const { t } = useTranslation('firewall');
  const { toast } = useToast();
  const [confirm, setConfirm] = useState<WlanOp | null>(null);
  const [manualWlanId, setManualWlanId] = useState('');
  const [manualPsk, setManualPsk] = useState('');

  const LIST_KEY = ['unifi', 'wlans', controllerId, site] as const;

  const query = useQuery({
    queryKey: LIST_KEY,
    queryFn: () => fetchWlans(controllerId, site),
    enabled: isActive && !!controllerId,
    refetchInterval: 60_000,
  });

  const stageMut = useMutation({
    mutationFn: async (op: WlanOp) => {
      if (op.kind === 'password') {
        return stageWlanChange(
          controllerId,
          'unifi.wlans.password',
          op.wlanId,
          { site, new_psk: op.psk },
        );
      }
      return stageWlanChange(controllerId, 'unifi.wlans.enable', op.wlanId, {
        site,
        enabled: op.enabled,
      });
    },
    onSuccess: (_, vars) => {
      toast({
        title:
          vars.kind === 'password'
            ? t('UniFiWlansTab.toast.pskStaged')
            : vars.enabled
              ? t('UniFiWlansTab.toast.enableStaged')
              : t('UniFiWlansTab.toast.disableStaged'),
        description: vars.label,
      });
      setConfirm(null);
      // Wipe the in-memory PSK after staging so it never sticks
      // around in component state.
      setManualPsk('');
      queryClient.invalidateQueries({ queryKey: LIST_KEY });
    },
    onError: (err: unknown) => {
      toast({
        title: t('UniFiWlansTab.toast.stageFailed'),
        description: getApiErrorMessage(err),
        variant: 'destructive',
      });
    },
  });

  const wlans = query.data?.data?.items ?? [];

  return (
    <Card>
      <CardHeader className="flex flex-row items-start justify-between">
        <div>
          <CardTitle className="flex items-center gap-2">
            <Wifi className="h-4 w-4" /> {t('UniFiWlansTab.title')}
            <Badge variant="default">{wlans.length}</Badge>
          </CardTitle>
          <p className="text-sm text-muted-foreground mt-1">
            {t('UniFiWlansTab.siteLabel')}{' '}
            <code className="font-mono">{site}</code>{' '}
            {t('UniFiWlansTab.description')}
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
        <div className="border border-border rounded-lg p-3 space-y-3">
          <Label className="text-sm font-medium">
            {t('UniFiWlansTab.stageByWlanId')}
          </Label>
          <Input
            placeholder={t('UniFiWlansTab.wlanIdPlaceholder')}
            value={manualWlanId}
            onChange={(e) => setManualWlanId(e.target.value)}
            className="font-mono text-sm"
          />
          <div className="flex items-end gap-2 pt-2 border-t border-border">
            <div className="flex-1 space-y-1">
              <Label htmlFor="unifi-psk" className="text-xs">
                {t('UniFiWlansTab.newPskLabel')}
              </Label>
              <Input
                id="unifi-psk"
                type="password"
                placeholder="••••••••"
                value={manualPsk}
                onChange={(e) => setManualPsk(e.target.value)}
                autoComplete="new-password"
                className="text-sm"
              />
            </div>
            <Button
              size="sm"
              variant="outline"
              onClick={() =>
                setConfirm({
                  kind: 'password',
                  wlanId: manualWlanId,
                  label: manualWlanId,
                  psk: manualPsk,
                })
              }
              disabled={
                !manualWlanId.trim() ||
                manualPsk.length < 8 ||
                manualPsk.length > 63
              }
            >
              <KeyRound className="h-4 w-4 mr-1" /> {t('UniFiWlansTab.actions.stagePsk')}
            </Button>
          </div>
          <div className="flex items-center gap-2 pt-2 border-t border-border">
            <Button
              size="sm"
              variant="outline"
              onClick={() =>
                setConfirm({
                  kind: 'enable',
                  wlanId: manualWlanId,
                  label: manualWlanId,
                  enabled: true,
                })
              }
              disabled={!manualWlanId.trim()}
            >
              <Power className="h-4 w-4 mr-1" /> {t('UniFiWlansTab.actions.stageEnable')}
            </Button>
            <Button
              size="sm"
              variant="outline"
              onClick={() =>
                setConfirm({
                  kind: 'enable',
                  wlanId: manualWlanId,
                  label: manualWlanId,
                  enabled: false,
                })
              }
              disabled={!manualWlanId.trim()}
            >
              <Power className="h-4 w-4 mr-1" /> {t('UniFiWlansTab.actions.stageDisable')}
            </Button>
          </div>
        </div>

        {query.isError && (
          <div className="rounded-md bg-destructive/10 border border-destructive p-3 text-sm text-destructive">
            {t('UniFiWlansTab.loadFailed')}{' '}
            {(query.error as Error)?.message || t('UniFiWlansTab.unknownError')}
          </div>
        )}

        {query.isLoading ? (
          <div className="flex items-center justify-center py-8 text-muted-foreground">
            <Loader2 className="h-4 w-4 animate-spin mr-2" /> {t('UniFiWlansTab.loading')}
          </div>
        ) : wlans.length === 0 ? (
          <div className="text-center py-8 text-sm text-muted-foreground">
            {t('UniFiWlansTab.empty')}
          </div>
        ) : (
          <ul className="space-y-2">
            {wlans.map((w) => {
              const label = w.name || w._id;
              return (
                <li
                  key={w._id}
                  className="flex items-center justify-between border border-border rounded-lg p-3"
                >
                  <div className="space-y-1 min-w-0">
                    <div className="text-sm font-medium">{label}</div>
                    <div className="text-xs text-muted-foreground font-mono">
                      {w._id}
                      {w.security ? ` · ${w.security}` : ''}
                      {w.enabled === false
                        ? ` · ${t('UniFiWlansTab.status.disabled')}`
                        : ''}
                      {w.hide_ssid ? ` · ${t('UniFiWlansTab.status.hidden')}` : ''}
                    </div>
                  </div>
                  <div className="flex items-center gap-1">
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() =>
                        setConfirm({
                          kind: 'enable',
                          wlanId: w._id,
                          label,
                          enabled: !w.enabled,
                        })
                      }
                      disabled={stageMut.isPending}
                    >
                      <Power className="h-4 w-4 mr-1" />
                      {w.enabled
                        ? t('UniFiWlansTab.actions.disable')
                        : t('UniFiWlansTab.actions.enable')}
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
              {confirm?.kind === 'password'
                ? t('UniFiWlansTab.dialog.rotatePskTitle')
                : confirm?.enabled
                  ? t('UniFiWlansTab.dialog.enableTitle')
                  : t('UniFiWlansTab.dialog.disableTitle')}
            </AlertDialogTitle>
            <AlertDialogDescription>
              {t('UniFiWlansTab.dialog.stagePrefix')}{' '}
              <code className="font-mono">
                unifi.wlans.{confirm?.kind === 'password' ? 'password' : 'enable'}
              </code>{' '}
              {t('UniFiWlansTab.dialog.against')}{' '}
              <code className="font-mono">{confirm?.label}</code>?
              {confirm?.kind === 'password'
                ? ` ${t('UniFiWlansTab.dialog.pskNote')}`
                : ''}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>
              {t('UniFiWlansTab.actions.cancel')}
            </AlertDialogCancel>
            <AlertDialogAction
              onClick={() => confirm && stageMut.mutate(confirm)}
              disabled={stageMut.isPending}
            >
              {t('UniFiWlansTab.actions.stage')}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </Card>
  );
}

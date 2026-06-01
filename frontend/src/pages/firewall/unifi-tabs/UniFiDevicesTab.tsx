// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN, UniFi Devices tab
 *
 * Stages restart / disable / set-port-poe against UniFi APs / switches /
 * gateways via the gateway-unifi-devices stage endpoint. Catastrophic
 * features (restart, disable) require typed APPLY in the drawer +
 * site_admin role on the backend.
 */
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Loader2, Power, RefreshCw, RotateCcw, Zap } from 'lucide-react';
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

interface UniFiDevice {
  mac: string;
  name?: string;
  model?: string;
  state?: number;
  ip?: string;
  type?: string;
  adopted?: boolean;
  disabled?: boolean;
  port_table?: Array<{ port_idx: number; name?: string; poe_enable?: boolean }>;
}

interface UniFiDevicesResponse {
  controller_id: string;
  site: string;
  items: UniFiDevice[];
  fetched_at: string;
}

async function fetchDevices(controllerId: string, site: string) {
  return api.get<UniFiDevicesResponse>(
    `/gateway-unifi-devices/${enc(controllerId)}/sites/${enc(site)}/devices`,
  );
}

async function stageDeviceChange(
  controllerId: string,
  feature: string,
  operation: 'update' | 'delete',
  mac: string,
  payload: Record<string, unknown>,
) {
  return api.post(
    `/gateway-unifi-devices/${enc(controllerId)}/changes/${enc(feature)}`,
    { payload, target_id: mac },
    { params: { operation } },
  );
}

type DeviceOp =
  | { kind: 'restart'; mac: string; label: string }
  | { kind: 'disable'; mac: string; label: string; disabled: boolean }
  | { kind: 'set_poe'; mac: string; label: string; port_idx: number; mode: string };

interface UniFiDevicesTabProps {
  controllerId: string;
  site: string;
  isActive: boolean;
}

export function UniFiDevicesTab({
  controllerId,
  site,
  isActive,
}: UniFiDevicesTabProps) {
  const { t } = useTranslation('firewall');
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const [confirm, setConfirm] = useState<DeviceOp | null>(null);
  // Manual fields for staging against an MAC not in the live list
  // (lab controllers ship without adopted devices).
  const [manualMac, setManualMac] = useState('');
  const [poePortIdx, setPoePortIdx] = useState<number>(1);
  const [poeMode, setPoeMode] = useState<string>('auto');

  const LIST_KEY = ['unifi', 'devices', controllerId, site] as const;

  const query = useQuery({
    queryKey: LIST_KEY,
    queryFn: () => fetchDevices(controllerId, site),
    enabled: isActive && !!controllerId,
    refetchInterval: 30_000,
  });

  const stageMut = useMutation({
    mutationFn: async (op: DeviceOp) => {
      if (op.kind === 'restart') {
        return stageDeviceChange(
          controllerId,
          'unifi.devices.restart',
          'update',
          op.mac,
          { site },
        );
      }
      if (op.kind === 'disable') {
        return stageDeviceChange(
          controllerId,
          'unifi.devices.disable',
          'update',
          op.mac,
          { site, disabled: op.disabled },
        );
      }
      // set_poe
      return stageDeviceChange(
        controllerId,
        'unifi.devices.set_port_poe',
        'update',
        op.mac,
        { site, port_idx: op.port_idx, mode: op.mode },
      );
    },
    onSuccess: (_, vars) => {
      toast({
        title: t('UniFiDevicesTab.toast.staged', { kind: vars.kind }),
        description: vars.mac,
      });
      setConfirm(null);
      queryClient.invalidateQueries({ queryKey: LIST_KEY });
    },
    onError: (err: unknown) => {
      toast({
        title: t('UniFiDevicesTab.toast.stageFailed'),
        description: getApiErrorMessage(err),
        variant: 'destructive',
      });
    },
  });

  const devices = query.data?.data?.items ?? [];

  return (
    <Card>
      <CardHeader className="flex flex-row items-start justify-between">
        <div>
          <CardTitle className="flex items-center gap-2">
            {t('UniFiDevicesTab.title')}
            <Badge variant="default">{devices.length}</Badge>
          </CardTitle>
          <p className="text-sm text-muted-foreground mt-1">
            {t('UniFiDevicesTab.subtitle.sitePrefix')}{' '}
            <code className="font-mono">{site}</code>{' '}
            {t('UniFiDevicesTab.subtitle.body')}
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
        {/* Manual stage form */}
        <div className="border border-border rounded-lg p-3 space-y-3">
          <Label className="text-sm font-medium">
            {t('UniFiDevicesTab.stageByMac.label')}
          </Label>
          <div className="flex items-center gap-2">
            <Input
              placeholder="aa:bb:cc:dd:ee:ff"
              value={manualMac}
              onChange={(e) => setManualMac(e.target.value)}
              className="flex-1 font-mono text-sm"
            />
            <Button
              size="sm"
              variant="outline"
              onClick={() =>
                setConfirm({
                  kind: 'restart',
                  mac: manualMac,
                  label: manualMac,
                })
              }
              disabled={!manualMac.trim()}
            >
              <RotateCcw className="h-4 w-4 mr-1" /> {t('UniFiDevicesTab.actions.restart')}
            </Button>
            <Button
              size="sm"
              variant="outline"
              onClick={() =>
                setConfirm({
                  kind: 'disable',
                  mac: manualMac,
                  label: manualMac,
                  disabled: true,
                })
              }
              disabled={!manualMac.trim()}
            >
              <Power className="h-4 w-4 mr-1" /> {t('UniFiDevicesTab.actions.disable')}
            </Button>
          </div>
          <div className="flex items-end gap-2 pt-2 border-t border-border">
            <div className="flex-1 space-y-1">
              <Label className="text-xs">{t('UniFiDevicesTab.fields.port')}</Label>
              <Input
                type="number"
                min={1}
                max={48}
                value={poePortIdx}
                onChange={(e) => setPoePortIdx(parseInt(e.target.value, 10) || 1)}
                className="text-sm"
              />
            </div>
            <div className="flex-1 space-y-1">
              <Label className="text-xs">{t('UniFiDevicesTab.fields.poeMode')}</Label>
              <Select value={poeMode} onValueChange={setPoeMode}>
                <SelectTrigger className="text-sm">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="auto">auto</SelectItem>
                  <SelectItem value="off">off</SelectItem>
                  <SelectItem value="passive24">passive24</SelectItem>
                  <SelectItem value="pasv24">pasv24</SelectItem>
                  <SelectItem value="passthrough">passthrough</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <Button
              size="sm"
              variant="outline"
              onClick={() =>
                setConfirm({
                  kind: 'set_poe',
                  mac: manualMac,
                  label: manualMac,
                  port_idx: poePortIdx,
                  mode: poeMode,
                })
              }
              disabled={!manualMac.trim()}
            >
              <Zap className="h-4 w-4 mr-1" /> {t('UniFiDevicesTab.actions.stagePoe')}
            </Button>
          </div>
        </div>

        {query.isError && (
          <div className="rounded-md bg-destructive/10 border border-destructive p-3 text-sm text-destructive">
            {t('UniFiDevicesTab.errors.loadFailed')}{' '}
            {(query.error as Error)?.message || t('UniFiDevicesTab.errors.unknown')}
          </div>
        )}

        {query.isLoading ? (
          <div className="flex items-center justify-center py-8 text-muted-foreground">
            <Loader2 className="h-4 w-4 animate-spin mr-2" /> {t('UniFiDevicesTab.loading')}
          </div>
        ) : devices.length === 0 ? (
          <div className="text-center py-8 text-sm text-muted-foreground">
            {t('UniFiDevicesTab.empty')}
          </div>
        ) : (
          <ul className="space-y-2">
            {devices.map((d) => {
              const label = d.name || d.mac;
              return (
                <li
                  key={d.mac}
                  className="flex items-center justify-between border border-border rounded-lg p-3"
                >
                  <div className="space-y-1 min-w-0">
                    <div className="text-sm font-medium">{label}</div>
                    <div className="text-xs text-muted-foreground font-mono">
                      {d.mac}
                      {d.ip ? ` · ${d.ip}` : ''}
                      {d.model ? ` · ${d.model}` : ''}
                      {d.disabled ? ` · ${t('UniFiDevicesTab.status.disabled')}` : ''}
                    </div>
                  </div>
                  <div className="flex items-center gap-1">
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() =>
                        setConfirm({
                          kind: 'restart',
                          mac: d.mac,
                          label,
                        })
                      }
                      disabled={stageMut.isPending}
                    >
                      <RotateCcw className="h-4 w-4 mr-1" /> {t('UniFiDevicesTab.actions.restart')}
                    </Button>
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() =>
                        setConfirm({
                          kind: 'disable',
                          mac: d.mac,
                          label,
                          disabled: !d.disabled,
                        })
                      }
                      disabled={stageMut.isPending}
                    >
                      <Power className="h-4 w-4 mr-1" />{' '}
                      {d.disabled
                        ? t('UniFiDevicesTab.actions.enable')
                        : t('UniFiDevicesTab.actions.disable')}
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
              {t('UniFiDevicesTab.dialog.title', {
                operation:
                  confirm?.kind === 'restart'
                    ? t('UniFiDevicesTab.operations.restart')
                    : confirm?.kind === 'disable'
                      ? confirm.disabled
                        ? t('UniFiDevicesTab.operations.disable')
                        : t('UniFiDevicesTab.operations.enable')
                      : t('UniFiDevicesTab.operations.poeSet'),
              })}
            </AlertDialogTitle>
            <AlertDialogDescription>
              {t('UniFiDevicesTab.dialog.bodyPrefix')}{' '}
              <code className="font-mono">
                unifi.devices.
                {confirm?.kind === 'set_poe'
                  ? 'set_port_poe'
                  : confirm?.kind}
              </code>{' '}
              {t('UniFiDevicesTab.dialog.bodyAgainst')}{' '}
              <code className="font-mono">{confirm?.label}</code>
              {t('UniFiDevicesTab.dialog.bodySuffix')}
              {confirm?.kind === 'restart' || confirm?.kind === 'disable' ? (
                <>
                  {' '}
                  {t('UniFiDevicesTab.dialog.catastrophicPrefix')}{' '}
                  <strong>{t('UniFiDevicesTab.dialog.catastrophicWord')}</strong>{' '}
                  {t('UniFiDevicesTab.dialog.catastrophicMid')}{' '}
                  <code>APPLY</code>{' '}
                  {t('UniFiDevicesTab.dialog.catastrophicSuffix')}
                </>
              ) : null}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t('UniFiDevicesTab.actions.cancel')}</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => confirm && stageMut.mutate(confirm)}
              disabled={stageMut.isPending}
            >
              {t('UniFiDevicesTab.actions.stage')}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </Card>
  );
}

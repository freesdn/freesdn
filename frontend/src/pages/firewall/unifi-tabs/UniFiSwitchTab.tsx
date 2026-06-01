// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN, UniFi Switch ports tab
 *
 * Stages per-port switch changes (PoE mode, port profile, power-cycle,
 * generic port settings) against gateway-unifi-switch. The read lists
 * switches with their ``port_table`` (live state) and ``port_overrides``
 * (configured deltas). All write features operate as ``update`` with
 * target_id = switch MAC. Like the other UniFi domain tabs, writes never
 * touch the controller directly, they land as pending rows that the
 * operator applies via the Pending Changes drawer
 * (POST /gateway-unifi-switch/{cid}/changes/...).
 */
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Loader2, Network, Power, RefreshCw, Zap } from 'lucide-react';
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

interface UniFiPort {
  port_idx: number;
  name?: string;
  poe_enable?: boolean;
  poe_mode?: string;
  up?: boolean;
  enable?: boolean;
  speed?: number;
  portconf_id?: string;
}

interface UniFiSwitch {
  mac: string;
  name?: string;
  model?: string;
  ip?: string;
  port_table?: UniFiPort[];
  port_overrides?: Array<{ port_idx: number; [k: string]: unknown }>;
}

interface UniFiSwitchResponse {
  controller_id: string;
  site: string;
  items: UniFiSwitch[];
  fetched_at: string;
}

async function fetchSwitches(controllerId: string, site: string) {
  return api.get<UniFiSwitchResponse>(
    `/gateway-unifi-switch/${enc(controllerId)}/sites/${enc(site)}/switches`,
  );
}

async function stageSwitchChange(
  controllerId: string,
  feature: string,
  mac: string,
  payload: Record<string, unknown>,
) {
  return api.post(
    `/gateway-unifi-switch/${enc(controllerId)}/changes/${enc(feature)}`,
    { payload, target_id: mac },
    { params: { operation: 'update' } },
  );
}

type SwitchOp =
  | {
      kind: 'set_poe';
      mac: string;
      label: string;
      port_idx: number;
      poe_mode: string;
    }
  | {
      kind: 'port_profile';
      mac: string;
      label: string;
      port_idx: number;
      profile_id: string;
    }
  | { kind: 'power_cycle'; mac: string; label: string; port_idx: number }
  | {
      kind: 'update_port';
      mac: string;
      label: string;
      port_idx: number;
      name: string;
    };

// Feature ids keyed by op kind. ``update_port`` carries arbitrary port
// settings under ``settings``; the others carry a flat field set.
const FEATURE: Record<SwitchOp['kind'], string> = {
  set_poe: 'unifi.switch.set_poe',
  port_profile: 'unifi.switch.port_profile',
  power_cycle: 'unifi.switch.power_cycle',
  update_port: 'unifi.switch.update_port',
};

interface UniFiSwitchTabProps {
  controllerId: string;
  site: string;
  isActive: boolean;
}

export function UniFiSwitchTab({
  controllerId,
  site,
  isActive,
}: UniFiSwitchTabProps) {
  const { t } = useTranslation('firewall');
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const [confirm, setConfirm] = useState<SwitchOp | null>(null);
  // Manual stage fields, for staging against a switch MAC + port that may
  // not be in the live list (lab controllers ship without adopted gear).
  const [mac, setMac] = useState('');
  const [portIdx, setPortIdx] = useState<number>(1);
  const [poeMode, setPoeMode] = useState<string>('auto');
  const [profileId, setProfileId] = useState('');
  const [portName, setPortName] = useState('');

  const LIST_KEY = ['unifi', 'switch', controllerId, site] as const;

  const query = useQuery({
    queryKey: LIST_KEY,
    queryFn: () => fetchSwitches(controllerId, site),
    enabled: isActive && !!controllerId,
    refetchInterval: 60_000,
  });

  const stageMut = useMutation({
    mutationFn: async (op: SwitchOp) => {
      const feature = FEATURE[op.kind];
      if (op.kind === 'set_poe') {
        return stageSwitchChange(controllerId, feature, op.mac, {
          site,
          mac: op.mac,
          port_idx: op.port_idx,
          poe_mode: op.poe_mode,
        });
      }
      if (op.kind === 'port_profile') {
        return stageSwitchChange(controllerId, feature, op.mac, {
          site,
          mac: op.mac,
          port_idx: op.port_idx,
          profile_id: op.profile_id,
        });
      }
      if (op.kind === 'power_cycle') {
        return stageSwitchChange(controllerId, feature, op.mac, {
          site,
          mac: op.mac,
          port_idx: op.port_idx,
        });
      }
      // update_port: arbitrary settings under ``settings``
      return stageSwitchChange(controllerId, feature, op.mac, {
        site,
        mac: op.mac,
        port_idx: op.port_idx,
        settings: { name: op.name.trim() },
      });
    },
    onSuccess: (_data, vars) => {
      toast({
        title: t('UniFiSwitchTab.toast.staged', { kind: vars.kind }),
        description: `${vars.mac} · ${t('UniFiSwitchTab.portLabel', {
          port: vars.port_idx,
        })}`,
      });
      setConfirm(null);
      queryClient.invalidateQueries({ queryKey: LIST_KEY });
    },
    onError: (err: unknown) => {
      toast({
        title: t('UniFiSwitchTab.toast.stageFailed'),
        description: getApiErrorMessage(err),
        variant: 'destructive',
      });
    },
  });

  const switches = query.data?.data?.items ?? [];
  const macReady = mac.trim().length > 0;

  return (
    <Card>
      <CardHeader className="flex flex-row items-start justify-between">
        <div>
          <CardTitle className="flex items-center gap-2">
            <Network className="h-4 w-4" /> {t('UniFiSwitchTab.title')}
            <Badge variant="default">{switches.length}</Badge>
          </CardTitle>
          <p className="text-sm text-muted-foreground mt-1">
            {t('UniFiSwitchTab.siteLabel')}{' '}
            <code className="font-mono">{site}</code> ·{' '}
            {t('UniFiSwitchTab.description')}
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
        {/* Manual stage form. Pick the switch MAC + port, then one of the
            four port actions. Blank optional fields are omitted. */}
        <div className="border border-border rounded-lg p-3 space-y-3">
          <Label className="text-sm font-medium">
            {t('UniFiSwitchTab.form.stageByMac')}
          </Label>
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1">
              <Label htmlFor="sw-mac" className="text-xs">
                {t('UniFiSwitchTab.fields.mac')}
              </Label>
              <Input
                id="sw-mac"
                placeholder="aa:bb:cc:dd:ee:ff"
                value={mac}
                onChange={(e) => setMac(e.target.value)}
                className="font-mono text-sm"
              />
            </div>
            <div className="space-y-1">
              <Label htmlFor="sw-port" className="text-xs">
                {t('UniFiSwitchTab.fields.port')}
              </Label>
              <Input
                id="sw-port"
                type="number"
                min={1}
                max={48}
                value={portIdx}
                onChange={(e) =>
                  setPortIdx(parseInt(e.target.value, 10) || 1)
                }
                className="text-sm"
              />
            </div>
          </div>

          {/* PoE */}
          <div className="flex items-end gap-2 pt-2 border-t border-border">
            <div className="flex-1 space-y-1">
              <Label className="text-xs">
                {t('UniFiSwitchTab.fields.poeMode')}
              </Label>
              <Select value={poeMode} onValueChange={setPoeMode}>
                <SelectTrigger className="text-sm">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="auto">auto</SelectItem>
                  <SelectItem value="off">off</SelectItem>
                  {/* Value must be a literal the controller understands —
                      ``pasv24`` (passive 24V), NOT ``passv24``, which the
                      adapter's validate_poe_mode rejects with a 400. */}
                  <SelectItem value="pasv24">passive 24V</SelectItem>
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
                  mac,
                  label: mac,
                  port_idx: portIdx,
                  poe_mode: poeMode,
                })
              }
              disabled={!macReady}
            >
              <Zap className="h-4 w-4 mr-1" />{' '}
              {t('UniFiSwitchTab.actions.stagePoe')}
            </Button>
          </div>

          {/* Port profile */}
          <div className="flex items-end gap-2 pt-2 border-t border-border">
            <div className="flex-1 space-y-1">
              <Label htmlFor="sw-profile" className="text-xs">
                {t('UniFiSwitchTab.fields.profileId')}
              </Label>
              <Input
                id="sw-profile"
                placeholder={t('UniFiSwitchTab.fields.profileIdPlaceholder')}
                value={profileId}
                onChange={(e) => setProfileId(e.target.value)}
                className="font-mono text-sm"
              />
            </div>
            <Button
              size="sm"
              variant="outline"
              onClick={() =>
                setConfirm({
                  kind: 'port_profile',
                  mac,
                  label: mac,
                  port_idx: portIdx,
                  profile_id: profileId.trim(),
                })
              }
              disabled={!macReady || !profileId.trim()}
            >
              {t('UniFiSwitchTab.actions.stageProfile')}
            </Button>
          </div>

          {/* Port name (generic update_port) + power-cycle */}
          <div className="flex items-end gap-2 pt-2 border-t border-border">
            <div className="flex-1 space-y-1">
              <Label htmlFor="sw-name" className="text-xs">
                {t('UniFiSwitchTab.fields.portName')}
              </Label>
              <Input
                id="sw-name"
                placeholder={t('UniFiSwitchTab.fields.portNamePlaceholder')}
                value={portName}
                onChange={(e) => setPortName(e.target.value)}
                className="text-sm"
              />
            </div>
            <Button
              size="sm"
              variant="outline"
              onClick={() =>
                setConfirm({
                  kind: 'update_port',
                  mac,
                  label: mac,
                  port_idx: portIdx,
                  name: portName,
                })
              }
              disabled={!macReady || !portName.trim()}
            >
              {t('UniFiSwitchTab.actions.stageUpdate')}
            </Button>
            <Button
              size="sm"
              variant="outline"
              onClick={() =>
                setConfirm({
                  kind: 'power_cycle',
                  mac,
                  label: mac,
                  port_idx: portIdx,
                })
              }
              disabled={!macReady}
            >
              <Power className="h-4 w-4 mr-1" />{' '}
              {t('UniFiSwitchTab.actions.stagePowerCycle')}
            </Button>
          </div>
        </div>

        {query.isError && (
          <div className="rounded-md bg-destructive/10 border border-destructive p-3 text-sm text-destructive">
            {t('UniFiSwitchTab.loadError')}{' '}
            {(query.error as Error)?.message ||
              t('UniFiSwitchTab.unknownError')}
          </div>
        )}

        {query.isLoading ? (
          <div className="flex items-center justify-center py-8 text-muted-foreground">
            <Loader2 className="h-4 w-4 animate-spin mr-2" />{' '}
            {t('UniFiSwitchTab.loading')}
          </div>
        ) : switches.length === 0 ? (
          <div className="text-center py-8 text-sm text-muted-foreground">
            {t('UniFiSwitchTab.empty')}
          </div>
        ) : (
          <ul className="space-y-2">
            {switches.map((sw) => {
              const label = sw.name || sw.mac;
              const ports = sw.port_table ?? [];
              return (
                <li
                  key={sw.mac}
                  className="border border-border rounded-lg p-3 space-y-2"
                >
                  <div className="flex items-center justify-between">
                    <div className="space-y-1 min-w-0">
                      <div className="text-sm font-medium">{label}</div>
                      <div className="text-xs text-muted-foreground font-mono">
                        {sw.mac}
                        {sw.model ? ` · ${sw.model}` : ''}
                        {sw.ip ? ` · ${sw.ip}` : ''}
                        {` · ${t('UniFiSwitchTab.portCount', {
                          count: ports.length,
                        })}`}
                      </div>
                    </div>
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => setMac(sw.mac)}
                      disabled={stageMut.isPending}
                    >
                      {t('UniFiSwitchTab.actions.select')}
                    </Button>
                  </div>
                  {ports.length > 0 ? (
                    <div className="flex flex-wrap gap-1">
                      {ports.map((p) => (
                        <Badge
                          key={p.port_idx}
                          variant={p.up ? 'success' : 'secondary'}
                        >
                          {t('UniFiSwitchTab.portShort', { port: p.port_idx })}
                          {p.poe_enable ? ' · PoE' : ''}
                          {p.enable === false
                            ? ` · ${t('UniFiSwitchTab.status.disabled')}`
                            : ''}
                        </Badge>
                      ))}
                    </div>
                  ) : null}
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
              {t('UniFiSwitchTab.dialog.title', {
                operation: confirm
                  ? t(`UniFiSwitchTab.operations.${confirm.kind}`)
                  : '',
              })}
            </AlertDialogTitle>
            <AlertDialogDescription>
              {t('UniFiSwitchTab.dialog.stagePrefix')}{' '}
              <code className="font-mono">
                {confirm ? FEATURE[confirm.kind] : ''}
              </code>{' '}
              {t('UniFiSwitchTab.dialog.against')}{' '}
              <code className="font-mono">{confirm?.mac}</code>{' '}
              {t('UniFiSwitchTab.dialog.onPort')}{' '}
              <code className="font-mono">{confirm?.port_idx}</code>
              {confirm?.kind === 'power_cycle' ? (
                <>
                  {' '}
                  {t('UniFiSwitchTab.dialog.powerCyclePrefix')}{' '}
                  <strong>{t('UniFiSwitchTab.dialog.powerCycleWord')}</strong>{' '}
                  {t('UniFiSwitchTab.dialog.powerCycleSuffix')}
                </>
              ) : (
                t('UniFiSwitchTab.dialog.suffix')
              )}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>
              {t('UniFiSwitchTab.actions.cancel')}
            </AlertDialogCancel>
            <AlertDialogAction
              onClick={() => confirm && stageMut.mutate(confirm)}
              disabled={stageMut.isPending}
            >
              {t('UniFiSwitchTab.actions.stage')}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </Card>
  );
}

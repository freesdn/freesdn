// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN, UniFi Radios tab
 *
 * Stages per-radio RF changes (channel, TX power, channel width) on
 * UniFi APs via gateway-unifi-radios. The read lists APs with their
 * ``radio_table`` so the operator can see the current band layout. Like
 * the other UniFi domain tabs, writes never touch the controller
 * directly, they land as pending rows that the operator applies via the
 * Pending Changes drawer (POST /gateway-unifi-radios/{cid}/changes/...).
 */
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Loader2, RadioTower, RefreshCw } from 'lucide-react';
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

interface UniFiRadioEntry {
  radio?: string; // ng | na | 6e
  name?: string;
  channel?: number | string;
  ht?: number; // channel width (20/40/80/160)
  tx_power_mode?: string;
  tx_power?: number;
}

interface UniFiRadioDevice {
  mac: string;
  name?: string;
  model?: string;
  state?: number;
  ip?: string;
  radio_table?: UniFiRadioEntry[];
}

interface UniFiRadiosResponse {
  controller_id: string;
  site: string;
  items: UniFiRadioDevice[];
  fetched_at: string;
}

async function fetchRadios(controllerId: string, site: string) {
  return api.get<UniFiRadiosResponse>(
    `/gateway-unifi-radios/${enc(controllerId)}/sites/${enc(site)}/radios`,
  );
}

async function stageRadioChange(
  controllerId: string,
  mac: string,
  payload: Record<string, unknown>,
) {
  return api.post(
    `/gateway-unifi-radios/${enc(controllerId)}/changes/unifi.radios.update`,
    { payload, target_id: mac },
    { params: { operation: 'update' } },
  );
}

// ``radio`` selects the band (UniFi band keys: ng=2.4GHz, na=5GHz,
// 6e=6GHz). Channel / power / width fields are optional, only the ones
// the operator sets land in the payload (refine-in-drawer philosophy).
interface RadioForm {
  mac: string;
  radio: string;
  channel: string;
  tx_power_mode: string;
  tx_power: string;
  ht: string;
}

const BLANK: RadioForm = {
  mac: '',
  radio: 'ng',
  channel: '',
  tx_power_mode: '',
  tx_power: '',
  ht: '',
};

interface RadioOp {
  mac: string;
  radio: string;
  channel: string;
  tx_power_mode: string;
  tx_power: string;
  ht: string;
}

interface UniFiRadiosTabProps {
  controllerId: string;
  site: string;
  isActive: boolean;
}

export function UniFiRadiosTab({
  controllerId,
  site,
  isActive,
}: UniFiRadiosTabProps) {
  const { t } = useTranslation('firewall');
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const [form, setForm] = useState<RadioForm>(BLANK);
  const [confirm, setConfirm] = useState<RadioOp | null>(null);

  const LIST_KEY = ['unifi', 'radios', controllerId, site] as const;

  const query = useQuery({
    queryKey: LIST_KEY,
    queryFn: () => fetchRadios(controllerId, site),
    enabled: isActive && !!controllerId,
    refetchInterval: 60_000,
  });

  const stageMut = useMutation({
    mutationFn: async (op: RadioOp) => {
      const payload: Record<string, unknown> = { site, radio: op.radio };
      if (op.channel.trim()) {
        const n = parseInt(op.channel.trim(), 10);
        payload.channel = Number.isNaN(n) ? op.channel.trim() : n;
      }
      if (op.tx_power_mode) payload.tx_power_mode = op.tx_power_mode;
      if (op.tx_power.trim()) {
        const n = parseInt(op.tx_power.trim(), 10);
        if (!Number.isNaN(n)) payload.tx_power = n;
      }
      if (op.ht.trim()) {
        const n = parseInt(op.ht.trim(), 10);
        if (!Number.isNaN(n)) payload.ht = n;
      }
      return stageRadioChange(controllerId, op.mac, payload);
    },
    onSuccess: (_data, vars) => {
      toast({
        title: t('UniFiRadiosTab.toast.staged.title'),
        description: `${vars.mac} · ${vars.radio}`,
      });
      setConfirm(null);
      queryClient.invalidateQueries({ queryKey: LIST_KEY });
    },
    onError: (err: unknown) => {
      toast({
        title: t('UniFiRadiosTab.toast.stageFailed.title'),
        description: getApiErrorMessage(err),
        variant: 'destructive',
      });
    },
  });

  const devices = query.data?.data?.items ?? [];
  const canStage = form.mac.trim().length > 0;

  return (
    <Card>
      <CardHeader className="flex flex-row items-start justify-between">
        <div>
          <CardTitle className="flex items-center gap-2">
            <RadioTower className="h-4 w-4" /> {t('UniFiRadiosTab.title')}
            <Badge variant="default">{devices.length}</Badge>
          </CardTitle>
          <p className="text-sm text-muted-foreground mt-1">
            {t('UniFiRadiosTab.siteLabel')}{' '}
            <code className="font-mono">{site}</code> ·{' '}
            {t('UniFiRadiosTab.description')}
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
        {/* Stage radio-update form. Set the AP MAC + band, then any of
            channel / TX power / width; blank fields are omitted from the
            payload. */}
        <div className="border border-border rounded-lg p-3 space-y-3">
          <Label className="text-sm font-medium">
            {t('UniFiRadiosTab.form.stageUpdate')}
          </Label>
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1">
              <Label htmlFor="radio-mac" className="text-xs">
                {t('UniFiRadiosTab.fields.mac')}
              </Label>
              <Input
                id="radio-mac"
                placeholder="aa:bb:cc:dd:ee:ff"
                value={form.mac}
                onChange={(e) =>
                  setForm((f) => ({ ...f, mac: e.target.value }))
                }
                className="font-mono text-sm"
              />
            </div>
            <div className="space-y-1">
              <Label className="text-xs">{t('UniFiRadiosTab.fields.band')}</Label>
              <Select
                value={form.radio}
                onValueChange={(v) => setForm((f) => ({ ...f, radio: v }))}
              >
                <SelectTrigger className="text-sm">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="ng">
                    {t('UniFiRadiosTab.bands.ng')}
                  </SelectItem>
                  <SelectItem value="na">
                    {t('UniFiRadiosTab.bands.na')}
                  </SelectItem>
                  <SelectItem value="6e">
                    {t('UniFiRadiosTab.bands.6e')}
                  </SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1">
              <Label htmlFor="radio-channel" className="text-xs">
                {t('UniFiRadiosTab.fields.channel')}
              </Label>
              <Input
                id="radio-channel"
                placeholder={t('UniFiRadiosTab.fields.channelPlaceholder')}
                value={form.channel}
                onChange={(e) =>
                  setForm((f) => ({ ...f, channel: e.target.value }))
                }
                className="text-sm"
              />
            </div>
            <div className="space-y-1">
              <Label className="text-xs">
                {t('UniFiRadiosTab.fields.width')}
              </Label>
              <Select
                value={form.ht || 'unset'}
                onValueChange={(v) =>
                  setForm((f) => ({ ...f, ht: v === 'unset' ? '' : v }))
                }
              >
                <SelectTrigger className="text-sm">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="unset">
                    {t('UniFiRadiosTab.fields.unset')}
                  </SelectItem>
                  <SelectItem value="20">20</SelectItem>
                  <SelectItem value="40">40</SelectItem>
                  <SelectItem value="80">80</SelectItem>
                  <SelectItem value="160">160</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1">
              <Label className="text-xs">
                {t('UniFiRadiosTab.fields.txPowerMode')}
              </Label>
              <Select
                value={form.tx_power_mode || 'unset'}
                onValueChange={(v) =>
                  setForm((f) => ({
                    ...f,
                    tx_power_mode: v === 'unset' ? '' : v,
                  }))
                }
              >
                <SelectTrigger className="text-sm">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="unset">
                    {t('UniFiRadiosTab.fields.unset')}
                  </SelectItem>
                  <SelectItem value="auto">auto</SelectItem>
                  <SelectItem value="high">high</SelectItem>
                  <SelectItem value="medium">medium</SelectItem>
                  <SelectItem value="low">low</SelectItem>
                  <SelectItem value="custom">custom</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1">
              <Label htmlFor="radio-txpower" className="text-xs">
                {t('UniFiRadiosTab.fields.txPower')}
              </Label>
              <Input
                id="radio-txpower"
                type="number"
                placeholder={t('UniFiRadiosTab.fields.txPowerPlaceholder')}
                value={form.tx_power}
                onChange={(e) =>
                  setForm((f) => ({ ...f, tx_power: e.target.value }))
                }
                className="text-sm"
              />
            </div>
          </div>
          <div className="flex justify-end pt-2 border-t border-border">
            <Button
              size="sm"
              onClick={() => setConfirm({ ...form })}
              disabled={!canStage}
            >
              <RadioTower className="h-4 w-4 mr-1" />{' '}
              {t('UniFiRadiosTab.actions.stageUpdate')}
            </Button>
          </div>
        </div>

        {query.isError && (
          <div className="rounded-md bg-destructive/10 border border-destructive p-3 text-sm text-destructive">
            {t('UniFiRadiosTab.loadError')}{' '}
            {(query.error as Error)?.message ||
              t('UniFiRadiosTab.unknownError')}
          </div>
        )}

        {query.isLoading ? (
          <div className="flex items-center justify-center py-8 text-muted-foreground">
            <Loader2 className="h-4 w-4 animate-spin mr-2" />{' '}
            {t('UniFiRadiosTab.loading')}
          </div>
        ) : devices.length === 0 ? (
          <div className="text-center py-8 text-sm text-muted-foreground">
            {t('UniFiRadiosTab.empty')}
          </div>
        ) : (
          <ul className="space-y-2">
            {devices.map((d) => {
              const label = d.name || d.mac;
              return (
                <li
                  key={d.mac}
                  className="border border-border rounded-lg p-3 space-y-2"
                >
                  <div className="flex items-center justify-between">
                    <div className="space-y-1 min-w-0">
                      <div className="text-sm font-medium">{label}</div>
                      <div className="text-xs text-muted-foreground font-mono">
                        {d.mac}
                        {d.model ? ` · ${d.model}` : ''}
                        {d.ip ? ` · ${d.ip}` : ''}
                      </div>
                    </div>
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => setForm((f) => ({ ...f, mac: d.mac }))}
                      disabled={stageMut.isPending}
                    >
                      {t('UniFiRadiosTab.actions.select')}
                    </Button>
                  </div>
                  {(d.radio_table ?? []).length > 0 ? (
                    <div className="flex flex-wrap gap-1">
                      {(d.radio_table ?? []).map((r, i) => (
                        <Badge key={r.radio || i} variant="secondary">
                          {r.radio || '?'}
                          {r.channel != null ? ` · ch ${r.channel}` : ''}
                          {r.ht != null ? ` · ${r.ht}MHz` : ''}
                          {r.tx_power_mode ? ` · ${r.tx_power_mode}` : ''}
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
              {t('UniFiRadiosTab.dialog.title')}
            </AlertDialogTitle>
            <AlertDialogDescription>
              {t('UniFiRadiosTab.dialog.stagePrefix')}{' '}
              <code className="font-mono">unifi.radios.update</code>{' '}
              {t('UniFiRadiosTab.dialog.against')}{' '}
              <code className="font-mono">{confirm?.mac}</code> (
              <code className="font-mono">{confirm?.radio}</code>)
              {t('UniFiRadiosTab.dialog.suffix')}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>
              {t('UniFiRadiosTab.actions.cancel')}
            </AlertDialogCancel>
            <AlertDialogAction
              onClick={() => confirm && stageMut.mutate(confirm)}
              disabled={stageMut.isPending}
            >
              {t('UniFiRadiosTab.actions.stage')}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </Card>
  );
}

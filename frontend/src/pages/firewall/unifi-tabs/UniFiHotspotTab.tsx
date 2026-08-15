// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN, UniFi Hotspot tab (guest portal)
 *
 * Stages guest-portal writes against gateway-unifi-hotspot — matching the Omada
 * hotspot capability:
 *   • VOUCHERS  — time/quota-limited guest access codes (create / revoke)
 *   • OPERATORS — portal-admin accounts (create / delete)
 * Writes never touch the controller directly; they land as pending rows the
 * operator applies via the Pending Changes drawer. A revoke/delete is gated by
 * the apply-time confirm (any UniFi delete is catastrophic per the preflight).
 */
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Loader2, Plus, RefreshCw, Ticket, Trash2 } from 'lucide-react';
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

type HotspotKind = 'voucher' | 'operator';

interface HotspotRow {
  _id: string;
  // voucher
  code?: string;
  note?: string;
  quota?: number;
  duration?: number;
  // operator
  name?: string;
}

interface HotspotResponse {
  controller_id: string;
  site: string;
  items: HotspotRow[];
  fetched_at: string;
}

async function fetchHotspot(controllerId: string, site: string, kind: HotspotKind) {
  const path = kind === 'voucher' ? 'vouchers' : 'operators';
  return api.get<HotspotResponse>(
    `/gateway-unifi-hotspot/${enc(controllerId)}/sites/${enc(site)}/${path}`,
  );
}

async function stageHotspotChange(
  controllerId: string,
  feature: string,
  operation: 'create' | 'delete',
  payload: Record<string, unknown>,
  targetId?: string,
) {
  return api.post(
    `/gateway-unifi-hotspot/${enc(controllerId)}/changes/${enc(feature)}`,
    targetId ? { payload, target_id: targetId } : { payload },
    { params: { operation } },
  );
}

interface VoucherForm {
  count: string;
  expire_minutes: string;
  quota: string;
  note: string;
}

const BLANK_VOUCHER: VoucherForm = { count: '1', expire_minutes: '480', quota: '1', note: '' };

type HotspotOp =
  | { kind: 'create-voucher'; form: VoucherForm }
  | { kind: 'create-operator'; name: string; password: string }
  | { kind: 'delete'; recordKind: HotspotKind; targetId: string; label: string };

interface Props {
  controllerId: string;
  site: string;
  isActive: boolean;
}

export function UniFiHotspotTab({ controllerId, site, isActive }: Props) {
  const { t } = useTranslation('firewall');
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const [recordKind, setRecordKind] = useState<HotspotKind>('voucher');
  const [voucher, setVoucher] = useState<VoucherForm>(BLANK_VOUCHER);
  const [opName, setOpName] = useState('');
  const [opPass, setOpPass] = useState('');
  const [confirm, setConfirm] = useState<HotspotOp | null>(null);

  const LIST_KEY = ['unifi', 'hotspot', controllerId, site, recordKind] as const;

  const query = useQuery({
    queryKey: LIST_KEY,
    queryFn: () => fetchHotspot(controllerId, site, recordKind),
    enabled: isActive && !!controllerId,
    refetchInterval: 60_000,
  });

  const stageMut = useMutation({
    mutationFn: async (op: HotspotOp) => {
      if (op.kind === 'create-voucher') {
        return stageHotspotChange(controllerId, 'unifi.hotspot.create_voucher', 'create', {
          site,
          count: Number(op.form.count) || 1,
          expire_minutes: Number(op.form.expire_minutes) || 480,
          quota: Number(op.form.quota) || 1,
          note: op.form.note.trim() || undefined,
        });
      }
      if (op.kind === 'create-operator') {
        return stageHotspotChange(controllerId, 'unifi.hotspot.create_operator', 'create', {
          site,
          name: op.name.trim(),
          x_password: op.password,
        });
      }
      const feature =
        op.recordKind === 'voucher'
          ? 'unifi.hotspot.revoke_voucher'
          : 'unifi.hotspot.delete_operator';
      return stageHotspotChange(controllerId, feature, 'delete', { site }, op.targetId);
    },
    onSuccess: (_data, vars) => {
      toast({
        title:
          vars.kind === 'delete'
            ? t('UniFiHotspotTab.toast.deleted.title')
            : t('UniFiHotspotTab.toast.created.title'),
      });
      setConfirm(null);
      if (vars.kind === 'create-voucher') setVoucher(BLANK_VOUCHER);
      if (vars.kind === 'create-operator') {
        setOpName('');
        setOpPass('');
      }
      queryClient.invalidateQueries({ queryKey: LIST_KEY });
    },
    onError: (err: unknown) => {
      toast({
        title: t('UniFiHotspotTab.toast.stageFailed.title'),
        description: getApiErrorMessage(err),
        variant: 'destructive',
      });
    },
  });

  const rows = query.data?.data?.items ?? [];
  const canStageOperator = opName.trim().length > 0 && opPass.length > 0;

  return (
    <Card>
      <CardHeader className="flex flex-row items-start justify-between">
        <div>
          <CardTitle className="flex items-center gap-2">
            <Ticket className="h-4 w-4" /> {t('UniFiHotspotTab.title')}
            <Badge variant="default">{rows.length}</Badge>
          </CardTitle>
          <p className="text-sm text-muted-foreground mt-1">
            {t('UniFiHotspotTab.siteLabel')}{' '}
            <code className="font-mono">{site}</code> ·{' '}
            {t('UniFiHotspotTab.description')}
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
        <div className="flex items-center gap-2">
          <Label className="text-xs">{t('UniFiHotspotTab.fields.kind')}</Label>
          <Select value={recordKind} onValueChange={(v) => setRecordKind(v as HotspotKind)}>
            <SelectTrigger className="w-44 text-sm">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="voucher">{t('UniFiHotspotTab.kinds.voucher')}</SelectItem>
              <SelectItem value="operator">{t('UniFiHotspotTab.kinds.operator')}</SelectItem>
            </SelectContent>
          </Select>
        </div>

        {/* Create form (per kind) */}
        {recordKind === 'voucher' ? (
          <div className="border border-border rounded-lg p-3 space-y-3">
            <Label className="text-sm font-medium">
              {t('UniFiHotspotTab.form.createVoucher')}
            </Label>
            <div className="grid grid-cols-3 gap-3">
              <div className="space-y-1">
                <Label htmlFor="hs-count" className="text-xs">
                  {t('UniFiHotspotTab.fields.count')}
                </Label>
                <Input
                  id="hs-count"
                  type="number"
                  min={1}
                  value={voucher.count}
                  onChange={(e) => setVoucher((f) => ({ ...f, count: e.target.value }))}
                  className="text-sm"
                />
              </div>
              <div className="space-y-1">
                <Label htmlFor="hs-expire" className="text-xs">
                  {t('UniFiHotspotTab.fields.expireMinutes')}
                </Label>
                <Input
                  id="hs-expire"
                  type="number"
                  min={1}
                  value={voucher.expire_minutes}
                  onChange={(e) =>
                    setVoucher((f) => ({ ...f, expire_minutes: e.target.value }))
                  }
                  className="text-sm"
                />
              </div>
              <div className="space-y-1">
                <Label htmlFor="hs-quota" className="text-xs">
                  {t('UniFiHotspotTab.fields.quota')}
                </Label>
                <Input
                  id="hs-quota"
                  type="number"
                  min={1}
                  value={voucher.quota}
                  onChange={(e) => setVoucher((f) => ({ ...f, quota: e.target.value }))}
                  className="text-sm"
                />
              </div>
            </div>
            <div className="space-y-1">
              <Label htmlFor="hs-note" className="text-xs">
                {t('UniFiHotspotTab.fields.note')}
              </Label>
              <Input
                id="hs-note"
                placeholder={t('UniFiHotspotTab.fields.notePlaceholder')}
                value={voucher.note}
                onChange={(e) => setVoucher((f) => ({ ...f, note: e.target.value }))}
                className="text-sm"
              />
            </div>
            <div className="flex justify-end pt-2 border-t border-border">
              <Button
                size="sm"
                onClick={() => setConfirm({ kind: 'create-voucher', form: voucher })}
              >
                <Plus className="h-4 w-4 mr-1" /> {t('UniFiHotspotTab.actions.stageVoucher')}
              </Button>
            </div>
          </div>
        ) : (
          <div className="border border-border rounded-lg p-3 space-y-3">
            <Label className="text-sm font-medium">
              {t('UniFiHotspotTab.form.createOperator')}
            </Label>
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1">
                <Label htmlFor="hs-op-name" className="text-xs">
                  {t('UniFiHotspotTab.fields.name')}
                </Label>
                <Input
                  id="hs-op-name"
                  value={opName}
                  onChange={(e) => setOpName(e.target.value)}
                  className="font-mono text-sm"
                  autoComplete="off"
                />
              </div>
              <div className="space-y-1">
                <Label htmlFor="hs-op-pass" className="text-xs">
                  {t('UniFiHotspotTab.fields.password')}
                </Label>
                <Input
                  id="hs-op-pass"
                  type="password"
                  value={opPass}
                  onChange={(e) => setOpPass(e.target.value)}
                  className="font-mono text-sm"
                  autoComplete="new-password"
                />
              </div>
            </div>
            <div className="flex justify-end pt-2 border-t border-border">
              <Button
                size="sm"
                onClick={() => setConfirm({ kind: 'create-operator', name: opName, password: opPass })}
                disabled={!canStageOperator}
              >
                <Plus className="h-4 w-4 mr-1" /> {t('UniFiHotspotTab.actions.stageOperator')}
              </Button>
            </div>
          </div>
        )}

        {query.isError && (
          <div className="rounded-md bg-destructive/10 border border-destructive p-3 text-sm text-destructive">
            {t('UniFiHotspotTab.loadError')}{' '}
            {(query.error as Error)?.message || t('UniFiHotspotTab.unknownError')}
          </div>
        )}

        {query.isLoading ? (
          <div className="flex items-center justify-center py-8 text-muted-foreground">
            <Loader2 className="h-4 w-4 animate-spin mr-2" /> {t('UniFiHotspotTab.loading')}
          </div>
        ) : rows.length === 0 ? (
          <div className="text-center py-8 text-sm text-muted-foreground">
            {t('UniFiHotspotTab.empty')}
          </div>
        ) : (
          <ul className="space-y-2">
            {rows.map((r) => {
              const label =
                recordKind === 'voucher' ? r.code || r.note || r._id : r.name || r._id;
              return (
                <li
                  key={r._id}
                  className="flex items-center justify-between border border-border rounded-lg p-3"
                >
                  <div className="space-y-1 min-w-0">
                    <div className="text-sm font-medium font-mono">{label}</div>
                    <div className="text-xs text-muted-foreground">
                      {recordKind === 'voucher'
                        ? [
                            r.note && r.note !== r.code ? r.note : null,
                            r.quota ? `${t('UniFiHotspotTab.fields.quota')}: ${r.quota}` : null,
                          ]
                            .filter(Boolean)
                            .join(' · ')
                        : r._id}
                    </div>
                  </div>
                  <Button
                    size="sm"
                    variant="ghost"
                    onClick={() =>
                      setConfirm({ kind: 'delete', recordKind, targetId: r._id, label })
                    }
                    disabled={stageMut.isPending}
                    className="text-destructive hover:bg-destructive/10"
                  >
                    <Trash2 className="h-4 w-4" />
                  </Button>
                </li>
              );
            })}
          </ul>
        )}
      </CardContent>

      <AlertDialog open={!!confirm} onOpenChange={(open) => !open && setConfirm(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>
              {confirm?.kind === 'delete'
                ? t('UniFiHotspotTab.dialog.deleteTitle')
                : t('UniFiHotspotTab.dialog.createTitle')}
            </AlertDialogTitle>
            <AlertDialogDescription>
              {confirm?.kind === 'delete'
                ? t('UniFiHotspotTab.dialog.deleteBody', { label: confirm.label })
                : t('UniFiHotspotTab.dialog.createBody')}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t('UniFiHotspotTab.actions.cancel')}</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => confirm && stageMut.mutate(confirm)}
              disabled={stageMut.isPending}
            >
              {t('UniFiHotspotTab.actions.stage')}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </Card>
  );
}

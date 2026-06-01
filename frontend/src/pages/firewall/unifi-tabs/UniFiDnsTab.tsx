// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN, UniFi DNS tab
 *
 * Stages static + dynamic DNS record create / update / delete against
 * gateway-unifi-dns. Lists the current records for context. Like the
 * other UniFi domain tabs, writes never touch the controller directly,
 * they land as pending rows that the operator applies via the Pending
 * Changes drawer (POST /gateway-unifi-dns/{cid}/changes/...).
 */
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Globe, Loader2, Plus, RefreshCw, Trash2 } from 'lucide-react';
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

type DnsKind = 'static' | 'dynamic';

interface UniFiDnsRecord {
  _id: string;
  key?: string; // hostname / record name
  value?: string; // ip / target
  record_type?: string; // A / AAAA / CNAME / TXT …
  enabled?: boolean;
  // dynamic-DNS specific
  host_name?: string;
  service?: string;
  interface?: string;
}

interface UniFiDnsResponse {
  controller_id: string;
  site: string;
  items: UniFiDnsRecord[];
  fetched_at: string;
}

async function fetchDns(controllerId: string, site: string, kind: DnsKind) {
  return api.get<UniFiDnsResponse>(
    `/gateway-unifi-dns/${enc(controllerId)}/sites/${enc(site)}/${enc(kind)}`,
  );
}

async function stageDnsChange(
  controllerId: string,
  feature: string,
  operation: 'create' | 'update' | 'delete',
  payload: Record<string, unknown>,
  targetId?: string,
) {
  return api.post(
    `/gateway-unifi-dns/${enc(controllerId)}/changes/${enc(feature)}`,
    targetId ? { payload, target_id: targetId } : { payload },
    { params: { operation } },
  );
}

interface CreateForm {
  name: string;
  value: string;
  record_type: string;
}

const BLANK: CreateForm = {
  name: '',
  value: '',
  record_type: 'A',
};

type DnsOp =
  | { kind: 'create'; recordKind: DnsKind; form: CreateForm }
  | { kind: 'delete'; recordKind: DnsKind; targetId: string; label: string };

interface UniFiDnsTabProps {
  controllerId: string;
  site: string;
  isActive: boolean;
}

export function UniFiDnsTab({
  controllerId,
  site,
  isActive,
}: UniFiDnsTabProps) {
  const { t } = useTranslation('firewall');
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const [recordKind, setRecordKind] = useState<DnsKind>('static');
  const [form, setForm] = useState<CreateForm>(BLANK);
  const [confirm, setConfirm] = useState<DnsOp | null>(null);

  const LIST_KEY = ['unifi', 'dns', controllerId, site, recordKind] as const;

  const query = useQuery({
    queryKey: LIST_KEY,
    queryFn: () => fetchDns(controllerId, site, recordKind),
    enabled: isActive && !!controllerId,
    refetchInterval: 60_000,
  });

  const stageMut = useMutation({
    mutationFn: async (op: DnsOp) => {
      if (op.kind === 'create') {
        const feature =
          op.recordKind === 'static'
            ? 'unifi.dns.create_static'
            : 'unifi.dns.create_dynamic';
        // Field names are the controller's wire schema (the adapter posts the
        // payload verbatim to /static-dns). A static record is keyed by ``key``
        // (the hostname) — NOT ``name``, which the controller silently ignores,
        // creating an empty-hostname record. A dynamic-DNS config is keyed by
        // ``host_name``. (Validated live: static {enabled,key,record_type,value}.)
        const payload: Record<string, unknown> =
          op.recordKind === 'static'
            ? {
                site,
                enabled: true,
                key: op.form.name.trim(),
                record_type: op.form.record_type,
                value: op.form.value.trim(),
              }
            : {
                site,
                host_name: op.form.name.trim(),
                value: op.form.value.trim(),
              };
        return stageDnsChange(controllerId, feature, 'create', payload);
      }
      // delete
      const feature =
        op.recordKind === 'static'
          ? 'unifi.dns.delete_static'
          : 'unifi.dns.delete_dynamic';
      return stageDnsChange(
        controllerId,
        feature,
        'delete',
        { site },
        op.targetId,
      );
    },
    onSuccess: (_data, vars) => {
      toast({
        title:
          vars.kind === 'create'
            ? t('UniFiDnsTab.toast.created.title')
            : t('UniFiDnsTab.toast.deleted.title'),
        description:
          vars.kind === 'create' ? vars.form.name : vars.label,
      });
      setConfirm(null);
      if (vars.kind === 'create') setForm(BLANK);
      // The global MutationCache subscriber invalidates the
      // cross-cutting ['pending-changes'] key, so the drawer + badge
      // refresh automatically; we just refresh this tab's list.
      queryClient.invalidateQueries({ queryKey: LIST_KEY });
    },
    onError: (err: unknown) => {
      toast({
        title: t('UniFiDnsTab.toast.stageFailed.title'),
        description: getApiErrorMessage(err),
        variant: 'destructive',
      });
    },
  });

  const records = query.data?.data?.items ?? [];
  const canStage =
    form.name.trim().length > 0 && form.value.trim().length > 0;

  return (
    <Card>
      <CardHeader className="flex flex-row items-start justify-between">
        <div>
          <CardTitle className="flex items-center gap-2">
            <Globe className="h-4 w-4" /> {t('UniFiDnsTab.title')}
            <Badge variant="default">{records.length}</Badge>
          </CardTitle>
          <p className="text-sm text-muted-foreground mt-1">
            {t('UniFiDnsTab.siteLabel')}{' '}
            <code className="font-mono">{site}</code> ·{' '}
            {t('UniFiDnsTab.description')}
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
        {/* Record-kind selector */}
        <div className="flex items-center gap-2">
          <Label className="text-xs">{t('UniFiDnsTab.fields.recordKind')}</Label>
          <Select
            value={recordKind}
            onValueChange={(v) => setRecordKind(v as DnsKind)}
          >
            <SelectTrigger className="w-40 text-sm">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="static">
                {t('UniFiDnsTab.kinds.static')}
              </SelectItem>
              <SelectItem value="dynamic">
                {t('UniFiDnsTab.kinds.dynamic')}
              </SelectItem>
            </SelectContent>
          </Select>
        </div>

        {/* Stage create form */}
        <div className="border border-border rounded-lg p-3 space-y-3">
          <Label className="text-sm font-medium">
            {recordKind === 'static'
              ? t('UniFiDnsTab.form.createStatic')
              : t('UniFiDnsTab.form.createDynamic')}
          </Label>
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1">
              <Label htmlFor="dns-name" className="text-xs">
                {t('UniFiDnsTab.fields.name')}
              </Label>
              <Input
                id="dns-name"
                placeholder={t('UniFiDnsTab.fields.namePlaceholder')}
                value={form.name}
                onChange={(e) =>
                  setForm((f) => ({ ...f, name: e.target.value }))
                }
                className="font-mono text-sm"
              />
            </div>
            <div className="space-y-1">
              <Label htmlFor="dns-value" className="text-xs">
                {t('UniFiDnsTab.fields.value')}
              </Label>
              <Input
                id="dns-value"
                placeholder={t('UniFiDnsTab.fields.valuePlaceholder')}
                value={form.value}
                onChange={(e) =>
                  setForm((f) => ({ ...f, value: e.target.value }))
                }
                className="font-mono text-sm"
              />
            </div>
          </div>
          {recordKind === 'static' ? (
            <div className="space-y-1">
              <Label className="text-xs">
                {t('UniFiDnsTab.fields.recordType')}
              </Label>
              <Select
                value={form.record_type}
                onValueChange={(v) =>
                  setForm((f) => ({ ...f, record_type: v }))
                }
              >
                <SelectTrigger className="text-sm">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="A">A</SelectItem>
                  <SelectItem value="AAAA">AAAA</SelectItem>
                  <SelectItem value="CNAME">CNAME</SelectItem>
                  <SelectItem value="TXT">TXT</SelectItem>
                  <SelectItem value="MX">MX</SelectItem>
                  <SelectItem value="SRV">SRV</SelectItem>
                </SelectContent>
              </Select>
            </div>
          ) : null}
          <div className="flex justify-end pt-2 border-t border-border">
            <Button
              size="sm"
              onClick={() =>
                setConfirm({ kind: 'create', recordKind, form })
              }
              disabled={!canStage}
            >
              <Plus className="h-4 w-4 mr-1" />{' '}
              {t('UniFiDnsTab.actions.stageCreate')}
            </Button>
          </div>
        </div>

        {query.isError && (
          <div className="rounded-md bg-destructive/10 border border-destructive p-3 text-sm text-destructive">
            {t('UniFiDnsTab.loadError')}{' '}
            {(query.error as Error)?.message ||
              t('UniFiDnsTab.unknownError')}
          </div>
        )}

        {query.isLoading ? (
          <div className="flex items-center justify-center py-8 text-muted-foreground">
            <Loader2 className="h-4 w-4 animate-spin mr-2" />{' '}
            {t('UniFiDnsTab.loading')}
          </div>
        ) : records.length === 0 ? (
          <div className="text-center py-8 text-sm text-muted-foreground">
            {t('UniFiDnsTab.empty')}
          </div>
        ) : (
          <ul className="space-y-2">
            {records.map((r) => {
              const label = r.key || r.host_name || r._id;
              return (
                <li
                  key={r._id}
                  className="flex items-center justify-between border border-border rounded-lg p-3"
                >
                  <div className="space-y-1 min-w-0">
                    <div className="text-sm font-medium">{label}</div>
                    <div className="text-xs text-muted-foreground font-mono">
                      {r._id}
                      {r.record_type ? ` · ${r.record_type}` : ''}
                      {r.value ? ` · ${r.value}` : ''}
                      {r.service ? ` · ${r.service}` : ''}
                      {r.enabled === false
                        ? ` · ${t('UniFiDnsTab.status.disabled')}`
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
                          recordKind,
                          targetId: r._id,
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
                ? t('UniFiDnsTab.dialog.deleteTitle')
                : t('UniFiDnsTab.dialog.createTitle')}
            </AlertDialogTitle>
            <AlertDialogDescription>
              {t('UniFiDnsTab.dialog.stagePrefix')}{' '}
              <code className="font-mono">
                unifi.dns.
                {confirm?.kind === 'delete' ? 'delete' : 'create'}_
                {confirm?.recordKind}
              </code>{' '}
              {t('UniFiDnsTab.dialog.against')}{' '}
              <code className="font-mono">
                {confirm?.kind === 'delete'
                  ? confirm.label
                  : confirm?.form.name}
              </code>
              {t('UniFiDnsTab.dialog.suffix')}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>
              {t('UniFiDnsTab.actions.cancel')}
            </AlertDialogCancel>
            <AlertDialogAction
              onClick={() => confirm && stageMut.mutate(confirm)}
              disabled={stageMut.isPending}
            >
              {t('UniFiDnsTab.actions.stage')}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </Card>
  );
}

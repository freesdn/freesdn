// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN, UniFi Firewall tab
 *
 * Stages firewall create / delete against gateway-unifi-firewall across
 * the modern zone-based policy model (policies, zones, NAT, groups) and
 * the classic rule model (rules). The zone matrix is read-only, it shows
 * the allow/deny grid between zones for context (no create feature).
 *
 * Like every UniFi domain tab, writes never touch the controller
 * directly, they land as pending rows the operator applies via the
 * Pending Changes drawer (POST /gateway-unifi-firewall/{cid}/changes/...).
 */
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Loader2, Plus, RefreshCw, Shield, Trash2 } from 'lucide-react';
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

// Writable resource kinds map to a URL segment + a singular feature
// noun (``create_<noun>`` / ``delete_<noun>``). ``zone-matrix`` is
// read-only and handled separately, it has no create feature.
type FirewallKind = 'policies' | 'zones' | 'nat' | 'groups' | 'rules';
type FirewallView = FirewallKind | 'zone-matrix';

const FEATURE_NOUN: Record<FirewallKind, string> = {
  policies: 'policy',
  zones: 'zone',
  nat: 'nat',
  groups: 'group',
  rules: 'rule',
};

interface UniFiFirewallEntry {
  _id: string;
  name?: string;
  description?: string;
  enabled?: boolean;
  action?: string;
  ruleset?: string;
  protocol?: string;
  // zone-specific
  zone_key?: string;
  // group-specific
  group_type?: string;
  group_members?: string[];
}

interface UniFiFirewallResponse {
  controller_id: string;
  site: string;
  items: UniFiFirewallEntry[];
  fetched_at: string;
}

// The zone matrix is a grid keyed by source → destination zone with an
// allow/deny verdict per cell. The exact shape is adapter-defined; we
// render it defensively as a list of source-zone rows.
interface UniFiZoneMatrixCell {
  to_zone?: string;
  to_zone_id?: string;
  action?: string;
  allowed?: boolean;
}
interface UniFiZoneMatrixRow {
  zone?: string;
  zone_id?: string;
  cells?: UniFiZoneMatrixCell[];
}
interface UniFiZoneMatrixResponse {
  controller_id: string;
  site: string;
  items: UniFiZoneMatrixRow[];
  fetched_at: string;
}

async function fetchFirewall(
  controllerId: string,
  site: string,
  kind: FirewallKind,
) {
  return api.get<UniFiFirewallResponse>(
    `/gateway-unifi-firewall/${enc(controllerId)}/sites/${enc(site)}/${enc(kind)}`,
  );
}

async function fetchZoneMatrix(controllerId: string, site: string) {
  return api.get<UniFiZoneMatrixResponse>(
    `/gateway-unifi-firewall/${enc(controllerId)}/sites/${enc(site)}/zone-matrix`,
  );
}

async function stageFirewallChange(
  controllerId: string,
  feature: string,
  operation: 'create' | 'update' | 'delete',
  payload: Record<string, unknown>,
  targetId?: string,
) {
  return api.post(
    `/gateway-unifi-firewall/${enc(controllerId)}/changes/${enc(feature)}`,
    targetId ? { payload, target_id: targetId } : { payload },
    { params: { operation } },
  );
}

type FirewallOp =
  | { kind: 'create'; resource: FirewallKind; name: string }
  | { kind: 'delete'; resource: FirewallKind; targetId: string; label: string };

interface UniFiFirewallTabProps {
  controllerId: string;
  site: string;
  isActive: boolean;
}

export function UniFiFirewallTab({
  controllerId,
  site,
  isActive,
}: UniFiFirewallTabProps) {
  const { t } = useTranslation('firewall');
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const [view, setView] = useState<FirewallView>('policies');
  const [name, setName] = useState('');
  const [confirm, setConfirm] = useState<FirewallOp | null>(null);

  const isMatrix = view === 'zone-matrix';
  const resource = (isMatrix ? 'policies' : view) as FirewallKind;

  const LIST_KEY = ['unifi', 'firewall', controllerId, site, view] as const;

  const listQuery = useQuery({
    queryKey: LIST_KEY,
    queryFn: () => fetchFirewall(controllerId, site, resource),
    enabled: isActive && !!controllerId && !isMatrix,
    refetchInterval: 60_000,
  });

  const matrixQuery = useQuery({
    queryKey: ['unifi', 'firewall', controllerId, site, 'zone-matrix'] as const,
    queryFn: () => fetchZoneMatrix(controllerId, site),
    enabled: isActive && !!controllerId && isMatrix,
    refetchInterval: 60_000,
  });

  const activeQuery = isMatrix ? matrixQuery : listQuery;

  const stageMut = useMutation({
    mutationFn: async (op: FirewallOp) => {
      const noun = FEATURE_NOUN[op.resource];
      if (op.kind === 'create') {
        const feature = `unifi.firewall.create_${noun}`;
        return stageFirewallChange(controllerId, feature, 'create', {
          site,
          name: op.name.trim(),
        });
      }
      const feature = `unifi.firewall.delete_${noun}`;
      return stageFirewallChange(
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
            ? t('UniFiFirewallTab.toast.created.title')
            : t('UniFiFirewallTab.toast.deleted.title'),
        description: vars.kind === 'create' ? vars.name : vars.label,
      });
      setConfirm(null);
      if (vars.kind === 'create') setName('');
      queryClient.invalidateQueries({ queryKey: LIST_KEY });
    },
    onError: (err: unknown) => {
      toast({
        title: t('UniFiFirewallTab.toast.stageFailed.title'),
        description: getApiErrorMessage(err),
        variant: 'destructive',
      });
    },
  });

  const entries = listQuery.data?.data?.items ?? [];
  const matrixRows = matrixQuery.data?.data?.items ?? [];
  const count = isMatrix ? matrixRows.length : entries.length;
  const canStage = name.trim().length > 0;

  return (
    <Card>
      <CardHeader className="flex flex-row items-start justify-between">
        <div>
          <CardTitle className="flex items-center gap-2">
            <Shield className="h-4 w-4" /> {t('UniFiFirewallTab.title')}
            <Badge variant="default">{count}</Badge>
          </CardTitle>
          <p className="text-sm text-muted-foreground mt-1">
            {t('UniFiFirewallTab.siteLabel')}{' '}
            <code className="font-mono">{site}</code> ·{' '}
            {t('UniFiFirewallTab.description')}
          </p>
        </div>
        <Button
          variant="outline"
          size="sm"
          onClick={() => activeQuery.refetch()}
          disabled={activeQuery.isFetching}
        >
          {activeQuery.isFetching ? (
            <Loader2 className="h-4 w-4 animate-spin" />
          ) : (
            <RefreshCw className="h-4 w-4" />
          )}
        </Button>
      </CardHeader>

      <CardContent className="space-y-4">
        {/* Resource / view selector */}
        <div className="flex items-center gap-2">
          <Label className="text-xs">{t('UniFiFirewallTab.fields.view')}</Label>
          <Select
            value={view}
            onValueChange={(v) => setView(v as FirewallView)}
          >
            <SelectTrigger className="w-48 text-sm">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="policies">
                {t('UniFiFirewallTab.views.policies')}
              </SelectItem>
              <SelectItem value="zones">
                {t('UniFiFirewallTab.views.zones')}
              </SelectItem>
              <SelectItem value="zone-matrix">
                {t('UniFiFirewallTab.views.zoneMatrix')}
              </SelectItem>
              <SelectItem value="nat">
                {t('UniFiFirewallTab.views.nat')}
              </SelectItem>
              <SelectItem value="groups">
                {t('UniFiFirewallTab.views.groups')}
              </SelectItem>
              <SelectItem value="rules">
                {t('UniFiFirewallTab.views.rules')}
              </SelectItem>
            </SelectContent>
          </Select>
        </div>

        {/* Stage create form (writable resources only; the zone matrix
            is read-only). Payload is minimal (name); operators refine
            in the drawer payload preview or via a follow-up update. */}
        {!isMatrix && (
          <div className="border border-border rounded-lg p-3 space-y-3">
            <Label className="text-sm font-medium">
              {t('UniFiFirewallTab.form.create', {
                resource: t(`UniFiFirewallTab.viewsSingular.${resource}`),
              })}
            </Label>
            <div className="flex items-end gap-2">
              <div className="flex-1 space-y-1">
                <Label htmlFor="fw-name" className="text-xs">
                  {t('UniFiFirewallTab.fields.name')}
                </Label>
                <Input
                  id="fw-name"
                  placeholder={t('UniFiFirewallTab.fields.namePlaceholder')}
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  className="text-sm"
                />
              </div>
              <Button
                size="sm"
                onClick={() =>
                  setConfirm({ kind: 'create', resource, name })
                }
                disabled={!canStage}
              >
                <Plus className="h-4 w-4 mr-1" />{' '}
                {t('UniFiFirewallTab.actions.stageCreate')}
              </Button>
            </div>
          </div>
        )}

        {activeQuery.isError && (
          <div className="rounded-md bg-destructive/10 border border-destructive p-3 text-sm text-destructive">
            {t('UniFiFirewallTab.loadError')}{' '}
            {(activeQuery.error as Error)?.message ||
              t('UniFiFirewallTab.unknownError')}
          </div>
        )}

        {activeQuery.isLoading ? (
          <div className="flex items-center justify-center py-8 text-muted-foreground">
            <Loader2 className="h-4 w-4 animate-spin mr-2" />{' '}
            {t('UniFiFirewallTab.loading')}
          </div>
        ) : isMatrix ? (
          matrixRows.length === 0 ? (
            <div className="text-center py-8 text-sm text-muted-foreground">
              {t('UniFiFirewallTab.matrixEmpty')}
            </div>
          ) : (
            <ul className="space-y-2">
              {matrixRows.map((row, i) => (
                <li
                  key={row.zone_id || row.zone || i}
                  className="border border-border rounded-lg p-3"
                >
                  <div className="text-sm font-medium">
                    {row.zone || row.zone_id || t('UniFiFirewallTab.unnamed')}
                  </div>
                  <div className="mt-1 flex flex-wrap gap-1">
                    {(row.cells ?? []).map((cell, j) => {
                      const allowed =
                        cell.allowed ?? cell.action === 'allow';
                      return (
                        <Badge
                          key={cell.to_zone_id || cell.to_zone || j}
                          variant={allowed ? 'success' : 'destructive'}
                        >
                          {cell.to_zone || cell.to_zone_id || '?'}
                          {': '}
                          {allowed
                            ? t('UniFiFirewallTab.matrix.allow')
                            : t('UniFiFirewallTab.matrix.deny')}
                        </Badge>
                      );
                    })}
                  </div>
                </li>
              ))}
            </ul>
          )
        ) : entries.length === 0 ? (
          <div className="text-center py-8 text-sm text-muted-foreground">
            {t('UniFiFirewallTab.empty')}
          </div>
        ) : (
          <ul className="space-y-2">
            {entries.map((e) => {
              const label = e.name || e.description || e._id;
              return (
                <li
                  key={e._id}
                  className="flex items-center justify-between border border-border rounded-lg p-3"
                >
                  <div className="space-y-1 min-w-0">
                    <div className="text-sm font-medium">{label}</div>
                    <div className="text-xs text-muted-foreground font-mono">
                      {e._id}
                      {e.action ? ` · ${e.action}` : ''}
                      {e.ruleset ? ` · ${e.ruleset}` : ''}
                      {e.protocol ? ` · ${e.protocol}` : ''}
                      {e.group_type ? ` · ${e.group_type}` : ''}
                      {e.enabled === false
                        ? ` · ${t('UniFiFirewallTab.status.disabled')}`
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
                          resource,
                          targetId: e._id,
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
                ? t('UniFiFirewallTab.dialog.deleteTitle')
                : t('UniFiFirewallTab.dialog.createTitle')}
            </AlertDialogTitle>
            <AlertDialogDescription>
              {t('UniFiFirewallTab.dialog.stagePrefix')}{' '}
              <code className="font-mono">
                unifi.firewall.
                {confirm?.kind === 'delete' ? 'delete' : 'create'}_
                {confirm ? FEATURE_NOUN[confirm.resource] : ''}
              </code>{' '}
              {t('UniFiFirewallTab.dialog.against')}{' '}
              <code className="font-mono">
                {confirm?.kind === 'delete' ? confirm.label : confirm?.name}
              </code>
              {t('UniFiFirewallTab.dialog.suffix')}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>
              {t('UniFiFirewallTab.actions.cancel')}
            </AlertDialogCancel>
            <AlertDialogAction
              onClick={() => confirm && stageMut.mutate(confirm)}
              disabled={stageMut.isPending}
            >
              {t('UniFiFirewallTab.actions.stage')}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </Card>
  );
}

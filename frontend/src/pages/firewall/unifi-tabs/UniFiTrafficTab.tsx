// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN, UniFi Traffic tab
 *
 * Stages traffic-management create / delete against gateway-unifi-traffic
 * across three resource kinds: traffic rules, traffic routes, and QoS
 * rules. Lists current entries for context. Writes never touch the
 * controller directly, they land as pending rows applied via the
 * Pending Changes drawer (POST /gateway-unifi-traffic/{cid}/changes/...).
 */
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Loader2, Plus, RefreshCw, Route, Trash2 } from 'lucide-react';
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

// Resource kind ↔ URL segment ↔ singular feature noun.
type TrafficKind = 'rules' | 'routes' | 'qos';

const FEATURE_NOUN: Record<TrafficKind, string> = {
  rules: 'rule',
  routes: 'route',
  qos: 'qos',
};

interface UniFiTrafficEntry {
  _id: string;
  name?: string;
  description?: string;
  enabled?: boolean;
  action?: string;
  matching_target?: string;
  network_id?: string;
  // route-specific
  next_hop?: string;
  // qos-specific
  dscp?: number;
  bandwidth_limit?: number;
}

interface UniFiTrafficResponse {
  controller_id: string;
  site: string;
  items: UniFiTrafficEntry[];
  fetched_at: string;
}

async function fetchTraffic(
  controllerId: string,
  site: string,
  kind: TrafficKind,
) {
  return api.get<UniFiTrafficResponse>(
    `/gateway-unifi-traffic/${enc(controllerId)}/sites/${enc(site)}/${enc(kind)}`,
  );
}

async function stageTrafficChange(
  controllerId: string,
  feature: string,
  operation: 'create' | 'update' | 'delete',
  payload: Record<string, unknown>,
  targetId?: string,
) {
  return api.post(
    `/gateway-unifi-traffic/${enc(controllerId)}/changes/${enc(feature)}`,
    targetId ? { payload, target_id: targetId } : { payload },
    { params: { operation } },
  );
}

type TrafficOp =
  | { kind: 'create'; resource: TrafficKind; name: string }
  | { kind: 'delete'; resource: TrafficKind; targetId: string; label: string };

interface UniFiTrafficTabProps {
  controllerId: string;
  site: string;
  isActive: boolean;
}

export function UniFiTrafficTab({
  controllerId,
  site,
  isActive,
}: UniFiTrafficTabProps) {
  const { t } = useTranslation('firewall');
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const [resource, setResource] = useState<TrafficKind>('rules');
  const [name, setName] = useState('');
  const [confirm, setConfirm] = useState<TrafficOp | null>(null);

  const LIST_KEY = ['unifi', 'traffic', controllerId, site, resource] as const;

  const query = useQuery({
    queryKey: LIST_KEY,
    queryFn: () => fetchTraffic(controllerId, site, resource),
    enabled: isActive && !!controllerId,
    refetchInterval: 60_000,
  });

  const stageMut = useMutation({
    mutationFn: async (op: TrafficOp) => {
      const noun = FEATURE_NOUN[op.resource];
      if (op.kind === 'create') {
        const feature = `unifi.traffic.create_${noun}`;
        return stageTrafficChange(controllerId, feature, 'create', {
          site,
          name: op.name.trim(),
        });
      }
      const feature = `unifi.traffic.delete_${noun}`;
      return stageTrafficChange(
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
            ? t('UniFiTrafficTab.toast.created.title')
            : t('UniFiTrafficTab.toast.deleted.title'),
        description: vars.kind === 'create' ? vars.name : vars.label,
      });
      setConfirm(null);
      if (vars.kind === 'create') setName('');
      queryClient.invalidateQueries({ queryKey: LIST_KEY });
    },
    onError: (err: unknown) => {
      toast({
        title: t('UniFiTrafficTab.toast.stageFailed.title'),
        description: getApiErrorMessage(err),
        variant: 'destructive',
      });
    },
  });

  const entries = query.data?.data?.items ?? [];
  const canStage = name.trim().length > 0;

  return (
    <Card>
      <CardHeader className="flex flex-row items-start justify-between">
        <div>
          <CardTitle className="flex items-center gap-2">
            <Route className="h-4 w-4" /> {t('UniFiTrafficTab.title')}
            <Badge variant="default">{entries.length}</Badge>
          </CardTitle>
          <p className="text-sm text-muted-foreground mt-1">
            {t('UniFiTrafficTab.siteLabel')}{' '}
            <code className="font-mono">{site}</code> ·{' '}
            {t('UniFiTrafficTab.description')}
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
        {/* Resource-kind selector */}
        <div className="flex items-center gap-2">
          <Label className="text-xs">{t('UniFiTrafficTab.fields.resource')}</Label>
          <Select
            value={resource}
            onValueChange={(v) => setResource(v as TrafficKind)}
          >
            <SelectTrigger className="w-40 text-sm">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="rules">
                {t('UniFiTrafficTab.resources.rules')}
              </SelectItem>
              <SelectItem value="routes">
                {t('UniFiTrafficTab.resources.routes')}
              </SelectItem>
              <SelectItem value="qos">
                {t('UniFiTrafficTab.resources.qos')}
              </SelectItem>
            </SelectContent>
          </Select>
        </div>

        {/* Stage create form. The payload here is intentionally minimal
            (name only); operators flesh out the remaining fields in the
            drawer payload preview / via a follow-up update once the
            adapter exposes richer create schemas. */}
        <div className="border border-border rounded-lg p-3 space-y-3">
          <Label className="text-sm font-medium">
            {t('UniFiTrafficTab.form.create', {
              resource: t(`UniFiTrafficTab.resourcesSingular.${resource}`),
            })}
          </Label>
          <div className="flex items-end gap-2">
            <div className="flex-1 space-y-1">
              <Label htmlFor="traffic-name" className="text-xs">
                {t('UniFiTrafficTab.fields.name')}
              </Label>
              <Input
                id="traffic-name"
                placeholder={t('UniFiTrafficTab.fields.namePlaceholder')}
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
              {t('UniFiTrafficTab.actions.stageCreate')}
            </Button>
          </div>
        </div>

        {query.isError && (
          <div className="rounded-md bg-destructive/10 border border-destructive p-3 text-sm text-destructive">
            {t('UniFiTrafficTab.loadError')}{' '}
            {(query.error as Error)?.message ||
              t('UniFiTrafficTab.unknownError')}
          </div>
        )}

        {query.isLoading ? (
          <div className="flex items-center justify-center py-8 text-muted-foreground">
            <Loader2 className="h-4 w-4 animate-spin mr-2" />{' '}
            {t('UniFiTrafficTab.loading')}
          </div>
        ) : entries.length === 0 ? (
          <div className="text-center py-8 text-sm text-muted-foreground">
            {t('UniFiTrafficTab.empty')}
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
                      {e.next_hop ? ` · ${e.next_hop}` : ''}
                      {typeof e.dscp === 'number' ? ` · DSCP ${e.dscp}` : ''}
                      {e.enabled === false
                        ? ` · ${t('UniFiTrafficTab.status.disabled')}`
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
                ? t('UniFiTrafficTab.dialog.deleteTitle')
                : t('UniFiTrafficTab.dialog.createTitle')}
            </AlertDialogTitle>
            <AlertDialogDescription>
              {t('UniFiTrafficTab.dialog.stagePrefix')}{' '}
              <code className="font-mono">
                unifi.traffic.
                {confirm?.kind === 'delete' ? 'delete' : 'create'}_
                {confirm ? FEATURE_NOUN[confirm.resource] : ''}
              </code>{' '}
              {t('UniFiTrafficTab.dialog.against')}{' '}
              <code className="font-mono">
                {confirm?.kind === 'delete' ? confirm.label : confirm?.name}
              </code>
              {t('UniFiTrafficTab.dialog.suffix')}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>
              {t('UniFiTrafficTab.actions.cancel')}
            </AlertDialogCancel>
            <AlertDialogAction
              onClick={() => confirm && stageMut.mutate(confirm)}
              disabled={stageMut.isPending}
            >
              {t('UniFiTrafficTab.actions.stage')}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </Card>
  );
}

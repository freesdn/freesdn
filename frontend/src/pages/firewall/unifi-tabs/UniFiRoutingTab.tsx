// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN, UniFi Routing tab
 *
 * Stages static-route create / update / delete against
 * gateway-unifi-routing. Lists the current routes for context. Like the
 * other UniFi domain tabs, writes never touch the controller directly,
 * they land as pending rows that the operator applies via the Pending
 * Changes drawer (POST /gateway-unifi-routing/{cid}/changes/...).
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

interface UniFiRoute {
  _id: string;
  name?: string;
  static_route_network?: string;
  static_route_nexthop?: string;
  static_route_distance?: number;
  static_route_type?: string;
  gateway_type?: string;
  enabled?: boolean;
}

interface UniFiRoutesResponse {
  controller_id: string;
  site: string;
  items: UniFiRoute[];
  fetched_at: string;
}

async function fetchRoutes(controllerId: string, site: string) {
  return api.get<UniFiRoutesResponse>(
    `/gateway-unifi-routing/${enc(controllerId)}/sites/${enc(site)}/routes`,
  );
}

async function stageRoutingChange(
  controllerId: string,
  feature: string,
  operation: 'create' | 'update' | 'delete',
  payload: Record<string, unknown>,
  targetId?: string,
) {
  return api.post(
    `/gateway-unifi-routing/${enc(controllerId)}/changes/${enc(feature)}`,
    targetId ? { payload, target_id: targetId } : { payload },
    { params: { operation } },
  );
}

interface CreateForm {
  name: string;
  network: string;
  nexthop: string;
}

const BLANK: CreateForm = {
  name: '',
  network: '',
  nexthop: '',
};

type RoutingOp =
  | { kind: 'create'; form: CreateForm }
  | { kind: 'delete'; targetId: string; label: string };

interface UniFiRoutingTabProps {
  controllerId: string;
  site: string;
  isActive: boolean;
}

export function UniFiRoutingTab({
  controllerId,
  site,
  isActive,
}: UniFiRoutingTabProps) {
  const { t } = useTranslation('firewall');
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const [form, setForm] = useState<CreateForm>(BLANK);
  const [confirm, setConfirm] = useState<RoutingOp | null>(null);

  const LIST_KEY = ['unifi', 'routing', controllerId, site] as const;

  const query = useQuery({
    queryKey: LIST_KEY,
    queryFn: () => fetchRoutes(controllerId, site),
    enabled: isActive && !!controllerId,
    refetchInterval: 60_000,
  });

  const stageMut = useMutation({
    mutationFn: async (op: RoutingOp) => {
      if (op.kind === 'create') {
        return stageRoutingChange(controllerId, 'unifi.routing.create', 'create', {
          site,
          name: op.form.name.trim(),
          network: op.form.network.trim(),
          nexthop: op.form.nexthop.trim(),
        });
      }
      // delete
      return stageRoutingChange(
        controllerId,
        'unifi.routing.delete',
        'delete',
        { site },
        op.targetId,
      );
    },
    onSuccess: (_data, vars) => {
      toast({
        title:
          vars.kind === 'create'
            ? t('UniFiRoutingTab.toast.created.title')
            : t('UniFiRoutingTab.toast.deleted.title'),
        description: vars.kind === 'create' ? vars.form.name : vars.label,
      });
      setConfirm(null);
      if (vars.kind === 'create') setForm(BLANK);
      queryClient.invalidateQueries({ queryKey: LIST_KEY });
    },
    onError: (err: unknown) => {
      toast({
        title: t('UniFiRoutingTab.toast.stageFailed.title'),
        description: getApiErrorMessage(err),
        variant: 'destructive',
      });
    },
  });

  const routes = query.data?.data?.items ?? [];
  const canStage =
    form.name.trim().length > 0 &&
    form.network.trim().length > 0 &&
    form.nexthop.trim().length > 0;

  return (
    <Card>
      <CardHeader className="flex flex-row items-start justify-between">
        <div>
          <CardTitle className="flex items-center gap-2">
            <Route className="h-4 w-4" /> {t('UniFiRoutingTab.title')}
            <Badge variant="default">{routes.length}</Badge>
          </CardTitle>
          <p className="text-sm text-muted-foreground mt-1">
            {t('UniFiRoutingTab.siteLabel')}{' '}
            <code className="font-mono">{site}</code> ·{' '}
            {t('UniFiRoutingTab.description')}
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
        {/* Stage create form. Payload is minimal (name + network +
            next-hop); operators refine in the drawer payload preview
            or via a follow-up update. */}
        <div className="border border-border rounded-lg p-3 space-y-3">
          <Label className="text-sm font-medium">
            {t('UniFiRoutingTab.form.createRoute')}
          </Label>
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1">
              <Label htmlFor="route-name" className="text-xs">
                {t('UniFiRoutingTab.fields.name')}
              </Label>
              <Input
                id="route-name"
                placeholder={t('UniFiRoutingTab.fields.namePlaceholder')}
                value={form.name}
                onChange={(e) =>
                  setForm((f) => ({ ...f, name: e.target.value }))
                }
                className="text-sm"
              />
            </div>
            <div className="space-y-1">
              <Label htmlFor="route-network" className="text-xs">
                {t('UniFiRoutingTab.fields.network')}
              </Label>
              <Input
                id="route-network"
                placeholder="192.168.50.0/24"
                value={form.network}
                onChange={(e) =>
                  setForm((f) => ({ ...f, network: e.target.value }))
                }
                className="font-mono text-sm"
              />
            </div>
          </div>
          <div className="space-y-1">
            <Label htmlFor="route-nexthop" className="text-xs">
              {t('UniFiRoutingTab.fields.nexthop')}
            </Label>
            <Input
              id="route-nexthop"
              placeholder="10.0.0.1"
              value={form.nexthop}
              onChange={(e) =>
                setForm((f) => ({ ...f, nexthop: e.target.value }))
              }
              className="font-mono text-sm"
            />
          </div>
          <div className="flex justify-end pt-2 border-t border-border">
            <Button
              size="sm"
              onClick={() => setConfirm({ kind: 'create', form })}
              disabled={!canStage}
            >
              <Plus className="h-4 w-4 mr-1" />{' '}
              {t('UniFiRoutingTab.actions.stageCreate')}
            </Button>
          </div>
        </div>

        {query.isError && (
          <div className="rounded-md bg-destructive/10 border border-destructive p-3 text-sm text-destructive">
            {t('UniFiRoutingTab.loadError')}{' '}
            {(query.error as Error)?.message ||
              t('UniFiRoutingTab.unknownError')}
          </div>
        )}

        {query.isLoading ? (
          <div className="flex items-center justify-center py-8 text-muted-foreground">
            <Loader2 className="h-4 w-4 animate-spin mr-2" />{' '}
            {t('UniFiRoutingTab.loading')}
          </div>
        ) : routes.length === 0 ? (
          <div className="text-center py-8 text-sm text-muted-foreground">
            {t('UniFiRoutingTab.empty')}
          </div>
        ) : (
          <ul className="space-y-2">
            {routes.map((r) => {
              const label = r.name || r.static_route_network || r._id;
              return (
                <li
                  key={r._id}
                  className="flex items-center justify-between border border-border rounded-lg p-3"
                >
                  <div className="space-y-1 min-w-0">
                    <div className="text-sm font-medium">{label}</div>
                    <div className="text-xs text-muted-foreground font-mono">
                      {r._id}
                      {r.static_route_network
                        ? ` · ${r.static_route_network}`
                        : ''}
                      {r.static_route_nexthop
                        ? ` → ${r.static_route_nexthop}`
                        : ''}
                      {r.static_route_type ? ` · ${r.static_route_type}` : ''}
                      {r.enabled === false
                        ? ` · ${t('UniFiRoutingTab.status.disabled')}`
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
                ? t('UniFiRoutingTab.dialog.deleteTitle')
                : t('UniFiRoutingTab.dialog.createTitle')}
            </AlertDialogTitle>
            <AlertDialogDescription>
              {t('UniFiRoutingTab.dialog.stagePrefix')}{' '}
              <code className="font-mono">
                unifi.routing.{confirm?.kind === 'delete' ? 'delete' : 'create'}
              </code>{' '}
              {t('UniFiRoutingTab.dialog.against')}{' '}
              <code className="font-mono">
                {confirm?.kind === 'delete' ? confirm.label : confirm?.form.name}
              </code>
              {t('UniFiRoutingTab.dialog.suffix')}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>
              {t('UniFiRoutingTab.actions.cancel')}
            </AlertDialogCancel>
            <AlertDialogAction
              onClick={() => confirm && stageMut.mutate(confirm)}
              disabled={stageMut.isPending}
            >
              {t('UniFiRoutingTab.actions.stage')}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </Card>
  );
}

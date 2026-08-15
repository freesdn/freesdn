// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN, UniFi WLAN Groups tab
 *
 * Stages WLAN-group create / update / delete against
 * gateway-unifi-wlan-groups. A WLAN group bundles a set of SSIDs that
 * are broadcast together by the APs assigned to the group. Like the
 * other UniFi domain tabs, writes never touch the controller directly,
 * they land as pending rows that the operator applies via the Pending
 * Changes drawer (POST /gateway-unifi-wlan-groups/{cid}/changes/...).
 */
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Layers, Loader2, Plus, RefreshCw, Trash2 } from 'lucide-react';
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

interface UniFiWlanGroup {
  _id: string;
  name?: string;
  wlan_ids?: string[];
  na_eirp_mode?: string;
  ng_eirp_mode?: string;
}

interface UniFiWlanGroupsResponse {
  controller_id: string;
  site: string;
  items: UniFiWlanGroup[];
  fetched_at: string;
}

async function fetchGroups(controllerId: string, site: string) {
  return api.get<UniFiWlanGroupsResponse>(
    `/gateway-unifi-wlan-groups/${enc(controllerId)}/sites/${enc(site)}/groups`,
  );
}

async function stageGroupChange(
  controllerId: string,
  feature: string,
  operation: 'create' | 'update' | 'delete',
  payload: Record<string, unknown>,
  targetId?: string,
) {
  return api.post(
    `/gateway-unifi-wlan-groups/${enc(controllerId)}/changes/${enc(feature)}`,
    targetId ? { payload, target_id: targetId } : { payload },
    { params: { operation } },
  );
}

type GroupOp =
  | { kind: 'create'; name: string }
  | { kind: 'delete'; targetId: string; label: string };

interface UniFiWlanGroupsTabProps {
  controllerId: string;
  site: string;
  isActive: boolean;
}

export function UniFiWlanGroupsTab({
  controllerId,
  site,
  isActive,
}: UniFiWlanGroupsTabProps) {
  const { t } = useTranslation('firewall');
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const [name, setName] = useState('');
  const [confirm, setConfirm] = useState<GroupOp | null>(null);

  const LIST_KEY = ['unifi', 'wlan-groups', controllerId, site] as const;

  const query = useQuery({
    queryKey: LIST_KEY,
    queryFn: () => fetchGroups(controllerId, site),
    enabled: isActive && !!controllerId,
    refetchInterval: 60_000,
  });

  const stageMut = useMutation({
    mutationFn: async (op: GroupOp) => {
      if (op.kind === 'create') {
        return stageGroupChange(
          controllerId,
          'unifi.wlangroups.create',
          'create',
          { site, name: op.name.trim() },
        );
      }
      // delete
      return stageGroupChange(
        controllerId,
        'unifi.wlangroups.delete',
        'delete',
        { site },
        op.targetId,
      );
    },
    onSuccess: (_data, vars) => {
      toast({
        title:
          vars.kind === 'create'
            ? t('UniFiWlanGroupsTab.toast.created.title')
            : t('UniFiWlanGroupsTab.toast.deleted.title'),
        description: vars.kind === 'create' ? vars.name : vars.label,
      });
      setConfirm(null);
      if (vars.kind === 'create') setName('');
      queryClient.invalidateQueries({ queryKey: LIST_KEY });
    },
    onError: (err: unknown) => {
      toast({
        title: t('UniFiWlanGroupsTab.toast.stageFailed.title'),
        description: getApiErrorMessage(err),
        variant: 'destructive',
      });
    },
  });

  const groups = query.data?.data?.items ?? [];
  const canStage = name.trim().length > 0;

  return (
    <Card>
      <CardHeader className="flex flex-row items-start justify-between">
        <div>
          <CardTitle className="flex items-center gap-2">
            <Layers className="h-4 w-4" /> {t('UniFiWlanGroupsTab.title')}
            <Badge variant="default">{groups.length}</Badge>
          </CardTitle>
          <p className="text-sm text-muted-foreground mt-1">
            {t('UniFiWlanGroupsTab.siteLabel')}{' '}
            <code className="font-mono">{site}</code> ·{' '}
            {t('UniFiWlanGroupsTab.description')}
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
        {/* Stage create form. Payload is minimal (name); operators assign
            SSIDs to the group in the drawer payload preview or via a
            follow-up update. */}
        <div className="border border-border rounded-lg p-3 space-y-3">
          <Label className="text-sm font-medium">
            {t('UniFiWlanGroupsTab.form.createGroup')}
          </Label>
          <div className="flex items-end gap-2">
            <div className="flex-1 space-y-1">
              <Label htmlFor="wg-name" className="text-xs">
                {t('UniFiWlanGroupsTab.fields.name')}
              </Label>
              <Input
                id="wg-name"
                placeholder={t('UniFiWlanGroupsTab.fields.namePlaceholder')}
                value={name}
                onChange={(e) => setName(e.target.value)}
                className="text-sm"
              />
            </div>
            <Button
              size="sm"
              onClick={() => setConfirm({ kind: 'create', name })}
              disabled={!canStage}
            >
              <Plus className="h-4 w-4 mr-1" />{' '}
              {t('UniFiWlanGroupsTab.actions.stageCreate')}
            </Button>
          </div>
        </div>

        {query.isError && (
          <div className="rounded-md bg-destructive/10 border border-destructive p-3 text-sm text-destructive">
            {t('UniFiWlanGroupsTab.loadError')}{' '}
            {(query.error as Error)?.message ||
              t('UniFiWlanGroupsTab.unknownError')}
          </div>
        )}

        {query.isLoading ? (
          <div className="flex items-center justify-center py-8 text-muted-foreground">
            <Loader2 className="h-4 w-4 animate-spin mr-2" />{' '}
            {t('UniFiWlanGroupsTab.loading')}
          </div>
        ) : groups.length === 0 ? (
          <div className="text-center py-8 text-sm text-muted-foreground">
            {t('UniFiWlanGroupsTab.empty')}
          </div>
        ) : (
          <ul className="space-y-2">
            {groups.map((g) => {
              const label = g.name || g._id;
              const wlanCount = g.wlan_ids?.length ?? 0;
              return (
                <li
                  key={g._id}
                  className="flex items-center justify-between border border-border rounded-lg p-3"
                >
                  <div className="space-y-1 min-w-0">
                    <div className="text-sm font-medium">{label}</div>
                    <div className="text-xs text-muted-foreground font-mono">
                      {g._id}
                      {` · ${t('UniFiWlanGroupsTab.wlanCount', {
                        count: wlanCount,
                      })}`}
                    </div>
                  </div>
                  <div className="flex items-center gap-1">
                    <Button
                      size="sm"
                      variant="ghost"
                      onClick={() =>
                        setConfirm({
                          kind: 'delete',
                          targetId: g._id,
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
                ? t('UniFiWlanGroupsTab.dialog.deleteTitle')
                : t('UniFiWlanGroupsTab.dialog.createTitle')}
            </AlertDialogTitle>
            <AlertDialogDescription>
              {t('UniFiWlanGroupsTab.dialog.stagePrefix')}{' '}
              <code className="font-mono">
                unifi.wlangroups.
                {confirm?.kind === 'delete' ? 'delete' : 'create'}
              </code>{' '}
              {t('UniFiWlanGroupsTab.dialog.against')}{' '}
              <code className="font-mono">
                {confirm?.kind === 'delete' ? confirm.label : confirm?.name}
              </code>
              {t('UniFiWlanGroupsTab.dialog.suffix')}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>
              {t('UniFiWlanGroupsTab.actions.cancel')}
            </AlertDialogCancel>
            <AlertDialogAction
              onClick={() => confirm && stageMut.mutate(confirm)}
              disabled={stageMut.isPending}
            >
              {t('UniFiWlanGroupsTab.actions.stage')}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </Card>
  );
}

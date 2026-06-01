// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN, UniFi Port Profiles tab
 *
 * Stages switch port-profile create / update / delete against
 * gateway-unifi-port-profiles. Port profiles are reusable port configs
 * (native network, tagged VLANs, PoE mode, port-security) that switch
 * ports reference by id. Like the other UniFi domain tabs, writes never
 * touch the controller directly, they land as pending rows that the
 * operator applies via the Pending Changes drawer
 * (POST /gateway-unifi-port-profiles/{cid}/changes/...).
 */
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Loader2, Plus, RefreshCw, SlidersHorizontal, Trash2 } from 'lucide-react';
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

interface UniFiPortProfile {
  _id: string;
  name?: string;
  forward?: string; // all / native / customize / disabled
  poe_mode?: string;
  native_networkconf_id?: string;
  op_mode?: string;
}

interface UniFiPortProfilesResponse {
  controller_id: string;
  site: string;
  items: UniFiPortProfile[];
  fetched_at: string;
}

async function fetchProfiles(controllerId: string, site: string) {
  return api.get<UniFiPortProfilesResponse>(
    `/gateway-unifi-port-profiles/${enc(controllerId)}/sites/${enc(site)}/profiles`,
  );
}

async function stageProfileChange(
  controllerId: string,
  feature: string,
  operation: 'create' | 'update' | 'delete',
  payload: Record<string, unknown>,
  targetId?: string,
) {
  return api.post(
    `/gateway-unifi-port-profiles/${enc(controllerId)}/changes/${enc(feature)}`,
    targetId ? { payload, target_id: targetId } : { payload },
    { params: { operation } },
  );
}

type ProfileOp =
  | { kind: 'create'; name: string }
  | { kind: 'delete'; targetId: string; label: string };

interface UniFiPortProfilesTabProps {
  controllerId: string;
  site: string;
  isActive: boolean;
}

export function UniFiPortProfilesTab({
  controllerId,
  site,
  isActive,
}: UniFiPortProfilesTabProps) {
  const { t } = useTranslation('firewall');
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const [name, setName] = useState('');
  const [confirm, setConfirm] = useState<ProfileOp | null>(null);

  const LIST_KEY = ['unifi', 'port-profiles', controllerId, site] as const;

  const query = useQuery({
    queryKey: LIST_KEY,
    queryFn: () => fetchProfiles(controllerId, site),
    enabled: isActive && !!controllerId,
    refetchInterval: 60_000,
  });

  const stageMut = useMutation({
    mutationFn: async (op: ProfileOp) => {
      if (op.kind === 'create') {
        return stageProfileChange(
          controllerId,
          'unifi.portprofiles.create',
          'create',
          { site, name: op.name.trim() },
        );
      }
      // delete
      return stageProfileChange(
        controllerId,
        'unifi.portprofiles.delete',
        'delete',
        { site },
        op.targetId,
      );
    },
    onSuccess: (_data, vars) => {
      toast({
        title:
          vars.kind === 'create'
            ? t('UniFiPortProfilesTab.toast.created.title')
            : t('UniFiPortProfilesTab.toast.deleted.title'),
        description: vars.kind === 'create' ? vars.name : vars.label,
      });
      setConfirm(null);
      if (vars.kind === 'create') setName('');
      queryClient.invalidateQueries({ queryKey: LIST_KEY });
    },
    onError: (err: unknown) => {
      toast({
        title: t('UniFiPortProfilesTab.toast.stageFailed.title'),
        description: getApiErrorMessage(err),
        variant: 'destructive',
      });
    },
  });

  const profiles = query.data?.data?.items ?? [];
  const canStage = name.trim().length > 0;

  return (
    <Card>
      <CardHeader className="flex flex-row items-start justify-between">
        <div>
          <CardTitle className="flex items-center gap-2">
            <SlidersHorizontal className="h-4 w-4" />{' '}
            {t('UniFiPortProfilesTab.title')}
            <Badge variant="default">{profiles.length}</Badge>
          </CardTitle>
          <p className="text-sm text-muted-foreground mt-1">
            {t('UniFiPortProfilesTab.siteLabel')}{' '}
            <code className="font-mono">{site}</code> ·{' '}
            {t('UniFiPortProfilesTab.description')}
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
        {/* Stage create form. Payload is minimal (name); operators refine
            forwarding / VLAN / PoE details in the drawer payload preview
            or via a follow-up update. */}
        <div className="border border-border rounded-lg p-3 space-y-3">
          <Label className="text-sm font-medium">
            {t('UniFiPortProfilesTab.form.createProfile')}
          </Label>
          <div className="flex items-end gap-2">
            <div className="flex-1 space-y-1">
              <Label htmlFor="pp-name" className="text-xs">
                {t('UniFiPortProfilesTab.fields.name')}
              </Label>
              <Input
                id="pp-name"
                placeholder={t('UniFiPortProfilesTab.fields.namePlaceholder')}
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
              {t('UniFiPortProfilesTab.actions.stageCreate')}
            </Button>
          </div>
        </div>

        {query.isError && (
          <div className="rounded-md bg-destructive/10 border border-destructive p-3 text-sm text-destructive">
            {t('UniFiPortProfilesTab.loadError')}{' '}
            {(query.error as Error)?.message ||
              t('UniFiPortProfilesTab.unknownError')}
          </div>
        )}

        {query.isLoading ? (
          <div className="flex items-center justify-center py-8 text-muted-foreground">
            <Loader2 className="h-4 w-4 animate-spin mr-2" />{' '}
            {t('UniFiPortProfilesTab.loading')}
          </div>
        ) : profiles.length === 0 ? (
          <div className="text-center py-8 text-sm text-muted-foreground">
            {t('UniFiPortProfilesTab.empty')}
          </div>
        ) : (
          <ul className="space-y-2">
            {profiles.map((p) => {
              const label = p.name || p._id;
              return (
                <li
                  key={p._id}
                  className="flex items-center justify-between border border-border rounded-lg p-3"
                >
                  <div className="space-y-1 min-w-0">
                    <div className="text-sm font-medium">{label}</div>
                    <div className="text-xs text-muted-foreground font-mono">
                      {p._id}
                      {p.forward ? ` · ${p.forward}` : ''}
                      {p.poe_mode ? ` · PoE ${p.poe_mode}` : ''}
                      {p.op_mode ? ` · ${p.op_mode}` : ''}
                    </div>
                  </div>
                  <div className="flex items-center gap-1">
                    <Button
                      size="sm"
                      variant="ghost"
                      onClick={() =>
                        setConfirm({
                          kind: 'delete',
                          targetId: p._id,
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
                ? t('UniFiPortProfilesTab.dialog.deleteTitle')
                : t('UniFiPortProfilesTab.dialog.createTitle')}
            </AlertDialogTitle>
            <AlertDialogDescription>
              {t('UniFiPortProfilesTab.dialog.stagePrefix')}{' '}
              <code className="font-mono">
                unifi.portprofiles.
                {confirm?.kind === 'delete' ? 'delete' : 'create'}
              </code>{' '}
              {t('UniFiPortProfilesTab.dialog.against')}{' '}
              <code className="font-mono">
                {confirm?.kind === 'delete' ? confirm.label : confirm?.name}
              </code>
              {t('UniFiPortProfilesTab.dialog.suffix')}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>
              {t('UniFiPortProfilesTab.actions.cancel')}
            </AlertDialogCancel>
            <AlertDialogAction
              onClick={() => confirm && stageMut.mutate(confirm)}
              disabled={stageMut.isPending}
            >
              {t('UniFiPortProfilesTab.actions.stage')}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </Card>
  );
}

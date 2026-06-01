// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN, UniFi RADIUS tab
 *
 * Stages built-in RADIUS user create / delete against gateway-unifi-radius
 * (used by WPA-Enterprise SSIDs + RADIUS-authenticated switch ports). Writes
 * never touch the controller directly — they land as pending rows the operator
 * applies via the Pending Changes drawer. A delete is gated by the apply-time
 * confirm (any UniFi delete is catastrophic per the backend preflight).
 */
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { KeyRound, Loader2, Plus, RefreshCw, Trash2 } from 'lucide-react';
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

interface UniFiRadiusUser {
  _id: string;
  name?: string;
  vlan?: string | number;
  tunnel_type?: number;
}

interface UniFiRadiusResponse {
  controller_id: string;
  site: string;
  items: UniFiRadiusUser[];
  fetched_at: string;
}

async function fetchUsers(controllerId: string, site: string) {
  return api.get<UniFiRadiusResponse>(
    `/gateway-unifi-radius/${enc(controllerId)}/sites/${enc(site)}/users`,
  );
}

async function stageRadiusChange(
  controllerId: string,
  feature: string,
  operation: 'create' | 'delete',
  payload: Record<string, unknown>,
  targetId?: string,
) {
  return api.post(
    `/gateway-unifi-radius/${enc(controllerId)}/changes/${enc(feature)}`,
    targetId ? { payload, target_id: targetId } : { payload },
    { params: { operation } },
  );
}

type RadiusOp =
  | { kind: 'create'; name: string; password: string }
  | { kind: 'delete'; targetId: string; label: string };

interface Props {
  controllerId: string;
  site: string;
  isActive: boolean;
}

export function UniFiRadiusTab({ controllerId, site, isActive }: Props) {
  const { t } = useTranslation('firewall');
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const [name, setName] = useState('');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState<RadiusOp | null>(null);

  const LIST_KEY = ['unifi', 'radius', controllerId, site] as const;

  const query = useQuery({
    queryKey: LIST_KEY,
    queryFn: () => fetchUsers(controllerId, site),
    enabled: isActive && !!controllerId,
    refetchInterval: 60_000,
  });

  const stageMut = useMutation({
    mutationFn: async (op: RadiusOp) => {
      if (op.kind === 'create') {
        // tunnel_type 13 (VLAN) + tunnel_medium_type 6 (802) are the controller
        // defaults for a dynamic-VLAN RADIUS account (validated live).
        return stageRadiusChange(controllerId, 'unifi.radius.create_user', 'create', {
          site,
          name: op.name.trim(),
          x_password: op.password,
          tunnel_type: 13,
          tunnel_medium_type: 6,
        });
      }
      return stageRadiusChange(
        controllerId,
        'unifi.radius.delete_user',
        'delete',
        { site },
        op.targetId,
      );
    },
    onSuccess: (_data, vars) => {
      toast({
        title:
          vars.kind === 'create'
            ? t('UniFiRadiusTab.toast.created.title')
            : t('UniFiRadiusTab.toast.deleted.title'),
        description: vars.kind === 'create' ? vars.name : vars.label,
      });
      setConfirm(null);
      if (vars.kind === 'create') {
        setName('');
        setPassword('');
      }
      queryClient.invalidateQueries({ queryKey: LIST_KEY });
    },
    onError: (err: unknown) => {
      toast({
        title: t('UniFiRadiusTab.toast.stageFailed.title'),
        description: getApiErrorMessage(err),
        variant: 'destructive',
      });
    },
  });

  const users = query.data?.data?.items ?? [];
  const canStage = name.trim().length > 0 && password.length > 0;

  return (
    <Card>
      <CardHeader className="flex flex-row items-start justify-between">
        <div>
          <CardTitle className="flex items-center gap-2">
            <KeyRound className="h-4 w-4" /> {t('UniFiRadiusTab.title')}
            <Badge variant="default">{users.length}</Badge>
          </CardTitle>
          <p className="text-sm text-muted-foreground mt-1">
            {t('UniFiRadiusTab.siteLabel')}{' '}
            <code className="font-mono">{site}</code> ·{' '}
            {t('UniFiRadiusTab.description')}
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
        <div className="border border-border rounded-lg p-3 space-y-3">
          <Label className="text-sm font-medium">
            {t('UniFiRadiusTab.form.create')}
          </Label>
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1">
              <Label htmlFor="radius-name" className="text-xs">
                {t('UniFiRadiusTab.fields.name')}
              </Label>
              <Input
                id="radius-name"
                placeholder={t('UniFiRadiusTab.fields.namePlaceholder')}
                value={name}
                onChange={(e) => setName(e.target.value)}
                className="font-mono text-sm"
                autoComplete="off"
              />
            </div>
            <div className="space-y-1">
              <Label htmlFor="radius-pass" className="text-xs">
                {t('UniFiRadiusTab.fields.password')}
              </Label>
              <Input
                id="radius-pass"
                type="password"
                placeholder={t('UniFiRadiusTab.fields.passwordPlaceholder')}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="font-mono text-sm"
                autoComplete="new-password"
              />
            </div>
          </div>
          <div className="flex justify-end pt-2 border-t border-border">
            <Button
              size="sm"
              onClick={() => setConfirm({ kind: 'create', name, password })}
              disabled={!canStage}
            >
              <Plus className="h-4 w-4 mr-1" /> {t('UniFiRadiusTab.actions.stageCreate')}
            </Button>
          </div>
        </div>

        {query.isError && (
          <div className="rounded-md bg-destructive/10 border border-destructive p-3 text-sm text-destructive">
            {t('UniFiRadiusTab.loadError')}{' '}
            {(query.error as Error)?.message || t('UniFiRadiusTab.unknownError')}
          </div>
        )}

        {query.isLoading ? (
          <div className="flex items-center justify-center py-8 text-muted-foreground">
            <Loader2 className="h-4 w-4 animate-spin mr-2" />{' '}
            {t('UniFiRadiusTab.loading')}
          </div>
        ) : users.length === 0 ? (
          <div className="text-center py-8 text-sm text-muted-foreground">
            {t('UniFiRadiusTab.empty')}
          </div>
        ) : (
          <ul className="space-y-2">
            {users.map((u) => {
              const label = u.name || u._id;
              return (
                <li
                  key={u._id}
                  className="flex items-center justify-between border border-border rounded-lg p-3"
                >
                  <div className="space-y-1 min-w-0">
                    <div className="text-sm font-medium">{label}</div>
                    <div className="text-xs text-muted-foreground font-mono">
                      {u._id}
                      {u.vlan ? ` · VLAN ${u.vlan}` : ''}
                    </div>
                  </div>
                  <Button
                    size="sm"
                    variant="ghost"
                    onClick={() =>
                      setConfirm({ kind: 'delete', targetId: u._id, label })
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
                ? t('UniFiRadiusTab.dialog.deleteTitle')
                : t('UniFiRadiusTab.dialog.createTitle')}
            </AlertDialogTitle>
            <AlertDialogDescription>
              {t('UniFiRadiusTab.dialog.stagePrefix')}{' '}
              <code className="font-mono">
                unifi.radius.{confirm?.kind === 'delete' ? 'delete' : 'create'}_user
              </code>{' '}
              {t('UniFiRadiusTab.dialog.against')}{' '}
              <code className="font-mono">
                {confirm?.kind === 'delete' ? confirm.label : confirm?.name}
              </code>
              {t('UniFiRadiusTab.dialog.suffix')}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t('UniFiRadiusTab.actions.cancel')}</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => confirm && stageMut.mutate(confirm)}
              disabled={stageMut.isPending}
            >
              {t('UniFiRadiusTab.actions.stage')}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </Card>
  );
}

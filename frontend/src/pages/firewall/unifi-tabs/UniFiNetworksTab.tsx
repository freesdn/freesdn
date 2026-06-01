// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN, UniFi Networks tab
 *
 * Stages VLAN create + per-network update / delete against the UniFi
 * networks endpoint. Lists the current networks for context. Create
 * stages ``unifi.networks.create_vlan``; update / delete stage
 * ``unifi.networks.update`` / ``unifi.networks.delete`` against a
 * network ``_id``. Like the other UniFi domain tabs, writes never touch
 * the controller directly, they land as pending rows that the operator
 * applies via the Pending Changes drawer.
 */
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Loader2, Network, Pencil, Plus, RefreshCw, Trash2 } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
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

interface UniFiNetwork {
  _id: string;
  name?: string;
  vlan?: number;
  vlan_enabled?: boolean;
  ip_subnet?: string;
  purpose?: string;
  dhcpd_enabled?: boolean;
  dhcpd_start?: string;
  dhcpd_stop?: string;
}

interface UniFiNetworksResponse {
  controller_id: string;
  site: string;
  items: UniFiNetwork[];
  fetched_at: string;
}

async function fetchNetworks(controllerId: string, site: string) {
  return api.get<UniFiNetworksResponse>(
    `/gateway-unifi-networks/${enc(controllerId)}/sites/${enc(site)}/networks`,
  );
}

async function stageNetworkChange(
  controllerId: string,
  feature: string,
  operation: 'create' | 'update' | 'delete',
  payload: Record<string, unknown>,
  targetId?: string,
) {
  return api.post(
    `/gateway-unifi-networks/${enc(controllerId)}/changes/${enc(feature)}`,
    targetId ? { payload, target_id: targetId } : { payload },
    { params: { operation } },
  );
}

interface CreateForm {
  vlan_id: number;
  name: string;
  subnet: string;
  dhcp_enabled: boolean;
  dhcp_start: string;
  dhcp_stop: string;
}

const BLANK: CreateForm = {
  vlan_id: 10,
  name: '',
  subnet: '',
  dhcp_enabled: false,
  dhcp_start: '',
  dhcp_stop: '',
};

// Update is a minimal rename-in-place (changed fields only). Operators
// refine the rest of the payload in the drawer preview, mirroring the
// create form's refine-in-drawer philosophy.
interface UpdateForm {
  targetId: string;
  name: string;
  subnet: string;
}

type NetworkOp =
  | { kind: 'create'; form: CreateForm }
  | { kind: 'update'; form: UpdateForm }
  | { kind: 'delete'; targetId: string; label: string };

interface UniFiNetworksTabProps {
  controllerId: string;
  site: string;
  isActive: boolean;
}

export function UniFiNetworksTab({
  controllerId,
  site,
  isActive,
}: UniFiNetworksTabProps) {
  const { t } = useTranslation('firewall');
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const [form, setForm] = useState<CreateForm>(BLANK);
  const [editing, setEditing] = useState<UpdateForm | null>(null);
  const [confirm, setConfirm] = useState<NetworkOp | null>(null);

  const LIST_KEY = ['unifi', 'networks', controllerId, site] as const;

  const query = useQuery({
    queryKey: LIST_KEY,
    queryFn: () => fetchNetworks(controllerId, site),
    enabled: isActive && !!controllerId,
    refetchInterval: 60_000,
  });

  const stageMut = useMutation({
    mutationFn: async (op: NetworkOp) => {
      if (op.kind === 'create') {
        const f = op.form;
        const payload: Record<string, unknown> = {
          site,
          vlan_id: f.vlan_id,
          name: f.name.trim(),
        };
        if (f.subnet.trim()) payload.subnet = f.subnet.trim();
        if (f.dhcp_enabled) {
          payload.dhcp_enabled = true;
          if (f.dhcp_start.trim()) payload.dhcp_start = f.dhcp_start.trim();
          if (f.dhcp_stop.trim()) payload.dhcp_stop = f.dhcp_stop.trim();
        }
        return stageNetworkChange(
          controllerId,
          'unifi.networks.create_vlan',
          'create',
          payload,
        );
      }
      if (op.kind === 'update') {
        // Send only the changed fields.
        const payload: Record<string, unknown> = { site };
        if (op.form.name.trim()) payload.name = op.form.name.trim();
        if (op.form.subnet.trim()) payload.subnet = op.form.subnet.trim();
        return stageNetworkChange(
          controllerId,
          'unifi.networks.update',
          'update',
          payload,
          op.form.targetId,
        );
      }
      // delete
      return stageNetworkChange(
        controllerId,
        'unifi.networks.delete',
        'delete',
        { site },
        op.targetId,
      );
    },
    onSuccess: (_data, vars) => {
      toast({
        title:
          vars.kind === 'create'
            ? t('UniFiNetworksTab.toast.staged.title')
            : vars.kind === 'update'
              ? t('UniFiNetworksTab.toast.updated.title')
              : t('UniFiNetworksTab.toast.deleted.title'),
        description:
          vars.kind === 'create'
            ? t('UniFiNetworksTab.toast.staged.description', {
                vlanId: vars.form.vlan_id,
                name: vars.form.name,
              })
            : vars.kind === 'update'
              ? vars.form.targetId
              : vars.label,
      });
      setConfirm(null);
      if (vars.kind === 'create') setForm(BLANK);
      if (vars.kind === 'update') setEditing(null);
      queryClient.invalidateQueries({ queryKey: LIST_KEY });
    },
    onError: (err: unknown) => {
      toast({
        title: t('UniFiNetworksTab.toast.error.title'),
        description: getApiErrorMessage(err),
        variant: 'destructive',
      });
    },
  });

  const networks = query.data?.data?.items ?? [];
  const canStage =
    form.vlan_id >= 1 &&
    form.vlan_id <= 4094 &&
    form.name.trim().length > 0;
  const canUpdate =
    !!editing &&
    (editing.name.trim().length > 0 || editing.subnet.trim().length > 0);

  return (
    <Card>
      <CardHeader className="flex flex-row items-start justify-between">
        <div>
          <CardTitle className="flex items-center gap-2">
            <Network className="h-4 w-4" /> {t('UniFiNetworksTab.title')}
            <Badge variant="default">{networks.length}</Badge>
          </CardTitle>
          <p className="text-sm text-muted-foreground mt-1">
            {t('UniFiNetworksTab.siteLabel')}{' '}
            <code className="font-mono">{site}</code> ·{' '}
            {t('UniFiNetworksTab.description')}
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
            {t('UniFiNetworksTab.form.createVlan')}
          </Label>
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1">
              <Label htmlFor="vlan-id" className="text-xs">
                {t('UniFiNetworksTab.form.vlanId')}
              </Label>
              <Input
                id="vlan-id"
                type="number"
                min={1}
                max={4094}
                value={form.vlan_id}
                onChange={(e) =>
                  setForm((f) => ({
                    ...f,
                    vlan_id: parseInt(e.target.value, 10) || 1,
                  }))
                }
                className="text-sm"
              />
            </div>
            <div className="space-y-1">
              <Label htmlFor="vlan-name" className="text-xs">
                {t('UniFiNetworksTab.form.networkName')}
              </Label>
              <Input
                id="vlan-name"
                placeholder={t('UniFiNetworksTab.form.networkNamePlaceholder')}
                value={form.name}
                onChange={(e) =>
                  setForm((f) => ({ ...f, name: e.target.value }))
                }
                className="text-sm"
              />
            </div>
          </div>
          <div className="space-y-1">
            <Label htmlFor="vlan-subnet" className="text-xs">
              {t('UniFiNetworksTab.form.subnet')}
            </Label>
            <Input
              id="vlan-subnet"
              placeholder="10.10.0.1/24"
              value={form.subnet}
              onChange={(e) =>
                setForm((f) => ({ ...f, subnet: e.target.value }))
              }
              className="font-mono text-sm"
            />
          </div>
          <div className="flex items-center justify-between pt-2 border-t border-border">
            <Label className="text-xs flex items-center gap-2">
              <Switch
                checked={form.dhcp_enabled}
                onCheckedChange={(checked) =>
                  setForm((f) => ({ ...f, dhcp_enabled: !!checked }))
                }
              />
              {t('UniFiNetworksTab.form.enableDhcp')}
            </Label>
          </div>
          {form.dhcp_enabled ? (
            <div className="grid grid-cols-2 gap-3">
              <Input
                placeholder={t('UniFiNetworksTab.form.dhcpStartPlaceholder')}
                value={form.dhcp_start}
                onChange={(e) =>
                  setForm((f) => ({ ...f, dhcp_start: e.target.value }))
                }
                className="font-mono text-sm"
              />
              <Input
                placeholder={t('UniFiNetworksTab.form.dhcpStopPlaceholder')}
                value={form.dhcp_stop}
                onChange={(e) =>
                  setForm((f) => ({ ...f, dhcp_stop: e.target.value }))
                }
                className="font-mono text-sm"
              />
            </div>
          ) : null}
          <div className="flex justify-end pt-2 border-t border-border">
            <Button
              size="sm"
              onClick={() => setConfirm({ kind: 'create', form })}
              disabled={!canStage}
            >
              <Plus className="h-4 w-4 mr-1" />{' '}
              {t('UniFiNetworksTab.actions.stageVlanCreate')}
            </Button>
          </div>
        </div>

        {/* Inline edit form (rename / re-subnet a network). Appears when
            the operator clicks the pencil on a listed network. */}
        {editing ? (
          <div className="border border-primary/40 rounded-lg p-3 space-y-3">
            <Label className="text-sm font-medium">
              {t('UniFiNetworksTab.form.updateNetwork')}{' '}
              <code className="font-mono">{editing.targetId}</code>
            </Label>
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1">
                <Label htmlFor="edit-name" className="text-xs">
                  {t('UniFiNetworksTab.form.networkName')}
                </Label>
                <Input
                  id="edit-name"
                  placeholder={t('UniFiNetworksTab.form.unchanged')}
                  value={editing.name}
                  onChange={(e) =>
                    setEditing((prev) =>
                      prev ? { ...prev, name: e.target.value } : prev,
                    )
                  }
                  className="text-sm"
                />
              </div>
              <div className="space-y-1">
                <Label htmlFor="edit-subnet" className="text-xs">
                  {t('UniFiNetworksTab.form.subnet')}
                </Label>
                <Input
                  id="edit-subnet"
                  placeholder={t('UniFiNetworksTab.form.unchanged')}
                  value={editing.subnet}
                  onChange={(e) =>
                    setEditing((prev) =>
                      prev ? { ...prev, subnet: e.target.value } : prev,
                    )
                  }
                  className="font-mono text-sm"
                />
              </div>
            </div>
            <div className="flex justify-end gap-2 pt-2 border-t border-border">
              <Button
                size="sm"
                variant="ghost"
                onClick={() => setEditing(null)}
              >
                {t('UniFiNetworksTab.actions.cancel')}
              </Button>
              <Button
                size="sm"
                onClick={() =>
                  editing && setConfirm({ kind: 'update', form: editing })
                }
                disabled={!canUpdate}
              >
                <Pencil className="h-4 w-4 mr-1" />{' '}
                {t('UniFiNetworksTab.actions.stageUpdate')}
              </Button>
            </div>
          </div>
        ) : null}

        {query.isError && (
          <div className="rounded-md bg-destructive/10 border border-destructive p-3 text-sm text-destructive">
            {t('UniFiNetworksTab.loadError')}{' '}
            {(query.error as Error)?.message ||
              t('UniFiNetworksTab.unknownError')}
          </div>
        )}

        {query.isLoading ? (
          <div className="flex items-center justify-center py-8 text-muted-foreground">
            <Loader2 className="h-4 w-4 animate-spin mr-2" />{' '}
            {t('UniFiNetworksTab.loading')}
          </div>
        ) : (
          <ul className="space-y-2">
            {networks.map((n) => (
              <li
                key={n._id}
                className="flex items-center justify-between border border-border rounded-lg p-3"
              >
                <div className="space-y-1 min-w-0">
                  <div className="text-sm font-medium">
                    {n.name || t('UniFiNetworksTab.unnamed')}
                  </div>
                  <div className="text-xs text-muted-foreground font-mono">
                    {n._id}
                    {n.vlan ? ` · VLAN ${n.vlan}` : ''}
                    {n.ip_subnet ? ` · ${n.ip_subnet}` : ''}
                    {n.purpose ? ` · ${n.purpose}` : ''}
                    {n.dhcpd_enabled
                      ? ` · ${t('UniFiNetworksTab.dhcpOn')}`
                      : ''}
                  </div>
                </div>
                <div className="flex items-center gap-1">
                  <Button
                    size="sm"
                    variant="ghost"
                    onClick={() =>
                      setEditing({
                        targetId: n._id,
                        name: '',
                        subnet: '',
                      })
                    }
                    disabled={stageMut.isPending}
                  >
                    <Pencil className="h-4 w-4" />
                  </Button>
                  <Button
                    size="sm"
                    variant="ghost"
                    onClick={() =>
                      setConfirm({
                        kind: 'delete',
                        targetId: n._id,
                        label: n.name || n._id,
                      })
                    }
                    disabled={stageMut.isPending}
                    className="text-destructive hover:bg-destructive/10"
                  >
                    <Trash2 className="h-4 w-4" />
                  </Button>
                </div>
              </li>
            ))}
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
                ? t('UniFiNetworksTab.dialog.deleteTitle')
                : confirm?.kind === 'update'
                  ? t('UniFiNetworksTab.dialog.updateTitle')
                  : t('UniFiNetworksTab.dialog.title')}
            </AlertDialogTitle>
            <AlertDialogDescription>
              {confirm?.kind === 'create' ? (
                <>
                  {t('UniFiNetworksTab.dialog.stagePrefix')}{' '}
                  <code className="font-mono">
                    unifi.networks.create_vlan
                  </code>{' '}
                  {t('UniFiNetworksTab.dialog.forVlan')}{' '}
                  <code className="font-mono">{confirm.form.vlan_id}</code> (
                  <code className="font-mono">{confirm.form.name}</code>).
                  {confirm.form.subnet ? (
                    <>
                      {' '}
                      {t('UniFiNetworksTab.dialog.subnetLabel')}{' '}
                      <code className="font-mono">{confirm.form.subnet}</code>.
                    </>
                  ) : null}
                </>
              ) : (
                <>
                  {t('UniFiNetworksTab.dialog.stagePrefix')}{' '}
                  <code className="font-mono">
                    unifi.networks.
                    {confirm?.kind === 'delete' ? 'delete' : 'update'}
                  </code>{' '}
                  {t('UniFiNetworksTab.dialog.against')}{' '}
                  <code className="font-mono">
                    {confirm?.kind === 'delete'
                      ? confirm.label
                      : confirm?.form.targetId}
                  </code>
                  {t('UniFiNetworksTab.dialog.suffix')}
                </>
              )}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>
              {t('UniFiNetworksTab.actions.cancel')}
            </AlertDialogCancel>
            <AlertDialogAction
              onClick={() => confirm && stageMut.mutate(confirm)}
              disabled={stageMut.isPending}
            >
              {confirm?.kind === 'create'
                ? t('UniFiNetworksTab.actions.stageVlanCreate')
                : t('UniFiNetworksTab.actions.stage')}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </Card>
  );
}

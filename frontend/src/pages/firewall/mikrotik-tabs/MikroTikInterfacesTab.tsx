// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * MikroTikInterfacesTab · ethernet stats, bridge CRUD, wireless toggle.
 *
 * Three sub-tables driven by three independent queries:
 *   - ``/interfaces/ethernet`` (read-only; counters + state)
 *   - ``/interfaces/bridges`` (CRUD via Pending Changes stage)
 *   - ``/interfaces/list`` filtered to wireless types (read-only + toggle)
 */
import { useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  CheckCircle,
  Loader2,
  Pencil,
  Plus,
  RefreshCw,
  Trash2,
  Wifi,
  XCircle,
} from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { EmptyState, ErrorState } from '@/components/ui/empty-state';
import { useToast } from '@/hooks/use-toast';
import {
  getApiErrorMessage,
  mikrotikApi,
  type MikroTikBridgeInterface,
  type MikroTikEthernetInterface,
  type MikroTikGenericInterface,
} from '@/lib/api';

export interface MikroTikInterfacesTabProps {
  controllerId: string;
  isActive: boolean;
  /** Display name of the controller, surfaced in error toasts. */
  gatewayName?: string;
}

const ETHERNET_KEY = (cid: string) => ['mikrotik', cid, 'ethernet'];
const BRIDGES_KEY = (cid: string) => ['mikrotik', cid, 'bridges'];
const ALL_IFACE_KEY = (cid: string) => ['mikrotik', cid, 'interfaces'];

function fmtNumber(value: unknown): string {
  if (value === undefined || value === null || value === '') return '-';
  const num = typeof value === 'number' ? value : Number(value);
  if (!Number.isFinite(num)) return String(value);
  return num.toLocaleString();
}

function asBool(value: unknown): boolean {
  if (typeof value === 'boolean') return value;
  if (typeof value === 'string') return value === 'true' || value === 'yes';
  return false;
}

/**
 * RouterOS marks ``disabled`` as the canonical truth, not ``enabled``.
 * Treat a row as enabled when ``disabled`` is falsy.
 */
function isEnabled(row: { disabled?: unknown }): boolean {
  return !asBool(row.disabled);
}

function isRunning(row: { running?: unknown }): boolean {
  return asBool(row.running);
}

function asStr(value: unknown): string {
  if (value === undefined || value === null) return '-';
  if (typeof value === 'string') return value || '-';
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  return '-';
}

type BridgeFormState = { name: string; comment: string; mtu: string };

const BLANK_BRIDGE: BridgeFormState = { name: '', comment: '', mtu: '' };

export function MikroTikInterfacesTab({
  controllerId,
  isActive,
  gatewayName,
}: MikroTikInterfacesTabProps) {
  const { t } = useTranslation('firewall');
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const ctx = gatewayName ? `${gatewayName}: ` : '';
  const [bridgeFormOpen, setBridgeFormOpen] = useState(false);
  const [editingBridge, setEditingBridge] = useState<MikroTikBridgeInterface | null>(null);
  const [bridgeForm, setBridgeForm] = useState<BridgeFormState>(BLANK_BRIDGE);
  const [deleteTarget, setDeleteTarget] = useState<MikroTikBridgeInterface | null>(null);
  /**
   * wireless enable/disable toggle confirmation.
   *
   * Holds the in-flight row (and the action verb) so we can render a
   * shadcn AlertDialog instead of using `window.confirm` (which doesn't
   * match the design system + can't be styled or i18n'd).
   */
  const [toggleTarget, setToggleTarget] = useState<{
    id: string;
    name: string;
    enabled: boolean;
  } | null>(null);

  const ethernet = useQuery({
    queryKey: ETHERNET_KEY(controllerId),
    queryFn: () => mikrotikApi.getEthernet(controllerId),
    enabled: !!controllerId && isActive,
    refetchInterval: 30_000,
  });

  const bridges = useQuery({
    queryKey: BRIDGES_KEY(controllerId),
    queryFn: () => mikrotikApi.getBridges(controllerId),
    enabled: !!controllerId && isActive,
    refetchInterval: 60_000,
  });

  const allInterfaces = useQuery({
    queryKey: ALL_IFACE_KEY(controllerId),
    queryFn: () => mikrotikApi.getAllInterfaces(controllerId),
    enabled: !!controllerId && isActive,
    refetchInterval: 60_000,
  });

  const ethRows: MikroTikEthernetInterface[] = ethernet.data?.data.items ?? [];
  const bridgeRows: MikroTikBridgeInterface[] = bridges.data?.data.items ?? [];

  // Wireless rows · filter the global ``/list`` for wireless-like type.
  //
  // MEDIUM-7: use `startsWith` for the wlan family (and explicit
  // `wireless` / `wifi` namespaces) so we don't accidentally match
  // ``vlan`` (substring `lan`) or pull in virtual `*-virtual` shadow
  // interfaces RouterOS creates for guest networks.
  const wirelessRows: MikroTikGenericInterface[] = useMemo(() => {
    const rows = allInterfaces.data?.data.items ?? [];
    return rows.filter((row) => {
      const t = typeof row.type === 'string' ? row.type.toLowerCase() : '';
      if (t.endsWith('-virtual')) return false;
      return t.startsWith('wlan') || t.startsWith('wireless') || t.startsWith('wifi');
    });
  }, [allInterfaces.data]);

  // ── Mutations ────────────────────────────────────────────────────
  const createBridgeMut = useMutation({
    mutationFn: (payload: Record<string, unknown>) =>
      mikrotikApi.createBridge(controllerId, payload),
    onSuccess: () => {
      toast({ title: t('MikroTikInterfacesTab.toasts.bridgeCreateStaged') });
      setBridgeFormOpen(false);
      queryClient.invalidateQueries({ queryKey: BRIDGES_KEY(controllerId) });
    },
    onError: (err) =>
      toast({
        title: `${ctx}${t('MikroTikInterfacesTab.toasts.bridgeCreateFailed')}`,
        description: getApiErrorMessage(err),
        variant: 'destructive',
      }),
  });

  const updateBridgeMut = useMutation({
    mutationFn: ({ id, payload }: { id: string; payload: Record<string, unknown> }) =>
      mikrotikApi.updateBridge(controllerId, id, payload),
    onSuccess: () => {
      toast({ title: t('MikroTikInterfacesTab.toasts.bridgeUpdateStaged') });
      setBridgeFormOpen(false);
      queryClient.invalidateQueries({ queryKey: BRIDGES_KEY(controllerId) });
    },
    onError: (err) =>
      toast({
        title: `${ctx}${t('MikroTikInterfacesTab.toasts.bridgeUpdateFailed')}`,
        description: getApiErrorMessage(err),
        variant: 'destructive',
      }),
  });

  const deleteBridgeMut = useMutation({
    mutationFn: (id: string) => mikrotikApi.deleteBridge(controllerId, id),
    onSuccess: () => {
      toast({ title: t('MikroTikInterfacesTab.toasts.bridgeDeleteStaged') });
      setDeleteTarget(null);
      queryClient.invalidateQueries({ queryKey: BRIDGES_KEY(controllerId) });
    },
    onError: (err) =>
      toast({
        title: `${ctx}${t('MikroTikInterfacesTab.toasts.bridgeDeleteFailed')}`,
        description: getApiErrorMessage(err),
        variant: 'destructive',
      }),
  });

  const toggleMut = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      mikrotikApi.toggleInterface(controllerId, id, enabled),
    onSuccess: () => {
      toast({ title: t('MikroTikInterfacesTab.toasts.toggleStaged') });
      setToggleTarget(null);
      queryClient.invalidateQueries({ queryKey: ALL_IFACE_KEY(controllerId) });
      queryClient.invalidateQueries({ queryKey: ETHERNET_KEY(controllerId) });
    },
    onError: (err) =>
      toast({
        title: `${ctx}${t('MikroTikInterfacesTab.toasts.toggleFailed')}`,
        description: getApiErrorMessage(err),
        variant: 'destructive',
      }),
  });

  // ── Dialog helpers ───────────────────────────────────────────────
  function openNewBridge() {
    setEditingBridge(null);
    setBridgeForm(BLANK_BRIDGE);
    setBridgeFormOpen(true);
  }

  function openEditBridge(row: MikroTikBridgeInterface) {
    setEditingBridge(row);
    setBridgeForm({
      name: typeof row.name === 'string' ? row.name : '',
      comment: typeof row.comment === 'string' ? row.comment : '',
      mtu:
        row.mtu !== undefined && row.mtu !== null && row.mtu !== ''
          ? String(row.mtu)
          : '',
    });
    setBridgeFormOpen(true);
  }

  function submitBridge() {
    const payload: Record<string, unknown> = {
      name: bridgeForm.name.trim(),
    };
    if (bridgeForm.comment.trim()) payload.comment = bridgeForm.comment.trim();
    if (bridgeForm.mtu.trim()) payload.mtu = bridgeForm.mtu.trim();

    if (editingBridge) {
      const id = (editingBridge['.id'] as string | undefined) ?? '';
      if (!id) {
        toast({
          title: t('MikroTikInterfacesTab.toasts.cannotUpdateTitle'),
          description: t('MikroTikInterfacesTab.toasts.missingIdDescription'),
          variant: 'destructive',
        });
        return;
      }
      updateBridgeMut.mutate({ id, payload });
    } else {
      createBridgeMut.mutate(payload);
    }
  }

  function confirmDeleteBridge(row: MikroTikBridgeInterface) {
    setDeleteTarget(row);
  }

  // ── Render ───────────────────────────────────────────────────────
  if (ethernet.isLoading && bridges.isLoading && allInterfaces.isLoading) {
    return (
      <div className="flex items-center justify-center py-16 text-muted-foreground">
        <Loader2 className="h-5 w-5 animate-spin mr-2" />
        {t('MikroTikInterfacesTab.loading')}
      </div>
    );
  }

  // per-card `<ErrorState>` is the single source of error UI.
  // The previous global "one or more failed" banner duplicated info that
  // was already visible per-card and added a destructive-styled bar even
  // when only one of three queries failed.
  const anyFetching =
    ethernet.isFetching || bridges.isFetching || allInterfaces.isFetching;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-end">
        <Button
          variant="outline"
          size="sm"
          disabled={anyFetching}
          onClick={() => {
            ethernet.refetch();
            bridges.refetch();
            allInterfaces.refetch();
          }}
        >
          {anyFetching ? (
            <Loader2 className="h-4 w-4 animate-spin mr-1" />
          ) : (
            <RefreshCw className="h-4 w-4 mr-1" />
          )}
          {t('MikroTikInterfacesTab.actions.refresh')}
        </Button>
      </div>

      {/* Ethernet */}
      <Card className="border-border/50">
        <CardHeader className="pb-4">
          <CardTitle>{t('MikroTikInterfacesTab.ethernet.title')}</CardTitle>
          <CardDescription>{t('MikroTikInterfacesTab.ethernet.description')}</CardDescription>
        </CardHeader>
        <CardContent>
          {ethernet.isError ? (
            <ErrorState
              message={getApiErrorMessage(ethernet.error, t('MikroTikInterfacesTab.ethernet.loadError'))}
              onRetry={() => ethernet.refetch()}
            />
          ) : ethRows.length === 0 && !ethernet.isLoading ? (
            <EmptyState
              variant="compact"
              title={t('MikroTikInterfacesTab.ethernet.emptyTitle')}
              description={t('MikroTikInterfacesTab.ethernet.emptyDescription')}
            />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b text-left text-muted-foreground">
                    <th className="px-3 py-2 font-medium">{t('MikroTikInterfacesTab.columns.name')}</th>
                    <th className="px-3 py-2 font-medium">{t('MikroTikInterfacesTab.columns.mac')}</th>
                    <th className="px-3 py-2 font-medium">{t('MikroTikInterfacesTab.columns.mtu')}</th>
                    <th className="px-3 py-2 font-medium">{t('MikroTikInterfacesTab.columns.running')}</th>
                    <th className="px-3 py-2 font-medium">{t('MikroTikInterfacesTab.columns.enabled')}</th>
                    <th className="px-3 py-2 font-medium text-right">{t('MikroTikInterfacesTab.columns.rxBytes')}</th>
                    <th className="px-3 py-2 font-medium text-right">{t('MikroTikInterfacesTab.columns.txBytes')}</th>
                    <th className="px-3 py-2 font-medium">{t('MikroTikInterfacesTab.columns.comment')}</th>
                  </tr>
                </thead>
                <tbody>
                  {ethRows.map((row) => (
                    <tr key={(row['.id'] as string) ?? row.name ?? Math.random()} className="border-b last:border-0">
                      <td className="px-3 py-2 font-medium">{asStr(row.name)}</td>
                      <td className="px-3 py-2 font-mono text-xs">{asStr(row['mac-address'])}</td>
                      <td className="px-3 py-2">{asStr(row.mtu)}</td>
                      <td className="px-3 py-2">
                        {isRunning(row) ? (
                          <CheckCircle className="h-4 w-4 text-green-600" />
                        ) : (
                          <XCircle className="h-4 w-4 text-muted-foreground" />
                        )}
                      </td>
                      <td className="px-3 py-2">
                        <Badge variant={isEnabled(row) ? 'default' : 'secondary'}>
                          {isEnabled(row) ? t('MikroTikInterfacesTab.common.yes') : t('MikroTikInterfacesTab.common.no')}
                        </Badge>
                      </td>
                      <td className="px-3 py-2 text-right font-mono">{fmtNumber(row['rx-byte'])}</td>
                      <td className="px-3 py-2 text-right font-mono">{fmtNumber(row['tx-byte'])}</td>
                      <td className="px-3 py-2 text-xs text-muted-foreground">{asStr(row.comment)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Bridges */}
      <Card className="border-border/50">
        <CardHeader className="pb-4">
          <div className="flex items-center justify-between">
            <div>
              <CardTitle>{t('MikroTikInterfacesTab.bridges.title')}</CardTitle>
              <CardDescription>
                {t('MikroTikInterfacesTab.bridges.description')}
              </CardDescription>
            </div>
            <Button size="sm" onClick={openNewBridge}>
              <Plus className="h-4 w-4 mr-1" /> {t('MikroTikInterfacesTab.actions.addBridge')}
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          {bridges.isError ? (
            <ErrorState
              message={getApiErrorMessage(bridges.error, t('MikroTikInterfacesTab.bridges.loadError'))}
              onRetry={() => bridges.refetch()}
            />
          ) : bridgeRows.length === 0 && !bridges.isLoading ? (
            <EmptyState
              variant="compact"
              title={t('MikroTikInterfacesTab.bridges.emptyTitle')}
              description={t('MikroTikInterfacesTab.bridges.emptyDescription')}
              action={{ label: t('MikroTikInterfacesTab.actions.addBridge'), onClick: openNewBridge, icon: Plus }}
            />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b text-left text-muted-foreground">
                    <th className="px-3 py-2 font-medium">{t('MikroTikInterfacesTab.columns.name')}</th>
                    <th className="px-3 py-2 font-medium">{t('MikroTikInterfacesTab.columns.mac')}</th>
                    <th className="px-3 py-2 font-medium">{t('MikroTikInterfacesTab.columns.protocol')}</th>
                    <th className="px-3 py-2 font-medium">{t('MikroTikInterfacesTab.columns.mtu')}</th>
                    <th className="px-3 py-2 font-medium">{t('MikroTikInterfacesTab.columns.vlanFiltering')}</th>
                    <th className="px-3 py-2 font-medium">{t('MikroTikInterfacesTab.columns.running')}</th>
                    <th className="px-3 py-2 font-medium">{t('MikroTikInterfacesTab.columns.enabled')}</th>
                    <th className="px-3 py-2 font-medium">{t('MikroTikInterfacesTab.columns.comment')}</th>
                    <th className="px-3 py-2 font-medium text-right">{t('MikroTikInterfacesTab.columns.actions')}</th>
                  </tr>
                </thead>
                <tbody>
                  {bridgeRows.map((row) => {
                    const id = (row['.id'] as string | undefined) ?? '';
                    const bridgeLabel = asStr(row.name) !== '-' ? asStr(row.name) : id || 'bridge';
                    return (
                      <tr key={id || row.name || Math.random()} className="border-b last:border-0">
                        <td className="px-3 py-2 font-medium">{asStr(row.name)}</td>
                        <td className="px-3 py-2 font-mono text-xs">{asStr(row['mac-address'])}</td>
                        <td className="px-3 py-2">{asStr(row.protocol)}</td>
                        <td className="px-3 py-2">{asStr(row.mtu)}</td>
                        <td className="px-3 py-2">
                          <Badge variant={asBool(row['vlan-filtering']) ? 'default' : 'secondary'}>
                            {asBool(row['vlan-filtering']) ? t('MikroTikInterfacesTab.common.on') : t('MikroTikInterfacesTab.common.off')}
                          </Badge>
                        </td>
                        <td className="px-3 py-2">
                          {isRunning(row) ? (
                            <CheckCircle className="h-4 w-4 text-green-600" />
                          ) : (
                            <XCircle className="h-4 w-4 text-muted-foreground" />
                          )}
                        </td>
                        <td className="px-3 py-2">
                          <Badge variant={isEnabled(row) ? 'default' : 'secondary'}>
                            {isEnabled(row) ? t('MikroTikInterfacesTab.common.yes') : t('MikroTikInterfacesTab.common.no')}
                          </Badge>
                        </td>
                        <td className="px-3 py-2 text-xs text-muted-foreground">{asStr(row.comment)}</td>
                        <td className="px-3 py-2 text-right">
                          <div className="flex items-center gap-1 justify-end">
                            <Button
                              variant="ghost"
                              size="sm"
                              aria-label={t('MikroTikInterfacesTab.actions.editBridgeAria', { name: bridgeLabel })}
                              onClick={() => openEditBridge(row)}
                            >
                              <Pencil className="h-3.5 w-3.5" aria-hidden="true" />
                            </Button>
                            <Button
                              variant="ghost"
                              size="sm"
                              disabled={!id}
                              aria-label={t('MikroTikInterfacesTab.actions.deleteBridgeAria', { name: bridgeLabel })}
                              onClick={() => confirmDeleteBridge(row)}
                            >
                              <Trash2 className="h-3.5 w-3.5 text-destructive" aria-hidden="true" />
                            </Button>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Wireless */}
      <Card className="border-border/50">
        <CardHeader className="pb-4">
          <CardTitle className="flex items-center gap-2">
            <Wifi className="h-4 w-4" /> {t('MikroTikInterfacesTab.wireless.title')}
          </CardTitle>
          <CardDescription>
            {t('MikroTikInterfacesTab.wireless.description')}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {allInterfaces.isError ? (
            <ErrorState
              message={getApiErrorMessage(allInterfaces.error, t('MikroTikInterfacesTab.wireless.loadError'))}
              onRetry={() => allInterfaces.refetch()}
            />
          ) : wirelessRows.length === 0 && !allInterfaces.isLoading ? (
            <EmptyState
              variant="compact"
              title={t('MikroTikInterfacesTab.wireless.emptyTitle')}
              description={t('MikroTikInterfacesTab.wireless.emptyDescription')}
            />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b text-left text-muted-foreground">
                    <th className="px-3 py-2 font-medium">{t('MikroTikInterfacesTab.columns.name')}</th>
                    <th className="px-3 py-2 font-medium">{t('MikroTikInterfacesTab.columns.type')}</th>
                    <th className="px-3 py-2 font-medium">{t('MikroTikInterfacesTab.columns.mac')}</th>
                    <th className="px-3 py-2 font-medium">{t('MikroTikInterfacesTab.columns.mtu')}</th>
                    <th className="px-3 py-2 font-medium">{t('MikroTikInterfacesTab.columns.running')}</th>
                    <th className="px-3 py-2 font-medium">{t('MikroTikInterfacesTab.columns.enabled')}</th>
                    <th className="px-3 py-2 font-medium">{t('MikroTikInterfacesTab.columns.comment')}</th>
                    <th className="px-3 py-2 font-medium text-right">{t('MikroTikInterfacesTab.columns.actions')}</th>
                  </tr>
                </thead>
                <tbody>
                  {wirelessRows.map((row) => {
                    const id = (row['.id'] as string | undefined) ?? '';
                    const enabled = isEnabled(row);
                    return (
                      <tr key={id || row.name || Math.random()} className="border-b last:border-0">
                        <td className="px-3 py-2 font-medium">{asStr(row.name)}</td>
                        <td className="px-3 py-2">{asStr(row.type)}</td>
                        <td className="px-3 py-2 font-mono text-xs">{asStr(row['mac-address'])}</td>
                        <td className="px-3 py-2">{asStr(row.mtu)}</td>
                        <td className="px-3 py-2">
                          {isRunning(row) ? (
                            <CheckCircle className="h-4 w-4 text-green-600" />
                          ) : (
                            <XCircle className="h-4 w-4 text-muted-foreground" />
                          )}
                        </td>
                        <td className="px-3 py-2">
                          <Badge variant={enabled ? 'default' : 'secondary'}>
                            {enabled ? t('MikroTikInterfacesTab.common.yes') : t('MikroTikInterfacesTab.common.no')}
                          </Badge>
                        </td>
                        <td className="px-3 py-2 text-xs text-muted-foreground">{asStr(row.comment)}</td>
                        <td className="px-3 py-2 text-right">
                          <Button
                            variant="ghost"
                            size="sm"
                            disabled={!id || toggleMut.isPending}
                            onClick={() => {
                              if (!id) return;
                              // open shadcn AlertDialog instead
                              // of `window.confirm` so the prompt is
                              // styled + announced consistently with
                              // the rest of the UI.
                              setToggleTarget({
                                id,
                                name: asStr(row.name),
                                enabled,
                              });
                            }}
                          >
                            {toggleMut.isPending && toggleTarget?.id === id ? (
                              <Loader2 className="h-3.5 w-3.5 animate-spin" />
                            ) : enabled ? (
                              t('MikroTikInterfacesTab.actions.disable')
                            ) : (
                              t('MikroTikInterfacesTab.actions.enable')
                            )}
                          </Button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Bridge create/edit dialog */}
      <Dialog open={bridgeFormOpen} onOpenChange={setBridgeFormOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{editingBridge ? t('MikroTikInterfacesTab.bridgeDialog.editTitle') : t('MikroTikInterfacesTab.bridgeDialog.addTitle')}</DialogTitle>
            <DialogDescription>
              {t('MikroTikInterfacesTab.bridgeDialog.description')}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            <div className="space-y-2">
              <Label htmlFor="mikrotik-bridge-name">{t('MikroTikInterfacesTab.columns.name')}</Label>
              <Input
                id="mikrotik-bridge-name"
                value={bridgeForm.name}
                onChange={(e) => setBridgeForm((f) => ({ ...f, name: e.target.value }))}
                placeholder="bridge1"
                autoFocus
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="mikrotik-bridge-mtu">{t('MikroTikInterfacesTab.bridgeDialog.mtuLabel')}</Label>
              <Input
                id="mikrotik-bridge-mtu"
                value={bridgeForm.mtu}
                onChange={(e) => setBridgeForm((f) => ({ ...f, mtu: e.target.value }))}
                placeholder="1500"
                inputMode="numeric"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="mikrotik-bridge-comment">{t('MikroTikInterfacesTab.columns.comment')}</Label>
              <Input
                id="mikrotik-bridge-comment"
                value={bridgeForm.comment}
                onChange={(e) => setBridgeForm((f) => ({ ...f, comment: e.target.value }))}
                placeholder="LAN bridge"
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setBridgeFormOpen(false)}>
              {t('MikroTikInterfacesTab.actions.cancel')}
            </Button>
            <Button
              onClick={submitBridge}
              disabled={
                createBridgeMut.isPending ||
                updateBridgeMut.isPending ||
                bridgeForm.name.trim().length === 0
              }
            >
              {(createBridgeMut.isPending || updateBridgeMut.isPending) && (
                <Loader2 className="h-4 w-4 animate-spin mr-1" />
              )}
              {editingBridge ? t('MikroTikInterfacesTab.actions.stageUpdate') : t('MikroTikInterfacesTab.actions.stageCreate')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Bridge delete confirmation */}
      <Dialog
        open={deleteTarget !== null}
        onOpenChange={(open) => {
          if (!open) setDeleteTarget(null);
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t('MikroTikInterfacesTab.deleteDialog.title')}</DialogTitle>
            <DialogDescription>
              {t('MikroTikInterfacesTab.deleteDialog.descriptionPrefix')}{' '}
              <span className="font-mono">{asStr(deleteTarget?.name)}</span>
              {t('MikroTikInterfacesTab.deleteDialog.descriptionSuffix')}
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDeleteTarget(null)}>
              {t('MikroTikInterfacesTab.actions.cancel')}
            </Button>
            <Button
              variant="destructive"
              disabled={deleteBridgeMut.isPending}
              onClick={() => {
                const id = (deleteTarget?.['.id'] as string | undefined) ?? '';
                if (!id) {
                  toast({
                    title: t('MikroTikInterfacesTab.toasts.cannotDeleteTitle'),
                    description: t('MikroTikInterfacesTab.toasts.missingIdDescription'),
                    variant: 'destructive',
                  });
                  return;
                }
                deleteBridgeMut.mutate(id);
              }}
            >
              {deleteBridgeMut.isPending && (
                <Loader2 className="h-4 w-4 animate-spin mr-1" />
              )}
              {t('MikroTikInterfacesTab.actions.stageDelete')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Wireless toggle confirmation replaces window.confirm */}
      <Dialog
        open={toggleTarget !== null}
        onOpenChange={(open) => {
          if (!open) setToggleTarget(null);
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>
              {toggleTarget?.enabled
                ? t('MikroTikInterfacesTab.toggleDialog.disableTitle')
                : t('MikroTikInterfacesTab.toggleDialog.enableTitle')}
            </DialogTitle>
            <DialogDescription>
              {t('MikroTikInterfacesTab.toggleDialog.descriptionPrefix')}{' '}
              <span className="font-mono">{toggleTarget?.name ?? ''}</span>
              {t('MikroTikInterfacesTab.toggleDialog.descriptionSuffix')}
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setToggleTarget(null)}>
              {t('MikroTikInterfacesTab.actions.cancel')}
            </Button>
            <Button
              disabled={toggleMut.isPending}
              onClick={() => {
                if (!toggleTarget) return;
                toggleMut.mutate({
                  id: toggleTarget.id,
                  enabled: !toggleTarget.enabled,
                });
              }}
            >
              {toggleMut.isPending && (
                <Loader2 className="h-4 w-4 animate-spin mr-1" />
              )}
              {toggleTarget?.enabled ? t('MikroTikInterfacesTab.actions.stageDisable') : t('MikroTikInterfacesTab.actions.stageEnable')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

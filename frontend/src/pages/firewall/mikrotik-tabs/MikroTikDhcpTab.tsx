// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * MikroTikDhcpTab · DHCP servers, live leases, static mappings.
 *
 * - Servers: full CRUD via stage (``mikrotik.dhcp.server``).
 * - Leases: read-only with a "Make static" action that stages a
 *   ``mikrotik.dhcp.lease_static`` create. We filter the leases
 *   endpoint client-side: dynamic rows → Leases table, static rows →
 *   Static mappings table (RouterOS surfaces both via /ip/dhcp-server/lease).
 * - Static mappings: full CRUD via stage (``mikrotik.dhcp.lease_static``).
 */
import { useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  Database,
  Loader2,
  Pencil,
  Pin,
  Plus,
  RefreshCw,
  Trash2,
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
  type MikroTikDHCPLease,
  type MikroTikDHCPServer,
} from '@/lib/api';
import { IpInput, MacInput, isValidIp, isValidMac } from './_shared';

export interface MikroTikDhcpTabProps {
  controllerId: string;
  isActive: boolean;
  /** Display name of the controller, surfaced in error toasts. */
  gatewayName?: string;
}

const SERVERS_KEY = (cid: string) => ['mikrotik', cid, 'dhcp-servers'];
const LEASES_KEY = (cid: string) => ['mikrotik', cid, 'dhcp-leases'];

type ServerForm = {
  name: string;
  iface: string;
  pool: string;
  leaseTime: string;
  comment: string;
};

type StaticForm = {
  address: string;
  mac: string;
  server: string;
  comment: string;
};

const BLANK_SERVER: ServerForm = {
  name: '',
  iface: '',
  pool: '',
  leaseTime: '',
  comment: '',
};

const BLANK_STATIC: StaticForm = {
  address: '',
  mac: '',
  server: '',
  comment: '',
};

function asStr(value: unknown): string {
  if (value === undefined || value === null) return '-';
  if (typeof value === 'string') return value || '-';
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  return '-';
}

function asBool(value: unknown): boolean {
  if (typeof value === 'boolean') return value;
  if (typeof value === 'string') return value === 'true' || value === 'yes';
  return false;
}

type DeleteTarget =
  | { kind: 'server'; row: MikroTikDHCPServer }
  | { kind: 'static'; row: MikroTikDHCPLease };

export function MikroTikDhcpTab({ controllerId, isActive, gatewayName }: MikroTikDhcpTabProps) {
  const { t } = useTranslation('firewall');
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const ctx = gatewayName ? `${gatewayName}: ` : '';

  const [serverFormOpen, setServerFormOpen] = useState(false);
  const [editingServer, setEditingServer] = useState<MikroTikDHCPServer | null>(null);
  const [serverForm, setServerForm] = useState<ServerForm>(BLANK_SERVER);

  const [staticFormOpen, setStaticFormOpen] = useState(false);
  const [editingStatic, setEditingStatic] = useState<MikroTikDHCPLease | null>(null);
  const [staticForm, setStaticForm] = useState<StaticForm>(BLANK_STATIC);

  const [deleteTarget, setDeleteTarget] = useState<DeleteTarget | null>(null);
  /**
   * "Make static" confirmation target.
   *
   * Replaces the old `window.confirm` flow with a shadcn AlertDialog so
   * the prompt matches the rest of the design system and isn't blocked
   * by browser-level pop-up disablement.
   */
  const [makeStaticTarget, setMakeStaticTarget] = useState<MikroTikDHCPLease | null>(null);

  const servers = useQuery({
    queryKey: SERVERS_KEY(controllerId),
    queryFn: () => mikrotikApi.getDHCPServers(controllerId),
    enabled: !!controllerId && isActive,
    refetchInterval: 60_000,
  });

  const leases = useQuery({
    queryKey: LEASES_KEY(controllerId),
    queryFn: () => mikrotikApi.getDHCPLeases(controllerId),
    enabled: !!controllerId && isActive,
    refetchInterval: 30_000,
  });

  const serverRows: MikroTikDHCPServer[] = servers.data?.data.items ?? [];
  // Memoise so dependent useMemos receive a stable reference between
  // renders (silences the react-hooks/exhaustive-deps warning).
  const allLeases: MikroTikDHCPLease[] = useMemo(
    () => leases.data?.data.items ?? [],
    [leases.data],
  );

  const dynamicLeases = useMemo(
    () => allLeases.filter((row) => asBool(row.dynamic)),
    [allLeases],
  );
  const staticLeases = useMemo(
    () => allLeases.filter((row) => !asBool(row.dynamic)),
    [allLeases],
  );

  // ── Mutations ────────────────────────────────────────────────────
  const createServerMut = useMutation({
    mutationFn: (payload: Record<string, unknown>) =>
      mikrotikApi.createDHCPServer(controllerId, payload),
    onSuccess: () => {
      toast({ title: t('MikroTikDhcpTab.toasts.serverCreateStaged') });
      setServerFormOpen(false);
      queryClient.invalidateQueries({ queryKey: SERVERS_KEY(controllerId) });
    },
    onError: (err) =>
      toast({
        title: `${ctx}${t('MikroTikDhcpTab.toasts.serverCreateFailed')}`,
        description: getApiErrorMessage(err),
        variant: 'destructive',
      }),
  });

  const updateServerMut = useMutation({
    mutationFn: ({ id, payload }: { id: string; payload: Record<string, unknown> }) =>
      mikrotikApi.updateDHCPServer(controllerId, id, payload),
    onSuccess: () => {
      toast({ title: t('MikroTikDhcpTab.toasts.serverUpdateStaged') });
      setServerFormOpen(false);
      queryClient.invalidateQueries({ queryKey: SERVERS_KEY(controllerId) });
    },
    onError: (err) =>
      toast({
        title: `${ctx}${t('MikroTikDhcpTab.toasts.serverUpdateFailed')}`,
        description: getApiErrorMessage(err),
        variant: 'destructive',
      }),
  });

  const deleteServerMut = useMutation({
    mutationFn: (id: string) => mikrotikApi.deleteDHCPServer(controllerId, id),
    onSuccess: () => {
      toast({ title: t('MikroTikDhcpTab.toasts.serverDeleteStaged') });
      setDeleteTarget(null);
      queryClient.invalidateQueries({ queryKey: SERVERS_KEY(controllerId) });
    },
    onError: (err) =>
      toast({
        title: `${ctx}${t('MikroTikDhcpTab.toasts.serverDeleteFailed')}`,
        description: getApiErrorMessage(err),
        variant: 'destructive',
      }),
  });

  const makeStaticMut = useMutation({
    mutationFn: (lease: MikroTikDHCPLease) =>
      mikrotikApi.makeLeaseStatic(controllerId, {
        'mac-address':
          typeof lease['mac-address'] === 'string' ? lease['mac-address'] : undefined,
        address: typeof lease.address === 'string' ? lease.address : undefined,
        server: typeof lease.server === 'string' ? lease.server : undefined,
        'host-name':
          typeof lease['host-name'] === 'string' ? lease['host-name'] : undefined,
        comment: typeof lease.comment === 'string' ? lease.comment : undefined,
      }),
    onSuccess: () => {
      toast({ title: t('MikroTikDhcpTab.toasts.staticCreateStaged') });
      setMakeStaticTarget(null);
      queryClient.invalidateQueries({ queryKey: LEASES_KEY(controllerId) });
    },
    onError: (err) =>
      toast({
        title: `${ctx}${t('MikroTikDhcpTab.toasts.staticCreateFailed')}`,
        description: getApiErrorMessage(err),
        variant: 'destructive',
      }),
  });

  const createStaticMut = useMutation({
    mutationFn: (payload: Record<string, unknown>) =>
      mikrotikApi.createStaticLease(controllerId, payload),
    onSuccess: () => {
      toast({ title: t('MikroTikDhcpTab.toasts.staticCreateStaged') });
      setStaticFormOpen(false);
      queryClient.invalidateQueries({ queryKey: LEASES_KEY(controllerId) });
    },
    onError: (err) =>
      toast({
        title: `${ctx}${t('MikroTikDhcpTab.toasts.staticCreateFailed')}`,
        description: getApiErrorMessage(err),
        variant: 'destructive',
      }),
  });

  const updateStaticMut = useMutation({
    mutationFn: ({ id, payload }: { id: string; payload: Record<string, unknown> }) =>
      mikrotikApi.updateStaticLease(controllerId, id, payload),
    onSuccess: () => {
      toast({ title: t('MikroTikDhcpTab.toasts.staticUpdateStaged') });
      setStaticFormOpen(false);
      queryClient.invalidateQueries({ queryKey: LEASES_KEY(controllerId) });
    },
    onError: (err) =>
      toast({
        title: `${ctx}${t('MikroTikDhcpTab.toasts.staticUpdateFailed')}`,
        description: getApiErrorMessage(err),
        variant: 'destructive',
      }),
  });

  const deleteStaticMut = useMutation({
    mutationFn: (id: string) => mikrotikApi.deleteStaticLease(controllerId, id),
    onSuccess: () => {
      toast({ title: t('MikroTikDhcpTab.toasts.staticDeleteStaged') });
      setDeleteTarget(null);
      queryClient.invalidateQueries({ queryKey: LEASES_KEY(controllerId) });
    },
    onError: (err) =>
      toast({
        title: `${ctx}${t('MikroTikDhcpTab.toasts.staticDeleteFailed')}`,
        description: getApiErrorMessage(err),
        variant: 'destructive',
      }),
  });

  // ── Form helpers ─────────────────────────────────────────────────
  function openNewServer() {
    setEditingServer(null);
    setServerForm(BLANK_SERVER);
    setServerFormOpen(true);
  }

  function openEditServer(row: MikroTikDHCPServer) {
    setEditingServer(row);
    setServerForm({
      name: typeof row.name === 'string' ? row.name : '',
      iface: typeof row.interface === 'string' ? row.interface : '',
      pool: typeof row['address-pool'] === 'string' ? row['address-pool'] : '',
      leaseTime: typeof row['lease-time'] === 'string' ? row['lease-time'] : '',
      comment: typeof row.comment === 'string' ? row.comment : '',
    });
    setServerFormOpen(true);
  }

  function submitServer() {
    const trimmed = {
      name: serverForm.name.trim(),
      iface: serverForm.iface.trim(),
      pool: serverForm.pool.trim(),
      leaseTime: serverForm.leaseTime.trim(),
      comment: serverForm.comment.trim(),
    };
    if (!trimmed.name || !trimmed.iface) return;
    const payload: Record<string, unknown> = {
      name: trimmed.name,
      interface: trimmed.iface,
    };
    if (trimmed.pool) payload['address-pool'] = trimmed.pool;
    if (trimmed.leaseTime) payload['lease-time'] = trimmed.leaseTime;
    if (trimmed.comment) payload.comment = trimmed.comment;

    if (editingServer) {
      const id = (editingServer['.id'] as string | undefined) ?? '';
      if (!id) {
        toast({
          title: t('MikroTikDhcpTab.toasts.cannotUpdateServer'),
          description: t('MikroTikDhcpTab.toasts.serverMissingId'),
          variant: 'destructive',
        });
        return;
      }
      updateServerMut.mutate({ id, payload });
    } else {
      createServerMut.mutate(payload);
    }
  }

  function openNewStatic() {
    setEditingStatic(null);
    setStaticForm(BLANK_STATIC);
    setStaticFormOpen(true);
  }

  function openEditStatic(row: MikroTikDHCPLease) {
    setEditingStatic(row);
    setStaticForm({
      address: typeof row.address === 'string' ? row.address : '',
      mac: typeof row['mac-address'] === 'string' ? row['mac-address'] : '',
      server: typeof row.server === 'string' ? row.server : '',
      comment: typeof row.comment === 'string' ? row.comment : '',
    });
    setStaticFormOpen(true);
  }

  function submitStatic() {
    const trimmed = {
      address: staticForm.address.trim(),
      mac: staticForm.mac.trim(),
      server: staticForm.server.trim(),
      comment: staticForm.comment.trim(),
    };
    if (!trimmed.address || !trimmed.mac) return;
    const payload: Record<string, unknown> = {
      address: trimmed.address,
      'mac-address': trimmed.mac,
    };
    if (trimmed.server) payload.server = trimmed.server;
    if (trimmed.comment) payload.comment = trimmed.comment;

    if (editingStatic) {
      const id = (editingStatic['.id'] as string | undefined) ?? '';
      if (!id) {
        toast({
          title: t('MikroTikDhcpTab.toasts.cannotUpdateLease'),
          description: t('MikroTikDhcpTab.toasts.leaseMissingId'),
          variant: 'destructive',
        });
        return;
      }
      updateStaticMut.mutate({ id, payload });
    } else {
      createStaticMut.mutate(payload);
    }
  }

  function submitDelete() {
    if (!deleteTarget) return;
    const id = (deleteTarget.row['.id'] as string | undefined) ?? '';
    if (!id) {
      toast({
        title: t('MikroTikDhcpTab.toasts.cannotDelete'),
        description: t('MikroTikDhcpTab.toasts.rowMissingId'),
        variant: 'destructive',
      });
      return;
    }
    if (deleteTarget.kind === 'server') deleteServerMut.mutate(id);
    else deleteStaticMut.mutate(id);
  }

  if (servers.isLoading && leases.isLoading) {
    return (
      <div className="flex items-center justify-center py-16 text-muted-foreground">
        <Loader2 className="h-5 w-5 animate-spin mr-2" />
        {t('MikroTikDhcpTab.loading')}
      </div>
    );
  }

  const deleteLabel = (() => {
    if (!deleteTarget) return '';
    if (deleteTarget.kind === 'server')
      return t('MikroTikDhcpTab.deleteLabel.server', {
        name: asStr((deleteTarget.row as MikroTikDHCPServer).name),
      });
    const r = deleteTarget.row as MikroTikDHCPLease;
    return t('MikroTikDhcpTab.deleteLabel.static', {
      address: asStr(r.address),
      mac: asStr(r['mac-address']),
    });
  })();

  const anyFetching = servers.isFetching || leases.isFetching;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-end">
        <Button
          variant="outline"
          size="sm"
          disabled={anyFetching}
          onClick={() => {
            servers.refetch();
            leases.refetch();
          }}
        >
          {anyFetching ? (
            <Loader2 className="h-4 w-4 animate-spin mr-1" />
          ) : (
            <RefreshCw className="h-4 w-4 mr-1" />
          )}
          {t('MikroTikDhcpTab.actions.refresh')}
        </Button>
      </div>

      {/* Servers */}
      <Card className="border-border/50">
        <CardHeader className="pb-4">
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="flex items-center gap-2">
                <Database className="h-4 w-4" /> {t('MikroTikDhcpTab.servers.title')}
              </CardTitle>
              <CardDescription>{t('MikroTikDhcpTab.servers.description')}</CardDescription>
            </div>
            <Button size="sm" onClick={openNewServer}>
              <Plus className="h-4 w-4 mr-1" /> {t('MikroTikDhcpTab.servers.add')}
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          {servers.isError ? (
            <ErrorState
              message={getApiErrorMessage(servers.error, t('MikroTikDhcpTab.servers.loadError'))}
              onRetry={() => servers.refetch()}
            />
          ) : serverRows.length === 0 && !servers.isLoading ? (
            <EmptyState
              variant="compact"
              title={t('MikroTikDhcpTab.servers.emptyTitle')}
              description={t('MikroTikDhcpTab.servers.emptyDescription')}
              action={{ label: t('MikroTikDhcpTab.servers.add'), icon: Plus, onClick: openNewServer }}
            />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b text-left text-muted-foreground">
                    <th className="px-3 py-2 font-medium">{t('MikroTikDhcpTab.serverColumns.name')}</th>
                    <th className="px-3 py-2 font-medium">{t('MikroTikDhcpTab.serverColumns.interface')}</th>
                    <th className="px-3 py-2 font-medium">{t('MikroTikDhcpTab.serverColumns.pool')}</th>
                    <th className="px-3 py-2 font-medium">{t('MikroTikDhcpTab.serverColumns.leaseTime')}</th>
                    <th className="px-3 py-2 font-medium">{t('MikroTikDhcpTab.serverColumns.authoritative')}</th>
                    <th className="px-3 py-2 font-medium">{t('MikroTikDhcpTab.serverColumns.enabled')}</th>
                    <th className="px-3 py-2 font-medium">{t('MikroTikDhcpTab.serverColumns.comment')}</th>
                    <th className="px-3 py-2 font-medium text-right">{t('MikroTikDhcpTab.serverColumns.actions')}</th>
                  </tr>
                </thead>
                <tbody>
                  {serverRows.map((row) => {
                    const id = (row['.id'] as string | undefined) ?? '';
                    const enabled = !asBool(row.disabled);
                    const serverLabel =
                      asStr(row.name) !== '-'
                        ? asStr(row.name)
                        : id || t('MikroTikDhcpTab.servers.fallbackLabel');
                    return (
                      <tr key={id || row.name || Math.random()} className="border-b last:border-0">
                        <td className="px-3 py-2 font-medium">{asStr(row.name)}</td>
                        <td className="px-3 py-2">{asStr(row.interface)}</td>
                        <td className="px-3 py-2">{asStr(row['address-pool'])}</td>
                        <td className="px-3 py-2">{asStr(row['lease-time'])}</td>
                        <td className="px-3 py-2">
                          <Badge variant={asBool(row.authoritative) ? 'default' : 'secondary'}>
                            {asBool(row.authoritative)
                              ? t('MikroTikDhcpTab.common.yes')
                              : t('MikroTikDhcpTab.common.no')}
                          </Badge>
                        </td>
                        <td className="px-3 py-2">
                          <Badge variant={enabled ? 'default' : 'secondary'}>
                            {enabled
                              ? t('MikroTikDhcpTab.common.yes')
                              : t('MikroTikDhcpTab.common.no')}
                          </Badge>
                        </td>
                        <td className="px-3 py-2 text-xs text-muted-foreground">{asStr(row.comment)}</td>
                        <td className="px-3 py-2 text-right">
                          <div className="flex items-center gap-1 justify-end">
                            <Button
                              variant="ghost"
                              size="sm"
                              disabled={!id}
                              aria-label={t('MikroTikDhcpTab.servers.editAria', { label: serverLabel })}
                              onClick={() => openEditServer(row)}
                            >
                              <Pencil className="h-3.5 w-3.5" aria-hidden="true" />
                            </Button>
                            <Button
                              variant="ghost"
                              size="sm"
                              disabled={!id}
                              aria-label={t('MikroTikDhcpTab.servers.deleteAria', { label: serverLabel })}
                              onClick={() => setDeleteTarget({ kind: 'server', row })}
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

      {/* Dynamic leases (read-only + make static) */}
      <Card className="border-border/50">
        <CardHeader className="pb-4">
          <CardTitle>{t('MikroTikDhcpTab.leases.title')}</CardTitle>
          <CardDescription>
            {t('MikroTikDhcpTab.leases.description')}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {leases.isError ? (
            <ErrorState
              message={getApiErrorMessage(leases.error, t('MikroTikDhcpTab.leases.loadError'))}
              onRetry={() => leases.refetch()}
            />
          ) : dynamicLeases.length === 0 && !leases.isLoading ? (
            <EmptyState
              variant="compact"
              title={t('MikroTikDhcpTab.leases.emptyTitle')}
              description={t('MikroTikDhcpTab.leases.emptyDescription')}
            />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b text-left text-muted-foreground">
                    <th className="px-3 py-2 font-medium">{t('MikroTikDhcpTab.leaseColumns.ip')}</th>
                    <th className="px-3 py-2 font-medium">{t('MikroTikDhcpTab.leaseColumns.mac')}</th>
                    <th className="px-3 py-2 font-medium">{t('MikroTikDhcpTab.leaseColumns.hostname')}</th>
                    <th className="px-3 py-2 font-medium">{t('MikroTikDhcpTab.leaseColumns.server')}</th>
                    <th className="px-3 py-2 font-medium">{t('MikroTikDhcpTab.leaseColumns.status')}</th>
                    <th className="px-3 py-2 font-medium">{t('MikroTikDhcpTab.leaseColumns.expires')}</th>
                    <th className="px-3 py-2 font-medium text-right">{t('MikroTikDhcpTab.leaseColumns.actions')}</th>
                  </tr>
                </thead>
                <tbody>
                  {dynamicLeases.map((row) => {
                    const id = (row['.id'] as string | undefined) ?? '';
                    return (
                      <tr key={id || Math.random()} className="border-b last:border-0">
                        <td className="px-3 py-2 font-mono">{asStr(row.address)}</td>
                        <td className="px-3 py-2 font-mono text-xs">{asStr(row['mac-address'])}</td>
                        <td className="px-3 py-2">{asStr(row['host-name'])}</td>
                        <td className="px-3 py-2">{asStr(row.server)}</td>
                        <td className="px-3 py-2">
                          <Badge variant={row.status === 'bound' ? 'default' : 'secondary'}>
                            {asStr(row.status)}
                          </Badge>
                        </td>
                        <td className="px-3 py-2 text-xs">{asStr(row['expires-after'])}</td>
                        <td className="px-3 py-2 text-right">
                          <Button
                            variant="outline"
                            size="sm"
                            disabled={makeStaticMut.isPending}
                            onClick={() => {
                              // open shadcn dialog instead of
                              // `window.confirm` for design-system
                              // consistency.
                              setMakeStaticTarget(row);
                            }}
                          >
                            {makeStaticMut.isPending ? (
                              <Loader2 className="h-3.5 w-3.5 animate-spin" />
                            ) : (
                              <>
                                <Pin className="h-3.5 w-3.5 mr-1" /> {t('MikroTikDhcpTab.actions.makeStatic')}
                              </>
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

      {/* Static mappings */}
      <Card className="border-border/50">
        <CardHeader className="pb-4">
          <div className="flex items-center justify-between">
            <div>
              <CardTitle>{t('MikroTikDhcpTab.static.title')}</CardTitle>
              <CardDescription>
                {t('MikroTikDhcpTab.static.description')}
              </CardDescription>
            </div>
            <Button size="sm" onClick={openNewStatic}>
              <Plus className="h-4 w-4 mr-1" /> {t('MikroTikDhcpTab.static.add')}
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          {staticLeases.length === 0 && !leases.isLoading ? (
            <EmptyState
              variant="compact"
              title={t('MikroTikDhcpTab.static.emptyTitle')}
              description={t('MikroTikDhcpTab.static.emptyDescription')}
              action={{ label: t('MikroTikDhcpTab.static.add'), icon: Plus, onClick: openNewStatic }}
            />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b text-left text-muted-foreground">
                    <th className="px-3 py-2 font-medium">{t('MikroTikDhcpTab.staticColumns.ip')}</th>
                    <th className="px-3 py-2 font-medium">{t('MikroTikDhcpTab.staticColumns.mac')}</th>
                    <th className="px-3 py-2 font-medium">{t('MikroTikDhcpTab.staticColumns.server')}</th>
                    <th className="px-3 py-2 font-medium">{t('MikroTikDhcpTab.staticColumns.status')}</th>
                    <th className="px-3 py-2 font-medium">{t('MikroTikDhcpTab.staticColumns.comment')}</th>
                    <th className="px-3 py-2 font-medium text-right">{t('MikroTikDhcpTab.staticColumns.actions')}</th>
                  </tr>
                </thead>
                <tbody>
                  {staticLeases.map((row) => {
                    const id = (row['.id'] as string | undefined) ?? '';
                    const staticLabel =
                      asStr(row.address) !== '-'
                        ? `${asStr(row.address)} (${asStr(row['mac-address'])})`
                        : asStr(row['mac-address']) !== '-'
                          ? asStr(row['mac-address'])
                          : id || t('MikroTikDhcpTab.static.fallbackLabel');
                    return (
                      <tr key={id || Math.random()} className="border-b last:border-0">
                        <td className="px-3 py-2 font-mono">{asStr(row.address)}</td>
                        <td className="px-3 py-2 font-mono text-xs">{asStr(row['mac-address'])}</td>
                        <td className="px-3 py-2">{asStr(row.server)}</td>
                        <td className="px-3 py-2">
                          <Badge variant="secondary">{asStr(row.status)}</Badge>
                        </td>
                        <td className="px-3 py-2 text-xs text-muted-foreground">{asStr(row.comment)}</td>
                        <td className="px-3 py-2 text-right">
                          <div className="flex items-center gap-1 justify-end">
                            <Button
                              variant="ghost"
                              size="sm"
                              disabled={!id}
                              aria-label={t('MikroTikDhcpTab.static.editAria', { label: staticLabel })}
                              onClick={() => openEditStatic(row)}
                            >
                              <Pencil className="h-3.5 w-3.5" aria-hidden="true" />
                            </Button>
                            <Button
                              variant="ghost"
                              size="sm"
                              disabled={!id}
                              aria-label={t('MikroTikDhcpTab.static.deleteAria', { label: staticLabel })}
                              onClick={() => setDeleteTarget({ kind: 'static', row })}
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

      {/* Server form dialog */}
      <Dialog open={serverFormOpen} onOpenChange={setServerFormOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>
              {editingServer
                ? t('MikroTikDhcpTab.serverDialog.editTitle')
                : t('MikroTikDhcpTab.serverDialog.addTitle')}
            </DialogTitle>
            <DialogDescription>
              {t('MikroTikDhcpTab.serverDialog.description')}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            <div className="space-y-2">
              <Label htmlFor="mikrotik-dhcp-name">{t('MikroTikDhcpTab.serverForm.name')}</Label>
              <Input
                id="mikrotik-dhcp-name"
                value={serverForm.name}
                onChange={(e) => setServerForm((f) => ({ ...f, name: e.target.value }))}
                placeholder="dhcp-lan"
                autoFocus
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="mikrotik-dhcp-iface">{t('MikroTikDhcpTab.serverForm.interface')}</Label>
              <Input
                id="mikrotik-dhcp-iface"
                value={serverForm.iface}
                onChange={(e) => setServerForm((f) => ({ ...f, iface: e.target.value }))}
                placeholder="bridge1"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="mikrotik-dhcp-pool">{t('MikroTikDhcpTab.serverForm.pool')}</Label>
              <Input
                id="mikrotik-dhcp-pool"
                value={serverForm.pool}
                onChange={(e) => setServerForm((f) => ({ ...f, pool: e.target.value }))}
                placeholder="dhcp-pool"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="mikrotik-dhcp-lease">{t('MikroTikDhcpTab.serverForm.leaseTime')}</Label>
              <Input
                id="mikrotik-dhcp-lease"
                value={serverForm.leaseTime}
                onChange={(e) => setServerForm((f) => ({ ...f, leaseTime: e.target.value }))}
                placeholder="1d"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="mikrotik-dhcp-comment">{t('MikroTikDhcpTab.serverForm.comment')}</Label>
              <Input
                id="mikrotik-dhcp-comment"
                value={serverForm.comment}
                onChange={(e) => setServerForm((f) => ({ ...f, comment: e.target.value }))}
                placeholder=""
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setServerFormOpen(false)}>
              {t('MikroTikDhcpTab.actions.cancel')}
            </Button>
            <Button
              onClick={submitServer}
              disabled={
                createServerMut.isPending ||
                updateServerMut.isPending ||
                serverForm.name.trim().length === 0 ||
                serverForm.iface.trim().length === 0
              }
            >
              {(createServerMut.isPending || updateServerMut.isPending) && (
                <Loader2 className="h-4 w-4 animate-spin mr-1" />
              )}
              {editingServer
                ? t('MikroTikDhcpTab.actions.stageUpdate')
                : t('MikroTikDhcpTab.actions.stageCreate')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Static mapping dialog */}
      <Dialog open={staticFormOpen} onOpenChange={setStaticFormOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>
              {editingStatic
                ? t('MikroTikDhcpTab.staticDialog.editTitle')
                : t('MikroTikDhcpTab.staticDialog.addTitle')}
            </DialogTitle>
            <DialogDescription>
              {t('MikroTikDhcpTab.staticDialog.description')}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            <div className="space-y-2">
              <Label htmlFor="mikrotik-static-addr">{t('MikroTikDhcpTab.staticForm.address')}</Label>
              <IpInput
                id="mikrotik-static-addr"
                value={staticForm.address}
                onChange={(e) => setStaticForm((f) => ({ ...f, address: e.target.value }))}
                placeholder="192.168.88.50"
                autoFocus
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="mikrotik-static-mac">{t('MikroTikDhcpTab.staticForm.mac')}</Label>
              <MacInput
                id="mikrotik-static-mac"
                value={staticForm.mac}
                onChange={(e) => setStaticForm((f) => ({ ...f, mac: e.target.value }))}
                placeholder="aa:bb:cc:dd:ee:ff"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="mikrotik-static-server">{t('MikroTikDhcpTab.staticForm.server')}</Label>
              <Input
                id="mikrotik-static-server"
                value={staticForm.server}
                onChange={(e) => setStaticForm((f) => ({ ...f, server: e.target.value }))}
                placeholder="dhcp-lan"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="mikrotik-static-comment">{t('MikroTikDhcpTab.staticForm.comment')}</Label>
              <Input
                id="mikrotik-static-comment"
                value={staticForm.comment}
                onChange={(e) => setStaticForm((f) => ({ ...f, comment: e.target.value }))}
                placeholder=""
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setStaticFormOpen(false)}>
              {t('MikroTikDhcpTab.actions.cancel')}
            </Button>
            <Button
              onClick={submitStatic}
              disabled={
                createStaticMut.isPending ||
                updateStaticMut.isPending ||
                staticForm.address.trim().length === 0 ||
                staticForm.mac.trim().length === 0 ||
                !isValidIp(staticForm.address.trim()) ||
                !isValidMac(staticForm.mac.trim())
              }
            >
              {(createStaticMut.isPending || updateStaticMut.isPending) && (
                <Loader2 className="h-4 w-4 animate-spin mr-1" />
              )}
              {editingStatic
                ? t('MikroTikDhcpTab.actions.stageUpdate')
                : t('MikroTikDhcpTab.actions.stageCreate')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete confirmation */}
      <Dialog
        open={deleteTarget !== null}
        onOpenChange={(open) => {
          if (!open) setDeleteTarget(null);
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t('MikroTikDhcpTab.deleteDialog.title')}</DialogTitle>
            <DialogDescription>
              {t('MikroTikDhcpTab.deleteDialog.descriptionPrefix')}{' '}
              <span className="font-mono">{deleteLabel}</span>
              {t('MikroTikDhcpTab.deleteDialog.descriptionSuffix')}
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDeleteTarget(null)}>
              {t('MikroTikDhcpTab.actions.cancel')}
            </Button>
            <Button
              variant="destructive"
              disabled={deleteServerMut.isPending || deleteStaticMut.isPending}
              onClick={submitDelete}
            >
              {(deleteServerMut.isPending || deleteStaticMut.isPending) && (
                <Loader2 className="h-4 w-4 animate-spin mr-1" />
              )}
              {t('MikroTikDhcpTab.actions.stageDelete')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Make-static confirmation replaces window.confirm */}
      <Dialog
        open={makeStaticTarget !== null}
        onOpenChange={(open) => {
          if (!open) setMakeStaticTarget(null);
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t('MikroTikDhcpTab.makeStaticDialog.title')}</DialogTitle>
            <DialogDescription>
              {t('MikroTikDhcpTab.makeStaticDialog.descriptionPrefix')}{' '}
              <span className="font-mono">
                {asStr(makeStaticTarget?.address)}
              </span>{' '}
              ↔{' '}
              <span className="font-mono">
                {asStr(makeStaticTarget?.['mac-address'])}
              </span>{' '}
              {t('MikroTikDhcpTab.makeStaticDialog.descriptionSuffix')}
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setMakeStaticTarget(null)}>
              {t('MikroTikDhcpTab.actions.cancel')}
            </Button>
            <Button
              disabled={makeStaticMut.isPending}
              onClick={() => {
                if (!makeStaticTarget) return;
                makeStaticMut.mutate(makeStaticTarget);
              }}
            >
              {makeStaticMut.isPending && (
                <Loader2 className="h-4 w-4 animate-spin mr-1" />
              )}
              {t('MikroTikDhcpTab.actions.stageMapping')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * MikroTikIpTab · L3 plumbing: IP addresses, static routes, IP pools.
 *
 * - Addresses: CRUD via stage (RouterOS has no native PATCH for
 *   ``/ip/address``, UI hides edit and offers create + delete).
 * - Routes: CRUD via stage (``mikrotik.routing.static_route``). Note
 *   routes live under the routing domain, not /ip, but we present them
 *   here because that's where operators expect to find them.
 * - Pools: CRUD via stage (``mikrotik.ip.pool``).
 *
 * Every destructive action is gated by a confirmation dialog.
 */
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  Loader2,
  Network,
  Pencil,
  Plus,
  RefreshCw,
  Route as RouteIcon,
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
  type MikroTikIPAddress,
  type MikroTikIPPool,
  type MikroTikRoute,
} from '@/lib/api';
import { CidrInput, IpInput, isValidCidr, isValidIp } from './_shared';

export interface MikroTikIpTabProps {
  controllerId: string;
  isActive: boolean;
  /** Display name of the controller, surfaced in error toasts. */
  gatewayName?: string;
}

const ADDR_KEY = (cid: string) => ['mikrotik', cid, 'ip-addresses'];
const ROUTE_KEY = (cid: string) => ['mikrotik', cid, 'routes'];
const POOL_KEY = (cid: string) => ['mikrotik', cid, 'ip-pools'];

type AddressForm = { address: string; iface: string; comment: string };
type RouteForm = { dst: string; gateway: string; distance: string; comment: string };
type PoolForm = { name: string; ranges: string; comment: string };

const BLANK_ADDR: AddressForm = { address: '', iface: '', comment: '' };
const BLANK_ROUTE: RouteForm = { dst: '', gateway: '', distance: '1', comment: '' };
const BLANK_POOL: PoolForm = { name: '', ranges: '', comment: '' };

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
  | { kind: 'address'; row: MikroTikIPAddress }
  | { kind: 'route'; row: MikroTikRoute }
  | { kind: 'pool'; row: MikroTikIPPool };

export function MikroTikIpTab({ controllerId, isActive, gatewayName }: MikroTikIpTabProps) {
  const { t } = useTranslation('firewall');
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const ctx = gatewayName ? `${gatewayName}: ` : '';

  const [addrFormOpen, setAddrFormOpen] = useState(false);
  const [addrForm, setAddrForm] = useState<AddressForm>(BLANK_ADDR);

  const [routeFormOpen, setRouteFormOpen] = useState(false);
  const [editingRoute, setEditingRoute] = useState<MikroTikRoute | null>(null);
  const [routeForm, setRouteForm] = useState<RouteForm>(BLANK_ROUTE);

  const [poolFormOpen, setPoolFormOpen] = useState(false);
  const [editingPool, setEditingPool] = useState<MikroTikIPPool | null>(null);
  const [poolForm, setPoolForm] = useState<PoolForm>(BLANK_POOL);

  const [deleteTarget, setDeleteTarget] = useState<DeleteTarget | null>(null);

  const addresses = useQuery({
    queryKey: ADDR_KEY(controllerId),
    queryFn: () => mikrotikApi.getIPAddresses(controllerId),
    enabled: !!controllerId && isActive,
    refetchInterval: 60_000,
  });

  const routes = useQuery({
    queryKey: ROUTE_KEY(controllerId),
    queryFn: () => mikrotikApi.getRoutes(controllerId),
    enabled: !!controllerId && isActive,
    refetchInterval: 60_000,
  });

  const pools = useQuery({
    queryKey: POOL_KEY(controllerId),
    queryFn: () => mikrotikApi.getIPPools(controllerId),
    enabled: !!controllerId && isActive,
    refetchInterval: 60_000,
  });

  const addrRows: MikroTikIPAddress[] = addresses.data?.data.items ?? [];
  const routeRows: MikroTikRoute[] = routes.data?.data.items ?? [];
  const poolRows: MikroTikIPPool[] = pools.data?.data.items ?? [];

  // ── Mutations ────────────────────────────────────────────────────
  const createAddrMut = useMutation({
    mutationFn: (payload: { address: string; interface: string; comment?: string }) =>
      mikrotikApi.createIPAddress(controllerId, payload),
    onSuccess: () => {
      toast({ title: t('MikroTikIpTab.toasts.addressCreateStaged') });
      setAddrFormOpen(false);
      queryClient.invalidateQueries({ queryKey: ADDR_KEY(controllerId) });
    },
    onError: (err) =>
      toast({
        title: `${ctx}${t('MikroTikIpTab.toasts.addressCreateFailed')}`,
        description: getApiErrorMessage(err),
        variant: 'destructive',
      }),
  });

  const deleteAddrMut = useMutation({
    mutationFn: (id: string) => mikrotikApi.deleteIPAddress(controllerId, id),
    onSuccess: () => {
      toast({ title: t('MikroTikIpTab.toasts.addressDeleteStaged') });
      setDeleteTarget(null);
      queryClient.invalidateQueries({ queryKey: ADDR_KEY(controllerId) });
    },
    onError: (err) =>
      toast({
        title: `${ctx}${t('MikroTikIpTab.toasts.addressDeleteFailed')}`,
        description: getApiErrorMessage(err),
        variant: 'destructive',
      }),
  });

  const createRouteMut = useMutation({
    mutationFn: (payload: {
      'dst-address': string;
      gateway: string;
      distance?: string;
      comment?: string;
    }) => mikrotikApi.createRoute(controllerId, payload),
    onSuccess: () => {
      toast({ title: t('MikroTikIpTab.toasts.routeCreateStaged') });
      setRouteFormOpen(false);
      queryClient.invalidateQueries({ queryKey: ROUTE_KEY(controllerId) });
    },
    onError: (err) =>
      toast({
        title: `${ctx}${t('MikroTikIpTab.toasts.routeCreateFailed')}`,
        description: getApiErrorMessage(err),
        variant: 'destructive',
      }),
  });

  const updateRouteMut = useMutation({
    mutationFn: ({ id, payload }: { id: string; payload: Record<string, unknown> }) =>
      mikrotikApi.updateRoute(controllerId, id, payload),
    onSuccess: () => {
      toast({ title: t('MikroTikIpTab.toasts.routeUpdateStaged') });
      setRouteFormOpen(false);
      queryClient.invalidateQueries({ queryKey: ROUTE_KEY(controllerId) });
    },
    onError: (err) =>
      toast({
        title: `${ctx}${t('MikroTikIpTab.toasts.routeUpdateFailed')}`,
        description: getApiErrorMessage(err),
        variant: 'destructive',
      }),
  });

  const deleteRouteMut = useMutation({
    mutationFn: (id: string) => mikrotikApi.deleteRoute(controllerId, id),
    onSuccess: () => {
      toast({ title: t('MikroTikIpTab.toasts.routeDeleteStaged') });
      setDeleteTarget(null);
      queryClient.invalidateQueries({ queryKey: ROUTE_KEY(controllerId) });
    },
    onError: (err) =>
      toast({
        title: `${ctx}${t('MikroTikIpTab.toasts.routeDeleteFailed')}`,
        description: getApiErrorMessage(err),
        variant: 'destructive',
      }),
  });

  const createPoolMut = useMutation({
    mutationFn: (payload: { name: string; ranges: string; comment?: string }) =>
      mikrotikApi.createIPPool(controllerId, payload),
    onSuccess: () => {
      toast({ title: t('MikroTikIpTab.toasts.poolCreateStaged') });
      setPoolFormOpen(false);
      queryClient.invalidateQueries({ queryKey: POOL_KEY(controllerId) });
    },
    onError: (err) =>
      toast({
        title: `${ctx}${t('MikroTikIpTab.toasts.poolCreateFailed')}`,
        description: getApiErrorMessage(err),
        variant: 'destructive',
      }),
  });

  const updatePoolMut = useMutation({
    mutationFn: ({ id, payload }: { id: string; payload: Record<string, unknown> }) =>
      mikrotikApi.updateIPPool(controllerId, id, payload),
    onSuccess: () => {
      toast({ title: t('MikroTikIpTab.toasts.poolUpdateStaged') });
      setPoolFormOpen(false);
      queryClient.invalidateQueries({ queryKey: POOL_KEY(controllerId) });
    },
    onError: (err) =>
      toast({
        title: `${ctx}${t('MikroTikIpTab.toasts.poolUpdateFailed')}`,
        description: getApiErrorMessage(err),
        variant: 'destructive',
      }),
  });

  const deletePoolMut = useMutation({
    mutationFn: (id: string) => mikrotikApi.deleteIPPool(controllerId, id),
    onSuccess: () => {
      toast({ title: t('MikroTikIpTab.toasts.poolDeleteStaged') });
      setDeleteTarget(null);
      queryClient.invalidateQueries({ queryKey: POOL_KEY(controllerId) });
    },
    onError: (err) =>
      toast({
        title: `${ctx}${t('MikroTikIpTab.toasts.poolDeleteFailed')}`,
        description: getApiErrorMessage(err),
        variant: 'destructive',
      }),
  });

  // ── Form handlers ────────────────────────────────────────────────
  function submitAddress() {
    if (!addrForm.address.trim() || !addrForm.iface.trim()) return;
    const payload: { address: string; interface: string; comment?: string } = {
      address: addrForm.address.trim(),
      interface: addrForm.iface.trim(),
    };
    if (addrForm.comment.trim()) payload.comment = addrForm.comment.trim();
    createAddrMut.mutate(payload);
  }

  function openNewRoute() {
    setEditingRoute(null);
    setRouteForm(BLANK_ROUTE);
    setRouteFormOpen(true);
  }

  function openEditRoute(row: MikroTikRoute) {
    setEditingRoute(row);
    setRouteForm({
      dst: typeof row['dst-address'] === 'string' ? row['dst-address'] : '',
      gateway: typeof row.gateway === 'string' ? row.gateway : '',
      distance:
        row.distance !== undefined && row.distance !== null && row.distance !== ''
          ? String(row.distance)
          : '1',
      comment: typeof row.comment === 'string' ? row.comment : '',
    });
    setRouteFormOpen(true);
  }

  function submitRoute() {
    const trimmed = {
      dst: routeForm.dst.trim(),
      gateway: routeForm.gateway.trim(),
      distance: routeForm.distance.trim(),
      comment: routeForm.comment.trim(),
    };
    if (!trimmed.dst || !trimmed.gateway) return;
    const payload: Record<string, unknown> = {
      'dst-address': trimmed.dst,
      gateway: trimmed.gateway,
    };
    if (trimmed.distance) payload.distance = trimmed.distance;
    if (trimmed.comment) payload.comment = trimmed.comment;

    if (editingRoute) {
      const id = (editingRoute['.id'] as string | undefined) ?? '';
      if (!id) {
        toast({
          title: t('MikroTikIpTab.errors.cannotUpdateRoute'),
          description: t('MikroTikIpTab.errors.routeNoId'),
          variant: 'destructive',
        });
        return;
      }
      updateRouteMut.mutate({ id, payload });
    } else {
      createRouteMut.mutate({
        'dst-address': trimmed.dst,
        gateway: trimmed.gateway,
        ...(trimmed.distance ? { distance: trimmed.distance } : {}),
        ...(trimmed.comment ? { comment: trimmed.comment } : {}),
      });
    }
  }

  function openNewPool() {
    setEditingPool(null);
    setPoolForm(BLANK_POOL);
    setPoolFormOpen(true);
  }

  function openEditPool(row: MikroTikIPPool) {
    setEditingPool(row);
    setPoolForm({
      name: typeof row.name === 'string' ? row.name : '',
      ranges: typeof row.ranges === 'string' ? row.ranges : '',
      comment: typeof row.comment === 'string' ? row.comment : '',
    });
    setPoolFormOpen(true);
  }

  function submitPool() {
    const trimmed = {
      name: poolForm.name.trim(),
      ranges: poolForm.ranges.trim(),
      comment: poolForm.comment.trim(),
    };
    if (!trimmed.name || !trimmed.ranges) return;

    if (editingPool) {
      const id = (editingPool['.id'] as string | undefined) ?? '';
      if (!id) {
        toast({
          title: t('MikroTikIpTab.errors.cannotUpdatePool'),
          description: t('MikroTikIpTab.errors.poolNoId'),
          variant: 'destructive',
        });
        return;
      }
      const payload: Record<string, unknown> = {
        name: trimmed.name,
        ranges: trimmed.ranges,
      };
      if (trimmed.comment) payload.comment = trimmed.comment;
      updatePoolMut.mutate({ id, payload });
    } else {
      createPoolMut.mutate({
        name: trimmed.name,
        ranges: trimmed.ranges,
        ...(trimmed.comment ? { comment: trimmed.comment } : {}),
      });
    }
  }

  function submitDelete() {
    if (!deleteTarget) return;
    const id = (deleteTarget.row['.id'] as string | undefined) ?? '';
    if (!id) {
      toast({
        title: t('MikroTikIpTab.errors.cannotDelete'),
        description: t('MikroTikIpTab.errors.rowNoId'),
        variant: 'destructive',
      });
      return;
    }
    if (deleteTarget.kind === 'address') deleteAddrMut.mutate(id);
    else if (deleteTarget.kind === 'route') deleteRouteMut.mutate(id);
    else deletePoolMut.mutate(id);
  }

  const allLoading = addresses.isLoading && routes.isLoading && pools.isLoading;
  if (allLoading) {
    return (
      <div className="flex items-center justify-center py-16 text-muted-foreground">
        <Loader2 className="h-5 w-5 animate-spin mr-2" />
        {t('MikroTikIpTab.loading')}
      </div>
    );
  }

  const deleteLabel = (() => {
    if (!deleteTarget) return '';
    if (deleteTarget.kind === 'address')
      return t('MikroTikIpTab.deleteLabel.address', {
        value: asStr((deleteTarget.row as MikroTikIPAddress).address),
      });
    if (deleteTarget.kind === 'route')
      return t('MikroTikIpTab.deleteLabel.route', {
        value: asStr((deleteTarget.row as MikroTikRoute)['dst-address']),
      });
    return t('MikroTikIpTab.deleteLabel.pool', {
      value: asStr((deleteTarget.row as MikroTikIPPool).name),
    });
  })();

  const anyFetching = addresses.isFetching || routes.isFetching || pools.isFetching;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-end">
        <Button
          variant="outline"
          size="sm"
          disabled={anyFetching}
          onClick={() => {
            addresses.refetch();
            routes.refetch();
            pools.refetch();
          }}
        >
          {anyFetching ? (
            <Loader2 className="h-4 w-4 animate-spin mr-1" />
          ) : (
            <RefreshCw className="h-4 w-4 mr-1" />
          )}
          {t('MikroTikIpTab.actions.refresh')}
        </Button>
      </div>

      {/* Addresses */}
      <Card className="border-border/50">
        <CardHeader className="pb-4">
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="flex items-center gap-2">
                <Network className="h-4 w-4" /> {t('MikroTikIpTab.addresses.title')}
              </CardTitle>
              <CardDescription>
                {t('MikroTikIpTab.addresses.description')}
              </CardDescription>
            </div>
            <Button
              size="sm"
              onClick={() => {
                setAddrForm(BLANK_ADDR);
                setAddrFormOpen(true);
              }}
            >
              <Plus className="h-4 w-4 mr-1" /> {t('MikroTikIpTab.addresses.add')}
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          {addresses.isError ? (
            <ErrorState
              message={getApiErrorMessage(addresses.error, t('MikroTikIpTab.addresses.loadError'))}
              onRetry={() => addresses.refetch()}
            />
          ) : addrRows.length === 0 && !addresses.isLoading ? (
            <EmptyState
              variant="compact"
              title={t('MikroTikIpTab.addresses.emptyTitle')}
              description={t('MikroTikIpTab.addresses.emptyDescription')}
              action={{
                label: t('MikroTikIpTab.addresses.add'),
                icon: Plus,
                onClick: () => {
                  setAddrForm(BLANK_ADDR);
                  setAddrFormOpen(true);
                },
              }}
            />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b text-left text-muted-foreground">
                    <th className="px-3 py-2 font-medium">{t('MikroTikIpTab.addresses.columns.address')}</th>
                    <th className="px-3 py-2 font-medium">{t('MikroTikIpTab.addresses.columns.network')}</th>
                    <th className="px-3 py-2 font-medium">{t('MikroTikIpTab.addresses.columns.interface')}</th>
                    <th className="px-3 py-2 font-medium">{t('MikroTikIpTab.addresses.columns.dynamic')}</th>
                    <th className="px-3 py-2 font-medium">{t('MikroTikIpTab.addresses.columns.disabled')}</th>
                    <th className="px-3 py-2 font-medium">{t('MikroTikIpTab.columns.comment')}</th>
                    <th className="px-3 py-2 font-medium text-right">{t('MikroTikIpTab.columns.actions')}</th>
                  </tr>
                </thead>
                <tbody>
                  {addrRows.map((row) => {
                    const id = (row['.id'] as string | undefined) ?? '';
                    const addrLabel =
                      asStr(row.address) !== '-'
                        ? asStr(row.address)
                        : id || t('MikroTikIpTab.addresses.fallbackLabel');
                    return (
                      <tr key={id || row.address || Math.random()} className="border-b last:border-0">
                        <td className="px-3 py-2 font-mono">{asStr(row.address)}</td>
                        <td className="px-3 py-2 font-mono text-xs">{asStr(row.network)}</td>
                        <td className="px-3 py-2">{asStr(row['actual-interface'] ?? row.interface)}</td>
                        <td className="px-3 py-2">
                          {asBool(row.dynamic) ? (
                            <Badge variant="secondary">{t('MikroTikIpTab.badges.dynamic')}</Badge>
                          ) : (
                            <Badge>{t('MikroTikIpTab.badges.static')}</Badge>
                          )}
                        </td>
                        <td className="px-3 py-2">
                          <Badge variant={asBool(row.disabled) ? 'secondary' : 'default'}>
                            {asBool(row.disabled) ? t('MikroTikIpTab.badges.yes') : t('MikroTikIpTab.badges.no')}
                          </Badge>
                        </td>
                        <td className="px-3 py-2 text-xs text-muted-foreground">
                          {asStr(row.comment)}
                        </td>
                        <td className="px-3 py-2 text-right">
                          <Button
                            variant="ghost"
                            size="sm"
                            disabled={!id || asBool(row.dynamic)}
                            aria-label={t('MikroTikIpTab.addresses.deleteAria', { label: addrLabel })}
                            onClick={() => setDeleteTarget({ kind: 'address', row })}
                          >
                            <Trash2 className="h-3.5 w-3.5 text-destructive" aria-hidden="true" />
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

      {/* Routes */}
      <Card className="border-border/50">
        <CardHeader className="pb-4">
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="flex items-center gap-2">
                <RouteIcon className="h-4 w-4" /> {t('MikroTikIpTab.routes.title')}
              </CardTitle>
              <CardDescription>
                {t('MikroTikIpTab.routes.description')}
              </CardDescription>
            </div>
            <Button size="sm" onClick={openNewRoute}>
              <Plus className="h-4 w-4 mr-1" /> {t('MikroTikIpTab.routes.add')}
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          {routes.isError ? (
            <ErrorState
              message={getApiErrorMessage(routes.error, t('MikroTikIpTab.routes.loadError'))}
              onRetry={() => routes.refetch()}
            />
          ) : routeRows.length === 0 && !routes.isLoading ? (
            <EmptyState
              variant="compact"
              title={t('MikroTikIpTab.routes.emptyTitle')}
              description={t('MikroTikIpTab.routes.emptyDescription')}
              action={{ label: t('MikroTikIpTab.routes.add'), icon: Plus, onClick: openNewRoute }}
            />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b text-left text-muted-foreground">
                    <th className="px-3 py-2 font-medium">{t('MikroTikIpTab.routes.columns.destination')}</th>
                    <th className="px-3 py-2 font-medium">{t('MikroTikIpTab.routes.columns.gateway')}</th>
                    <th className="px-3 py-2 font-medium">{t('MikroTikIpTab.routes.columns.distance')}</th>
                    <th className="px-3 py-2 font-medium">{t('MikroTikIpTab.routes.columns.active')}</th>
                    <th className="px-3 py-2 font-medium">{t('MikroTikIpTab.routes.columns.static')}</th>
                    <th className="px-3 py-2 font-medium">{t('MikroTikIpTab.columns.comment')}</th>
                    <th className="px-3 py-2 font-medium text-right">{t('MikroTikIpTab.columns.actions')}</th>
                  </tr>
                </thead>
                <tbody>
                  {routeRows.map((row) => {
                    const id = (row['.id'] as string | undefined) ?? '';
                    const isStatic = asBool(row.static);
                    const routeLabel =
                      asStr(row['dst-address']) !== '-'
                        ? t('MikroTikIpTab.routes.rowLabel', {
                            dst: asStr(row['dst-address']),
                            gateway: asStr(row.gateway),
                          })
                        : id || t('MikroTikIpTab.routes.fallbackLabel');
                    return (
                      <tr key={id || Math.random()} className="border-b last:border-0">
                        <td className="px-3 py-2 font-mono">{asStr(row['dst-address'])}</td>
                        <td className="px-3 py-2 font-mono">{asStr(row.gateway)}</td>
                        <td className="px-3 py-2">{asStr(row.distance)}</td>
                        <td className="px-3 py-2">
                          <Badge variant={asBool(row.active) ? 'default' : 'secondary'}>
                            {asBool(row.active) ? t('MikroTikIpTab.badges.yes') : t('MikroTikIpTab.badges.no')}
                          </Badge>
                        </td>
                        <td className="px-3 py-2">
                          <Badge variant={isStatic ? 'default' : 'secondary'}>
                            {isStatic ? t('MikroTikIpTab.badges.static') : t('MikroTikIpTab.badges.dynamic')}
                          </Badge>
                        </td>
                        <td className="px-3 py-2 text-xs text-muted-foreground">
                          {asStr(row.comment)}
                        </td>
                        <td className="px-3 py-2 text-right">
                          <div className="flex items-center gap-1 justify-end">
                            <Button
                              variant="ghost"
                              size="sm"
                              disabled={!id || !isStatic}
                              aria-label={t('MikroTikIpTab.routes.editAria', { label: routeLabel })}
                              onClick={() => openEditRoute(row)}
                            >
                              <Pencil className="h-3.5 w-3.5" aria-hidden="true" />
                            </Button>
                            <Button
                              variant="ghost"
                              size="sm"
                              disabled={!id || !isStatic}
                              aria-label={t('MikroTikIpTab.routes.deleteAria', { label: routeLabel })}
                              onClick={() => setDeleteTarget({ kind: 'route', row })}
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

      {/* Pools */}
      <Card className="border-border/50">
        <CardHeader className="pb-4">
          <div className="flex items-center justify-between">
            <div>
              <CardTitle>{t('MikroTikIpTab.pools.title')}</CardTitle>
              <CardDescription>
                {t('MikroTikIpTab.pools.description')}
              </CardDescription>
            </div>
            <Button size="sm" onClick={openNewPool}>
              <Plus className="h-4 w-4 mr-1" /> {t('MikroTikIpTab.pools.add')}
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          {pools.isError ? (
            <ErrorState
              message={getApiErrorMessage(pools.error, t('MikroTikIpTab.pools.loadError'))}
              onRetry={() => pools.refetch()}
            />
          ) : poolRows.length === 0 && !pools.isLoading ? (
            <EmptyState
              variant="compact"
              title={t('MikroTikIpTab.pools.emptyTitle')}
              description={t('MikroTikIpTab.pools.emptyDescription')}
              action={{ label: t('MikroTikIpTab.pools.add'), icon: Plus, onClick: openNewPool }}
            />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b text-left text-muted-foreground">
                    <th className="px-3 py-2 font-medium">{t('MikroTikIpTab.pools.columns.name')}</th>
                    <th className="px-3 py-2 font-medium">{t('MikroTikIpTab.pools.columns.ranges')}</th>
                    <th className="px-3 py-2 font-medium">{t('MikroTikIpTab.pools.columns.nextPool')}</th>
                    <th className="px-3 py-2 font-medium">{t('MikroTikIpTab.columns.comment')}</th>
                    <th className="px-3 py-2 font-medium text-right">{t('MikroTikIpTab.columns.actions')}</th>
                  </tr>
                </thead>
                <tbody>
                  {poolRows.map((row) => {
                    const id = (row['.id'] as string | undefined) ?? '';
                    const poolLabel =
                      asStr(row.name) !== '-'
                        ? asStr(row.name)
                        : id || t('MikroTikIpTab.pools.fallbackLabel');
                    return (
                      <tr key={id || row.name || Math.random()} className="border-b last:border-0">
                        <td className="px-3 py-2 font-medium">{asStr(row.name)}</td>
                        <td className="px-3 py-2 font-mono">{asStr(row.ranges)}</td>
                        <td className="px-3 py-2">{asStr(row['next-pool'])}</td>
                        <td className="px-3 py-2 text-xs text-muted-foreground">{asStr(row.comment)}</td>
                        <td className="px-3 py-2 text-right">
                          <div className="flex items-center gap-1 justify-end">
                            <Button
                              variant="ghost"
                              size="sm"
                              disabled={!id}
                              aria-label={t('MikroTikIpTab.pools.editAria', { label: poolLabel })}
                              onClick={() => openEditPool(row)}
                            >
                              <Pencil className="h-3.5 w-3.5" aria-hidden="true" />
                            </Button>
                            <Button
                              variant="ghost"
                              size="sm"
                              disabled={!id}
                              aria-label={t('MikroTikIpTab.pools.deleteAria', { label: poolLabel })}
                              onClick={() => setDeleteTarget({ kind: 'pool', row })}
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

      {/* Address create dialog */}
      <Dialog open={addrFormOpen} onOpenChange={setAddrFormOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t('MikroTikIpTab.addressDialog.title')}</DialogTitle>
            <DialogDescription>
              {t('MikroTikIpTab.addressDialog.description')}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            <div className="space-y-2">
              <Label htmlFor="mikrotik-addr">{t('MikroTikIpTab.addressDialog.addressLabel')}</Label>
              <CidrInput
                id="mikrotik-addr"
                value={addrForm.address}
                onChange={(e) => setAddrForm((f) => ({ ...f, address: e.target.value }))}
                placeholder="192.168.88.1/24"
                autoFocus
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="mikrotik-iface">{t('MikroTikIpTab.addressDialog.interfaceLabel')}</Label>
              <Input
                id="mikrotik-iface"
                value={addrForm.iface}
                onChange={(e) => setAddrForm((f) => ({ ...f, iface: e.target.value }))}
                placeholder="bridge1"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="mikrotik-addr-comment">{t('MikroTikIpTab.columns.comment')}</Label>
              <Input
                id="mikrotik-addr-comment"
                value={addrForm.comment}
                onChange={(e) => setAddrForm((f) => ({ ...f, comment: e.target.value }))}
                placeholder={t('MikroTikIpTab.addressDialog.commentPlaceholder')}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setAddrFormOpen(false)}>
              {t('MikroTikIpTab.actions.cancel')}
            </Button>
            <Button
              onClick={submitAddress}
              disabled={
                createAddrMut.isPending ||
                addrForm.address.trim().length === 0 ||
                addrForm.iface.trim().length === 0 ||
                !isValidCidr(addrForm.address.trim())
              }
            >
              {createAddrMut.isPending && <Loader2 className="h-4 w-4 animate-spin mr-1" />}
              {t('MikroTikIpTab.actions.stageCreate')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Route form dialog */}
      <Dialog open={routeFormOpen} onOpenChange={setRouteFormOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>
              {editingRoute
                ? t('MikroTikIpTab.routeDialog.editTitle')
                : t('MikroTikIpTab.routeDialog.addTitle')}
            </DialogTitle>
            <DialogDescription>
              {t('MikroTikIpTab.routeDialog.description')}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            <div className="space-y-2">
              <Label htmlFor="mikrotik-route-dst">{t('MikroTikIpTab.routeDialog.destinationLabel')}</Label>
              <CidrInput
                id="mikrotik-route-dst"
                value={routeForm.dst}
                onChange={(e) => setRouteForm((f) => ({ ...f, dst: e.target.value }))}
                placeholder="10.0.0.0/8"
                autoFocus
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="mikrotik-route-gw">{t('MikroTikIpTab.routeDialog.gatewayLabel')}</Label>
              <IpInput
                id="mikrotik-route-gw"
                value={routeForm.gateway}
                onChange={(e) => setRouteForm((f) => ({ ...f, gateway: e.target.value }))}
                placeholder="192.168.1.254"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="mikrotik-route-dist">{t('MikroTikIpTab.routeDialog.distanceLabel')}</Label>
              <Input
                id="mikrotik-route-dist"
                value={routeForm.distance}
                onChange={(e) => setRouteForm((f) => ({ ...f, distance: e.target.value }))}
                placeholder="1"
                inputMode="numeric"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="mikrotik-route-comment">{t('MikroTikIpTab.columns.comment')}</Label>
              <Input
                id="mikrotik-route-comment"
                value={routeForm.comment}
                onChange={(e) => setRouteForm((f) => ({ ...f, comment: e.target.value }))}
                placeholder={t('MikroTikIpTab.routeDialog.commentPlaceholder')}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setRouteFormOpen(false)}>
              {t('MikroTikIpTab.actions.cancel')}
            </Button>
            <Button
              onClick={submitRoute}
              disabled={
                createRouteMut.isPending ||
                updateRouteMut.isPending ||
                routeForm.dst.trim().length === 0 ||
                routeForm.gateway.trim().length === 0 ||
                !isValidCidr(routeForm.dst.trim()) ||
                !isValidIp(routeForm.gateway.trim())
              }
            >
              {(createRouteMut.isPending || updateRouteMut.isPending) && (
                <Loader2 className="h-4 w-4 animate-spin mr-1" />
              )}
              {editingRoute
                ? t('MikroTikIpTab.actions.stageUpdate')
                : t('MikroTikIpTab.actions.stageCreate')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Pool form dialog */}
      <Dialog open={poolFormOpen} onOpenChange={setPoolFormOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>
              {editingPool
                ? t('MikroTikIpTab.poolDialog.editTitle')
                : t('MikroTikIpTab.poolDialog.addTitle')}
            </DialogTitle>
            <DialogDescription>
              {t('MikroTikIpTab.poolDialog.description')}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            <div className="space-y-2">
              <Label htmlFor="mikrotik-pool-name">{t('MikroTikIpTab.poolDialog.nameLabel')}</Label>
              <Input
                id="mikrotik-pool-name"
                value={poolForm.name}
                onChange={(e) => setPoolForm((f) => ({ ...f, name: e.target.value }))}
                placeholder="dhcp-pool"
                autoFocus
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="mikrotik-pool-ranges">{t('MikroTikIpTab.poolDialog.rangesLabel')}</Label>
              <Input
                id="mikrotik-pool-ranges"
                value={poolForm.ranges}
                onChange={(e) => setPoolForm((f) => ({ ...f, ranges: e.target.value }))}
                placeholder="192.168.88.10-192.168.88.254"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="mikrotik-pool-comment">{t('MikroTikIpTab.columns.comment')}</Label>
              <Input
                id="mikrotik-pool-comment"
                value={poolForm.comment}
                onChange={(e) => setPoolForm((f) => ({ ...f, comment: e.target.value }))}
                placeholder={t('MikroTikIpTab.poolDialog.commentPlaceholder')}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setPoolFormOpen(false)}>
              {t('MikroTikIpTab.actions.cancel')}
            </Button>
            <Button
              onClick={submitPool}
              disabled={
                createPoolMut.isPending ||
                updatePoolMut.isPending ||
                poolForm.name.trim().length === 0 ||
                poolForm.ranges.trim().length === 0
              }
            >
              {(createPoolMut.isPending || updatePoolMut.isPending) && (
                <Loader2 className="h-4 w-4 animate-spin mr-1" />
              )}
              {editingPool
                ? t('MikroTikIpTab.actions.stageUpdate')
                : t('MikroTikIpTab.actions.stageCreate')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Shared delete confirmation */}
      <Dialog
        open={deleteTarget !== null}
        onOpenChange={(open) => {
          if (!open) setDeleteTarget(null);
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t('MikroTikIpTab.deleteDialog.title')}</DialogTitle>
            <DialogDescription>
              {t('MikroTikIpTab.deleteDialog.descriptionBefore')}{' '}
              <span className="font-mono">{deleteLabel}</span>.{' '}
              {t('MikroTikIpTab.deleteDialog.descriptionAfter')}
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDeleteTarget(null)}>
              {t('MikroTikIpTab.actions.cancel')}
            </Button>
            <Button
              variant="destructive"
              disabled={
                deleteAddrMut.isPending ||
                deleteRouteMut.isPending ||
                deletePoolMut.isPending
              }
              onClick={submitDelete}
            >
              {(deleteAddrMut.isPending ||
                deleteRouteMut.isPending ||
                deletePoolMut.isPending) && (
                <Loader2 className="h-4 w-4 animate-spin mr-1" />
              )}
              {t('MikroTikIpTab.actions.stageDelete')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

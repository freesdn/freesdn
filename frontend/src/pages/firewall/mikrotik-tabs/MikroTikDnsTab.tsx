// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * MikroTikDnsTab · RouterOS DNS, static entries + cache.
 *
 * Two sub-tables:
 * - Static DNS entries: full CRUD via stage
 *   (``mikrotik.dns.static`` create / update / delete).
 * - DNS cache: read-only with a manual Refresh button. RouterOS exposes
 *   the cache at ``/ip/dns/cache``; the rows are short-lived so we
 *   refetch on demand rather than polling.
 *
 * The static-entry form covers the A / AAAA / CNAME / TXT shapes most
 * operators reach for. Anything more exotic (MX, SRV, regexp) can still
 * be staged via the existing JSON-payload UI but isn't surfaced as a
 * first-class form field yet.
 */
import { useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  Database,
  Globe,
  Loader2,
  Pencil,
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
  type MikroTikDNSCacheEntry,
  type MikroTikDNSStaticEntry,
} from '@/lib/api';

export interface MikroTikDnsTabProps {
  controllerId: string;
  isActive: boolean;
  /** Display name of the controller, surfaced in error toasts. */
  gatewayName?: string;
}

const STATIC_KEY = (cid: string) => ['mikrotik', cid, 'dns-static'];
const CACHE_KEY = (cid: string) => ['mikrotik', cid, 'dns-cache'];

type StaticForm = {
  name: string;
  type: string;
  address: string;
  cname: string;
  text: string;
  ttl: string;
  comment: string;
};

const BLANK_STATIC: StaticForm = {
  name: '',
  type: 'A',
  address: '',
  cname: '',
  text: '',
  ttl: '',
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

export function MikroTikDnsTab({ controllerId, isActive, gatewayName }: MikroTikDnsTabProps) {
  const { t } = useTranslation('firewall');
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const ctx = gatewayName ? `${gatewayName}: ` : '';

  const [staticFormOpen, setStaticFormOpen] = useState(false);
  const [editingStatic, setEditingStatic] =
    useState<MikroTikDNSStaticEntry | null>(null);
  const [staticForm, setStaticForm] = useState<StaticForm>(BLANK_STATIC);
  const [deleteTarget, setDeleteTarget] =
    useState<MikroTikDNSStaticEntry | null>(null);

  const staticQuery = useQuery({
    queryKey: STATIC_KEY(controllerId),
    queryFn: () => mikrotikApi.getDNSStatic(controllerId),
    enabled: !!controllerId && isActive,
    refetchInterval: 60_000,
  });

  const cacheQuery = useQuery({
    queryKey: CACHE_KEY(controllerId),
    queryFn: () => mikrotikApi.getDNSCache(controllerId),
    // Cache list can be large; only fetch on demand.
    enabled: !!controllerId && isActive,
  });

  // MEDIUM-4: stable row arrays across renders.
  const staticRows: MikroTikDNSStaticEntry[] = useMemo(
    () => staticQuery.data?.data.items ?? [],
    [staticQuery.data],
  );
  const cacheRows: MikroTikDNSCacheEntry[] = useMemo(
    () => cacheQuery.data?.data.items ?? [],
    [cacheQuery.data],
  );

  const createStaticMut = useMutation({
    mutationFn: (payload: Record<string, unknown>) =>
      mikrotikApi.createDNSStatic(controllerId, payload),
    onSuccess: () => {
      toast({ title: t('MikroTikDnsTab.toasts.createStaged') });
      setStaticFormOpen(false);
      queryClient.invalidateQueries({ queryKey: STATIC_KEY(controllerId) });
    },
    onError: (err) =>
      toast({
        title: `${ctx}${t('MikroTikDnsTab.toasts.createFailed')}`,
        description: getApiErrorMessage(err),
        variant: 'destructive',
      }),
  });

  const updateStaticMut = useMutation({
    mutationFn: ({ id, payload }: { id: string; payload: Record<string, unknown> }) =>
      mikrotikApi.updateDNSStatic(controllerId, id, payload),
    onSuccess: () => {
      toast({ title: t('MikroTikDnsTab.toasts.updateStaged') });
      setStaticFormOpen(false);
      queryClient.invalidateQueries({ queryKey: STATIC_KEY(controllerId) });
    },
    onError: (err) =>
      toast({
        title: `${ctx}${t('MikroTikDnsTab.toasts.updateFailed')}`,
        description: getApiErrorMessage(err),
        variant: 'destructive',
      }),
  });

  const deleteStaticMut = useMutation({
    mutationFn: (id: string) => mikrotikApi.deleteDNSStatic(controllerId, id),
    onSuccess: () => {
      toast({ title: t('MikroTikDnsTab.toasts.deleteStaged') });
      setDeleteTarget(null);
      queryClient.invalidateQueries({ queryKey: STATIC_KEY(controllerId) });
    },
    onError: (err) =>
      toast({
        title: `${ctx}${t('MikroTikDnsTab.toasts.deleteFailed')}`,
        description: getApiErrorMessage(err),
        variant: 'destructive',
      }),
  });

  function openNewStatic() {
    setEditingStatic(null);
    setStaticForm(BLANK_STATIC);
    setStaticFormOpen(true);
  }

  function openEditStatic(row: MikroTikDNSStaticEntry) {
    setEditingStatic(row);
    setStaticForm({
      name: typeof row.name === 'string' ? row.name : '',
      type: typeof row.type === 'string' ? row.type : 'A',
      address: typeof row.address === 'string' ? row.address : '',
      cname: typeof row.cname === 'string' ? row.cname : '',
      text: typeof row.text === 'string' ? row.text : '',
      ttl: typeof row.ttl === 'string' ? row.ttl : '',
      comment: typeof row.comment === 'string' ? row.comment : '',
    });
    setStaticFormOpen(true);
  }

  function submitStatic() {
    const trimmed = {
      name: staticForm.name.trim(),
      type: staticForm.type.trim() || 'A',
      address: staticForm.address.trim(),
      cname: staticForm.cname.trim(),
      text: staticForm.text.trim(),
      ttl: staticForm.ttl.trim(),
      comment: staticForm.comment.trim(),
    };
    if (!trimmed.name) return;
    // Per-type required field.
    if (trimmed.type === 'A' || trimmed.type === 'AAAA') {
      if (!trimmed.address) return;
    } else if (trimmed.type === 'CNAME') {
      if (!trimmed.cname) return;
    } else if (trimmed.type === 'TXT') {
      if (!trimmed.text) return;
    }
    const payload: Record<string, unknown> = {
      name: trimmed.name,
      type: trimmed.type,
    };
    if (trimmed.address) payload.address = trimmed.address;
    if (trimmed.cname) payload.cname = trimmed.cname;
    if (trimmed.text) payload.text = trimmed.text;
    if (trimmed.ttl) payload.ttl = trimmed.ttl;
    if (trimmed.comment) payload.comment = trimmed.comment;

    if (editingStatic) {
      const id = (editingStatic['.id'] as string | undefined) ?? '';
      if (!id) {
        toast({
          title: t('MikroTikDnsTab.toasts.cannotUpdate'),
          description: t('MikroTikDnsTab.toasts.missingId'),
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
    const id = (deleteTarget['.id'] as string | undefined) ?? '';
    if (!id) {
      toast({
        title: t('MikroTikDnsTab.toasts.cannotDelete'),
        description: t('MikroTikDnsTab.toasts.missingId'),
        variant: 'destructive',
      });
      return;
    }
    deleteStaticMut.mutate(id);
  }

  if (staticQuery.isLoading && cacheQuery.isLoading) {
    return (
      <div className="flex items-center justify-center py-16 text-muted-foreground">
        <Loader2 className="h-5 w-5 animate-spin mr-2" />
        {t('MikroTikDnsTab.loading')}
      </div>
    );
  }

  const anyFetching = staticQuery.isFetching || cacheQuery.isFetching;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-end">
        <Button
          variant="outline"
          size="sm"
          disabled={anyFetching}
          onClick={() => {
            staticQuery.refetch();
            cacheQuery.refetch();
          }}
        >
          {anyFetching ? (
            <Loader2 className="h-4 w-4 animate-spin mr-1" />
          ) : (
            <RefreshCw className="h-4 w-4 mr-1" />
          )}
          {t('MikroTikDnsTab.actions.refresh')}
        </Button>
      </div>

      {/* Static entries */}
      <Card className="border-border/50">
        <CardHeader className="pb-4">
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="flex items-center gap-2">
                <Globe className="h-4 w-4" /> {t('MikroTikDnsTab.static.title')}
              </CardTitle>
              <CardDescription>
                {t('MikroTikDnsTab.static.description')}
              </CardDescription>
            </div>
            <Button size="sm" onClick={openNewStatic}>
              <Plus className="h-4 w-4 mr-1" /> {t('MikroTikDnsTab.actions.addEntry')}
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          {staticQuery.isError ? (
            <ErrorState
              message={getApiErrorMessage(staticQuery.error, t('MikroTikDnsTab.static.loadError'))}
              onRetry={() => staticQuery.refetch()}
            />
          ) : staticRows.length === 0 && !staticQuery.isLoading ? (
            <EmptyState
              variant="compact"
              title={t('MikroTikDnsTab.static.emptyTitle')}
              description={t('MikroTikDnsTab.static.emptyDescription')}
              action={{ label: t('MikroTikDnsTab.actions.addEntry'), icon: Plus, onClick: openNewStatic }}
            />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b text-left text-muted-foreground">
                    <th className="px-3 py-2 font-medium">{t('MikroTikDnsTab.columns.name')}</th>
                    <th className="px-3 py-2 font-medium">{t('MikroTikDnsTab.columns.type')}</th>
                    <th className="px-3 py-2 font-medium">{t('MikroTikDnsTab.columns.value')}</th>
                    <th className="px-3 py-2 font-medium">{t('MikroTikDnsTab.columns.ttl')}</th>
                    <th className="px-3 py-2 font-medium">{t('MikroTikDnsTab.columns.enabled')}</th>
                    <th className="px-3 py-2 font-medium">{t('MikroTikDnsTab.columns.comment')}</th>
                    <th className="px-3 py-2 font-medium text-right">{t('MikroTikDnsTab.columns.actions')}</th>
                  </tr>
                </thead>
                <tbody>
                  {staticRows.map((row) => {
                    const id = (row['.id'] as string | undefined) ?? '';
                    const enabled = !asBool(row.disabled);
                    const value =
                      (typeof row.address === 'string' && row.address) ||
                      (typeof row.cname === 'string' && row.cname) ||
                      (typeof row.text === 'string' && row.text) ||
                      '-';
                    const dnsLabel = asStr(row.name) !== '-' ? asStr(row.name) : id || t('MikroTikDnsTab.entryFallback');
                    return (
                      <tr key={id || row.name || Math.random()} className="border-b last:border-0">
                        <td className="px-3 py-2 font-medium">{asStr(row.name)}</td>
                        <td className="px-3 py-2">
                          <Badge variant="secondary">{asStr(row.type) || 'A'}</Badge>
                        </td>
                        <td className="px-3 py-2 font-mono text-xs">{value}</td>
                        <td className="px-3 py-2">{asStr(row.ttl)}</td>
                        <td className="px-3 py-2">
                          <Badge variant={enabled ? 'default' : 'secondary'}>
                            {enabled ? t('MikroTikDnsTab.yes') : t('MikroTikDnsTab.no')}
                          </Badge>
                        </td>
                        <td className="px-3 py-2 text-xs text-muted-foreground">{asStr(row.comment)}</td>
                        <td className="px-3 py-2 text-right">
                          <div className="flex items-center gap-1 justify-end">
                            <Button
                              variant="ghost"
                              size="sm"
                              disabled={!id}
                              aria-label={t('MikroTikDnsTab.actions.editAria', { name: dnsLabel })}
                              onClick={() => openEditStatic(row)}
                            >
                              <Pencil className="h-3.5 w-3.5" aria-hidden="true" />
                            </Button>
                            <Button
                              variant="ghost"
                              size="sm"
                              disabled={!id}
                              aria-label={t('MikroTikDnsTab.actions.deleteAria', { name: dnsLabel })}
                              onClick={() => setDeleteTarget(row)}
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

      {/* DNS cache (read-only) */}
      <Card className="border-border/50">
        <CardHeader className="pb-4">
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="flex items-center gap-2">
                <Database className="h-4 w-4" /> {t('MikroTikDnsTab.cache.title')}
              </CardTitle>
              <CardDescription>
                {t('MikroTikDnsTab.cache.description')}
              </CardDescription>
            </div>
            <Button
              variant="outline"
              size="sm"
              disabled={cacheQuery.isFetching}
              onClick={() => cacheQuery.refetch()}
            >
              {cacheQuery.isFetching ? (
                <Loader2 className="h-4 w-4 animate-spin mr-1" />
              ) : (
                <RefreshCw className="h-4 w-4 mr-1" />
              )}
              {t('MikroTikDnsTab.actions.refresh')}
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          {cacheQuery.isError ? (
            <ErrorState
              message={getApiErrorMessage(cacheQuery.error, t('MikroTikDnsTab.cache.loadError'))}
              onRetry={() => cacheQuery.refetch()}
            />
          ) : cacheRows.length === 0 && !cacheQuery.isLoading ? (
            <EmptyState
              variant="compact"
              title={t('MikroTikDnsTab.cache.emptyTitle')}
              description={t('MikroTikDnsTab.cache.emptyDescription')}
            />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b text-left text-muted-foreground">
                    <th className="px-3 py-2 font-medium">{t('MikroTikDnsTab.columns.name')}</th>
                    <th className="px-3 py-2 font-medium">{t('MikroTikDnsTab.columns.type')}</th>
                    <th className="px-3 py-2 font-medium">{t('MikroTikDnsTab.columns.data')}</th>
                    <th className="px-3 py-2 font-medium">{t('MikroTikDnsTab.columns.ttl')}</th>
                    <th className="px-3 py-2 font-medium">{t('MikroTikDnsTab.columns.static')}</th>
                  </tr>
                </thead>
                <tbody>
                  {cacheRows.map((row, idx) => {
                    const id = (row['.id'] as string | undefined) ?? String(idx);
                    return (
                      <tr key={id} className="border-b last:border-0">
                        <td className="px-3 py-2 font-mono text-xs">{asStr(row.name)}</td>
                        <td className="px-3 py-2">
                          <Badge variant="secondary">{asStr(row.type) || 'A'}</Badge>
                        </td>
                        <td className="px-3 py-2 font-mono text-xs">{asStr(row.data)}</td>
                        <td className="px-3 py-2">{asStr(row.ttl)}</td>
                        <td className="px-3 py-2">
                          <Badge variant={asBool(row.static) ? 'default' : 'secondary'}>
                            {asBool(row.static) ? t('MikroTikDnsTab.yes') : t('MikroTikDnsTab.no')}
                          </Badge>
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

      {/* Static entry dialog */}
      <Dialog open={staticFormOpen} onOpenChange={setStaticFormOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>
              {editingStatic ? t('MikroTikDnsTab.dialog.editTitle') : t('MikroTikDnsTab.dialog.addTitle')}
            </DialogTitle>
            <DialogDescription>
              {t('MikroTikDnsTab.dialog.description')}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            <div className="space-y-2">
              <Label htmlFor="mtk-dns-name">{t('MikroTikDnsTab.dialog.nameLabel')}</Label>
              <Input
                id="mtk-dns-name"
                value={staticForm.name}
                onChange={(e) => setStaticForm((f) => ({ ...f, name: e.target.value }))}
                placeholder="server.lan"
                autoFocus
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="mtk-dns-type">{t('MikroTikDnsTab.dialog.typeLabel')}</Label>
              <select
                id="mtk-dns-type"
                value={staticForm.type}
                onChange={(e) => setStaticForm((f) => ({ ...f, type: e.target.value }))}
                className="w-full rounded-md border bg-background px-3 py-2 text-sm"
              >
                <option value="A">A</option>
                <option value="AAAA">AAAA</option>
                <option value="CNAME">CNAME</option>
                <option value="TXT">TXT</option>
              </select>
            </div>
            {(staticForm.type === 'A' || staticForm.type === 'AAAA') && (
              <div className="space-y-2">
                <Label htmlFor="mtk-dns-addr">{t('MikroTikDnsTab.dialog.addressLabel')}</Label>
                <Input
                  id="mtk-dns-addr"
                  value={staticForm.address}
                  onChange={(e) =>
                    setStaticForm((f) => ({ ...f, address: e.target.value }))
                  }
                  placeholder={staticForm.type === 'AAAA' ? '::1' : '192.168.88.10'}
                />
              </div>
            )}
            {staticForm.type === 'CNAME' && (
              <div className="space-y-2">
                <Label htmlFor="mtk-dns-cname">{t('MikroTikDnsTab.dialog.cnameLabel')}</Label>
                <Input
                  id="mtk-dns-cname"
                  value={staticForm.cname}
                  onChange={(e) =>
                    setStaticForm((f) => ({ ...f, cname: e.target.value }))
                  }
                  placeholder="alias.lan"
                />
              </div>
            )}
            {staticForm.type === 'TXT' && (
              <div className="space-y-2">
                <Label htmlFor="mtk-dns-text">{t('MikroTikDnsTab.dialog.textLabel')}</Label>
                <Input
                  id="mtk-dns-text"
                  value={staticForm.text}
                  onChange={(e) =>
                    setStaticForm((f) => ({ ...f, text: e.target.value }))
                  }
                  placeholder="v=spf1 -all"
                />
              </div>
            )}
            <div className="space-y-2">
              <Label htmlFor="mtk-dns-ttl">{t('MikroTikDnsTab.dialog.ttlLabel')}</Label>
              <Input
                id="mtk-dns-ttl"
                value={staticForm.ttl}
                onChange={(e) => setStaticForm((f) => ({ ...f, ttl: e.target.value }))}
                placeholder="1d"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="mtk-dns-comment">{t('MikroTikDnsTab.dialog.commentLabel')}</Label>
              <Input
                id="mtk-dns-comment"
                value={staticForm.comment}
                onChange={(e) =>
                  setStaticForm((f) => ({ ...f, comment: e.target.value }))
                }
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setStaticFormOpen(false)}>
              {t('MikroTikDnsTab.actions.cancel')}
            </Button>
            <Button
              onClick={submitStatic}
              disabled={
                createStaticMut.isPending ||
                updateStaticMut.isPending ||
                staticForm.name.trim().length === 0
              }
            >
              {(createStaticMut.isPending || updateStaticMut.isPending) && (
                <Loader2 className="h-4 w-4 animate-spin mr-1" />
              )}
              {editingStatic ? t('MikroTikDnsTab.actions.stageUpdate') : t('MikroTikDnsTab.actions.stageCreate')}
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
            <DialogTitle>{t('MikroTikDnsTab.deleteDialog.title')}</DialogTitle>
            <DialogDescription>
              {t('MikroTikDnsTab.deleteDialog.descriptionPrefix')}{' '}
              <span className="font-mono">{asStr(deleteTarget?.name)}</span>.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDeleteTarget(null)}>
              {t('MikroTikDnsTab.actions.cancel')}
            </Button>
            <Button
              variant="destructive"
              disabled={deleteStaticMut.isPending}
              onClick={submitDelete}
            >
              {deleteStaticMut.isPending && (
                <Loader2 className="h-4 w-4 animate-spin mr-1" />
              )}
              {t('MikroTikDnsTab.actions.stageDelete')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * MikroTikQueuesTab · RouterOS QoS, simple queues + queue tree.
 *
 * Two sub-panes:
 * - Simple queues (``/queue/simple``): full CRUD via stage
 *   (``mikrotik.queues.simple``). The dialog covers the operator's
 *   most common fields (name, target, max-limit up/down via the
 *   combined ``rx/tx`` RouterOS form, priority, parent, comment).
 * - Queue tree (``/queue/tree``): read-only display for now. The
 *   tree is hierarchical (HTB classes with parent links) and the
 *   editor surface is large enough that it benefits from a dedicated
 *   commit; this view surfaces the rows so operators can sanity-check
 *   the tree, with edits deferred to a later release.
 *
 * RouterOS quirk: ``max-limit`` is a single ``rx/tx`` string like
 * ``5M/10M``. The dialog accepts split up/down fields for ergonomics
 * and joins them before sending. Empty up *or* down is rejected.
 */
import { useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  Gauge,
  Loader2,
  Pencil,
  Plus,
  RefreshCw,
  Trash2,
  TreePine,
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
  type MikroTikQueueTree,
  type MikroTikSimpleQueue,
} from '@/lib/api';

export interface MikroTikQueuesTabProps {
  controllerId: string;
  isActive: boolean;
  /** Display name of the controller, surfaced in error toasts. */
  gatewayName?: string;
}

const SIMPLE_KEY = (cid: string) => ['mikrotik', cid, 'queues-simple'];
const TREE_KEY = (cid: string) => ['mikrotik', cid, 'queues-tree'];

type SimpleForm = {
  name: string;
  target: string;
  maxLimitUp: string;
  maxLimitDown: string;
  priority: string;
  parent: string;
  comment: string;
};

const BLANK_SIMPLE: SimpleForm = {
  name: '',
  target: '',
  maxLimitUp: '',
  maxLimitDown: '',
  priority: '8',
  parent: '',
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

/** Split a RouterOS rx/tx string like ``5M/10M`` into [up, down]. */
function splitRxTx(value: unknown): [string, string] {
  if (typeof value !== 'string') return ['', ''];
  const parts = value.split('/');
  if (parts.length !== 2) return [value, ''];
  return [parts[0] ?? '', parts[1] ?? ''];
}

export function MikroTikQueuesTab({
  controllerId,
  isActive,
  gatewayName,
}: MikroTikQueuesTabProps) {
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const { t } = useTranslation('firewall');
  const ctx = gatewayName ? `${gatewayName}: ` : '';

  const [simpleFormOpen, setSimpleFormOpen] = useState(false);
  const [editingSimple, setEditingSimple] = useState<MikroTikSimpleQueue | null>(null);
  const [simpleForm, setSimpleForm] = useState<SimpleForm>(BLANK_SIMPLE);
  const [deleteTarget, setDeleteTarget] = useState<MikroTikSimpleQueue | null>(null);

  const simple = useQuery({
    queryKey: SIMPLE_KEY(controllerId),
    queryFn: () => mikrotikApi.getSimpleQueues(controllerId),
    enabled: !!controllerId && isActive,
    refetchInterval: 60_000,
  });

  const tree = useQuery({
    queryKey: TREE_KEY(controllerId),
    queryFn: () => mikrotikApi.getQueueTree(controllerId),
    enabled: !!controllerId && isActive,
    refetchInterval: 60_000,
  });

  // MEDIUM-4: stable row arrays across renders.
  const simpleRows: MikroTikSimpleQueue[] = useMemo(
    () => simple.data?.data.items ?? [],
    [simple.data],
  );
  const treeRows: MikroTikQueueTree[] = useMemo(
    () => tree.data?.data.items ?? [],
    [tree.data],
  );

  const createSimpleMut = useMutation({
    mutationFn: (payload: Record<string, unknown>) =>
      mikrotikApi.createSimpleQueue(controllerId, payload),
    onSuccess: () => {
      toast({ title: t('MikroTikQueuesTab.toasts.createStaged') });
      setSimpleFormOpen(false);
      queryClient.invalidateQueries({ queryKey: SIMPLE_KEY(controllerId) });
    },
    onError: (err) =>
      toast({
        title: `${ctx}${t('MikroTikQueuesTab.toasts.createFailed')}`,
        description: getApiErrorMessage(err),
        variant: 'destructive',
      }),
  });

  const updateSimpleMut = useMutation({
    mutationFn: ({ id, payload }: { id: string; payload: Record<string, unknown> }) =>
      mikrotikApi.updateSimpleQueue(controllerId, id, payload),
    onSuccess: () => {
      toast({ title: t('MikroTikQueuesTab.toasts.updateStaged') });
      setSimpleFormOpen(false);
      queryClient.invalidateQueries({ queryKey: SIMPLE_KEY(controllerId) });
    },
    onError: (err) =>
      toast({
        title: `${ctx}${t('MikroTikQueuesTab.toasts.updateFailed')}`,
        description: getApiErrorMessage(err),
        variant: 'destructive',
      }),
  });

  const deleteSimpleMut = useMutation({
    mutationFn: (id: string) => mikrotikApi.deleteSimpleQueue(controllerId, id),
    onSuccess: () => {
      toast({ title: t('MikroTikQueuesTab.toasts.deleteStaged') });
      setDeleteTarget(null);
      queryClient.invalidateQueries({ queryKey: SIMPLE_KEY(controllerId) });
    },
    onError: (err) =>
      toast({
        title: `${ctx}${t('MikroTikQueuesTab.toasts.deleteFailed')}`,
        description: getApiErrorMessage(err),
        variant: 'destructive',
      }),
  });

  function openNewSimple() {
    setEditingSimple(null);
    setSimpleForm(BLANK_SIMPLE);
    setSimpleFormOpen(true);
  }

  function openEditSimple(row: MikroTikSimpleQueue) {
    setEditingSimple(row);
    const [up, down] = splitRxTx(row['max-limit']);
    setSimpleForm({
      name: typeof row.name === 'string' ? row.name : '',
      target: typeof row.target === 'string' ? row.target : '',
      maxLimitUp: up,
      maxLimitDown: down,
      priority:
        typeof row.priority === 'string'
          ? row.priority
          : typeof row.priority === 'number'
            ? String(row.priority)
            : '8',
      parent: typeof row.parent === 'string' ? row.parent : '',
      comment: typeof row.comment === 'string' ? row.comment : '',
    });
    setSimpleFormOpen(true);
  }

  function submitSimple() {
    const trimmed = {
      name: simpleForm.name.trim(),
      target: simpleForm.target.trim(),
      maxLimitUp: simpleForm.maxLimitUp.trim(),
      maxLimitDown: simpleForm.maxLimitDown.trim(),
      priority: simpleForm.priority.trim() || '8',
      parent: simpleForm.parent.trim(),
      comment: simpleForm.comment.trim(),
    };
    if (!trimmed.name || !trimmed.target) return;
    if (!trimmed.maxLimitUp || !trimmed.maxLimitDown) return;
    const payload: Record<string, unknown> = {
      name: trimmed.name,
      target: trimmed.target,
      'max-limit': `${trimmed.maxLimitUp}/${trimmed.maxLimitDown}`,
      priority: trimmed.priority,
    };
    if (trimmed.parent) payload.parent = trimmed.parent;
    if (trimmed.comment) payload.comment = trimmed.comment;

    if (editingSimple) {
      const id = (editingSimple['.id'] as string | undefined) ?? '';
      if (!id) {
        toast({
          title: t('MikroTikQueuesTab.toasts.cannotUpdateTitle'),
          description: t('MikroTikQueuesTab.toasts.missingIdDescription'),
          variant: 'destructive',
        });
        return;
      }
      updateSimpleMut.mutate({ id, payload });
    } else {
      createSimpleMut.mutate(payload);
    }
  }

  function submitDelete() {
    if (!deleteTarget) return;
    const id = (deleteTarget['.id'] as string | undefined) ?? '';
    if (!id) {
      toast({
        title: t('MikroTikQueuesTab.toasts.cannotDeleteTitle'),
        description: t('MikroTikQueuesTab.toasts.missingIdDescription'),
        variant: 'destructive',
      });
      return;
    }
    deleteSimpleMut.mutate(id);
  }

  if (simple.isLoading && tree.isLoading) {
    return (
      <div className="flex items-center justify-center py-16 text-muted-foreground">
        <Loader2 className="h-5 w-5 animate-spin mr-2" />
        {t('MikroTikQueuesTab.loading')}
      </div>
    );
  }

  const anyFetching = simple.isFetching || tree.isFetching;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-end">
        <Button
          variant="outline"
          size="sm"
          disabled={anyFetching}
          onClick={() => {
            simple.refetch();
            tree.refetch();
          }}
        >
          {anyFetching ? (
            <Loader2 className="h-4 w-4 animate-spin mr-1" />
          ) : (
            <RefreshCw className="h-4 w-4 mr-1" />
          )}
          {t('MikroTikQueuesTab.actions.refresh')}
        </Button>
      </div>

      {/* Simple queues */}
      <Card className="border-border/50">
        <CardHeader className="pb-4">
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="flex items-center gap-2">
                <Gauge className="h-4 w-4" /> {t('MikroTikQueuesTab.simple.title')}
              </CardTitle>
              <CardDescription>
                {t('MikroTikQueuesTab.simple.description')}
              </CardDescription>
            </div>
            <Button size="sm" onClick={openNewSimple}>
              <Plus className="h-4 w-4 mr-1" /> {t('MikroTikQueuesTab.actions.addQueue')}
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          {simple.isError ? (
            <ErrorState
              message={getApiErrorMessage(simple.error, t('MikroTikQueuesTab.simple.loadError'))}
              onRetry={() => simple.refetch()}
            />
          ) : simpleRows.length === 0 && !simple.isLoading ? (
            <EmptyState
              variant="compact"
              title={t('MikroTikQueuesTab.simple.emptyTitle')}
              description={t('MikroTikQueuesTab.simple.emptyDescription')}
              action={{ label: t('MikroTikQueuesTab.actions.addQueue'), icon: Plus, onClick: openNewSimple }}
            />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b text-left text-muted-foreground">
                    <th className="px-3 py-2 font-medium">{t('MikroTikQueuesTab.columns.name')}</th>
                    <th className="px-3 py-2 font-medium">{t('MikroTikQueuesTab.columns.target')}</th>
                    <th className="px-3 py-2 font-medium">{t('MikroTikQueuesTab.columns.maxLimitUpDown')}</th>
                    <th className="px-3 py-2 font-medium">{t('MikroTikQueuesTab.columns.priority')}</th>
                    <th className="px-3 py-2 font-medium">{t('MikroTikQueuesTab.columns.parent')}</th>
                    <th className="px-3 py-2 font-medium">{t('MikroTikQueuesTab.columns.enabled')}</th>
                    <th className="px-3 py-2 font-medium">{t('MikroTikQueuesTab.columns.comment')}</th>
                    <th className="px-3 py-2 font-medium text-right">{t('MikroTikQueuesTab.columns.actions')}</th>
                  </tr>
                </thead>
                <tbody>
                  {simpleRows.map((row) => {
                    const id = (row['.id'] as string | undefined) ?? '';
                    const enabled = !asBool(row.disabled);
                    const queueLabel =
                      asStr(row.name) !== '-'
                        ? asStr(row.name)
                        : id || t('MikroTikQueuesTab.queueFallback');
                    return (
                      <tr key={id || row.name || Math.random()} className="border-b last:border-0">
                        <td className="px-3 py-2 font-medium">{asStr(row.name)}</td>
                        <td className="px-3 py-2 font-mono text-xs">{asStr(row.target)}</td>
                        <td className="px-3 py-2 font-mono text-xs">{asStr(row['max-limit'])}</td>
                        <td className="px-3 py-2">{asStr(row.priority)}</td>
                        <td className="px-3 py-2">{asStr(row.parent)}</td>
                        <td className="px-3 py-2">
                          <Badge variant={enabled ? 'default' : 'secondary'}>
                            {enabled
                              ? t('MikroTikQueuesTab.enabled.yes')
                              : t('MikroTikQueuesTab.enabled.no')}
                          </Badge>
                        </td>
                        <td className="px-3 py-2 text-xs text-muted-foreground">{asStr(row.comment)}</td>
                        <td className="px-3 py-2 text-right">
                          <div className="flex items-center gap-1 justify-end">
                            <Button
                              variant="ghost"
                              size="sm"
                              disabled={!id}
                              aria-label={t('MikroTikQueuesTab.actions.editAria', { name: queueLabel })}
                              onClick={() => openEditSimple(row)}
                            >
                              <Pencil className="h-3.5 w-3.5" aria-hidden="true" />
                            </Button>
                            <Button
                              variant="ghost"
                              size="sm"
                              disabled={!id}
                              aria-label={t('MikroTikQueuesTab.actions.deleteAria', { name: queueLabel })}
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

      {/* Queue tree, read-only display */}
      <Card className="border-border/50">
        <CardHeader className="pb-4">
          <CardTitle className="flex items-center gap-2">
            <TreePine className="h-4 w-4" /> {t('MikroTikQueuesTab.tree.title')}
          </CardTitle>
          <CardDescription>
            {t('MikroTikQueuesTab.tree.description')}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {tree.isError ? (
            <ErrorState
              message={getApiErrorMessage(tree.error, t('MikroTikQueuesTab.tree.loadError'))}
              onRetry={() => tree.refetch()}
            />
          ) : treeRows.length === 0 && !tree.isLoading ? (
            <EmptyState
              variant="compact"
              title={t('MikroTikQueuesTab.tree.emptyTitle')}
              description={t('MikroTikQueuesTab.tree.emptyDescription')}
            />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b text-left text-muted-foreground">
                    <th className="px-3 py-2 font-medium">{t('MikroTikQueuesTab.columns.name')}</th>
                    <th className="px-3 py-2 font-medium">{t('MikroTikQueuesTab.columns.parent')}</th>
                    <th className="px-3 py-2 font-medium">{t('MikroTikQueuesTab.columns.packetMark')}</th>
                    <th className="px-3 py-2 font-medium">{t('MikroTikQueuesTab.columns.queue')}</th>
                    <th className="px-3 py-2 font-medium">{t('MikroTikQueuesTab.columns.priority')}</th>
                    <th className="px-3 py-2 font-medium">{t('MikroTikQueuesTab.columns.maxLimit')}</th>
                    <th className="px-3 py-2 font-medium">{t('MikroTikQueuesTab.columns.limitAt')}</th>
                  </tr>
                </thead>
                <tbody>
                  {treeRows.map((row, idx) => {
                    const id = (row['.id'] as string | undefined) ?? String(idx);
                    return (
                      <tr key={id} className="border-b last:border-0">
                        <td className="px-3 py-2 font-medium">{asStr(row.name)}</td>
                        <td className="px-3 py-2 font-mono text-xs">{asStr(row.parent)}</td>
                        <td className="px-3 py-2 font-mono text-xs">{asStr(row['packet-mark'])}</td>
                        <td className="px-3 py-2">{asStr(row.queue)}</td>
                        <td className="px-3 py-2">{asStr(row.priority)}</td>
                        <td className="px-3 py-2 font-mono text-xs">{asStr(row['max-limit'])}</td>
                        <td className="px-3 py-2 font-mono text-xs">{asStr(row['limit-at'])}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Simple queue form dialog */}
      <Dialog open={simpleFormOpen} onOpenChange={setSimpleFormOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>
              {editingSimple
                ? t('MikroTikQueuesTab.dialog.editTitle')
                : t('MikroTikQueuesTab.dialog.addTitle')}
            </DialogTitle>
            <DialogDescription>
              {t('MikroTikQueuesTab.dialog.description')}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            <div className="space-y-2">
              <Label htmlFor="mtk-q-name">{t('MikroTikQueuesTab.form.name')}</Label>
              <Input
                id="mtk-q-name"
                value={simpleForm.name}
                onChange={(e) => setSimpleForm((f) => ({ ...f, name: e.target.value }))}
                placeholder={t('MikroTikQueuesTab.form.namePlaceholder')}
                autoFocus
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="mtk-q-target">{t('MikroTikQueuesTab.form.target')}</Label>
              <Input
                id="mtk-q-target"
                value={simpleForm.target}
                onChange={(e) =>
                  setSimpleForm((f) => ({ ...f, target: e.target.value }))
                }
                placeholder={t('MikroTikQueuesTab.form.targetPlaceholder')}
              />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-2">
                <Label htmlFor="mtk-q-up">{t('MikroTikQueuesTab.form.maxLimitUp')}</Label>
                <Input
                  id="mtk-q-up"
                  value={simpleForm.maxLimitUp}
                  onChange={(e) =>
                    setSimpleForm((f) => ({ ...f, maxLimitUp: e.target.value }))
                  }
                  placeholder="5M"
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="mtk-q-down">{t('MikroTikQueuesTab.form.maxLimitDown')}</Label>
                <Input
                  id="mtk-q-down"
                  value={simpleForm.maxLimitDown}
                  onChange={(e) =>
                    setSimpleForm((f) => ({ ...f, maxLimitDown: e.target.value }))
                  }
                  placeholder="10M"
                />
              </div>
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-2">
                <Label htmlFor="mtk-q-prio">{t('MikroTikQueuesTab.form.priority')}</Label>
                <Input
                  id="mtk-q-prio"
                  value={simpleForm.priority}
                  onChange={(e) =>
                    setSimpleForm((f) => ({ ...f, priority: e.target.value }))
                  }
                  placeholder="8"
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="mtk-q-parent">{t('MikroTikQueuesTab.form.parent')}</Label>
                <Input
                  id="mtk-q-parent"
                  value={simpleForm.parent}
                  onChange={(e) =>
                    setSimpleForm((f) => ({ ...f, parent: e.target.value }))
                  }
                  placeholder={t('MikroTikQueuesTab.form.parentPlaceholder')}
                />
              </div>
            </div>
            <div className="space-y-2">
              <Label htmlFor="mtk-q-comment">{t('MikroTikQueuesTab.form.comment')}</Label>
              <Input
                id="mtk-q-comment"
                value={simpleForm.comment}
                onChange={(e) =>
                  setSimpleForm((f) => ({ ...f, comment: e.target.value }))
                }
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setSimpleFormOpen(false)}>
              {t('MikroTikQueuesTab.actions.cancel')}
            </Button>
            <Button
              onClick={submitSimple}
              disabled={
                createSimpleMut.isPending ||
                updateSimpleMut.isPending ||
                simpleForm.name.trim().length === 0 ||
                simpleForm.target.trim().length === 0 ||
                simpleForm.maxLimitUp.trim().length === 0 ||
                simpleForm.maxLimitDown.trim().length === 0
              }
            >
              {(createSimpleMut.isPending || updateSimpleMut.isPending) && (
                <Loader2 className="h-4 w-4 animate-spin mr-1" />
              )}
              {editingSimple
                ? t('MikroTikQueuesTab.actions.stageUpdate')
                : t('MikroTikQueuesTab.actions.stageCreate')}
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
            <DialogTitle>{t('MikroTikQueuesTab.delete.title')}</DialogTitle>
            <DialogDescription>
              {t('MikroTikQueuesTab.delete.descriptionPrefix')}{' '}
              <span className="font-mono">{asStr(deleteTarget?.name)}</span>
              {t('MikroTikQueuesTab.delete.descriptionSuffix')}
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDeleteTarget(null)}>
              {t('MikroTikQueuesTab.actions.cancel')}
            </Button>
            <Button
              variant="destructive"
              disabled={deleteSimpleMut.isPending}
              onClick={submitDelete}
            >
              {deleteSimpleMut.isPending && (
                <Loader2 className="h-4 w-4 animate-spin mr-1" />
              )}
              {t('MikroTikQueuesTab.actions.stageDelete')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

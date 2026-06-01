// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * MikroTikFirewallTab · /ip/firewall filter + NAT rule CRUD.
 *
 * Filter rules:
 *   - Full CRUD via stage (``mikrotik.firewall.filter_rule``).
 *   - Drag-and-drop reorder via @dnd-kit. The reorder action stages a
 *     ``mikrotik.firewall.filter_reorder`` change carrying the full
 *     ordered ID array. RouterOS rule order is load-bearing (match-first
 *     wins) so this is the operator's main "move rule up/down" path.
 *
 * NAT rules:
 *   - Full CRUD via stage (``mikrotik.firewall.nat_rule``). No reorder
 *     (the chain is far less order-sensitive for NAT).
 */
import { useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  DndContext,
  KeyboardSensor,
  PointerSensor,
  closestCenter,
  useSensor,
  useSensors,
  type DragEndEvent,
} from '@dnd-kit/core';
import {
  SortableContext,
  arrayMove,
  useSortable,
  verticalListSortingStrategy,
  sortableKeyboardCoordinates,
} from '@dnd-kit/sortable';
import { CSS } from '@dnd-kit/utilities';
import {
  GripVertical,
  Loader2,
  Pencil,
  Plus,
  RefreshCw,
  Shield,
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
  type MikroTikFirewallFilterRule,
  type MikroTikFirewallNATRule,
} from '@/lib/api';
import { getRouterId } from './_shared';

export interface MikroTikFirewallTabProps {
  controllerId: string;
  isActive: boolean;
  /** Display name of the controller, surfaced in error toasts. */
  gatewayName?: string;
}

const FILTER_KEY = (cid: string) => ['mikrotik', cid, 'fw-filter'];
const NAT_KEY = (cid: string) => ['mikrotik', cid, 'fw-nat'];

type FilterForm = {
  chain: string;
  action: string;
  protocol: string;
  srcAddress: string;
  dstAddress: string;
  dstPort: string;
  inInterface: string;
  comment: string;
};

type NatForm = {
  chain: string;
  action: string;
  protocol: string;
  srcAddress: string;
  dstAddress: string;
  dstPort: string;
  toAddresses: string;
  toPorts: string;
  comment: string;
};

const BLANK_FILTER: FilterForm = {
  chain: 'forward',
  action: 'accept',
  protocol: '',
  srcAddress: '',
  dstAddress: '',
  dstPort: '',
  inInterface: '',
  comment: '',
};

const BLANK_NAT: NatForm = {
  chain: 'srcnat',
  action: 'masquerade',
  protocol: '',
  srcAddress: '',
  dstAddress: '',
  dstPort: '',
  toAddresses: '',
  toPorts: '',
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

function actionVariant(action: unknown): 'default' | 'destructive' | 'secondary' {
  if (typeof action !== 'string') return 'secondary';
  if (action === 'accept') return 'default';
  if (action === 'drop' || action === 'reject') return 'destructive';
  return 'secondary';
}

// ── Sortable row component for filter rules ─────────────────────────────

interface SortableFilterRowProps {
  row: MikroTikFirewallFilterRule;
  onEdit: (row: MikroTikFirewallFilterRule) => void;
  onDelete: (row: MikroTikFirewallFilterRule) => void;
  /** When true, grip is non-interactive (in-flight reorder). */
  dragDisabled?: boolean;
}

function SortableFilterRow({ row, onEdit, onDelete, dragDisabled }: SortableFilterRowProps) {
  const { t } = useTranslation('firewall');
  const id = getRouterId(row);
  // human-readable label for the edit/delete buttons. Prefer
  // the operator-set comment, then fall back to chain/action shape,
  // then to the RouterOS .id. Screen readers / automated tests need a
  // deterministic identifier here, not "(unnamed)" or the icon name.
  const ruleLabel =
    asStr(row.comment) !== '-'
      ? asStr(row.comment)
      : `${asStr(row.chain)} ${asStr(row.action)}`.trim() || id || t('MikroTikFirewallTab.ruleFallback');
  const {
    attributes,
    listeners,
    setNodeRef,
    transform,
    transition,
    isDragging,
  } = useSortable({ id });

  const style = {
    transform: CSS.Transform.toString(transform),
    transition,
    opacity: isDragging ? 0.4 : 1,
  };

  return (
    <tr
      ref={setNodeRef}
      style={style}
      className="border-b last:border-0 bg-card"
    >
      <td
        className={
          'px-2 py-2 w-8 text-muted-foreground ' +
          (dragDisabled ? 'cursor-not-allowed opacity-40' : 'cursor-grab')
        }
        aria-label={t('MikroTikFirewallTab.dragToReorder')}
        aria-disabled={dragDisabled || undefined}
        role="button"
        {...(dragDisabled ? {} : attributes)}
        {...(dragDisabled ? {} : listeners)}
      >
        <GripVertical className="h-4 w-4" aria-hidden="true" />
      </td>
      <td className="px-3 py-2 font-mono text-xs">{asStr(row.chain)}</td>
      <td className="px-3 py-2">
        <Badge variant={actionVariant(row.action)}>{asStr(row.action)}</Badge>
      </td>
      <td className="px-3 py-2 text-xs">{asStr(row.protocol)}</td>
      <td className="px-3 py-2 text-xs font-mono">{asStr(row['src-address'])}</td>
      <td className="px-3 py-2 text-xs font-mono">{asStr(row['dst-address'])}</td>
      <td className="px-3 py-2 text-xs">{asStr(row['dst-port'])}</td>
      <td className="px-3 py-2 text-xs">{asStr(row['in-interface'])}</td>
      <td className="px-3 py-2">
        <Badge variant={asBool(row.disabled) ? 'secondary' : 'default'}>
          {asBool(row.disabled) ? t('MikroTikFirewallTab.no') : t('MikroTikFirewallTab.yes')}
        </Badge>
      </td>
      <td className="px-3 py-2 text-xs text-muted-foreground">{asStr(row.comment)}</td>
      <td className="px-3 py-2 text-right">
        <div className="flex items-center gap-1 justify-end">
          <Button
            variant="ghost"
            size="sm"
            disabled={!id}
            aria-label={t('MikroTikFirewallTab.aria.editFilterRule', { label: ruleLabel })}
            onClick={() => onEdit(row)}
          >
            <Pencil className="h-3.5 w-3.5" aria-hidden="true" />
          </Button>
          <Button
            variant="ghost"
            size="sm"
            disabled={!id}
            aria-label={t('MikroTikFirewallTab.aria.deleteFilterRule', { label: ruleLabel })}
            onClick={() => onDelete(row)}
          >
            <Trash2 className="h-3.5 w-3.5 text-destructive" aria-hidden="true" />
          </Button>
        </div>
      </td>
    </tr>
  );
}

// ── Main component ──────────────────────────────────────────────────────

type DeleteTarget =
  | { kind: 'filter'; row: MikroTikFirewallFilterRule }
  | { kind: 'nat'; row: MikroTikFirewallNATRule };

export function MikroTikFirewallTab({
  controllerId,
  isActive,
  gatewayName,
}: MikroTikFirewallTabProps) {
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const { t } = useTranslation('firewall');
  const ctx = gatewayName ? `${gatewayName}: ` : '';

  const [filterFormOpen, setFilterFormOpen] = useState(false);
  const [editingFilter, setEditingFilter] = useState<MikroTikFirewallFilterRule | null>(null);
  const [filterForm, setFilterForm] = useState<FilterForm>(BLANK_FILTER);

  const [natFormOpen, setNatFormOpen] = useState(false);
  const [editingNat, setEditingNat] = useState<MikroTikFirewallNATRule | null>(null);
  const [natForm, setNatForm] = useState<NatForm>(BLANK_NAT);

  const [deleteTarget, setDeleteTarget] = useState<DeleteTarget | null>(null);

  // Local ordered IDs for drag-and-drop · seeded from the server,
  // re-synced whenever the server list changes (e.g. after a reload).
  const [localOrder, setLocalOrder] = useState<string[]>([]);
  const [orderDirty, setOrderDirty] = useState(false);

  const filterQ = useQuery({
    queryKey: FILTER_KEY(controllerId),
    queryFn: () => mikrotikApi.getFilterRules(controllerId),
    enabled: !!controllerId && isActive,
    refetchInterval: 60_000,
  });

  const natQ = useQuery({
    queryKey: NAT_KEY(controllerId),
    queryFn: () => mikrotikApi.getNATRules(controllerId),
    enabled: !!controllerId && isActive,
    refetchInterval: 60_000,
  });

  // Memoise filterRows so dependent useMemo / useEffect get a stable
  // reference (silences react-hooks/exhaustive-deps warning).
  const filterRows: MikroTikFirewallFilterRule[] = useMemo(
    () => filterQ.data?.data.items ?? [],
    [filterQ.data],
  );
  const natRows: MikroTikFirewallNATRule[] = natQ.data?.data.items ?? [];

  // Build id-keyed lookup and seed local order if we haven't touched it.
  const filterById = useMemo(() => {
    const map = new Map<string, MikroTikFirewallFilterRule>();
    for (const row of filterRows) {
      const id = (row['.id'] as string | undefined) ?? '';
      if (id) map.set(id, row);
    }
    return map;
  }, [filterRows]);

  useEffect(() => {
    if (orderDirty) return;
    const serverOrder = filterRows
      .map((row) => (row['.id'] as string | undefined) ?? '')
      .filter((id) => id.length > 0);
    setLocalOrder(serverOrder);
  }, [filterRows, orderDirty]);

  const orderedFilters = useMemo(
    () =>
      localOrder
        .map((id) => filterById.get(id))
        .filter((row): row is MikroTikFirewallFilterRule => row !== undefined),
    [localOrder, filterById],
  );

  // Always-on sensor set. We don't conditionally drop sensors during
  // an in-flight reorder because pre-React 19 useSensors memoises the
  // sensor instance and toggling its arguments per render can produce
  // unstable references. Instead we guard the side-effecting handlers
  const sensors = useSensors(
    useSensor(PointerSensor, { activationConstraint: { distance: 4 } }),
    useSensor(KeyboardSensor, { coordinateGetter: sortableKeyboardCoordinates }),
  );

  function handleDragEnd(event: DragEndEvent) {
    // lock DnD while a reorder is in-flight. A second drag
    // before the stage-reorder request settles would otherwise compute
    // its `arrayMove` against the *displayed* (proposed) order, but
    // send the IDs in an order the backend hasn't yet acked.
    if (reorderMut.isPending) return;
    const { active, over } = event;
    if (!over || active.id === over.id) return;
    const oldIdx = localOrder.indexOf(String(active.id));
    const newIdx = localOrder.indexOf(String(over.id));
    if (oldIdx < 0 || newIdx < 0) return;
    setLocalOrder((prev) => arrayMove(prev, oldIdx, newIdx));
    setOrderDirty(true);
  }

  // ── Mutations ────────────────────────────────────────────────────
  const createFilterMut = useMutation({
    mutationFn: (payload: Record<string, unknown>) =>
      mikrotikApi.createFilterRule(controllerId, payload),
    onSuccess: () => {
      toast({ title: t('MikroTikFirewallTab.toast.filterCreateStaged') });
      setFilterFormOpen(false);
      queryClient.invalidateQueries({ queryKey: FILTER_KEY(controllerId) });
    },
    onError: (err) =>
      toast({
        title: t('MikroTikFirewallTab.toast.filterCreateFailed', { ctx }),
        description: getApiErrorMessage(err),
        variant: 'destructive',
      }),
  });

  const updateFilterMut = useMutation({
    mutationFn: ({ id, payload }: { id: string; payload: Record<string, unknown> }) =>
      mikrotikApi.updateFilterRule(controllerId, id, payload),
    onSuccess: () => {
      toast({ title: t('MikroTikFirewallTab.toast.filterUpdateStaged') });
      setFilterFormOpen(false);
      queryClient.invalidateQueries({ queryKey: FILTER_KEY(controllerId) });
    },
    onError: (err) =>
      toast({
        title: t('MikroTikFirewallTab.toast.filterUpdateFailed', { ctx }),
        description: getApiErrorMessage(err),
        variant: 'destructive',
      }),
  });

  const deleteFilterMut = useMutation({
    mutationFn: (id: string) => mikrotikApi.deleteFilterRule(controllerId, id),
    onSuccess: () => {
      toast({ title: t('MikroTikFirewallTab.toast.filterDeleteStaged') });
      setDeleteTarget(null);
      queryClient.invalidateQueries({ queryKey: FILTER_KEY(controllerId) });
    },
    onError: (err) =>
      toast({
        title: t('MikroTikFirewallTab.toast.filterDeleteFailed', { ctx }),
        description: getApiErrorMessage(err),
        variant: 'destructive',
      }),
  });

  const reorderMut = useMutation({
    mutationFn: (orderedIds: string[]) =>
      mikrotikApi.reorderFilterRules(controllerId, orderedIds),
    onSuccess: () => {
      toast({ title: t('MikroTikFirewallTab.toast.reorderStaged') });
      setOrderDirty(false);
      queryClient.invalidateQueries({ queryKey: FILTER_KEY(controllerId) });
    },
    onError: (err) => {
      // a failed reorder must NOT leave the UI displaying the
      // proposed (un-applied) order, otherwise the operator believes
      // the rules are staged in the new positions when they're really
      // still in the original server order. Reset local order back to
      // server truth.
      const serverOrder = filterRows
        .map((row) => getRouterId(row))
        .filter((id) => id.length > 0);
      setLocalOrder(serverOrder);
      setOrderDirty(false);
      toast({
        title: t('MikroTikFirewallTab.toast.reorderFailed', { ctx }),
        description: getApiErrorMessage(err),
        variant: 'destructive',
      });
    },
  });

  const createNatMut = useMutation({
    mutationFn: (payload: Record<string, unknown>) =>
      mikrotikApi.createNATRule(controllerId, payload),
    onSuccess: () => {
      toast({ title: t('MikroTikFirewallTab.toast.natCreateStaged') });
      setNatFormOpen(false);
      queryClient.invalidateQueries({ queryKey: NAT_KEY(controllerId) });
    },
    onError: (err) =>
      toast({
        title: t('MikroTikFirewallTab.toast.natCreateFailed', { ctx }),
        description: getApiErrorMessage(err),
        variant: 'destructive',
      }),
  });

  const updateNatMut = useMutation({
    mutationFn: ({ id, payload }: { id: string; payload: Record<string, unknown> }) =>
      mikrotikApi.updateNATRule(controllerId, id, payload),
    onSuccess: () => {
      toast({ title: t('MikroTikFirewallTab.toast.natUpdateStaged') });
      setNatFormOpen(false);
      queryClient.invalidateQueries({ queryKey: NAT_KEY(controllerId) });
    },
    onError: (err) =>
      toast({
        title: t('MikroTikFirewallTab.toast.natUpdateFailed', { ctx }),
        description: getApiErrorMessage(err),
        variant: 'destructive',
      }),
  });

  const deleteNatMut = useMutation({
    mutationFn: (id: string) => mikrotikApi.deleteNATRule(controllerId, id),
    onSuccess: () => {
      toast({ title: t('MikroTikFirewallTab.toast.natDeleteStaged') });
      setDeleteTarget(null);
      queryClient.invalidateQueries({ queryKey: NAT_KEY(controllerId) });
    },
    onError: (err) =>
      toast({
        title: t('MikroTikFirewallTab.toast.natDeleteFailed', { ctx }),
        description: getApiErrorMessage(err),
        variant: 'destructive',
      }),
  });

  // ── Form helpers ─────────────────────────────────────────────────
  function openNewFilter() {
    setEditingFilter(null);
    setFilterForm(BLANK_FILTER);
    setFilterFormOpen(true);
  }

  function openEditFilter(row: MikroTikFirewallFilterRule) {
    setEditingFilter(row);
    setFilterForm({
      chain: typeof row.chain === 'string' ? row.chain : 'forward',
      action: typeof row.action === 'string' ? row.action : 'accept',
      protocol: typeof row.protocol === 'string' ? row.protocol : '',
      srcAddress: typeof row['src-address'] === 'string' ? row['src-address'] : '',
      dstAddress: typeof row['dst-address'] === 'string' ? row['dst-address'] : '',
      dstPort: typeof row['dst-port'] === 'string' ? row['dst-port'] : '',
      inInterface: typeof row['in-interface'] === 'string' ? row['in-interface'] : '',
      comment: typeof row.comment === 'string' ? row.comment : '',
    });
    setFilterFormOpen(true);
  }

  function buildFilterPayload(form: FilterForm): Record<string, unknown> {
    const payload: Record<string, unknown> = {
      chain: form.chain.trim() || 'forward',
      action: form.action.trim() || 'accept',
    };
    if (form.protocol.trim()) payload.protocol = form.protocol.trim();
    if (form.srcAddress.trim()) payload['src-address'] = form.srcAddress.trim();
    if (form.dstAddress.trim()) payload['dst-address'] = form.dstAddress.trim();
    if (form.dstPort.trim()) payload['dst-port'] = form.dstPort.trim();
    if (form.inInterface.trim()) payload['in-interface'] = form.inInterface.trim();
    if (form.comment.trim()) payload.comment = form.comment.trim();
    return payload;
  }

  function submitFilter() {
    const payload = buildFilterPayload(filterForm);
    if (editingFilter) {
      const id = (editingFilter['.id'] as string | undefined) ?? '';
      if (!id) {
        toast({
          title: t('MikroTikFirewallTab.toast.cannotUpdate'),
          description: t('MikroTikFirewallTab.toast.missingRuleId'),
          variant: 'destructive',
        });
        return;
      }
      updateFilterMut.mutate({ id, payload });
    } else {
      createFilterMut.mutate(payload);
    }
  }

  function openNewNat() {
    setEditingNat(null);
    setNatForm(BLANK_NAT);
    setNatFormOpen(true);
  }

  function openEditNat(row: MikroTikFirewallNATRule) {
    setEditingNat(row);
    setNatForm({
      chain: typeof row.chain === 'string' ? row.chain : 'srcnat',
      action: typeof row.action === 'string' ? row.action : 'masquerade',
      protocol: typeof row.protocol === 'string' ? row.protocol : '',
      srcAddress: typeof row['src-address'] === 'string' ? row['src-address'] : '',
      dstAddress: typeof row['dst-address'] === 'string' ? row['dst-address'] : '',
      dstPort: typeof row['dst-port'] === 'string' ? row['dst-port'] : '',
      toAddresses: typeof row['to-addresses'] === 'string' ? row['to-addresses'] : '',
      toPorts: typeof row['to-ports'] === 'string' ? row['to-ports'] : '',
      comment: typeof row.comment === 'string' ? row.comment : '',
    });
    setNatFormOpen(true);
  }

  function buildNatPayload(form: NatForm): Record<string, unknown> {
    const payload: Record<string, unknown> = {
      chain: form.chain.trim() || 'srcnat',
      action: form.action.trim() || 'masquerade',
    };
    if (form.protocol.trim()) payload.protocol = form.protocol.trim();
    if (form.srcAddress.trim()) payload['src-address'] = form.srcAddress.trim();
    if (form.dstAddress.trim()) payload['dst-address'] = form.dstAddress.trim();
    if (form.dstPort.trim()) payload['dst-port'] = form.dstPort.trim();
    if (form.toAddresses.trim()) payload['to-addresses'] = form.toAddresses.trim();
    if (form.toPorts.trim()) payload['to-ports'] = form.toPorts.trim();
    if (form.comment.trim()) payload.comment = form.comment.trim();
    return payload;
  }

  function submitNat() {
    const payload = buildNatPayload(natForm);
    if (editingNat) {
      const id = (editingNat['.id'] as string | undefined) ?? '';
      if (!id) {
        toast({
          title: t('MikroTikFirewallTab.toast.cannotUpdate'),
          description: t('MikroTikFirewallTab.toast.missingRuleId'),
          variant: 'destructive',
        });
        return;
      }
      updateNatMut.mutate({ id, payload });
    } else {
      createNatMut.mutate(payload);
    }
  }

  function submitDelete() {
    if (!deleteTarget) return;
    const id = (deleteTarget.row['.id'] as string | undefined) ?? '';
    if (!id) {
      toast({
        title: t('MikroTikFirewallTab.toast.cannotDelete'),
        description: t('MikroTikFirewallTab.toast.missingRowId'),
        variant: 'destructive',
      });
      return;
    }
    if (deleteTarget.kind === 'filter') deleteFilterMut.mutate(id);
    else deleteNatMut.mutate(id);
  }

  function resetOrder() {
    const serverOrder = filterRows
      .map((row) => (row['.id'] as string | undefined) ?? '')
      .filter((id) => id.length > 0);
    setLocalOrder(serverOrder);
    setOrderDirty(false);
  }

  if (filterQ.isLoading && natQ.isLoading) {
    return (
      <div className="flex items-center justify-center py-16 text-muted-foreground">
        <Loader2 className="h-5 w-5 animate-spin mr-2" />
        {t('MikroTikFirewallTab.loading')}
      </div>
    );
  }

  // MEDIUM-3: surface the rule's chain / action / src / dst / comment
  // as a structured `<dl>` so an operator about to delete a destructive
  // chain=forward action=accept dst=0.0.0.0/0 rule sees the full scope
  //, not a vague "filter rule forward/accept" label.
  const deleteRuleDetails = (() => {
    if (!deleteTarget) return null;
    if (deleteTarget.kind === 'filter') {
      const r = deleteTarget.row;
      return {
        kind: t('MikroTikFirewallTab.kind.filterRule'),
        chain: asStr(r.chain),
        action: asStr(r.action),
        proto: asStr(r.protocol),
        src: asStr(r['src-address']),
        dst: asStr(r['dst-address']),
        dstPort: asStr(r['dst-port']),
        inIface: asStr(r['in-interface']),
        comment: asStr(r.comment),
      };
    }
    const r = deleteTarget.row;
    return {
      kind: t('MikroTikFirewallTab.kind.natRule'),
      chain: asStr(r.chain),
      action: asStr(r.action),
      proto: asStr(r.protocol),
      src: asStr(r['src-address']),
      dst: asStr(r['dst-address']),
      dstPort: asStr(r['dst-port']),
      inIface: '-',
      comment: asStr(r.comment),
    };
  })();

  const anyFetching = filterQ.isFetching || natQ.isFetching;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-end">
        <Button
          variant="outline"
          size="sm"
          disabled={anyFetching}
          onClick={() => {
            filterQ.refetch();
            natQ.refetch();
          }}
        >
          {anyFetching ? (
            <Loader2 className="h-4 w-4 animate-spin mr-1" />
          ) : (
            <RefreshCw className="h-4 w-4 mr-1" />
          )}
          {t('MikroTikFirewallTab.actions.refresh')}
        </Button>
      </div>

      {/* Filter rules */}
      <Card className="border-border/50">
        <CardHeader className="pb-4">
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="flex items-center gap-2">
                <Shield className="h-4 w-4" /> {t('MikroTikFirewallTab.filter.title')}
              </CardTitle>
              <CardDescription>
                {t('MikroTikFirewallTab.filter.description')}
              </CardDescription>
            </div>
            <div className="flex items-center gap-2">
              {orderDirty && (
                <>
                  <Button variant="outline" size="sm" onClick={resetOrder}>
                    {t('MikroTikFirewallTab.actions.discardReorder')}
                  </Button>
                  <Button
                    size="sm"
                    onClick={() => reorderMut.mutate(localOrder)}
                    disabled={reorderMut.isPending}
                  >
                    {reorderMut.isPending && (
                      <Loader2 className="h-4 w-4 animate-spin mr-1" />
                    )}
                    {t('MikroTikFirewallTab.actions.stageReorder')}
                  </Button>
                </>
              )}
              <Button size="sm" onClick={openNewFilter}>
                <Plus className="h-4 w-4 mr-1" /> {t('MikroTikFirewallTab.actions.addRule')}
              </Button>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {filterQ.isError ? (
            <ErrorState
              message={getApiErrorMessage(filterQ.error, t('MikroTikFirewallTab.filter.loadError'))}
              onRetry={() => filterQ.refetch()}
            />
          ) : orderedFilters.length === 0 && !filterQ.isLoading ? (
            <EmptyState
              variant="compact"
              title={t('MikroTikFirewallTab.filter.emptyTitle')}
              description={t('MikroTikFirewallTab.filter.emptyDescription')}
              action={{ label: t('MikroTikFirewallTab.actions.addRule'), icon: Plus, onClick: openNewFilter }}
            />
          ) : (
            <div className="overflow-x-auto">
              <DndContext
                sensors={sensors}
                collisionDetection={closestCenter}
                onDragEnd={handleDragEnd}
              >
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b text-left text-muted-foreground">
                      <th className="px-2 py-2 w-8"></th>
                      <th className="px-3 py-2 font-medium">{t('MikroTikFirewallTab.columns.chain')}</th>
                      <th className="px-3 py-2 font-medium">{t('MikroTikFirewallTab.columns.action')}</th>
                      <th className="px-3 py-2 font-medium">{t('MikroTikFirewallTab.columns.proto')}</th>
                      <th className="px-3 py-2 font-medium">{t('MikroTikFirewallTab.columns.src')}</th>
                      <th className="px-3 py-2 font-medium">{t('MikroTikFirewallTab.columns.dst')}</th>
                      <th className="px-3 py-2 font-medium">{t('MikroTikFirewallTab.columns.dstPort')}</th>
                      <th className="px-3 py-2 font-medium">{t('MikroTikFirewallTab.columns.inIface')}</th>
                      <th className="px-3 py-2 font-medium">{t('MikroTikFirewallTab.columns.enabled')}</th>
                      <th className="px-3 py-2 font-medium">{t('MikroTikFirewallTab.columns.comment')}</th>
                      <th className="px-3 py-2 font-medium text-right">{t('MikroTikFirewallTab.columns.actions')}</th>
                    </tr>
                  </thead>
                  <SortableContext
                    items={localOrder}
                    strategy={verticalListSortingStrategy}
                  >
                    <tbody>
                      {orderedFilters.map((row) => (
                        <SortableFilterRow
                          key={getRouterId(row)}
                          row={row}
                          onEdit={openEditFilter}
                          onDelete={(r) => setDeleteTarget({ kind: 'filter', row: r })}
                          dragDisabled={reorderMut.isPending}
                        />
                      ))}
                    </tbody>
                  </SortableContext>
                </table>
              </DndContext>
            </div>
          )}
        </CardContent>
      </Card>

      {/* NAT rules */}
      <Card className="border-border/50">
        <CardHeader className="pb-4">
          <div className="flex items-center justify-between">
            <div>
              <CardTitle>{t('MikroTikFirewallTab.nat.title')}</CardTitle>
              <CardDescription>{t('MikroTikFirewallTab.nat.description')}</CardDescription>
            </div>
            <Button size="sm" onClick={openNewNat}>
              <Plus className="h-4 w-4 mr-1" /> {t('MikroTikFirewallTab.actions.addNatRule')}
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          {natQ.isError ? (
            <ErrorState
              message={getApiErrorMessage(natQ.error, t('MikroTikFirewallTab.nat.loadError'))}
              onRetry={() => natQ.refetch()}
            />
          ) : natRows.length === 0 && !natQ.isLoading ? (
            <EmptyState
              variant="compact"
              title={t('MikroTikFirewallTab.nat.emptyTitle')}
              description={t('MikroTikFirewallTab.nat.emptyDescription')}
              action={{ label: t('MikroTikFirewallTab.actions.addNatRule'), icon: Plus, onClick: openNewNat }}
            />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b text-left text-muted-foreground">
                    <th className="px-3 py-2 font-medium">{t('MikroTikFirewallTab.columns.chain')}</th>
                    <th className="px-3 py-2 font-medium">{t('MikroTikFirewallTab.columns.action')}</th>
                    <th className="px-3 py-2 font-medium">{t('MikroTikFirewallTab.columns.proto')}</th>
                    <th className="px-3 py-2 font-medium">{t('MikroTikFirewallTab.columns.src')}</th>
                    <th className="px-3 py-2 font-medium">{t('MikroTikFirewallTab.columns.dst')}</th>
                    <th className="px-3 py-2 font-medium">{t('MikroTikFirewallTab.columns.dstPort')}</th>
                    <th className="px-3 py-2 font-medium">{t('MikroTikFirewallTab.columns.toAddrs')}</th>
                    <th className="px-3 py-2 font-medium">{t('MikroTikFirewallTab.columns.toPorts')}</th>
                    <th className="px-3 py-2 font-medium">{t('MikroTikFirewallTab.columns.enabled')}</th>
                    <th className="px-3 py-2 font-medium">{t('MikroTikFirewallTab.columns.comment')}</th>
                    <th className="px-3 py-2 font-medium text-right">{t('MikroTikFirewallTab.columns.actions')}</th>
                  </tr>
                </thead>
                <tbody>
                  {natRows.map((row) => {
                    const id = (row['.id'] as string | undefined) ?? '';
                    const natLabel =
                      asStr(row.comment) !== '-'
                        ? asStr(row.comment)
                        : `${asStr(row.chain)} ${asStr(row.action)}`.trim() || id || t('MikroTikFirewallTab.ruleFallback');
                    return (
                      <tr key={id || Math.random()} className="border-b last:border-0">
                        <td className="px-3 py-2 font-mono text-xs">{asStr(row.chain)}</td>
                        <td className="px-3 py-2">
                          <Badge variant={actionVariant(row.action)}>{asStr(row.action)}</Badge>
                        </td>
                        <td className="px-3 py-2 text-xs">{asStr(row.protocol)}</td>
                        <td className="px-3 py-2 text-xs font-mono">{asStr(row['src-address'])}</td>
                        <td className="px-3 py-2 text-xs font-mono">{asStr(row['dst-address'])}</td>
                        <td className="px-3 py-2 text-xs">{asStr(row['dst-port'])}</td>
                        <td className="px-3 py-2 text-xs font-mono">{asStr(row['to-addresses'])}</td>
                        <td className="px-3 py-2 text-xs">{asStr(row['to-ports'])}</td>
                        <td className="px-3 py-2">
                          <Badge variant={asBool(row.disabled) ? 'secondary' : 'default'}>
                            {asBool(row.disabled) ? t('MikroTikFirewallTab.no') : t('MikroTikFirewallTab.yes')}
                          </Badge>
                        </td>
                        <td className="px-3 py-2 text-xs text-muted-foreground">{asStr(row.comment)}</td>
                        <td className="px-3 py-2 text-right">
                          <div className="flex items-center gap-1 justify-end">
                            <Button
                              variant="ghost"
                              size="sm"
                              disabled={!id}
                              aria-label={t('MikroTikFirewallTab.aria.editNatRule', { label: natLabel })}
                              onClick={() => openEditNat(row)}
                            >
                              <Pencil className="h-3.5 w-3.5" aria-hidden="true" />
                            </Button>
                            <Button
                              variant="ghost"
                              size="sm"
                              disabled={!id}
                              aria-label={t('MikroTikFirewallTab.aria.deleteNatRule', { label: natLabel })}
                              onClick={() => setDeleteTarget({ kind: 'nat', row })}
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

      {/* Filter rule dialog */}
      <Dialog open={filterFormOpen} onOpenChange={setFilterFormOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{editingFilter ? t('MikroTikFirewallTab.filterDialog.editTitle') : t('MikroTikFirewallTab.filterDialog.addTitle')}</DialogTitle>
            <DialogDescription>
              {t('MikroTikFirewallTab.filterDialog.description')}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-2">
                <Label htmlFor="mikrotik-filter-chain">{t('MikroTikFirewallTab.fields.chain')}</Label>
                <Input
                  id="mikrotik-filter-chain"
                  value={filterForm.chain}
                  onChange={(e) => setFilterForm((f) => ({ ...f, chain: e.target.value }))}
                  placeholder="forward"
                  autoFocus
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="mikrotik-filter-action">{t('MikroTikFirewallTab.fields.action')}</Label>
                <Input
                  id="mikrotik-filter-action"
                  value={filterForm.action}
                  onChange={(e) => setFilterForm((f) => ({ ...f, action: e.target.value }))}
                  placeholder="accept · drop · reject"
                />
              </div>
            </div>
            <div className="space-y-2">
              <Label htmlFor="mikrotik-filter-proto">{t('MikroTikFirewallTab.fields.protocol')}</Label>
              <Input
                id="mikrotik-filter-proto"
                value={filterForm.protocol}
                onChange={(e) => setFilterForm((f) => ({ ...f, protocol: e.target.value }))}
                placeholder="tcp · udp · icmp · …"
              />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-2">
                <Label htmlFor="mikrotik-filter-src">{t('MikroTikFirewallTab.fields.srcAddress')}</Label>
                <Input
                  id="mikrotik-filter-src"
                  value={filterForm.srcAddress}
                  onChange={(e) => setFilterForm((f) => ({ ...f, srcAddress: e.target.value }))}
                  placeholder="0.0.0.0/0"
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="mikrotik-filter-dst">{t('MikroTikFirewallTab.fields.dstAddress')}</Label>
                <Input
                  id="mikrotik-filter-dst"
                  value={filterForm.dstAddress}
                  onChange={(e) => setFilterForm((f) => ({ ...f, dstAddress: e.target.value }))}
                  placeholder="0.0.0.0/0"
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="mikrotik-filter-port">{t('MikroTikFirewallTab.fields.dstPort')}</Label>
                <Input
                  id="mikrotik-filter-port"
                  value={filterForm.dstPort}
                  onChange={(e) => setFilterForm((f) => ({ ...f, dstPort: e.target.value }))}
                  placeholder="80,443"
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="mikrotik-filter-iface">{t('MikroTikFirewallTab.fields.inIface')}</Label>
                <Input
                  id="mikrotik-filter-iface"
                  value={filterForm.inInterface}
                  onChange={(e) =>
                    setFilterForm((f) => ({ ...f, inInterface: e.target.value }))
                  }
                  placeholder="ether1"
                />
              </div>
            </div>
            <div className="space-y-2">
              <Label htmlFor="mikrotik-filter-comment">{t('MikroTikFirewallTab.fields.comment')}</Label>
              <Input
                id="mikrotik-filter-comment"
                value={filterForm.comment}
                onChange={(e) => setFilterForm((f) => ({ ...f, comment: e.target.value }))}
                placeholder=""
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setFilterFormOpen(false)}>
              {t('MikroTikFirewallTab.actions.cancel')}
            </Button>
            <Button
              onClick={submitFilter}
              disabled={
                createFilterMut.isPending ||
                updateFilterMut.isPending ||
                filterForm.chain.trim().length === 0 ||
                filterForm.action.trim().length === 0
              }
            >
              {(createFilterMut.isPending || updateFilterMut.isPending) && (
                <Loader2 className="h-4 w-4 animate-spin mr-1" />
              )}
              {editingFilter ? t('MikroTikFirewallTab.actions.stageUpdate') : t('MikroTikFirewallTab.actions.stageCreate')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* NAT rule dialog */}
      <Dialog open={natFormOpen} onOpenChange={setNatFormOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{editingNat ? t('MikroTikFirewallTab.natDialog.editTitle') : t('MikroTikFirewallTab.natDialog.addTitle')}</DialogTitle>
            <DialogDescription>
              {t('MikroTikFirewallTab.natDialog.description')}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-2">
                <Label htmlFor="mikrotik-nat-chain">{t('MikroTikFirewallTab.fields.chain')}</Label>
                <Input
                  id="mikrotik-nat-chain"
                  value={natForm.chain}
                  onChange={(e) => setNatForm((f) => ({ ...f, chain: e.target.value }))}
                  placeholder="srcnat · dstnat"
                  autoFocus
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="mikrotik-nat-action">{t('MikroTikFirewallTab.fields.action')}</Label>
                <Input
                  id="mikrotik-nat-action"
                  value={natForm.action}
                  onChange={(e) => setNatForm((f) => ({ ...f, action: e.target.value }))}
                  placeholder="masquerade · dst-nat · src-nat"
                />
              </div>
            </div>
            <div className="space-y-2">
              <Label htmlFor="mikrotik-nat-proto">{t('MikroTikFirewallTab.fields.protocol')}</Label>
              <Input
                id="mikrotik-nat-proto"
                value={natForm.protocol}
                onChange={(e) => setNatForm((f) => ({ ...f, protocol: e.target.value }))}
                placeholder="tcp · udp · icmp · …"
              />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-2">
                <Label htmlFor="mikrotik-nat-src">{t('MikroTikFirewallTab.fields.srcAddress')}</Label>
                <Input
                  id="mikrotik-nat-src"
                  value={natForm.srcAddress}
                  onChange={(e) => setNatForm((f) => ({ ...f, srcAddress: e.target.value }))}
                  placeholder="0.0.0.0/0"
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="mikrotik-nat-dst">{t('MikroTikFirewallTab.fields.dstAddress')}</Label>
                <Input
                  id="mikrotik-nat-dst"
                  value={natForm.dstAddress}
                  onChange={(e) => setNatForm((f) => ({ ...f, dstAddress: e.target.value }))}
                  placeholder="0.0.0.0/0"
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="mikrotik-nat-port">{t('MikroTikFirewallTab.fields.dstPort')}</Label>
                <Input
                  id="mikrotik-nat-port"
                  value={natForm.dstPort}
                  onChange={(e) => setNatForm((f) => ({ ...f, dstPort: e.target.value }))}
                  placeholder="80"
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="mikrotik-nat-to-addr">{t('MikroTikFirewallTab.fields.toAddresses')}</Label>
                <Input
                  id="mikrotik-nat-to-addr"
                  value={natForm.toAddresses}
                  onChange={(e) => setNatForm((f) => ({ ...f, toAddresses: e.target.value }))}
                  placeholder="192.168.88.10"
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="mikrotik-nat-to-port">{t('MikroTikFirewallTab.fields.toPorts')}</Label>
                <Input
                  id="mikrotik-nat-to-port"
                  value={natForm.toPorts}
                  onChange={(e) => setNatForm((f) => ({ ...f, toPorts: e.target.value }))}
                  placeholder="8080"
                />
              </div>
            </div>
            <div className="space-y-2">
              <Label htmlFor="mikrotik-nat-comment">{t('MikroTikFirewallTab.fields.comment')}</Label>
              <Input
                id="mikrotik-nat-comment"
                value={natForm.comment}
                onChange={(e) => setNatForm((f) => ({ ...f, comment: e.target.value }))}
                placeholder=""
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setNatFormOpen(false)}>
              {t('MikroTikFirewallTab.actions.cancel')}
            </Button>
            <Button
              onClick={submitNat}
              disabled={
                createNatMut.isPending ||
                updateNatMut.isPending ||
                natForm.chain.trim().length === 0 ||
                natForm.action.trim().length === 0
              }
            >
              {(createNatMut.isPending || updateNatMut.isPending) && (
                <Loader2 className="h-4 w-4 animate-spin mr-1" />
              )}
              {editingNat ? t('MikroTikFirewallTab.actions.stageUpdate') : t('MikroTikFirewallTab.actions.stageCreate')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete confirmation · MEDIUM-3 shows full rule detail */}
      <Dialog
        open={deleteTarget !== null}
        onOpenChange={(open) => {
          if (!open) setDeleteTarget(null);
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>
              {t('MikroTikFirewallTab.deleteDialog.title', { kind: deleteRuleDetails?.kind })}
            </DialogTitle>
            <DialogDescription>
              {t('MikroTikFirewallTab.deleteDialog.description')}
            </DialogDescription>
          </DialogHeader>
          {deleteRuleDetails && (
            <dl className="grid grid-cols-[100px_1fr] gap-x-3 gap-y-1 text-sm rounded-md border bg-muted/30 p-3">
              <dt className="text-muted-foreground">{t('MikroTikFirewallTab.fields.chain')}</dt>
              <dd className="font-mono">{deleteRuleDetails.chain}</dd>
              <dt className="text-muted-foreground">{t('MikroTikFirewallTab.fields.action')}</dt>
              <dd className="font-mono">{deleteRuleDetails.action}</dd>
              <dt className="text-muted-foreground">{t('MikroTikFirewallTab.fields.protocol')}</dt>
              <dd className="font-mono">{deleteRuleDetails.proto}</dd>
              <dt className="text-muted-foreground">{t('MikroTikFirewallTab.columns.src')}</dt>
              <dd className="font-mono">{deleteRuleDetails.src}</dd>
              <dt className="text-muted-foreground">{t('MikroTikFirewallTab.columns.dst')}</dt>
              <dd className="font-mono">{deleteRuleDetails.dst}</dd>
              <dt className="text-muted-foreground">{t('MikroTikFirewallTab.columns.dstPort')}</dt>
              <dd className="font-mono">{deleteRuleDetails.dstPort}</dd>
              {deleteTarget?.kind === 'filter' && (
                <>
                  <dt className="text-muted-foreground">{t('MikroTikFirewallTab.columns.inIface')}</dt>
                  <dd className="font-mono">{deleteRuleDetails.inIface}</dd>
                </>
              )}
              <dt className="text-muted-foreground">{t('MikroTikFirewallTab.fields.comment')}</dt>
              <dd>{deleteRuleDetails.comment}</dd>
            </dl>
          )}
          <DialogFooter>
            <Button variant="outline" onClick={() => setDeleteTarget(null)}>
              {t('MikroTikFirewallTab.actions.cancel')}
            </Button>
            <Button
              variant="destructive"
              disabled={deleteFilterMut.isPending || deleteNatMut.isPending}
              onClick={submitDelete}
            >
              {(deleteFilterMut.isPending || deleteNatMut.isPending) && (
                <Loader2 className="h-4 w-4 animate-spin mr-1" />
              )}
              {t('MikroTikFirewallTab.actions.stageDelete')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

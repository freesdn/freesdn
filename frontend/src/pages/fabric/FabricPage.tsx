// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
//
// Fabric cockpit, the visual builder for the universal app-interconnect.
// Browse the catalog (event sources + operation targets across every module)
// and author Connections (source event -> step chain) that fire on the live bus.
import { useMemo, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  ArrowRight,
  ChevronDown,
  History,
  Loader2,
  Lock,
  Paperclip,
  Pencil,
  Play,
  Plus,
  Radio,
  Search,
  ShieldAlert,
  Trash2,
  Workflow,
  Zap,
} from 'lucide-react';

import {
  fabricApi,
  type FabricCatalog,
  type FabricConnection,
  type FabricOperation,
  type FabricRun,
  type FabricSuggestedTarget,
} from '@/lib/api/fabric';
import { getApiErrorMessage } from '@/lib/api';
import { useToast } from '@/hooks/use-toast';
import { PageHeader } from '@/components/layout';
import { CapabilityMaturityBadge } from '@/components/ui/capability-maturity-badge';
import { DataTable, type DataTableColumn } from '@/components/ui/data-table';
import { EmptyState, ErrorState } from '@/components/ui/empty-state';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { Label } from '@/components/ui/label';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
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
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible';
import { FabricFlowCanvas, PermissionSummary, TargetPicker, TierBadge } from './fabricFlow';

interface DraftStep {
  operation_id: string;
  params: string; // JSON text the operator edits
  continue_on_error: boolean;
}

const EMPTY_STEP: DraftStep = { operation_id: '', params: '{}', continue_on_error: false };

export default function FabricPage() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [tab, setTab] = useState('connections');
  const [catalogSearch, setCatalogSearch] = useState('');
  const [dialogOpen, setDialogOpen] = useState(false);
  const [editing, setEditing] = useState<FabricConnection | null>(null);
  const [runsFor, setRunsFor] = useState<FabricConnection | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<FabricConnection | null>(null);

  // ── data ────────────────────────────────────────────────────────────────
  const catalogQ = useQuery<FabricCatalog>({
    queryKey: ['fabric-catalog'],
    queryFn: async () => (await fabricApi.getCatalog()).data,
  });
  const connectionsQ = useQuery<FabricConnection[]>({
    queryKey: ['fabric-connections'],
    queryFn: async () => (await fabricApi.listConnections()).data.connections ?? [],
    refetchInterval: 30_000,
  });

  const catalog = catalogQ.data;
  const connections = connectionsQ.data ?? [];

  // ── form state ──────────────────────────────────────────────────────────
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [sourceEvent, setSourceEvent] = useState('');
  const [enabled, setEnabled] = useState(true);
  const [steps, setSteps] = useState<DraftStep[]>([{ ...EMPTY_STEP }]);
  const [conditions, setConditions] = useState(''); // optional JSON text
  const [cooldownSeconds, setCooldownSeconds] = useState(0);
  // Which step the visual canvas has focused (clicking a flow node selects it).
  const [selectedStepIndex, setSelectedStepIndex] = useState<number | null>(0);

  // Negotiator matchmaking: once a source event is chosen, fetch the operations
  // compatible with it so the step picker can recommend (and gate) targets. Falls
  // back to the full catalog before a source is picked / while loading.
  const suggestQ = useQuery({
    queryKey: ['fabric-suggest', sourceEvent],
    queryFn: async () => (await fabricApi.suggestTargets(sourceEvent)).data,
    enabled: dialogOpen && !!sourceEvent,
    staleTime: 60_000,
  });
  const suggestedTargets = suggestQ.data?.targets;

  // Lookups for the visual builder (canvas / target picker / permission summary).
  const opById = useMemo(() => {
    const m = new Map<string, FabricOperation>();
    for (const o of catalog?.operations ?? []) m.set(o.id, o);
    return m;
  }, [catalog]);
  const suggestById = useMemo(() => {
    const m = new Map<string, FabricSuggestedTarget>();
    for (const t of suggestedTargets ?? []) m.set(t.id, t);
    return m;
  }, [suggestedTargets]);
  // Resolve op metadata (prefer the negotiator-annotated suggestion).
  const resolveOp = (id: string) => suggestById.get(id) ?? opById.get(id) ?? null;
  // Whether the caller may author a step with this op. Unknown (no suggestion
  // loaded yet) is optimistically true, the backend re-gates on save.
  const isAllowed = (id: string) => {
    const t = suggestById.get(id);
    return t ? t.allowed : true;
  };
  // The chosen source event's catalog descriptor (for the canvas trigger node).
  const eventForSource =
    suggestQ.data?.event ??
    (catalog?.events ?? []).find((e) => e.event_type === sourceEvent) ??
    null;

  // The full negotiator target list for the picker, with a graceful fallback to
  // the whole catalog before a source event is chosen / while suggestions load.
  const pickerTargets: FabricSuggestedTarget[] =
    suggestedTargets ??
    (catalog?.operations ?? []).map((o) => ({
      ...o,
      match: (o.accepts?.length ? 'artifact' : 'data') as 'artifact' | 'data',
      allowed: true,
    }));

  // The option list for a step's operation picker: the negotiator's compatible
  // targets for the chosen source (ranked + permission-gated) when available,
  // else the full catalog (optimistically selectable). Always keeps the step's
  // current selection present so editing never silently drops it.
  const buildOpOptions = (currentId: string): FabricSuggestedTarget[] => {
    const base: FabricSuggestedTarget[] =
      suggestedTargets ??
      (catalog?.operations ?? []).map((o) => ({
        ...o,
        match: (o.accepts?.length ? 'artifact' : 'data') as 'artifact' | 'data',
        allowed: true,
      }));
    if (currentId && !base.some((o) => o.id === currentId)) {
      const fromCatalog = (catalog?.operations ?? []).find((o) => o.id === currentId);
      if (fromCatalog) {
        return [
          {
            ...fromCatalog,
            match: (fromCatalog.accepts?.length ? 'artifact' : 'data') as 'artifact' | 'data',
            allowed: true,
          },
          ...base,
        ];
      }
    }
    return base;
  };

  const resetForm = () => {
    setName('');
    setDescription('');
    setSourceEvent('');
    setEnabled(true);
    setSteps([{ ...EMPTY_STEP }]);
    setConditions('');
    setCooldownSeconds(0);
    setSelectedStepIndex(0);
  };

  const openCreate = () => {
    setEditing(null);
    resetForm();
    setDialogOpen(true);
  };

  const openEdit = (c: FabricConnection) => {
    setEditing(c);
    setName(c.name);
    setDescription(c.description ?? '');
    setSourceEvent(c.source_event);
    setEnabled(c.enabled);
    const mappedSteps = (c.steps ?? []).map((s) => ({
      operation_id: s.operation_id,
      params: JSON.stringify(s.params ?? {}, null, 2),
      continue_on_error: s.continue_on_error ?? false,
    }));
    // `.map` always returns an array (never falsy), so guard on length to keep at
    // least one editable row for a connection that somehow has no steps.
    setSteps(mappedSteps.length ? mappedSteps : [{ ...EMPTY_STEP }]);
    setConditions(c.conditions ? JSON.stringify(c.conditions, null, 2) : '');
    setCooldownSeconds(c.cooldown_seconds ?? 0);
    setSelectedStepIndex(0);
    setDialogOpen(true);
  };

  // Add a step and focus it in the visual canvas.
  const addStep = () => {
    setSteps((prev) => {
      setSelectedStepIndex(prev.length);
      return [...prev, { ...EMPTY_STEP }];
    });
  };

  // ── mutations ───────────────────────────────────────────────────────────
  const createMut = useMutation({
    mutationFn: (body: Parameters<typeof fabricApi.createConnection>[0]) =>
      fabricApi.createConnection(body),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['fabric-connections'] });
      toast({ title: 'Connection created', description: 'It is live on the event bus.' });
      setDialogOpen(false);
      resetForm();
    },
    onError: (err) =>
      toast({ title: 'Could not create connection', description: getApiErrorMessage(err), variant: 'destructive' }),
  });

  const updateMut = useMutation({
    mutationFn: ({ id, body }: { id: string; body: Partial<Parameters<typeof fabricApi.createConnection>[0]> }) =>
      fabricApi.updateConnection(id, body),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['fabric-connections'] });
      toast({ title: 'Connection updated', description: 'The live wire was refreshed.' });
      setDialogOpen(false);
      setEditing(null);
      resetForm();
    },
    onError: (err) =>
      toast({ title: 'Could not update connection', description: getApiErrorMessage(err), variant: 'destructive' }),
  });

  const toggleMut = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      fabricApi.updateConnection(id, { enabled }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['fabric-connections'] }),
    onError: (err) =>
      toast({ title: 'Update failed', description: getApiErrorMessage(err), variant: 'destructive' }),
  });

  const deleteMut = useMutation({
    mutationFn: (id: string) => fabricApi.deleteConnection(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['fabric-connections'] });
      toast({ title: 'Connection deleted' });
      setDeleteTarget(null);
    },
    onError: (err) =>
      toast({ title: 'Delete failed', description: getApiErrorMessage(err), variant: 'destructive' }),
  });

  const testMut = useMutation({
    mutationFn: (id: string) => fabricApi.testConnection(id, {}),
    onSuccess: (res) => {
      const run = res.data as { success?: boolean; steps?: unknown[] };
      toast({
        title: run.success ? 'Test run succeeded' : 'Test run completed with errors',
        description: `${(run.steps ?? []).length} step(s) executed. Writes stage for sign-off; they are not auto-applied.`,
        variant: run.success ? 'default' : 'destructive',
      });
      queryClient.invalidateQueries({ queryKey: ['fabric-connections'] });
    },
    onError: (err) =>
      toast({ title: 'Test failed', description: getApiErrorMessage(err), variant: 'destructive' }),
  });

  // ── submit (create or edit) ───────────────────────────────────────────────
  const submitDialog = () => {
    if (!name.trim()) {
      toast({ title: 'Name is required', variant: 'destructive' });
      return;
    }
    if (!sourceEvent) {
      toast({ title: 'Pick a source event', variant: 'destructive' });
      return;
    }
    const parsedSteps = [];
    for (let i = 0; i < steps.length; i++) {
      const s = steps[i];
      if (!s.operation_id) {
        toast({ title: `Step ${i + 1}: pick an operation`, variant: 'destructive' });
        return;
      }
      let params: Record<string, unknown>;
      try {
        const parsed = s.params.trim() ? JSON.parse(s.params) : {};
        if (typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('not an object');
        params = parsed;
      } catch {
        toast({ title: `Step ${i + 1}: params must be valid JSON object`, variant: 'destructive' });
        return;
      }
      parsedSteps.push({ operation_id: s.operation_id, params, continue_on_error: s.continue_on_error });
    }

    let parsedConditions: Record<string, unknown> | null = null;
    if (conditions.trim()) {
      try {
        parsedConditions = JSON.parse(conditions);
        if (typeof parsedConditions !== 'object' || Array.isArray(parsedConditions)) {
          throw new Error('not an object');
        }
      } catch {
        toast({ title: 'Conditions must be a valid JSON object', variant: 'destructive' });
        return;
      }
    }

    const body = {
      name: name.trim(),
      description: description.trim() || null,
      source_event: sourceEvent,
      enabled,
      steps: parsedSteps,
      conditions: parsedConditions,
      cooldown_seconds: Math.max(0, Math.floor(cooldownSeconds) || 0),
    };
    if (editing) {
      updateMut.mutate({ id: editing.id, body });
    } else {
      createMut.mutate(body);
    }
  };

  // ── columns ───────────────────────────────────────────────────────────────
  const columns: DataTableColumn<FabricConnection>[] = useMemo(
    () => [
      {
        id: 'name',
        header: 'Connection',
        accessorFn: (c) => `${c.name} ${c.source_event}`,
        cell: (c) => (
          <div>
            <div className="font-medium">{c.name}</div>
            {c.description && <div className="text-xs text-muted-foreground">{c.description}</div>}
          </div>
        ),
      },
      {
        id: 'wire',
        header: 'Wire',
        sortable: false,
        cell: (c) => (
          <div className="flex items-center gap-2 text-xs">
            <Badge variant="outline" className="font-mono">{c.source_event}</Badge>
            <ArrowRight className="h-3 w-3 text-muted-foreground" />
            <span className="text-muted-foreground">
              {c.steps.map((s) => s.operation_id).join(' → ') || '-'}
            </span>
          </div>
        ),
      },
      {
        id: 'enabled',
        header: 'Status',
        accessorFn: (c) => (c.enabled ? 1 : 0),
        cell: (c) => (
          <Badge variant={c.enabled ? 'success' : 'muted'}>{c.enabled ? 'Enabled' : 'Disabled'}</Badge>
        ),
      },
      {
        id: 'runs',
        header: 'Runs',
        accessorFn: (c) => c.run_count,
        cell: (c) => (
          <div className="text-xs">
            <div>{c.run_count} run(s)</div>
            {c.last_run_at && (
              <div className="text-muted-foreground">{new Date(c.last_run_at).toLocaleString()}</div>
            )}
          </div>
        ),
      },
      {
        id: 'actions',
        header: '',
        sortable: false,
        className: 'w-[300px] text-right',
        cell: (c) => (
          <div className="flex justify-end gap-1">
            <Button variant="ghost" size="sm" onClick={() => testMut.mutate(c.id)} disabled={testMut.isPending}>
              <Play className="mr-1 h-3.5 w-3.5" /> Test
            </Button>
            <Button variant="ghost" size="sm" onClick={() => setRunsFor(c)}>
              <History className="mr-1 h-3.5 w-3.5" /> Runs
            </Button>
            <Button variant="ghost" size="sm" onClick={() => openEdit(c)}>
              <Pencil className="mr-1 h-3.5 w-3.5" /> Edit
            </Button>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => toggleMut.mutate({ id: c.id, enabled: !c.enabled })}
              disabled={toggleMut.isPending}
            >
              {c.enabled ? 'Disable' : 'Enable'}
            </Button>
            <Button variant="ghost" size="icon" onClick={() => setDeleteTarget(c)}>
              <Trash2 className="h-4 w-4 text-destructive" />
            </Button>
          </div>
        ),
      },
    ],
    [testMut, toggleMut],
  );

  // ── catalog groupings ──────────────────────────────────────────────────────
  const catalogNeedle = catalogSearch.trim().toLowerCase();
  const eventsByProvider = useMemo(
    () =>
      groupBy(
        (catalog?.events ?? []).filter(
          (e) =>
            !catalogNeedle ||
            e.event_type.toLowerCase().includes(catalogNeedle) ||
            e.title.toLowerCase().includes(catalogNeedle) ||
            e.provider_id.toLowerCase().includes(catalogNeedle),
        ),
        (e) => e.provider_id,
      ),
    [catalog, catalogNeedle],
  );
  const opsByProvider = useMemo(
    () =>
      groupBy(
        (catalog?.operations ?? []).filter(
          (o) =>
            !catalogNeedle ||
            o.id.toLowerCase().includes(catalogNeedle) ||
            o.title.toLowerCase().includes(catalogNeedle) ||
            o.provider_id.toLowerCase().includes(catalogNeedle),
        ),
        (o) => o.provider_id,
      ),
    [catalog, catalogNeedle],
  );

  if (connectionsQ.isError) {
    return (
      <div className="space-y-6">
        <PageHeader icon={Workflow} title="Fabric" />
        <ErrorState message="Could not load Fabric connections." onRetry={() => connectionsQ.refetch()} />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader
        icon={Workflow}
        title="Fabric"
        titleBadge={<CapabilityMaturityBadge capabilityId="fabric" />}
        description="Wire any app to any other, an event in one module triggers an action in another, as config, no code."
        onRefresh={() => {
          connectionsQ.refetch();
          catalogQ.refetch();
        }}
        refreshing={connectionsQ.isLoading || catalogQ.isFetching}
        actions={
          <Button onClick={openCreate} disabled={!catalog}>
            <Plus className="mr-2 h-4 w-4" /> Create connection
          </Button>
        }
      />

      <Tabs value={tab} onValueChange={setTab} className="space-y-6">
        <TabsList>
          <TabsTrigger value="connections">
            Connections {connections.length > 0 && <span className="ml-1 text-muted-foreground">({connections.length})</span>}
          </TabsTrigger>
          <TabsTrigger value="catalog">
            Catalog {catalog && <span className="ml-1 text-muted-foreground">({catalog.events.length} sources · {catalog.operations.length} ops)</span>}
          </TabsTrigger>
        </TabsList>

        <TabsContent value="connections" className="mt-0 space-y-4">
          {connections.length === 0 && !connectionsQ.isLoading ? (
            <EmptyState
              icon={Workflow}
              title="No connections yet"
              description="Wire a source event to a step chain, e.g. a camera motion event to a snapshot saved on TrueNAS."
              action={{ label: 'Create connection', onClick: openCreate, icon: Plus }}
            />
          ) : (
            <DataTable
              data={connections}
              columns={columns}
              isLoading={connectionsQ.isLoading}
              searchable
              itemName="connections"
              paginated
              defaultPageSize={25}
              getRowId={(c) => c.id}
            />
          )}
        </TabsContent>

        <TabsContent value="catalog" className="mt-0 space-y-8">
          <div className="relative max-w-sm">
            <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
            <Input
              value={catalogSearch}
              onChange={(e) => setCatalogSearch(e.target.value)}
              placeholder="Search sources & operations…"
              className="pl-8"
            />
          </div>
          <CatalogSection
            icon={Radio}
            title="Event sources"
            subtitle="Things that happen, wire these as a Connection's trigger."
            grouped={eventsByProvider}
            render={(e) => (
              <div key={e.event_type} className="flex items-start justify-between gap-3 rounded-md border border-border p-3">
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <code className="text-xs font-medium">{e.event_type}</code>
                    <TierBadge tier={e.tier} />
                    {e.produces?.length > 0 && <Badge variant="outline" className="text-[10px]">{e.produces.join(', ')}</Badge>}
                  </div>
                  <div className="text-xs text-muted-foreground">{e.title}</div>
                </div>
              </div>
            )}
            loading={catalogQ.isLoading}
          />
          <CatalogSection
            icon={Zap}
            title="Operations"
            subtitle="Things you can do, wire these as a Connection's steps."
            grouped={opsByProvider}
            render={(o) => (
              <div key={o.id} className="flex items-start justify-between gap-3 rounded-md border border-border p-3">
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <code className="text-xs font-medium">{o.id}</code>
                    <TierBadge tier={o.tier} />
                    {o.write && (
                      <Badge variant="destructive" className="text-[10px]">
                        <ShieldAlert className="mr-1 h-3 w-3" /> writes (staged)
                      </Badge>
                    )}
                    {o.permission && <Badge variant="muted" className="text-[10px]">{o.permission}</Badge>}
                  </div>
                  <div className="text-xs text-muted-foreground">{o.title}</div>
                </div>
              </div>
            )}
            loading={catalogQ.isLoading}
          />
        </TabsContent>
      </Tabs>

      {/* Create / edit dialog */}
      <Dialog
        open={dialogOpen}
        onOpenChange={(o) => {
          setDialogOpen(o);
          if (!o) {
            setEditing(null);
            resetForm();
          }
        }}
      >
        <DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-4xl">
          <DialogHeader>
            <DialogTitle>{editing ? 'Edit connection' : 'Create connection'}</DialogTitle>
            <DialogDescription>
              When the source event fires, the steps run in order. Device-write steps stage a change
              for operator sign-off, they are never auto-applied.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4">
            <div className="grid gap-2">
              <Label>Name</Label>
              <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="Motion → snapshot → TrueNAS" />
            </div>
            <div className="grid gap-2">
              <Label>Description (optional)</Label>
              <Input value={description} onChange={(e) => setDescription(e.target.value)} />
            </div>
            <div className="grid gap-2">
              <Label>Source event</Label>
              <Select value={sourceEvent} onValueChange={setSourceEvent}>
                <SelectTrigger><SelectValue placeholder="Pick an event source…" /></SelectTrigger>
                <SelectContent>
                  {(catalog?.events ?? []).map((e) => (
                    <SelectItem key={e.event_type} value={e.event_type}>
                      {e.event_type}, {e.title}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              {sourceEvent && suggestQ.data && (
                <p className="text-xs text-muted-foreground">
                  {suggestQ.data.counts.total} compatible operation(s) · {suggestQ.data.counts.allowed} you can author.
                  {suggestQ.data.event?.produces?.length ? (
                    <> Produces <code>{suggestQ.data.event.produces.join(', ')}</code>.</>
                  ) : null}
                </p>
              )}
            </div>

            {/* Visual flow: trigger → step chain, with artifact/data hand-off */}
            <div className="grid gap-2">
              <Label>Flow</Label>
              <FabricFlowCanvas
                sourceEvent={sourceEvent}
                event={eventForSource}
                steps={steps}
                resolveOp={resolveOp}
                isAllowed={isAllowed}
                selectedIndex={selectedStepIndex}
                onSelectStep={setSelectedStepIndex}
                onAddStep={addStep}
              />
              <p className="text-xs text-muted-foreground">
                Click a node to edit that step; the dashed <span className="font-medium">Add step</span> node extends
                the chain. A blue <Paperclip className="inline h-3 w-3 text-blue-500" /> edge means the upstream
                artifact is handed to the next operation.
              </p>
            </div>

            <PermissionSummary steps={steps} resolveOp={resolveOp} isAllowed={isAllowed} />

            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <Label>Steps</Label>
                <Button variant="outline" size="sm" onClick={addStep}>
                  <Plus className="mr-1 h-3.5 w-3.5" /> Add step
                </Button>
              </div>
              {steps.map((s, i) => {
                const options = buildOpOptions(s.operation_id);
                const isSel = selectedStepIndex === i;
                return (
                  <div
                    key={i}
                    onClick={() => setSelectedStepIndex(i)}
                    className={`space-y-2 rounded-md border p-3 ${
                      isSel ? 'border-primary ring-2 ring-primary/30' : 'border-border'
                    }`}
                  >
                    <div className="flex items-center gap-2">
                      <span className="text-xs text-muted-foreground">#{i + 1}</span>
                      <Select
                        value={s.operation_id}
                        onValueChange={(v) => setSteps(steps.map((x, j) => (j === i ? { ...x, operation_id: v } : x)))}
                      >
                        <SelectTrigger className="flex-1"><SelectValue placeholder="Pick an operation…" /></SelectTrigger>
                        <SelectContent>
                          {options.map((o) => (
                            <SelectItem key={o.id} value={o.id} disabled={!o.allowed}>
                              <span className="flex items-center gap-1.5">
                                {o.match === 'artifact' && <Paperclip className="h-3 w-3 text-blue-500" />}
                                {!o.allowed && <Lock className="h-3 w-3 text-muted-foreground" />}
                                <span className="font-mono text-xs">{o.id}</span>
                                <TierBadge tier={o.tier} />
                                {o.write && <span className="text-[10px] text-destructive">writes</span>}
                                {!o.allowed && (
                                  <span className="text-[10px] text-muted-foreground">
                                    {o.permission ? `needs ${o.permission}` : 'not wirable'}
                                  </span>
                                )}
                              </span>
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                      {steps.length > 1 && (
                        <Button
                          variant="ghost"
                          size="icon"
                          onClick={() => {
                            setSteps(steps.filter((_, j) => j !== i));
                            setSelectedStepIndex((cur) =>
                              cur === null ? null : Math.max(0, Math.min(cur, steps.length - 2)),
                            );
                          }}
                        >
                          <Trash2 className="h-4 w-4 text-destructive" />
                        </Button>
                      )}
                    </div>

                    <Collapsible open={isSel} onOpenChange={(o) => setSelectedStepIndex(o ? i : null)}>
                      <CollapsibleTrigger className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground">
                        <ChevronDown className="h-3 w-3" /> Browse compatible operations
                      </CollapsibleTrigger>
                      <CollapsibleContent className="pt-2">
                        <TargetPicker
                          targets={pickerTargets}
                          value={s.operation_id}
                          onPick={(id) =>
                            setSteps(steps.map((x, j) => (j === i ? { ...x, operation_id: id } : x)))
                          }
                        />
                      </CollapsibleContent>
                    </Collapsible>

                    <Textarea
                      rows={3}
                      className="font-mono text-xs"
                      value={s.params}
                      onChange={(e) => setSteps(steps.map((x, j) => (j === i ? { ...x, params: e.target.value } : x)))}
                      placeholder='{"camera_id": "{{trigger.camera_id}}"}'
                    />
                    <label className="flex items-center gap-2 text-xs text-muted-foreground">
                      <input
                        type="checkbox"
                        checked={s.continue_on_error}
                        onChange={(e) => setSteps(steps.map((x, j) => (j === i ? { ...x, continue_on_error: e.target.checked } : x)))}
                      />
                      Continue the chain even if this step fails
                    </label>
                  </div>
                );
              })}
              <p className="text-xs text-muted-foreground">
                <Paperclip className="mr-1 inline h-3 w-3 text-blue-500" /> = the source's artifact can be handed
                to this op. Params accept templates: <code>{'{{trigger.<field>}}'}</code> and{' '}
                <code>{'{{steps.0.output.<field>}}'}</code>.
              </p>
            </div>

            <div className="grid gap-2">
              <Label>Conditions (optional)</Label>
              <Textarea
                rows={3}
                className="font-mono text-xs"
                value={conditions}
                onChange={(e) => setConditions(e.target.value)}
                placeholder='{"all": [{"field": "name", "op": "eq", "value": "n8n_done"}]}'
              />
              <p className="text-xs text-muted-foreground">
                A JSON condition group evaluated against the trigger payload. Leave empty to fire on every matching event.
              </p>
            </div>

            <div className="grid gap-2">
              <Label>Cooldown (seconds)</Label>
              <Input
                type="number"
                min={0}
                value={cooldownSeconds}
                onChange={(e) => setCooldownSeconds(Number(e.target.value))}
                className="w-40"
              />
              <p className="text-xs text-muted-foreground">
                Minimum seconds between firings, guards against floods and self-amplifying loops. 0 = no cooldown.
              </p>
            </div>

            <label className="flex items-center gap-2 text-sm">
              <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
              {editing ? 'Enabled' : 'Enable immediately'}
            </label>
          </div>

          <DialogFooter>
            <Button variant="outline" onClick={() => setDialogOpen(false)}>Cancel</Button>
            <Button onClick={submitDialog} disabled={createMut.isPending || updateMut.isPending}>
              {(createMut.isPending || updateMut.isPending) && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              {editing ? 'Save changes' : 'Create'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Runs dialog */}
      <RunsDialog connection={runsFor} onClose={() => setRunsFor(null)} />

      {/* Delete confirm */}
      <AlertDialog open={!!deleteTarget} onOpenChange={(o) => !o && setDeleteTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete connection?</AlertDialogTitle>
            <AlertDialogDescription>
              “{deleteTarget?.name}” will stop firing and its run history will be removed. This cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
              onClick={(e) => {
                e.preventDefault();
                if (deleteTarget) deleteMut.mutate(deleteTarget.id);
              }}
            >
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}

function groupBy<T>(items: T[], key: (t: T) => string): Record<string, T[]> {
  const out: Record<string, T[]> = {};
  for (const it of items) {
    const k = key(it) || 'other';
    (out[k] ||= []).push(it);
  }
  return out;
}

function CatalogSection<T>({
  icon: Icon,
  title,
  subtitle,
  grouped,
  render,
  loading,
}: {
  icon: typeof Workflow;
  title: string;
  subtitle: string;
  grouped: Record<string, T[]>;
  render: (item: T) => React.ReactNode;
  loading: boolean;
}) {
  const providers = Object.keys(grouped).sort();
  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2">
        <Icon className="h-4 w-4 text-muted-foreground" />
        <h3 className="text-sm font-semibold">{title}</h3>
        <span className="text-xs text-muted-foreground">{subtitle}</span>
      </div>
      {loading ? (
        <div className="flex items-center gap-2 text-sm text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin" /> Loading…</div>
      ) : (
        <div className="space-y-4">
          {providers.map((p) => (
            <div key={p} className="space-y-2">
              <div className="text-xs font-medium uppercase tracking-wide text-muted-foreground">{p}</div>
              <div className="grid gap-2 md:grid-cols-2">{grouped[p].map(render)}</div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function RunsDialog({ connection, onClose }: { connection: FabricConnection | null; onClose: () => void }) {
  const runsQ = useQuery<FabricRun[]>({
    queryKey: ['fabric-runs', connection?.id],
    queryFn: async () => (await fabricApi.listRuns(connection!.id)).data.runs ?? [],
    enabled: !!connection,
  });
  return (
    <Dialog open={!!connection} onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="max-h-[80vh] overflow-y-auto sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>Run history, {connection?.name}</DialogTitle>
          <DialogDescription>Most recent firings of this connection.</DialogDescription>
        </DialogHeader>
        {runsQ.isLoading ? (
          <div className="flex items-center gap-2 text-sm text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin" /> Loading…</div>
        ) : (runsQ.data ?? []).length === 0 ? (
          <p className="text-sm text-muted-foreground">No runs yet.</p>
        ) : (
          <div className="space-y-2">
            {(runsQ.data ?? []).map((r) => (
              <div key={r.id} className="rounded-md border border-border p-3 text-xs">
                <div className="flex items-center justify-between">
                  <Badge variant={r.success ? 'success' : 'destructive'}>{r.success ? 'success' : 'failed'}</Badge>
                  <span className="text-muted-foreground">
                    {r.created_at ? new Date(r.created_at).toLocaleString() : ''} · {r.duration_ms}ms
                  </span>
                </div>
                <div className="mt-1 text-muted-foreground">trigger: <code>{r.source_event_type}</code></div>
                {r.error && <div className="mt-1 text-destructive">{r.error}</div>}
                {r.steps?.length > 0 && (
                  <div className="mt-1 space-y-0.5">
                    {r.steps.map((s, i) => (
                      <div key={i} className="flex items-center gap-2">
                        <Badge variant={s.success ? 'success' : 'destructive'} className="text-[10px]">
                          {String(s.operation_id ?? `step ${i + 1}`)}
                        </Badge>
                        {!!s.error && <span className="text-destructive">{String(s.error)}</span>}
                        {!!s.staged_change_id && <span className="text-amber-600">staged: {String(s.staged_change_id)}</span>}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}

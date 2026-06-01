// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
//
// Fabric, the visual builder surface. Renders a Connection draft as a live
// node graph (source event → step chain) using @xyflow/react, a card-based
// negotiator target picker, and a permission-requirement summary. Pure
// presentation over the draft the parent owns; no data fetching here.
import { useMemo, useState } from 'react';
import {
  ReactFlow,
  Background,
  Controls,
  MarkerType,
  Position,
  Handle,
  type Node,
  type Edge,
  type NodeProps,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { Lock, Paperclip, Plus, Radio, ShieldAlert, Zap } from 'lucide-react';

import type {
  FabricEvent,
  FabricOperation,
  FabricSuggestedTarget,
} from '@/lib/api/fabric';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';

// ── shared atoms ────────────────────────────────────────────────────────────

export function TierBadge({ tier }: { tier: string }) {
  return (
    <Badge variant={tier === 'plugin' ? 'warning' : 'secondary'} className="text-[10px]">
      {tier}
    </Badge>
  );
}

export interface DraftStepLike {
  operation_id: string;
}

/** Intersect the upstream producer's media-types with what an op accepts. */
export function handoff(
  upstreamProduces: string[] | undefined,
  accepts: string[] | undefined,
): { kind: 'artifact' | 'data'; media: string | null } {
  const up = upstreamProduces ?? [];
  const acc = accepts ?? [];
  const match = up.find((m) => acc.includes(m));
  return match ? { kind: 'artifact', media: match } : { kind: 'data', media: null };
}

// ── custom nodes ────────────────────────────────────────────────────────────

interface EventNodeData {
  sourceEvent: string;
  event: FabricEvent | null;
  [key: string]: unknown;
}

interface OpNodeData {
  index: number;
  opId: string;
  op: FabricOperation | FabricSuggestedTarget | null;
  inflow: 'artifact' | 'data';
  inflowMedia: string | null;
  allowed: boolean;
  selected: boolean;
  [key: string]: unknown;
}

function EventNodeView({ data }: NodeProps) {
  const d = data as EventNodeData;
  const ev = d.event;
  return (
    <div className="min-w-[190px] max-w-[210px] rounded-md border-2 border-sky-500 bg-sky-50 px-3 py-2 shadow-sm dark:bg-sky-950/40">
      <div className="mb-1 flex items-center gap-1.5">
        <Radio className="h-3.5 w-3.5 text-sky-600" />
        <span className="text-[10px] font-semibold uppercase tracking-wide text-sky-700 dark:text-sky-300">
          Trigger
        </span>
        {ev && <TierBadge tier={ev.tier} />}
      </div>
      <code className="block truncate text-xs font-medium" title={d.sourceEvent}>
        {d.sourceEvent || 'pick an event…'}
      </code>
      {ev?.title && <div className="truncate text-[11px] text-muted-foreground">{ev.title}</div>}
      {ev?.produces?.length ? (
        <div className="mt-1 flex items-center gap-1 text-[10px] text-blue-600">
          <Paperclip className="h-3 w-3" /> {ev.produces.join(', ')}
        </div>
      ) : null}
      <Handle type="source" position={Position.Right} className="!bg-sky-500" />
    </div>
  );
}

function OpNodeView({ data }: NodeProps) {
  const d = data as OpNodeData;
  const op = d.op;
  return (
    <div
      className={`min-w-[190px] max-w-[210px] rounded-md border px-3 py-2 shadow-sm transition-colors ${
        d.selected
          ? 'border-primary ring-2 ring-primary/40'
          : d.allowed
            ? 'border-border bg-card'
            : 'border-destructive/40 bg-destructive/5'
      }`}
    >
      <Handle type="target" position={Position.Left} className="!bg-slate-400" />
      <div className="mb-0.5 flex items-center gap-1.5">
        <span className="text-[10px] text-muted-foreground">#{d.index + 1}</span>
        {op && <TierBadge tier={op.tier} />}
        {op?.write && (
          <Badge variant="destructive" className="text-[10px]">
            <ShieldAlert className="mr-0.5 h-2.5 w-2.5" /> staged
          </Badge>
        )}
        {!d.allowed && <Lock className="h-3 w-3 text-destructive" />}
      </div>
      <code className="block truncate text-xs font-medium" title={d.opId}>
        {d.opId || 'pick an operation…'}
      </code>
      {op?.title && <div className="truncate text-[11px] text-muted-foreground">{op.title}</div>}
      {op?.permission && (
        <div className="mt-1 truncate text-[10px] text-muted-foreground" title={op.permission}>
          needs <code>{op.permission}</code>
        </div>
      )}
      <Handle type="source" position={Position.Right} className="!bg-slate-400" />
    </div>
  );
}

function AddNodeView({ data }: NodeProps) {
  void data;
  return (
    <div className="flex min-w-[120px] cursor-pointer items-center justify-center gap-1.5 rounded-md border-2 border-dashed border-muted-foreground/40 px-3 py-3 text-xs text-muted-foreground hover:border-primary hover:text-primary">
      <Handle type="target" position={Position.Left} className="!bg-slate-400" />
      <Plus className="h-3.5 w-3.5" /> Add step
    </div>
  );
}

const nodeTypes = { event: EventNodeView, op: OpNodeView, add: AddNodeView };

// ── canvas ──────────────────────────────────────────────────────────────────

export interface FabricFlowCanvasProps {
  sourceEvent: string;
  event: FabricEvent | null;
  steps: DraftStepLike[];
  /** Resolve an operation_id to its catalog/suggested metadata. */
  resolveOp: (id: string) => FabricOperation | FabricSuggestedTarget | null;
  /** Is the caller allowed to author this op (from negotiator suggestions)? */
  isAllowed: (id: string) => boolean;
  selectedIndex: number | null;
  onSelectStep: (index: number) => void;
  onAddStep: () => void;
}

const COL = 250;

export function FabricFlowCanvas({
  sourceEvent,
  event,
  steps,
  resolveOp,
  isAllowed,
  selectedIndex,
  onSelectStep,
  onAddStep,
}: FabricFlowCanvasProps) {
  const { nodes, edges } = useMemo(() => {
    const ns: Node[] = [];
    const es: Edge[] = [];

    ns.push({
      id: 'event',
      type: 'event',
      position: { x: 0, y: 0 },
      data: { sourceEvent, event } as EventNodeData,
      draggable: false,
      selectable: false,
    });

    let upstreamProduces = event?.produces ?? [];
    steps.forEach((s, i) => {
      const op = resolveOp(s.operation_id);
      const flow = handoff(upstreamProduces, op?.accepts);
      ns.push({
        id: `op-${i}`,
        type: 'op',
        position: { x: (i + 1) * COL, y: 0 },
        data: {
          index: i,
          opId: s.operation_id,
          op,
          inflow: flow.kind,
          inflowMedia: flow.media,
          allowed: s.operation_id ? isAllowed(s.operation_id) : true,
          selected: selectedIndex === i,
        } as OpNodeData,
        draggable: false,
      });
      es.push({
        id: `e-${i}`,
        source: i === 0 ? 'event' : `op-${i - 1}`,
        target: `op-${i}`,
        animated: flow.kind === 'artifact',
        label: flow.kind === 'artifact' ? `📎 ${flow.media}` : 'data',
        labelStyle: { fontSize: 10 },
        markerEnd: { type: MarkerType.ArrowClosed },
        style: flow.kind === 'artifact' ? { stroke: '#3b82f6' } : undefined,
      });
      upstreamProduces = op?.produces ?? [];
    });

    // trailing "add step" affordance
    const addIdx = steps.length;
    ns.push({
      id: 'add',
      type: 'add',
      position: { x: (addIdx + 1) * COL, y: 4 },
      data: {},
      draggable: false,
    });
    es.push({
      id: 'e-add',
      source: addIdx === 0 ? 'event' : `op-${addIdx - 1}`,
      target: 'add',
      style: { strokeDasharray: '4 4', stroke: '#94a3b8' },
      markerEnd: { type: MarkerType.ArrowClosed },
    });

    return { nodes: ns, edges: es };
  }, [sourceEvent, event, steps, resolveOp, isAllowed, selectedIndex]);

  return (
    <div className="h-56 w-full rounded-md border border-border bg-muted/20">
      <ReactFlow
        nodes={nodes}
        edges={edges}
        nodeTypes={nodeTypes}
        fitView
        fitViewOptions={{ padding: 0.2 }}
        nodesConnectable={false}
        proOptions={{ hideAttribution: true }}
        onNodeClick={(_e, node) => {
          if (node.type === 'op') onSelectStep((node.data as OpNodeData).index);
          else if (node.type === 'add') onAddStep();
        }}
      >
        <Background gap={18} />
        <Controls showInteractive={false} />
      </ReactFlow>
    </div>
  );
}

// ── negotiator target picker (card grid) ─────────────────────────────────────

export interface TargetPickerProps {
  targets: FabricSuggestedTarget[];
  value: string;
  onPick: (id: string) => void;
}

export function TargetPicker({ targets, value, onPick }: TargetPickerProps) {
  const [q, setQ] = useState('');
  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    if (!needle) return targets;
    return targets.filter(
      (t) =>
        t.id.toLowerCase().includes(needle) ||
        t.title.toLowerCase().includes(needle) ||
        t.provider_id.toLowerCase().includes(needle),
    );
  }, [targets, q]);

  return (
    <div className="space-y-2">
      <Input
        value={q}
        onChange={(e) => setQ(e.target.value)}
        placeholder="Search compatible operations…"
        className="h-8 text-xs"
      />
      <div className="grid max-h-48 grid-cols-1 gap-1.5 overflow-y-auto pr-1 sm:grid-cols-2">
        {filtered.length === 0 ? (
          <div className="col-span-full py-4 text-center text-xs text-muted-foreground">
            No compatible operations match.
          </div>
        ) : (
          filtered.map((t) => {
            const selected = t.id === value;
            return (
              <button
                key={t.id}
                type="button"
                disabled={!t.allowed}
                onClick={() => onPick(t.id)}
                title={t.allowed ? t.title : t.permission ? `Needs ${t.permission}` : 'Not wirable'}
                className={`flex flex-col items-start gap-1 rounded-md border p-2 text-left transition-colors ${
                  selected
                    ? 'border-primary bg-primary/5 ring-1 ring-primary/40'
                    : t.allowed
                      ? 'border-border hover:border-primary/60 hover:bg-accent'
                      : 'cursor-not-allowed border-destructive/30 bg-destructive/5 opacity-70'
                }`}
              >
                <div className="flex w-full flex-wrap items-center gap-1">
                  {t.match === 'artifact' ? (
                    <Paperclip className="h-3 w-3 text-blue-500" />
                  ) : (
                    <Zap className="h-3 w-3 text-muted-foreground" />
                  )}
                  <code className="truncate text-[11px] font-medium">{t.id}</code>
                  <TierBadge tier={t.tier} />
                  {t.write && (
                    <Badge variant="destructive" className="text-[10px]">
                      staged
                    </Badge>
                  )}
                  {!t.allowed && <Lock className="ml-auto h-3 w-3 text-destructive" />}
                </div>
                <span className="truncate text-[10px] text-muted-foreground">{t.title}</span>
                {!t.allowed && t.permission && (
                  <span className="text-[10px] text-destructive">needs {t.permission}</span>
                )}
              </button>
            );
          })
        )}
      </div>
    </div>
  );
}

// ── permission summary ───────────────────────────────────────────────────────

export interface PermissionSummaryProps {
  steps: DraftStepLike[];
  resolveOp: (id: string) => FabricOperation | FabricSuggestedTarget | null;
  isAllowed: (id: string) => boolean;
}

export function PermissionSummary({ steps, resolveOp, isAllowed }: PermissionSummaryProps) {
  const { perms, anyWrite, anyBlocked } = useMemo(() => {
    const map = new Map<string, boolean>(); // permission → allowed
    let write = false;
    let blocked = false;
    for (const s of steps) {
      if (!s.operation_id) continue;
      const op = resolveOp(s.operation_id);
      if (op?.write) write = true;
      const ok = isAllowed(s.operation_id);
      if (!ok) blocked = true;
      if (op?.permission) map.set(op.permission, (map.get(op.permission) ?? true) && ok);
    }
    return { perms: [...map.entries()], anyWrite: write, anyBlocked: blocked };
  }, [steps, resolveOp, isAllowed]);

  if (perms.length === 0 && !anyWrite) return null;

  return (
    <div className="rounded-md border border-border bg-muted/30 p-2.5 text-xs">
      <div className="mb-1.5 font-medium">This connection requires</div>
      <div className="flex flex-wrap items-center gap-1.5">
        {perms.map(([perm, ok]) => (
          <Badge key={perm} variant={ok ? 'muted' : 'destructive'} className="text-[10px]">
            {!ok && <Lock className="mr-1 h-2.5 w-2.5" />}
            {perm}
          </Badge>
        ))}
        {anyWrite && (
          <Badge variant="outline" className="text-[10px]">
            <ShieldAlert className="mr-1 h-2.5 w-2.5" /> device writes stage for sign-off
          </Badge>
        )}
      </div>
      {anyBlocked && (
        <div className="mt-1.5 text-destructive">
          Some steps need a permission you don’t hold, you can’t save this wire until they’re
          replaced or you’re granted access.
        </div>
      )}
    </div>
  );
}

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN · Enterprise Network Topology
 *
 * Interactive topology visualization built on @xyflow/react:
 *  - Smooth mousewheel zoom + pinch-to-zoom + click-and-drag pan
 *  - MiniMap with status-colored nodes for navigation
 *  - Rich custom nodes with device icons, status indicators, health badges
 *  - Custom edges with port labels, speed badges, animated flow
 *  - Search / filter to highlight devices in the graph
 *  - Layout algorithms (hierarchical, force-directed, auto) via backend
 *  - Fullscreen mode, PNG export, layout persistence
 *  - Slide-in device detail panel with connections & quick actions
 */

import { useState, useCallback, useMemo, useEffect, useRef, memo } from 'react';
import { useTranslation } from 'react-i18next';
import { useNavigate } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  ReactFlow,
  ReactFlowProvider,
  Controls,
  MiniMap,
  Background,
  BackgroundVariant,
  Panel,
  Handle,
  Position,
  BaseEdge,
  EdgeLabelRenderer,
  getSmoothStepPath,
  useReactFlow,
  useNodesState,
  useEdgesState,
  useNodesInitialized,
  type Node,
  type Edge,
  type NodeProps,
  type EdgeProps,
  type OnNodesChange,
  type OnEdgesChange,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { toPng } from 'html-to-image';
import { topologyApi, deviceControlApi } from '@/lib/api';
import { useSiteStore } from '@/stores/siteStore';
import { useToast } from '@/hooks/use-toast';
import type { TopologyNode as APITopologyNode, TopologyGraph } from '@/lib/api';
import { PageHeader } from '@/components/layout';
import { StatsGrid } from '@/components/ui/stats-grid';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Card, CardContent } from '@/components/ui/card';
import { Switch } from '@/components/ui/switch';
import { Separator } from '@/components/ui/separator';
import { ScrollArea } from '@/components/ui/scroll-area';
import {
  Sheet, SheetContent, SheetHeader, SheetTitle, SheetDescription,
} from '@/components/ui/sheet';
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from '@/components/ui/select';
import {
  Tooltip, TooltipContent, TooltipProvider, TooltipTrigger,
} from '@/components/ui/tooltip';
import { useUIStore } from '@/stores';
import { cn } from '@/lib/utils';
import {
  Activity, HardDrive, Wifi, Router, Globe, Shield, Camera, Video,
  DoorOpen, Radio, Phone, Cpu, Zap, Server,
  Network, Layers, Save, Search, Download, Maximize2, Minimize2,
  Power, ExternalLink, RefreshCw, ChevronRight,
} from 'lucide-react';


/* ═══════════════════════════════════════════════════════════════════════════
   Constants
   ═══════════════════════════════════════════════════════════════════════════ */

// `labelKey` is a suffix under `TopologyPage.deviceTypes.*`; it is translated at
// each render site via t(`TopologyPage.deviceTypes.${labelKey}`). Cannot call
// t() here because this constant lives at module scope.
const DEVICE_TYPE_META: Record<string, { icon: typeof Server; labelKey: string; color: string }> = {
  switch:         { icon: HardDrive,  labelKey: 'switch',         color: 'text-blue-500' },
  access_point:   { icon: Wifi,       labelKey: 'access_point',   color: 'text-indigo-500' },
  router:         { icon: Router,     labelKey: 'router',         color: 'text-teal-500' },
  gateway:        { icon: Globe,      labelKey: 'gateway',        color: 'text-cyan-500' },
  firewall:       { icon: Shield,     labelKey: 'firewall',       color: 'text-rose-500' },
  camera:         { icon: Camera,     labelKey: 'camera',         color: 'text-violet-500' },
  nvr:            { icon: Video,      labelKey: 'nvr',            color: 'text-purple-500' },
  dvr:            { icon: Video,      labelKey: 'dvr',            color: 'text-purple-400' },
  access_control: { icon: DoorOpen,   labelKey: 'access_control', color: 'text-amber-500' },
  intercom:       { icon: Radio,      labelKey: 'intercom',       color: 'text-orange-500' },
  voip_phone:     { icon: Phone,      labelKey: 'voip_phone',     color: 'text-green-500' },
  pbx:            { icon: Phone,      labelKey: 'pbx',            color: 'text-emerald-500' },
  server:         { icon: Cpu,        labelKey: 'server',         color: 'text-slate-500' },
  iot:            { icon: Zap,        labelKey: 'iot',            color: 'text-yellow-500' },
  sensor:         { icon: Activity,   labelKey: 'sensor',         color: 'text-lime-500' },
  ap:             { icon: Wifi,       labelKey: 'access_point',   color: 'text-indigo-500' },
  other:          { icon: Server,     labelKey: 'other',          color: 'text-slate-400' },
};

const STATUS_COLORS: Record<string, string> = {
  online: '#22c55e',
  offline: '#ef4444',
  degraded: '#eab308',
  unknown: '#94a3b8',
};

const STATUS_BG: Record<string, string> = {
  online: 'bg-emerald-500',
  offline: 'bg-red-500',
  degraded: 'bg-amber-500',
  unknown: 'bg-slate-400',
};

const LAYER_Y: Record<string, number> = {
  core: 0,
  distribution: 1,
  access: 2,
  edge: 3,
};


/* ═══════════════════════════════════════════════════════════════════════════
   Types
   ═══════════════════════════════════════════════════════════════════════════ */

type DeviceNodeData = {
  label: string;
  device_type: string;
  status: string;
  ip_address: string | null;
  mac_address: string | null;
  model: string | null;
  health_score: number | null;
  health_status: string | null;
  layer: string | null;
  site_name: string | null;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  metadata: Record<string, any>;
  showHealth: boolean;
  dimmed: boolean;
};

type DeviceFlowNode = Node<DeviceNodeData, 'device'>;

type TopologyEdgeData = {
  source_port: string | null;
  target_port: string | null;
  speed: string | null;
  status: string;
  link_type: string;
  discovered_via: string | null;
};

type TopologyFlowEdge = Edge<TopologyEdgeData, 'topology'>;


/* ═══════════════════════════════════════════════════════════════════════════
   Custom Node: DeviceNode
   ═══════════════════════════════════════════════════════════════════════════ */

const DeviceNode = memo(function DeviceNode({ data, selected }: NodeProps<DeviceFlowNode>) {
  const { t } = useTranslation('enterprise');
  const meta = DEVICE_TYPE_META[data.device_type] || DEVICE_TYPE_META.other;
  const Icon = meta.icon;
  const statusColor = STATUS_COLORS[data.status] || STATUS_COLORS.unknown;
  const statusBg = STATUS_BG[data.status] || STATUS_BG.unknown;

  const healthColor =
    data.health_score == null ? '' :
    data.health_score >= 80 ? 'text-emerald-500 bg-emerald-500/10' :
    data.health_score >= 50 ? 'text-amber-500 bg-amber-500/10' :
    'text-red-500 bg-red-500/10';

  const portCount = data.metadata?.port_count as number | undefined;
  const clientCount = data.metadata?.client_count as number | undefined;

  return (
    <TooltipProvider delayDuration={300}>
      <Tooltip>
        <TooltipTrigger asChild>
          <div
            className={cn(
              'relative px-3 py-2 rounded-lg border-2 bg-background shadow-md transition-all min-w-[156px]',
              selected ? 'border-primary ring-2 ring-primary/30 shadow-lg shadow-primary/10' : 'border-border',
              data.dimmed && 'opacity-20',
            )}
          >
            {/* Top handle */}
            <Handle type="target" position={Position.Top} className="!w-2 !h-2 !bg-border !border-0 !opacity-0" />

            {/* Status dot */}
            <span
              className={cn('absolute top-2 right-2 w-2.5 h-2.5 rounded-full', statusBg)}
              style={{ boxShadow: `0 0 6px ${statusColor}40` }}
            />

            {/* Main content */}
            <div className="flex items-center gap-2.5 mb-1">
              <div className={cn('flex items-center justify-center w-8 h-8 rounded-md bg-muted shrink-0')}>
                <Icon className={cn('h-4.5 w-4.5', meta.color)} />
              </div>
              <div className="min-w-0 pr-4">
                <p className="text-[12px] font-semibold leading-tight truncate max-w-[110px]">
                  {data.label}
                </p>
                {data.ip_address && (
                  <p className="text-[10px] text-muted-foreground font-mono leading-tight truncate">
                    {data.ip_address}
                  </p>
                )}
              </div>
            </div>

            {/* Bottom row: health + port/client count */}
            {(data.showHealth && data.health_score != null) || portCount || clientCount ? (
              <div className="flex items-center justify-between mt-1 gap-2">
                {data.showHealth && data.health_score != null ? (
                  <span className={cn('text-[9px] font-bold px-1.5 py-0.5 rounded-full', healthColor)}>
                    {Math.round(data.health_score)}%
                  </span>
                ) : <span />}
                <div className="flex items-center gap-1.5">
                  {data.device_type === 'switch' && portCount != null && (
                    <span className="text-[9px] text-muted-foreground bg-muted px-1.5 py-0.5 rounded-full">
                      {portCount}P
                    </span>
                  )}
                  {(data.device_type === 'access_point' || data.device_type === 'ap') && clientCount != null && (
                    <span className="text-[9px] text-muted-foreground bg-muted px-1.5 py-0.5 rounded-full">
                      {clientCount}C
                    </span>
                  )}
                </div>
              </div>
            ) : null}

            {/* Bottom handle */}
            <Handle type="source" position={Position.Bottom} className="!w-2 !h-2 !bg-border !border-0 !opacity-0" />
          </div>
        </TooltipTrigger>
        <TooltipContent side="right" className="max-w-[240px]">
          <div className="space-y-1">
            <p className="font-semibold text-sm">{data.label}</p>
            <p className="text-xs text-muted-foreground">{t(`TopologyPage.deviceTypes.${meta.labelKey}`)}</p>
            {data.ip_address && <p className="text-xs font-mono">{data.ip_address}</p>}
            {data.mac_address && <p className="text-xs font-mono uppercase">{data.mac_address}</p>}
            {data.model && <p className="text-xs">{data.model}</p>}
            <div className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full" style={{ backgroundColor: statusColor }} />
              <span className="text-xs capitalize">{data.status}</span>
            </div>
            {data.health_score != null && (
              <p className="text-xs">{t('TopologyPage.node.health', { value: Math.round(data.health_score) })}</p>
            )}
            {data.layer && <p className="text-xs">{t('TopologyPage.node.layer', { layer: data.layer })}</p>}
          </div>
        </TooltipContent>
      </Tooltip>
    </TooltipProvider>
  );
});


/* ═══════════════════════════════════════════════════════════════════════════
   Custom Edge: TopologyLinkEdge
   ═══════════════════════════════════════════════════════════════════════════ */

function TopologyLinkEdge({
  id, sourceX, sourceY, targetX, targetY, sourcePosition, targetPosition, data, style,
}: EdgeProps<TopologyFlowEdge>) {
  const [edgePath, labelX, labelY] = getSmoothStepPath({
    sourceX, sourceY, targetX, targetY, sourcePosition, targetPosition, borderRadius: 8,
  });

  const status = data?.status || 'unknown';
  const color = status === 'up' ? '#22c55e' : status === 'down' ? '#ef4444' : '#94a3b8';
  const speedStr = data?.speed || '';
  const speedNum = parseInt(speedStr, 10) || 0;
  const strokeWidth = speedNum >= 10000 ? 3 : speedNum >= 1000 ? 2 : 1.5;

  const hasLabel = data?.source_port || data?.target_port || speedStr;
  const portLabel = data?.source_port && data?.target_port
    ? `${data.source_port} → ${data.target_port}`
    : data?.source_port || data?.target_port || '';

  const speedLabel = speedNum >= 10000 ? '10G' : speedNum >= 1000 ? '1G' : speedNum >= 100 ? '100M' : speedStr || '';

  return (
    <>
      <BaseEdge
        id={id}
        path={edgePath}
        style={{
          ...style,
          stroke: color,
          strokeWidth,
          strokeDasharray: status === 'down' ? '6 4' : undefined,
        }}
      />
      {hasLabel && (
        <EdgeLabelRenderer>
          <div
            className="bg-background/80 backdrop-blur-sm border border-border rounded px-1.5 py-0.5 flex items-center gap-1.5 pointer-events-auto"
            style={{
              position: 'absolute',
              transform: `translate(-50%, -50%) translate(${labelX}px,${labelY}px)`,
              fontSize: '9px',
              lineHeight: 1,
            }}
          >
            {portLabel && (
              <span className="text-muted-foreground font-mono">{portLabel}</span>
            )}
            {speedLabel && (
              <span
                className="font-bold px-1 py-px rounded-sm text-white"
                style={{ backgroundColor: color, fontSize: '8px' }}
              >
                {speedLabel}
              </span>
            )}
          </div>
        </EdgeLabelRenderer>
      )}
    </>
  );
}


/* ═══════════════════════════════════════════════════════════════════════════
   Module-level nodeTypes / edgeTypes (MUST be outside component)
   ═══════════════════════════════════════════════════════════════════════════ */

const nodeTypes = { device: DeviceNode };
const edgeTypes = { topology: TopologyLinkEdge };


/* ═══════════════════════════════════════════════════════════════════════════
   Auto-layout · tree-based hierarchical topology layout

   Builds a true network topology tree using edge connections:
     1. Finds root nodes (gateways/routers/core, or highest-priority devices)
     2. BFS from roots to assign depth levels
     3. Centers children under their parent for a balanced tree
     4. Orphan nodes (no connections) are placed in a row at the bottom
   ═══════════════════════════════════════════════════════════════════════════ */

/** Device type priority · lower = closer to root / upstream */
const DEVICE_PRIORITY: Record<string, number> = {
  gateway: 0, router: 1, firewall: 2,
  switch: 3, server: 4, pbx: 4,
  nvr: 5, dvr: 5, access_point: 5, ap: 5,
  camera: 6, access_control: 6, intercom: 6, voip_phone: 6,
  iot: 7, sensor: 7, other: 8,
};

function computeAutoPositions(
  apiNodes: APITopologyNode[],
  apiEdges: { source_id: string; target_id: string }[],
): Record<string, { x: number; y: number }> {
  if (apiNodes.length === 0) return {};

  const NODE_W = 200;
  const GAP_X = 50;
  const GAP_Y = 120;
  const PADDING = 60;

  // Build adjacency list (undirected)
  const adj = new Map<string, Set<string>>();
  const nodeMap = new Map<string, APITopologyNode>();
  for (const n of apiNodes) {
    nodeMap.set(n.id, n);
    adj.set(n.id, new Set());
  }
  for (const e of apiEdges) {
    adj.get(e.source_id)?.add(e.target_id);
    adj.get(e.target_id)?.add(e.source_id);
  }

  // Priority for a node: use explicit layer first, then device type
  function nodePriority(n: APITopologyNode): number {
    if (n.layer && LAYER_Y[n.layer] != null) return LAYER_Y[n.layer];
    return DEVICE_PRIORITY[n.device_type] ?? 8;
  }

  // Separate connected components and orphans
  const visited = new Set<string>();
  const positions: Record<string, { x: number; y: number }> = {};

  // Find all connected components via BFS
  const components: string[][] = [];
  for (const n of apiNodes) {
    if (visited.has(n.id)) continue;
    const neighbors = adj.get(n.id);
    if (!neighbors || neighbors.size === 0) continue; // orphan · handle later
    const component: string[] = [];
    const queue = [n.id];
    visited.add(n.id);
    while (queue.length > 0) {
      const cur = queue.shift()!;
      component.push(cur);
      for (const neighbor of adj.get(cur) || []) {
        if (!visited.has(neighbor)) {
          visited.add(neighbor);
          queue.push(neighbor);
        }
      }
    }
    components.push(component);
  }

  // Orphans: no edges at all
  const orphans = apiNodes.filter((n) => !visited.has(n.id));

  // Layout each connected component as a tree
  let componentOffsetX = PADDING;
  let globalMaxY = PADDING;

  for (const component of components) {
    // Pick root: lowest priority value (most "upstream")
    const root = component.reduce((best, id) => {
      const bp = nodePriority(nodeMap.get(best)!);
      const cp = nodePriority(nodeMap.get(id)!);
      return cp < bp ? id : best;
    }, component[0]);

    // BFS from root to assign depth, directing edges parent→child
    const depth = new Map<string, number>();
    const children = new Map<string, string[]>();
    depth.set(root, 0);
    const bfsQueue = [root];
    let maxDepth = 0;

    while (bfsQueue.length > 0) {
      const cur = bfsQueue.shift()!;
      const curDepth = depth.get(cur)!;
      const kids: string[] = [];
      for (const neighbor of adj.get(cur) || []) {
        if (!depth.has(neighbor)) {
          depth.set(neighbor, curDepth + 1);
          maxDepth = Math.max(maxDepth, curDepth + 1);
          bfsQueue.push(neighbor);
          kids.push(neighbor);
        }
      }
      // Sort children: place switches/routers toward center, APs/cameras outward
      kids.sort((a, b) => nodePriority(nodeMap.get(a)!) - nodePriority(nodeMap.get(b)!));
      children.set(cur, kids);
    }

    // Bottom-up pass: compute subtree width for each node
    const subtreeWidth = new Map<string, number>();
    function calcWidth(id: string): number {
      const kids = children.get(id) || [];
      if (kids.length === 0) {
        subtreeWidth.set(id, NODE_W);
        return NODE_W;
      }
      const total = kids.reduce((sum, k) => sum + calcWidth(k), 0) + GAP_X * (kids.length - 1);
      const w = Math.max(NODE_W, total);
      subtreeWidth.set(id, w);
      return w;
    }
    const treeW = calcWidth(root);

    // Top-down pass: assign x positions by centering children under parent
    function assignPositions(id: string, left: number, top: number) {
      const w = subtreeWidth.get(id) || NODE_W;
      positions[id] = { x: left + (w - NODE_W) / 2, y: top };

      const kids = children.get(id) || [];
      if (kids.length === 0) return;
      let childLeft = left;
      for (const kid of kids) {
        const kidW = subtreeWidth.get(kid) || NODE_W;
        assignPositions(kid, childLeft, top + GAP_Y);
        childLeft += kidW + GAP_X;
      }
    }
    assignPositions(root, componentOffsetX, PADDING);
    globalMaxY = Math.max(globalMaxY, PADDING + maxDepth * GAP_Y);

    componentOffsetX += treeW + GAP_X * 3; // gap between components
  }

  // Orphans row at the bottom, below all tree components
  if (orphans.length > 0) {
    const orphanY = globalMaxY + GAP_Y * 1.5;
    const totalW = orphans.length * (NODE_W + GAP_X);
    const startX = Math.max(PADDING, (componentOffsetX - totalW) / 2);
    orphans.forEach((n, i) => {
      positions[n.id] = {
        x: startX + i * (NODE_W + GAP_X),
        y: orphanY,
      };
    });
  }

  return positions;
}


/* ═══════════════════════════════════════════════════════════════════════════
   TopologyCanvas · inner component that uses useReactFlow()
   ═══════════════════════════════════════════════════════════════════════════ */

function TopologyCanvas({
  graph,
  savedPositions,
  savedViewport,
  showHealth,
  searchQuery,
  selectedNodeId,
  onNodeSelect,
  onNodesRef,
  onViewportRef,
  colorMode,
}: {
  graph: TopologyGraph;
  savedPositions: Record<string, { x: number; y: number; pinned: boolean }> | null;
  savedViewport: { x: number; y: number; zoom: number } | null;
  showHealth: boolean;
  searchQuery: string;
  selectedNodeId: string | null;
  onNodeSelect: (id: string | null) => void;
  onNodesRef: React.MutableRefObject<DeviceFlowNode[]>;
  onViewportRef: React.MutableRefObject<{ x: number; y: number; zoom: number }>;
  colorMode: 'dark' | 'light';
}) {
  const { t } = useTranslation('enterprise');
  const reactFlow = useReactFlow();
  const [nodes, setNodes, onNodesChange] = useNodesState<DeviceFlowNode>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState<TopologyFlowEdge>([]);
  const nodesInitialized = useNodesInitialized();
  const initialFitDone = useRef(false);
  const prevGraphRef = useRef<string | null>(null);

  // Keep parent ref in sync
  useEffect(() => {
    onNodesRef.current = nodes;
  }, [nodes, onNodesRef]);

  // Map API data → React Flow nodes/edges
  useEffect(() => {
    const graphKey = graph.generated_at;
    const isNewGraph = graphKey !== prevGraphRef.current;
    prevGraphRef.current = graphKey;

    const autoPos = computeAutoPositions(graph.nodes, graph.edges);
    const search = searchQuery.toLowerCase().trim();

    const flowNodes: DeviceFlowNode[] = graph.nodes.map((n) => {
      const saved = savedPositions?.[n.id];
      const pos = saved
        ? { x: saved.x, y: saved.y }
        : n.x != null && n.y != null
          ? { x: n.x, y: n.y }
          : autoPos[n.id] || { x: 0, y: 0 };

      const dimmed = search.length > 0 && ![
        n.label, n.ip_address, n.device_type, n.status, n.mac_address, n.model,
      ].some((v) => v?.toLowerCase().includes(search));

      return {
        id: n.id,
        type: 'device' as const,
        position: pos,
        data: {
          label: n.label,
          device_type: n.device_type,
          status: n.status,
          ip_address: n.ip_address,
          mac_address: n.mac_address,
          model: n.model,
          health_score: n.health_score,
          health_status: n.health_status,
          layer: n.layer,
          site_name: n.site_name,
          metadata: n.metadata,
          showHealth,
          dimmed,
        },
        draggable: true,
        selected: n.id === selectedNodeId,
      };
    });

    const flowEdges: TopologyFlowEdge[] = graph.edges.map((e) => ({
      id: e.id,
      source: e.source_id,
      target: e.target_id,
      type: 'topology' as const,
      animated: e.status === 'up',
      data: {
        source_port: e.source_port,
        target_port: e.target_port,
        speed: e.speed,
        status: e.status,
        link_type: e.link_type,
        discovered_via: e.discovered_via,
      },
    }));

    if (isNewGraph) {
      // Full replacement on first load or when graph structure changes
      setNodes(flowNodes);
      setEdges(flowEdges);
    } else {
      // Partial update · only update data, preserve user-dragged positions
      setNodes((prev) => {
        const prevMap = new Map(prev.map((n) => [n.id, n]));
        return flowNodes.map((fn) => {
          const existing = prevMap.get(fn.id);
          if (existing) {
            return { ...fn, position: existing.position };
          }
          return fn;
        });
      });
      setEdges(flowEdges);
    }
  }, [graph, savedPositions, showHealth, searchQuery, selectedNodeId, setNodes, setEdges]);

  // Restore saved viewport
  useEffect(() => {
    if (savedViewport && savedViewport.zoom) {
      setTimeout(() => {
        reactFlow.setViewport(savedViewport, { duration: 300 });
      }, 100);
    }
  }, [savedViewport, reactFlow]);

  // Auto fit-view on first initialization (only if no saved layout)
  useEffect(() => {
    if (nodesInitialized && !initialFitDone.current) {
      initialFitDone.current = true;
      if (!savedViewport?.zoom) {
        setTimeout(() => reactFlow.fitView({ padding: 0.15, duration: 400 }), 50);
      }
    }
  }, [nodesInitialized, savedViewport, reactFlow]);

  const handleNodeClick = useCallback((_: React.MouseEvent, node: DeviceFlowNode) => {
    onNodeSelect(node.id);
  }, [onNodeSelect]);

  const handlePaneClick = useCallback(() => {
    onNodeSelect(null);
  }, [onNodeSelect]);

  const miniMapNodeColor = useCallback((node: DeviceFlowNode) => {
    return STATUS_COLORS[node.data?.status] || STATUS_COLORS.unknown;
  }, []);

  return (
    <ReactFlow
      nodes={nodes}
      edges={edges}
      onNodesChange={onNodesChange as OnNodesChange<DeviceFlowNode>}
      onEdgesChange={onEdgesChange as OnEdgesChange<TopologyFlowEdge>}
      nodeTypes={nodeTypes}
      edgeTypes={edgeTypes}
      onNodeClick={handleNodeClick}
      onPaneClick={handlePaneClick}
      // Capture the current viewport on every pan/zoom so the parent's
      // Save Layout button can persist what the user actually sees,
      // not a hardcoded ``zoom=1, center=0,0``.
      onMove={(_evt, vp) => {
        onViewportRef.current = vp;
      }}
      fitView={false}
      minZoom={0.1}
      maxZoom={4}
      defaultEdgeOptions={{ type: 'topology' }}
      proOptions={{ hideAttribution: true }}
      className="!bg-background [&_.react-flow__edge-interaction]:!stroke-transparent [&_.react-flow__selection]:!bg-primary/10 [&_.react-flow__selection]:!border-primary/40"
      colorMode={colorMode}
    >
      <Background
        variant={BackgroundVariant.Dots}
        gap={20}
        size={1}
        className="!bg-background"
        color="hsl(var(--muted-foreground) / 0.15)"
      />
      <Controls
        showInteractive={false}
        className="!bg-background !border-border !shadow-lg [&>button]:!bg-background [&>button]:!border-border [&>button]:!text-foreground [&>button:hover]:!bg-muted [&>button>svg]:!fill-current"
      />
      <MiniMap
        nodeColor={miniMapNodeColor}
        nodeStrokeWidth={2}
        maskColor="hsl(var(--background) / 0.85)"
        className="!bg-muted/50 !border-border !shadow-lg [&_svg]:!bg-transparent"
        pannable
        zoomable
      />

      {/* Legend overlay */}
      <Panel position="bottom-left" className="!m-3">
        <div className="bg-background/90 backdrop-blur-sm border border-border rounded-lg px-3 py-2 text-xs flex items-center gap-4 shadow-sm">
          {Object.entries(STATUS_COLORS).map(([status, color]) => (
            <span key={status} className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full shrink-0" style={{ backgroundColor: color }} />
              {t(`TopologyPage.status.${status}`)}
            </span>
          ))}
          <Separator orientation="vertical" className="h-4" />
          <span className="flex items-center gap-1.5 text-muted-foreground">
            <span className="w-4 h-[3px] rounded bg-emerald-500" /> 10G+
          </span>
          <span className="flex items-center gap-1.5 text-muted-foreground">
            <span className="w-4 h-[2px] rounded bg-emerald-500" /> 1G
          </span>
          <span className="flex items-center gap-1.5 text-muted-foreground">
            <span className="w-4 h-[1.5px] rounded bg-emerald-500" /> {t('TopologyPage.legend.otherSpeed')}
          </span>
        </div>
      </Panel>
    </ReactFlow>
  );
}


/* ═══════════════════════════════════════════════════════════════════════════
   Device Detail Panel
   ═══════════════════════════════════════════════════════════════════════════ */

function DeviceDetailPanel({
  node,
  graph,
  onSelectNode,
}: {
  node: APITopologyNode;
  graph: TopologyGraph;
  onSelectNode: (id: string) => void;
}) {
  const { t } = useTranslation('enterprise');
  const navigate = useNavigate();
  const { toast } = useToast();
  const meta = DEVICE_TYPE_META[node.device_type] || DEVICE_TYPE_META.other;
  const Icon = meta.icon;
  const statusColor = STATUS_COLORS[node.status] || STATUS_COLORS.unknown;

  // Reboot used to fire on a single click with no error surface, silent
  // failures + no recovery. Now: typed confirm + toast on success/error.
  const rebootMutation = useMutation({
    mutationFn: () => deviceControlApi.reboot(node.id),
    onSuccess: () => toast({
      title: t('TopologyPage.toast.rebootDispatched.title'),
      description: t('TopologyPage.toast.rebootDispatched.description', { label: node.label }),
    }),
    onError: (err) => toast({
      variant: 'destructive',
      title: t('TopologyPage.toast.rebootFailed.title'),
      description: err instanceof Error ? err.message : t('TopologyPage.toast.unknownError'),
    }),
  });

  // Find connected devices
  const connections = useMemo(() => {
    return graph.edges
      .filter((e) => e.source_id === node.id || e.target_id === node.id)
      .map((e) => {
        const peerId = e.source_id === node.id ? e.target_id : e.source_id;
        const peerNode = graph.nodes.find((n) => n.id === peerId);
        const localPort = e.source_id === node.id ? e.source_port : e.target_port;
        const remotePort = e.source_id === node.id ? e.target_port : e.source_port;
        return { edge: e, peerId, peerNode, localPort, remotePort };
      });
  }, [graph, node.id]);

  return (
    <ScrollArea className="h-full">
      <div className="space-y-6 p-1">
        {/* Header */}
        <div className="flex items-center gap-3">
          <div className={cn('flex items-center justify-center w-12 h-12 rounded-xl bg-muted')}>
            <Icon className={cn('h-6 w-6', meta.color)} />
          </div>
          <div className="min-w-0 flex-1">
            <p className="font-semibold text-lg truncate">{node.label}</p>
            <div className="flex items-center gap-2">
              <span className="text-sm text-muted-foreground">{t(`TopologyPage.deviceTypes.${meta.labelKey}`)}</span>
              <Badge
                variant="outline"
                className="gap-1"
                style={{ borderColor: statusColor + '40', color: statusColor }}
              >
                <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: statusColor }} />
                {node.status}
              </Badge>
            </div>
          </div>
        </div>

        <Separator />

        {/* Info grid */}
        <div className="grid grid-cols-2 gap-3 text-sm">
          {node.ip_address && (
            <div>
              <p className="text-[11px] text-muted-foreground">{t('TopologyPage.detail.ipAddress')}</p>
              <p className="font-mono">{node.ip_address}</p>
            </div>
          )}
          {node.mac_address && (
            <div>
              <p className="text-[11px] text-muted-foreground">{t('TopologyPage.detail.macAddress')}</p>
              <p className="font-mono uppercase text-xs">{node.mac_address}</p>
            </div>
          )}
          {node.model && (
            <div>
              <p className="text-[11px] text-muted-foreground">{t('TopologyPage.detail.model')}</p>
              <p>{node.model}</p>
            </div>
          )}
          {node.layer && (
            <div>
              <p className="text-[11px] text-muted-foreground">{t('TopologyPage.detail.networkLayer')}</p>
              <p className="capitalize">{node.layer}</p>
            </div>
          )}
          {node.site_name && (
            <div>
              <p className="text-[11px] text-muted-foreground">{t('TopologyPage.detail.site')}</p>
              <p>{node.site_name}</p>
            </div>
          )}
          {node.health_score != null && (
            <div>
              <p className="text-[11px] text-muted-foreground">{t('TopologyPage.detail.healthScore')}</p>
              <div className="flex items-center gap-2 mt-0.5">
                <div className="flex-1 h-1.5 rounded-full bg-muted overflow-hidden">
                  <div
                    className={cn(
                      'h-full rounded-full transition-all',
                      node.health_score >= 80 ? 'bg-emerald-500' : node.health_score >= 50 ? 'bg-amber-500' : 'bg-red-500',
                    )}
                    style={{ width: `${Math.min(node.health_score, 100)}%` }}
                  />
                </div>
                <span className="font-mono text-xs">{Math.round(node.health_score)}%</span>
              </div>
            </div>
          )}
        </div>

        {/* Connected devices */}
        {connections.length > 0 && (
          <>
            <Separator />
            <div>
              <p className="text-sm font-medium mb-2">{t('TopologyPage.detail.connectedDevices', { n: connections.length })}</p>
              <div className="space-y-1">
                {connections.map(({ edge, peerId, peerNode, localPort, remotePort }) => {
                  const peerMeta = DEVICE_TYPE_META[peerNode?.device_type || 'other'] || DEVICE_TYPE_META.other;
                  const PeerIcon = peerMeta.icon;
                  const peerStatus = STATUS_COLORS[peerNode?.status || 'unknown'] || STATUS_COLORS.unknown;
                  return (
                    <button
                      key={edge.id}
                      className="w-full flex items-center gap-2.5 rounded-lg px-2.5 py-2 hover:bg-muted transition-colors text-left"
                      onClick={() => onSelectNode(peerId)}
                    >
                      <div className="relative">
                        <div className="flex items-center justify-center w-8 h-8 rounded-md bg-muted">
                          <PeerIcon className={cn('h-4 w-4', peerMeta.color)} />
                        </div>
                        <span
                          className="absolute -bottom-0.5 -right-0.5 w-2 h-2 rounded-full border border-background"
                          style={{ backgroundColor: peerStatus }}
                        />
                      </div>
                      <div className="flex-1 min-w-0">
                        <p className="text-xs font-medium truncate">{peerNode?.label || peerId.slice(0, 8)}</p>
                        {(localPort || remotePort) && (
                          <p className="text-[10px] text-muted-foreground font-mono">
                            {localPort || '?'} → {remotePort || '?'}
                            {edge.speed && ` · ${edge.speed}`}
                          </p>
                        )}
                      </div>
                      <ChevronRight className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
                    </button>
                  );
                })}
              </div>
            </div>
          </>
        )}

        <Separator />

        {/* Quick actions */}
        <div className="space-y-2">
          <p className="text-sm font-medium">{t('TopologyPage.detail.quickActions')}</p>
          <div className="flex flex-wrap gap-2">
            <Button size="sm" onClick={() => navigate(`/devices/${node.id}`)}>
              <ExternalLink className="h-3.5 w-3.5 mr-1.5" />
              {t('TopologyPage.actions.viewDevice')}
            </Button>
            <Button
              size="sm"
              variant="outline"
              disabled={node.status !== 'online' || rebootMutation.isPending}
              onClick={() => {
                // Confirm, one click was previously a live reboot with no undo.
                if (window.confirm(
                  t('TopologyPage.confirm.reboot', { label: node.label }),
                )) {
                  rebootMutation.mutate();
                }
              }}
            >
              <Power className="h-3.5 w-3.5 mr-1.5" />
              {rebootMutation.isPending ? t('TopologyPage.actions.rebooting') : t('TopologyPage.actions.reboot')}
            </Button>
          </div>
        </div>
      </div>
    </ScrollArea>
  );
}


/* ═══════════════════════════════════════════════════════════════════════════
   Main Page Component
   ═══════════════════════════════════════════════════════════════════════════ */

export default function TopologyPage() {
  const { t } = useTranslation('enterprise');
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const canvasContainerRef = useRef<HTMLDivElement>(null);
  const nodesRef = useRef<DeviceFlowNode[]>([]);
  // The TopologyCanvas (inner component, has ``useReactFlow``) writes the
  // current viewport to this ref whenever the user pans/zooms; the parent's
  // ``handleSaveLayout`` reads it so we persist the real viewport instead of
  // the hardcoded ``zoom: 1, center: 0,0`` that the previous version sent.
  const viewportRef = useRef<{ x: number; y: number; zoom: number }>({ x: 0, y: 0, zoom: 1 });

  // Resolve dark/light for React Flow colorMode
  const { theme } = useUIStore();
  const [systemPrefersDark, setSystemPrefersDark] = useState(
    () => window.matchMedia('(prefers-color-scheme: dark)').matches,
  );
  useEffect(() => {
    const mql = window.matchMedia('(prefers-color-scheme: dark)');
    const handler = (e: MediaQueryListEvent) => setSystemPrefersDark(e.matches);
    mql.addEventListener('change', handler);
    return () => mql.removeEventListener('change', handler);
  }, []);
  const resolvedColorMode: 'dark' | 'light' =
    theme === 'system' ? (systemPrefersDark ? 'dark' : 'light') : theme;

  // Site context · synced with global site selector
  const selectedSiteId = useSiteStore((s) => s.selectedSiteId);
  const siteId = selectedSiteId ?? '';

  // UI state
  const [showHealth, setShowHealth] = useState(true);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [layoutAlgorithm, setLayoutAlgorithm] = useState<string>('auto');
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [detailPanelOpen, setDetailPanelOpen] = useState(false);

  // Data queries
  const graphQuery = useQuery({
    queryKey: ['topology-graph', siteId, showHealth],
    queryFn: () => topologyApi.getGraph({ site_id: siteId || undefined, include_health: showHealth }),
    refetchInterval: 30000,
  });

  const layoutQuery = useQuery({
    queryKey: ['topology-layout', siteId],
    queryFn: () => topologyApi.getLayout(siteId),
    enabled: !!siteId,
  });

  // Save/auto-layout require a real site UUID, backend route is
  // ``/topology/layout/{site_id}``. The previous ``siteId || '_default'``
  // fallback sent the literal string ``_default`` as a UUID path param
  // and 4xx-d silently. We now refuse to dispatch without a site (see
  // ``handleSaveLayout`` + the algorithm-change handler) and surface a
  // toast on the rare cases something does fail.
  const saveLayoutMutation = useMutation({
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    mutationFn: (payload: { positions: Record<string, any>; zoom: number; center_x: number; center_y: number }) => {
      if (!siteId) throw new Error('No site selected, cannot save layout');
      return topologyApi.saveLayout(siteId, payload);
    },
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['topology-layout'] }),
    onError: (err) => toast({
      variant: 'destructive',
      title: t('TopologyPage.toast.saveLayoutFailed.title'),
      description: err instanceof Error ? err.message : t('TopologyPage.toast.unknownError'),
    }),
  });

  const autoLayoutMutation = useMutation({
    mutationFn: (algorithm: string) => {
      if (!siteId) throw new Error('No site selected, cannot run auto-layout');
      return topologyApi.autoLayout(siteId, algorithm);
    },
    onSuccess: (resp) => {
      // The server returns a full graph with freshly-computed x/y for the
      // chosen algorithm. Write it straight into the active graph cache so
      // the canvas re-renders with those positions. Invalidating instead
      // would refetch ``/topology/graph`` (the default ``auto`` layout) and
      // silently discard the algorithm-specific result, the selector would
      // be a visual no-op. Auto-layout doesn't persist to the saved-layout
      // table, so there's nothing else to invalidate.
      queryClient.setQueryData(['topology-graph', siteId, showHealth], resp);
    },
    onError: (err) => toast({
      variant: 'destructive',
      title: t('TopologyPage.toast.autoLayoutFailed.title'),
      description: err instanceof Error ? err.message : t('TopologyPage.toast.unknownError'),
    }),
  });

  const graph: TopologyGraph | null = graphQuery.data?.data || null;
  const savedLayout = layoutQuery.data?.data;

  const savedPositions = useMemo(() => savedLayout?.positions || null, [savedLayout]);
  const savedViewport = useMemo(() => {
    if (!savedLayout?.zoom) return null;
    return { x: savedLayout.center_x, y: savedLayout.center_y, zoom: savedLayout.zoom };
  }, [savedLayout]);

  // Node select handler
  const handleNodeSelect = useCallback((id: string | null) => {
    setSelectedNodeId(id);
    setDetailPanelOpen(!!id);
  }, []);

  // Save layout handler (reads positions from nodesRef + viewport from viewportRef).
  const handleSaveLayout = useCallback(() => {
    if (!siteId) {
      toast({
        variant: 'destructive',
        title: t('TopologyPage.toast.noSiteSelected.title'),
        description: t('TopologyPage.toast.noSiteSelected.description'),
      });
      return;
    }
    const rfNodes = nodesRef.current;
    const positions: Record<string, { x: number; y: number; pinned: boolean }> = {};
    for (const node of rfNodes) {
      positions[node.id] = {
        x: node.position.x,
        y: node.position.y,
        pinned: true,
      };
    }
    const vp = viewportRef.current;
    saveLayoutMutation.mutate({
      positions,
      zoom: vp.zoom,
      center_x: vp.x,
      center_y: vp.y,
    });
  }, [saveLayoutMutation, siteId, toast, t]);

  // Fullscreen toggle
  const toggleFullscreen = useCallback(() => {
    const el = canvasContainerRef.current;
    if (!el) return;
    if (!document.fullscreenElement) {
      el.requestFullscreen().then(() => setIsFullscreen(true)).catch(() => {});
    } else {
      document.exitFullscreen().then(() => setIsFullscreen(false)).catch(() => {});
    }
  }, []);

  useEffect(() => {
    const handler = () => setIsFullscreen(!!document.fullscreenElement);
    document.addEventListener('fullscreenchange', handler);
    return () => document.removeEventListener('fullscreenchange', handler);
  }, []);

  // Export PNG
  const handleExportPng = useCallback(() => {
    const el = canvasContainerRef.current?.querySelector('.react-flow') as HTMLElement | null;
    if (!el) return;
    // Read actual background from CSS variables so export respects light/dark theme
    const rawBg = getComputedStyle(document.documentElement).getPropertyValue('--background').trim();
    const bgColor = rawBg ? `hsl(${rawBg})` : '#ffffff';
    toPng(el, {
      backgroundColor: bgColor,
      quality: 1,
    }).then((dataUrl) => {
      const a = document.createElement('a');
      a.download = `topology-${new Date().toISOString().slice(0, 10)}.png`;
      a.href = dataUrl;
      a.click();
    }).catch(() => {});
  }, []);

  // Layout algorithm change. Local picker state always updates so the UI
  // reflects the selection; the server-side mutation only fires when a
  // site is selected (auto-layout is per-site, no org-wide target).
  const handleLayoutChange = useCallback((algo: string) => {
    setLayoutAlgorithm(algo);
    if (!siteId) return;
    autoLayoutMutation.mutate(algo);
  }, [autoLayoutMutation, siteId]);

  // Selected node info
  const selectedNode = useMemo(
    () => graph?.nodes.find((n) => n.id === selectedNodeId) || null,
    [graph, selectedNodeId],
  );

  return (
    <div className="flex flex-col" style={{ height: 'calc(100vh - 64px - 24px)' }}>
      {/* Header */}
      <PageHeader
        icon={Network}
        title={t('TopologyPage.header.title')}
        description={t('TopologyPage.header.description')}
        onRefresh={() => graphQuery.refetch()}
        refreshing={graphQuery.isFetching}
      />

      {graphQuery.isError && (
        <div className="rounded-md bg-destructive/10 p-3 text-sm text-destructive mt-4">
          {t('TopologyPage.error.loadFailed')}
        </div>
      )}

      {/* Stats */}
      {graph?.stats && (
        <div className="mt-4">
          <StatsGrid
            stats={[
              { title: t('TopologyPage.stats.devices'), value: graph.stats.total_nodes, icon: Server },
              { title: t('TopologyPage.stats.links'), value: graph.stats.total_edges, icon: Network },
              { title: t('TopologyPage.stats.orphans'), value: graph.stats.orphan_count, icon: Activity },
              { title: t('TopologyPage.stats.types'), value: Object.keys(graph.stats.nodes_by_type || {}).length, icon: Layers },
            ]}
          />
        </div>
      )}

      {/* Toolbar */}
      <Card className="mt-4">
        <CardContent noOffset className="py-3">
          <div className="flex items-center gap-3 flex-wrap">
            {/* Search */}
            <div className="relative flex-1 max-w-[220px]">
              <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
              <Input
                className="pl-8 h-8 text-xs"
                placeholder={t('TopologyPage.toolbar.searchPlaceholder')}
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
              />
            </div>

            {/* Layout algorithm */}
            <Select value={layoutAlgorithm} onValueChange={handleLayoutChange}>
              <SelectTrigger className="w-[140px] h-8 text-xs">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="auto">{t('TopologyPage.layoutAlgorithm.auto')}</SelectItem>
                <SelectItem value="hierarchical">{t('TopologyPage.layoutAlgorithm.hierarchical')}</SelectItem>
                <SelectItem value="force_directed">{t('TopologyPage.layoutAlgorithm.forceDirected')}</SelectItem>
              </SelectContent>
            </Select>

            {/* Health overlay */}
            <div className="flex items-center gap-2">
              <Switch checked={showHealth} onCheckedChange={setShowHealth} className="scale-90" />
              <Label className="text-xs text-muted-foreground">{t('TopologyPage.toolbar.health')}</Label>
            </div>

            <div className="ml-auto flex items-center gap-1.5">
              {/* Export PNG */}
              <TooltipProvider delayDuration={200}>
                <Tooltip>
                  <TooltipTrigger asChild>
                    <Button variant="outline" size="icon" className="h-8 w-8" onClick={handleExportPng}>
                      <Download className="h-3.5 w-3.5" />
                    </Button>
                  </TooltipTrigger>
                  <TooltipContent>{t('TopologyPage.toolbar.exportPng')}</TooltipContent>
                </Tooltip>
              </TooltipProvider>

              {/* Fullscreen */}
              <TooltipProvider delayDuration={200}>
                <Tooltip>
                  <TooltipTrigger asChild>
                    <Button variant="outline" size="icon" className="h-8 w-8" onClick={toggleFullscreen}>
                      {isFullscreen ? <Minimize2 className="h-3.5 w-3.5" /> : <Maximize2 className="h-3.5 w-3.5" />}
                    </Button>
                  </TooltipTrigger>
                  <TooltipContent>{isFullscreen ? t('TopologyPage.toolbar.exitFullscreen') : t('TopologyPage.toolbar.fullscreen')}</TooltipContent>
                </Tooltip>
              </TooltipProvider>

              {/* Save Layout, disabled without a site because the backend
                  endpoint is ``/topology/layout/{site_id}`` and there's
                  no org-wide layout target. The previous version silently
                  POSTed the string ``_default`` against a UUID path. */}
              <Button
                variant="outline"
                size="sm"
                className="h-8 text-xs"
                onClick={handleSaveLayout}
                disabled={!siteId || saveLayoutMutation.isPending}
                title={siteId ? undefined : t('TopologyPage.toolbar.saveLayoutDisabledHint')}
              >
                <Save className="h-3.5 w-3.5 mr-1.5" />
                {saveLayoutMutation.isPending ? t('TopologyPage.actions.saving') : t('TopologyPage.actions.saveLayout')}
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Canvas */}
      <div ref={canvasContainerRef} className="flex-1 min-h-0 mt-4 rounded-lg border border-border overflow-hidden bg-background">
        {graphQuery.isLoading ? (
          <div className="flex items-center justify-center h-full">
            <div className="text-center">
              <RefreshCw className="h-8 w-8 text-muted-foreground animate-spin mx-auto mb-3" />
              <p className="text-sm text-muted-foreground">{t('TopologyPage.loading')}</p>
            </div>
          </div>
        ) : !graph || graph.nodes.length === 0 ? (
          <div className="flex items-center justify-center h-full">
            <div className="text-center">
              <Network className="h-12 w-12 text-muted-foreground/30 mx-auto mb-3" />
              <h3 className="font-medium text-lg">{t('TopologyPage.empty.title')}</h3>
              <p className="text-sm text-muted-foreground mt-1 max-w-[300px]">
                {t('TopologyPage.empty.description')}
              </p>
            </div>
          </div>
        ) : (
          <ReactFlowProvider>
            <TopologyCanvas
              graph={graph}
              savedPositions={savedPositions}
              savedViewport={savedViewport}
              showHealth={showHealth}
              searchQuery={searchQuery}
              selectedNodeId={selectedNodeId}
              onNodeSelect={handleNodeSelect}
              onNodesRef={nodesRef}
              onViewportRef={viewportRef}
              colorMode={resolvedColorMode}
            />
          </ReactFlowProvider>
        )}
      </div>

      {/* Detail Panel */}
      <Sheet open={detailPanelOpen} onOpenChange={(open) => {
        setDetailPanelOpen(open);
        if (!open) setSelectedNodeId(null);
      }}>
        <SheetContent side="right" className="w-[380px] sm:w-[420px] p-4">
          <SheetHeader className="sr-only">
            <SheetTitle>{t('TopologyPage.detail.sheetTitle')}</SheetTitle>
            <SheetDescription>{t('TopologyPage.detail.sheetDescription')}</SheetDescription>
          </SheetHeader>
          {selectedNode && graph && (
            <DeviceDetailPanel
              node={selectedNode}
              graph={graph}
              onSelectNode={(id) => {
                setSelectedNodeId(id);
              }}
            />
          )}
        </SheetContent>
      </Sheet>
    </div>
  );
}

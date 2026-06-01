// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * VPN Topology Visualization
 *
 * React Flow graph that renders sites as nodes and S2S tunnels as edges.
 * Designed to be lazy-loaded inside VPNPage's tab system.
 */

import { useCallback, useMemo, useEffect, useRef } from 'react';
import { useTranslation } from 'react-i18next';
import {
  ReactFlow,
  ReactFlowProvider,
  Background,
  Controls,
  MiniMap,
  Handle,
  useNodesState,
  useEdgesState,
  Position,
  MarkerType,
  type Node,
  type Edge,
  type NodeProps,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { useQuery } from '@tanstack/react-query';
import { vpnApi, sitesApiV2 } from '@/lib/api';
import type { SiteToSiteTunnel, Site } from '@/lib/api/types';
import { Card, CardContent } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Skeleton } from '@/components/ui/skeleton';
import { Network, AlertTriangle } from 'lucide-react';

// ─── Status → color mapping ─────────────────────────────────────────────────

const STATUS_COLORS: Record<string, string> = {
  active: '#10b981',
  error: '#ef4444',
  disabled: '#6b7280',
  pending: '#f59e0b',
  provisioning: '#f97316',
};

const STATUS_BADGE_CLASSES: Record<string, string> = {
  active: 'bg-emerald-500/10 text-emerald-600 border-emerald-500/20',
  error: 'bg-red-500/10 text-red-600 border-red-500/20',
  disabled: 'bg-muted-foreground/10 text-muted-foreground border-muted-foreground/20',
  pending: 'bg-amber-500/10 text-amber-600 border-amber-500/20',
  provisioning: 'bg-orange-500/10 text-orange-600 border-orange-500/20',
};

// ─── Types ───────────────────────────────────────────────────────────────────

type SiteNodeData = {
  label: string;
  tunnelCount: number;
  hasError: boolean;
  siteType?: string;
};

type SiteFlowNode = Node<SiteNodeData, 'site'>;

// ─── Custom site node ────────────────────────────────────────────────────────

function SiteNode({ data }: NodeProps<SiteFlowNode>) {
  const { t } = useTranslation('vpn');
  return (
    <>
      <Handle
        type="target"
        position={Position.Top}
        className="!w-2 !h-2 !bg-border !border-0 !opacity-0"
      />
      <div
        className={`px-4 py-3 rounded-lg border-2 shadow-sm bg-white dark:bg-slate-800 min-w-[140px] ${
          data.hasError ? 'border-red-500' : 'border-emerald-500'
        }`}
      >
        <div className="flex items-center gap-2 mb-1">
          <Network className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
          <div className="font-medium text-sm truncate">{data.label}</div>
        </div>
        <div className="flex items-center justify-between gap-2">
          <span className="text-xs text-muted-foreground">
            {data.tunnelCount === 1
              ? t('VPNTopologyTab.tunnelCount.one', { count: data.tunnelCount })
              : t('VPNTopologyTab.tunnelCount.other', { count: data.tunnelCount })}
          </span>
          {data.siteType && (
            <Badge variant="outline" className="text-[10px] px-1.5 py-0">
              {data.siteType}
            </Badge>
          )}
        </div>
      </div>
      <Handle
        type="source"
        position={Position.Bottom}
        className="!w-2 !h-2 !bg-border !border-0 !opacity-0"
      />
    </>
  );
}

// Module-level nodeTypes · must be defined outside component to avoid
// re-creating on every render (React Flow requirement).
const nodeTypes = { site: SiteNode };

// ─── Layout helper (circular) ────────────────────────────────────────────────

function circularLayout(count: number, index: number): { x: number; y: number } {
  if (count <= 1) return { x: 400, y: 300 };
  const angle = (2 * Math.PI * index) / count - Math.PI / 2; // start from top
  const radius = Math.min(250, 120 + count * 20);
  return {
    x: 400 + radius * Math.cos(angle),
    y: 300 + radius * Math.sin(angle),
  };
}

// ─── Graph builder ───────────────────────────────────────────────────────────

function buildGraph(
  sites: Site[],
  tunnels: SiteToSiteTunnel[],
): { nodes: SiteFlowNode[]; edges: Edge[] } {
  // Collect site IDs referenced by tunnels
  const siteIdsInTunnels = new Set<string>();
  for (const t of tunnels) {
    siteIdsInTunnels.add(t.site_a_id);
    siteIdsInTunnels.add(t.site_b_id);
  }

  // Only include sites that participate in at least one tunnel
  const relevantSites = sites.filter((s) => siteIdsInTunnels.has(s.id));

  // Build a map for quick lookup
  const siteMap = new Map<string, Site>();
  for (const s of sites) siteMap.set(s.id, s);

  // Count tunnels per site + detect errors
  const tunnelCounts = new Map<string, number>();
  const errorSites = new Set<string>();
  for (const t of tunnels) {
    tunnelCounts.set(t.site_a_id, (tunnelCounts.get(t.site_a_id) || 0) + 1);
    tunnelCounts.set(t.site_b_id, (tunnelCounts.get(t.site_b_id) || 0) + 1);
    if (t.status === 'error') {
      errorSites.add(t.site_a_id);
      errorSites.add(t.site_b_id);
    }
  }

  // Nodes
  const nodes: SiteFlowNode[] = relevantSites.map((site, i) => {
    const pos = circularLayout(relevantSites.length, i);
    return {
      id: site.id,
      type: 'site',
      position: pos,
      data: {
        label: site.name,
        tunnelCount: tunnelCounts.get(site.id) || 0,
        hasError: errorSites.has(site.id),
        siteType: site.site_type,
      },
    };
  });

  // Edges
  const edges: Edge[] = tunnels.map((tunnel) => {
    const color = STATUS_COLORS[tunnel.status] || '#6b7280';
    const siteA = siteMap.get(tunnel.site_a_id);
    const siteB = siteMap.get(tunnel.site_b_id);
    const labelParts: string[] = [tunnel.status];
    if (siteA && siteB) {
      labelParts.unshift(`${siteA.name} \u2194 ${siteB.name}`);
    }

    return {
      id: tunnel.id,
      source: tunnel.site_a_id,
      target: tunnel.site_b_id,
      label: tunnel.status,
      animated: tunnel.status === 'active' || tunnel.status === 'provisioning',
      style: { stroke: color, strokeWidth: 2 },
      markerEnd: {
        type: MarkerType.ArrowClosed,
        color,
        width: 16,
        height: 16,
      },
      labelStyle: {
        fill: color,
        fontWeight: 600,
        fontSize: 11,
      },
      labelBgStyle: {
        fill: 'white',
        fillOpacity: 0.85,
      },
      labelBgPadding: [6, 3] as [number, number],
      labelBgBorderRadius: 4,
    };
  });

  return { nodes, edges };
}

// ─── Inner component (needs ReactFlowProvider wrapper) ───────────────────────

function VPNTopologyInner() {
  const { t } = useTranslation('vpn');

  // Fetch tunnels
  const {
    data: tunnelsData,
    isLoading: tunnelsLoading,
    isError: tunnelsError,
  } = useQuery({
    queryKey: ['vpn', 'tunnels', { limit: 200 }],
    queryFn: async () => (await vpnApi.orchestration.listTunnels(undefined, 200)).data,
    refetchInterval: 30_000,
    refetchIntervalInBackground: false,
  });

  // Fetch sites
  const {
    data: sitesData,
    isLoading: sitesLoading,
    isError: sitesError,
  } = useQuery({
    queryKey: ['sites', { page_size: 500 }],
    queryFn: async () => (await sitesApiV2.list({ page_size: 500 })).data,
  });

  const tunnels = useMemo(() => tunnelsData?.tunnels ?? [], [tunnelsData]);
  const sites = useMemo(() => sitesData?.items ?? [], [sitesData]);

  const { nodes: initialNodes, edges: initialEdges } = useMemo(
    () => buildGraph(sites, tunnels),
    [sites, tunnels],
  );

  const [nodes, setNodes, onNodesChange] = useNodesState<SiteFlowNode>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([]);

  // Track which site/tunnel IDs we've seen to avoid resetting positions on refetch
  const prevGraphKey = useRef('');

  // Sync graph only when the actual set of sites/tunnels changes (not on every refetch)
  useEffect(() => {
    const siteIds = initialNodes.map((n) => n.id).sort().join(',');
    const edgeIds = initialEdges.map((e) => e.id).sort().join(',');
    const graphKey = `${siteIds}|${edgeIds}`;
    if (graphKey !== prevGraphKey.current) {
      prevGraphKey.current = graphKey;
      setNodes(initialNodes);
      setEdges(initialEdges);
    } else {
      // Update edge data (status colors) without resetting node positions
      setEdges(initialEdges);
    }
  }, [initialNodes, initialEdges, setNodes, setEdges]);

  const isLoading = tunnelsLoading || sitesLoading;
  const isError = tunnelsError || sitesError;

  // MiniMap color callback
  const minimapNodeColor = useCallback(
    (node: Node) => {
      const d = (node as SiteFlowNode).data;
      return d?.hasError ? '#ef4444' : '#10b981';
    },
    [],
  );

  // ── Loading state ────────────────────────────────────────────────────────

  if (isLoading) {
    return (
      <Card>
        <CardContent noOffset className="p-4">
          <Skeleton className="h-[600px] w-full rounded-lg" />
        </CardContent>
      </Card>
    );
  }

  // ── Error state ──────────────────────────────────────────────────────────

  if (isError) {
    return (
      <Card className="border-destructive">
        <CardContent noOffset className="flex items-center gap-3 p-6">
          <AlertTriangle className="h-5 w-5 text-destructive shrink-0" />
          <div>
            <p className="text-sm font-medium">{t('VPNTopologyTab.error.title')}</p>
            <p className="text-xs text-muted-foreground mt-1">
              {t('VPNTopologyTab.error.description')}
            </p>
          </div>
        </CardContent>
      </Card>
    );
  }

  // ── Empty state ──────────────────────────────────────────────────────────

  if (tunnels.length === 0) {
    return (
      <Card className="p-12">
        <div className="flex flex-col items-center justify-center text-center">
          <Network className="h-12 w-12 text-muted-foreground/50 mb-4" />
          <h3 className="text-lg font-medium text-foreground mb-2">{t('VPNTopologyTab.empty.title')}</h3>
          <p className="text-muted-foreground max-w-md">
            {t('VPNTopologyTab.empty.description')}
          </p>
        </div>
      </Card>
    );
  }

  // ── Summary bar ──────────────────────────────────────────────────────────

  const statusCounts = tunnels.reduce<Record<string, number>>((acc, t) => {
    acc[t.status] = (acc[t.status] || 0) + 1;
    return acc;
  }, {});

  // ── Graph ────────────────────────────────────────────────────────────────

  return (
    <div className="space-y-4">
      {/* Summary badges */}
      <div className="flex items-center gap-3 flex-wrap">
        <span className="text-sm font-medium text-muted-foreground">
          {(nodes.length === 1
            ? t('VPNTopologyTab.summary.site.one', { count: nodes.length })
            : t('VPNTopologyTab.summary.site.other', { count: nodes.length }))}
          {' · '}
          {(tunnels.length === 1
            ? t('VPNTopologyTab.summary.tunnel.one', { count: tunnels.length })
            : t('VPNTopologyTab.summary.tunnel.other', { count: tunnels.length }))}
        </span>
        {Object.entries(statusCounts).map(([status, count]) => (
          <Badge
            key={status}
            variant="outline"
            className={STATUS_BADGE_CLASSES[status] || ''}
          >
            {count} {status}
          </Badge>
        ))}
      </div>

      {/* React Flow canvas */}
      <Card className="overflow-hidden">
        <div className="h-[600px] w-full">
          <ReactFlow
            nodes={nodes}
            edges={edges}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            nodeTypes={nodeTypes}
            fitView
            fitViewOptions={{ padding: 0.3 }}
            proOptions={{ hideAttribution: true }}
            minZoom={0.3}
            maxZoom={2}
            defaultEdgeOptions={{
              type: 'smoothstep',
            }}
          >
            <Background gap={20} size={1} />
            <Controls showInteractive={false} />
            <MiniMap
              nodeColor={minimapNodeColor}
              nodeStrokeWidth={2}
              zoomable
              pannable
              className="!bg-muted/50 !border-border"
            />
          </ReactFlow>
        </div>
      </Card>
    </div>
  );
}

// ─── Exported wrapper (ReactFlowProvider is required) ────────────────────────

export default function VPNTopologyTab() {
  return (
    <ReactFlowProvider>
      <VPNTopologyInner />
    </ReactFlowProvider>
  );
}

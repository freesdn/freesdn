// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * TopologyDiscoveryTab, React Flow visualization of agent-discovered hosts.
 *
 * Two layers:
 *  - Subnet nodes (one per Site.subnets CIDR) act as group anchors.
 *  - Host nodes attach to their claiming subnet via dashed edges.
 *  - Real LLDP/CDP edges from devices.topology_edges render between
 *    chassis nodes when the agent has captured them.
 *
 * Layout is a simple radial cluster: subnets along a horizontal axis,
 * hosts arranged below their subnet. Good enough for under ~50 hosts;
 * larger sites should run a force-directed layout (deferred to v2).
 */

import { useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { useQuery } from '@tanstack/react-query';
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  type Node,
  type Edge,
  type NodeProps,
  Handle,
  Position,
  MarkerType,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { RefreshCw, Network, Server, CheckCircle2 } from 'lucide-react';
import {
  discoveryApi,
  type DiscoveryTopologyHostNode,
  type DiscoveryTopologySubnetNode,
} from '@/lib/api/discovery';
import { Link } from 'react-router-dom';

interface Props {
  siteId?: string;
}

// ---------- Custom node renderers ----------

interface HostNodeData {
  host: DiscoveryTopologyHostNode;
  [key: string]: unknown;
}

interface SubnetNodeData {
  subnet: DiscoveryTopologySubnetNode;
  [key: string]: unknown;
}

function HostNodeView({ data }: NodeProps) {
  const { t } = useTranslation('common');
  const host = (data as HostNodeData).host;
  const adopted = host.is_adopted;
  return (
    <div
      className={`px-3 py-2 rounded border shadow-sm text-xs min-w-[150px] ${
        adopted
          ? 'bg-emerald-50 border-emerald-400'
          : 'bg-white border-slate-300'
      }`}
    >
      <Handle type="target" position={Position.Top} className="!bg-slate-400" />
      <div className="flex items-center gap-1.5 font-mono font-medium">
        {adopted ? (
          <CheckCircle2 className="h-3 w-3 text-emerald-600" />
        ) : (
          <Server className="h-3 w-3 text-slate-500" />
        )}
        {host.ip_address}
      </div>
      {host.hostname ? (
        <div className="text-slate-500 truncate max-w-[140px]">
          {host.hostname}
        </div>
      ) : host.vendor ? (
        <div className="text-slate-500 truncate max-w-[140px]">{host.vendor}</div>
      ) : null}
      {adopted && host.adopted_device_id ? (
        <Link
          to={`/devices/${host.adopted_device_id}`}
          className="text-[10px] text-emerald-700 hover:underline"
        >
          {t('TopologyDiscoveryTab.host.managedLink')}
        </Link>
      ) : null}
      <Handle type="source" position={Position.Bottom} className="!bg-slate-400" />
    </div>
  );
}

function SubnetNodeView({ data }: NodeProps) {
  const { t } = useTranslation('common');
  const subnet = (data as SubnetNodeData).subnet;
  return (
    <div className="px-4 py-3 rounded-lg border-2 border-sky-500 bg-sky-50 shadow text-xs min-w-[200px]">
      <Handle
        type="target"
        position={Position.Top}
        className="!bg-sky-500"
      />
      <Handle
        type="source"
        position={Position.Bottom}
        className="!bg-sky-500"
      />
      <div className="flex items-center gap-2 font-semibold">
        <Network className="h-4 w-4 text-sky-600" />
        {subnet.label}
      </div>
      <div className="text-slate-600 font-mono mt-0.5">{subnet.cidr}</div>
      <div className="text-slate-500 mt-1 flex items-center gap-2">
        <span>{t('TopologyDiscoveryTab.subnet.hostCount', { count: subnet.host_count })}</span>
        {subnet.vlan_id ? (
          <Badge variant="outline">
            {t('TopologyDiscoveryTab.subnet.vlanBadge', { id: subnet.vlan_id })}
          </Badge>
        ) : null}
      </div>
    </div>
  );
}

const nodeTypes = {
  host: HostNodeView,
  subnet: SubnetNodeView,
};

// ---------- Layout (simple deterministic placement) ----------

function layoutGraph(
  hosts: DiscoveryTopologyHostNode[],
  subnets: DiscoveryTopologySubnetNode[],
): { nodes: Node[]; edges: Edge[] } {
  const nodes: Node[] = [];
  // Subnets in a horizontal row at the top
  const subnetSpacing = 360;
  subnets.forEach((s, idx) => {
    nodes.push({
      id: s.id,
      type: 'subnet',
      position: { x: idx * subnetSpacing, y: 0 },
      data: { subnet: s },
      draggable: true,
    });
  });

  // Hosts: bucket by subnet_id, then lay each bucket out as a grid below the subnet
  const bucketed: Record<string, DiscoveryTopologyHostNode[]> = {};
  const orphans: DiscoveryTopologyHostNode[] = [];
  for (const h of hosts) {
    if (h.subnet_id) {
      bucketed[h.subnet_id] = bucketed[h.subnet_id] || [];
      bucketed[h.subnet_id].push(h);
    } else {
      orphans.push(h);
    }
  }

  const subnetIndex: Record<string, number> = {};
  subnets.forEach((s, i) => (subnetIndex[s.id] = i));

  const HOST_COL_WIDTH = 170;
  const HOST_ROW_HEIGHT = 90;
  const PER_ROW = 5;

  for (const [subnetId, members] of Object.entries(bucketed)) {
    const baseX = (subnetIndex[subnetId] ?? 0) * subnetSpacing;
    members.forEach((h, i) => {
      const col = i % PER_ROW;
      const row = Math.floor(i / PER_ROW);
      nodes.push({
        id: h.id,
        type: 'host',
        position: {
          x: baseX - (PER_ROW * HOST_COL_WIDTH) / 2 + col * HOST_COL_WIDTH + 100,
          y: 150 + row * HOST_ROW_HEIGHT,
        },
        data: { host: h },
        draggable: true,
      });
    });
  }

  // Orphans (no subnet match) in a row at the far right
  const orphanX = subnets.length * subnetSpacing + 100;
  orphans.forEach((h, i) => {
    nodes.push({
      id: h.id,
      type: 'host',
      position: { x: orphanX, y: i * HOST_ROW_HEIGHT },
      data: { host: h },
      draggable: true,
    });
  });

  return { nodes, edges: [] };
}

export function TopologyDiscoveryTab({ siteId }: Props) {
  const { t } = useTranslation('common');
  const { data, isLoading, isError, refetch } = useQuery({
    queryKey: ['discovery-topology', siteId],
    queryFn: async () => {
      const resp = await discoveryApi.getDiscoveryTopology({
        site_id: siteId,
        include_adopted: true,
      });
      return resp.data;
    },
    enabled: !!siteId,
    refetchInterval: 60_000,
  });

  const { rfNodes, rfEdges } = useMemo(() => {
    if (!data) return { rfNodes: [], rfEdges: [] };
    const hosts = data.nodes.filter(
      (n): n is DiscoveryTopologyHostNode => n.type === 'host',
    );
    const subnets = data.nodes.filter(
      (n): n is DiscoveryTopologySubnetNode => n.type === 'subnet',
    );

    const { nodes } = layoutGraph(hosts, subnets);

    const edges: Edge[] = data.edges.map((e) => {
      const isSubnet = e.type === 'subnet_member';
      return {
        id: e.id,
        source: e.source,
        target: e.target,
        animated: isSubnet ? false : true,
        style: isSubnet
          ? { stroke: '#94a3b8', strokeDasharray: '4 4' }
          : { stroke: '#10b981', strokeWidth: 2 },
        markerEnd: isSubnet
          ? undefined
          : { type: MarkerType.ArrowClosed, color: '#10b981' },
        label: isSubnet ? undefined : e.neighbor_port_id,
        labelStyle: { fontSize: 10, fill: '#475569' },
      };
    });

    return { rfNodes: nodes, rfEdges: edges };
  }, [data]);

  if (!siteId) {
    return (
      <Card>
        <CardContent className="p-6 text-sm text-muted-foreground">
          {t('TopologyDiscoveryTab.selectSitePrompt')}
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle className="flex items-center gap-2">
            <Network className="h-5 w-5 text-sky-600" />
            {t('TopologyDiscoveryTab.title')}
            {data ? (
              <Badge variant="secondary">
                {t('TopologyDiscoveryTab.countBadge', {
                  hosts: data.nodes.filter((n) => n.type === 'host').length,
                  subnets: data.subnets.length,
                })}
              </Badge>
            ) : null}
          </CardTitle>
          <div className="flex items-center gap-2">
            <div className="text-xs text-muted-foreground flex items-center gap-3">
              <span className="flex items-center gap-1">
                <span className="inline-block w-3 h-3 rounded bg-emerald-50 border border-emerald-400" />
                {t('TopologyDiscoveryTab.legend.adopted')}
              </span>
              <span className="flex items-center gap-1">
                <span className="inline-block w-3 h-3 rounded bg-white border border-slate-300" />
                {t('TopologyDiscoveryTab.legend.discovered')}
              </span>
              <span className="flex items-center gap-1">
                <span className="inline-block w-6 h-0.5 bg-emerald-500" />
                {t('TopologyDiscoveryTab.legend.lldp')}
              </span>
            </div>
            <Button variant="outline" size="sm" onClick={() => refetch()}>
              <RefreshCw className="h-4 w-4" />
            </Button>
          </div>
        </div>
      </CardHeader>
      <CardContent>
        {isError ? (
          <div className="text-sm text-destructive p-4">
            {t('TopologyDiscoveryTab.error')}
          </div>
        ) : isLoading ? (
          <div className="text-sm text-muted-foreground p-4">
            {t('TopologyDiscoveryTab.loading')}
          </div>
        ) : !data || data.nodes.length === 0 ? (
          <div className="text-sm text-muted-foreground p-4">
            {t('TopologyDiscoveryTab.empty')}
          </div>
        ) : (
          <div className="h-[600px] border rounded">
            <ReactFlow
              nodes={rfNodes}
              edges={rfEdges}
              nodeTypes={nodeTypes}
              fitView
              minZoom={0.2}
              maxZoom={2}
              proOptions={{ hideAttribution: true }}
            >
              <Background gap={20} />
              <Controls />
              <MiniMap pannable zoomable />
            </ReactFlow>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

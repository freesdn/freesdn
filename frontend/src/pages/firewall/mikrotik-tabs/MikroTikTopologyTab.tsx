// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * MikroTikTopologyTab · neighbor discovery + topology graph.
 *
 * RouterOS detects L2 neighbors via:
 *   - LLDP (IEEE 802.1AB · most common with switches + APs)
 *   - CDP (Cisco)
 *   - MNDP (MikroTik Neighbor Discovery Protocol)
 *
 * Three cards:
 *   - Topology graph (@xyflow/react). One node per discovered neighbor
 *     + the device itself; edges are colored by discovery protocol.
 *     Falls back to an EmptyState if no neighbors are reachable (lab
 *     CHR / isolated network).
 *   - Discovery settings: which protocols are enabled, which interface
 *     scope to discover on. Edit dialog stages
 *     ``mikrotik.system.neighbor.settings``.
 *   - LLDP per-interface table: for each interface that has an LLDP
 *     neighbor, show the neighbor's system-name + port-id + management
 *     address.
 *
 * Layout: the topology has the device at the center and neighbors
 * arranged in a circle around it. The basic layout is fine for the
 * small graphs typical on a single MikroTik device, building a force
 * layout adds complexity and isn't needed at this scale.
 */
import { useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  ReactFlow,
  ReactFlowProvider,
  Background,
  Controls,
  MarkerType,
  type Node,
  type Edge,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import {
  Loader2,
  Network,
  Pencil,
  RefreshCw,
  Wifi,
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
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { EmptyState, ErrorState } from '@/components/ui/empty-state';
import { useToast } from '@/hooks/use-toast';
import {
  getApiErrorMessage,
  mikrotikApi,
  type MikroTikLldpInterface,
  type MikroTikTopologyEdge,
  type MikroTikTopologyNode,
} from '@/lib/api';

export interface MikroTikTopologyTabProps {
  controllerId: string;
  isActive: boolean;
}

const TOPOLOGY_KEY = (cid: string) => ['mikrotik', cid, 'topology'];
const NEIGHBORS_KEY = (cid: string) => ['mikrotik', cid, 'neighbors'];
const SETTINGS_KEY = (cid: string) => ['mikrotik', cid, 'neighbor-settings'];
const LLDP_KEY = (cid: string) => ['mikrotik', cid, 'lldp-interfaces'];

const PROTOCOL_COLORS: Record<string, string> = {
  lldp: '#10b981', // emerald
  cdp: '#3b82f6', // blue
  mndp: '#f59e0b', // amber
  unknown: '#94a3b8', // slate
};

function protocolColor(p: string): string {
  return PROTOCOL_COLORS[p.toLowerCase()] ?? PROTOCOL_COLORS.unknown;
}

function asStr(value: unknown): string {
  if (value === undefined || value === null) return '-';
  if (typeof value === 'string') return value || '-';
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  return '-';
}

/**
 * Place neighbor nodes on a circle around the device node. Returns a
 * tuple of (x, y) for a given index out of `count` neighbors.
 */
function ringPosition(index: number, count: number, radius = 220): {
  x: number;
  y: number;
} {
  if (count === 0) return { x: 0, y: 0 };
  const angle = (2 * Math.PI * index) / count;
  return {
    x: Math.cos(angle) * radius,
    y: Math.sin(angle) * radius,
  };
}

export function MikroTikTopologyTab({
  controllerId,
  isActive,
}: MikroTikTopologyTabProps) {
  const { t } = useTranslation('firewall');
  const queryClient = useQueryClient();
  const { toast } = useToast();

  const [settingsDialogOpen, setSettingsDialogOpen] = useState(false);
  const [protocolForm, setProtocolForm] = useState<string>('');
  const [scopeForm, setScopeForm] = useState<string>('');

  const topologyQuery = useQuery({
    queryKey: TOPOLOGY_KEY(controllerId),
    queryFn: () => mikrotikApi.buildTopology(controllerId),
    enabled: !!controllerId && isActive,
    refetchInterval: 60_000,
  });

  const neighborsQuery = useQuery({
    queryKey: NEIGHBORS_KEY(controllerId),
    queryFn: () => mikrotikApi.getNeighbors(controllerId),
    enabled: !!controllerId && isActive,
    refetchInterval: 60_000,
  });

  const settingsQuery = useQuery({
    queryKey: SETTINGS_KEY(controllerId),
    queryFn: () => mikrotikApi.getNeighborDiscoverySettings(controllerId),
    enabled: !!controllerId && isActive,
    refetchInterval: 60_000,
  });

  const lldpQuery = useQuery({
    queryKey: LLDP_KEY(controllerId),
    queryFn: () => mikrotikApi.getLldpInterfaces(controllerId),
    enabled: !!controllerId && isActive,
    refetchInterval: 60_000,
  });

  const topology = topologyQuery.data?.data;
  // Backend returns a bare settings dict (not a {item} envelope).
  const settings = settingsQuery.data?.data;
  const lldp = lldpQuery.data?.data.items ?? [];
  // Backend returns a bare neighbor list; derive the count from its length.
  const neighborCount = neighborsQuery.data?.data?.length ?? 0;

  const updateSettingsMut = useMutation({
    mutationFn: (payload: Record<string, unknown>) =>
      mikrotikApi.updateNeighborDiscoverySettings(controllerId, payload),
    onSuccess: () => {
      toast({ title: t('MikroTikTopologyTab.toast.settingsStaged') });
      setSettingsDialogOpen(false);
      queryClient.invalidateQueries({ queryKey: SETTINGS_KEY(controllerId) });
    },
    onError: (err) =>
      toast({
        title: t('MikroTikTopologyTab.toast.settingsStageFailed'),
        description: getApiErrorMessage(err),
        variant: 'destructive',
      }),
  });

  // Build React Flow nodes + edges from the topology response. Memoize
  // to avoid recomputing on every render, the topology only changes
  // when refetched.
  const { rfNodes, rfEdges } = useMemo(() => {
    const responseNodes = topology?.nodes ?? [];
    const responseEdges = topology?.edges ?? [];
    // Identify the device node (type === 'device') and place it at the
    // origin; lay neighbors on a ring around it.
    const deviceNode = responseNodes.find((n: MikroTikTopologyNode) => n.type === 'device');
    const others = responseNodes.filter(
      (n: MikroTikTopologyNode) => n.type !== 'device',
    );

    const nodes: Node[] = [];
    if (deviceNode) {
      nodes.push({
        id: deviceNode.id,
        position: { x: 0, y: 0 },
        data: {
          label: deviceNode.label,
        },
        type: 'default',
        style: {
          background: '#1e293b',
          color: '#f1f5f9',
          border: '2px solid #3b82f6',
          borderRadius: 8,
          padding: '6px 10px',
          fontSize: 12,
        },
      });
    }
    others.forEach((n: MikroTikTopologyNode, i: number) => {
      const pos = ringPosition(i, others.length || 1);
      nodes.push({
        id: n.id,
        position: pos,
        data: {
          label: `${n.label}${n.platform ? `\n(${n.platform})` : ''}`,
        },
        type: 'default',
        style: {
          background: '#f8fafc',
          color: '#0f172a',
          border: '1px solid #cbd5e1',
          borderRadius: 6,
          padding: '6px 8px',
          fontSize: 11,
          maxWidth: 180,
          whiteSpace: 'pre-line',
        },
      });
    });

    const edges: Edge[] = responseEdges.map((e: MikroTikTopologyEdge) => ({
      id: e.id,
      source: e.source,
      target: e.target,
      label: e.protocol.toUpperCase(),
      style: { stroke: protocolColor(e.protocol), strokeWidth: 2 },
      labelStyle: { fontSize: 10, fill: protocolColor(e.protocol) },
      markerEnd: {
        type: MarkerType.ArrowClosed,
        color: protocolColor(e.protocol),
      },
    }));

    return { rfNodes: nodes, rfEdges: edges };
  }, [topology]);

  // Seed the settings form whenever the dialog opens or the data
  // refreshes, the operator types over the current values.
  function openSettingsDialog() {
    if (settings) {
      setProtocolForm(asStr(settings.protocol) === '-' ? '' : asStr(settings.protocol));
      setScopeForm(
        asStr(settings['discover-interface-list']) === '-'
          ? ''
          : asStr(settings['discover-interface-list']),
      );
    }
    setSettingsDialogOpen(true);
  }

  function submitSettings() {
    const payload: Record<string, unknown> = {};
    if (protocolForm.trim()) payload.protocol = protocolForm.trim();
    if (scopeForm.trim()) payload['discover-interface-list'] = scopeForm.trim();
    updateSettingsMut.mutate(payload);
  }

  if (
    topologyQuery.isLoading &&
    neighborsQuery.isLoading &&
    lldpQuery.isLoading
  ) {
    return (
      <div className="flex items-center justify-center py-16 text-muted-foreground">
        <Loader2 className="h-5 w-5 animate-spin mr-2" />
        {t('MikroTikTopologyTab.loading')}
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-end">
        <Button
          variant="outline"
          size="sm"
          onClick={() => {
            topologyQuery.refetch();
            neighborsQuery.refetch();
            settingsQuery.refetch();
            lldpQuery.refetch();
          }}
        >
          <RefreshCw className="h-4 w-4 mr-1" /> {t('MikroTikTopologyTab.actions.refresh')}
        </Button>
      </div>

      {/* Card 1: Topology graph */}
      <Card className="border-border/50">
        <CardHeader className="pb-4">
          <CardTitle className="flex items-center gap-2">
            <Network className="h-4 w-4" /> {t('MikroTikTopologyTab.graph.title')}
          </CardTitle>
          <CardDescription>
            {t('MikroTikTopologyTab.graph.description', { count: neighborCount })}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {topologyQuery.isError ? (
            <ErrorState
              message={getApiErrorMessage(
                topologyQuery.error,
                t('MikroTikTopologyTab.graph.loadError'),
              )}
              onRetry={() => topologyQuery.refetch()}
            />
          ) : rfNodes.length === 0 ? (
            <EmptyState
              variant="compact"
              title={t('MikroTikTopologyTab.graph.empty.title')}
              description={t('MikroTikTopologyTab.graph.empty.description')}
            />
          ) : (
            <div className="border rounded-md bg-background" style={{ height: 420 }}>
              <ReactFlowProvider>
                <ReactFlow
                  nodes={rfNodes}
                  edges={rfEdges}
                  fitView
                  nodesDraggable={true}
                  nodesConnectable={false}
                  proOptions={{ hideAttribution: true }}
                >
                  <Background gap={16} />
                  <Controls showInteractive={false} />
                </ReactFlow>
              </ReactFlowProvider>
              <div className="flex items-center gap-3 px-3 py-2 border-t text-xs text-muted-foreground">
                <span className="font-medium">{t('MikroTikTopologyTab.graph.legend')}</span>
                {Object.entries(PROTOCOL_COLORS).map(([proto, color]) => (
                  <span key={proto} className="flex items-center gap-1">
                    <span
                      className="inline-block h-2 w-3 rounded-sm"
                      style={{ background: color }}
                    />
                    {proto.toUpperCase()}
                  </span>
                ))}
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Card 2: Discovery settings */}
      <Card className="border-border/50">
        <CardHeader className="pb-4">
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="flex items-center gap-2">
                <Wifi className="h-4 w-4" /> {t('MikroTikTopologyTab.settings.title')}
              </CardTitle>
              <CardDescription>
                {t('MikroTikTopologyTab.settings.description')}
              </CardDescription>
            </div>
            <Button
              size="sm"
              variant="outline"
              onClick={openSettingsDialog}
              disabled={!settings}
            >
              <Pencil className="h-4 w-4 mr-1" aria-hidden="true" /> {t('MikroTikTopologyTab.settings.edit')}
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          {settingsQuery.isError ? (
            <ErrorState
              message={getApiErrorMessage(
                settingsQuery.error,
                t('MikroTikTopologyTab.settings.loadError'),
              )}
              onRetry={() => settingsQuery.refetch()}
            />
          ) : !settings ? (
            <EmptyState
              variant="compact"
              title={t('MikroTikTopologyTab.settings.empty.title')}
              description={t('MikroTikTopologyTab.settings.empty.description')}
            />
          ) : (
            <dl className="grid grid-cols-2 gap-x-6 gap-y-3 text-sm">
              <dt className="text-muted-foreground">{t('MikroTikTopologyTab.settings.protocolsEnabled')}</dt>
              <dd className="font-mono text-xs">{asStr(settings.protocol)}</dd>
              <dt className="text-muted-foreground">{t('MikroTikTopologyTab.settings.interfaceScope')}</dt>
              <dd className="font-mono text-xs">
                {asStr(settings['discover-interface-list'])}
              </dd>
            </dl>
          )}
        </CardContent>
      </Card>

      {/* Card 3: LLDP per-interface */}
      <Card className="border-border/50">
        <CardHeader className="pb-4">
          <CardTitle className="flex items-center gap-2">
            <Network className="h-4 w-4" /> {t('MikroTikTopologyTab.lldp.title')}
          </CardTitle>
          <CardDescription>
            {t('MikroTikTopologyTab.lldp.description')}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {lldpQuery.isError ? (
            <ErrorState
              message={getApiErrorMessage(
                lldpQuery.error,
                t('MikroTikTopologyTab.lldp.loadError'),
              )}
              onRetry={() => lldpQuery.refetch()}
            />
          ) : lldp.length === 0 ? (
            <EmptyState
              variant="compact"
              title={t('MikroTikTopologyTab.lldp.empty.title')}
              description={t('MikroTikTopologyTab.lldp.empty.description')}
            />
          ) : (
            <div className="border rounded-md overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>{t('MikroTikTopologyTab.lldp.columns.interface')}</TableHead>
                    <TableHead>{t('MikroTikTopologyTab.lldp.columns.systemName')}</TableHead>
                    <TableHead>{t('MikroTikTopologyTab.lldp.columns.portId')}</TableHead>
                    <TableHead>{t('MikroTikTopologyTab.lldp.columns.mgmtAddress')}</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {lldp.map((row: MikroTikLldpInterface) => (
                    <TableRow key={row['.id'] ?? asStr(row.interface)}>
                      <TableCell className="font-mono text-xs">
                        {asStr(row.interface)}
                      </TableCell>
                      <TableCell className="font-mono text-xs">
                        {asStr(row['system-name'])}
                      </TableCell>
                      <TableCell className="font-mono text-xs">
                        {asStr(row['port-id'])}
                      </TableCell>
                      <TableCell className="font-mono text-xs">
                        {asStr(row['management-address'])}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Discovery settings dialog */}
      <Dialog
        open={settingsDialogOpen}
        onOpenChange={(open) => {
          if (!open) setSettingsDialogOpen(false);
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t('MikroTikTopologyTab.dialog.title')}</DialogTitle>
            <DialogDescription>
              {t('MikroTikTopologyTab.dialog.description')}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            <div className="space-y-2">
              <Label htmlFor="mtk-disc-protocol">{t('MikroTikTopologyTab.dialog.protocolLabel')}</Label>
              <Input
                id="mtk-disc-protocol"
                value={protocolForm}
                onChange={(e) => setProtocolForm(e.target.value)}
                placeholder="lldp,cdp,mndp"
              />
              <p className="text-xs text-muted-foreground">
                {t('MikroTikTopologyTab.dialog.protocolHelp')}
              </p>
            </div>
            <div className="space-y-2">
              <Label htmlFor="mtk-disc-scope">{t('MikroTikTopologyTab.dialog.scopeLabel')}</Label>
              <Input
                id="mtk-disc-scope"
                value={scopeForm}
                onChange={(e) => setScopeForm(e.target.value)}
                placeholder="all | LAN | trusted-discovery"
              />
              <p className="text-xs text-muted-foreground">
                {t('MikroTikTopologyTab.dialog.scopeHelp')}
              </p>
            </div>
          </div>
          <Badge variant="secondary">
            {t('MikroTikTopologyTab.dialog.badge')}
          </Badge>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setSettingsDialogOpen(false)}
            >
              {t('MikroTikTopologyTab.dialog.cancel')}
            </Button>
            <Button
              onClick={submitSettings}
              disabled={updateSettingsMut.isPending}
            >
              {updateSettingsMut.isPending && (
                <Loader2 className="h-4 w-4 animate-spin mr-1" />
              )}
              {t('MikroTikTopologyTab.dialog.submit')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

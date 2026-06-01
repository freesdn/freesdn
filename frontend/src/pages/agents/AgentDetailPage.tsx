// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * AgentDetailPage, per-agent drilldown at /agents/{id}.
 *
 * Surfaces everything we know about ONE agent in tabs:
 * - Overview (header card + agent metadata)
 * - Schedules (pinned + site-wide)
 * - Runs (cross-schedule, newest first)
 * - Discoveries (DiscoveredHost rows this agent contributed)
 * - Topology (LLDP/CDP edges this agent observed)
 *
 * Pairs with the AgentsPage fleet view: fleet shows aggregates,
 * detail shows the per-agent contribution to those aggregates.
 */

import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useParams, Link } from 'react-router-dom';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  Bot,
  Activity,
  Clock,
  Server,
  CheckCircle2,
  XCircle,
  ExternalLink,
  ArrowLeft,
  Wifi,
  WifiOff,
} from 'lucide-react';
import { PageHeader } from '@/components/layout';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog';
import { Bell, AlertTriangle } from 'lucide-react';
import { useToast } from '@/hooks/use-toast';
import { StatsGrid } from '@/components/ui/stats-grid';
import { ErrorState } from '@/components/ui/empty-state';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import {
  agentsApi,
  agentDetailApi,
  type AgentRunRow,
  type AgentDiscoveryRow,
  type AgentTopologyRow,
  type AgentScheduleRowDetail,
} from '@/lib/api/agents';
import { RunScanDialog } from '@/components/agent/RunScanDialog';
import { AdHocScansPanel } from '@/components/agent/AdHocScansPanel';
import { AgentSettingsPanel } from '@/components/agent/AgentSettingsPanel';

type TFn = (key: string, options?: Record<string, unknown>) => string;

function _formatRelative(iso: string | null, t: TFn): string {
  if (!iso) return t('AgentDetailPage.relative.never');
  const ms = Date.now() - new Date(iso).getTime();
  if (ms < 0) return new Date(iso).toLocaleString();
  const s = Math.floor(ms / 1000);
  if (s < 60) return t('AgentDetailPage.relative.secondsAgo', { n: s });
  const m = Math.floor(s / 60);
  if (m < 60) return t('AgentDetailPage.relative.minutesAgo', { n: m });
  const h = Math.floor(m / 60);
  if (h < 24) return t('AgentDetailPage.relative.hoursAgo', { n: h });
  const d = Math.floor(h / 24);
  return t('AgentDetailPage.relative.daysAgo', { n: d });
}

export function AgentDetailPage() {
  const { t } = useTranslation('agents');
  const { id: agentId } = useParams<{ id: string }>();
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [alertDialogOpen, setAlertDialogOpen] = useState(false);
  const [alertEmails, setAlertEmails] = useState('');
  const [alertSlack, setAlertSlack] = useState('');
  const [alertThreshold, setAlertThreshold] = useState(180);

  const {
    data: agent,
    isLoading: agentLoading,
    isError: agentError,
    error: agentErrorObj,
    refetch: refetchAgent,
  } = useQuery({
    queryKey: ['agent-detail', agentId],
    queryFn: async () => {
      const resp = await agentsApi.get(agentId!);
      return resp.data;
    },
    enabled: !!agentId,
  });

  const alertMutation = useMutation({
    mutationFn: async () => {
      const channels: Record<string, unknown> = {};
      const emails = alertEmails.split(/[,;]/).map((s) => s.trim()).filter(Boolean);
      if (emails.length > 0) channels.email = { to: emails };
      if (alertSlack.trim()) channels.slack = { channel: alertSlack.trim() };
      return agentsApi.update(agentId!, {
        notification_channels: channels,
        offline_threshold_seconds: Math.max(60, alertThreshold || 180),
      } as any);
    },
    onSuccess: () => {
      toast({ title: t('AgentDetailPage.toast.alertConfigSaved') });
      setAlertDialogOpen(false);
      queryClient.invalidateQueries({ queryKey: ['agent-detail', agentId] });
    },
    onError: (err: any) => {
      toast({
        title: t('AgentDetailPage.toast.saveFailed'),
        description: err?.response?.data?.detail || String(err),
        variant: 'destructive',
      });
    },
  });

  const { data: schedules = [] } = useQuery({
    queryKey: ['agent-schedules-detail', agentId],
    queryFn: async () => (await agentDetailApi.schedules(agentId!)).data,
    enabled: !!agentId,
  });

  const { data: runs = [] } = useQuery({
    queryKey: ['agent-runs', agentId],
    queryFn: async () => (await agentDetailApi.runs(agentId!, 50)).data,
    enabled: !!agentId,
    refetchInterval: 30_000,
  });

  const { data: discoveries = [] } = useQuery({
    queryKey: ['agent-discoveries', agentId],
    queryFn: async () => (await agentDetailApi.discoveries(agentId!, 100)).data,
    enabled: !!agentId,
  });

  const { data: topology = [] } = useQuery({
    queryKey: ['agent-topology', agentId],
    queryFn: async () => (await agentDetailApi.topology(agentId!, 200)).data,
    enabled: !!agentId,
  });

  if (!agentId) {
    return <div className="p-6">{t('AgentDetailPage.errors.noAgentId')}</div>;
  }
  if (agentLoading) {
    return (
      <div className="p-6 text-sm text-muted-foreground">
        {t('AgentDetailPage.loading')}
      </div>
    );
  }
  // A real 404 means the agent doesn't exist → show the "not found" copy.
  // Any other failure (network, 500, 403) is a load error → ErrorState + retry.
  if (agentError && (agentErrorObj as any)?.response?.status !== 404) {
    return (
      <div className="p-6">
        <ErrorState onRetry={() => refetchAgent()} />
      </div>
    );
  }
  if (!agent) {
    return (
      <div className="p-6 text-sm text-destructive">
        {t('AgentDetailPage.errors.notFound')}
      </div>
    );
  }

  const isOnline = agent.status === 'online';
  const failedRuns24h = runs.filter(
    (r: AgentRunRow) =>
      r.status === 'failed' &&
      Date.now() - new Date(r.started_at).getTime() < 24 * 60 * 60 * 1000,
  ).length;
  const completedRuns24h = runs.filter(
    (r: AgentRunRow) =>
      r.status === 'completed' &&
      Date.now() - new Date(r.started_at).getTime() < 24 * 60 * 60 * 1000,
  ).length;

  return (
    <div className="space-y-6">
      <Link
        to="/agents"
        className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground"
      >
        <ArrowLeft className="h-3.5 w-3.5" />
        {t('AgentDetailPage.backToAgents')}
      </Link>

      <PageHeader
        title={agent.name}
        description={agent.description || t('AgentDetailPage.defaultDescription')}
        icon={Bot}
      />

      {(agent as any).offline_notified_at && !isOnline ? (
        <Card className="border-destructive bg-destructive/5">
          <CardContent className="p-4 flex items-center gap-3 text-sm">
            <AlertTriangle className="h-5 w-5 text-destructive flex-shrink-0" />
            <div>
              <div className="font-medium">
                {t('AgentDetailPage.offlineAlert.title')}
              </div>
              <div className="text-xs text-muted-foreground">
                {t('AgentDetailPage.offlineAlert.body', {
                  when: new Date(
                    (agent as any).offline_notified_at,
                  ).toLocaleString(),
                })}
              </div>
            </div>
          </CardContent>
        </Card>
      ) : null}

      <StatsGrid
        columns={4}
        stats={[
          {
            title: t('AgentDetailPage.stats.status'),
            value: agent.status,
            icon: isOnline ? Wifi : WifiOff,
            variant: isOnline ? 'success' : 'warning',
            description: isOnline
              ? t('AgentDetailPage.stats.connected')
              : t('AgentDetailPage.stats.disconnected'),
          },
          {
            title: t('AgentDetailPage.stats.schedules'),
            value: schedules.length,
            icon: Clock,
            variant: 'default',
            description: t('AgentDetailPage.stats.pinnedCount', {
              n: schedules.filter((s) => s.is_pinned).length,
            }),
          },
          {
            title: t('AgentDetailPage.stats.runs24h'),
            value: completedRuns24h + failedRuns24h,
            icon: Activity,
            variant: failedRuns24h > 0 ? 'warning' : 'success',
            description:
              failedRuns24h > 0
                ? t('AgentDetailPage.stats.failedCount', { n: failedRuns24h })
                : t('AgentDetailPage.stats.allSucceeded'),
          },
          {
            title: t('AgentDetailPage.stats.discoveries'),
            value: discoveries.length,
            icon: Server,
            variant: 'default',
            description: t('AgentDetailPage.stats.adoptedCount', {
              n: discoveries.filter((d) => d.is_adopted).length,
            }),
          },
        ]}
      />

      <Tabs defaultValue="overview">
        <TabsList>
          <TabsTrigger value="overview">{t('AgentDetailPage.tabs.overview')}</TabsTrigger>
          <TabsTrigger value="schedules">
            {t('AgentDetailPage.tabs.schedules')}
            {schedules.length > 0 ? (
              <Badge variant="secondary" className="ml-1.5">
                {schedules.length}
              </Badge>
            ) : null}
          </TabsTrigger>
          <TabsTrigger value="runs">
            {t('AgentDetailPage.tabs.runs')}
            {runs.length > 0 ? (
              <Badge variant="secondary" className="ml-1.5">
                {runs.length}
              </Badge>
            ) : null}
          </TabsTrigger>
          <TabsTrigger value="discoveries">
            {t('AgentDetailPage.tabs.discoveries')}
            {discoveries.length > 0 ? (
              <Badge variant="secondary" className="ml-1.5">
                {discoveries.length}
              </Badge>
            ) : null}
          </TabsTrigger>
          <TabsTrigger value="topology">
            {t('AgentDetailPage.tabs.topology')}
            {topology.length > 0 ? (
              <Badge variant="secondary" className="ml-1.5">
                {topology.length}
              </Badge>
            ) : null}
          </TabsTrigger>
          <TabsTrigger value="ad-hoc">{t('AgentDetailPage.tabs.adHoc')}</TabsTrigger>
          <TabsTrigger value="settings">{t('AgentDetailPage.tabs.settings')}</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="mt-4 space-y-4">
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <CardTitle>{t('AgentDetailPage.details.title')}</CardTitle>
                <div className="flex items-center gap-2">
                  <RunScanDialog
                    agentId={agent.id}
                    agentName={agent.name}
                    agentStatus={agent.status}
                    supportedScanTypes={
                      ((agent.capabilities as any)?.scan_types as
                        | string[]
                        | undefined) ?? undefined
                    }
                    onScanComplete={() => {
                      queryClient.invalidateQueries({
                        queryKey: ['agent-discoveries', agentId],
                      });
                      queryClient.invalidateQueries({
                        queryKey: ['agent-runs', agentId],
                      });
                    }}
                  />
                <Dialog
                  open={alertDialogOpen}
                  onOpenChange={(o) => {
                    setAlertDialogOpen(o);
                    if (o && agent) {
                      // Prefill from current config
                      const ch: any = (agent as any).notification_channels || {};
                      setAlertEmails((ch.email?.to || []).join(', '));
                      setAlertSlack(ch.slack?.channel || '');
                      setAlertThreshold((agent as any).offline_threshold_seconds || 180);
                    }
                  }}
                >
                  <DialogTrigger asChild>
                    <Button variant="outline" size="sm">
                      <Bell className="h-4 w-4 mr-1" />
                      {t('AgentDetailPage.alertsDialog.trigger')}
                    </Button>
                  </DialogTrigger>
                  <DialogContent>
                    <DialogHeader>
                      <DialogTitle>
                        {t('AgentDetailPage.alertsDialog.title', {
                          name: agent?.name,
                        })}
                      </DialogTitle>
                    </DialogHeader>
                    <div className="space-y-3 pt-2">
                      <div className="text-xs text-muted-foreground">
                        {t('AgentDetailPage.alertsDialog.description')}
                      </div>
                      <div>
                        <Label>{t('AgentDetailPage.alertsDialog.emailLabel')}</Label>
                        <Input
                          placeholder="ops@example.com"
                          value={alertEmails}
                          onChange={(e) => setAlertEmails(e.target.value)}
                        />
                      </div>
                      <div>
                        <Label>{t('AgentDetailPage.alertsDialog.slackLabel')}</Label>
                        <Input
                          placeholder="#alerts"
                          value={alertSlack}
                          onChange={(e) => setAlertSlack(e.target.value)}
                        />
                      </div>
                      <div>
                        <Label>
                          {t('AgentDetailPage.alertsDialog.thresholdLabel')}
                        </Label>
                        <Input
                          type="number"
                          min={60}
                          value={alertThreshold}
                          onChange={(e) =>
                            setAlertThreshold(parseInt(e.target.value, 10) || 180)
                          }
                        />
                      </div>
                    </div>
                    <DialogFooter>
                      <Button variant="outline" onClick={() => setAlertDialogOpen(false)}>
                        {t('AgentDetailPage.alertsDialog.cancel')}
                      </Button>
                      <Button
                        onClick={() => alertMutation.mutate()}
                        disabled={alertMutation.isPending}
                      >
                        {t('AgentDetailPage.alertsDialog.save')}
                      </Button>
                    </DialogFooter>
                  </DialogContent>
                </Dialog>
                </div>
              </div>
            </CardHeader>
            <CardContent>
              <dl className="grid grid-cols-2 gap-x-6 gap-y-3 text-sm">
                <dt className="text-muted-foreground">{t('AgentDetailPage.details.id')}</dt>
                <dd className="font-mono">{agent.id}</dd>
                <dt className="text-muted-foreground">{t('AgentDetailPage.details.type')}</dt>
                <dd>{agent.agent_type}</dd>
                <dt className="text-muted-foreground">{t('AgentDetailPage.details.version')}</dt>
                <dd>{agent.version || '-'}</dd>
                <dt className="text-muted-foreground">{t('AgentDetailPage.details.site')}</dt>
                <dd>
                  <Link
                    to={`/sites/${agent.site_id}`}
                    className="hover:underline text-sky-600"
                  >
                    {agent.site_id}
                  </Link>
                </dd>
                <dt className="text-muted-foreground">{t('AgentDetailPage.details.lastHeartbeat')}</dt>
                <dd>{_formatRelative(agent.last_heartbeat ?? null, t)}</dd>
                <dt className="text-muted-foreground">{t('AgentDetailPage.details.approved')}</dt>
                <dd>
                  {agent.is_approved
                    ? t('AgentDetailPage.details.yes')
                    : t('AgentDetailPage.details.no')}
                </dd>
              </dl>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="schedules" className="mt-4">
          <Card>
            <CardContent className="p-0">
              {schedules.length === 0 ? (
                <div className="p-6 text-sm text-muted-foreground">
                  {t('AgentDetailPage.schedules.empty')}
                </div>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>{t('AgentDetailPage.schedules.columns.name')}</TableHead>
                      <TableHead>{t('AgentDetailPage.schedules.columns.type')}</TableHead>
                      <TableHead>{t('AgentDetailPage.schedules.columns.cron')}</TableHead>
                      <TableHead>{t('AgentDetailPage.schedules.columns.targets')}</TableHead>
                      <TableHead>{t('AgentDetailPage.schedules.columns.lastFired')}</TableHead>
                      <TableHead>{t('AgentDetailPage.schedules.columns.status')}</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {schedules.map((s: AgentScheduleRowDetail) => (
                      <TableRow key={s.id}>
                        <TableCell className="font-medium">{s.name}</TableCell>
                        <TableCell>{s.scan_type}</TableCell>
                        <TableCell className="font-mono text-xs">{s.cron}</TableCell>
                        <TableCell className="text-xs">
                          {s.targets.join(', ') || '-'}
                        </TableCell>
                        <TableCell
                          className="text-xs text-muted-foreground"
                          title={
                            s.last_fired_at
                              ? new Date(s.last_fired_at).toLocaleString()
                              : ''
                          }
                        >
                          {_formatRelative(s.last_fired_at, t)}
                        </TableCell>
                        <TableCell>
                          {s.is_pinned ? (
                            <Badge variant="secondary" className="text-xs">
                              {t('AgentDetailPage.schedules.pinned')}
                            </Badge>
                          ) : (
                            <Badge variant="outline" className="text-xs">
                              {t('AgentDetailPage.schedules.siteWide')}
                            </Badge>
                          )}
                          {!s.enabled ? (
                            <Badge variant="outline" className="text-xs ml-1">
                              {t('AgentDetailPage.schedules.disabled')}
                            </Badge>
                          ) : null}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="runs" className="mt-4">
          <Card>
            <CardContent className="p-0">
              {runs.length === 0 ? (
                <div className="p-6 text-sm text-muted-foreground">
                  {t('AgentDetailPage.runs.empty')}
                </div>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>{t('AgentDetailPage.runs.columns.status')}</TableHead>
                      <TableHead>{t('AgentDetailPage.runs.columns.schedule')}</TableHead>
                      <TableHead>{t('AgentDetailPage.runs.columns.when')}</TableHead>
                      <TableHead>{t('AgentDetailPage.runs.columns.duration')}</TableHead>
                      <TableHead>{t('AgentDetailPage.runs.columns.devices')}</TableHead>
                      <TableHead>{t('AgentDetailPage.runs.columns.error')}</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {runs.map((r: AgentRunRow) => (
                      <TableRow key={r.id}>
                        <TableCell>
                          {r.status === 'completed' ? (
                            <CheckCircle2 className="h-4 w-4 text-emerald-600" />
                          ) : r.status === 'failed' ? (
                            <XCircle className="h-4 w-4 text-destructive" />
                          ) : (
                            <Badge variant="outline" className="text-xs">
                              {r.status}
                            </Badge>
                          )}
                        </TableCell>
                        <TableCell className="text-xs">
                          {r.schedule_name || '-'}
                        </TableCell>
                        <TableCell
                          className="text-xs text-muted-foreground"
                          title={new Date(r.started_at).toLocaleString()}
                        >
                          {_formatRelative(r.started_at, t)}
                        </TableCell>
                        <TableCell className="text-xs">
                          {r.duration_seconds != null
                            ? `${r.duration_seconds.toFixed(1)}s`
                            : '-'}
                        </TableCell>
                        <TableCell className="text-xs tabular-nums">
                          {r.device_count}
                        </TableCell>
                        <TableCell className="text-xs text-destructive max-w-[200px] truncate">
                          {r.error_message || ''}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="discoveries" className="mt-4">
          <Card>
            <CardContent className="p-0">
              {discoveries.length === 0 ? (
                <div className="p-6 text-sm text-muted-foreground">
                  {t('AgentDetailPage.discoveries.empty')}
                </div>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>{t('AgentDetailPage.discoveries.columns.ip')}</TableHead>
                      <TableHead>{t('AgentDetailPage.discoveries.columns.mac')}</TableHead>
                      <TableHead>{t('AgentDetailPage.discoveries.columns.vendor')}</TableHead>
                      <TableHead>{t('AgentDetailPage.discoveries.columns.hostname')}</TableHead>
                      <TableHead>{t('AgentDetailPage.discoveries.columns.lastSeen')}</TableHead>
                      <TableHead>{t('AgentDetailPage.discoveries.columns.status')}</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {discoveries.map((d: AgentDiscoveryRow) => (
                      <TableRow key={d.id}>
                        <TableCell className="font-mono text-xs">
                          {d.ip_address}
                        </TableCell>
                        <TableCell className="font-mono text-xs">
                          {d.mac_address || '-'}
                        </TableCell>
                        <TableCell className="text-xs">
                          {d.vendor || '-'}
                        </TableCell>
                        <TableCell className="text-xs">
                          {d.hostname || '-'}
                        </TableCell>
                        <TableCell
                          className="text-xs text-muted-foreground"
                          title={
                            d.last_seen
                              ? new Date(d.last_seen).toLocaleString()
                              : ''
                          }
                        >
                          {_formatRelative(d.last_seen, t)}
                        </TableCell>
                        <TableCell>
                          {d.is_adopted && d.adopted_device_id ? (
                            <Link
                              to={`/devices/${d.adopted_device_id}`}
                              className="text-emerald-600 hover:underline text-xs flex items-center gap-1"
                            >
                              <CheckCircle2 className="h-3 w-3" />
                              {t('AgentDetailPage.discoveries.adopted')}
                              <ExternalLink className="h-3 w-3" />
                            </Link>
                          ) : (
                            <Badge variant="outline" className="text-xs">
                              {t('AgentDetailPage.discoveries.new')}
                            </Badge>
                          )}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="topology" className="mt-4">
          <Card>
            <CardContent className="p-0">
              {topology.length === 0 ? (
                <div className="p-6 text-sm text-muted-foreground">
                  {t('AgentDetailPage.topology.empty')}
                </div>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>{t('AgentDetailPage.topology.columns.protocol')}</TableHead>
                      <TableHead>{t('AgentDetailPage.topology.columns.localInterface')}</TableHead>
                      <TableHead>{t('AgentDetailPage.topology.columns.neighborChassis')}</TableHead>
                      <TableHead>{t('AgentDetailPage.topology.columns.neighborPort')}</TableHead>
                      <TableHead>{t('AgentDetailPage.topology.columns.system')}</TableHead>
                      <TableHead>{t('AgentDetailPage.topology.columns.vlan')}</TableHead>
                      <TableHead>{t('AgentDetailPage.topology.columns.lastSeen')}</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {topology.map((e: AgentTopologyRow) => (
                      <TableRow key={e.id}>
                        <TableCell>
                          <Badge variant="outline" className="text-xs">
                            {e.protocol}
                          </Badge>
                        </TableCell>
                        <TableCell className="font-mono text-xs">
                          {e.local_interface}
                        </TableCell>
                        <TableCell className="font-mono text-xs">
                          {e.neighbor_chassis_id}
                        </TableCell>
                        <TableCell className="font-mono text-xs">
                          {e.neighbor_port_id}
                        </TableCell>
                        <TableCell className="text-xs">
                          {e.neighbor_system_name || '-'}
                        </TableCell>
                        <TableCell className="text-xs tabular-nums">
                          {e.vlan_id ?? '-'}
                        </TableCell>
                        <TableCell
                          className="text-xs text-muted-foreground"
                          title={
                            e.last_seen
                              ? new Date(e.last_seen).toLocaleString()
                              : ''
                          }
                        >
                          {_formatRelative(e.last_seen, t)}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="ad-hoc" className="mt-4">
          <AdHocScansPanel agentId={agent.id} />
        </TabsContent>

        <TabsContent value="settings" className="mt-4">
          <AgentSettingsPanel agent={agent} />
        </TabsContent>
      </Tabs>
    </div>
  );
}

export default AgentDetailPage;

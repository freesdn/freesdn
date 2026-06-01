// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN · Remote Agents Page
 *
 * Canonical list-page pattern.
 */
/* eslint-disable @typescript-eslint/no-explicit-any */

import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { z } from 'zod';
import { useSiteStore } from '@/stores/siteStore';
import {
  Server,
  Plus,
  Wifi,
  WifiOff,
  Trash2,
  AlertTriangle,
  CheckCircle,
  Copy,
  Eye,
  EyeOff,
  ShieldCheck,
  ShieldOff,
  Download,
  MoreHorizontal,
  Play,
} from 'lucide-react';
import { PageHeader, PageToolbar } from '@/components/layout';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { DataTable, type DataTableColumn } from '@/components/ui/data-table';
import { SearchBar } from '@/components/ui/search-bar';
import { StatsGrid } from '@/components/ui/stats-grid';
import { StatusBadge, type StatusVariant } from '@/components/ui/status-indicator';
import { BulkActionsBar } from '@/components/ui/bulk-actions-bar';
import { ErrorState } from '@/components/ui/empty-state';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { FormDialog } from '@/components/ui/form-dialog';
import { FormControl, FormField, FormItem, FormLabel, FormMessage } from '@/components/ui/form';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import {
  agentsApi,
  sitesApiV2,
  type AgentSummary,
  type Site,
} from '@/lib/api';
import { agentFleetApi } from '@/lib/api/agents';
import { FleetActivityPanel } from '@/components/agent/FleetActivityPanel';
import { useToast } from '@/hooks/use-toast';

const AGENT_STATUS_VARIANT: Record<string, StatusVariant> = {
  online: 'connected',
  offline: 'disconnected',
  connecting: 'syncing',
  error: 'error',
  maintenance: 'updating',
};

// Maps agent_type → i18n key suffix under AgentsPage.agentTypes.*
// (module-level: translated at the render/use site, not here).
const agentTypeLabelKeys: Record<string, string> = {
  site: 'site',
  scanner: 'scanner',
  collector: 'collector',
  gateway: 'gateway',
};

// ─── Register Agent Dialog ─────────────────────────────────────────────

type TFunc = (key: string, options?: Record<string, unknown>) => string;

const buildRegisterSchema = (t: TFunc) =>
  z.object({
    site_id: z.string().min(1, t('AgentsPage.register.validation.siteRequired')),
    name: z.string().min(1, t('AgentsPage.register.validation.nameRequired')),
    agent_type: z.enum(['site', 'scanner', 'collector', 'gateway']),
    description: z.string(),
  });
type RegisterFormValues = z.infer<ReturnType<typeof buildRegisterSchema>>;

function RegisterAgentDialog({
  open,
  onOpenChange,
  sites,
  defaultSiteId,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  sites: Site[];
  defaultSiteId?: string | null;
}) {
  const { t } = useTranslation('agents');
  const queryClient = useQueryClient();
  const registerSchema = buildRegisterSchema(t);
  const [showApiKey, setShowApiKey] = useState(false);
  const [registrationResult, setRegistrationResult] = useState<{
    agent_id: string;
    agent_key: string;
    websocket_url: string;
    instructions: string;
  } | null>(null);

  const registerMutation = useMutation({
    mutationFn: async (values: RegisterFormValues) => {
      const response = await agentsApi.register({
        site_id: values.site_id,
        name: values.name,
        description: values.description || undefined,
        agent_type: values.agent_type,
      });
      return response.data;
    },
    onSuccess: (data) => {
      setRegistrationResult(data);
      queryClient.invalidateQueries({ queryKey: ['agents'] });
      queryClient.invalidateQueries({ queryKey: ['agent-stats'] });
    },
  });

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  const handleClose = () => {
    setRegistrationResult(null);
    setShowApiKey(false);
    onOpenChange(false);
  };

  // Once registration succeeds, swap to a read-only result Dialog so users
  // can copy the credentials. Form mode uses FormDialog.
  if (registrationResult) {
    return (
      <Dialog open={open} onOpenChange={handleClose}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>{t('AgentsPage.register.title')}</DialogTitle>
            <DialogDescription>
              {t('AgentsPage.register.description')}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-4">
            <Alert variant="default" className="bg-success/10 border-success/20">
              <CheckCircle className="h-4 w-4 text-success" />
              <AlertTitle className="text-success">{t('AgentsPage.register.success.title')}</AlertTitle>
              <AlertDescription>
                {t('AgentsPage.register.success.description')}
              </AlertDescription>
            </Alert>

            <div className="space-y-4">
              <div className="space-y-2">
                <label className="text-sm font-medium text-muted-foreground">{t('AgentsPage.register.fields.agentId')}</label>
                <div className="flex gap-2">
                  <Input value={registrationResult.agent_id} readOnly className="font-mono text-sm" />
                  <Button variant="outline" size="icon" onClick={() => copyToClipboard(registrationResult.agent_id)}>
                    <Copy className="h-4 w-4" />
                  </Button>
                </div>
              </div>

              <div className="space-y-2">
                <label className="text-sm font-medium text-muted-foreground">{t('AgentsPage.register.fields.agentKey')}</label>
                <div className="flex gap-2">
                  <Input
                    type={showApiKey ? 'text' : 'password'}
                    value={registrationResult.agent_key}
                    readOnly
                    className="font-mono text-sm"
                  />
                  <Button variant="outline" size="icon" onClick={() => setShowApiKey(!showApiKey)}>
                    {showApiKey ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                  </Button>
                  <Button variant="outline" size="icon" onClick={() => copyToClipboard(registrationResult.agent_key)}>
                    <Copy className="h-4 w-4" />
                  </Button>
                </div>
              </div>

              <div className="space-y-2">
                <label className="text-sm font-medium text-muted-foreground">{t('AgentsPage.register.fields.websocketUrl')}</label>
                <div className="flex gap-2">
                  <Input value={registrationResult.websocket_url} readOnly className="font-mono text-sm" />
                  <Button variant="outline" size="icon" onClick={() => copyToClipboard(registrationResult.websocket_url)}>
                    <Copy className="h-4 w-4" />
                  </Button>
                </div>
              </div>

              <div className="p-4 bg-muted/50 rounded-lg">
                <label className="text-sm font-medium">{t('AgentsPage.register.fields.envVars')}</label>
                <pre className="mt-2 text-xs font-mono whitespace-pre-wrap">
{`FREESDN_AGENT_ID=${registrationResult.agent_id}
FREESDN_AGENT_KEY=${registrationResult.agent_key}
FREESDN_SERVER_URL=${registrationResult.websocket_url}`}
                </pre>
                <Button
                  variant="outline"
                  size="sm"
                  className="mt-2"
                  onClick={() => copyToClipboard(`FREESDN_AGENT_ID=${registrationResult.agent_id}\nFREESDN_AGENT_KEY=${registrationResult.agent_key}\nFREESDN_SERVER_URL=${registrationResult.websocket_url}`)}
                >
                  <Copy className="mr-2 h-3 w-3" />
                  {t('AgentsPage.register.copyAll')}
                </Button>
              </div>
            </div>

            <DialogFooter>
              <Button onClick={handleClose}>{t('AgentsPage.register.done')}</Button>
            </DialogFooter>
          </div>
        </DialogContent>
      </Dialog>
    );
  }

  return (
    <FormDialog<RegisterFormValues>
      open={open}
      onOpenChange={handleClose}
      title={t('AgentsPage.register.title')}
      description={t('AgentsPage.register.description')}
      schema={registerSchema}
      defaultValues={{
        site_id: defaultSiteId ?? '',
        name: '',
        agent_type: 'site',
        description: '',
      }}
      submitLabel={registerMutation.isPending ? t('AgentsPage.register.submitting') : t('AgentsPage.register.submit')}
      contentClassName="max-w-2xl"
      onSubmit={async (values) => {
        await registerMutation.mutateAsync(values);
      }}
    >
      {(form) => (
        <>
          <FormField
            control={form.control}
            name="site_id"
            render={({ field }) => (
              <FormItem>
                <FormLabel>{t('AgentsPage.register.fields.site')}</FormLabel>
                <Select value={field.value} onValueChange={field.onChange}>
                  <FormControl>
                    <SelectTrigger>
                      <SelectValue placeholder={t('AgentsPage.register.fields.sitePlaceholder')} />
                    </SelectTrigger>
                  </FormControl>
                  <SelectContent>
                    {sites.map((site) => (
                      <SelectItem key={site.id} value={site.id}>
                        {site.name}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <FormMessage />
              </FormItem>
            )}
          />
          <FormField
            control={form.control}
            name="name"
            render={({ field }) => (
              <FormItem>
                <FormLabel>{t('AgentsPage.register.fields.name')}</FormLabel>
                <FormControl>
                  <Input placeholder={t('AgentsPage.register.fields.namePlaceholder')} {...field} />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
          <FormField
            control={form.control}
            name="agent_type"
            render={({ field }) => (
              <FormItem>
                <FormLabel>{t('AgentsPage.register.fields.agentType')}</FormLabel>
                <Select value={field.value} onValueChange={field.onChange}>
                  <FormControl>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                  </FormControl>
                  <SelectContent>
                    <SelectItem value="site">{t('AgentsPage.agentTypes.site')}</SelectItem>
                    <SelectItem value="scanner">{t('AgentsPage.agentTypes.scanner')}</SelectItem>
                    <SelectItem value="collector">{t('AgentsPage.agentTypes.collector')}</SelectItem>
                    <SelectItem value="gateway">{t('AgentsPage.agentTypes.gateway')}</SelectItem>
                  </SelectContent>
                </Select>
                <FormMessage />
              </FormItem>
            )}
          />
          <FormField
            control={form.control}
            name="description"
            render={({ field }) => (
              <FormItem>
                <FormLabel>{t('AgentsPage.register.fields.descriptionLabel')}</FormLabel>
                <FormControl>
                  <Input placeholder={t('AgentsPage.register.fields.descriptionPlaceholder')} {...field} />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
        </>
      )}
    </FormDialog>
  );
}

// ─── Page ──────────────────────────────────────────────────────────────

export default function AgentsPage() {
  const { t } = useTranslation('agents');
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const selectedSiteId = useSiteStore((s) => s.selectedSiteId);
  const [registerDialogOpen, setRegisterDialogOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [typeFilter, setTypeFilter] = useState<string>('all');
  const [selectedAgents, setSelectedAgents] = useState<AgentSummary[]>([]);

  // Fetch agents
  const {
    data: agentsData,
    isLoading,
    error,
    refetch,
  } = useQuery({
    queryKey: ['agents', selectedSiteId, statusFilter, typeFilter],
    queryFn: async () => {
      const params: Record<string, any> = { page: 1, per_page: 200 };
      if (selectedSiteId) params.site_id = selectedSiteId;
      if (statusFilter !== 'all') params.status = statusFilter;
      if (typeFilter !== 'all') params.agent_type = typeFilter;
      const response = await agentsApi.list(params);
      return response.data;
    },
    refetchInterval: 30000,
  });

  // Stats, org-wide. The /agents/stats endpoint is organization-scoped and
  // ignores site_id, so the query key must NOT include selectedSiteId
  // (keying on it would cache a per-site copy of identical org-wide numbers).
  const { data: stats } = useQuery({
    queryKey: ['agent-stats'],
    queryFn: async () => {
      const response = await agentsApi.stats();
      return response.data;
    },
    refetchInterval: 30000,
  });

  // Fleet activity overview (schedules, runs 24h, discoveries)
  const { data: fleet } = useQuery({
    queryKey: ['agent-fleet-overview'],
    queryFn: async () => {
      const response = await agentFleetApi.overview();
      return response.data;
    },
    refetchInterval: 30000,
  });

  // Sites for registration
  const { data: sitesData } = useQuery({
    queryKey: ['sites'],
    queryFn: async () => {
      const response = await sitesApiV2.list();
      return response.data;
    },
  });
  const sites = sitesData?.items || [];

  // Mutations
  const approveMutation = useMutation({
    mutationFn: (agentId: string) => agentsApi.approve(agentId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['agents'] });
      queryClient.invalidateQueries({ queryKey: ['agent-stats'] });
    },
    onError: (err: any) => {
      toast({ title: t('AgentsPage.toasts.approveFailed.title'), description: err?.response?.data?.detail || t('AgentsPage.toasts.approveFailed.description'), variant: 'destructive' });
    },
  });

  const disconnectMutation = useMutation({
    mutationFn: (agentId: string) => agentsApi.disconnect(agentId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['agents'] });
      queryClient.invalidateQueries({ queryKey: ['agent-stats'] });
    },
    onError: (err: any) => {
      toast({ title: t('AgentsPage.toasts.disconnectFailed.title'), description: err?.response?.data?.detail || t('AgentsPage.toasts.disconnectFailed.description'), variant: 'destructive' });
    },
  });

  const allAgents: AgentSummary[] = agentsData?.items || [];

  // Apply local search filter
  const agents = allAgents.filter((agent) => {
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      const matches =
        agent.name.toLowerCase().includes(q) ||
        (agent.last_ip ?? '').toLowerCase().includes(q) ||
        (agent.site_name ?? '').toLowerCase().includes(q);
      if (!matches) return false;
    }
    return true;
  });

  const hasActiveFilters = searchQuery !== '' || statusFilter !== 'all' || typeFilter !== 'all';
  const handleClearFilters = () => {
    setSearchQuery('');
    setStatusFilter('all');
    setTypeFilter('all');
  };

  // Client-side CSV export of the rows already loaded (respects the active
  // search/status/type filters). No backend round-trip.
  const handleExport = () => {
    const headers = ['id', 'name', 'agent_type', 'status', 'is_approved', 'site_name', 'last_ip', 'last_heartbeat'];
    const escape = (v: unknown) => {
      const s = v == null ? '' : String(v);
      return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
    };
    const rows = agents.map((a) => [
      a.id,
      a.name,
      a.agent_type,
      a.status,
      a.is_approved,
      a.site_name ?? '',
      a.last_ip ?? '',
      a.last_heartbeat ?? '',
    ]);
    const csv = [headers, ...rows].map((r) => r.map(escape).join(',')).join('\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `agents-${new Date().toISOString().slice(0, 10)}.csv`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  // Columns
  const columns: DataTableColumn<AgentSummary>[] = [
    {
      id: 'name',
      header: t('AgentsPage.columns.agent'),
      accessorKey: 'name',
      cell: (agent) => {
        const isOnline = agent.status === 'online';
        return (
          <div className="flex items-center gap-3 min-w-0">
            <div
              className={`flex h-9 w-9 items-center justify-center rounded-lg flex-shrink-0 ${
                isOnline ? 'bg-success/10' : 'bg-muted'
              }`}
            >
              <Server className={`h-4 w-4 ${isOnline ? 'text-success' : 'text-muted-foreground'}`} />
            </div>
            <div className="min-w-0">
              <Link
                to={`/agents/${agent.id}`}
                className="font-medium truncate hover:underline"
              >
                {agent.name}
              </Link>
              <div className="text-xs text-muted-foreground font-mono truncate">
                {agent.id.slice(0, 8)}…
              </div>
            </div>
          </div>
        );
      },
    },
    {
      id: 'type',
      header: t('AgentsPage.columns.type'),
      accessorKey: 'agent_type',
      cell: (agent) => (
        <span className="text-sm">
          {agentTypeLabelKeys[agent.agent_type]
            ? t(`AgentsPage.agentTypes.${agentTypeLabelKeys[agent.agent_type]}`)
            : agent.agent_type}
        </span>
      ),
    },
    {
      id: 'status',
      header: t('AgentsPage.columns.status'),
      accessorKey: 'status',
      cell: (agent) => (
        <div className="flex flex-col gap-1">
          <StatusBadge variant={AGENT_STATUS_VARIANT[agent.status] ?? 'unknown'}>
            {AGENT_STATUS_VARIANT[agent.status]
              ? t(`AgentsPage.status.${agent.status}`)
              : agent.status}
          </StatusBadge>
          {!agent.is_approved && (
            <StatusBadge variant="warning" hideIcon size="sm">
              {t('AgentsPage.status.pendingApproval')}
            </StatusBadge>
          )}
        </div>
      ),
    },
    {
      id: 'site',
      header: t('AgentsPage.columns.site'),
      accessorFn: (a) => a.site_name ?? '',
      cell: (agent) => (
        <span className="text-sm text-muted-foreground">{agent.site_name || '-'}</span>
      ),
    },
    {
      id: 'ip',
      header: t('AgentsPage.columns.lastIp'),
      accessorFn: (a) => a.last_ip ?? '',
      cell: (agent) => (
        <span className="text-sm font-mono text-muted-foreground">{agent.last_ip || '-'}</span>
      ),
    },
    {
      id: 'heartbeat',
      header: t('AgentsPage.columns.lastHeartbeat'),
      accessorFn: (a) => a.last_heartbeat ?? '',
      cell: (agent) => (
        <span className="text-xs text-muted-foreground">
          {agent.last_heartbeat ? new Date(agent.last_heartbeat).toLocaleString() : t('AgentsPage.never')}
        </span>
      ),
    },
    {
      id: 'actions',
      header: '',
      sortable: false,
      cell: (agent) => (
        <div className="flex justify-end" onClick={(e) => e.stopPropagation()}>
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" size="icon" className="h-8 w-8" aria-label={t('AgentsPage.actions.menuLabel', { name: agent.name })}>
                <MoreHorizontal className="h-4 w-4" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              {!agent.is_approved && (
                <DropdownMenuItem onClick={() => approveMutation.mutate(agent.id)}>
                  <ShieldCheck className="h-4 w-4 mr-2" />
                  {t('AgentsPage.actions.approveAgent')}
                </DropdownMenuItem>
              )}
              {agent.is_approved && agent.status === 'online' && (
                <DropdownMenuItem asChild>
                  <Link to={`/agents/${agent.id}`}>
                    <Play className="h-4 w-4 mr-2" />
                    {t('AgentsPage.actions.runScan')}
                  </Link>
                </DropdownMenuItem>
              )}
              <DropdownMenuSeparator />
              <DropdownMenuItem
                className="text-destructive focus:text-destructive"
                onClick={() => {
                  if (confirm(t('AgentsPage.actions.disconnectConfirm'))) {
                    disconnectMutation.mutate(agent.id);
                  }
                }}
              >
                <Trash2 className="h-4 w-4 mr-2" />
                {t('AgentsPage.actions.disconnect')}
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      ),
    },
  ];

  if (error) {
    return (
      <div className="space-y-6">
        <PageHeader
          title={t('AgentsPage.pageHeader.title')}
          description={t('AgentsPage.pageHeader.description')}
          icon={Server}
        />
        <ErrorState
          message={error instanceof Error ? error.message : t('AgentsPage.errors.loadFailed')}
          onRetry={() => refetch()}
        />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <PageHeader
        title={t('AgentsPage.pageHeader.title')}
        description={t('AgentsPage.pageHeader.description')}
        icon={Server}
        onRefresh={() => refetch()}
        refreshing={isLoading}
        secondaryActions={[
          { label: t('AgentsPage.actions.export'), icon: Download, onClick: handleExport },
        ]}
        primaryAction={{
          label: t('AgentsPage.actions.registerAgent'),
          icon: Plus,
          onClick: () => setRegisterDialogOpen(true),
        }}
      />

      {/* Stats, top row: agent connection state. These come from the
          org-scoped /agents/stats endpoint (site filter does not apply). */}
      <div className="text-xs font-medium text-muted-foreground">
        {t('common:allSites')}
      </div>
      <StatsGrid
        columns={4}
        isLoading={isLoading}
        stats={[
          {
            title: t('AgentsPage.stats.totalAgents.title'),
            value: stats?.total ?? 0,
            icon: Server,
            variant: 'default',
            description: t('AgentsPage.stats.totalAgents.description'),
          },
          {
            title: t('AgentsPage.stats.online.title'),
            value: stats?.online ?? 0,
            icon: Wifi,
            variant: 'success',
            description: t('AgentsPage.stats.online.description'),
          },
          {
            title: t('AgentsPage.stats.offline.title'),
            value: stats?.offline ?? 0,
            icon: WifiOff,
            variant: (stats?.offline ?? 0) > 0 ? 'warning' : 'default',
            description: t('AgentsPage.stats.offline.description'),
          },
          {
            title: t('AgentsPage.stats.pendingApproval.title'),
            value: stats?.pending_approval ?? 0,
            icon: ShieldOff,
            variant: (stats?.pending_approval ?? 0) > 0 ? 'warning' : 'default',
            description: t('AgentsPage.stats.pendingApproval.description'),
          },
        ]}
      />

      {/* Stats, second row: fleet activity (schedules, runs, discoveries) */}
      <StatsGrid
        columns={4}
        isLoading={!fleet}
        stats={[
          {
            title: t('AgentsPage.fleet.activeSchedules.title'),
            value: fleet?.schedules_enabled ?? 0,
            icon: Play,
            variant: 'default',
            description: t('AgentsPage.fleet.activeSchedules.description', { count: fleet?.schedules_total ?? 0 }),
          },
          {
            title: t('AgentsPage.fleet.runs24h.title'),
            value: fleet?.runs_24h ?? 0,
            icon: CheckCircle,
            variant: (fleet?.runs_24h_failed ?? 0) > 0 ? 'warning' : 'success',
            description:
              (fleet?.runs_24h_failed ?? 0) > 0
                ? t('AgentsPage.fleet.runs24h.failed', { count: fleet?.runs_24h_failed })
                : t('AgentsPage.fleet.runs24h.allSucceeded'),
          },
          {
            title: t('AgentsPage.fleet.discoveredHosts.title'),
            value: fleet?.discovered_hosts_total ?? 0,
            icon: Server,
            variant: 'default',
            description: t('AgentsPage.fleet.discoveredHosts.description', { count: fleet?.discovered_hosts_unadopted ?? 0 }),
          },
          {
            title: t('AgentsPage.fleet.lastRun.title'),
            value: fleet?.last_run_at
              ? new Date(fleet.last_run_at).toLocaleString([], {
                  month: 'short',
                  day: 'numeric',
                  hour: '2-digit',
                  minute: '2-digit',
                })
              : '-',
            icon: AlertTriangle,
            variant: 'default',
            description: fleet?.last_run_at ? t('AgentsPage.fleet.lastRun.mostRecent') : t('AgentsPage.fleet.lastRun.noRuns'),
          },
        ]}
      />

      {/* Toolbar */}
      <PageToolbar>
        <SearchBar
          value={searchQuery}
          onChange={setSearchQuery}
          placeholder={t('AgentsPage.toolbar.searchPlaceholder')}
          className="w-full sm:w-auto"
        />
        <Select value={statusFilter} onValueChange={setStatusFilter}>
          <SelectTrigger className="w-full sm:w-[160px]">
            <SelectValue placeholder={t('AgentsPage.toolbar.allStatuses')} />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">{t('AgentsPage.toolbar.allStatuses')}</SelectItem>
            <SelectItem value="online">{t('AgentsPage.status.online')}</SelectItem>
            <SelectItem value="offline">{t('AgentsPage.status.offline')}</SelectItem>
            <SelectItem value="connecting">{t('AgentsPage.status.connecting')}</SelectItem>
            <SelectItem value="error">{t('AgentsPage.status.error')}</SelectItem>
            <SelectItem value="maintenance">{t('AgentsPage.status.maintenance')}</SelectItem>
          </SelectContent>
        </Select>
        <Select value={typeFilter} onValueChange={setTypeFilter}>
          <SelectTrigger className="w-full sm:w-[160px]">
            <SelectValue placeholder={t('AgentsPage.toolbar.allTypes')} />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">{t('AgentsPage.toolbar.allTypes')}</SelectItem>
            <SelectItem value="site">{t('AgentsPage.agentTypes.site')}</SelectItem>
            <SelectItem value="scanner">{t('AgentsPage.agentTypes.scanner')}</SelectItem>
            <SelectItem value="collector">{t('AgentsPage.agentTypes.collector')}</SelectItem>
            <SelectItem value="gateway">{t('AgentsPage.agentTypes.gateway')}</SelectItem>
          </SelectContent>
        </Select>
        {hasActiveFilters && (
          <Button variant="ghost" size="sm" onClick={handleClearFilters}>
            {t('AgentsPage.toolbar.clearFilters')}
          </Button>
        )}
      </PageToolbar>

      {/* Table */}
      <DataTable
        data={agents}
        columns={columns}
        isLoading={isLoading}
        selectable
        onSelectionChange={setSelectedAgents}
        searchable={false}
        itemName={t('AgentsPage.itemNamePlural')}
        getRowId={(a) => a.id}
      />

      {/* Recent activity across the fleet, surfaces scheduled-scan
          runs from every agent in the org. Pairs with the per-schedule
          run history dialog on the Site detail Agent tab. */}
      <FleetActivityPanel />

      {/* Bulk actions */}
      <BulkActionsBar
        selectedCount={selectedAgents.length}
        itemName={t('AgentsPage.itemNameSingular')}
        onClear={() => setSelectedAgents([])}
        actions={[
          {
            label: t('AgentsPage.bulk.approve.label'),
            icon: ShieldCheck,
            onClick: async () => {
              // Fan out to per-agent /approve. Promise.allSettled
              // tolerates per-row failures (e.g. already approved).
              const results = await Promise.allSettled(
                selectedAgents.map((a) => agentsApi.approve(a.id)),
              );
              const ok = results.filter((r) => r.status === 'fulfilled').length;
              const fail = results.length - ok;
              toast({
                title: t('AgentsPage.bulk.approve.toastTitle'),
                description: fail
                  ? t('AgentsPage.bulk.approve.resultWithFailures', { ok, fail })
                  : t('AgentsPage.bulk.approve.result', { ok }),
                variant: fail > 0 ? 'destructive' : undefined,
              });
              setSelectedAgents([]);
              queryClient.invalidateQueries({ queryKey: ['agents'] });
            },
          },
          {
            label: t('AgentsPage.bulk.disable.label'),
            icon: ShieldOff,
            onClick: async () => {
              const results = await Promise.allSettled(
                selectedAgents.map((a) =>
                  agentsApi.update(a.id, { is_enabled: false }),
                ),
              );
              const ok = results.filter((r) => r.status === 'fulfilled').length;
              toast({
                title: t('AgentsPage.bulk.disable.toastTitle'),
                description: t('AgentsPage.bulk.disable.result', { ok, total: results.length }),
              });
              setSelectedAgents([]);
              queryClient.invalidateQueries({ queryKey: ['agents'] });
            },
          },
          {
            label: t('AgentsPage.bulk.delete.label'),
            icon: Trash2,
            variant: 'destructive',
            onClick: async () => {
              if (
                !confirm(
                  t('AgentsPage.bulk.delete.confirm', { count: selectedAgents.length }),
                )
              ) {
                return;
              }
              const results = await Promise.allSettled(
                selectedAgents.map((a) => agentsApi.disconnect(a.id)),
              );
              const ok = results.filter((r) => r.status === 'fulfilled').length;
              const fail = results.length - ok;
              toast({
                title: t('AgentsPage.bulk.delete.toastTitle'),
                description: fail
                  ? t('AgentsPage.bulk.delete.resultWithFailures', { ok, fail })
                  : t('AgentsPage.bulk.delete.result', { ok }),
                variant: fail > 0 ? 'destructive' : undefined,
              });
              setSelectedAgents([]);
              queryClient.invalidateQueries({ queryKey: ['agents'] });
            },
          },
        ]}
      />

      {/* Register Agent Dialog */}
      <RegisterAgentDialog
        open={registerDialogOpen}
        onOpenChange={setRegisterDialogOpen}
        sites={sites}
        defaultSiteId={selectedSiteId}
      />

      {/* Hidden alert if data partially failed */}
      {agentsData == null && !isLoading && (
        <div className="rounded-lg border border-warning/30 bg-warning/5 px-4 py-3 text-sm flex items-center gap-2">
          <AlertTriangle className="h-4 w-4 text-warning" />
          {t('AgentsPage.partialFailure')}
        </div>
      )}
    </div>
  );
}

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { useState, useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { useParams, useNavigate } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useToast } from '@/hooks/use-toast';
import { useSiteStore } from '@/stores/siteStore';
import { correlationApi, usersApi, type CorrelationRule, type Incident, type IncidentEvent, type UserAccount } from '@/lib/api';
import { PageHeader, PageToolbar } from '@/components/layout';
import { StatsGrid } from '@/components/ui/stats-grid';
import { DataTable, type DataTableColumn } from '@/components/ui/data-table';
import { StatusBadge, type StatusVariant } from '@/components/ui/status-indicator';
import { TypeBadge } from '@/components/ui/type-badge';
import { BulkActionsBar } from '@/components/ui/bulk-actions-bar';
import { ErrorState } from '@/components/ui/empty-state';
import { SearchBar } from '@/components/ui/search-bar';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from '@/components/ui/dialog';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { FormDialog } from '@/components/ui/form-dialog';
import { FormControl, FormField, FormItem, FormLabel, FormMessage } from '@/components/ui/form';
import { z } from 'zod';
import { Badge } from '@/components/ui/badge';
import {
  AlertTriangle,
  Bell,
  Eye,
  Layers,
  Plus,
  Play,
  Shield,
  Zap,
  Check,
  X as XIcon,
  UserPlus,
  Pencil,
  Trash2,
  Power,
  PowerOff,
} from 'lucide-react';

// ───────────────────────────────────────────────────────────────────
// Mappings to canonical StatusBadge variants
// ───────────────────────────────────────────────────────────────────

const SEVERITY_VARIANT: Record<string, StatusVariant> = {
  critical: 'severity_critical',
  high: 'severity_high',
  medium: 'severity_medium',
  low: 'severity_low',
  info: 'severity_info',
};

const STATUS_VARIANT: Record<string, StatusVariant> = {
  open: 'error',
  investigating: 'warning',
  mitigating: 'warning',
  resolved: 'success',
  closed: 'neutral',
};

const INCIDENT_TABS = ['incidents', 'rules'] as const;

export default function IncidentsPage() {
  const { t } = useTranslation('enterprise');
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const { tab: urlTab } = useParams<{ tab?: string }>();
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const activeTab = INCIDENT_TABS.includes(urlTab as any) ? urlTab! : 'incidents';
  const setActiveTab = (v: string) => navigate(v === 'incidents' ? '/incidents' : `/incidents/${v}`, { replace: true });
  const selectedSiteId = useSiteStore((s) => s.selectedSiteId);

  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedIncidents, setSelectedIncidents] = useState<Incident[]>([]);
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null);
  const [showRuleDialog, setShowRuleDialog] = useState(false);
  // Same FormDialog drives create + edit. When non-null we're editing that
  // rule (defaults prefilled); when null the dialog is in "create" mode.
  const [editingRule, setEditingRule] = useState<CorrelationRule | null>(null);
  const [showTriggerDialog, setShowTriggerDialog] = useState(false);
  // Bulk-assign user-picker dialog state.
  const [showAssignDialog, setShowAssignDialog] = useState(false);
  const [assignUserId, setAssignUserId] = useState<string>('');

  // Rule form schema. `patterns` is JSON-as-text so we can show parse errors.
  const ruleSchema = z
    .object({
      name: z.string().min(1, t('IncidentsPage.validation.nameRequired')),
      scope: z.string(),
      severity: z.string(),
      window: z.coerce.number().int().positive(),
      patterns: z.string().min(1, t('IncidentsPage.validation.patternsRequired')),
    })
    .superRefine((data, ctx) => {
      try {
        JSON.parse(data.patterns);
      } catch {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['patterns'],
          message: t('IncidentsPage.validation.invalidJson'),
        });
      }
    });
  type RuleFormValues = z.infer<typeof ruleSchema>;
  const ruleDefaults: RuleFormValues = {
    name: '',
    scope: 'site',
    severity: 'medium',
    window: 300,
    patterns: '',
  };

  const { toast } = useToast();
  const errToast = (title: string) => (err: unknown) => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const detail = (err as any)?.response?.data?.detail
      || (err instanceof Error ? err.message : t('IncidentsPage.errors.unknown'));
    toast({ variant: 'destructive', title, description: String(detail) });
  };

  // Site context propagates to BOTH the queryKey (cache split) AND the
  // backend params (real filtering). When a site is selected we pass
  // site_id so the open/24h counts narrow to that site; otherwise the
  // stats come back org-wide.
  const statsQuery = useQuery({
    queryKey: ['correlation-stats', { siteId: selectedSiteId }],
    queryFn: async () => (await correlationApi.getStats(
      selectedSiteId ? { site_id: selectedSiteId } : undefined,
    )).data,
    refetchInterval: 30000,
  });

  const incidentsQuery = useQuery({
    queryKey: ['incidents', statusFilter, severityFilter, { siteId: selectedSiteId }],
    queryFn: async () => (await correlationApi.listIncidents({
      ...(statusFilter !== 'all' && { status: statusFilter }),
      ...(severityFilter !== 'all' && { severity: severityFilter }),
      ...(selectedSiteId && { site_id: selectedSiteId }),
      limit: 100,
    })).data,
    refetchInterval: 10000,
  });

  const rulesQuery = useQuery({
    queryKey: ['correlation-rules', { siteId: selectedSiteId }],
    queryFn: async () => (await correlationApi.listRules()).data,
  });

  const incidentEventsQuery = useQuery({
    queryKey: ['incident-events', selectedIncident?.id, { siteId: selectedSiteId }],
    queryFn: async () => (await correlationApi.getIncidentEvents(selectedIncident!.id)).data,
    enabled: !!selectedIncident,
  });

  const updateIncidentMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<Incident> }) =>
      correlationApi.updateIncident(id, data),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['incidents'] }),
    onError: errToast(t('IncidentsPage.errors.updateIncident')),
  });

  const createRuleMutation = useMutation({
    mutationFn: (data: Partial<CorrelationRule>) => correlationApi.createRule(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['correlation-rules'] });
      setShowRuleDialog(false);
    },
    onError: errToast(t('IncidentsPage.errors.createRule')),
  });

  const triggerMutation = useMutation({
    // Backend ``correlation.trigger`` accepts site_id, forward the
    // global site context so "Run Correlation Now" matches what the
    // user sees in the list, not org-wide.
    mutationFn: (data: { time_window_minutes?: number; dry_run?: boolean }) =>
      correlationApi.trigger({ ...data, ...(selectedSiteId && { site_id: selectedSiteId }) }),
    onSuccess: (res, vars) => {
      // Surface the engine summary the backend returns
      // ({rules_evaluated, incidents_created, incidents_updated, ...}) so
      // both Trigger and Dry-Run give observable feedback instead of a
      // silent close. Description composed from existing translated labels
      // + the returned counts (no new locale keys).
      const r = (res?.data ?? {}) as {
        rules_evaluated?: number;
        incidents_created?: number;
        incidents_updated?: number;
        dry_run?: boolean;
      };
      toast({
        title: vars?.dry_run
          ? t('IncidentsPage.dialogs.trigger.dryRun')
          : t('IncidentsPage.actions.runCorrelation'),
        description: `${t('IncidentsPage.tabs.rules', { count: r.rules_evaluated ?? 0 })} · `
          + `+${r.incidents_created ?? 0} / ~${r.incidents_updated ?? 0} `
          + `${t('IncidentsPage.itemNames.incidents')}`,
      });
      if (!vars?.dry_run) queryClient.invalidateQueries({ queryKey: ['incidents'] });
    },
    onError: errToast(t('IncidentsPage.errors.triggerCorrelation')),
  });

  const updateRuleMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<CorrelationRule> }) =>
      correlationApi.updateRule(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['correlation-rules'] });
      setShowRuleDialog(false);
      setEditingRule(null);
    },
    // No dedicated update-rule error key exists; reuse the generic common error.
    onError: errToast(t('error', { ns: 'common' })),
  });

  const deleteRuleMutation = useMutation({
    mutationFn: (id: string) => correlationApi.deleteRule(id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['correlation-rules'] }),
    onError: errToast(t('error', { ns: 'common' })),
  });

  // Org users for the bulk-assign picker (small, org-scoped list).
  const usersQuery = useQuery({
    queryKey: ['users', 'incident-assign'],
    queryFn: async () => (await usersApi.list({ per_page: 100 })).data,
    enabled: showAssignDialog,
  });
  const assignableUsers: UserAccount[] = usersQuery.data?.items ?? [];

  const stats = statsQuery.data;
  const allIncidents: Incident[] = useMemo(() => incidentsQuery.data?.incidents || [], [incidentsQuery.data?.incidents]);
  const rules = rulesQuery.data?.rules || [];

  // Client-side search filter
  const incidents = useMemo(() => {
    if (!searchQuery) return allIncidents;
    const q = searchQuery.toLowerCase();
    return allIncidents.filter(
      (i) =>
        i.title.toLowerCase().includes(q) ||
        i.severity.toLowerCase().includes(q) ||
        i.status.toLowerCase().includes(q),
    );
  }, [allIncidents, searchQuery]);

  const hasActiveFilters = statusFilter !== 'all' || severityFilter !== 'all' || searchQuery !== '';
  const handleClearFilters = () => {
    setStatusFilter('all');
    setSeverityFilter('all');
    setSearchQuery('');
  };

  const incidentColumns: DataTableColumn<Incident>[] = [
    {
      id: 'severity',
      header: t('IncidentsPage.columns.severity'),
      accessorKey: 'severity',
      cell: (row) => (
        <StatusBadge variant={SEVERITY_VARIANT[row.severity] || 'severity_info'} />
      ),
    },
    { id: 'title', header: t('IncidentsPage.columns.title'), accessorKey: 'title' },
    {
      id: 'status',
      header: t('IncidentsPage.columns.status'),
      accessorKey: 'status',
      cell: (row) => (
        <StatusBadge variant={STATUS_VARIANT[row.status] || 'neutral'}>
          {row.status}
        </StatusBadge>
      ),
    },
    {
      id: 'event_count',
      header: t('IncidentsPage.columns.events'),
      accessorKey: 'event_count',
      cell: (row) => <span className="font-mono">{row.event_count}</span>,
    },
    {
      id: 'affected_devices',
      header: t('IncidentsPage.columns.devices'),
      accessorFn: (row) => row.affected_devices?.length || 0,
      cell: (row) => <span>{row.affected_devices?.length || 0}</span>,
    },
    {
      id: 'opened_at',
      header: t('IncidentsPage.columns.opened'),
      accessorKey: 'opened_at',
      cell: (row) => (row.opened_at ? new Date(row.opened_at).toLocaleString() : '—'),
    },
    {
      id: 'actions',
      header: '',
      sortable: false,
      cell: (row) => (
        <div className="flex justify-end gap-1">
          <Button variant="ghost" size="sm" onClick={() => setSelectedIncident(row)}>
            <Eye className="h-4 w-4" />
          </Button>
          {row.status === 'open' && (
            <Button
              variant="ghost"
              size="sm"
              onClick={() => updateIncidentMutation.mutate({
                id: row.id,
                data: { status: 'investigating' },
              })}
            >
              {t('IncidentsPage.actions.investigate')}
            </Button>
          )}
        </div>
      ),
    },
  ];

  const ruleColumns: DataTableColumn<CorrelationRule>[] = [
    { id: 'name', header: t('IncidentsPage.columns.name'), accessorKey: 'name' },
    {
      id: 'status',
      header: t('IncidentsPage.columns.status'),
      accessorKey: 'status',
      cell: (row) => (
        <StatusBadge variant={row.status === 'active' ? 'success' : 'neutral'}>
          {row.status}
        </StatusBadge>
      ),
    },
    {
      id: 'scope',
      header: t('IncidentsPage.columns.scope'),
      accessorKey: 'scope',
      cell: (row) => <TypeBadge type={row.scope} />,
    },
    {
      id: 'severity',
      header: t('IncidentsPage.columns.severity'),
      accessorKey: 'severity',
      cell: (row) => (
        <StatusBadge variant={SEVERITY_VARIANT[row.severity] || 'severity_info'} />
      ),
    },
    {
      id: 'time_window',
      header: t('IncidentsPage.columns.window'),
      accessorKey: 'time_window_seconds',
      cell: (row) => `${row.time_window_seconds}s`,
    },
    {
      id: 'fire_count',
      header: t('IncidentsPage.columns.fires'),
      accessorKey: 'fire_count',
      cell: (row) => <span className="font-mono">{row.fire_count}</span>,
    },
    {
      id: 'patterns',
      header: t('IncidentsPage.columns.patterns'),
      accessorFn: (row) => row.event_patterns?.length || 0,
      cell: (row) => <span>{t('IncidentsPage.rules.patternsCount', { count: row.event_patterns?.length || 0 })}</span>,
    },
    {
      id: 'actions',
      header: '',
      sortable: false,
      cell: (row) => (
        <div className="flex justify-end gap-1">
          <Button
            variant="ghost"
            size="sm"
            title={t('edit', { ns: 'common' })}
            onClick={() => openEditRule(row)}
          >
            <Pencil className="h-4 w-4" />
          </Button>
          <Button
            variant="ghost"
            size="sm"
            // Icon-only enable/disable toggle (mirrors AlertRulesPage). No
            // common.enable/disable key exists, so we keep it label-free
            // rather than render a raw key; the icon (Power/PowerOff) conveys
            // the action and the status badge column reflects the result.
            onClick={() =>
              updateRuleMutation.mutate({
                id: row.id,
                data: { status: row.status === 'active' ? 'disabled' : 'active' },
              })
            }
          >
            {row.status === 'active' ? <PowerOff className="h-4 w-4" /> : <Power className="h-4 w-4" />}
          </Button>
          <Button
            variant="ghost"
            size="sm"
            title={t('delete', { ns: 'common' })}
            className="text-destructive hover:text-destructive"
            onClick={() => {
              if (window.confirm(`${t('delete', { ns: 'common' })} "${row.name}"?`)) {
                deleteRuleMutation.mutate(row.id);
              }
            }}
          >
            <Trash2 className="h-4 w-4" />
          </Button>
        </div>
      ),
    },
  ];

  // ── Bulk handlers ──
  const handleBulkAcknowledge = () => {
    selectedIncidents.forEach((i) => {
      if (i.status === 'open') {
        updateIncidentMutation.mutate({ id: i.id, data: { status: 'investigating' } });
      }
    });
    setSelectedIncidents([]);
  };
  const handleBulkClose = () => {
    selectedIncidents.forEach((i) => {
      updateIncidentMutation.mutate({ id: i.id, data: { status: 'closed' } });
    });
    setSelectedIncidents([]);
  };

  // Open the shared rule FormDialog in "create" mode.
  const openCreateRule = () => {
    setEditingRule(null);
    setShowRuleDialog(true);
  };
  // Open the shared rule FormDialog in "edit" mode. editingRule must be set
  // BEFORE opening so FormDialog's open-transition reset picks up the
  // prefilled defaults.
  const openEditRule = (rule: CorrelationRule) => {
    setEditingRule(rule);
    setShowRuleDialog(true);
  };

  // Defaults reuse the create shape; in edit mode they reflect the row.
  const ruleFormValues: RuleFormValues = editingRule
    ? {
        name: editingRule.name,
        scope: editingRule.scope,
        severity: editingRule.severity,
        window: editingRule.time_window_seconds,
        patterns: JSON.stringify(editingRule.event_patterns ?? [], null, 2),
      }
    : ruleDefaults;

  // Bulk-assign: set assigned_to on every selected incident, summarize result.
  const handleBulkAssign = async () => {
    if (!assignUserId) return;
    const targets = [...selectedIncidents];
    const results = await Promise.allSettled(
      targets.map((i) =>
        correlationApi.updateIncident(i.id, { assigned_to: assignUserId } as Partial<Incident>),
      ),
    );
    const ok = results.filter((r) => r.status === 'fulfilled').length;
    const failed = results.length - ok;
    queryClient.invalidateQueries({ queryKey: ['incidents'] });
    // Summary composed from counts + existing item-name label (no new keys).
    toast({
      title: t('IncidentsPage.actions.assign'),
      description: `${ok} / ${results.length} ${t('IncidentsPage.itemNames.incidents')}`
        + (failed > 0 ? ` · ${failed} ${t('error', { ns: 'common' })}` : ''),
      ...(failed > 0 ? { variant: 'destructive' as const } : {}),
    });
    setShowAssignDialog(false);
    setAssignUserId('');
    setSelectedIncidents([]);
  };

  if (incidentsQuery.isError && rulesQuery.isError) {
    return (
      <div className="space-y-6">
        <PageHeader
          icon={Shield}
          title={t('IncidentsPage.header.title')}
          description={t('IncidentsPage.header.description')}
        />
        <ErrorState
          message={t('IncidentsPage.errors.loadFailed')}
          onRetry={() => {
            incidentsQuery.refetch();
            rulesQuery.refetch();
          }}
        />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader
        icon={Shield}
        title={t('IncidentsPage.header.title')}
        description={t('IncidentsPage.header.description')}
        onRefresh={() => { statsQuery.refetch(); incidentsQuery.refetch(); rulesQuery.refetch(); }}
        refreshing={statsQuery.isFetching || incidentsQuery.isFetching}
        secondaryActions={[
          { label: t('IncidentsPage.actions.runCorrelation'), icon: Play, onClick: () => setShowTriggerDialog(true) },
        ]}
        primaryAction={{ label: t('IncidentsPage.actions.newRule'), icon: Plus, onClick: openCreateRule }}
      />

      {/* When /correlation/stats errors, the cards would otherwise show
          misleading all-zeros. Dim them and surface a small inline indicator
          (with retry) so zeros aren't mistaken for real values. */}
      <div className={statsQuery.isError ? 'opacity-50' : undefined}>
        {statsQuery.isError && (
          <div className="mb-2 flex items-center gap-2 text-xs text-destructive">
            <AlertTriangle className="h-3.5 w-3.5" />
            <span>{t('IncidentsPage.errors.loadFailed')}</span>
            <Button variant="ghost" size="sm" className="h-6 px-2 text-xs" onClick={() => statsQuery.refetch()}>
              {t('EmptyState.inlineError.retry', { ns: 'common' })}
            </Button>
          </div>
        )}
        <StatsGrid
          columns={4}
          isLoading={statsQuery.isLoading}
          stats={[
            { title: t('IncidentsPage.stats.activeRules.title'), value: stats?.active_rules ?? 0, icon: Zap, variant: 'default', description: t('IncidentsPage.stats.activeRules.description') },
            { title: t('IncidentsPage.stats.openIncidents.title'), value: stats?.open_incidents ?? 0, icon: AlertTriangle, variant: 'destructive', description: t('IncidentsPage.stats.openIncidents.description') },
            { title: t('IncidentsPage.stats.last24h.title'), value: stats?.incidents_last_24h ?? 0, icon: Bell, variant: 'default', description: t('IncidentsPage.stats.last24h.description') },
            { title: t('IncidentsPage.stats.totalRules.title'), value: stats?.total_rules ?? 0, icon: Layers, variant: 'default', description: t('IncidentsPage.stats.totalRules.description') },
          ]}
        />
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          <TabsTrigger value="incidents">
            {t('IncidentsPage.tabs.incidents', { count: incidents.length })}
          </TabsTrigger>
          <TabsTrigger value="rules">
            {t('IncidentsPage.tabs.rules', { count: rules.length })}
          </TabsTrigger>
        </TabsList>

        <TabsContent value="incidents" className="space-y-4">
          <PageToolbar>
            <SearchBar
              value={searchQuery}
              onChange={setSearchQuery}
              placeholder={t('IncidentsPage.search.placeholder')}
              className="w-full sm:w-auto"
            />
            <Select value={statusFilter} onValueChange={setStatusFilter}>
              <SelectTrigger className="w-full sm:w-[160px]"><SelectValue placeholder={t('IncidentsPage.filters.allStatuses')} /></SelectTrigger>
              <SelectContent>
                <SelectItem value="all">{t('IncidentsPage.filters.allStatuses')}</SelectItem>
                <SelectItem value="open">{t('IncidentsPage.status.open')}</SelectItem>
                <SelectItem value="investigating">{t('IncidentsPage.status.investigating')}</SelectItem>
                <SelectItem value="mitigating">{t('IncidentsPage.status.mitigating')}</SelectItem>
                <SelectItem value="resolved">{t('IncidentsPage.status.resolved')}</SelectItem>
                <SelectItem value="closed">{t('IncidentsPage.status.closed')}</SelectItem>
              </SelectContent>
            </Select>
            <Select value={severityFilter} onValueChange={setSeverityFilter}>
              <SelectTrigger className="w-full sm:w-[160px]"><SelectValue placeholder={t('IncidentsPage.filters.allSeverities')} /></SelectTrigger>
              <SelectContent>
                <SelectItem value="all">{t('IncidentsPage.filters.allSeverities')}</SelectItem>
                <SelectItem value="critical">{t('IncidentsPage.severity.critical')}</SelectItem>
                <SelectItem value="high">{t('IncidentsPage.severity.high')}</SelectItem>
                <SelectItem value="medium">{t('IncidentsPage.severity.medium')}</SelectItem>
                <SelectItem value="low">{t('IncidentsPage.severity.low')}</SelectItem>
              </SelectContent>
            </Select>
            {hasActiveFilters && (
              <Button variant="ghost" size="sm" onClick={handleClearFilters}>
                {t('IncidentsPage.filters.clear')}
              </Button>
            )}
          </PageToolbar>

          {/* Inline per-tab error so a single failing query is honest about
              the failure instead of masking as an empty table. */}
          {incidentsQuery.isError ? (
            <ErrorState
              message={t('IncidentsPage.errors.loadFailed')}
              onRetry={() => incidentsQuery.refetch()}
            />
          ) : (
            <DataTable
              data={incidents}
              columns={incidentColumns}
              isLoading={incidentsQuery.isLoading}
              selectable
              onSelectionChange={setSelectedIncidents}
              searchable={false}
              itemName={t('IncidentsPage.itemNames.incidents')}
              getRowId={(r) => r.id}
            />
          )}

          <BulkActionsBar
            selectedCount={selectedIncidents.length}
            itemName={t('IncidentsPage.itemNames.incident')}
            onClear={() => setSelectedIncidents([])}
            actions={[
              { label: t('IncidentsPage.actions.acknowledge'), icon: Check, onClick: handleBulkAcknowledge },
              { label: t('IncidentsPage.actions.assign'), icon: UserPlus, onClick: () => setShowAssignDialog(true) },
              { label: t('IncidentsPage.actions.close'), icon: XIcon, variant: 'destructive', onClick: handleBulkClose },
            ]}
          />
        </TabsContent>

        <TabsContent value="rules">
          {rulesQuery.isError ? (
            <ErrorState
              message={t('IncidentsPage.errors.loadFailed')}
              onRetry={() => rulesQuery.refetch()}
            />
          ) : (
            <DataTable
              columns={ruleColumns}
              data={rules}
              isLoading={rulesQuery.isLoading}
              searchable={false}
              getRowId={(r) => r.id}
              itemName={t('IncidentsPage.itemNames.rules')}
            />
          )}
        </TabsContent>
      </Tabs>

      {/* Incident Detail Dialog */}
      <Dialog open={!!selectedIncident} onOpenChange={(open) => !open && setSelectedIncident(null)}>
        <DialogContent className="max-w-2xl max-h-[80vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <StatusBadge variant={SEVERITY_VARIANT[selectedIncident?.severity || 'info'] || 'severity_info'} />
              {selectedIncident?.title}
            </DialogTitle>
          </DialogHeader>
          {selectedIncident && (
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4 text-sm">
                <div>
                  <span className="text-muted-foreground">{t('IncidentsPage.detail.statusLabel')}</span>{' '}
                  <StatusBadge variant={STATUS_VARIANT[selectedIncident.status] || 'neutral'}>
                    {selectedIncident.status}
                  </StatusBadge>
                </div>
                <div><span className="text-muted-foreground">{t('IncidentsPage.detail.openedLabel')}</span> {selectedIncident.opened_at ? new Date(selectedIncident.opened_at).toLocaleString() : '—'}</div>
                <div><span className="text-muted-foreground">{t('IncidentsPage.detail.eventsLabel')}</span> {selectedIncident.event_count}</div>
                <div><span className="text-muted-foreground">{t('IncidentsPage.detail.devicesLabel')}</span> {selectedIncident.affected_devices?.length || 0}</div>
              </div>
              {selectedIncident.description && (
                <pre className="text-sm bg-muted p-3 rounded-md whitespace-pre-wrap">{selectedIncident.description}</pre>
              )}
              {selectedIncident.root_cause && (
                <div><Label>{t('IncidentsPage.detail.rootCause')}</Label><p className="text-sm mt-1">{selectedIncident.root_cause}</p></div>
              )}

              <div>
                <Label className="mb-2 block">{t('IncidentsPage.detail.linkedEvents')}</Label>
                {incidentEventsQuery.isLoading ? (
                  <p className="text-sm text-muted-foreground">{t('IncidentsPage.detail.loading')}</p>
                ) : (
                  <div className="space-y-2 max-h-60 overflow-y-auto">
                    {(incidentEventsQuery.data || []).map((ev: IncidentEvent) => (
                      <div key={ev.id} className="flex items-center gap-2 text-sm border rounded p-2">
                        <Badge variant="outline">{ev.event_type || t('IncidentsPage.detail.unknownEventType')}</Badge>
                        <span className="text-muted-foreground">{ev.event_timestamp ? new Date(ev.event_timestamp).toLocaleString() : ''}</span>
                        {ev.matched_pattern && <span className="ml-auto text-xs text-muted-foreground">{t('IncidentsPage.detail.patternPrefix', { pattern: ev.matched_pattern })}</span>}
                      </div>
                    ))}
                  </div>
                )}
              </div>

              <DialogFooter>
                <div className="flex gap-2">
                  {selectedIncident.status === 'open' && (
                    <Button onClick={() => { updateIncidentMutation.mutate({ id: selectedIncident.id, data: { status: 'investigating' } }); setSelectedIncident(null); }}>
                      {t('IncidentsPage.actions.startInvestigation')}
                    </Button>
                  )}
                  {['open', 'investigating', 'mitigating'].includes(selectedIncident.status) && (
                    <Button variant="outline" onClick={() => { updateIncidentMutation.mutate({ id: selectedIncident.id, data: { status: 'resolved' } }); setSelectedIncident(null); }}>
                      {t('IncidentsPage.actions.resolve')}
                    </Button>
                  )}
                </div>
              </DialogFooter>
            </div>
          )}
        </DialogContent>
      </Dialog>

      {/* Create / Edit Rule Dialog (same FormDialog, prefilled when editing) */}
      <FormDialog<RuleFormValues>
        open={showRuleDialog}
        onOpenChange={(open) => { setShowRuleDialog(open); if (!open) setEditingRule(null); }}
        title={editingRule ? t('edit', { ns: 'common' }) : t('IncidentsPage.dialogs.newRule.title')}
        schema={ruleSchema}
        defaultValues={ruleFormValues}
        submitLabel={editingRule ? t('save', { ns: 'common' }) : t('IncidentsPage.dialogs.newRule.submit')}
        onSubmit={async (values) => {
          const patterns = JSON.parse(values.patterns); // schema-validated
          const payload = {
            name: values.name,
            scope: values.scope,
            severity: values.severity,
            time_window_seconds: values.window,
            event_patterns: patterns,
          };
          if (editingRule) {
            await updateRuleMutation.mutateAsync({ id: editingRule.id, data: payload });
          } else {
            await createRuleMutation.mutateAsync(payload);
          }
        }}
      >
        {(form) => (
          <>
            <FormField
              control={form.control}
              name="name"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>{t('IncidentsPage.form.name')}</FormLabel>
                  <FormControl>
                    <Input {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <div className="grid grid-cols-2 gap-4">
              <FormField
                control={form.control}
                name="scope"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>{t('IncidentsPage.form.scope')}</FormLabel>
                    <Select value={field.value} onValueChange={field.onChange}>
                      <FormControl>
                        <SelectTrigger><SelectValue /></SelectTrigger>
                      </FormControl>
                      <SelectContent>
                        <SelectItem value="site">{t('IncidentsPage.scope.site')}</SelectItem>
                        <SelectItem value="device_group">{t('IncidentsPage.scope.deviceGroup')}</SelectItem>
                        <SelectItem value="organization">{t('IncidentsPage.scope.organization')}</SelectItem>
                      </SelectContent>
                    </Select>
                    <FormMessage />
                  </FormItem>
                )}
              />
              <FormField
                control={form.control}
                name="severity"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>{t('IncidentsPage.form.severity')}</FormLabel>
                    <Select value={field.value} onValueChange={field.onChange}>
                      <FormControl>
                        <SelectTrigger><SelectValue /></SelectTrigger>
                      </FormControl>
                      <SelectContent>
                        <SelectItem value="critical">{t('IncidentsPage.severity.critical')}</SelectItem>
                        <SelectItem value="high">{t('IncidentsPage.severity.high')}</SelectItem>
                        <SelectItem value="medium">{t('IncidentsPage.severity.medium')}</SelectItem>
                        <SelectItem value="low">{t('IncidentsPage.severity.low')}</SelectItem>
                      </SelectContent>
                    </Select>
                    <FormMessage />
                  </FormItem>
                )}
              />
            </div>
            <FormField
              control={form.control}
              name="window"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>{t('IncidentsPage.form.timeWindow')}</FormLabel>
                  <FormControl>
                    <Input type="number" {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <FormField
              control={form.control}
              name="patterns"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>{t('IncidentsPage.form.eventPatterns')}</FormLabel>
                  <FormControl>
                    <textarea
                      className="w-full h-32 rounded-md border p-3 font-mono text-sm bg-background"
                      placeholder='[{"event_type": "device.offline", "min_count": 1}]'
                      {...field}
                    />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
          </>
        )}
      </FormDialog>

      {/* Trigger Dialog */}
      <Dialog open={showTriggerDialog} onOpenChange={setShowTriggerDialog}>
        <DialogContent>
          <DialogHeader><DialogTitle>{t('IncidentsPage.dialogs.trigger.title')}</DialogTitle></DialogHeader>
          <p className="text-sm text-muted-foreground">
            {t('IncidentsPage.dialogs.trigger.description')}
          </p>
          <DialogFooter>
            <Button variant="outline" onClick={() => { triggerMutation.mutate({ dry_run: true }); setShowTriggerDialog(false); }}>
              {t('IncidentsPage.dialogs.trigger.dryRun')}
            </Button>
            <Button onClick={() => { triggerMutation.mutate({}); setShowTriggerDialog(false); }}>
              {t('IncidentsPage.dialogs.trigger.runNow')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Bulk Assign Dialog, pick a user, set assigned_to on every selected
          incident via updateIncident. Summary toast reports n ok / m failed. */}
      <Dialog open={showAssignDialog} onOpenChange={(open) => { setShowAssignDialog(open); if (!open) setAssignUserId(''); }}>
        <DialogContent>
          <DialogHeader><DialogTitle>{t('IncidentsPage.actions.assign')}</DialogTitle></DialogHeader>
          <div className="space-y-2">
            <Label>{t('CameraAccessPanel.form.userLabel', { ns: 'common' })}</Label>
            <Select value={assignUserId} onValueChange={setAssignUserId}>
              <SelectTrigger>
                <SelectValue placeholder={t('CameraAccessPanel.form.userPlaceholder', { ns: 'common' })} />
              </SelectTrigger>
              <SelectContent>
                {assignableUsers.map((u) => (
                  <SelectItem key={u.id} value={u.id}>
                    {u.full_name || u.username || u.email}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => { setShowAssignDialog(false); setAssignUserId(''); }}>
              {t('cancel', { ns: 'common' })}
            </Button>
            <Button disabled={!assignUserId} onClick={handleBulkAssign}>
              {t('IncidentsPage.actions.assign')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

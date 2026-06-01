/* eslint-disable @typescript-eslint/no-explicit-any */
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { useState, useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { useParams, useNavigate } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useSiteStore } from '@/stores/siteStore';
import { slaApi, type SLAPolicy, type SLABreach } from '@/lib/api';
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
import { Progress } from '@/components/ui/progress';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Skeleton } from '@/components/ui/skeleton';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from '@/components/ui/dialog';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { FormDialog } from '@/components/ui/form-dialog';
import { FormControl, FormField, FormItem, FormLabel, FormMessage } from '@/components/ui/form';
import { z } from 'zod';
import {
  AlertTriangle,
  Eye,
  Gauge,
  Plus,
  RefreshCw,
  Shield,
  XCircle,
  Trash2,
  Settings,
  Check,
} from 'lucide-react';
import { useToast } from '@/hooks/use-toast';

const SEVERITY_VARIANT: Record<string, StatusVariant> = {
  critical: 'severity_critical',
  // SLA breaches are emitted as either "warning" or "critical"
  // (SLABreachSeverity). "warning" is the lower-but-still-significant tier
  // below critical, so render it amber/high rather than falling through to
  // the misleading "Info" default.
  warning: 'severity_high',
  high: 'severity_high',
  medium: 'severity_medium',
  low: 'severity_low',
  info: 'severity_info',
};

const BREACH_STATUS_VARIANT: Record<string, StatusVariant> = {
  active: 'error',
  resolved: 'success',
  acknowledged: 'info',
};

function ComplianceGauge({ value }: { value: number | null }) {
  const pct = value ?? 0;
  const color = pct >= 95 ? 'text-success' : pct >= 80 ? 'text-warning' : 'text-destructive';
  return (
    <div className="flex items-center gap-2">
      <Progress value={pct} className="h-2 flex-1" />
      <span className={`font-mono font-bold ${color}`}>{pct.toFixed(1)}%</span>
    </div>
  );
}

const SLA_TABS = ['overview', 'policies', 'breaches'] as const;

export default function SLAPage() {
  const { t } = useTranslation('enterprise');
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const navigate = useNavigate();
  const { tab: urlTab } = useParams<{ tab?: string }>();
  const activeTab = SLA_TABS.includes(urlTab as any) ? urlTab! : 'overview';
  const setActiveTab = (v: string) => navigate(v === 'overview' ? '/sla' : `/sla/${v}`, { replace: true });
  const selectedSiteId = useSiteStore((s) => s.selectedSiteId);
  const [showCreateDialog, setShowCreateDialog] = useState(false);
  const [editPolicy, setEditPolicy] = useState<SLAPolicy | null>(null);
  const [selectedPolicy, setSelectedPolicy] = useState<SLAPolicy | null>(null);
  const [selectedPolicies, setSelectedPolicies] = useState<SLAPolicy[]>([]);
  const [selectedBreaches, setSelectedBreaches] = useState<SLABreach[]>([]);
  const [policySearch, setPolicySearch] = useState('');
  const [breachSearch, setBreachSearch] = useState('');
  const [breachStatus, setBreachStatus] = useState('all');

  const summaryQuery = useQuery({
    queryKey: ['sla-summary', { siteId: selectedSiteId }],
    queryFn: () => slaApi.getSummary({ ...(selectedSiteId ? { site_id: selectedSiteId } : {}) }),
    refetchInterval: 30000,
  });

  const policiesQuery = useQuery({
    queryKey: ['sla-policies', { siteId: selectedSiteId }],
    queryFn: () => slaApi.listPolicies({ limit: 100, ...(selectedSiteId ? { site_id: selectedSiteId } : {}) }),
  });

  const breachesQuery = useQuery({
    queryKey: ['sla-breaches', { siteId: selectedSiteId }],
    queryFn: () => slaApi.listBreaches({ limit: 100, ...(selectedSiteId ? { site_id: selectedSiteId } : {}) }),
  });

  const createPolicyMutation = useMutation({
    mutationFn: (data: Partial<SLAPolicy>) => slaApi.createPolicy(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['sla-policies'] });
      queryClient.invalidateQueries({ queryKey: ['sla-summary'] });
      setShowCreateDialog(false);
    },
    // Errors propagate to FormDialog's banner via mutateAsync rejection.
  });

  const updatePolicyMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<SLAPolicy> }) => slaApi.updatePolicy(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['sla-policies'] });
      queryClient.invalidateQueries({ queryKey: ['sla-summary'] });
      setEditPolicy(null);
    },
    // Errors propagate to FormDialog's banner via mutateAsync rejection.
  });

  const deletePolicyMutation = useMutation({
    mutationFn: (policyId: string) => slaApi.deletePolicy(policyId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['sla-policies'] });
      queryClient.invalidateQueries({ queryKey: ['sla-summary'] });
    },
    onError: (err: any) => {
      toast({ title: t('SLAPage.toast.errorTitle'), description: err?.response?.data?.detail || err?.message || t('SLAPage.toast.operationFailed'), variant: 'destructive' });
    },
  });

  // Bulk-delete: confirm, then run per-row deletes and report a single summary
  // toast (n ok / m failed) so partial failures aren't masked as success.
  const handleBulkDeletePolicies = async () => {
    if (selectedPolicies.length === 0) return;
    if (!window.confirm(t('SLAPage.actions.delete') + ` (${selectedPolicies.length})`)) return;
    const results = await Promise.allSettled(
      selectedPolicies.map((p) => slaApi.deletePolicy(p.id)),
    );
    const failed = results.filter((r) => r.status === 'rejected').length;
    const ok = results.length - failed;
    queryClient.invalidateQueries({ queryKey: ['sla-policies'] });
    queryClient.invalidateQueries({ queryKey: ['sla-summary'] });
    setSelectedPolicies([]);
    toast({
      title: t('SLAPage.actions.delete'),
      description: `${ok} ✓ / ${failed} ✗`,
      variant: failed > 0 ? 'destructive' : 'default',
    });
  };

  const handleDeletePolicy = (policy: SLAPolicy) => {
    if (!window.confirm(t('SLAPage.actions.delete') + `, ${policy.name}`)) return;
    deletePolicyMutation.mutate(policy.id, {
      onSuccess: () => setSelectedPolicy(null),
    });
  };

  const acknowledgeBreachMutation = useMutation({
    mutationFn: (breachId: string) => slaApi.acknowledgeBreach(breachId),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['sla-breaches'] }),
    onError: (err: any) => {
      toast({ title: t('SLAPage.toast.errorTitle'), description: err?.response?.data?.detail || err?.message || t('SLAPage.toast.operationFailed'), variant: 'destructive' });
    },
  });

  const evaluateMutation = useMutation({
    mutationFn: () => slaApi.evaluate(),
    onSuccess: (res: any) => {
      queryClient.invalidateQueries({ queryKey: ['sla-summary'] });
      queryClient.invalidateQueries({ queryKey: ['sla-policies'] });
      queryClient.invalidateQueries({ queryKey: ['sla-breaches'] });
      const r = res?.data ?? {};
      const evaluated = r.policies_evaluated ?? 0;
      const created = r.breaches_created ?? 0;
      const resolved = r.breaches_resolved ?? 0;
      // Surface the returned counts (no SLAPage-namespace prose key exists, so
      // reuse the action label as the title and report counts with stat labels).
      toast({
        title: t('SLAPage.actions.evaluateNow'),
        description: `${t('SLAPage.tabs.policies', { count: evaluated })} · ${t('SLAPage.stats.activeBreaches.title')}: +${created} / -${resolved}`,
      });
    },
    onError: (err: any) => {
      toast({ title: t('SLAPage.toast.errorTitle'), description: err?.response?.data?.detail || err?.message || t('SLAPage.toast.operationFailed'), variant: 'destructive' });
    },
  });

  // SLA Policy form schema. Threshold strings stay as strings so we can
  // distinguish "unset" (empty) from "0".
  const slaPolicySchema = z.object({
    name: z.string().min(1, t('SLAPage.form.nameRequired')),
    scope: z.string(),
    scope_id: z.string(),
    scope_name: z.string(),
    window: z.coerce.number().int().positive(),
    health_min: z.string(),
    uptime_min: z.string(),
    latency_max: z.string(),
  });
  type SLAPolicyFormValues = z.infer<typeof slaPolicySchema>;
  const slaPolicyDefaults: SLAPolicyFormValues = {
    name: '',
    scope: 'site',
    scope_id: '',
    scope_name: '',
    window: 15,
    health_min: '80',
    uptime_min: '99.5',
    latency_max: '',
  };

  // Edit-thresholds form: name + eval window + the three threshold metrics.
  const slaThresholdsSchema = z.object({
    name: z.string().min(1, t('SLAPage.form.nameRequired')),
    window: z.coerce.number().int().positive(),
    health_min: z.string(),
    uptime_min: z.string(),
    latency_max: z.string(),
  });
  type SLAThresholdsFormValues = z.infer<typeof slaThresholdsSchema>;
  const editThresholdsDefaults: SLAThresholdsFormValues = editPolicy
    ? {
        name: editPolicy.name,
        window: editPolicy.evaluation_window_minutes,
        health_min: editPolicy.thresholds?.health_score_min != null ? String(editPolicy.thresholds.health_score_min) : '',
        uptime_min: editPolicy.thresholds?.uptime_percent_min != null ? String(editPolicy.thresholds.uptime_percent_min) : '',
        latency_max: editPolicy.thresholds?.latency_ms_max != null ? String(editPolicy.thresholds.latency_ms_max) : '',
      }
    : { name: '', window: 15, health_min: '', uptime_min: '', latency_max: '' };

  const summary = summaryQuery.data?.data;
  const allPolicies = useMemo(() => policiesQuery.data?.data?.policies || [], [policiesQuery.data]);
  const allBreaches = useMemo(() => breachesQuery.data?.data?.breaches || [], [breachesQuery.data]);

  const policies = useMemo(() => {
    if (!policySearch) return allPolicies;
    const q = policySearch.toLowerCase();
    return allPolicies.filter(
      (p) => p.name.toLowerCase().includes(q) || (p.scope_name || '').toLowerCase().includes(q),
    );
  }, [allPolicies, policySearch]);

  const breaches = useMemo(() => {
    let list = allBreaches;
    if (breachStatus !== 'all') list = list.filter((b) => b.status === breachStatus);
    if (breachSearch) {
      const q = breachSearch.toLowerCase();
      list = list.filter((b) => b.violated_metric.toLowerCase().includes(q));
    }
    return list;
  }, [allBreaches, breachSearch, breachStatus]);

  const hasQueryError = summaryQuery.isError || policiesQuery.isError || breachesQuery.isError;

  const policyColumns: DataTableColumn<SLAPolicy>[] = [
    { id: 'name', header: t('SLAPage.columns.name'), accessorKey: 'name' },
    {
      id: 'status',
      header: t('SLAPage.columns.status'),
      accessorKey: 'status',
      cell: (row) => (
        <StatusBadge variant={row.status === 'active' ? 'success' : 'neutral'}>
          {row.status}
        </StatusBadge>
      ),
    },
    {
      id: 'scope',
      header: t('SLAPage.columns.scope'),
      accessorKey: 'scope',
      cell: (row) => <TypeBadge type={row.scope} />,
    },
    { id: 'scope_name', header: t('SLAPage.columns.target'), accessorKey: 'scope_name', cell: (row) => row.scope_name || '-' },
    {
      id: 'compliance',
      header: t('SLAPage.columns.compliance'),
      accessorKey: 'current_compliance_percent',
      cell: (row) => <ComplianceGauge value={row.current_compliance_percent} />,
    },
    {
      id: 'last_evaluated',
      header: t('SLAPage.columns.lastEvaluated'),
      accessorKey: 'last_evaluated_at',
      cell: (row) => row.last_evaluated_at
        ? new Date(row.last_evaluated_at).toLocaleString()
        : t('SLAPage.columns.never'),
    },
    {
      id: 'actions',
      header: '',
      sortable: false,
      cell: (row) => (
        <Button variant="ghost" size="sm" onClick={() => setSelectedPolicy(row)}>
          <Eye className="h-4 w-4" />
        </Button>
      ),
    },
  ];

  const breachColumns: DataTableColumn<SLABreach>[] = [
    {
      id: 'severity',
      header: t('SLAPage.columns.severity'),
      accessorKey: 'severity',
      cell: (row) => (
        <StatusBadge variant={SEVERITY_VARIANT[row.severity] || 'severity_info'} />
      ),
    },
    { id: 'violated_metric', header: t('SLAPage.columns.metric'), accessorKey: 'violated_metric' },
    {
      id: 'threshold',
      header: t('SLAPage.columns.threshold'),
      accessorKey: 'threshold_value',
      cell: (row) => <span className="font-mono">{row.threshold_value}</span>,
    },
    {
      id: 'actual',
      header: t('SLAPage.columns.actual'),
      accessorKey: 'actual_value',
      cell: (row) => (
        <span className="font-mono text-destructive">
          {row.actual_value.toFixed(2)}
        </span>
      ),
    },
    {
      id: 'deviation',
      header: t('SLAPage.columns.deviation'),
      accessorKey: 'deviation_percent',
      cell: (row) => <span className="font-mono">{row.deviation_percent.toFixed(1)}%</span>,
    },
    {
      id: 'status',
      header: t('SLAPage.columns.status'),
      accessorKey: 'status',
      cell: (row) => (
        <StatusBadge variant={BREACH_STATUS_VARIANT[row.status] || 'neutral'}>
          {row.status}
        </StatusBadge>
      ),
    },
    {
      id: 'started_at',
      header: t('SLAPage.columns.started'),
      accessorKey: 'started_at',
      cell: (row) => new Date(row.started_at).toLocaleString(),
    },
    {
      id: 'actions',
      header: '',
      sortable: false,
      cell: (row) =>
        row.status === 'active' ? (
          <Button
            variant="ghost"
            size="sm"
            onClick={() => acknowledgeBreachMutation.mutate(row.id)}
          >
            {t('SLAPage.actions.acknowledge')}
          </Button>
        ) : null,
    },
  ];

  if (hasQueryError && !summary && allPolicies.length === 0) {
    return (
      <div className="space-y-6">
        <PageHeader
          icon={Shield}
          title={t('SLAPage.header.title')}
          description={t('SLAPage.header.description')}
        />
        <ErrorState
          message={t('SLAPage.errorState.message')}
          onRetry={() => { summaryQuery.refetch(); policiesQuery.refetch(); breachesQuery.refetch(); }}
        />
      </div>
    );
  }

  const policySearchActive = policySearch !== '';
  const breachFiltersActive = breachSearch !== '' || breachStatus !== 'all';

  return (
    <div className="space-y-6">
      <PageHeader
        icon={Shield}
        title={t('SLAPage.header.title')}
        description={t('SLAPage.header.description')}
        onRefresh={() => { summaryQuery.refetch(); policiesQuery.refetch(); breachesQuery.refetch(); }}
        refreshing={summaryQuery.isFetching || policiesQuery.isFetching}
        secondaryActions={[
          {
            label: t('SLAPage.actions.evaluateNow'),
            icon: RefreshCw,
            onClick: () => evaluateMutation.mutate(),
            loading: evaluateMutation.isPending,
          },
        ]}
        primaryAction={{ label: t('SLAPage.actions.newPolicy'), icon: Plus, onClick: () => setShowCreateDialog(true) }}
      />

      <StatsGrid
        columns={4}
        isLoading={summaryQuery.isLoading}
        stats={[
          { title: t('SLAPage.stats.activePolicies.title'), value: summary?.active_policies ?? 0, icon: Shield, variant: 'default', description: t('SLAPage.stats.activePolicies.description') },
          { title: t('SLAPage.stats.activeBreaches.title'), value: summary?.active_breaches ?? 0, icon: AlertTriangle, variant: 'destructive', description: t('SLAPage.stats.activeBreaches.description') },
          { title: t('SLAPage.stats.avgCompliance.title'), value: summary?.avg_compliance_percent != null ? `${summary.avg_compliance_percent.toFixed(1)}%` : t('SLAPage.stats.notAvailable'), icon: Gauge, variant: 'success', description: t('SLAPage.stats.avgCompliance.description') },
          { title: t('SLAPage.stats.breaches24h.title'), value: summary?.breaches_last_24h ?? 0, icon: XCircle, variant: 'default', description: t('SLAPage.stats.breaches24h.description') },
        ]}
      />

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          <TabsTrigger value="overview">{t('SLAPage.tabs.overview')}</TabsTrigger>
          <TabsTrigger value="policies">{t('SLAPage.tabs.policies', { count: allPolicies.length })}</TabsTrigger>
          <TabsTrigger value="breaches">{t('SLAPage.tabs.breaches', { count: allBreaches.length })}</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-4">
          {summaryQuery.isLoading && (
            <div className="space-y-4">
              <Skeleton className="h-24 rounded-xl" />
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {Array.from({ length: 6 }).map((_, i) => (
                  <Skeleton key={i} className="h-32 rounded-xl" />
                ))}
              </div>
            </div>
          )}
          {summary?.worst_policy && (
            <Card className="border-destructive/30">
              <CardHeader>
                <CardTitle className="text-sm text-destructive flex items-center gap-2">
                  <AlertTriangle className="h-4 w-4" /> {t('SLAPage.overview.worstPerforming')}
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="flex items-center justify-between">
                  <div>
                    <p className="font-medium">{summary.worst_policy.name}</p>
                    <p className="text-sm text-muted-foreground">{summary.worst_policy.scope}: {summary.worst_policy.scope_name || '-'}</p>
                  </div>
                  <ComplianceGauge value={summary.worst_policy.current_compliance_percent} />
                </div>
              </CardContent>
            </Card>
          )}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {allPolicies.filter(p => p.status === 'active').slice(0, 6).map(policy => (
              <Card key={policy.id} className="cursor-pointer hover:border-primary/50 transition-colors" onClick={() => setSelectedPolicy(policy)}>
                <CardContent noOffset>
                  <div className="flex justify-between items-start mb-2">
                    <div>
                      <p className="font-medium">{policy.name}</p>
                      <p className="text-xs text-muted-foreground">{policy.scope}: {policy.scope_name || '-'}</p>
                    </div>
                    <StatusBadge variant={policy.status === 'active' ? 'success' : 'neutral'}>{policy.status}</StatusBadge>
                  </div>
                  <ComplianceGauge value={policy.current_compliance_percent} />
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>

        <TabsContent value="policies" className="space-y-4">
          <PageToolbar>
            <SearchBar
              value={policySearch}
              onChange={setPolicySearch}
              placeholder={t('SLAPage.policies.searchPlaceholder')}
              className="w-full sm:w-auto"
            />
            {policySearchActive && (
              <Button variant="ghost" size="sm" onClick={() => setPolicySearch('')}>
                {t('SLAPage.actions.clearFilters')}
              </Button>
            )}
          </PageToolbar>
          <DataTable
            columns={policyColumns}
            data={policies}
            isLoading={policiesQuery.isLoading}
            selectable
            onSelectionChange={setSelectedPolicies}
            searchable={false}
            getRowId={(r) => r.id}
            itemName={t('SLAPage.itemNames.policies')}
          />
          <BulkActionsBar
            selectedCount={selectedPolicies.length}
            itemName={t('SLAPage.itemNames.policy')}
            onClear={() => setSelectedPolicies([])}
            actions={[
              {
                label: t('SLAPage.actions.editThresholds'),
                icon: Settings,
                // Threshold edits are per-policy; only enabled for a single selection.
                disabled: selectedPolicies.length !== 1,
                onClick: () => { if (selectedPolicies.length === 1) setEditPolicy(selectedPolicies[0]); },
              },
              {
                label: t('SLAPage.actions.delete'),
                icon: Trash2,
                variant: 'destructive',
                onClick: handleBulkDeletePolicies,
              },
            ]}
          />
        </TabsContent>

        <TabsContent value="breaches" className="space-y-4">
          <PageToolbar>
            <SearchBar
              value={breachSearch}
              onChange={setBreachSearch}
              placeholder={t('SLAPage.breaches.searchPlaceholder')}
              className="w-full sm:w-auto"
            />
            <Select value={breachStatus} onValueChange={setBreachStatus}>
              <SelectTrigger className="w-full sm:w-[160px]"><SelectValue placeholder={t('SLAPage.breaches.allStatuses')} /></SelectTrigger>
              <SelectContent>
                <SelectItem value="all">{t('SLAPage.breaches.allStatuses')}</SelectItem>
                <SelectItem value="active">{t('SLAPage.breaches.statusActive')}</SelectItem>
                <SelectItem value="acknowledged">{t('SLAPage.breaches.statusAcknowledged')}</SelectItem>
                <SelectItem value="resolved">{t('SLAPage.breaches.statusResolved')}</SelectItem>
              </SelectContent>
            </Select>
            {breachFiltersActive && (
              <Button variant="ghost" size="sm" onClick={() => { setBreachSearch(''); setBreachStatus('all'); }}>
                {t('SLAPage.actions.clearFilters')}
              </Button>
            )}
          </PageToolbar>
          <DataTable
            columns={breachColumns}
            data={breaches}
            isLoading={breachesQuery.isLoading}
            selectable
            onSelectionChange={setSelectedBreaches}
            searchable={false}
            getRowId={(r) => r.id}
            itemName={t('SLAPage.itemNames.breaches')}
          />
          <BulkActionsBar
            selectedCount={selectedBreaches.length}
            itemName={t('SLAPage.itemNames.breach')}
            onClear={() => setSelectedBreaches([])}
            actions={[
              {
                label: t('SLAPage.actions.acknowledge'),
                icon: Check,
                onClick: () => {
                  selectedBreaches.forEach((b) => acknowledgeBreachMutation.mutate(b.id));
                  setSelectedBreaches([]);
                },
              },
            ]}
          />
        </TabsContent>
      </Tabs>

      {/* Policy Detail Dialog */}
      <Dialog open={!!selectedPolicy} onOpenChange={(open) => !open && setSelectedPolicy(null)}>
        <DialogContent className="max-w-lg">
          <DialogHeader><DialogTitle>{selectedPolicy?.name}</DialogTitle></DialogHeader>
          {selectedPolicy && (
            <div className="space-y-4 text-sm">
              <ComplianceGauge value={selectedPolicy.current_compliance_percent} />
              <div className="grid grid-cols-2 gap-3">
                <div><span className="text-muted-foreground">{t('SLAPage.detail.scope')}</span> {selectedPolicy.scope}</div>
                <div><span className="text-muted-foreground">{t('SLAPage.detail.target')}</span> {selectedPolicy.scope_name || '-'}</div>
                <div><span className="text-muted-foreground">{t('SLAPage.detail.evalWindow')}</span> {t('SLAPage.detail.minutes', { count: selectedPolicy.evaluation_window_minutes })}</div>
                <div><span className="text-muted-foreground">{t('SLAPage.detail.consecutive')}</span> {selectedPolicy.breach_after_consecutive}</div>
              </div>
              <div>
                <Label className="mb-2 block">{t('SLAPage.detail.thresholds')}</Label>
                <div className="bg-muted rounded-md p-3 space-y-1">
                  {Object.entries(selectedPolicy.thresholds || {}).map(([key, val]) => (
                    <div key={key} className="flex justify-between">
                      <span className="text-muted-foreground">{key.replace(/_/g, ' ')}</span>
                      <span className="font-mono">{String(val)}</span>
                    </div>
                  ))}
                </div>
              </div>
              {selectedPolicy.last_evaluated_at && (
                <p className="text-xs text-muted-foreground">
                  {t('SLAPage.detail.lastEvaluated', { date: new Date(selectedPolicy.last_evaluated_at).toLocaleString() })}
                </p>
              )}
            </div>
          )}
          {selectedPolicy && (
            <DialogFooter>
              <Button
                variant="destructive"
                onClick={() => handleDeletePolicy(selectedPolicy)}
                disabled={deletePolicyMutation.isPending}
              >
                <Trash2 className="h-4 w-4 mr-2" />
                {t('SLAPage.actions.delete')}
              </Button>
              <Button
                onClick={() => { setEditPolicy(selectedPolicy); setSelectedPolicy(null); }}
              >
                <Settings className="h-4 w-4 mr-2" />
                {t('SLAPage.actions.editThresholds')}
              </Button>
            </DialogFooter>
          )}
        </DialogContent>
      </Dialog>

      {/* Create Policy Dialog */}
      <FormDialog<SLAPolicyFormValues>
        open={showCreateDialog}
        onOpenChange={setShowCreateDialog}
        title={t('SLAPage.dialog.newPolicyTitle')}
        schema={slaPolicySchema}
        defaultValues={slaPolicyDefaults}
        submitLabel={t('SLAPage.dialog.createPolicy')}
        onSubmit={async (values) => {
          const thresholds: Record<string, number> = {};
          if (values.health_min) thresholds.health_score_min = Number(values.health_min);
          if (values.uptime_min) thresholds.uptime_percent_min = Number(values.uptime_min);
          if (values.latency_max) thresholds.latency_ms_max = Number(values.latency_max);
          await createPolicyMutation.mutateAsync({
            name: values.name,
            scope: values.scope,
            scope_id: values.scope_id || undefined,
            scope_name: values.scope_name || undefined,
            thresholds,
            evaluation_window_minutes: values.window,
          } as any);
        }}
      >
        {(form) => {
          const scope = form.watch('scope');
          return (
            <>
              <FormField
                control={form.control}
                name="name"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>{t('SLAPage.form.name')}</FormLabel>
                    <FormControl>
                      <Input placeholder={t('SLAPage.form.namePlaceholder')} {...field} />
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
                      <FormLabel>{t('SLAPage.form.scope')}</FormLabel>
                      <Select value={field.value} onValueChange={field.onChange}>
                        <FormControl>
                          <SelectTrigger><SelectValue /></SelectTrigger>
                        </FormControl>
                        <SelectContent>
                          <SelectItem value="organization">{t('SLAPage.form.scopeOptions.organization')}</SelectItem>
                          <SelectItem value="site">{t('SLAPage.form.scopeOptions.site')}</SelectItem>
                          <SelectItem value="site_group">{t('SLAPage.form.scopeOptions.siteGroup')}</SelectItem>
                          <SelectItem value="device_group">{t('SLAPage.form.scopeOptions.deviceGroup')}</SelectItem>
                          <SelectItem value="ssid">{t('SLAPage.form.scopeOptions.ssid')}</SelectItem>
                        </SelectContent>
                      </Select>
                      <FormMessage />
                    </FormItem>
                  )}
                />
                <FormField
                  control={form.control}
                  name="window"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>{t('SLAPage.form.evalWindow')}</FormLabel>
                      <FormControl>
                        <Input type="number" {...field} />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
              </div>
              {scope !== 'organization' && (
                <div className="grid grid-cols-2 gap-4">
                  <FormField
                    control={form.control}
                    name="scope_id"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>{t('SLAPage.form.scopeId')}</FormLabel>
                        <FormControl>
                          <Input placeholder={t('SLAPage.form.scopeIdPlaceholder')} {...field} />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                  <FormField
                    control={form.control}
                    name="scope_name"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>{t('SLAPage.form.scopeName')}</FormLabel>
                        <FormControl>
                          <Input placeholder={t('SLAPage.form.scopeNamePlaceholder')} {...field} />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                </div>
              )}
              <div>
                <Label className="mb-2 block">{t('SLAPage.detail.thresholds')}</Label>
                <div className="space-y-2">
                  <FormField
                    control={form.control}
                    name="health_min"
                    render={({ field }) => (
                      <FormItem className="flex items-center gap-2 space-y-0">
                        <FormLabel className="w-40 text-xs">{t('SLAPage.form.healthScoreMin')}</FormLabel>
                        <FormControl>
                          <Input type="number" className="flex-1" {...field} />
                        </FormControl>
                      </FormItem>
                    )}
                  />
                  <FormField
                    control={form.control}
                    name="uptime_min"
                    render={({ field }) => (
                      <FormItem className="flex items-center gap-2 space-y-0">
                        <FormLabel className="w-40 text-xs">{t('SLAPage.form.uptimePercentMin')}</FormLabel>
                        <FormControl>
                          <Input type="number" className="flex-1" {...field} />
                        </FormControl>
                      </FormItem>
                    )}
                  />
                  <FormField
                    control={form.control}
                    name="latency_max"
                    render={({ field }) => (
                      <FormItem className="flex items-center gap-2 space-y-0">
                        <FormLabel className="w-40 text-xs">{t('SLAPage.form.latencyMsMax')}</FormLabel>
                        <FormControl>
                          <Input type="number" placeholder={t('SLAPage.form.optional')} className="flex-1" {...field} />
                        </FormControl>
                      </FormItem>
                    )}
                  />
                </div>
              </div>
            </>
          );
        }}
      </FormDialog>

      {/* Edit Thresholds Dialog */}
      <FormDialog<SLAThresholdsFormValues>
        open={!!editPolicy}
        onOpenChange={(open) => !open && setEditPolicy(null)}
        title={t('SLAPage.actions.editThresholds')}
        schema={slaThresholdsSchema}
        defaultValues={editThresholdsDefaults}
        onSubmit={async (values) => {
          if (!editPolicy) return;
          const thresholds: Record<string, number> = {};
          if (values.health_min) thresholds.health_score_min = Number(values.health_min);
          if (values.uptime_min) thresholds.uptime_percent_min = Number(values.uptime_min);
          if (values.latency_max) thresholds.latency_ms_max = Number(values.latency_max);
          await updatePolicyMutation.mutateAsync({
            id: editPolicy.id,
            data: {
              name: values.name,
              thresholds,
              evaluation_window_minutes: values.window,
            } as Partial<SLAPolicy>,
          });
        }}
      >
        {(form) => (
          <>
            <FormField
              control={form.control}
              name="name"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>{t('SLAPage.form.name')}</FormLabel>
                  <FormControl>
                    <Input placeholder={t('SLAPage.form.namePlaceholder')} {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <FormField
              control={form.control}
              name="window"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>{t('SLAPage.form.evalWindow')}</FormLabel>
                  <FormControl>
                    <Input type="number" {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <div>
              <Label className="mb-2 block">{t('SLAPage.detail.thresholds')}</Label>
              <div className="space-y-2">
                <FormField
                  control={form.control}
                  name="health_min"
                  render={({ field }) => (
                    <FormItem className="flex items-center gap-2 space-y-0">
                      <FormLabel className="w-40 text-xs">{t('SLAPage.form.healthScoreMin')}</FormLabel>
                      <FormControl>
                        <Input type="number" className="flex-1" {...field} />
                      </FormControl>
                    </FormItem>
                  )}
                />
                <FormField
                  control={form.control}
                  name="uptime_min"
                  render={({ field }) => (
                    <FormItem className="flex items-center gap-2 space-y-0">
                      <FormLabel className="w-40 text-xs">{t('SLAPage.form.uptimePercentMin')}</FormLabel>
                      <FormControl>
                        <Input type="number" className="flex-1" {...field} />
                      </FormControl>
                    </FormItem>
                  )}
                />
                <FormField
                  control={form.control}
                  name="latency_max"
                  render={({ field }) => (
                    <FormItem className="flex items-center gap-2 space-y-0">
                      <FormLabel className="w-40 text-xs">{t('SLAPage.form.latencyMsMax')}</FormLabel>
                      <FormControl>
                        <Input type="number" placeholder={t('SLAPage.form.optional')} className="flex-1" {...field} />
                      </FormControl>
                    </FormItem>
                  )}
                />
              </div>
            </div>
          </>
        )}
      </FormDialog>
    </div>
  );
}

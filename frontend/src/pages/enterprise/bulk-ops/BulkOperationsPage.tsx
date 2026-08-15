// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN Enterprise · Bulk Operations
 *
 * Create, monitor, and manage bulk operations (push_config, reboot, firmware_update)
 * with staged rollout support, progress tracking, and failure threshold.
 */

import { useState, useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  PlayCircle,
  Plus,
  StopCircle,
  CheckCircle2,
  AlertOctagon,
  Loader2,
  ListChecks,
} from 'lucide-react';
import { PageHeader, PageToolbar } from '@/components/layout';
import { StatsGrid } from '@/components/ui/stats-grid';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Progress } from '@/components/ui/progress';
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
import { Switch } from '@/components/ui/switch';
import { DataTable, type DataTableColumn } from '@/components/ui/data-table';
import { StatusBadge, type StatusVariant } from '@/components/ui/status-indicator';
import { TypeBadge } from '@/components/ui/type-badge';
import { BulkActionsBar } from '@/components/ui/bulk-actions-bar';
import { ErrorState } from '@/components/ui/empty-state';
import { SearchBar } from '@/components/ui/search-bar';
import { enterpriseApi, type BulkOperation } from '@/lib/api';
import { useToast } from '@/hooks/use-toast';

// Map bulk-op status → canonical StatusBadge variant
const STATUS_VARIANT: Record<string, StatusVariant> = {
  pending: 'pending',
  running: 'syncing',
  paused: 'warning',
  completed: 'success',
  failed: 'error',
  cancelled: 'neutral',
  rolling_back: 'warning',
  rolled_back: 'warning',
};

// Builds the localized status-label map. Status keys mirror the backend
// enum values; only the human-readable labels are translated.
const buildStatusLabel = (t: (key: string) => string): Record<string, string> => ({
  pending: t('BulkOperationsPage.status.pending'),
  running: t('BulkOperationsPage.status.running'),
  paused: t('BulkOperationsPage.status.paused'),
  completed: t('BulkOperationsPage.status.completed'),
  failed: t('BulkOperationsPage.status.failed'),
  cancelled: t('BulkOperationsPage.status.cancelled'),
  rolling_back: t('BulkOperationsPage.status.rollingBack'),
  rolled_back: t('BulkOperationsPage.status.rolledBack'),
});

export default function BulkOperationsPage() {
  const { t } = useTranslation('enterprise');
  const { toast } = useToast();
  const STATUS_LABEL = useMemo(() => buildStatusLabel(t), [t]);
  const [showCreate, setShowCreate] = useState(false);
  const [filterStatus, setFilterStatus] = useState('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedOps, setSelectedOps] = useState<BulkOperation[]>([]);
  const [selectedJob, setSelectedJob] = useState<BulkOperation | null>(null);
  const queryClient = useQueryClient();
  // Bulk-ops live at the org level; per-site filtering happens via the
  // create form's ``target.scope_id`` instead. Keeping the import as a
  // default-import for ``useSiteStore`` would trigger an unused-symbol
  // lint, so we drop it entirely.

  // Form state
  const [form, setForm] = useState({
    operation: 'push_config',
    scope: 'site',
    scope_id: '',
    device_type: '',
    tag: '',
    device_ids: '',
    config: '{}',
    strategy: 'immediate',
    stages: '[\n  { "percent": 10, "wait_minutes": 15 },\n  { "percent": 50, "wait_minutes": 30 },\n  { "percent": 100, "wait_minutes": 0 }\n]',
    failure_threshold: 5,
    rollback_on_failure: true,
  });

  // Bulk operations are organization-scoped (the backend has no site
  // filter on the list endpoint); keeping ``siteId`` in the queryKey
  // was misleading, it split the cache per site but the data was
  // identical. Removed so what the user sees matches what the cache
  // holds.
  const { data: operations, isLoading, isError, refetch } = useQuery({
    queryKey: ['enterprise', 'bulk-operations', filterStatus],
    queryFn: () => enterpriseApi.listBulkOperations(
      filterStatus !== 'all' ? { status: filterStatus } : undefined,
    ).then(r => r.data),
    refetchInterval: 5000,
  });

  const errToast = (title: string) => (err: unknown) => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const detail = (err as any)?.response?.data?.detail
      || (err instanceof Error ? err.message : t('BulkOperationsPage.toasts.unknownError'));
    toast({ variant: 'destructive', title, description: String(detail) });
  };

  const createMutation = useMutation({
    mutationFn: (data: Parameters<typeof enterpriseApi.createBulkOperation>[0]) =>
      enterpriseApi.createBulkOperation(data),
    onSuccess: (res) => {
      queryClient.invalidateQueries({ queryKey: ['enterprise', 'bulk-operations'] });
      setShowCreate(false);
      toast({
        title: t('BulkOperationsPage.toasts.queued.title'),
        description: t('BulkOperationsPage.toasts.queued.description', {
          operation: res.data.operation.replace('_', ' '),
          count: res.data.devices_total,
        }),
      });
    },
    onError: errToast(t('BulkOperationsPage.toasts.createFailed')),
  });

  const cancelMutation = useMutation({
    mutationFn: (jobId: string) => enterpriseApi.cancelBulkOperation(jobId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['enterprise', 'bulk-operations'] });
      toast({ title: t('BulkOperationsPage.toasts.cancelRequested') });
    },
    onError: errToast(t('BulkOperationsPage.toasts.cancelFailed')),
  });

  // Fetch full job detail (including error_message + timestamps) when
  // the row dialog is open. List rows used to *be* the detail source,
  // which left the existing GET endpoint orphaned and hid error_message.
  const { data: jobDetail } = useQuery({
    queryKey: ['enterprise', 'bulk-operations', 'detail', selectedJob?.job_id],
    queryFn: () => enterpriseApi.getBulkOperation(selectedJob!.job_id).then(r => r.data),
    enabled: !!selectedJob?.job_id,
    refetchInterval: selectedJob && (selectedJob.status === 'pending' || selectedJob.status === 'running') ? 3000 : false,
  });

  function handleCreate() {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    let config: Record<string, any> | undefined;
    let stages: Array<{ percent: number; wait_minutes?: number }> | undefined;
    try {
      if (form.operation === 'push_config') config = JSON.parse(form.config);
      if (form.strategy === 'staged') stages = JSON.parse(form.stages);
    } catch { toast({ title: t('BulkOperationsPage.toasts.error'), description: t('BulkOperationsPage.toasts.invalidJson'), variant: 'destructive' }); return; }

    // Split the device-list textarea on newlines and/or commas, trimming
    // whitespace and dropping empties. Only attached to the target when
    // scope === 'device_list' (the only scope the backend reads it for).
    const deviceIds = form.device_ids
      .split(/[\n,]+/)
      .map(id => id.trim())
      .filter(Boolean);

    createMutation.mutate({
      operation: form.operation,
      target: {
        scope: form.scope,
        scope_id: form.scope_id || undefined,
        device_type: form.device_type || undefined,
        tag: form.tag || undefined,
        device_ids: form.scope === 'device_list' && deviceIds.length > 0 ? deviceIds : undefined,
      },
      config,
      rollout: {
        strategy: form.strategy,
        stages,
        failure_threshold_percent: form.failure_threshold,
        rollback_on_failure: form.rollback_on_failure,
      },
    });
  }

  const allOps = useMemo(() => operations ?? [], [operations]);
  const filteredOps = useMemo(() => {
    if (!searchQuery) return allOps;
    const q = searchQuery.toLowerCase();
    return allOps.filter(
      (o) =>
        o.job_id.toLowerCase().includes(q) ||
        o.operation.toLowerCase().includes(q) ||
        o.status.toLowerCase().includes(q),
    );
  }, [allOps, searchQuery]);

  const statusCounts = allOps.reduce((acc, op) => {
    acc[op.status] = (acc[op.status] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  const hasActiveFilters = searchQuery !== '' || filterStatus !== 'all';

  const columns: DataTableColumn<BulkOperation>[] = [
    {
      id: 'job_id', header: t('BulkOperationsPage.columns.jobId'), accessorKey: 'job_id',
      cell: (r) => <span className="font-mono text-xs">{r.job_id.slice(0, 8)}...</span>,
    },
    {
      id: 'operation', header: t('BulkOperationsPage.columns.operation'), accessorKey: 'operation', sortable: true,
      cell: (r) => <TypeBadge type={r.operation.replace('_', ' ')} />,
    },
    {
      id: 'status', header: t('BulkOperationsPage.columns.status'), accessorKey: 'status', sortable: true,
      cell: (r) => (
        <StatusBadge variant={STATUS_VARIANT[r.status] || 'neutral'}>
          {STATUS_LABEL[r.status] || r.status}
        </StatusBadge>
      ),
    },
    {
      id: 'progress', header: t('BulkOperationsPage.columns.progress'),
      cell: (r) => {
        const pct = r.devices_total > 0 ? Math.round((r.devices_completed / r.devices_total) * 100) : 0;
        return (
          <div className="flex items-center gap-3 min-w-[180px]">
            <Progress value={pct} className="flex-1" />
            <span className="text-xs text-muted-foreground whitespace-nowrap">
              {r.devices_completed}/{r.devices_total}
              {r.devices_failed > 0 && <span className="text-destructive ml-1">({t('BulkOperationsPage.table.failedCount', { count: r.devices_failed })})</span>}
            </span>
          </div>
        );
      },
    },
    {
      id: 'stage', header: t('BulkOperationsPage.columns.stage'), accessorKey: 'current_stage',
      cell: (r) => r.current_stage > 0 ? <span className="text-sm">{t('BulkOperationsPage.table.stage', { stage: r.current_stage })}</span> : <span className="text-muted-foreground">-</span>,
    },
    {
      id: 'created', header: t('BulkOperationsPage.columns.created'), accessorKey: 'created_at', sortable: true,
      cell: (r) => <span className="text-sm text-muted-foreground">{new Date(r.created_at).toLocaleString()}</span>,
    },
    {
      id: 'actions', header: '', sortable: false,
      cell: (r) => (
        <div className="flex items-center gap-1 justify-end">
          <Button variant="ghost" size="sm" onClick={() => setSelectedJob(r)}>{t('BulkOperationsPage.actions.details')}</Button>
          {(r.status === 'pending' || r.status === 'running') && (
            <Button variant="ghost" size="sm" className="text-destructive" onClick={() => cancelMutation.mutate(r.job_id)}>
              <StopCircle className="h-4 w-4 mr-1" /> {t('BulkOperationsPage.actions.cancel')}
            </Button>
          )}
        </div>
      ),
    },
  ];

  if (isError) {
    return (
      <div className="space-y-6">
        <PageHeader icon={PlayCircle} title={t('BulkOperationsPage.title')} description={t('BulkOperationsPage.description')} />
        <ErrorState message={t('BulkOperationsPage.errorState.message')} onRetry={() => refetch()} />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader
        icon={PlayCircle}
        title={t('BulkOperationsPage.title')}
        description={t('BulkOperationsPage.description')}
        onRefresh={() => refetch()}
        refreshing={isLoading}
        primaryAction={{ label: t('BulkOperationsPage.actions.newOperation'), icon: Plus, onClick: () => setShowCreate(true) }}
      />

      <StatsGrid
        columns={4}
        isLoading={isLoading}
        stats={[
          { title: t('BulkOperationsPage.stats.totalJobs.title'), value: allOps.length, icon: ListChecks, variant: 'default', description: t('BulkOperationsPage.stats.totalJobs.description') },
          { title: t('BulkOperationsPage.stats.running.title'), value: statusCounts.running || 0, icon: Loader2, variant: 'default', description: t('BulkOperationsPage.stats.running.description') },
          { title: t('BulkOperationsPage.stats.completed.title'), value: statusCounts.completed || 0, icon: CheckCircle2, variant: 'success', description: t('BulkOperationsPage.stats.completed.description') },
          { title: t('BulkOperationsPage.stats.failed.title'), value: (statusCounts.failed || 0) + (statusCounts.rolled_back || 0), icon: AlertOctagon, variant: 'destructive', description: t('BulkOperationsPage.stats.failed.description') },
        ]}
      />

      <PageToolbar>
        <SearchBar
          value={searchQuery}
          onChange={setSearchQuery}
          placeholder={t('BulkOperationsPage.searchPlaceholder')}
          className="w-full sm:w-auto"
        />
        <Select value={filterStatus} onValueChange={setFilterStatus}>
          <SelectTrigger className="w-full sm:w-[180px]"><SelectValue placeholder={t('BulkOperationsPage.filters.allStatuses')} /></SelectTrigger>
          <SelectContent>
            <SelectItem value="all">{t('BulkOperationsPage.filters.allStatuses')}</SelectItem>
            {Object.entries(STATUS_LABEL).map(([k, v]) => <SelectItem key={k} value={k}>{v}</SelectItem>)}
          </SelectContent>
        </Select>
        {hasActiveFilters && (
          <Button variant="ghost" size="sm" onClick={() => { setSearchQuery(''); setFilterStatus('all'); }}>
            {t('BulkOperationsPage.filters.clear')}
          </Button>
        )}
      </PageToolbar>

      <DataTable
        data={filteredOps}
        columns={columns}
        isLoading={isLoading}
        selectable
        onSelectionChange={setSelectedOps}
        searchable={false}
        getRowId={(r) => r.job_id}
        itemName={t('BulkOperationsPage.itemNamePlural')}
      />

      <BulkActionsBar
        selectedCount={selectedOps.length}
        itemName={t('BulkOperationsPage.itemName')}
        onClear={() => setSelectedOps([])}
        actions={[
          {
            label: t('BulkOperationsPage.bulkActions.cancelRunning'),
            icon: StopCircle,
            variant: 'destructive',
            onClick: async () => {
              const cancelable = selectedOps.filter(
                (op) => op.status === 'pending' || op.status === 'running',
              );
              if (cancelable.length === 0) {
                toast({ title: t('BulkOperationsPage.toasts.nothingToCancel.title'), description: t('BulkOperationsPage.toasts.nothingToCancel.description') });
                setSelectedOps([]);
                return;
              }
              // ``forEach + mutate`` previously fired N parallel requests
              // and swallowed individual failures via ``onError``,
              // operators couldn't tell how many actually cancelled.
              const results = await Promise.allSettled(
                cancelable.map((op) => enterpriseApi.cancelBulkOperation(op.job_id)),
              );
              const ok = results.filter((r) => r.status === 'fulfilled').length;
              const failed = results.length - ok;
              queryClient.invalidateQueries({ queryKey: ['enterprise', 'bulk-operations'] });
              toast({
                title: t('BulkOperationsPage.toasts.bulkCancel.title'),
                description: failed
                  ? t('BulkOperationsPage.toasts.bulkCancel.descriptionWithFailures', { ok, failed })
                  : t('BulkOperationsPage.toasts.bulkCancel.description', { ok }),
                variant: failed ? 'destructive' : 'default',
              });
              setSelectedOps([]);
            },
          },
        ]}
      />

      {/* Create Dialog */}
      <Dialog open={showCreate} onOpenChange={setShowCreate}>
        <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>{t('BulkOperationsPage.createDialog.title')}</DialogTitle>
            <DialogDescription>{t('BulkOperationsPage.createDialog.description')}</DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-4">
            <div className="grid gap-4 md:grid-cols-2">
              <div className="space-y-2">
                <Label>{t('BulkOperationsPage.createDialog.operationType')}</Label>
                <Select value={form.operation} onValueChange={v => setForm(p => ({ ...p, operation: v }))}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="push_config">{t('BulkOperationsPage.operations.pushConfig')}</SelectItem>
                    <SelectItem value="reboot">{t('BulkOperationsPage.operations.reboot')}</SelectItem>
                    <SelectItem value="firmware_update">{t('BulkOperationsPage.operations.firmwareUpdate')}</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-2">
                <Label>{t('BulkOperationsPage.createDialog.targetScope')}</Label>
                <Select value={form.scope} onValueChange={v => setForm(p => ({ ...p, scope: v }))}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="site">{t('BulkOperationsPage.scopes.site')}</SelectItem>
                    <SelectItem value="device_group">{t('BulkOperationsPage.scopes.deviceGroup')}</SelectItem>
                    <SelectItem value="tag">{t('BulkOperationsPage.scopes.tag')}</SelectItem>
                    <SelectItem value="device_list">{t('BulkOperationsPage.scopes.deviceList')}</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>

            <div className="grid gap-4 md:grid-cols-2">
              <div className="space-y-2">
                <Label>{t('BulkOperationsPage.createDialog.scopeId')}</Label>
                <Input value={form.scope_id} onChange={e => setForm(p => ({ ...p, scope_id: e.target.value }))} placeholder={t('BulkOperationsPage.createDialog.scopeIdPlaceholder')} />
              </div>
              <div className="space-y-2">
                <Label>{t('BulkOperationsPage.createDialog.deviceType')}</Label>
                <Select value={form.device_type || '_all'} onValueChange={v => setForm(p => ({ ...p, device_type: v === '_all' ? '' : v }))}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="_all">{t('BulkOperationsPage.deviceTypes.all')}</SelectItem>
                    <SelectItem value="access_point">{t('BulkOperationsPage.deviceTypes.accessPoint')}</SelectItem>
                    <SelectItem value="switch">{t('BulkOperationsPage.deviceTypes.switch')}</SelectItem>
                    <SelectItem value="router">{t('BulkOperationsPage.deviceTypes.router')}</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>

            {form.scope === 'tag' && (
              <div className="space-y-2">
                <Label>{t('BulkOperationsPage.createDialog.tag')}</Label>
                <Input value={form.tag} onChange={e => setForm(p => ({ ...p, tag: e.target.value }))} placeholder={t('BulkOperationsPage.createDialog.tagPlaceholder')} />
              </div>
            )}

            {form.scope === 'device_list' && (
              <div className="space-y-2">
                <Label>{t('BulkOperationsPage.createDialog.deviceIds')}</Label>
                <textarea
                  className="w-full h-24 font-mono text-sm bg-muted border border-border rounded-lg p-3 resize-y focus:outline-none focus:ring-2 focus:ring-primary"
                  value={form.device_ids}
                  onChange={e => setForm(p => ({ ...p, device_ids: e.target.value }))}
                  placeholder={t('BulkOperationsPage.createDialog.deviceIdsPlaceholder')}
                  spellCheck={false}
                />
                <p className="text-xs text-muted-foreground">{t('BulkOperationsPage.createDialog.deviceIdsHint')}</p>
              </div>
            )}

            {form.operation === 'push_config' && (
              <div className="space-y-2">
                <Label>{t('BulkOperationsPage.createDialog.configPayload')}</Label>
                <textarea
                  className="w-full h-32 font-mono text-sm bg-muted border border-border rounded-lg p-3 resize-y focus:outline-none focus:ring-2 focus:ring-primary"
                  value={form.config}
                  onChange={e => setForm(p => ({ ...p, config: e.target.value }))}
                  spellCheck={false}
                />
              </div>
            )}

            <Card>
              <CardHeader>
                <CardTitle className="text-sm">{t('BulkOperationsPage.rollout.title')}</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex items-center gap-4">
                  <Select value={form.strategy} onValueChange={v => setForm(p => ({ ...p, strategy: v }))}>
                    <SelectTrigger className="w-40"><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="immediate">{t('BulkOperationsPage.strategies.immediate')}</SelectItem>
                      <SelectItem value="staged">{t('BulkOperationsPage.strategies.staged')}</SelectItem>
                    </SelectContent>
                  </Select>
                  <div className="flex items-center gap-2">
                    <Label className="text-sm">{t('BulkOperationsPage.rollout.failureThreshold')}</Label>
                    <Input
                      type="number"
                      min={1}
                      max={100}
                      value={form.failure_threshold}
                      onChange={e => setForm(p => ({ ...p, failure_threshold: parseInt(e.target.value) || 5 }))}
                      className="w-20"
                    />
                  </div>
                  <div className="flex items-center gap-2">
                    <Switch checked={form.rollback_on_failure} onCheckedChange={v => setForm(p => ({ ...p, rollback_on_failure: v }))} />
                    <Label className="text-sm">{t('BulkOperationsPage.rollout.autoRollback')}</Label>
                  </div>
                </div>

                {form.strategy === 'staged' && (
                  <div className="space-y-2">
                    <Label>{t('BulkOperationsPage.rollout.stages')}</Label>
                    <textarea
                      className="w-full h-32 font-mono text-sm bg-muted border border-border rounded-lg p-3 resize-y focus:outline-none focus:ring-2 focus:ring-primary"
                      value={form.stages}
                      onChange={e => setForm(p => ({ ...p, stages: e.target.value }))}
                      spellCheck={false}
                    />
                    <p className="text-xs text-muted-foreground">{t('BulkOperationsPage.rollout.stagesHint')} {`{ "percent": 10, "wait_minutes": 15 }`}</p>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowCreate(false)}>{t('BulkOperationsPage.actions.cancel')}</Button>
            <Button onClick={handleCreate} disabled={createMutation.isPending}>
              {createMutation.isPending ? t('BulkOperationsPage.actions.creating') : t('BulkOperationsPage.actions.createAndRun')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Job Details Dialog, uses fresh GET to surface fields the
          list response omits (error_message, started_at, completed_at,
          devices_skipped). Falls back to the list row while loading. */}
      <Dialog open={!!selectedJob} onOpenChange={open => { if (!open) setSelectedJob(null); }}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>{t('BulkOperationsPage.detailsDialog.title')}</DialogTitle>
          </DialogHeader>
          {selectedJob && (() => {
            const job = jobDetail ?? selectedJob;
            return (
              <div className="space-y-4 py-4">
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <Label className="text-xs text-muted-foreground">{t('BulkOperationsPage.detailsDialog.jobId')}</Label>
                    <p className="font-mono text-sm break-all">{job.job_id}</p>
                  </div>
                  <div>
                    <Label className="text-xs text-muted-foreground">{t('BulkOperationsPage.detailsDialog.status')}</Label>
                    <div className="mt-1">
                      <StatusBadge variant={STATUS_VARIANT[job.status] || 'neutral'}>
                        {STATUS_LABEL[job.status] || job.status}
                      </StatusBadge>
                    </div>
                  </div>
                  <div>
                    <Label className="text-xs text-muted-foreground">{t('BulkOperationsPage.detailsDialog.operation')}</Label>
                    <p className="text-sm">{job.operation.replace('_', ' ')}</p>
                  </div>
                  <div>
                    <Label className="text-xs text-muted-foreground">{t('BulkOperationsPage.detailsDialog.stage')}</Label>
                    <p className="text-sm">{job.current_stage || '-'}</p>
                  </div>
                </div>
                <div>
                  <Label className="text-xs text-muted-foreground">{t('BulkOperationsPage.detailsDialog.progress')}</Label>
                  <div className="flex items-center gap-3 mt-2">
                    <Progress value={job.devices_total > 0 ? (job.devices_completed / job.devices_total) * 100 : 0} className="flex-1" />
                    <span className="text-sm">{job.devices_completed} / {job.devices_total}</span>
                  </div>
                  {(job.devices_failed > 0 || (job.devices_skipped ?? 0) > 0) && (
                    <p className="text-sm mt-1">
                      {job.devices_failed > 0 && (
                        <span className="text-destructive">{t('BulkOperationsPage.detailsDialog.failed', { count: job.devices_failed })}</span>
                      )}
                      {job.devices_failed > 0 && (job.devices_skipped ?? 0) > 0 && <span> · </span>}
                      {(job.devices_skipped ?? 0) > 0 && (
                        <span className="text-muted-foreground">{t('BulkOperationsPage.detailsDialog.skipped', { count: job.devices_skipped })}</span>
                      )}
                    </p>
                  )}
                </div>
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <Label className="text-xs text-muted-foreground">{t('BulkOperationsPage.detailsDialog.created')}</Label>
                    <p className="text-sm">{new Date(job.created_at).toLocaleString()}</p>
                  </div>
                  {job.started_at && (
                    <div>
                      <Label className="text-xs text-muted-foreground">{t('BulkOperationsPage.detailsDialog.started')}</Label>
                      <p className="text-sm">{new Date(job.started_at).toLocaleString()}</p>
                    </div>
                  )}
                  {job.completed_at && (
                    <div>
                      <Label className="text-xs text-muted-foreground">{t('BulkOperationsPage.detailsDialog.finished')}</Label>
                      <p className="text-sm">{new Date(job.completed_at).toLocaleString()}</p>
                    </div>
                  )}
                </div>
                {job.error_message && (
                  <div>
                    <Label className="text-xs text-muted-foreground">{t('BulkOperationsPage.detailsDialog.error')}</Label>
                    <p className="text-sm text-destructive whitespace-pre-wrap break-words">{job.error_message}</p>
                  </div>
                )}
              </div>
            );
          })()}
        </DialogContent>
      </Dialog>
    </div>
  );
}

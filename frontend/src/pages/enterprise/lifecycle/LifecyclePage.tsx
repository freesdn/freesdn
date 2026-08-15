// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN Enterprise · Device Lifecycle Manager
 *
 * Visualize and manage the device lifecycle state machine:
 * discovered → adopting → provisioning → managed → updating → offline → error → decommissioned
 */

import { useState, useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useToast } from '@/hooks/use-toast';
import { useSiteStore } from '@/stores/siteStore';
import {
  Workflow,
  ArrowRight,
  RefreshCw,
  Clock,
  CheckCircle2,
  AlertOctagon,
  WifiOff,
  Package,
  Eye,
  Trash2,
  Radar,
  ArrowUpCircle,
  Check,
  X as XIcon,
} from 'lucide-react';
import { PageHeader, PageToolbar } from '@/components/layout';
import { StatsGrid } from '@/components/ui/stats-grid';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
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
import { DataTable, type DataTableColumn } from '@/components/ui/data-table';
import { StatusBadge, type StatusVariant } from '@/components/ui/status-indicator';
import { TypeBadge } from '@/components/ui/type-badge';
import { BulkActionsBar } from '@/components/ui/bulk-actions-bar';
import { ErrorState } from '@/components/ui/empty-state';
import { SearchBar } from '@/components/ui/search-bar';
import { cn } from '@/lib/utils';
import { devicesApi, enterpriseApi, type LifecycleLogEntry } from '@/lib/api';

const LIFECYCLE_STATES = [
  'discovered', 'adopting', 'provisioning', 'managed',
  'updating', 'offline', 'error', 'decommissioned', 'ignored',
] as const;

const STATE_VARIANT: Record<string, StatusVariant> = {
  discovered: 'info',
  adopting: 'info',
  provisioning: 'syncing',
  managed: 'success',
  updating: 'updating',
  offline: 'neutral',
  error: 'error',
  decommissioned: 'disabled',
  ignored: 'disabled',
};

// State labels are localized at the render site. ``buildStateLabel`` maps a
// lifecycle-state slug to its translated label using the ``t`` function from
// the component (it cannot live at module scope because ``t`` is a hook value).
const buildStateLabel = (t: (key: string) => string): Record<string, string> => ({
  discovered: t('LifecyclePage.states.discovered'),
  adopting: t('LifecyclePage.states.adopting'),
  provisioning: t('LifecyclePage.states.provisioning'),
  managed: t('LifecyclePage.states.managed'),
  updating: t('LifecyclePage.states.updating'),
  offline: t('LifecyclePage.states.offline'),
  error: t('LifecyclePage.states.error'),
  decommissioned: t('LifecyclePage.states.decommissioned'),
  ignored: t('LifecyclePage.states.ignored'),
});

const STATE_ICON: Record<string, React.ElementType> = {
  discovered: Radar,
  adopting: Package,
  provisioning: ArrowUpCircle,
  managed: CheckCircle2,
  updating: RefreshCw,
  offline: WifiOff,
  error: AlertOctagon,
  decommissioned: Trash2,
  ignored: Eye,
};

// Mirror the backend FSM at ``models/enterprise.py:LIFECYCLE_TRANSITIONS``.
// Previously this table dropped 3 legal edges (offline→decommissioned,
// error→provisioning, adopting→discovered = "cancel"), so the UI hid
// transition buttons the backend would have happily accepted. Keep the
// two sides in lockstep; ideally future work exposes the FSM via
// `GET /enterprise/lifecycle/fsm` so we stop duplicating it.
const VALID_TRANSITIONS: Record<string, string[]> = {
  discovered:     ['adopting', 'ignored'],
  adopting:       ['provisioning', 'error', 'discovered'],
  provisioning:   ['managed', 'error'],
  managed:        ['updating', 'error', 'offline', 'provisioning', 'decommissioned'],
  updating:       ['managed', 'error'],
  offline:        ['managed', 'error', 'decommissioned'],
  error:          ['managed', 'provisioning', 'decommissioned'],
  decommissioned: [],
  ignored:        ['adopting'],
};

interface DeviceWithLifecycle {
  id: string;
  name: string;
  ip_address?: string;
  device_type?: string;
  lifecycle_state: string;
  lifecycle_changed_at: string | null;
  lifecycle_error: string | null;
  site_id?: string;
}

export default function LifecyclePage() {
  const { t } = useTranslation('enterprise');
  const STATE_LABEL = useMemo(() => buildStateLabel(t), [t]);
  const [search, setSearch] = useState('');
  const [filterState, setFilterState] = useState('all');
  const [selectedDevice, setSelectedDevice] = useState<DeviceWithLifecycle | null>(null);
  const [selectedDevices, setSelectedDevices] = useState<DeviceWithLifecycle[]>([]);
  const [showTransition, setShowTransition] = useState(false);
  const [transitionTarget, setTransitionTarget] = useState('');
  const queryClient = useQueryClient();
  const selectedSiteId = useSiteStore((s) => s.selectedSiteId);

  const { data: devices, isLoading, isError, refetch } = useQuery({
    queryKey: ['devices', 'list', 'lifecycle', { siteId: selectedSiteId }],
    // Forward the global site context AND request a meaningful page
    // size. The backend default is per_page=25, max=100, the previous
    // version sent neither and the page silently rendered (and counted
    // in StatsGrid) only the first 25 devices in the org. With a max
    // of 100, organisations >100 devices need real pagination (see
    // deferred chapter work) but at least the lie is now sized to the
    // backend cap rather than the default.
    queryFn: () => devicesApi.getAll({
      ...(selectedSiteId ? { site_id: selectedSiteId } : {}),
      per_page: 100,
    }).then(r => {
      const d = r.data;
      if (Array.isArray(d)) return d as DeviceWithLifecycle[];
      if (d && Array.isArray(d.items)) return d.items as DeviceWithLifecycle[];
      return [] as DeviceWithLifecycle[];
    }),
  });

  const { data: history, isLoading: historyLoading } = useQuery({
    queryKey: ['enterprise', 'lifecycle', 'history', selectedDevice?.id, { siteId: selectedSiteId }],
    queryFn: () => enterpriseApi.getLifecycleHistory(selectedDevice!.id).then(r => r.data),
    enabled: !!selectedDevice,
  });

  const { toast } = useToast();
  const transitionMutation = useMutation({
    mutationFn: ({ deviceId, toState }: { deviceId: string; toState: string }) =>
      enterpriseApi.transitionLifecycle(deviceId, { to_state: toState, trigger: 'user_action' }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['devices'] });
      queryClient.invalidateQueries({ queryKey: ['enterprise', 'lifecycle'] });
      setShowTransition(false);
    },
    onError: (err) => {
      // Backend returns 422 on FSM violations (FE's VALID_TRANSITIONS
      // table can drift from backend ``LifecycleState`` enum). Without
      // this toast the user clicked Transition and saw nothing happen.
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const detail = (err as any)?.response?.data?.detail
        || (err instanceof Error ? err.message : t('LifecyclePage.errors.unknown'));
      toast({ variant: 'destructive', title: t('LifecyclePage.toast.transitionFailedTitle'), description: String(detail) });
    },
  });

  // Bulk transition runner: drives every selected device to ``toState`` in
  // parallel and emits exactly ONE summary toast (applied / skipped / failed)
  // instead of N per-call destructive toasts. Devices whose current state has
  // no legal edge to ``toState`` are counted as skipped, never dispatched.
  const runBulkTransition = async (toState: string) => {
    const eligible = selectedDevices.filter((d) =>
      (VALID_TRANSITIONS[d.lifecycle_state] || []).includes(toState),
    );
    const skipped = selectedDevices.length - eligible.length;
    setSelectedDevices([]);
    if (eligible.length === 0) {
      // Nothing was actionable for the current selection, say so honestly
      // rather than firing a no-op success.
      toast({ title: t('BulkOperationsPage.detailsDialog.skipped', { count: skipped }) });
      return;
    }
    const results = await Promise.allSettled(
      eligible.map((d) =>
        enterpriseApi.transitionLifecycle(d.id, { to_state: toState, trigger: 'user_action' }),
      ),
    );
    queryClient.invalidateQueries({ queryKey: ['devices'] });
    queryClient.invalidateQueries({ queryKey: ['enterprise', 'lifecycle'] });
    const applied = results.filter((r) => r.status === 'fulfilled').length;
    const failed = results.filter((r) => r.status === 'rejected').length;
    const parts = [`${applied} ${t('common:success')}`];
    if (failed > 0) parts.push(`${failed} ${t('BulkOperationsPage.status.failed')}`);
    if (skipped > 0) parts.push(t('BulkOperationsPage.detailsDialog.skipped', { count: skipped }));
    toast({
      variant: failed > 0 ? 'destructive' : undefined,
      title: failed > 0 ? t('LifecyclePage.toast.transitionFailedTitle') : t('common:success'),
      description: parts.join(' · '),
    });
  };

  const allDevices = useMemo(() => devices ?? [], [devices]);
  const filtered = useMemo(() => {
    return allDevices.filter(d => {
      if (filterState !== 'all' && d.lifecycle_state !== filterState) return false;
      if (search && !d.name?.toLowerCase().includes(search.toLowerCase()) && !d.ip_address?.includes(search)) return false;
      return true;
    });
  }, [allDevices, filterState, search]);

  const stateCounts = allDevices.reduce((acc, d) => {
    const s = d.lifecycle_state || 'discovered';
    acc[s] = (acc[s] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  const hasActiveFilters = search !== '' || filterState !== 'all';

  const columns: DataTableColumn<DeviceWithLifecycle>[] = [
    {
      id: 'name', header: t('LifecyclePage.columns.device'), accessorKey: 'name', sortable: true,
      cell: (r) => (
        <div>
          <span className="font-medium text-foreground">{r.name || t('LifecyclePage.unnamed')}</span>
          {r.ip_address && <p className="text-xs text-muted-foreground">{r.ip_address}</p>}
        </div>
      ),
    },
    {
      id: 'type', header: t('LifecyclePage.columns.type'), accessorKey: 'device_type',
      cell: (r) => r.device_type ? <TypeBadge type={r.device_type} /> : <span className="text-muted-foreground">-</span>,
    },
    {
      id: 'state', header: t('LifecyclePage.columns.lifecycleState'), accessorKey: 'lifecycle_state', sortable: true,
      cell: (r) => (
        <StatusBadge variant={STATE_VARIANT[r.lifecycle_state || 'discovered'] || 'neutral'}>
          {STATE_LABEL[r.lifecycle_state || 'discovered'] || r.lifecycle_state}
        </StatusBadge>
      ),
    },
    {
      id: 'changed', header: t('LifecyclePage.columns.lastChanged'), accessorKey: 'lifecycle_changed_at',
      cell: (r) => r.lifecycle_changed_at
        ? <span className="text-sm text-muted-foreground">{new Date(r.lifecycle_changed_at).toLocaleString()}</span>
        : <span className="text-muted-foreground">-</span>,
    },
    {
      id: 'error', header: t('LifecyclePage.columns.error'), accessorKey: 'lifecycle_error',
      cell: (r) => r.lifecycle_error
        ? <span className="text-sm text-destructive truncate max-w-xs">{r.lifecycle_error}</span>
        : <span className="text-muted-foreground">-</span>,
    },
    {
      id: 'actions', header: '', sortable: false,
      cell: (r) => (
        <div className="flex items-center gap-1 justify-end">
          <Button variant="ghost" size="sm" onClick={() => setSelectedDevice(r)}>
            <Clock className="h-4 w-4 mr-1" /> {t('LifecyclePage.actions.history')}
          </Button>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => { setSelectedDevice(r); setShowTransition(true); setTransitionTarget(''); }}
            disabled={VALID_TRANSITIONS[r.lifecycle_state || 'discovered']?.length === 0}
          >
            <ArrowRight className="h-4 w-4 mr-1" /> {t('LifecyclePage.actions.transition')}
          </Button>
        </div>
      ),
    },
  ];

  const historyColumns: DataTableColumn<LifecycleLogEntry>[] = [
    {
      id: 'time', header: t('LifecyclePage.historyColumns.time'), accessorKey: 'created_at', sortable: true,
      cell: (r) => <span className="text-sm">{new Date(r.created_at).toLocaleString()}</span>,
    },
    {
      id: 'transition', header: t('LifecyclePage.historyColumns.transition'),
      cell: (r) => (
        <div className="flex items-center gap-2">
          <StatusBadge variant={STATE_VARIANT[r.from_state] || 'neutral'}>{STATE_LABEL[r.from_state] || r.from_state}</StatusBadge>
          <ArrowRight className="h-3 w-3 text-muted-foreground" />
          <StatusBadge variant={STATE_VARIANT[r.to_state] || 'neutral'}>{STATE_LABEL[r.to_state] || r.to_state}</StatusBadge>
        </div>
      ),
    },
    {
      id: 'trigger', header: t('LifecyclePage.historyColumns.trigger'), accessorKey: 'trigger',
      cell: (r) => <TypeBadge type={r.trigger} />,
    },
    {
      id: 'details', header: t('LifecyclePage.historyColumns.details'),
      cell: (r) => r.details ? <span className="text-xs text-muted-foreground">{JSON.stringify(r.details).slice(0, 60)}</span> : <span className="text-muted-foreground">-</span>,
    },
  ];

  if (isError) {
    return (
      <div className="space-y-6">
        <PageHeader icon={Workflow} title={t('LifecyclePage.title')} description={t('LifecyclePage.description')} />
        <ErrorState message={t('LifecyclePage.loadError')} onRetry={() => refetch()} />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader
        icon={Workflow}
        title={t('LifecyclePage.title')}
        description={t('LifecyclePage.description')}
        onRefresh={() => refetch()}
        refreshing={isLoading}
      />

      <StatsGrid
        columns={4}
        isLoading={isLoading}
        stats={[
          { title: t('LifecyclePage.stats.managed.title'), value: stateCounts.managed || 0, icon: CheckCircle2, variant: 'success', description: t('LifecyclePage.stats.managed.description') },
          { title: t('LifecyclePage.stats.discovered.title'), value: stateCounts.discovered || 0, icon: Radar, variant: 'default', description: t('LifecyclePage.stats.discovered.description') },
          { title: t('LifecyclePage.stats.offline.title'), value: stateCounts.offline || 0, icon: WifiOff, variant: 'default', description: t('LifecyclePage.stats.offline.description') },
          { title: t('LifecyclePage.stats.error.title'), value: stateCounts.error || 0, icon: AlertOctagon, variant: 'destructive', description: t('LifecyclePage.stats.error.description') },
        ]}
      />

      {/* FSM Diagram */}
      <Card>
        <CardHeader>
          <CardTitle className="text-sm font-medium">{t('LifecyclePage.stateMachine')}</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex flex-wrap items-center gap-2">
            {LIFECYCLE_STATES.map((state, i) => {
              const Icon = STATE_ICON[state];
              const count = stateCounts[state] || 0;
              return (
                <div key={state} className="flex items-center gap-1">
                  {i > 0 && <ArrowRight className="h-3 w-3 text-muted-foreground mx-1" />}
                  <button
                    onClick={() => setFilterState(filterState === state ? 'all' : state)}
                    className={cn(
                      'flex items-center gap-1.5 px-3 py-1.5 rounded-full border text-xs font-medium transition-colors',
                      filterState === state ? 'border-primary bg-primary/10' : 'border-border hover:border-primary/30',
                    )}
                  >
                    <Icon className="h-3.5 w-3.5 text-muted-foreground" />
                    {STATE_LABEL[state]}
                    {count > 0 && <span className="ml-1 bg-muted px-1.5 py-0.5 rounded-full text-[10px]">{count}</span>}
                  </button>
                </div>
              );
            })}
          </div>
        </CardContent>
      </Card>

      <PageToolbar>
        <SearchBar
          value={search}
          onChange={setSearch}
          placeholder={t('LifecyclePage.searchPlaceholder')}
          className="w-full sm:w-auto"
        />
        <Select value={filterState} onValueChange={setFilterState}>
          <SelectTrigger className="w-full sm:w-[180px]"><SelectValue placeholder={t('LifecyclePage.allStates')} /></SelectTrigger>
          <SelectContent>
            <SelectItem value="all">{t('LifecyclePage.allStates')}</SelectItem>
            {LIFECYCLE_STATES.map(s => <SelectItem key={s} value={s}>{STATE_LABEL[s]}</SelectItem>)}
          </SelectContent>
        </Select>
        {hasActiveFilters && (
          <Button variant="ghost" size="sm" onClick={() => { setSearch(''); setFilterState('all'); }}>
            {t('LifecyclePage.clearFilters')}
          </Button>
        )}
      </PageToolbar>

      <DataTable
        data={filtered}
        columns={columns}
        isLoading={isLoading}
        selectable
        onSelectionChange={setSelectedDevices}
        searchable={false}
        getRowId={r => r.id}
        itemName={t('LifecyclePage.itemName.devices')}
      />

      <BulkActionsBar
        selectedCount={selectedDevices.length}
        itemName={t('LifecyclePage.itemName.device')}
        onClear={() => setSelectedDevices([])}
        actions={[
          {
            label: t('LifecyclePage.bulkActions.approve'),
            icon: Check,
            onClick: () => { void runBulkTransition('adopting'); },
          },
          {
            label: t('LifecyclePage.bulkActions.reject'),
            icon: XIcon,
            onClick: () => { void runBulkTransition('ignored'); },
          },
          {
            label: t('LifecyclePage.bulkActions.markStale'),
            icon: AlertOctagon,
            variant: 'destructive',
            onClick: () => { void runBulkTransition('decommissioned'); },
          },
        ]}
      />

      {/* History Dialog */}
      <Dialog open={!!selectedDevice && !showTransition} onOpenChange={open => { if (!open) setSelectedDevice(null); }}>
        <DialogContent className="max-w-3xl max-h-[80vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>{t('LifecyclePage.historyDialog.title', { name: selectedDevice?.name })}</DialogTitle>
            <DialogDescription>{t('LifecyclePage.historyDialog.description')}</DialogDescription>
          </DialogHeader>
          <DataTable data={history ?? []} columns={historyColumns} isLoading={historyLoading} searchable={false} paginated getRowId={r => r.id} itemName={t('LifecyclePage.itemName.entries')} />
        </DialogContent>
      </Dialog>

      {/* Transition Dialog */}
      <Dialog open={showTransition} onOpenChange={open => { if (!open) setShowTransition(false); }}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t('LifecyclePage.transitionDialog.title')}</DialogTitle>
            <DialogDescription>
              {selectedDevice?.name} · {selectedDevice ? STATE_LABEL[selectedDevice.lifecycle_state] : ''}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-4">
            <div className="space-y-2">
              <Label>{t('LifecyclePage.transitionDialog.currentState')}</Label>
              <div>
                <StatusBadge variant={STATE_VARIANT[selectedDevice?.lifecycle_state ?? 'discovered'] || 'neutral'}>
                  {STATE_LABEL[selectedDevice?.lifecycle_state ?? 'discovered']}
                </StatusBadge>
              </div>
            </div>
            <div className="space-y-2">
              <Label>{t('LifecyclePage.transitionDialog.transitionTo')}</Label>
              <Select value={transitionTarget} onValueChange={setTransitionTarget}>
                <SelectTrigger><SelectValue placeholder={t('LifecyclePage.transitionDialog.selectTarget')} /></SelectTrigger>
                <SelectContent>
                  {VALID_TRANSITIONS[selectedDevice?.lifecycle_state ?? 'discovered']?.map(s => (
                    <SelectItem key={s} value={s}>{STATE_LABEL[s] ?? s}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowTransition(false)}>{t('LifecyclePage.actions.cancel')}</Button>
            <Button
              onClick={() => selectedDevice && transitionTarget && transitionMutation.mutate({ deviceId: selectedDevice.id, toState: transitionTarget })}
              disabled={!transitionTarget || transitionMutation.isPending}
            >
              {transitionMutation.isPending ? t('LifecyclePage.actions.transitioning') : t('LifecyclePage.actions.transition')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

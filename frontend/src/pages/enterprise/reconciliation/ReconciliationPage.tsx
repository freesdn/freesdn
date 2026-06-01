// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN Enterprise · Reconciliation & Drift View
 *
 * View device config drift, trigger reconciliation, and inspect the
 * three-state config model (desired vs pushed vs running).
 */

import { useState, useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useToast } from '@/hooks/use-toast';
import { useSiteStore } from '@/stores/siteStore';
import {
  GitCompareArrows,
  Eye,
  Play,
  ShieldCheck,
  FileCode2,
  ArrowRight,
  EyeOff,
} from 'lucide-react';
import { PageHeader, PageToolbar } from '@/components/layout';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { DataTable, type DataTableColumn } from '@/components/ui/data-table';
import { StatusBadge } from '@/components/ui/status-indicator';
import { TypeBadge } from '@/components/ui/type-badge';
import { BulkActionsBar } from '@/components/ui/bulk-actions-bar';
import { ErrorState } from '@/components/ui/empty-state';
import { SearchBar } from '@/components/ui/search-bar';
import { Badge } from '@/components/ui/badge';
import { enterpriseApi, devicesApi } from '@/lib/api';

interface DeviceWithConfig {
  id: string;
  name: string;
  ip_address?: string;
  device_type?: string;
  site_id?: string;
}

export default function ReconciliationPage() {
  const { t } = useTranslation('enterprise');
  const [search, setSearch] = useState('');
  const [selectedDeviceId, setSelectedDeviceId] = useState<string | null>(null);
  const [selectedDevices, setSelectedDevices] = useState<DeviceWithConfig[]>([]);
  const [configTab, setConfigTab] = useState('three-state');
  const queryClient = useQueryClient();
  const selectedSiteId = useSiteStore((s) => s.selectedSiteId);

  const { toast } = useToast();
  const errToast = (title: string) => (err: unknown) => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const detail = (err as any)?.response?.data?.detail
      || (err instanceof Error ? err.message : t('ReconciliationPage.errors.unknown'));
    toast({ variant: 'destructive', title, description: String(detail) });
  };

  const { data: devices, isLoading: devicesLoading, isError: devicesError, refetch } = useQuery({
    queryKey: ['devices', 'list', { siteId: selectedSiteId }],
    // Forward site context so the device list actually narrows when the
    // user picks a site, previously the queryKey split the cache but
    // the request returned org-wide data.
    queryFn: () => devicesApi.getAll(
      selectedSiteId ? { site_id: selectedSiteId } : undefined,
    ).then(r => {
      const d = r.data;
      if (Array.isArray(d)) return d as DeviceWithConfig[];
      if (d && Array.isArray(d.items)) return d.items as DeviceWithConfig[];
      return [] as DeviceWithConfig[];
    }),
  });

  const { data: deviceConfig, isLoading: configLoading } = useQuery({
    queryKey: ['enterprise', 'device-config', selectedDeviceId, { siteId: selectedSiteId }],
    queryFn: () => enterpriseApi.getDeviceConfig(selectedDeviceId!).then(r => r.data),
    enabled: !!selectedDeviceId,
  });

  const {
    data: resolvedConfig,
    isLoading: resolvedLoading,
    isError: resolvedError,
  } = useQuery({
    queryKey: ['enterprise', 'resolved-config', selectedDeviceId, { siteId: selectedSiteId }],
    queryFn: () => enterpriseApi.getResolvedConfig(selectedDeviceId!).then(r => r.data),
    enabled: !!selectedDeviceId,
  });

  const reconcileMutation = useMutation({
    // ``scope_id`` is optional for ``scope=organization`` per backend +
    // FE API client; required for device/site.
    mutationFn: (data: { scope: string; scope_id?: string }) =>
      enterpriseApi.triggerReconcile(data),
    onSuccess: (res) => {
      queryClient.invalidateQueries({ queryKey: ['enterprise'] });
      // Reconciliation is dispatched async (returns immediately with all-zero
      // compliant/drifted counts), so the only meaningful confirmation we can
      // surface is how many devices were queued.
      toast({
        title: t('HealthDashboardPage.toast.reconcileDispatched.title'),
        description: t('HealthDashboardPage.toast.reconcileDispatched.description', {
          count: res?.data?.total ?? 0,
        }),
      });
    },
    onError: errToast(t('ReconciliationPage.errors.reconcileFailed')),
  });

  const settingsMutation = useMutation({
    mutationFn: ({ deviceId, settings }: { deviceId: string; settings: { auto_remediate?: boolean; drift_acknowledged?: boolean } }) =>
      enterpriseApi.updateDeviceConfigSettings(deviceId, settings),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['enterprise', 'device-config'] }),
    onError: errToast(t('ReconciliationPage.errors.updateSettingsFailed')),
  });

  // Bulk Re-run: dispatch a per-device reconcile for every selected row in
  // parallel and emit exactly ONE summary toast. We call the API directly
  // (not reconcileMutation.mutate) so the single-device onSuccess toast does
  // not fire once per row.
  const runBulkReconcile = async () => {
    const targets = selectedDevices;
    setSelectedDevices([]);
    if (targets.length === 0) return;
    const results = await Promise.allSettled(
      targets.map((d) => enterpriseApi.triggerReconcile({ scope: 'device', scope_id: d.id })),
    );
    queryClient.invalidateQueries({ queryKey: ['enterprise'] });
    const ok = results.filter((r) => r.status === 'fulfilled').length;
    const failed = results.length - ok;
    const parts = [
      t('HealthDashboardPage.toast.reconcileDispatched.description', { count: ok }),
    ];
    if (failed > 0) parts.push(`${failed} ${t('BulkOperationsPage.status.failed')}`);
    toast({
      variant: failed > 0 ? 'destructive' : undefined,
      title: failed > 0
        ? t('ReconciliationPage.errors.reconcileFailed')
        : t('HealthDashboardPage.toast.reconcileDispatched.title'),
      description: parts.join(' · '),
    });
  };

  // Bulk Dismiss Diff: acknowledge drift on every selected row in parallel and
  // emit exactly ONE summary toast. Previously this fanned out one
  // settingsMutation.mutate() per device, which fired one error toast per
  // device lacking a DeviceConfig row (404 storm). Mirror runBulkReconcile:
  // call the API directly with Promise.allSettled and summarize.
  const runBulkDismissDiff = async () => {
    const targets = selectedDevices;
    setSelectedDevices([]);
    if (targets.length === 0) return;
    const results = await Promise.allSettled(
      targets.map((d) =>
        enterpriseApi.updateDeviceConfigSettings(d.id, { drift_acknowledged: true }),
      ),
    );
    queryClient.invalidateQueries({ queryKey: ['enterprise', 'device-config'] });
    const ok = results.filter((r) => r.status === 'fulfilled').length;
    const failed = results.length - ok;
    const parts = [
      t('ReconciliationPage.toast.dismissed', { count: ok }),
    ];
    if (failed > 0) parts.push(`${failed} ${t('BulkOperationsPage.status.failed')}`);
    toast({
      variant: failed > 0 ? 'destructive' : undefined,
      title: failed > 0
        ? t('ReconciliationPage.errors.updateSettingsFailed')
        : t('ReconciliationPage.toast.dismissedTitle'),
      description: parts.join(' · '),
    });
  };

  const allDevices = useMemo(() => devices ?? [], [devices]);

  const filtered = useMemo(() => {
    if (!search) return allDevices;
    const q = search.toLowerCase();
    return allDevices.filter(d =>
      (d.name || '').toLowerCase().includes(q) || (d.ip_address || '').includes(search),
    );
  }, [allDevices, search]);

  const columns: DataTableColumn<DeviceWithConfig>[] = [
    {
      id: 'name', header: t('ReconciliationPage.columns.device'), accessorKey: 'name', sortable: true,
      cell: (r) => (
        <div>
          <span className="font-medium text-foreground">{r.name || t('ReconciliationPage.unnamed')}</span>
          {r.ip_address && <p className="text-xs text-muted-foreground">{r.ip_address}</p>}
        </div>
      ),
    },
    {
      id: 'type', header: t('ReconciliationPage.columns.type'), accessorKey: 'device_type',
      cell: (r) => r.device_type ? <TypeBadge type={r.device_type} /> : <span className="text-muted-foreground">-</span>,
    },
    {
      id: 'actions', header: '', sortable: false,
      cell: (r) => (
        <div className="flex items-center gap-1 justify-end">
          <Button variant="ghost" size="sm" onClick={() => { setSelectedDeviceId(r.id); setConfigTab('three-state'); }}>
            <Eye className="h-4 w-4 mr-1" /> {t('ReconciliationPage.actions.inspect')}
          </Button>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => reconcileMutation.mutate({ scope: 'device', scope_id: r.id })}
            disabled={reconcileMutation.isPending}
          >
            <GitCompareArrows className="h-4 w-4 mr-1" /> {t('ReconciliationPage.actions.reconcile')}
          </Button>
        </div>
      ),
    },
  ];

  if (devicesError) {
    return (
      <div className="space-y-6">
        <PageHeader
          icon={GitCompareArrows}
          title={t('ReconciliationPage.header.title')}
          description={t('ReconciliationPage.header.description')}
        />
        <ErrorState message={t('ReconciliationPage.errors.loadDevices')} onRetry={() => refetch()} />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader
        icon={GitCompareArrows}
        title={t('ReconciliationPage.header.title')}
        description={t('ReconciliationPage.header.description')}
        onRefresh={() => refetch()}
        refreshing={devicesLoading}
        secondaryActions={[
          {
            label: t('ReconciliationPage.actions.reconcileAll'),
            icon: Play,
            onClick: () => {
              // Backend ignores scope_id for ``scope=organization`` and
              // falls back to the caller's own org. Sending an all-zeros
              // UUID as a placeholder is a footgun if pydantic ever
              // tightens UUID validation on ReconcileRequest. The FE API
              // signature now permits omitting scope_id; do that here.
              reconcileMutation.mutate({ scope: 'organization' });
            },
            loading: reconcileMutation.isPending,
          },
        ]}
      />

      <PageToolbar>
        <SearchBar
          value={search}
          onChange={setSearch}
          placeholder={t('ReconciliationPage.searchPlaceholder')}
          className="w-full sm:w-auto"
        />
        {search && (
          <Button variant="ghost" size="sm" onClick={() => setSearch('')}>
            {t('ReconciliationPage.actions.clearFilters')}
          </Button>
        )}
      </PageToolbar>

      <DataTable
        data={filtered}
        columns={columns}
        isLoading={devicesLoading}
        selectable
        onSelectionChange={setSelectedDevices}
        searchable={false}
        getRowId={r => r.id}
        itemName={t('ReconciliationPage.itemNamePlural')}
      />

      <BulkActionsBar
        selectedCount={selectedDevices.length}
        itemName={t('ReconciliationPage.itemName')}
        onClear={() => setSelectedDevices([])}
        actions={[
          {
            label: t('ReconciliationPage.actions.rerun'),
            icon: Play,
            onClick: () => { void runBulkReconcile(); },
          },
          {
            label: t('ReconciliationPage.actions.dismissDiff'),
            icon: EyeOff,
            onClick: () => { void runBulkDismissDiff(); },
          },
        ]}
      />

      {/* Config Inspector Dialog */}
      <Dialog open={!!selectedDeviceId} onOpenChange={open => { if (!open) setSelectedDeviceId(null); }}>
        <DialogContent className="max-w-5xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>{t('ReconciliationPage.inspector.title')}</DialogTitle>
            <DialogDescription>{t('ReconciliationPage.inspector.description', { id: selectedDeviceId?.slice(0, 8) })}</DialogDescription>
          </DialogHeader>

          {configLoading ? (
            <div className="py-8 text-center text-muted-foreground">{t('ReconciliationPage.inspector.loading')}</div>
          ) : deviceConfig ? (
            <div className="space-y-4">
              <div className="flex items-center gap-4 flex-wrap">
                <div className="flex items-center gap-2">
                  {deviceConfig.has_drift
                    ? <StatusBadge variant="error">{t('ReconciliationPage.status.driftDetected')}</StatusBadge>
                    : <StatusBadge variant="success">{t('ReconciliationPage.status.compliant')}</StatusBadge>}
                </div>
                <Badge variant="outline">{t('ReconciliationPage.inspector.push', { value: deviceConfig.push_result ?? t('ReconciliationPage.inspector.neverPushed') })}</Badge>
                <Badge variant="outline">{t('ReconciliationPage.inspector.version', { value: deviceConfig.config_version })}</Badge>
                <div className="flex items-center gap-2 ml-auto">
                  <Switch
                    checked={deviceConfig.auto_remediate}
                    onCheckedChange={v => settingsMutation.mutate({ deviceId: selectedDeviceId!, settings: { auto_remediate: v } })}
                  />
                  <Label className="text-sm">{t('ReconciliationPage.inspector.autoRemediate')}</Label>
                </div>
              </div>

              {deviceConfig.has_drift && deviceConfig.drift_details && (
                <Card className="border-destructive/30 bg-destructive/5">
                  <CardContent noOffset className="p-4">
                    <h4 className="text-sm font-medium text-destructive mb-2">{t('ReconciliationPage.driftDetails')}</h4>
                    <pre className="text-xs font-mono overflow-auto max-h-40">{JSON.stringify(deviceConfig.drift_details, null, 2)}</pre>
                  </CardContent>
                </Card>
              )}

              <Tabs value={configTab} onValueChange={setConfigTab}>
                <TabsList>
                  <TabsTrigger value="three-state">{t('ReconciliationPage.tabs.threeState')}</TabsTrigger>
                  <TabsTrigger value="resolved">{t('ReconciliationPage.tabs.resolved')}</TabsTrigger>
                  <TabsTrigger value="overrides">{t('ReconciliationPage.tabs.overrides')}</TabsTrigger>
                </TabsList>

                <TabsContent value="three-state" className="mt-4 space-y-4">
                  <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-4">
                    <div>
                      <div className="flex items-center gap-2 mb-2">
                        <FileCode2 className="h-4 w-4 text-info" />
                        <h4 className="text-sm font-medium">{t('ReconciliationPage.threeState.desired')}</h4>
                      </div>
                      <pre className="bg-muted/50 rounded-lg p-3 text-xs font-mono overflow-auto max-h-96 border border-border">
                        {JSON.stringify(deviceConfig.desired_config, null, 2) || '{}'}
                      </pre>
                    </div>
                    <div>
                      <div className="flex items-center gap-2 mb-2">
                        <ArrowRight className="h-4 w-4 text-warning" />
                        <h4 className="text-sm font-medium">{t('ReconciliationPage.threeState.pushed')}</h4>
                      </div>
                      <pre className="bg-muted/50 rounded-lg p-3 text-xs font-mono overflow-auto max-h-96 border border-border">
                        {JSON.stringify(deviceConfig.pushed_config, null, 2) || '{}'}
                      </pre>
                    </div>
                    <div>
                      <div className="flex items-center gap-2 mb-2">
                        <ShieldCheck className="h-4 w-4 text-success" />
                        <h4 className="text-sm font-medium">{t('ReconciliationPage.threeState.running')}</h4>
                      </div>
                      <pre className="bg-muted/50 rounded-lg p-3 text-xs font-mono overflow-auto max-h-96 border border-border">
                        {JSON.stringify(deviceConfig.running_config, null, 2) || '{}'}
                      </pre>
                    </div>
                  </div>
                  <div className="flex items-center gap-2 text-xs text-muted-foreground">
                    {deviceConfig.pushed_at && <span>{t('ReconciliationPage.threeState.lastPushed', { date: new Date(deviceConfig.pushed_at).toLocaleString() })}</span>}
                    {deviceConfig.running_synced_at && <span>{t('ReconciliationPage.threeState.lastSynced', { date: new Date(deviceConfig.running_synced_at).toLocaleString() })}</span>}
                  </div>
                </TabsContent>

                <TabsContent value="resolved" className="mt-4">
                  {/* Three-state branch: previously loading, error and
                      genuinely-empty all collapsed into the single "empty"
                      message, which lied to the operator while the query was
                      still in flight or had failed. */}
                  {resolvedLoading ? (
                    <div className="py-8 text-center text-muted-foreground">{t('ReconciliationPage.inspector.loading')}</div>
                  ) : resolvedError ? (
                    <p className="text-destructive text-center py-8">{t('common:error')}</p>
                  ) : resolvedConfig ? (
                    <div className="space-y-3">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-sm font-medium">{t('ReconciliationPage.resolved.templateChain')}</span>
                        {resolvedConfig.template_chain.map((name, i) => (
                          <div key={i} className="flex items-center gap-1">
                            {i > 0 && <ArrowRight className="h-3 w-3 text-muted-foreground" />}
                            <Badge variant="outline" className="text-xs">{name}</Badge>
                          </div>
                        ))}
                      </div>
                      <pre className="bg-muted/50 rounded-lg p-4 text-xs font-mono overflow-auto max-h-96 border border-border">
                        {JSON.stringify(resolvedConfig.resolved_config, null, 2)}
                      </pre>
                    </div>
                  ) : (
                    <p className="text-muted-foreground text-center py-8">{t('ReconciliationPage.resolved.empty')}</p>
                  )}
                </TabsContent>

                <TabsContent value="overrides" className="mt-4">
                  <pre className="bg-muted/50 rounded-lg p-4 text-xs font-mono overflow-auto max-h-96 border border-border">
                    {JSON.stringify(deviceConfig.device_overrides, null, 2) || '{}'}
                  </pre>
                </TabsContent>
              </Tabs>
            </div>
          ) : (
            <div className="py-8 text-center text-muted-foreground">
              <FileCode2 className="h-12 w-12 mx-auto mb-4 opacity-30" />
              <p>{t('ReconciliationPage.noConfig.title')}</p>
              <p className="text-sm mt-1">{t('ReconciliationPage.noConfig.description')}</p>
            </div>
          )}
        </DialogContent>
      </Dialog>

    </div>
  );
}

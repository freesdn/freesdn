// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN · Extensions & Ring Groups Page
 *
 * Canonical list-page pattern (matches ControllersPage):
 * PageHeader → StatsGrid → PageToolbar → DataTable → BulkActionsBar
 */

import { useState, useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { useSearchParams } from 'react-router-dom';
import { useQuery, useQueryClient, useMutation } from '@tanstack/react-query';
import { useSiteStore } from '@/stores/siteStore';
import {
  Hash,
  Users,
  Phone,
  AlertTriangle,
  Trash2,
  Power,
  PowerOff,
  Download,
  Plus,
} from 'lucide-react';
import { Card, CardContent } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { DataTable, type DataTableColumn } from '@/components/ui/data-table';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { SearchBar } from '@/components/ui/search-bar';
import { StatsGrid } from '@/components/ui/stats-grid';
import { BulkActionsBar } from '@/components/ui/bulk-actions-bar';
import { EmptyState } from '@/components/ui/empty-state';
import { voipApi, getApiErrorMessage } from '@/lib/api';
import { PageHeader, PageToolbar, PageTabs, type PageTab } from '@/components/layout';
import { useToast } from '@/hooks/use-toast';
import type { Extension, RingGroup, PBXSystem } from './types';

function RingStrategyBadge({ strategy }: { strategy?: string }) {
  const { t } = useTranslation('voip');
  const label =
    strategy?.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase()) ||
    t('ExtensionsPage.ringStrategy.ringAll');
  return (
    <Badge variant="outline" className="text-xs">
      {label}
    </Badge>
  );
}

export default function ExtensionsPage() {
  const { t } = useTranslation('voip');
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [searchParams] = useSearchParams();
  const defaultPBX = searchParams.get('pbx') || 'all';
  const [filterPBX, setFilterPBX] = useState(defaultPBX);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedExt, setSelectedExt] = useState<Extension[]>([]);
  const [selectedRG, setSelectedRG] = useState<RingGroup[]>([]);

  // Ring-group create dialog
  const emptyRgForm = {
    pbx_id: '',
    group_number: '',
    name: '',
    description: '',
    ring_strategy: 'ringall',
    ring_time: 20,
    members: '',
  };
  const [showRgDialog, setShowRgDialog] = useState(false);
  const [rgForm, setRgForm] = useState(emptyRgForm);

  const selectedSiteId = useSiteStore((s) => s.selectedSiteId);

  const { data: pbxRes, isError: pbxError } = useQuery({
    queryKey: ['voip-pbx', { siteId: selectedSiteId }],
    queryFn: () => voipApi.getPBXSystems(),
    staleTime: 60_000,
  });
  const pbxSystems: PBXSystem[] = pbxRes?.data?.items ?? pbxRes?.data ?? [];

  const {
    data: extRes,
    isLoading: extLoading,
    isError: extError,
    refetch: refetchExt,
  } = useQuery({
    queryKey: ['voip-all-extensions', { siteId: selectedSiteId }],
    queryFn: () => voipApi.getAllExtensions({ limit: 500, ...(selectedSiteId ? { site_id: selectedSiteId } : {}) }),
    refetchInterval: 30_000,
  });
  const {
    data: rgRes,
    isLoading: rgLoading,
    isError: rgError,
    refetch: refetchRG,
  } = useQuery({
    queryKey: ['voip-ring-groups', { siteId: selectedSiteId }],
    queryFn: () => voipApi.getRingGroups({ limit: 500, ...(selectedSiteId ? { site_id: selectedSiteId } : {}) }),
    refetchInterval: 30_000,
  });

  const allExtensions: Extension[] = useMemo(
    () => extRes?.data?.items ?? extRes?.data ?? [],
    [extRes],
  );
  const allRingGroups: RingGroup[] = useMemo(
    () => rgRes?.data?.items ?? rgRes?.data ?? [],
    [rgRes],
  );

  const extensions = useMemo(() => {
    let list = filterPBX === 'all' ? allExtensions : allExtensions.filter((e) => (e.pbx_id ?? e.pbx_system_id) === filterPBX);
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      list = list.filter(
        (e) =>
          e.extension_number?.toLowerCase().includes(q) ||
          (e.display_name || '').toLowerCase().includes(q) ||
          (e.caller_id_name || '').toLowerCase().includes(q),
      );
    }
    return list;
  }, [allExtensions, filterPBX, searchQuery]);

  const filteredGroups = useMemo(() => {
    let list = filterPBX === 'all' ? allRingGroups : allRingGroups.filter((g) => (g.pbx_id ?? g.pbx_system_id) === filterPBX);
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      list = list.filter(
        (g) =>
          g.name?.toLowerCase().includes(q) ||
          (g.group_number ?? g.extension_number)?.toLowerCase().includes(q),
      );
    }
    return list;
  }, [allRingGroups, filterPBX, searchQuery]);

  const hasActiveFilters = filterPBX !== 'all' || searchQuery !== '';

  // ── CSV export · serialize the loaded extension rows client-side ──

  function exportExtensionsCsv() {
    if (extensions.length === 0) return;
    const headers = ['extension_number', 'display_name', 'caller_id_name', 'extension_type', 'pbx', 'voicemail_enabled'];
    const escape = (v: unknown) => {
      const s = v == null ? '' : String(v);
      return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
    };
    const rows = extensions.map((e) => {
      const pbx = pbxSystems.find((p) => p.id === (e.pbx_id ?? e.pbx_system_id));
      return [
        e.extension_number, e.display_name, e.caller_id_name, (e.settings?.tech as string) || 'SIP', pbx?.name ?? '', e.voicemail_enabled ? 'yes' : 'no',
      ].map(escape).join(',');
    });
    const csv = [headers.join(','), ...rows].join('\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `extensions-${new Date().toISOString().slice(0, 10)}.csv`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  // ── Bulk delete · confirm + per-extension DELETE with a summary toast.
  // Each extension is removed via /voip/pbx/{pbxId}/extensions/{number}.
  async function handleBulkDeleteExtensions() {
    if (selectedExt.length === 0) return;
    if (!window.confirm(t('ExtensionsPage.toasts.bulkDelete') + ` (${selectedExt.length})`)) return;
    const results = await Promise.allSettled(
      selectedExt.map((e) => {
        const pbxId = e.pbx_id ?? e.pbx_system_id;
        if (!pbxId) return Promise.reject(new Error('no pbx'));
        return voipApi.deletePBXExtension(pbxId, e.extension_number);
      }),
    );
    const ok = results.filter((r) => r.status === 'fulfilled').length;
    const failed = results.length - ok;
    queryClient.invalidateQueries({ queryKey: ['voip-all-extensions'] });
    setSelectedExt([]);
    toast({
      title: t('ExtensionsPage.toasts.bulkDelete'),
      description: t('PhonesListPage.toasts.bulkConnectComplete.description', { succeeded: ok, failed, skipped: 0 }),
      variant: failed > 0 ? 'destructive' : undefined,
    });
  }

  // ── Bulk voicemail toggle · per-extension PATCH with a summary toast.
  // Each extension's voicemail_enabled is flipped via
  // /voip/pbx/{pbxId}/extensions/{number} (ExtensionUpdate.voicemail_enabled).
  async function handleBulkVoicemail(enabled: boolean) {
    if (selectedExt.length === 0) return;
    const results = await Promise.allSettled(
      selectedExt.map((e) => {
        const pbxId = e.pbx_id ?? e.pbx_system_id;
        if (!pbxId) return Promise.reject(new Error('no pbx'));
        return voipApi.updatePBXExtension(pbxId, e.extension_number, { voicemail_enabled: enabled });
      }),
    );
    const ok = results.filter((r) => r.status === 'fulfilled').length;
    const failed = results.length - ok;
    queryClient.invalidateQueries({ queryKey: ['voip-all-extensions'] });
    setSelectedExt([]);
    toast({
      title: t('ExtensionsPage.toasts.bulkAction'),
      description: t(
        enabled ? 'ExtensionsPage.toasts.enableVoicemail' : 'ExtensionsPage.toasts.disableVoicemail',
        { count: ok },
      ) + (failed > 0 ? ` (${failed} failed)` : ''),
      variant: failed > 0 ? 'destructive' : undefined,
    });
  }

  // ── Ring-group create · POST /voip/ring-groups ──
  const createRgMutation = useMutation({
    mutationFn: () => {
      const members = rgForm.members
        .split(',')
        .map((m) => m.trim())
        .filter(Boolean);
      return voipApi.createRingGroup({
        pbx_id: rgForm.pbx_id,
        group_number: rgForm.group_number,
        name: rgForm.name,
        description: rgForm.description || undefined,
        ring_strategy: rgForm.ring_strategy,
        ring_time: Number(rgForm.ring_time) || 20,
        members,
      });
    },
    onSuccess: () => {
      toast({ title: t('ExtensionsPage.tabs.ringGroups') + ' · ' + t('common:create') });
      setShowRgDialog(false);
      setRgForm(emptyRgForm);
      refetchRG();
    },
    onError: (err: unknown) =>
      toast({
        title: getApiErrorMessage(err, t('ExtensionsPage.errors.partialLoad')),
        variant: 'destructive',
      }),
  });

  // ── Ring-group bulk delete · DELETE /voip/ring-groups/{id} ──
  async function handleBulkDeleteRingGroups() {
    if (selectedRG.length === 0) return;
    if (!window.confirm(t('ExtensionsPage.toasts.bulkDelete') + ` (${selectedRG.length})`)) return;
    const results = await Promise.allSettled(
      selectedRG.map((g) => voipApi.deleteRingGroup(g.id)),
    );
    const ok = results.filter((r) => r.status === 'fulfilled').length;
    const failed = results.length - ok;
    queryClient.invalidateQueries({ queryKey: ['voip-ring-groups'] });
    setSelectedRG([]);
    refetchRG();
    toast({
      title: t('ExtensionsPage.toasts.bulkDelete'),
      description: t('PhonesListPage.toasts.bulkConnectComplete.description', { succeeded: ok, failed, skipped: 0 }),
      variant: failed > 0 ? 'destructive' : undefined,
    });
  }

  const extColumns: DataTableColumn<Extension>[] = [
    {
      id: 'extension',
      header: t('ExtensionsPage.columns.extension'),
      cell: (row) => (
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-muted">
            <Hash className="h-4 w-4 text-muted-foreground" />
          </div>
          <div>
            <p className="font-medium font-mono">{row.extension_number}</p>
            <p className="text-xs text-muted-foreground">
              {row.display_name || row.caller_id_name || '-'}
            </p>
          </div>
        </div>
      ),
      sortable: true,
    },
    {
      id: 'caller_id',
      header: t('ExtensionsPage.columns.callerId'),
      cell: (row) => <span className="text-sm">{row.caller_id_name || '-'}</span>,
    },
    {
      id: 'type',
      header: t('ExtensionsPage.columns.type'),
      cell: (row) => <Badge variant="outline">{(row.settings?.tech as string) || 'SIP'}</Badge>,
    },
    {
      id: 'pbx',
      header: t('ExtensionsPage.columns.pbx'),
      cell: (row) => {
        const pbx = pbxSystems.find((p) => p.id === (row.pbx_id ?? row.pbx_system_id));
        return <span className="text-sm text-muted-foreground">{pbx?.name || '-'}</span>;
      },
    },
    {
      id: 'voicemail',
      header: t('ExtensionsPage.columns.voicemail'),
      cell: (row) =>
        row.voicemail_enabled ? (
          <Badge variant="secondary" className="text-xs">
            {t('ExtensionsPage.voicemail.enabled')}
          </Badge>
        ) : (
          <span className="text-xs text-muted-foreground">-</span>
        ),
    },
  ];

  const rgColumns: DataTableColumn<RingGroup>[] = [
    {
      id: 'name',
      header: t('ExtensionsPage.columns.ringGroup'),
      cell: (row) => (
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-muted">
            <Users className="h-4 w-4 text-muted-foreground" />
          </div>
          <div>
            <p className="font-medium">{row.name}</p>
            <p className="text-xs text-muted-foreground font-mono">{row.group_number ?? row.extension_number}</p>
          </div>
        </div>
      ),
    },
    {
      id: 'strategy',
      header: t('ExtensionsPage.columns.strategy'),
      cell: (row) => <RingStrategyBadge strategy={row.ring_strategy} />,
    },
    {
      id: 'members',
      header: t('ExtensionsPage.columns.members'),
      cell: (row) => (
        <div className="flex items-center gap-2">
          <Badge variant="outline">{row.members?.length ?? 0}</Badge>
          <span className="text-xs text-muted-foreground truncate max-w-[140px]">
            {row.members?.slice(0, 3).join(', ')}
            {row.members && row.members.length > 3 ? '…' : ''}
          </span>
        </div>
      ),
    },
    {
      id: 'ring_time',
      header: t('ExtensionsPage.columns.ringTime'),
      cell: (row) => (
        <span className="text-sm">
          {t('ExtensionsPage.ringTimeSeconds', { seconds: row.ring_time ?? 25 })}
        </span>
      ),
    },
    {
      id: 'pbx',
      header: t('ExtensionsPage.columns.pbx'),
      cell: (row) => {
        const pbx = pbxSystems.find((p) => p.id === (row.pbx_id ?? row.pbx_system_id));
        return <span className="text-sm text-muted-foreground">{pbx?.name || '-'}</span>;
      },
    },
  ];

  return (
    <div className="space-y-6">
      <PageHeader
        icon={Hash}
        title={t('ExtensionsPage.header.title')}
        description={t('ExtensionsPage.header.description', {
          extensions: extensions.length,
          ringGroups: filteredGroups.length,
        })}
        onRefresh={() => {
          refetchExt();
          refetchRG();
        }}
        refreshing={extLoading || rgLoading}
        primaryAction={{
          label: t('ExtensionsPage.tabs.ringGroups'),
          icon: Plus,
          onClick: () => {
            // Default the PBX selector to the active filter (or the only PBX).
            const defaultPbx =
              filterPBX !== 'all' ? filterPBX : pbxSystems.length === 1 ? pbxSystems[0].id : '';
            setRgForm({ ...emptyRgForm, pbx_id: defaultPbx });
            setShowRgDialog(true);
          },
          disabled: pbxSystems.length === 0,
        }}
        secondaryActions={[
          { label: t('ExtensionsPage.actions.export'), icon: Download, onClick: exportExtensionsCsv, disabled: extensions.length === 0 },
        ]}
      />

      {(pbxError || extError || rgError) && (
        <Card className="border-destructive">
          <CardContent noOffset className="p-4 flex items-center gap-3">
            <AlertTriangle className="h-5 w-5 text-destructive" />
            <span className="text-sm">{t('ExtensionsPage.errors.partialLoad')}</span>
          </CardContent>
        </Card>
      )}

      <StatsGrid
        columns={2}
        isLoading={extLoading || rgLoading}
        stats={[
          {
            title: t('ExtensionsPage.stats.extensions.title'),
            value: allExtensions.length,
            icon: Hash,
            variant: 'primary',
            description: t('ExtensionsPage.stats.extensions.description'),
          },
          {
            title: t('ExtensionsPage.stats.ringGroups.title'),
            value: allRingGroups.length,
            icon: Users,
            variant: 'info',
            description: t('ExtensionsPage.stats.ringGroups.description'),
          },
        ]}
      />

      <PageToolbar>
        <SearchBar
          value={searchQuery}
          onChange={setSearchQuery}
          placeholder={t('ExtensionsPage.toolbar.searchPlaceholder')}
          className="w-full sm:w-auto"
        />
        <Select value={filterPBX} onValueChange={setFilterPBX}>
          <SelectTrigger className="w-full sm:w-[200px]">
            <SelectValue placeholder={t('ExtensionsPage.toolbar.allPbxSystems')} />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">{t('ExtensionsPage.toolbar.allPbxSystems')}</SelectItem>
            {pbxSystems.map((p) => (
              <SelectItem key={p.id} value={p.id}>
                {p.name}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        {hasActiveFilters && (
          <Button
            variant="ghost"
            size="sm"
            onClick={() => {
              setSearchQuery('');
              setFilterPBX('all');
            }}
          >
            {t('ExtensionsPage.toolbar.clearFilters')}
          </Button>
        )}
      </PageToolbar>

      <PageTabs
        basePath="/voip/extensions"
        tabs={[
          {
            value: 'extensions',
            label: t('ExtensionsPage.tabs.extensions'),
            count: extensions.length,
            content: (
              <>
                <DataTable
                  data={extensions}
                  columns={extColumns}
                  isLoading={extLoading}
                  selectable
                  onSelectionChange={setSelectedExt}
                  searchable={false}
                  itemName="extensions"
                  paginated
                  defaultPageSize={25}
                  getRowId={(row) => row.id}
                  emptyState={
                    <EmptyState
                      icon={Phone}
                      title={t('ExtensionsPage.empty.extensions.title')}
                      description={t('ExtensionsPage.empty.extensions.description')}
                    />
                  }
                />
                <BulkActionsBar
                  selectedCount={selectedExt.length}
                  itemName="extension"
                  onClear={() => setSelectedExt([])}
                  actions={[
                    {
                      label: t('ExtensionsPage.bulk.enableVm'),
                      icon: Power,
                      onClick: () => handleBulkVoicemail(true),
                    },
                    {
                      label: t('ExtensionsPage.bulk.disableVm'),
                      icon: PowerOff,
                      onClick: () => handleBulkVoicemail(false),
                    },
                    {
                      label: t('ExtensionsPage.bulk.delete'),
                      icon: Trash2,
                      variant: 'destructive',
                      onClick: handleBulkDeleteExtensions,
                    },
                  ]}
                />
              </>
            ),
          },
          {
            value: 'ringgroups',
            label: t('ExtensionsPage.tabs.ringGroups'),
            count: filteredGroups.length,
            content: (
              <>
                <DataTable
                  data={filteredGroups}
                  columns={rgColumns}
                  isLoading={rgLoading}
                  selectable
                  onSelectionChange={setSelectedRG}
                  searchable={false}
                  itemName="ring groups"
                  paginated
                  defaultPageSize={15}
                  getRowId={(row) => row.id}
                  emptyState={
                    <EmptyState icon={Phone} title={t('ExtensionsPage.empty.ringGroups.title')} />
                  }
                />
                <BulkActionsBar
                  selectedCount={selectedRG.length}
                  itemName="ring group"
                  onClear={() => setSelectedRG([])}
                  actions={[
                    {
                      label: t('ExtensionsPage.bulk.delete'),
                      icon: Trash2,
                      variant: 'destructive',
                      onClick: handleBulkDeleteRingGroups,
                    },
                  ]}
                />
              </>
            ),
          },
        ] satisfies PageTab[]}
      />

      {/* Add Ring Group dialog, mirrors the PBX extension-create form. */}
      <Dialog open={showRgDialog} onOpenChange={setShowRgDialog}>
        <DialogContent className="sm:max-w-[480px]">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Users className="h-5 w-5" />
              {t('ExtensionsPage.tabs.ringGroups')}
            </DialogTitle>
            <DialogDescription>
              {t('ExtensionsPage.stats.ringGroups.description')}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-2">
            <div className="space-y-2">
              <Label>{t('ExtensionsPage.columns.pbx')}</Label>
              <Select
                value={rgForm.pbx_id}
                onValueChange={(v) => setRgForm((f) => ({ ...f, pbx_id: v }))}
              >
                <SelectTrigger>
                  <SelectValue placeholder={t('ExtensionsPage.toolbar.allPbxSystems')} />
                </SelectTrigger>
                <SelectContent>
                  {pbxSystems.map((p) => (
                    <SelectItem key={p.id} value={p.id}>
                      {p.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-2">
                <Label>{t('ExtensionsPage.columns.ringGroup')}</Label>
                <Input
                  placeholder="600"
                  value={rgForm.group_number}
                  onChange={(e) => setRgForm((f) => ({ ...f, group_number: e.target.value }))}
                />
              </div>
              <div className="space-y-2">
                <Label>{t('ExtensionsPage.columns.ringTime')}</Label>
                <Input
                  type="number"
                  min={1}
                  max={300}
                  value={rgForm.ring_time}
                  onChange={(e) => setRgForm((f) => ({ ...f, ring_time: Number(e.target.value) }))}
                />
              </div>
            </div>
            <div className="space-y-2">
              <Label>{t('ExtensionsPage.columns.ringGroup')}</Label>
              <Input
                value={rgForm.name}
                onChange={(e) => setRgForm((f) => ({ ...f, name: e.target.value }))}
              />
            </div>
            <div className="space-y-2">
              <Label>{t('ExtensionsPage.columns.strategy')}</Label>
              <Select
                value={rgForm.ring_strategy}
                onValueChange={(v) => setRgForm((f) => ({ ...f, ring_strategy: v }))}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="ringall">{t('ExtensionsPage.ringStrategy.ringAll')}</SelectItem>
                  <SelectItem value="hunt">hunt</SelectItem>
                  <SelectItem value="memoryhunt">memoryhunt</SelectItem>
                  <SelectItem value="firstavail">firstavail</SelectItem>
                  <SelectItem value="random">random</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label>{t('ExtensionsPage.columns.members')}</Label>
              <Input
                placeholder="100, 101, 102"
                value={rgForm.members}
                onChange={(e) => setRgForm((f) => ({ ...f, members: e.target.value }))}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowRgDialog(false)}>
              {t('common:cancel')}
            </Button>
            <Button
              onClick={() => createRgMutation.mutate()}
              disabled={
                !rgForm.pbx_id ||
                !rgForm.group_number ||
                !rgForm.name ||
                createRgMutation.isPending
              }
            >
              {createRgMutation.isPending ? t('common:loading') : t('common:create')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

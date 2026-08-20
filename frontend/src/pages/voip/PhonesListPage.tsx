// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN · Phone Fleet List Page
 *
 * Full GDMS-style phone fleet table with:
 *  - Advanced filters (lifecycle, vendor, template, status, search)
 *  - Bulk operations (reboot, provision, firmware)
 *  - Lifecycle actions (onboard, decommission, maintenance)
 *  - Grid + Table views
 */
/* eslint-disable @typescript-eslint/no-explicit-any */

import { useState, useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useSiteStore } from '@/stores/siteStore';
import {
  Phone, Plus, Upload, Wrench, XCircle,
  MoreHorizontal, Radar, Power, Settings,
  Eye, Trash2, CheckCircle, LayoutGrid, List,
  Plug, Loader2, AlertCircle, Wifi, WifiOff, KeyRound,
  Shield, Monitor, Hash, Globe, EyeOff, AlertTriangle,
  Link2,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { DataTable, type DataTableColumn } from '@/components/ui/data-table';
import { EmptyState } from '@/components/ui/empty-state';
import { Badge } from '@/components/ui/badge';
import {
  DropdownMenu, DropdownMenuContent, DropdownMenuItem,
  DropdownMenuSeparator, DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import {
  Dialog, DialogContent, DialogDescription, DialogFooter,
  DialogHeader, DialogTitle,
} from '@/components/ui/dialog';
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from '@/components/ui/select';
import { Label } from '@/components/ui/label';
import { Progress } from '@/components/ui/progress';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Separator } from '@/components/ui/separator';
import { useToast } from '@/hooks/use-toast';
import { voipApi } from '@/lib/api';
import { PageHeader, PageToolbar } from '@/components/layout';
import { StatsGrid } from '@/components/ui/stats-grid';
import { BulkActionsBar } from '@/components/ui/bulk-actions-bar';
import { SearchBar } from '@/components/ui/search-bar';
import { Download } from 'lucide-react';
import { PhoneStatusBadge, LifecycleBadge, ProvisionBadge, SIPIndicator, VendorLabel, formatTimeAgo } from './components';
import type { VoIPPhone } from './types';

export default function PhonesListPage() {
  const { t } = useTranslation('voip');
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [searchParams] = useSearchParams();
  const { toast } = useToast();

  const [search, setSearch] = useState('');
  const [filterLifecycle, setFilterLifecycle] = useState(searchParams.get('lifecycle') || 'all');
  const [filterVendor, setFilterVendor] = useState('all');
  const [filterStatus, setFilterStatus] = useState('all');
  const [viewMode, setViewMode] = useState<'table' | 'grid'>('table');
  const [showAddDialog, setShowAddDialog] = useState(searchParams.get('action') === 'add');
  const [showOnboardDialog, setShowOnboardDialog] = useState(false);
  const [showBulkConnectDialog, setShowBulkConnectDialog] = useState(false);
  const [selectedPhone, setSelectedPhone] = useState<VoIPPhone | null>(null);
  const [selectedIds, setSelectedIds] = useState<string[]>([]);
  const [bulkConnectCreds, setBulkConnectCreds] = useState({ username: 'admin', password: '' });
  const [showBulkPassword, setShowBulkPassword] = useState(false);
  const [bulkConnectResults, setBulkConnectResults] = useState<any>(null);

  // Site context
  const selectedSiteId = useSiteStore((s) => s.selectedSiteId);

  // ── Queries ──

  const { data: phonesRes, isLoading, isError: phonesError, refetch } = useQuery({
    queryKey: ['voip-phones', filterLifecycle, filterVendor, filterStatus, search, { siteId: selectedSiteId }],
    queryFn: () => voipApi.getPhones({
      limit: 500,
      ...(selectedSiteId ? { site_id: selectedSiteId } : {}),
      status: filterStatus !== 'all' ? filterStatus : undefined,
      lifecycle_state: filterLifecycle !== 'all' ? filterLifecycle : undefined,
      vendor: filterVendor !== 'all' ? filterVendor : undefined,
      search: search || undefined,
    } as any),
    refetchInterval: 30_000,
    staleTime: 10_000,
  });

  const phones: VoIPPhone[] = phonesRes?.data?.items ?? [];

  const { data: templatesRes, isError: templatesError } = useQuery({
    queryKey: ['voip-templates-list'],
    queryFn: () => voipApi.getTemplates({ limit: 100 }),
    staleTime: 60_000,
  });
  const templates = templatesRes?.data?.items ?? [];

  // ── Mutations ──

  const deleteMutation = useMutation({
    mutationFn: (id: string) => voipApi.deletePhone(id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['voip-phones'] }),
    onError: (err: any) => toast({ title: t('PhonesListPage.toasts.deleteFailed'), description: err?.response?.data?.detail || err.message, variant: 'destructive' }),
  });

  const onboardMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: any }) => voipApi.onboardPhone(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['voip-phones'] });
      setShowOnboardDialog(false);
      setSelectedPhone(null);
    },
    onError: (err: any) => toast({ title: t('PhonesListPage.toasts.onboardFailed'), description: err?.response?.data?.detail || err.message, variant: 'destructive' }),
  });

  const decommissionMutation = useMutation({
    mutationFn: (id: string) => voipApi.decommissionPhone(id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['voip-phones'] }),
    onError: (err: any) => toast({ title: t('PhonesListPage.toasts.decommissionFailed'), description: err?.response?.data?.detail || err.message, variant: 'destructive' }),
  });

  const maintenanceMutation = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) => voipApi.toggleMaintenance(id, enabled),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['voip-phones'] }),
    onError: (err: any) => toast({ title: t('PhonesListPage.toasts.maintenanceFailed'), description: err?.response?.data?.detail || err.message, variant: 'destructive' }),
  });

  const provisionMutation = useMutation({
    mutationFn: (id: string) => voipApi.provisionPhone(id, { force: true }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['voip-phones'] }),
    onError: (err: any) => toast({ title: t('PhonesListPage.toasts.provisionFailed'), description: err?.response?.data?.detail || err.message, variant: 'destructive' }),
  });

  const bulkRebootMutation = useMutation({
    mutationFn: (ids: string[]) => voipApi.bulkReboot(ids),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['voip-phones'] }),
    onError: (err: any) => toast({ title: t('PhonesListPage.toasts.bulkRebootFailed'), description: err?.response?.data?.detail || err.message, variant: 'destructive' }),
  });

  const bulkProvisionMutation = useMutation({
    mutationFn: (ids: string[]) => voipApi.bulkProvision(ids),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['voip-phones'] }),
    onError: (err: any) => toast({ title: t('PhonesListPage.toasts.bulkProvisionFailed'), description: err?.response?.data?.detail || err.message, variant: 'destructive' }),
  });

  const bulkConnectMutation = useMutation({
    mutationFn: ({ ids, username, password }: { ids: string[]; username: string; password: string }) =>
      voipApi.bulkConnect(ids, username, password),
    onSuccess: (res) => {
      const data = res.data;
      setBulkConnectResults(data);
      queryClient.invalidateQueries({ queryKey: ['voip-phones'] });
      toast({
        title: t('PhonesListPage.toasts.bulkConnectComplete.title'),
        description: t('PhonesListPage.toasts.bulkConnectComplete.description', {
          succeeded: data.succeeded,
          failed: data.failed,
          skipped: data.skipped,
        }),
      });
    },
    onError: (err: any) => {
      toast({
        title: t('PhonesListPage.toasts.bulkConnectFailed'),
        description: err?.response?.data?.detail || err.message,
        variant: 'destructive',
      });
    },
  });

  // ── Add Phone Dialog State ──
  const [newPhone, setNewPhone] = useState({
    name: '', mac_address: '', ip_address: '', vendor: 'grandstream',
    model: '', location: '',
  });

  const createMutation = useMutation({
    mutationFn: (data: any) => voipApi.createPhone(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['voip-phones'] });
      setShowAddDialog(false);
      setNewPhone({ name: '', mac_address: '', ip_address: '', vendor: 'grandstream', model: '', location: '' });
    },
    onError: (err: any) => toast({ title: t('PhonesListPage.toasts.createFailed'), description: err?.response?.data?.detail || err.message, variant: 'destructive' }),
  });

  // Auto-link discovered phones to PBX extensions in one click.
  // Match rule: phone.sip_registrar → pbx.ip_address AND
  // phone.sip_user_id → extension.extension_number. Re-running is
  // safe, already-linked phones are skipped server-side.
  const autoLinkMutation = useMutation({
    mutationFn: () => voipApi.autoLinkPhones({
      site_id: selectedSiteId || undefined,
    }),
    onSuccess: (res: any) => {
      const d = res?.data;
      const counts = d?.counts || {};
      const linked = counts.linked || 0;
      const skipped = counts.skipped || 0;
      const alreadyLinked = counts.already_linked || 0;
      queryClient.invalidateQueries({ queryKey: ['voip-phones'] });
      if (linked > 0) {
        toast({
          title: t('PhonesListPage.toasts.autoLink.linked.title', { count: linked }),
          description: t('PhonesListPage.toasts.autoLink.linked.description', { alreadyLinked, skipped }),
        });
      } else if (alreadyLinked > 0) {
        toast({
          title: t('PhonesListPage.toasts.autoLink.allLinked.title'),
          description: t('PhonesListPage.toasts.autoLink.allLinked.description', { alreadyLinked }),
        });
      } else {
        toast({
          title: t('PhonesListPage.toasts.autoLink.none.title'),
          description: skipped > 0
            ? t('PhonesListPage.toasts.autoLink.none.skipped', { skipped })
            : t('PhonesListPage.toasts.autoLink.none.noSip'),
        });
      }
    },
    onError: (err: any) => toast({
      title: t('PhonesListPage.toasts.autoLink.failed'),
      description: err?.response?.data?.detail || err.message,
      variant: 'destructive',
    }),
  });

  // ── Onboard Dialog State ──
  const [onboardData, setOnboardData] = useState({
    name: '', config_template_id: '', location: '',
  });

  // ── CSV export · serialize the loaded phone rows client-side ──

  function exportPhonesCsv() {
    if (phones.length === 0) return;
    const headers = ['name', 'status', 'lifecycle_state', 'ip_address', 'mac_address', 'vendor', 'model', 'extension', 'firmware_version', 'location', 'last_seen'];
    const escape = (v: unknown) => {
      const s = v == null ? '' : String(v);
      return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
    };
    const rows = phones.map((p) => [
      p.name, p.status, p.lifecycle_state, p.ip_address, p.mac_address, p.vendor, p.model, p.extension, p.firmware_version, p.location, p.last_seen,
    ].map(escape).join(','));
    const csv = [headers.join(','), ...rows].join('\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `phones-${new Date().toISOString().slice(0, 10)}.csv`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  // ── Bulk delete · confirm + per-phone delete with a summary toast ──

  async function handleBulkDelete() {
    if (selectedIds.length === 0) return;
    if (!window.confirm(t('PhonesListPage.toasts.bulkDelete.title') + ` (${selectedIds.length})`)) return;
    const results = await Promise.allSettled(selectedIds.map((id) => voipApi.deletePhone(id)));
    const ok = results.filter((r) => r.status === 'fulfilled').length;
    const failed = results.length - ok;
    queryClient.invalidateQueries({ queryKey: ['voip-phones'] });
    setSelectedIds([]);
    toast({
      title: t('PhonesListPage.toasts.bulkDelete.title'),
      description: t('PhonesListPage.toasts.bulkConnectComplete.description', { succeeded: ok, failed, skipped: 0 }),
      variant: failed > 0 ? 'destructive' : undefined,
    });
  }

  // ── Column defs ──

  const columns: DataTableColumn<VoIPPhone>[] = useMemo(() => [
    {
      id: 'name',
      header: t('PhonesListPage.columns.device'),
      cell: (row) => (
        <div className="flex flex-col gap-0.5">
          <span className="font-medium truncate max-w-[200px]">{row.name || row.mac_address || t('PhonesListPage.unnamed')}</span>
          <span className="text-xs text-muted-foreground">{row.model || row.vendor || ''}</span>
        </div>
      ),
      sortable: true,
    },
    {
      id: 'status',
      header: t('PhonesListPage.columns.status'),
      cell: (row) => (
        <div className="flex flex-col gap-1">
          <PhoneStatusBadge status={row.status} />
          <SIPIndicator registered={row.sip_registered} />
        </div>
      ),
    },
    {
      id: 'lifecycle',
      header: t('PhonesListPage.columns.lifecycle'),
      cell: (row) => <LifecycleBadge state={row.lifecycle_state} />,
    },
    {
      id: 'ip_mac',
      header: t('PhonesListPage.columns.network'),
      cell: (row) => (
        <div className="flex flex-col gap-0.5 text-xs font-mono">
          {row.ip_address && <span>{row.ip_address}</span>}
          {row.mac_address && <span className="text-muted-foreground">{row.mac_address}</span>}
        </div>
      ),
    },
    {
      id: 'vendor',
      header: t('PhonesListPage.columns.vendor'),
      cell: (row) => <VendorLabel vendor={row.vendor} />,
    },
    {
      id: 'extension',
      header: t('PhonesListPage.columns.extension'),
      cell: (row) => {
        // ``extension`` + ``extension_display`` populated when the
        // phone is linked to a FreePBX extension via auto-link or
        // manual onboard. Falls back to ``sip_user`` (what the phone
        // reports it's *trying* to register as) so the operator can
        // tell when a phone is registered but not yet bound.
        if (row.extension) {
          return (
            <div className="flex flex-col gap-0.5">
              <span className="font-mono text-sm">{row.extension}</span>
              {row.extension_display && row.extension_display !== row.extension && (
                <span className="text-xs text-muted-foreground truncate max-w-[160px]">
                  {row.extension_display}
                </span>
              )}
              {row.pbx_system_name && (
                <span className="text-[10px] text-muted-foreground truncate max-w-[160px]">
                  {t('PhonesListPage.extension.onPbx', { name: row.pbx_system_name })}
                </span>
              )}
            </div>
          );
        }
        if (row.sip_user) {
          return (
            <div className="flex flex-col gap-0.5">
              <span className="font-mono text-sm text-muted-foreground">{row.sip_user}</span>
              <span className="text-[10px] text-amber-600">{t('PhonesListPage.extension.unlinked')}</span>
            </div>
          );
        }
        return <span className="text-xs text-muted-foreground">-</span>;
      },
    },
    {
      id: 'firmware',
      header: t('PhonesListPage.columns.firmware'),
      cell: (row) => (
        <span className="text-xs font-mono">{row.firmware_version || '-'}</span>
      ),
    },
    {
      id: 'provision',
      header: t('PhonesListPage.columns.provisioning'),
      cell: (row) => <ProvisionBadge status={row.provision_status} />,
    },
    {
      id: 'location',
      header: t('PhonesListPage.columns.location'),
      accessorKey: 'location',
      cell: (row) => <span className="text-sm truncate max-w-[120px]">{row.location || '-'}</span>,
    },
    {
      id: 'last_seen',
      header: t('PhonesListPage.columns.lastSeen'),
      cell: (row) => <span className="text-xs text-muted-foreground">{formatTimeAgo(row.last_seen)}</span>,
    },
    {
      id: 'actions',
      header: '',
      cell: (row) => (
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" size="icon" className="h-8 w-8">
              <MoreHorizontal className="h-4 w-4" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end">
            <DropdownMenuItem onClick={() => navigate(`/voip/phones/${row.id}`)}>
              <Eye className="h-4 w-4 mr-2" /> {t('PhonesListPage.rowActions.viewDetails')}
            </DropdownMenuItem>
            {row.lifecycle_state === 'discovered' && (
              <DropdownMenuItem onClick={() => { setSelectedPhone(row); setShowOnboardDialog(true); setOnboardData({ name: row.name || '', config_template_id: '', location: row.location || '' }); }}>
                <Upload className="h-4 w-4 mr-2" /> {t('PhonesListPage.rowActions.onboard')}
              </DropdownMenuItem>
            )}
            {row.lifecycle_state === 'managed' && (
              <>
                <DropdownMenuItem onClick={() => provisionMutation.mutate(row.id)}>
                  <Settings className="h-4 w-4 mr-2" /> {t('PhonesListPage.rowActions.reprovision')}
                </DropdownMenuItem>
                <DropdownMenuItem onClick={() => maintenanceMutation.mutate({ id: row.id, enabled: true })}>
                  <Wrench className="h-4 w-4 mr-2" /> {t('PhonesListPage.rowActions.maintenanceMode')}
                </DropdownMenuItem>
              </>
            )}
            {row.lifecycle_state === 'maintenance' && (
              <DropdownMenuItem onClick={() => maintenanceMutation.mutate({ id: row.id, enabled: false })}>
                <CheckCircle className="h-4 w-4 mr-2" /> {t('PhonesListPage.rowActions.exitMaintenance')}
              </DropdownMenuItem>
            )}
            <DropdownMenuSeparator />
            <DropdownMenuItem onClick={() => decommissionMutation.mutate(row.id)} className="text-warning focus:text-warning">
              <XCircle className="h-4 w-4 mr-2" /> {t('PhonesListPage.rowActions.decommission')}
            </DropdownMenuItem>
            <DropdownMenuItem onClick={() => deleteMutation.mutate(row.id)} className="text-destructive focus:text-destructive">
              <Trash2 className="h-4 w-4 mr-2" /> {t('PhonesListPage.rowActions.delete')}
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      ),
    },
  ], [t, navigate, provisionMutation, maintenanceMutation, decommissionMutation, deleteMutation]);

  // ── Render ──

  // ── Stats ──
  const onlineCount = phones.filter((p) => p.status === 'online').length;
  const managedCount = phones.filter((p) => p.lifecycle_state === 'managed').length;
  const sipRegisteredCount = phones.filter((p) => p.sip_registered).length;
  const hasActiveFilters =
    search !== '' || filterLifecycle !== 'all' || filterVendor !== 'all' || filterStatus !== 'all';

  return (
    <div className="space-y-6">
      <PageHeader
        icon={Phone}
        title={t('PhonesListPage.header.title')}
        description={t('PhonesListPage.header.description', { count: phones.length })}
        onRefresh={() => refetch()}
        refreshing={isLoading}
        primaryAction={{ label: t('PhonesListPage.actions.addPhone'), icon: Plus, onClick: () => setShowAddDialog(true) }}
        secondaryActions={[
          {
            label: autoLinkMutation.isPending ? t('PhonesListPage.actions.linking') : t('PhonesListPage.actions.autoLink'),
            icon: Link2,
            onClick: () => autoLinkMutation.mutate(),
            disabled: autoLinkMutation.isPending,
          },
          { label: t('PhonesListPage.actions.discover'), icon: Radar, onClick: () => navigate('/voip/discovery') },
          { label: t('PhonesListPage.actions.export'), icon: Download, onClick: exportPhonesCsv, disabled: phones.length === 0 },
        ]}
      />

      {(phonesError || templatesError) && (
        <Card className="border-destructive">
          <CardContent noOffset className="p-4 flex items-center gap-3">
            <AlertTriangle className="h-5 w-5 text-destructive" />
            <span className="text-sm">{t('PhonesListPage.errors.partialLoad')}</span>
          </CardContent>
        </Card>
      )}

      <StatsGrid
        columns={4}
        isLoading={isLoading}
        stats={[
          {
            title: t('PhonesListPage.stats.totalPhones.title'),
            value: phones.length,
            icon: Phone,
            variant: 'primary',
            description: t('PhonesListPage.stats.totalPhones.description'),
          },
          {
            title: t('PhonesListPage.stats.online.title'),
            value: onlineCount,
            icon: Wifi,
            variant: 'success',
            description: phones.length > 0
              ? t('PhonesListPage.stats.online.reachable', { percent: Math.round((onlineCount / phones.length) * 100) })
              : t('PhonesListPage.stats.online.noPhones'),
          },
          {
            title: t('PhonesListPage.stats.managed.title'),
            value: managedCount,
            icon: CheckCircle,
            variant: 'info',
            description: t('PhonesListPage.stats.managed.description'),
          },
          {
            title: t('PhonesListPage.stats.sipRegistered.title'),
            value: sipRegisteredCount,
            icon: Plug,
            variant: 'success',
            description: t('PhonesListPage.stats.sipRegistered.description'),
          },
        ]}
      />

      <PageToolbar>
        <SearchBar
          value={search}
          onChange={setSearch}
          placeholder={t('PhonesListPage.filters.searchPlaceholder')}
          className="w-full sm:w-auto"
        />
        <Select value={filterLifecycle} onValueChange={setFilterLifecycle}>
          <SelectTrigger className="w-full sm:w-[160px]"><SelectValue placeholder={t('PhonesListPage.filters.lifecycle.placeholder')} /></SelectTrigger>
          <SelectContent>
            <SelectItem value="all">{t('PhonesListPage.filters.lifecycle.all')}</SelectItem>
            <SelectItem value="discovered">{t('PhonesListPage.filters.lifecycle.discovered')}</SelectItem>
            <SelectItem value="onboarding">{t('PhonesListPage.filters.lifecycle.onboarding')}</SelectItem>
            <SelectItem value="managed">{t('PhonesListPage.filters.lifecycle.managed')}</SelectItem>
            <SelectItem value="maintenance">{t('PhonesListPage.filters.lifecycle.maintenance')}</SelectItem>
            <SelectItem value="decommissioned">{t('PhonesListPage.filters.lifecycle.decommissioned')}</SelectItem>
          </SelectContent>
        </Select>
        <Select value={filterVendor} onValueChange={setFilterVendor}>
          <SelectTrigger className="w-full sm:w-[160px]"><SelectValue placeholder={t('PhonesListPage.filters.vendor.placeholder')} /></SelectTrigger>
          <SelectContent>
            <SelectItem value="all">{t('PhonesListPage.filters.vendor.all')}</SelectItem>
            <SelectItem value="grandstream">Grandstream</SelectItem>
            <SelectItem value="yealink">Yealink</SelectItem>
            <SelectItem value="polycom">Polycom</SelectItem>
            <SelectItem value="cisco">Cisco</SelectItem>
            <SelectItem value="fanvil">Fanvil</SelectItem>
          </SelectContent>
        </Select>
        <Select value={filterStatus} onValueChange={setFilterStatus}>
          <SelectTrigger className="w-full sm:w-[140px]"><SelectValue placeholder={t('PhonesListPage.filters.status.placeholder')} /></SelectTrigger>
          <SelectContent>
            <SelectItem value="all">{t('PhonesListPage.filters.status.all')}</SelectItem>
            <SelectItem value="online">{t('PhonesListPage.filters.status.online')}</SelectItem>
            <SelectItem value="offline">{t('PhonesListPage.filters.status.offline')}</SelectItem>
            <SelectItem value="in_call">{t('PhonesListPage.filters.status.inCall')}</SelectItem>
          </SelectContent>
        </Select>
        {hasActiveFilters && (
          <Button
            variant="ghost"
            size="sm"
            onClick={() => {
              setSearch('');
              setFilterLifecycle('all');
              setFilterVendor('all');
              setFilterStatus('all');
            }}
          >
            {t('PhonesListPage.filters.clear')}
          </Button>
        )}
        <div className="ml-auto flex items-center gap-2">
          <Button
            variant={viewMode === 'table' ? 'default' : 'outline'}
            size="icon" className="h-8 w-8"
            onClick={() => setViewMode('table')}
            aria-label={t('PhonesListPage.viewMode.table')}
          >
            <List className="h-4 w-4" />
          </Button>
          <Button
            variant={viewMode === 'grid' ? 'default' : 'outline'}
            size="icon" className="h-8 w-8"
            onClick={() => setViewMode('grid')}
            aria-label={t('PhonesListPage.viewMode.grid')}
          >
            <LayoutGrid className="h-4 w-4" />
          </Button>
        </div>
      </PageToolbar>

      {/* Table View */}
      {viewMode === 'table' ? (
        <DataTable
          data={phones}
          columns={columns}
          isLoading={isLoading}
          selectable
          onSelectionChange={(rows) => setSelectedIds(rows.map((r) => r.id))}
          getRowId={(row) => row.id}
          onRowClick={(row) => navigate(`/voip/phones/${row.id}`)}
          searchable={false}
          itemName={t('PhonesListPage.itemName.phones')}
          paginated
          defaultPageSize={25}
          emptyState={
            <EmptyState
              icon={Phone}
              title={t('PhonesListPage.empty.title')}
              action={{ label: t('PhonesListPage.actions.addPhone'), onClick: () => setShowAddDialog(true), icon: Plus }}
              secondaryAction={{ label: t('PhonesListPage.empty.discoverDevices'), onClick: () => navigate('/voip/discovery') }}
            />
          }
        />
      ) : (
        /* Grid View */
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
          {phones.map((phone) => (
            <Card key={phone.id} className="cursor-pointer hover:border-primary/40 transition-colors"
              onClick={() => navigate(`/voip/phones/${phone.id}`)}>
              <CardContent noOffset className="p-4 space-y-3">
                <div className="flex items-start justify-between">
                  <div className="flex-1 min-w-0">
                    <p className="font-medium truncate">{phone.name || phone.mac_address || t('PhonesListPage.unnamed')}</p>
                    <p className="text-xs text-muted-foreground">{phone.model || phone.vendor}</p>
                  </div>
                  <PhoneStatusBadge status={phone.status} />
                </div>
                <div className="flex items-center gap-2">
                  <LifecycleBadge state={phone.lifecycle_state} />
                  <SIPIndicator registered={phone.sip_registered} />
                </div>
                <div className="text-xs text-muted-foreground space-y-0.5 font-mono">
                  {phone.ip_address && <p>{phone.ip_address}</p>}
                  {phone.mac_address && <p>{phone.mac_address}</p>}
                </div>
                <div className="flex items-center justify-between text-xs text-muted-foreground">
                  <VendorLabel vendor={phone.vendor} />
                  <span>{formatTimeAgo(phone.last_seen)}</span>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      <BulkActionsBar
        selectedCount={selectedIds.length}
        itemName={t('PhonesListPage.itemName.phone')}
        onClear={() => setSelectedIds([])}
        actions={[
          {
            label: t('PhonesListPage.bulkActions.connect'),
            icon: Plug,
            onClick: () => {
              setBulkConnectResults(null);
              setShowBulkConnectDialog(true);
            },
          },
          {
            label: t('PhonesListPage.bulkActions.reboot'),
            icon: Power,
            // Confirm first. This fired straight from the bulk bar with no
            // prompt; the backend's required confirm flag (which the client
            // never sent) was the only thing preventing a one-click fleet-wide
            // reboot. Same window.confirm pattern the bulk-delete action above
            // already uses.
            onClick: () => {
              if (
                !window.confirm(
                  t('PhonesListPage.bulkActions.reboot') + ` (${selectedIds.length})`,
                )
              )
                return;
              bulkRebootMutation.mutate(selectedIds);
            },
          },
          {
            label: t('PhonesListPage.bulkActions.provision'),
            icon: Upload,
            onClick: () => bulkProvisionMutation.mutate(selectedIds),
          },
          {
            label: t('PhonesListPage.bulkActions.delete'),
            icon: Trash2,
            variant: 'destructive',
            onClick: handleBulkDelete,
          },
        ]}
      />

      {/* Add Phone Dialog */}
      <Dialog open={showAddDialog} onOpenChange={setShowAddDialog}>
        <DialogContent className="sm:max-w-[500px]">
          <DialogHeader>
            <DialogTitle>{t('PhonesListPage.addDialog.title')}</DialogTitle>
            <DialogDescription>{t('PhonesListPage.addDialog.description')}</DialogDescription>
          </DialogHeader>
          <div className="grid gap-4 py-4">
            <div className="grid gap-2">
              <Label>{t('PhonesListPage.addDialog.fields.name')}</Label>
              <Input placeholder={t('PhonesListPage.addDialog.placeholders.name')} value={newPhone.name}
                onChange={(e) => setNewPhone({ ...newPhone, name: e.target.value })} />
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div className="grid gap-2">
                <Label>{t('PhonesListPage.addDialog.fields.macAddress')}</Label>
                <Input placeholder="00:0B:82:xx:xx:xx" value={newPhone.mac_address}
                  onChange={(e) => setNewPhone({ ...newPhone, mac_address: e.target.value })} />
              </div>
              <div className="grid gap-2">
                <Label>{t('PhonesListPage.addDialog.fields.ipAddress')}</Label>
                <Input placeholder="192.168.1.100" value={newPhone.ip_address}
                  onChange={(e) => setNewPhone({ ...newPhone, ip_address: e.target.value })} />
              </div>
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div className="grid gap-2">
                <Label>{t('PhonesListPage.addDialog.fields.vendor')}</Label>
                <Select value={newPhone.vendor} onValueChange={(v) => setNewPhone({ ...newPhone, vendor: v })}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="grandstream">Grandstream</SelectItem>
                    <SelectItem value="yealink">Yealink</SelectItem>
                    <SelectItem value="polycom">Polycom</SelectItem>
                    <SelectItem value="cisco">Cisco</SelectItem>
                    <SelectItem value="fanvil">Fanvil</SelectItem>
                    <SelectItem value="other">{t('PhonesListPage.addDialog.vendorOther')}</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="grid gap-2">
                <Label>{t('PhonesListPage.addDialog.fields.model')}</Label>
                <Input placeholder="GRP2612" value={newPhone.model}
                  onChange={(e) => setNewPhone({ ...newPhone, model: e.target.value })} />
              </div>
            </div>
            <div className="grid gap-2">
              <Label>{t('PhonesListPage.addDialog.fields.location')}</Label>
              <Input placeholder={t('PhonesListPage.addDialog.placeholders.location')} value={newPhone.location}
                onChange={(e) => setNewPhone({ ...newPhone, location: e.target.value })} />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowAddDialog(false)}>{t('PhonesListPage.common.cancel')}</Button>
            <Button onClick={() => createMutation.mutate(newPhone)} disabled={!newPhone.name?.trim()}>
              <Plus className="h-4 w-4 mr-2" /> {t('PhonesListPage.actions.addPhone')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Onboard Dialog */}
      <Dialog open={showOnboardDialog} onOpenChange={setShowOnboardDialog}>
        <DialogContent className="sm:max-w-[500px]">
          <DialogHeader>
            <DialogTitle>{t('PhonesListPage.onboardDialog.title')}</DialogTitle>
            <DialogDescription>
              {t('PhonesListPage.onboardDialog.description', { name: selectedPhone?.name || selectedPhone?.mac_address })}
            </DialogDescription>
          </DialogHeader>
          <div className="grid gap-4 py-4">
            <div className="grid gap-2">
              <Label>{t('PhonesListPage.onboardDialog.fields.deviceName')}</Label>
              <Input value={onboardData.name}
                onChange={(e) => setOnboardData({ ...onboardData, name: e.target.value })} />
            </div>
            <div className="grid gap-2">
              <Label>{t('PhonesListPage.onboardDialog.fields.configTemplate')}</Label>
              <Select value={onboardData.config_template_id}
                onValueChange={(v) => setOnboardData({ ...onboardData, config_template_id: v })}>
                <SelectTrigger><SelectValue placeholder={t('PhonesListPage.onboardDialog.selectTemplate')} /></SelectTrigger>
                <SelectContent>
                  {templates.map((tpl: any) => (
                    <SelectItem key={tpl.id} value={tpl.id}>{tpl.name}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="grid gap-2">
              <Label>{t('PhonesListPage.onboardDialog.fields.location')}</Label>
              <Input value={onboardData.location}
                onChange={(e) => setOnboardData({ ...onboardData, location: e.target.value })} />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowOnboardDialog(false)}>{t('PhonesListPage.common.cancel')}</Button>
            <Button onClick={() => selectedPhone && onboardMutation.mutate({
              id: selectedPhone.id,
              data: {
                name: onboardData.name || undefined,
                config_template_id: onboardData.config_template_id || undefined,
                location: onboardData.location || undefined,
              },
            })}>
              <Upload className="h-4 w-4 mr-2" /> {t('PhonesListPage.rowActions.onboard')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Bulk Connect Dialog */}
      <Dialog open={showBulkConnectDialog} onOpenChange={(open) => {
        setShowBulkConnectDialog(open);
        if (!open) setBulkConnectResults(null);
      }}>
        <DialogContent className="sm:max-w-[640px] p-0 gap-0 overflow-hidden">
          {/* Header */}
          <div className="px-6 pt-6 pb-4">
            <DialogHeader>
              <DialogTitle className="flex items-center gap-2.5 text-lg">
                <div className="flex items-center justify-center h-9 w-9 rounded-lg bg-primary/10">
                  <Plug className="h-5 w-5 text-primary" />
                </div>
                {t('PhonesListPage.bulkConnect.title')}
              </DialogTitle>
              <DialogDescription className="text-sm leading-relaxed">
                {!bulkConnectResults
                  ? t('PhonesListPage.bulkConnect.descriptionForm', { count: selectedIds.length })
                  : t('PhonesListPage.bulkConnect.descriptionDone', { count: bulkConnectResults.total })}
              </DialogDescription>
            </DialogHeader>
          </div>

          <Separator />

          {!bulkConnectResults ? (
            /* ─── Credentials Form ─── */
            <>
              <div className="px-6 py-5 space-y-5">
                <div className="grid grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <Label htmlFor="bulk-username" className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
                      {t('PhonesListPage.bulkConnect.username')}
                    </Label>
                    <Input
                      id="bulk-username"
                      value={bulkConnectCreds.username}
                      onChange={(e) => setBulkConnectCreds({ ...bulkConnectCreds, username: e.target.value })}
                      placeholder="admin"
                      className="h-10"
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="bulk-password" className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
                      {t('PhonesListPage.bulkConnect.password')}
                    </Label>
                    <div className="relative">
                      <Input
                        id="bulk-password"
                        type={showBulkPassword ? 'text' : 'password'}
                        value={bulkConnectCreds.password}
                        onChange={(e) => setBulkConnectCreds({ ...bulkConnectCreds, password: e.target.value })}
                        placeholder={t('PhonesListPage.bulkConnect.passwordPlaceholder')}
                        className="h-10 pr-10"
                      />
                      <Button
                        type="button" variant="ghost" size="icon"
                        className="absolute right-1 top-1/2 -translate-y-1/2 h-8 w-8 text-muted-foreground hover:text-foreground"
                        onClick={() => setShowBulkPassword(!showBulkPassword)}
                      >
                        {showBulkPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                      </Button>
                    </div>
                  </div>
                </div>

                {/* Info Cards */}
                <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3">
                  <div className="rounded-lg border bg-muted/30 p-3 text-center">
                    <Monitor className="h-4 w-4 mx-auto mb-1.5 text-muted-foreground" />
                    <p className="text-lg font-semibold">{selectedIds.length}</p>
                    <p className="text-[11px] text-muted-foreground">{t('PhonesListPage.bulkConnect.cards.devices')}</p>
                  </div>
                  <div className="rounded-lg border bg-muted/30 p-3 text-center">
                    <Shield className="h-4 w-4 mx-auto mb-1.5 text-muted-foreground" />
                    <p className="text-lg font-semibold">{t('PhonesListPage.bulkConnect.cards.autoValue')}</p>
                    <p className="text-[11px] text-muted-foreground">{t('PhonesListPage.bulkConnect.cards.saveCredentials')}</p>
                  </div>
                  <div className="rounded-lg border bg-muted/30 p-3 text-center">
                    <Globe className="h-4 w-4 mx-auto mb-1.5 text-muted-foreground" />
                    <p className="text-lg font-semibold">{t('PhonesListPage.bulkConnect.cards.fullValue')}</p>
                    <p className="text-[11px] text-muted-foreground">{t('PhonesListPage.bulkConnect.cards.configSync')}</p>
                  </div>
                </div>

                <div className="flex items-start gap-3 rounded-lg border border-primary/20 bg-primary/5 p-3">
                  <KeyRound className="h-4 w-4 mt-0.5 shrink-0 text-primary" />
                  <p className="text-xs text-muted-foreground leading-relaxed">
                    {t('PhonesListPage.bulkConnect.infoText')}
                  </p>
                </div>
              </div>

              <Separator />

              <div className="flex items-center justify-between px-6 py-4 bg-muted/20">
                <Button variant="ghost" onClick={() => setShowBulkConnectDialog(false)}>{t('PhonesListPage.common.cancel')}</Button>
                <Button
                  size="lg"
                  onClick={() => bulkConnectMutation.mutate({
                    ids: selectedIds,
                    username: bulkConnectCreds.username,
                    password: bulkConnectCreds.password,
                  })}
                  disabled={!bulkConnectCreds.password || bulkConnectMutation.isPending}
                  className="min-w-[200px]"
                >
                  {bulkConnectMutation.isPending ? (
                    <><Loader2 className="h-4 w-4 mr-2 animate-spin" /> {t('PhonesListPage.bulkConnect.connecting', { count: selectedIds.length })}</>
                  ) : (
                    <><Plug className="h-4 w-4 mr-2" /> {t('PhonesListPage.bulkConnect.connectButton', { count: selectedIds.length })}</>
                  )}
                </Button>
              </div>
            </>
          ) : (
            /* ─── Results View ─── */
            <>
              {/* Summary Stats */}
              <div className="px-6 py-4 space-y-4">
                <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3">
                  <div className="rounded-lg border border-success/20 bg-success/5 p-3 text-center">
                    <div className="flex items-center justify-center gap-1.5 mb-1">
                      <CheckCircle className="h-4 w-4 text-success" />
                      <span className="text-2xl font-bold text-success">{bulkConnectResults.succeeded}</span>
                    </div>
                    <p className="text-[11px] font-medium text-success/70 uppercase tracking-wider">{t('PhonesListPage.bulkConnect.results.connected')}</p>
                  </div>
                  <div className={`rounded-lg border p-3 text-center ${
                    bulkConnectResults.failed > 0
                      ? 'border-destructive/20 bg-destructive/5'
                      : 'border-border bg-muted/30'
                  }`}>
                    <div className="flex items-center justify-center gap-1.5 mb-1">
                      <XCircle className={`h-4 w-4 ${bulkConnectResults.failed > 0 ? 'text-destructive' : 'text-muted-foreground/40'}`} />
                      <span className={`text-2xl font-bold ${bulkConnectResults.failed > 0 ? 'text-destructive' : 'text-muted-foreground/50'}`}>
                        {bulkConnectResults.failed}
                      </span>
                    </div>
                    <p className={`text-[11px] font-medium uppercase tracking-wider ${bulkConnectResults.failed > 0 ? 'text-destructive/70' : 'text-muted-foreground/40'}`}>
                      {t('PhonesListPage.bulkConnect.results.failed')}
                    </p>
                  </div>
                  <div className={`rounded-lg border p-3 text-center ${
                    bulkConnectResults.skipped > 0
                      ? 'border-warning/20 bg-warning/5'
                      : 'border-border bg-muted/30'
                  }`}>
                    <div className="flex items-center justify-center gap-1.5 mb-1">
                      <AlertCircle className={`h-4 w-4 ${bulkConnectResults.skipped > 0 ? 'text-warning' : 'text-muted-foreground/40'}`} />
                      <span className={`text-2xl font-bold ${bulkConnectResults.skipped > 0 ? 'text-warning' : 'text-muted-foreground/50'}`}>
                        {bulkConnectResults.skipped}
                      </span>
                    </div>
                    <p className={`text-[11px] font-medium uppercase tracking-wider ${bulkConnectResults.skipped > 0 ? 'text-warning/70' : 'text-muted-foreground/40'}`}>
                      {t('PhonesListPage.bulkConnect.results.skipped')}
                    </p>
                  </div>
                </div>

                <div className="space-y-1.5">
                  <div className="flex items-center justify-between text-xs text-muted-foreground">
                    <span>{t('PhonesListPage.bulkConnect.results.successRate')}</span>
                    <span className="font-mono font-medium">
                      {Math.round((bulkConnectResults.succeeded / bulkConnectResults.total) * 100)}%
                    </span>
                  </div>
                  <Progress
                    value={(bulkConnectResults.succeeded / bulkConnectResults.total) * 100}
                    className="h-1.5"
                  />
                </div>
              </div>

              <Separator />

              {/* Per-phone results table */}
              <div className="px-6 pt-3 pb-1">
                <p className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
                  {t('PhonesListPage.bulkConnect.results.deviceResults')}
                </p>
              </div>
              <ScrollArea className="h-[300px]">
                <div className="px-6 pb-4 space-y-1.5">
                  {bulkConnectResults.results?.map((r: any, _i: number) => (
                    <div
                      key={r.phone_id}
                      className={`group flex items-center gap-3 rounded-lg border px-3.5 py-2.5 transition-colors hover:bg-accent/50 ${
                        r.status === 'connected'
                          ? 'border-success/20 bg-success/5'
                          : r.status === 'error' || r.status === 'skipped'
                          ? 'border-destructive/20 bg-destructive/5'
                          : 'border-warning/20 bg-warning/5'
                      }`}
                    >
                      {/* Status icon */}
                      <div className={`flex items-center justify-center h-8 w-8 rounded-full shrink-0 ${
                        r.status === 'connected'
                          ? 'bg-success/10'
                          : r.status === 'error' || r.status === 'skipped'
                          ? 'bg-destructive/10'
                          : 'bg-warning/10'
                      }`}>
                        {r.status === 'connected' ? (
                          <Wifi className="h-4 w-4 text-success" />
                        ) : r.status === 'error' || r.status === 'skipped' ? (
                          <WifiOff className="h-4 w-4 text-destructive" />
                        ) : (
                          <AlertCircle className="h-4 w-4 text-warning" />
                        )}
                      </div>

                      {/* Device name & IP */}
                      <div className="flex-1 min-w-0">
                        <p className="text-sm font-medium truncate">
                          {r.name || r.ip_address || r.phone_id}
                        </p>
                        <div className="flex items-center gap-2 mt-0.5">
                          {r.ip_address && (
                            <span className="text-[11px] font-mono text-muted-foreground">{r.ip_address}</span>
                          )}
                          {r.model && (
                            <>
                              <span className="text-muted-foreground/30">·</span>
                              <span className="text-[11px] text-muted-foreground">{r.model}</span>
                            </>
                          )}
                        </div>
                      </div>

                      {/* SIP extension */}
                      {r.sip_account && (
                        <div className="hidden sm:flex items-center gap-1.5 shrink-0">
                          <Hash className="h-3 w-3 text-muted-foreground/50" />
                          <span className="text-xs font-mono text-muted-foreground">{r.sip_account}</span>
                        </div>
                      )}

                      {/* SIP badge */}
                      {r.sip_registered && (
                        <Badge variant="outline" className="shrink-0 h-6 text-[10px] font-medium border-info/30 text-info bg-info/5">
                          SIP
                        </Badge>
                      )}

                      {/* Auth status */}
                      <div className="shrink-0 ml-1">
                        {r.authenticated ? (
                          <Badge variant="outline" className="h-6 text-[10px] font-medium border-success/30 text-success bg-success/5">
                            <CheckCircle className="h-3 w-3 mr-1" /> {t('PhonesListPage.bulkConnect.results.authenticated')}
                          </Badge>
                        ) : r.error ? (
                          <Badge variant="outline" className="h-6 text-[10px] font-medium border-destructive/30 text-destructive bg-destructive/5 max-w-[140px]">
                            <XCircle className="h-3 w-3 mr-1 shrink-0" />
                            <span className="truncate">{r.error}</span>
                          </Badge>
                        ) : (
                          <Badge variant="outline" className="h-6 text-[10px] font-medium border-warning/30 text-warning bg-warning/5">
                            {r.status}
                          </Badge>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </ScrollArea>

              <Separator />

              <div className="flex items-center justify-between px-6 py-4 bg-muted/20">
                <p className="text-xs text-muted-foreground">
                  {t('PhonesListPage.bulkConnect.results.summary', { succeeded: bulkConnectResults.succeeded, total: bulkConnectResults.total })}
                </p>
                <Button onClick={() => {
                  setShowBulkConnectDialog(false);
                  setBulkConnectResults(null);
                }}>
                  {t('PhonesListPage.common.done')}
                </Button>
              </div>
            </>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN · PBX Systems Management Page
 *
 * Full PBX CRUD with:
 *  - PBX list table with status badges
 *  - Add PBX dialog (FreePBX, Asterisk, FreeSWITCH, 3CX)
 *  - Test connection, Sync, Delete
 */
/* eslint-disable @typescript-eslint/no-explicit-any */

import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useNavigate } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useSiteStore } from '@/stores/siteStore';
import {
  Server, Plus, RefreshCw, Trash2, Link2,
  CheckCircle, XCircle, MoreHorizontal,
  Users, ExternalLink, AlertTriangle,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { DataTable, type DataTableColumn } from '@/components/ui/data-table';
import {
  Dialog, DialogContent, DialogDescription, DialogFooter,
  DialogHeader, DialogTitle,
} from '@/components/ui/dialog';
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from '@/components/ui/select';
import {
  DropdownMenu, DropdownMenuContent, DropdownMenuItem,
  DropdownMenuSeparator, DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { voipApi } from '@/lib/api';
import { cn } from '@/lib/utils';
import { PageHeader, PageToolbar } from '@/components/layout';
import { StatsGrid } from '@/components/ui/stats-grid';
import { StatusBadge } from '@/components/ui/status-indicator';
import { BulkActionsBar } from '@/components/ui/bulk-actions-bar';
import { SearchBar } from '@/components/ui/search-bar';
import { useToast } from '@/hooks/use-toast';
import { useAdapterMaturity } from '@/hooks/useAdapterMaturity';
import { MaturityBadge } from '@/components/ui/maturity-badge';
import { PBXTypeBadge, formatTimeAgo } from './components';
import { Download } from 'lucide-react';
import type { PBXSystem } from './types';

// Only vendors with a real, shipping adapter are selectable — we don't list a
// PBX type we can't actually talk to. FreePBX is the live-validated adapter;
// Asterisk / FreeSWITCH / 3CX have no backend adapter yet, so they are NOT
// offered (removed rather than shown broken). See app/adapters/maturity.py.
const PBX_TYPE_OPTIONS = [
  { value: 'freepbx', label: 'FreePBX', labelKey: 'pbxTypes.freepbx.label', descKey: 'pbxTypes.freepbx.description', defaultPort: 443 },
] as const;

function PBXStatusBadge({ status }: { status?: string }) {
  const { t } = useTranslation('voip');
  if (status === 'online' || status === 'connected') {
    return <StatusBadge variant="online">{t('PBXPage.status.online')}</StatusBadge>;
  }
  if (status === 'error' || status === 'unreachable') {
    return <StatusBadge variant="error">{t('PBXPage.status.error')}</StatusBadge>;
  }
  return <StatusBadge variant="unknown">{t('PBXPage.status.unknown')}</StatusBadge>;
}

export default function PBXPage() {
  const { t } = useTranslation('voip');
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const { toast } = useToast();
  const { maturityFor } = useAdapterMaturity();
  const [showAddDialog, setShowAddDialog] = useState(false);
  const [testResult, setTestResult] = useState<any>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [selected, setSelected] = useState<PBXSystem[]>([]);

  const [form, setForm] = useState({
    name: '', pbx_type: 'freepbx', ip_address: '', api_port: 443,
    sip_port: 5060, description: '', api_username: '', api_password: '', api_key: '',
    // OAuth2 client_credentials for FreePBX 16+ Admin API → M2M app.
    // When both are filled in, the adapter prefers GraphQL + REST over
    // legacy AJAX (78 query fields, 105 mutations vs. ~4 endpoints).
    api_client_id: '', api_client_secret: '',
    // TLS verification acknowledgement, operator must opt in to
    // skip cert verification on a self-signed / expired-cert PBX.
    tls_verify_disabled_acknowledged: false,
  });

  // Site context
  const selectedSiteId = useSiteStore((s) => s.selectedSiteId);

  // ── Queries ──

  const { data: pbxRes, isLoading, isError, refetch } = useQuery({
    queryKey: ['voip-pbx', { siteId: selectedSiteId }],
    queryFn: () => voipApi.getPBXSystems(selectedSiteId ? { site_id: selectedSiteId } : undefined),
    refetchInterval: 30_000,
  });

  const allSystems: PBXSystem[] = pbxRes?.data?.items ?? pbxRes?.data ?? [];
  const systems = allSystems.filter((s) => {
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      const hay = `${s.name} ${s.ip_address} ${s.pbx_type} ${s.description ?? ''}`.toLowerCase();
      if (!hay.includes(q)) return false;
    }
    if (statusFilter !== 'all') {
      const isOnline = s.is_active;
      if (statusFilter === 'online' && !isOnline) return false;
      if (statusFilter === 'offline' && isOnline) return false;
    }
    return true;
  });
  const hasActiveFilters = searchQuery !== '' || statusFilter !== 'all';

  // ── Mutations ──

  const createMutation = useMutation({
    mutationFn: (data: any) => voipApi.createPBX(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['voip-pbx'] });
      setShowAddDialog(false);
      resetForm();
      toast({ title: t('PBXPage.toasts.added.title'), description: t('PBXPage.toasts.added.description', { name: form.name }) });
    },
    onError: (err: any) => {
      toast({ title: t('PBXPage.toasts.error.title'), description: err?.response?.data?.detail || t('PBXPage.toasts.error.createFailed'), variant: 'destructive' });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => voipApi.deletePBX(id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['voip-pbx'] }),
    onError: (err: any) => {
      toast({ title: t('PBXPage.toasts.error.title'), description: err?.response?.data?.detail || t('PBXPage.toasts.error.deleteFailed'), variant: 'destructive' });
    },
  });

  const syncMutation = useMutation({
    mutationFn: (id: string) => voipApi.syncPBX(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['voip-pbx'] });
      queryClient.invalidateQueries({ queryKey: ['voip-extensions'] });
    },
    onError: (err: any) => {
      toast({ title: t('PBXPage.toasts.error.title'), description: err?.response?.data?.detail || t('PBXPage.toasts.error.syncFailed'), variant: 'destructive' });
    },
  });

  const testMutation = useMutation({
    mutationFn: (data: any) => voipApi.testPBXConnection(data),
    onSuccess: (res) => setTestResult(res?.data ?? { status: 'success', message: t('PBXPage.test.connected') }),
    onError: () => setTestResult({ status: 'error', message: t('PBXPage.test.connectionFailed') }),
  });

  // ── Helpers ──

  function resetForm() {
    setForm({
      name: '', pbx_type: 'freepbx', ip_address: '', api_port: 443,
      sip_port: 5060, description: '',
      api_username: '', api_password: '', api_key: '',
      api_client_id: '', api_client_secret: '',
      tls_verify_disabled_acknowledged: false,
    });
    setTestResult(null);
  }

  function handleTypeChange(type: string) {
    const opt = PBX_TYPE_OPTIONS.find((o) => o.value === type);
    setForm((prev) => ({ ...prev, pbx_type: type, api_port: opt?.defaultPort ?? 443 }));
  }

  function handleTest() {
    setTestResult(null);
    testMutation.mutate({
      pbx_type: form.pbx_type, ip_address: form.ip_address, api_port: form.api_port,
      api_username: form.api_username || undefined, api_password: form.api_password || undefined,
      api_key: form.api_key || undefined,
      api_client_id: form.api_client_id || undefined,
      api_client_secret: form.api_client_secret || undefined,
      verify_ssl: !form.tls_verify_disabled_acknowledged,
    });
  }

  function handleSubmit() {
    createMutation.mutate({
      name: form.name, pbx_type: form.pbx_type, ip_address: form.ip_address,
      api_port: form.api_port, sip_port: form.sip_port,
      description: form.description || undefined,
      api_username: form.api_username || undefined, api_password: form.api_password || undefined,
      api_key: form.api_key || undefined, is_active: true,
      api_client_id: form.api_client_id || undefined,
      api_client_secret: form.api_client_secret || undefined,
      tls_verify_disabled_acknowledged: form.tls_verify_disabled_acknowledged,
      site_id: selectedSiteId || undefined,
    });
  }

  // ── Columns ──

  const columns: DataTableColumn<PBXSystem>[] = [
    {
      id: 'name',
      header: t('PBXPage.columns.name'),
      cell: (row) => (
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-muted">
            <Server className="h-4 w-4 text-muted-foreground" />
          </div>
          <div>
            <p className="font-medium text-primary hover:underline cursor-pointer" onClick={() => navigate(`/voip/pbx/${row.id}`)}>{row.name}</p>
            <p className="text-xs text-muted-foreground">{row.description || row.ip_address}</p>
          </div>
        </div>
      ),
      sortable: true,
    },
    {
      id: 'type',
      header: t('PBXPage.columns.type'),
      cell: (row) => <PBXTypeBadge type={row.pbx_type} />,
    },
    {
      id: 'status',
      header: t('PBXPage.columns.status'),
      cell: (row) => <PBXStatusBadge status={row.is_active ? 'connected' : 'offline'} />,
    },
    {
      id: 'connection',
      header: t('PBXPage.columns.connection'),
      cell: (row) => (
        <div className="text-xs font-mono">
          <span>{row.ip_address}</span>
          <span className="text-muted-foreground">:{row.api_port}</span>
        </div>
      ),
    },
    {
      id: 'extensions',
      header: t('PBXPage.columns.extensions'),
      cell: (row) => <Badge variant="outline">{row.extension_count ?? 0}</Badge>,
    },
    {
      id: 'last_sync',
      header: t('PBXPage.columns.lastSynced'),
      cell: (row) => <span className="text-sm text-muted-foreground">{formatTimeAgo(row.last_seen)}</span>,
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
            <DropdownMenuItem onClick={() => navigate(`/voip/pbx/${row.id}`)}>
              <Server className="h-4 w-4 mr-2" /> {t('PBXPage.rowActions.viewDashboard')}
            </DropdownMenuItem>
            <DropdownMenuItem onClick={() => syncMutation.mutate(row.id)}>
              <RefreshCw className="h-4 w-4 mr-2" /> {t('PBXPage.rowActions.syncNow')}
            </DropdownMenuItem>
            <DropdownMenuItem onClick={() => navigate(`/voip/extensions?pbx=${row.id}`)}>
              <Users className="h-4 w-4 mr-2" /> {t('PBXPage.rowActions.viewExtensions')}
            </DropdownMenuItem>
            <DropdownMenuItem
              onClick={() => window.open(`https://${row.ip_address}:${row.api_port}`, '_blank', 'noopener,noreferrer')}>
              <ExternalLink className="h-4 w-4 mr-2" /> {t('PBXPage.rowActions.openWebUI')}
            </DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem onClick={() => deleteMutation.mutate(row.id)} className="text-destructive focus:text-destructive">
              <Trash2 className="h-4 w-4 mr-2" /> {t('PBXPage.rowActions.delete')}
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      ),
    },
  ];

  // ── CSV export · serialize the loaded PBX rows client-side ──

  function exportPbxCsv() {
    if (allSystems.length === 0) return;
    const headers = ['name', 'pbx_type', 'ip_address', 'api_port', 'sip_port', 'is_active', 'extension_count', 'description'];
    const escape = (v: unknown) => {
      const s = v == null ? '' : String(v);
      return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
    };
    const rows = allSystems.map((p) => [
      p.name, p.pbx_type, p.ip_address, p.api_port, p.sip_port, p.is_active, p.extension_count ?? 0, p.description,
    ].map(escape).join(','));
    const csv = [headers.join(','), ...rows].join('\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `pbx-systems-${new Date().toISOString().slice(0, 10)}.csv`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  // ── Bulk delete · confirm + per-row delete with a summary toast ──

  async function handleBulkDelete() {
    if (selected.length === 0) return;
    if (!window.confirm(t('PBXPage.bulk.deleteToast.title') + ` (${selected.length})`)) return;
    const results = await Promise.allSettled(selected.map((s) => voipApi.deletePBX(s.id)));
    const ok = results.filter((r) => r.status === 'fulfilled').length;
    const failed = results.length - ok;
    queryClient.invalidateQueries({ queryKey: ['voip-pbx'] });
    setSelected([]);
    toast({
      title: t('PBXPage.bulk.deleteToast.title'),
      description: t('PhonesListPage.toasts.bulkConnectComplete.description', { succeeded: ok, failed, skipped: 0 }),
      variant: failed > 0 ? 'destructive' : undefined,
    });
  }

  // ── Stats ──

  const onlineCount = allSystems.filter((s) => s.is_active).length;
  const totalExt = allSystems.reduce((s, p) => s + (p.extension_count ?? 0), 0);

  return (
    <div className="space-y-6">
      <PageHeader
        icon={Server}
        title={t('PBXPage.header.title')}
        description={t('PBXPage.header.description', { count: allSystems.length, online: onlineCount })}
        onRefresh={() => refetch()}
        refreshing={isLoading}
        secondaryActions={[{ label: t('PBXPage.actions.export'), icon: Download, onClick: exportPbxCsv, disabled: allSystems.length === 0 }]}
        primaryAction={{ label: t('PBXPage.actions.addPBX'), icon: Plus, onClick: () => { resetForm(); setShowAddDialog(true); } }}
      />

      {isError && (
        <Card className="border-destructive">
          <CardContent noOffset className="p-4 flex items-center gap-3">
            <AlertTriangle className="h-5 w-5 text-destructive" />
            <span className="text-sm">{t('PBXPage.errorBanner')}</span>
          </CardContent>
        </Card>
      )}

      <StatsGrid
        columns={4}
        isLoading={isLoading}
        stats={[
          {
            title: t('PBXPage.stats.totalPBX.title'),
            value: allSystems.length,
            icon: Server,
            variant: 'primary',
            description: t('PBXPage.stats.totalPBX.description'),
          },
          {
            title: t('PBXPage.stats.online.title'),
            value: onlineCount,
            icon: CheckCircle,
            variant: 'success',
            description: allSystems.length > 0
              ? t('PBXPage.stats.online.reachable', { percent: Math.round((onlineCount / allSystems.length) * 100) })
              : t('PBXPage.stats.online.noPBX'),
          },
          {
            title: t('PBXPage.stats.offlineError.title'),
            value: allSystems.length - onlineCount,
            icon: XCircle,
            variant: 'destructive',
            description: t('PBXPage.stats.offlineError.description'),
          },
          {
            title: t('PBXPage.stats.totalExtensions.title'),
            value: totalExt,
            icon: Users,
            variant: 'info',
            description: t('PBXPage.stats.totalExtensions.description'),
          },
        ]}
      />

      <PageToolbar>
        <SearchBar
          value={searchQuery}
          onChange={setSearchQuery}
          placeholder={t('PBXPage.toolbar.searchPlaceholder')}
          className="w-full sm:w-auto"
        />
        <Select value={statusFilter} onValueChange={setStatusFilter}>
          <SelectTrigger className="w-full sm:w-[160px]">
            <SelectValue placeholder={t('PBXPage.toolbar.allStatuses')} />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">{t('PBXPage.toolbar.allStatuses')}</SelectItem>
            <SelectItem value="online">{t('PBXPage.status.online')}</SelectItem>
            <SelectItem value="offline">{t('PBXPage.toolbar.offlineError')}</SelectItem>
          </SelectContent>
        </Select>
        {hasActiveFilters && (
          <Button
            variant="ghost"
            size="sm"
            onClick={() => {
              setSearchQuery('');
              setStatusFilter('all');
            }}
          >
            {t('PBXPage.toolbar.clearFilters')}
          </Button>
        )}
      </PageToolbar>

      <DataTable
        data={systems}
        columns={columns}
        isLoading={isLoading}
        selectable
        onSelectionChange={setSelected}
        searchable={false}
        itemName={t('PBXPage.itemNamePlural')}
        getRowId={(row) => row.id}
        emptyState={
          <div className="flex flex-col items-center gap-3 py-12">
            <Server className="h-12 w-12 text-muted-foreground/30" />
            <p className="text-muted-foreground">{t('PBXPage.empty.title')}</p>
            <Button onClick={() => { resetForm(); setShowAddDialog(true); }}>
              <Plus className="h-4 w-4 mr-2" /> {t('PBXPage.empty.addFirst')}
            </Button>
          </div>
        }
      />

      <BulkActionsBar
        selectedCount={selected.length}
        itemName={t('PBXPage.itemName')}
        onClear={() => setSelected([])}
        actions={[
          {
            label: t('PBXPage.bulk.syncAll'),
            icon: RefreshCw,
            onClick: () => {
              selected.forEach((s) => syncMutation.mutate(s.id));
              setSelected([]);
            },
          },
          {
            label: t('PBXPage.bulk.delete'),
            icon: Trash2,
            variant: 'destructive',
            onClick: handleBulkDelete,
          },
        ]}
      />

      {/* Add PBX Dialog */}
      <Dialog open={showAddDialog} onOpenChange={(v) => { setShowAddDialog(v); if (!v) resetForm(); }}>
        <DialogContent className="sm:max-w-[560px]">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Server className="h-5 w-5" /> {t('PBXPage.dialog.title')}
            </DialogTitle>
            <DialogDescription>
              {t('PBXPage.dialog.description')}
            </DialogDescription>
          </DialogHeader>

          <div className="grid gap-4 py-2">
            <div className="grid gap-2">
              <div className="flex items-center gap-2">
                <Label>{t('PBXPage.dialog.fields.pbxType')}</Label>
                <MaturityBadge info={maturityFor(form.pbx_type)} />
              </div>
              <Select value={form.pbx_type} onValueChange={handleTypeChange}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  {PBX_TYPE_OPTIONS.map((opt) => (
                    <SelectItem key={opt.value} value={opt.value}>
                      <div className="flex items-center gap-2">
                        <span className="font-medium">{t(`PBXPage.${opt.labelKey}`)}</span>
                        <span className="text-muted-foreground text-xs">- {t(`PBXPage.${opt.descKey}`)}</span>
                      </div>
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <div className="grid gap-2">
              <Label>{t('PBXPage.dialog.fields.displayName')}</Label>
              <Input placeholder={t('PBXPage.dialog.placeholders.displayName')} value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })} />
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div className="grid gap-2">
                <Label>{t('PBXPage.dialog.fields.ipAddress')}</Label>
                <Input placeholder="192.168.1.100" value={form.ip_address}
                  onChange={(e) => setForm({ ...form, ip_address: e.target.value })} />
              </div>
              <div className="grid grid-cols-2 gap-2">
                <div className="grid gap-2">
                  <Label>{t('PBXPage.dialog.fields.apiPort')}</Label>
                  <Input type="number" value={form.api_port}
                    onChange={(e) => setForm({ ...form, api_port: parseInt(e.target.value) || 443 })} />
                </div>
                <div className="grid gap-2">
                  <Label>{t('PBXPage.dialog.fields.sipPort')}</Label>
                  <Input type="number" value={form.sip_port}
                    onChange={(e) => setForm({ ...form, sip_port: parseInt(e.target.value) || 5060 })} />
                </div>
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div className="grid gap-2">
                <Label>{t('PBXPage.dialog.fields.username')}</Label>
                <Input placeholder={t('PBXPage.dialog.placeholders.username')} value={form.api_username}
                  onChange={(e) => setForm({ ...form, api_username: e.target.value })} />
              </div>
              <div className="grid gap-2">
                <Label>{t('PBXPage.dialog.fields.password')}</Label>
                <Input type="password" placeholder="••••••••" value={form.api_password}
                  onChange={(e) => setForm({ ...form, api_password: e.target.value })} />
              </div>
            </div>

            <div className="grid gap-2">
              <Label>{t('PBXPage.dialog.fields.apiKey')}</Label>
              <Input placeholder={t('PBXPage.dialog.placeholders.apiKey')} value={form.api_key}
                onChange={(e) => setForm({ ...form, api_key: e.target.value })} />
            </div>

            {/* OAuth2 M2M client_credentials, FreePBX 16+ Admin API */}
            <div className="grid gap-2 rounded-lg border border-border bg-muted/30 p-3">
              <div className="text-sm font-medium">
                {t('PBXPage.dialog.oauth.heading')} <span className="font-normal text-muted-foreground">{t('PBXPage.dialog.oauth.optional')}</span>
              </div>
              <p className="text-xs text-muted-foreground">
                {t('PBXPage.dialog.oauth.createAt')} <span className="font-mono">Admin → API → Applications → Machine-to-Machine app</span>.
                {' '}{t('PBXPage.dialog.oauth.whenSet')}
              </p>
              <div className="grid grid-cols-2 gap-4">
                <div className="grid gap-2">
                  <Label>{t('PBXPage.dialog.fields.clientId')}</Label>
                  <Input placeholder={t('PBXPage.dialog.placeholders.clientId')} value={form.api_client_id}
                    onChange={(e) => setForm({ ...form, api_client_id: e.target.value })} />
                </div>
                <div className="grid gap-2">
                  <Label>{t('PBXPage.dialog.fields.clientSecret')}</Label>
                  <Input type="password" placeholder="••••••••" value={form.api_client_secret}
                    onChange={(e) => setForm({ ...form, api_client_secret: e.target.value })} />
                </div>
              </div>
            </div>

            {/* TLS verification opt-out */}
            <div className="flex items-start gap-2 rounded-lg border border-border p-3">
              <input
                type="checkbox"
                id="tls-ack"
                className="mt-1"
                checked={form.tls_verify_disabled_acknowledged}
                onChange={(e) => setForm({ ...form, tls_verify_disabled_acknowledged: e.target.checked })}
              />
              <label htmlFor="tls-ack" className="text-sm">
                <span className="font-medium">{t('PBXPage.dialog.tls.label')}</span>
                <br />
                <span className="text-xs text-muted-foreground">
                  {t('PBXPage.dialog.tls.help')}
                </span>
              </label>
            </div>

            <div className="grid gap-2">
              <Label>{t('PBXPage.dialog.fields.description')}</Label>
              <Input placeholder={t('PBXPage.dialog.placeholders.description')} value={form.description}
                onChange={(e) => setForm({ ...form, description: e.target.value })} />
            </div>

            {testResult && (
              <Card className={cn('border', testResult.status === 'success'
                ? 'border-success/30 bg-success/5' : 'border-destructive/30 bg-destructive/5')}>
                <CardContent noOffset className="py-3 flex items-center gap-3">
                  {testResult.status === 'success'
                    ? <CheckCircle className="h-5 w-5 text-success" />
                    : <XCircle className="h-5 w-5 text-destructive" />}
                  <div>
                    <p className="text-sm font-medium">{testResult.message}</p>
                    {testResult.response_time_ms && (
                      <p className="text-xs text-muted-foreground">
                        {t('PBXPage.test.responseTime', { ms: testResult.response_time_ms })}
                      </p>
                    )}
                  </div>
                </CardContent>
              </Card>
            )}
          </div>

          <DialogFooter className="gap-2 sm:gap-0">
            <Button variant="outline" onClick={handleTest}
              disabled={!form.ip_address.trim() || testMutation.isPending}>
              {testMutation.isPending
                ? <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
                : <Link2 className="h-4 w-4 mr-2" />}
              {t('PBXPage.dialog.testConnection')}
            </Button>
            <Button onClick={handleSubmit}
              disabled={!form.name.trim() || !form.ip_address.trim() || createMutation.isPending}>
              {createMutation.isPending
                ? <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
                : <Plus className="h-4 w-4 mr-2" />}
              {t('PBXPage.actions.addPBX')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

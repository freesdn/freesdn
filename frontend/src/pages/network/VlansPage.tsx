// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN - VLAN Management Page
 * 
 * Interface for viewing and managing VLANs.
 */
/* eslint-disable @typescript-eslint/no-explicit-any */

import { useState, useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useSiteStore } from '@/stores/siteStore';
import {
  RefreshCw,
  Plus,
  Pencil,
  Trash2,
  Network,
  Server,
  AlertCircle,
  MoreHorizontal,
  CheckCircle,
  XCircle,
  Loader2,
  ArrowRightLeft,
  Download,
} from 'lucide-react';
import { DataTable, DataTableColumn } from '@/components/ui/data-table';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Skeleton } from '@/components/ui/skeleton';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog';
import { networkApi, Vlan, VlanCreate, VlanUpdate } from '@/lib/api';
import { cn } from '@/lib/utils';
import { PageHeader, PageTabs, PageToolbar } from '@/components/layout';
import { StatsGrid } from '@/components/ui/stats-grid';
import { StatusBadge } from '@/components/ui/status-indicator';
import { BulkActionsBar } from '@/components/ui/bulk-actions-bar';
import { ErrorState } from '@/components/ui/empty-state';
import { SearchBar } from '@/components/ui/search-bar';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { useToast } from '@/hooks/use-toast';

// DHCP Status badge · uses canonical StatusBadge
function DhcpBadge({ enabled }: { enabled: boolean }) {
  const { t } = useTranslation('network');
  return (
    <StatusBadge variant={enabled ? 'success' : 'neutral'} hideIcon size="sm">
      {enabled ? (
        <span className="inline-flex items-center gap-1">
          <CheckCircle className="h-3 w-3" /> {t('VlansPage.dhcp.enabled')}
        </span>
      ) : (
        <span className="inline-flex items-center gap-1">
          <XCircle className="h-3 w-3" /> {t('VlansPage.dhcp.disabled')}
        </span>
      )}
    </StatusBadge>
  );
}

// VLAN Form Dialog
interface VlanFormDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  vlan?: Vlan;
  onSubmit: (data: VlanCreate | VlanUpdate) => void;
  isLoading?: boolean;
}

function VlanFormDialog({ open, onOpenChange, vlan, onSubmit, isLoading }: VlanFormDialogProps) {
  const { t } = useTranslation('network');
  const isEditing = !!vlan;
  const [formData, setFormData] = useState<VlanCreate>({
    vlan_id: vlan?.vlan_id || 1,
    name: vlan?.name || '',
    description: vlan?.description || '',
    dhcp_enabled: vlan?.dhcp_enabled || false,
    dhcp_start: vlan?.dhcp_start || '',
    dhcp_end: vlan?.dhcp_end || '',
    gateway: vlan?.gateway || '',
    subnet_mask: vlan?.subnet_mask || '',
  });

  // Reset form when dialog opens or vlan prop changes
  useEffect(() => {
    if (open) {
      setFormData({
        vlan_id: vlan?.vlan_id || 1,
        name: vlan?.name || '',
        description: vlan?.description || '',
        dhcp_enabled: vlan?.dhcp_enabled || false,
        dhcp_start: vlan?.dhcp_start || '',
        dhcp_end: vlan?.dhcp_end || '',
        gateway: vlan?.gateway || '',
        subnet_mask: vlan?.subnet_mask || '',
      });
    }
  }, [open, vlan]);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onSubmit(formData);
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-[500px]">
        <DialogHeader>
          <DialogTitle>{isEditing ? t('VlansPage.form.editTitle') : t('VlansPage.form.createTitle')}</DialogTitle>
          <DialogDescription>
            {isEditing
              ? t('VlansPage.form.editDescription')
              : t('VlansPage.form.createDescription')}
          </DialogDescription>
        </DialogHeader>
        <form onSubmit={handleSubmit}>
          <div className="grid gap-4 py-4">
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="vlan_id">{t('VlansPage.form.vlanId')}</Label>
                <Input
                  id="vlan_id"
                  type="number"
                  min={1}
                  max={4094}
                  value={formData.vlan_id}
                  onChange={(e) => setFormData({ ...formData, vlan_id: parseInt(e.target.value) })}
                  disabled={isEditing}
                  required
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="name">{t('VlansPage.form.name')}</Label>
                <Input
                  id="name"
                  value={formData.name}
                  onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                  placeholder={t('VlansPage.form.namePlaceholder')}
                  required
                />
              </div>
            </div>
            
            <div className="space-y-2">
              <Label htmlFor="description">{t('VlansPage.form.description')}</Label>
              <Input
                id="description"
                value={formData.description}
                onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                placeholder={t('VlansPage.form.descriptionPlaceholder')}
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="gateway">{t('VlansPage.form.gateway')}</Label>
              <Input
                id="gateway"
                value={formData.gateway}
                onChange={(e) => setFormData({ ...formData, gateway: e.target.value })}
                placeholder={t('VlansPage.form.gatewayPlaceholder')}
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="subnet_mask">{t('VlansPage.form.subnetMask')}</Label>
              <Input
                id="subnet_mask"
                value={formData.subnet_mask}
                onChange={(e) => setFormData({ ...formData, subnet_mask: e.target.value })}
                placeholder={t('VlansPage.form.subnetMaskPlaceholder')}
              />
            </div>

            <div className="flex items-center justify-between rounded-lg border p-4">
              <div className="space-y-0.5">
                <Label>{t('VlansPage.form.dhcpServer')}</Label>
                <p className="text-sm text-muted-foreground">
                  {t('VlansPage.form.dhcpServerHelp')}
                </p>
              </div>
              <Switch
                checked={formData.dhcp_enabled}
                onCheckedChange={(checked) => setFormData({ ...formData, dhcp_enabled: checked })}
              />
            </div>

            {formData.dhcp_enabled && (
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="dhcp_start">{t('VlansPage.form.dhcpStart')}</Label>
                  <Input
                    id="dhcp_start"
                    value={formData.dhcp_start}
                    onChange={(e) => setFormData({ ...formData, dhcp_start: e.target.value })}
                    placeholder={t('VlansPage.form.dhcpStartPlaceholder')}
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="dhcp_end">{t('VlansPage.form.dhcpEnd')}</Label>
                  <Input
                    id="dhcp_end"
                    value={formData.dhcp_end}
                    onChange={(e) => setFormData({ ...formData, dhcp_end: e.target.value })}
                    placeholder={t('VlansPage.form.dhcpEndPlaceholder')}
                  />
                </div>
              </div>
            )}
          </div>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
              {t('VlansPage.form.cancel')}
            </Button>
            <Button type="submit" disabled={isLoading}>
              {isLoading ? (
                <>
                  <RefreshCw className="mr-2 h-4 w-4 animate-spin" />
                  {isEditing ? t('VlansPage.form.saving') : t('VlansPage.form.creating')}
                </>
              ) : (
                isEditing ? t('VlansPage.form.saveChanges') : t('VlansPage.form.createSubmit')
              )}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

// Main component
export default function VlansPage() {
  const { t } = useTranslation('network');
  const queryClient = useQueryClient();
  const selectedSiteId = useSiteStore((s) => s.selectedSiteId);
  const [createDialogOpen, setCreateDialogOpen] = useState(false);
  const [editingVlan, setEditingVlan] = useState<Vlan | undefined>();
  const [deletingVlan, setDeletingVlan] = useState<Vlan | undefined>();
  const [selected, setSelected] = useState<Vlan[]>([]);
  const [searchQuery, setSearchQuery] = useState('');
  const [dhcpFilter, setDhcpFilter] = useState<string>('all');

  // Fetch VLANs
  const { data, isLoading, isError, refetch } = useQuery({
    queryKey: ['vlans', { siteId: selectedSiteId }],
    queryFn: () => networkApi.vlans.list({ site_id: selectedSiteId ?? undefined, limit: 500 }),
  });

  const allVlans: Vlan[] = data?.data?.items || [];
  const vlans = allVlans.filter((v) => {
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      const hay = `${v.vlan_id} ${v.name} ${v.description || ''} ${v.gateway || ''}`.toLowerCase();
      if (!hay.includes(q)) return false;
    }
    if (dhcpFilter === 'enabled' && !v.dhcp_enabled) return false;
    if (dhcpFilter === 'disabled' && v.dhcp_enabled) return false;
    return true;
  });
  const hasActiveFilters = searchQuery !== '' || dhcpFilter !== 'all';
  const createMutation = useMutation({
    mutationFn: (data: VlanCreate) => networkApi.vlans.create(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['vlans'] });
      setCreateDialogOpen(false);
    },
    onError: (err: any) => {
      toast({ title: t('VlansPage.toast.errorTitle'), description: err?.response?.data?.detail || t('VlansPage.toast.operationFailed'), variant: 'destructive' });
    },
  });

  // Update mutation
  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: VlanUpdate }) =>
      networkApi.vlans.update(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['vlans'] });
      setEditingVlan(undefined);
    },
    onError: (err: any) => {
      toast({ title: t('VlansPage.toast.errorTitle'), description: err?.response?.data?.detail || t('VlansPage.toast.operationFailed'), variant: 'destructive' });
    },
  });

  // Delete mutation
  const deleteMutation = useMutation({
    mutationFn: (id: string) => networkApi.vlans.delete(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['vlans'] });
      setDeletingVlan(undefined);
    },
    onError: (err: any) => {
      toast({ title: t('VlansPage.toast.errorTitle'), description: err?.response?.data?.detail || t('VlansPage.toast.operationFailed'), variant: 'destructive' });
    },
  });

  const { toast } = useToast();

  // VLAN Alignment query
  const { data: alignment, isLoading: alignmentLoading } = useQuery({
    queryKey: ['vlan-alignment', selectedSiteId],
    queryFn: async () => {
      if (!selectedSiteId) return null;
      const response = await networkApi.getVlanAlignment(selectedSiteId);
      return response.data;
    },
    enabled: !!selectedSiteId,
    staleTime: 30000,
  });

  // Distribute VLAN mutation
  const distributeMutation = useMutation({
    mutationFn: ({ sourceId, targetIds }: { sourceId: string; targetIds: string[] }) =>
      networkApi.distributeVlan(sourceId, targetIds),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['vlan-alignment'] });
      queryClient.invalidateQueries({ queryKey: ['vlans'] });
      toast({ title: t('VlansPage.toast.successTitle'), description: t('VlansPage.toast.distributeSuccess') });
    },
    onError: (err: any) => {
      toast({
        title: t('VlansPage.toast.errorTitle'),
        description: t('VlansPage.toast.distributeFailed', { error: err.response?.data?.detail || err.message }),
        variant: 'destructive',
      });
    },
  });

  // Table columns
  const columns: DataTableColumn<Vlan>[] = [
    {
      id: 'vlan_id',
      header: t('VlansPage.columns.vlanId'),
      cell: (vlan: Vlan) => (
        <div className="flex items-center gap-2">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-primary/10">
            <span className="text-sm font-bold text-primary">{vlan.vlan_id}</span>
          </div>
        </div>
      ),
    },
    {
      id: 'name',
      header: t('VlansPage.columns.name'),
      cell: (vlan: Vlan) => (
        <div>
          <div className="font-medium">{vlan.name}</div>
          {vlan.description && (
            <div className="text-xs text-muted-foreground">{vlan.description}</div>
          )}
        </div>
      ),
    },
    {
      id: 'gateway',
      header: t('VlansPage.columns.gateway'),
      cell: (vlan: Vlan) => (
        <span className="font-mono text-sm">{vlan.gateway || '-'}</span>
      ),
    },
    {
      id: 'subnet_mask',
      header: t('VlansPage.columns.subnet'),
      cell: (vlan: Vlan) => (
        <span className="font-mono text-sm text-muted-foreground">
          {vlan.subnet_mask || '-'}
        </span>
      ),
    },
    {
      id: 'dhcp_enabled',
      header: t('VlansPage.columns.dhcp'),
      cell: (vlan: Vlan) => <DhcpBadge enabled={vlan.dhcp_enabled} />,
    },
    {
      id: 'dhcp_range',
      header: t('VlansPage.columns.dhcpRange'),
      cell: (vlan: Vlan) => (
        <span className="font-mono text-xs text-muted-foreground">
          {vlan.dhcp_enabled && vlan.dhcp_start && vlan.dhcp_end
            ? `${vlan.dhcp_start} - ${vlan.dhcp_end}`
            : '-'}
        </span>
      ),
    },
    {
      id: 'actions',
      header: '',
      cell: (vlan: Vlan) => (
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" size="sm">
              <MoreHorizontal className="h-4 w-4" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end">
            <DropdownMenuItem onClick={() => setEditingVlan(vlan)}>
              <Pencil className="mr-2 h-4 w-4" />
              {t('VlansPage.actions.edit')}
            </DropdownMenuItem>
            <DropdownMenuItem
              onClick={() => setDeletingVlan(vlan)}
              className="text-destructive focus:text-destructive"
            >
              <Trash2 className="mr-2 h-4 w-4" />
              {t('VlansPage.actions.delete')}
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      ),
    },
  ];

  if (isError) {
    return (
      <div className="space-y-6">
        <PageHeader
          icon={Network}
          title={t('VlansPage.header.title')}
          description={t('VlansPage.header.description')}
        />
        <ErrorState message={t('VlansPage.errors.loadFailed')} onRetry={() => refetch()} />
      </div>
    );
  }

  const dhcpEnabledCount = allVlans.filter((v) => v.dhcp_enabled).length;
  const withGatewayCount = allVlans.filter((v) => v.gateway).length;
  const vlanRange =
    allVlans.length > 0
      ? `${Math.min(...allVlans.map((v) => v.vlan_id))}-${Math.max(...allVlans.map((v) => v.vlan_id))}`
      : '-';

  // Export (client-side CSV from loaded/filtered rows)
  const handleExport = () => {
    const rows = vlans;
    if (rows.length === 0) return;
    const headers = [
      'vlan_id',
      'name',
      'description',
      'gateway',
      'subnet_mask',
      'dhcp_enabled',
      'dhcp_start',
      'dhcp_end',
    ];
    const esc = (val: unknown) => {
      const s = val === undefined || val === null ? '' : String(val);
      return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
    };
    const csv = [
      headers.join(','),
      ...rows.map((v) =>
        [
          v.vlan_id,
          v.name,
          v.description ?? '',
          v.gateway ?? '',
          v.subnet_mask ?? '',
          v.dhcp_enabled,
          v.dhcp_start ?? '',
          v.dhcp_end ?? '',
        ]
          .map(esc)
          .join(','),
      ),
    ].join('\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `vlans-${new Date().toISOString().slice(0, 10)}.csv`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <PageHeader
        icon={Network}
        title={t('VlansPage.header.title')}
        description={t('VlansPage.header.description')}
        onRefresh={() => refetch()}
        refreshing={isLoading}
        secondaryActions={[{ label: t('VlansPage.actions.export'), icon: Download, onClick: handleExport }]}
        primaryAction={{
          label: t('VlansPage.actions.addVlan'),
          icon: Plus,
          onClick: () => setCreateDialogOpen(true),
        }}
      />

      <PageTabs
        basePath="/vlans"
        tabs={[
          {
            value: 'vlans',
            label: t('VlansPage.tabs.vlans'),
            content: (
              <div className="space-y-6">
                <StatsGrid
            columns={4}
            isLoading={isLoading}
            stats={[
              {
                title: t('VlansPage.stats.totalVlans'),
                value: allVlans.length,
                icon: Network,
                variant: 'default',
                description: t('VlansPage.stats.rangeValue', { range: vlanRange }),
              },
              {
                title: t('VlansPage.stats.dhcpEnabled'),
                value: dhcpEnabledCount,
                icon: Server,
                variant: 'success',
                description:
                  allVlans.length > 0
                    ? t('VlansPage.stats.percentOfVlans', { percent: Math.round((dhcpEnabledCount / allVlans.length) * 100) })
                    : t('VlansPage.stats.noVlans'),
              },
              {
                title: t('VlansPage.stats.withGateway'),
                value: withGatewayCount,
                icon: Network,
                variant: 'info',
                description: t('VlansPage.stats.routedVlans'),
              },
              {
                title: t('VlansPage.stats.vlanRange'),
                value: vlanRange,
                icon: Network,
                variant: 'default',
                description: t('VlansPage.stats.lowestHighestId'),
              },
            ]}
          />

          <PageToolbar>
            <SearchBar
              value={searchQuery}
              onChange={setSearchQuery}
              placeholder={t('VlansPage.toolbar.searchPlaceholder')}
              className="w-full sm:w-auto"
            />
            <Select value={dhcpFilter} onValueChange={setDhcpFilter}>
              <SelectTrigger className="w-full sm:w-[160px]">
                <SelectValue placeholder={t('VlansPage.toolbar.allDhcp')} />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">{t('VlansPage.toolbar.allDhcp')}</SelectItem>
                <SelectItem value="enabled">{t('VlansPage.toolbar.dhcpEnabled')}</SelectItem>
                <SelectItem value="disabled">{t('VlansPage.toolbar.dhcpDisabled')}</SelectItem>
              </SelectContent>
            </Select>
            {hasActiveFilters && (
              <Button
                variant="ghost"
                size="sm"
                onClick={() => {
                  setSearchQuery('');
                  setDhcpFilter('all');
                }}
              >
                {t('VlansPage.toolbar.clearFilters')}
              </Button>
            )}
          </PageToolbar>

          <DataTable
            data={vlans}
            columns={columns}
            isLoading={isLoading}
            selectable
            onSelectionChange={setSelected}
            searchable={false}
            itemName={t('VlansPage.itemNamePlural')}
            getRowId={(row) => row.id}
          />

                <BulkActionsBar
                  selectedCount={selected.length}
                  itemName={t('VlansPage.itemName')}
                  onClear={() => setSelected([])}
                  actions={[
                    {
                      label: t('VlansPage.actions.delete'),
                      icon: Trash2,
                      variant: 'destructive',
                      onClick: () => {
                        if (selected.length === 0) return;
                        if (!confirm(t('VlansPage.toast.bulkDeleteTitle'))) return;
                        selected.forEach((v) => deleteMutation.mutate(v.id));
                        setSelected([]);
                      },
                    },
                  ]}
                />
              </div>
            ),
          },
          {
            value: 'alignment',
            label: t('VlansPage.tabs.alignment'),
            hidden: !(alignment && alignment.total_controllers >= 2),
            badge:
              alignment && alignment.alignment_score < 1.0 ? (
                <Badge variant="destructive" className="text-xs">
                  {Math.round(alignment.alignment_score * 100)}%
                </Badge>
              ) : undefined,
            content: (
              <div className="space-y-4">
                {alignmentLoading && (
                  <div className="space-y-4">
                    <Skeleton className="h-24 rounded-xl" />
                    <Skeleton className="h-[320px] rounded-xl" />
                  </div>
                )}
                {alignment && (
                  <div className="space-y-4">
                    {/* Score card · symmetric padding via direct div (Card's CardContent default has pt-0 on sm+) */}
                    <Card>
                      <div className="flex items-center justify-between p-6">
                        <div>
                          <h3 className="text-lg font-semibold">{t('VlansPage.alignment.scoreTitle')}</h3>
                          <p className="text-muted-foreground text-sm">
                            {t('VlansPage.alignment.scoreSummary', { vlans: alignment.total_vlans, controllers: alignment.total_controllers })}
                          </p>
                        </div>
                        <div
                          className={cn(
                            'text-3xl font-bold',
                            alignment.alignment_score >= 1.0
                              ? 'text-success'
                              : alignment.alignment_score >= 0.7
                                ? 'text-warning'
                                : 'text-destructive',
                          )}
                        >
                          {Math.round(alignment.alignment_score * 100)}%
                        </div>
                      </div>
                    </Card>

                    {/* Alignment matrix */}
                    <Card>
                      <CardHeader>
                        <div className="flex items-center justify-between">
                          <div>
                            <CardTitle>{t('VlansPage.alignment.matrixTitle')}</CardTitle>
                            <CardDescription>
                              {t('VlansPage.alignment.matrixDescription')}
                            </CardDescription>
                          </div>
                          {alignment.alignment_score < 1.0 && (
                            <Button
                              size="sm"
                              disabled={distributeMutation.isPending}
                              onClick={() => {
                                if (
                                  !confirm(
                                    t('VlansPage.alignment.syncAllConfirm'),
                                  )
                                )
                                  return;
                                for (const item of alignment.items ?? []) {
                                  if (item.all_aligned) continue;
                                  const source = (item.controllers ?? []).find(
                                    (c: any) => c.present && c.network_id && !c.differs,
                                  );
                                  if (!source) continue;
                                  const targets = (item.controllers ?? [])
                                    .filter((c: any) => !c.present)
                                    .map((c: any) => c.controller_id);
                                  if (targets.length > 0) {
                                    distributeMutation.mutate({
                                      sourceId: source.network_id,
                                      targetIds: targets,
                                    });
                                  }
                                }
                              }}
                            >
                              {distributeMutation.isPending ? (
                                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                              ) : (
                                <ArrowRightLeft className="mr-2 h-4 w-4" />
                              )}
                              {t('VlansPage.alignment.syncAll')}
                            </Button>
                          )}
                        </div>
                      </CardHeader>
                      <CardContent>
                        <div className="overflow-x-auto">
                          <Table>
                            <TableHeader>
                              <TableRow>
                                <TableHead className="min-w-[80px]">{t('VlansPage.alignment.columnVlan')}</TableHead>
                                <TableHead className="min-w-[120px]">{t('VlansPage.alignment.columnName')}</TableHead>
                                {((alignment.items?.length ?? 0) > 0
                                  ? alignment.items[0].controllers ?? []
                                  : []
                                ).map((c: any) => (
                                  <TableHead
                                    key={c.controller_id}
                                    className="text-center min-w-[120px]"
                                  >
                                    {c.controller_name}
                                  </TableHead>
                                ))}
                                <TableHead>{t('VlansPage.alignment.columnStatus')}</TableHead>
                              </TableRow>
                            </TableHeader>
                            <TableBody>
                              {(alignment.items ?? []).map((item: any) => (
                                <TableRow key={item.vlan_id}>
                                  <TableCell className="font-mono font-medium">
                                    {item.vlan_id}
                                  </TableCell>
                                  <TableCell>{item.name}</TableCell>
                                  {(item.controllers ?? []).map((ctrl: any) => (
                                    <TableCell
                                      key={ctrl.controller_id}
                                      className="text-center"
                                    >
                                      {ctrl.present && !ctrl.differs ? (
                                        <Badge variant="default" className="text-xs">
                                          {t('VlansPage.alignment.present')}
                                        </Badge>
                                      ) : ctrl.present && ctrl.differs ? (
                                        <div className="flex flex-col items-center gap-1">
                                          <Badge
                                            variant="secondary"
                                            className="text-xs border-warning text-warning"
                                          >
                                            {t('VlansPage.alignment.different')}
                                          </Badge>
                                          <span className="text-[10px] text-muted-foreground">
                                            {ctrl.subnet || t('VlansPage.alignment.noSubnet')}
                                            {ctrl.dhcp_enabled ? ' +DHCP' : ''}
                                          </span>
                                        </div>
                                      ) : (
                                        <div className="flex flex-col items-center gap-1">
                                          <Badge variant="destructive" className="text-xs">
                                            {t('VlansPage.alignment.missing')}
                                          </Badge>
                                          {(() => {
                                            const source = (item.controllers ?? []).find(
                                              (c: any) => c.present && c.network_id,
                                            );
                                            if (!source) return null;
                                            return (
                                              <Button
                                                size="sm"
                                                variant="outline"
                                                className="text-xs h-6"
                                                disabled={distributeMutation.isPending}
                                                onClick={() =>
                                                  distributeMutation.mutate({
                                                    sourceId: source.network_id,
                                                    targetIds: [ctrl.controller_id],
                                                  })
                                                }
                                              >
                                                {t('VlansPage.alignment.copy')}
                                              </Button>
                                            );
                                          })()}
                                        </div>
                                      )}
                                    </TableCell>
                                  ))}
                                  <TableCell>
                                    {item.all_aligned ? (
                                      <CheckCircle className="h-4 w-4 text-success" />
                                    ) : (
                                      <AlertCircle className="h-4 w-4 text-warning" />
                                    )}
                                  </TableCell>
                                </TableRow>
                              ))}
                            </TableBody>
                          </Table>
                        </div>
                      </CardContent>
                    </Card>
                  </div>
                )}
              </div>
            ),
          },
        ]}
      />

      {/* Create Dialog */}
      <VlanFormDialog
        open={createDialogOpen}
        onOpenChange={setCreateDialogOpen}
        onSubmit={(data) => {
          const payload = data as VlanCreate;
          createMutation.mutate({
            ...payload,
            site_id: payload.site_id ?? selectedSiteId ?? undefined,
          });
        }}
        isLoading={createMutation.isPending}
      />

      {/* Edit Dialog */}
      <VlanFormDialog
        open={!!editingVlan}
        onOpenChange={(open) => !open && setEditingVlan(undefined)}
        vlan={editingVlan}
        onSubmit={(data) =>
          editingVlan && updateMutation.mutate({ id: editingVlan.id, data: data as VlanUpdate })
        }
        isLoading={updateMutation.isPending}
      />

      {/* Delete Confirmation */}
      <AlertDialog open={!!deletingVlan} onOpenChange={(open) => !open && setDeletingVlan(undefined)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t('VlansPage.deleteDialog.title')}</AlertDialogTitle>
            <AlertDialogDescription>
              {t('VlansPage.deleteDialog.description', { vlanId: deletingVlan?.vlan_id, name: deletingVlan?.name })}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t('VlansPage.form.cancel')}</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => deletingVlan && deleteMutation.mutate(deletingVlan.id)}
              className="bg-destructive hover:bg-destructive/90"
            >
              {deleteMutation.isPending ? t('VlansPage.deleteDialog.deleting') : t('VlansPage.actions.delete')}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}

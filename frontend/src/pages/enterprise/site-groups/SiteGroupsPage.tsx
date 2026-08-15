// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN Enterprise · Site Groups & Device Groups
 *
 * Manage organizational groupings for template hierarchy.
 * Site Groups: Org → Site Group → Sites
 * Device Groups: Site → Device Group → Devices
 */

import { useState, useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { useParams, useNavigate } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useToast } from '@/hooks/use-toast';
import { useSiteStore } from '@/stores/siteStore';
import { z } from 'zod';
import {
  FolderTree,
  Plus,
  Pencil,
  Trash2,
  Server,
  Layers,
  Users2,
} from 'lucide-react';
import { PageHeader, PageToolbar } from '@/components/layout';
import { StatsGrid } from '@/components/ui/stats-grid';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { FormDialog } from '@/components/ui/form-dialog';
import { FormControl, FormField, FormItem, FormLabel, FormMessage } from '@/components/ui/form';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { DataTable, type DataTableColumn } from '@/components/ui/data-table';
import { StatusBadge } from '@/components/ui/status-indicator';
import { BulkActionsBar } from '@/components/ui/bulk-actions-bar';
import { ErrorState } from '@/components/ui/empty-state';
import { SearchBar } from '@/components/ui/search-bar';
import { enterpriseApi, type SiteGroup, type DeviceGroup } from '@/lib/api';

const GROUP_TABS = ['site-groups', 'device-groups'] as const;

export default function SiteGroupsPage() {
  const { t } = useTranslation('enterprise');
  const navigate = useNavigate();
  const { tab: urlTab } = useParams<{ tab?: string }>();
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const activeTab = GROUP_TABS.includes(urlTab as any) ? urlTab! : 'site-groups';
  const setActiveTab = (v: string) => navigate(v === 'site-groups' ? '/groups' : `/groups/${v}`, { replace: true });
  const [showCreateSG, setShowCreateSG] = useState(false);
  const [editingSG, setEditingSG] = useState<SiteGroup | null>(null);
  const [showCreateDG, setShowCreateDG] = useState(false);
  const [editingDG, setEditingDG] = useState<DeviceGroup | null>(null);
  const [sgSearch, setSgSearch] = useState('');
  const [dgSearch, setDgSearch] = useState('');
  const [selectedSGs, setSelectedSGs] = useState<SiteGroup[]>([]);
  const [selectedDGs, setSelectedDGs] = useState<DeviceGroup[]>([]);
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const selectedSiteId = useSiteStore((s) => s.selectedSiteId);

  // Surface backend 4xx through a toast, none of the 6 mutations below
  // had ``onError``, so destructive failures (delete denied, name
  // collision, parent_id cycle) used to look like a success to the user.
  const errToast = (title: string) => (err: unknown) => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const detail = (err as any)?.response?.data?.detail
      || (err instanceof Error ? err.message : t('SiteGroupsPage.errors.unknown'));
    toast({ variant: 'destructive', title, description: String(detail) });
  };

  const { data: siteGroups, isLoading: sgLoading, isError: sgError, refetch: sgRefetch } = useQuery({
    queryKey: ['enterprise', 'site-groups'],
    queryFn: () => enterpriseApi.listSiteGroups().then(r => r.data),
  });

  const { data: deviceGroups, isLoading: dgLoading, isError: dgError, refetch: dgRefetch } = useQuery({
    // ``selectedSiteId`` is included in the queryKey so the cache splits
    // per site context; ``listDeviceGroups`` now forwards it so the
    // returned rows are actually narrowed to that site (the page
    // previously listed every device-group org-wide regardless of
    // selector, misleading).
    queryKey: ['enterprise', 'device-groups', selectedSiteId],
    queryFn: () => enterpriseApi.listDeviceGroups(
      selectedSiteId ? { site_id: selectedSiteId } : undefined,
    ).then(r => r.data),
  });

  const createSG = useMutation({
    mutationFn: (data: { name: string; description?: string; parent_id?: string }) =>
      enterpriseApi.createSiteGroup(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['enterprise', 'site-groups'] });
      setShowCreateSG(false);
    },
    onError: errToast(t('SiteGroupsPage.errors.createSiteGroup')),
  });

  const updateSG = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<SiteGroup> }) =>
      enterpriseApi.updateSiteGroup(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['enterprise', 'site-groups'] });
      setEditingSG(null);
    },
    onError: errToast(t('SiteGroupsPage.errors.updateSiteGroup')),
  });

  const deleteSG = useMutation({
    mutationFn: (id: string) => enterpriseApi.deleteSiteGroup(id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['enterprise', 'site-groups'] }),
    onError: errToast(t('SiteGroupsPage.errors.deleteSiteGroup')),
  });

  const createDG = useMutation({
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    mutationFn: (data: { name: string; description?: string; site_id: string; match_rules?: Record<string, any> }) =>
      enterpriseApi.createDeviceGroup(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['enterprise', 'device-groups'] });
      setShowCreateDG(false);
    },
    onError: errToast(t('SiteGroupsPage.errors.createDeviceGroup')),
  });

  const updateDG = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<DeviceGroup> }) =>
      enterpriseApi.updateDeviceGroup(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['enterprise', 'device-groups'] });
      setEditingDG(null);
    },
    onError: errToast(t('SiteGroupsPage.errors.updateDeviceGroup')),
  });

  const deleteDG = useMutation({
    mutationFn: (id: string) => enterpriseApi.deleteDeviceGroup(id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['enterprise', 'device-groups'] }),
    onError: errToast(t('SiteGroupsPage.errors.deleteDeviceGroup')),
  });

  // Schemas / form types for the two dialogs.
  const sgSchema = z.object({
    name: z.string().min(1, t('SiteGroupsPage.validation.nameRequired')),
    description: z.string(),
    parent_id: z.string(),
  });
  type SGFormValues = z.infer<typeof sgSchema>;

  const dgSchema = z
    .object({
      name: z.string().min(1, t('SiteGroupsPage.validation.nameRequired')),
      description: z.string(),
      site_id: z.string().min(1, t('SiteGroupsPage.validation.siteIdRequired')),
      match_rules: z.string(),
    })
    .superRefine((data, ctx) => {
      if (data.match_rules.trim()) {
        try {
          JSON.parse(data.match_rules);
        } catch {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            path: ['match_rules'],
            message: t('SiteGroupsPage.validation.invalidJson'),
          });
        }
      }
    });
  type DGFormValues = z.infer<typeof dgSchema>;

  const sgDefaults: SGFormValues = editingSG
    ? { name: editingSG.name, description: editingSG.description ?? '', parent_id: editingSG.parent_id ?? '' }
    : { name: '', description: '', parent_id: '' };

  const dgDefaults: DGFormValues = editingDG
    ? {
        name: editingDG.name,
        description: editingDG.description ?? '',
        site_id: editingDG.site_id,
        match_rules: JSON.stringify(editingDG.match_rules, null, 2),
      }
    : { name: '', description: '', site_id: '', match_rules: '{}' };

  function openEditSG(sg: SiteGroup) {
    setEditingSG(sg);
  }

  function openEditDG(dg: DeviceGroup) {
    setEditingDG(dg);
  }

  const allSiteGroups = useMemo(() => siteGroups ?? [], [siteGroups]);
  const allDeviceGroups = useMemo(() => deviceGroups ?? [], [deviceGroups]);

  const filteredSG = useMemo(() => allSiteGroups.filter(sg =>
    !sgSearch || sg.name.toLowerCase().includes(sgSearch.toLowerCase()),
  ), [allSiteGroups, sgSearch]);

  const filteredDG = useMemo(() => allDeviceGroups.filter(dg =>
    !dgSearch || dg.name.toLowerCase().includes(dgSearch.toLowerCase()),
  ), [allDeviceGroups, dgSearch]);

  const sgColumns: DataTableColumn<SiteGroup>[] = [
    {
      id: 'name', header: t('SiteGroupsPage.columns.name'), accessorKey: 'name', sortable: true,
      cell: (r) => (
        <div className="flex items-center gap-2">
          <FolderTree className="h-4 w-4 text-muted-foreground" />
          <span className="font-medium">{r.name}</span>
        </div>
      ),
    },
    { id: 'description', header: t('SiteGroupsPage.columns.description'), accessorKey: 'description', cell: (r) => <span className="text-muted-foreground">{r.description || '-'}</span> },
    {
      id: 'parent', header: t('SiteGroupsPage.columns.parent'), accessorKey: 'parent_id',
      cell: (r) => {
        if (!r.parent_id) return <span className="text-muted-foreground">{t('SiteGroupsPage.values.root')}</span>;
        const parent = siteGroups?.find(sg => sg.id === r.parent_id);
        return <Badge variant="outline">{parent?.name ?? r.parent_id.slice(0, 8)}</Badge>;
      },
    },
    {
      id: 'actions', header: '', sortable: false,
      cell: (r) => (
        <div className="flex items-center gap-1 justify-end">
          <Button variant="ghost" size="icon" className="h-8 w-8" onClick={() => openEditSG(r)}><Pencil className="h-4 w-4" /></Button>
          <Button
            variant="ghost"
            size="icon"
            className="h-8 w-8 text-destructive"
            onClick={() => {
              // Bulk Delete (line ~352) confirms; row-level was a single
              // click. Mirror so a misclick can't wipe a group silently.
              if (window.confirm(t('SiteGroupsPage.confirm.deleteSiteGroup', { name: r.name }))) {
                deleteSG.mutate(r.id);
              }
            }}
          >
            <Trash2 className="h-4 w-4" />
          </Button>
        </div>
      ),
    },
  ];

  const dgColumns: DataTableColumn<DeviceGroup>[] = [
    {
      id: 'name', header: t('SiteGroupsPage.columns.name'), accessorKey: 'name', sortable: true,
      cell: (r) => (
        <div className="flex items-center gap-2">
          <Users2 className="h-4 w-4 text-muted-foreground" />
          <span className="font-medium">{r.name}</span>
        </div>
      ),
    },
    { id: 'description', header: t('SiteGroupsPage.columns.description'), accessorKey: 'description', cell: (r) => <span className="text-muted-foreground">{r.description || '-'}</span> },
    {
      id: 'site_id', header: t('SiteGroupsPage.columns.site'), accessorKey: 'site_id',
      cell: (r) => <Badge variant="outline" className="font-mono text-xs">{r.site_id.slice(0, 8)}...</Badge>,
    },
    {
      id: 'status', header: t('SiteGroupsPage.columns.status'), accessorKey: 'is_active',
      cell: (r) => (
        <StatusBadge variant={r.is_active ? 'success' : 'neutral'}>
          {r.is_active ? t('SiteGroupsPage.values.active') : t('SiteGroupsPage.values.inactive')}
        </StatusBadge>
      ),
    },
    {
      id: 'actions', header: '', sortable: false,
      cell: (r) => (
        <div className="flex items-center gap-1 justify-end">
          <Button variant="ghost" size="icon" className="h-8 w-8" onClick={() => openEditDG(r)}><Pencil className="h-4 w-4" /></Button>
          <Button
            variant="ghost"
            size="icon"
            className="h-8 w-8 text-destructive"
            onClick={() => {
              if (window.confirm(t('SiteGroupsPage.confirm.deleteDeviceGroup', { name: r.name }))) {
                deleteDG.mutate(r.id);
              }
            }}
          >
            <Trash2 className="h-4 w-4" />
          </Button>
        </div>
      ),
    },
  ];

  if (sgError && dgError) {
    return (
      <div className="space-y-6">
        <PageHeader icon={FolderTree} title={t('SiteGroupsPage.header.title')} description={t('SiteGroupsPage.header.description')} />
        <ErrorState message={t('SiteGroupsPage.error.loadFailed')} onRetry={() => { sgRefetch(); dgRefetch(); }} />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader
        icon={FolderTree}
        title={t('SiteGroupsPage.header.title')}
        description={t('SiteGroupsPage.header.description')}
        onRefresh={() => {
          queryClient.invalidateQueries({ queryKey: ['enterprise', 'site-groups'] });
          queryClient.invalidateQueries({ queryKey: ['enterprise', 'device-groups'] });
        }}
        refreshing={sgLoading || dgLoading}
        primaryAction={
          activeTab === 'site-groups'
            ? { label: t('SiteGroupsPage.actions.newSiteGroup'), icon: Plus, onClick: () => setShowCreateSG(true) }
            : { label: t('SiteGroupsPage.actions.newDeviceGroup'), icon: Plus, onClick: () => setShowCreateDG(true) }
        }
      />

      <StatsGrid
        columns={4}
        // Show the skeleton while either query is still loading. The
        // previous ``&&`` meant the grid only skeleton'd when BOTH were
        // loading; when one was cached you'd see the count jump from
        // 0 to N on the second response, visually janky.
        isLoading={sgLoading || dgLoading}
        stats={[
          { title: t('SiteGroupsPage.stats.siteGroups.title'), value: allSiteGroups.length, icon: FolderTree, variant: 'default', description: t('SiteGroupsPage.stats.siteGroups.description') },
          { title: t('SiteGroupsPage.stats.deviceGroups.title'), value: allDeviceGroups.length, icon: Users2, variant: 'default', description: t('SiteGroupsPage.stats.deviceGroups.description') },
          { title: t('SiteGroupsPage.stats.rootGroups.title'), value: allSiteGroups.filter(sg => !sg.parent_id).length, icon: Layers, variant: 'default', description: t('SiteGroupsPage.stats.rootGroups.description') },
          { title: t('SiteGroupsPage.stats.activeDeviceGroups.title'), value: allDeviceGroups.filter(dg => dg.is_active).length, icon: Server, variant: 'success', description: t('SiteGroupsPage.stats.activeDeviceGroups.description') },
        ]}
      />

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          <TabsTrigger value="site-groups">{t('SiteGroupsPage.tabs.siteGroups')}</TabsTrigger>
          <TabsTrigger value="device-groups">{t('SiteGroupsPage.tabs.deviceGroups')}</TabsTrigger>
        </TabsList>

        <TabsContent value="site-groups" className="mt-4 space-y-4">
          <PageToolbar>
            <SearchBar
              value={sgSearch}
              onChange={setSgSearch}
              placeholder={t('SiteGroupsPage.search.siteGroups')}
              className="w-full sm:w-auto"
            />
            {sgSearch && (
              <Button variant="ghost" size="sm" onClick={() => setSgSearch('')}>
                {t('SiteGroupsPage.actions.clearFilters')}
              </Button>
            )}
          </PageToolbar>
          <DataTable
            data={filteredSG}
            columns={sgColumns}
            isLoading={sgLoading}
            selectable
            onSelectionChange={setSelectedSGs}
            searchable={false}
            paginated
            getRowId={r => r.id}
            itemName={t('SiteGroupsPage.itemName.siteGroups')}
          />
          <BulkActionsBar
            selectedCount={selectedSGs.length}
            itemName={t('SiteGroupsPage.itemName.siteGroup')}
            onClear={() => setSelectedSGs([])}
            actions={[
              {
                label: t('SiteGroupsPage.actions.delete'),
                icon: Trash2,
                variant: 'destructive',
                onClick: () => {
                  if (confirm(t('SiteGroupsPage.confirm.bulkDeleteSiteGroups', { count: selectedSGs.length }))) {
                    selectedSGs.forEach((sg) => deleteSG.mutate(sg.id));
                    setSelectedSGs([]);
                  }
                },
              },
            ]}
          />
        </TabsContent>

        <TabsContent value="device-groups" className="mt-4 space-y-4">
          <PageToolbar>
            <SearchBar
              value={dgSearch}
              onChange={setDgSearch}
              placeholder={t('SiteGroupsPage.search.deviceGroups')}
              className="w-full sm:w-auto"
            />
            {dgSearch && (
              <Button variant="ghost" size="sm" onClick={() => setDgSearch('')}>
                {t('SiteGroupsPage.actions.clearFilters')}
              </Button>
            )}
          </PageToolbar>
          <DataTable
            data={filteredDG}
            columns={dgColumns}
            isLoading={dgLoading}
            selectable
            onSelectionChange={setSelectedDGs}
            searchable={false}
            paginated
            getRowId={r => r.id}
            itemName={t('SiteGroupsPage.itemName.deviceGroups')}
          />
          <BulkActionsBar
            selectedCount={selectedDGs.length}
            itemName={t('SiteGroupsPage.itemName.deviceGroup')}
            onClear={() => setSelectedDGs([])}
            actions={[
              {
                label: t('SiteGroupsPage.actions.delete'),
                icon: Trash2,
                variant: 'destructive',
                onClick: () => {
                  if (confirm(t('SiteGroupsPage.confirm.bulkDeleteDeviceGroups', { count: selectedDGs.length }))) {
                    selectedDGs.forEach((dg) => deleteDG.mutate(dg.id));
                    setSelectedDGs([]);
                  }
                },
              },
            ]}
          />
        </TabsContent>
      </Tabs>

      {/* Site Group Dialog */}
      <FormDialog<SGFormValues>
        open={showCreateSG || !!editingSG}
        onOpenChange={(open) => {
          if (!open) {
            setShowCreateSG(false);
            setEditingSG(null);
          }
        }}
        title={editingSG ? t('SiteGroupsPage.dialogs.siteGroup.editTitle') : t('SiteGroupsPage.dialogs.siteGroup.createTitle')}
        description={t('SiteGroupsPage.dialogs.siteGroup.description')}
        schema={sgSchema}
        defaultValues={sgDefaults}
        submitLabel={editingSG ? t('SiteGroupsPage.actions.save') : t('SiteGroupsPage.actions.create')}
        onSubmit={async (values) => {
          const payload = {
            name: values.name,
            description: values.description || undefined,
            parent_id: values.parent_id || undefined,
          };
          if (editingSG) {
            await updateSG.mutateAsync({ id: editingSG.id, data: payload });
          } else {
            await createSG.mutateAsync(payload);
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
                  <FormLabel>{t('SiteGroupsPage.fields.name.label')}</FormLabel>
                  <FormControl>
                    <Input placeholder={t('SiteGroupsPage.fields.siteGroupName.placeholder')} {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <FormField
              control={form.control}
              name="description"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>{t('SiteGroupsPage.fields.description.label')}</FormLabel>
                  <FormControl>
                    <Input placeholder={t('SiteGroupsPage.fields.siteGroupDescription.placeholder')} {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <FormField
              control={form.control}
              name="parent_id"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>{t('SiteGroupsPage.fields.parentGroup.label')}</FormLabel>
                  <Select
                    value={field.value || '_none'}
                    onValueChange={(v) => field.onChange(v === '_none' ? '' : v)}
                  >
                    <FormControl>
                      <SelectTrigger><SelectValue placeholder={t('SiteGroupsPage.fields.parentGroup.none')} /></SelectTrigger>
                    </FormControl>
                    <SelectContent>
                      <SelectItem value="_none">{t('SiteGroupsPage.fields.parentGroup.none')}</SelectItem>
                      {allSiteGroups.filter((sg) => sg.id !== editingSG?.id).map((sg) => (
                        <SelectItem key={sg.id} value={sg.id}>{sg.name}</SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  <FormMessage />
                </FormItem>
              )}
            />
          </>
        )}
      </FormDialog>

      {/* Device Group Dialog */}
      <FormDialog<DGFormValues>
        open={showCreateDG || !!editingDG}
        onOpenChange={(open) => {
          if (!open) {
            setShowCreateDG(false);
            setEditingDG(null);
          }
        }}
        title={editingDG ? t('SiteGroupsPage.dialogs.deviceGroup.editTitle') : t('SiteGroupsPage.dialogs.deviceGroup.createTitle')}
        description={t('SiteGroupsPage.dialogs.deviceGroup.description')}
        schema={dgSchema}
        defaultValues={dgDefaults}
        submitLabel={editingDG ? t('SiteGroupsPage.actions.save') : t('SiteGroupsPage.actions.create')}
        contentClassName="max-w-lg"
        onSubmit={async (values) => {
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          let matchRules: Record<string, any> = {};
          try { matchRules = JSON.parse(values.match_rules); } catch { /* validated by schema */ }
          const payload = {
            name: values.name,
            description: values.description || undefined,
            site_id: values.site_id,
            match_rules: matchRules,
          };
          if (editingDG) {
            await updateDG.mutateAsync({ id: editingDG.id, data: payload });
          } else {
            await createDG.mutateAsync(payload);
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
                  <FormLabel>{t('SiteGroupsPage.fields.name.label')}</FormLabel>
                  <FormControl>
                    <Input placeholder={t('SiteGroupsPage.fields.deviceGroupName.placeholder')} {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <FormField
              control={form.control}
              name="description"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>{t('SiteGroupsPage.fields.description.label')}</FormLabel>
                  <FormControl>
                    <Input placeholder={t('SiteGroupsPage.fields.deviceGroupDescription.placeholder')} {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <FormField
              control={form.control}
              name="site_id"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>{t('SiteGroupsPage.fields.siteId.label')}</FormLabel>
                  <FormControl>
                    <Input placeholder={t('SiteGroupsPage.fields.siteId.placeholder')} {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <FormField
              control={form.control}
              name="match_rules"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>{t('SiteGroupsPage.fields.matchRules.label')}</FormLabel>
                  <FormControl>
                    <textarea
                      className="w-full h-32 font-mono text-sm bg-muted border border-border rounded-lg p-3 resize-y focus:outline-none focus:ring-2 focus:ring-primary"
                      spellCheck={false}
                      placeholder='{"device_type": "access_point", "tags": ["floor-3"]}'
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
    </div>
  );
}

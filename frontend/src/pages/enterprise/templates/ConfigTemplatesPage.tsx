// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN Enterprise · Config Templates CRUD
 *
 * Full template management with scope-based filtering, JSON config editing,
 * and preview of template hierarchy resolution.
 */

import { useState, useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { z } from 'zod';
import {
  FileCode2,
  Plus,
  Pencil,
  Trash2,
  Filter,
  Building2,
  Layers,
  Server,
  Eye,
  Copy,
} from 'lucide-react';
import { PageHeader, PageToolbar } from '@/components/layout';
import { StatsGrid } from '@/components/ui/stats-grid';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { FormDialog } from '@/components/ui/form-dialog';
import { FormControl, FormField, FormItem, FormLabel, FormMessage } from '@/components/ui/form';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { DataTable, type DataTableColumn } from '@/components/ui/data-table';
import { StatusBadge } from '@/components/ui/status-indicator';
import { TypeBadge } from '@/components/ui/type-badge';
import { BulkActionsBar } from '@/components/ui/bulk-actions-bar';
import { ErrorState } from '@/components/ui/empty-state';
import { SearchBar } from '@/components/ui/search-bar';
import { enterpriseApi, type ConfigTemplate } from '@/lib/api';
import { useToast } from '@/hooks/use-toast';

const SCOPE_ICONS: Record<string, React.ElementType> = {
  organization: Building2,
  site_group: Layers,
  site: Building2,
  device_group: Server,
};

export default function ConfigTemplatesPage() {
  const { t } = useTranslation('enterprise');
  const { toast } = useToast();
  const scopeLabel = (scope?: string) =>
    scope ? t(`ConfigTemplatesPage.scopes.${scope}`, { defaultValue: scope }) : '';
  const [showCreateDialog, setShowCreateDialog] = useState(false);
  const [editingTemplate, setEditingTemplate] = useState<ConfigTemplate | null>(null);
  const [viewingTemplate, setViewingTemplate] = useState<ConfigTemplate | null>(null);
  const [filterScope, setFilterScope] = useState<string>('all');
  const [search, setSearch] = useState('');
  const [selectedTemplates, setSelectedTemplates] = useState<ConfigTemplate[]>([]);
  const queryClient = useQueryClient();

  // Schema validates name + JSON-parseable config payload (cross-field).
  const templateSchema = z
    .object({
      name: z.string().min(1, t('ConfigTemplatesPage.validation.nameRequired')),
      description: z.string(),
      scope: z.enum(['organization', 'site_group', 'site', 'device_group']),
      scope_id: z.string(),
      device_type: z.string(),
      config: z.string(),
      priority: z.coerce.number().int().min(0).max(999),
    })
    .superRefine((data, ctx) => {
      try {
        JSON.parse(data.config);
      } catch {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['config'],
          message: t('ConfigTemplatesPage.validation.invalidJson'),
        });
      }
    });
  type TemplateFormValues = z.infer<typeof templateSchema>;

  const templateDefaults: TemplateFormValues = editingTemplate
    ? {
        name: editingTemplate.name,
        description: editingTemplate.description ?? '',
        scope: editingTemplate.scope,
        scope_id: editingTemplate.scope_id ?? '',
        device_type: editingTemplate.device_type ?? '',
        config: JSON.stringify(editingTemplate.config, null, 2),
        priority: editingTemplate.priority,
      }
    : {
        name: '',
        description: '',
        scope: 'organization',
        scope_id: '',
        device_type: '',
        config: '{}',
        priority: 100,
      };

  const { data: templates, isLoading, isError, refetch } = useQuery({
    queryKey: ['enterprise', 'templates', filterScope],
    queryFn: () =>
      enterpriseApi.listTemplates(
        filterScope !== 'all' ? { scope: filterScope } : undefined,
      ).then(r => r.data),
  });

  // Centralised error helper, the 3 mutations below previously had no
  // ``onError`` so a 4xx from the backend left the form closed and the
  // user assumed success. Surface the server detail via toast.
  const errToast = (title: string) => (err: unknown) => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const detail = (err as any)?.response?.data?.detail
      || (err instanceof Error ? err.message : t('ConfigTemplatesPage.errors.unknown'));
    toast({ variant: 'destructive', title, description: String(detail) });
  };

  const createMutation = useMutation({
    mutationFn: (data: Parameters<typeof enterpriseApi.createTemplate>[0]) =>
      enterpriseApi.createTemplate(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['enterprise', 'templates'] });
      setShowCreateDialog(false);
    },
    onError: errToast(t('ConfigTemplatesPage.errors.createFailed')),
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<ConfigTemplate> }) =>
      enterpriseApi.updateTemplate(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['enterprise', 'templates'] });
      setEditingTemplate(null);
    },
    onError: errToast(t('ConfigTemplatesPage.errors.updateFailed')),
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => enterpriseApi.deleteTemplate(id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['enterprise', 'templates'] }),
    onError: errToast(t('ConfigTemplatesPage.errors.deleteFailed')),
  });

  // Clone server-side so the real (unredacted) config is copied, a
  // client-side duplicate would copy the "***REDACTED***" placeholders.
  const duplicateMutation = useMutation({
    mutationFn: (id: string) => enterpriseApi.duplicateTemplate(id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['enterprise', 'templates'] }),
    onError: errToast(t('ConfigTemplatesPage.errors.duplicateFailed')),
  });

  function openEdit(t: ConfigTemplate) {
    setEditingTemplate(t);
  }

  const allTemplates = useMemo(() => templates ?? [], [templates]);
  const filtered = useMemo(() => {
    return allTemplates.filter(t =>
      !search || t.name.toLowerCase().includes(search.toLowerCase())
        || t.description?.toLowerCase().includes(search.toLowerCase()),
    );
  }, [allTemplates, search]);

  const byScope = allTemplates.reduce(
    (acc, t) => {
      acc[t.scope] = (acc[t.scope] || 0) + 1;
      return acc;
    },
    {} as Record<string, number>,
  );

  const hasActiveFilters = search !== '' || filterScope !== 'all';

  const columns: DataTableColumn<ConfigTemplate>[] = [
    {
      id: 'name',
      header: t('ConfigTemplatesPage.columns.name'),
      accessorKey: 'name',
      cell: (row) => (
        <div>
          <span className="font-medium text-foreground">{row.name}</span>
          {row.description && <p className="text-xs text-muted-foreground mt-0.5 truncate max-w-xs">{row.description}</p>}
        </div>
      ),
      sortable: true,
    },
    {
      id: 'scope',
      header: t('ConfigTemplatesPage.columns.scope'),
      accessorKey: 'scope',
      cell: (row) => {
        const Icon = SCOPE_ICONS[row.scope] ?? Layers;
        return (
          <div className="flex items-center gap-2">
            <Icon className="h-4 w-4 text-muted-foreground" />
            <span>{scopeLabel(row.scope)}</span>
          </div>
        );
      },
      sortable: true,
    },
    {
      id: 'device_type',
      header: t('ConfigTemplatesPage.columns.deviceType'),
      accessorKey: 'device_type',
      cell: (row) => row.device_type ? <TypeBadge type={row.device_type} /> : <span className="text-muted-foreground">{t('ConfigTemplatesPage.deviceType.all')}</span>,
    },
    {
      id: 'priority',
      header: t('ConfigTemplatesPage.columns.priority'),
      accessorKey: 'priority',
      cell: (row) => <span className="font-mono text-sm">{row.priority}</span>,
      sortable: true,
    },
    {
      id: 'status',
      header: t('ConfigTemplatesPage.columns.status'),
      accessorKey: 'is_active',
      cell: (row) => (
        <StatusBadge variant={row.is_active ? 'success' : 'neutral'}>
          {row.is_active ? t('ConfigTemplatesPage.status.active') : t('ConfigTemplatesPage.status.inactive')}
        </StatusBadge>
      ),
    },
    {
      id: 'actions',
      header: '',
      sortable: false,
      cell: (row) => (
        <div className="flex items-center gap-1 justify-end">
          <Button variant="ghost" size="icon" className="h-8 w-8" onClick={() => setViewingTemplate(row)}>
            <Eye className="h-4 w-4" />
          </Button>
          <Button variant="ghost" size="icon" className="h-8 w-8" onClick={() => openEdit(row)}>
            <Pencil className="h-4 w-4" />
          </Button>
          <Button
            variant="ghost"
            size="icon"
            className="h-8 w-8 text-destructive"
            onClick={() => {
              // The bulk Delete confirms (line ~348) but the row-level
              // trash icon was a single click = silent destroy. Mirror
              // the bulk path so a misclick can't lose a template.
              if (window.confirm(t('ConfigTemplatesPage.confirm.deleteOne', { name: row.name }))) {
                deleteMutation.mutate(row.id);
              }
            }}
          >
            <Trash2 className="h-4 w-4" />
          </Button>
        </div>
      ),
    },
  ];

  if (isError) {
    return (
      <div className="space-y-6">
        <PageHeader icon={FileCode2} title={t('ConfigTemplatesPage.header.title')} description={t('ConfigTemplatesPage.header.descriptionShort')} />
        <ErrorState message={t('ConfigTemplatesPage.errors.loadFailed')} onRetry={() => refetch()} />
      </div>
    );
  }

  const isDialogOpen = showCreateDialog || !!editingTemplate;

  return (
    <div className="space-y-6">
      <PageHeader
        icon={FileCode2}
        title={t('ConfigTemplatesPage.header.title')}
        description={t('ConfigTemplatesPage.header.description')}
        onRefresh={() => refetch()}
        refreshing={isLoading}
        primaryAction={{ label: t('ConfigTemplatesPage.actions.newTemplate'), icon: Plus, onClick: () => setShowCreateDialog(true) }}
      />

      <StatsGrid
        columns={4}
        isLoading={isLoading}
        stats={[
          { title: t('ConfigTemplatesPage.stats.total.title'), value: allTemplates.length, icon: FileCode2, variant: 'default', description: t('ConfigTemplatesPage.stats.total.description') },
          { title: t('ConfigTemplatesPage.stats.organization.title'), value: byScope.organization ?? 0, icon: Building2, variant: 'default', description: t('ConfigTemplatesPage.stats.organization.description') },
          { title: t('ConfigTemplatesPage.stats.siteGroup.title'), value: byScope.site_group ?? 0, icon: Layers, variant: 'default', description: t('ConfigTemplatesPage.stats.siteGroup.description') },
          { title: t('ConfigTemplatesPage.stats.siteDevice.title'), value: (byScope.site ?? 0) + (byScope.device_group ?? 0), icon: Server, variant: 'default', description: t('ConfigTemplatesPage.stats.siteDevice.description') },
        ]}
      />

      <PageToolbar>
        <SearchBar
          value={search}
          onChange={setSearch}
          placeholder={t('ConfigTemplatesPage.search.placeholder')}
          className="w-full sm:w-auto"
        />
        <Select value={filterScope} onValueChange={setFilterScope}>
          <SelectTrigger className="w-full sm:w-[180px]">
            <Filter className="h-4 w-4 mr-2 text-muted-foreground" />
            <SelectValue placeholder={t('ConfigTemplatesPage.filter.scopePlaceholder')} />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">{t('ConfigTemplatesPage.filter.allScopes')}</SelectItem>
            <SelectItem value="organization">{t('ConfigTemplatesPage.scopes.organization')}</SelectItem>
            <SelectItem value="site_group">{t('ConfigTemplatesPage.scopes.site_group')}</SelectItem>
            <SelectItem value="site">{t('ConfigTemplatesPage.scopes.site')}</SelectItem>
            <SelectItem value="device_group">{t('ConfigTemplatesPage.scopes.device_group')}</SelectItem>
          </SelectContent>
        </Select>
        {hasActiveFilters && (
          <Button variant="ghost" size="sm" onClick={() => { setSearch(''); setFilterScope('all'); }}>
            {t('ConfigTemplatesPage.actions.clearFilters')}
          </Button>
        )}
      </PageToolbar>

      <DataTable
        data={filtered}
        columns={columns}
        isLoading={isLoading}
        selectable
        onSelectionChange={setSelectedTemplates}
        searchable={false}
        paginated
        defaultPageSize={25}
        itemName="templates"
        getRowId={(r) => r.id}
      />

      <BulkActionsBar
        selectedCount={selectedTemplates.length}
        itemName="template"
        onClear={() => setSelectedTemplates([])}
        actions={[
          {
            label: t('ConfigTemplatesPage.bulk.duplicate'),
            icon: Copy,
            onClick: () => {
              selectedTemplates.forEach((tpl) => duplicateMutation.mutate(tpl.id));
              setSelectedTemplates([]);
            },
          },
          {
            label: t('ConfigTemplatesPage.bulk.delete'),
            icon: Trash2,
            variant: 'destructive',
            onClick: () => {
              if (confirm(t('ConfigTemplatesPage.confirm.deleteMany', { count: selectedTemplates.length }))) {
                selectedTemplates.forEach((tpl) => deleteMutation.mutate(tpl.id));
                setSelectedTemplates([]);
              }
            },
          },
        ]}
      />

      {/* Create / Edit Dialog */}
      <FormDialog<TemplateFormValues>
        open={isDialogOpen}
        onOpenChange={(open) => {
          if (!open) {
            setShowCreateDialog(false);
            setEditingTemplate(null);
          }
        }}
        title={editingTemplate ? t('ConfigTemplatesPage.dialog.editTitle') : t('ConfigTemplatesPage.dialog.createTitle')}
        description={t('ConfigTemplatesPage.dialog.description')}
        schema={templateSchema}
        defaultValues={templateDefaults}
        submitLabel={editingTemplate ? t('ConfigTemplatesPage.dialog.saveChanges') : t('ConfigTemplatesPage.dialog.createSubmit')}
        contentClassName="max-w-2xl max-h-[90vh] overflow-y-auto"
        onSubmit={async (values) => {
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          const config: Record<string, any> = JSON.parse(values.config); // schema-validated
          const payload = {
            name: values.name,
            description: values.description || undefined,
            scope: values.scope,
            scope_id: values.scope_id || undefined,
            device_type: values.device_type || undefined,
            config,
            priority: values.priority,
          };
          if (editingTemplate) {
            await updateMutation.mutateAsync({ id: editingTemplate.id, data: payload });
          } else {
            await createMutation.mutateAsync(payload);
          }
        }}
      >
        {(form) => (
          <>
            <div className="grid gap-4 md:grid-cols-2">
              <FormField
                control={form.control}
                name="name"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>{t('ConfigTemplatesPage.form.name')}</FormLabel>
                    <FormControl>
                      <Input placeholder={t('ConfigTemplatesPage.form.namePlaceholder')} {...field} />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
              <FormField
                control={form.control}
                name="priority"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>{t('ConfigTemplatesPage.form.priority')}</FormLabel>
                    <FormControl>
                      <Input type="number" min={0} max={999} {...field} />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
            </div>

            <FormField
              control={form.control}
              name="description"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>{t('ConfigTemplatesPage.form.description')}</FormLabel>
                  <FormControl>
                    <Input placeholder={t('ConfigTemplatesPage.form.descriptionPlaceholder')} {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />

            <div className="grid gap-4 md:grid-cols-3">
              <FormField
                control={form.control}
                name="scope"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>{t('ConfigTemplatesPage.form.scope')}</FormLabel>
                    <Select value={field.value} onValueChange={field.onChange}>
                      <FormControl>
                        <SelectTrigger><SelectValue /></SelectTrigger>
                      </FormControl>
                      <SelectContent>
                        <SelectItem value="organization">{t('ConfigTemplatesPage.scopes.organization')}</SelectItem>
                        <SelectItem value="site_group">{t('ConfigTemplatesPage.scopes.site_group')}</SelectItem>
                        <SelectItem value="site">{t('ConfigTemplatesPage.scopes.site')}</SelectItem>
                        <SelectItem value="device_group">{t('ConfigTemplatesPage.scopes.device_group')}</SelectItem>
                      </SelectContent>
                    </Select>
                    <FormMessage />
                  </FormItem>
                )}
              />
              <FormField
                control={form.control}
                name="scope_id"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>{t('ConfigTemplatesPage.form.scopeId')}</FormLabel>
                    <FormControl>
                      <Input placeholder={t('ConfigTemplatesPage.form.scopeIdPlaceholder')} {...field} />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
              <FormField
                control={form.control}
                name="device_type"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>{t('ConfigTemplatesPage.form.deviceType')}</FormLabel>
                    <Select
                      value={field.value || '_all'}
                      onValueChange={(v) => field.onChange(v === '_all' ? '' : v)}
                    >
                      <FormControl>
                        <SelectTrigger><SelectValue /></SelectTrigger>
                      </FormControl>
                      <SelectContent>
                        <SelectItem value="_all">{t('ConfigTemplatesPage.deviceTypes.all')}</SelectItem>
                        <SelectItem value="access_point">{t('ConfigTemplatesPage.deviceTypes.accessPoint')}</SelectItem>
                        <SelectItem value="switch">{t('ConfigTemplatesPage.deviceTypes.switch')}</SelectItem>
                        <SelectItem value="router">{t('ConfigTemplatesPage.deviceTypes.router')}</SelectItem>
                        <SelectItem value="gateway">{t('ConfigTemplatesPage.deviceTypes.gateway')}</SelectItem>
                      </SelectContent>
                    </Select>
                    <FormMessage />
                  </FormItem>
                )}
              />
            </div>

            <FormField
              control={form.control}
              name="config"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>{t('ConfigTemplatesPage.form.config')}</FormLabel>
                  <FormControl>
                    <textarea
                      className="w-full h-64 font-mono text-sm bg-muted border border-border rounded-lg p-3 resize-y focus:outline-none focus:ring-2 focus:ring-primary"
                      spellCheck={false}
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

      {/* View Dialog */}
      <Dialog open={!!viewingTemplate} onOpenChange={open => { if (!open) setViewingTemplate(null); }}>
        <DialogContent className="max-w-2xl max-h-[80vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>{viewingTemplate?.name}</DialogTitle>
            <DialogDescription>{viewingTemplate?.description}</DialogDescription>
          </DialogHeader>
          <div className="space-y-3 py-4">
            <div className="flex items-center gap-4 flex-wrap">
              <Badge variant="outline">{scopeLabel(viewingTemplate?.scope)}</Badge>
              {viewingTemplate?.device_type && <TypeBadge type={viewingTemplate.device_type} />}
              <Badge variant="outline">{t('ConfigTemplatesPage.view.priority', { priority: viewingTemplate?.priority })}</Badge>
              <StatusBadge variant={viewingTemplate?.is_active ? 'success' : 'neutral'}>
                {viewingTemplate?.is_active ? t('ConfigTemplatesPage.status.active') : t('ConfigTemplatesPage.status.inactive')}
              </StatusBadge>
            </div>
            <pre className="bg-muted rounded-lg p-4 text-sm font-mono overflow-auto max-h-96">
              {JSON.stringify(viewingTemplate?.config, null, 2)}
            </pre>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}

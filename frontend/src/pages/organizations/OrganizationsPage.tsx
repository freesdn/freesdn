// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN · Organizations Management Page
 *
 * Canonical list-page pattern.
 */

import { useCallback, useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { z } from 'zod';
import {
  Plus,
  Building2,
  MoreHorizontal,
  Edit,
  Trash2,
  Users,
  CheckCircle,
  Settings,
  Crown,
  Download,
  Eye,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { SearchBar } from '@/components/ui/search-bar';
import { DataTable, type DataTableColumn } from '@/components/ui/data-table';
import { StatsGrid } from '@/components/ui/stats-grid';
import { StatusBadge, type StatusVariant } from '@/components/ui/status-indicator';
import { BulkActionsBar } from '@/components/ui/bulk-actions-bar';
import { ErrorState } from '@/components/ui/empty-state';
import { Badge } from '@/components/ui/badge';
import { FormDialog } from '@/components/ui/form-dialog';
import {
  FormControl,
  FormDescription,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from '@/components/ui/form';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { PageHeader, PageToolbar } from '@/components/layout';
import { useToast } from '@/hooks/use-toast';
import { api } from '@/lib/api';

// Types
interface Organization {
  id: string;
  name: string;
  slug: string;
  description: string | null;
  plan: 'free' | 'pro' | 'enterprise';
  status: 'active' | 'suspended';
  user_count: number;
  site_count: number;
  device_limit: number;
  owner_email: string;
  created_at: string;
}

const PLAN_LIMITS: Record<Organization['plan'], number> = {
  free: 10,
  pro: 100,
  enterprise: 1000,
};

const STATUS_VARIANT: Record<Organization['status'], StatusVariant> = {
  active: 'success',
  suspended: 'error',
};

// Add Organization Dialog
const orgSchema = z.object({
  name: z.string().trim().min(1, 'Name is required'),
  slug: z
    .string()
    .trim()
    .min(1, 'Slug is required')
    .regex(/^[a-z0-9-]+$/, 'Lowercase letters, numbers, and hyphens only'),
  owner_email: z.string().trim().email('Valid email required'),
  plan: z.enum(['free', 'pro', 'enterprise']),
  description: z.string(),
});
type OrgFormValues = z.infer<typeof orgSchema>;

function AddOrgDialog({
  open,
  onOpenChange,
  onAdd,
}: {
  open: boolean;
  onOpenChange: (v: boolean) => void;
  onAdd: (org: Partial<Organization>) => Promise<void>;
}) {
  const { t } = useTranslation();
  const { t: tOrg } = useTranslation('organizations');

  return (
    <FormDialog<OrgFormValues>
      open={open}
      onOpenChange={onOpenChange}
      title={t('organizations.dialogs.createTitle')}
      description={t('organizations.dialogs.createDescription')}
      schema={orgSchema}
      defaultValues={{ name: '', slug: '', owner_email: '', plan: 'free', description: '' }}
      submitLabel={t('organizations.actions.createOrganization')}
      cancelLabel={t('common:cancel')}
      contentClassName="sm:max-w-[500px]"
      onSubmit={async (values) => {
        await onAdd(values);
        onOpenChange(false);
      }}
    >
      {(form) => {
        // Auto-generate slug as name is typed (only when slug hasn't been
        // manually edited from the value derived from the previous name).
        const handleNameChange = (value: string) => {
          const currentSlug = form.getValues('slug');
          const expectedSlug = form
            .getValues('name')
            .toLowerCase()
            .replace(/\s+/g, '-')
            .replace(/[^a-z0-9-]/g, '');
          form.setValue('name', value);
          if (currentSlug === expectedSlug || currentSlug === '') {
            form.setValue(
              'slug',
              value.toLowerCase().replace(/\s+/g, '-').replace(/[^a-z0-9-]/g, ''),
            );
          }
        };

        const slugPreview =
          form.watch('slug') || t('organizations.placeholders.yourOrg');

        return (
          <>
            <FormField
              control={form.control}
              name="name"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>{t('organizations.fields.name')} *</FormLabel>
                  <FormControl>
                    <Input
                      placeholder={t('organizations.placeholders.name')}
                      {...field}
                      onChange={(e) => handleNameChange(e.target.value)}
                    />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <FormField
              control={form.control}
              name="slug"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>{t('organizations.fields.slug')}</FormLabel>
                  <FormControl>
                    <Input
                      placeholder={t('organizations.placeholders.slug')}
                      className="font-mono"
                      {...field}
                    />
                  </FormControl>
                  <FormDescription>
                    {t('organizations.hints.urlSlug', { slug: slugPreview })}
                  </FormDescription>
                  <FormMessage />
                </FormItem>
              )}
            />
            <FormField
              control={form.control}
              name="owner_email"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>{t('organizations.fields.ownerEmail')} *</FormLabel>
                  <FormControl>
                    <Input
                      type="email"
                      placeholder={t('organizations.placeholders.ownerEmail')}
                      {...field}
                    />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <FormField
              control={form.control}
              name="plan"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>{t('organizations.fields.plan')}</FormLabel>
                  <Select value={field.value} onValueChange={field.onChange}>
                    <FormControl>
                      <SelectTrigger>
                        <SelectValue placeholder={tOrg('OrganizationsPage.placeholders.selectPlan')} />
                      </SelectTrigger>
                    </FormControl>
                    <SelectContent>
                      <SelectItem value="free">{t('organizations.planOptions.free')}</SelectItem>
                      <SelectItem value="pro">{t('organizations.planOptions.pro')}</SelectItem>
                      <SelectItem value="enterprise">{t('organizations.planOptions.enterprise')}</SelectItem>
                    </SelectContent>
                  </Select>
                  <FormMessage />
                </FormItem>
              )}
            />
            <FormField
              control={form.control}
              name="description"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>{t('organizations.fields.description')}</FormLabel>
                  <FormControl>
                    <Textarea
                      placeholder={t('organizations.placeholders.description')}
                      {...field}
                    />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
          </>
        );
      }}
    </FormDialog>
  );
}

// Edit Organization Dialog
const editOrgSchema = z.object({
  name: z.string().trim().min(1, 'Name is required'),
  owner_email: z.string().trim().email('Valid email required').or(z.literal('')),
  plan: z.enum(['free', 'pro', 'enterprise']),
  description: z.string(),
});
type EditOrgFormValues = z.infer<typeof editOrgSchema>;

function EditOrgDialog({
  org,
  open,
  onOpenChange,
  onSave,
}: {
  org: Organization | null;
  open: boolean;
  onOpenChange: (v: boolean) => void;
  onSave: (id: string, values: EditOrgFormValues) => Promise<void>;
}) {
  const { t } = useTranslation();

  if (!org) return null;

  return (
    <FormDialog<EditOrgFormValues>
      open={open}
      onOpenChange={onOpenChange}
      title={t('organizations.actions.editOrganization')}
      schema={editOrgSchema}
      defaultValues={{
        name: org.name,
        owner_email: org.owner_email === '-' ? '' : org.owner_email,
        plan: org.plan,
        description: org.description ?? '',
      }}
      submitLabel={t('common:save')}
      cancelLabel={t('common:cancel')}
      contentClassName="sm:max-w-[500px]"
      onSubmit={async (values) => {
        await onSave(org.id, values);
        onOpenChange(false);
      }}
    >
      {(form) => (
        <>
          <FormField
            control={form.control}
            name="name"
            render={({ field }) => (
              <FormItem>
                <FormLabel>{t('organizations.fields.name')} *</FormLabel>
                <FormControl>
                  <Input placeholder={t('organizations.placeholders.name')} {...field} />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
          <FormField
            control={form.control}
            name="owner_email"
            render={({ field }) => (
              <FormItem>
                <FormLabel>{t('organizations.fields.ownerEmail')}</FormLabel>
                <FormControl>
                  <Input
                    type="email"
                    placeholder={t('organizations.placeholders.ownerEmail')}
                    {...field}
                  />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
          <FormField
            control={form.control}
            name="plan"
            render={({ field }) => (
              <FormItem>
                <FormLabel>{t('organizations.fields.plan')}</FormLabel>
                <Select value={field.value} onValueChange={field.onChange}>
                  <FormControl>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                  </FormControl>
                  <SelectContent>
                    <SelectItem value="free">{t('organizations.planOptions.free')}</SelectItem>
                    <SelectItem value="pro">{t('organizations.planOptions.pro')}</SelectItem>
                    <SelectItem value="enterprise">{t('organizations.planOptions.enterprise')}</SelectItem>
                  </SelectContent>
                </Select>
                <FormMessage />
              </FormItem>
            )}
          />
          <FormField
            control={form.control}
            name="description"
            render={({ field }) => (
              <FormItem>
                <FormLabel>{t('organizations.fields.description')}</FormLabel>
                <FormControl>
                  <Textarea placeholder={t('organizations.placeholders.description')} {...field} />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
        </>
      )}
    </FormDialog>
  );
}

export function OrganizationsPage() {
  const { t } = useTranslation();
  const { t: tOrg } = useTranslation('organizations');
  const { toast } = useToast();
  const navigate = useNavigate();
  const [searchQuery, setSearchQuery] = useState('');
  const [planFilter, setPlanFilter] = useState<string>('all');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [orgs, setOrgs] = useState<Organization[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [addOpen, setAddOpen] = useState(false);
  const [editOrg, setEditOrg] = useState<Organization | null>(null);
  const [selectedRows, setSelectedRows] = useState<Organization[]>([]);

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const mapOrganization = (org: any): Organization => {
    const plan: Organization['plan'] =
      org.settings?.plan === 'pro' || org.settings?.plan === 'enterprise' ? org.settings.plan : 'free';
    return {
      id: org.id,
      name: org.name,
      slug: org.slug,
      description: org.description ?? null,
      plan,
      status: org.is_active ? 'active' : 'suspended',
      user_count: org.user_count ?? 0,
      site_count: org.site_count ?? 0,
      device_limit: org.settings?.device_limit ?? PLAN_LIMITS[plan],
      owner_email: org.contact_email ?? '-',
      created_at: org.created_at,
    };
  };

  const loadOrganizations = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const response = await api.get('/organizations', { params: { page: 1, per_page: 100 } });
      const items = Array.isArray(response.data.items) ? response.data.items : [];
      setOrgs(items.map(mapOrganization));
    } catch (err) {
      setError(err instanceof Error ? err.message : t('organizations.errors.loadGeneric'));
      setOrgs([]);
    } finally {
      setIsLoading(false);
    }
  }, [t]);

  useEffect(() => {
    void loadOrganizations();
  }, [loadOrganizations]);

  // Filter
  const filteredOrgs = orgs.filter((org) => {
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      const matches =
        org.name.toLowerCase().includes(q) ||
        org.slug.toLowerCase().includes(q) ||
        org.owner_email.toLowerCase().includes(q);
      if (!matches) return false;
    }
    if (planFilter !== 'all' && org.plan !== planFilter) return false;
    if (statusFilter !== 'all' && org.status !== statusFilter) return false;
    return true;
  });

  // Stats
  const stats = {
    total: orgs.length,
    active: orgs.filter((o) => o.status === 'active').length,
    totalUsers: orgs.reduce((sum, o) => sum + o.user_count, 0),
    enterprise: orgs.filter((o) => o.plan === 'enterprise').length,
  };

  const hasActiveFilters = searchQuery !== '' || planFilter !== 'all' || statusFilter !== 'all';
  const handleClearFilters = () => {
    setSearchQuery('');
    setPlanFilter('all');
    setStatusFilter('all');
  };

  // Create, throws on failure so FormDialog surfaces the server-error banner.
  const handleAddOrg = async (orgData: Partial<Organization>) => {
    await api.post('/organizations', {
      name: orgData.name || '',
      slug: orgData.slug || '',
      description: orgData.description || null,
      contact_email: orgData.owner_email || null,
      settings: { plan: orgData.plan || 'free' },
    });
    await loadOrganizations();
    toast({ title: t('common:success'), description: t('organizations.actions.createOrganization') });
  };

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const errDetail = (err: any, fallback: string): string =>
    err?.response?.data?.detail || (err instanceof Error ? err.message : fallback);

  // Edit, throws on failure so FormDialog surfaces the server-error banner.
  const handleEditOrg = async (id: string, values: EditOrgFormValues) => {
    await api.patch(`/organizations/${id}`, {
      name: values.name,
      description: values.description || null,
      contact_email: values.owner_email || null,
      settings: { plan: values.plan },
    });
    await loadOrganizations();
    toast({ title: t('common:success'), description: t('organizations.actions.editOrganization') });
  };

  const handleDeleteOrg = (org: Organization) => {
    if (!window.confirm(t('organizations.actions.deleteOrganization') + `: ${org.name}?`)) return;
    void (async () => {
      try {
        await api.delete(`/organizations/${org.id}`);
        await loadOrganizations();
        toast({ title: t('common:success'), description: org.name });
      } catch (err) {
        toast({
          title: t('common:error'),
          description: errDetail(err, t('common:error')),
          variant: 'destructive',
        });
      }
    })();
  };

  const handleBulkDelete = () => {
    if (selectedRows.length === 0) return;
    if (
      !window.confirm(
        t('organizations.actions.deleteOrganization') + ` (${selectedRows.length})?`,
      )
    )
      return;
    void (async () => {
      const results = await Promise.allSettled(
        selectedRows.map((o) => api.delete(`/organizations/${o.id}`)),
      );
      const ok = results.filter((r) => r.status === 'fulfilled').length;
      const failed = results.length - ok;
      await loadOrganizations();
      setSelectedRows([]);
      toast({
        title: failed === 0 ? t('common:success') : t('common:error'),
        // Language-neutral numeric summary (ok / total) to avoid faking a single-status result.
        description: `${ok} / ${results.length}`,
        variant: failed === 0 ? 'default' : 'destructive',
      });
    })();
  };

  // Client-side CSV export from already-loaded rows.
  const exportToCsv = (rows: Organization[]) => {
    if (rows.length === 0) return;
    const headers = ['name', 'slug', 'plan', 'status', 'user_count', 'site_count', 'owner_email', 'created_at'];
    const escape = (v: unknown) => `"${String(v ?? '').replace(/"/g, '""')}"`;
    const csv = [
      headers.join(','),
      ...rows.map((o) =>
        [o.name, o.slug, o.plan, o.status, o.user_count, o.site_count, o.owner_email, o.created_at]
          .map(escape)
          .join(','),
      ),
    ].join('\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `organizations-${new Date().toISOString().slice(0, 10)}.csv`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  // Columns
  const columns: DataTableColumn<Organization>[] = [
    {
      id: 'name',
      header: tOrg('OrganizationsPage.columns.organization'),
      accessorKey: 'name',
      cell: (org) => (
        <button
          className="flex items-center gap-3 text-left min-w-0"
          onClick={() => navigate(`/organizations/${org.id}`)}
        >
          <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-primary/10 flex-shrink-0">
            <Building2 className="h-4 w-4 text-primary" />
          </div>
          <div className="min-w-0">
            <div className="font-medium hover:text-primary hover:underline truncate">
              {org.name}
            </div>
            <div className="text-xs text-muted-foreground font-mono truncate">{org.slug}</div>
          </div>
        </button>
      ),
    },
    {
      id: 'status',
      header: tOrg('OrganizationsPage.columns.status'),
      accessorKey: 'status',
      cell: (org) => (
        <StatusBadge variant={STATUS_VARIANT[org.status]}>
          {t(`organizations.statuses.${org.status}`)}
        </StatusBadge>
      ),
    },
    {
      id: 'plan',
      header: tOrg('OrganizationsPage.columns.plan'),
      accessorKey: 'plan',
      cell: (org) => (
        <Badge variant="outline" className="gap-1 text-xs">
          {org.plan === 'enterprise' && <Crown className="h-3 w-3" />}
          {t(`organizations.plans.${org.plan}`)}
        </Badge>
      ),
    },
    {
      id: 'users',
      header: t('organizations.metrics.users'),
      accessorKey: 'user_count',
      cell: (org) => (
        <span className="flex items-center gap-1.5 tabular-nums text-sm">
          <Users className="h-3.5 w-3.5 text-muted-foreground" />
          {org.user_count}
        </span>
      ),
    },
    {
      id: 'sites',
      header: t('organizations.metrics.sites'),
      accessorKey: 'site_count',
      cell: (org) => (
        <span className="text-sm tabular-nums">{org.site_count}</span>
      ),
    },
    {
      id: 'device_limit',
      header: t('organizations.metrics.deviceLimit'),
      accessorKey: 'device_limit',
      cell: (org) => (
        <span className="text-sm tabular-nums text-muted-foreground">{org.device_limit}</span>
      ),
    },
    {
      id: 'owner',
      header: t('organizations.owner'),
      accessorKey: 'owner_email',
      cell: (org) => (
        <span className="text-sm text-muted-foreground truncate max-w-[200px] inline-block">
          {org.owner_email}
        </span>
      ),
    },
    {
      id: 'actions',
      header: '',
      sortable: false,
      cell: (org) => (
        <div className="flex justify-end" onClick={(e) => e.stopPropagation()}>
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" size="icon" className="h-8 w-8" aria-label={tOrg('OrganizationsPage.actions.actionsFor', { name: org.name })}>
                <MoreHorizontal className="h-4 w-4" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuItem onClick={() => navigate(`/organizations/${org.id}`)}>
                <Eye className="mr-2 h-4 w-4" />
                {tOrg('OrganizationsPage.actions.viewDetails')}
              </DropdownMenuItem>
              <DropdownMenuItem onClick={() => setEditOrg(org)}>
                <Edit className="mr-2 h-4 w-4" />
                {t('organizations.actions.editOrganization')}
              </DropdownMenuItem>
              <DropdownMenuItem onClick={() => navigate(`/organizations/${org.id}/settings`)}>
                <Settings className="mr-2 h-4 w-4" />
                {t('common:settings')}
              </DropdownMenuItem>
              <DropdownMenuSeparator />
              <DropdownMenuItem
                className="text-destructive focus:text-destructive"
                onClick={() => handleDeleteOrg(org)}
              >
                <Trash2 className="mr-2 h-4 w-4" />
                {t('organizations.actions.deleteOrganization')}
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      ),
    },
  ];

  if (error && !isLoading) {
    return (
      <div className="space-y-6">
        <PageHeader
          icon={Building2}
          title={t('organizations.title')}
          description={t('organizations.subtitle')}
        />
        <ErrorState message={error} onRetry={() => loadOrganizations()} />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <PageHeader
        icon={Building2}
        title={t('organizations.title')}
        description={t('organizations.subtitle')}
        onRefresh={() => loadOrganizations()}
        refreshing={isLoading}
        secondaryActions={[
          {
            label: tOrg('OrganizationsPage.actions.export'),
            icon: Download,
            onClick: () => exportToCsv(filteredOrgs),
          },
        ]}
        primaryAction={{
          label: t('organizations.actions.addOrganization'),
          icon: Plus,
          onClick: () => setAddOpen(true),
        }}
      />

      {/* Stats */}
      <StatsGrid
        columns={4}
        isLoading={isLoading}
        stats={[
          {
            title: t('organizations.metrics.totalOrganizations'),
            value: stats.total,
            icon: Building2,
            variant: 'default',
          },
          {
            title: t('organizations.metrics.active'),
            value: stats.active,
            icon: CheckCircle,
            variant: 'success',
          },
          {
            title: t('organizations.metrics.totalUsers'),
            value: stats.totalUsers,
            icon: Users,
            variant: 'info',
          },
          {
            title: t('organizations.metrics.enterprise'),
            value: stats.enterprise,
            icon: Crown,
            variant: 'success',
          },
        ]}
      />

      {/* Toolbar */}
      <PageToolbar>
        <SearchBar
          value={searchQuery}
          onChange={setSearchQuery}
          placeholder={t('organizations.searchPlaceholder')}
          className="w-full sm:w-auto"
        />
        <Select value={planFilter} onValueChange={setPlanFilter}>
          <SelectTrigger className="w-full sm:w-[160px]">
            <SelectValue placeholder={tOrg('OrganizationsPage.filters.allPlans')} />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">{tOrg('OrganizationsPage.filters.allPlans')}</SelectItem>
            <SelectItem value="free">{tOrg('OrganizationsPage.planOptions.free')}</SelectItem>
            <SelectItem value="pro">{tOrg('OrganizationsPage.planOptions.pro')}</SelectItem>
            <SelectItem value="enterprise">{tOrg('OrganizationsPage.planOptions.enterprise')}</SelectItem>
          </SelectContent>
        </Select>
        <Select value={statusFilter} onValueChange={setStatusFilter}>
          <SelectTrigger className="w-full sm:w-[160px]">
            <SelectValue placeholder={tOrg('OrganizationsPage.filters.allStatuses')} />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">{tOrg('OrganizationsPage.filters.allStatuses')}</SelectItem>
            <SelectItem value="active">{tOrg('OrganizationsPage.statusOptions.active')}</SelectItem>
            <SelectItem value="suspended">{tOrg('OrganizationsPage.statusOptions.suspended')}</SelectItem>
          </SelectContent>
        </Select>
        {hasActiveFilters && (
          <Button variant="ghost" size="sm" onClick={handleClearFilters}>
            {tOrg('OrganizationsPage.filters.clearFilters')}
          </Button>
        )}
      </PageToolbar>

      {/* Table */}
      <DataTable
        data={filteredOrgs}
        columns={columns}
        isLoading={isLoading}
        selectable
        onSelectionChange={setSelectedRows}
        searchable={false}
        itemName={tOrg('OrganizationsPage.itemNamePlural')}
        getRowId={(o) => o.id}
        onRowClick={(o) => navigate(`/organizations/${o.id}`)}
      />

      {/* Bulk actions */}
      <BulkActionsBar
        selectedCount={selectedRows.length}
        itemName={tOrg('OrganizationsPage.itemNameSingular')}
        onClear={() => setSelectedRows([])}
        actions={[
          {
            label: tOrg('OrganizationsPage.actions.export'),
            icon: Download,
            onClick: () => exportToCsv(selectedRows),
          },
          {
            label: tOrg('OrganizationsPage.actions.delete'),
            icon: Trash2,
            variant: 'destructive',
            onClick: handleBulkDelete,
          },
        ]}
      />

      {/* Add organization dialog */}
      <AddOrgDialog open={addOpen} onOpenChange={setAddOpen} onAdd={handleAddOrg} />

      {/* Edit organization dialog */}
      <EditOrgDialog
        org={editOrg}
        open={editOrg !== null}
        onOpenChange={(v) => {
          if (!v) setEditOrg(null);
        }}
        onSave={handleEditOrg}
      />
    </div>
  );
}

export default OrganizationsPage;

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN · Sites Management Page
 *
 * Canonical list-page pattern (PageHeader + StatsGrid + PageToolbar +
 * DataTable + BulkActionsBar). Mirrors ControllersPage.
 */

import { useState, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { z } from 'zod';
import {
  Plus,
  MapPin,
  Building2,
  Server,
  Wifi,
  MoreHorizontal,
  Edit,
  Trash2,
  CheckCircle,
  Globe,
  Clock,
  Eye,
  Activity,
  Download,
} from 'lucide-react';
import { DataTable, type DataTableColumn } from '@/components/ui/data-table';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { FormDialog } from '@/components/ui/form-dialog';
import { FormControl, FormField, FormItem, FormLabel, FormMessage } from '@/components/ui/form';
import { SearchBar } from '@/components/ui/search-bar';
import { StatsGrid } from '@/components/ui/stats-grid';
import { StatusBadge, type StatusVariant } from '@/components/ui/status-indicator';
import { BulkActionsBar } from '@/components/ui/bulk-actions-bar';
import { ErrorState } from '@/components/ui/empty-state';
import { PageHeader, PageToolbar } from '@/components/layout';
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
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from '@/components/ui/tooltip';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { sitesApi, api } from '@/lib/api';
import { useAuthStore } from '@/stores/authStore';
import { cn } from '@/lib/utils';
import { useToast } from '@/hooks/use-toast';

/* ============================================================
   Types
   ============================================================ */

interface Site {
  id: string;
  name: string;
  slug: string;
  description: string | null;
  address: string | null;
  city: string | null;
  country: string | null;
  timezone: string;
  time_format: string;
  date_format: string;
  is_active: boolean;
  organization_id: string;
  settings: Record<string, unknown>;
  controller_count: number;
  device_count: number;
  online_device_count: number;
  created_at: string;
  updated_at: string;
}

function formatRelative(
  iso: string | null,
  t: (key: string, options?: Record<string, unknown>) => string,
): string {
  if (!iso) return '-';
  const d = new Date(iso);
  const now = new Date();
  const diff = now.getTime() - d.getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return t('SitesPage.time.justNow');
  if (mins < 60) return t('SitesPage.time.minutesAgo', { count: mins });
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return t('SitesPage.time.hoursAgo', { count: hrs });
  const days = Math.floor(hrs / 24);
  if (days < 30) return t('SitesPage.time.daysAgo', { count: days });
  return d.toLocaleDateString();
}

/* ============================================================
   Create / Edit Site Dialog
   ============================================================ */

interface SiteFormData {
  name: string;
  slug: string;
  description: string;
  address: string;
  city: string;
  country: string;
  timezone: string;
}

const EMPTY_FORM: SiteFormData = {
  name: '',
  slug: '',
  description: '',
  address: '',
  city: '',
  country: '',
  timezone: 'UTC',
};

function toSlug(name: string) {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '');
}

// Schema validates: name is required, slug must be URL-safe.
// Built per-component so validation messages can be translated via `t`.
type TFunc = (key: string, options?: Record<string, unknown>) => string;

const buildSiteFormSchema = (t: TFunc) =>
  z
    .object({
      name: z.string().min(1, t('SitesPage.validation.nameRequired')).max(255),
      slug: z.string().max(100),
      description: z.string(),
      address: z.string(),
      city: z.string(),
      country: z.string(),
      timezone: z.string(),
    })
    .superRefine((data, ctx) => {
      if (data.slug && !/^[a-z0-9-]+$/.test(data.slug)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['slug'],
          message: t('SitesPage.validation.slugFormat'),
        });
      }
    });

function SiteFormDialog({
  open,
  onOpenChange,
  initial,
  onSubmit,
  mode,
}: {
  open: boolean;
  onOpenChange: (v: boolean) => void;
  initial?: Partial<SiteFormData>;
  onSubmit: (data: SiteFormData) => Promise<unknown>;
  mode: 'create' | 'edit';
}) {
  const { t } = useTranslation('sites');
  // `autoSlug` lives outside the form because it's UI state that gates
  // auto-derivation of slug from name. Reset whenever the dialog opens.
  const [autoSlug, setAutoSlug] = useState(mode === 'create');

  const defaultValues: SiteFormData = { ...EMPTY_FORM, ...initial };
  const siteFormSchema = useMemo(() => buildSiteFormSchema(t), [t]);

  return (
    <FormDialog<SiteFormData>
      open={open}
      onOpenChange={(v) => {
        if (v) setAutoSlug(mode === 'create');
        onOpenChange(v);
      }}
      title={mode === 'create' ? t('SitesPage.dialogs.create.title') : t('SitesPage.dialogs.edit.title')}
      description={
        mode === 'create'
          ? t('SitesPage.dialogs.create.description')
          : t('SitesPage.dialogs.edit.description')
      }
      schema={siteFormSchema}
      defaultValues={defaultValues}
      submitLabel={mode === 'create' ? t('SitesPage.dialogs.create.submit') : t('SitesPage.dialogs.edit.submit')}
      contentClassName="sm:max-w-[520px]"
      onSubmit={async (values, form) => {
        // Slug is required for create mode but optional in the schema (because
        // it's not editable in edit mode). Surface as a field error.
        if (mode === 'create' && !values.slug.trim()) {
          form.setError('slug', { type: 'required', message: t('SitesPage.validation.slugRequired') });
          return;
        }
        await onSubmit(values);
      }}
    >
      {(form) => (
        <>
          <FormField
            control={form.control}
            name="name"
            render={({ field }) => (
              <FormItem>
                <FormLabel>
                  {t('SitesPage.fields.name')} <span className="text-destructive">*</span>
                </FormLabel>
                <FormControl>
                  <Input
                    placeholder={t('SitesPage.placeholders.name')}
                    maxLength={255}
                    {...field}
                    onChange={(e) => {
                      field.onChange(e);
                      if (autoSlug) form.setValue('slug', toSlug(e.target.value));
                    }}
                  />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
          {mode === 'create' && (
            <FormField
              control={form.control}
              name="slug"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>
                    {t('SitesPage.fields.slug')} <span className="text-destructive">*</span>
                  </FormLabel>
                  <FormControl>
                    <Input
                      placeholder={t('SitesPage.placeholders.slug')}
                      maxLength={100}
                      {...field}
                      onChange={(e) => {
                        setAutoSlug(false);
                        field.onChange(e);
                      }}
                    />
                  </FormControl>
                  <p className="text-xs text-muted-foreground">
                    {t('SitesPage.hints.slug')}
                  </p>
                  <FormMessage />
                </FormItem>
              )}
            />
          )}

          <FormField
            control={form.control}
            name="description"
            render={({ field }) => (
              <FormItem>
                <FormLabel>{t('SitesPage.fields.description')}</FormLabel>
                <FormControl>
                  <Textarea placeholder={t('SitesPage.placeholders.description')} rows={2} {...field} />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />

          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3">
            <FormField
              control={form.control}
              name="city"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>{t('SitesPage.fields.city')}</FormLabel>
                  <FormControl>
                    <Input placeholder={t('SitesPage.placeholders.city')} {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <FormField
              control={form.control}
              name="country"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>{t('SitesPage.fields.country')}</FormLabel>
                  <FormControl>
                    <Input placeholder={t('SitesPage.placeholders.country')} {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <FormField
              control={form.control}
              name="timezone"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>{t('SitesPage.fields.timezone')}</FormLabel>
                  <FormControl>
                    <Input placeholder="America/New_York" {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
          </div>

          <FormField
            control={form.control}
            name="address"
            render={({ field }) => (
              <FormItem>
                <FormLabel>{t('SitesPage.fields.address')}</FormLabel>
                <FormControl>
                  <Input placeholder={t('SitesPage.placeholders.address')} {...field} />
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

/* ============================================================
   Page
   ============================================================ */

export default function SitesPage() {
  const { t } = useTranslation('sites');
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const { user } = useAuthStore();
  const [createOpen, setCreateOpen] = useState(false);
  const [editSite, setEditSite] = useState<Site | null>(null);
  const [deleteSite, setDeleteSite] = useState<Site | null>(null);
  const [bulkDeleteOpen, setBulkDeleteOpen] = useState(false);
  const [bulkDeleting, setBulkDeleting] = useState(false);
  const [selectedOrgId, setSelectedOrgId] = useState<string | undefined>(undefined);
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [selectedSites, setSelectedSites] = useState<Site[]>([]);

  const isSuperAdmin = user?.is_superuser ?? false;

  // Fetch organisations for filter (super_admin only)
  const { data: orgs = [] } = useQuery<{ id: string; name: string; slug: string }[]>({
    queryKey: ['organizations-list'],
    queryFn: async () => {
      const r = await api.get('/organizations', { params: { per_page: 200 } });
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      return (r.data.items ?? []).map((o: any) => ({ id: o.id, name: o.name, slug: o.slug }));
    },
    enabled: isSuperAdmin,
  });

  // Data
  const {
    data: allSites = [],
    isLoading,
    error,
    refetch,
  } = useQuery<Site[]>({
    queryKey: ['sites', selectedOrgId],
    queryFn: async () => {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const params: Record<string, any> = { per_page: 100 };
      if (selectedOrgId) params.organization_id = selectedOrgId;
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const r = await sitesApi.getAll(params as any);
      return r.data.items ?? [];
    },
    refetchInterval: 30_000,
  });

  // Mutations
  const createMutation = useMutation({
    mutationFn: (data: SiteFormData) =>
      sitesApi.create({
        ...data,
        // super_admins can scope new sites to the org they're filtering on;
        // everyone else (and super_admin with no org filter) targets their own org.
        organization_id:
          isSuperAdmin && selectedOrgId ? selectedOrgId : user?.organization_id,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['sites'] });
      setCreateOpen(false);
    },
    onError: () => {
      toast({ title: t('SitesPage.toasts.createFailed.title'), description: t('SitesPage.toasts.createFailed.description'), variant: 'destructive' });
    },
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<SiteFormData> }) =>
      sitesApi.update(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['sites'] });
      setEditSite(null);
    },
    onError: () => {
      toast({ title: t('SitesPage.toasts.updateFailed.title'), description: t('SitesPage.toasts.updateFailed.description'), variant: 'destructive' });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => sitesApi.delete(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['sites'] });
      setDeleteSite(null);
    },
    onError: () => {
      toast({ title: t('SitesPage.toasts.deleteFailed.title'), description: t('SitesPage.toasts.deleteFailed.description'), variant: 'destructive' });
    },
  });

  // ---- Client-side CSV export (no backend) -------------------------------
  // Serializes the supplied rows straight from memory into a downloadable CSV.
  const exportSitesCsv = (rows: Site[]) => {
    if (rows.length === 0) return;
    const headers = [
      t('SitesPage.fields.name'),
      t('SitesPage.fields.slug'),
      t('SitesPage.columns.status'),
      t('SitesPage.fields.city'),
      t('SitesPage.fields.country'),
      t('SitesPage.fields.timezone'),
      t('SitesPage.columns.controllers'),
      t('SitesPage.columns.devices'),
      t('SitesPage.stats.online.title'),
      t('SitesPage.columns.updated'),
    ];
    const esc = (v: unknown) => {
      const s = v == null ? '' : String(v);
      return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
    };
    const lines = rows.map((s) =>
      [
        s.name,
        s.slug,
        s.is_active ? t('SitesPage.status.active') : t('SitesPage.status.inactive'),
        s.city ?? '',
        s.country ?? '',
        s.timezone,
        s.controller_count,
        s.device_count,
        s.online_device_count,
        s.updated_at,
      ]
        .map(esc)
        .join(','),
    );
    const csv = [headers.map(esc).join(','), ...lines].join('\n');
    const blob = new Blob([`\uFEFF${csv}`], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `sites-${new Date().toISOString().slice(0, 10)}.csv`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  // ---- Bulk delete (confirm + per-row mutation + summary toast) -----------
  const handleBulkDelete = async () => {
    const targets = [...selectedSites];
    if (targets.length === 0) return;
    setBulkDeleting(true);
    const results = await Promise.allSettled(targets.map((s) => sitesApi.delete(s.id)));
    setBulkDeleting(false);
    const ok = results.filter((r) => r.status === 'fulfilled').length;
    const failed = results.length - ok;
    queryClient.invalidateQueries({ queryKey: ['sites'] });
    setBulkDeleteOpen(false);
    setSelectedSites([]);
    if (failed === 0) {
      toast({
        title: t('common:success'),
        description: `${t('SitesPage.actions.delete')}: ${ok} / ${results.length}`,
      });
    } else {
      toast({
        title: t('SitesPage.toasts.deleteFailed.title'),
        description: `${t('SitesPage.actions.delete')}: ${ok} / ${results.length}`,
        variant: 'destructive',
      });
    }
  };

  // Filter
  const sites = allSites.filter((site) => {
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      const matches =
        site.name.toLowerCase().includes(q) ||
        site.slug.toLowerCase().includes(q) ||
        (site.city ?? '').toLowerCase().includes(q) ||
        (site.country ?? '').toLowerCase().includes(q);
      if (!matches) return false;
    }
    if (statusFilter === 'active' && !site.is_active) return false;
    if (statusFilter === 'inactive' && site.is_active) return false;
    return true;
  });

  // Stats from full list
  const stats = {
    total: allSites.length,
    active: allSites.filter((s) => s.is_active).length,
    devices: allSites.reduce((n, s) => n + s.device_count, 0),
    online: allSites.reduce((n, s) => n + s.online_device_count, 0),
  };

  const hasActiveFilters = searchQuery !== '' || statusFilter !== 'all';
  const handleClearFilters = () => {
    setSearchQuery('');
    setStatusFilter('all');
  };

  // Table columns
  const columns: DataTableColumn<Site>[] = useMemo(
    () => [
      {
        id: 'name',
        header: t('SitesPage.columns.site'),
        accessorFn: (s) => s.name,
        cell: (s) => (
          <button
            className="flex items-center gap-3 text-left min-w-0"
            onClick={() => navigate(`/sites/${s.id}`)}
          >
            <div
              className={cn(
                'flex h-9 w-9 items-center justify-center rounded-lg flex-shrink-0',
                s.is_active ? 'bg-primary/10' : 'bg-muted',
              )}
            >
              <Building2
                className={cn('h-4 w-4', s.is_active ? 'text-primary' : 'text-muted-foreground')}
              />
            </div>
            <div className="min-w-0">
              <div className="font-medium hover:text-primary hover:underline truncate">
                {s.name}
              </div>
              <div className="truncate text-xs text-muted-foreground">
                {[s.city, s.country].filter(Boolean).join(', ') || s.slug}
              </div>
            </div>
          </button>
        ),
      },
      {
        id: 'status',
        header: t('SitesPage.columns.status'),
        accessorFn: (s) => (s.is_active ? 'active' : 'inactive'),
        cell: (s) => {
          const variant: StatusVariant = s.is_active ? 'success' : 'disabled';
          return (
            <StatusBadge variant={variant}>
              {s.is_active ? t('SitesPage.status.active') : t('SitesPage.status.inactive')}
            </StatusBadge>
          );
        },
      },
      {
        id: 'controllers',
        header: t('SitesPage.columns.controllers'),
        accessorKey: 'controller_count' as keyof Site,
        cell: (s) => (
          <span className="flex items-center gap-1.5 tabular-nums">
            <Server className="h-3.5 w-3.5 text-muted-foreground" />
            {s.controller_count}
          </span>
        ),
      },
      {
        id: 'devices',
        header: t('SitesPage.columns.devices'),
        accessorKey: 'device_count' as keyof Site,
        cell: (s) => {
          const total = s.device_count;
          const online = s.online_device_count;
          const offline = total - online;
          return (
            <div className="flex items-center gap-1.5">
              <span className="inline-flex h-7 min-w-[28px] items-center justify-center rounded-md bg-muted px-1.5 text-sm font-medium">
                {total}
              </span>
              {total > 0 && (
                <div className="flex gap-1 text-xs">
                  <span className="text-success font-medium">{online}</span>
                  <span className="text-muted-foreground">/</span>
                  <span
                    className={cn(
                      'font-medium',
                      offline > 0 ? 'text-destructive' : 'text-muted-foreground',
                    )}
                  >
                    {offline}
                  </span>
                </div>
              )}
            </div>
          );
        },
      },
      {
        id: 'timezone',
        header: t('SitesPage.columns.timezone'),
        accessorKey: 'timezone' as keyof Site,
        cell: (s) => (
          <span className="flex items-center gap-1.5 text-sm text-muted-foreground">
            <Globe className="h-3.5 w-3.5" />
            {s.timezone}
          </span>
        ),
      },
      {
        id: 'updated',
        header: t('SitesPage.columns.updated'),
        accessorFn: (s) => s.updated_at,
        cell: (s) => (
          <TooltipProvider>
            <Tooltip>
              <TooltipTrigger asChild>
                <span className="flex items-center gap-1.5 text-xs text-muted-foreground whitespace-nowrap">
                  <Clock className="h-3 w-3" />
                  {formatRelative(s.updated_at, t)}
                </span>
              </TooltipTrigger>
              <TooltipContent>{new Date(s.updated_at).toLocaleString()}</TooltipContent>
            </Tooltip>
          </TooltipProvider>
        ),
      },
      {
        id: 'actions',
        header: '',
        sortable: false,
        cell: (s) => (
          <div onClick={(e) => e.stopPropagation()} className="flex justify-end">
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="ghost" size="icon" className="h-8 w-8" aria-label={t('SitesPage.actions.actionsFor', { name: s.name })}>
                  <MoreHorizontal className="h-4 w-4" />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end">
                <DropdownMenuItem onClick={() => navigate(`/sites/${s.id}`)}>
                  <Eye className="mr-2 h-4 w-4" />
                  {t('SitesPage.actions.viewDetails')}
                </DropdownMenuItem>
                <DropdownMenuItem onClick={() => setEditSite(s)}>
                  <Edit className="mr-2 h-4 w-4" />
                  {t('SitesPage.actions.editSite')}
                </DropdownMenuItem>
                <DropdownMenuSeparator />
                <DropdownMenuItem
                  className="text-destructive focus:text-destructive"
                  onClick={() => setDeleteSite(s)}
                >
                  <Trash2 className="mr-2 h-4 w-4" />
                  {t('SitesPage.actions.deleteSite')}
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        ),
      },
    ],
    [navigate, t],
  );

  if (error) {
    return (
      <div className="space-y-6">
        <PageHeader
          icon={MapPin}
          title={t('SitesPage.header.title')}
          description={t('SitesPage.header.description')}
        />
        <ErrorState
          message={error instanceof Error ? error.message : t('SitesPage.errors.loadFailed')}
          onRetry={() => refetch()}
        />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <PageHeader
        icon={MapPin}
        title={t('SitesPage.header.title')}
        description={t('SitesPage.header.description')}
        onRefresh={() => refetch()}
        refreshing={isLoading}
        secondaryActions={[
          {
            label: t('SitesPage.actions.export'),
            icon: Download,
            onClick: () => exportSitesCsv(allSites),
          },
        ]}
        primaryAction={{
          label: t('SitesPage.actions.addSite'),
          icon: Plus,
          onClick: () => setCreateOpen(true),
        }}
      />

      {/* Stats */}
      <StatsGrid
        columns={4}
        isLoading={isLoading}
        stats={[
          {
            title: t('SitesPage.stats.total.title'),
            value: stats.total,
            icon: Building2,
            variant: 'default',
            description: t('SitesPage.stats.total.description'),
          },
          {
            title: t('SitesPage.stats.active.title'),
            value: stats.active,
            icon: CheckCircle,
            variant: 'success',
            description:
              stats.total > 0
                ? t('SitesPage.stats.active.percent', {
                    percent: Math.round((stats.active / stats.total) * 100),
                  })
                : t('SitesPage.stats.active.none'),
          },
          {
            title: t('SitesPage.stats.devices.title'),
            value: stats.devices,
            icon: Wifi,
            variant: 'info',
            description: t('SitesPage.stats.devices.description'),
          },
          {
            title: t('SitesPage.stats.online.title'),
            value: stats.online,
            icon: Activity,
            variant: 'success',
            description: t('SitesPage.stats.online.description'),
          },
        ]}
      />

      {/* Toolbar */}
      <PageToolbar>
        <SearchBar
          value={searchQuery}
          onChange={setSearchQuery}
          placeholder={t('SitesPage.toolbar.searchPlaceholder')}
          className="w-full sm:w-auto"
        />
        {isSuperAdmin && orgs.length > 0 && (
          <Select
            value={selectedOrgId ?? '__all__'}
            onValueChange={(v) => setSelectedOrgId(v === '__all__' ? undefined : v)}
          >
            <SelectTrigger className="w-full sm:w-[200px]">
              <SelectValue placeholder={t('SitesPage.toolbar.allOrganizations')} />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="__all__">{t('SitesPage.toolbar.allOrganizations')}</SelectItem>
              {orgs.map((o) => (
                <SelectItem key={o.id} value={o.id}>
                  {o.name}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        )}
        <Select value={statusFilter} onValueChange={setStatusFilter}>
          <SelectTrigger className="w-full sm:w-[160px]">
            <SelectValue placeholder={t('SitesPage.toolbar.allStatuses')} />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">{t('SitesPage.toolbar.allStatuses')}</SelectItem>
            <SelectItem value="active">{t('SitesPage.status.active')}</SelectItem>
            <SelectItem value="inactive">{t('SitesPage.status.inactive')}</SelectItem>
          </SelectContent>
        </Select>
        {hasActiveFilters && (
          <Button variant="ghost" size="sm" onClick={handleClearFilters}>
            {t('SitesPage.toolbar.clearFilters')}
          </Button>
        )}
      </PageToolbar>

      {/* Table */}
      <DataTable
        data={sites}
        columns={columns}
        isLoading={isLoading}
        selectable
        onSelectionChange={setSelectedSites}
        searchable={false}
        itemName="sites"
        getRowId={(s) => s.id}
        onRowClick={(s) => navigate(`/sites/${s.id}`)}
      />

      {/* Bulk actions */}
      <BulkActionsBar
        selectedCount={selectedSites.length}
        itemName="site"
        onClear={() => setSelectedSites([])}
        actions={[
          {
            label: t('SitesPage.actions.export'),
            icon: Download,
            onClick: () => exportSitesCsv(selectedSites),
          },
          {
            label: t('SitesPage.actions.delete'),
            icon: Trash2,
            variant: 'destructive',
            onClick: () => setBulkDeleteOpen(true),
          },
        ]}
      />

      {/* Create Dialog */}
      <SiteFormDialog
        open={createOpen}
        onOpenChange={setCreateOpen}
        onSubmit={(d) => createMutation.mutateAsync(d)}
        mode="create"
      />

      {/* Edit Dialog */}
      {editSite && (
        <SiteFormDialog
          open
          onOpenChange={(v) => !v && setEditSite(null)}
          initial={{
            name: editSite.name,
            slug: editSite.slug,
            description: editSite.description ?? '',
            address: editSite.address ?? '',
            city: editSite.city ?? '',
            country: editSite.country ?? '',
            timezone: editSite.timezone,
          }}
          onSubmit={(d) => updateMutation.mutateAsync({ id: editSite.id, data: d })}
          mode="edit"
        />
      )}

      {/* Delete confirmation */}
      <AlertDialog open={!!deleteSite} onOpenChange={(v) => !v && setDeleteSite(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t('SitesPage.dialogs.delete.title', { name: deleteSite?.name })}</AlertDialogTitle>
            <AlertDialogDescription>
              {t('SitesPage.dialogs.delete.description')}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t('SitesPage.actions.cancel')}</AlertDialogCancel>
            <AlertDialogAction
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
              onClick={() => deleteSite && deleteMutation.mutate(deleteSite.id)}
            >
              {deleteMutation.isPending ? t('SitesPage.dialogs.delete.deleting') : t('SitesPage.dialogs.delete.confirm')}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Bulk delete confirmation */}
      <AlertDialog
        open={bulkDeleteOpen}
        onOpenChange={(v) => !bulkDeleting && setBulkDeleteOpen(v)}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t('SitesPage.toasts.bulkDelete.title')}</AlertDialogTitle>
            <AlertDialogDescription>
              {t('SitesPage.dialogs.delete.description')}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={bulkDeleting}>
              {t('SitesPage.actions.cancel')}
            </AlertDialogCancel>
            <AlertDialogAction
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
              disabled={bulkDeleting}
              onClick={(e) => {
                e.preventDefault();
                void handleBulkDelete();
              }}
            >
              {bulkDeleting
                ? t('SitesPage.dialogs.delete.deleting')
                : `${t('SitesPage.actions.delete')} (${selectedSites.length})`}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}

export { SitesPage };

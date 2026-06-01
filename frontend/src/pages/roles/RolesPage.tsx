// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN · Roles & Permissions Management
 *
 * Canonical list-page pattern. The Permission Matrix tab is preserved as
 * a secondary view, but the primary Roles list now uses DataTable with
 * the standard PageHeader / StatsGrid / PageToolbar / BulkActionsBar.
 */

import { useState, useMemo, useEffect } from 'react';
import { useTranslation, Trans } from 'react-i18next';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Plus,
  Shield,
  ShieldCheck,
  ShieldAlert,
  MoreHorizontal,
  Edit,
  Trash2,
  Users,
  Lock,
  Check,
  X,
  Crown,
  Download,
  Eye,
  KeyRound,
} from 'lucide-react';
import { PageHeader, PageTabs, PageToolbar } from '@/components/layout';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Progress } from '@/components/ui/progress';
import { SearchBar } from '@/components/ui/search-bar';
import { StatsGrid } from '@/components/ui/stats-grid';
import { StatusBadge, type StatusVariant } from '@/components/ui/status-indicator';
import { BulkActionsBar } from '@/components/ui/bulk-actions-bar';
import { ErrorState } from '@/components/ui/empty-state';
import { DataTable, type DataTableColumn } from '@/components/ui/data-table';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
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
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from '@/components/ui/tooltip';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Switch } from '@/components/ui/switch';
import { ScrollArea } from '@/components/ui/scroll-area';
import { useToast } from '@/hooks/use-toast';
import { api, getApiErrorMessage } from '@/lib/api';
import { cn } from '@/lib/utils';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface Role {
  id: string;
  organization_id: string;
  name: string;
  slug: string;
  description?: string;
  permissions: string[];
  level: number;
  is_system: boolean;
  is_default: boolean;
  user_count: number;
  created_at?: string;
  updated_at?: string;
}

type TypeFilter = 'all' | 'system' | 'custom';

// ---------------------------------------------------------------------------
// Permission Categories
// ---------------------------------------------------------------------------

// Permission metadata is keyed by stable identifiers (`value`, plus category
// keys). Human-facing label/description text is stored as translation key
// suffixes (`labelKey`/`descriptionKey`) and translated at the render site via
// t(`RolesPage.${suffix}`). Category keys are also stable identifiers; their
// display labels live under RolesPage.categories.<key> (see CATEGORY_LABEL_KEYS).
type PermissionMeta = { value: string; labelKey: string; descriptionKey: string };

const PERMISSION_CATEGORIES: Record<string, PermissionMeta[]> = {
  'Users & Access': [
    { value: 'user:read', labelKey: 'permissions.user.read.label', descriptionKey: 'permissions.user.read.description' },
    { value: 'user:create', labelKey: 'permissions.user.create.label', descriptionKey: 'permissions.user.create.description' },
    { value: 'user:update', labelKey: 'permissions.user.update.label', descriptionKey: 'permissions.user.update.description' },
    { value: 'user:delete', labelKey: 'permissions.user.delete.label', descriptionKey: 'permissions.user.delete.description' },
    { value: 'role:read', labelKey: 'permissions.role.read.label', descriptionKey: 'permissions.role.read.description' },
    { value: 'role:create', labelKey: 'permissions.role.create.label', descriptionKey: 'permissions.role.create.description' },
    { value: 'role:update', labelKey: 'permissions.role.update.label', descriptionKey: 'permissions.role.update.description' },
    { value: 'role:delete', labelKey: 'permissions.role.delete.label', descriptionKey: 'permissions.role.delete.description' },
  ],
  'Devices': [
    { value: 'device:read', labelKey: 'permissions.device.read.label', descriptionKey: 'permissions.device.read.description' },
    { value: 'device:create', labelKey: 'permissions.device.create.label', descriptionKey: 'permissions.device.create.description' },
    { value: 'device:update', labelKey: 'permissions.device.update.label', descriptionKey: 'permissions.device.update.description' },
    { value: 'device:delete', labelKey: 'permissions.device.delete.label', descriptionKey: 'permissions.device.delete.description' },
    { value: 'device:actions', labelKey: 'permissions.device.actions.label', descriptionKey: 'permissions.device.actions.description' },
  ],
  'Controllers': [
    { value: 'controller:read', labelKey: 'permissions.controller.read.label', descriptionKey: 'permissions.controller.read.description' },
    { value: 'controller:create', labelKey: 'permissions.controller.create.label', descriptionKey: 'permissions.controller.create.description' },
    { value: 'controller:update', labelKey: 'permissions.controller.update.label', descriptionKey: 'permissions.controller.update.description' },
    { value: 'controller:delete', labelKey: 'permissions.controller.delete.label', descriptionKey: 'permissions.controller.delete.description' },
    { value: 'controller:sync', labelKey: 'permissions.controller.sync.label', descriptionKey: 'permissions.controller.sync.description' },
  ],
  'Sites': [
    { value: 'site:read', labelKey: 'permissions.site.read.label', descriptionKey: 'permissions.site.read.description' },
    { value: 'site:create', labelKey: 'permissions.site.create.label', descriptionKey: 'permissions.site.create.description' },
    { value: 'site:update', labelKey: 'permissions.site.update.label', descriptionKey: 'permissions.site.update.description' },
    { value: 'site:delete', labelKey: 'permissions.site.delete.label', descriptionKey: 'permissions.site.delete.description' },
  ],
  'Monitoring & Alerts': [
    { value: 'alert:read', labelKey: 'permissions.alert.read.label', descriptionKey: 'permissions.alert.read.description' },
    { value: 'alert:create', labelKey: 'permissions.alert.create.label', descriptionKey: 'permissions.alert.create.description' },
    { value: 'alert:update', labelKey: 'permissions.alert.update.label', descriptionKey: 'permissions.alert.update.description' },
    { value: 'alert:delete', labelKey: 'permissions.alert.delete.label', descriptionKey: 'permissions.alert.delete.description' },
    { value: 'alert:acknowledge', labelKey: 'permissions.alert.acknowledge.label', descriptionKey: 'permissions.alert.acknowledge.description' },
  ],
  'Security & Audit': [
    { value: 'audit:read', labelKey: 'permissions.audit.read.label', descriptionKey: 'permissions.audit.read.description' },
    { value: 'audit:export', labelKey: 'permissions.audit.export.label', descriptionKey: 'permissions.audit.export.description' },
    { value: 'audit:security', labelKey: 'permissions.audit.security.label', descriptionKey: 'permissions.audit.security.description' },
    { value: 'security:manage', labelKey: 'permissions.security.manage.label', descriptionKey: 'permissions.security.manage.description' },
  ],
  'Settings': [
    // Backend vocabulary uses the plural `settings:` prefix (DEFAULT_ROLE_PERMISSIONS
    // grants `settings:*` to admin and `settings:read` to lower tiers). The FE
    // previously used the singular `setting:` which never matched. The i18n
    // labelKeys stay under the existing `permissions.setting.*` namespace.
    { value: 'settings:read', labelKey: 'permissions.setting.read.label', descriptionKey: 'permissions.setting.read.description' },
    { value: 'settings:update', labelKey: 'permissions.setting.update.label', descriptionKey: 'permissions.setting.update.description' },
    { value: 'integration:read', labelKey: 'permissions.integration.read.label', descriptionKey: 'permissions.integration.read.description' },
    { value: 'integration:manage', labelKey: 'permissions.integration.manage.label', descriptionKey: 'permissions.integration.manage.description' },
  ],
};

// Maps the stable category keys above to their translation key suffixes.
const CATEGORY_LABEL_KEYS: Record<string, string> = {
  'Users & Access': 'categories.usersAccess',
  'Devices': 'categories.devices',
  'Controllers': 'categories.controllers',
  'Sites': 'categories.sites',
  'Monitoring & Alerts': 'categories.monitoringAlerts',
  'Security & Audit': 'categories.securityAudit',
  'Settings': 'categories.settings',
};

const ALL_PERMISSIONS = Object.values(PERMISSION_CATEGORIES).flat();
const TOTAL_PERMISSIONS = ALL_PERMISSIONS.length;

// ---------------------------------------------------------------------------
// Role Level helpers
// ---------------------------------------------------------------------------

// Returns a translation key suffix (`labelKey`) rather than literal text so the
// label can be resolved with t(`RolesPage.${labelKey}`) at the render site.
function getRoleLevelConfig(level: number) {
  if (level >= 100) return { labelKey: 'levels.superAdmin', tone: 'text-destructive', icon: Crown };
  if (level >= 80)  return { labelKey: 'levels.admin', tone: 'text-info', icon: ShieldAlert };
  if (level >= 60)  return { labelKey: 'levels.orgAdmin', tone: 'text-info', icon: ShieldCheck };
  if (level >= 40)  return { labelKey: 'levels.siteAdmin', tone: 'text-info', icon: Shield };
  if (level >= 20)  return { labelKey: 'levels.operator', tone: 'text-success', icon: KeyRound };
  if (level >= 10)  return { labelKey: 'levels.viewer', tone: 'text-muted-foreground', icon: Eye };
  return { labelKey: 'levels.guest', tone: 'text-muted-foreground', icon: Users };
}

// ---------------------------------------------------------------------------
// Permission matching (FE/BE vocabulary aware)
// ---------------------------------------------------------------------------

// Mirrors the backend permission semantics in backend/app/core/dependencies.py:
//   - a bare "*" grants everything (super_admin holds exactly ["*"])
//   - a "<prefix>:*" wildcard grants every "<prefix>:<action>" permission
//     (admin holds "network:*", "settings:*", "organization:*", etc.)
//   - otherwise an exact match is required
// Accepts a pre-built Set for hot paths (matrix / view dialog render loops).
function permissionGrants(permSet: Set<string>, permission: string): boolean {
  if (permSet.has('*')) return true;
  if (permSet.has(permission)) return true;
  const prefix = permission.split(':')[0];
  return permSet.has(`${prefix}:*`);
}

function getCategoryCounts(permissions: string[]) {
  const permSet = new Set(permissions);
  return Object.entries(PERMISSION_CATEGORIES).map(([cat, perms]) => {
    const total = perms.length;
    const granted = perms.filter((p) => permissionGrants(permSet, p.value)).length;
    return { category: cat, granted, total };
  });
}

// Counts how many of the matrix permissions a role actually grants, expanding
// bare "*" / "<prefix>:*" wildcards. Raw `permissions.length` is misleading:
// super_admin holds a single "*" (would show 1/27) and admin holds wildcards
// that each expand to several concrete grants.
function getGrantedPermissionCount(permissions: string[]): number {
  const permSet = new Set(permissions);
  return ALL_PERMISSIONS.filter((p) => permissionGrants(permSet, p.value)).length;
}

// ---------------------------------------------------------------------------
// API
// ---------------------------------------------------------------------------

const rolesApi = {
  getAll: (params?: Record<string, unknown>) => api.get('/roles', { params }),
  getById: (id: string) => api.get(`/roles/${id}`),
  create: (data: Record<string, unknown>) => api.post('/roles', data),
  update: (id: string, data: Record<string, unknown>) => api.patch(`/roles/${id}`, data),
  delete: (id: string) => api.delete(`/roles/${id}`),
};

// ---------------------------------------------------------------------------
// Permission Matrix
// ---------------------------------------------------------------------------

function PermissionMatrix({ roles }: { roles: Role[] }) {
  const { t } = useTranslation('roles');
  const sortedRoles = useMemo(
    () => [...roles].sort((a, b) => b.level - a.level),
    [roles]
  );
  // Precompute a permission Set per role so wildcard matching (bare "*" and
  // "<prefix>:*") is O(1) per cell instead of rebuilding a Set every render.
  const permSets = useMemo(
    () => new Map(sortedRoles.map((role) => [role.id, new Set(role.permissions)])),
    [sortedRoles]
  );

  return (
    <Card>
      <div className="overflow-x-auto">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="sticky left-0 bg-background z-10 min-w-[180px]">{t('RolesPage.matrix.permissionHeader')}</TableHead>
              {sortedRoles.map((role) => (
                <TableHead key={role.id} className="text-center min-w-[90px]">
                  <div className="flex flex-col items-center gap-1">
                    <span className="text-xs font-medium truncate max-w-[80px]">{role.name}</span>
                    <span className="text-[10px] text-muted-foreground">L{role.level}</span>
                  </div>
                </TableHead>
              ))}
            </TableRow>
          </TableHeader>
          <TableBody>
            {Object.entries(PERMISSION_CATEGORIES).map(([category, perms]) => (
              <>
                <TableRow key={`cat-${category}`} className="bg-muted/50">
                  <TableCell colSpan={sortedRoles.length + 1} className="py-2">
                    <span className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">{t(`RolesPage.${CATEGORY_LABEL_KEYS[category]}`)}</span>
                  </TableCell>
                </TableRow>
                {perms.map((perm) => (
                  <TableRow key={perm.value}>
                    <TableCell className="sticky left-0 bg-background z-10">
                      <div>
                        <span className="text-sm">{t(`RolesPage.${perm.labelKey}`)}</span>
                        <p className="text-[10px] text-muted-foreground">{perm.value}</p>
                      </div>
                    </TableCell>
                    {sortedRoles.map((role) => {
                      const has = permissionGrants(permSets.get(role.id) ?? new Set(role.permissions), perm.value);
                      return (
                        <TableCell key={role.id} className="text-center">
                          {has ? (
                            <div className="inline-flex h-5 w-5 items-center justify-center rounded-full bg-success/10">
                              <Check className="h-3 w-3 text-success" />
                            </div>
                          ) : (
                            <div className="inline-flex h-5 w-5 items-center justify-center rounded-full bg-muted">
                              <X className="h-3 w-3 text-muted-foreground/40" />
                            </div>
                          )}
                        </TableCell>
                      );
                    })}
                  </TableRow>
                ))}
              </>
            ))}
          </TableBody>
        </Table>
      </div>
    </Card>
  );
}

// ---------------------------------------------------------------------------
// Main Page Component
// ---------------------------------------------------------------------------

export default function RolesPage() {
  const { t } = useTranslation('roles');
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const [search, setSearch] = useState('');
  const [typeFilter, setTypeFilter] = useState<TypeFilter>('all');
  const [addDialogOpen, setAddDialogOpen] = useState(false);
  const [editingRole, setEditingRole] = useState<Role | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<Role | null>(null);
  const [viewingRole, setViewingRole] = useState<Role | null>(null);
  const [selectedRoles, setSelectedRoles] = useState<Role[]>([]);

  // Fetch roles
  const {
    data: rolesData,
    isLoading,
    error,
    refetch,
  } = useQuery({
    queryKey: ['roles'],
    queryFn: async () => {
      const response = await rolesApi.getAll({ include_system: true });
      return response.data;
    },
  });

  const roles: Role[] = useMemo(() => rolesData?.items ?? [], [rolesData?.items]);

  // Delete mutation
  const deleteMutation = useMutation({
    mutationFn: (id: string) => rolesApi.delete(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['roles'] });
      setDeleteTarget(null);
      toast({ title: t('common:success') });
    },
    onError: (err: unknown) => {
      toast({
        title: t('common:error'),
        description: getApiErrorMessage(err),
        variant: 'destructive',
      });
    },
  });

  // Filtering
  const filteredRoles = useMemo(() => {
    let list = roles;
    if (search) {
      const q = search.toLowerCase();
      list = list.filter(
        (r) =>
          r.name.toLowerCase().includes(q) ||
          r.slug.toLowerCase().includes(q) ||
          r.description?.toLowerCase().includes(q)
      );
    }
    if (typeFilter === 'system') list = list.filter((r) => r.is_system);
    if (typeFilter === 'custom') list = list.filter((r) => !r.is_system);
    return list;
  }, [roles, search, typeFilter]);

  // Stats
  const stats = {
    total: roles.length,
    system: roles.filter((r) => r.is_system).length,
    custom: roles.filter((r) => !r.is_system).length,
    totalUsers: roles.reduce((sum, r) => sum + r.user_count, 0),
  };

  const hasActiveFilters = search !== '' || typeFilter !== 'all';
  const handleClearFilters = () => {
    setSearch('');
    setTypeFilter('all');
  };

  // Shared export handler used by both the PageHeader secondary action and the
  // BulkActionsBar export button so they give identical feedback.
  const handleExport = () =>
    toast({
      title: t('RolesPage.toasts.export.title'),
      description: t('RolesPage.toasts.export.description'),
    });

  // Bulk delete, wires the BulkActionsBar Delete action to the same single-row
  // delete API. System roles are skipped (mirrors the per-row guard, which
  // disables delete when ``is_system``), so a built-in role can never be
  // removed via the bulk path. Runs the deletes concurrently and reports an
  // aggregate summary so a partial failure is visible rather than swallowed.
  const handleBulkDelete = async () => {
    const deletable = selectedRoles.filter((r) => !r.is_system);
    const skipped = selectedRoles.length - deletable.length;
    if (deletable.length === 0) {
      toast({
        title: t('RolesPage.toasts.bulkDelete.nothingTitle'),
        description: t('RolesPage.toasts.bulkDelete.nothingDescription'),
      });
      setSelectedRoles([]);
      return;
    }
    const results = await Promise.allSettled(
      deletable.map((r) => rolesApi.delete(r.id)),
    );
    const ok = results.filter((r) => r.status === 'fulfilled').length;
    const failed = results.length - ok;
    queryClient.invalidateQueries({ queryKey: ['roles'] });
    toast({
      title: t('RolesPage.toasts.bulkDelete.title'),
      description: t('RolesPage.toasts.bulkDelete.summary', { ok, failed, skipped }),
      variant: failed ? 'destructive' : 'default',
    });
    setSelectedRoles([]);
  };

  // Columns
  const columns: DataTableColumn<Role>[] = [
    {
      id: 'name',
      header: t('RolesPage.columns.role'),
      accessorKey: 'name',
      cell: (role) => {
        const lvl = getRoleLevelConfig(role.level);
        const Icon = lvl.icon;
        return (
          <button
            className="flex items-center gap-3 text-left min-w-0"
            onClick={() => setViewingRole(role)}
          >
            <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-muted flex-shrink-0">
              <Icon className={cn('h-4 w-4', lvl.tone)} />
            </div>
            <div className="min-w-0">
              <div className="font-medium hover:text-primary hover:underline truncate">
                {role.name}
              </div>
              <div className="text-xs text-muted-foreground truncate">
                {role.description || role.slug}
              </div>
            </div>
          </button>
        );
      },
    },
    {
      id: 'type',
      header: t('RolesPage.columns.type'),
      accessorFn: (r) => (r.is_system ? 'system' : 'custom'),
      cell: (role) => {
        const variant: StatusVariant = role.is_system ? 'neutral' : 'success';
        return (
          <div className="flex items-center gap-1">
            <StatusBadge variant={variant} hideIcon>
              {role.is_system ? t('RolesPage.type.system') : t('RolesPage.type.custom')}
            </StatusBadge>
            {role.is_default && (
              <StatusBadge variant="info" hideIcon>{t('RolesPage.type.default')}</StatusBadge>
            )}
          </div>
        );
      },
    },
    {
      id: 'level',
      header: t('RolesPage.columns.level'),
      accessorKey: 'level',
      cell: (role) => {
        const lvl = getRoleLevelConfig(role.level);
        return (
          <div className="flex items-center gap-1.5">
            <span className="font-mono text-sm tabular-nums">{role.level}</span>
            <span className={cn('text-xs', lvl.tone)}>{t(`RolesPage.${lvl.labelKey}`)}</span>
          </div>
        );
      },
    },
    {
      id: 'permissions',
      header: t('RolesPage.columns.permissions'),
      accessorFn: (r) => getGrantedPermissionCount(r.permissions),
      cell: (role) => {
        const granted = getGrantedPermissionCount(role.permissions);
        const pct = Math.round((granted / TOTAL_PERMISSIONS) * 100);
        return (
          <div className="flex items-center gap-2 min-w-[160px]">
            <Progress value={pct} className="h-1.5 flex-1" />
            <span className="text-xs text-muted-foreground tabular-nums w-14 text-right">
              {granted}/{TOTAL_PERMISSIONS}
            </span>
          </div>
        );
      },
    },
    {
      id: 'users',
      header: t('RolesPage.columns.users'),
      accessorKey: 'user_count',
      cell: (role) => (
        <span className="flex items-center gap-1.5 text-sm tabular-nums">
          <Users className="h-3.5 w-3.5 text-muted-foreground" />
          {role.user_count}
        </span>
      ),
    },
    {
      id: 'actions',
      header: '',
      sortable: false,
      cell: (role) => (
        <div className="flex justify-end" onClick={(e) => e.stopPropagation()}>
          <TooltipProvider>
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Tooltip>
                  <TooltipTrigger asChild>
                    <Button variant="ghost" size="icon" className="h-8 w-8" aria-label={t('RolesPage.actions.actionsForRole', { name: role.name })}>
                      <MoreHorizontal className="h-4 w-4" />
                    </Button>
                  </TooltipTrigger>
                  <TooltipContent>{t('RolesPage.actions.actions')}</TooltipContent>
                </Tooltip>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end">
                <DropdownMenuItem onClick={() => setViewingRole(role)}>
                  <Eye className="h-4 w-4 mr-2" /> {t('RolesPage.actions.viewPermissions')}
                </DropdownMenuItem>
                <DropdownMenuItem onClick={() => setEditingRole(role)} disabled={role.is_system}>
                  <Edit className="h-4 w-4 mr-2" /> {t('RolesPage.actions.edit')}
                </DropdownMenuItem>
                <DropdownMenuSeparator />
                <DropdownMenuItem
                  className="text-destructive focus:text-destructive"
                  onClick={() => setDeleteTarget(role)}
                  disabled={role.is_system}
                >
                  <Trash2 className="h-4 w-4 mr-2" /> {t('RolesPage.actions.delete')}
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </TooltipProvider>
        </div>
      ),
    },
  ];

  if (error) {
    return (
      <div className="space-y-6">
        <PageHeader
          icon={Shield}
          title={t('RolesPage.header.title')}
          description={t('RolesPage.header.description')}
        />
        <ErrorState
          message={error instanceof Error ? error.message : t('RolesPage.errors.loadFailed')}
          onRetry={() => refetch()}
        />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <PageHeader
        title={t('RolesPage.header.title')}
        description={t('RolesPage.header.description')}
        icon={Shield}
        onRefresh={() => refetch()}
        refreshing={isLoading}
        secondaryActions={[
          { label: t('RolesPage.actions.export'), icon: Download, onClick: handleExport },
        ]}
        primaryAction={{
          label: t('RolesPage.actions.createRole'),
          icon: Plus,
          onClick: () => setAddDialogOpen(true),
        }}
      />

      {/* Stats */}
      <StatsGrid
        columns={4}
        isLoading={isLoading}
        stats={[
          {
            title: t('RolesPage.stats.totalRoles.title'),
            value: stats.total,
            icon: Shield,
            variant: 'default',
            description: t('RolesPage.stats.totalRoles.description'),
          },
          {
            title: t('RolesPage.stats.systemRoles.title'),
            value: stats.system,
            icon: Lock,
            variant: 'info',
            description: t('RolesPage.stats.systemRoles.description'),
          },
          {
            title: t('RolesPage.stats.customRoles.title'),
            value: stats.custom,
            icon: ShieldCheck,
            variant: 'success',
            description: t('RolesPage.stats.customRoles.description'),
          },
          {
            title: t('RolesPage.stats.usersAssigned.title'),
            value: stats.totalUsers,
            icon: Users,
            variant: 'default',
            description: t('RolesPage.stats.usersAssigned.description'),
          },
        ]}
      />

      {/* Tabs: Roles list / Permission Matrix */}
      <PageTabs
        basePath="/roles"
        tabs={[
          {
            value: 'roles',
            label: t('RolesPage.tabs.roles'),
            content: (
              <div className="space-y-4">
                {/* Toolbar */}
                <PageToolbar>
            <SearchBar
              value={search}
              onChange={setSearch}
              placeholder={t('RolesPage.toolbar.searchPlaceholder')}
              className="w-full sm:w-auto"
            />
            <Select value={typeFilter} onValueChange={(v) => setTypeFilter(v as TypeFilter)}>
              <SelectTrigger className="w-full sm:w-[160px]">
                <SelectValue placeholder={t('RolesPage.toolbar.allTypes')} />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">{t('RolesPage.toolbar.allTypes')}</SelectItem>
                <SelectItem value="system">{t('RolesPage.type.system')}</SelectItem>
                <SelectItem value="custom">{t('RolesPage.type.custom')}</SelectItem>
              </SelectContent>
            </Select>
            {hasActiveFilters && (
              <Button variant="ghost" size="sm" onClick={handleClearFilters}>
                {t('RolesPage.toolbar.clearFilters')}
              </Button>
            )}
          </PageToolbar>

          {/* Table */}
          <DataTable
            data={filteredRoles}
            columns={columns}
            isLoading={isLoading}
            selectable
            onSelectionChange={setSelectedRoles}
            searchable={false}
            itemName={t('RolesPage.itemNamePlural')}
            getRowId={(r) => r.id}
          />

          {/* Bulk actions */}
                <BulkActionsBar
                  selectedCount={selectedRoles.length}
                  itemName={t('RolesPage.itemName')}
                  onClear={() => setSelectedRoles([])}
                  actions={[
                    {
                      label: t('RolesPage.actions.export'),
                      icon: Download,
                      onClick: handleExport,
                    },
                    {
                      label: t('RolesPage.actions.delete'),
                      icon: Trash2,
                      variant: 'destructive',
                      onClick: handleBulkDelete,
                    },
                  ]}
                />
              </div>
            ),
          },
          {
            value: 'matrix',
            label: t('RolesPage.tabs.matrix'),
            content: <PermissionMatrix roles={roles} />,
          },
        ]}
      />

      {/* Add/Edit Role Dialog */}
      <RoleDialog
        open={addDialogOpen || !!editingRole}
        onOpenChange={(open) => {
          if (!open) {
            setAddDialogOpen(false);
            setEditingRole(null);
          }
        }}
        role={editingRole}
        onSuccess={() => {
          queryClient.invalidateQueries({ queryKey: ['roles'] });
          setAddDialogOpen(false);
          setEditingRole(null);
        }}
      />

      {/* View Role Dialog */}
      <ViewRoleDialog
        open={!!viewingRole}
        onOpenChange={(open) => !open && setViewingRole(null)}
        role={viewingRole}
        onEdit={() => {
          setEditingRole(viewingRole);
          setViewingRole(null);
        }}
      />

      {/* Delete Confirmation */}
      <AlertDialog open={!!deleteTarget} onOpenChange={(open) => !open && setDeleteTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t('RolesPage.deleteDialog.title')}</AlertDialogTitle>
            <AlertDialogDescription>
              <Trans
                i18nKey="RolesPage.deleteDialog.confirm"
                t={t}
                values={{ name: deleteTarget?.name ?? '' }}
                components={{ strong: <strong /> }}
              />
              {deleteTarget && deleteTarget.user_count > 0 && (
                <span className="block mt-2 text-warning">
                  {deleteTarget.user_count === 1
                    ? t('RolesPage.deleteDialog.warningOne', { count: deleteTarget.user_count })
                    : t('RolesPage.deleteDialog.warningMany', { count: deleteTarget.user_count })}
                </span>
              )}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={deleteMutation.isPending}>{t('RolesPage.actions.cancel')}</AlertDialogCancel>
            <AlertDialogAction
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
              disabled={deleteMutation.isPending || deleteTarget?.is_system}
              onClick={() => deleteTarget && deleteMutation.mutate(deleteTarget.id)}
            >
              {deleteMutation.isPending ? t('RolesPage.actions.deleting') : t('RolesPage.actions.delete')}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Role Dialog (Create / Edit)
// ---------------------------------------------------------------------------

interface RoleDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  role: Role | null;
  onSuccess: () => void;
}

function RoleDialog({ open, onOpenChange, role, onSuccess }: RoleDialogProps) {
  const { t } = useTranslation('roles');
  const { toast } = useToast();
  const [formData, setFormData] = useState({
    name: '',
    slug: '',
    description: '',
    permissions: [] as string[],
    level: 50,
    is_default: false,
  });

  useEffect(() => {
    if (open) {
      if (role) {
        setFormData({
          name: role.name,
          slug: role.slug,
          description: role.description || '',
          permissions: [...role.permissions],
          level: role.level,
          is_default: role.is_default,
        });
      } else {
        setFormData({ name: '', slug: '', description: '', permissions: [], level: 50, is_default: false });
      }
    }
  }, [open, role]);

  const mutation = useMutation({
    mutationFn: (data: Record<string, unknown>) =>
      role ? rolesApi.update(role.id, data) : rolesApi.create(data),
    onSuccess: () => {
      onSuccess();
      onOpenChange(false);
      toast({ title: t('common:success') });
    },
    onError: (err: unknown) => {
      toast({
        title: t('common:error'),
        description: getApiErrorMessage(err),
        variant: 'destructive',
      });
    },
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const data = { ...formData };
    if (!data.slug) {
      data.slug = data.name.toLowerCase().replace(/\s+/g, '-');
    }
    mutation.mutate(data);
  };

  const togglePermission = (permission: string) => {
    setFormData((prev) => ({
      ...prev,
      permissions: prev.permissions.includes(permission)
        ? prev.permissions.filter((p) => p !== permission)
        : [...prev.permissions, permission],
    }));
  };

  const toggleCategory = (permissions: { value: string }[]) => {
    const categoryPerms = permissions.map((p) => p.value);
    const allSelected = categoryPerms.every((p) => formData.permissions.includes(p));
    setFormData((prev) => ({
      ...prev,
      permissions: allSelected
        ? prev.permissions.filter((p) => !categoryPerms.includes(p))
        : [...new Set([...prev.permissions, ...categoryPerms])],
    }));
  };

  const permPct = Math.round((formData.permissions.length / TOTAL_PERMISSIONS) * 100);

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl max-h-[90vh] overflow-hidden flex flex-col">
        <DialogHeader>
          <DialogTitle>{role ? t('RolesPage.roleDialog.editTitle') : t('RolesPage.roleDialog.createTitle')}</DialogTitle>
          <DialogDescription>
            {role ? t('RolesPage.roleDialog.editDescription') : t('RolesPage.roleDialog.createDescription')}
          </DialogDescription>
        </DialogHeader>
        <form onSubmit={handleSubmit} className="flex-1 flex flex-col overflow-hidden">
          <ScrollArea className="flex-1 pr-4">
            <div className="space-y-6 pb-2">
              <div className="space-y-4">
                <div className="grid grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <Label htmlFor="name">{t('RolesPage.roleDialog.nameLabel')}</Label>
                    <Input
                      id="name"
                      value={formData.name}
                      onChange={(e) => setFormData((prev) => ({ ...prev, name: e.target.value }))}
                      placeholder={t('RolesPage.roleDialog.namePlaceholder')}
                      required
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="slug">{t('RolesPage.roleDialog.slugLabel')}</Label>
                    <Input
                      id="slug"
                      value={formData.slug}
                      onChange={(e) => setFormData((prev) => ({ ...prev, slug: e.target.value }))}
                      placeholder={t('RolesPage.roleDialog.slugPlaceholder')}
                    />
                  </div>
                </div>
                <div className="space-y-2">
                  <Label htmlFor="description">{t('RolesPage.roleDialog.descriptionLabel')}</Label>
                  <Textarea
                    id="description"
                    value={formData.description}
                    onChange={(e) => setFormData((prev) => ({ ...prev, description: e.target.value }))}
                    placeholder={t('RolesPage.roleDialog.descriptionPlaceholder')}
                    rows={2}
                  />
                </div>
                <div className="grid grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <Label htmlFor="level">{t('RolesPage.roleDialog.levelLabel')}</Label>
                    <Input
                      id="level"
                      type="number"
                      min={1}
                      max={100}
                      value={formData.level}
                      onChange={(e) => setFormData((prev) => ({ ...prev, level: parseInt(e.target.value) || 50 }))}
                    />
                    <p className="text-xs text-muted-foreground">{t('RolesPage.roleDialog.levelHelp')}</p>
                  </div>
                  <div className="space-y-2">
                    <Label>{t('RolesPage.roleDialog.optionsLabel')}</Label>
                    <div className="flex items-center gap-2 mt-2">
                      <Switch
                        id="is_default"
                        checked={formData.is_default}
                        onCheckedChange={(checked) => setFormData((prev) => ({ ...prev, is_default: checked }))}
                      />
                      <Label htmlFor="is_default" className="font-normal">
                        {t('RolesPage.roleDialog.defaultRoleLabel')}
                      </Label>
                    </div>
                  </div>
                </div>
              </div>

              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <Label className="text-base">{t('RolesPage.roleDialog.permissionsLabel')}</Label>
                  <div className="flex items-center gap-3">
                    <span className="text-sm text-muted-foreground">
                      {t('RolesPage.roleDialog.permissionsCount', { selected: formData.permissions.length, total: TOTAL_PERMISSIONS })}
                    </span>
                    <div className="w-20">
                      <Progress value={permPct} className="h-1.5" />
                    </div>
                  </div>
                </div>

                <div className="space-y-3">
                  {Object.entries(PERMISSION_CATEGORIES).map(([category, permissions]) => {
                    const selectedCount = permissions.filter((p) => formData.permissions.includes(p.value)).length;
                    const allSelected = selectedCount === permissions.length;

                    return (
                      <div key={category} className="border rounded-lg overflow-hidden">
                        <div
                          className="flex items-center justify-between px-4 py-3 bg-muted/30 cursor-pointer hover:bg-muted/50 transition-colors"
                          onClick={() => toggleCategory(permissions)}
                        >
                          <h4 className="text-sm font-medium">{t(`RolesPage.${CATEGORY_LABEL_KEYS[category]}`)}</h4>
                          <div className="flex items-center gap-2">
                            <span className="text-xs text-muted-foreground">
                              {selectedCount}/{permissions.length}
                            </span>
                            <div
                              className={cn(
                                'w-5 h-5 rounded border flex items-center justify-center transition-colors',
                                allSelected
                                  ? 'bg-primary border-primary'
                                  : selectedCount > 0
                                  ? 'bg-primary/50 border-primary'
                                  : 'border-input'
                              )}
                            >
                              {(allSelected || selectedCount > 0) && (
                                <Check className="h-3 w-3 text-primary-foreground" />
                              )}
                            </div>
                          </div>
                        </div>
                        <div className="grid grid-cols-2 gap-1 p-2">
                          {permissions.map((perm) => (
                            <div
                              key={perm.value}
                              className={cn(
                                'flex items-center gap-2 p-2 rounded cursor-pointer transition-colors',
                                formData.permissions.includes(perm.value) ? 'bg-primary/5' : 'hover:bg-muted/50'
                              )}
                              onClick={(e) => { e.stopPropagation(); togglePermission(perm.value); }}
                            >
                              <div
                                className={cn(
                                  'w-4 h-4 rounded border flex items-center justify-center shrink-0 transition-colors',
                                  formData.permissions.includes(perm.value)
                                    ? 'bg-primary border-primary'
                                    : 'border-input'
                                )}
                              >
                                {formData.permissions.includes(perm.value) && (
                                  <Check className="h-3 w-3 text-primary-foreground" />
                                )}
                              </div>
                              <div className="flex-1 min-w-0">
                                <p className="text-sm">{t(`RolesPage.${perm.labelKey}`)}</p>
                                <p className="text-[10px] text-muted-foreground truncate">{t(`RolesPage.${perm.descriptionKey}`)}</p>
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>
          </ScrollArea>
          <DialogFooter className="mt-4 pt-4 border-t">
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
              {t('RolesPage.actions.cancel')}
            </Button>
            <Button type="submit" disabled={mutation.isPending}>
              {mutation.isPending ? t('RolesPage.actions.saving') : role ? t('RolesPage.actions.updateRole') : t('RolesPage.actions.createRole')}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

// ---------------------------------------------------------------------------
// View Role Dialog
// ---------------------------------------------------------------------------

interface ViewRoleDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  role: Role | null;
  onEdit: () => void;
}

function ViewRoleDialog({ open, onOpenChange, role, onEdit }: ViewRoleDialogProps) {
  const { t } = useTranslation('roles');
  if (!role) return null;

  const lvl = getRoleLevelConfig(role.level);
  const LevelIcon = lvl.icon;
  const categoryCounts = getCategoryCounts(role.permissions);

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl max-h-[90vh] overflow-hidden flex flex-col">
        <DialogHeader>
          <div className="flex items-center gap-3">
            <div className="h-10 w-10 rounded-lg flex items-center justify-center bg-muted">
              <LevelIcon className={cn('h-5 w-5', lvl.tone)} />
            </div>
            <div>
              <DialogTitle className="flex items-center gap-2">
                {role.name}
                {role.is_system && <Badge variant="outline" className="text-[10px]">{t('RolesPage.type.system')}</Badge>}
                {role.is_default && <StatusBadge variant="info" hideIcon size="sm">{t('RolesPage.type.default')}</StatusBadge>}
              </DialogTitle>
              <DialogDescription>{role.description || t('RolesPage.viewDialog.noDescription')}</DialogDescription>
            </div>
          </div>
        </DialogHeader>

        <ScrollArea className="flex-1">
          <div className="space-y-5">
            <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3">
              <div className="flex items-center gap-3 p-3 rounded-lg bg-muted/50 border">
                <Users className="h-4 w-4 text-muted-foreground" />
                <div>
                  <p className="text-lg font-bold">{role.user_count}</p>
                  <p className="text-[10px] text-muted-foreground">{t('RolesPage.viewDialog.usersLabel')}</p>
                </div>
              </div>
              <div className="flex items-center gap-3 p-3 rounded-lg bg-muted/50 border">
                <KeyRound className="h-4 w-4 text-muted-foreground" />
                <div>
                  <p className="text-lg font-bold">{getGrantedPermissionCount(role.permissions)}</p>
                  <p className="text-[10px] text-muted-foreground">{t('RolesPage.viewDialog.permissionsLabel')}</p>
                </div>
              </div>
              <div className="flex items-center gap-3 p-3 rounded-lg bg-muted/50 border">
                <Shield className="h-4 w-4 text-muted-foreground" />
                <div>
                  <div className="flex items-baseline gap-1.5">
                    <p className="text-lg font-bold">{role.level}</p>
                    <span className={cn('text-xs', lvl.tone)}>{t(`RolesPage.${lvl.labelKey}`)}</span>
                  </div>
                  <p className="text-[10px] text-muted-foreground">{t('RolesPage.viewDialog.levelLabel')}</p>
                </div>
              </div>
            </div>

            <div className="space-y-3">
              <h4 className="text-sm font-semibold text-muted-foreground uppercase tracking-wider">{t('RolesPage.viewDialog.permissionBreakdown')}</h4>
              {categoryCounts.map(({ category, granted, total }) => {
                const perms = PERMISSION_CATEGORIES[category] || [];
                const permSet = new Set(role.permissions);
                return (
                  <div key={category} className="border rounded-lg overflow-hidden">
                    <div className="flex items-center justify-between px-4 py-2.5 bg-muted/30">
                      <span className="text-sm font-medium">{t(`RolesPage.${CATEGORY_LABEL_KEYS[category]}`)}</span>
                      <div className="flex items-center gap-2">
                        <Progress
                          value={total > 0 ? (granted / total) * 100 : 0}
                          className="h-1.5 w-16"
                        />
                        <span
                          className={cn(
                            'text-xs font-medium min-w-[32px] text-right',
                            granted === total ? 'text-success' : granted > 0 ? 'text-info' : 'text-muted-foreground',
                          )}
                        >
                          {granted}/{total}
                        </span>
                      </div>
                    </div>
                    <div className="grid grid-cols-2 gap-1 p-2">
                      {perms.map((perm) => {
                        const has = permissionGrants(permSet, perm.value);
                        return (
                          <div key={perm.value} className="flex items-center gap-2 px-2 py-1.5 rounded">
                            {has ? (
                              <div className="h-4 w-4 rounded-full bg-success/10 flex items-center justify-center shrink-0">
                                <Check className="h-3 w-3 text-success" />
                              </div>
                            ) : (
                              <div className="h-4 w-4 rounded-full bg-muted flex items-center justify-center shrink-0">
                                <X className="h-3 w-3 text-muted-foreground/40" />
                              </div>
                            )}
                            <span className={cn('text-sm', has ? 'text-foreground' : 'text-muted-foreground')}>
                              {t(`RolesPage.${perm.labelKey}`)}
                            </span>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                );
              })}
            </div>

            <div className="space-y-2 text-sm border-t pt-3">
              <div className="flex justify-between">
                <span className="text-muted-foreground">{t('RolesPage.viewDialog.slug')}</span>
                <code className="text-xs bg-muted px-2 py-0.5 rounded font-mono">{role.slug}</code>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">{t('RolesPage.viewDialog.roleId')}</span>
                <code className="text-xs bg-muted px-2 py-0.5 rounded font-mono truncate max-w-[200px]">{role.id}</code>
              </div>
            </div>
          </div>
        </ScrollArea>

        <DialogFooter className="mt-4 pt-4 border-t">
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            {t('RolesPage.actions.close')}
          </Button>
          {!role.is_system && (
            <Button onClick={onEdit}>
              <Edit className="h-4 w-4 mr-2" />
              {t('RolesPage.actions.editRole')}
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

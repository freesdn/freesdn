// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN · Users Management Page
 *
 * Canonical list-page pattern.
 */
/* eslint-disable @typescript-eslint/no-explicit-any */

import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { z } from 'zod';
import {
  MoreHorizontal,
  User,
  Users,
  Shield,
  Key,
  CheckCircle,
  XCircle,
  Trash2,
  Edit,
  UserPlus,
  Lock,
  Unlock,
  MapPin,
  Download,
} from 'lucide-react';
import { DataTable, type DataTableColumn } from '@/components/ui/data-table';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Checkbox } from '@/components/ui/checkbox';
import { SearchBar } from '@/components/ui/search-bar';
import { StatsGrid } from '@/components/ui/stats-grid';
import { StatusBadge, type StatusVariant } from '@/components/ui/status-indicator';
import { BulkActionsBar } from '@/components/ui/bulk-actions-bar';
import { ErrorState } from '@/components/ui/empty-state';
import { PageHeader, PageToolbar } from '@/components/layout';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { FormDialog } from '@/components/ui/form-dialog';
import {
  FormControl,
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
import { cn } from '@/lib/utils';
import { useToast } from '@/hooks/use-toast';
import { usersApi, sitesApi, api, type UserAccount, type UserUpdatePayload } from '@/lib/api';
import { useAuthStore } from '@/stores/authStore';

type TFn = (key: string, options?: Record<string, unknown>) => string;

// Role label map, key suffixes translated at the render site
const ROLE_LABEL_KEYS: Record<string, string> = {
  super_admin: 'roles.super_admin',
  org_admin: 'roles.org_admin',
  operator: 'roles.operator',
  viewer: 'roles.viewer',
  api_key: 'roles.api_key',
};

function userStatusVariant(user: UserAccount, t: TFn): { variant: StatusVariant; label: string } {
  if (!user.is_active) return { variant: 'disabled', label: t('UsersPage.status.inactive') };
  if (!user.is_verified) return { variant: 'pending', label: t('UsersPage.status.pending') };
  return { variant: 'success', label: t('UsersPage.status.active') };
}

function formatRelativeTime(timestamp: string | null, t: TFn): string {
  if (!timestamp) return t('UsersPage.time.never');
  const date = new Date(timestamp);
  const diff = Date.now() - date.getTime();
  const minutes = Math.floor(diff / 60000);
  const hours = Math.floor(diff / 3600000);
  const days = Math.floor(diff / 86400000);
  if (minutes < 1) return t('UsersPage.time.justNow');
  if (minutes < 60) return t('UsersPage.time.minutesAgo', { n: minutes });
  if (hours < 24) return t('UsersPage.time.hoursAgo', { n: hours });
  if (days < 7) return t('UsersPage.time.daysAgo', { n: days });
  return date.toLocaleDateString();
}

/* ============================================================
   Site Access Dialog (kept inline)
   ============================================================ */

function SiteAccessDialog({
  user,
  orgId,
  open,
  onOpenChange,
}: {
  user: UserAccount;
  orgId: string | null;
  open: boolean;
  onOpenChange: (v: boolean) => void;
}) {
  const { t } = useTranslation('users');
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [initialised, setInitialised] = useState(false);

  const {
    data: allSites = [],
    isError: sitesError,
    error: sitesErrorObj,
    refetch: refetchSites,
  } = useQuery<{ id: string; name: string; slug: string }[]>({
    queryKey: ['sites-for-access', orgId ?? user.organization_id],
    queryFn: async () => {
      // GET /sites/ caps per_page at 100, requesting more returns 422 and the
      // dialog silently renders zero sites. The dialog only needs this org's
      // sites, so 100 is both the max and sufficient. (If an org ever exceeds
      // 100 sites this would need pagination, but that's beyond current scope.)
      const params: Record<string, any> = { per_page: 100 };
      if (user.organization_id) params.organization_id = user.organization_id;
      const r = await sitesApi.getAll(params as any);
      return (r.data.items ?? []).map((s: any) => ({ id: s.id, name: s.name, slug: s.slug }));
    },
    enabled: open,
  });

  const {
    data: currentAccess = [],
    isError: accessError,
    error: accessErrorObj,
    refetch: refetchAccess,
  } = useQuery<{ id: string; site_id: string }[]>({
    queryKey: ['user-site-access', user.id],
    queryFn: async () => {
      const targetOrgId = user.organization_id || orgId;
      if (!targetOrgId) return [];
      const r = await api.get(`/organizations/${targetOrgId}/site-access`, {
        params: { user_id: user.id },
      });
      return r.data;
    },
    enabled: open,
  });

  const loadError = sitesError || accessError;
  const loadErrorObj = sitesErrorObj || accessErrorObj;

  if (open && currentAccess.length > 0 && !initialised) {
    setSelected(new Set(currentAccess.map((a) => a.site_id)));
    setInitialised(true);
  }
  if (open && currentAccess.length === 0 && allSites.length > 0 && !initialised) {
    setInitialised(true);
  }

  const handleOpenChange = (v: boolean) => {
    if (!v) setInitialised(false);
    onOpenChange(v);
  };

  const toggle = (siteId: string) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(siteId)) next.delete(siteId);
      else next.add(siteId);
      return next;
    });
  };

  const selectAll = () => setSelected(new Set(allSites.map((s) => s.id)));
  const selectNone = () => setSelected(new Set());

  const saveMutation = useMutation({
    mutationFn: async () => {
      const targetOrgId = user.organization_id || orgId;
      if (!targetOrgId) return;
      await api.put(`/organizations/${targetOrgId}/site-access/bulk`, {
        user_id: user.id,
        site_ids: Array.from(selected),
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['user-site-access', user.id] });
      handleOpenChange(false);
    },
    onError: (err: any) => {
      toast({ title: t('UsersPage.toast.errorTitle'), description: err?.response?.data?.detail || t('UsersPage.siteAccess.saveError'), variant: 'destructive' });
    },
  });

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogContent className="sm:max-w-[480px]">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <MapPin className="h-4 w-4" />
            {t('UsersPage.siteAccess.title', { name: user.full_name || user.username })}
          </DialogTitle>
          <DialogDescription>
            {user.role === 'org_admin' || user.role === 'super_admin'
              ? t('UsersPage.siteAccess.adminDescription')
              : t('UsersPage.siteAccess.userDescription')}
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-3 max-h-[320px] overflow-y-auto py-2">
          {loadError ? (
            <ErrorState
              message={
                loadErrorObj instanceof Error
                  ? loadErrorObj.message
                  : t('UsersPage.siteAccess.loadError')
              }
              onRetry={() => {
                if (sitesError) refetchSites();
                if (accessError) refetchAccess();
              }}
            />
          ) : allSites.length === 0 ? (
            <p className="py-4 text-center text-sm text-muted-foreground">
              {t('UsersPage.siteAccess.noSites')}
            </p>
          ) : (
            <>
              <div className="flex items-center justify-between px-1">
                <span className="text-xs text-muted-foreground">
                  {t('UsersPage.siteAccess.selectedCount', { selected: selected.size, total: allSites.length })}
                </span>
                <div className="flex gap-2">
                  <Button variant="link" size="sm" className="h-auto p-0 text-xs" onClick={selectAll}>
                    {t('UsersPage.siteAccess.selectAll')}
                  </Button>
                  <Button variant="link" size="sm" className="h-auto p-0 text-xs" onClick={selectNone}>
                    {t('UsersPage.siteAccess.clear')}
                  </Button>
                </div>
              </div>
              {allSites.map((site) => (
                <label
                  key={site.id}
                  className="flex items-center gap-3 rounded-md border px-3 py-2 cursor-pointer hover:bg-muted/30 transition-colors"
                >
                  <Checkbox
                    checked={selected.has(site.id)}
                    onCheckedChange={() => toggle(site.id)}
                  />
                  <div>
                    <div className="text-sm font-medium">{site.name}</div>
                    <div className="text-xs text-muted-foreground">{site.slug}</div>
                  </div>
                </label>
              ))}
            </>
          )}
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => handleOpenChange(false)}>
            {t('UsersPage.siteAccess.cancel')}
          </Button>
          <Button
            onClick={() => saveMutation.mutate()}
            disabled={saveMutation.isPending || loadError}
          >
            {saveMutation.isPending ? t('UsersPage.siteAccess.saving') : t('UsersPage.siteAccess.save')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

/* ============================================================
   Add User Dialog
   ============================================================ */

// FE mirror of backend ROLE_HIERARCHY (core/dependencies.py). Callers may only
// assign roles strictly below their own level, anything at or above is rejected
// server-side, so we hide those options entirely.
const ROLE_LEVELS: Record<string, number> = {
  super_admin: 100,
  admin: 80,
  org_admin: 60,
  site_admin: 40,
  operator: 20,
  viewer: 10,
  guest: 0,
};

// Roles offered in the Add User dialog, highest → lowest. We never offer
// super_admin (backend always rejects assigning it), and filter the rest to
// those strictly below the current user's level.
const ASSIGNABLE_ROLES = ['org_admin', 'operator', 'viewer'] as const;

const buildAddUserSchema = (t: TFn) =>
  z.object({
    email: z.string().trim().email(t('UsersPage.addUser.validation.email')),
    username: z.string().trim().min(3, t('UsersPage.addUser.validation.username')),
    full_name: z.string(),
    role: z.enum(['super_admin', 'org_admin', 'operator', 'viewer']),
    password: z.string().min(12, t('UsersPage.addUser.validation.password')),
  });
type AddUserFormValues = z.infer<ReturnType<typeof buildAddUserSchema>>;

function AddUserDialog({
  open,
  onOpenChange,
  onAdd,
  assignableRoles,
  showOrgSelector,
  organizations,
}: {
  open: boolean;
  onOpenChange: (v: boolean) => void;
  onAdd: (user: AddUserFormValues & { organization_id?: string }) => Promise<unknown> | unknown;
  assignableRoles: readonly string[];
  showOrgSelector: boolean;
  organizations: { id: string; name: string }[];
}) {
  const { t } = useTranslation('users');
  const { t: tc } = useTranslation('common');
  const addUserSchema = buildAddUserSchema(t);
  const [orgId, setOrgId] = useState<string>('');
  // Default role = the lowest-privilege assignable role (last in the list).
  const defaultRole = (assignableRoles[assignableRoles.length - 1] ?? 'viewer') as AddUserFormValues['role'];
  return (
    <FormDialog<AddUserFormValues>
      open={open}
      onOpenChange={(v) => {
        if (!v) setOrgId('');
        onOpenChange(v);
      }}
      title={t('UsersPage.addUser.title')}
      description={t('UsersPage.addUser.description')}
      schema={addUserSchema}
      defaultValues={{ email: '', username: '', full_name: '', role: defaultRole, password: '' }}
      submitLabel={t('UsersPage.addUser.submit')}
      onSubmit={async (values) => {
        await onAdd(showOrgSelector ? { ...values, organization_id: orgId || undefined } : values);
      }}
    >
      {(form) => (
        <>
          <FormField
            control={form.control}
            name="email"
            render={({ field }) => (
              <FormItem>
                <FormLabel>{t('UsersPage.addUser.fields.email')}</FormLabel>
                <FormControl>
                  <Input type="email" placeholder="user@example.com" {...field} />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
          <FormField
            control={form.control}
            name="username"
            render={({ field }) => (
              <FormItem>
                <FormLabel>{t('UsersPage.addUser.fields.username')}</FormLabel>
                <FormControl>
                  <Input placeholder="johndoe" autoComplete="off" {...field} />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
          <FormField
            control={form.control}
            name="full_name"
            render={({ field }) => (
              <FormItem>
                <FormLabel>{t('UsersPage.addUser.fields.fullName')}</FormLabel>
                <FormControl>
                  <Input placeholder="John Doe" {...field} />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
          <FormField
            control={form.control}
            name="password"
            render={({ field }) => (
              <FormItem>
                <FormLabel>{t('UsersPage.addUser.fields.password')}</FormLabel>
                <FormControl>
                  <Input
                    type="password"
                    placeholder={t('UsersPage.addUser.fields.passwordPlaceholder')}
                    autoComplete="new-password"
                    {...field}
                  />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
          <FormField
            control={form.control}
            name="role"
            render={({ field }) => (
              <FormItem>
                <FormLabel>{t('UsersPage.addUser.fields.role')}</FormLabel>
                <Select value={field.value} onValueChange={field.onChange}>
                  <FormControl>
                    <SelectTrigger>
                      <SelectValue placeholder={t('UsersPage.addUser.fields.rolePlaceholder')} />
                    </SelectTrigger>
                  </FormControl>
                  <SelectContent>
                    {assignableRoles.map((r) => (
                      <SelectItem key={r} value={r}>
                        {t(`UsersPage.addUser.roleOptions.${r}`)}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <FormMessage />
              </FormItem>
            )}
          />
          {showOrgSelector && (
            <FormItem>
              <FormLabel>{tc('profile.organization')}</FormLabel>
              <Select value={orgId} onValueChange={setOrgId}>
                <FormControl>
                  <SelectTrigger>
                    <SelectValue placeholder={tc('profile.organization')} />
                  </SelectTrigger>
                </FormControl>
                <SelectContent>
                  {organizations.map((o) => (
                    <SelectItem key={o.id} value={o.id}>
                      {o.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </FormItem>
          )}
        </>
      )}
    </FormDialog>
  );
}

/* ============================================================
   Edit User Dialog
   ============================================================ */

const buildEditUserSchema = (t: TFn) =>
  z.object({
    email: z.string().trim().email(t('UsersPage.addUser.validation.email')),
    username: z.string().trim().min(3, t('UsersPage.addUser.validation.username')),
    full_name: z.string(),
    role: z.enum(['super_admin', 'admin', 'org_admin', 'site_admin', 'operator', 'viewer']),
    is_active: z.boolean(),
  });
type EditUserFormValues = z.infer<ReturnType<typeof buildEditUserSchema>>;

function EditUserDialog({
  user,
  open,
  onOpenChange,
  onSave,
  assignableRoles,
}: {
  user: UserAccount;
  open: boolean;
  onOpenChange: (v: boolean) => void;
  onSave: (id: string, values: UserUpdatePayload) => Promise<unknown>;
  assignableRoles: readonly string[];
}) {
  const { t } = useTranslation('users');
  const editUserSchema = buildEditUserSchema(t);
  // Show the user's current role even if it isn't in the assignable set (so we
  // never silently change it on save), plus the roles the caller may assign.
  const roleOptions = Array.from(new Set([user.role, ...assignableRoles]));
  return (
    <FormDialog<EditUserFormValues>
      open={open}
      onOpenChange={onOpenChange}
      title={t('UsersPage.actions.edit')}
      description={t('UsersPage.header.description')}
      schema={editUserSchema}
      defaultValues={{
        email: user.email,
        username: user.username,
        full_name: user.full_name ?? '',
        role: user.role as EditUserFormValues['role'],
        is_active: user.is_active,
      }}
      submitLabel={t('UsersPage.siteAccess.save')}
      onSubmit={async (values) => {
        await onSave(user.id, values);
      }}
    >
      {(form) => (
        <>
          <FormField
            control={form.control}
            name="email"
            render={({ field }) => (
              <FormItem>
                <FormLabel>{t('UsersPage.addUser.fields.email')}</FormLabel>
                <FormControl>
                  <Input type="email" placeholder="user@example.com" {...field} />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
          <FormField
            control={form.control}
            name="username"
            render={({ field }) => (
              <FormItem>
                <FormLabel>{t('UsersPage.addUser.fields.username')}</FormLabel>
                <FormControl>
                  <Input placeholder="johndoe" autoComplete="off" {...field} />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
          <FormField
            control={form.control}
            name="full_name"
            render={({ field }) => (
              <FormItem>
                <FormLabel>{t('UsersPage.addUser.fields.fullName')}</FormLabel>
                <FormControl>
                  <Input placeholder="John Doe" {...field} />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
          <FormField
            control={form.control}
            name="role"
            render={({ field }) => (
              <FormItem>
                <FormLabel>{t('UsersPage.addUser.fields.role')}</FormLabel>
                <Select value={field.value} onValueChange={field.onChange}>
                  <FormControl>
                    <SelectTrigger>
                      <SelectValue placeholder={t('UsersPage.addUser.fields.rolePlaceholder')} />
                    </SelectTrigger>
                  </FormControl>
                  <SelectContent>
                    {roleOptions.map((r) => (
                      <SelectItem key={r} value={r}>
                        {ROLE_LABEL_KEYS[r] ? t(`UsersPage.${ROLE_LABEL_KEYS[r]}`) : r}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <FormMessage />
              </FormItem>
            )}
          />
          <FormField
            control={form.control}
            name="is_active"
            render={({ field }) => (
              <FormItem className="flex flex-row items-center gap-3 space-y-0">
                <FormControl>
                  <Checkbox checked={field.value} onCheckedChange={field.onChange} />
                </FormControl>
                <FormLabel className="!mt-0">{t('UsersPage.status.active')}</FormLabel>
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

export function UsersPage() {
  const { t } = useTranslation('users');
  const { t: tc } = useTranslation('common');
  const [searchQuery, setSearchQuery] = useState('');
  const [roleFilter, setRoleFilter] = useState<string>('all');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [siteAccessUser, setSiteAccessUser] = useState<UserAccount | null>(null);
  const [editUser, setEditUser] = useState<UserAccount | null>(null);
  const [addOpen, setAddOpen] = useState(false);
  const [selectedUsers, setSelectedUsers] = useState<UserAccount[]>([]);
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const { user: currentUser } = useAuthStore();

  const isSuperAdmin = currentUser?.role === 'super_admin';

  // Roles a caller may assign: strictly below the caller's own level, and never
  // super_admin (the backend always rejects assigning it, see
  // validate_role_assignment in core/dependencies.py).
  const callerLevel = ROLE_LEVELS[currentUser?.role ?? ''] ?? 0;
  const assignableRoles = ASSIGNABLE_ROLES.filter((r) => ROLE_LEVELS[r] < callerLevel);

  // Fetch users
  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ['users'],
    queryFn: async () => {
      const res = await usersApi.list({ page: 1, per_page: 100 });
      return res.data;
    },
  });

  // Org list (super_admin only, needed to pick the target org when creating).
  const { data: organizations = [] } = useQuery<{ id: string; name: string }[]>({
    queryKey: ['organizations-for-user-create'],
    queryFn: async () => {
      const r = await api.get('/organizations', { params: { per_page: 200 } });
      const items = Array.isArray(r.data) ? r.data : (r.data.items ?? []);
      return items.map((o: any) => ({ id: o.id, name: o.name }));
    },
    enabled: isSuperAdmin && addOpen,
  });

  const users: UserAccount[] = data?.items ?? [];

  // Mutations
  const createMutation = useMutation({
    mutationFn: (payload: { email: string; username: string; full_name: string; role: string; password: string; organization_id?: string }) =>
      usersApi.create(payload),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] });
      setAddOpen(false);
    },
    onError: (err: any) => {
      toast({ title: t('UsersPage.toast.errorTitle'), description: err?.response?.data?.detail || t('UsersPage.toast.createError'), variant: 'destructive' });
    },
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, values }: { id: string; values: UserUpdatePayload }) =>
      usersApi.update(id, values),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] });
      setEditUser(null);
    },
    onError: (err: any) => {
      toast({ title: t('UsersPage.toast.errorTitle'), description: err?.response?.data?.detail || t('UsersPage.toast.updateError'), variant: 'destructive' });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => usersApi.delete(id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['users'] }),
    onError: (err: any) => {
      toast({ title: t('UsersPage.toast.errorTitle'), description: err?.response?.data?.detail || t('UsersPage.toast.deleteError'), variant: 'destructive' });
    },
  });

  const toggleActiveMutation = useMutation({
    mutationFn: ({ id, is_active }: { id: string; is_active: boolean }) =>
      usersApi.update(id, { is_active }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['users'] }),
    onError: (err: any) => {
      toast({ title: t('UsersPage.toast.errorTitle'), description: err?.response?.data?.detail || t('UsersPage.toast.updateError'), variant: 'destructive' });
    },
  });

  // Filter
  const filteredUsers = users.filter((u) => {
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      const matches =
        (u.full_name ?? '').toLowerCase().includes(q) ||
        u.username.toLowerCase().includes(q) ||
        u.email.toLowerCase().includes(q);
      if (!matches) return false;
    }
    if (roleFilter !== 'all' && u.role !== roleFilter) return false;
    if (statusFilter === 'active' && !u.is_active) return false;
    if (statusFilter === 'inactive' && u.is_active) return false;
    if (statusFilter === 'pending' && (u.is_verified || !u.is_active)) return false;
    return true;
  });

  // Stats
  const stats = {
    total: users.length,
    active: users.filter((u) => u.is_active).length,
    admins: users.filter((u) => u.role === 'super_admin' || u.role === 'org_admin').length,
    mfaEnabled: users.filter((u) => u.mfa_enabled).length,
  };

  const hasActiveFilters = searchQuery !== '' || roleFilter !== 'all' || statusFilter !== 'all';
  const handleClearFilters = () => {
    setSearchQuery('');
    setRoleFilter('all');
    setStatusFilter('all');
  };

  // Client-side CSV export of the currently-filtered rows (no backend needed,
  // the rows are already loaded in memory).
  const handleExport = () => {
    const rows = filteredUsers;
    const headers = ['username', 'email', 'full_name', 'role', 'is_active', 'is_verified', 'mfa_enabled', 'last_login'];
    const esc = (v: unknown) => {
      const s = v === null || v === undefined ? '' : String(v);
      return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
    };
    const lines = [
      headers.join(','),
      ...rows.map((u) =>
        [u.username, u.email, u.full_name ?? '', u.role, u.is_active, u.is_verified, u.mfa_enabled, u.last_login ?? '']
          .map(esc)
          .join(','),
      ),
    ];
    const blob = new Blob([lines.join('\n')], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `users-${new Date().toISOString().slice(0, 10)}.csv`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  // Bulk disable: loop the per-row update mutation, then a single summary toast.
  const handleBulkDisable = async () => {
    const targets = selectedUsers.filter((u) => u.is_active);
    if (targets.length === 0) {
      setSelectedUsers([]);
      return;
    }
    const results = await Promise.allSettled(
      targets.map((u) => usersApi.update(u.id, { is_active: false })),
    );
    const ok = results.filter((r) => r.status === 'fulfilled').length;
    const failed = results.length - ok;
    queryClient.invalidateQueries({ queryKey: ['users'] });
    setSelectedUsers([]);
    toast({
      title: t('UsersPage.bulk.disableTitle'),
      description: `${tc('BatchProgressDialog.stats.success', { count: ok })} · ${tc('BatchProgressDialog.stats.failed', { count: failed })}`,
      variant: failed > 0 ? 'destructive' : undefined,
    });
  };

  // Bulk delete: gated behind a confirm (matches the per-row delete convention).
  const handleBulkDelete = async () => {
    if (selectedUsers.length === 0) return;
    if (!confirm(t('UsersPage.actions.deleteConfirm', { name: t('UsersPage.itemNamePlural') }))) return;
    const results = await Promise.allSettled(selectedUsers.map((u) => usersApi.delete(u.id)));
    const ok = results.filter((r) => r.status === 'fulfilled').length;
    const failed = results.length - ok;
    queryClient.invalidateQueries({ queryKey: ['users'] });
    setSelectedUsers([]);
    toast({
      title: t('UsersPage.bulk.deleteTitle'),
      description: `${tc('BatchProgressDialog.stats.success', { count: ok })} · ${tc('BatchProgressDialog.stats.failed', { count: failed })}`,
      variant: failed > 0 ? 'destructive' : undefined,
    });
  };

  // Columns
  const columns: DataTableColumn<UserAccount>[] = [
    {
      id: 'user',
      header: t('UsersPage.columns.user'),
      accessorFn: (u) => u.full_name ?? u.username,
      cell: (u) => (
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-full bg-primary/10 flex-shrink-0">
            <User className="h-5 w-5 text-primary" />
          </div>
          <div className="min-w-0">
            <div className="font-medium truncate">{u.full_name || u.username}</div>
            <div className="text-sm text-muted-foreground truncate">{u.email}</div>
          </div>
        </div>
      ),
    },
    {
      id: 'role',
      header: t('UsersPage.columns.role'),
      accessorKey: 'role',
      cell: (u) => (
        <span className="inline-flex items-center gap-1 text-sm">
          <Shield className="h-3.5 w-3.5 text-muted-foreground" />
          {ROLE_LABEL_KEYS[u.role] ? t(`UsersPage.${ROLE_LABEL_KEYS[u.role]}`) : u.role}
        </span>
      ),
    },
    {
      id: 'status',
      header: t('UsersPage.columns.status'),
      accessorFn: (u) => userStatusVariant(u, t).label,
      cell: (u) => {
        const { variant, label } = userStatusVariant(u, t);
        return <StatusBadge variant={variant}>{label}</StatusBadge>;
      },
    },
    {
      id: 'mfa',
      header: t('UsersPage.columns.mfa'),
      accessorFn: (u) => (u.mfa_enabled ? 'enabled' : 'disabled'),
      cell: (u) => (
        <span
          className={cn(
            'inline-flex items-center gap-1 text-sm',
            u.mfa_enabled ? 'text-success' : 'text-muted-foreground',
          )}
        >
          <Key className="h-4 w-4" />
          {u.mfa_enabled ? t('UsersPage.mfa.enabled') : t('UsersPage.mfa.disabled')}
        </span>
      ),
    },
    {
      id: 'last_login',
      header: t('UsersPage.columns.lastLogin'),
      accessorFn: (u) => u.last_login ?? '',
      cell: (u) => (
        <span className="text-sm text-muted-foreground">
          {formatRelativeTime(u.last_login, t)}
        </span>
      ),
    },
    {
      id: 'actions',
      header: '',
      sortable: false,
      cell: (u) => (
        <div className="flex justify-end" onClick={(e) => e.stopPropagation()}>
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" size="icon" className="h-8 w-8" aria-label={t('UsersPage.actions.menuLabel', { name: u.username })}>
                <MoreHorizontal className="h-4 w-4" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuItem onClick={() => setEditUser(u)}>
                <Edit className="mr-2 h-4 w-4" />
                {t('UsersPage.actions.edit')}
              </DropdownMenuItem>
              <DropdownMenuItem onClick={() => setSiteAccessUser(u)}>
                <MapPin className="mr-2 h-4 w-4" />
                {t('UsersPage.actions.manageSiteAccess')}
              </DropdownMenuItem>
              {/* 'Send Password Reset' removed, there is no admin-trigger reset
                  endpoint (the only reset flow is the public self-service
                  /auth/password/reset-request, which an admin cannot invoke on a
                  user's behalf). Wiring it would fake an action that can't run. */}
              {!u.is_active ? (
                <DropdownMenuItem onClick={() => toggleActiveMutation.mutate({ id: u.id, is_active: true })}>
                  <Unlock className="mr-2 h-4 w-4" />
                  {t('UsersPage.actions.enableAccount')}
                </DropdownMenuItem>
              ) : (
                <DropdownMenuItem onClick={() => toggleActiveMutation.mutate({ id: u.id, is_active: false })}>
                  <Lock className="mr-2 h-4 w-4" />
                  {t('UsersPage.actions.disableAccount')}
                </DropdownMenuItem>
              )}
              <DropdownMenuSeparator />
              <DropdownMenuItem
                className="text-destructive focus:text-destructive"
                onClick={() => {
                  if (confirm(t('UsersPage.actions.deleteConfirm', { name: u.username || u.email }))) {
                    deleteMutation.mutate(u.id);
                  }
                }}
              >
                <Trash2 className="mr-2 h-4 w-4" />
                {t('UsersPage.actions.delete')}
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      ),
    },
  ];

  if (error) {
    return (
      <div className="space-y-6">
        <PageHeader
          icon={Users}
          title={t('UsersPage.header.title')}
          description={t('UsersPage.header.description')}
        />
        <ErrorState
          message={error instanceof Error ? error.message : t('UsersPage.loadError')}
          onRetry={() => refetch()}
        />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <PageHeader
        icon={Users}
        title={t('UsersPage.header.title')}
        description={t('UsersPage.header.description')}
        onRefresh={() => refetch()}
        refreshing={isLoading}
        secondaryActions={[
          { label: t('UsersPage.header.export'), icon: Download, onClick: handleExport },
        ]}
        primaryAction={{
          label: t('UsersPage.header.addUser'),
          icon: UserPlus,
          onClick: () => setAddOpen(true),
        }}
      />

      {/* Stats */}
      <StatsGrid
        columns={4}
        isLoading={isLoading}
        stats={[
          {
            title: t('UsersPage.stats.totalUsers'),
            value: stats.total,
            icon: Users,
            variant: 'default',
            description: t('UsersPage.stats.registeredAccounts'),
          },
          {
            title: t('UsersPage.stats.active'),
            value: stats.active,
            icon: CheckCircle,
            variant: 'success',
            description:
              stats.total > 0
                ? t('UsersPage.stats.percentActive', { percent: Math.round((stats.active / stats.total) * 100) })
                : t('UsersPage.stats.noUsers'),
          },
          {
            title: t('UsersPage.stats.administrators'),
            value: stats.admins,
            icon: Shield,
            variant: 'info',
            description: t('UsersPage.stats.orgSuperAdmins'),
          },
          {
            title: t('UsersPage.stats.mfaEnabled'),
            value: stats.mfaEnabled,
            icon: Key,
            variant: 'success',
            description:
              stats.total > 0
                ? t('UsersPage.stats.percentSecured', { percent: Math.round((stats.mfaEnabled / stats.total) * 100) })
                : t('UsersPage.stats.noUsers'),
          },
        ]}
      />

      {/* Toolbar */}
      <PageToolbar>
        <SearchBar
          value={searchQuery}
          onChange={setSearchQuery}
          placeholder={t('UsersPage.toolbar.searchPlaceholder')}
          className="w-full sm:w-auto"
        />
        <Select value={roleFilter} onValueChange={setRoleFilter}>
          <SelectTrigger className="w-full sm:w-[160px]">
            <SelectValue placeholder={t('UsersPage.toolbar.allRoles')} />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">{t('UsersPage.toolbar.allRoles')}</SelectItem>
            <SelectItem value="super_admin">{t('UsersPage.roles.super_admin')}</SelectItem>
            <SelectItem value="org_admin">{t('UsersPage.roles.org_admin')}</SelectItem>
            <SelectItem value="operator">{t('UsersPage.roles.operator')}</SelectItem>
            <SelectItem value="viewer">{t('UsersPage.roles.viewer')}</SelectItem>
          </SelectContent>
        </Select>
        <Select value={statusFilter} onValueChange={setStatusFilter}>
          <SelectTrigger className="w-full sm:w-[160px]">
            <SelectValue placeholder={t('UsersPage.toolbar.allStatuses')} />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">{t('UsersPage.toolbar.allStatuses')}</SelectItem>
            <SelectItem value="active">{t('UsersPage.status.active')}</SelectItem>
            <SelectItem value="pending">{t('UsersPage.status.pending')}</SelectItem>
            <SelectItem value="inactive">{t('UsersPage.status.inactive')}</SelectItem>
          </SelectContent>
        </Select>
        {hasActiveFilters && (
          <Button variant="ghost" size="sm" onClick={handleClearFilters}>
            {t('UsersPage.toolbar.clearFilters')}
          </Button>
        )}
      </PageToolbar>

      {/* Table */}
      <DataTable
        data={filteredUsers}
        columns={columns}
        isLoading={isLoading}
        selectable
        onSelectionChange={setSelectedUsers}
        searchable={false}
        itemName={t('UsersPage.itemNamePlural')}
        getRowId={(u) => u.id}
      />

      {/* Bulk actions */}
      <BulkActionsBar
        selectedCount={selectedUsers.length}
        itemName={t('UsersPage.itemNameSingular')}
        onClear={() => setSelectedUsers([])}
        actions={[
          // 'Send Invite' removed, there is no invite endpoint to back it.
          {
            label: t('UsersPage.bulk.disable'),
            icon: XCircle,
            onClick: handleBulkDisable,
          },
          {
            label: t('UsersPage.bulk.delete'),
            icon: Trash2,
            variant: 'destructive',
            onClick: handleBulkDelete,
          },
        ]}
      />

      {/* Add User Dialog */}
      <AddUserDialog
        open={addOpen}
        onOpenChange={setAddOpen}
        assignableRoles={assignableRoles}
        showOrgSelector={isSuperAdmin}
        organizations={organizations}
        onAdd={(d) =>
          createMutation.mutateAsync({
            ...d,
            // org_admins (and other non-super callers) can only create users in
            // their own org, the backend 403s otherwise, so default it here.
            organization_id: isSuperAdmin
              ? d.organization_id
              : (currentUser?.organization_id ?? undefined),
          })
        }
      />

      {/* Edit User Dialog */}
      {editUser && (
        <EditUserDialog
          user={editUser}
          open
          onOpenChange={(v) => !v && setEditUser(null)}
          assignableRoles={assignableRoles}
          onSave={(id, values) => updateMutation.mutateAsync({ id, values })}
        />
      )}

      {/* Site Access Dialog */}
      {siteAccessUser && (
        <SiteAccessDialog
          user={siteAccessUser}
          orgId={currentUser?.organization_id ?? null}
          open
          onOpenChange={(v) => !v && setSiteAccessUser(null)}
        />
      )}
    </div>
  );
}

export default UsersPage;

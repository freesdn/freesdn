// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN · Credentials Vault Page
 *
 * Canonical list-page pattern.
 *
 * Dialogs are built on the canonical FormDialog primitive:
 *   - <CredentialFormDialog mode="create" />  · fresh credential, all fields required by type
 *   - <CredentialFormDialog mode="edit" />    · prefilled from existingCredential, secrets optional
 *   - <TestCredentialDialog />                · one-field dialog (target host)
 */

import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { z } from 'zod';
import {
  Key,
  Plus,
  MoreHorizontal,
  Trash2,
  Edit,
  CheckCircle,
  Loader2,
  Shield,
  Eye,
  EyeOff,
  Server,
  Download,
  TestTube,
} from 'lucide-react';
import { PageHeader, PageToolbar } from '@/components/layout';
import { DataTable, type DataTableColumn } from '@/components/ui/data-table';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { SearchBar } from '@/components/ui/search-bar';
import { StatsGrid } from '@/components/ui/stats-grid';
import { BulkActionsBar } from '@/components/ui/bulk-actions-bar';
import { ErrorState } from '@/components/ui/empty-state';
import { FormDialog } from '@/components/ui/form-dialog';
import { FormControl, FormField, FormItem, FormLabel, FormMessage, FormDescription } from '@/components/ui/form';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
  DropdownMenuSeparator,
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
import { Textarea } from '@/components/ui/textarea';
import { credentialsApi, getApiErrorMessage, type Credential, type CreateCredentialRequest } from '@/lib/api';
import { useNotificationsStore } from '@/stores';

// Mirrors backend CredentialType (app/models/core.py): every value the API
// can return must have a label + render branch here, otherwise the edit
// dialog shows a raw enum and blank secret fields.
type CredentialType =
  | 'basic_auth'
  | 'username_password'
  | 'api_key'
  | 'ssh_key'
  | 'token'
  | 'certificate'
  | 'snmp_community';

const CREDENTIAL_TYPES: readonly CredentialType[] = [
  'username_password',
  'basic_auth',
  'api_key',
  'token',
  'ssh_key',
  'certificate',
  'snmp_community',
];

type TFunc = (key: string, options?: Record<string, unknown>) => string;

const buildTypeLabels = (t: TFunc): Record<string, string> => ({
  basic_auth: t('CredentialsPage.types.basic_auth'),
  username_password: t('CredentialsPage.types.username_password'),
  api_key: t('CredentialsPage.types.api_key'),
  ssh_key: t('CredentialsPage.types.ssh_key'),
  token: t('CredentialsPage.types.token'),
  certificate: t('CredentialsPage.types.certificate'),
  snmp_community: t('CredentialsPage.types.snmp_community'),
});

function getTypeIcon(type: string) {
  switch (type) {
    case 'ssh_key':
      return Server;
    case 'api_key':
    case 'token':
    case 'certificate':
      return Shield;
    case 'snmp_community':
      return Server;
    default:
      return Key;
  }
}

// ─── Shared form schema ────────────────────────────────────────────────────
//
// Single schema covers Create + Edit. Use `superRefine` parameterized by
// `mode` to make secret fields required in create mode and optional in edit
// mode (where empty = "keep existing value").

const baseCredentialSchema = z.object({
  name: z.string().min(1, 'Name is required'),
  type: z.enum([
    'basic_auth',
    'username_password',
    'api_key',
    'ssh_key',
    'token',
    'certificate',
    'snmp_community',
  ]),
  username: z.string(),
  password: z.string(),
  api_key: z.string(),
  ssh_key: z.string(),
  token: z.string(),
  certificate: z.string(),
  snmp_community: z.string(),
  description: z.string(),
});

type CredentialFormValues = z.infer<typeof baseCredentialSchema>;

const credentialSchemaForMode = (mode: 'create' | 'edit') =>
  baseCredentialSchema.superRefine((data, ctx) => {
    if (mode === 'edit') return; // edit: secrets optional
    switch (data.type) {
      // basic_auth and username_password both carry username + password.
      case 'basic_auth':
      case 'username_password':
        if (!data.username.trim()) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['username'], message: 'Username is required' });
        if (!data.password) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['password'], message: 'Password is required' });
        break;
      case 'api_key':
        if (!data.api_key) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['api_key'], message: 'API key is required' });
        break;
      case 'ssh_key':
        if (!data.username.trim()) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['username'], message: 'Username is required' });
        if (!data.ssh_key) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['ssh_key'], message: 'Private key is required' });
        break;
      case 'token':
        if (!data.token) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['token'], message: 'Token is required' });
        break;
      case 'certificate':
        if (!data.certificate) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['certificate'], message: 'Certificate is required' });
        break;
      case 'snmp_community':
        if (!data.snmp_community) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['snmp_community'], message: 'SNMP community string is required' });
        break;
    }
  });

const emptyDefaults: CredentialFormValues = {
  name: '',
  type: 'username_password',
  username: '',
  password: '',
  api_key: '',
  ssh_key: '',
  token: '',
  certificate: '',
  snmp_community: '',
  description: '',
};

/** Build the API payload from form values. In edit mode, omit empty secret fields. */
function toApiPayload(values: CredentialFormValues, mode: 'create' | 'edit'): Partial<CreateCredentialRequest> {
  const data: Partial<CreateCredentialRequest> = {
    name: values.name,
    description: values.description || undefined,
  };
  if (mode === 'create') {
    // Backend field is ``credential_type``, not ``type``. Sending
    // ``type`` made the row default to ``basic_auth`` regardless of
    // the user's selection, every api_key / ssh_key / token
    // credential was mis-classified.
    data.credential_type = values.type;
  }
  switch (values.type) {
    // basic_auth and username_password are both username+password creds.
    case 'basic_auth':
    case 'username_password':
      if (mode === 'create' || values.username) data.username = values.username;
      if (mode === 'create' || values.password) data.password = values.password;
      break;
    case 'api_key':
      if (mode === 'create' || values.api_key) data.api_key = values.api_key;
      break;
    case 'ssh_key':
      if (mode === 'create' || values.username) data.username = values.username;
      // Backend column is ``ssh_private_key``; sending ``ssh_key``
      // was silently dropped, leaving SSH-key credentials with no
      // actual key material in the DB.
      if (mode === 'create' || values.ssh_key) data.ssh_private_key = values.ssh_key;
      break;
    case 'token':
      if (mode === 'create' || values.token) data.token = values.token;
      break;
    case 'certificate':
      if (mode === 'create' || values.certificate) data.certificate = values.certificate;
      break;
    case 'snmp_community':
      // ``snmp_community`` is accepted by the backend CredentialCreate/Update
      // schema but not yet declared on the lib/api request type, widen here.
      if (mode === 'create' || values.snmp_community) {
        (data as Record<string, unknown>).snmp_community = values.snmp_community;
      }
      break;
  }
  return data;
}

export default function CredentialsPage() {
  const { t } = useTranslation('credentials');
  const queryClient = useQueryClient();
  const { addNotification } = useNotificationsStore();
  const TYPE_LABELS = buildTypeLabels(t);

  const [searchQuery, setSearchQuery] = useState('');
  const [typeFilter, setTypeFilter] = useState<string>('all');
  const [createDialogOpen, setCreateDialogOpen] = useState(false);
  const [editDialogOpen, setEditDialogOpen] = useState(false);
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [bulkDeleteOpen, setBulkDeleteOpen] = useState(false);
  const [bulkDeleting, setBulkDeleting] = useState(false);
  const [testDialogOpen, setTestDialogOpen] = useState(false);
  const [selectedCredential, setSelectedCredential] = useState<Credential | null>(null);
  const [selectedRows, setSelectedRows] = useState<Credential[]>([]);

  // Fetch credentials
  const {
    data: credentialsData,
    isLoading,
    error,
    refetch,
  } = useQuery({
    queryKey: ['credentials'],
    queryFn: async () => {
      const response = await credentialsApi.list();
      // Backend returns a bare array; the type field is `credential_type`.
      // Backfill `type` so the page's existing cred.type reads keep working.
      return (response.data ?? []).map((c) => ({ ...c, type: c.credential_type ?? c.type }));
    },
  });

  const credentials: Credential[] = credentialsData ?? [];

  // Mutations
  const createMutation = useMutation({
    mutationFn: async (data: CreateCredentialRequest) => {
      const response = await credentialsApi.create(data);
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['credentials'] });
      setCreateDialogOpen(false);
      addNotification({ type: 'success', title: t('CredentialsPage.notifications.created.title'), message: t('CredentialsPage.notifications.created.message') });
    },
    onError: () => {
      addNotification({ type: 'error', title: t('CredentialsPage.notifications.error.title'), message: t('CredentialsPage.notifications.createError') });
    },
  });

  const updateMutation = useMutation({
    mutationFn: async ({ id, data }: { id: string; data: Partial<CreateCredentialRequest> }) => {
      const response = await credentialsApi.update(id, data);
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['credentials'] });
      setEditDialogOpen(false);
      setSelectedCredential(null);
      addNotification({ type: 'success', title: t('CredentialsPage.notifications.updated.title'), message: t('CredentialsPage.notifications.updated.message') });
    },
    onError: () => {
      addNotification({ type: 'error', title: t('CredentialsPage.notifications.error.title'), message: t('CredentialsPage.notifications.updateError') });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: async (id: string) => {
      await credentialsApi.delete(id);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['credentials'] });
      setDeleteDialogOpen(false);
      setSelectedCredential(null);
      addNotification({ type: 'success', title: t('CredentialsPage.notifications.deleted.title'), message: t('CredentialsPage.notifications.deleted.message') });
    },
    onError: () => {
      addNotification({ type: 'error', title: t('CredentialsPage.notifications.error.title'), message: t('CredentialsPage.notifications.deleteError') });
    },
  });

  const testMutation = useMutation({
    mutationFn: async ({ id, targetHost }: { id: string; targetHost: string }) => {
      const response = await credentialsApi.test(id, targetHost);
      return response.data;
    },
    onSuccess: (data) => {
      if (data.success) {
        addNotification({ type: 'success', title: t('CredentialsPage.notifications.testSuccess.title'), message: t('CredentialsPage.notifications.testSuccess.message') });
      } else {
        // Backend returns the diagnostic under `message` (CredentialTestResponse).
        addNotification({ type: 'error', title: t('CredentialsPage.notifications.testFailed.title'), message: data.message || t('CredentialsPage.notifications.testFailed.message') });
      }
      setTestDialogOpen(false);
    },
    onError: (err) => {
      addNotification({
        type: 'error',
        title: t('CredentialsPage.notifications.testFailed.title'),
        message: getApiErrorMessage(err, t('CredentialsPage.notifications.testFailed.message')),
      });
      setTestDialogOpen(false);
    },
  });

  const handleEdit = (credential: Credential) => {
    setSelectedCredential(credential);
    setEditDialogOpen(true);
  };

  const handleDelete = (credential: Credential) => {
    setSelectedCredential(credential);
    setDeleteDialogOpen(true);
  };

  // ---- Export: client-side CSV of NON-secret metadata only ----------------
  const handleExport = () => {
    if (credentials.length === 0) return;
    const esc = (v: unknown) => {
      let s = v == null ? '' : String(v);
      // neutralize spreadsheet formula injection (=,+,-,@,tab,CR).
      if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
      return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
    };
    const headers = [
      t('CredentialsPage.columns.credential'),
      t('CredentialsPage.columns.type'),
      t('CredentialsPage.columns.username'),
      t('CredentialsPage.columns.devices'),
      t('CredentialsPage.columns.lastUsed'),
    ];
    const lines = credentials.map((c) =>
      [
        c.name,
        TYPE_LABELS[c.type] ?? c.type,
        c.username ?? '',
        c.devices_count ?? 0,
        c.last_used ?? '',
      ]
        .map(esc)
        .join(','),
    );
    const csv = [headers.map(esc).join(','), ...lines].join('\n');
    const blob = new Blob([`\uFEFF${csv}`], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `credentials-${new Date().toISOString().slice(0, 10)}.csv`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  // ---- Bulk delete: confirm + per-row deleteMutation + summary toast ------
  const handleBulkDelete = async () => {
    const targets = [...selectedRows];
    if (targets.length === 0) return;
    setBulkDeleting(true);
    const results = await Promise.allSettled(targets.map((c) => credentialsApi.delete(c.id)));
    setBulkDeleting(false);
    const ok = results.filter((r) => r.status === 'fulfilled').length;
    const failed = results.length - ok;
    queryClient.invalidateQueries({ queryKey: ['credentials'] });
    setBulkDeleteOpen(false);
    setSelectedRows([]);
    addNotification({
      type: failed === 0 ? 'success' : 'error',
      title: failed === 0
        ? t('CredentialsPage.notifications.deleted.title')
        : t('CredentialsPage.notifications.error.title'),
      message: `${t('CredentialsPage.actions.delete')}: ${ok} / ${results.length}`,
    });
  };

  // ---- Bulk test: per-row test against each credential's own host --------
  // Each credential needs a distinct target host to test against, which the
  // bulk bar cannot collect. Per-row testing remains available via the row
  // action menu, so a no-op bulk test is removed rather than faked.

  // Filter
  const filteredCredentials = credentials.filter((cred) => {
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      const matches =
        cred.name.toLowerCase().includes(q) ||
        cred.type.toLowerCase().includes(q) ||
        (cred.description ?? '').toLowerCase().includes(q) ||
        (cred.username ?? '').toLowerCase().includes(q);
      if (!matches) return false;
    }
    if (typeFilter !== 'all' && cred.type !== typeFilter) return false;
    return true;
  });

  // Stats
  const stats = {
    total: credentials.length,
    usernamePassword: credentials.filter((c) => c.type === 'username_password').length,
    apiKeys: credentials.filter((c) => c.type === 'api_key').length,
    sshKeys: credentials.filter((c) => c.type === 'ssh_key').length,
  };

  const hasActiveFilters = searchQuery !== '' || typeFilter !== 'all';
  const handleClearFilters = () => {
    setSearchQuery('');
    setTypeFilter('all');
  };

  // Columns
  const columns: DataTableColumn<Credential>[] = [
    {
      id: 'name',
      header: t('CredentialsPage.columns.credential'),
      accessorKey: 'name',
      cell: (cred) => {
        const Icon = getTypeIcon(cred.type);
        return (
          <div className="flex items-center gap-3 min-w-0">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-muted flex-shrink-0">
              <Icon className="h-4 w-4 text-muted-foreground" />
            </div>
            <div className="min-w-0">
              <div className="font-medium truncate">{cred.name}</div>
              {cred.description && (
                <div className="text-xs text-muted-foreground truncate">{cred.description}</div>
              )}
            </div>
          </div>
        );
      },
    },
    {
      id: 'type',
      header: t('CredentialsPage.columns.type'),
      accessorKey: 'type',
      cell: (cred) => (
        <Badge variant="outline" className="text-xs">
          {TYPE_LABELS[cred.type] ?? cred.type}
        </Badge>
      ),
    },
    {
      id: 'username',
      header: t('CredentialsPage.columns.username'),
      accessorFn: (c) => c.username ?? '',
      cell: (cred) => (
        <span className="text-sm text-muted-foreground font-mono">
          {cred.username || '-'}
        </span>
      ),
    },
    {
      id: 'devices',
      header: t('CredentialsPage.columns.devices'),
      accessorFn: (c) => c.devices_count ?? 0,
      cell: (cred) => {
        const count = cred.devices_count ?? 0;
        return (
          <span className="inline-flex h-7 min-w-[28px] items-center justify-center rounded-md bg-muted px-1.5 text-sm font-medium tabular-nums">
            {count}
          </span>
        );
      },
    },
    {
      id: 'last_used',
      header: t('CredentialsPage.columns.lastUsed'),
      accessorFn: (c) => c.last_used ?? '',
      cell: (cred) => (
        <span className="text-sm text-muted-foreground">
          {cred.last_used ? new Date(cred.last_used).toLocaleDateString() : t('CredentialsPage.never')}
        </span>
      ),
    },
    {
      id: 'actions',
      header: '',
      sortable: false,
      cell: (cred) => (
        <div className="flex justify-end" onClick={(e) => e.stopPropagation()}>
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" size="icon" className="h-8 w-8" aria-label={t('CredentialsPage.actions.actionsFor', { name: cred.name })}>
                <MoreHorizontal className="h-4 w-4" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuItem onClick={() => handleEdit(cred)}>
                <Edit className="h-4 w-4 mr-2" />
                {t('CredentialsPage.actions.edit')}
              </DropdownMenuItem>
              <DropdownMenuItem
                onClick={() => {
                  setSelectedCredential(cred);
                  setTestDialogOpen(true);
                }}
              >
                <TestTube className="h-4 w-4 mr-2" />
                {t('CredentialsPage.actions.test')}
              </DropdownMenuItem>
              <DropdownMenuSeparator />
              <DropdownMenuItem
                className="text-destructive focus:text-destructive"
                onClick={() => handleDelete(cred)}
              >
                <Trash2 className="h-4 w-4 mr-2" />
                {t('CredentialsPage.actions.delete')}
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
          title={t('CredentialsPage.title')}
          description={t('CredentialsPage.description')}
          icon={Key}
        />
        <ErrorState
          message={error instanceof Error ? error.message : t('CredentialsPage.loadError')}
          onRetry={() => refetch()}
        />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <PageHeader
        title={t('CredentialsPage.title')}
        description={t('CredentialsPage.description')}
        icon={Key}
        onRefresh={() => refetch()}
        refreshing={isLoading}
        secondaryActions={[
          { label: t('CredentialsPage.actions.export'), icon: Download, onClick: handleExport },
        ]}
        primaryAction={{
          label: t('CredentialsPage.actions.addCredential'),
          icon: Plus,
          onClick: () => setCreateDialogOpen(true),
        }}
      />

      {/* Stats */}
      <StatsGrid
        columns={4}
        isLoading={isLoading}
        stats={[
          {
            title: t('CredentialsPage.stats.total.title'),
            value: stats.total,
            icon: Key,
            variant: 'default',
            description: t('CredentialsPage.stats.total.description'),
          },
          {
            title: t('CredentialsPage.stats.usernamePassword.title'),
            value: stats.usernamePassword,
            icon: Key,
            variant: 'info',
            description: t('CredentialsPage.stats.usernamePassword.description'),
          },
          {
            title: t('CredentialsPage.stats.apiKeys.title'),
            value: stats.apiKeys,
            icon: Shield,
            variant: 'success',
            description: t('CredentialsPage.stats.apiKeys.description'),
          },
          {
            title: t('CredentialsPage.stats.sshKeys.title'),
            value: stats.sshKeys,
            icon: Server,
            variant: 'default',
            description: t('CredentialsPage.stats.sshKeys.description'),
          },
        ]}
      />

      {/* Toolbar */}
      <PageToolbar>
        <SearchBar
          value={searchQuery}
          onChange={setSearchQuery}
          placeholder={t('CredentialsPage.searchPlaceholder')}
          className="w-full sm:w-auto"
        />
        <Select value={typeFilter} onValueChange={setTypeFilter}>
          <SelectTrigger className="w-full sm:w-[200px]">
            <SelectValue placeholder={t('CredentialsPage.filters.allTypes')} />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">{t('CredentialsPage.filters.allTypes')}</SelectItem>
            {CREDENTIAL_TYPES.map((ct) => (
              <SelectItem key={ct} value={ct}>{TYPE_LABELS[ct] ?? ct}</SelectItem>
            ))}
          </SelectContent>
        </Select>
        {hasActiveFilters && (
          <Button variant="ghost" size="sm" onClick={handleClearFilters}>
            {t('CredentialsPage.filters.clear')}
          </Button>
        )}
      </PageToolbar>

      {/* Table */}
      <DataTable
        data={filteredCredentials}
        columns={columns}
        isLoading={isLoading}
        selectable
        onSelectionChange={setSelectedRows}
        searchable={false}
        itemName={t('CredentialsPage.itemNamePlural')}
        getRowId={(c) => c.id}
      />

      {/* Bulk actions · bulk Test removed (needs a per-credential target host
          the bulk bar can't collect, use the per-row Test action instead) */}
      <BulkActionsBar
        selectedCount={selectedRows.length}
        itemName={t('CredentialsPage.itemName')}
        onClear={() => setSelectedRows([])}
        actions={[
          {
            label: t('CredentialsPage.actions.delete'),
            icon: Trash2,
            variant: 'destructive',
            onClick: () => setBulkDeleteOpen(true),
          },
        ]}
      />

      {/* Create / Edit Credential Dialogs (FormDialog-based) */}
      <CredentialFormDialog
        mode="create"
        open={createDialogOpen}
        onOpenChange={setCreateDialogOpen}
        onSubmit={async (values) => {
          await createMutation.mutateAsync(toApiPayload(values, 'create') as CreateCredentialRequest);
        }}
      />
      <CredentialFormDialog
        mode="edit"
        editingCredential={selectedCredential}
        open={editDialogOpen}
        onOpenChange={(v) => { setEditDialogOpen(v); if (!v) setSelectedCredential(null); }}
        onSubmit={async (values) => {
          if (!selectedCredential) return;
          await updateMutation.mutateAsync({
            id: selectedCredential.id,
            data: toApiPayload(values, 'edit'),
          });
        }}
      />

      {/* Delete confirmation */}
      <AlertDialog open={deleteDialogOpen} onOpenChange={setDeleteDialogOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t('CredentialsPage.dialogs.delete.title')}</AlertDialogTitle>
            <AlertDialogDescription>
              {t('CredentialsPage.dialogs.delete.description', { name: selectedCredential?.name ?? '' })}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t('CredentialsPage.dialogs.delete.cancel')}</AlertDialogCancel>
            <AlertDialogAction
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
              onClick={() => selectedCredential && deleteMutation.mutate(selectedCredential.id)}
            >
              {deleteMutation.isPending ? (
                <>
                  <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                  {t('CredentialsPage.dialogs.delete.deleting')}
                </>
              ) : (
                t('CredentialsPage.dialogs.delete.confirm')
              )}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Bulk delete confirmation */}
      <AlertDialog open={bulkDeleteOpen} onOpenChange={setBulkDeleteOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t('CredentialsPage.dialogs.delete.title')}</AlertDialogTitle>
            <AlertDialogDescription>
              {t('CredentialsPage.dialogs.delete.description', {
                name: `${selectedRows.length} ${t('CredentialsPage.itemNamePlural')}`,
              })}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t('CredentialsPage.dialogs.delete.cancel')}</AlertDialogCancel>
            <AlertDialogAction
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
              onClick={(e) => { e.preventDefault(); handleBulkDelete(); }}
              disabled={bulkDeleting}
            >
              {bulkDeleting ? (
                <>
                  <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                  {t('CredentialsPage.dialogs.delete.deleting')}
                </>
              ) : (
                t('CredentialsPage.dialogs.delete.confirm')
              )}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Test credential dialog */}
      <TestCredentialDialog
        open={testDialogOpen}
        onOpenChange={setTestDialogOpen}
        credential={selectedCredential}
        onSubmit={async (values) => {
          if (!selectedCredential) return;
          await testMutation.mutateAsync({ id: selectedCredential.id, targetHost: values.targetHost });
        }}
      />
    </div>
  );
}

// ────────────────────────────────────────────────────────────────────────────
// CredentialFormDialog · shared Create + Edit dialog
// ────────────────────────────────────────────────────────────────────────────

interface CredentialFormDialogProps {
  mode: 'create' | 'edit';
  /** Required in edit mode; ignored in create mode */
  editingCredential?: Credential | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onSubmit: (values: CredentialFormValues) => Promise<void>;
}

function CredentialFormDialog({
  mode,
  editingCredential,
  open,
  onOpenChange,
  onSubmit,
}: CredentialFormDialogProps) {
  const { t } = useTranslation('credentials');
  const [showPassword, setShowPassword] = useState(false);
  const TYPE_LABELS = buildTypeLabels(t);

  // Default values: blank for create, prefilled for edit (secrets stay blank
  // · backend treats empty fields as "keep existing", and we never receive
  // the existing secrets back from the API).
  const defaultValues: CredentialFormValues =
    mode === 'edit' && editingCredential
      ? {
          ...emptyDefaults,
          name: editingCredential.name,
          type: (editingCredential.type as CredentialType) ?? 'username_password',
          description: editingCredential.description ?? '',
        }
      : emptyDefaults;

  const handleOpenChange = (next: boolean) => {
    if (!next) setShowPassword(false);
    onOpenChange(next);
  };

  return (
    <FormDialog<CredentialFormValues>
      open={open}
      onOpenChange={handleOpenChange}
      title={mode === 'create' ? t('CredentialsPage.dialogs.form.createTitle') : t('CredentialsPage.dialogs.form.editTitle')}
      description={
        mode === 'create'
          ? t('CredentialsPage.dialogs.form.createDescription')
          : t('CredentialsPage.dialogs.form.editDescription')
      }
      schema={credentialSchemaForMode(mode)}
      defaultValues={defaultValues}
      submitLabel={mode === 'create' ? t('CredentialsPage.dialogs.form.createSubmit') : t('CredentialsPage.dialogs.form.editSubmit')}
      contentClassName="max-w-md"
      onSubmit={onSubmit}
    >
      {(form) => {
        const type = form.watch('type');

        return (
          <>
            {/* Name */}
            <FormField
              control={form.control}
              name="name"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>{t('CredentialsPage.fields.name.label')}</FormLabel>
                  <FormControl>
                    <Input placeholder={t('CredentialsPage.fields.name.placeholder')} {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />

            {/* Type · selectable on create, read-only on edit */}
            {mode === 'create' ? (
              <FormField
                control={form.control}
                name="type"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>{t('CredentialsPage.fields.type.label')}</FormLabel>
                    <Select value={field.value} onValueChange={(v) => field.onChange(v as CredentialType)}>
                      <FormControl>
                        <SelectTrigger>
                          <SelectValue />
                        </SelectTrigger>
                      </FormControl>
                      <SelectContent>
                        {CREDENTIAL_TYPES.map((ct) => (
                          <SelectItem key={ct} value={ct}>
                            {ct === 'username_password'
                              ? t('CredentialsPage.fields.type.usernamePasswordOption')
                              : TYPE_LABELS[ct] ?? ct}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                    <FormMessage />
                  </FormItem>
                )}
              />
            ) : (
              <div className="rounded-lg bg-muted p-3 text-sm">
                <span className="text-muted-foreground">{t('CredentialsPage.fields.type.readOnlyLabel')} </span>
                <Badge variant="outline">{TYPE_LABELS[type] ?? type}</Badge>
              </div>
            )}

            {/* Type-specific secret fields */}
            {(type === 'username_password' || type === 'basic_auth') && (
              <>
                <FormField
                  control={form.control}
                  name="username"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>{mode === 'edit' ? t('CredentialsPage.fields.username.editLabel') : t('CredentialsPage.fields.username.label')}</FormLabel>
                      <FormControl>
                        <Input
                          placeholder={mode === 'edit' ? t('CredentialsPage.fields.keepCurrentPlaceholder') : t('CredentialsPage.fields.username.placeholder')}
                          {...field}
                        />
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
                      <FormLabel>{mode === 'edit' ? t('CredentialsPage.fields.password.editLabel') : t('CredentialsPage.fields.password.label')}</FormLabel>
                      <FormControl>
                        <div className="relative">
                          <Input
                            type={showPassword ? 'text' : 'password'}
                            placeholder={mode === 'edit' ? t('CredentialsPage.fields.keepCurrentPlaceholder') : '••••••••'}
                            className="pr-10"
                            {...field}
                          />
                          <Button
                            type="button"
                            variant="ghost"
                            size="icon"
                            className="absolute right-0 top-0 h-full"
                            onClick={() => setShowPassword(!showPassword)}
                          >
                            {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                          </Button>
                        </div>
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
              </>
            )}

            {type === 'api_key' && (
              <FormField
                control={form.control}
                name="api_key"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>{mode === 'edit' ? t('CredentialsPage.fields.apiKey.editLabel') : t('CredentialsPage.fields.apiKey.label')}</FormLabel>
                    <FormControl>
                      <Input
                        type="password"
                        placeholder={mode === 'edit' ? t('CredentialsPage.fields.keepCurrentPlaceholder') : t('CredentialsPage.fields.apiKey.placeholder')}
                        {...field}
                      />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
            )}

            {type === 'ssh_key' && (
              <>
                <FormField
                  control={form.control}
                  name="username"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>{mode === 'edit' ? t('CredentialsPage.fields.username.editLabel') : t('CredentialsPage.fields.username.label')}</FormLabel>
                      <FormControl>
                        <Input
                          placeholder={mode === 'edit' ? t('CredentialsPage.fields.keepCurrentPlaceholder') : t('CredentialsPage.fields.sshUsername.placeholder')}
                          {...field}
                        />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
                <FormField
                  control={form.control}
                  name="ssh_key"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>{mode === 'edit' ? t('CredentialsPage.fields.privateKey.editLabel') : t('CredentialsPage.fields.privateKey.label')}</FormLabel>
                      <FormControl>
                        <Textarea
                          placeholder={mode === 'edit' ? t('CredentialsPage.fields.keepCurrentPlaceholder') : '-----BEGIN OPENSSH PRIVATE KEY-----'}
                          rows={5}
                          {...field}
                        />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
              </>
            )}

            {type === 'token' && (
              <FormField
                control={form.control}
                name="token"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>{mode === 'edit' ? t('CredentialsPage.fields.token.editLabel') : t('CredentialsPage.fields.token.label')}</FormLabel>
                    <FormControl>
                      <Input
                        type="password"
                        placeholder={mode === 'edit' ? t('CredentialsPage.fields.keepCurrentPlaceholder') : t('CredentialsPage.fields.token.placeholder')}
                        {...field}
                      />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
            )}

            {type === 'certificate' && (
              <FormField
                control={form.control}
                name="certificate"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>{mode === 'edit' ? t('CredentialsPage.fields.certificate.editLabel') : t('CredentialsPage.fields.certificate.label')}</FormLabel>
                    <FormControl>
                      <Textarea
                        placeholder={mode === 'edit' ? t('CredentialsPage.fields.keepCurrentPlaceholder') : '-----BEGIN CERTIFICATE-----'}
                        rows={5}
                        {...field}
                      />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
            )}

            {type === 'snmp_community' && (
              <FormField
                control={form.control}
                name="snmp_community"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>{mode === 'edit' ? t('CredentialsPage.fields.snmpCommunity.editLabel') : t('CredentialsPage.fields.snmpCommunity.label')}</FormLabel>
                    <FormControl>
                      <Input
                        type="password"
                        placeholder={mode === 'edit' ? t('CredentialsPage.fields.keepCurrentPlaceholder') : t('CredentialsPage.fields.snmpCommunity.placeholder')}
                        {...field}
                      />
                    </FormControl>
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
                  <FormLabel>{mode === 'create' ? t('CredentialsPage.fields.description.labelOptional') : t('CredentialsPage.fields.description.label')}</FormLabel>
                  <FormControl>
                    <Textarea placeholder={t('CredentialsPage.fields.description.placeholder')} rows={2} {...field} />
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

// ────────────────────────────────────────────────────────────────────────────
// TestCredentialDialog · single-field FormDialog for "Test against host"
// ────────────────────────────────────────────────────────────────────────────

const testSchema = z.object({
  targetHost: z.string().min(1, 'Target host is required'),
});
type TestFormValues = z.infer<typeof testSchema>;

interface TestCredentialDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  credential: Credential | null;
  onSubmit: (values: TestFormValues) => Promise<void>;
}

function TestCredentialDialog({
  open,
  onOpenChange,
  credential,
  onSubmit,
}: TestCredentialDialogProps) {
  const { t } = useTranslation('credentials');
  if (!credential) return null;

  return (
    <FormDialog<TestFormValues>
      open={open}
      onOpenChange={onOpenChange}
      title={t('CredentialsPage.dialogs.test.title')}
      description={t('CredentialsPage.dialogs.test.description', { name: credential.name })}
      schema={testSchema}
      defaultValues={{ targetHost: '' }}
      submitLabel={t('CredentialsPage.dialogs.test.submit')}
      contentClassName="max-w-md"
      onSubmit={onSubmit}
    >
      {(form) => (
        <FormField
          control={form.control}
          name="targetHost"
          render={({ field }) => (
            <FormItem>
              <FormLabel>{t('CredentialsPage.dialogs.test.targetHostLabel')}</FormLabel>
              <FormControl>
                <Input placeholder={t('CredentialsPage.dialogs.test.targetHostPlaceholder')} {...field} />
              </FormControl>
              <FormDescription>
                <span className="inline-flex items-center gap-1">
                  <CheckCircle className="h-3 w-3" />
                  {t('CredentialsPage.dialogs.test.targetHostHelp')}
                </span>
              </FormDescription>
              <FormMessage />
            </FormItem>
          )}
        />
      )}
    </FormDialog>
  );
}

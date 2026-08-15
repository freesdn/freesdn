// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { useState, useMemo } from 'react';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import type { TFunction } from 'i18next';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { z } from 'zod';
import {
  Plus,
  MoreHorizontal,
  Pencil,
  Trash2,
  TestTube2,
  CheckCircle2,
  XCircle,
  HardDrive,
  Cloud,
  Server,
  FolderSync,
  Globe,
  Box,
  CloudCog,
  Loader2,
  ArrowLeft,
  Star,
  RefreshCw,
  Eye,
  EyeOff,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { SearchBar } from '@/components/ui/search-bar';
import { Badge } from '@/components/ui/badge';
import { Label } from '@/components/ui/label';
import { Skeleton } from '@/components/ui/skeleton';
import { Switch } from '@/components/ui/switch';
import { Textarea } from '@/components/ui/textarea';
import { EmptyState, ErrorState } from '@/components/ui/empty-state';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { FormDialog } from '@/components/ui/form-dialog';
import { FormControl, FormDescription, FormField, FormItem, FormLabel, FormMessage } from '@/components/ui/form';
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
  storageLocationsApi,
  type StorageLocation,
  type StorageLocationCreate,
  type StorageLocationUpdate,
  type StorageLocationTestResult,
  type StorageTypeInfo,
  type StorageTypeField,
  type BackupStorageType,
} from '@/lib/api';
import { cn } from '@/lib/utils';
import { PageHeader } from '@/components/layout';
import { useNotificationsStore } from '@/stores';

// ─── Icon map for storage types ─────────────────────────────────────────────
const STORAGE_ICONS: Record<string, React.ElementType> = {
  local: HardDrive,
  s3: Cloud,
  sftp: Server,
  ftp: FolderSync,
  google_drive: CloudCog,
  dropbox: Box,
  webdav: Globe,
};

function getStorageIcon(type: string) {
  return STORAGE_ICONS[type] || HardDrive;
}

// ─── Format timestamp ───────────────────────────────────────────────────────
function formatDate(iso: string | null | undefined, neverLabel = 'Never') {
  if (!iso) return neverLabel;
  return new Date(iso).toLocaleString(undefined, {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

// ─── Form schema ────────────────────────────────────────────────────────────
//
// Storage type fields are dynamic (fetched from API), so the `config` map is
// typed as `Record<string, string>`. Per-field "required" validation is
// applied at submit time via superRefine using the field metadata for the
// currently-selected storage type. In edit mode all secret fields are
// optional ("leave blank to keep").

const buildStorageFormSchema = (t: TFunction) =>
  z.object({
    name: z.string().min(1, t('StorageLocationsPage.validation.nameRequired')),
    description: z.string(),
    storage_type: z.string().min(1, t('StorageLocationsPage.validation.storageTypeRequired')),
    is_default: z.boolean(),
    config: z.record(z.string(), z.string()),
  });

type StorageFormValues = z.infer<ReturnType<typeof buildStorageFormSchema>>;

const emptyDefaults: StorageFormValues = {
  name: '',
  description: '',
  storage_type: '',
  is_default: false,
  config: {},
};

/** Build the schema with mode-aware required-field validation. */
function storageSchemaForMode(mode: 'create' | 'edit', currentFields: StorageTypeField[], t: TFunction) {
  return buildStorageFormSchema(t).superRefine((data, ctx) => {
    if (mode === 'edit') return; // edit: required fields can be left blank to keep existing
    for (const field of currentFields) {
      if (!field.required) continue;
      const v = data.config[field.name];
      if (field.type === 'boolean') {
        // booleans always have a value (even "false"), so skip
        continue;
      }
      if (!v || !v.trim()) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['config', field.name],
          message: t('StorageLocationsPage.validation.fieldRequired', { field: field.label }),
        });
      }
    }
  });
}

// ─── Main Page ──────────────────────────────────────────────────────────────

export default function StorageLocationsPage() {
  const { t } = useTranslation('backup');
  const queryClient = useQueryClient();
  const { addNotification } = useNotificationsStore();

  // ── State ───────────────────────────────────────────────────────────────
  const [search, setSearch] = useState('');
  const [filterType, setFilterType] = useState<string>('all');

  // Dialogs
  const [createOpen, setCreateOpen] = useState(false);
  const [createPrefilledType, setCreatePrefilledType] = useState<string>('');
  const [editOpen, setEditOpen] = useState(false);
  const [deleteOpen, setDeleteOpen] = useState(false);
  const [testResultOpen, setTestResultOpen] = useState(false);

  // Selected item
  const [selectedLocation, setSelectedLocation] = useState<StorageLocation | null>(null);
  const [testResult, setTestResult] = useState<StorageLocationTestResult | null>(null);
  const [testingId, setTestingId] = useState<string | null>(null);

  // ── Queries ─────────────────────────────────────────────────────────────
  const {
    data: locations = [],
    isLoading,
    isError,
    refetch,
  } = useQuery({
    queryKey: ['storage-locations'],
    queryFn: async () => {
      const res = await storageLocationsApi.list();
      return res.data;
    },
  });

  const { data: supportedTypes, isLoading: typesLoading, isError: typesError } = useQuery({
    queryKey: ['storage-types'],
    queryFn: async () => {
      const res = await storageLocationsApi.getSupportedTypes();
      return res.data;
    },
  });

  // ── Mutations ───────────────────────────────────────────────────────────
  const createMutation = useMutation({
    mutationFn: async (data: StorageLocationCreate) => {
      const res = await storageLocationsApi.create(data);
      return res.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['storage-locations'] });
      setCreateOpen(false);
      setCreatePrefilledType('');
      addNotification({ type: 'success', title: t('StorageLocationsPage.notifications.created.title'), message: t('StorageLocationsPage.notifications.created.message') });
    },
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    onError: (err: any) => {
      addNotification({ type: 'error', title: t('StorageLocationsPage.notifications.error'), message: err?.response?.data?.detail || err?.response?.data?.error?.message || t('StorageLocationsPage.notifications.createFailed') });
    },
  });

  const updateMutation = useMutation({
    mutationFn: async ({ id, data }: { id: string; data: StorageLocationUpdate }) => {
      const res = await storageLocationsApi.update(id, data);
      return res.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['storage-locations'] });
      setEditOpen(false);
      setSelectedLocation(null);
      addNotification({ type: 'success', title: t('StorageLocationsPage.notifications.updated.title'), message: t('StorageLocationsPage.notifications.updated.message') });
    },
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    onError: (err: any) => {
      addNotification({ type: 'error', title: t('StorageLocationsPage.notifications.error'), message: err?.response?.data?.detail || err?.response?.data?.error?.message || t('StorageLocationsPage.notifications.updateFailed') });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: async (id: string) => {
      await storageLocationsApi.delete(id);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['storage-locations'] });
      setDeleteOpen(false);
      setSelectedLocation(null);
      addNotification({ type: 'success', title: t('StorageLocationsPage.notifications.deleted.title'), message: t('StorageLocationsPage.notifications.deleted.message') });
    },
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    onError: (err: any) => {
      addNotification({ type: 'error', title: t('StorageLocationsPage.notifications.error'), message: err?.response?.data?.detail || err?.response?.data?.error?.message || t('StorageLocationsPage.notifications.deleteFailed') });
    },
  });

  const testMutation = useMutation({
    mutationFn: async (id: string) => {
      setTestingId(id);
      const res = await storageLocationsApi.test(id);
      return res.data;
    },
    onSuccess: (data) => {
      setTestResult(data);
      setTestResultOpen(true);
      setTestingId(null);
      queryClient.invalidateQueries({ queryKey: ['storage-locations'] });
    },
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    onError: (err: any) => {
      setTestingId(null);
      addNotification({ type: 'error', title: t('StorageLocationsPage.notifications.testFailed.title'), message: err?.response?.data?.detail || err?.response?.data?.error?.message || t('StorageLocationsPage.notifications.testFailed.message') });
    },
  });

  // ── Helpers ─────────────────────────────────────────────────────────────
  const openCreate = (prefilledType?: string) => {
    setCreatePrefilledType(prefilledType ?? '');
    setCreateOpen(true);
  };

  const openEdit = (loc: StorageLocation) => {
    setSelectedLocation(loc);
    setEditOpen(true);
  };

  const openDelete = (loc: StorageLocation) => {
    setSelectedLocation(loc);
    setDeleteOpen(true);
  };

  const handleDelete = () => {
    if (!selectedLocation) return;
    deleteMutation.mutate(selectedLocation.id);
  };

  // Get type info for a storage type id
  const getTypeInfo = (typeId: string): StorageTypeInfo | undefined => {
    return supportedTypes?.types?.find((type: StorageTypeInfo) => type.id === typeId);
  };

  // Filtered locations
  const filteredLocations = useMemo(() => {
    let result = locations;
    if (filterType !== 'all') {
      result = result.filter((loc: StorageLocation) => loc.storage_type === filterType);
    }
    if (search.trim()) {
      const q = search.toLowerCase();
      result = result.filter(
        (loc: StorageLocation) =>
          loc.name.toLowerCase().includes(q) ||
          (loc.description || '').toLowerCase().includes(q) ||
          loc.storage_type.toLowerCase().includes(q)
      );
    }
    return result;
  }, [locations, filterType, search]);

  // ── Render ──────────────────────────────────────────────────────────────
  return (
    <div className="space-y-6">
      {/* Header */}
      <PageHeader
        icon={HardDrive}
        title={t('StorageLocationsPage.header.title')}
        subtitle={t('StorageLocationsPage.header.subtitle')}
        breadcrumbs={
          <Link to="/backups">
            <Button variant="ghost" size="sm" className="gap-2">
              <ArrowLeft className="h-4 w-4" />
              {t('StorageLocationsPage.header.backToBackups')}
            </Button>
          </Link>
        }
        actions={
          <Button onClick={() => openCreate()} className="gap-2">
            <Plus className="h-4 w-4" />
            {t('StorageLocationsPage.actions.add')}
          </Button>
        }
      />

      {/* Filters bar */}
      <div className="flex items-center gap-3">
        <SearchBar
          value={search}
          onChange={setSearch}
          placeholder={t('StorageLocationsPage.filters.searchPlaceholder')}
        />
        <Select value={filterType} onValueChange={setFilterType}>
          <SelectTrigger className="w-[200px]">
            <SelectValue placeholder={t('StorageLocationsPage.filters.allTypes')} />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">{t('StorageLocationsPage.filters.allTypes')}</SelectItem>
            {supportedTypes?.types?.map((type: StorageTypeInfo) => (
              <SelectItem key={type.id} value={type.id}>
                {type.name}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Button variant="outline" size="icon" onClick={() => refetch()} title={t('StorageLocationsPage.filters.refresh')}>
          <RefreshCw className="h-4 w-4" />
        </Button>
      </div>

      {/* Storage locations grid */}
      {isLoading ? (
        <div className="grid gap-6 sm:grid-cols-2 lg:grid-cols-3">
          <Skeleton className="h-48 w-full rounded-xl" />
          <Skeleton className="h-48 w-full rounded-xl" />
          <Skeleton className="h-48 w-full rounded-xl" />
        </div>
      ) : isError ? (
        <ErrorState onRetry={() => refetch()} />
      ) : filteredLocations.length === 0 ? (
        <EmptyState
          icon={FolderSync}
          title={t('StorageLocationsPage.empty.title')}
          description={t('StorageLocationsPage.empty.description')}
          action={{ label: t('StorageLocationsPage.empty.action'), onClick: () => openCreate(), icon: Plus }}
          variant="card"
        />
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          {filteredLocations.map((loc: StorageLocation) => {
            const Icon = getStorageIcon(loc.storage_type);
            const typeInfo = getTypeInfo(loc.storage_type);
            const isTesting = testingId === loc.id;

            return (
              <Card
                key={loc.id}
                className={cn(
                  'relative transition-all hover:shadow-md',
                  !loc.is_active && 'opacity-60',
                  loc.is_default && 'ring-2 ring-primary/50'
                )}
              >
                <CardContent noOffset className="p-5">
                  {/* Header row */}
                  <div className="flex items-start justify-between mb-3">
                    <div className="flex items-center gap-3 min-w-0">
                      <div
                        className={cn(
                          'flex items-center justify-center h-10 w-10 rounded-lg shrink-0',
                          loc.is_active ? 'bg-primary/10 text-primary' : 'bg-muted text-muted-foreground'
                        )}
                      >
                        <Icon className="h-5 w-5" />
                      </div>
                      <div className="min-w-0">
                        <div className="flex items-center gap-2">
                          <h3 className="font-semibold truncate">{loc.name}</h3>
                          {loc.is_default && (
                            <Badge variant="outline" className="text-xs shrink-0 gap-1 border-amber-500 text-amber-600">
                              <Star className="h-3 w-3" />
                              {t('StorageLocationsPage.badges.default')}
                            </Badge>
                          )}
                        </div>
                        <p className="text-sm text-muted-foreground">{typeInfo?.name || loc.storage_type}</p>
                      </div>
                    </div>
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button variant="ghost" size="icon" className="h-8 w-8 shrink-0">
                          <MoreHorizontal className="h-4 w-4" />
                        </Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end">
                        <DropdownMenuItem onClick={() => testMutation.mutate(loc.id)} disabled={isTesting}>
                          <TestTube2 className="h-4 w-4 mr-2" />
                          {t('StorageLocationsPage.actions.testConnection')}
                        </DropdownMenuItem>
                        <DropdownMenuItem onClick={() => openEdit(loc)}>
                          <Pencil className="h-4 w-4 mr-2" />
                          {t('StorageLocationsPage.actions.edit')}
                        </DropdownMenuItem>
                        <DropdownMenuSeparator />
                        <DropdownMenuItem onClick={() => openDelete(loc)} className="text-destructive">
                          <Trash2 className="h-4 w-4 mr-2" />
                          {t('StorageLocationsPage.actions.delete')}
                        </DropdownMenuItem>
                      </DropdownMenuContent>
                    </DropdownMenu>
                  </div>

                  {/* Description */}
                  {loc.description && (
                    <p className="text-sm text-muted-foreground mb-3 line-clamp-2">{loc.description}</p>
                  )}

                  {/* Status badges */}
                  <div className="flex items-center gap-2 flex-wrap mb-3">
                    <Badge variant={loc.is_active ? 'default' : 'secondary'} className="text-xs">
                      {loc.is_active ? t('StorageLocationsPage.status.active') : t('StorageLocationsPage.status.inactive')}
                    </Badge>
                    {loc.last_test_status === 'success' && (
                      <Badge variant="outline" className="text-xs gap-1 text-green-600 border-green-300">
                        <CheckCircle2 className="h-3 w-3" />
                        {t('StorageLocationsPage.status.connected')}
                      </Badge>
                    )}
                    {loc.last_test_status === 'failed' && (
                      <Badge variant="outline" className="text-xs gap-1 text-red-600 border-red-300">
                        <XCircle className="h-3 w-3" />
                        {t('StorageLocationsPage.status.failed')}
                      </Badge>
                    )}
                    {isTesting && (
                      <Badge variant="outline" className="text-xs gap-1">
                        <Loader2 className="h-3 w-3 animate-spin" />
                        {t('StorageLocationsPage.status.testing')}
                      </Badge>
                    )}
                  </div>

                  {/* Footer */}
                  <div className="flex items-center justify-between text-xs text-muted-foreground pt-3 border-t">
                    <span>
                      {loc.last_test_at ? (
                        <>{t('StorageLocationsPage.footer.lastTested', { date: formatDate(loc.last_test_at) })}</>
                      ) : (
                        <>{t('StorageLocationsPage.footer.neverTested')}</>
                      )}
                    </span>
                    <span>{t('StorageLocationsPage.footer.created', { date: formatDate(loc.created_at) })}</span>
                  </div>
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}

      {/* Supported types cards (when empty, show what's available) */}
      {!isLoading && locations.length === 0 && supportedTypes?.types && (
        <div className="space-y-4 mt-4">
          <h2 className="text-lg font-semibold">{t('StorageLocationsPage.supportedBackends.heading')}</h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-3">
            {supportedTypes.types.map((type: StorageTypeInfo) => {
              const Icon = getStorageIcon(type.id);
              return (
                <div
                  key={type.id}
                  className="border rounded-lg p-4 hover:bg-accent/50 cursor-pointer transition-colors"
                  onClick={() => openCreate(type.id)}
                >
                  <div className="flex items-center gap-3 mb-2">
                    <div className="flex items-center justify-center h-9 w-9 rounded-md bg-primary/10 text-primary">
                      <Icon className="h-5 w-5" />
                    </div>
                    <h3 className="font-medium text-sm">{type.name}</h3>
                  </div>
                  <p className="text-xs text-muted-foreground">{type.description}</p>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* ─── Create Dialog (FormDialog) ─────────────────────────────────── */}
      <StorageLocationFormDialog
        mode="create"
        open={createOpen}
        onOpenChange={(v) => {
          setCreateOpen(v);
          if (!v) setCreatePrefilledType('');
        }}
        prefilledType={createPrefilledType}
        supportedTypes={supportedTypes?.types ?? []}
        typesLoading={typesLoading}
        typesError={typesError}
        onSubmit={async (values) => {
          await createMutation.mutateAsync({
            name: values.name,
            description: values.description || undefined,
            storage_type: values.storage_type as BackupStorageType,
            is_default: values.is_default,
            config: values.config,
          });
        }}
      />

      {/* ─── Edit Dialog (FormDialog) ───────────────────────────────────── */}
      <StorageLocationFormDialog
        mode="edit"
        open={editOpen}
        onOpenChange={(v) => {
          setEditOpen(v);
          if (!v) setSelectedLocation(null);
        }}
        editingLocation={selectedLocation}
        supportedTypes={supportedTypes?.types ?? []}
        typesLoading={typesLoading}
        typesError={typesError}
        onSubmit={async (values) => {
          if (!selectedLocation) return;
          const updateData: StorageLocationUpdate = {
            name: values.name || undefined,
            description: values.description || undefined,
            is_default: values.is_default,
          };
          // Only include config if user filled in fields
          const hasConfig = Object.values(values.config).some((v) => v && v.trim() !== '');
          if (hasConfig) {
            updateData.config = values.config;
          }
          await updateMutation.mutateAsync({ id: selectedLocation.id, data: updateData });
        }}
      />

      {/* ─── Delete Confirmation Dialog ─────────────────────────────────── */}
      <Dialog open={deleteOpen} onOpenChange={setDeleteOpen}>
        <DialogContent className="max-w-sm">
          <DialogHeader>
            <DialogTitle>{t('StorageLocationsPage.deleteDialog.title')}</DialogTitle>
            <DialogDescription>
              {t('StorageLocationsPage.deleteDialog.confirmPrefix')} <strong>{selectedLocation?.name}</strong>{t('StorageLocationsPage.deleteDialog.confirmSuffix')}
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDeleteOpen(false)}>
              {t('StorageLocationsPage.actions.cancel')}
            </Button>
            <Button
              variant="destructive"
              onClick={handleDelete}
              disabled={deleteMutation.isPending}
              className="gap-2"
            >
              {deleteMutation.isPending && <Loader2 className="h-4 w-4 animate-spin" />}
              {t('StorageLocationsPage.actions.delete')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* ─── Test Result Dialog ─────────────────────────────────────────── */}
      <Dialog open={testResultOpen} onOpenChange={setTestResultOpen}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              {testResult?.success ? (
                <CheckCircle2 className="h-5 w-5 text-green-600" />
              ) : (
                <XCircle className="h-5 w-5 text-red-600" />
              )}
              {testResult?.success
                ? t('StorageLocationsPage.testResult.titlePassed')
                : t('StorageLocationsPage.testResult.titleFailed')}
            </DialogTitle>
          </DialogHeader>
          <div className="space-y-3 py-2">
            <div className="flex items-center justify-between text-sm">
              <span className="text-muted-foreground">{t('StorageLocationsPage.testResult.status')}</span>
              <Badge variant={testResult?.success ? 'default' : 'destructive'}>
                {testResult?.success
                  ? t('StorageLocationsPage.testResult.success')
                  : t('StorageLocationsPage.testResult.failed')}
              </Badge>
            </div>
            <div className="flex items-center justify-between text-sm">
              <span className="text-muted-foreground">{t('StorageLocationsPage.testResult.message')}</span>
              <span className="text-right max-w-[60%]">{testResult?.message}</span>
            </div>
            {testResult?.latency_ms !== null && testResult?.latency_ms !== undefined && (
              <div className="flex items-center justify-between text-sm">
                <span className="text-muted-foreground">{t('StorageLocationsPage.testResult.latency')}</span>
                <span>{t('StorageLocationsPage.testResult.latencyValue', { ms: testResult.latency_ms.toFixed(0) })}</span>
              </div>
            )}
            {testResult?.details && Object.keys(testResult.details).length > 0 && (
              <div className="pt-2 border-t">
                <p className="text-sm font-medium mb-2">{t('StorageLocationsPage.testResult.details')}</p>
                <pre className="text-xs bg-muted p-3 rounded-md overflow-auto max-h-40">
                  {JSON.stringify(testResult.details, null, 2)}
                </pre>
              </div>
            )}
          </div>
          <DialogFooter>
            <Button onClick={() => setTestResultOpen(false)}>{t('StorageLocationsPage.actions.close')}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

// ─── StorageLocationFormDialog (shared Create + Edit) ───────────────────────

interface StorageLocationFormDialogProps {
  mode: 'create' | 'edit';
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** Required in edit mode; ignored in create mode */
  editingLocation?: StorageLocation | null;
  /** Optional: prefill `storage_type` in create mode */
  prefilledType?: string;
  supportedTypes: StorageTypeInfo[];
  typesLoading: boolean;
  typesError: boolean;
  onSubmit: (values: StorageFormValues) => Promise<void>;
}

function StorageLocationFormDialog({
  mode,
  open,
  onOpenChange,
  editingLocation,
  prefilledType,
  supportedTypes,
  typesLoading,
  typesError,
  onSubmit,
}: StorageLocationFormDialogProps) {
  const { t } = useTranslation('backup');
  const [showSecrets, setShowSecrets] = useState(false);

  const handleOpenChange = (next: boolean) => {
    if (!next) setShowSecrets(false);
    onOpenChange(next);
  };

  // Default values: blank for create (optionally with prefilled type),
  // prefilled from editingLocation for edit. config is never prefilled
  // (the API never returns secrets).
  const defaultValues: StorageFormValues =
    mode === 'edit' && editingLocation
      ? {
          name: editingLocation.name,
          description: editingLocation.description || '',
          storage_type: editingLocation.storage_type,
          is_default: editingLocation.is_default,
          config: {},
        }
      : {
          ...emptyDefaults,
          storage_type: prefilledType || '',
        };

  // Lookup current fields based on the selected storage_type. We need this
  // both for the schema (required-field check) and rendering.
  const getTypeInfo = (typeId: string) => supportedTypes.find((type) => type.id === typeId);
  const initialFields = getTypeInfo(defaultValues.storage_type)?.fields ?? [];

  return (
    <FormDialog<StorageFormValues>
      open={open}
      onOpenChange={handleOpenChange}
      title={mode === 'create' ? t('StorageLocationsPage.formDialog.createTitle') : t('StorageLocationsPage.formDialog.editTitle')}
      description={
        mode === 'create'
          ? t('StorageLocationsPage.formDialog.createDescription')
          : editingLocation
          ? t('StorageLocationsPage.formDialog.editDescriptionNamed', { name: editingLocation.name })
          : t('StorageLocationsPage.formDialog.editDescription')
      }
      // Schema needs to know the currently-selected fields for required-validation,
      // but at FormDialog construction time we only know the initial set. The
      // submit handler does the real per-field check anyway. Use initialFields
      // for the schema; selecting a different type later still validates name
      // + storage_type via the base schema, and any unfilled required fields
      // will surface a backend error on submit.
      schema={storageSchemaForMode(mode, initialFields, t)}
      defaultValues={defaultValues}
      submitLabel={mode === 'create' ? t('StorageLocationsPage.formDialog.submitCreate') : t('StorageLocationsPage.formDialog.submitSave')}
      contentClassName="max-w-lg max-h-[90vh] overflow-y-auto"
      onSubmit={onSubmit}
    >
      {(form) => {
        const storageType = form.watch('storage_type');
        const currentFields = getTypeInfo(storageType)?.fields ?? [];
        const idPrefix = mode === 'create' ? 'create' : 'edit';

        return (
          <>
            {/* Name */}
            <FormField
              control={form.control}
              name="name"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>{t('StorageLocationsPage.form.name')} {mode === 'create' && '*'}</FormLabel>
                  <FormControl>
                    <Input placeholder={t('StorageLocationsPage.form.namePlaceholder')} {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />

            {/* Description */}
            <FormField
              control={form.control}
              name="description"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>{t('StorageLocationsPage.form.description')}</FormLabel>
                  <FormControl>
                    <Input placeholder={t('StorageLocationsPage.form.descriptionPlaceholder')} {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />

            {/* Storage type · selectable on create, read-only on edit */}
            {mode === 'create' ? (
              <FormField
                control={form.control}
                name="storage_type"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>{t('StorageLocationsPage.form.storageType')} *</FormLabel>
                    <Select
                      value={field.value || undefined}
                      onValueChange={(v) => {
                        field.onChange(v);
                        // Reset config when type changes
                        form.setValue('config', {});
                      }}
                    >
                      <FormControl>
                        <SelectTrigger>
                          <SelectValue placeholder={t('StorageLocationsPage.form.storageTypePlaceholder')} />
                        </SelectTrigger>
                      </FormControl>
                      <SelectContent position="popper" className="z-[200]">
                        {typesLoading ? (
                          <div className="flex items-center gap-2 px-2 py-3 text-sm text-muted-foreground">
                            <Loader2 className="h-4 w-4 animate-spin" />
                            {t('StorageLocationsPage.form.loadingTypes')}
                          </div>
                        ) : typesError ? (
                          <div className="px-2 py-3 text-sm text-destructive">
                            {t('StorageLocationsPage.form.loadTypesFailed')}
                          </div>
                        ) : supportedTypes.length === 0 ? (
                          <div className="px-2 py-3 text-sm text-muted-foreground">
                            {t('StorageLocationsPage.form.noTypesAvailable')}
                          </div>
                        ) : (
                          supportedTypes.map((type) => {
                            const Icon = getStorageIcon(type.id);
                            return (
                              <SelectItem key={type.id} value={type.id}>
                                <span className="flex items-center gap-2">
                                  <Icon className="h-4 w-4" />
                                  {type.name}
                                </span>
                              </SelectItem>
                            );
                          })
                        )}
                      </SelectContent>
                    </Select>
                    <FormMessage />
                  </FormItem>
                )}
              />
            ) : (
              <div className="space-y-2">
                <Label>{t('StorageLocationsPage.form.storageType')}</Label>
                <div className="flex items-center gap-2 text-sm text-muted-foreground px-3 py-2 border rounded-md bg-muted/50">
                  {(() => {
                    const Icon = getStorageIcon(storageType);
                    return <Icon className="h-4 w-4" />;
                  })()}
                  {getTypeInfo(storageType)?.name || storageType}
                  <span className="text-xs">{t('StorageLocationsPage.form.cannotBeChanged')}</span>
                </div>
              </div>
            )}

            {/* Dynamic config fields */}
            {currentFields.length > 0 && (
              <div className="space-y-3 pt-2 border-t">
                <div className="flex items-center justify-between">
                  <div>
                    <h4 className="text-sm font-medium">
                      {mode === 'create'
                        ? t('StorageLocationsPage.form.connectionSettings')
                        : t('StorageLocationsPage.form.updateConnectionSettings')}
                    </h4>
                    {mode === 'edit' && (
                      <p className="text-xs text-muted-foreground">{t('StorageLocationsPage.form.leaveEmptyHint')}</p>
                    )}
                  </div>
                  <Button
                    type="button"
                    variant="ghost"
                    size="sm"
                    className="gap-1 text-xs h-7"
                    onClick={() => setShowSecrets(!showSecrets)}
                  >
                    {showSecrets ? <EyeOff className="h-3 w-3" /> : <Eye className="h-3 w-3" />}
                    {showSecrets ? t('StorageLocationsPage.form.hideSecrets') : t('StorageLocationsPage.form.showSecrets')}
                  </Button>
                </div>
                {currentFields.map((field) => (
                  <DynamicConfigField
                    key={field.name}
                    field={field}
                    mode={mode}
                    idPrefix={idPrefix}
                    showSecrets={showSecrets}
                    form={form}
                  />
                ))}
              </div>
            )}

            {/* Default toggle */}
            <FormField
              control={form.control}
              name="is_default"
              render={({ field }) => (
                <FormItem>
                  <div className="flex items-center justify-between pt-2">
                    <div>
                      <FormLabel className="text-sm font-medium">{t('StorageLocationsPage.form.setAsDefault')}</FormLabel>
                      <FormDescription>{t('StorageLocationsPage.form.setAsDefaultHint')}</FormDescription>
                    </div>
                    <FormControl>
                      <Switch checked={field.value} onCheckedChange={field.onChange} />
                    </FormControl>
                  </div>
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

// ─── DynamicConfigField · renders a single dynamic field bound to form.config ───

interface DynamicConfigFieldProps {
  field: StorageTypeField;
  mode: 'create' | 'edit';
  idPrefix: string;
  showSecrets: boolean;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  form: any;
}

function DynamicConfigField({ field, mode, idPrefix, showSecrets, form }: DynamicConfigFieldProps) {
  const { t } = useTranslation('backup');
  return (
    <FormField
      control={form.control}
      name={`config.${field.name}` as `config.${string}`}
      render={({ field: rhfField }) => {
        const value = (rhfField.value as string | undefined) ?? '';
        const placeholder = mode === 'edit'
          ? (field.placeholder || t('StorageLocationsPage.dynamicField.leaveEmptyPlaceholder'))
          : (field.placeholder || '');

        return (
          <FormItem>
            <FormLabel className="text-sm" htmlFor={`${idPrefix}-${field.name}`}>
              {field.label}
              {mode === 'create' && field.required && <span className="text-destructive ml-1">*</span>}
            </FormLabel>
            <FormControl>
              {field.type === 'textarea' ? (
                <Textarea
                  id={`${idPrefix}-${field.name}`}
                  placeholder={placeholder}
                  rows={3}
                  value={value}
                  onChange={(e) => rhfField.onChange(e.target.value)}
                  onBlur={rhfField.onBlur}
                />
              ) : field.type === 'boolean' ? (
                <div className="flex items-center gap-2">
                  <Switch
                    id={`${idPrefix}-${field.name}`}
                    checked={value === 'true'}
                    onCheckedChange={(v) => rhfField.onChange(String(v))}
                  />
                  {mode === 'create' && (
                    <Label htmlFor={`${idPrefix}-${field.name}`} className="text-sm text-muted-foreground">
                      {value === 'true' ? t('StorageLocationsPage.dynamicField.enabled') : t('StorageLocationsPage.dynamicField.disabled')}
                    </Label>
                  )}
                </div>
              ) : (
                <Input
                  id={`${idPrefix}-${field.name}`}
                  type={
                    field.type === 'password' && !showSecrets
                      ? 'password'
                      : field.type === 'number'
                      ? 'number'
                      : 'text'
                  }
                  placeholder={placeholder}
                  value={value}
                  onChange={(e) => rhfField.onChange(e.target.value)}
                  onBlur={rhfField.onBlur}
                />
              )}
            </FormControl>
            <FormMessage />
          </FormItem>
        );
      }}
    />
  );
}
